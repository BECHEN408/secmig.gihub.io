"""
多语言项目迁移系统 - Flask Web 应用
支持：Java ↔ Python、C ↔ C++、JavaScript ↔ Python 等
功能：项目上传 → 迁移 → 漏洞扫描 → 可视化报告 → 文件下载
"""

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import re
import shutil
import zipfile
import io
from datetime import datetime
from pathlib import Path
import uuid
import traceback
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# 导入迁移核心模块
import mig

# 导入 GitHub 导入模块
from github_import import GitHubImporter

# ==================== Flask 配置 ====================
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# 文件上传配置
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'migrated_projects'
ALLOWED_EXTENSIONS = {'.py', '.java', '.cpp', '.c', '.js', '.go', '.h'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# 创建必要的文件夹
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('task_state', exist_ok=True)

MIGRATION_TASKS = {}
MIGRATION_TASKS_LOCK = threading.Lock()
TASK_STATE_DIR = 'task_state'


def _task_executor_workers() -> int:
    try:
        n = int(os.environ.get("MIGRATION_TASK_EXECUTOR_WORKERS", "2"))
    except ValueError:
        n = 2
    return max(1, min(n, 4))


MIGRATION_TASK_EXECUTOR = ThreadPoolExecutor(max_workers=_task_executor_workers())

# 并行迁移线程数（LLM 请求为主，默认 3；设为 1 即串行）
def _migration_max_workers(file_count: int) -> int:
    try:
        n = int(os.environ.get("MIGRATION_MAX_WORKERS", "1"))
    except ValueError:
        n = 1
    n = max(1, min(n, 16))
    return min(n, max(1, file_count))


def _resolve_cached_source(file_codes: dict, src_path: str):
    """从 project_deps 缓存取源码，兼容路径规范化差异（尤其 Windows）。"""
    if not file_codes:
        return None
    if src_path in file_codes:
        return file_codes[src_path]
    norm = os.path.normpath(src_path)
    if norm in file_codes:
        return file_codes[norm]
    try:
        want = os.path.normcase(os.path.normpath(src_path))
        for k, v in file_codes.items():
            if os.path.normcase(os.path.normpath(k)) == want:
                return v
    except (OSError, ValueError):
        pass
    return None


def _update_task(task_id: str, **updates):
    with MIGRATION_TASKS_LOCK:
        task = MIGRATION_TASKS.get(task_id)
        if not task:
            return
        task.update(updates)
        task["updated_at"] = datetime.now().isoformat()
        _persist_task_state(task_id, task)


def _task_state_path(task_id: str) -> str:
    return os.path.join(TASK_STATE_DIR, f'{task_id}.json')


def _persist_task_state(task_id: str, task: dict):
    path = _task_state_path(task_id)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(task, f, indent=2, ensure_ascii=False)


def _load_task_state(task_id: str):
    path = _task_state_path(task_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def allowed_file(filename):
    return any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS)

def detect_language(file_path):
    """根据文件扩展名检测语言"""
    ext = Path(file_path).suffix.lower()
    lang_map = {
        '.py': 'python',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.js': 'javascript',
        '.go': 'go',
        '.h': 'cpp'
    }
    return lang_map.get(ext, 'python')

def extract_project_info(upload_dir):
    """分析上传的项目文件"""
    files_info = []
    languages = set()
    
    for root, dirs, files in os.walk(upload_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if allowed_file(file):
                try:
                    lang = detect_language(file)
                    languages.add(lang)
                    
                    rel_path = os.path.relpath(file_path, upload_dir)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    
                    lines = code.count('\n') + (1 if code else 0)
                    files_info.append({
                        'path': rel_path,
                        'language': lang,
                        'lines': lines,
                        'size': len(code),
                        'code': code[:200]  # 前 200 字符预览
                    })
                except Exception as e:
                    print(f"解析文件出错: {file_path}, {e}")
    
    return files_info, list(languages)


def _run_migration_task(task_id, session_id, src_lang, tgt_lang):
    migration_id = None
    try:
        _update_task(task_id, status='running', message='正在初始化迁移任务...', progress=5)

        session_dir = os.path.join(UPLOAD_FOLDER, session_id)
        if not os.path.exists(session_dir):
            raise FileNotFoundError('会话不存在')

        migration_id = str(uuid.uuid4())
        output_dir = os.path.join(OUTPUT_FOLDER, migration_id)
        os.makedirs(output_dir, exist_ok=True)
        _update_task(
            task_id,
            migration_id=migration_id,
            output_dir=output_dir,
            message='正在初始化技能...',
            progress=10
        )

        mig.init_skills(src_lang)

        try:
            max_iterations = int(os.environ.get("MIGRATION_MAX_ITERATIONS", "2"))
        except ValueError:
            max_iterations = 2

        actor = mig.EnhancedActor(max_iterations=max(1, min(max_iterations, 3)))
        critic = mig.EnhancedCritic()
        graph_builder = mig.SemanticGraphBuilder(src_lang)

        _update_task(task_id, message='正在分析项目结构...', progress=20)
        deps_skill = mig.SkillRegistry.get("project_deps")
        proj_data = deps_skill.run(project_root=session_dir)
        semantic_graph = graph_builder.build_from_project(proj_data)
        rules = mig.SAFE_RULES.get("common", []) + mig.SAFE_RULES.get(src_lang, [])

        scan_results = {
            'before': [],
            'after': [],
            'files': []
        }

        file_codes = proj_data.get("file_codes") if isinstance(proj_data.get("file_codes"), dict) else {}
        file_tasks = []
        for root, dirs, files in os.walk(session_dir):
            for file in files:
                if allowed_file(file):
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, session_dir)
                    file_tasks.append((rel_path, src_path))
        file_tasks.sort(key=lambda x: x[0])

        workers = _migration_max_workers(len(file_tasks))
        migrated_count = 0
        error_count = 0
        errors = []
        total_files = max(len(file_tasks), 1)

        def _migrate_one(rel_path, src_path):
            src_code = _resolve_cached_source(file_codes, src_path)
            if src_code is None:
                with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    src_code = f.read()

            before_vulns = critic.scan(src_code, src_lang)
            migrated_code, iterations = actor.translate(
                code=src_code,
                src=src_lang,
                tgt=tgt_lang,
                path=rel_path,
                rules=rules,
                proj=semantic_graph,
                critic_ref=critic
            )

            if not migrated_code or "迁移失败" in migrated_code or "降级模式" in migrated_code:
                raise Exception("LLM 迁移失败，返回空代码或错误标记")

            after_vulns = critic.scan(migrated_code, tgt_lang)
            vpi_result = critic.vpi(before_vulns, after_vulns)
            vpi_score = vpi_result['vpi']

            mig.write_output_file(
                src_path,
                src_lang,
                tgt_lang,
                migrated_code,
                output_dir,
                project_root=session_dir
            )

            return {
                'path': rel_path,
                'before_vulns': before_vulns,
                'after_vulns': after_vulns,
                'vpi': vpi_score,
                'status': 'success',
                'iterations': len(iterations)
            }

        _update_task(task_id, message='正在执行迁移...', progress=30, total_files=len(file_tasks), completed_files=0)

        if file_tasks:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(_migrate_one, rel, sp): rel
                    for rel, sp in file_tasks
                }
                for fut in as_completed(future_map):
                    rel_path = future_map[fut]
                    try:
                        done = fut.result()
                        scan_results['files'].append({
                            'path': done['path'],
                            'before_vulns': len(done['before_vulns']),
                            'after_vulns': len(done['after_vulns']),
                            'vpi': done['vpi'],
                            'status': done['status']
                        })
                        scan_results['before'].extend(done['before_vulns'])
                        scan_results['after'].extend(done['after_vulns'])
                        migrated_count += 1
                    except requests.exceptions.Timeout:
                        error_count += 1
                        errors.append(f"{rel_path}: API 请求超时（超过 180 秒）")
                    except requests.exceptions.ConnectionError as e:
                        error_count += 1
                        errors.append(f"{rel_path}: 网络连接失败 - {str(e)}")
                    except Exception as e:
                        error_count += 1
                        errors.append(f"{rel_path}: {str(e)}")
                        traceback.print_exc()
                    finally:
                        completed = migrated_count + error_count
                        progress = 30 + int((completed / total_files) * 60)
                        _update_task(
                            task_id,
                            message=f'正在迁移文件... ({completed}/{len(file_tasks)})',
                            progress=progress,
                            completed_files=completed,
                            migrated_count=migrated_count,
                            error_count=error_count,
                            errors=errors[:5]
                        )

            scan_results['files'].sort(key=lambda x: x['path'])

        _update_task(task_id, message='正在生成报告...', progress=95)
        report_data = generate_report(session_id, migration_id, src_lang, tgt_lang, scan_results)
        report_path = os.path.join('reports', f'{migration_id}_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        result = {
            'success': True,
            'migration_id': migration_id,
            'migrated_count': migrated_count,
            'error_count': error_count,
            'errors': errors[:5],
            'report': report_data,
            'output_dir': output_dir
        }
        _update_task(task_id, status='completed', message='迁移完成', progress=100, result=result)
    except Exception as e:
        traceback.print_exc()
        _update_task(
            task_id,
            status='failed',
            message=str(e),
            error=str(e),
            progress=100
        )

# ==================== 路由：页面渲染 ====================
@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/api/languages', methods=['GET'])
def get_languages():
    """获取支持的语言列表"""
    return jsonify({
        'languages': list(mig.LANG_CONFIG.keys()),
        'pairs': [
            {'from': 'java', 'to': 'python'},
            {'from': 'python', 'to': 'java'},
            {'from': 'python', 'to': 'javascript'},
            {'from': 'javascript', 'to': 'python'},
            {'from': 'c', 'to': 'cpp'},
            {'from': 'cpp', 'to': 'c'},
            {'from': 'python', 'to': 'go'},
        ]
    })

# ==================== 路由：项目上传 ====================
@app.route('/api/upload', methods=['POST'])
def upload_project():
    """处理项目文件上传"""
    try:
        # 检查是否有文件
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': '未检测到文件'}), 400
        
        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            return jsonify({'success': False, 'error': '没有选择文件'}), 400
        
        # 创建上传会话
        session_id = str(uuid.uuid4())
        session_dir = os.path.join(UPLOAD_FOLDER, session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        uploaded_files = []
        total_size = 0
        
        # 保存上传的文件，保留文件夹结构
        for idx, file in enumerate(files):
            if file and allowed_file(file.filename):
                # 获取相对路径信息（从表单中传入）
                relative_path = request.form.get(f'path_{idx}', secure_filename(file.filename))
                
                # 确保路径安全（防止路径遍历）
                # 移除任何上级目录引用
                relative_path = os.path.normpath(relative_path)
                if relative_path.startswith('..'):
                    relative_path = secure_filename(file.filename)
                
                # 构建完整的文件路径
                file_path = os.path.join(session_dir, relative_path)
                
                # 创建必要的目录
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # 保存文件
                file.save(file_path)
                uploaded_files.append(relative_path)
                total_size += os.path.getsize(file_path)
        
        if not uploaded_files:
            return jsonify({'success': False, 'error': '没有有效的代码文件'}), 400
        
        # 分析项目
        files_info, languages = extract_project_info(session_dir)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'files_count': len(uploaded_files),
            'total_size': total_size,
            'files': files_info,
            'languages': languages
        })
    
    except Exception as e:
        print(f"上传错误: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 路由：GitHub 导入 ====================
@app.route('/api/github/validate', methods=['POST'])
def validate_github_url():
    """验证 GitHub 仓库 URL"""
    try:
        data = request.json
        url = data.get('url', '')
        
        importer = GitHubImporter(UPLOAD_FOLDER)
        is_valid, normalized_url, error, branch_hint = importer.validate_github_url(url)
        
        if is_valid:
            repo_info = importer.extract_repo_info(normalized_url)
            return jsonify({
                'success': True,
                'valid': True,
                'normalized_url': normalized_url,
                'branch_hint': branch_hint,
                'repo_info': repo_info
            })
        else:
            return jsonify({
                'success': True,
                'valid': False,
                'error': error
            })
    
    except Exception as e:
        print(f"URL验证错误: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/github/import', methods=['POST'])
def import_from_github():
    """从 GitHub 导入仓库"""
    try:
        print("\n" + "="*60)
        print("[API] 收到 GitHub 导入请求")
        
        data = request.json
        github_url = data.get('url', '')
        branch = data.get('branch', None)
        
        print(f"[API] URL: {github_url}, Branch: {branch}")
        
        if not github_url:
            return jsonify({'success': False, 'error': '请提供 GitHub 仓库 URL'}), 400
        
        # 创建导入器并执行导入
        importer = GitHubImporter(UPLOAD_FOLDER)
        result = importer.import_repository(github_url, branch)
        
        if result['success']:
            print(f"[API] GitHub 导入成功: {result['files_count']} 个文件")
            return jsonify(result)
        else:
            print(f"[API] GitHub 导入失败: {result['error']}")
            return jsonify(result), 400
    
    except Exception as e:
        print(f"GitHub 导入错误: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 路由：执行迁移 ====================
@app.route('/api/migrate', methods=['POST'])
def migrate_project():
    """创建后台迁移任务"""
    try:
        data = request.json or {}
        session_id = data.get('session_id')
        src_lang = data.get('src_lang')
        tgt_lang = data.get('tgt_lang')

        if not session_id or not src_lang or not tgt_lang:
            return jsonify({'success': False, 'error': '缺少必要参数'}), 400

        session_dir = os.path.join(UPLOAD_FOLDER, session_id)
        if not os.path.exists(session_dir):
            return jsonify({'success': False, 'error': '会话不存在'}), 400

        task_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with MIGRATION_TASKS_LOCK:
            MIGRATION_TASKS[task_id] = {
                'task_id': task_id,
                'status': 'queued',
                'message': '迁移任务已创建',
                'progress': 0,
                'created_at': now,
                'updated_at': now,
                'session_id': session_id,
                'src_lang': src_lang,
                'tgt_lang': tgt_lang,
                'completed_files': 0,
                'total_files': 0,
                'migrated_count': 0,
                'error_count': 0,
                'errors': []
            }
            _persist_task_state(task_id, MIGRATION_TASKS[task_id])

        MIGRATION_TASK_EXECUTOR.submit(_run_migration_task, task_id, session_id, src_lang, tgt_lang)

        return jsonify({
            'success': True,
            'task_id': task_id,
            'status': 'queued',
            'message': '迁移任务已提交'
        })

    except Exception as e:
        print(f"迁移任务创建失败: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/migrate/<task_id>', methods=['GET'])
def get_migration_task(task_id):
    """查询迁移任务状态"""
    with MIGRATION_TASKS_LOCK:
        task = MIGRATION_TASKS.get(task_id)
        if task:
            return jsonify({'success': True, 'task': task})

    task = _load_task_state(task_id)
    if task:
        with MIGRATION_TASKS_LOCK:
            MIGRATION_TASKS[task_id] = task
        return jsonify({'success': True, 'task': task})

    return jsonify({'success': False, 'error': '任务不存在'}), 404

# ==================== 报告生成 ====================
def generate_report(session_id, migration_id, src_lang, tgt_lang, scan_results):
    """生成详细的迁移报告"""
    
    # 统计数据
    total_before = len(scan_results['before'])
    total_after = len(scan_results['after'])
    
    # 按严重程度统计
    severity_before = {}
    severity_after = {}
    
    for vuln in scan_results['before']:
        sev = vuln.get('severity', 'UNKNOWN')
        severity_before[sev] = severity_before.get(sev, 0) + 1
    
    for vuln in scan_results['after']:
        sev = vuln.get('severity', 'UNKNOWN')
        severity_after[sev] = severity_after.get(sev, 0) + 1
    
    # 漏洞类型统计
    vuln_types_before = {}
    vuln_types_after = {}
    
    for vuln in scan_results['before']:
        msg = vuln.get('msg', 'Unknown')
        
        if ':' in msg:
            vuln_type = msg.split(':')[0].strip()
        else:
            match = re.match(r'^([^(]+)', msg)
            if match:
                vuln_type = match.group(1).strip()
            else:
                vuln_type = msg.strip()
        
        vuln_types_before[vuln_type] = vuln_types_before.get(vuln_type, 0) + 1
    
    for vuln in scan_results['after']:
        msg = vuln.get('msg', 'Unknown')
        
        if ':' in msg:
            vuln_type = msg.split(':')[0].strip()
        else:
            match = re.match(r'^([^(]+)', msg)
            if match:
                vuln_type = match.group(1).strip()
            else:
                vuln_type = msg.strip()
        
        vuln_types_after[vuln_type] = vuln_types_after.get(vuln_type, 0) + 1
    
    # 计算整体 VPI
    all_files_vpi = [f['vpi'] for f in scan_results['files']]
    overall_vpi = sum(all_files_vpi) / len(all_files_vpi) if all_files_vpi else 1.0
    
    # 修复率
    fixed_vulns = total_before - total_after
    fix_rate = (fixed_vulns / total_before) if total_before > 0 else 0
    
    report = {
        'migration_id': migration_id,
        'timestamp': datetime.now().isoformat(),
        'source_language': src_lang,
        'target_language': tgt_lang,
        'file_count': len(scan_results['files']),
        'statistics': {
            'vulnerabilities_before': total_before,
            'vulnerabilities_after': total_after,
            'vulnerabilities_fixed': fixed_vulns,
            'fix_rate': round(fix_rate * 100, 2),
            'vpi': round(overall_vpi, 3)
        },
        'severity_breakdown': {
            'before': severity_before,
            'after': severity_after
        },
        'vulnerability_types': {
            'before': vuln_types_before,
            'after': vuln_types_after
        },
        'files': scan_results['files'],
        'top_vulnerabilities': {
            'before': scan_results['before'][:10],
            'after': scan_results['after'][:10]
        }
    }
    
    return report


def _get_report_path(migration_id):
    return os.path.join('reports', f'{migration_id}_report.json')


def _load_report(migration_id):
    report_path = _get_report_path(migration_id)
    if not os.path.exists(report_path):
        raise FileNotFoundError('报告不存在')

    with open(report_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def _format_report_timestamp(timestamp_str):
    try:
        return datetime.fromisoformat(timestamp_str).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return timestamp_str or 'N/A'


def _sorted_breakdown_items(items):
    severity_order = {
        'CRITICAL': 0,
        'ERROR': 1,
        'HIGH': 2,
        'WARNING': 3,
        'MEDIUM': 4,
        'LOW': 5,
        'INFO': 6,
        'UNKNOWN': 7
    }
    return sorted(
        (items or {}).items(),
        key=lambda item: (severity_order.get(str(item[0]).upper(), 99), str(item[0]))
    )


def _top_type_lines(items, limit=8):
    sorted_items = sorted((items or {}).items(), key=lambda item: (-item[1], item[0]))
    if not sorted_items:
        return ['- None']
    return [f'- {name}: {count}' for name, count in sorted_items[:limit]]


def _summarize_vulnerability(vuln, index):
    severity = vuln.get('severity', 'UNKNOWN')
    path = vuln.get('path', 'N/A')
    line = vuln.get('line', '?')
    message = vuln.get('msg', 'Unknown vulnerability')
    return f'{index}. [{severity}] {message} ({path}:{line})'


def _vulnerability_lines(vulns):
    if not vulns:
        return ['- None']
    return [_summarize_vulnerability(vuln, index) for index, vuln in enumerate(vulns, start=1)]


def _file_detail_lines(files):
    if not files:
        return ['- None']

    lines = []
    for file_info in files:
        file_path = file_info.get('file', 'Unknown file')
        vpi = file_info.get('vpi', 0)
        before = file_info.get('vulnerabilities_before', 0)
        after = file_info.get('vulnerabilities_after', 0)
        status = file_info.get('status', 'unknown')
        lines.append(
            f'- {file_path} | status={status} | vpi={vpi:.3f} | before={before} | after={after}'
        )
    return lines


def _truncate_text(text, max_length=72):
    text = str(text or '')
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + '…'


def _get_report_risk_level(report):
    stats = report.get('statistics', {})
    remaining = stats.get('vulnerabilities_after', 0)
    vpi = stats.get('vpi', 0)
    if remaining == 0 and vpi <= 0.2:
        return '低风险', colors.HexColor('#059669')
    if remaining <= 3 and vpi <= 1.2:
        return '中风险', colors.HexColor('#d97706')
    return '高风险', colors.HexColor('#dc2626')


def _build_report_conclusion(report):
    stats = report.get('statistics', {})
    remaining = stats.get('vulnerabilities_after', 0)
    fixed = stats.get('vulnerabilities_fixed', 0)
    fix_rate = stats.get('fix_rate', 0)
    if remaining == 0:
        return f'本次迁移后的代码未发现残留漏洞，共修复 {fixed} 个问题，整体安全性表现稳定。'
    return f'本次迁移共修复 {fixed} 个问题，修复率 {fix_rate:.1f}%，仍有 {remaining} 个漏洞建议继续处理。'


def _build_report_recommendations(report):
    stats = report.get('statistics', {})
    after_types = report.get('vulnerability_types', {}).get('after', {})
    recommendations = []

    if stats.get('vulnerabilities_after', 0) == 0:
        recommendations.append('建议将本次迁移结果作为基线版本，并纳入后续回归扫描。')
    else:
        recommendations.append('建议优先处理迁移后仍然存在的残留漏洞，避免问题进入上线环境。')

    if after_types:
        top_type = max(after_types.items(), key=lambda item: item[1])[0]
        recommendations.append(f'建议针对高频问题类型“{top_type}”补充专项修复规则与测试用例。')

    if stats.get('fix_rate', 0) < 80:
        recommendations.append('修复率偏低，建议复核迁移规则与自动修复策略，重点关注复杂语法场景。')

    recommendations.append('建议保留 JSON 或 Markdown 报告，便于后续自动归档、审计和二次分析。')
    return recommendations[:4]


def build_markdown_report(report):
    stats = report.get('statistics', {})
    sections = [
        '# Migration Report',
        '',
        f"- Migration ID: `{report.get('migration_id', 'N/A')}`",
        f"- Generated At: {_format_report_timestamp(report.get('timestamp'))}",
        f"- Source Language: `{report.get('source_language', 'N/A')}`",
        f"- Target Language: `{report.get('target_language', 'N/A')}`",
        f"- Files Processed: {report.get('file_count', 0)}",
        '',
        '## Summary',
        '',
        '| Metric | Value |',
        '| --- | --- |',
        f"| Vulnerabilities Before | {stats.get('vulnerabilities_before', 0)} |",
        f"| Vulnerabilities After | {stats.get('vulnerabilities_after', 0)} |",
        f"| Vulnerabilities Fixed | {stats.get('vulnerabilities_fixed', 0)} |",
        f"| Fix Rate | {stats.get('fix_rate', 0)}% |",
        f"| Overall VPI | {stats.get('vpi', 0):.3f} |",
        '',
        '## Severity Breakdown',
        '',
        '### Before Migration',
    ]

    sections.extend(
        [f'- {severity}: {count}' for severity, count in _sorted_breakdown_items(report.get('severity_breakdown', {}).get('before'))]
        or ['- None']
    )
    sections.extend(['', '### After Migration'])
    sections.extend(
        [f'- {severity}: {count}' for severity, count in _sorted_breakdown_items(report.get('severity_breakdown', {}).get('after'))]
        or ['- None']
    )

    sections.extend(['', '## Top Vulnerability Types', '', '### Before Migration'])
    sections.extend(_top_type_lines(report.get('vulnerability_types', {}).get('before')))
    sections.extend(['', '### After Migration'])
    sections.extend(_top_type_lines(report.get('vulnerability_types', {}).get('after')))

    sections.extend(['', '## Top Vulnerabilities', '', '### Before Migration'])
    sections.extend(_vulnerability_lines(report.get('top_vulnerabilities', {}).get('before')))
    sections.extend(['', '### After Migration'])
    sections.extend(_vulnerability_lines(report.get('top_vulnerabilities', {}).get('after')))

    sections.extend(['', '## File Details'])
    sections.extend(_file_detail_lines(report.get('files')))

    sections.extend(['', '## Recommendations'])
    sections.extend([f'- {item}' for item in _build_report_recommendations(report)])

    return '\n'.join(sections) + '\n'


def _ensure_pdf_font():
    try:
        pdfmetrics.getFont('STSong-Light')
    except KeyError:
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))


def _get_pdf_styles():
    _ensure_pdf_font()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='PdfTitle',
        fontName='STSong-Light',
        fontSize=20,
        leading=26,
        textColor=colors.white,
        alignment=TA_LEFT,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name='PdfSubtitle',
        fontName='STSong-Light',
        fontSize=9,
        leading=14,
        textColor=colors.HexColor('#dbeafe'),
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name='PdfSectionTitle',
        fontName='STSong-Light',
        fontSize=13,
        leading=18,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=10,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name='PdfBody',
        fontName='STSong-Light',
        fontSize=9.5,
        leading=15,
        textColor=colors.HexColor('#334155'),
        wordWrap='CJK',
    ))
    styles.add(ParagraphStyle(
        name='PdfBodySmall',
        fontName='STSong-Light',
        fontSize=8.5,
        leading=13,
        textColor=colors.HexColor('#475569'),
        wordWrap='CJK',
    ))
    styles.add(ParagraphStyle(
        name='PdfMetricValue',
        fontName='STSong-Light',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#0f172a'),
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='PdfMetricLabel',
        fontName='STSong-Light',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748b'),
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='PdfBadge',
        fontName='STSong-Light',
        fontSize=9,
        leading=11,
        textColor=colors.white,
        alignment=TA_CENTER,
    ))
    return styles


def _paragraph(text, style):
    return Paragraph(str(text).replace('\n', '<br/>'), style)


def _make_metric_cell(value, label, styles):
    return Table(
        [
            [_paragraph(value, styles['PdfMetricValue'])],
            [_paragraph(label, styles['PdfMetricLabel'])],
        ],
        colWidths=[34 * mm]
    )


def _make_simple_table(data, col_widths, header_background=colors.HexColor('#e2e8f0')):
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), header_background),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('FONTNAME', (0, 0), (-1, -1), 'STSong-Light'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ('LEADING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table


def _draw_pdf_page(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(colors.HexColor('#0f172a'))
    canvas.rect(0, height - 10 * mm, width, 10 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.HexColor('#64748b'))
    canvas.setFont('Helvetica', 8)
    canvas.drawString(doc.leftMargin, 8 * mm, 'Migration Security Report')
    canvas.drawRightString(width - doc.rightMargin, 8 * mm, f'Page {doc.page}')
    canvas.restoreState()


def build_pdf_report(report):
    styles = _get_pdf_styles()
    stats = report.get('statistics', {})
    risk_label, risk_color = _get_report_risk_level(report)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title='Migration Security Report'
    )

    story = []

    hero = Table([[
        Table([
            [_paragraph('代码迁移安全分析报告', styles['PdfTitle'])],
            [_paragraph(
                f"任务编号：{report.get('migration_id', 'N/A')}<br/>"
                f"生成时间：{_format_report_timestamp(report.get('timestamp'))}<br/>"
                f"迁移方向：{str(report.get('source_language', 'N/A')).upper()} → {str(report.get('target_language', 'N/A')).upper()}",
                styles['PdfSubtitle']
            )]
        ], colWidths=[118 * mm]),
        Table([[
            _paragraph(risk_label, styles['PdfBadge'])
        ]], colWidths=[24 * mm], rowHeights=[14 * mm])
    ]], colWidths=[122 * mm, 30 * mm])
    hero.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
        ('BOX', (0, 0), (-1, -1), 0, colors.white),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (1, 0), (1, 0), risk_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(hero)
    story.append(Spacer(1, 8 * mm))

    story.append(_paragraph('执行摘要', styles['PdfSectionTitle']))
    story.append(_paragraph(_build_report_conclusion(report), styles['PdfBody']))
    story.append(Spacer(1, 4 * mm))

    metrics = Table([[
        _make_metric_cell(str(report.get('file_count', 0)), '处理文件数', styles),
        _make_metric_cell(str(stats.get('vulnerabilities_before', 0)), '迁移前漏洞', styles),
        _make_metric_cell(str(stats.get('vulnerabilities_after', 0)), '迁移后漏洞', styles),
        _make_metric_cell(str(stats.get('vulnerabilities_fixed', 0)), '已修复问题', styles),
        _make_metric_cell(f"{stats.get('fix_rate', 0):.1f}%", '修复率', styles),
        _make_metric_cell(f"{stats.get('vpi', 0):.3f}", '整体 VPI', styles),
    ]], colWidths=[25.3 * mm] * 6)
    metrics.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.6, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(metrics)
    story.append(Spacer(1, 6 * mm))

    story.append(_paragraph('风险分布概览', styles['PdfSectionTitle']))
    severity_rows = [[
        _paragraph('风险等级', styles['PdfBody']),
        _paragraph('迁移前', styles['PdfBody']),
        _paragraph('迁移后', styles['PdfBody']),
    ]]
    severities = {key for key, _ in _sorted_breakdown_items(report.get('severity_breakdown', {}).get('before'))}
    severities.update({key for key, _ in _sorted_breakdown_items(report.get('severity_breakdown', {}).get('after'))})
    for severity in ['CRITICAL', 'HIGH', 'ERROR', 'WARNING', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
        if severity not in severities:
            continue
        severity_rows.append([
            _paragraph(severity, styles['PdfBodySmall']),
            _paragraph(str(report.get('severity_breakdown', {}).get('before', {}).get(severity, 0)), styles['PdfBodySmall']),
            _paragraph(str(report.get('severity_breakdown', {}).get('after', {}).get(severity, 0)), styles['PdfBodySmall']),
        ])
    if len(severity_rows) == 1:
        severity_rows.append([
            _paragraph('无', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
        ])
    story.append(_make_simple_table(severity_rows, [60 * mm, 45 * mm, 45 * mm]))
    story.append(Spacer(1, 6 * mm))

    story.append(_paragraph('高频漏洞类型', styles['PdfSectionTitle']))
    type_rows = [[
        _paragraph('漏洞类型', styles['PdfBody']),
        _paragraph('迁移前', styles['PdfBody']),
        _paragraph('迁移后', styles['PdfBody']),
    ]]
    before_types = report.get('vulnerability_types', {}).get('before', {})
    after_types = report.get('vulnerability_types', {}).get('after', {})
    all_types = sorted(set(before_types.keys()) | set(after_types.keys()), key=lambda item: -(before_types.get(item, 0) + after_types.get(item, 0)))
    for vuln_type in all_types[:8]:
        type_rows.append([
            _paragraph(_truncate_text(vuln_type, 28), styles['PdfBodySmall']),
            _paragraph(str(before_types.get(vuln_type, 0)), styles['PdfBodySmall']),
            _paragraph(str(after_types.get(vuln_type, 0)), styles['PdfBodySmall']),
        ])
    if len(type_rows) == 1:
        type_rows.append([
            _paragraph('无', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
        ])
    story.append(_make_simple_table(type_rows, [92 * mm, 29 * mm, 29 * mm], header_background=colors.HexColor('#dbeafe')))
    story.append(Spacer(1, 6 * mm))

    story.append(_paragraph('重点漏洞明细', styles['PdfSectionTitle']))
    vuln_rows = [[
        _paragraph('阶段', styles['PdfBody']),
        _paragraph('级别', styles['PdfBody']),
        _paragraph('问题描述', styles['PdfBody']),
        _paragraph('位置', styles['PdfBody']),
    ]]
    highlighted = []
    for phase, vulns in [('迁移前', report.get('top_vulnerabilities', {}).get('before', [])),
                         ('迁移后', report.get('top_vulnerabilities', {}).get('after', []))]:
        for vuln in vulns[:5]:
            highlighted.append([
                _paragraph(phase, styles['PdfBodySmall']),
                _paragraph(str(vuln.get('severity', 'UNKNOWN')), styles['PdfBodySmall']),
                _paragraph(_truncate_text(vuln.get('msg', 'Unknown vulnerability'), 52), styles['PdfBodySmall']),
                _paragraph(_truncate_text(f"{vuln.get('path', 'N/A')}:{vuln.get('line', '?')}", 34), styles['PdfBodySmall']),
            ])
    vuln_rows.extend(highlighted or [[
        _paragraph('无', styles['PdfBodySmall']),
        _paragraph('-', styles['PdfBodySmall']),
        _paragraph('未记录重点漏洞', styles['PdfBodySmall']),
        _paragraph('-', styles['PdfBodySmall']),
    ]])
    story.append(_make_simple_table(vuln_rows, [18 * mm, 22 * mm, 88 * mm, 34 * mm], header_background=colors.HexColor('#fee2e2')))
    story.append(Spacer(1, 6 * mm))

    story.append(_paragraph('文件级迁移结果', styles['PdfSectionTitle']))
    file_rows = [[
        _paragraph('文件', styles['PdfBody']),
        _paragraph('状态', styles['PdfBody']),
        _paragraph('前', styles['PdfBody']),
        _paragraph('后', styles['PdfBody']),
        _paragraph('VPI', styles['PdfBody']),
    ]]
    for file_info in report.get('files', [])[:24]:
        file_rows.append([
            _paragraph(_truncate_text(file_info.get('file', 'Unknown file'), 46), styles['PdfBodySmall']),
            _paragraph(str(file_info.get('status', 'unknown')), styles['PdfBodySmall']),
            _paragraph(str(file_info.get('vulnerabilities_before', 0)), styles['PdfBodySmall']),
            _paragraph(str(file_info.get('vulnerabilities_after', 0)), styles['PdfBodySmall']),
            _paragraph(f"{file_info.get('vpi', 0):.3f}", styles['PdfBodySmall']),
        ])
    if len(file_rows) == 1:
        file_rows.append([
            _paragraph('无', styles['PdfBodySmall']),
            _paragraph('-', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
            _paragraph('0', styles['PdfBodySmall']),
            _paragraph('0.000', styles['PdfBodySmall']),
        ])
    story.append(_make_simple_table(file_rows, [92 * mm, 28 * mm, 14 * mm, 14 * mm, 18 * mm]))
    story.append(Spacer(1, 6 * mm))

    story.append(_paragraph('建议动作', styles['PdfSectionTitle']))
    for index, recommendation in enumerate(_build_report_recommendations(report), start=1):
        story.append(_paragraph(f'{index}. {recommendation}', styles['PdfBody']))
        story.append(Spacer(1, 1.5 * mm))

    doc.build(story, onFirstPage=_draw_pdf_page, onLaterPages=_draw_pdf_page)
    buffer.seek(0)
    return buffer

# ==================== 路由：获取报告 ====================
@app.route('/api/report/<migration_id>', methods=['GET'])
def get_report(migration_id):
    """获取迁移报告"""
    try:
        report = _load_report(migration_id)
        
        return jsonify({
            'success': True,
            'report': report
        })
    
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 路由：下载文件 ====================
@app.route('/api/download/<migration_id>', methods=['GET'])
def download_project(migration_id):
    """下载迁移后的项目（ZIP 文件）"""
    try:
        output_dir = os.path.join(OUTPUT_FOLDER, migration_id)
        if not os.path.exists(output_dir):
            return jsonify({'success': False, 'error': '项目不存在'}), 404
        
        # 创建 ZIP 文件
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, output_dir)
                    zip_file.write(file_path, arcname)
        
        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'migrated_project_{migration_id[:8]}.zip'
        )
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 路由：下载报告 ====================
@app.route('/api/download-report/<migration_id>', methods=['GET'])
def download_report(migration_id):
    """下载迁移报告（JSON / Markdown / PDF）"""
    try:
        report = _load_report(migration_id)
        export_format = (request.args.get('format', 'json') or 'json').strip().lower()
        if export_format == 'markdown':
            export_format = 'md'

        base_name = f'migration_report_{migration_id[:8]}'

        if export_format == 'json':
            return send_file(
                _get_report_path(migration_id),
                mimetype='application/json',
                as_attachment=True,
                download_name=f'{base_name}.json'
            )

        if export_format == 'md':
            markdown_content = build_markdown_report(report)
            markdown_buffer = io.BytesIO(markdown_content.encode('utf-8'))
            markdown_buffer.seek(0)
            return send_file(
                markdown_buffer,
                mimetype='text/markdown; charset=utf-8',
                as_attachment=True,
                download_name=f'{base_name}.md'
            )

        if export_format == 'pdf':
            pdf_buffer = build_pdf_report(report)
            return send_file(
                pdf_buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'{base_name}.pdf'
            )

        return jsonify({'success': False, 'error': '不支持的报告格式'}), 400

    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 路由：健康检查 ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

# ==================== 错误处理 ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': '页面不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': '服务器内部错误'}), 500

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║   多语言项目迁移系统 v1.0                            ║
    ║   支持: Java ↔ Python、C ↔ C++、JavaScript ↔ Python ║
    ║   访问: http://localhost:5000                        ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    # 🔥 关闭自动重载,避免迁移过程中因临时文件变化导致服务器重启
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
