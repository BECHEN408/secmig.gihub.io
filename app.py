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

MIGRATION_TASKS = {}
MIGRATION_TASKS_LOCK = threading.Lock()


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
        if not task:
            return jsonify({'success': False, 'error': '任务不存在'}), 404
        return jsonify({'success': True, 'task': task})

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

# ==================== 路由：获取报告 ====================
@app.route('/api/report/<migration_id>', methods=['GET'])
def get_report(migration_id):
    """获取迁移报告"""
    try:
        report_path = os.path.join('reports', f'{migration_id}_report.json')
        if not os.path.exists(report_path):
            return jsonify({'success': False, 'error': '报告不存在'}), 404
        
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        return jsonify({
            'success': True,
            'report': report
        })
    
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
    """下载迁移报告（JSON）"""
    try:
        report_path = os.path.join('reports', f'{migration_id}_report.json')
        if not os.path.exists(report_path):
            return jsonify({'success': False, 'error': '报告不存在'}), 404
        
        return send_file(
            report_path,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'migration_report_{migration_id[:8]}.json'
        )
    
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
