"""
GitHub 仓库导入模块
支持从 GitHub 导入代码仓库到本地项目
"""

import os
import re
import requests
import zipfile
import io
import json
import uuid
from pathlib import Path
from urllib.parse import urlparse, urljoin
import tempfile
import shutil


class GitHubImporter:
    """GitHub 仓库导入器"""

    def __init__(self, upload_folder):
        """
        初始化 GitHub 导入器

        Args:
            upload_folder: 上传文件夹路径
        """
        self.upload_folder = upload_folder
        # 与 app.py 迁移管线一致，仅拉取可迁移的源代码类型
        self.allowed_extensions = {'.py', '.java', '.cpp', '.c', '.js', '.go', '.h'}

    def validate_github_url(self, url):
        """
        验证 GitHub URL 是否有效

        Args:
            url: GitHub 仓库 URL

        Returns:
            tuple: (is_valid, normalized_url, error_message, branch_hint)
            branch_hint: 从 /tree/xxx、/blob/xxx 解析出的分支或标签首段，可为 None
        """
        if not url or not isinstance(url, str):
            return False, None, "URL 不能为空", None

        url = url.strip()

        # /tree/owner/repo/tree/branch/... → 提取分支首段（复杂分支名建议在表单中填写）
        tree_m = re.match(
            r'^https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)',
            url,
            re.IGNORECASE,
        )
        if tree_m:
            owner, repo, branch_hint = tree_m.groups()
            repo = repo.replace('.git', '').strip()
            normalized_url = f"https://github.com/{owner}/{repo}"
            return True, normalized_url, None, branch_hint.strip()

        blob_m = re.match(
            r'^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)',
            url,
            re.IGNORECASE,
        )
        if blob_m:
            owner, repo, branch_hint = blob_m.groups()
            repo = repo.replace('.git', '').strip()
            normalized_url = f"https://github.com/{owner}/{repo}"
            return True, normalized_url, None, branch_hint.strip()

        patterns = [
            r'^https?://github\.com/([^/]+)/([^/]+)(?:\.git)?/?$',
            r'^git@github\.com:([^/]+)/([^/]+)\.git$',
            r'^github\.com/([^/]+)/([^/]+)(?:\.git)?/?$',
        ]

        for pattern in patterns:
            match = re.match(pattern, url, re.IGNORECASE)
            if match:
                owner, repo = match.groups()[:2]
                repo = repo.replace('.git', '')
                normalized_url = f"https://github.com/{owner}/{repo}"
                return True, normalized_url, None, None

        return False, None, "无效的 GitHub 仓库 URL 格式", None

    def extract_repo_info(self, url):
        """
        从 GitHub URL 提取仓库信息

        Args:
            url: 规范化的 GitHub URL

        Returns:
            dict: 仓库信息
        """
        try:
            # 解析 URL
            parsed = urlparse(url)
            path_parts = parsed.path.strip('/').split('/')

            if len(path_parts) >= 2:
                owner, repo = path_parts[0], path_parts[1]

                # 调用 GitHub API 获取仓库信息
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                response = requests.get(api_url, timeout=10)

                if response.status_code == 200:
                    repo_data = response.json()
                    return {
                        'owner': owner,
                        'name': repo,
                        'full_name': repo_data.get('full_name', f"{owner}/{repo}"),
                        'description': repo_data.get('description', ''),
                        'language': repo_data.get('language', 'Unknown'),
                        'stars': repo_data.get('stargazers_count', 0),
                        'forks': repo_data.get('forks_count', 0),
                        'size': repo_data.get('size', 0),
                        'default_branch': repo_data.get('default_branch', 'main'),
                        'private': repo_data.get('private', False),
                        'archived': repo_data.get('archived', False)
                    }
                else:
                    # API 调用失败，返回基本信息
                    return {
                        'owner': owner,
                        'name': repo,
                        'full_name': f"{owner}/{repo}",
                        'description': '无法获取仓库信息',
                        'language': 'Unknown',
                        'stars': 0,
                        'forks': 0,
                        'size': 0,
                        'default_branch': 'main',
                        'private': False,
                        'archived': False
                    }
            else:
                return None

        except Exception as e:
            print(f"提取仓库信息失败: {e}")
            return None

    def import_repository(self, github_url, branch=None):
        """
        从 GitHub 导入仓库

        Args:
            github_url: GitHub 仓库 URL
            branch: 指定分支，默认为默认分支

        Returns:
            dict: 导入结果
        """
        try:
            print(f"[GitHub] 开始导入仓库: {github_url}")

            is_valid, normalized_url, error, branch_from_url = self.validate_github_url(github_url)
            if not is_valid:
                return {
                    'success': False,
                    'error': error
                }

            # 提取仓库信息
            repo_info = self.extract_repo_info(normalized_url)
            if not repo_info:
                return {
                    'success': False,
                    'error': '无法获取仓库信息'
                }

            explicit = (branch or '').strip() or None
            if explicit:
                use_branch = explicit
            elif branch_from_url:
                use_branch = branch_from_url
            else:
                use_branch = repo_info.get('default_branch', 'main')

            branch = use_branch
            print(f"[GitHub] 仓库: {repo_info['full_name']}, 分支: {branch}")

            # 创建会话目录
            session_id = str(uuid.uuid4())
            session_dir = os.path.join(self.upload_folder, session_id)
            os.makedirs(session_dir, exist_ok=True)

            # 下载仓库 ZIP
            zip_url = f"{normalized_url}/archive/refs/heads/{branch}.zip"
            print(f"[GitHub] 下载 ZIP: {zip_url}")

            ua = {'User-Agent': 'CodeMigrationTool/1.0'}
            response = requests.get(zip_url, timeout=120, headers=ua)
            if response.status_code != 200 and branch == 'main':
                zip_url = f"{normalized_url}/archive/refs/heads/master.zip"
                print(f"[GitHub] 重试下载 ZIP (master): {zip_url}")
                response = requests.get(zip_url, timeout=120, headers=ua)
            if response.status_code != 200:
                tag_zip = f"{normalized_url}/archive/refs/tags/{branch}.zip"
                print(f"[GitHub] 尝试标签归档: {tag_zip}")
                response = requests.get(tag_zip, timeout=120, headers=ua)
            if response.status_code != 200:
                return {
                    'success': False,
                    'error': f'无法下载仓库归档 (HTTP {response.status_code})，请检查分支/标签名或私有仓库需使用本地上传'
                }

            # 解压 ZIP 文件
            print("[GitHub] 正在解压文件...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                names = zip_ref.namelist()
                if not names:
                    return {
                        'success': False,
                        'error': 'ZIP 文件为空'
                    }
                root_dir = names[0].split('/')[0] + '/'

                # 解压文件
                for file_info in zip_ref.filelist:
                    # 只处理允许的文件类型
                    file_path = file_info.filename
                    if not file_path.endswith('/') and self._is_allowed_file(file_path):
                        # 移除根目录前缀
                        rel_path = file_path[len(root_dir):]
                        if rel_path:  # 跳过空路径
                            target_path = os.path.join(session_dir, rel_path)
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)

                            with zip_ref.open(file_info) as source, open(target_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

            # 分析导入的文件
            files_info, languages = self._analyze_imported_files(session_dir)

            if not files_info:
                try:
                    shutil.rmtree(session_dir, ignore_errors=True)
                except Exception:
                    pass
                return {
                    'success': False,
                    'error': '仓库中未找到可迁移的源代码（支持: .py .java .cpp .c .js .go .h）'
                }

            print(f"[GitHub] 导入完成: {len(files_info)} 个文件")

            return {
                'success': True,
                'session_id': session_id,
                'repo_info': repo_info,
                'branch': branch,
                'files_count': len(files_info),
                'files': files_info,
                'languages': languages,
                'total_size': sum(f['size'] for f in files_info)
            }

        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': '下载超时，请检查网络连接'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': '网络连接失败'
            }
        except Exception as e:
            print(f"[GitHub] 导入失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'导入失败: {str(e)}'
            }

    def _is_allowed_file(self, filename):
        """
        检查文件是否为允许的文件类型

        Args:
            filename: 文件名

        Returns:
            bool: 是否允许
        """
        if not filename:
            return False

        # 检查扩展名
        ext = Path(filename).suffix.lower()
        return ext in self.allowed_extensions

    def _analyze_imported_files(self, session_dir):
        """
        分析导入的文件

        Args:
            session_dir: 会话目录

        Returns:
            tuple: (files_info, languages)
        """
        files_info = []
        languages = set()

        for root, dirs, files in os.walk(session_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self._is_allowed_file(file):
                    try:
                        # 检测语言
                        lang = self._detect_language(file_path)
                        languages.add(lang)

                        # 获取相对路径
                        rel_path = os.path.relpath(file_path, session_dir)

                        # 读取文件内容
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            code = f.read()

                        files_info.append({
                            'path': rel_path,
                            'language': lang,
                            'lines': len(code.split('\n')),
                            'size': len(code),
                            'code': code[:200]  # 前 200 字符预览
                        })
                    except Exception as e:
                        print(f"分析文件出错: {file_path}, {e}")

        return files_info, list(languages)

    def _detect_language(self, file_path):
        """
        根据文件扩展名检测语言

        Args:
            file_path: 文件路径

        Returns:
            str: 语言名称
        """
        ext = Path(file_path).suffix.lower()
        lang_map = {
            '.py': 'python',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.go': 'go',
            '.h': 'cpp',
            '.php': 'php',
            '.rb': 'ruby',
            '.rs': 'rust'
        }
        return lang_map.get(ext, 'unknown')