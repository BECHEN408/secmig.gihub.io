import hashlib
import re
import os
import json
import uuid
import threading
import shutil
import requests
from requests.adapters import HTTPAdapter
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from dotenv import load_dotenv

# 加载 .env 文件中的环境变量
load_dotenv()

# ==================== 核心配置 ====================
# 🔥 从环境变量读取 API Key（安全方式）
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_MODEL_NAME = "qwen3.7-plus"  # 或 qwen2.5-coder-7b-instruct
DASHSCOPE_BASE_URL = "https://ws-58adetjua8vv5our.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"  # 通义千问兼容模式地址

# 方案 2: 保留 DeepSeek (备选)
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

# 当前使用的服务商：dashscope | deepseek
CURRENT_PROVIDER = os.getenv("CURRENT_PROVIDER", "dashscope")

SAFE_RULES_FILE = "safe_rules.json"
SAFE_RULES = {"common": []}

# 验证 API Key 是否已配置
if not DASHSCOPE_API_KEY and CURRENT_PROVIDER == "dashscope":
    print("⚠️  警告: DASHSCOPE_API_KEY 未配置，请在 .env 文件中设置或配置环境变量")
if not DEEPSEEK_API_KEY and CURRENT_PROVIDER == "deepseek":
    print("⚠️  警告: DEEPSEEK_API_KEY 未配置，请在 .env 文件中设置或配置环境变量")

# 每线程一个 Session，复用 TCP/TLS，降低并行迁移时的连接开销
_llm_session_local = threading.local()


def _thread_http_session() -> requests.Session:
    s = getattr(_llm_session_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _llm_session_local.session = s
    return s


LANG_CONFIG = {
    "python": {"exts": [".py"], "comment": "#", "structure": "module"},
    "java": {"exts": [".java"], "comment": "//", "structure": "package"},
    "cpp": {"exts": [".cpp", ".h"], "comment": "//", "structure": "namespace"},
    "c": {"exts": [".c", ".h"], "comment": "//", "structure": "header"},
    "javascript": {"exts": [".js"], "comment": "//", "structure": "module"},
    "go": {"exts": [".go"], "comment": "//", "structure": "package"}
}

# ==================== Skill 架构基类 ====================
class BaseSkill(ABC):
    skill_id: str
    @abstractmethod
    def run(self, **kwargs): pass

class SkillRegistry:
    _skills: Dict[str, BaseSkill] = {}
    @classmethod
    def register(cls, skill): cls._skills[skill.skill_id] = skill
    @classmethod
    def get(cls, skill_id): return cls._skills[skill_id]

# ==============================================================================
# 🔥 1. 多语言项目资产与依赖分析（全语言通用）
# ==============================================================================
class ProjectDependencySkill(BaseSkill):
    skill_id = "project_deps"

    def __init__(self, src_lang):
        self.src = src_lang
        self.exts = LANG_CONFIG[src_lang]["exts"]

    def run(self, **kwargs):
        root = kwargs["project_root"]
        project = {
            "files": [], "deps": {}, "imports": {}, "functions": {}, "classes": {},
            "file_codes": {},
        }

        for base, _, files in os.walk(root):
            for f in files:
                if any(f.endswith(e) for e in self.exts):
                    path = os.path.join(base, f)
                    try:
                        with open(path, encoding="utf-8", errors="ignore") as fp:
                            code = fp.read()
                        project["files"].append(path)
                        project["file_codes"][path] = code
                        project["deps"][path] = self._extract_imports(code)
                    except Exception:
                        pass
        return project

    def _extract_imports(self, code):
        patterns = {
            "python": r'from\s+([\w.]+)|import\s+([\w.]+)',
            "java": r'import\s+([\w.]+);',
            "cpp": r'#include\s*["<]([\w./]+)[">]',
            "javascript": r'require\(["\']([^"\']+)["\']|import\s+.*from\s+["\']([^"\']+)["\']'
        }
        imports = []
        if self.src in patterns:
            for g in re.findall(patterns[self.src], code):
                imports.extend([i for i in g if i])
        return imports

# ==============================================================================
# 🔥 2. 多语言 SAST 漏洞扫描（集成 Semgrep 专业工具）
# ==============================================================================
class UniversalSastSkill(BaseSkill):
    skill_id = "sast_scan"

    def run(self, **kwargs):
        code, lang = kwargs["code"], kwargs["lang"]
        mode = kwargs.get("mode", "full")
        
        # 🔥 方案 A: 使用 Semgrep 专业扫描（推荐）
        try:
            return self._scan_with_semgrep(code, lang, mode=mode)
        except Exception as e:
            print(f"⚠️ Semgrep 扫描失败，降级到正则匹配：{e}")
            # 降级到方案 B：正则匹配
            return self._scan_with_regex(code, lang)

    def _semgrep_enabled(self) -> bool:
        return os.environ.get("ENABLE_SEMGREP", "1").strip().lower() in {"1", "true", "yes", "on"}

    def _semgrep_command(self):
        return shutil.which("semgrep")
    
    def _scan_with_semgrep(self, code: str, lang: str, mode: str = "full") -> Dict:
        """使用 Semgrep 进行专业漏洞扫描"""
        import subprocess
        import json
        import os
        import sys

        if not self._semgrep_enabled():
            print("ℹ️ Semgrep 已禁用，直接使用正则扫描")
            return self._scan_with_regex(code, lang)

        semgrep_bin = self._semgrep_command()
        if not semgrep_bin:
            print("⚠️ 未找到 semgrep 可执行文件，降级到正则扫描")
            return self._scan_with_regex(code, lang)
        
        # 🔥 修复 Windows 编码问题
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        if sys.platform == "win32":
            env["PYTHONUTF8"] = "1"
        
        lang_map = {
            "python": "python", "java": "java", "cpp": "cpp",
            "c": "c", "javascript": "javascript", "go": "go"
        }
        
        if lang not in lang_map:
            print(f"⚠️ 不支持的语言: {lang}，使用正则匹配")
            return self._scan_with_regex(code, lang)
        
        ext_map = {
            "python": ".py", "java": ".java", "cpp": ".cpp",
            "c": ".c", "javascript": ".js", "go": ".go"
        }
        # 唯一临时文件名，避免多文件并行迁移时 Semgrep 互相覆盖
        tid = uuid.uuid4().hex[:16]
        tmp_file = f"tmp_semgrep_scan_{tid}{ext_map[lang]}"
        custom_rules_file = f"tmp_custom_rules_{lang}_{tid}.yml"
        custom_rules = self._generate_custom_semgrep_rules(lang)
        
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(code)
            
            # 写入自定义规则
            if custom_rules:
                with open(custom_rules_file, "w", encoding="utf-8") as f:
                    f.write(custom_rules)
            
            print(f"🔍 Semgrep 扫描中... (语言：{lang}, 文件：{tmp_file})")
            print(f"📋 代码长度: {len(code)} 字符, {code.count(chr(10))} 行")
            if custom_rules:
                print(f"📋 使用自定义规则：{custom_rules_file}")
            
            semgrep_timeout = "20" if mode == "fast" else os.environ.get("SEMGREP_RULE_TIMEOUT", "40")
            try:
                process_timeout = 45 if mode == "fast" else int(os.environ.get("SEMGREP_PROCESS_TIMEOUT", "90"))
            except ValueError:
                process_timeout = 45 if mode == "fast" else 90

            # 只使用本地自定义规则，避免 auto 规则集带来的高耗时和网络开销
            cmd = [
                semgrep_bin,
                "--config", custom_rules_file,
            ]
            
            cmd.extend([
                "--json",
                "--metrics", "off",
                "--timeout", semgrep_timeout,
                "--jobs", "1",
                "--disable-version-check",
                tmp_file
            ])
            
            print(f"📋 执行命令：{' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=process_timeout,
                shell=False,  # 🔥 修复：不使用shell，避免Windows路径问题
                env=env
            )
            
            print(f"📊 Semgrep 返回码：{result.returncode}")
            
            if result.stderr:
                print(f"⚠️ Semgrep 错误输出：{result.stderr[:1000]}")
            if result.stdout:
                print(f"✅ Semgrep 标准输出：{len(result.stdout)} 字符")
                print(f"📄 Semgrep 输出预览：{result.stdout[:500]}")
            else:
                print("❌ Semgrep 无标准输出")
           
            if result.returncode in [0, 7] and result.stdout:
                try:
                    semgrep_data = json.loads(result.stdout)
                    
                    if "errors" in semgrep_data and semgrep_data["errors"]:
                        print(f"⚠️ Semgrep 配置错误：{semgrep_data['errors'][0].get('message', 'Unknown')}")
                        print("⚠️ 降级到正则匹配...")
                        return self._scan_with_regex(code, lang)
                    
                    vulns = []
                    results = semgrep_data.get("results", [])
                    print(f"📊 Semgrep 原始结果数：{len(results)} 条")
                    
                    # 🔥 详细打印每个检测结果
                    for idx, finding in enumerate(results):
                        print(f"   [{idx+1}] Check ID: {finding.get('check_id', 'N/A')}")
                        print(f"       Severity: {finding.get('severity', 'N/A')}")
                        print(f"       Line: {finding.get('start', {}).get('line', 'N/A')}")
                        extra = finding.get("extra", {})
                        print(f"       Message: {extra.get('message', 'N/A')[:100]}")
                    
                    for finding in results:
                        severity = finding.get("severity", "WARNING").upper()
                        
                        # 🔥 放宽过滤条件，包括 WARNING
                        if severity not in ["INFO"]:
                            extra = finding.get("extra", {})
                            message = extra.get("message", "Unknown issue detected")
                            
                            vulns.append({
                                "msg": f"{finding['check_id']}: {message}",
                                "severity": severity,
                                "line": finding.get("start", {}).get("line", 0),
                                "rule": finding["check_id"],
                                "type": "semgrep"
                            })
                    
                    if vulns:
                        print(f"✅ Semgrep 检测到 {len(vulns)} 个漏洞")
                        for v in vulns[:10]:  # 🔥 显示前 10 个
                            print(f"   - [{v['severity']}] Line {v['line']}: {v['msg'][:100]}")
                        return {"vulns": vulns, "tool": "semgrep"}
                    else:
                        print("⚠️ Semgrep 未检测到漏洞，尝试正则匹配补充...")
                        # 🔥 关键改进：Semgrep 没检测到，用正则补充
                        regex_result = self._scan_with_regex(code, lang)
                        if regex_result["vulns"]:
                            print(f"✅ 正则匹配补充检测到 {len(regex_result['vulns'])} 个漏洞")
                            return regex_result
                        return {"vulns": [], "tool": "semgrep"}
                
                except json.JSONDecodeError as e:
                    print(f"⚠️ JSON 解析失败：{e}")
                    print(f"   原始输出：{result.stdout[:500]}")
            
            # 降级到正则匹配
            print("⚠️ 降级到正则匹配...")
            return self._scan_with_regex(code, lang)
        
        except subprocess.TimeoutExpired:
            print("⚠️ Semgrep 扫描超时，降级到正则匹配")
            return self._scan_with_regex(code, lang)
        except Exception as e:
            print(f"⚠️ Semgrep 扫描异常：{e}")
            import traceback
            traceback.print_exc()
            return self._scan_with_regex(code, lang)
        finally:
            # 清理临时文件
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
            if os.path.exists(custom_rules_file):
                os.remove(custom_rules_file)

    def _generate_custom_semgrep_rules(self, lang: str) -> str:
        """生成自定义 Semgrep 规则(YAML 格式)"""
        
        if lang == "python":
            return '''rules:
  # 🔥 规则1: 硬编码密码/密钥检测（更宽松的模式）
  - id: hardcoded-password-python
    patterns:
      - pattern-either:
          - pattern: $VAR = "..."
          - pattern: $VAR = '...'
      - metavariable-regex:
          metavariable: $VAR
          regex: '(?i).*(password|passwd|pwd|secret|api_key|apikey|token|db_password|database_password).*'
    message: "硬编码密码/密钥 detected - 建议使用环境变量或配置中心"
    severity: ERROR
    languages: [python]

  # 🔥 规则2: SQL注入检测（支持f-string和拼接）
  - id: sql-injection-python
    pattern-either:
      - pattern: f"SELECT ... {$VAR} ..."
      - pattern: f"INSERT ... {$VAR} ..."
      - pattern: f"UPDATE ... {$VAR} ..."
      - pattern: f"DELETE ... {$VAR} ..."
      - pattern: f"... SELECT ... {$VAR} ..."
      - pattern: f"... INSERT ... {$VAR} ..."
      - pattern: '"SELECT ... " + $VAR'
      - pattern: '"INSERT ... " + $VAR'
      - pattern: '"UPDATE ... " + $VAR'
      - pattern: '"DELETE ... " + $VAR'
      - patterns:
          - pattern-inside: |
              $QUERY = f"..."
              ...
          - pattern: $QUERY
          - metavariable-regex:
              metavariable: $QUERY
              regex: '(?i)(SELECT|INSERT|UPDATE|DELETE).*\{.*\}'
    message: "SQL 注入风险 detected - 建议使用参数化查询"
    severity: ERROR
    languages: [python]

  # 🔥 规则3: 危险函数 eval/exec
  - id: dangerous-eval-exec-python
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
    message: "高危函数 eval/exec detected - 可能导致代码注入"
    severity: ERROR
    languages: [python]

  # 🔥 规则4: 系统命令执行
  - id: dangerous-system-call-python
    pattern-either:
      - pattern: os.system(...)
      - pattern: subprocess.call(..., shell=True)
      - pattern: subprocess.run(..., shell=True)
      - pattern: subprocess.Popen(..., shell=True)
      - pattern: os.popen(...)
    message: "系统命令执行风险 detected - 注意命令注入"
    severity: WARNING
    languages: [python]

  # 🔥 规则5: 信息泄露（打印敏感信息）
  - id: info-leak-python
    patterns:
      - pattern-either:
          - pattern: print(..., $VAR, ...)
          - pattern: print($VAR)
      - metavariable-regex:
          metavariable: $VAR
          regex: '(?i).*(password|passwd|secret|token|api_key).*'
    message: "敏感信息泄露风险 - 避免打印密码/密钥"
    severity: WARNING
    languages: [python]
'''
        elif lang == "java":
            return '''rules:
  - id: hardcoded-password-java
    patterns:
      - pattern: String $VAR = "...";
      - metavariable-regex:
          metavariable: $VAR
          regex: '(?i).*(password|passwd|secret|apiKey|token|db_password).*'
    message: "硬编码密码/密钥 detected"
    severity: ERROR
    languages: [java]

  - id: sql-injection-java
    pattern-either:
      - pattern: '"SELECT ... " + $VAR'
      - pattern: Statement.executeQuery("SELECT ... " + $VAR)
    message: "SQL 注入风险 detected"
    severity: ERROR
    languages: [java]

  - id: dangerous-runtime-exec-java
    pattern-either:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: new ProcessBuilder(...).start()
    message: "系统命令执行风险 detected"
    severity: WARNING
    languages: [java]
'''
        else:
            # 其他语言返回空规则
            return "rules: []"
    
    def _scan_with_regex(self, code: str, lang: str) -> Dict:
        """使用正则表达式进行基础扫描（降级方案）"""
        vulns = []
        low = code.lower()

        # 硬编码凭证检测
        if re.search(r'password\s*=\s*["\'].+["\']', code, re.I):
            vulns.append({"msg": "硬编码密码", "severity": "HIGH", "type": "regex"})
        if re.search(r'api[_]?key\s*=\s*["\'].+["\']', code, re.I):
            vulns.append({"msg": "硬编码密钥", "severity": "HIGH", "type": "regex"})
        if re.search(r'secret\s*=\s*["\'].+["\']', code, re.I):
            vulns.append({"msg": "硬编码密钥", "severity": "HIGH", "type": "regex"})
        
        # 危险函数检测
        if "eval(" in code or "exec(" in code:
            vulns.append({"msg": "高危代码执行", "severity": "HIGH", "type": "regex"})
        if "system(" in code:
            vulns.append({"msg": "系统命令风险", "severity": "MEDIUM", "type": "regex"})
        
        # SQL 注入检测
        if re.search(r'select.*from.*where.*=', code, re.I) and "?" not in code:
            vulns.append({"msg": "SQL 注入", "severity": "HIGH", "type": "regex"})
        
        return {"vulns": vulns, "tool": "regex"}

    def quick_scan(self, code: str, lang: str) -> Dict:
        """快速扫描：用于迭代修复阶段，避免重复触发完整 Semgrep。"""
        return self._scan_with_regex(code, lang)

# ==============================================================================
# 🔥 3. VPI 漏洞传播指数（全语言通用）
# ==============================================================================
class VpiSkill(BaseSkill):
    skill_id = "vpi"
    def run(self,** kwargs):
        before = kwargs.get("before", [])
        after = kwargs.get("after", [])
        b = {v["msg"] for v in before}
        a = {v["msg"] for v in after}
        retained = len(b & a)
        introduced = len(a - b)
        total = max(len(before) + introduced, 1)
        return {"vpi": round((retained + introduced) / total, 3)}

# ==============================================================================
# 🔥 4. 多语言安全规则自动沉淀
# ==============================================================================
class RuleEvolveSkill(BaseSkill):
    skill_id = "rule_evolve"
    def run(self,** kwargs):
        vulns, lang = kwargs["vulns"], kwargs["lang"]
        rules = set()
        for v in vulns:
            m = v["msg"].lower()
            # 🔥 更精准的规则提取
            if "password" in m or "key" in m or "secret" in m or "token" in m or "credential" in m or "硬编码" in m: 
                rules.add("禁止硬编码密钥/密码/令牌，必须使用环境变量（如 os.environ.get('VAR_NAME')）或配置中心管理")
            if "eval" in m or "exec" in m or "dangerous" in m or "危险" in m: 
                rules.add("禁止使用 eval/exec 等高危执行函数，改用 ast.literal_eval 或删除该功能")
            if "sql" in m or "inject" in m or "注入" in m or "拼接" in m: 
                rules.add("禁止SQL字符串拼接，必须使用参数化查询（? 占位符或 %s 占位符）防止SQL注入")
            if "system" in m or "command" in m or "命令" in m or "process" in m or "subprocess" in m: 
                rules.add("禁止直接调用系统命令，如必须使用则用 subprocess.run([...], check=True, timeout=10) 并严格验证输入")
            if "xss" in m or "cross-site" in m or "脚本" in m:
                rules.add("防止XSS跨站脚本攻击，对用户输入进行HTML转义或使用模板引擎的自动转义功能")
            if "path" in m or "遍历" in m or "directory" in m or "目录" in m:
                rules.add("防止路径遍历攻击，使用 os.path.basename() 清理文件名，验证路径合法性")
            if "file" in m and ("upload" in m or "上传" in m):
                rules.add("文件上传需验证文件类型、大小和扩展名，存储时使用随机文件名")
        
        if lang not in SAFE_RULES: SAFE_RULES[lang] = []
        for r in rules:
            if r not in SAFE_RULES[lang]: SAFE_RULES[lang].append(r)
        with open(SAFE_RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(SAFE_RULES, f, indent=2, ensure_ascii=False)
        return {"added": len(rules)}

# ==============================================================================
# 🔥 5. 多语言智能迁移引擎（核心：工程结构 + 依赖修复）
# ==============================================================================
class UniversalTranslateSkill(BaseSkill):
    skill_id = "trans"

    def run(self,** kwargs):
        code = kwargs["code"]
        src = kwargs["src"]
        tgt = kwargs["tgt"]
        path = kwargs["file_path"]
        rules = kwargs["rules"]
        project_struct = kwargs["project_struct"]

        prompt = f"""你是顶级多语言工程级迁移引擎和安全专家。
源语言：{src}
目标语言：{tgt}

【🔥 安全规则 - 必须严格遵守】
{rules}

【核心任务】
1. 将代码从 {src} 迁移到 {tgt}
2. **在迁移过程中自动修复所有安全漏洞**
3. 保持业务逻辑完全一致
4. 生成符合 {tgt} 最佳实践的代码

【严格要求 - 违反将导致失败】
1. ✅ 只输出纯净的目标语言代码，不要任何解释、注释、说明文字
2. ✅ 不要包含"以下是代码"、"```{tgt}"等多余标记
3. ✅ 直接以 {LANG_CONFIG.get(tgt, {}).get("comment", "//")} 开头的文件注释开始
4. ✅ 严格保持原业务逻辑不变
5. ✅ 自动修复跨文件依赖、模块调用、导入关系
6. ✅ 生成符合 {tgt} 官方标准的工程结构
7. ✅ 自动修复包名/命名空间/模块名
8. ✅ **必须修复所有检测到的安全漏洞**（见下方安全规则）
9. ✅ 输出可直接编译运行的纯净代码

【🛡️ 安全漏洞修复指南】
针对以下常见漏洞类型，必须在迁移时主动修复：

❌ **硬编码密钥/密码** 
   → ✅ 使用环境变量：os.environ.get('VAR_NAME') 或配置中心
   
❌ **SQL 注入风险**
   → ✅ 使用参数化查询：cursor.execute("SELECT * FROM t WHERE id=?", (id,))
   
❌ **eval/exec 危险函数**
   → ✅ 删除或使用安全替代：ast.literal_eval()
   
❌ **系统命令执行**
   → ✅ 删除或使用 subprocess.run([...], check=True, timeout=10)
   
❌ **XSS 跨站脚本**
   → ✅ 对用户输入进行 HTML 转义
   
❌ **路径遍历攻击**
   → ✅ 使用 os.path.basename() 清理文件名，验证路径合法性

【代码质量要求】
- 遵循 {tgt} 语言的官方编码规范
- 添加必要的错误处理（try-except）
- 使用合适的日志记录
- 确保代码可读性和可维护性

源文件路径：{path}
项目依赖关系：{project_struct}

【原始代码】
```{src}
{code}
```

【纯净且安全的{tgt}代码】(直接从第一行开始写代码，不要任何前缀):"""
        return self._llm(prompt)

    def _llm(self, prompt):
        try:
            # 根据配置选择 API 服务商
            session = _thread_http_session()
            if CURRENT_PROVIDER == "dashscope":
                r = session.post(
                    f"{DASHSCOPE_BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": QWEN_MODEL_NAME,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0,
                        "max_tokens": 4000
                    },
                    timeout=180
                )
            else:
                r = session.post(
                    f"{DEEPSEEK_BASE_URL}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
                    json={
                        "model": "deepseek-coder",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0,
                        "max_tokens": 4000
                    },
                    timeout=180
                )
            
            # 检查响应状态
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"].strip()
            
            # 🔥 关键修复：清理多余的说明文字
            # 如果包含"```"等标记，提取其中的代码
            if "```" in content:
                import re
                # 提取第一个代码块
                match = re.search(r'```(?:\w+)?\s*(.*?)```', content, re.DOTALL)
                if match:
                    content = match.group(1).strip()
            
            # 如果包含中文解释，尝试提取代码部分
            lines = content.split('\n')
            code_lines = []
            in_code = False
            
            for line in lines:
                # 检测是否开始代码 (遇到 package/import/class 等关键字)
                if not in_code:
                    if (line.strip().startswith('package ') or 
                        line.strip().startswith('import ') or 
                        line.strip().startswith('public class') or
                        line.strip().startswith('class ') or
                        line.strip().startswith('//')):
                        in_code = True
                        code_lines.append(line)
                else:
                    code_lines.append(line)
            
            # 如果成功提取代码，使用提取结果
            if code_lines and in_code:
                content = '\n'.join(code_lines).strip()
            
            return content
        except requests.exceptions.Timeout:
            error_msg = f"LLM API 请求超时（超过 180 秒）"
            print(f"[ERROR] {error_msg}")
            raise Exception(error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"LLM API 网络连接失败: {str(e)}"
            print(f"[ERROR] {error_msg}")
            print(f"[ERROR] 请检查:")
            print(f"  1. 网络连接是否正常")
            print(f"  2. API Key 是否正确: {CURRENT_PROVIDER}")
            print(f"  3. API 服务是否可用")
            raise Exception(error_msg)
        except requests.exceptions.HTTPError as e:
            error_msg = f"LLM API HTTP 错误: {e.response.status_code} - {e.response.text[:200]}"
            print(f"[ERROR] {error_msg}")
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"LLM 迁移失败: {str(e)}"
            print(f"[ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            raise Exception(error_msg)

# ==================== 注册全部技能 ====================
def init_skills(src_lang):
    SkillRegistry.register(ProjectDependencySkill(src_lang))
    SkillRegistry.register(UniversalSastSkill())
    SkillRegistry.register(VpiSkill())
    SkillRegistry.register(RuleEvolveSkill())
    SkillRegistry.register(UniversalTranslateSkill())

# ==============================================================================
# 🔥 Actor-Critic 智能迁移核心
# ==============================================================================
class Actor:
    def translate(self, code, src, tgt, path, rules, proj):
        return SkillRegistry.get("trans").run(code=code, src=src, tgt=tgt, file_path=path, rules=rules, project_struct=proj)

class Critic:
    def __init__(self): self.threshold = 0.2
    def scan(self, code, lang): return SkillRegistry.get("sast_scan").run(code=code, lang=lang)["vulns"]
    def vpi(self, before, after): return SkillRegistry.get("vpi").run(before=before, after=after)["vpi"]

# ==============================================================================
# 🔥 多语言通用工程输出
# ==============================================================================
def write_output_file(src_path, src, tgt, content, out_root, project_root=None):
    """保存迁移后的文件到输出目录,保持原始目录结构
    
    Args:
        src_path: 源文件绝对路径 (如: uploads/xxx/test_project\main.py)
        src: 源语言
        tgt: 目标语言
        content: 迁移后的代码内容
        out_root: 输出根目录 (如: migrated_projects/xxx)
        project_root: 项目根目录 (可选,如: uploads/xxx/test_project)
                     如果提供,则直接使用;否则自动推断
    """
    # 如果未提供 project_root,则自动推断
    if project_root is None:
        # 计算相对于项目根目录的相对路径
        # src_path 示例: uploads/xxx/test_project\main.py
        # 我们需要提取: test_project\main.py
        project_root = os.path.dirname(src_path)
        while os.path.dirname(project_root) != project_root:  # 不是根目录
            parent = os.path.dirname(project_root)
            # 查找 uploads 或 test_project 等关键目录
            if os.path.basename(parent) in ['uploads', 'test_project']:
                break
            project_root = parent
    
    rel = os.path.relpath(src_path, project_root)
    base = os.path.splitext(rel)[0]
    ext = {
        "python": ".py", "java": ".java", "cpp": ".cpp", "c": ".c",
        "javascript": ".js", "go": ".go"
    }.get(tgt, ".txt")
    
    # 构建输出路径: out_root/test_project/main.java
    out_path = os.path.join(out_root, base + ext)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    print(f"[DEBUG] 保存文件: {out_path}")
    print(f"[DEBUG] 项目根目录: {project_root}")
    print(f"[DEBUG] 相对路径: {rel}")
    print(f"[DEBUG] 内容长度: {len(content)} 字符")
    
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"[DEBUG] ✅ 文件保存成功")
    return out_path

# ==============================================================================
# 🔥 创新点 4.1 增强版：语义图谱构建器
# ==============================================================================
class SemanticGraphBuilder:
    """构建全项目的语义图谱，包括目录拓扑、依赖树、调用链"""
    
    def __init__(self, lang: str):
        self.lang = lang
        self.graph = {
            "nodes": {},      # 文件节点
            "edges": [],      # 依赖边
            "call_graph": {}, # 函数调用图
            "topology": {}    # 目录拓扑
        }
    
    def build_from_project(self, project_data: Dict) -> Dict:
        """从项目数据构建语义图谱"""
        
        # 1. 构建目录拓扑
        for file_path in project_data["files"]:
            dir_structure = self._parse_directory(file_path)
            self.graph["topology"][file_path] = dir_structure
            
            # 2. 创建文件节点
            file_code = project_data.get("file_codes", {}).get(file_path, "")
            self.graph["nodes"][file_path] = {
                "path": file_path,
                "imports": project_data["deps"].get(file_path, []),
                "exports": self._extract_exports(file_code),
                "role": self._infer_role(file_path)
            }
        
        # 3. 构建依赖边
        self._build_dependency_edges()
        
        # 4. 构建调用图
        self._build_call_graph(project_data)
        
        return self.graph
    
    def _parse_directory(self, file_path: str) -> Dict:
        """解析目录结构"""
        parts = file_path.replace("\\", "/").split("/")
        return {
            "depth": len(parts) - 1,
            "parent": "/".join(parts[:-1]),
            "filename": parts[-1],
            "is_module": parts[-1].startswith("__init__") or "main" in parts[-1].lower()
        }
    
    def _extract_exports(self, code: str) -> List[str]:
        """提取导出的函数/类"""
        exports = []
        patterns = {
            "python": [
                r'def\s+(\w+)\s*\(',           # 函数定义
                r'class\s+(\w+)',              # 类定义
                r'async\s+def\s+(\w+)\s*\('    # 异步函数
            ],
            "java": [
                r'public\s+(?:static\s+)?(?:void|int|String|\w+)\s+(\w+)\s*\(',  # 方法
                r'public\s+class\s+(\w+)',     # 类定义
                r'private\s+(?:static\s+)?(?:void|int|String|\w+)\s+(\w+)\s*\('   # 私有方法
            ],
            "cpp": [
                r'(?:void|int|char|double|\w+)\s+(\w+)\s*\([^)]*\)\s*\{',  # 函数
                r'class\s+(\w+)',              # 类定义
            ]
        }
        
        if self.lang in patterns:
            for pattern in patterns[self.lang]:
                matches = re.findall(pattern, code)
                exports.extend(matches)
        
        return list(set(exports))  # 去重
    
    def _infer_role(self, file_path: str) -> str:
        """推断文件在项目中的角色"""
        filename = file_path.lower()
        path_parts = filename.replace("\\", "/").split("/")
        
        # 优先级 1: 检查是否在测试目录
        if "test" in path_parts or "tests" in path_parts:
            return "测试模块"
        
        # 优先级 2: 检查文件名特征
        if "test" in filename:
            return "测试模块"
        elif "config" in filename or "settings" in filename:
            return "配置文件"
        elif "main" in filename or "app" in filename or filename.endswith("main.py"):
            return "入口模块"
        elif "main" in path_parts[-1]:  # 文件名包含 main
            return "入口模块"
        elif "util" in filename or "helper" in filename:
            return "工具模块"
        elif "model" in filename or "entity" in filename:
            return "数据模型"
        elif "api" in path_parts or "controller" in path_parts or "view" in path_parts:
            return "业务模块"
        elif "db" in path_parts or "database" in path_parts or "repo" in path_parts:
            return "数据模块"
        elif "__init__" in filename:
            return "包初始化文件"
        else:
            return "业务模块"  # 默认为业务模块
    
    def _build_dependency_edges(self):
        """构建依赖关系边"""
        for file_path, node in self.graph["nodes"].items():
            for imp in node["imports"]:
                # 查找被依赖的文件
                for target_path, target_node in self.graph["nodes"].items():
                    # 匹配 1: 完整模块名匹配
                    if imp in target_path:
                        self.graph["edges"].append({
                            "from": file_path,
                            "to": target_path,
                            "type": "import",
                            "symbol": imp
                        })
                        break
                    
                    # 匹配 2: 检查是否在 exports 中
                    if any(imp in t for t in target_node["exports"]):
                        self.graph["edges"].append({
                            "from": file_path,
                            "to": target_path,
                            "type": "import",
                            "symbol": imp
                        })
                        break
                    
                    # 匹配 3: 简化的模块名匹配 (处理 from api.user_api import UserService)
                    imp_parts = imp.split(".")
                    if len(imp_parts) > 1:
                        # 尝试匹配 api.user_api -> api/user_api.py
                        potential_module = "/".join(imp_parts) + ".py"
                        if potential_module in target_path:
                            self.graph["edges"].append({
                                "from": file_path,
                                "to": target_path,
                                "type": "import",
                                "symbol": imp
                            })
                            break
    
    def _build_call_graph(self, project_data: Dict):
        """构建函数调用图"""
        # 简化版：提取代码中的函数调用
        for file_path in project_data["files"]:
            code = project_data.get("file_codes", {}).get(file_path, "")
            calls = re.findall(r'(\w+)\s*\(', code)
            self.graph["call_graph"][file_path] = list(set(calls))


# ==============================================================================
# 🔥 创新点 4.2 增强版：带迭代修复的 Actor-Critic
# ==============================================================================
class EnhancedActor:
    """增强版 Actor：支持多轮迭代修复"""
    
    def __init__(self, max_iterations: int = 5):  # 🔥 从3增加到5，给更多修复机会
        self.max_iterations = max_iterations
        self.translation_skill = SkillRegistry.get("trans")
    
    def translate(self, code, src, tgt, path, rules, proj, critic_ref=None):
        """带迭代修复的翻译"""
        current_code = code
        iteration_log = []
        
        for i in range(self.max_iterations):
            # 第 1 轮：直接翻译；后续轮：基于反馈修复
            if i == 0:
                new_code = self.translation_skill.run(
                    code=current_code, src=src, tgt=tgt, 
                    file_path=path, rules=rules, project_struct=proj
                )
            else:
                # 基于上一轮的漏洞进行针对性修复
                feedback = iteration_log[-1]["feedback"]
                new_code = self._fix_with_feedback(current_code, src, tgt, rules, feedback)
            
            # 如果提供了 Critic，进行质量检查
            if critic_ref:
                after_vulns = critic_ref.quick_scan(new_code, tgt)
                vpi = critic_ref.vpi(
                    [{"msg": "initial"}],  # 占位符
                    after_vulns
                )
                
                iteration_log.append({
                    "iteration": i + 1,
                    "vuln_count": len(after_vulns),
                    "vpi": vpi,
                    "feedback": after_vulns
                })
                
                print(f"  📊 第 {i+1} 轮扫描结果: {len(after_vulns)} 个漏洞, VPI={vpi}")
                if after_vulns:
                    for v in after_vulns[:3]:  # 只显示前3个
                        print(f"     - [{v['severity']}] {v['msg']}")
                
                # 🔥 优化的终止条件：更严格的质量要求
                high_severity_vulns = [v for v in after_vulns if v.get('severity') == 'HIGH']
                medium_severity_vulns = [v for v in after_vulns if v.get('severity') == 'MEDIUM']
                
                # 条件1: 无任何漏洞 - 完美
                if len(after_vulns) == 0:
                    print(f"  ✅ 第 {i+1} 轮迭代后无漏洞，完美！")
                    break
                
                # 条件2: 无高危漏洞且VPI很低 - 可接受
                if len(high_severity_vulns) == 0 and isinstance(vpi, float) and vpi < 0.2:
                    print(f"  ✅ 第 {i+1} 轮迭代后无高危漏洞且VPI={vpi}，质量达标")
                    break
                
                # 条件3: 只有少量低危漏洞且VPI较低 - 可接受
                if len(high_severity_vulns) == 0 and len(medium_severity_vulns) <= 1 and isinstance(vpi, float) and vpi < 0.4:
                    print(f"  ✅ 第 {i+1} 轮迭代后仅有{len(after_vulns)}个低危漏洞，VPI={vpi}，可接受")
                    break
                
                # 继续下一轮修复
                current_code = new_code
            else:
                break
        
        return new_code, iteration_log
    
    def _fix_with_feedback(self, code, src, tgt, rules, feedback):
        """基于反馈的修复"""
        # 🔥 按严重程度排序，优先处理高危漏洞
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_feedback = sorted(feedback, key=lambda x: severity_order.get(x['severity'], 3))
        
        feedback_str = "\n".join([f"- [{v['severity']}] {v['msg']}" for v in sorted_feedback])
        
        # 🔥 提取具体的漏洞类型和修复建议
        vuln_types = []
        for v in sorted_feedback:
            msg_lower = v['msg'].lower()
            if '硬编码' in msg_lower or 'password' in msg_lower or 'key' in msg_lower or 'secret' in msg_lower:
                vuln_types.append("❌ 硬编码密钥/密码 → ✅ 使用环境变量 os.environ.get('VAR_NAME') 或配置文件")
            if 'eval' in msg_lower or 'exec' in msg_lower:
                vuln_types.append("❌ eval/exec 危险函数 → ✅ 删除或使用安全的替代方案（如 ast.literal_eval）")
            if 'sql' in msg_lower or '注入' in msg_lower:
                vuln_types.append("❌ SQL 拼接注入 → ✅ 使用参数化查询（? 占位符或 %s 占位符）")
            if 'system' in msg_lower or '命令' in msg_lower:
                vuln_types.append("❌ 系统命令执行 → ✅ 删除或使用 subprocess.run() 并严格验证输入")
            if 'xss' in msg_lower:
                vuln_types.append("❌ XSS 跨站脚本 → ✅ 对用户输入进行 HTML 转义")
            if '路径' in msg_lower or 'path' in msg_lower:
                vuln_types.append("❌ 路径遍历 → ✅ 使用 os.path.basename() 限制文件名，验证路径合法性")
        
        fix_examples = ""
        if vuln_types:
            fix_examples = "\n【针对性修复指南】\n" + "\n".join(vuln_types)
        
        fix_prompt = f"""你是资深安全代码修复专家。你的任务是修复代码中的所有安全漏洞，确保代码既安全又可运行。

【待修复的{tgt}代码】
``{tgt}
{code}
```

【检测到的安全漏洞】（按严重程度排序）
{feedback_str}
{fix_examples}

【安全规则】
{rules}

【🔥 修复核心要求 - 必须严格遵守】
1. ✅ **必须修复所有列出的漏洞** - 每个漏洞都要针对性处理，不能遗漏
2. ✅ **保持原有功能完整** - 修复后代码的业务逻辑必须与原代码一致
3. ✅ **输出纯净可运行代码** - 不要任何解释、注释、说明文字
4. ✅ **不要包含多余标记** - 不输出"修复后的代码"、"```{tgt}"等前缀
5. ✅ **使用最佳实践** - 采用该语言官方推荐的安全编程方式
6. ✅ **验证修复效果** - 确保修复后的代码不会引入新漏洞

【常见漏洞修复模式参考】
- 硬编码密钥 → 改为从环境变量读取：os.environ.get('DB_PASSWORD', '')
- SQL 注入 → 使用参数化查询：cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
- eval/exec → 删除或用 ast.literal_eval 替代
- 系统命令 → 删除或用 subprocess.run([...], check=True, timeout=10)
- 文件路径 → 用 os.path.basename() 清理用户输入

【输出格式要求】
直接输出修复后的完整代码，从第一行开始，不要任何其他内容。

【修复后的代码】:"""
        
        try:
            r = _thread_http_session().post(
                f"{DEEPSEEK_BASE_URL}/v1/chat/completions",
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
                json={
                    "model": "deepseek-coder",
                    "messages": [{"role": "user", "content": fix_prompt}],
                    "temperature": 0.3,  # 🔥 略微提高温度，让AI更有创造性地修复
                    "max_tokens": 4000,
                    "top_p": 0.9  # 🔥 添加 top_p 参数，提高生成质量
                },
                timeout=180
            )
            content = r.json()["choices"][0]["message"]["content"].strip()
            
            # 🔥 同样清理多余内容
            if "```" in content:
                import re
                match = re.search(r'```(?:\w+)?\s*(.*?)```', content, re.DOTALL)
                if match:
                    content = match.group(1).strip()
            
            return content
        except Exception as e:
            print(f"[ERROR] 漏洞修复失败: {str(e)}")
            return code


class EnhancedCritic:
    """增强版 Critic：支持多维度评估"""
    
    def __init__(self):
        self.sast_skill = SkillRegistry.get("sast_scan")
        self.vpi_skill = SkillRegistry.get("vpi")
    
    def scan(self, code, lang, mode: str = "full") -> List[Dict]:
        """漏洞扫描"""
        result = self.sast_skill.run(code=code, lang=lang, mode=mode)
        return result.get("vulns", [])

    def quick_scan(self, code, lang) -> List[Dict]:
        """迭代阶段的快速漏洞扫描。"""
        result = self.sast_skill.quick_scan(code, lang)
        return result.get("vulns", [])
    
    def vpi(self, before: List[Dict], after: List[Dict]) -> Dict:
        """
        增强版 VPI：多维度评估
        返回：{"vpi": float, "retained": int, "removed": int, "introduced": int, "score": float}
        """
        before_msgs = {v["msg"] for v in before}
        after_msgs = {v["msg"] for v in after}
        
        retained = len(before_msgs & after_msgs)      # 存留
        removed = len(before_msgs - after_msgs)       # 消除
        introduced = len(after_msgs - before_msgs)    # 新增
        
        # 原始 VPI
        total = max(len(before) + introduced, 1)
        vpi = round((retained + introduced) / total, 3)
        
        # 综合评分 (0-100)
        if len(before) == 0:
            # 原始代码无漏洞
            score = 100 if len(after) == 0 else max(0, 100 - len(after) * 20)
        else:
            removal_rate = removed / len(before)  # 消除率
            introduction_penalty = min(introduced * 0.2, 1.0)  # 引入惩罚
            score = round((removal_rate * 0.7 + (1 - vpi) * 0.3 - introduction_penalty) * 100, 1)
        
        return {
            "vpi": vpi,
            "retained": retained,
            "removed": removed,
            "introduced": introduced,
            "score": score,
            "assessment": "优秀" if score >= 80 else "良好" if score >= 60 else "需改进"
        }


# ==============================================================================
# 🔥 创新点 4.4 增强版：RAG 知识库
# ==============================================================================
class RagKnowledgeBase:
    """基于 RAG 的安全知识库"""
    
    def __init__(self, db_file: str = "knowledge_base.json"):
        self.db_file = db_file
        self.knowledge = self._load()
    
    def _load(self) -> Dict:
        """加载知识库"""
        if os.path.exists(self.db_file):
            with open(self.db_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"rules": [], "cases": [], "patterns": {}}
    
    def _vectorize(self, text: str) -> str:
        """简化的向量化（用哈希代替真实向量）"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def add_case(self, vuln: Dict, fix_rule: str, context: str = ""):
        """添加失败案例到知识库"""
        case = {
            "id": self._vectorize(f"{vuln}{context}"),
            "vuln_pattern": vuln.get("msg", ""),
            "vuln_type": vuln.get("type", "unknown"),
            "fix_rule": fix_rule,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
        
        # 去重
        if not any(c["id"] == case["id"] for c in self.knowledge.get("cases", [])):
            if "cases" not in self.knowledge:
                self.knowledge["cases"] = []
            self.knowledge["cases"].append(case)
            self._save()
            print(f"  📚 已添加新案例到知识库：{vuln.get('msg', '')[:30]}...")
    
    def retrieve_similar_cases(self, query: str, top_k: int = 3) -> List[Dict]:
        """检索相似案例（简化版：关键词匹配）"""
        similar = []
        query_words = set(query.lower().split())
        
        for case in self.knowledge.get("cases", []):
            # 计算相似度
            case_text = f"{case['vuln_pattern']} {case['context']}".lower()
            overlap = len(query_words & set(case_text.split()))
            
            if overlap > 0:
                similar.append({
                    **case,
                    "similarity": overlap / len(query_words)
                })
        
        # 按相似度排序
        similar.sort(key=lambda x: x["similarity"], reverse=True)
        return similar[:top_k]
    
    def _save(self):
        """保存知识库"""
        with open(self.db_file, "w", encoding="utf-8") as f:
            json.dump(self.knowledge, f, indent=2, ensure_ascii=False)


class EnhancedRuleEvolveSkill(BaseSkill):
    skill_id = "rule_evolve_enhanced"
    
    def __init__(self, rag_db: RagKnowledgeBase = None):
        self.rag_db = rag_db or RagKnowledgeBase()
    
    def run(self, **kwargs):
        vulns = kwargs["vulns"]
        lang = kwargs["lang"]
        context = kwargs.get("context", "")
        
        added_rules = []
        
        for v in vulns:
            m = v["msg"].lower()
            
            # 生成修复规则
            rule = None
            if "password" in m or "key" in m:
                rule = "禁止硬编码密钥，使用环境变量/配置中心"
            elif "eval" in m or "exec" in m:
                rule = "禁止高危执行函数，使用安全替代方案"
            elif "sql" in m or "inject" in m:
                rule = "禁止 SQL 拼接，使用预编译语句/参数化查询"
            elif "system" in m:
                rule = "禁止系统命令调用，使用安全的 API 封装"
            
            if rule:
                added_rules.append(rule)
                
                # 添加到 RAG 知识库
                self.rag_db.add_case(v, rule, context)
        
        # 同时更新传统规则文件
        if lang not in SAFE_RULES:
            SAFE_RULES[lang] = []
        
        for r in added_rules:
            if r not in SAFE_RULES[lang]:
                SAFE_RULES[lang].append(r)
        
        with open(SAFE_RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(SAFE_RULES, f, indent=2, ensure_ascii=False)
        
        return {
            "added": len(added_rules),
            "total_rules": sum(len(v) for v in SAFE_RULES.values()),
            "rag_cases": len(self.rag_db.knowledge.get("cases", []))
        }


# ==============================================================================
# 🔥 增强版主程序：整合所有创新点
# ==============================================================================
def migrate_project(project_root, src_lang, tgt_lang):
    print(f"🚀 【增强版多语言项目级智能迁移系统】启动")
    print(f"📦 源语言：{src_lang} → 目标语言：{tgt_lang}")
    print(f"🎯 创新点：语义图谱 + Actor-Critic 迭代 + VPI 量化 + RAG 知识库\n")

    init_skills(src_lang)
    
    # 初始化增强组件
    graph_builder = SemanticGraphBuilder(src_lang)
    rag_db = RagKnowledgeBase()
    actor = EnhancedActor(max_iterations=3)
    critic = EnhancedCritic()
    rule_evolver = EnhancedRuleEvolveSkill(rag_db)
    
    # ========== 创新点 4.1: 语义图谱构建 ==========
    print("="*60)
    print("【阶段 1/5】构建全项目语义图谱...")
    deps_skill = SkillRegistry.get("project_deps")
    proj = deps_skill.run(project_root=project_root)
    
    # 读取所有文件内容
    proj["file_codes"] = {}
    for f in proj["files"]:
        with open(f, encoding="utf-8") as fp:
            proj["file_codes"][f] = fp.read()
    
    # 构建语义图谱
    semantic_graph = graph_builder.build_from_project(proj)
    
    print(f"✅ 扫描 {len(proj['files'])} 个文件")
    print(f"✅ 发现 {len(semantic_graph['edges'])} 个依赖关系")
    print(f"✅ 推断 {len(set(n['role'] for n in semantic_graph['nodes'].values()))} 种模块角色")
    
    # 显示拓扑示例
    print("\n📊 项目拓扑示例:")
    for i, (path, topo) in enumerate(list(semantic_graph['topology'].items())[:3]):
        role = semantic_graph['nodes'][path]['role']
        print(f"   {path} → {role} (深度:{topo['depth']})")
    
    # ========== 全局漏洞扫描 ==========
    print("\n" + "="*60)
    print("【阶段 2/5】全局漏洞扫描与规则沉淀...")
    
    all_vulns = []
    for f in proj["files"]:
        code = proj["file_codes"][f]
        vulns = critic.scan(code, src_lang)
        all_vulns.extend(vulns)
    
    # 使用 RAG 知识库增强规则
    evolve_result = rule_evolver.run(vulns=all_vulns, lang=src_lang, context="全局扫描")
    
    rules = SAFE_RULES.get("common", []) + SAFE_RULES.get(src_lang, [])
    print(f"✅ 发现 {len(all_vulns)} 个漏洞")
    print(f"✅ 安全规则总数：{len(rules)}")
    print(f"✅ RAG 知识库案例数：{evolve_result['rag_cases']}")
    
    # ========== 逐文件迁移 ==========
    out_dir = f"migrated_{tgt_lang}_project"
    print(f"\n{'='*60}")
    print(f"【阶段 3/5】执行 Actor-Critic 迭代迁移...\n")
    
    migration_results = []
    
    for idx, f in enumerate(proj["files"], 1):
        print(f"\n{'-'*60}")
        print(f"[{idx}/{len(proj['files'])}] 迁移：{f}")
        
        code = proj["file_codes"][f]
        before_vulns = critic.scan(code, src_lang)
        
        print(f"🔍 迁移前漏洞：{len(before_vulns)}")
        for v in before_vulns[:3]:  # 只显示前 3 个
            print(f"   [{v['severity']}] {v['msg']}")
        if len(before_vulns) > 3:
            print(f"   ... 还有 {len(before_vulns)-3} 个")
        
        # ========== 创新点 4.2: Actor-Critic 迭代 ==========
        new_code, iterations = actor.translate(
            code, src_lang, tgt_lang, f, rules, 
            semantic_graph, critic_ref=critic
        )
        
        # 最终评估
        after_vulns = critic.scan(new_code, tgt_lang)
        vpi_result = critic.vpi(before_vulns, after_vulns)
        
        print(f"\n📊 迁移效果评估:")
        print(f"   VPI 指数：{vpi_result['vpi']}")
        print(f"   存留：{vpi_result['retained']} | 消除：{vpi_result['removed']} | 新增：{vpi_result['introduced']}")
        print(f"   综合评分：{vpi_result['score']} ({vpi_result['assessment']})")
        
        if iterations:
            print(f"   迭代轮数：{len(iterations)}")
        
        # ========== 创新点 4.4: RAG 知识沉淀 ==========
        if after_vulns:
            print(f"\n📚 更新 RAG 知识库...")
            rule_evolver.run(vulns=after_vulns, lang=tgt_lang, context=f"迁移后文件：{f}")
        
        # 保存输出
        out_path = write_output_file(f, src_lang, tgt_lang, new_code, out_dir)
        print(f"✅ 输出：{out_path}")
        
        migration_results.append({
            "file": f,
            "before_count": len(before_vulns),
            "after_count": len(after_vulns),
            "vpi": vpi_result,
            "iterations": len(iterations)
        })
    
    # ========== 总结报告 ==========
    print(f"\n{'='*60}")
    print("【阶段 4/5】生成迁移总结报告...")
    
    total_before = sum(r["before_count"] for r in migration_results)
    total_after = sum(r["after_count"] for r in migration_results)
    avg_vpi = sum(r["vpi"]["vpi"] for r in migration_results) / max(len(migration_results), 1)
    avg_score = sum(r["vpi"]["score"] for r in migration_results) / max(len(migration_results), 1)
    
    print(f"\n📊 整体效果:")
    print(f"   总漏洞数：{total_before} → {total_after} (减少 {total_before-total_after})")
    print(f"   平均 VPI: {round(avg_vpi, 3)}")
    print(f"   平均评分：{round(avg_score, 1)}")
    
    # ========== 创新点 4.3: VPI 分析报告 ==========
    print(f"\n{'='*60}")
    print("【阶段 5/5】VPI 深度分析报告")
    
    excellent = [r for r in migration_results if r["vpi"]["score"] >= 80]
    needs_improve = [r for r in migration_results if r["vpi"]["score"] < 60]
    
    print(f"\n✅ 优秀文件：{len(excellent)}/{len(migration_results)}")
    if needs_improve:
        print(f"⚠️ 需改进文件：{len(needs_improve)}")
        for r in needs_improve[:3]:
            print(f"   - {r['file']} (评分:{r['vpi']['score']})")
    
    print(f"\n📚 RAG 知识库统计:")
    print(f"   总案例数：{len(rag_db.knowledge.get('cases', []))}")
    
    print(f"\n🎉 {'='*60}")
    print("【多语言项目级智能迁移全部完成】")
    print(f"✅ 输出工程路径：{out_dir}")
    print(f"✅ 语义图谱已构建：{len(semantic_graph['edges'])} 个依赖关系")
    print(f"✅ Actor-Critic 迭代：自动修复 {sum(r['iterations'] for r in migration_results)} 轮")
    print(f"✅ VPI 平均评分：{round(avg_score, 1)}")
    print(f"✅ RAG 知识库新增：{evolve_result['rag_cases']} 个案例")
    print(f"{'='*60}\n")


# ==============================================================================
# 终端交互入口
# ==============================================================================
def terminal():
    global SAFE_RULES
    if os.path.exists(SAFE_RULES_FILE):
        with open(SAFE_RULES_FILE, encoding="utf-8") as f:
            SAFE_RULES = json.load(f)

    print("==== 🔥 多语言通用项目级智能迁移系统 ====")
    path = input("项目路径：")
    src = input("源语言：")
    tgt = input("目标语言：")

    if src not in LANG_CONFIG or tgt not in LANG_CONFIG:
        print("❌ 支持的语言：python, java, cpp, c, javascript, go")
        return

    migrate_project(path, src, tgt)

if __name__ == "__main__":
    terminal()
