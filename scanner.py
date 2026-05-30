import os
import re
import ast

class PluginScanner:
    def __init__(self, config):
        self.config = config
        self.suspicious_envs = config.get("rules", {}).get("suspicious_env_vars", [])
        self.sensitive_paths = config.get("rules", {}).get("sensitive_paths", [])

    def scan_file(self, file_path):
        \"\"\"分析单个文件，返回发现的所有安全风险\"\"\"
        findings = []
        if not file_path.endswith('.py'):
            # 目前主要针对 Python 编写的插件进行深度 AST 审计
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return [{"level": "ERROR", "message": f"无法读取文件: {str(e)}", "line": 0}]

        # 1. 基础正则初步粗筛（用于网络请求特征、硬编码明文等）
        findings.extend(self._regex_analysis(content))

        # 2. 深度 AST 语法树结构分析
        findings.extend(self._ast_analysis(content, file_path))

        return findings

    def _regex_analysis(self, content):
        findings = []
        # 匹配潜在的敏感URL外发行为（排除官方和知名公共API）
        url_pattern = re.compile(r'https?://[^\s\'\"]+')
        urls = url_pattern.findall(content)
        for url in urls:
            if not any(domain in url for domain in ["api.anthropic.com", "github.com", "google.com"]):
                findings.append({
                    "level": "WARNING",
                    "message": f"发现非官方外部网络请求终结点: {url}，请核实数据外发合规性。",
                    "line": "未知"
                })
        return findings

    def _ast_analysis(self, content, file_path):
        findings = []
        try:
            root = ast.parse(content, filename=file_path)
        except SyntaxError as se:
            return [{"level": "ERROR", "message": f"语法解析错误 (可能混淆或非标准Python): {se.msg}", "line": se.lineno}]

        for node in ast.walk(root):
            # 检查函数调用
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # 检测任意代码/命令执行风险
                if func_name in ["eval", "exec", "system", "popen", "subprocess"]:
                    findings.append({
                        "level": "CRITICAL",
                        "message": f"高危函数调用 [{func_name}]：具有执行任意系统命令或动态脚本的能力。",
                        "line": node.lineno
                    })

            # 检查硬编码或敏感环境变量获取
            if isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
                    # 捕捉 os.environ['KEY']
                    if node.value.value.id == "os" and node.value.attr == "environ":
                        if isinstance(node.slice, ast.Constant) and node.slice.value in self.suspicious_envs:
                            findings.append({
                                "level": "HIGH",
                                "message": f"尝试读取核心敏感环境变量: {node.slice.value}，存在被非法上报的风险。",
                                "line": node.lineno
                            })

            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # 捕捉 os.getenv('KEY')
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "getenv":
                    if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in self.suspicious_envs:
                        findings.append({
                            "level": "HIGH",
                            "message": f"尝试读取核心敏感环境变量(getenv): {node.args[0].value}。",
                            "line": node.lineno
                        })

            # 检查敏感文件路径访问
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for path in self.sensitive_paths:
                    if path in node.value:
                        findings.append({
                            "level": "HIGH",
                            "message": f"代码中包含敏感系统路径或配置文件指引: '{node.value}'。",
                            "line": node.lineno
                        })
        return findings