import os
import sys
import json
import time
from datetime import datetime
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import PluginScanner

# 终端颜色定义
COLOR_RESET = "\\033[0m"
COLOR_CRITICAL = "\\033[91m\\033[1m" # 粗红
COLOR_HIGH = "\\033[93m"             # 黄色
COLOR_WARNING = "\\033[96m"          # 青色
COLOR_SUCCESS = "\\033[92m"          # 绿色

CONFIG_PATH = os.path.expanduser("~/.claude-scanner/config.json")

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"[-] 找不到配置文件，将创建默认配置于: {CONFIG_PATH}")
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        default_config = {
            "plugin_directory": "~/.claude/plugins",
            "frequency": "weekly",
            "scan_on_start": True,
            "rules": {
                "suspicious_env_vars": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "PASSWORD", "SECRET"],
                "sensitive_paths": [".ssh", ".env", ".aws/credentials"]
            }
        }
        with open(CONFIG_PATH, 'w') as f:
            json.dump(default_config, f, indent=2)
        return default_config
    
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def print_report(plugin_name, findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not findings:
        print(f"[{timestamp}] {COLOR_SUCCESS}✅ [CLEAN] 插件 '{plugin_name}' 未检测到已知恶意模式。{COLOR_RESET}")
        return

    print(f"\\n[{timestamp}] 🚨 {COLOR_CRITICAL}[警告] 插件 '{plugin_name}' 风险审计报告如下:{COLOR_RESET}")
    print("-" * 70)
    for f in findings:
        level = f['level']
        color = COLOR_WARNING
        if level == "CRITICAL": color = COLOR_CRITICAL
        elif level == "HIGH": color = COLOR_HIGH
        
        print(f" {color}[{level}]{COLOR_RESET} 行 {f['line']}: {f['message']}")
    print("-" * 70 + "\\n")

def run_global_scan(config):
    print(f"[*] [{datetime.now().strftime('%H:%M:%S')}] 启动全量插件目录扫描...")
    plugin_dir = os.path.expanduser(config.get("plugin_directory", "~/.claude/plugins"))
    if not os.path.exists(plugin_dir):
        print(f"[-] 插件目录不存在: {plugin_dir}")
        return

    scanner = PluginScanner(config)
    for root, _, files in os.walk(plugin_dir):
        for file in files:
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, plugin_dir)
                findings = scanner.scan_file(full_path)
                if findings:
                    print_report(rel_path, findings)
    print("[*] 全量扫描结束。")

# --- 监听器模块 ---
class PluginChangeHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.scanner = PluginScanner(config)
        self.last_triggered = {}

    def on_ Harbinger(self, event, action_text):
        if event.is_directory or not event.src_path.endswith('.py'):
            return
        
        # 防抖处理：避免编辑器保存时连续触发多次事件
        now = time.time()
        if event.src_path in self.last_triggered and (now - self.last_triggered[event.src_path] < 1.0):
            return
        self.last_triggered[event.src_path] = now

        plugin_dir = os.path.expanduser(self.config.get("plugin_directory", "~/.claude/plugins"))
        rel_path = os.path.relpath(event.src_path, plugin_dir)
        
        print(f"\\n[🔄 状态变更] 检测到插件 {action_text}: {rel_path}，自动触发安全审查。")
        findings = self.scanner.scan_file(event.src_path)
        print_report(rel_path, findings)

    def on_created(self, event):
        self.on_ Harbinger(event, "新安装")

    def on_modified(self, event):
        self.on_ Harbinger(event, "更新更新")

def start_watcher(config):
    plugin_dir = os.path.expanduser(config.get("plugin_directory", "~/.claude/plugins"))
    os.makedirs(plugin_dir, exist_ok=True)
    
    event_handler = PluginChangeHandler(config)
    observer = Observer()
    observer.schedule(event_handler, path=plugin_dir, recursive=True)
    observer.start()
    print(f"[+] 实时监控服务已上线，正在监听目录: {plugin_dir}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# --- 定时调度模块 ---
def start_scheduler(config):
    freq = config.get("frequency", "weekly").lower()
    if freq == "never":
        print("[*] 计划任务配置为 [never]，将不会自动执行周期扫描。")
        return

    # 计算间隔秒数
    if freq == "daily":
        interval = 60 * 60 * 24
        print("[+] 自动全量扫描计划已配置：每 24 小时执行一次")
    elif freq == "weekly":
        interval = 60 * 60 * 24 * 7
        print("[+] 自动全量扫描计划已配置：每 7 天执行一次")
    else:
        print("[-] 未知频率配置，默认转为每周执行")
        interval = 60 * 60 * 24 * 7

    def schedule_loop():
        while True:
            time.sleep(interval)
            run_global_scan(config)

    sched_thread = threading.Thread(target=schedule_loop, daemon=True)
    sched_thread.start()

if __name__ == "__main__":
    print("=" * 60)
    print("   Claude Plugin Security Scanner (CPSS) 初始化中...")
    print("=" * 60)
    
    config_data = load_config()
    
    # 是否开启程序启动时立刻进行首次全量检查
    if config_data.get("scan_on_start", True):
        run_global_scan(config_data)

    # 启动后台定时器线程
    start_scheduler(config_data)

    # 启动文件系统监听（阻塞主线程）
    start_watcher(config_data)