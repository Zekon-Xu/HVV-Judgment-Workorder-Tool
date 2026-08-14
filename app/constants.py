# -*- coding: utf-8 -*-
"""常量定义
Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Designed By Zekon_Sec For 2026 HVV
# 研判工单自动生成工具 — 仅研判与处置意见，不执行处置动作
# ---------------------------------------------------------------------------
DESIGNER_CREDIT = "工单处理工具"
APP_DISPLAY_NAME = "工单快捷工具"


def _resolve_app_root() -> Path:
    """开发环境用源码目录；打包 exe 用 exe 所在目录（配置可持久化）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _resolve_bundle_root() -> Path:
    """PyInstaller 解压资源目录（只读）；开发环境等同 APP_ROOT。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


APP_ROOT = _resolve_app_root()
BUNDLE_ROOT = _resolve_bundle_root()
CONFIG_DIR = APP_ROOT / "settings"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
WHITELIST_PATH = CONFIG_DIR / "whitelist.json"
ORIGINAL_WHITELIST_PATH = BUNDLE_ROOT / "config" / "original_whitelist.json"
HISTORY_CACHE_PATH = CONFIG_DIR / "history_cache.json"
PROJECT_PROFILES_DIR = CONFIG_DIR / "projects"
ASSETS_DIR = APP_ROOT / "assets"

# 监测来源与对应平台 IP
MONITOR_SOURCES = [("自定义监测平台", "")]

MONITOR_SOURCE_NAMES = [n for n, _ in MONITOR_SOURCES]
MONITOR_SOURCE_IP = {n: ip for n, ip in MONITOR_SOURCES}

ALERT_LEVELS = ["高危", "中危", "低危"]
EVENT_LEVELS = ["一级", "二级", "三级", "四级", "五级"]
ATTACK_RESULTS = ["失败", "成功"]
WHITELIST_OPTIONS = ["否", "是"]

# 攻击名称/类型常见关键词映射
ATTACK_TYPE_HINTS = [
    (r"SSH.?暴力|暴力破解|爆破|brute", "SSH暴力破解攻击", "暴力破解"),
    (r"扫号|credential.?stuff", "HTTP扫号攻击", "暴力猜解"),
    (r"弱口令", "弱口令尝试登录", "弱口令"),
    (r"命令注入|命令执行", "命令注入攻击(通用)", "命令执行"),
    (r"代码执行|RCE|远程代码", "代码执行攻击", "代码执行"),
    (r"PHP.?代码|PHPUnit|eval-stdin", "PHP代码执行攻击", "代码执行"),
    (r"目录遍历|路径遍历|path.?traversal|\.\./\.\.", "目录遍历攻击(通用)", "目录遍历"),
    (r"跨站脚本|XSS", "跨站脚本攻击（XSS）", "跨站脚本注入攻击"),
    (r"SQL.?注入|sqli", "SQL注入攻击", "SQL注入"),
    (r"文件上传", "文件上传攻击", "文件上传"),
    (r"Nmap|端口扫描|工具扫描", "黑客工具Nmap扫描器", "工具扫描"),
    (r"网络探针|高频攻击源", "网络探针检测到高频攻击源", "检测到攻击源"),
    (r"敏感文件|信息泄露|信息泄漏", "敏感文件探测", "信息泄露"),
    (r"GIT|\.git", "GIT项目源代码探测", "信息泄露"),
    (r"漏洞扫描|漏洞探测", "漏洞扫描", "漏洞扫描"),
    (r"WebSocket", "WebSocket代码注入", "代码注入"),
    (r"反序列化", "反序列化攻击", "反序列化"),
    (r"SSRF|服务端请求伪造", "SSRF攻击", "SSRF"),
]

# 主题色
THEME_COLORS = {
    "dark": {
        "bg": "#1a1d27",
        "card": "#242836",
        "card_hover": "#2c3142",
        "accent": "#5b8def",
        "accent2": "#3ecf8e",
        "danger": "#f07178",
        "warning": "#e6b450",
        "text": "#e8eaed",
        "text_dim": "#9aa0a6",
        "border": "#3a3f55",
        "input": "#1e2230",
    },
    "light": {
        "bg": "#f0f2f5",
        "card": "#ffffff",
        "card_hover": "#f7f8fa",
        "accent": "#3b6fd9",
        "accent2": "#2aa86c",
        "danger": "#d64550",
        "warning": "#c9921a",
        "text": "#1f2328",
        "text_dim": "#656d76",
        "border": "#d0d7de",
        "input": "#f7f9fc",
    },
}
