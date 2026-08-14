# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 单文件打包配置"""

import json
import shutil
from copy import deepcopy
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None
root = Path(SPECPATH)

# Never embed the developer machine's saved API keys or local paths in the EXE.
from app.settings_store import DEFAULT_SETTINGS

bundle_defaults = root / "build_clean" / "bundle_defaults"
if bundle_defaults.exists():
    shutil.rmtree(bundle_defaults)
bundle_defaults.mkdir(parents=True, exist_ok=True)
bundle_settings = bundle_defaults / "settings.json"
default_bundle_settings = deepcopy(DEFAULT_SETTINGS)
default_bundle_settings["active_project_profile"] = ""
default_bundle_settings["company_networks_blank"] = True
bundle_settings.write_text(
    json.dumps(default_bundle_settings, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
bundle_whitelist = bundle_defaults / "whitelist.json"
source_whitelist = root / "settings" / "whitelist.json"
if source_whitelist.is_file():
    shutil.copy2(source_whitelist, bundle_whitelist)
else:
    bundle_whitelist.write_text(
        json.dumps({"version": 1, "description": "白名单IP/网段", "rules": []}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
bundle_original_whitelist = bundle_defaults / "original_whitelist.json"
shutil.copy2(bundle_whitelist, bundle_original_whitelist)
bundle_templates = bundle_defaults / "templates"
bundle_templates.mkdir(parents=True, exist_ok=True)
from app.template_store import DEFAULT_TEMPLATE
bundle_template = bundle_templates / "default.json"
bundle_template.write_text(
    json.dumps(deepcopy(DEFAULT_TEMPLATE), ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
datas = [
    (str(bundle_settings), "settings"),
    (str(bundle_whitelist), "settings"),
    (str(bundle_original_whitelist), "config"),
    (str(bundle_template), "settings/templates"),
]

binaries = []
hiddenimports = [
    "openpyxl",
    "bs4",
    "lxml",
    "lxml.etree",
    "lxml._elementpath",
    "httpx",
    "httpx._transports",
    "httpcore",
    "anyio",
    "certifi",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL.ImageGrab",
    "PIL.ImageTk",
    "customtkinter",
    "windnd",
    "pystray",
    "pystray._win32",
    "app",
    "app.gui",
    "app.extractor",
    "app.order_builder",
    "app.whitelist",
    "app.whitelist_import",
    "app.company_networks",
    "app.history",
    "app.settings_store",
    "app.batch_engine",
    "app.tray_icon",
    "app.constants",
    "app.ai_client",
    "app.ai_extract",
    "app.threatbook",
    "app.template_store",
    "app.branding",
    "app.drop_support",
]

for pkg in ("customtkinter", "windnd"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

try:
    datas += collect_data_files("customtkinter")
except Exception:
    pass

try:
    hiddenimports += collect_submodules("pystray")
except Exception:
    pass

# HTTPS 证书（迁移到无 Python 的机器上 httpx 仍可用）
try:
    import certifi

    datas.append((certifi.where(), "certifi"))
except Exception:
    pass

a = Analysis(
    [str(root / "main.py")],
    pathex=[str(root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib", "numpy", "scipy", "pandas", "torch", "tensorflow",
        "IPython", "jedi", "parso", "zmq", "pytest", "pygments", "rich",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="工单生成工具",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
