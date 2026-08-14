# -*- coding: utf-8 -*-
"""配置读写
Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import json
import re
import shutil
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .constants import APP_DISPLAY_NAME, APP_ROOT, BUNDLE_ROOT, CONFIG_DIR, SETTINGS_PATH, WHITELIST_PATH
from .io_utils import atomic_write_text
from .secret_store import protect_secret, unprotect_secret


DEFAULT_SETTINGS: dict[str, Any] = {
    "theme": "dark",
    # 自定义外观
    "app_title": "工单快捷工具",
    "subtitle_enabled": False,
    "subtitle_text": "",
    "logo_path": "",
    "history_xlsx": "",
    # Online history synchronization is opt-in.  A blank install must never
    # contact a previously used document service or display stale-sync alerts.
    "history_sync_enabled": False,
    "history_sync_stale_alert_enabled": False,
    "history_sync_urls": [],
    "history_auto_sync_minutes": 15,
    "history_last_sync_at": "",
    "history_last_success_at": "",
    "history_last_error": "",
    "history_sync_cookie": "",
    "network_xlsx": "",
    "number_date": "",
    "number_seq": {},
    "default_event_level": "",
    "default_source": "",
    "window_geometry": "1600x1000+0+0",
    "window_state": "normal",
    "window_layout_version": 2,
    "window_opacity": 1.0,
    "company_networks_blank": True,
    "close_to_tray": True,
    "tray_enabled": True,
    "batch_skip_history": True,
    # auto: AI 优先、文本/HTML 本地回落；local: 强制本地；ai: 强制在线 AI
    "analysis_mode": "auto",
    # AI（默认只预置 DeepSeek 基址，API Key 后期自行填写）
    "ai_enabled": False,
    "ai_base_url": "https://api.deepseek.com/v1",
    "ai_api_key": "",
    "ai_model": "deepseek-v4-flash",
    "ai_timeout": 45,
    "ai_use_ocr": True,
    "ai_use_judge": True,
    "ai_active_profile": "DeepSeek",
    "ai_vision_profile": "DeepSeek",
    "ai_profiles": [
        {
            "name": "DeepSeek",
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "",
            "wire_api": "chat",
            "model": "deepseek-v4-flash",
        },
    ],
    # ThreatBook cloud intelligence is opt-in and requires the user's API key.
    "threatbook_enabled": False,
    "threatbook_auto_enrich": False,
    "threatbook_api_key": "",
    "threatbook_base_url": "https://api.threatbook.cn/v3",
    "threatbook_timeout": 8,
    "active_template": "自定义手动模板",
}


def normalize_ai_profiles(settings: dict[str, Any]) -> list[dict[str, str]]:
    """保证至少有一组 AI 配置，并同步当前激活项到顶层字段。"""
    profiles = settings.get("ai_profiles")
    if not isinstance(profiles, list) or not profiles:
        profiles = deepcopy(DEFAULT_SETTINGS["ai_profiles"])
    cleaned: list[dict[str, str]] = []
    seen: set[str] = set()
    for p in profiles:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip() or f"配置{len(cleaned) + 1}"
        unique_name = name
        suffix = 2
        while unique_name.casefold() in seen:
            unique_name = f"{name}_{suffix}"
            suffix += 1
        name = unique_name
        seen.add(name.casefold())
        wire_api = str(p.get("wire_api") or ("responses" if "luna" in name.casefold() else "chat")).strip().casefold()
        if wire_api not in {"auto", "chat", "responses", "anthropic"}:
            wire_api = "auto"
        cleaned.append({
            "name": name,
            "base_url": str(p.get("base_url") or "").strip() or "https://api.deepseek.com/v1",
            "api_key": unprotect_secret(str(p.get("api_key") or "").strip()),
            "model": str(p.get("model") or "").strip() or "deepseek-v4-flash",
            "wire_api": wire_api,
        })
    if not cleaned:
        cleaned = deepcopy(DEFAULT_SETTINGS["ai_profiles"])
    settings["ai_profiles"] = cleaned

    active = str(settings.get("ai_active_profile") or "").strip()
    names = [p["name"] for p in cleaned]
    if active not in names:
        active = names[0]
    settings["ai_active_profile"] = active
    vision = str(settings.get("ai_vision_profile") or "").strip()
    if vision not in names:
        vision = next((name for name in names if "gpt" in name.casefold()), active)
    settings["ai_vision_profile"] = vision
    current = next(p for p in cleaned if p["name"] == active)
    # 顶层字段与激活配置保持一致（供 AIClient 使用）
    settings["ai_base_url"] = current["base_url"]
    settings["ai_api_key"] = current["api_key"]
    settings["ai_model"] = current["model"]
    settings["ai_wire_api"] = current.get("wire_api") or "chat"
    return cleaned


def get_ai_profile(settings: dict[str, Any], name: str | None = None) -> dict[str, str]:
    profiles = normalize_ai_profiles(settings)
    target = (name or settings.get("ai_active_profile") or "").strip()
    for p in profiles:
        if p["name"] == target:
            return dict(p)
    return dict(profiles[0])


def upsert_ai_profile(
    settings: dict[str, Any],
    *,
    name: str,
    base_url: str,
    api_key: str,
    model: str,
    wire_api: str = "auto",
    activate: bool = True,
    original_name: str | None = None,
) -> None:
    name = (name or "").strip()
    if not name:
        raise ValueError("配置名称不能为空")
    if len(name) > 40:
        raise ValueError("配置名称不能超过 40 个字符")
    base_url = (base_url or "").strip()
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL 基址必须是有效的 http/https 地址")
    model = (model or "").strip()
    if not model:
        raise ValueError("模型名不能为空")
    profiles = normalize_ai_profiles(settings)
    item = {
        "name": name,
        "base_url": base_url,
        "api_key": (api_key or "").strip(),
        "model": model,
        "wire_api": wire_api if wire_api in {"auto", "chat", "responses", "anthropic"} else "auto",
    }
    original = (original_name or "").strip()
    target_index = next(
        (i for i, p in enumerate(profiles) if p["name"].casefold() == original.casefold()),
        None,
    ) if original else None
    conflict = next(
        (
            i for i, p in enumerate(profiles)
            if p["name"].casefold() == name.casefold() and i != target_index
        ),
        None,
    )
    if conflict is not None:
        raise ValueError(f"AI 配置“{name}”已存在")
    if target_index is None:
        profiles.append(item)
    else:
        profiles[target_index] = item
    settings["ai_profiles"] = profiles
    if activate:
        settings["ai_active_profile"] = name
    normalize_ai_profiles(settings)


def delete_ai_profile(settings: dict[str, Any], name: str) -> bool:
    name = (name or "").strip()
    profiles = normalize_ai_profiles(settings)
    if len(profiles) <= 1:
        return False
    new_list = [p for p in profiles if p["name"].casefold() != name.casefold()]
    if len(new_list) == len(profiles):
        return False
    settings["ai_profiles"] = new_list
    if settings.get("ai_active_profile") == name:
        settings["ai_active_profile"] = new_list[0]["name"]
    normalize_ai_profiles(settings)
    return True


def _migrate_legacy_runtime_dirs() -> None:
    """Move pre-settings runtime data into the unified settings directory."""
    legacy_config = APP_ROOT / "config"
    if not CONFIG_DIR.exists() and legacy_config.is_dir():
        shutil.move(str(legacy_config), str(CONFIG_DIR))

    legacy_profiles = APP_ROOT / "项目配置"
    runtime_profiles = CONFIG_DIR / "projects"
    if legacy_profiles.is_dir():
        runtime_profiles.mkdir(parents=True, exist_ok=True)
        for profile in legacy_profiles.glob("*.json"):
            target = runtime_profiles / profile.name
            if not target.exists():
                shutil.move(str(profile), str(target))
        try:
            legacy_profiles.rmdir()
        except OSError:
            pass


def ensure_runtime_files() -> None:
    """打包后首次运行：从 bundle 拷贝默认 config 到 exe 旁。"""
    _migrate_legacy_runtime_dirs()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (SETTINGS_PATH.parent).mkdir(parents=True, exist_ok=True)
    # Older releases kept the tracking cache beside the executable.  Move it
    # once into settings so the runtime directory has a single, predictable
    # home for user data.
    legacy_history = APP_ROOT / "history_cache.json"
    history_target = CONFIG_DIR / "history_cache.json"
    if legacy_history.exists() and not history_target.exists():
        try:
            shutil.move(str(legacy_history), str(history_target))
        except OSError:
            shutil.copy2(legacy_history, history_target)

    bundled_config = BUNDLE_ROOT / "settings"
    if not SETTINGS_PATH.exists():
        src = bundled_config / "settings.json"
        if src.exists():
            shutil.copy2(src, SETTINGS_PATH)
        else:
            save_settings(deepcopy(DEFAULT_SETTINGS))
    # Project bundles belong under config too.  Copy bundled examples only
    # when absent so later user edits and locally saved project packages win.
    bundled_profiles = bundled_config / "projects"
    runtime_profiles = CONFIG_DIR / "projects"
    if bundled_profiles.is_dir():
        runtime_profiles.mkdir(parents=True, exist_ok=True)
        for profile in bundled_profiles.glob("*.json"):
            target = runtime_profiles / profile.name
            if not target.exists():
                shutil.copy2(profile, target)
    # Migrate legacy standalone data into the active project bundle once.
    try:
        active = str(json.loads(SETTINGS_PATH.read_text(encoding="utf-8")).get("active_project_profile") or "").strip()
        project_path = runtime_profiles / f"{active}.json" if active else None
        if project_path and project_path.is_file():
            project = json.loads(project_path.read_text(encoding="utf-8"))
            changed = False
            if WHITELIST_PATH.is_file() and not project.get("whitelist"):
                project["whitelist"] = json.loads(WHITELIST_PATH.read_text(encoding="utf-8")); changed = True
            if history_target.is_file() and not project.get("history_cache"):
                project["history_cache"] = json.loads(history_target.read_text(encoding="utf-8")); changed = True
            if changed:
                atomic_write_text(project_path, json.dumps(project, ensure_ascii=False, indent=2) + "\n")
            WHITELIST_PATH.unlink(missing_ok=True)
            history_target.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError):
        pass
    # 默认提取模板
    try:
        from .template_store import ensure_templates_dir

        ensure_templates_dir()
    except Exception:
        pass


def load_settings() -> dict[str, Any]:
    ensure_runtime_files()
    data = deepcopy(DEFAULT_SETTINGS)
    stored_layout_version = 0
    if SETTINGS_PATH.exists():
        try:
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                stored_layout_version = int(raw.get("window_layout_version") or 0)
                data.update(raw)
        except Exception:
            pass
    legacy_appearance = any(key in data for key in ("transparency", "content_opacity", "wallpaper"))
    if str(data.get("app_title") or "").strip() == "工单处理工具":
        data["app_title"] = APP_DISPLAY_NAME
    # Legacy appearance settings are intentionally discarded. The tool no
    # longer exposes transparency or wallpaper controls.
    data.pop("transparency", None)
    data.pop("content_opacity", None)
    data.pop("wallpaper", None)
    try:
        data["window_opacity"] = min(1.0, max(0.65, float(data.get("window_opacity", 1.0))))
    except (TypeError, ValueError):
        data["window_opacity"] = 1.0
    # 兼容旧配置：无多组档案时，用顶层字段生成一组
    if not isinstance(data.get("ai_profiles"), list) or not data.get("ai_profiles"):
        data["ai_profiles"] = [{
            "name": str(data.get("ai_active_profile") or "DeepSeek"),
            "base_url": str(data.get("ai_base_url") or "https://api.deepseek.com/v1"),
            "api_key": str(data.get("ai_api_key") or ""),
            "model": str(data.get("ai_model") or "deepseek-v4-flash"),
        }]
        # 若旧配置只有 deepseek 基址，补一组 Grok 空 Key 模板方便切换
        names = {p.get("name") for p in data["ai_profiles"]}
        if "Grok" not in names:
            data["ai_profiles"].append({
                "name": "Grok",
                "base_url": "https://api.x.ai/v1",
                "api_key": "",
                "model": "grok-4.5",
            })
    normalize_ai_profiles(data)
    data["history_sync_cookie"] = unprotect_secret(str(data.get("history_sync_cookie") or ""))
    data["threatbook_api_key"] = unprotect_secret(str(data.get("threatbook_api_key") or ""))
    urls = data.get("history_sync_urls")
    if not isinstance(urls, list):
        urls = DEFAULT_SETTINGS["history_sync_urls"]
    data["history_sync_urls"] = [str(url).strip() for url in urls if str(url).strip()]
    try:
        data["history_auto_sync_minutes"] = min(1440, max(1, int(data.get("history_auto_sync_minutes", 15))))
    except (TypeError, ValueError):
        data["history_auto_sync_minutes"] = 15
    if str(data.get("analysis_mode") or "auto").casefold() not in {"auto", "local", "ai"}:
        data["analysis_mode"] = "auto"
    layout_migrated = stored_layout_version < int(DEFAULT_SETTINGS["window_layout_version"])
    if layout_migrated:
        data["window_geometry"] = DEFAULT_SETTINGS["window_geometry"]
        data["window_state"] = "normal"
        data["window_layout_version"] = DEFAULT_SETTINGS["window_layout_version"]
    if legacy_appearance or layout_migrated:
        save_settings(data)
    return data


def save_settings(settings: dict[str, Any]) -> None:
    normalize_ai_profiles(settings)
    payload = deepcopy(settings)
    try:
        payload["window_opacity"] = min(1.0, max(0.65, float(payload.get("window_opacity", 1.0))))
    except (TypeError, ValueError):
        payload["window_opacity"] = 1.0
    payload.pop("transparency", None)
    payload.pop("content_opacity", None)
    payload.pop("wallpaper", None)
    for profile in payload.get("ai_profiles") or []:
        if isinstance(profile, dict):
            profile["api_key"] = protect_secret(str(profile.get("api_key") or ""))
    payload["ai_api_key"] = protect_secret(str(payload.get("ai_api_key") or ""))
    payload["history_sync_cookie"] = protect_secret(str(payload.get("history_sync_cookie") or ""))
    payload["threatbook_api_key"] = protect_secret(str(payload.get("threatbook_api_key") or ""))
    atomic_write_text(
        SETTINGS_PATH,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )


def resolve_output_md(path: str | Path | None) -> Path:
    """相对路径按 exe/程序根目录解析，便于整包拷贝迁移。"""
    raw = str(path or "").strip() or "较确定工单.md"
    p = Path(raw)
    if p.is_absolute():
        return p
    return (APP_ROOT / p).resolve()


def validate_number_date(date_mmdd: str) -> str:
    """校验并返回 MMDD 编号日期。"""
    date_mmdd = (date_mmdd or "").strip()
    if not re.fullmatch(r"\d{4}", date_mmdd):
        raise ValueError("编号日期必须是 4 位 MMDD，例如 0809")
    try:
        datetime.strptime(f"2000{date_mmdd}", "%Y%m%d")
    except ValueError as exc:
        raise ValueError("编号日期不是有效的月日") from exc
    return date_mmdd


def validate_number_seq(seq_raw: str | int | None) -> int | None:
    """
    解析手动序号。
    空字符串 / None → 自动递增；
    "013" / 13 → 13。
    """
    if seq_raw is None:
        return None
    if isinstance(seq_raw, int):
        if seq_raw < 1:
            raise ValueError("序号至少为 1")
        return seq_raw
    s = str(seq_raw).strip()
    if not s:
        return None
    if not re.fullmatch(r"\d{1,6}", s):
        raise ValueError("序号必须是 1~6 位数字，例如 013")
    value = int(s)
    if value < 1:
        raise ValueError("序号至少为 1")
    return value


def format_number(date_mmdd: str, seq: int) -> str:
    return f"{validate_number_date(date_mmdd)}-{int(seq):03d}"


def auto_next_seq(settings: dict[str, Any], date_mmdd: str) -> int:
    date_mmdd = validate_number_date(date_mmdd)
    seq_map = settings.get("number_seq") or {}
    return int(seq_map.get(date_mmdd, 0)) + 1


def peek_number(
    settings: dict[str, Any],
    date_mmdd: str,
    manual_seq: str | int | None = None,
) -> str:
    """预览编号。manual_seq 为空则自动 last+1。"""
    date_mmdd = validate_number_date(date_mmdd)
    seq = validate_number_seq(manual_seq)
    if seq is None:
        seq = auto_next_seq(settings, date_mmdd)
    return format_number(date_mmdd, seq)


def resolve_number(
    settings: dict[str, Any],
    date_mmdd: str,
    manual_seq: str | int | None = None,
) -> tuple[str, int]:
    """返回 (编号字符串, 使用的序号整数)。"""
    date_mmdd = validate_number_date(date_mmdd)
    seq = validate_number_seq(manual_seq)
    if seq is None:
        seq = auto_next_seq(settings, date_mmdd)
    return format_number(date_mmdd, seq), seq


def commit_number(
    settings: dict[str, Any],
    date_mmdd: str,
    used_seq: int | None = None,
) -> int:
    """
    工单成功写入后提交序号。
    used_seq 指定本次实际使用的序号；为空则按自动 +1。
    提交后 number_seq[date]=used，下次自动从 used+1 开始。
    """
    date_mmdd = validate_number_date(date_mmdd)
    seq_map = settings.setdefault("number_seq", {})
    if not isinstance(seq_map, dict):
        seq_map = {}
        settings["number_seq"] = seq_map
    if used_seq is None:
        cur = int(seq_map.get(date_mmdd, 0)) + 1
    else:
        cur = int(used_seq)
        if cur < 1:
            raise ValueError("序号至少为 1")
    seq_map[date_mmdd] = cur
    settings["number_date"] = date_mmdd
    return cur


def next_number(
    settings: dict[str, Any],
    date_mmdd: str,
    manual_seq: str | int | None = None,
) -> str:
    """兼容旧调用：解析编号并提交。"""
    number, seq = resolve_number(settings, date_mmdd, manual_seq)
    commit_number(settings, date_mmdd, used_seq=seq)
    return number


def sync_number_sequences(settings: dict[str, Any], md_path: str | Path) -> dict[str, int]:
    """从已有 Markdown 工单同步每个日期的最大序号。"""
    path = Path(md_path)
    seq_map = settings.setdefault("number_seq", {})
    if not isinstance(seq_map, dict):
        seq_map = {}
        settings["number_seq"] = seq_map
    if not path.exists():
        return seq_map

    text = path.read_text(encoding="utf-8", errors="ignore")
    for mmdd, seq in re.findall(r"编号\s*[：:]\s*(\d{4})-(\d+)", text):
        seq_map[mmdd] = max(int(seq_map.get(mmdd, 0)), int(seq))
    return seq_map
