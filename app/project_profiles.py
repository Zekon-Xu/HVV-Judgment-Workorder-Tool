"""Portable project configuration bundles for the blank work-order tool."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import CONFIG_DIR, HISTORY_CACHE_PATH, SETTINGS_PATH, WHITELIST_PATH
from .default_whitelist import DEFAULT_COMPANY_SOURCE, active_company_profile_path, current_company_rules
from .io_utils import atomic_write_text
from .secret_store import protect_secret, unprotect_secret
from .settings_store import DEFAULT_SETTINGS, save_settings
from .template_store import DEFAULT_TEMPLATE, TEMPLATES_DIR, enrich_template_runtime, ensure_templates_dir

PROJECT_PROFILES_DIR = CONFIG_DIR / "projects"
PROFILE_VERSION = 2


def _safe_name(name: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\r\n]+', "_", (name or "").strip()).strip(" .")
    if not value:
        raise ValueError("项目配置名称不能为空")
    return value[:80]


def list_project_profiles() -> list[str]:
    PROJECT_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for path in sorted(PROJECT_PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            names.append(str(data.get("name") or path.stem))
        except Exception:
            continue
    return names


def _protect_settings(settings: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(settings)
    payload["ai_api_key"] = protect_secret(str(payload.get("ai_api_key") or ""))
    payload["history_sync_cookie"] = protect_secret(str(payload.get("history_sync_cookie") or ""))
    payload["threatbook_api_key"] = protect_secret(str(payload.get("threatbook_api_key") or ""))
    for profile in payload.get("ai_profiles") or []:
        if isinstance(profile, dict):
            profile["api_key"] = protect_secret(str(profile.get("api_key") or ""))
    return payload


def _unprotect_settings(settings: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(DEFAULT_SETTINGS)
    payload.update(deepcopy(settings))
    try:
        layout_version = int(settings.get("window_layout_version") or 0)
    except (TypeError, ValueError):
        layout_version = 0
    if "window_layout_version" not in settings or layout_version < int(DEFAULT_SETTINGS["window_layout_version"]):
        payload["window_geometry"] = DEFAULT_SETTINGS["window_geometry"]
        payload["window_state"] = "normal"
        payload["window_layout_version"] = DEFAULT_SETTINGS["window_layout_version"]
    payload["ai_api_key"] = unprotect_secret(str(payload.get("ai_api_key") or ""))
    payload["history_sync_cookie"] = unprotect_secret(str(payload.get("history_sync_cookie") or ""))
    payload["threatbook_api_key"] = unprotect_secret(str(payload.get("threatbook_api_key") or ""))
    for profile in payload.get("ai_profiles") or []:
        if isinstance(profile, dict):
            profile["api_key"] = unprotect_secret(str(profile.get("api_key") or ""))
    return payload


def _read_templates() -> list[dict[str, Any]]:
    ensure_templates_dir()
    result: list[dict[str, Any]] = []
    for path in sorted(TEMPLATES_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                result.append(enrich_template_runtime(data))
        except Exception:
            continue
    return result


def _read_whitelist() -> dict[str, Any]:
    project_path = active_company_profile_path()
    if project_path:
        try:
            payload = json.loads(project_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("whitelist"), dict):
                return payload["whitelist"]
        except Exception:
            pass
    if WHITELIST_PATH.is_file():
        try:
            data = json.loads(WHITELIST_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"version": 1, "description": "白名单", "rules": []}


def _read_history_cache() -> Any:
    project_path = active_company_profile_path()
    if project_path:
        try:
            payload = json.loads(project_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("history_cache"), list):
                return payload["history_cache"]
        except Exception:
            pass
    if HISTORY_CACHE_PATH.is_file():
        try:
            return json.loads(HISTORY_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def save_project_profile(
    name: str,
    settings: dict[str, Any],
    *,
    include_ai_key: bool = True,
    include_threatbook_key: bool = True,
    include_whitelist: bool = True,
    include_company_networks: bool = True,
    include_history: bool = True,
) -> Path:
    safe = _safe_name(name)
    PROJECT_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    # Project files are intended to move between devices. Secrets are therefore
    # included only when explicitly selected by the user; legacy DPAPI payloads
    # remain readable in load_project_profile for backward compatibility.
    portable_settings = deepcopy(settings)
    if not include_ai_key:
        portable_settings["ai_api_key"] = ""
        for profile in portable_settings.get("ai_profiles") or []:
            if isinstance(profile, dict):
                profile["api_key"] = ""
    if not include_threatbook_key:
        portable_settings["threatbook_api_key"] = ""
    document = {
        "version": PROFILE_VERSION,
        "name": safe,
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "settings": portable_settings,
        "data_included": {
            "ai_key": bool(include_ai_key),
            "threatbook_key": bool(include_threatbook_key),
            "whitelist": bool(include_whitelist),
            "company_networks": bool(include_company_networks),
            "history": bool(include_history),
        },
        "whitelist": _read_whitelist() if include_whitelist else {"version": 1, "description": "白名单", "rules": []},
        "company_networks": {
            "version": 1,
            "description": "工单涉及的内网部门判断库（仅用于归属判断，不是白名单）",
            "source": DEFAULT_COMPANY_SOURCE,
            "rules": current_company_rules() if include_company_networks else [],
        },
        "templates": _read_templates(),
        "history_cache": _read_history_cache() if include_history else [],
    }
    # The portable bundle is the canonical owner of these datasets.
    document["data_included"]["whitelist"] = True
    document["data_included"]["company_networks"] = True
    document["data_included"]["history"] = True
    path = PROJECT_PROFILES_DIR / f"{safe}.json"
    atomic_write_text(path, json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    return path


def _profile_path(name_or_path: str | Path) -> Path:
    candidate = Path(name_or_path)
    if candidate.is_file():
        return candidate
    safe = _safe_name(str(name_or_path))
    path = PROJECT_PROFILES_DIR / f"{safe}.json"
    if not path.is_file():
        for item in PROJECT_PROFILES_DIR.glob("*.json"):
            try:
                data = json.loads(item.read_text(encoding="utf-8"))
                if str(data.get("name") or "") == str(name_or_path):
                    return item
            except Exception:
                continue
    return path


def load_project_profile(name_or_path: str | Path) -> dict[str, Any]:
    path = _profile_path(name_or_path)
    if not path.is_file():
        raise FileNotFoundError(f"项目配置不存在：{path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("settings"), dict):
        raise ValueError("项目配置格式无效")
    settings = _unprotect_settings(data["settings"])
    settings["active_project_profile"] = str(data.get("name") or path.stem)
    included = data.get("data_included") if isinstance(data.get("data_included"), dict) else {}
    settings["company_networks_blank"] = not bool(included.get("company_networks", True))
    save_settings(settings)

    # Imported bundles must become the active local project so company-network
    # edits and future saves operate on the same JSON under settings/projects.
    local_path = PROJECT_PROFILES_DIR / f"{_safe_name(settings['active_project_profile'])}.json"
    if path.resolve() != local_path.resolve():
        atomic_write_text(local_path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    whitelist = data.get("whitelist")
    if not isinstance(whitelist, dict):
        whitelist = {"version": 1, "description": "白名单", "rules": []}

    history = data.get("history_cache")

    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    for existing in TEMPLATES_DIR.glob("*.json"):
        existing.unlink(missing_ok=True)
    templates = [item for item in (data.get("templates") or []) if isinstance(item, dict)]
    if not templates:
        templates = [deepcopy(DEFAULT_TEMPLATE)]
    for index, template in enumerate(templates, start=1):
        name = _safe_name(str(template.get("name") or f"模板{index}"))
        template = enrich_template_runtime(template)
        atomic_write_text(
            TEMPLATES_DIR / ("default.json" if index == 1 else f"{name}.json"),
            json.dumps(template, ensure_ascii=False, indent=2) + "\n",
        )
    return {"name": str(data.get("name") or path.stem), "path": str(path), "settings": settings}


def restore_blank_workspace() -> None:
    active_before = ""
    try:
        if SETTINGS_PATH.is_file():
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            active_before = str(raw.get("active_project_profile") or "").strip()
    except Exception:
        pass
    blank_settings = deepcopy(DEFAULT_SETTINGS)
    blank_settings["company_networks_blank"] = True
    save_settings(blank_settings)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    for existing in TEMPLATES_DIR.glob("*.json"):
        existing.unlink(missing_ok=True)
    atomic_write_text(
        TEMPLATES_DIR / "default.json",
        json.dumps(enrich_template_runtime(DEFAULT_TEMPLATE), ensure_ascii=False, indent=2) + "\n",
    )
    # Keep the active project file usable while making its company network data blank.
    active = active_before
    if active:
        path = PROJECT_PROFILES_DIR / f"{_safe_name(active)}.json"
        if path.is_file():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    payload["whitelist"] = {"version": 1, "description": "白名单", "rules": []}
                    payload["company_networks"] = {"version": 1, "description": "工单涉及的内网部门判断库（仅用于归属判断，不是白名单）", "source": DEFAULT_COMPANY_SOURCE, "rules": []}
                    payload["history_cache"] = []
                    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            except Exception:
                pass
