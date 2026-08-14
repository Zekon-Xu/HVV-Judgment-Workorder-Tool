"""Project-scoped company network attribution.

Company networks identify ownership only. They are loaded exclusively from
the active project bundle and are never embedded in a blank distribution.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .constants import CONFIG_DIR, SETTINGS_PATH


DEFAULT_COMPANY_SOURCE: Final = "公司内网来源判断"


def default_company_rules() -> list[dict[str, str]]:
    """A clean install intentionally has no customer network rules."""
    return []


def _normalize_company_rules(items: object) -> list[tuple[str, str]]:
    if isinstance(items, dict):
        items = items.get("rules")
    if not isinstance(items, list):
        return []
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            network = str(ipaddress.ip_network(str(item.get("rule") or ""), strict=False))
        except ValueError:
            continue
        department = str(item.get("reason") or item.get("department") or "").strip()
        if not department or network in seen:
            continue
        seen.add(network)
        result.append((network, department))
    return result


def active_company_profile_path() -> Path | None:
    try:
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        active = str(settings.get("active_project_profile") or "").strip()
        safe = re.sub(r'[<>:"/\\|?*\r\n]+', "_", active).strip(" .")[:80]
        if safe:
            path = CONFIG_DIR / "projects" / f"{safe}.json"
            if path.is_file():
                return path
    except (OSError, ValueError, TypeError):
        pass
    return None


def active_project_profile_path() -> Path | None:
    return active_company_profile_path()


def _active_company_networks() -> list[tuple[str, str]]:
    try:
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        if bool(settings.get("company_networks_blank")):
            return []
    except (OSError, ValueError, TypeError):
        pass
    path = active_company_profile_path()
    try:
        if path:
            profile = json.loads(path.read_text(encoding="utf-8"))
            data = profile.get("company_networks")
            if isinstance(data, dict) and isinstance(data.get("rules"), list):
                return _normalize_company_rules(data)
    except (OSError, ValueError, TypeError):
        pass
    return []


def current_company_rules() -> list[dict[str, str]]:
    return [
        {"rule": network, "reason": company, "source": DEFAULT_COMPANY_SOURCE}
        for network, company in _active_company_networks()
    ]


@dataclass(frozen=True)
class CompanyNetworkMatch:
    ip: str
    department: str
    network: str


def company_network_match(value: str) -> CompanyNetworkMatch | None:
    raw = (value or "").strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    networks = sorted(
        _active_company_networks(),
        key=lambda item: ipaddress.ip_network(item[0], strict=False).prefixlen,
        reverse=True,
    )
    for network, department in networks:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return CompanyNetworkMatch(raw, department, network)
        except ValueError:
            continue
    return None


def company_attribution_lines(
    *,
    attack_ip: str = "",
    target_ip: str = "",
    xff: str = "",
    domain_url: str = "",
) -> list[str]:
    from .whitelist import extract_ips

    rows: list[str] = []
    seen: set[tuple[str, str]] = set()
    for role, value in (
        ("攻击来源", attack_ip),
        ("受害/目标", target_ip),
        ("XFF来源", xff),
        ("域名/URL", domain_url),
    ):
        for ip in extract_ips(value or ""):
            match = company_network_match(ip)
            if not match or (role, ip) in seen:
                continue
            seen.add((role, ip))
            rows.append(f"{role} {ip} -> {match.department}（{match.network}）")
    return rows
