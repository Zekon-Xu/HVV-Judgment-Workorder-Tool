"""白名单匹配（兼容 ip.exe 逻辑：CIDR / 范围 / 单 IP）"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .constants import ORIGINAL_WHITELIST_PATH, WHITELIST_PATH
from .default_whitelist import active_project_profile_path
from .io_utils import atomic_write_text


@dataclass
class MatchResult:
    matched: bool
    rule: str = ""
    reason: str = ""
    source: str = ""


_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
    re.I,
)


def _normalize_indicator(value: str) -> str:
    raw = (value or "").strip().strip('"\'`<>[](){}').rstrip(".,;；")
    if not raw:
        return ""
    raw = re.sub(r"^[a-z][a-z0-9+.-]*://", "", raw, flags=re.I)
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in raw and raw.count(":") == 1:
        raw = raw.rsplit(":", 1)[0]
    return raw.rstrip(".").casefold()


def extract_indicators(text: str) -> list[str]:
    """Extract domain/URL IOC values while preserving input order."""
    result: list[str] = []
    for match in re.finditer(
        r"(?i)(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d+)?(?:/[^\s,，;；]*)?",
        str(text or ""),
    ):
        token = _normalize_indicator(match.group(0))
        if token and token not in result and _DOMAIN_RE.fullmatch(token):
            result.append(token)
    return result


def prune_redundant_single_ip_rules(rules: list[dict]) -> tuple[list[dict], int]:
    """Drop single-IP rules already covered by another CIDR/range rule."""
    parsed: list[tuple[dict, str, object]] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("rule") or "").strip()
        try:
            if "/" in raw:
                parsed.append((item, "network", ipaddress.ip_network(raw, strict=False)))
            elif "-" in raw:
                left, right = [part.strip() for part in raw.split("-", 1)]
                start, end = ipaddress.ip_address(left), ipaddress.ip_address(right)
                if start.version == end.version:
                    parsed.append((item, "range", (start, end)))
            else:
                parsed.append((item, "single", ipaddress.ip_address(raw)))
        except ValueError:
            parsed.append((item, "other", None))
    containers = [value for _item, kind, value in parsed if kind in {"network", "range"}]
    compact: list[dict] = []
    removed = 0
    for item, kind, value in parsed:
        covered = False
        if kind == "single":
            for container in containers:
                if isinstance(container, tuple):
                    if container[0].version == value.version and container[0] <= value <= container[1]:
                        covered = True
                        break
                elif value.version == container.version and value in container:
                    covered = True
                    break
        if covered:
            removed += 1
            continue
        compact.append(dict(item))
    return compact, removed


class WhitelistEngine:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or WHITELIST_PATH
        self.rules: list[dict] = []
        self._compiled: list[dict] = []
        self.reload()

    def _read_data(self) -> dict:
        data = {"version": 1, "description": "白名单IP/网段", "rules": [], "manual": []}
        project_path = None if self.path != WHITELIST_PATH else active_project_profile_path()
        if project_path:
            try:
                project = json.loads(project_path.read_text(encoding="utf-8"))
                nested = project.get("whitelist") if isinstance(project, dict) else None
                if isinstance(nested, dict):
                    data.update(nested)
            except Exception:
                pass
        elif self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    data.update(raw)
            except Exception:
                pass
        # A whitelist has one editable rule collection. ``manual`` is read
        # only for compatibility with older JSON files and folded into it.
        combined = list(data.get("rules") or []) + list(data.get("manual") or [])
        normalized: list[dict] = []
        seen: set[str] = set()
        for item in combined:
            if not isinstance(item, dict):
                continue
            key = str(item.get("rule") or "").strip().casefold()
            if not key or key in seen:
                continue
            seen.add(key)
            normalized.append(dict(item))
        data["rules"] = normalized
        data["manual"] = []
        return data

    def _write_data(self, data: dict) -> None:
        payload = dict(data)
        payload.pop("manual", None)
        project_path = None if self.path != WHITELIST_PATH else active_project_profile_path()
        if project_path:
            project = json.loads(project_path.read_text(encoding="utf-8"))
            project["whitelist"] = payload
            atomic_write_text(project_path, json.dumps(project, ensure_ascii=False, indent=2) + "\n")
        else:
            atomic_write_text(self.path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def reload(self) -> None:
        data = self._read_data()
        # Manual rules win reason/source selection when rules overlap.
        self.rules = list(data.get("manual") or []) + list(data.get("rules") or [])
        self._compile()

    def save(self, rules: list[dict] | None = None, manual: list[dict] | None = None) -> None:
        data = self._read_data()
        if rules is not None or manual is not None:
            data["rules"] = list(rules or []) + list(manual or [])
            data["manual"] = []
        data["rules"], _removed = prune_redundant_single_ip_rules(list(data.get("rules") or []))
        self._write_data(data)
        self.reload()

    def restore_original(self) -> int:
        """Restore the editable rules from the bundled JSON rollback file."""
        if not ORIGINAL_WHITELIST_PATH.is_file():
            raise RuntimeError("未找到随程序发布的白名单 JSON 回滚文件")
        try:
            baseline = json.loads(ORIGINAL_WHITELIST_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("白名单 JSON 回滚文件无法读取") from exc
        rules = baseline.get("rules") if isinstance(baseline, dict) else None
        if not isinstance(rules, list):
            raise RuntimeError("白名单 JSON 回滚文件格式无效")
        normalized: list[dict] = []
        seen: set[str] = set()
        for item in rules:
            if not isinstance(item, dict):
                continue
            rule = self.normalize_rule(str(item.get("rule") or ""))
            key = rule.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized.append({
                "rule": rule,
                "reason": str(item.get("reason") or "原始白名单"),
                "source": str(item.get("source") or "原始白名单"),
            })
        self._write_data({
            "version": 1,
            "description": str(baseline.get("description") or "原始白名单"),
            "rules": normalized,
            "manual": [],
        })
        self.reload()
        return len(normalized)

    def merge_rules(self, items: list[dict], *, manual: bool = False) -> int:
        """Normalize and incrementally merge rule dictionaries."""
        data = self._read_data()
        target = list(data.get("rules") or [])
        known = {
            self.normalize_rule(str(item.get("rule") or "")).casefold()
            for item in data.get("rules") or []
            if str(item.get("rule") or "").strip()
        }
        added = 0
        for raw in items:
            rule = self.normalize_rule(str(raw.get("rule") or ""))
            if rule.casefold() in known:
                continue
            target.append({
                "rule": rule,
                "reason": str(raw.get("reason") or ("手动添加" if manual else "导入规则")),
                "source": str(raw.get("source") or ("手动" if manual else "导入")),
            })
            known.add(rule.casefold())
            added += 1
        if added:
            self.save(rules=target)
        return added

    def all_entries(self) -> list[dict]:
        data = self._read_data()
        out = []
        for r in data.get("rules") or []:
            item = dict(r)
            item["group"] = "rule"
            out.append(item)
        return out

    @staticmethod
    def normalize_rule(rule: str) -> str:
        raw = (rule or "").strip()
        if not raw:
            raise ValueError("规则不能为空")
        try:
            if "-" in raw and "/" not in raw:
                left, right = [part.strip() for part in raw.split("-", 1)]
                start = ipaddress.ip_address(left)
                end = ipaddress.ip_address(right)
                if start.version != end.version:
                    raise ValueError("范围两端必须是同一 IP 版本")
                if int(start) > int(end):
                    start, end = end, start
                return f"{start}-{end}"
            if "/" in raw:
                return str(ipaddress.ip_network(raw, strict=False))
            return str(ipaddress.ip_address(raw))
        except ValueError as exc:
            normalized = _normalize_indicator(raw)
            if _DOMAIN_RE.fullmatch(normalized):
                return normalized
            raise ValueError("规则格式无效，请输入单个 IP、CIDR、域名或完整起止范围") from exc

    def add_manual(self, rule: str, reason: str = "手动添加") -> bool:
        rule = self.normalize_rule(rule)
        return bool(self.merge_rules([{
            "rule": rule, "reason": reason or "手动添加", "source": "手动"
        }], manual=True))

    def remove_rule(self, rule: str) -> bool:
        storage_path = active_project_profile_path() if self.path == WHITELIST_PATH else self.path
        if not storage_path or not storage_path.exists():
            return False
        data = self._read_data()
        try:
            normalized = self.normalize_rule(rule)
        except ValueError:
            normalized = (rule or "").strip()
        old = list(data.get("rules") or [])
        remaining = [item for item in old if str(item.get("rule") or "") != normalized]
        if len(remaining) == len(old):
            return False
        data["rules"] = remaining
        data["manual"] = []
        self._write_data(data)
        self.reload()
        return True

    def remove_manual(self, rule: str) -> bool:
        return self.remove_rule(rule)

    def export_json(self, path: Path) -> None:
        """Write the current editable whitelist to a portable JSON backup."""
        data = self._read_data()
        data.pop("manual", None)
        atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    def restore_json(self, path: Path) -> int:
        """Replace all rules with a JSON backup created by this tool."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError("无法读取白名单 JSON 文件") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
            raise ValueError("白名单 JSON 文件格式无效")
        rules: list[dict] = []
        seen: set[str] = set()
        for item in [*(raw.get("rules") or []), *(raw.get("manual") or [])]:
            if not isinstance(item, dict):
                continue
            rule = self.normalize_rule(str(item.get("rule") or ""))
            key = rule.casefold()
            if key in seen:
                continue
            seen.add(key)
            rules.append({
                "rule": rule,
                "reason": str(item.get("reason") or "JSON 回滚"),
                "source": str(item.get("source") or "JSON 回滚"),
            })
        self._write_data({
            "version": 1,
            "description": str(raw.get("description") or "白名单"),
            "rules": rules,
        })
        self.reload()
        return len(rules)

    def _compile(self) -> None:
        compiled = []
        for item in self.rules:
            rule = str(item.get("rule", "")).strip()
            if not rule:
                continue
            reason = str(item.get("reason", "") or "")
            source = str(item.get("source", "") or "")
            try:
                if "-" in rule and "/" not in rule:
                    # 范围 a.b.c.d-e.f.g.h
                    a, b = [x.strip() for x in rule.split("-", 1)]
                    start = int(ipaddress.ip_address(a))
                    end = int(ipaddress.ip_address(b))
                    if start > end:
                        start, end = end, start
                    compiled.append({
                        "type": "range", "start": start, "end": end,
                        "rule": rule, "reason": reason, "source": source,
                    })
                elif "/" in rule:
                    net = ipaddress.ip_network(rule, strict=False)
                    compiled.append({
                        "type": "cidr", "network": net,
                        "rule": rule, "reason": reason, "source": source,
                    })
                else:
                    try:
                        ip = ipaddress.ip_address(rule)
                    except ValueError:
                        indicator = _normalize_indicator(rule)
                        if not _DOMAIN_RE.fullmatch(indicator):
                            continue
                        compiled.append({
                            "type": "indicator", "indicator": indicator,
                            "rule": rule, "reason": reason, "source": source,
                        })
                    else:
                        compiled.append({
                            "type": "ip", "ip": ip,
                            "rule": rule, "reason": reason, "source": source,
                        })
            except Exception:
                continue
        self._compiled = compiled

    def check(self, ip_str: str) -> MatchResult:
        ip_str = (ip_str or "").strip()
        if not ip_str:
            return MatchResult(False)
        normalized = _normalize_indicator(ip_str)
        for item in self._compiled:
            if item["type"] == "indicator" and normalized == item["indicator"]:
                return MatchResult(True, item["rule"], item["reason"], item["source"])
        try:
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            return MatchResult(False)
        n = int(ip)
        for item in self._compiled:
            t = item["type"]
            if t == "ip" and ip == item["ip"]:
                return MatchResult(True, item["rule"], item["reason"], item["source"])
            if t == "cidr" and ip in item["network"]:
                return MatchResult(True, item["rule"], item["reason"], item["source"])
            if t == "range" and item["start"] <= n <= item["end"]:
                return MatchResult(True, item["rule"], item["reason"], item["source"])
        return MatchResult(False)

    def check_any(self, ips: Iterable[str]) -> dict[str, MatchResult]:
        return {ip: self.check(ip) for ip in ips if ip}


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except Exception:
        return False
    return any(ip in n for n in _PRIVATE_NETS)


# 不用 \b：Python 把中文当 word char，会与 IP 粘连时匹配失败
_IP_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])"
)


def extract_ips(text: str) -> list[str]:
    if not text:
        return []
    seen = set()
    out = []
    for m in _IP_RE.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


@dataclass
class AllWhitelistResult:
    """日志中源IP/XFF/URL/目标IP 是否全部为白名单。"""
    all_whitelisted: bool
    has_ips: bool
    ips: list[str]
    matched: list[dict]  # {ip, rule, reason}
    unmatched: list[str]


@dataclass
class AlertWhitelistResult:
    """Role-aware whitelist decision used to decide whether to report."""

    has_attack_ip: bool
    skip_order: bool
    matched: list[dict]
    semi_matched: list[dict]
    unmatched: list[dict]


def check_alert_whitelist_gate(
    engine: WhitelistEngine,
    attack_ip: str = "",
    target_ip: str = "",
    xff: str = "",
    domain_url: str = "",
) -> AlertWhitelistResult:
    """Require all involved IP roles to pass before an alert is exempt.

    Editable whitelist entries pass in every role.  A known company internal
    subnet is only a semi-whitelist when it is the attack IP; the same address
    in target/victim/destination or XFF roles still needs an explicit whitelist
    entry.  Blank optional roles are neutral, while a missing attack IP never
    produces an automatic exemption.
    """
    from .default_whitelist import company_network_match

    roles = (
        ("攻击IP", extract_ips(attack_ip)),
        ("目标/受害/目的IP", extract_ips(target_ip)),
        ("XFF", extract_ips(xff)),
        ("域名/URL内IP", extract_ips(domain_url)),
    )
    domain_tokens = extract_indicators(domain_url)
    matched: list[dict] = []
    semi_matched: list[dict] = []
    unmatched: list[dict] = []
    for role, ips in roles:
        for ip in ips:
            result = engine.check(ip)
            if result.matched:
                matched.append({
                    "role": role, "ip": ip, "rule": result.rule,
                    "reason": result.reason,
                })
                continue
            company = company_network_match(ip) if role == "攻击IP" else None
            if company:
                semi_matched.append({
                    "role": role, "ip": ip, "rule": company.network,
                    "reason": company.department,
                })
            else:
                unmatched.append({"role": role, "ip": ip})
    for indicator in domain_tokens:
        result = engine.check(indicator)
        if result.matched:
            matched.append({"role": "IOC域名/URL", "ip": indicator, "rule": result.rule, "reason": result.reason})
        else:
            unmatched.append({"role": "IOC域名/URL", "ip": indicator})
    has_attack = bool(roles[0][1])
    return AlertWhitelistResult(
        has_attack_ip=has_attack,
        skip_order=has_attack and not unmatched,
        matched=matched,
        semi_matched=semi_matched,
        unmatched=unmatched,
    )


def collect_log_ips(
    attack_ip: str = "",
    target_ip: str = "",
    xff: str = "",
    domain_url: str = "",
    extra_text: str = "",
) -> list[str]:
    """汇总日志中的源IP、目标IP、XFF、URL内IP（去重保序）。"""
    chunks = [attack_ip, target_ip, xff, domain_url, extra_text]
    seen: set[str] = set()
    out: list[str] = []
    for chunk in chunks:
        for ip in extract_ips(chunk or ""):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def check_all_log_ips_whitelisted(
    engine: WhitelistEngine,
    attack_ip: str = "",
    target_ip: str = "",
    xff: str = "",
    domain_url: str = "",
    extra_text: str = "",
) -> AllWhitelistResult:
    """
    若日志中出现的各类 IP（源/攻击、XFF、URL、目标）全部命中白名单，
    则无需研判、不产出工单。
    """
    ips = collect_log_ips(attack_ip, target_ip, xff, domain_url, extra_text)
    if not ips:
        return AllWhitelistResult(False, False, [], [], [])
    matched: list[dict] = []
    unmatched: list[str] = []
    for ip in ips:
        r = engine.check(ip)
        if r.matched:
            matched.append({"ip": ip, "rule": r.rule, "reason": r.reason})
        else:
            unmatched.append(ip)
    return AllWhitelistResult(
        all_whitelisted=len(unmatched) == 0,
        has_ips=True,
        ips=ips,
        matched=matched,
        unmatched=unmatched,
    )
