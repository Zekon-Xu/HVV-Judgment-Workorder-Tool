"""Editable company network attribution library stored in the active project."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

try:
    import openpyxl
except ImportError:  # pragma: no cover
    openpyxl = None

from .default_whitelist import (
    DEFAULT_COMPANY_SOURCE,
    active_company_profile_path,
    current_company_rules,
)
from .io_utils import atomic_write_text


_THIRD_OCTET_RANGE = re.compile(
    r"(?<![\d.])(\d{1,3}\.\d{1,3})\.(\d{1,3})\.(?:0|[xX])\s*-\s*"
    r"(?:(\d{1,3}\.\d{1,3})\.)?(\d{1,3})\.(?:0|[xX])(?![\d.])"
)
_ABBREVIATED_RANGE = re.compile(
    r"(?<![\d.])(\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})(?![\d.])"
)
_IP_TOKEN = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}(?:\d{1,3}|[xX])(?:/\d{1,2})?(?![\d.])"
)


def normalize_company_network(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("公司网段不能为空")
    raw = re.sub(r"\.[xX](?=/|$)", ".0", raw)
    if "/" not in raw:
        address = ipaddress.ip_address(raw)
        parts = raw.split(".")
        if address.version == 4 and parts[-1] == "0":
            raw = f"{raw}/{'16' if parts[-2] == '0' else '24'}"
        else:
            raw = f"{raw}/{'32' if address.version == 4 else '128'}"
    return str(ipaddress.ip_network(raw, strict=False))


def _network_tokens(text: str) -> list[str]:
    value = text or ""
    expanded: list[str] = []
    spans: list[tuple[int, int]] = []
    for match in _THIRD_OCTET_RANGE.finditer(value):
        prefix, start, end_prefix, end = match.groups()
        if end_prefix and end_prefix != prefix:
            continue
        lo, hi = sorted((int(start), int(end)))
        if hi <= 255:
            expanded.extend(f"{prefix}.{octet}.0/24" for octet in range(lo, hi + 1))
            spans.append(match.span())
    for match in _ABBREVIATED_RANGE.finditer(value):
        prefix, start, end = match.groups()
        lo, hi = sorted((int(start), int(end)))
        if hi <= 255:
            expanded.extend(f"{prefix}.{octet}.0/24" for octet in range(lo, hi + 1))
            spans.append(match.span())
    chars = list(value)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    for match in _IP_TOKEN.finditer("".join(chars)):
        try:
            expanded.append(normalize_company_network(match.group(0)))
        except ValueError:
            continue
    return list(dict.fromkeys(expanded))


def _items_from_rows(rows: list[list[Any]], *, source: str) -> list[dict[str, str]]:
    if not rows:
        return []
    headers = [str(value or "").strip() for value in rows[0]]
    company_col = next((i for i, value in enumerate(headers) if "公司名称" in value), 0)
    short_col = next((i for i, value in enumerate(headers) if "简称" in value), company_col)
    network_col = next((i for i, value in enumerate(headers) if "网段" in value), len(headers) - 1)
    items: list[dict[str, str]] = []
    for row in rows[1:]:
        company = str(row[company_col] or "").strip() if company_col < len(row) else ""
        short = str(row[short_col] or "").strip() if short_col < len(row) else ""
        department = short or company
        network_text = str(row[network_col] or "") if network_col < len(row) else ""
        if not department or not network_text.strip():
            continue
        for network in _network_tokens(network_text):
            items.append({"rule": network, "reason": department, "source": source})
    return items


def extract_company_rules_from_file(path: str | Path) -> list[dict[str, str]]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"公司网段文件不存在：{path}")
    suffix = path.suffix.casefold()
    if suffix in {".xlsx", ".xlsm"}:
        if openpyxl is None:
            raise RuntimeError("缺少 openpyxl，无法读取公司网段 Excel")
        workbook = openpyxl.load_workbook(path, data_only=True, read_only=True)
        try:
            for sheet in workbook.worksheets:
                rows = [list(row) for row in sheet.iter_rows(values_only=True)]
                headers = [str(value or "").strip() for value in (rows[0] if rows else [])]
                if any("网段" in value for value in headers) and any(
                    "公司名称" in value or "简称" in value for value in headers
                ):
                    items = _items_from_rows(rows, source=f"公司网段导入:{sheet.title}")
                    if items:
                        return items
            raise ValueError("未找到包含“公司名称/简称/网段”表头的工作表")
        finally:
            workbook.close()
    if suffix == ".json":
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(raw, dict) and isinstance(raw.get("company_networks"), dict):
            raw = raw["company_networks"]
        rules = raw.get("rules") if isinstance(raw, dict) else None
        if not isinstance(rules, list):
            raise ValueError("公司网段 JSON 格式无效")
        return [item for item in rules if isinstance(item, dict)]

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    rows: list[list[Any]] = []
    if suffix in {".csv", ".tsv"}:
        dialect = csv.excel_tab if suffix == ".tsv" else csv.excel
        rows = [list(row) for row in csv.reader(text.splitlines(), dialect=dialect)]
        if rows and any("网段" in str(value) for value in rows[0]):
            return _items_from_rows(rows, source="公司网段导入")
    items: list[dict[str, str]] = []
    for line in text.splitlines():
        networks = _network_tokens(line)
        if not networks:
            continue
        department = line
        for token in networks:
            department = department.replace(token, "")
        department = re.sub(r"[\d./xX\-]+", " ", department).strip(" \t,，:：-|【】[]") or "文件导入"
        items.extend({"rule": rule, "reason": department, "source": "公司网段导入"} for rule in networks)
    return items


class CompanyNetworkStore:
    def _path(self) -> Path:
        path = active_company_profile_path()
        if not path:
            raise RuntimeError("当前没有可写的项目配置，请先加载或另存一个项目配置")
        return path

    def _profile(self) -> tuple[Path, dict[str, Any]]:
        path = self._path()
        profile = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(profile, dict):
            raise ValueError("当前项目配置格式无效")
        return path, profile

    def all_entries(self) -> list[dict[str, str]]:
        path = active_company_profile_path()
        if not path:
            return current_company_rules()
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
            data = profile.get("company_networks") or {}
            rules = data.get("rules") if isinstance(data, dict) else None
            if isinstance(rules, list):
                return [dict(item) for item in rules if isinstance(item, dict)]
        except (OSError, ValueError, TypeError):
            pass
        return current_company_rules()

    def _write(self, rules: list[dict[str, str]]) -> None:
        path, profile = self._profile()
        profile["company_networks"] = {
            "version": 1,
            "description": "工单涉及的内网部门判断库（仅用于归属判断，不是白名单）",
            "source": DEFAULT_COMPANY_SOURCE,
            "rules": rules,
        }
        atomic_write_text(path, json.dumps(profile, ensure_ascii=False, indent=2) + "\n")

    def merge_rules(self, items: list[dict[str, str]], *, source: str = "公司网段导入") -> int:
        rules = self.all_entries()
        known = {normalize_company_network(str(item.get("rule") or "")) for item in rules}
        added = 0
        for item in items:
            network = normalize_company_network(str(item.get("rule") or ""))
            if network in known:
                continue
            department = str(item.get("reason") or item.get("department") or "").strip()
            if not department:
                raise ValueError(f"{network} 缺少部门名称")
            rules.append({
                "rule": network,
                "reason": department,
                "source": str(item.get("source") or source),
            })
            known.add(network)
            added += 1
        if added:
            self._write(rules)
        return added

    def add(self, network: str, department: str) -> bool:
        return bool(self.merge_rules([{
            "rule": network, "reason": department, "source": "公司网段手动",
        }], source="公司网段手动"))

    def remove(self, network: str) -> bool:
        normalized = normalize_company_network(network)
        rules = self.all_entries()
        remaining = [item for item in rules if normalize_company_network(str(item.get("rule") or "")) != normalized]
        if len(remaining) == len(rules):
            return False
        self._write(remaining)
        return True

    def remove_many(self, networks: list[str] | set[str]) -> int:
        normalized = {normalize_company_network(value) for value in networks if str(value).strip()}
        rules = self.all_entries()
        remaining = [
            item for item in rules
            if normalize_company_network(str(item.get("rule") or "")) not in normalized
        ]
        removed = len(rules) - len(remaining)
        if removed:
            self._write(remaining)
        return removed

    def export_json(self, path: Path) -> None:
        payload = {
            "version": 1,
            "description": "公司内网部门判断库（不是白名单）",
            "rules": self.all_entries(),
        }
        atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def restore_json(self, path: Path) -> int:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(raw, dict) and isinstance(raw.get("company_networks"), dict):
            raw = raw["company_networks"]
        items = raw.get("rules") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            raise ValueError("公司网段 JSON 格式无效")
        rules: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            network = normalize_company_network(str(item.get("rule") or ""))
            department = str(item.get("reason") or item.get("department") or "").strip()
            if not department or network in seen:
                continue
            seen.add(network)
            rules.append({
                "rule": network,
                "reason": department,
                "source": str(item.get("source") or "公司网段JSON回滚"),
            })
        self._write(rules)
        return len(rules)
