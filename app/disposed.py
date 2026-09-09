"""已处置攻击 IP 索引与批量过滤。"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Iterable

from .constants import CONFIG_DIR
from .whitelist import parse_batch_ips, extract_ips

try:
    import openpyxl
except ImportError:  # pragma: no cover
    openpyxl = None


DISPOSED_IPS_PATH = CONFIG_DIR / "disposed_ips.json"


def load_disposed_ips(path: Path | None = None) -> set[str]:
    """Load the generated index and return normalized IPv4/IPv6 strings."""
    target = path or DISPOSED_IPS_PATH
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    values = (
        [*(payload.get("ips") or []), *(payload.get("manual_ips") or [])]
        if isinstance(payload, dict)
        else payload
    )
    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    for value in values:
        try:
            result.add(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    return result


def disposed_ips_from_records(records: Iterable[dict]) -> set[str]:
    """Extract IPs from tracking records whose disposition explicitly says block."""
    result: set[str] = set()
    for record in records or []:
        values = [
            record.get("reason"),
            record.get("disposition"),
            record.get("处置建议"),
            record.get("处置建议修订结果"),
            record.get("raw_result"),
            record.get("all_fields"),
        ]
        text = json.dumps(values, ensure_ascii=False) if any(isinstance(v, (dict, list)) for v in values) else " ".join(str(v or "") for v in values)
        if "封禁" not in text:
            continue
        for ip in extract_ips(text):
            try:
                result.add(str(ipaddress.ip_address(ip)))
            except ValueError:
                pass
    return result


def extract_disposed_ips_from_xlsx(path: str | Path) -> tuple[set[str], int, int]:
    """Rebuild the disposed-IP set from the latest tracking workbook.

    Only rows whose ``处置建议`` contains ``封禁`` are included. The return
    value is ``(ips, matching_rows, sheet_count)`` so callers can persist
    provenance and display an auditable refresh summary.
    """
    if openpyxl is None:
        raise RuntimeError("缺少 openpyxl，无法读取已处置 IP 索引")
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"告警跟踪表不存在: {source}")
    ips: set[str] = set()
    matched_rows = 0
    sheets: set[str] = set()
    workbook = openpyxl.load_workbook(source, read_only=True, data_only=True)
    try:
        for sheet in workbook.worksheets:
            rows = sheet.iter_rows(values_only=True)
            header = None
            indexes: dict[str, int] = {}
            for raw in rows:
                values = [str(value or "").strip() for value in raw]
                if header is None:
                    if "攻击IP" in values and "编号" in values:
                        header = values
                        indexes = {label: i for i, label in enumerate(values) if label}
                    continue
                if header is None:
                    continue
                position = indexes.get("处置建议")
                reason = values[position] if position is not None and position < len(values) else ""
                if "封禁" not in reason:
                    continue
                found = extract_ips(reason)
                if not found:
                    continue
                matched_rows += 1
                sheets.add(str(sheet.title))
                ips.update(found)
    finally:
        workbook.close()
    return ips, matched_rows, len(sheets)


def refresh_disposed_index(path: str | Path, *, manual_ips: Iterable[str] = ()) -> dict:
    """Rebuild and persist the Excel-derived index while retaining manual IPs."""
    source = Path(path)
    excel_ips, rows, sheets = extract_disposed_ips_from_xlsx(source)
    normalized_manual: set[str] = set()
    for value in manual_ips:
        try:
            normalized_manual.add(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    payload = {
        "version": 1,
        "description": "告警跟踪表中处置建议明确包含“封禁”的去重 IP 索引",
        "source": str(source),
        "match_rule": "处置建议字段包含“封禁”",
        "record_count": rows,
        "sheet_count": sheets,
        "ip_count": len(excel_ips | normalized_manual),
        "ips": sorted(excel_ips | normalized_manual, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))),
        "manual_ips": sorted(normalized_manual, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))),
    }
    DISPOSED_IPS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DISPOSED_IPS_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def filter_disposed_ips(text: str, disposed: set[str]) -> dict[str, list]:
    """Parse a pasted batch and split it into disposed and pending IPs."""
    ips, invalid = parse_batch_ips(text)
    hit = [ip for ip in ips if ip in disposed]
    pending = [ip for ip in ips if ip not in disposed]
    return {"ips": ips, "disposed": hit, "pending": pending, "invalid": invalid}
