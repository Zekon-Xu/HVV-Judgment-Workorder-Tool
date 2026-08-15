"""从文本 / 图片 / 网页文件提取告警字段"""

from __future__ import annotations

import csv
import email
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .constants import ATTACK_TYPE_HINTS, MONITOR_SOURCE_IP
from .order_builder import normalize_event_level
from .whitelist import extract_indicators, extract_ips, is_private_ip

try:
    import openpyxl
except ImportError:  # pragma: no cover
    openpyxl = None

SPREADSHEET_EXTS = {".xlsx", ".xlsm", ".xltx", ".xltm", ".xls"}

# 全角/OCR 噪声修正
_OCR_FIXES = [
    (r"[．。·•]", "."),
    (r"[：:]", ":"),
    (r"[，,]", ","),
    (r"甲", "IP"),
    (r"源IP|源IP|源ip|源1P|源lP", "源IP"),
    (r"目的IP|目的ip|目的1P|目的lP|目的》P", "目的IP"),
    (r"2S4", "254"),
    (r"1S8", "168"),
    (r"S(\d)", r"5\1"),
    (r"暴力猎解", "暴力猜解"),
    (r"扫号攻击", "扫号攻击"),
    (r"命令注入攻击[（(]通用[)）]", "命令注入攻击(通用)"),
    (r"目录遍历攻击[（(]通用[)）]", "目录遍历攻击(通用)"),
]


DEFAULT_FIELD_ALIASES: dict[str, list[str]] = {
    "time": ["时间", "告警时间", "发生时间", "事件时间", "检测时间", "timestamp", "event_time", "alert_time"],
    "attack_ip": [
        "攻击IP", "源IP", "源地址", "源地址IP", "攻击者", "攻击者IP",
        "src_ip", "source_ip", "client_ip", "remote_ip",
    ],
    "target_ip": [
        "目标IP", "目的IP", "目的地址", "目的地址IP", "受害者", "受害IP",
        "dst_ip", "dest_ip", "destination_ip", "server_ip",
    ],
    "xff": ["XFF", "X-Forwarded-For", "x_forwarded_for", "forwarded_for", "xff_ip"],
    "domain_url": [
        "域名URL", "域名", "URL", "URI", "IOC/URI", "请求URL", "请求地址", "访问地址", "资源",
        "request_url", "request_uri", "url", "uri", "domain", "host", "IOC", "IOC域名",
    ],
    "alert_level": ["告警级别", "危害等级", "威胁等级", "风险等级", "severity", "risk_level", "alert_level"],
    "attack_name": ["攻击名称", "规则名称", "告警名称", "威胁名称", "事件名称", "signature", "rule_name", "alert_name"],
    "event_type": ["事件类型", "攻击类型", "威胁类型", "category", "event_type", "attack_type"],
    "event_level": ["事件等级", "event_level"],
    "attack_result": ["攻击结果", "失陷状态", "处置结果", "result", "attack_result", "compromise_status"],
    "data_source_ip": ["数据源IP", "设备IP", "探针IP", "平台IP", "sensor_ip", "device_ip"],
}


def _field_aliases(
    key: str,
    custom_aliases: dict[str, Any] | None = None,
) -> list[str]:
    aliases = list(DEFAULT_FIELD_ALIASES.get(key, []))
    custom = (custom_aliases or {}).get(key, [])
    if isinstance(custom, str):
        custom = [custom]
    if isinstance(custom, list):
        aliases.extend(str(item).strip() for item in custom if str(item).strip())
    seen: set[str] = set()
    result: list[str] = []
    for alias in aliases:
        folded = alias.casefold()
        if folded not in seen:
            seen.add(folded)
            result.append(alias)
    return result


def _label_pattern(labels: list[str]) -> str:
    return "(?:" + "|".join(re.escape(label) for label in sorted(labels, key=len, reverse=True)) + ")"


def _labeled_text_value(
    labels: list[str],
    text: str,
    *,
    max_length: int = 240,
) -> str:
    """Read label/value pairs from plain lines, flattened tables, JSON, or HTML text."""
    if not labels or not text:
        return ""
    label = _label_pattern(labels)
    same_line = re.compile(
        rf"(?im)^[ \t]*[\"']?{label}[\"']?[ \t]*(?::|：|=|\t+|[ ]{{2,}})[ \t]*([^\n\r]*)$"
    )
    for match in same_line.finditer(text):
        value = _clean_field_value(match.group(1))[:max_length]
        if value:
            return value

    # WAF, IDS, and proxy products often emit one complete event on one line,
    # such as ``src_ip=1.2.3.4 dst_ip=10.0.0.5``.  These key/value pairs are
    # deterministic structured data and should work without an AI request.
    for alias in sorted(labels, key=len, reverse=True):
        escaped = re.escape(alias)
        inline = re.compile(
            rf"(?i)(?<![\w.-]){escaped}\s*(?:[:=：])\s*"
            rf"(.*?)(?=(?:[,;|]|\s+)\s*[A-Za-z_][\w.-]*\s*(?:[:=：])|$)"
        )
        for match in inline.finditer(text):
            value = _clean_field_value(match.group(1))[:max_length]
            if value:
                return value

    lines = [line.strip() for line in text.replace("\r", "\n").split("\n")]
    exact = re.compile(rf"^[\"']?{label}[\"']?[ \t]*(?::|：|=)?[ \t]*$", re.I)
    all_labels = _label_pattern(
        [alias for values in DEFAULT_FIELD_ALIASES.values() for alias in values]
    )
    another_label = re.compile(rf"^[\"']?{all_labels}[\"']?[ \t]*(?::|：|=)?[ \t]*$", re.I)
    for index, line in enumerate(lines):
        if not exact.fullmatch(line):
            continue
        for candidate in lines[index + 1 : index + 4]:
            if not candidate:
                continue
            if another_label.fullmatch(candidate):
                break
            return _clean_field_value(candidate)[:max_length]
    return ""


def normalize_ocr_text(text: str) -> str:
    if not text:
        return ""
    # 只去掉同行内中文/英文间多余空格，绝不吞掉换行（避免字段粘连）
    t = re.sub(r"(?<=[\u4e00-\u9fff])[ \t]+(?=[\u4e00-\u9fff])", "", text)
    t = re.sub(r"(?<=[\u4e00-\u9fff])[ \t]+(?=[A-Za-z0-9])", "", t)
    t = re.sub(r"(?<=[A-Za-z0-9])[ \t]+(?=[\u4e00-\u9fff])", "", t)
    for pat, rep in _OCR_FIXES:
        t = re.sub(pat, rep, t)
    # 仅修复日期数字之间被识别成“一”的连接符，不能全局替换中文“一”。
    t = re.sub(r"(?<=\d)一(?=\d)", "-", t)
    # 修复被拆开的 IP: 10. 209. 193. 101
    t = re.sub(
        r"(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})\s*\.\s*(\d{1,3})",
        r"\1.\2.\3.\4",
        t,
    )
    return t


@dataclass
class ExtractedAlert:
    time: str = ""
    attack_ip: str = ""
    target_ip: str = ""
    xff: str = ""
    domain_url: str = ""
    alert_level: str = "高危"
    attack_name: str = ""
    event_type: str = ""
    event_level: str = "五级"
    attack_result: str = "失败"
    is_whitelist: str = "否"
    raw_text: str = ""
    ai_output: str = ""
    template_fields: dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _first_group(patterns: list[str], text: str, flags: int = re.I) -> str:
    for p in patterns:
        m = re.search(p, text, flags)
        if m:
            return (m.group(1) if m.lastindex else m.group(0)).strip()
    return ""


def _normalize_level(raw: str) -> str:
    s = (raw or "").strip()
    folded = s.casefold()
    if not s:
        return "高危"
    if any(k in s for k in ("危急", "紧急", "严重", "超危")) or "critical" in folded:
        return "高危"
    if "高" in s or folded == "high":
        return "高危"
    if "中" in s or folded in {"medium", "middle"}:
        return "中危"
    if "低" in s or folded == "low":
        return "低危"
    return "高危"


def _normalize_result(raw: str) -> str:
    s = (raw or "").strip()
    folded = s.casefold()
    if not s:
        return "失败"
    if any(k in s for k in ("成功", "失陷", "已成功", "利用成功")) or "success" in folded:
        # 排除“未成功”
        if any(k in s for k in ("未成功", "不成功", "失败", "企图", "尝试")):
            return "失败"
        return "成功"
    if any(k in s for k in ("企图", "尝试", "失败", "未成功", "攻击失败", "真实攻击未成功")) or any(
        k in folded for k in ("false", "fail", "blocked", "attempt")
    ):
        return "失败"
    return "失败"


def _clean_field_value(value: str) -> str:
    """截断串行字段，避免 OCR/粘贴把下一列拼进来。"""
    value = (value or "").strip()
    if not value:
        return ""
    value = re.split(
        r"(?:攻击结果|事件类型|事件等级|告警级别|危害等级|是否白名单|处置建议|监测来源|攻击IP|目标IP|源IP|目的IP|XFF|域名URL|规则名称)[:：]",
        value,
        maxsplit=1,
    )[0].strip()
    return value.rstrip("，,;；|")


def _guess_attack(
    text: str,
    field_aliases: dict[str, Any] | None = None,
) -> tuple[str, str]:
    # 明确字段优先，避免关键词映射覆盖平台给出的真实攻击名称。
    name = _labeled_text_value(
        _field_aliases("attack_name", field_aliases), text, max_length=80
    )
    if not name:
        name = _clean_field_value(_first_group(
            [
                # 平台标题：2065894-目录遍历攻击(通用)
                r"(?m)^\s*\d{4,8}\s*[-_]\s*([A-Za-z\u4e00-\u9fff][^\n\r]{1,79})",
                r"(SSH暴力破解攻击|HTTP扫号攻击|命令注入攻击(?:\(通用\))?|目录遍历攻击(?:\(通用\))?|跨站脚本攻击（XSS）|PHP代码执行攻击|网络探针检测到高频攻击源|黑客工具Nmap扫描器)",
            ],
            text,
        ))
    etype = _labeled_text_value(
        _field_aliases("event_type", field_aliases), text, max_length=40
    )
    if name and not etype:
        for pat, n, t in ATTACK_TYPE_HINTS:
            if n in name or re.search(pat, name, re.I):
                etype = t
                break
    if name:
        return name, etype
    for pat, mapped_name, mapped_type in ATTACK_TYPE_HINTS:
        if re.search(pat, text, re.I):
            return mapped_name, etype or mapped_type
    return name, etype


_OFFLINE_ATTACK_EVIDENCE: tuple[tuple[str, str, str], ...] = (
    (r"(?i)(?:\bunion\s+(?:all\s+)?select\b|\bsleep\s*\(|\bbenchmark\s*\(|\bor\s+1\s*=\s*1\b|\bsqli\b|sql(?:\s|-)?injection)", "SQL注入攻击", "SQL注入"),
    (r"(?i)(?:\.\./|%2e%2e(?:%2f|/)|/etc/passwd|/proc/self/environ|path(?:\s|-)?traversal)", "目录遍历攻击(通用)", "目录遍历"),
    (r"(?i)(?:\b(?:cmd|command)\s*(?:=|:)|\b(?:wget|curl|powershell|whoami)\b|\$\{jndi:|\blog4shell\b|remote(?:\s|-)?code(?:\s|-)?execution|\brce\b)", "命令注入攻击(通用)", "命令执行"),
    (r"(?i)(?:<script\b|%3cscript|javascript:|\bonerror\s*=|\bxss\b)", "跨站脚本攻击(XSS)", "跨站脚本注入攻击"),
    (r"(?i)(?:\b(?:password|passwd|pwd)=|\blogin\b.*\b(?:fail|failed|invalid)\b|\bbrute[ -]?force\b|credential[ -]?stuff)", "SSH暴力破解攻击", "暴力破解"),
    (r"(?i)(?:\bnmap\b|\bmasscan\b|\bport(?:\s|-)?scan\b|\bscan\s+ports?\b)", "黑客工具Nmap扫描器", "工具扫描"),
    (r"(?i)(?:\bfile(?:\s|-)?upload\b|multipart/form-data|filename\s*=)", "文件上传攻击", "文件上传"),
    (r"(?i)(?:\bssrf\b|(?:url|uri|target)\s*=\s*https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254))", "SSRF攻击", "SSRF"),
    (r"(?i)(?:\.git/(?:config|head)|\.env\b|/wp-config\.php|/\.aws/credentials|sensitive(?:\s|-)?file)", "敏感文件探测", "信息泄露"),
)


def _infer_attack_from_evidence(text: str, current_name: str, current_type: str) -> tuple[str, str]:
    """Infer a conservative label from verifiable text/HTML evidence only."""
    generic_names = {"", "HTTP扫描攻击", "Web攻击", "未知攻击", "Unknown"}
    for pattern, name, event_type in _OFFLINE_ATTACK_EVIDENCE:
        if re.search(pattern, text):
            return (
                name if current_name in generic_names else current_name,
                current_type or event_type,
            )
    return current_name, current_type


def _pick_time(text: str, field_aliases: dict[str, Any] | None = None) -> str:
    labeled = _labeled_text_value(
        _field_aliases("time", field_aliases), text, max_length=80
    )
    search_text = labeled or text
    m = re.search(
        r"(20\d{2})[-/年](\d{1,2})[-/月](\d{1,2})[日T\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?",
        search_text,
    )
    if m:
        y, mo, d, h, mi, se = m.groups()
        se = se or "00"
        return f"{int(y):04d}-{int(mo):02d}-{int(d):02d} {int(h):02d}:{int(mi):02d}:{int(se):02d}"
    m = re.search(r"(20\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", search_text)
    return m.group(1) if m else ""


def _pick_url(text: str, field_aliases: dict[str, Any] | None = None) -> str:
    labels = _field_aliases("domain_url", field_aliases)
    fallback = ""

    def candidate(value: str) -> str:
        cleaned = _clean_field_value(value)[:240].rstrip(").,，；;")
        if not cleaned:
            return ""
        # Preserve a complete URL in the automatic recognition field.
        if re.search(r"https?://", cleaned, re.I):
            url = re.search(r"https?://[^\s,，;；|]+", cleaned, re.I)
            return url.group(0).rstrip(").,，；;") if url else cleaned
        # For IOC/URI values, normalize a bare host to the host itself.
        if extract_indicators(cleaned):
            return extract_indicators(cleaned)[0]
        return ""

    labeled = _labeled_text_value(labels, text, max_length=240)
    if labeled:
        value = candidate(labeled)
        if value:
            return value
        fallback = labeled.rstrip(").,，；;")

    # _labeled_text_value returns the first matching label. Inspect every
    # IOC/URI/domain-labelled value too, because an earlier ``URI: /path``
    # must not hide a later ``IOC: bad.example``.
    label = _label_pattern(labels)
    labelled_value = re.compile(
        rf"(?im)^[ \t]*[\"']?{label}[\"']?[ \t]*(?::|：|=|\t+|[ ]{{2,}})?[ \t]*(?:\r?\n[ \t]*)?([^\n\r]*)$"
    )
    for match in labelled_value.finditer(text):
        value = candidate(match.group(1))
        if value:
            return value
    # 优先完整 URL
    m = re.search(r"https?://[^\s\"'<>]+", text, re.I)
    if m:
        return m.group(0).rstrip(").,，；;")

    # A bare domain may appear after an unlabelled OCR line such as
    # ``IOC类型 / 域名 / IOC / example.org``.
    indicators = extract_indicators(text)
    if indicators:
        return indicators[0]
    m = re.search(
        r"(?:域名URL|URI|URL|请求URL|资源)[:：\t ]*([^\n\r]{3,200})",
        text,
        re.I,
    )
    if m:
        u = m.group(1).strip()
        u = re.split(r"\s{2,}|告警|攻击|源IP|目的", u)[0].strip()
        return u
    # 常见恶意路径
    m = re.search(r"(/[A-Za-z0-9_\-./%?=&:;]{8,160})", text)
    if m:
        return m.group(1)
    return fallback if fallback.startswith("/") else ""


def _labeled_ip_value(labels: list[str], text: str) -> str:
    """
    读取「标签: 值」或「标签\\n值」两种排版下的 IP 字段。
    注意：不要把「数据源IP」误当成「源IP」。
    """
    direct = _labeled_text_value(labels, text, max_length=300)
    found = extract_ips(direct)
    if found:
        return found[0]
    for lab in labels:
        lab_re = re.escape(lab)
        # 同行：源IP：10.1.1.1  / 源IP 10.1.1.1
        pat_same = rf"(?m)^[ \t]*{lab_re}[ \t]*[:：]?[ \t]*([^\n\r]+)$"
        m = re.search(pat_same, text, re.I)
        if m:
            found = extract_ips(m.group(1))
            if found:
                return found[0]
            # 同行无 IP，可能值在下一行
        # 下一行：源IP\n10.1.1.1
        pat_next = rf"(?m)^[ \t]*{lab_re}[ \t]*[:：]?[ \t]*\r?\n[ \t]*([^\n\r]+)$"
        m = re.search(pat_next, text, re.I)
        if m:
            found = extract_ips(m.group(1))
            if found:
                return found[0]
        # 宽松：标签后紧跟 IP（可跨一行）
        pat_loose = (
            rf"(?m)(?:^|[\n\r])[ \t]*{lab_re}[ \t]*[:：]?[ \t]*(?:\r?\n[ \t]*)?"
            rf"((?:\d{{1,3}}\.){{3}}\d{{1,3}}(?:\s*[,，、]\s*(?:\d{{1,3}}\.){{3}}\d{{1,3}})*)"
        )
        m = re.search(pat_loose, text, re.I)
        if m:
            found = extract_ips(m.group(1))
            if found:
                return found[0]
    return ""


def _classify_ips(
    ips: list[str],
    text: str,
    field_aliases: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    """返回 attack_ip, target_ip, xff（严格区分源/目的，避免写成同一个）。"""
    if not ips:
        return "", "", ""

    # 优先：攻击者/受害者、攻击IP/目标IP；源IP 用 (?!…) 避免命中「数据源IP」——用行首标签匹配
    atk = _labeled_ip_value(_field_aliases("attack_ip", field_aliases), text)
    # 若误匹配到数据源IP 行，下面会用 数据源IP 单独排除
    data_src = _labeled_ip_value(_field_aliases("data_source_ip", field_aliases), text)
    tgt = _labeled_ip_value(_field_aliases("target_ip", field_aliases), text)
    xff = _labeled_ip_value(_field_aliases("xff", field_aliases), text)

    # 数据源IP 不应作为攻击IP（监测设备）
    if atk and data_src and atk == data_src:
        atk = ""
    if atk and data_src:
        atk_list = [i for i in extract_ips(atk) if i not in extract_ips(data_src)]
        if atk_list:
            atk = ", ".join(atk_list)

    # 攻击与目标不能相同：若相同则清空较弱一侧重判
    if atk and tgt and atk == tgt:
        # 保留攻击侧，重找目标
        tgt = ""

    if atk and tgt:
        return atk, tgt, xff

    # 按文中出现顺序：源类标签后的第一个 IP、目的类标签后的第一个 IP
    ordered = list(ips)
    # 去掉数据源 IP 优先干扰
    data_ips = set(extract_ips(data_src)) if data_src else set()
    data_ips.update(MONITOR_SOURCE_IP.values())
    role_ordered = [i for i in ordered if i not in data_ips] or ordered

    if not atk:
        # 优先公网；否则取有序列表中第一个非目标
        public = [i for i in role_ordered if not is_private_ip(i)]
        if public:
            atk = public[0]
        elif role_ordered:
            atk = role_ordered[0]

    if not tgt:
        atk_set = set(extract_ips(atk))
        # 优先：第二个不同 IP；再：内网中不同于攻击的
        for i in role_ordered:
            if i not in atk_set:
                tgt = i
                break
        if not tgt:
            private = [i for i in role_ordered if is_private_ip(i) and i not in atk_set]
            if private:
                tgt = private[0]

    # 仍相同则目标置空，避免错误写成同一个
    if atk and tgt and atk == tgt:
        others = [i for i in role_ordered if i != atk]
        tgt = others[0] if others else ""

    return atk, tgt, xff


def parse_text(
    text: str,
    source_file: str = "",
    field_aliases: dict[str, Any] | None = None,
) -> ExtractedAlert:
    raw = text or ""
    text = normalize_ocr_text(raw)
    alert = ExtractedAlert(raw_text=text, source_file=source_file)

    # 若原文本身已是工单格式
    if "编号：" in text and "监测来源：" in text:
        alert.time = _first_group([r"时间[:：\t ]*([^\n\r]+)"], text)
        alert.attack_ip = _first_group([r"攻击IP[:：\t ]*([^\n\r]*)"], text)
        alert.target_ip = _first_group([r"目标IP[:：\t ]*([^\n\r]*)"], text)
        alert.xff = _first_group([r"XFF[:：\t ]*([^\n\r]*)"], text)
        alert.domain_url = _first_group([r"域名URL[:：\t ]*([^\n\r]*)"], text)
        alert.alert_level = _normalize_level(_first_group([r"告警级别[:：\t ]*([^\n\r]*)"], text))
        alert.attack_name = _first_group([r"攻击名称[:：\t ]*([^\n\r]*)"], text)
        alert.event_type = _first_group([r"事件类型[:：\t ]*([^\n\r]*)"], text)
        lvl = _first_group([r"事件等级[:：\t ]*([^\n\r]*)"], text)
        alert.event_level = normalize_event_level(lvl)
        alert.attack_result = _normalize_result(_first_group([r"攻击结果[:：\t ]*([^\n\r]*)"], text))
        wl = _first_group([r"是否白名单[:：\t ]*([^\n\r]*)"], text)
        alert.is_whitelist = "是" if wl.startswith("是") else "否"
        advice = _first_group([r"处置(?:建议|意见)[:：\t ]*([^\n\r]*)"], text)
        if advice:
            alert.notes.append(f"AI_ADVICE::{advice}")
        return alert

    alert.time = _pick_time(text, field_aliases)
    ips = extract_ips(text)
    alert.attack_ip, alert.target_ip, alert.xff = _classify_ips(ips, text, field_aliases)
    alert.domain_url = _pick_url(text, field_aliases)

    level_raw = _labeled_text_value(
        _field_aliases("alert_level", field_aliases), text, max_length=20
    )
    if not level_raw:
        level_raw = _first_group([r"(高危|中危|低危|危急|critical|high|medium|low)"], text)
    alert.alert_level = _normalize_level(level_raw)

    name, etype = _guess_attack(text, field_aliases)
    name, etype = _infer_attack_from_evidence(text, name, etype)
    alert.attack_name = name
    alert.event_type = etype

    result_raw = _labeled_text_value(
        _field_aliases("attack_result", field_aliases), text, max_length=30
    )
    if not result_raw:
        result_raw = _first_group(
            [r"(失败|成功|企图|未成功|真实攻击未成功|success|failed?|blocked)"], text
        )
    alert.attack_result = _normalize_result(result_raw)

    event_level_raw = _labeled_text_value(
        _field_aliases("event_level", field_aliases), text, max_length=20
    )
    if event_level_raw:
        alert.event_level = normalize_event_level(event_level_raw)

    if not alert.attack_name:
        alert.notes.append("未能可靠识别攻击名称，请手工确认")
    recognized = [
        label
        for label, value in (
            ("时间", alert.time),
            ("攻击IP", alert.attack_ip),
            ("目标IP", alert.target_ip),
            ("XFF", alert.xff),
            ("域名URL", alert.domain_url),
            ("攻击名称", alert.attack_name),
            ("事件类型", alert.event_type),
        )
        if value
    ]
    alert.notes.append(
        "本地规则命中：" + ("、".join(recognized) if recognized else "无明确字段")
    )
    return alert


def _html_to_local_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        # Dashboard exports frequently put the alert payload in an
        # application/json script tag.  Keep and flatten only that structured
        # data; executable scripts and styles are intentionally ignored.
        embedded_json: list[str] = []
        for tag in soup.find_all("script"):
            kind = str(tag.get("type") or "").casefold()
            raw_json = tag.get_text("", strip=True)
            if kind in {"application/json", "application/ld+json"} and raw_json:
                try:
                    embedded_json.extend(_flatten_json(json.loads(raw_json)))
                except Exception:
                    pass
            tag.decompose()
        for tag in soup(["style", "noscript"]):
            tag.decompose()
        table_rows: list[str] = []
        for row in soup.select("tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.select("th,td")]
            cells = [cell for cell in cells if cell]
            if len(cells) >= 2:
                table_rows.append(f"{cells[0]}: {' '.join(cells[1:])}")
        body = soup.get_text("\n", strip=True)
        parts = table_rows + embedded_json + ([body] if body else [])
        return "\n".join(parts)
    except Exception:
        return re.sub(r"<[^>]+>", "\n", html)


def parse_html_file(
    path: str | Path,
    field_aliases: dict[str, Any] | None = None,
) -> ExtractedAlert:
    path = Path(path)
    if path.suffix.lower() in {".mhtml", ".mht"}:
        message = email.message_from_bytes(path.read_bytes())
        html_parts = []
        for part in message.walk():
            if part.get_content_type() != "text/html":
                continue
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            html_parts.append(payload.decode(charset, errors="ignore"))
        html = "\n".join(html_parts)
    else:
        html = _read_text_file(path)
    text = _html_to_local_text(html)
    alert = parse_text(text, source_file=str(path), field_aliases=field_aliases)
    return alert


def _flatten_json(value: Any, prefix: str = "") -> list[str]:
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_prefix = str(key) if not prefix else f"{prefix}.{key}"
            lines.extend(_flatten_json(item, child_prefix))
    elif isinstance(value, list):
        for index, item in enumerate(value[:20]):
            lines.extend(_flatten_json(item, prefix or str(index)))
    elif prefix and value is not None:
        lines.append(f"{prefix}: {value}")
        leaf = prefix.rsplit(".", 1)[-1]
        if leaf != prefix:
            lines.append(f"{leaf}: {value}")
    return lines


def _spreadsheet_to_text(path: Path) -> str:
    """Convert workbook rows to labelled text so local and AI paths agree."""
    if openpyxl is None:
        raise RuntimeError("缺少 openpyxl，无法读取 Excel 文件")
    if path.suffix.lower() == ".xls":
        raise RuntimeError("旧版 .xls 暂不支持，请另存为 .xlsx")
    workbook = openpyxl.load_workbook(path, data_only=True, read_only=True)
    lines: list[str] = []
    try:
        for sheet in workbook.worksheets:
            normalized_rows: list[list[str]] = []
            for row in sheet.iter_rows(values_only=True):
                values = [str(value).strip() if value is not None else "" for value in row]
                while values and not values[-1]:
                    values.pop()
                if not values or not any(values):
                    continue
                normalized_rows.append(values)
                if len(normalized_rows) >= 501:
                    break
            if not normalized_rows:
                continue
            known_labels = {
                alias.casefold()
                for aliases in DEFAULT_FIELD_ALIASES.values()
                for alias in aliases
            }
            key_value_rows = sum(
                1 for row in normalized_rows[:20]
                if len(row) >= 2 and row[0].strip().casefold() in known_labels
            )
            sheet_lines: list[str] = []
            if key_value_rows >= 2:
                for row in normalized_rows:
                    if len(row) >= 2 and row[0]:
                        sheet_lines.append(f"{row[0]}: {' '.join(value for value in row[1:] if value)}")
                    else:
                        sheet_lines.append(" | ".join(value for value in row if value))
            else:
                headers = normalized_rows[0]
                header_like = any(
                    value.casefold() in known_labels
                    or re.search(r"IP|时间|攻击|告警|事件|URL|XFF", value, re.I)
                    for value in headers
                )
                body_rows = normalized_rows[1:] if header_like else normalized_rows
                for row in body_rows:
                    if header_like:
                        fields = [
                            f"{headers[i]}: {value}"
                            for i, value in enumerate(row)
                            if value and i < len(headers) and headers[i]
                        ]
                        if fields:
                            sheet_lines.append("；".join(fields))
                    else:
                        sheet_lines.append(" | ".join(value for value in row if value))
            if sheet_lines:
                lines.append(f"工作表：{sheet.title}")
                lines.extend(sheet_lines)
    finally:
        workbook.close()
    return "\n".join(lines)


def _structured_text_file(path: Path) -> str:
    raw = _read_text_file(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return "\n".join(_flatten_json(json.loads(raw))) or raw
        except Exception:
            return raw
    if suffix in {".csv", ".tsv"}:
        try:
            sample = raw[:8192]
            dialect = csv.excel_tab if suffix == ".tsv" else csv.Sniffer().sniff(sample, delimiters=",;\t|")
            rows = list(csv.reader(io.StringIO(raw), dialect=dialect))
            if not rows:
                return raw
            headers = [cell.strip() for cell in rows[0]]
            lines: list[str] = []
            for row in rows[1:501]:
                fields = [
                    f"{headers[i]}: {value.strip()}"
                    for i, value in enumerate(row)
                    if value.strip() and i < len(headers) and headers[i]
                ]
                lines.append("；".join(fields) if fields else " | ".join(cell.strip() for cell in row if cell.strip()))
            return "\n".join(lines) or raw
        except Exception:
            return raw
    if suffix == ".xml":
        try:
            root = ET.fromstring(raw)
            lines = []
            for node in root.iter():
                value = (node.text or "").strip()
                if value and not list(node):
                    lines.append(f"{node.tag.rsplit('}', 1)[-1]}: {value}")
            return "\n".join(lines) or raw
        except Exception:
            return raw
    return raw


def parse_local_file(
    path: str | Path,
    field_aliases: dict[str, Any] | None = None,
) -> ExtractedAlert:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm", ".mhtml", ".mht"}:
        return parse_html_file(path, field_aliases=field_aliases)
    if suffix in SPREADSHEET_EXTS:
        return parse_text(_spreadsheet_to_text(path), source_file=str(path), field_aliases=field_aliases)
    if suffix in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}:
        alert = ExtractedAlert(source_file=str(path))
        alert.notes.append("本地解析仅支持文本与HTML；图片必须使用在线AI识别")
        return alert
    text = _structured_text_file(path)
    return parse_text(text, source_file=str(path), field_aliases=field_aliases)


def file_to_text(path: str | Path) -> str:
    """Return the same normalized evidence text used by local parsing."""
    path_obj = Path(path)
    suffix = path_obj.suffix.lower()
    if suffix in {".html", ".htm", ".mhtml", ".mht"}:
        if suffix in {".mhtml", ".mht"}:
            message = email.message_from_bytes(path_obj.read_bytes())
            html_parts: list[str] = []
            for part in message.walk():
                if part.get_content_type() != "text/html":
                    continue
                payload = part.get_payload(decode=True) or b""
                html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
            return _html_to_local_text("\n".join(html_parts))
        return _html_to_local_text(_read_text_file(path_obj))
    if suffix in SPREADSHEET_EXTS:
        return _spreadsheet_to_text(path_obj)
    return _structured_text_file(path_obj)


def parse_image(path: str | Path) -> ExtractedAlert:
    """图片不使用本地 OCR，只允许交给在线 AI 提取。"""
    path = Path(path)
    alert = ExtractedAlert(source_file=str(path))
    alert.notes.append("本地解析仅支持文本与HTML；图片必须使用在线AI识别")
    return alert


def parse_any(path_or_text: str, is_path: bool = False) -> ExtractedAlert:
    if not is_path:
        return parse_text(path_or_text)
    p = Path(path_or_text)
    suffix = p.suffix.lower()
    if suffix in {".html", ".htm", ".mhtml", ".mht"}:
        return parse_html_file(p)
    if suffix in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}:
        return parse_image(p)
    if suffix in {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".xml"} | SPREADSHEET_EXTS:
        return parse_local_file(p)
    # 尝试当文本读
    try:
        return parse_text(_read_text_file(p), source_file=str(p))
    except Exception:
        return ExtractedAlert(source_file=str(p), notes=["无法识别的文件类型"])


def _read_text_file(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "gb18030", "utf-16"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")
