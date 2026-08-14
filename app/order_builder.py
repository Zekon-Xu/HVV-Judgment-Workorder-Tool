"""工单字段规范化与 Markdown 输出"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

from .constants import MONITOR_SOURCE_NAMES
from .default_whitelist import company_attribution_lines
from .whitelist import (
    WhitelistEngine,
    check_alert_whitelist_gate,
    extract_indicators,
    extract_ips,
    is_private_ip,
)


@dataclass
class WorkOrder:
    number: str = ""
    source: str = "自定义监测平台"
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
    advice: str = ""
    notes: list[str] = field(default_factory=list)
    custom_fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        if self.custom_fields:
            return "\n".join(f"{key}：{value}" for key, value in self.custom_fields.items())
        lines = [
            f"编号：{self.number}",
            f"监测来源：{self.source}",
            f"时间：{self.time}",
            f"攻击IP：{self.attack_ip}",
            f"目标IP：{self.target_ip}",
            f"XFF：{self.xff}",
            f"域名URL：{self.domain_url}",
            f"告警级别：{self.alert_level}",
            f"攻击名称：{self.attack_name}",
            f"事件类型：{self.event_type}",
            f"事件等级：{self.event_level}",
            f"攻击结果：{self.attack_result}",
            f"是否白名单：{self.is_whitelist}",
            # 工单格式字段名保持「处置建议」（意见文案，不表示已执行处置）
            f"处置建议：{self.advice}",
        ]
        return "\n".join(lines)


def normalize_alert_level(v: str) -> str:
    s = (v or "").strip()
    if any(k in s for k in ("危急", "紧急", "严重", "critical")):
        return "高危"
    if "高" in s:
        return "高危"
    if "中" in s:
        return "中危"
    if "低" in s:
        return "低危"
    return "高危"


def normalize_result(v: str) -> str:
    s = (v or "").strip()
    if any(k in s for k in ("成功", "失陷")) and not any(
        k in s for k in ("未成功", "不成功", "失败", "企图", "尝试")
    ):
        return "成功"
    return "失败"


def normalize_event_level(value: str) -> str:
    text = (value or "").strip()
    for level in ("一级", "二级", "三级", "四级", "五级"):
        if level in text:
            return level
    return "五级"


def build_advice(
    attack_ip: str,
    target_ip: str,
    xff: str,
    is_whitelist: str,
    attack_result: str = "失败",
    wl_engine: WhitelistEngine | None = None,
    domain_url: str = "",
) -> str:
    """
    本地规则生成的「处置意见」文案（建议，不执行任何动作）。
    只分两类：公网非白名单封禁；内网可疑源核实授权。
    """
    del is_whitelist  # 保留参数兼容调用方
    atk_ips = extract_ips(attack_ip)
    xff_ips = extract_ips(xff)
    del target_ip, attack_result

    ban_ips: list[str] = []
    ban_iocs: list[str] = []
    verify_ips: list[str] = []

    for ip in atk_ips:
        if wl_engine and wl_engine.check(ip).matched:
            continue
        if is_private_ip(ip):
            verify_ips.append(ip)
        else:
            ban_ips.append(ip)

    for ip in xff_ips:
        if wl_engine and wl_engine.check(ip).matched:
            continue
        if ip not in ban_ips and ip not in verify_ips:
            if is_private_ip(ip):
                verify_ips.append(ip)
            else:
                ban_ips.append(ip)

    for indicator in extract_indicators(domain_url):
        if wl_engine and wl_engine.check(indicator).matched:
            continue
        if indicator not in ban_iocs:
            ban_iocs.append(indicator)

    parts = []
    if ban_ips:
        parts.append(f"封禁 {', '.join(ban_ips)}")
    if ban_iocs:
        parts.append(f"封禁 {', '.join(ban_iocs)}")
    if verify_ips:
        parts.append(
            f"核实 {', '.join(verify_ips)} 的任务授权情况；已授权则加白，未授权则隔离并排查源主机"
        )
    if not parts:
        return "暂无明确对象，请人工补充处置意见"
    return "；".join(parts[:2])


def _ensure_ioc_actions(advice: str, domain_url: str, wl_engine: WhitelistEngine) -> str:
    """Never allow an unwhitelisted domain IOC to disappear from advice."""
    required = [
        f"封禁 {indicator}"
        for indicator in extract_indicators(domain_url)
        if not wl_engine.check(indicator).matched
    ]
    missing = [item for item in required if item not in advice]
    if not missing:
        return advice
    return "；".join([part for part in (advice, *missing) if part])


def judge_whitelist(
    attack_ip: str,
    xff: str,
    wl_engine: WhitelistEngine,
    target_ip: str = "",
    domain_url: str = "",
) -> tuple[str, str]:
    """
    返回 (是否白名单文案, 备注)
    工单字段只输出“是/否”；是否跳过工单由全日志 IP 检查单独决定。
    """
    decision = check_alert_whitelist_gate(
        wl_engine,
        attack_ip=attack_ip,
        target_ip=target_ip,
        xff=xff,
        domain_url=domain_url,
    )
    if not decision.has_attack_ip:
        return "否", ""
    details = []
    for item in [*decision.matched, *decision.semi_matched]:
        details.append(f"{item['ip']}->{item['reason'] or item['rule']}")
    return ("是" if decision.skip_order else "否"), "；".join(details)


def assemble_order(
    fields: dict[str, Any],
    wl_engine: WhitelistEngine,
    auto_whitelist: bool = True,
    auto_advice: bool = True,
) -> WorkOrder:
    requested_source = str(fields.get("source", "") or "自定义监测平台").strip()
    order = WorkOrder(
        number=str(fields.get("number", "") or ""),
        # 允许下拉以外的自定义监测来源文案
        source=requested_source or "自定义监测平台",
        time=str(fields.get("time", "") or ""),
        attack_ip=str(fields.get("attack_ip", "") or "").strip(),
        target_ip=str(fields.get("target_ip", "") or "").strip(),
        xff=str(fields.get("xff", "") or "").strip(),
        domain_url=str(fields.get("domain_url", "") or "").strip(),
        alert_level=normalize_alert_level(str(fields.get("alert_level", "高危"))),
        attack_name=str(fields.get("attack_name", "") or "").strip(),
        event_type=str(fields.get("event_type", "") or "").strip(),
        event_level=normalize_event_level(str(fields.get("event_level", "五级"))),
        attack_result=normalize_result(str(fields.get("attack_result", "失败"))),
        is_whitelist="是" if str(fields.get("is_whitelist", "否") or "否").startswith("是") else "否",
        advice=str(fields.get("advice", "") or "").strip(),
    )

    # 空字段置空字符串（XFF / 域名URL 没有就空）
    if order.xff.lower() in {"none", "null", "无", "-"}:
        order.xff = ""
    if order.domain_url.lower() in {"none", "null", "无", "-"}:
        order.domain_url = ""

    if auto_whitelist:
        wl, note = judge_whitelist(
            order.attack_ip, order.xff, wl_engine,
            target_ip=order.target_ip, domain_url=order.domain_url,
        )
        order.is_whitelist = wl
        if note:
            order.notes.append(note)

    for attribution in company_attribution_lines(
        attack_ip=order.attack_ip,
        target_ip=order.target_ip,
        xff=order.xff,
        domain_url=order.domain_url,
    ):
        order.notes.append(f"内网部门归属：{attribution}")

    if auto_advice or not order.advice:
        order.advice = build_advice(
            order.attack_ip,
            order.target_ip,
            order.xff,
            order.is_whitelist,
            order.attack_result,
            wl_engine,
            order.domain_url,
        )
    order.advice = _ensure_ioc_actions(order.advice, order.domain_url, wl_engine)

    return order
