"""ThreatBook cloud-API lookups for IP and domain intelligence."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

import httpx


DEFAULT_BASE_URL = "https://api.threatbook.cn/v3"


def domain_report_url(value: str) -> str:
    """Return the public X intelligence page for a normalized domain."""
    domain = (value or "").strip().lower().rstrip(".")
    if indicator_type(domain) != "domain":
        raise ThreatBookError("仅支持域名详情页查询")
    return f"https://x.threatbook.com/v5/domain/{domain}"


class ThreatBookError(RuntimeError):
    pass


@dataclass
class ThreatBookResult:
    indicator: str
    indicator_type: str
    summary: str
    payload: dict[str, Any]

    def display_text(self) -> str:
        return f"{self.summary}\n\n原始响应：\n{json.dumps(self.payload, ensure_ascii=False, indent=2)}"


def indicator_type(value: str) -> str:
    value = (value or "").strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    domain = value.lower().rstrip(".")
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        return "domain"
    raise ThreatBookError("仅支持单个 IPv4/IPv6 地址或域名")


def _items(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, dict):
        return [str(v).strip() for v in value.values() if str(v).strip()]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, dict):
                candidate = item.get("name") or item.get("judgment") or item.get("label") or item.get("value")
                if candidate:
                    result.append(str(candidate).strip())
            elif str(item).strip():
                result.append(str(item).strip())
        return result
    return []


def _summary(indicator: str, kind: str, payload: dict[str, Any]) -> str:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    if isinstance(data, dict) and kind == "domain":
        # Domain analysis returns a map keyed by the queried domain.
        nested = data.get(indicator) or data.get(indicator.rstrip(".").lower())
        if isinstance(nested, dict):
            data = nested
    if not isinstance(data, dict):
        return f"微步 {kind.upper()} 情报：接口返回格式异常，未形成可用结论"
    judgments = _items(data.get("judgments"))
    verdict = (
        data.get("judgment") or data.get("verdict") or data.get("is_malicious")
        or data.get("malicious") or data.get("severity") or data.get("risk_level") or "未发现明确风险结论"
    )
    if verdict == "未发现明确风险结论" and judgments:
        verdict = "、".join(judgments)
    tags = _items(data.get("tags") or data.get("scene"))[:6]
    parts = [f"微步 {kind.upper()} 情报：{indicator}，结论：{verdict}"]
    if tags:
        parts.append("标签：" + "、".join(tags))
    confidence = data.get("confidence") or data.get("confidence_level")
    if confidence is not None:
        parts.append(f"置信度：{confidence}")
    if kind == "domain":
        permalink = str(data.get("permalink") or f"https://x.threatbook.com/v5/domain/{indicator}")
        parts.append(f"详情：{permalink}")
    return "；".join(parts)


class ThreatBookClient:
    def __init__(self, settings: dict[str, Any]) -> None:
        self.enabled = bool(settings.get("threatbook_enabled", False))
        self.api_key = str(settings.get("threatbook_api_key") or "").strip()
        self.base_url = str(settings.get("threatbook_base_url") or DEFAULT_BASE_URL).strip().rstrip("/")
        try:
            self.timeout = max(3.0, min(float(settings.get("threatbook_timeout", 8) or 8), 30.0))
        except (TypeError, ValueError):
            self.timeout = 8.0

    def ready(self) -> bool:
        return self.enabled and bool(self.api_key) and self.base_url.startswith(("http://", "https://"))

    def lookup(self, indicator: str) -> ThreatBookResult:
        kind = indicator_type(indicator)
        # Domain API access is a separately permissioned product. Always use
        # the public X intelligence page for domains so a valid domain never
        # fails with "没有访问接口权限" because of the API package.
        if kind == "domain":
            normalized = indicator.strip().lower().rstrip(".")
            permalink = domain_report_url(normalized)
            return ThreatBookResult(
                normalized,
                kind,
                f"微步域名情报：{normalized}\n已打开详情页：{permalink}",
                {"query_mode": "web", "permalink": permalink},
            )
        if not self.enabled:
            raise ThreatBookError("微步情报未启用，请在配置中心启用并保存 API Key")
        if not self.api_key:
            raise ThreatBookError("微步 API Key 为空")
        endpoint = "scene/ip_reputation"
        url = f"{self.base_url}/{endpoint}"
        try:
            response = httpx.get(
                url,
                params={"apikey": self.api_key, "resource": indicator, "lang": "zh"},
                timeout=self.timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            raise ThreatBookError(f"微步查询超时（{self.timeout:g}s）") from exc
        except httpx.HTTPError as exc:
            raise ThreatBookError(f"微步网络请求失败：{exc}") from exc
        if response.status_code >= 400:
            raise ThreatBookError(f"微步接口错误 HTTP {response.status_code}：{response.text[:400]}")
        try:
            payload = response.json()
        except Exception as exc:
            raise ThreatBookError(f"微步响应不是 JSON：{response.text[:300]}") from exc
        if not isinstance(payload, dict):
            raise ThreatBookError("微步响应格式无效")
        code = payload.get("response_code")
        if code not in (None, 0, "0"):
            raise ThreatBookError(str(payload.get("verbose_msg") or payload.get("message") or f"微步返回错误码 {code}"))
        return ThreatBookResult(indicator, kind, _summary(indicator, kind, payload), payload)
