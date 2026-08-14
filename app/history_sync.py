"""Download and incrementally merge remotely hosted alert tracking workbooks."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


class HistorySyncError(RuntimeError):
    """A user-facing remote history synchronization error."""


@dataclass
class HistorySyncResult:
    url: str
    added: int = 0
    updated: int = 0
    total: int = 0


_TRUSTED_WPS_HOSTS = ("wps.cn", "kdocs.cn", "wpscdn.cn")
_URL_RE = re.compile(r"https?:[\\/a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%-]+")


def _is_trusted_wps_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").casefold()
    return any(host == suffix or host.endswith("." + suffix) for suffix in _TRUSTED_WPS_HOSTS)


def _headers_for(url: str, cookie: str) -> dict[str, str]:
    headers = {"User-Agent": "Mozilla/5.0"}
    if cookie and _is_trusted_wps_url(url):
        headers["Cookie"] = cookie
        headers["Origin"] = "https://www.kdocs.cn"
        headers["Referer"] = "https://www.kdocs.cn/"
    return headers


def _workbook_urls_from_share_page(text: str) -> list[str]:
    """Extract only explicit Excel download URLs from KDocs' serialized page state."""
    normalized = html.unescape(text or "").replace("\\u002F", "/").replace("\\/", "/")
    found: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(normalized):
        candidate = match.group(0).rstrip("\\\"'<>)],; ")
        path = (urlparse(candidate).path or "").casefold()
        if not path.endswith((".xlsx", ".xlsm", ".xls")) or candidate in seen:
            continue
        if not _is_trusted_wps_url(candidate):
            continue
        seen.add(candidate)
        found.append(candidate)
    return found


def normalize_sync_urls(value: Any) -> list[str]:
    """Accept a list or newline/comma-separated URL input and deduplicate it."""
    values = value if isinstance(value, list) else str(value or "").replace(",", "\n").splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        url = str(raw or "").strip()
        if not url or url in seen:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        out.append(url)
        seen.add(url)
    return out


def download_history_workbook(url: str, *, timeout: float = 30, session_cookie: str = "") -> bytes:
    """Fetch an XLSX/XLSM workbook, rejecting sign-in HTML and other web pages."""
    if httpx is None:
        raise HistorySyncError("缺少 httpx，无法执行在线同步")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HistorySyncError("同步链接必须是有效的 http/https 地址")
    cookie = str(session_cookie or "").strip().replace("\r", "").replace("\n", "")
    if cookie.casefold().startswith("cookie:"):
        cookie = cookie.split(":", 1)[1].strip()
    try:
        response = httpx.get(
            url, follow_redirects=True, timeout=timeout, headers=_headers_for(url, cookie),
        )
        response.raise_for_status()
    except Exception as exc:
        raise HistorySyncError(f"下载失败：{exc}") from exc

    final_url = str(response.url)
    content_type = (response.headers.get("content-type") or "").casefold()
    body = response.content
    # XLSX/XLSM are ZIP containers. This is stricter than trusting an extension.
    if body[:4] == b"PK\x03\x04":
        return body
    # Logged-in KDocs share links render an HTML application. Extract only a
    # trusted, explicit Excel export URL and try it with the same session.
    if cookie and "kdocs.cn" in (urlparse(final_url).hostname or "") and "text/html" in content_type:
        for workbook_url in _workbook_urls_from_share_page(response.text):
            try:
                exported = httpx.get(
                    workbook_url, follow_redirects=True, timeout=timeout,
                    headers=_headers_for(workbook_url, cookie),
                )
                exported.raise_for_status()
            except Exception:
                continue
            if exported.content[:4] == b"PK\x03\x04":
                return exported.content
        if cookie:
            raise HistorySyncError("已登录 KDocs，但未找到可直接导出的 Excel 文件；请确认该文档已开放下载权限")
    if body[:4] != b"PK\x03\x04":
        if "kdocs.cn/passport" in final_url or "singlesign" in final_url or "text/html" in content_type:
            raise HistorySyncError("链接已跳转到金山文档登录页，请提供可直接下载的公开 Excel 链接")
        raise HistorySyncError("下载内容不是 Excel 文件，请使用可直接下载的 XLSX/XLSM 链接")
    return body


def sync_history_urls(
    history: Any, urls: Any, *, timeout: float = 30, session_cookie: str = "",
) -> list[HistorySyncResult]:
    """Synchronize every configured URL. Caller records timestamps/errors."""
    normalized = normalize_sync_urls(urls)
    if not normalized:
        raise HistorySyncError("请至少配置一个告警跟踪 Excel 下载链接")
    results: list[HistorySyncResult] = []
    for url in normalized:
        payload = download_history_workbook(url, timeout=timeout, session_cookie=session_cookie)
        added, updated, total = history.merge_from_xlsx_bytes(payload, sheet_label=url)
        results.append(HistorySyncResult(url=url, added=added, updated=updated, total=total))
    return results
