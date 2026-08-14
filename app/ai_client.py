# -*- coding: utf-8 -*-
"""OpenAI 兼容 API 客户端（默认 DeepSeek，可改 Grok/其它兼容接口）。"""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_MODEL = "deepseek-v4-flash"
DEFAULT_TIMEOUT = 45.0
WIRE_API_CHOICES = ("auto", "chat", "responses", "anthropic")


def _is_deepseek_v4(model: str) -> bool:
    value = str(model or "").casefold().replace("_", "-")
    return "deepseek-v4" in value or value in {"deepseek-chat", "deepseek-reasoner"}


def detect_wire_api(base_url: str, model: str = "") -> str:
    """Select a documented wire protocol from provider URL/model hints."""
    raw = f"{base_url} {model}".casefold()
    if any(token in raw for token in ("anthropic", "claude")):
        return "anthropic"
    if any(token in raw for token in ("openai", "codex", "gpt-5.6", "gpt-5.5")):
        return "responses"
    return "chat"


def _ssl_verify() -> str | bool:
    """打包 exe 下优先使用随包 certifi 证书。"""
    try:
        import certifi

        path = certifi.where()
        if path and Path(path).exists():
            return path
        # frozen 时 certifi 可能在 _MEIPASS
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            alt = Path(sys._MEIPASS) / "certifi" / "cacert.pem"  # type: ignore[attr-defined]
            if alt.exists():
                return str(alt)
    except Exception:
        pass
    return True


def normalize_base_url(base: str) -> str:
    raw = (base or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL
    if not re.match(r"^https?://", raw, re.I):
        raise ValueError("AI URL 基址必须以 http:// 或 https:// 开头")
    parts = urlsplit(raw)
    if not parts.netloc:
        raise ValueError("AI URL 基址无效")
    path = parts.path.rstrip("/")
    for endpoint in ("/chat/completions", "/responses"):
        if path.casefold().endswith(endpoint):
            path = path[: -len(endpoint)].rstrip("/")
            break
    # Provider roots use the OpenAI-compatible /v1 path. Custom paths are
    # preserved because gateways commonly use /api/v1 or tenant prefixes.
    if not path:
        path = "/v1"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, "", ""))


@dataclass
class AIConfig:
    enabled: bool = True
    base_url: str = DEFAULT_BASE_URL
    api_key: str = ""
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT
    use_for_ocr: bool = True
    use_for_judge: bool = True
    wire_api: str = "chat"

    @classmethod
    def from_settings(cls, settings: dict[str, Any]) -> "AIConfig":
        key = (settings.get("ai_api_key") or "").strip()
        if not key:
            key = (
                os.environ.get("DEEPSEEK_API_KEY")
                or os.environ.get("XAI_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
                or ""
            ).strip()
        try:
            base = normalize_base_url(str(settings.get("ai_base_url") or DEFAULT_BASE_URL))
        except ValueError:
            base = str(settings.get("ai_base_url") or "").strip()
        try:
            timeout = float(settings.get("ai_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = max(5.0, min(timeout, 600.0))
        requested_wire = str(settings.get("ai_wire_api") or "auto").strip().casefold()
        if requested_wire not in WIRE_API_CHOICES:
            requested_wire = "auto"
        resolved_wire = detect_wire_api(base, str(settings.get("ai_model") or "")) if requested_wire == "auto" else requested_wire
        return cls(
            enabled=bool(settings.get("ai_enabled", True)),
            base_url=base,
            api_key=key,
            model=(settings.get("ai_model") or DEFAULT_MODEL).strip() or DEFAULT_MODEL,
            timeout=timeout,
            use_for_ocr=bool(settings.get("ai_use_ocr", True)),
            use_for_judge=bool(settings.get("ai_use_judge", True)),
            wire_api=resolved_wire,
        )

    def ready(self) -> bool:
        return bool(self.enabled and self.api_key and self.base_url and self.model)


class AIClientError(RuntimeError):
    pass


class AIClient:
    def __init__(self, config: AIConfig) -> None:
        self.config = config

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> str:
        if not self.config.enabled:
            raise AIClientError("AI 未启用（配置中心勾选「启用 AI」）")
        if not self.config.api_key:
            raise AIClientError("API Key 为空：请在配置中心填写并「保存/更新此配置」")
        if not self.config.model:
            raise AIClientError("模型名为空")
        try:
            base_url = normalize_base_url(self.config.base_url)
        except ValueError as exc:
            raise AIClientError(str(exc)) from exc

        use_responses = self.config.wire_api == "responses"
        endpoint = "/responses" if use_responses else ("/messages" if self.config.wire_api == "anthropic" else "/chat/completions")
        url = base_url.rstrip("/") + endpoint
        headers = {"Content-Type": "application/json"}
        if self.config.wire_api == "anthropic":
            headers.update({
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
            })
        else:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        if self.config.wire_api == "anthropic":
            payload = self._anthropic_payload(messages, self.config.model, max_tokens, temperature)
        elif use_responses:
            payload = {
                "model": self.config.model,
                "input": self._responses_input(messages),
                "max_output_tokens": max_tokens,
                "store": False,
            }
        else:
            payload = {
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            # DeepSeek V4 defaults to thinking mode.  Its reasoning tokens are
            # counted inside max_tokens, so a field-extraction request can
            # exhaust the budget before any usable ``content`` is emitted.
            # Extraction and advice need a concise machine-readable answer;
            # disable thinking explicitly for this model family.
            if _is_deepseek_v4(self.config.model):
                payload["thinking"] = {"type": "disabled"}
        try:
            with httpx.Client(timeout=self.config.timeout, verify=_ssl_verify()) as client:
                for attempt in range(2):
                    resp = client.post(url, headers=headers, json=payload)
                    if resp.status_code not in {429, 502, 503, 504} or attempt == 1:
                        break
                    # One short retry helps transient gateway errors without
                    # making a throttled request appear to hang.
                    time.sleep(0.8)
        except httpx.TimeoutException as e:
            raise AIClientError(f"AI 请求超时（{self.config.timeout}s）：{e}") from e
        except httpx.ConnectError as e:
            raise AIClientError(
                f"无法连接 AI 服务\nURL: {url}\n原因: {e}\n请检查网络/代理/基址是否正确"
            ) from e
        except httpx.HTTPError as e:
            raise AIClientError(f"AI 网络请求失败: {e}") from e

        if resp.status_code >= 400:
            detail = resp.text[:800]
            hint = ""
            if resp.status_code in {502, 503, 504}:
                hint = "\n上游模型服务暂时不可用；配置已送达网关，请稍后重试或切换其它AI档案。"
            elif resp.status_code == 429:
                hint = "\n请求被限流或额度不足，请稍后重试并检查账户额度。"
            raise AIClientError(
                f"AI 接口错误 HTTP {resp.status_code}\nURL: {url}\n模型: {self.config.model}\n协议: {self.config.wire_api}\n{detail}{hint}"
            )

        try:
            data = resp.json()
        except Exception as e:
            raise AIClientError(f"AI 响应非 JSON: {resp.text[:300]}") from e

        try:
            if self.config.wire_api == "anthropic":
                content = self._anthropic_output_text(data)
            elif use_responses:
                content = data.get("output_text") or self._responses_output_text(data)
            else:
                choice = data["choices"][0]
                message = choice["message"]
                content = message.get("content")
                if not content:
                    finish = choice.get("finish_reason")
                    if message.get("reasoning_content"):
                        raise AIClientError(
                            "AI 仅返回思考过程，未返回可用结果"
                            + (f"（输出达到上限，finish_reason={finish}）" if finish else "")
                        )
                    raise AIClientError(f"AI 返回空内容（finish_reason={finish or 'unknown'}）")
            if isinstance(content, list):
                content = "".join(
                    str(part.get("text") or "") if isinstance(part, dict) else str(part)
                    for part in content
                )
            return str(content or "").strip()
        except AIClientError:
            raise
        except Exception as e:
            raise AIClientError(
                f"AI 响应结构异常: {json.dumps(data, ensure_ascii=False)[:500]}"
            ) from e

    @staticmethod
    def _responses_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted: list[dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role") or "user")
            content = message.get("content")
            if isinstance(content, str):
                converted.append({"role": role, "content": [{"type": "input_text", "text": content}]})
                continue
            parts: list[dict[str, Any]] = []
            for part in content if isinstance(content, list) else []:
                if not isinstance(part, dict):
                    parts.append({"type": "input_text", "text": str(part)})
                elif part.get("type") == "text":
                    parts.append({"type": "input_text", "text": str(part.get("text") or "")})
                elif part.get("type") == "image_url":
                    image = part.get("image_url") or {}
                    url = image.get("url") if isinstance(image, dict) else image
                    parts.append({"type": "input_image", "image_url": str(url or "")})
            converted.append({"role": role, "content": parts})
        return converted

    @staticmethod
    def _responses_output_text(data: dict[str, Any]) -> str:
        chunks: list[str] = []
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                    chunks.append(str(part.get("text") or ""))
        return "".join(chunks).strip()

    @staticmethod
    def _anthropic_payload(messages: list[dict[str, Any]], model: str, max_tokens: int, temperature: float) -> dict[str, Any]:
        system: list[str] = []
        converted: list[dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role") or "user")
            content = message.get("content")
            if role == "system":
                system.append(str(content or ""))
                continue
            parts: list[dict[str, Any]] = []
            for part in content if isinstance(content, list) else [content]:
                if isinstance(part, dict) and part.get("type") == "image_url":
                    image = part.get("image_url") or {}
                    url = image.get("url") if isinstance(image, dict) else image
                    match = re.match(r"data:([^;]+);base64,(.+)", str(url or ""), re.S)
                    if match:
                        parts.append({"type": "image", "source": {"type": "base64", "media_type": match.group(1), "data": match.group(2)}})
                elif isinstance(part, dict):
                    parts.append({"type": "text", "text": str(part.get("text") or "")})
                else:
                    parts.append({"type": "text", "text": str(part or "")})
            converted.append({"role": "assistant" if role == "assistant" else "user", "content": parts})
        payload: dict[str, Any] = {"model": model, "max_tokens": max_tokens, "messages": converted}
        if system:
            payload["system"] = "\n\n".join(system)
        if temperature is not None:
            payload["temperature"] = temperature
        return payload

    @staticmethod
    def _anthropic_output_text(data: dict[str, Any]) -> str:
        return "".join(
            str(part.get("text") or "")
            for part in (data.get("content") or [])
            if isinstance(part, dict) and part.get("type") == "text"
        ).strip()


def file_to_data_url(path: str | Path, max_side: int = 1600) -> str:
    """图片转 data URL；过大则缩小，避免请求体爆炸。"""
    path = Path(path)
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    try:
        from PIL import Image
        import io

        img = Image.open(path)
        w, h = img.size
        scale = min(1.0, max_side / max(w, h))
        if scale < 1.0:
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        if path.suffix.lower() == ".png":
            mime = "image/png"
            if img.mode not in ("RGB", "RGBA", "L", "LA"):
                img = img.convert("RGBA")
            img.save(buf, format="PNG")
        else:
            mime = "image/jpeg"
            if img.mode != "RGB":
                img = img.convert("RGB")
            img.save(buf, format="JPEG", quality=85)
        raw = buf.getvalue()
    except Exception:
        raw = path.read_bytes()
        if len(raw) > 4_000_000:
            raise AIClientError("图片过大且无法压缩")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:{mime};base64,{b64}"


def extract_json_object(text: str) -> dict[str, Any]:
    """从模型输出中抠出 JSON 对象。"""
    text = (text or "").strip()
    if not text:
        raise AIClientError("模型返回空内容")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        return json.loads(m.group(0))
    raise AIClientError(f"无法解析 JSON: {text[:300]}")
