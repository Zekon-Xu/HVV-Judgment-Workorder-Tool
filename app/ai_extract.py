# -*- coding: utf-8 -*-
"""
AI 主路径：文字提取 / 图片识别 / 文件分析 / 研判意见。
本地备选：仅文字与 HTML（AI 不通时）；图片只允许在线 AI 识别。
本工具只产出研判工单与处置意见，不执行任何封禁/隔离动作。

Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .ai_client import AIClient, AIClientError, AIConfig, extract_json_object, file_to_data_url
from .default_whitelist import company_attribution_lines
from .extractor import ExtractedAlert, file_to_text, parse_local_file, parse_text, _read_text_file, SPREADSHEET_EXTS
from .order_builder import normalize_alert_level, normalize_event_level, normalize_result
from .settings_store import get_ai_profile
from .template_store import (
    build_template_prompt_section,
    extract_template_fields,
    load_template,
    sample_fields_from_text,
)

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}
WEB_EXTS = {".html", ".htm", ".mhtml", ".mht"}
TEXT_EXTS = {".txt", ".md", ".log", ".csv", ".json", ".xml"}
TEXT_EXTS |= SPREADSHEET_EXTS


def _annotate_company_departments(alert: ExtractedAlert) -> ExtractedAlert:
    for line in company_attribution_lines(
        attack_ip=alert.attack_ip,
        target_ip=alert.target_ip,
        xff=alert.xff,
        domain_url=alert.domain_url,
    ):
        note = f"内网部门归属：{line}"
        if note not in alert.notes:
            alert.notes.append(note)
    return alert


def _ensure_domain_from_evidence(
    alert: ExtractedAlert,
    evidence: str,
    template: dict[str, Any] | None = None,
) -> ExtractedAlert:
    """Fill a missing domain from deterministic IOC/URI parsing after AI output."""
    if alert.domain_url.strip() or not evidence.strip():
        return alert
    parsed = parse_text(evidence, field_aliases=(template or {}).get("field_aliases"))
    if parsed.domain_url:
        alert.domain_url = parsed.domain_url
        alert.notes.append("确定性规则补取 IOC/URI 域名")
    return alert

SYSTEM_EXTRACT = """清洗传入内容并作研判，再按当前模板和标准研判结构生成结果。
你是安全运营告警字段清洗助手。只根据输入中明确出现的证据提取字段，不得臆造；外部情报只能作为辅助证据，不能替代原始告警字段。公司内网网段仅用于部门归属判断，绝不能因此把IP判为白名单：攻击IP命中时说明攻击来源部门，目标/受害/目的IP命中时说明受攻击部门。
如果用户消息提供了模板字段，先输出“【当前模板工单初版】”，严格按模板字段名和顺序逐行输出，不得增加、删除或改名；没有证据的值留空。
然后输出“【标准研判字段】”，每个字段独占一行，供本地规则使用。标准字段之后追加“研判依据”和“处置依据”，各用一行简述可核验的证据，不要输出隐藏推理过程。标准字段顺序必须是：
时间、攻击IP、目标IP、XFF、域名URL、告警级别、攻击名称、事件类型、事件等级、攻击结果、是否白名单、处置建议。
源IP/攻击者是攻击IP，目的IP/受害者是目标IP；不要把探针IP或数据源IP当成攻击IP。原文中 IOC、IOC域名、域名、URI、URL 或 host 字段出现的域名/URL 必须原样填入“域名URL”，即使建议或研判字段没有提到它，也不能留空。
事件等级默认五级；企图、拦截、未成功均算攻击失败。处置建议只允许两类固定句式：外部非白名单公网攻击源写“封禁 <IP>”；内网可疑行为源写“核实 <IP> 的任务授权情况；已授权则加白，未授权则隔离并排查源主机”。不要对受害/目标IP使用封禁或授权核实句式，不要声称已经执行处置。

格式示例（内容仅示范结构，不得照抄）：
编号：0807-165
监测来源：自定义监测平台
时间：2026-08-07 21:58:00
攻击IP：103.213.96.237
目标IP：10.2.3.4
XFF：
域名URL：
告警级别：高危
攻击名称：SSH暴力破解攻击
事件类型：暴力破解
事件等级：五级
攻击结果：失败
是否白名单：否
处置建议：封禁 103.213.96.237"""

SYSTEM_JUDGE = """你是安全运营处置建议助手。只根据已给出的告警字段和外部情报生成 1-2 句可执行建议；不要复述告警、不要写分析过程、不要用“建议如下”等标题，也不要声称动作已经执行。

决策规则：
0. 只有攻击IP、目标/受害/目的IP、XFF及URL中的IP全部通过白名单判断才免报，空XFF视为通过。公司内网网段只在攻击IP角色下算半白名单；其余角色必须命中显式白名单。任一IP未通过就出工单，并对非白名单攻击源/XFF给出处置动作。
1. 外部非白名单公网攻击源或XFF：只使用“封禁 <IP>”。
2. 内网可疑行为攻击源或XFF：只使用“核实 <IP> 的任务授权情况；已授权则加白，未授权则隔离并排查源主机”。
3. 不对受害/目标IP生成封禁、隔离或授权核实建议。不能编造授权、失陷或微步命中结论。

示例：
封禁 176.65.132.131
核实 10.128.51.71 的任务授权情况；已授权则加白，未授权则隔离并排查源主机"""


def _apply_json_to_alert(data: dict[str, Any], source_file: str = "", template: dict[str, Any] | None = None) -> ExtractedAlert:
    standard = data.get("standard_fields") if isinstance(data.get("standard_fields"), dict) else data
    alert = ExtractedAlert(source_file=source_file)
    alert.time = str(standard.get("time") or "").strip()
    alert.attack_ip = str(standard.get("attack_ip") or "").strip()
    alert.target_ip = str(standard.get("target_ip") or "").strip()
    alert.xff = str(standard.get("xff") or "").strip()
    if alert.xff.lower() in {"none", "null", "无", "-"}:
        alert.xff = ""
    alert.domain_url = str(standard.get("domain_url") or "").strip()
    if alert.domain_url.lower() in {"none", "null", "无", "-"}:
        alert.domain_url = ""
    alert.alert_level = normalize_alert_level(str(standard.get("alert_level") or "高危"))
    alert.attack_name = str(standard.get("attack_name") or "").strip()
    alert.event_type = str(standard.get("event_type") or "").strip()
    alert.event_level = normalize_event_level(str(standard.get("event_level") or "五级"))
    alert.attack_result = normalize_result(str(standard.get("attack_result") or "失败"))
    wl = str(standard.get("is_whitelist") or "否")
    alert.is_whitelist = "是" if wl.startswith("是") else "否"
    advice = str(standard.get("advice") or "").strip()
    ocr = str(data.get("ocr_text") or data.get("raw_text") or "").strip()
    alert.raw_text = ocr
    _ensure_domain_from_evidence(alert, ocr, template)
    alert.ai_output = json.dumps(data, ensure_ascii=False, indent=2)
    raw_template_fields = data.get("template_fields")
    if isinstance(raw_template_fields, dict):
        allowed = set((template or {}).get("field_schema") or {})
        alert.template_fields = {
            str(key): str(value or "") for key, value in raw_template_fields.items()
            if not allowed or str(key) in allowed
        }
        for label, semantic in ((template or {}).get("field_bindings") or {}).items():
            if semantic == "attack_result" and str(label) in alert.template_fields:
                alert.template_fields[str(label)] = normalize_result(alert.template_fields[str(label)])
    if advice:
        alert.notes.append(f"AI_ADVICE::{advice}")
    rationale = str(data.get("rationale") or data.get("研判依据") or "").strip()
    disposal_basis = str(data.get("disposal_basis") or data.get("处置依据") or "").strip()
    if rationale:
        alert.notes.append(f"AI研判依据：{rationale}")
    if disposal_basis:
        alert.notes.append(f"AI处置依据：{disposal_basis}")
    alert.notes.append("AI提取/研判")
    return alert


def _apply_standard_output(content: str, source_file: str = "", template: dict[str, Any] | None = None) -> ExtractedAlert:
    text = (content or "").strip()
    if not text:
        raise AIClientError("模型返回空内容")
    if text.startswith("{") or "```json" in text.casefold():
        try:
            return _apply_json_to_alert(extract_json_object(text), source_file=source_file, template=template)
        except Exception:
            pass
    alert = parse_text(text, source_file=source_file)
    alert.ai_output = text
    alert.raw_text = text
    schema = (template or {}).get("field_schema") or {}
    if schema:
        extracted = sample_fields_from_text(text)
        alert.template_fields = {str(label): extracted.get(str(label), "") for label in schema}
        for label, semantic in ((template or {}).get("field_bindings") or {}).items():
            if semantic == "attack_result" and str(label) in alert.template_fields:
                alert.template_fields[str(label)] = normalize_result(alert.template_fields[str(label)])
    for label in ("研判依据", "处置依据"):
        match = re.search(rf"(?m)^\s*{label}\s*[：:]\s*(.+?)\s*$", text)
        if match:
            alert.notes.append(f"AI{label}：{match.group(1).strip()}")
    alert.notes.append("AI标准工单清洗")
    if not alert.attack_ip and not alert.attack_name:
        try:
            return _apply_json_to_alert(extract_json_object(text), source_file=source_file, template=template)
        except Exception as exc:
            raise AIClientError("AI 返回内容无法按标准工单结构提取，请查看原始结果") from exc
    return alert


def require_client(settings: dict[str, Any], *, purpose: str = "extract") -> AIClient:
    cfg = AIConfig.from_settings(settings)
    if not cfg.ready():
        raise AIClientError(
            "AI 未就绪：请在「配置中心」填写 API Key，或设置环境变量 XAI_API_KEY。\n"
            f"当前基址：{cfg.base_url}，模型：{cfg.model}"
        )
    if purpose == "extract" and not cfg.use_for_ocr:
        raise AIClientError("AI 识别/提取已关闭，请在配置中心启用")
    if purpose == "judge" and not cfg.use_for_judge:
        raise AIClientError("AI 研判建议已关闭，请在配置中心启用")
    return AIClient(cfg)


def ai_extract_from_text(
    client: AIClient,
    text: str,
    *,
    template: dict[str, Any] | None = None,
    source_file: str = "",
) -> ExtractedAlert:
    tpl = template or load_template()
    body = (text or "").strip()
    if not body:
        raise AIClientError("没有可分析的文字内容")
    user = (
        build_template_prompt_section(tpl)
        + "\n\n—— 待分析告警原文（文字提取+研判意见）——\n"
        + body[:16000]
    )
    content = client.chat(
        [
            {"role": "system", "content": SYSTEM_EXTRACT},
            {"role": "user", "content": user},
        ],
        temperature=0.05,
        max_tokens=2500,
    )
    alert = _apply_standard_output(content, source_file=source_file, template=tpl)
    return _ensure_domain_from_evidence(alert, body, tpl)


def ai_extract_from_image(
    client: AIClient,
    image_path: str | Path,
    *,
    template: dict[str, Any] | None = None,
    extra_text: str = "",
) -> ExtractedAlert:
    path = Path(image_path)
    if not path.exists():
        raise AIClientError(f"图片不存在: {path}")
    tpl = template or load_template()
    data_url = file_to_data_url(path)
    prompt = (
        build_template_prompt_section(tpl)
        + "\n\n请识别截图中的安全告警信息，完成识别 + 字段提取 + 处置意见。IOC、IOC域名、域名、URI、URL 或 host 中出现的域名/URL 必须填入 domain_url。"
        + "\nocr_text 填入你读到的关键文字。只给意见，不执行处置。"
    )
    if extra_text.strip():
        prompt += "\n\n用户补充文字：\n" + extra_text.strip()[:3000]
    content = client.chat(
        [
            {"role": "system", "content": SYSTEM_EXTRACT},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            },
        ],
        temperature=0.05,
        max_tokens=2800,
    )
    alert = _apply_standard_output(content, source_file=str(path), template=tpl)
    return _ensure_domain_from_evidence(alert, alert.raw_text + "\n" + extra_text, tpl)


def _html_to_text(raw: str) -> str:
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(raw, "lxml")
        for tag in soup(["script", "style"]):
            tag.decompose()
        return soup.get_text("\n", strip=True)
    except Exception:
        return re.sub(r"<[^>]+>", "\n", raw)


def _read_any_file_text(path: Path) -> str:
    return file_to_text(path)


def ai_extract_from_file(
    client: AIClient,
    path: str | Path,
    *,
    template: dict[str, Any] | None = None,
    extra_text: str = "",
) -> ExtractedAlert:
    path = Path(path)
    if not path.exists():
        raise AIClientError(f"文件不存在: {path}")
    suffix = path.suffix.lower()
    if suffix in IMAGE_EXTS:
        return ai_extract_from_image(client, path, template=template, extra_text=extra_text)
    text = _read_any_file_text(path)
    if extra_text.strip():
        text = extra_text.strip() + "\n\n" + text
    if not text.strip():
        raise AIClientError("文件内容为空，无法分析")
    return ai_extract_from_text(client, text, template=template, source_file=str(path))


def ai_judge_advice(client: AIClient, fields: dict[str, Any]) -> str:
    content = client.chat(
        [
            {"role": "system", "content": SYSTEM_JUDGE},
            {"role": "user", "content": f"告警字段与历史提交证据：\n{json.dumps(fields, ensure_ascii=False, indent=2)}"},
        ],
        temperature=0.15,
        max_tokens=200,
    )
    return content.strip().strip('"')


def _resolve_path_and_text(
    text: str, path: str | Path | None
) -> tuple[Path | None, str]:
    path_obj = Path(path) if path else None
    clean_text = (text or "").strip()
    if clean_text.startswith("[") and any(
        clean_text.startswith(p) for p in ("[图片]", "[网页文件]", "[剪贴板图片]")
    ):
        for line in clean_text.splitlines():
            p = re.sub(r"^\[(图片|网页文件|剪贴板图片)\]\s*", "", line).split("（")[0].strip()
            if p and Path(p).exists():
                path_obj = Path(p)
                clean_text = ""
                break
    return path_obj, clean_text


def local_extract_text_or_html(
    *,
    text: str = "",
    path: str | Path | None = None,
    template: dict[str, Any] | None = None,
) -> ExtractedAlert:
    """
    本地备选：仅支持纯文字、txt/md/log 与 HTML/MHTML。
    图片等类型明确拒绝（必须使用在线 AI）。
    """
    path_obj, clean_text = _resolve_path_and_text(text, path)
    aliases = (template or {}).get("field_aliases")

    def apply_template_rules(alert: ExtractedAlert) -> ExtractedAlert:
        if not template or not (template.get("field_schema") or {}):
            return _annotate_company_departments(alert)
        alert.template_fields = extract_template_fields(alert.raw_text, template)
        bindings = template.get("field_bindings") or {}
        for label, semantic in bindings.items():
            value = str(alert.template_fields.get(str(label)) or "").strip()
            if value and hasattr(alert, str(semantic)):
                if semantic == "attack_result":
                    value = normalize_result(value)
                    alert.template_fields[str(label)] = value
                setattr(alert, str(semantic), value)
        alert.notes.append(f"模板本地规则解析 {len(alert.template_fields)} 个字段")
        return _annotate_company_departments(alert)

    if path_obj and path_obj.exists():
        suffix = path_obj.suffix.lower()
        if suffix in IMAGE_EXTS:
            alert = ExtractedAlert(source_file=str(path_obj))
            alert.notes.append("本地解析仅支持文本与HTML；图片必须使用在线AI识别")
            return apply_template_rules(alert)
        try:
            alert = parse_local_file(path_obj, field_aliases=aliases)
            kind = "HTML" if suffix in WEB_EXTS else "文本"
            alert.notes.append(f"本地{kind}规则解析")
            return apply_template_rules(alert)
        except Exception as e:
            return ExtractedAlert(source_file=str(path_obj), notes=[f"本地无法解析该类型:{e}"])

    if clean_text:
        alert = parse_text(clean_text, field_aliases=aliases)
        alert.notes.append("本地文本规则解析")
        return apply_template_rules(alert)

    return ExtractedAlert(notes=["无内容可提取"])


def smart_extract(
    *,
    settings: dict[str, Any],
    text: str = "",
    path: str | Path | None = None,
    template: dict[str, Any] | None = None,
    prefer_ai: bool = True,
    require_ai: bool = False,
    analysis_mode: str | None = None,
) -> ExtractedAlert:
    """
    统一入口：自动模式优先 AI，失败时仅文字/HTML 回落本地。
    analysis_mode=local 强制本地；analysis_mode=ai 强制在线 AI。
    """
    path_obj, clean_text = _resolve_path_and_text(text, path)
    tpl = template or load_template(settings.get("active_template") or None)
    is_image = bool(path_obj and path_obj.suffix.lower() in IMAGE_EXTS)
    selected_mode = str(analysis_mode or settings.get("analysis_mode") or "auto").strip().casefold()
    if selected_mode not in {"auto", "local", "ai"}:
        selected_mode = "auto"
    if selected_mode == "local":
        prefer_ai = False
        require_ai = False
    elif selected_mode == "ai":
        prefer_ai = True
        require_ai = True
    if is_image and selected_mode == "local":
        raise AIClientError("本地解析仅支持文本与HTML；图片必须切换到“自动”或“在线AI”模式")
    runtime_settings = dict(settings)
    if is_image:
        vision_name = str(settings.get("ai_vision_profile") or "").strip()
        vision_profile = get_ai_profile(runtime_settings, vision_name or None)
        runtime_settings["ai_base_url"] = vision_profile["base_url"]
        runtime_settings["ai_api_key"] = vision_profile["api_key"]
        runtime_settings["ai_model"] = vision_profile["model"]
        runtime_settings["ai_wire_api"] = vision_profile.get("wire_api") or "auto"
    cfg = AIConfig.from_settings(runtime_settings)

    ai_error: str | None = None
    use_ai_extract = prefer_ai and cfg.ready() and cfg.enabled and cfg.use_for_ocr
    if use_ai_extract:
        try:
            client = AIClient(cfg)
            if path_obj and path_obj.exists():
                alert = ai_extract_from_file(
                    client,
                    path_obj,
                    template=tpl,
                    extra_text=clean_text if clean_text else "",
                )
            else:
                alert = ai_extract_from_text(
                    client, clean_text, template=tpl, source_file=""
                )
            if not cfg.use_for_judge:
                alert.notes = [n for n in alert.notes if not n.startswith("AI_ADVICE::")]
            return _annotate_company_departments(
                _ensure_domain_from_evidence(alert, clean_text or alert.raw_text, tpl)
            )
        except Exception as e:
            ai_error = str(e)
            if require_ai:
                raise AIClientError(f"AI 提取失败: {e}") from e
    elif prefer_ai and require_ai:
        if cfg.ready() and not cfg.use_for_ocr:
            raise AIClientError("AI 识别/提取已关闭，请在配置中心启用")
        raise AIClientError(
            "AI 未就绪：请在配置中心填写当前 AI 配置的 API Key。"
        )
    elif prefer_ai:
        ai_error = "AI 识别/提取已关闭" if cfg.ready() else "AI 未配置或未启用"

    # —— 本地备选：仅文字 / HTML ——
    if is_image:
        alert = ExtractedAlert(source_file=str(path_obj or ""))
        vision_label = str(settings.get("ai_vision_profile") or "GPT 图像识别配置")
        msg = f"图片必须使用在线AI识别；当前“{vision_label}”配置不可用"
        if ai_error:
            msg += f"（{ai_error[:120]}）"
        alert.notes.append(msg)
        raise AIClientError(msg)

    alert = local_extract_text_or_html(text=clean_text, path=path_obj, template=tpl)
    if ai_error:
        alert.notes.insert(0, f"AI不可用已回落本地: {ai_error[:160]}")
    return _annotate_company_departments(alert)


def pull_ai_advice(alert: ExtractedAlert) -> str:
    for n in alert.notes:
        if n.startswith("AI_ADVICE::"):
            return n[len("AI_ADVICE::") :]
    return ""


def rejudge_advice(settings: dict[str, Any], fields: dict[str, Any]) -> str:
    """AI 重出处置意见；失败则抛错（本地不单独做「重判」）。"""
    client = require_client(settings, purpose="judge")
    return ai_judge_advice(client, fields)


def ai_extract_whitelist_rules(settings: dict[str, Any], text: str) -> list[dict[str, str]]:
    """Use the selected online model to propose explicit whitelist rules."""
    body = (text or "").strip()
    if not body:
        raise AIClientError("没有可分析的白名单文本")
    client = require_client(settings, purpose="extract")
    prompt = """从输入中提取明确声明为白名单、可信、允许、公司出口、DNS、VPN、扫描器或授权渗透地址的 IP/CIDR。
不要把普通攻击IP、目标IP或未说明用途的地址加入白名单。只输出 JSON：
{"rules":[{"rule":"1.2.3.4/32","reason":"原文证据"}]}
没有可靠候选时返回 {"rules":[]}。"""
    content = client.chat([
        {"role": "system", "content": prompt},
        {"role": "user", "content": body[:16000]},
    ], temperature=0, max_tokens=1200)
    data = extract_json_object(content)
    rules = data.get("rules") or []
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in rules if isinstance(rules, list) else []:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("rule") or "").strip()
        if not rule or rule.casefold() in seen:
            continue
        seen.add(rule.casefold())
        result.append({"rule": rule, "reason": str(item.get("reason") or "AI提取").strip(), "source": "AI提取"})
    return result
