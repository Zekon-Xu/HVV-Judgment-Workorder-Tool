# -*- coding: utf-8 -*-
"""提取模板：保存/导入/复用，供 AI 智能提取。"""

from __future__ import annotations

import json
import re
import shutil
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import APP_ROOT, BUNDLE_ROOT, CONFIG_DIR
from .io_utils import atomic_write_text

TEMPLATES_DIR = CONFIG_DIR / "templates"
BUILTIN_TEMPLATE_NAME = "自定义手动模板"
LEGACY_BUILTIN_TEMPLATE_NAME = "默认工单字段"

DEFAULT_TEMPLATE: dict[str, Any] = {
    "name": BUILTIN_TEMPLATE_NAME,
    "version": 1,
    "description": "空白手动模板。可逐项添加字段名和字段值，或上传样本文本生成字段。",
    "created_at": "",
    "field_schema": {},
    "field_rows": {},
    "field_options": {},
    "field_aliases": {},
    "field_bindings": {},
    "local_rules": [],
    "ai_prompt": "",
    "extra_prompt": "",
    "sample_text": "",
}

_FIELD_BINDING_ALIASES: dict[str, tuple[str, ...]] = {
    "number": ("编号", "工单编号"),
    "source": ("监测来源", "来源平台"),
    "time": ("时间", "告警时间", "事件时间"),
    "attack_ip": ("攻击IP", "源IP", "攻击者IP"),
    "target_ip": ("目标IP", "目的IP", "受害IP"),
    "xff": ("XFF", "X-Forwarded-For"),
    "domain_url": ("域名URL", "URL", "URI", "请求URL"),
    "alert_level": ("告警级别", "危害等级", "威胁等级"),
    "attack_name": ("攻击名称", "规则名称", "告警名称"),
    "event_type": ("事件类型", "攻击类型"),
    "event_level": ("事件等级", "事件级别"),
    "attack_result": ("攻击结果", "失陷状态"),
    "is_whitelist": ("是否白名单", "白名单"),
    "advice": ("处置建议", "处置意见"),
}


def infer_field_binding(label: str) -> str:
    folded = re.sub(r"[\s_\-：:]", "", str(label or "")).casefold()
    for semantic, aliases in _FIELD_BINDING_ALIASES.items():
        if folded == semantic.casefold() or any(
            folded == re.sub(r"[\s_\-：:]", "", alias).casefold() for alias in aliases
        ):
            return semantic
    return ""


def _value_parser(value: str) -> str:
    text = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{1,6}", text):
        return "order_number"
    if re.search(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}(?::\d{2})?", text):
        return "datetime"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", text):
        return "ip_or_cidr"
    if re.match(r"https?://", text, re.I):
        return "url"
    if re.fullmatch(r"\d+", text):
        return "integer"
    return "text"


def _binding_from_sample(label: str, value: str) -> str:
    explicit = infer_field_binding(label)
    if explicit:
        return explicit
    parser = _value_parser(value)
    if parser == "order_number":
        return "number"
    if parser == "datetime":
        return "time"
    folded = str(value or "").casefold()
    if any(token in folded for token in ("奇安信", "360", "xdr", "一体化平台")):
        return "source"
    return ""


def enrich_template_runtime(template: dict[str, Any]) -> dict[str, Any]:
    """Attach deterministic local rules and a template-specific AI prompt."""
    data = deepcopy(template)
    schema = data.get("field_schema") if isinstance(data.get("field_schema"), dict) else {}
    samples = data.get("sample_fields") if isinstance(data.get("sample_fields"), dict) else {}
    raw_bindings = data.get("field_bindings") if isinstance(data.get("field_bindings"), dict) else {}
    bindings: dict[str, str] = {}
    rules: list[dict[str, Any]] = []
    for position, raw_label in enumerate(schema, start=1):
        label = str(raw_label)
        sample = str(samples.get(label) or "")
        semantic = str(raw_bindings.get(label) or _binding_from_sample(label, sample))
        if semantic:
            bindings[label] = semantic
        rules.append({
            "field": label,
            "aliases": [label],
            "position": position,
            "parser": _value_parser(sample),
            "semantic": semantic,
        })
    data["field_schema"] = schema
    data["field_bindings"] = bindings
    data["local_rules"] = rules
    field_list = "、".join(str(label) for label in schema)
    data["ai_prompt"] = (
        f"当前模板字段依次为：{field_list}。"
        "先输出【当前模板工单初版】，严格逐行使用这些字段名和顺序；"
        "再输出【标准研判字段】供白名单、历史和处置规则使用。"
    ) if schema else ""
    return data


def extract_template_fields(text: str, template: dict[str, Any]) -> dict[str, str]:
    """Apply the template's generated label rules to text or flattened HTML."""
    source = str(text or "")
    direct = sample_fields_from_text(source)
    result: dict[str, str] = {}
    lines = [line.strip() for line in source.replace("\r", "\n").split("\n")]
    for rule in enrich_template_runtime(template).get("local_rules") or []:
        label = str(rule.get("field") or "")
        aliases = [str(item) for item in (rule.get("aliases") or [label]) if str(item)]
        value = next((direct.get(alias, "") for alias in aliases if direct.get(alias, "")), "")
        if not value:
            for index, line in enumerate(lines):
                if line not in aliases:
                    continue
                value = next((candidate for candidate in lines[index + 1:index + 4] if candidate), "")
                break
        result[label] = value
    return result


def ensure_templates_dir() -> Path:
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    # 从 bundle 拷贝内置模板
    for src_root in (BUNDLE_ROOT / "config" / "templates", APP_ROOT / "config" / "templates"):
        if src_root.exists() and src_root.resolve() != TEMPLATES_DIR.resolve():
            for f in src_root.glob("*.json"):
                dest = TEMPLATES_DIR / f.name
                if not dest.exists():
                    try:
                        shutil.copy2(f, dest)
                    except Exception:
                        pass
    default_path = TEMPLATES_DIR / "default.json"
    if not default_path.exists():
        atomic_write_text(
            default_path,
            json.dumps(DEFAULT_TEMPLATE, ensure_ascii=False, indent=2) + "\n",
        )
    return TEMPLATES_DIR


def _safe_name(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\s]+', "_", (name or "template").strip())
    return name[:80] or "template"


def list_templates() -> list[dict[str, Any]]:
    ensure_templates_dir()
    items: list[dict[str, Any]] = []
    for path in sorted(TEMPLATES_DIR.glob("*.json")):
        try:
            data = _validate_template(json.loads(path.read_text(encoding="utf-8")))
            items.append({
                "name": data.get("name") or path.stem,
                "path": str(path),
                "description": data.get("description", ""),
            })
        except Exception:
            continue
    if not items:
        p = save_template(DEFAULT_TEMPLATE)
        items.append({"name": DEFAULT_TEMPLATE["name"], "path": str(p), "description": ""})
    return sorted(items, key=lambda item: (item["name"] != BUILTIN_TEMPLATE_NAME, item["name"].casefold()))


def _validate_template(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("模板文件必须包含一个 JSON 对象")
    name = str(data.get("name") or "").strip()
    if not name:
        raise ValueError("模板名称不能为空")
    if len(name) > 80:
        raise ValueError("模板名称不能超过 80 个字符")
    schema = data.get("field_schema")
    if schema is not None and not isinstance(schema, dict):
        raise ValueError("field_schema 必须是对象")
    aliases = data.get("field_aliases")
    if aliases is not None and not isinstance(aliases, dict):
        raise ValueError("field_aliases 必须是对象")
    for key in ("field_rows", "field_options"):
        value = data.get(key)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"{key} 必须是对象")
    return deepcopy(data)


def load_template(path_or_name: str | Path | None = None) -> dict[str, Any]:
    ensure_templates_dir()
    if not path_or_name:
        return deepcopy(DEFAULT_TEMPLATE)
    if str(path_or_name).strip() == LEGACY_BUILTIN_TEMPLATE_NAME:
        path_or_name = BUILTIN_TEMPLATE_NAME
    p = Path(path_or_name)
    if not p.exists():
        # 按名称找
        for item in list_templates():
            if item["name"] == str(path_or_name) or Path(item["path"]).stem == str(path_or_name):
                p = Path(item["path"])
                break
    if not p.exists():
        return deepcopy(DEFAULT_TEMPLATE)
    data = _validate_template(json.loads(p.read_text(encoding="utf-8")))
    if p.name.casefold() == "default.json" and data.get("name") == LEGACY_BUILTIN_TEMPLATE_NAME:
        data["name"] = BUILTIN_TEMPLATE_NAME
    merged = deepcopy(DEFAULT_TEMPLATE)
    merged.update(data)
    # User templates are authoritative.  Switching a template must remove
    # fields that are absent from its schema instead of restoring legacy rows.
    merged["field_schema"] = deepcopy(data.get("field_schema") or {})
    merged["field_aliases"] = deepcopy(data.get("field_aliases") or {})
    bindings = data.get("field_bindings") if isinstance(data.get("field_bindings"), dict) else {}
    merged["field_bindings"] = {
        str(label): str(bindings.get(label) or infer_field_binding(str(label)))
        for label in merged["field_schema"]
        if str(bindings.get(label) or infer_field_binding(str(label)))
    }
    return enrich_template_runtime(merged)


def save_template(template: dict[str, Any], path: str | Path | None = None) -> Path:
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    data = enrich_template_runtime(_validate_template(template))
    data.setdefault("version", 1)
    data.setdefault("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    name = data.get("name") or "template"
    if path is None:
        path = TEMPLATES_DIR / f"{_safe_name(name)}.json"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    return path


def add_manual_template_field(
    path_or_name: str | Path,
    label: str,
    value: str = "",
    *,
    rows: int = 1,
    options: list[str] | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Append one user-defined field to a template without changing its order."""
    label = str(label or "").strip()
    if not label:
        raise ValueError("字段名不能为空")
    if len(label) > 80:
        raise ValueError("字段名不能超过 80 个字符")
    try:
        rows = max(1, min(12, int(rows)))
    except (TypeError, ValueError) as exc:
        raise ValueError("字段行数必须是 1 到 12 的整数") from exc
    cleaned_options: list[str] = []
    for option in options or []:
        option = str(option or "").strip()
        if option and option not in cleaned_options:
            cleaned_options.append(option)
    if len(cleaned_options) > 30:
        raise ValueError("自定义选项最多 30 个")
    if any(len(option) > 120 for option in cleaned_options):
        raise ValueError("自定义选项不能超过 120 个字符")
    template = load_template(path_or_name)
    schema = dict(template.get("field_schema") or {})
    if label in schema:
        raise ValueError(f"字段“{label}”已存在")
    schema[label] = label
    samples = dict(template.get("sample_fields") or {})
    initial_value = str(value or "").strip()
    if cleaned_options and initial_value not in cleaned_options:
        initial_value = cleaned_options[0]
    samples[label] = initial_value
    field_rows = dict(template.get("field_rows") or {})
    field_rows[label] = rows
    template["field_rows"] = field_rows
    field_options = dict(template.get("field_options") or {})
    if cleaned_options:
        field_options[label] = cleaned_options
    else:
        field_options.pop(label, None)
    template["field_options"] = field_options
    template["field_schema"] = schema
    template["sample_fields"] = samples
    sample_line = f"{label}：{samples[label]}"
    prior_sample = str(template.get("sample_text") or "").strip()
    template["sample_text"] = f"{prior_sample}\n{sample_line}".strip()

    target = _template_storage_path(path_or_name, template)
    return save_template(template, target), enrich_template_runtime(template)


def _template_storage_path(path_or_name: str | Path, template: dict[str, Any]) -> Path:
    requested = Path(path_or_name)
    if requested.is_file():
        target = requested.resolve()
        if target.parent != TEMPLATES_DIR.resolve():
            raise ValueError("只能编辑模板目录中的文件")
        return target
    if template.get("name") == BUILTIN_TEMPLATE_NAME:
        return TEMPLATES_DIR / "default.json"
    return TEMPLATES_DIR / f"{_safe_name(str(template['name']))}.json"


def remove_template_field(path_or_name: str | Path, label: str) -> tuple[Path, dict[str, Any]]:
    """Remove one named field and its sample value from a saved template."""
    template = load_template(path_or_name)
    schema = dict(template.get("field_schema") or {})
    if label not in schema:
        raise ValueError(f"字段“{label}”不存在")
    del schema[label]
    template["field_schema"] = schema
    samples = dict(template.get("sample_fields") or {})
    samples.pop(label, None)
    template["sample_fields"] = samples
    field_rows = dict(template.get("field_rows") or {})
    field_rows.pop(label, None)
    template["field_rows"] = field_rows
    field_options = dict(template.get("field_options") or {})
    field_options.pop(label, None)
    template["field_options"] = field_options
    template["field_bindings"] = {
        key: value for key, value in (template.get("field_bindings") or {}).items() if key != label
    }
    pattern = re.compile(rf"^\s*{re.escape(label)}\s*(?:：|:|=).*$", re.M)
    template["sample_text"] = "\n".join(
        line for line in str(template.get("sample_text") or "").splitlines() if not pattern.match(line)
    ).strip()
    target = _template_storage_path(path_or_name, template)
    return save_template(template, target), enrich_template_runtime(template)


def move_template_field(
    path_or_name: str | Path,
    label: str,
    target_index: int,
) -> tuple[Path, dict[str, Any]]:
    """Move one field to a zero-based position while preserving all values."""
    template = load_template(path_or_name)
    fields = list((template.get("field_schema") or {}).items())
    names = [str(name) for name, _ in fields]
    if label not in names:
        raise ValueError(f"字段“{label}”不存在")
    source_index = names.index(label)
    target_index = max(0, min(int(target_index), len(fields) - 1))
    if source_index == target_index:
        return _template_storage_path(path_or_name, template), template
    item = fields.pop(source_index)
    fields.insert(target_index, item)
    template["field_schema"] = dict(fields)
    samples = dict(template.get("sample_fields") or {})
    template["sample_fields"] = {name: samples.get(name, "") for name, _ in fields}
    field_rows = dict(template.get("field_rows") or {})
    template["field_rows"] = {name: field_rows[name] for name, _ in fields if name in field_rows}
    field_options = dict(template.get("field_options") or {})
    template["field_options"] = {
        name: field_options[name] for name, _ in fields if name in field_options
    }
    target = _template_storage_path(path_or_name, template)
    return save_template(template, target), enrich_template_runtime(template)


def export_template(template: dict[str, Any], dest: str | Path) -> Path:
    return save_template(template, dest)


def import_template_file(src: str | Path) -> Path:
    src = Path(src)
    data = json.loads(src.read_text(encoding="utf-8"))
    if "name" not in data:
        data["name"] = src.stem
    data = _validate_template(data)
    if data["name"] == BUILTIN_TEMPLATE_NAME:
        raise ValueError("不能用导入文件覆盖内置模板")
    dest = TEMPLATES_DIR / f"{_safe_name(data['name'])}.json"
    if dest.exists():
        stem = _safe_name(data["name"])
        suffix = 2
        while dest.exists():
            data["name"] = f"{stem}_{suffix}"
            dest = TEMPLATES_DIR / f"{_safe_name(data['name'])}.json"
            suffix += 1
    return save_template(data, dest)


def delete_template(path_or_name: str | Path) -> bool:
    """Delete a user template while keeping the built-in template protected."""
    ensure_templates_dir()
    candidate = Path(path_or_name)
    target: Path | None = candidate if candidate.exists() and candidate.is_file() else None
    if target is None:
        wanted = str(path_or_name).strip()
        for item in list_templates():
            if item["name"] == wanted or Path(item["path"]).stem == wanted:
                target = Path(item["path"])
                break
    if target is None or not target.exists():
        return False
    target = target.resolve()
    if target.parent != TEMPLATES_DIR.resolve():
        raise ValueError("只能删除模板目录中的文件")
    data = _validate_template(json.loads(target.read_text(encoding="utf-8")))
    if data.get("name") == BUILTIN_TEMPLATE_NAME or target.name.casefold() == "default.json":
        raise ValueError("内置模板不能删除")
    target.unlink()
    return True


def template_from_fields(
    name: str,
    fields: dict[str, str],
    *,
    sample_text: str = "",
    extra_prompt: str = "",
    description: str = "",
) -> dict[str, Any]:
    """根据当前工单字段样例生成可复用模板。"""
    schema = {str(k).strip(): str(k).strip() for k in fields if str(k).strip()}
    return enrich_template_runtime({
        "name": name,
        "version": 1,
        "description": description or f"由工单字段生成 {datetime.now():%Y-%m-%d}",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "field_schema": schema,
        "field_aliases": {},
        "field_bindings": {},
        "extra_prompt": extra_prompt,
        "sample_text": (sample_text or "")[:4000],
        "sample_fields": {k: str(fields.get(k, "") or "") for k in schema},
    })


def sample_fields_from_text(text: str) -> dict[str, str]:
    """Read ordered ``label: value`` sample fields without calling an AI."""
    result: dict[str, str] = {}
    for raw in (text or "").replace("\r", "\n").split("\n"):
        match = re.match(r"^\s*([^:=：]{1,80}?)\s*(?:：|:|=)\s*(.*?)\s*$", raw.strip())
        if not match:
            continue
        label, value = match.group(1).strip(), match.group(2).strip()
        if label and label not in result:
            result[label] = value
    return result


def template_from_sample(name: str, sample_text: str, *, description: str = "") -> dict[str, Any]:
    """Create an exact, blank field schema from the user's sample text."""
    fields = sample_fields_from_text(sample_text)
    if not fields:
        raise ValueError("样本文本中未找到“字段名：值”或“字段名=值”格式")
    return template_from_fields(
        name,
        fields,
        sample_text=sample_text,
        description=description or "根据样本文本生成的字段模板",
    )


def build_template_prompt_section(template: dict[str, Any]) -> str:
    lines = [
        f"提取模板：{template.get('name', '')}",
        f"说明：{template.get('description', '')}",
        "字段定义：",
    ]
    for k, desc in (template.get("field_schema") or {}).items():
        lines.append(f"- {k}: {desc}")
    if template.get("field_schema"):
        lines.append("输出要求：先在【当前模板工单初版】中严格按以上字段名和顺序逐行输出，再输出【标准研判字段】供本地规则处理。")
    aliases = template.get("field_aliases") or {}
    if aliases:
        lines.append("字段别名映射：")
        for k, arr in aliases.items():
            lines.append(f"- {k} 可能写作: {', '.join(arr)}")
    if template.get("sample_text"):
        lines.append("样例原文（参考版式，勿照抄IP）：")
        lines.append(str(template["sample_text"])[:1500])
    if template.get("sample_fields"):
        lines.append("样例字段（参考结构）：")
        lines.append(json.dumps(template["sample_fields"], ensure_ascii=False, indent=2)[:1200])
    if template.get("extra_prompt"):
        lines.append("额外规则：")
        lines.append(str(template["extra_prompt"]))
    if template.get("ai_prompt"):
        lines.append("当前模板动态提示词：")
        lines.append(str(template["ai_prompt"]))
    return "\n".join(lines)
