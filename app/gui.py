# -*- coding: utf-8 -*-
"""独立窗口 GUI：圆角卡片、透明度、昼夜主题与 Logo。

Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import webbrowser
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk

from .branding import load_logo_ctk
from .company_networks import CompanyNetworkStore, extract_company_rules_from_file
from .drop_support import FileDropTarget
from .default_whitelist import company_attribution_lines, company_network_match
from .constants import (
    ALERT_LEVELS,
    APP_DISPLAY_NAME,
    APP_ROOT,
    ASSETS_DIR,
    ATTACK_RESULTS,
    DESIGNER_CREDIT,
    EVENT_LEVELS,
    MONITOR_SOURCE_IP,
    MONITOR_SOURCE_NAMES,
    THEME_COLORS,
    WHITELIST_OPTIONS,
)
from .ai_client import AIConfig, WIRE_API_CHOICES, detect_wire_api
from .ai_extract import smart_extract
from .batch_engine import (
    BatchJob,
    jobs_from_paths,
    jobs_from_text_blob,
    process_batch,
)
from .extractor import ExtractedAlert, SPREADSHEET_EXTS
from .history import HistoryStore
from .history_sync import HistorySyncError, normalize_sync_urls, sync_history_urls
from .order_builder import (
    WorkOrder,
    assemble_order,
    normalize_result,
)
from .project_profiles import (
    list_project_profiles,
    load_project_profile,
    restore_blank_workspace,
    save_project_profile,
)
from .settings_store import (
    auto_next_seq,
    commit_number,
    delete_ai_profile,
    DEFAULT_SETTINGS,
    get_ai_profile,
    load_settings,
    normalize_ai_profiles,
    peek_number,
    resolve_number,
    save_settings,
    upsert_ai_profile,
    validate_number_date,
    validate_number_seq,
)
from .template_store import (
    BUILTIN_TEMPLATE_NAME,
    delete_template,
    add_manual_template_field,
    import_template_file,
    list_templates,
    load_template,
    move_template_field,
    remove_template_field,
    save_template,
    template_from_sample,
    sample_fields_from_text,
)
from .threatbook import ThreatBookClient, ThreatBookError, indicator_type
from .tray_icon import TrayController
from .whitelist import WhitelistEngine, check_alert_whitelist_gate, extract_ips
from .whitelist_import import merge_rules_from_file

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}
WEB_EXTS = {".html", ".htm", ".mhtml", ".mht"}
TEXT_EXTS = {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".xml"} | SPREADSHEET_EXTS
SUPPORTED_DROP_EXTS = IMAGE_EXTS | WEB_EXTS | TEXT_EXTS
ANALYSIS_MODE_LABELS = {"自动": "auto", "本地解析": "local", "在线AI": "ai"}
ANALYSIS_MODE_NAMES = {value: key for key, value in ANALYSIS_MODE_LABELS.items()}
WIRE_API_LABELS = {
    "auto": "自动识别",
    "chat": "OpenAI Chat Completions",
    "responses": "OpenAI Responses",
    "anthropic": "Anthropic Messages",
}
WIRE_API_CODES = {label: code for code, label in WIRE_API_LABELS.items()}
AI_PROVIDER_PRESETS = {
    "自定义": ("", "", "auto"),
    "OpenAI": ("https://api.openai.com/v1", "gpt-5.6-luna", "responses"),
    "Claude": ("https://api.anthropic.com/v1", "claude-sonnet-4-5", "anthropic"),
    "DeepSeek": ("https://api.deepseek.com/v1", "deepseek-v4-flash", "chat"),
    "Kimi / Moonshot": ("https://api.moonshot.ai/v1", "kimi-k2.6", "chat"),
    "MiniMax": ("https://api.minimax.io/v1", "MiniMax-M2.5", "chat"),
    "Qwen / DashScope": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-plus", "chat"),
    "SiliconFlow": ("https://api.siliconflow.cn/v1", "deepseek-ai/DeepSeek-V3.2", "chat"),
    "Grok / xAI": ("https://api.x.ai/v1", "grok-4.5", "chat"),
}


def _whitelist_role_label(role: str) -> str:
    value = str(role or "").strip()
    if value in {"目标/受害/目的IP", "目标IP", "受害IP", "目的IP"}:
        return "目的IP"
    if value in {"域名/URL内IP", "域名/URL中的IP"}:
        return "域名URL中的IP"
    return value or "IP"


def _whitelist_items_text(items: list[dict[str, Any]], *, reasons: bool = False) -> str:
    if not items:
        return "无"
    lines: list[str] = []
    for item in items:
        label = _whitelist_role_label(str(item.get("role") or "IP"))
        line = f"【{label} {item.get('ip') or '-'}】"
        if reasons and item.get("reason"):
            line += f"（{item['reason']}）"
        lines.append(line)
    return "\n".join(lines)


def _work_order_ip_shortcuts(order: WorkOrder | None, generated_output: str = "") -> list[str]:
    """Return unique IPs in the current order, preserving the order shown to users."""
    values: list[str] = []
    if order is not None:
        values.extend(
            [order.attack_ip, order.target_ip, order.xff, order.domain_url]
            + list((order.custom_fields or {}).values())
        )
    if generated_output:
        values.append(generated_output)
    result: list[str] = []
    for value in values:
        for ip in extract_ips(str(value or "")):
            if ip not in result:
                result.append(ip)
    return result


def _parse_indicator_input(raw: str) -> list[str]:
    """Split manual threat-intelligence input without silently duplicating values."""
    result: list[str] = []
    for token in re.split(r"[,，;；\s\n]+", str(raw or "").strip()):
        token = token.strip().strip("[](){}<>").strip()
        if token and token not in result:
            result.append(token)
    return result


def _insert_clipboard_text(widget: tk.Misc, text: str) -> None:
    """Insert text using normal Text selection semantics, without touching other editors."""
    target = getattr(widget, "_textbox", widget)
    try:
        target.edit_separator()
    except Exception:
        pass
    try:
        if target.tag_ranges("sel"):
            target.delete("sel.first", "sel.last")
    except Exception:
        pass
    target.insert("insert", text)
    try:
        target.see("insert")
        target.focus_set()
        target.edit_separator()
    except Exception:
        pass


def _record_count_text(total: int, visible: int | None = None, note: str = "") -> str:
    suffix = f"，当前显示 {visible} 条" if visible is not None else ""
    return f"共 {total} 条记录{suffix}{note}"


def _fit_window_geometry(raw: str, screen_width: int, screen_height: int) -> str:
    """Clamp and center a normal window without turning it into fullscreen."""
    match = re.match(r"^\s*(\d+)x(\d+)", str(raw or ""))
    requested_width = int(match.group(1)) if match else 1600
    requested_height = int(match.group(2)) if match else 1000
    available_width = max(900, int(screen_width) - 64)
    available_height = max(680, int(screen_height) - 96)
    width = max(900, min(requested_width, available_width))
    height = max(680, min(requested_height, available_height))
    x = max(0, (int(screen_width) - width) // 2)
    y = max(0, (int(screen_height) - height) // 2 - 12)
    return f"{width}x{height}+{x}+{y}"
def _restart_environment() -> dict[str, str]:
    """Return a clean environment for restarting a PyInstaller one-file app.

    Without the reset flag the child reuses the parent's ``_MEI`` extraction
    directory.  The parent then removes Tcl/Tk while the child is starting,
    causing both the missing ``tcl_data`` and cleanup warning dialogs.
    """
    env = dict(os.environ)
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    env.pop("_PYI_APPLICATION_HOME_DIR", None)
    env.pop("_MEIPASS2", None)
    return env


def _apply_win_round_corners(window: tk.Misc) -> None:
    """Windows 11 圆角窗口（失败则忽略）。"""
    try:
        import ctypes

        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if not hwnd:
            hwnd = window.winfo_id()
        DWMWA_WINDOW_CORNER_PREFERENCE = 33
        DWMWCP_ROUND = 2
        value = ctypes.c_int(DWMWCP_ROUND)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(value), ctypes.sizeof(value)
        )
    except Exception:
        pass


def _rounded_rect_image(w: int, h: int, radius: int, color: str, alpha: int = 230) -> Image.Image:
    img = Image.new("RGBA", (max(w, 1), max(h, 1)), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    r, g, b = tuple(int(color.lstrip("#")[i : i + 2], 16) for i in (0, 2, 4))
    draw.rounded_rectangle((0, 0, w - 1, h - 1), radius=radius, fill=(r, g, b, alpha))
    return img


class Toast(ctk.CTkToplevel):
    """轻量提示浮层。"""

    def __init__(self, master: tk.Misc, text: str, kind: str = "info", ms: int = 2200) -> None:
        super().__init__(master)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        try:
            self.attributes("-alpha", 0.94)
        except Exception:
            pass
        colors = {
            "info": ("#2b3348", "#e8eaed"),
            "ok": ("#1f4d38", "#d8f5e6"),
            "warn": ("#5a4020", "#ffe8b8"),
            "err": ("#5a2228", "#ffd6da"),
            "wl": ("#1e3a5f", "#cfe3ff"),
        }
        bg, fg = colors.get(kind, colors["info"])
        frame = ctk.CTkFrame(self, fg_color=bg, corner_radius=14, border_width=0)
        frame.pack(fill="both", expand=True)
        ctk.CTkLabel(
            frame, text=text, text_color=fg, font=ctk.CTkFont(size=14, weight="bold"),
            wraplength=420, justify="center",
        ).pack(padx=22, pady=16)
        self.update_idletasks()
        self._toast_master = master
        toasts = getattr(master, "_toast_stack", [])
        master._toast_stack = [toast for toast in toasts if toast.winfo_exists()]  # type: ignore[attr-defined]
        master._toast_stack.append(self)  # type: ignore[attr-defined]
        self._reposition_stack()
        self.after(ms, self._dismiss)

    def _dismiss(self) -> None:
        if self.winfo_exists():
            self.destroy()
        self._reposition_stack()

    def _reposition_stack(self) -> None:
        master = self._toast_master
        toasts = [toast for toast in getattr(master, "_toast_stack", []) if toast.winfo_exists()]
        master._toast_stack = toasts  # type: ignore[attr-defined]
        y = master.winfo_rooty() + 70
        for toast in toasts:
            toast.update_idletasks()
            x = master.winfo_rootx() + master.winfo_width() // 2 - toast.winfo_reqwidth() // 2
            toast.geometry(f"+{x}+{y}")
            y += toast.winfo_reqheight() + 8


class ReadOnlyTextDialog(ctk.CTkToplevel):
    """Scrollable viewer for history records and intelligence responses."""

    def __init__(self, master: tk.Misc, title: str, content: str) -> None:
        super().__init__(master)
        self.title(title)
        self.geometry("900x620")
        self.minsize(640, 420)
        self.transient(master)
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=17, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 10)
        )
        box = ctk.CTkTextbox(self, corner_radius=8, border_width=1, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        box.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        box.insert("1.0", content or "（暂无内容）")
        box.configure(state="disabled")
        ctk.CTkButton(self, text="关闭", width=90, command=self.destroy).pack(anchor="e", padx=18, pady=(0, 16))


class ThreatBookLookupDialog(ctk.CTkToplevel):
    """Collect one manually entered indicator or one IP shortcut from the order."""

    def __init__(self, master: tk.Misc, current_ips: list[str]) -> None:
        super().__init__(master)
        self.title("微步情报查询")
        self.geometry("640x360")
        self.minsize(540, 300)
        self.transient(master)
        self.result: list[str] | None = None

        ctk.CTkLabel(
            self, text="微步情报查询", font=ctk.CTkFont(size=17, weight="bold")
        ).pack(anchor="w", padx=18, pady=(16, 10))
        input_row = ctk.CTkFrame(self, fg_color="transparent")
        input_row.pack(fill="x", padx=18, pady=(0, 10))
        ctk.CTkLabel(input_row, text="自定义 IP / 域名", width=116, anchor="w").pack(side="left")
        self.input_var = ctk.StringVar()
        self.input_entry = ctk.CTkEntry(
            input_row, textvariable=self.input_var,
            placeholder_text="可输入工单中未出现的指标",
            corner_radius=8,
        )
        self.input_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            input_row, text="查询输入内容", width=112, corner_radius=8,
            command=self._submit,
        ).pack(side="left", padx=(8, 0))

        shortcut_label_kwargs: dict[str, Any] = {}
        if hasattr(master, "_colors"):
            shortcut_label_kwargs["text_color"] = master._colors()["text_dim"]
        ctk.CTkLabel(
            self, text="当前工单 IP", anchor="w", **shortcut_label_kwargs,
        ).pack(fill="x", padx=18, pady=(0, 5))
        shortcuts = ctk.CTkFrame(self, fg_color="transparent")
        shortcuts.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        columns = 3
        for index, ip in enumerate(current_ips):
            button = ctk.CTkButton(
                shortcuts, text=ip, width=174, height=30, corner_radius=6,
                fg_color="transparent", hover_color="#2d5e91",
                text_color="#76b7ff", anchor="w",
                font=ctk.CTkFont(size=13, underline=True),
                command=lambda value=ip: self._choose(value),
            )
            button.grid(row=index // columns, column=index % columns, sticky="ew", padx=4, pady=3)
        for column in range(columns):
            shortcuts.grid_columnconfigure(column, weight=1)
        if not current_ips:
            ctk.CTkLabel(shortcuts, text="当前工单没有识别到 IP").pack(anchor="w", padx=6, pady=8)

        ctk.CTkButton(
            self, text="取消", width=90, height=32, corner_radius=8,
            fg_color="#596579", command=self.destroy,
        ).pack(anchor="e", padx=18, pady=(0, 16))
        self.bind("<Return>", lambda _event: self._submit())
        self.bind("<Escape>", lambda _event: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(60, self._activate)

    def _activate(self) -> None:
        try:
            self.grab_set()
            self.input_entry.focus_set()
        except Exception:
            pass

    def _choose(self, indicator: str) -> None:
        self.result = [indicator]
        self.destroy()

    def _submit(self) -> None:
        indicators = _parse_indicator_input(self.input_var.get())
        if not indicators:
            messagebox.showwarning("微步情报查询", "请输入至少一个 IP 或域名", parent=self)
            return
        self.result = indicators[:50]
        self.destroy()


class HistoryBrowserDialog(ctk.CTkToplevel):
    """Searchable history browser with an exact-code full-record view."""

    def __init__(self, master: tk.Misc, records: list[dict[str, Any]]) -> None:
        super().__init__(master)
        self.title("历史工单")
        self.geometry("980x700")
        self.minsize(720, 480)
        self.transient(master)
        self.records = list(records or [])
        ctk.CTkLabel(self, text="历史工单", font=ctk.CTkFont(size=17, weight="bold")).pack(
            anchor="w", padx=18, pady=(16, 8)
        )
        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=18, pady=(0, 8))
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(
            search_row, textvariable=self.search_var, placeholder_text="搜索编号、IP、攻击名称、来源等关键字",
            corner_radius=8,
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(search_row, text="查看完整字段", width=130, command=self._show_exact).pack(side="left", padx=(8, 0))
        ctk.CTkButton(search_row, text="关闭", width=82, fg_color="#596579", command=self.destroy).pack(side="left", padx=(8, 0))
        self.status = ctk.CTkLabel(self, text="", anchor="w")
        self.status.pack(fill="x", padx=18, pady=(0, 4))
        self.box = ctk.CTkTextbox(self, corner_radius=8, border_width=1, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        self.box.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        self.search_var.trace_add("write", lambda *_: self._refresh())
        self._refresh()
        self.after(80, self.search_entry.focus_set)

    @staticmethod
    def _summary(record: dict[str, Any], index: int) -> str:
        return (
            f"[{index}] {record.get('code') or '无编号'} | {record.get('time') or '无时间'}\n"
            f"来源：{record.get('source') or '-'}\n"
            f"攻击IP：{record.get('attack_ip') or '-'}  目标IP：{record.get('target_ip') or '-'}\n"
            f"攻击名称：{record.get('attack_name') or '-'}  事件类型：{record.get('event_type') or '-'}\n"
            f"上报人员：{record.get('reporter') or '-'}\n"
        )

    def _refresh(self) -> None:
        query = self.search_var.get().strip().casefold()
        matches = []
        for index, record in enumerate(self.records, start=1):
            haystack = json.dumps(record, ensure_ascii=False).casefold()
            if not query or query in haystack:
                matches.append(self._summary(record, index))
        content = "\n".join(matches) or "（没有匹配的历史工单）"
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.insert("1.0", content)
        self.box.configure(state="disabled")
        self.status.configure(text=f"共 {len(self.records)} 条，当前显示 {len(matches)} 条；输入完整编号后可查看该条全部字段")

    def _show_exact(self) -> None:
        code = self.search_var.get().strip().casefold()
        if not code:
            messagebox.showwarning("历史工单", "请先输入准确的工单编号", parent=self)
            return
        hits = [record for record in self.records if str(record.get("code") or "").strip().casefold() == code]
        if not hits:
            messagebox.showinfo("历史工单", "没有找到该准确编号", parent=self)
            return
        record = hits[0]
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.insert("1.0", json.dumps(record, ensure_ascii=False, indent=2))
        self.box.configure(state="disabled")
        self.status.configure(text=f"已显示编号 {record.get('code')} 的全部字段")


class TemplateTextDialog(ctk.CTkToplevel):
    """Modal editor for a template name and its independent text sample."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.title("新增工单模板")
        self.geometry("680x520")
        self.minsize(560, 440)
        self.transient(master)
        self.result: tuple[str, str] | None = None

        ctk.CTkLabel(
            self, text="新增工单模板", font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w", padx=20, pady=(18, 12))

        name_row = ctk.CTkFrame(self, fg_color="transparent")
        name_row.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkLabel(name_row, text="模板名称", width=76, anchor="w").pack(side="left")
        self.name_var = ctk.StringVar()
        self.name_entry = ctk.CTkEntry(name_row, textvariable=self.name_var, corner_radius=8)
        self.name_entry.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(self, text="模板样本文本", anchor="w").pack(
            fill="x", padx=20, pady=(0, 6)
        )
        self.textbox = ctk.CTkTextbox(
            self, corner_radius=8, border_width=1, wrap="word",
            font=ctk.CTkFont(size=13),
        )
        self.textbox.pack(fill="both", expand=True, padx=20, pady=(0, 14))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=20, pady=(0, 18))
        ctk.CTkButton(
            actions, text="取消", width=90, height=36, corner_radius=8,
            fg_color="#596579", command=self.destroy,
        ).pack(side="right")
        ctk.CTkButton(
            actions, text="解析并新增", width=140, height=36, corner_radius=8,
            command=self._submit,
        ).pack(side="right", padx=(0, 8))

        self.bind("<Escape>", lambda _event: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(50, self._activate)

    def _activate(self) -> None:
        try:
            self.grab_set()
            self.name_entry.focus_set()
        except Exception:
            pass

    def _submit(self) -> None:
        name = self.name_var.get().strip()
        text = self.textbox.get("1.0", "end").strip()
        if not name:
            messagebox.showwarning("模板名称", "请填写模板名称", parent=self)
            return
        if not text:
            messagebox.showwarning("模板文本", "请粘贴或输入模板样本文本", parent=self)
            return
        self.result = (name, text)
        self.destroy()


class ManualFieldDialog(ctk.CTkToplevel):
    """Collect one field name and its initial value for a manual template."""

    def __init__(self, master: tk.Misc, template_name: str) -> None:
        super().__init__(master)
        self.title("添加模板字段")
        self.geometry("520x350")
        self.minsize(460, 300)
        self.transient(master)
        self.result: tuple[str, str, int, list[str]] | None = None

        ctk.CTkLabel(self, text=f"向“{template_name}”添加字段", font=ctk.CTkFont(size=17, weight="bold")).pack(
            anchor="w", padx=20, pady=(18, 14)
        )
        self.name_var = ctk.StringVar()
        self.value_var = ctk.StringVar()
        for label, variable, hint in (
            ("字段名", self.name_var, "例如：攻击次数"),
            ("字段值", self.value_var, "可留空，稍后在字段行填写"),
        ):
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(row, text=label, width=64, anchor="w").pack(side="left")
            ctk.CTkEntry(row, textvariable=variable, placeholder_text=hint, corner_radius=8).pack(
                side="left", fill="x", expand=True
            )

        options_row = ctk.CTkFrame(self, fg_color="transparent")
        options_row.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(options_row, text="行数", width=64, anchor="w").pack(side="left")
        self.rows_var = ctk.StringVar(value="1")
        ctk.CTkComboBox(
            options_row, variable=self.rows_var, values=[str(i) for i in range(1, 13)],
            state="readonly", width=90, corner_radius=8,
        ).pack(side="left")
        self.options_enabled_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            options_row, text="使用自定义选项下拉框",
            variable=self.options_enabled_var, command=self._toggle_options,
        ).pack(side="left", padx=(18, 0))
        self.options_box: ctk.CTkTextbox | None = None
        self.options_hint: ctk.CTkLabel | None = None

        actions = ctk.CTkFrame(self, fg_color="transparent")
        self._actions_frame = actions
        actions.pack(fill="x", padx=20, pady=(16, 18))
        ctk.CTkButton(actions, text="取消", width=88, height=34, corner_radius=8, fg_color="#596579", command=self.destroy).pack(side="right")
        ctk.CTkButton(actions, text="添加字段", width=104, height=34, corner_radius=8, command=self._submit).pack(side="right", padx=(0, 8))
        self.bind("<Escape>", lambda _event: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(50, self._activate)

    def _activate(self) -> None:
        try:
            self.grab_set()
            self.focus_force()
        except Exception:
            pass

    def _submit(self) -> None:
        label = self.name_var.get().strip()
        if not label:
            messagebox.showwarning("字段名", "请输入字段名", parent=self)
            return
        try:
            rows = max(1, min(12, int(self.rows_var.get())))
        except (TypeError, ValueError):
            messagebox.showwarning("字段行数", "字段行数必须是 1 到 12 的整数", parent=self)
            return
        options: list[str] = []
        if self.options_enabled_var.get() and self.options_box is not None:
            for item in self.options_box.get("1.0", "end").splitlines():
                item = item.strip()
                if item and item not in options:
                    options.append(item)
            if not options:
                messagebox.showwarning("自定义选项", "请至少填写一个下拉选项，每行一个", parent=self)
                return
        self.result = (label, self.value_var.get().strip(), rows, options)
        self.destroy()

    def _toggle_options(self) -> None:
        if self.options_enabled_var.get():
            if self.options_box is None:
                self.options_hint = ctk.CTkLabel(
                    self, text="自定义选项（每行一个）", anchor="w",
                )
                self.options_box = ctk.CTkTextbox(
                    self, height=92, corner_radius=8, border_width=1,
                    wrap="word", font=ctk.CTkFont(size=13),
                )
            if self.options_hint is not None:
                self.options_hint.pack(fill="x", padx=20, pady=(2, 2), before=self._actions_frame)
            self.options_box.pack(fill="x", padx=20, pady=(0, 6), before=self._actions_frame)
            self._actions_frame.pack_configure(pady=(8, 18))
            self.geometry("520x430")
        elif self.options_box is not None:
            if self.options_hint is not None:
                self.options_hint.pack_forget()
            self.options_box.pack_forget()
            self._actions_frame.pack_configure(pady=(16, 18))
            self.geometry("520x350")


class FieldRow(ctk.CTkFrame):
    """标签 + 输入行（标签加宽保证完整显示；处置意见支持多行）。"""

    def __init__(
        self,
        master: Any,
        label: str,
        kind: str = "entry",
        values: list[str] | None = None,
        rows: int = 1,
        readonly: bool = False,
        width: int = 320,
        label_width: int = 108,
        height: int = 36,
        actions: list[tuple[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.kind = kind
        self.rows = max(1, min(12, int(rows or 1)))
        self.readonly = bool(readonly)
        self.var = ctk.StringVar(value=(values or [""])[0] if kind == "combo" and values else "")
        self.grid_columnconfigure(1, weight=1)

        self.label_w = ctk.CTkLabel(
            self,
            text=label,
            width=label_width,
            anchor="e",
            font=ctk.CTkFont(size=13),
            justify="right",
        )
        self.label_w.grid(row=0, column=0, sticky="ne", padx=(4, 10), pady=(6, 4))

        if kind == "combo":
            self.widget = ctk.CTkComboBox(
                self,
                values=values or [""],
                variable=self.var,
                width=width,
                height=height,
                corner_radius=10,
                font=ctk.CTkFont(size=13),
                dropdown_font=ctk.CTkFont(size=13),
                state="readonly" if self.readonly else "normal",
            )
            self.widget.grid(row=0, column=1, sticky="ew", pady=3)
        elif kind == "text":
            # 处置意见等多行字段（约 2~3 行）
            self.widget = ctk.CTkTextbox(
                self,
                width=width,
                height=max(height, self.rows * 28 + 24, 78),
                corner_radius=10,
                font=ctk.CTkFont(size=13),
                wrap="word",
            )
            self.widget.grid(row=0, column=1, sticky="ew", pady=3)
        else:
            self.widget = ctk.CTkEntry(
                self,
                textvariable=self.var,
                width=width,
                height=height,
                corner_radius=10,
                font=ctk.CTkFont(size=13),
            )
            self.widget.grid(row=0, column=1, sticky="ew", pady=3)
        self.action_buttons: list[ctk.CTkButton] = []
        for index, (text, command) in enumerate(actions or []):
            button = ctk.CTkButton(
                self, text=text, command=command, width=28, height=28,
                corner_radius=6, font=ctk.CTkFont(size=13),
            )
            button.grid(row=0, column=index + 2, padx=(6 if index == 0 else 2, 0), pady=3)
            self.action_buttons.append(button)

    def get(self) -> str:
        if self.kind == "text":
            return self.widget.get("1.0", "end").strip()
        return self.var.get().strip()

    def set(self, value: str) -> None:
        value = value or ""
        if self.kind == "text":
            self.widget.delete("1.0", "end")
            if value:
                self.widget.insert("1.0", value)
        else:
            if self.kind == "combo" and self.readonly:
                allowed = list(self.widget.cget("values") or [])
                if value not in allowed:
                    value = allowed[0] if allowed else ""
            self.var.set(value)

    def apply_theme(self, colors: dict[str, str]) -> None:
        try:
            self.label_w.configure(text_color=colors.get("text"))
        except Exception:
            pass
        try:
            if self.kind == "text":
                self.widget.configure(
                    fg_color=colors.get("input"),
                    text_color=colors.get("text"),
                    border_color=colors.get("border"),
                )
            elif self.kind == "combo":
                self.widget.configure(
                    fg_color=colors.get("input"),
                    border_color=colors.get("border"),
                    button_color=colors.get("accent"),
                    button_hover_color=colors.get("accent"),
                    text_color=colors.get("text"),
                    dropdown_fg_color=colors.get("card"),
                    dropdown_text_color=colors.get("text"),
                    dropdown_hover_color=colors.get("card_hover"),
                )
            else:
                self.widget.configure(
                    fg_color=colors.get("input"),
                    border_color=colors.get("border"),
                    text_color=colors.get("text"),
                )
        except Exception:
            pass
        for button in self.action_buttons:
            try:
                button.configure(fg_color=colors.get("card_hover"), hover_color=colors.get("accent"), text_color=colors.get("text"))
            except Exception:
                pass


class WorkOrderApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.title(str(self.settings.get("app_title") or APP_DISPLAY_NAME))
        geo = self.settings.get("window_geometry") or "1600x1000+0+0"
        self.geometry(_fit_window_geometry(str(geo), self.winfo_screenwidth(), self.winfo_screenheight()))
        self.minsize(
            min(1080, max(900, self.winfo_screenwidth() - 64)),
            min(720, max(680, self.winfo_screenheight() - 96)),
        )

        self.wl = WhitelistEngine()
        self.company_store = CompanyNetworkStore()
        self.history = HistoryStore()
        if not self.history.records:
            self._try_load_history_silent()

        self._theme = self.settings.get("theme", "dark")
        self._window_opacity = float(self.settings.get("window_opacity", 1.0) or 1.0)
        self._window_opacity = min(1.0, max(0.65, self._window_opacity))
        self._branding_preview: dict[str, Any] | None = None
        self._logo_ctk = None
        self._window_icon_photo = None
        self._pending_image: str = ""
        self._pending_file: str = ""
        self._last_order: WorkOrder | None = None
        self._generated_output = ""
        self._ai_raw_output = ""
        self._analysis_notes = ""
        self._current_alert = None
        self._current_alert: ExtractedAlert | None = None
        self._last_copied_number = ""
        self._extracting = False
        self._analysis_progress_started_at: datetime | None = None
        self._analysis_progress_job: str | None = None
        self._batching = False
        self._batch_jobs: list[BatchJob] = []
        self._tray: TrayController | None = None
        self._drop_target: FileDropTarget | None = None
        self._really_quit = False
        self._history_sync_started_at = datetime.now()
        self._history_sync_failure_alerted = False

        ctk.set_appearance_mode("Dark" if self._theme == "dark" else "Light")
        ctk.set_default_color_theme("blue")

        self._build_chrome()
        self._build_layout()
        self._apply_theme_colors()
        self._apply_logo(self.settings.get("logo_path") or "")
        self._apply_brand_text(self.settings)
        self._apply_window_opacity(self._window_opacity)
        self.after(200, lambda: _apply_win_round_corners(self))
        if self.settings.get("window_state", "normal") == "zoomed":
            self.after(80, self._maximize_window)
        self.after(300, self._setup_drag_drop)
        self.after(400, self._setup_tray)
        self.after(1200, self._schedule_history_sync)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # 默认编号日期：今天 MMDD；序号填入当前自动下一号
        today = datetime.now().strftime("%m%d")
        saved = self.settings.get("number_date") or today
        self.number_date_var.set(saved)
        self._fill_auto_seq()
        self._refresh_number_preview()

    def _maximize_window(self) -> None:
        try:
            self.state("zoomed")
        except tk.TclError:
            pass

    def _capture_window_placement(self) -> None:
        state = self.state()
        if state not in {"normal", "zoomed"}:
            return
        self.settings["window_state"] = state
        if state == "normal":
            self.settings["window_geometry"] = self.geometry()

    # ── 外观 ──────────────────────────────────────────
    def _colors(self) -> dict[str, str]:
        return THEME_COLORS.get(self._theme, THEME_COLORS["dark"])

    def _build_chrome(self) -> None:
        self.configure(fg_color=self._colors()["bg"])
        self.bg_canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=self._colors()["bg"])
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        try:
            self.bg_canvas.lower()
        except Exception:
            pass
        self.bind("<Configure>", self._on_resize, add="+")

    def _on_resize(self, event: tk.Event | None = None) -> None:
        if event and event.widget is not self:
            return
        # 防抖：避免拖拽窗口时频繁重绘闪烁
        if getattr(self, "_resize_job", None):
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
        self._resize_job = self.after(80, self._redraw_background)

    def _redraw_background(self) -> None:
        if not hasattr(self, "bg_canvas"):
            return
        try:
            w, h = max(self.winfo_width(), 1), max(self.winfo_height(), 1)
            if w < 40 or h < 40:
                return
            c = self._colors()
            self.bg_canvas.configure(width=w, height=h, bg=c["bg"])
            self.bg_canvas.delete("all")
            self.bg_canvas.create_rectangle(0, 0, w, h, fill=c["bg"], outline="", tags="bg")
            if hasattr(self, "cfg_left_scroll"):
                self._style_scroll_descendants(self.cfg_left_scroll, c)
            try:
                self.bg_canvas.lower()
            except Exception:
                pass
        except Exception:
            pass

    def _apply_logo(self, path: str) -> None:
        """更新顶栏 Logo。"""
        path = (path or "").strip()
        if hasattr(self, "logo_var") and self.logo_var.get().strip() != path:
            self.logo_var.set(path)
        self._logo_ctk = None
        resolved = Path(path) if path else None
        if resolved and resolved.exists():
            self._logo_ctk = load_logo_ctk(resolved, size=(40, 40))
            try:
                icon = Image.open(resolved).convert("RGBA")
                self._window_icon_photo = ImageTk.PhotoImage(icon)
                self.iconphoto(True, self._window_icon_photo)
            except Exception:
                pass
        if hasattr(self, "logo_label"):
            try:
                if self._logo_ctk is not None:
                    self.logo_label.configure(image=self._logo_ctk, text="")
                else:
                    self.logo_label.configure(image=None, text="")
            except Exception:
                try:
                    self.logo_label.configure(text="")
                except Exception:
                    pass

    def _apply_brand_text(self, source: dict[str, Any]) -> None:
        title = str(source.get("app_title") or APP_DISPLAY_NAME).strip() or APP_DISPLAY_NAME
        subtitle = str(source.get("subtitle_text") or DESIGNER_CREDIT).strip()
        enabled = bool(source.get("subtitle_enabled", True))
        self.title(title)
        if hasattr(self, "title_label"):
            self.title_label.configure(text=title)
        if hasattr(self, "subtitle_label"):
            self.subtitle_label.configure(text=subtitle)
            if enabled:
                if not self.subtitle_label.winfo_manager():
                    self.subtitle_label.pack(anchor="w")
            else:
                self.subtitle_label.pack_forget()

    def _apply_window_opacity(self, value: float) -> None:
        self._window_opacity = min(1.0, max(0.65, float(value)))
        try:
            self.attributes("-alpha", self._window_opacity)
        except tk.TclError:
            pass

    def _on_window_opacity(self, value: str) -> None:
        self._apply_window_opacity(float(value))
        self.settings["window_opacity"] = self._window_opacity
        if hasattr(self, "opacity_value_label"):
            self.opacity_value_label.configure(text=f"{round(self._window_opacity * 100)}%")

    def _apply_theme_colors(self) -> None:
        c = self._colors()
        # 先切 appearance，再刷组件，避免 CTk 内部 canvas 残留反色块
        ctk.set_appearance_mode("Dark" if self._theme == "dark" else "Light")
        # 窗口底色和卡片均使用当前主题的实色。
        self.configure(fg_color=c["bg"])
        if hasattr(self, "root_frame"):
            self.root_frame.configure(fg_color="transparent")
        if hasattr(self, "body"):
            self.body.configure(fg_color="transparent")
        for page_name in ("page_work", "page_batch", "page_config"):
            page = getattr(self, page_name, None)
            if page is not None:
                page.configure(fg_color="transparent")
        self._style_cards()
        self._style_theme_widgets()
        self._redraw_background()

    def _style_cards(self) -> None:
        c = self._colors()
        for name in (
            "left_card", "right_card", "bottom_card", "top_bar", "cfg_card", "batch_card",
        ):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.configure(
                    fg_color=c["card"],
                    border_color=c["border"],
                    border_width=1,
                    corner_radius=8,
                )

    def _style_theme_widgets(self) -> None:
        """昼夜切换时同步滚动区/输入框/副文案颜色，消除黑块/白块。"""
        c = self._colors()
        dim = c["text_dim"]
        text = c["text"]
        card = c["card"]
        inp = c["input"]
        border = c["border"]

        for name in (
            "file_hint", "source_ip_label", "subtitle_label", "cfg_status",
            "wl_count", "company_count", "batch_count_label", "thumb_meta",
        ):
            w = getattr(self, name, None)
            if w is not None:
                try:
                    w.configure(text_color=dim)
                except Exception:
                    pass
        if hasattr(self, "thumb_label"):
            try:
                self.thumb_label.configure(fg_color=inp, text_color=text)
            except Exception:
                pass

        # 滚动容器：必须用实体底色，transparent 在切主题后易留黑/白底
        for name in ("fields_form", "cfg_left_scroll", "batch_list_box", "batch_log", "wl_list", "company_list", "input_box", "preview_box"):
            w = getattr(self, name, None)
            if w is None:
                continue
            try:
                if name in {"fields_form", "cfg_left_scroll"}:
                    w.configure(fg_color=card, border_color=border)
                else:
                    w.configure(fg_color=inp, text_color=text, border_color=border)
            except Exception:
                try:
                    w.configure(fg_color=inp)
                except Exception:
                    pass

        if hasattr(self, "fields"):
            for row in self.fields.values():
                if hasattr(row, "apply_theme"):
                    row.apply_theme(c)
        if hasattr(self, "_template_rows"):
            for row in self._template_rows.values():
                row.apply_theme(c)

        # CTkScrollableFrame does not reliably resolve tuple theme colors on
        # every CustomTkinter/Tk combination. Push concrete colors into its
        # descendants so labels and actions never disappear against the card.
        if hasattr(self, "cfg_left_scroll"):
            self._style_scroll_descendants(self.cfg_left_scroll, c)

        for name in (
            "number_date_entry", "number_seq_entry", "number_preview",
            "template_combo", "logo_label",
        ):
            w = getattr(self, name, None)
            if w is None:
                continue
            try:
                if name == "number_preview":
                    w.configure(text_color=text)
                elif name == "logo_label":
                    w.configure(text_color=text)
                else:
                    w.configure(fg_color=inp, border_color=border, text_color=text)
            except Exception:
                pass

    def _style_scroll_descendants(
        self,
        master: tk.Misc,
        colors: dict[str, str],
    ) -> None:
        for child in master.winfo_children():
            try:
                if isinstance(child, ctk.CTkLabel):
                    child.configure(text_color=colors["text"])
                elif isinstance(child, ctk.CTkCheckBox):
                    child.configure(
                        text_color=colors["text"],
                        fg_color=colors["accent"],
                        border_color=colors["border"],
                    )
                elif isinstance(child, ctk.CTkButton):
                    current = child.cget("fg_color")
                    kwargs: dict[str, Any] = {"text_color": "#ffffff"}
                    if isinstance(current, (list, tuple)):
                        kwargs.update(
                            fg_color=colors["accent"],
                            hover_color=colors["card_hover"],
                        )
                    child.configure(**kwargs)
            except Exception:
                pass
            self._style_scroll_descendants(child, colors)

    # ── 布局 ──────────────────────────────────────────
    def _build_layout(self) -> None:
        self.root_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.root_frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        # 顶栏
        self.top_bar = ctk.CTkFrame(self.root_frame, height=64, corner_radius=18, border_width=1)
        self.top_bar.pack(fill="x", padx=16, pady=(14, 8))
        self.top_bar.pack_propagate(False)

        brand = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        brand.pack(side="left", padx=(14, 8), pady=8)
        self.logo_label = ctk.CTkLabel(brand, text="🛡", width=44, height=44, font=ctk.CTkFont(size=22))
        self.logo_label.pack(side="left", padx=(0, 8))
        title_col = ctk.CTkFrame(brand, fg_color="transparent")
        title_col.pack(side="left")
        self.title_label = ctk.CTkLabel(
            title_col, text=APP_DISPLAY_NAME,
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        self.title_label.pack(anchor="w")
        self.subtitle_label = ctk.CTkLabel(
            title_col, text=DESIGNER_CREDIT,
            font=ctk.CTkFont(size=11),
            text_color=self._colors()["text_dim"],
        )
        self.subtitle_label.pack(anchor="w")

        self.theme_btn = ctk.CTkButton(
            self.top_bar, text="昼夜切换", width=96, height=34, corner_radius=12,
            command=self._toggle_theme,
        )
        self.theme_btn.pack(side="right", padx=(6, 14), pady=12)

        self.tray_btn = ctk.CTkButton(
            self.top_bar, text="隐藏到托盘", width=100, height=34, corner_radius=12,
            command=self._hide_to_tray, fg_color="#4a5568", hover_color="#3a4454",
        )
        self.tray_btn.pack(side="right", padx=(6, 0), pady=12)

        self.tab_seg = ctk.CTkSegmentedButton(
            self.top_bar, values=["工单生成", "批量生成", "配置中心"],
            command=self._switch_tab, height=34, font=ctk.CTkFont(size=13),
        )
        self.tab_seg.set("工单生成")
        self.tab_seg.pack(side="right", padx=8, pady=12)

        # 主体容器
        self.body = ctk.CTkFrame(self.root_frame, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self.page_work = ctk.CTkFrame(self.body, fg_color="transparent")
        self.page_batch = ctk.CTkFrame(self.body, fg_color="transparent")
        self.page_config = ctk.CTkFrame(self.body, fg_color="transparent")
        self.page_work.pack(fill="both", expand=True)

        self._build_work_page()
        self._build_batch_page()
        self._build_config_page()
        self._style_cards()
        self._style_theme_widgets()

    def _switch_tab(self, value: str) -> None:
        for page in (self.page_work, self.page_batch, self.page_config):
            page.pack_forget()
        if value == "工单生成":
            self.page_work.pack(fill="both", expand=True)
        elif value == "批量生成":
            self.page_batch.pack(fill="both", expand=True)
            self._refresh_batch_list()
        else:
            self.page_config.pack(fill="both", expand=True)
            self._refresh_whitelist_list()
            self.after_idle(self._scroll_config_top)
        self.after_idle(self._redraw_background)

    def _analysis_mode_code(self) -> str:
        label = self.analysis_mode_var.get() if hasattr(self, "analysis_mode_var") else "自动"
        return ANALYSIS_MODE_LABELS.get(label, "auto")

    def _on_analysis_mode_changed(self, choice: str) -> None:
        self.settings["analysis_mode"] = ANALYSIS_MODE_LABELS.get(choice, "auto")
        try:
            save_settings(self.settings)
        except Exception:
            pass

    def _scroll_config_top(self) -> None:
        try:
            self.cfg_left_scroll._parent_canvas.yview_moveto(0)  # type: ignore[attr-defined]
        except Exception:
            pass

    def _build_work_page(self) -> None:
        mid = ctk.CTkFrame(self.page_work, fg_color="transparent")
        mid.pack(fill="both", expand=True)

        # 左：输入
        self.left_card = ctk.CTkFrame(mid, corner_radius=18, border_width=1)
        self.left_card.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ctk.CTkLabel(
            self.left_card, text="告警输入",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(14, 6))

        btn_row = ctk.CTkFrame(self.left_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=4)
        ctk.CTkButton(
            btn_row, text="选择文件", width=100, height=34, corner_radius=12,
            command=self._pick_file,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="粘贴剪贴板", width=110, height=34, corner_radius=12,
            command=self._paste_clipboard, fg_color="#3d7a5a", hover_color="#2f6a4c",
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="加入批量", width=90, height=34, corner_radius=12,
            command=self._send_current_to_batch, fg_color="#5b6b8f", hover_color="#4a5878",
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="清空", width=72, height=34, corner_radius=12,
            command=self._clear_input, fg_color="#6b3a42", hover_color="#5a2f36",
        ).pack(side="left")

        self.file_hint = ctk.CTkLabel(
            self.left_card,
            text="未载入告警材料",
            font=ctk.CTkFont(size=12), text_color=self._colors()["text_dim"],
        )
        self.file_hint.pack(anchor="w", padx=16, pady=(2, 4))

        # 拖入文件缩略预览区
        self.preview_media = ctk.CTkFrame(self.left_card, fg_color="transparent", height=120)
        self.preview_media.pack(fill="x", padx=14, pady=(0, 6))
        self.preview_media.pack_propagate(False)
        self.thumb_label = ctk.CTkLabel(
            self.preview_media,
            text="（拖入图片将显示缩略图）",
            width=160,
            height=100,
            corner_radius=10,
            fg_color=self._colors()["input"],
            font=ctk.CTkFont(size=12),
        )
        self.thumb_label.pack(side="left", padx=(0, 10), pady=4)
        self.thumb_meta = ctk.CTkLabel(
            self.preview_media,
            text="未载入文件",
            anchor="w",
            justify="left",
            font=ctk.CTkFont(size=12),
            text_color=self._colors()["text_dim"],
        )
        self.thumb_meta.pack(side="left", fill="x", expand=True, pady=4)
        self._thumb_ctk = None
        self._pending_file: str = ""  # 非图片文件路径（html/txt 等）

        self.input_box = ctk.CTkTextbox(
            self.left_card, corner_radius=8, border_width=1,
            font=ctk.CTkFont(size=13), wrap="word",
        )
        self.input_box.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        # Bind paste only to the original-alert editor.  A former root-level
        # binding ran in addition to Tk's Text binding, causing double paste;
        # it also redirected paste from supplement/field editors into here.
        paste_target = getattr(self.input_box, "_textbox", self.input_box)
        paste_target.bind("<Control-v>", self._on_paste)
        paste_target.bind("<Control-V>", self._on_paste)

        self.supplement_toggle = ctk.CTkButton(
            self.left_card, text="补充研判材料  ▸", height=28, corner_radius=6,
            anchor="w", fg_color="transparent", hover_color=self._colors()["card_hover"],
            command=self._toggle_supplement,
        )
        self.supplement_toggle.pack(fill="x", padx=14, pady=(0, 4))
        self.supplement_frame = ctk.CTkFrame(self.left_card, fg_color="transparent")
        self.supplement_box = ctk.CTkTextbox(
            self.supplement_frame, height=88, corner_radius=8, border_width=1,
            wrap="word", font=ctk.CTkFont(size=12),
        )
        self.supplement_box.pack(fill="x")
        self._supplement_visible = False

        mode_row = ctk.CTkFrame(self.left_card, fg_color="transparent")
        mode_row.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(mode_row, text="解析方式", width=64, anchor="w").pack(side="left")
        mode_code = str(self.settings.get("analysis_mode") or "auto").casefold()
        self.analysis_mode_var = ctk.StringVar(value=ANALYSIS_MODE_NAMES.get(mode_code, "自动"))
        self.analysis_mode_seg = ctk.CTkSegmentedButton(
            mode_row,
            values=list(ANALYSIS_MODE_LABELS),
            variable=self.analysis_mode_var,
            command=self._on_analysis_mode_changed,
            height=30,
        )
        self.analysis_mode_seg.pack(side="left", fill="x", expand=True, padx=(4, 10))
        ctk.CTkLabel(
            mode_row, text="图片仅在线AI", font=ctk.CTkFont(size=11),
            text_color=self._colors()["text_dim"],
        ).pack(side="right")

        action_row = ctk.CTkFrame(self.left_card, fg_color="transparent")
        self.action_row = action_row
        action_row.pack(fill="x", padx=14, pady=(0, 14))
        ctk.CTkButton(
            action_row, text="生成工单", height=40, corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"), command=self._generate_order,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            action_row, text="复制工单", height=40, corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2aa86c", hover_color="#228a58", command=self._copy_current_order,
        ).pack(side="left", fill="x", expand=True)

        self.analysis_progress_frame = ctk.CTkFrame(self.left_card, fg_color="transparent")
        self.analysis_progress_label = ctk.CTkLabel(
            self.analysis_progress_frame, text="AI 正在分析材料", font=ctk.CTkFont(size=12)
        )
        self.analysis_progress_label.pack(side="left", padx=(2, 10))
        self.analysis_progress = ctk.CTkProgressBar(
            self.analysis_progress_frame, mode="indeterminate", height=8
        )
        self.analysis_progress.pack(side="left", fill="x", expand=True)

        # 右：字段（加宽，标签完整可见）
        self.right_card = ctk.CTkFrame(mid, width=560, corner_radius=18, border_width=1)
        self.right_card.pack(side="right", fill="both", padx=(8, 0))
        self.right_card.pack_propagate(False)

        fields_header = ctk.CTkFrame(self.right_card, fg_color="transparent")
        fields_header.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(
            fields_header, text="工单字段（全部可手改）",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(side="left")
        ctk.CTkButton(
            fields_header, text="刷新工单", width=92, height=30, corner_radius=6,
            command=self._refresh_current_order,
        ).pack(side="right")

        template_row = ctk.CTkFrame(self.right_card, fg_color="transparent")
        template_row.pack(fill="x", padx=14, pady=(0, 6))
        ctk.CTkLabel(template_row, text="模板", width=44, anchor="w").pack(side="left")
        self.template_var = ctk.StringVar(
            value=self.settings.get("active_template") or BUILTIN_TEMPLATE_NAME
        )
        self.template_combo = ctk.CTkComboBox(
            template_row,
            variable=self.template_var,
            values=self._template_names(),
            command=self._on_template_selected,
            corner_radius=8,
            state="readonly",
        )
        self.template_combo.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(
            template_row, text="新增模板", width=78, height=30, corner_radius=6,
            command=self._save_current_template,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            template_row, text="导入", width=54, height=30, corner_radius=6,
            command=self._import_template,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            template_row, text="删除", width=54, height=30, corner_radius=6,
            fg_color="#b44752", command=self._delete_current_template,
        ).pack(side="left")
        field_tools = ctk.CTkFrame(self.right_card, fg_color="transparent")
        field_tools.pack(fill="x", padx=14, pady=(0, 5))
        ctk.CTkLabel(field_tools, text="字段可拖动排序", font=ctk.CTkFont(size=12), text_color=self._colors()["text_dim"]).pack(side="left")
        ctk.CTkButton(
            field_tools, text="添加字段", width=80, height=28, corner_radius=6,
            command=self._add_manual_template_field,
        ).pack(side="right")

        c = self._colors()
        self.fields_form = ctk.CTkScrollableFrame(
            self.right_card,
            fg_color=c["card"],
            corner_radius=12,
            border_width=0,
        )
        self.fields_form.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        form = self.fields_form

        # 编号日期 + 手动序号 + 预览
        num_frame = ctk.CTkFrame(form, fg_color="transparent")
        self.number_frame = num_frame
        num_frame.pack(fill="x", pady=(2, 8))
        ctk.CTkLabel(num_frame, text="编号日期", width=108, anchor="e").pack(side="left", padx=(4, 10))
        self.number_date_var = ctk.StringVar()
        self.number_date_entry = ctk.CTkEntry(
            num_frame, textvariable=self.number_date_var, width=80, height=34, corner_radius=10,
            placeholder_text="MMDD",
        )
        self.number_date_entry.pack(side="left")
        self.number_date_entry.bind("<KeyRelease>", lambda _e: self._on_number_date_typed())
        self.number_date_entry.bind("<FocusOut>", lambda _e: self._on_number_date_change())

        ctk.CTkLabel(num_frame, text="序号", width=40, anchor="e").pack(side="left", padx=(10, 6))
        self.number_seq_var = ctk.StringVar()
        self.number_seq_entry = ctk.CTkEntry(
            num_frame, textvariable=self.number_seq_var, width=72, height=34, corner_radius=10,
            placeholder_text="013",
        )
        self.number_seq_entry.pack(side="left")
        self.number_seq_entry.bind("<KeyRelease>", lambda _e: self._refresh_number_preview())
        self.number_seq_entry.bind("<FocusOut>", lambda _e: self._on_number_seq_change())

        self.number_preview = ctk.CTkLabel(
            num_frame, text="→ 0000-000", font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.number_preview.pack(side="left", padx=(14, 8))

        self.fields: dict[str, FieldRow] = {}
        self._template_schema: list[str] = []
        self._template_bindings: dict[str, str] = {}
        self._template_rows: dict[str, FieldRow] = {}
        specs: list[tuple[str, str, str, list[str] | None]] = [
            ("source", "监测来源", "combo", MONITOR_SOURCE_NAMES),
            ("time", "时间", "entry", None),
            ("attack_ip", "攻击IP", "entry", None),
            ("target_ip", "目标IP", "entry", None),
            ("xff", "XFF", "entry", None),
            ("domain_url", "域名URL", "entry", None),
            ("alert_level", "告警级别", "combo", ALERT_LEVELS),
            ("attack_name", "攻击名称", "entry", None),
            ("event_type", "事件类型", "entry", None),
            ("event_level", "事件等级", "combo", EVENT_LEVELS),
            ("attack_result", "攻击结果", "combo", ATTACK_RESULTS),
            ("is_whitelist", "是否白名单", "combo", WHITELIST_OPTIONS),
            ("advice", "处置建议", "text", None),  # 2~3 行
        ]
        for key, label, kind, values in specs:
            row = FieldRow(
                form,
                label,
                kind=kind,
                values=values or [],
                label_width=108,
                width=360,
                height=78 if kind == "text" else 34,
            )
            row.pack(fill="x", pady=5, padx=2)
            self.fields[key] = row
            if key == "event_level":
                self.event_level_hint = ctk.CTkLabel(
                    form,
                    text="AI默认只给五级，实际等级可按需手动调整",
                    anchor="e",
                    font=ctk.CTkFont(size=11),
                    text_color=self._colors()["text_dim"],
                )
                self.event_level_hint.pack(fill="x", padx=(120, 8), pady=(0, 2))

        # Templates own their field definitions.  Their rows are recreated on
        # every switch, so a template is never limited by legacy field slots.
        self.template_fields_frame = ctk.CTkFrame(form, fg_color="transparent")

        self.fields["source"].set(self.settings.get("default_source", ""))
        self.fields["event_level"].set(self.settings.get("default_event_level", ""))
        self.fields["alert_level"].set("")
        self.fields["attack_result"].set("")
        self.fields["is_whitelist"].set("")

        self.source_ip_label = ctk.CTkLabel(
            form, text=f"平台IP：{MONITOR_SOURCE_IP.get(self.fields['source'].get(), '')}",
            font=ctk.CTkFont(size=12), text_color=self._colors()["text_dim"],
        )
        self.source_ip_label.pack(anchor="w", padx=12, pady=(6, 10))
        self.fields["source"].var.trace_add("write", lambda *_: self._on_source_change())
        self._apply_template_to_fields(self._active_template())

        # 底部预览
        self.bottom_card = ctk.CTkFrame(self.page_work, height=200, corner_radius=18, border_width=1)
        self.bottom_card.pack(fill="x", pady=(10, 0))
        self.bottom_card.pack_propagate(False)
        result_header = ctk.CTkFrame(self.bottom_card, fg_color="transparent")
        result_header.pack(fill="x", padx=14, pady=(8, 4))
        ctk.CTkLabel(
            result_header, text="结果",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(side="left")
        self.result_view_seg = ctk.CTkSegmentedButton(
            result_header, values=["生成工单", "原始结果", "研判依据"],
            command=self._show_result_view, height=30,
        )
        self.result_view_seg.set("生成工单")
        self.result_view_seg.pack(side="right")
        result_actions = ctk.CTkFrame(result_header, fg_color="transparent")
        result_actions.pack(side="right", padx=(8, 8))
        ctk.CTkButton(
            result_actions, text="历史工单", width=82, height=30, corner_radius=6,
            command=self._show_history_orders,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            result_actions, text="历史原始结果", width=106, height=30, corner_radius=6,
            command=self._show_history_raw_results,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            result_actions, text="微步情报查询", width=106, height=30, corner_radius=6,
            command=self._open_threatbook_lookup,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            result_actions, text="内网IP网段查询", width=124, height=30, corner_radius=6,
            command=self._open_internal_network_lookup,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            result_actions, text="检测各IP是否为白名单", width=158, height=30, corner_radius=6,
            command=self._check_result_whitelist,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            result_actions, text="检测需处置IP是否已被提交", width=190, height=30, corner_radius=6,
            command=self._check_result_history,
        ).pack(side="left")
        self.preview_box = ctk.CTkTextbox(
            self.bottom_card, corner_radius=8, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=13),
        )
        self.preview_box.pack(fill="both", expand=True, padx=14, pady=(0, 12))

    def _build_batch_page(self) -> None:
        self.batch_card = ctk.CTkFrame(self.page_batch, corner_radius=18, border_width=1)
        self.batch_card.pack(fill="both", expand=True)

        header = ctk.CTkFrame(self.batch_card, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(
            header, text="批量生成",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(side="left")
        self.batch_count_label = ctk.CTkLabel(header, text="队列 0 条", font=ctk.CTkFont(size=13))
        self.batch_count_label.pack(side="right")

        btn_row = ctk.CTkFrame(self.batch_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=4)
        ctk.CTkButton(
            btn_row, text="添加文件", width=100, height=34, corner_radius=12,
            command=self._batch_add_files,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="从输入区拆分文本", width=140, height=34, corner_radius=12,
            command=self._batch_from_input_text, fg_color="#5b6b8f", hover_color="#4a5878",
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="全选", width=70, height=34, corner_radius=12,
            command=lambda: self._batch_select_all(True),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="全不选", width=70, height=34, corner_radius=12,
            command=lambda: self._batch_select_all(False),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="清空队列", width=90, height=34, corner_radius=12,
            command=self._batch_clear, fg_color="#6b3a42", hover_color="#5a2f36",
        ).pack(side="left", padx=(0, 8))

        opts = ctk.CTkFrame(self.batch_card, fg_color="transparent")
        opts.pack(fill="x", padx=14, pady=6)
        self.batch_skip_hist_var = ctk.BooleanVar(value=bool(self.settings.get("batch_skip_history", True)))
        ctk.CTkCheckBox(
            opts, text="历史已处置自动跳过", variable=self.batch_skip_hist_var, font=ctk.CTkFont(size=13),
        ).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(opts, text="解析方式").pack(side="left", padx=(0, 6))
        self.batch_mode_seg = ctk.CTkSegmentedButton(
            opts,
            values=list(ANALYSIS_MODE_LABELS),
            variable=self.analysis_mode_var,
            command=self._on_analysis_mode_changed,
            height=28,
        )
        self.batch_mode_seg.pack(side="left", padx=(0, 16))
        self.batch_context_label = ctk.CTkLabel(opts, text="", font=ctk.CTkFont(size=12))
        self.batch_context_label.pack(side="left")
        self._update_batch_context()

        body = ctk.CTkFrame(self.batch_card, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=14, pady=(4, 10))

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        ctk.CTkLabel(left, text="任务队列", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
        self.batch_list_box = ctk.CTkTextbox(
            left, corner_radius=8, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.batch_list_box.pack(fill="both", expand=True, pady=(4, 0))

        right = ctk.CTkFrame(body, fg_color="transparent", width=420)
        right.pack(side="right", fill="both", padx=(8, 0))
        right.pack_propagate(False)
        ctk.CTkLabel(right, text="运行日志", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
        self.batch_log = ctk.CTkTextbox(
            right, corner_radius=8, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.batch_log.pack(fill="both", expand=True, pady=(4, 0))

        self.batch_progress = ctk.CTkProgressBar(self.batch_card, height=10, corner_radius=6)
        self.batch_progress.pack(fill="x", padx=16, pady=(0, 6))
        self.batch_progress.set(0)

        action = ctk.CTkFrame(self.batch_card, fg_color="transparent")
        action.pack(fill="x", padx=14, pady=(0, 14))
        ctk.CTkButton(
            action, text="批量生成", height=42, corner_radius=8,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#2aa86c", hover_color="#228a58", command=self._batch_run,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            action, text="复制全部工单", height=42, corner_radius=8, width=140,
            command=self._copy_batch_orders,
        ).pack(side="left")

    def _build_config_page(self) -> None:
        self.cfg_card = ctk.CTkFrame(self.page_config, corner_radius=18, border_width=1)
        self.cfg_card.pack(fill="both", expand=True)

        right = ctk.CTkFrame(self.cfg_card, fg_color="transparent", width=420)
        right.pack(side="right", fill="both", padx=16, pady=16)
        c = self._colors()
        self.cfg_left_scroll = ctk.CTkScrollableFrame(
            self.cfg_card, fg_color=c["card"], corner_radius=12,
        )
        self.cfg_left_scroll.pack(side="left", fill="both", expand=True, padx=16, pady=16)
        left = self.cfg_left_scroll

        ctk.CTkLabel(
            left, text="项目配置包", font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w")
        project_row = ctk.CTkFrame(left, fg_color="transparent")
        project_row.pack(fill="x", pady=(8, 12))
        project_names = list_project_profiles()
        self.project_profile_var = ctk.StringVar(value=project_names[0] if project_names else "")
        self.project_profile_combo = ctk.CTkComboBox(
            project_row, values=project_names or ["（暂无项目配置）"],
            variable=self.project_profile_var, state="readonly", corner_radius=8,
        )
        self.project_profile_combo.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(
            project_row, text="加载", width=58, height=30, corner_radius=6,
            command=self._load_selected_project_profile,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            project_row, text="导入文件", width=72, height=30, corner_radius=6,
            command=self._load_project_profile_file,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            project_row, text="另存当前", width=72, height=30, corner_radius=6,
            command=self._save_current_project_profile,
        ).pack(side="left", padx=(0, 5))
        ctk.CTkButton(
            project_row, text="恢复白板", width=72, height=30, corner_radius=6,
            fg_color="#596579", command=self._restore_blank_profile,
        ).pack(side="left")

        ctk.CTkLabel(
            left, text="AI 接口（可保存多组，下拉切换）",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w")

        self.ai_enabled_var = ctk.BooleanVar(value=bool(self.settings.get("ai_enabled", True)))
        self.ai_ocr_var = ctk.BooleanVar(value=bool(self.settings.get("ai_use_ocr", True)))
        self.ai_judge_var = ctk.BooleanVar(value=bool(self.settings.get("ai_use_judge", True)))
        ai_sw = ctk.CTkFrame(left, fg_color="transparent")
        ai_sw.pack(fill="x", pady=(10, 4))
        ctk.CTkCheckBox(ai_sw, text="启用 AI", variable=self.ai_enabled_var).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(ai_sw, text="AI识别/提取", variable=self.ai_ocr_var).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(ai_sw, text="AI研判建议", variable=self.ai_judge_var).pack(side="left")

        # 多组 AI 配置
        prof_row = ctk.CTkFrame(left, fg_color="transparent")
        prof_row.pack(fill="x", pady=(10, 4))
        ctk.CTkLabel(prof_row, text="已保存配置", width=100, anchor="w").pack(side="left")
        profiles = normalize_ai_profiles(self.settings)
        names = [p["name"] for p in profiles]
        self.ai_profile_var = ctk.StringVar(
            value=self.settings.get("ai_active_profile") or (names[0] if names else "DeepSeek")
        )
        self.ai_profile_combo = ctk.CTkComboBox(
            prof_row,
            values=names or ["DeepSeek"],
            variable=self.ai_profile_var,
            width=200,
            state="readonly",
            corner_radius=10,
            command=self._on_ai_profile_selected,
        )
        self.ai_profile_combo.pack(side="left", padx=8)

        preset_row = ctk.CTkFrame(left, fg_color="transparent")
        preset_row.pack(fill="x", pady=4)
        ctk.CTkLabel(preset_row, text="服务商预设", width=100, anchor="w").pack(side="left")
        self.ai_provider_var = ctk.StringVar(value="自定义")
        ctk.CTkComboBox(
            preset_row, values=list(AI_PROVIDER_PRESETS), variable=self.ai_provider_var,
            state="readonly", corner_radius=8, command=self._apply_ai_provider_preset,
        ).pack(side="left", fill="x", expand=True, padx=8)

        name_row = ctk.CTkFrame(left, fg_color="transparent")
        name_row.pack(fill="x", pady=4)
        ctk.CTkLabel(name_row, text="配置名称", width=100, anchor="w").pack(side="left")
        self.ai_profile_name_var = ctk.StringVar(value=self.ai_profile_var.get())
        ctk.CTkEntry(name_row, textvariable=self.ai_profile_name_var, corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=8
        )

        def _ai_row(label: str, var: ctk.StringVar, show: str = "") -> ctk.CTkEntry:
            row = ctk.CTkFrame(left, fg_color="transparent")
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=label, width=100, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, textvariable=var, corner_radius=10, show=show)
            entry.pack(side="left", fill="x", expand=True, padx=8)
            return entry

        active = get_ai_profile(self.settings)
        self.ai_base_var = ctk.StringVar(value=active.get("base_url") or "https://api.deepseek.com/v1")
        self.ai_key_var = ctk.StringVar(value=active.get("api_key") or "")
        self.ai_model_var = ctk.StringVar(value=active.get("model") or "deepseek-v4-flash")
        _ai_row("URL 基址", self.ai_base_var)
        # API Key 星号脱敏；初始为空，后期填写
        key_row = ctk.CTkFrame(left, fg_color="transparent")
        key_row.pack(fill="x", pady=4)
        ctk.CTkLabel(key_row, text="API Key", width=100, anchor="w").pack(side="left")
        self.ai_key_entry = ctk.CTkEntry(
            key_row, textvariable=self.ai_key_var, corner_radius=8, show="*"
        )
        self.ai_key_entry.pack(side="left", fill="x", expand=True, padx=(8, 4))
        self.ai_key_visible = False
        self.ai_key_toggle = ctk.CTkButton(
            key_row, text="显示", width=58, height=30, corner_radius=6,
            command=self._toggle_api_key_visibility,
        )
        self.ai_key_toggle.pack(side="left", padx=(0, 8))
        _ai_row("模型名", self.ai_model_var)

        api_type_row = ctk.CTkFrame(left, fg_color="transparent")
        api_type_row.pack(fill="x", pady=4)
        ctk.CTkLabel(api_type_row, text="API 类型", width=100, anchor="w").pack(side="left")
        current_wire = str(active.get("wire_api") or "auto").casefold()
        self.ai_wire_var = ctk.StringVar(value=WIRE_API_LABELS.get(current_wire, WIRE_API_LABELS["auto"]))
        self.ai_wire_combo = ctk.CTkComboBox(
            api_type_row, values=list(WIRE_API_LABELS.values()), variable=self.ai_wire_var,
            state="readonly", corner_radius=8, command=self._on_wire_api_changed,
        )
        self.ai_wire_combo.pack(side="left", fill="x", expand=True, padx=8)
        self.ai_wire_hint = ctk.CTkLabel(api_type_row, text="", width=170, anchor="w", text_color=self._colors()["text_dim"])
        self.ai_wire_hint.pack(side="left")
        self.ai_timeout_var = ctk.StringVar(value=str(self.settings.get("ai_timeout", 45)))
        ctk.CTkLabel(api_type_row, text="超时(秒)").pack(side="left", padx=(8, 4))
        ctk.CTkEntry(api_type_row, textvariable=self.ai_timeout_var, width=54, corner_radius=8).pack(side="left")
        self._on_wire_api_changed(self.ai_wire_var.get())

        vision_row = ctk.CTkFrame(left, fg_color="transparent")
        vision_row.pack(fill="x", pady=4)
        ctk.CTkLabel(vision_row, text="图像识别配置", width=100, anchor="w").pack(side="left")
        self.ai_vision_var = ctk.StringVar(
            value=self.settings.get("ai_vision_profile") or "GPT-5.6-Terra"
        )
        self.ai_vision_combo = ctk.CTkComboBox(
            vision_row, values=names, variable=self.ai_vision_var,
            state="readonly", corner_radius=8, command=self._on_ai_vision_selected,
        )
        self.ai_vision_combo.pack(side="left", fill="x", expand=True, padx=8)

        ctk.CTkLabel(
            left,
            text="配置按名称独立保存；测试连接使用当前表单值。",
            font=ctk.CTkFont(size=11),
            text_color=self._colors()["text_dim"],
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(2, 8))

        ai_btns = ctk.CTkFrame(left, fg_color="transparent")
        ai_btns.pack(fill="x", pady=(0, 12))
        ctk.CTkButton(
            ai_btns, text="保存/更新此配置", width=130, height=32, corner_radius=10,
            command=self._save_ai_profile,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            ai_btns, text="删除配置", width=90, height=32, corner_radius=10,
            fg_color="#6b3a42", hover_color="#5a2f36", command=self._delete_ai_profile,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            ai_btns, text="测试 AI 连接", width=110, height=32, corner_radius=10,
            command=self._test_ai,
        ).pack(side="left")

        ctk.CTkLabel(left, text="微步威胁情报", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", pady=(6, 2)
        )
        self.threatbook_enabled_var = ctk.BooleanVar(value=bool(self.settings.get("threatbook_enabled", False)))
        # ThreatBook is deliberately isolated from extraction and work-order
        # generation.  Keep the legacy setting for migration, but never let
        # an analysis worker call the cloud API.
        self.threatbook_auto_var = ctk.BooleanVar(value=False)
        ti_switches = ctk.CTkFrame(left, fg_color="transparent")
        ti_switches.pack(fill="x", pady=(4, 2))
        ctk.CTkCheckBox(ti_switches, text="启用微步 API（仅手动查询）", variable=self.threatbook_enabled_var).pack(side="left")
        self.threatbook_key_var = ctk.StringVar(value=str(self.settings.get("threatbook_api_key") or ""))
        ti_key_row = ctk.CTkFrame(left, fg_color="transparent")
        ti_key_row.pack(fill="x", pady=3)
        ctk.CTkLabel(ti_key_row, text="微步 API Key", width=100, anchor="w").pack(side="left")
        ctk.CTkEntry(ti_key_row, textvariable=self.threatbook_key_var, show="*", corner_radius=8).pack(
            side="left", fill="x", expand=True, padx=8
        )
        self.threatbook_timeout_var = ctk.StringVar(value=str(self.settings.get("threatbook_timeout", 8)))
        ctk.CTkLabel(ti_key_row, text="超时(秒)").pack(side="left", padx=(0, 5))
        ctk.CTkEntry(ti_key_row, textvariable=self.threatbook_timeout_var, width=54, corner_radius=8).pack(side="left")
        ctk.CTkButton(ti_key_row, text="测试", width=58, corner_radius=8, command=self._test_threatbook).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(left, text="外观与个性化", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(8, 0))

        opacity_row = ctk.CTkFrame(left, fg_color="transparent")
        opacity_row.pack(fill="x", pady=(8, 2))
        ctk.CTkLabel(opacity_row, text="窗口透明度", width=100, anchor="w").pack(side="left")
        self.opacity_value_label = ctk.CTkLabel(opacity_row, text=f"{round(self._window_opacity * 100)}%", width=46)
        self.opacity_value_label.pack(side="right", padx=(8, 0))
        ctk.CTkSlider(
            opacity_row, from_=0.65, to=1.0, number_of_steps=35,
            variable=ctk.DoubleVar(value=self._window_opacity), command=self._on_window_opacity,
        ).pack(side="left", fill="x", expand=True, padx=8)

        title_row = ctk.CTkFrame(left, fg_color="transparent")
        title_row.pack(fill="x", pady=(12, 4))
        ctk.CTkLabel(title_row, text="工具标题", width=100, anchor="w").pack(side="left")
        self.app_title_var = ctk.StringVar(
            value=self.settings.get("app_title") or APP_DISPLAY_NAME
        )
        ctk.CTkEntry(title_row, textvariable=self.app_title_var, corner_radius=8).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkButton(
            title_row, text="预览外观", width=80, corner_radius=6,
            command=self._preview_branding,
        ).pack(side="left")

        subtitle_row = ctk.CTkFrame(left, fg_color="transparent")
        subtitle_row.pack(fill="x", pady=4)
        self.subtitle_enabled_var = ctk.BooleanVar(
            value=bool(self.settings.get("subtitle_enabled", True))
        )
        ctk.CTkCheckBox(
            subtitle_row, text="标题下副标", variable=self.subtitle_enabled_var,
            command=self._preview_branding,
        ).pack(side="left")
        self.subtitle_text_var = ctk.StringVar(
            value=self.settings.get("subtitle_text") or DESIGNER_CREDIT
        )
        ctk.CTkEntry(
            subtitle_row, textvariable=self.subtitle_text_var, corner_radius=8
        ).pack(side="left", fill="x", expand=True, padx=(12, 8))
        ctk.CTkButton(
            subtitle_row, text="预览", width=64, corner_radius=6,
            command=self._preview_branding,
        ).pack(side="left")

        # Logo
        lg = ctk.CTkFrame(left, fg_color="transparent")
        lg.pack(fill="x", pady=6)
        ctk.CTkLabel(lg, text="自定义 Logo", width=100, anchor="w").pack(side="left")
        self.logo_var = ctk.StringVar(value=self.settings.get("logo_path") or "")
        ctk.CTkEntry(lg, textvariable=self.logo_var, corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkButton(lg, text="选择", width=70, corner_radius=10, command=self._pick_logo).pack(side="left", padx=4)
        ctk.CTkButton(lg, text="清除", width=70, corner_radius=10, command=self._clear_logo).pack(side="left")

        ctk.CTkLabel(
            left, text="数据与默认项", font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", pady=(14, 4))

        # 历史表
        hs = ctk.CTkFrame(left, fg_color="transparent")
        hs.pack(fill="x", pady=6)
        ctk.CTkLabel(hs, text="历史跟踪表", width=100, anchor="w").pack(side="left")
        self.history_var = ctk.StringVar(value=self.settings.get("history_xlsx", ""))
        ctk.CTkEntry(hs, textvariable=self.history_var, corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkButton(hs, text="浏览", width=70, corner_radius=10, command=self._pick_history_xlsx).pack(side="left", padx=(0, 4))
        ctk.CTkButton(hs, text="重载", width=70, corner_radius=10, command=self._reload_history).pack(side="left")

        sync_url_row = ctk.CTkFrame(left, fg_color="transparent")
        sync_url_row.pack(fill="x", pady=4)
        ctk.CTkLabel(sync_url_row, text="自动同步链接", width=100, anchor="w").pack(side="left")
        self.history_sync_urls_var = ctk.StringVar(
            value="\n".join(normalize_sync_urls(self.settings.get("history_sync_urls")))
        )
        ctk.CTkEntry(sync_url_row, textvariable=self.history_sync_urls_var, corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkButton(sync_url_row, text="立即同步", width=90, corner_radius=10, command=self._sync_history_now).pack(side="left")

        sync_opts = ctk.CTkFrame(left, fg_color="transparent")
        sync_opts.pack(fill="x", pady=4)
        ctk.CTkLabel(sync_opts, text="同步间隔(分钟)", width=100, anchor="w").pack(side="left")
        self.history_sync_interval_var = ctk.StringVar(value=str(self.settings.get("history_auto_sync_minutes", 15)))
        ctk.CTkEntry(sync_opts, textvariable=self.history_sync_interval_var, width=80, corner_radius=10).pack(side="left", padx=8)
        self.history_add_url_var = ctk.StringVar()
        ctk.CTkEntry(sync_opts, textvariable=self.history_add_url_var, placeholder_text="新增链接", corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=(10, 6)
        )
        ctk.CTkButton(sync_opts, text="添加链接", width=82, corner_radius=10, command=self._add_history_sync_url).pack(side="left")
        sync_switches = ctk.CTkFrame(left, fg_color="transparent")
        sync_switches.pack(fill="x", pady=(2, 4))
        self.history_sync_enabled_var = ctk.BooleanVar(value=bool(self.settings.get("history_sync_enabled", False)))
        self.history_stale_alert_var = ctk.BooleanVar(value=bool(self.settings.get("history_sync_stale_alert_enabled", False)))
        ctk.CTkCheckBox(sync_switches, text="启用在线自动同步", variable=self.history_sync_enabled_var).pack(side="left", padx=(0, 14))
        ctk.CTkCheckBox(sync_switches, text="超过 15 分钟未成功同步时提醒", variable=self.history_stale_alert_var).pack(side="left")
        self.history_sync_status = ctk.CTkLabel(left, text=self._history_sync_status_text(), font=ctk.CTkFont(size=12))
        self.history_sync_status.pack(anchor="w", pady=(0, 4))

        auth_row = ctk.CTkFrame(left, fg_color="transparent")
        auth_row.pack(fill="x", pady=4)
        ctk.CTkLabel(auth_row, text="WPS 登录态 Cookie", width=100, anchor="w").pack(side="left")
        self.history_cookie_var = ctk.StringVar(value=str(self.settings.get("history_sync_cookie") or ""))
        self.history_cookie_entry = ctk.CTkEntry(auth_row, textvariable=self.history_cookie_var, show="*", corner_radius=10)
        self.history_cookie_entry.pack(side="left", fill="x", expand=True, padx=8)
        ctk.CTkButton(auth_row, text="打开登录页", width=90, corner_radius=10, command=self._open_wps_login).pack(side="left", padx=(0, 4))
        ctk.CTkButton(auth_row, text="清除", width=58, corner_radius=10, command=self._clear_history_cookie).pack(side="left")

        # 网段表
        nt = ctk.CTkFrame(left, fg_color="transparent")
        nt.pack(fill="x", pady=6)
        ctk.CTkLabel(nt, text="白名单导入文件", width=112, anchor="w").pack(side="left")
        self.network_var = ctk.StringVar(value=self.settings.get("network_xlsx", ""))
        ctk.CTkEntry(nt, textvariable=self.network_var, corner_radius=10).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ctk.CTkButton(nt, text="浏览", width=70, corner_radius=10, command=self._pick_network_xlsx).pack(side="left", padx=(0, 4))
        ctk.CTkButton(nt, text="导入白名单", width=100, corner_radius=10, command=self._sync_network).pack(side="left")

        defaults = ctk.CTkFrame(left, fg_color="transparent")
        defaults.pack(fill="x", pady=10)
        ctk.CTkLabel(defaults, text="默认监测来源", width=100, anchor="w").pack(side="left")
        self.default_source_var = ctk.StringVar(value=self.settings.get("default_source", "自定义监测平台"))
        ctk.CTkComboBox(
            defaults, values=MONITOR_SOURCE_NAMES, variable=self.default_source_var,
            width=160, state="readonly", corner_radius=10,
        ).pack(side="left", padx=8)
        ctk.CTkLabel(defaults, text="默认事件等级").pack(side="left", padx=(16, 8))
        self.default_level_var = ctk.StringVar(value=self.settings.get("default_event_level", "五级"))
        ctk.CTkComboBox(
            defaults, values=EVENT_LEVELS, variable=self.default_level_var,
            width=100, state="readonly", corner_radius=10,
        ).pack(side="left")

        tray_opts = ctk.CTkFrame(left, fg_color="transparent")
        tray_opts.pack(fill="x", pady=8)
        self.close_to_tray_var = ctk.BooleanVar(value=bool(self.settings.get("close_to_tray", True)))
        self.tray_enabled_var = ctk.BooleanVar(value=bool(self.settings.get("tray_enabled", True)))
        ctk.CTkCheckBox(
            tray_opts, text="启用系统托盘", variable=self.tray_enabled_var, font=ctk.CTkFont(size=13),
        ).pack(side="left", padx=(0, 16))
        ctk.CTkCheckBox(
            tray_opts, text="关闭窗口时最小化到托盘", variable=self.close_to_tray_var, font=ctk.CTkFont(size=13),
        ).pack(side="left")

        cfg_actions = ctk.CTkFrame(left, fg_color="transparent")
        cfg_actions.pack(fill="x", pady=16)
        ctk.CTkButton(
            cfg_actions, text="保存全部配置", height=40, corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"), command=self._save_config,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(
            cfg_actions, text="外观恢复默认", width=120, height=40, corner_radius=8,
            fg_color="#596579", command=self._reset_branding_draft,
        ).pack(side="left")

        self.cfg_status = ctk.CTkLabel(left, text="", font=ctk.CTkFont(size=12))
        self.cfg_status.pack(anchor="w")

        # 右侧规则管理：白名单与公司网段严格分开。
        self.rule_manager_var = ctk.StringVar(value="白名单")
        self.rule_manager_seg = ctk.CTkSegmentedButton(
            right, values=["白名单", "公司网段"], variable=self.rule_manager_var,
            command=self._switch_rule_manager, height=32,
        )
        self.rule_manager_seg.pack(fill="x", pady=(0, 8))
        self.whitelist_manager = ctk.CTkFrame(right, fg_color="transparent")
        self.company_manager = ctk.CTkFrame(right, fg_color="transparent")

        self.wl_filter_var = ctk.StringVar()
        self.wl_filter_var.trace_add("write", lambda *_: self._refresh_whitelist_list())
        ctk.CTkEntry(
            self.whitelist_manager, textvariable=self.wl_filter_var, placeholder_text="输入 IP/CIDR/规则/单位；IP 会按网段匹配",
            corner_radius=8,
        ).pack(fill="x", pady=(8, 0))
        self.wl_list = ctk.CTkTextbox(
            self.whitelist_manager, corner_radius=8, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.wl_list.pack(fill="both", expand=True, pady=(10, 8))
        self.wl_list.bind("<Button-1>", self._toggle_whitelist_row)
        self.wl_list.bind("<Control-a>", lambda _event: self._select_all_whitelist_rows(True))
        self._whitelist_visible_rules: list[str] = []
        self._whitelist_selected_rules: set[str] = set()

        selection_row = ctk.CTkFrame(self.whitelist_manager, fg_color="transparent")
        selection_row.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(selection_row, text="全选", width=58, height=28, command=lambda: self._select_all_whitelist_rows(True)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(selection_row, text="全不选", width=68, height=28, command=lambda: self._select_all_whitelist_rows(False)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(selection_row, text="删除已选", width=78, height=28, fg_color="#6b3a42", hover_color="#5a2f36", command=self._delete_selected_whitelist_rows).pack(side="left")

        ctk.CTkButton(
            self.whitelist_manager, text="从文件增量导入并去重", height=32, corner_radius=8,
            command=self._import_whitelist_file,
        ).pack(fill="x", pady=(0, 6))
        rollback_row = ctk.CTkFrame(self.whitelist_manager, fg_color="transparent")
        rollback_row.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(
            rollback_row, text="备份 JSON", height=32, corner_radius=8,
            command=self._backup_whitelist_json,
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(
            rollback_row, text="从 JSON 回滚", height=32, corner_radius=8,
            fg_color="#596579", hover_color="#485364", command=self._restore_whitelist_json,
        ).pack(side="left", fill="x", expand=True, padx=(4, 0))
        ctk.CTkButton(
            self.whitelist_manager, text="AI分析输入内容并加入白名单", height=32, corner_radius=8,
            fg_color="#3d7a5a", hover_color="#2f6a4c",
            command=self._ai_import_whitelist,
        ).pack(fill="x", pady=(0, 6))
        self.whitelist_progress_frame = ctk.CTkFrame(self.whitelist_manager, fg_color="transparent")
        ctk.CTkLabel(self.whitelist_progress_frame, text="AI 正在分析白名单", font=ctk.CTkFont(size=12)).pack(
            side="left", padx=(2, 10)
        )
        self.whitelist_progress = ctk.CTkProgressBar(self.whitelist_progress_frame, mode="indeterminate", height=8)
        self.whitelist_progress.pack(side="left", fill="x", expand=True)

        add_row = ctk.CTkFrame(self.whitelist_manager, fg_color="transparent")
        add_row.pack(fill="x", pady=4)
        self.wl_rule_var = ctk.StringVar()
        self.wl_reason_var = ctk.StringVar(value="手动添加")
        ctk.CTkEntry(add_row, textvariable=self.wl_rule_var, placeholder_text="IP / CIDR / 范围 / 域名（支持逗号多条）", corner_radius=8).pack(
            side="left", fill="x", expand=True, padx=(0, 6)
        )
        ctk.CTkEntry(add_row, textvariable=self.wl_reason_var, width=96, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(add_row, text="添加", width=58, corner_radius=8, command=self._add_whitelist).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            add_row, text="删除", width=58, corner_radius=8,
            fg_color="#6b3a42", hover_color="#5a2f36", command=self._del_whitelist,
        ).pack(side="left")
        self.wl_count = ctk.CTkLabel(self.whitelist_manager, text="", font=ctk.CTkFont(size=12))
        self.wl_count.pack(anchor="w", pady=(6, 0))

        self.company_filter_var = ctk.StringVar()
        self.company_filter_var.trace_add("write", lambda *_: self._refresh_company_list())
        ctk.CTkEntry(
            self.company_manager, textvariable=self.company_filter_var,
            placeholder_text="筛选公司网段 / 部门名称", corner_radius=8,
        ).pack(fill="x", pady=(8, 0))
        self.company_list = ctk.CTkTextbox(
            self.company_manager, corner_radius=8, border_width=1,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.company_list.pack(fill="both", expand=True, pady=(10, 8))
        self.company_list.bind("<Button-1>", self._toggle_company_row)
        self.company_list.bind("<Control-a>", lambda _event: self._select_all_company_rows(True))
        self._company_visible_rules: list[str] = []
        self._company_selected_rules: set[str] = set()
        company_selection = ctk.CTkFrame(self.company_manager, fg_color="transparent")
        company_selection.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(company_selection, text="全选", width=58, height=28, command=lambda: self._select_all_company_rows(True)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(company_selection, text="全不选", width=68, height=28, command=lambda: self._select_all_company_rows(False)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(company_selection, text="删除已选", width=78, height=28, fg_color="#6b3a42", hover_color="#5a2f36", command=self._delete_selected_company_rows).pack(side="left")
        ctk.CTkButton(
            self.company_manager, text="从文件增量导入并去重", height=32, corner_radius=8,
            command=self._import_company_network_file,
        ).pack(fill="x", pady=(0, 6))
        company_rollback = ctk.CTkFrame(self.company_manager, fg_color="transparent")
        company_rollback.pack(fill="x", pady=(0, 6))
        ctk.CTkButton(
            company_rollback, text="备份 JSON", height=32, corner_radius=8,
            command=self._backup_company_json,
        ).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(
            company_rollback, text="从 JSON 回滚", height=32, corner_radius=8,
            fg_color="#596579", hover_color="#485364", command=self._restore_company_json,
        ).pack(side="left", fill="x", expand=True, padx=(4, 0))
        company_add = ctk.CTkFrame(self.company_manager, fg_color="transparent")
        company_add.pack(fill="x", pady=4)
        self.company_rule_var = ctk.StringVar()
        self.company_department_var = ctk.StringVar()
        ctk.CTkEntry(
            company_add, textvariable=self.company_rule_var,
            placeholder_text="内网 CIDR，如 10.2.0.0/16", corner_radius=8,
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkEntry(
            company_add, textvariable=self.company_department_var,
            placeholder_text="部门名称", width=116, corner_radius=8,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            company_add, text="添加", width=58, corner_radius=8,
            command=self._add_company_network,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            company_add, text="删除", width=58, corner_radius=8,
            fg_color="#6b3a42", hover_color="#5a2f36", command=self._delete_company_network,
        ).pack(side="left")
        self.company_count = ctk.CTkLabel(self.company_manager, text="", font=ctk.CTkFont(size=12))
        self.company_count.pack(anchor="w", pady=(6, 0))

        self._switch_rule_manager("白名单")
        self._refresh_whitelist_list()
        self._refresh_company_list()

    # ── 主题 ──────────────────────────────────────────
    def _toggle_theme(self) -> None:
        self._theme = "light" if self._theme == "dark" else "dark"
        self.settings["theme"] = self._theme
        self._apply_theme_colors()
        save_settings(self.settings)

    def _pick_logo(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 Logo",
            filetypes=[("图片", "*.png;*.jpg;*.jpeg;*.bmp;*.webp;*.ico;*.gif"), ("全部", "*.*")],
        )
        if path:
            self.logo_var.set(path)
            self._preview_branding()

    def _clear_logo(self) -> None:
        self.logo_var.set("")
        self._preview_branding()

    def _branding_draft_from_ui(self) -> dict[str, Any]:
        logo = self.logo_var.get().strip()
        for label, raw in (("Logo", logo),):
            if not raw:
                continue
            path = Path(raw)
            if not path.is_file():
                raise ValueError(f"{label}文件不存在：{path}")
            try:
                with Image.open(path) as image:
                    image.verify()
            except Exception as exc:
                raise ValueError(f"{label}不是可读取的图片：{path}") from exc
        return {
            "app_title": self.app_title_var.get().strip() or APP_DISPLAY_NAME,
            "subtitle_enabled": bool(self.subtitle_enabled_var.get()),
            "subtitle_text": self.subtitle_text_var.get().strip() or DESIGNER_CREDIT,
            "logo_path": logo,
        }

    def _sync_branding_from_ui(self) -> None:
        if not hasattr(self, "logo_var"):
            return
        draft = self._branding_draft_from_ui()
        self.settings.update(draft)
        self._branding_preview = None

    def _preview_branding(self) -> None:
        """Preview the appearance draft without changing saved settings."""
        try:
            self._branding_preview = {
                **self.settings,
                **self._branding_draft_from_ui(),
            }
            self._apply_logo(str(self._branding_preview.get("logo_path") or ""))
            self._apply_brand_text(self._branding_preview)
            Toast(self, "外观预览中，保存后生效", "info", 1400)
        except Exception as e:
            messagebox.showerror("预览失败", str(e))

    def _reset_branding_draft(self) -> None:
        if not messagebox.askyesno(
            "外观恢复默认",
            "只清除 Logo、工具标题和副标题，不会修改 API Key、白名单或其它配置。是否继续？",
            parent=self,
        ):
            return
        self.app_title_var.set(str(DEFAULT_SETTINGS["app_title"]))
        self.subtitle_enabled_var.set(bool(DEFAULT_SETTINGS["subtitle_enabled"]))
        self.subtitle_text_var.set(str(DEFAULT_SETTINGS["subtitle_text"]))
        self.logo_var.set(str(DEFAULT_SETTINGS["logo_path"]))
        self._preview_branding()

    # ── 编号 ──────────────────────────────────────────
    def _manual_seq_raw(self) -> str:
        return self.number_seq_var.get().strip() if hasattr(self, "number_seq_var") else ""

    def _fill_auto_seq(self) -> None:
        """按当前日期把序号框填成自动下一号（可再改）。"""
        try:
            d = validate_number_date(self.number_date_var.get())
            nxt = auto_next_seq(self.settings, d)
            self.number_seq_var.set(f"{nxt:03d}")
        except Exception:
            pass
        self._refresh_number_preview()

    def _on_number_date_typed(self) -> None:
        """改日期时同步建议序号为该日自动下一号。"""
        raw = self.number_date_var.get().strip()
        if re.fullmatch(r"\d{4}", raw):
            try:
                validate_number_date(raw)
                nxt = auto_next_seq(self.settings, raw)
                self.number_seq_var.set(f"{nxt:03d}")
            except Exception:
                pass
        self._refresh_number_preview()

    def _on_number_date_change(self) -> None:
        try:
            d = validate_number_date(self.number_date_var.get())
            self.settings["number_date"] = d
            # 失焦时若序号空则补自动号
            if not self._manual_seq_raw():
                self.number_seq_var.set(f"{auto_next_seq(self.settings, d):03d}")
            save_settings(self.settings)
        except ValueError:
            pass
        self._refresh_number_preview()

    def _on_number_seq_change(self) -> None:
        raw = self._manual_seq_raw()
        if not raw:
            self._fill_auto_seq()
            return
        try:
            validate_number_seq(raw)
        except ValueError:
            pass
        self._refresh_number_preview()

    def _refresh_number_preview(self) -> None:
        raw = self.number_date_var.get().strip()
        try:
            num = peek_number(self.settings, raw, self._manual_seq_raw() or None)
            self.number_preview.configure(text=f"→ {num}")
        except Exception as e:
            self.number_preview.configure(text=f"→ {e}")

    def _bump_seq_after_write(self, used_seq: int) -> None:
        """写入成功后，序号框跳到下一号，方便连续出单。"""
        self.number_seq_var.set(f"{used_seq + 1:03d}")
        self._refresh_number_preview()

    def _on_source_change(self) -> None:
        name = self._field_value("source")
        ip = MONITOR_SOURCE_IP.get(name, "")
        self.source_ip_label.configure(text=f"平台IP：{ip}")
        self._update_batch_context()

    def _update_batch_context(self) -> None:
        if not hasattr(self, "batch_context_label") or not hasattr(self, "fields"):
            return
        source = self._field_value("source") or self.settings.get("default_source", "自定义监测平台")
        level = self._field_value("event_level") or self.settings.get("default_event_level", "五级")
        self.batch_context_label.configure(text=f"来源 {source} · 事件等级 {level}")

    # ── 输入 ──────────────────────────────────────────
    def _pick_file(self) -> None:
        paths = filedialog.askopenfilenames(
            title="选择告警文件（可多选）",
            filetypes=[
                ("支持的文件", "*.png;*.jpg;*.jpeg;*.bmp;*.webp;*.gif;*.html;*.htm;*.mhtml;*.mht;*.txt;*.md;*.log;*.csv;*.tsv;*.json;*.xml;*.xlsx;*.xlsm"),
                ("图片", "*.png;*.jpg;*.jpeg;*.bmp;*.webp;*.gif"),
                ("网页", "*.html;*.htm;*.mhtml;*.mht"),
                ("文本", "*.txt;*.md;*.log"),
                ("全部", "*.*"),
            ],
        )
        if not paths:
            return
        if len(paths) == 1:
            self._load_file(paths[0], auto_ai=False)
        else:
            self._enqueue_paths(list(paths), switch_tab=True)

    def _set_thumb_image(self, path: str) -> None:
        """左侧缩略图预览（仅显示，不做 OCR）。"""
        try:
            img = Image.open(path)
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")
            img.thumbnail((150, 100), Image.Resampling.LANCZOS)
            self._thumb_ctk = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            self.thumb_label.configure(image=self._thumb_ctk, text="")
        except Exception:
            self._thumb_ctk = None
            try:
                self.thumb_label.configure(image=None, text="[图片]")
            except Exception:
                pass

    def _set_thumb_file(self, path: Path, kind: str) -> None:
        self._thumb_ctk = None
        icon = "🌐 HTML" if kind == "web" else "📄 文件"
        try:
            self.thumb_label.configure(image=None, text=icon)
        except Exception:
            pass
        try:
            size_kb = max(1, path.stat().st_size // 1024)
            self.thumb_meta.configure(
                text=f"{path.name}\n类型：{kind}\n大小：{size_kb} KB\n→ 将交 AI 研判填字段"
            )
        except Exception:
            pass

    def _load_file(self, path: str, auto_ai: bool = False) -> None:
        """载入文件：图片/HTML 只做缩略展示，再交给 AI 研判填字段。"""
        try:
            p = Path(str(path).strip().strip('"').strip("'"))
            if not p.exists() or not p.is_file():
                messagebox.showerror("读取失败", f"文件不存在：{path}")
                return
            size = p.stat().st_size
            if size > 15 * 1024 * 1024:
                messagebox.showerror("文件过大", f"{p.name} 超过 15MB")
                return
            resolved = str(p.resolve())
            size_kb = max(1, size // 1024)
            suffix = p.suffix.lower()

            try:
                self.file_hint.configure(
                    text=f"已载入：{p.name}（{size_kb} KB）"
                )
            except Exception:
                pass

            if suffix in IMAGE_EXTS:
                self._pending_image = resolved
                self._pending_file = ""
                self._set_thumb_image(resolved)
                try:
                    self.thumb_meta.configure(
                        text=f"{p.name}\n图片 {size_kb} KB\n→ 缩略预览，内容交 AI 识别研判"
                    )
                    self.input_box.delete("1.0", "end")
                    self.input_box.insert("1.0", f"[图片] {resolved}\n（缩略已显示，AI 将分析此图）")
                except Exception:
                    pass

                if auto_ai:
                    self.after(120, self._generate_order)
                return

            if suffix in WEB_EXTS:
                self._pending_image = ""
                self._pending_file = resolved
                self._set_thumb_file(p, "web")
                try:
                    self.input_box.delete("1.0", "end")
                    self.input_box.insert(
                        "1.0",
                        f"[网页文件] {resolved}\n（不预览全文，AI 将分析此文件）",
                    )
                except Exception:
                    pass
                if auto_ai:
                    self.after(120, self._generate_order)
                return

            # 文本：可预览部分内容 + 交 AI
            self._pending_image = ""
            self._pending_file = resolved
            self._set_thumb_file(p, "text")
            data = p.read_bytes()
            text = ""
            for enc in ("utf-8-sig", "gb18030", "utf-16", "utf-8"):
                try:
                    text = data.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if not text:
                text = data.decode("utf-8", errors="ignore")
            preview = text[:12000] if len(text) > 12000 else text
            try:
                self.input_box.delete("1.0", "end")
                if len(text) > 12000:
                    self.input_box.insert(
                        "1.0",
                        preview + f"\n\n…(已截断预览，完整文件将按路径交 AI)\n[文件] {resolved}",
                    )
                else:
                    self.input_box.insert("1.0", text)
            except Exception:
                self.input_box.delete("1.0", "end")
                self.input_box.insert("1.0", f"[文件] {resolved}")
            if auto_ai:
                self.after(120, self._generate_order)
        except Exception as e:
            try:
                messagebox.showerror("读取失败", f"{e}")
            except Exception:
                pass

    def _paste_clipboard(self) -> None:
        self._on_paste()

    def _on_paste(self, _event: Any = None) -> str | None:
        # 优先图片
        try:
            from PIL import ImageGrab

            img = ImageGrab.grabclipboard()
            if isinstance(img, Image.Image):
                tmp = ASSETS_DIR / "_clipboard.png"
                tmp.parent.mkdir(parents=True, exist_ok=True)
                img.convert("RGB").save(tmp)
                self._load_file(str(tmp), auto_ai=False)
                Toast(self, "截图已载入", "ok")
                return "break"
            if isinstance(img, list) and img:
                # 文件路径列表
                path = str(img[0])
                if Path(path).exists():
                    self._load_file(path)
                    return "break"
        except Exception:
            pass
        try:
            text = self.clipboard_get()
            if text:
                _insert_clipboard_text(self.input_box, text)
                self.file_hint.configure(text="已粘贴文字")
                return "break"
        except Exception:
            pass
        # The binding is intentionally limited to the original-alert editor.
        # Always stop propagation so Tk cannot run a second paste handler.
        return "break" if _event is not None else None

    def _clear_input(self) -> None:
        self.input_box.delete("1.0", "end")
        self.supplement_box.delete("1.0", "end")
        self._pending_image = ""
        self._pending_file = ""
        self._thumb_ctk = None
        try:
            self.thumb_label.configure(image=None, text="（拖入图片将显示缩略图）")
            self.thumb_meta.configure(text="未载入文件")
        except Exception:
            pass
        self.file_hint.configure(
            text="未载入告警材料"
        )
        self.preview_box.delete("1.0", "end")
        self._last_order = None
        self._generated_output = ""
        self._ai_raw_output = ""
        self._analysis_notes = ""

    def _toggle_supplement(self) -> None:
        self._supplement_visible = not self._supplement_visible
        if self._supplement_visible:
            self.supplement_frame.pack(
                fill="x", padx=14, pady=(0, 8), before=self.action_row
            )
            self.supplement_toggle.configure(text="补充研判材料  ▾")
            self.supplement_box.focus_set()
        else:
            self.supplement_frame.pack_forget()
            self.supplement_toggle.configure(text="补充研判材料  ▸")

    def _show_result_view(self, choice: str) -> None:
        if choice == "原始结果":
            content = self._ai_raw_output
        elif choice == "研判依据":
            content = self._analysis_notes
        else:
            content = self._generated_output
        self.preview_box.delete("1.0", "end")
        self.preview_box.insert("1.0", content or "（暂无结果）")

    def _set_analysis_progress(self, active: bool) -> None:
        if not hasattr(self, "analysis_progress_frame"):
            return
        if active:
            self._analysis_progress_started_at = datetime.now()
            self.analysis_progress_frame.pack(
                fill="x", padx=14, pady=(0, 8), before=self.action_row
            )
            self.analysis_progress.start()
            self._refresh_analysis_progress_label()
            return
        if self._analysis_progress_job:
            try:
                self.after_cancel(self._analysis_progress_job)
            except Exception:
                pass
            self._analysis_progress_job = None
        self._analysis_progress_started_at = None
        self.analysis_progress.stop()
        self.analysis_progress_frame.pack_forget()

    def _refresh_analysis_progress_label(self) -> None:
        if not self._extracting or not self._analysis_progress_started_at:
            return
        elapsed = max(0, int((datetime.now() - self._analysis_progress_started_at).total_seconds()))
        self.analysis_progress_label.configure(
            text=f"AI 正在分析材料 · 已用 {elapsed // 60:02d}:{elapsed % 60:02d}"
        )
        self._analysis_progress_job = self.after(500, self._refresh_analysis_progress_label)

    def _set_whitelist_progress(self, active: bool) -> None:
        if not hasattr(self, "whitelist_progress_frame"):
            return
        if active:
            self.whitelist_progress_frame.pack(fill="x", pady=(0, 6), after=self.wl_list)
            self.whitelist_progress.start()
        else:
            self.whitelist_progress.stop()
            self.whitelist_progress_frame.pack_forget()

    def _refresh_current_order(self) -> None:
        """Rebuild only the generated work order from the manually edited fields."""
        previous = self._last_order
        if previous is None:
            messagebox.showwarning("刷新工单", "请先生成工单")
            return

        fields = self._collect_fields()
        custom = fields.get("_custom_fields")
        if isinstance(custom, dict):
            order = WorkOrder(
                number=str(fields.get("number") or previous.number),
                source=str(fields.get("source") or previous.source),
                time=str(fields.get("time") or previous.time),
                attack_ip=str(fields.get("attack_ip") or previous.attack_ip),
                target_ip=str(fields.get("target_ip") or previous.target_ip),
                xff=str(fields.get("xff") or previous.xff),
                domain_url=str(fields.get("domain_url") or previous.domain_url),
                attack_name=str(fields.get("attack_name") or previous.attack_name),
                event_type=str(fields.get("event_type") or previous.event_type),
                custom_fields={key: str(value) for key, value in custom.items()},
            )
        else:
            fields["number"] = previous.number
            order = assemble_order(
                fields,
                self.wl,
                auto_whitelist=False,
                auto_advice=False,
            )

        self._last_order = order
        self._generated_output = order.to_markdown()
        self.result_view_seg.set("生成工单")
        self._show_result_view("生成工单")
        Toast(self, "已按手动修改刷新工单", "ok", 1800)

    def _check_result_whitelist(self) -> None:
        order = self._last_order
        if order is None:
            messagebox.showwarning("白名单检测", "请先生成工单")
            return
        result = check_alert_whitelist_gate(
            self.wl, attack_ip=order.attack_ip, target_ip=order.target_ip,
            xff=order.xff, domain_url=order.domain_url,
        )
        lines = [
            "本地离线白名单检测",
            f"免报：{'是' if result.skip_order else '否'}",
            "规则：所有参与IP均须通过；公司内网仅在攻击IP角色下算半白名单。",
            "显式白名单：",
            _whitelist_items_text(result.matched, reasons=True),
            "半白名单：",
            _whitelist_items_text(result.semi_matched, reasons=True),
            "未通过：",
            _whitelist_items_text(result.unmatched),
        ]
        attributions = company_attribution_lines(
            attack_ip=order.attack_ip, target_ip=order.target_ip,
            xff=order.xff, domain_url=order.domain_url,
        )
        lines.append("内网部门归属：\n" + ("\n".join(attributions) if attributions else "无匹配"))
        report = "\n".join(lines)
        messagebox.showinfo("白名单检测", report)

    def _check_result_history(self) -> None:
        order = self._last_order
        if order is None:
            messagebox.showwarning("历史提交检测", "请先生成工单")
            return
        related = self.history.find_related(
            attack_ip=order.attack_ip, target_ip=order.target_ip,
            attack_name=order.attack_name, event_type=order.event_type,
        )
        if not related:
            messagebox.showinfo("历史提交检测", "历史跟踪表中没有找到相同攻击IP、目标IP或相似攻击特征。")
            return
        evidence = "\n".join(
            f"- {hit.code or '无编号'} | 攻击IP {hit.attack_ip} | 目标IP {hit.target_ip} | "
            f"{hit.attack_name or '未知攻击'} | {hit.reason}"
            for hit in related[:30]
        )
        messagebox.showinfo("历史提交检测", "发现相关历史工单：\n\n" + evidence)

    def _show_history_orders(self) -> None:
        HistoryBrowserDialog(self, self.history.records)

    def _show_history_raw_results(self) -> None:
        records = [record for record in self.history.records if str(record.get("raw_result") or "").strip()]
        lines = []
        for index, record in enumerate(records, start=1):
            lines.append(f"[{index}] {record.get('code') or '无编号'}\n{record.get('raw_result')}\n")
        ReadOnlyTextDialog(
            self,
            "历史原始结果",
            "\n".join(lines) or "暂无已保存的 AI 原始结果。Excel 导入的历史工单不含原始模型响应；后续确认工单会自动保存。",
        )

    def _copy_current_order(self) -> None:
        content = self._generated_output.strip()
        if not content:
            messagebox.showwarning("复制工单", "请先生成工单")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(content)
            self.update_idletasks()
        except Exception as exc:
            messagebox.showerror("复制失败", str(exc))
            return
        if self._last_order and self._last_order.number != self._last_copied_number:
            match = re.fullmatch(r"(\d{4})-(\d+)", self._last_order.number)
            if match:
                date_mmdd, seq = match.groups()
                commit_number(self.settings, date_mmdd, used_seq=int(seq))
                save_settings(self.settings)
                self._last_copied_number = self._last_order.number
                self._bump_seq_after_write(int(seq))
        Toast(self, "工单已复制", "ok", 1800)

    def _confirm_current_order(self) -> None:
        """Commit the displayed work order into the built-in history cache."""
        if self._last_order is None:
            messagebox.showwarning("确认工单", "请先生成工单")
            return
        fields = self._collect_fields()
        fields["number"] = self._last_order.number
        order = assemble_order(
            fields, self.wl,
            auto_whitelist=fields.get("is_whitelist") != "是",
            auto_advice=not bool(fields.get("advice")),
        )
        try:
            changed, total = self.history.confirm_order(order, raw_result=self._ai_raw_output)
        except Exception as exc:
            messagebox.showerror("确认工单失败", str(exc))
            return
        match = re.fullmatch(r"(\d{4})-(\d+)", order.number)
        if match:
            date_mmdd, seq = match.groups()
            commit_number(self.settings, date_mmdd, used_seq=int(seq))
            self._last_copied_number = order.number
            self._bump_seq_after_write(int(seq))
        self._last_order = order
        self._generated_output = order.to_markdown()
        self._show_result_view(self.result_view_seg.get())
        save_settings(self.settings)
        Toast(self, f"工单已确认并写入告警跟踪（{total} 条）" if changed else "工单已确认，告警跟踪无需更新", "ok", 2600)

    # ── 模板 ──────────────────────────────────────────
    def _template_names(self) -> list[str]:
        names = [t["name"] for t in list_templates()]
        return names or [BUILTIN_TEMPLATE_NAME]

    def _reload_templates(self) -> None:
        names = self._template_names()
        self.template_combo.configure(values=names)
        cur = self.template_var.get()
        if cur not in names:
            self.template_var.set(names[0])

    def _apply_template_edit(self, template: dict[str, Any]) -> None:
        name = str(template.get("name") or BUILTIN_TEMPLATE_NAME)
        self.template_var.set(name)
        self.settings["active_template"] = name
        save_settings(self.settings)
        self._reload_templates()
        self._apply_template_to_fields(template)

    def _add_manual_template_field(self) -> None:
        name = self.template_var.get().strip() or BUILTIN_TEMPLATE_NAME
        dialog = ManualFieldDialog(self, name)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        label, value, rows, options = dialog.result
        try:
            _path, template = add_manual_template_field(
                name, label, value, rows=rows, options=options
            )
            self._apply_template_edit(template)
            Toast(self, f"已添加字段“{label}”", "ok", 1600)
        except Exception as exc:
            messagebox.showerror("添加字段失败", str(exc))

    def _remove_template_field(self, label: str) -> None:
        name = self.template_var.get().strip() or BUILTIN_TEMPLATE_NAME
        if not messagebox.askyesno("删除字段", f"从模板“{name}”删除字段“{label}”？"):
            return
        try:
            _path, template = remove_template_field(name, label)
            self._apply_template_edit(template)
            Toast(self, f"已删除字段“{label}”", "ok", 1600)
        except Exception as exc:
            messagebox.showerror("删除字段失败", str(exc))

    def _move_template_field(self, label: str, delta: int) -> None:
        names = list(self._template_schema)
        if label not in names:
            return
        target = max(0, min(names.index(label) + delta, len(names) - 1))
        if target == names.index(label):
            return
        try:
            _path, template = move_template_field(self.template_var.get().strip(), label, target)
            self._apply_template_edit(template)
        except Exception as exc:
            messagebox.showerror("调整字段顺序失败", str(exc))

    def _start_template_field_drag(self, label: str, _event: Any) -> None:
        self._template_drag_field = label

    def _finish_template_field_drag(self, event: Any) -> None:
        label = getattr(self, "_template_drag_field", "")
        self._template_drag_field = ""
        if not label or label not in self._template_rows:
            return
        ordered = [name for name in self._template_schema if name in self._template_rows]
        if len(ordered) < 2:
            return
        target_label = min(
            ordered,
            key=lambda name: abs((self._template_rows[name].winfo_rooty() + self._template_rows[name].winfo_height() / 2) - event.y_root),
        )
        source_index = ordered.index(label)
        target_index = ordered.index(target_label)
        if source_index == target_index:
            return
        try:
            _path, template = move_template_field(self.template_var.get().strip(), label, target_index)
            self._apply_template_edit(template)
            Toast(self, f"已调整字段“{label}”的位置", "ok", 1200)
        except Exception as exc:
            messagebox.showerror("拖动排序失败", str(exc))

    def _active_template(self) -> dict:
        name = self.template_var.get().strip() if hasattr(self, "template_var") else ""
        self.settings["active_template"] = name
        return load_template(name or None)

    def _field_value(self, key: str) -> str:
        if self._template_schema:
            for label in self._template_schema:
                if self._template_bindings.get(label) == key and label in self._template_rows:
                    return self._template_rows[label].get()
            return ""
        row = self.fields.get(key)
        return row.get() if row is not None and row.winfo_manager() else ""

    def _apply_template_to_fields(self, template: dict[str, Any]) -> None:
        schema = template.get("field_schema") or {}
        values = template.get("sample_fields") or {}
        raw_rows = template.get("field_rows") or {}
        raw_options = template.get("field_options") or {}
        names = [str(key).strip() for key in schema if str(key).strip()]
        raw_bindings = template.get("field_bindings") or {}
        self._template_bindings = {
            label: str(raw_bindings.get(label) or "") for label in names
            if str(raw_bindings.get(label) or "")
        }
        self._template_schema = names
        for row in self.fields.values():
            row.pack_forget()
            row.set("")
        for row in self._template_rows.values():
            row.destroy()
        self._template_rows = {}
        # Number/source controls belonged to the legacy fixed schema.  A blank
        # install and every imported template now show only their own fields.
        self.number_frame.pack_forget()
        self.source_ip_label.pack_forget()
        self.event_level_hint.pack_forget()
        self.template_fields_frame.pack_forget()
        for name in names:
            semantic = self._template_bindings.get(name, "")
            try:
                rows = max(1, min(12, int(raw_rows.get(name, 3 if semantic == "advice" else 1))))
            except (TypeError, ValueError):
                rows = 3 if semantic == "advice" else 1
            custom_options: list[str] = []
            for option in raw_options.get(name, []) if isinstance(raw_options.get(name), list) else []:
                option = str(option or "").strip()
                if option and option not in custom_options:
                    custom_options.append(option)
            kind = "text" if semantic == "advice" else "entry"
            choices = None
            readonly = False
            if custom_options:
                kind, choices, readonly, rows = "combo", custom_options, True, 1
            elif semantic == "source":
                kind, choices = "combo", MONITOR_SOURCE_NAMES
            elif semantic == "alert_level":
                kind, choices = "combo", ALERT_LEVELS
            elif semantic == "event_level":
                kind, choices = "combo", EVENT_LEVELS
            elif semantic == "attack_result":
                kind, choices = "combo", ATTACK_RESULTS
            elif semantic == "is_whitelist":
                kind, choices = "combo", WHITELIST_OPTIONS
            elif rows > 1:
                kind = "text"
            row = FieldRow(
                self.template_fields_frame,
                name,
                kind=kind,
                values=choices or [],
                rows=rows,
                readonly=readonly,
                label_width=108,
                width=360,
                height=78 if kind == "text" else 34,
                actions=[
                    ("↑", lambda field=name: self._move_template_field(field, -1)),
                    ("↓", lambda field=name: self._move_template_field(field, 1)),
                    ("×", lambda field=name: self._remove_template_field(field)),
                ],
            )
            row.pack(fill="x", pady=5, padx=2)
            initial_value = str(values.get(name) or "")
            if readonly and choices and initial_value not in choices:
                initial_value = choices[0]
            row.set(initial_value)
            row.label_w.configure(text=f"⠿ {name}")
            row.label_w.bind("<ButtonPress-1>", lambda event, field=name: self._start_template_field_drag(field, event))
            row.label_w.bind("<ButtonRelease-1>", self._finish_template_field_drag)
            row.apply_theme(self._colors())
            self._template_rows[name] = row
        if names:
            self.template_fields_frame.pack(fill="x", padx=2, pady=(0, 6))
        self._update_batch_context()

    def _on_template_selected(self, choice: str) -> None:
        self.settings["active_template"] = choice
        save_settings(self.settings)
        template = load_template(choice)
        self._apply_template_to_fields(template)
        Toast(self, f"已切换模板“{choice}”", "ok", 1400)

    def _save_current_template(self) -> None:
        if self._extracting:
            Toast(self, "正在处理，请稍候", "info")
            return
        dialog = TemplateTextDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        name, sample = dialog.result
        if name == BUILTIN_TEMPLATE_NAME:
            messagebox.showwarning("模板名称", "内置模板不能覆盖，请使用其它名称")
            return
        self._extracting = True
        Toast(self, "正在生成模板字段", "info", 1800)

        def worker() -> None:
            try:
                template = template_from_sample(name, sample)
                saved_path = save_template(template)

                def finish() -> None:
                    try:
                        self.settings["active_template"] = name
                        save_settings(self.settings)
                        self._reload_templates()
                        self.template_var.set(name)
                        self._apply_template_to_fields(load_template(saved_path))
                        Toast(self, f"模板“{name}”已生成并同步", "ok", 2400)
                    finally:
                        self._extracting = False

                self.after(0, finish)
            except Exception as exc:
                error = str(exc)
                def fail() -> None:
                    self._extracting = False
                    messagebox.showerror("模板生成失败", error)

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _import_template(self) -> None:
        path = filedialog.askopenfilename(
            title="导入提取模板",
            filetypes=[("JSON 模板", "*.json"), ("全部", "*.*")],
        )
        if not path:
            return
        try:
            dest = import_template_file(path)
            data = load_template(dest)
            self.template_var.set(data.get("name") or dest.stem)
            self.settings["active_template"] = self.template_var.get()
            save_settings(self.settings)
            self._reload_templates()
            self._apply_template_to_fields(data)
            Toast(self, "模板已导入", "ok")
        except Exception as e:
            messagebox.showerror("导入失败", str(e))

    def _delete_current_template(self) -> None:
        name = self.template_var.get().strip()
        if not name:
            return
        if name == BUILTIN_TEMPLATE_NAME:
            messagebox.showwarning("删除模板", "内置模板不能删除")
            return
        if not messagebox.askyesno("删除模板", f"确定删除模板“{name}”？"):
            return
        try:
            if not delete_template(name):
                messagebox.showwarning("删除模板", "模板不存在，可能已被移动或删除")
                return
            self.settings["active_template"] = BUILTIN_TEMPLATE_NAME
            save_settings(self.settings)
            self._reload_templates()
            self.template_var.set(BUILTIN_TEMPLATE_NAME)
            Toast(self, f"已删除模板“{name}”", "ok")
        except Exception as exc:
            messagebox.showerror("删除失败", str(exc))

    # ── 拖拽 ──────────────────────────────────────────
    def _setup_drag_drop(self) -> None:
        """安装稳定的 Windows 拖放（不用 windnd，避免 CTk 闪退）。"""
        if self._drop_target is not None:
            return

        def on_files(paths: list[str]) -> None:
            # 已在主线程（drop_support 的 after 轮询）
            try:
                self._on_files_dropped(paths)
            except Exception as e:
                try:
                    messagebox.showerror("拖拽处理失败", str(e))
                except Exception:
                    pass

        try:
            target = FileDropTarget(self, on_files)
            if target.install():
                self._drop_target = target
                if hasattr(self, "file_hint"):
                    self.file_hint.configure(
                        text="文件拖拽已启用"
                    )
            else:
                # 回退 windnd（仅当自定义安装失败）
                self._setup_drag_drop_windnd_fallback()
        except Exception:
            self._setup_drag_drop_windnd_fallback()

    def _setup_drag_drop_windnd_fallback(self) -> None:
        try:
            import windnd
        except ImportError:
            return

        def _hook(files: list) -> None:
            paths: list[str] = []
            try:
                for item in files or []:
                    if isinstance(item, bytes):
                        decoded = None
                        for enc in ("gbk", "mbcs", "utf-8", "utf-16le", "utf-16"):
                            try:
                                decoded = item.decode(enc)
                                break
                            except Exception:
                                continue
                        paths.append(decoded or item.decode("utf-8", errors="ignore"))
                    else:
                        paths.append(str(item))
            except Exception:
                paths = []
            # 关键路径拷贝，避免闭包问题
            captured = list(paths)
            try:
                self.after(50, lambda: self._on_files_dropped(captured))
            except Exception:
                pass

        try:
            # force_unicode 对中文路径更稳
            windnd.hook_dropfiles(self, func=_hook, force_unicode=True)
        except TypeError:
            try:
                windnd.hook_dropfiles(self, func=_hook)
            except Exception:
                pass
        except Exception:
            pass

    def _on_files_dropped(self, paths: list[str]) -> None:
        valid: list[str] = []
        for raw in paths or []:
            try:
                s = str(raw).strip().strip('"').strip("'")
                if not s:
                    continue
                p = Path(s)
                if not p.exists() and s.startswith("\\\\?\\"):
                    p = Path(s[4:])
                if p.is_file() and p.suffix.lower() in SUPPORTED_DROP_EXTS:
                    valid.append(str(p.resolve()))
            except Exception:
                continue
        if not valid:
            try:
                Toast(self, "未识别到可处理的文件（支持图片/HTML/文本）", "warn")
            except Exception:
                pass
            return
        try:
            # 确保在工单页
            if hasattr(self, "tab_seg") and self.tab_seg.get() != "工单生成" and len(valid) == 1:
                self.tab_seg.set("工单生成")
                self._switch_tab("工单生成")
            if len(valid) == 1:
                # 仅载入，用户确认解析方式后再生成。
                self._load_file(valid[0], auto_ai=False)
                try:
                    Toast(self, f"已载入 {Path(valid[0]).name}", "ok")
                except Exception:
                    pass
            else:
                self._enqueue_paths(valid, switch_tab=True)
                try:
                    Toast(self, f"已加入批量队列 {len(valid)} 个文件", "ok")
                except Exception:
                    pass
        except Exception as e:
            try:
                messagebox.showerror("拖拽处理失败", str(e))
            except Exception:
                pass

    def _enqueue_paths(self, paths: list[str], switch_tab: bool = False) -> None:
        new_jobs = jobs_from_paths(paths)
        existing = {j.path for j in self._batch_jobs if j.path}
        added = 0
        for job in new_jobs:
            if job.path and job.path in existing:
                continue
            self._batch_jobs.append(job)
            added += 1
        if switch_tab:
            self.tab_seg.set("批量生成")
            self._switch_tab("批量生成")
        self._refresh_batch_list()
        if added:
            self._batch_log_line(f"入队 {added} 个文件")

    def _send_current_to_batch(self) -> None:
        if self._pending_image and Path(self._pending_image).exists():
            self._enqueue_paths([self._pending_image], switch_tab=True)
            return
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            Toast(self, "输入区为空", "warn")
            return
        # 单文件路径标记
        for prefix in ("[图片]", "[网页文件]", "[剪贴板图片]"):
            if text.startswith(prefix):
                for line in text.splitlines():
                    p = line.replace(prefix, "").split("（")[0].strip()
                    if p and Path(p).exists():
                        self._enqueue_paths([p], switch_tab=True)
                        return
        jobs = jobs_from_text_blob(text)
        if not jobs:
            Toast(self, "无法拆分出告警", "warn")
            return
        self._batch_jobs.extend(jobs)
        self.tab_seg.set("批量生成")
        self._switch_tab("批量生成")
        self._refresh_batch_list()
        Toast(self, f"已加入 {len(jobs)} 条文本告警", "ok")

    # ── 批量 ──────────────────────────────────────────
    def _batch_add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="批量添加告警文件",
            filetypes=[
                ("支持的文件", "*.png;*.jpg;*.jpeg;*.bmp;*.webp;*.gif;*.html;*.htm;*.mhtml;*.mht;*.txt;*.md;*.log;*.csv;*.tsv;*.json;*.xml;*.xlsx;*.xlsm"),
                ("全部", "*.*"),
            ],
        )
        if paths:
            self._enqueue_paths(list(paths), switch_tab=False)

    def _batch_from_input_text(self) -> None:
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("拆分文本", "请先在「工单生成」页输入区粘贴多段告警文本")
            return
        jobs = jobs_from_text_blob(text)
        self._batch_jobs.extend(jobs)
        self._refresh_batch_list()
        self._batch_log_line(f"从输入区拆入 {len(jobs)} 条")
        Toast(self, f"拆入 {len(jobs)} 条", "ok")

    def _batch_select_all(self, selected: bool) -> None:
        for j in self._batch_jobs:
            if j.status != "error" or j.message != "文件不存在":
                j.selected = selected
        self._refresh_batch_list()

    def _batch_clear(self) -> None:
        self._batch_jobs.clear()
        self._refresh_batch_list()
        self.batch_log.delete("1.0", "end")
        self.batch_progress.set(0)

    def _refresh_batch_list(self) -> None:
        if not hasattr(self, "batch_list_box"):
            return
        lines = []
        selected_n = 0
        for i, j in enumerate(self._batch_jobs, 1):
            mark = "✓" if j.selected else "·"
            st = {
                "pending": "待处理",
                "done": "已生成",
                "skip_wl": "白名单",
                "skip_history": "历史跳过",
                "error": "失败",
            }.get(j.status, j.status)
            num = f" [{j.number}]" if j.number else ""
            msg = f" | {j.message}" if j.message else ""
            lines.append(f"{mark} {i:02d}. [{st}]{num} {j.label}{msg}")
            if j.selected:
                selected_n += 1
        self.batch_list_box.delete("1.0", "end")
        self.batch_list_box.insert(
            "1.0",
            "\n".join(lines) if lines else "（队列为空：拖拽多文件到窗口，或点「添加文件」）",
        )
        self.batch_count_label.configure(text=f"队列 {len(self._batch_jobs)} 条 · 勾选约 {selected_n}")

    def _batch_log_line(self, text: str) -> None:
        if not hasattr(self, "batch_log"):
            return
        self.batch_log.insert("end", text + "\n")
        self.batch_log.see("end")

    def _batch_run(self) -> None:
        if self._batching:
            Toast(self, "批量任务进行中…", "info")
            return
        # Finished/skipped items remain terminal to prevent duplicate orders.
        # Failed items can be retried after configuration or source fixes.
        runnable = []
        for j in self._batch_jobs:
            if not j.selected:
                continue
            if j.status not in {"pending", "error"}:
                continue
            if j.status == "error" and j.message == "文件不存在":
                continue
            runnable.append(j)
        if not runnable:
            messagebox.showwarning("批量生成", "队列为空或没有勾选可处理项")
            return
        try:
            date_mmdd = validate_number_date(self.number_date_var.get())
            start_seq = validate_number_seq(self._manual_seq_raw() or None)
        except ValueError as e:
            messagebox.showwarning("编号", str(e))
            return
        source = self._field_value("source") or self.settings.get("default_source", "自定义监测平台")
        event_level = self._field_value("event_level") or self.settings.get("default_event_level", "五级")
        skip_hist = bool(self.batch_skip_hist_var.get())
        analysis_mode = self._analysis_mode_code()
        self.settings["batch_skip_history"] = skip_hist
        self.settings["analysis_mode"] = analysis_mode

        total = len(runnable)
        self._batching = True
        self.batch_progress.set(0)
        self._batch_log_line("——" * 12)
        seq_hint = f"{start_seq:03d}起" if start_seq is not None else "自动"
        self._batch_log_line(
            f"开始：{total} 条 · {ANALYSIS_MODE_NAMES[analysis_mode]} · 来源 {source} · 编号 {date_mmdd}-{seq_hint}"
        )

        done_count = {"n": 0}

        def on_progress(msg: str, job: BatchJob | None) -> None:
            def ui() -> None:
                self._batch_log_line(msg)
                # 仅在条目终态回调时推进进度（job 非空且已写入/跳过/失败）
                if job is not None and job.status in {
                    "done", "skip_wl", "skip_history", "error",
                }:
                    done_count["n"] += 1
                    self.batch_progress.set(min(1.0, done_count["n"] / max(total, 1)))
                self._refresh_batch_list()

            self.after(0, ui)

        def worker() -> None:
            try:
                result = process_batch(
                    self._batch_jobs,
                    wl=self.wl,
                    history=self.history,
                    settings=self.settings,
                    source=source,
                    event_level=event_level,
                    date_mmdd=date_mmdd,
                    skip_history=skip_hist,
                    start_seq=start_seq,
                    analysis_mode=analysis_mode,
                    progress=on_progress,
                )
                save_settings(self.settings)

                def finish() -> None:
                    self._batching = False
                    self.batch_progress.set(1.0)
                    self._refresh_batch_list()
                    # 批量生成后序号对齐到自动下一号
                    try:
                        self.number_seq_var.set(
                            f"{auto_next_seq(self.settings, date_mmdd):03d}"
                        )
                    except Exception:
                        pass
                    self._refresh_number_preview()
                    summary = (
                        f"生成 {result.written} · 白名单跳过 {result.skipped_wl} · "
                        f"历史跳过 {result.skipped_history} · 失败 {result.errors}"
                    )
                    Toast(self, summary, "ok", 3200)
                    if self._tray:
                        self._tray.notify("批量生成完成", summary)

                self.after(0, finish)
            except Exception as e:
                def fail() -> None:
                    self._batching = False
                    messagebox.showerror("批量失败", str(e))

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _copy_batch_orders(self) -> None:
        blocks = [job.order_md.strip() for job in self._batch_jobs if job.status == "done" and job.order_md.strip()]
        if not blocks:
            messagebox.showwarning("复制全部工单", "当前没有已生成的工单")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n\n---\n\n".join(blocks))
            self.update_idletasks()
            Toast(self, f"已复制 {len(blocks)} 条工单", "ok", 1800)
        except Exception as exc:
            messagebox.showerror("复制失败", str(exc))

    # ── 托盘 ──────────────────────────────────────────
    def _setup_tray(self) -> None:
        if not self.settings.get("tray_enabled", True):
            return
        if self._tray and self._tray.running:
            return
        self._tray = TrayController(
            on_show=lambda: self.after(0, self._show_from_tray),
            on_quit=lambda: self.after(0, self._quit_app),
        )
        ok = self._tray.start()
        if not ok:
            self._tray = None
            Toast(self, "托盘启动失败（需 pystray）", "warn")

    def _hide_to_tray(self) -> None:
        if not self.settings.get("tray_enabled", True):
            Toast(self, "请先在配置中心启用系统托盘", "warn")
            return
        if not self._tray or not self._tray.running:
            self._setup_tray()
        if not self._tray:
            return
        self._persist_settings_light()
        self.withdraw()
        try:
            self._tray.notify("研判工单工具", "已隐藏到托盘，双击图标可恢复")
        except Exception:
            pass

    def _show_from_tray(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()
        try:
            self.attributes("-topmost", True)
            self.after(200, lambda: self.attributes("-topmost", False))
        except Exception:
            pass

    def _on_unmap(self, event: Any = None) -> None:
        pass
        # 仅处理主窗口最小化：可选托盘（默认不强制，避免误触）

    def _persist_settings_light(self) -> None:
        try:
            self._capture_window_placement()
            self.settings["theme"] = self._theme
            self.settings["number_date"] = self.number_date_var.get().strip()
            if hasattr(self, "close_to_tray_var"):
                self.settings["close_to_tray"] = bool(self.close_to_tray_var.get())
                self.settings["tray_enabled"] = bool(self.tray_enabled_var.get())
            if hasattr(self, "batch_skip_hist_var"):
                self.settings["batch_skip_history"] = bool(self.batch_skip_hist_var.get())
            if hasattr(self, "analysis_mode_var"):
                self.settings["analysis_mode"] = self._analysis_mode_code()
            save_settings(self.settings)
        except Exception:
            pass

    def _quit_app(self) -> None:
        self._really_quit = True
        if self._tray:
            self._tray.stop()
            self._tray = None
        self._persist_settings_light()
        super().destroy()

    def destroy(self) -> None:  # type: ignore[override]
        if self._drop_target is not None:
            try:
                self._drop_target.uninstall()
            except Exception:
                pass
            self._drop_target = None
        if self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
            self._tray = None
        super().destroy()

    # ── 提取 / 预览 / 写入 ────────────────────────────
    def _generate_order(self) -> None:
        if self._extracting:
            Toast(self, "正在生成，请稍候", "info")
            return
        try:
            self._sync_ai_settings_from_ui()
            self._sync_threatbook_settings_from_ui()
        except Exception:
            pass

        pending_image = getattr(self, "_pending_image", "") or ""
        pending_file = getattr(self, "_pending_file", "") or ""
        text = self.input_box.get("1.0", "end").strip()
        supplement = self.supplement_box.get("1.0", "end").strip()
        if not text and not pending_image and not pending_file:
            messagebox.showwarning("生成工单", "请先上传、粘贴或输入告警材料")
            return
        analysis_mode = self._analysis_mode_code()
        if analysis_mode == "local" and pending_image:
            messagebox.showwarning(
                "本地解析不支持图片",
                "本地解析仅支持文本与 HTML/MHTML。图片必须切换到“自动”或“在线AI”模式。",
            )
            return
        template = self._active_template()
        settings_snap = dict(self.settings)
        settings_snap["analysis_mode"] = analysis_mode
        self._extracting = True
        self._set_analysis_progress(analysis_mode != "local")
        Toast(self, f"{ANALYSIS_MODE_NAMES[analysis_mode]}处理中", "info", 2000)

        def worker() -> None:
            try:
                path = None
                if pending_image and Path(pending_image).exists():
                    path = pending_image
                elif pending_file and Path(pending_file).exists():
                    path = pending_file
                else:
                    for prefix in ("[网页文件]", "[图片]", "[剪贴板图片]", "[文件]"):
                        if prefix in text:
                            for line in text.splitlines():
                                if not line.strip().startswith("["):
                                    continue
                                p = re.sub(r"^\[[^\]]+\]\s*", "", line).split("（")[0].strip()
                                if p and Path(p).exists():
                                    path = p
                                    break
                    if not path and text:
                        first = text.splitlines()[0].strip()
                        if Path(first).exists():
                            path = first
                if path:
                    analysis_text = supplement
                else:
                    analysis_text = text
                    if supplement:
                        analysis_text += "\n\n补充研判材料：\n" + supplement
                alert = smart_extract(
                    settings=settings_snap,
                    text=analysis_text,
                    path=path,
                    template=template,
                    analysis_mode=analysis_mode,
                )
                def finish() -> None:
                    try:
                        if self._apply_extracted(alert):
                            self._build_preview()
                    finally:
                        self._extracting = False
                        self._set_analysis_progress(False)

                self.after(0, finish)
            except Exception as e:
                err = str(e)
                def fail(message: str = err) -> None:
                    self._extracting = False
                    self._set_analysis_progress(False)
                    messagebox.showerror("生成失败", message)

                self.after(0, fail)

        threading.Thread(target=worker, daemon=True).start()

    def _sync_ai_settings_from_ui(self) -> None:
        if hasattr(self, "ai_base_var"):
            self.settings["ai_enabled"] = bool(self.ai_enabled_var.get())
            self.settings["ai_use_ocr"] = bool(self.ai_ocr_var.get())
            self.settings["ai_use_judge"] = bool(self.ai_judge_var.get())
            # Runtime calls may use an unsaved draft, but saved profiles are
            # mutated only by the explicit save action.
            self.settings["ai_base_url"] = self.ai_base_var.get().strip()
            self.settings["ai_api_key"] = self.ai_key_var.get().strip()
            self.settings["ai_model"] = self.ai_model_var.get().strip()
            if hasattr(self, "ai_wire_var"):
                self.settings["ai_wire_api"] = WIRE_API_CODES.get(self.ai_wire_var.get(), "auto")
            if hasattr(self, "ai_timeout_var"):
                try:
                    self.settings["ai_timeout"] = max(8, min(int(self.ai_timeout_var.get().strip()), 120))
                except ValueError:
                    self.settings["ai_timeout"] = 45
            if hasattr(self, "ai_vision_var"):
                self.settings["ai_vision_profile"] = self.ai_vision_var.get().strip()
        if hasattr(self, "template_var"):
            self.settings["active_template"] = self.template_var.get().strip()

    def _sync_threatbook_settings_from_ui(self) -> None:
        if not hasattr(self, "threatbook_enabled_var"):
            return
        try:
            timeout = int(self.threatbook_timeout_var.get().strip())
        except ValueError:
            timeout = 8
        self.settings.update({
            "threatbook_enabled": bool(self.threatbook_enabled_var.get()),
            "threatbook_auto_enrich": False,
            "threatbook_api_key": self.threatbook_key_var.get().strip(),
            "threatbook_timeout": max(3, min(timeout, 30)),
        })

    def _test_threatbook(self) -> None:
        self._sync_threatbook_settings_from_ui()
        snapshot = dict(self.settings)
        try:
            client = ThreatBookClient(snapshot)
            if not client.ready():
                raise ThreatBookError("请启用微步 API 并填写 API Key")
        except ThreatBookError as exc:
            messagebox.showwarning("微步配置", str(exc))
            return
        Toast(self, "正在测试微步 API", "info", 1800)

        def worker() -> None:
            try:
                result = ThreatBookClient(snapshot).lookup("8.8.8.8")
                self.after(0, lambda: messagebox.showinfo("微步 API 连接成功", result.summary))
            except Exception as exc:
                self.after(0, lambda e=str(exc): messagebox.showerror("微步 API 连接失败", e))

        threading.Thread(target=worker, daemon=True).start()

    def _open_threatbook_lookup(self) -> None:
        indicators = ThreatBookLookupDialog(
            self, _work_order_ip_shortcuts(self._last_order, self._generated_output)
        )
        self.wait_window(indicators)
        selected = indicators.result
        if not selected:
            return
        invalid: list[str] = []
        for indicator in selected:
            try:
                indicator_type(indicator)
            except ThreatBookError:
                invalid.append(indicator)
        if invalid:
            messagebox.showwarning(
                "微步情报查询",
                "以下输入不是有效的 IP 或域名：\n\n" + "、".join(invalid[:20]),
                parent=self,
            )
            return
        selected = selected[:50]
        if not messagebox.askyesno(
                "确认微步查询",
                "将查询以下指标（不会参与研判或生成工单）：\n\n" + "、".join(selected)
                + ("\n……" if len(selected) > 50 else "") + "\n\n确定继续？",
                parent=self,
        ):
            return
        self._sync_threatbook_settings_from_ui()
        snapshot = dict(self.settings)
        Toast(self, f"正在查询 {len(selected)} 个微步指标", "info", 1800)

        def worker() -> None:
            lines: list[str] = []
            for indicator in selected:
                try:
                    result = ThreatBookClient(snapshot).lookup(indicator)
                    lines.append(result.display_text())
                except Exception as exc:
                    lines.append(f"{indicator}\n查询失败：{exc}")
            content = "\n\n".join(lines)
            self.after(0, lambda: ReadOnlyTextDialog(self, "微步威胁情报", content))

        threading.Thread(target=worker, daemon=True).start()

    def _open_internal_network_lookup(self) -> None:
        value = simpledialog.askstring(
            "内网IP网段查询", "输入一个或多个 IP：", parent=self,
        )
        if not value:
            return
        ips = extract_ips(value)
        if not ips:
            messagebox.showwarning("内网IP网段查询", "没有识别到有效 IP")
            return
        lines: list[str] = []
        for ip in ips:
            match = company_network_match(ip)
            if match:
                lines.append(f"{ip} -> {match.department}（{match.network}）")
            else:
                lines.append(f"{ip} -> 未匹配公司网段")
        ReadOnlyTextDialog(self, "内网IP网段查询", "\n".join(lines))

    @staticmethod
    def _is_internal_ip(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.version != 4:
            return address.is_private
        return any(address in network for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ))

    def _internal_network_result_section(self, alert: ExtractedAlert) -> str:
        rows: list[str] = []
        seen: set[tuple[str, str]] = set()
        values = (
            ("攻击IP", alert.attack_ip),
            ("目标/受害/目的IP", alert.target_ip),
            ("XFF", alert.xff),
            ("域名/URL中的IP", alert.domain_url),
        )
        for role, value in values:
            for ip in extract_ips(value or ""):
                if not self._is_internal_ip(ip) or (role, ip) in seen:
                    continue
                seen.add((role, ip))
                match = company_network_match(ip)
                if match:
                    rows.append(f"{role} {ip} -> {match.department}（{match.network}）")
                else:
                    rows.append(f"{role} {ip} -> 未匹配公司网段")
        return "【内网IP网段查询】\n" + ("\n".join(rows) if rows else "未发现内网IP")

    def _on_wire_api_changed(self, choice: str) -> None:
        code = WIRE_API_CODES.get(choice, "auto")
        if hasattr(self, "ai_wire_hint"):
            hint = {
                "auto": "按基址/模型智能判断",
                "chat": "Kimi、MiniMax、Qwen、SiliconFlow 等",
                "responses": "OpenAI / GPT-5.6 系列",
                "anthropic": "Claude / api.anthropic.com",
            }[code]
            self.ai_wire_hint.configure(text=hint)

    def _apply_ai_provider_preset(self, choice: str) -> None:
        base_url, model, wire = AI_PROVIDER_PRESETS.get(choice, AI_PROVIDER_PRESETS["自定义"])
        if choice == "自定义":
            return
        if hasattr(self, "ai_profile_name_var"):
            # Preset switches represent a new provider configuration. This
            # name change makes the subsequent save append instead of replace.
            self.ai_profile_name_var.set(choice)
        self.ai_base_var.set(base_url)
        self.ai_model_var.set(model)
        self.ai_wire_var.set(WIRE_API_LABELS[wire])
        self._on_wire_api_changed(self.ai_wire_var.get())

    def _refresh_ai_profile_combo(self) -> None:
        profiles = normalize_ai_profiles(self.settings)
        names = [p["name"] for p in profiles]
        if hasattr(self, "ai_profile_combo"):
            self.ai_profile_combo.configure(values=names)
            active = self.settings.get("ai_active_profile") or names[0]
            self.ai_profile_var.set(active)
        if hasattr(self, "ai_vision_combo"):
            self.ai_vision_combo.configure(values=names)
            vision = self.settings.get("ai_vision_profile") or names[0]
            if vision not in names:
                vision = names[0]
            self.ai_vision_var.set(vision)

    def _load_ai_profile_to_form(self, name: str | None = None) -> None:
        prof = get_ai_profile(self.settings, name)
        if hasattr(self, "ai_profile_name_var"):
            self.ai_profile_name_var.set(prof["name"])
        if hasattr(self, "ai_base_var"):
            self.ai_base_var.set(prof["base_url"])
            self.ai_key_var.set(prof["api_key"])  # Entry show='*' 自动脱敏显示
            self.ai_model_var.set(prof["model"])
            if hasattr(self, "ai_wire_var"):
                self.ai_wire_var.set(WIRE_API_LABELS.get(prof.get("wire_api", "auto"), WIRE_API_LABELS["auto"]))
                self._on_wire_api_changed(self.ai_wire_var.get())
        if hasattr(self, "ai_profile_var"):
            self.ai_profile_var.set(prof["name"])

    def _on_ai_profile_selected(self, choice: str) -> None:
        self.settings["ai_active_profile"] = choice
        normalize_ai_profiles(self.settings)
        self._load_ai_profile_to_form(choice)
        save_settings(self.settings)
        Toast(self, f"已切换 AI：{choice}", "ok")

    def _on_ai_vision_selected(self, choice: str) -> None:
        """Persist the dedicated image-analysis profile independently."""
        self.settings["ai_vision_profile"] = choice.strip()
        normalize_ai_profiles(self.settings)
        save_settings(self.settings)

    def _save_ai_profile(self, *, silent: bool = False) -> bool:
        name = self.ai_profile_name_var.get().strip() if hasattr(self, "ai_profile_name_var") else ""
        if not name:
            messagebox.showwarning("配置名称", "请填写配置名称")
            return False
        original = self.ai_profile_var.get().strip() if hasattr(self, "ai_profile_var") else None
        # Renaming creates a new saved profile; only an unchanged name updates
        # the selected profile instead of silently replacing another one.
        if original and original.casefold() != name.casefold():
            original = None
        if hasattr(self, "ai_vision_var"):
            self.settings["ai_vision_profile"] = self.ai_vision_var.get().strip()
        try:
            upsert_ai_profile(
                self.settings,
                name=name,
                base_url=self.ai_base_var.get().strip(),
                api_key=self.ai_key_var.get().strip(),
                model=self.ai_model_var.get().strip(),
                wire_api=WIRE_API_CODES.get(self.ai_wire_var.get(), "auto") if hasattr(self, "ai_wire_var") else "auto",
                activate=True,
                original_name=original,
            )
        except ValueError as exc:
            messagebox.showwarning("AI 配置", str(exc))
            return False
        save_settings(self.settings)
        self._refresh_ai_profile_combo()
        self._load_ai_profile_to_form(name)
        if not silent:
            Toast(self, f"已保存配置「{name}」", "ok")
        return True

    def _toggle_api_key_visibility(self) -> None:
        self.ai_key_visible = not bool(getattr(self, "ai_key_visible", False))
        self.ai_key_entry.configure(show="" if self.ai_key_visible else "*")
        self.ai_key_toggle.configure(text="隐藏" if self.ai_key_visible else "显示")

    def _delete_ai_profile(self) -> None:
        name = self.ai_profile_var.get().strip() if hasattr(self, "ai_profile_var") else ""
        if not name:
            return
        if not messagebox.askyesno("删除配置", f"确定删除 AI 配置「{name}」？"):
            return
        if not delete_ai_profile(self.settings, name):
            messagebox.showwarning("无法删除", "至少保留一组 AI 配置")
            return
        save_settings(self.settings)
        self._refresh_ai_profile_combo()
        self._load_ai_profile_to_form(self.settings.get("ai_active_profile"))
        Toast(self, f"已删除「{name}」", "ok")

    def _test_ai(self) -> None:
        try:
            self._sync_ai_settings_from_ui()
        except Exception as e:
            messagebox.showerror("配置同步失败", str(e))
            return
        cfg = AIConfig.from_settings(self.settings)
        if not cfg.api_key:
            messagebox.showwarning(
                "缺少 API Key",
                "请先在上方填写 API Key。测试连接会直接使用当前表单值。",
            )
            return
        Toast(self, f"正在测试 {cfg.model} …", "info", 2500)
        snap = {
            "ai_enabled": True,
            "ai_base_url": cfg.base_url,
            "ai_api_key": cfg.api_key,
            "ai_model": cfg.model,
            "ai_wire_api": cfg.wire_api,
            "ai_timeout": cfg.timeout,
            "ai_use_ocr": True,
            "ai_use_judge": True,
        }

        def worker() -> None:
            try:
                from .ai_client import AIClient, AIConfig as AC

                client = AIClient(AC.from_settings(snap))
                text = client.chat(
                    [{"role": "user", "content": "只回复两个字母：ok"}],
                    temperature=0,
                    max_tokens=32,
                )
                msg = (
                    f"连接成功\n\n"
                    f"基址：{cfg.base_url}\n"
                    f"模型：{cfg.model}\n"
                    f"返回：{text[:200]}"
                )
                self.after(0, lambda: messagebox.showinfo("AI 连接成功", msg))
            except Exception as e:
                err = str(e)
                self.after(0, lambda m=err: messagebox.showerror("AI 连接失败", m))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_extracted(self, alert: ExtractedAlert) -> bool:
        self._current_alert = alert
        is_local = any("本地" in note or "回落" in note for note in alert.notes)
        fallback_note = next((note for note in alert.notes if note.startswith("AI不可用已回落本地:")), "")
        detail_lines = [
            f"解析方式：{'本地规则' if is_local else '在线AI'}",
            f"来源文件：{alert.source_file or '输入区文本'}",
            "研判依据：根据原始告警字段、白名单匹配和历史工单记录生成；不包含模型隐藏推理过程。",
            f"攻击判断：{alert.attack_name or '未识别攻击名称'} / {alert.event_type or '未识别事件类型'}；结果={alert.attack_result or '失败'}；事件等级={alert.event_level or '五级'}。",
        ]
        if alert.notes:
            detail_lines.append("证据与解析记录：")
            detail_lines.extend(f"- {note}" for note in alert.notes if not note.startswith("AI_ADVICE::"))
        detail_lines.extend(f"内网部门归属：{line}" for line in company_attribution_lines(
            attack_ip=alert.attack_ip, target_ip=alert.target_ip,
            xff=alert.xff, domain_url=alert.domain_url,
        ))
        if fallback_note:
            self.after(50, lambda note=fallback_note: messagebox.showwarning(
                "AI 研判未完成", f"已改用本地规则解析。\n\n{note}"
            ))
        # Keep the model response untouched, then append a clearly separated
        # local department lookup. This evidence never enters the work order.
        raw_output = alert.ai_output.strip()[:20000]
        network_section = self._internal_network_result_section(alert)
        self._ai_raw_output = f"{raw_output}\n\n{network_section}".strip()
        self._analysis_notes = "\n".join(detail_lines)
        if self._template_schema:
            # The sample schema owns the form labels and order.  Read values
            # from the original material first; AI standard output remains in
            # the separate "原始结果" view for review.
            raw = self.input_box.get("1.0", "end") or alert.raw_text or alert.ai_output
            values = sample_fields_from_text(raw)
            values.update({key: value for key, value in alert.template_fields.items() if value})
            semantic_values = alert.to_dict()
            for label, semantic in self._template_bindings.items():
                if not values.get(label) and semantic_values.get(semantic):
                    values[label] = str(semantic_values[semantic])
                if semantic == "attack_result" and values.get(label):
                    values[label] = normalize_result(str(values[label]))
            for label in self._template_schema:
                if label in self._template_rows:
                    self._template_rows[label].set(values.get(label, ""))
            fallback = assemble_order(
                {**semantic_values, "source": semantic_values.get("source") or self.settings.get("default_source", "")},
                self.wl,
                auto_whitelist=True,
                auto_advice=True,
            )
            ai_advice = fallback.advice
            for label, semantic in self._template_bindings.items():
                if semantic == "advice" and label in self._template_rows:
                    self._template_rows[label].set(ai_advice)
            detail_lines.append("模板字段：按上传样本文本的字段名和顺序回填；未在原文出现的值保持空白。")
            self._analysis_notes = "\n".join(detail_lines)
            return True
        mapping = {
            "time": alert.time,
            "attack_ip": alert.attack_ip,
            "target_ip": alert.target_ip,
            "xff": alert.xff,
            "domain_url": alert.domain_url,
            "alert_level": alert.alert_level or "高危",
            "attack_name": alert.attack_name,
            "event_type": alert.event_type,
            "event_level": alert.event_level or self.settings.get("default_event_level", "五级"),
            "attack_result": alert.attack_result or "失败",
            "is_whitelist": alert.is_whitelist or "否",
        }
        # 全部回填，用户可再手改
        for k, v in mapping.items():
            if k in self.fields:
                self.fields[k].set(v or "")

        advice_order = assemble_order(
            {
                "attack_ip": alert.attack_ip,
                "target_ip": alert.target_ip,
                "xff": alert.xff,
                "domain_url": alert.domain_url,
                "attack_result": alert.attack_result,
            },
            self.wl,
            auto_whitelist=True,
            auto_advice=True,
        )
        ai_advice = advice_order.advice
        if ai_advice:
            self.fields["advice"].set(ai_advice)

        wl_decision = check_alert_whitelist_gate(
            self.wl, attack_ip=alert.attack_ip, target_ip=alert.target_ip,
            xff=alert.xff, domain_url=alert.domain_url,
        )
        if wl_decision.skip_order:
            detail = (
                "\n\n显式白名单：\n" + _whitelist_items_text(wl_decision.matched, reasons=True)
                + "\n\n半白名单：\n" + _whitelist_items_text(wl_decision.semi_matched, reasons=True)
            )
            messagebox.showinfo(
                "白名单可忽略~",
                "本次告警中攻击IP、目标/受害/目的IP、XFF及IOC域名/URL均已通过白名单判定。\n\n公司内网攻击IP按半白名单处理；本次未发现其它非白名单指标，免报且不生成工单。"
                + detail,
            )
            Toast(self, "白名单可忽略~", "wl", 2800)
            self._generated_output = ""
            self.result_view_seg.set("研判依据")
            self._show_result_view("研判依据")
            return False

        # 若无 AI 意见则用本地规则生成「建议」文案（仍不执行处置）
        order = assemble_order(
            {
                "source": self.fields["source"].get() or self.settings.get("default_source", "自定义监测平台"),
                "time": alert.time,
                "attack_ip": alert.attack_ip,
                "target_ip": alert.target_ip,
                "xff": alert.xff,
                "domain_url": alert.domain_url,
                "alert_level": alert.alert_level,
                "attack_name": alert.attack_name,
                "event_type": alert.event_type,
                "event_level": alert.event_level,
                "attack_result": alert.attack_result,
                "is_whitelist": alert.is_whitelist,
                "advice": ai_advice,
            },
            self.wl,
            auto_whitelist=True,
            auto_advice=not bool(ai_advice),
        )
        self.fields["is_whitelist"].set(order.is_whitelist)
        if not ai_advice:
            self.fields["advice"].set(order.advice)
        detail_lines.append(f"处置思路：{order.advice or '暂无明确处置对象，需人工补充。'}")
        detail_lines.extend(f"内网部门归属：{line}" for line in company_attribution_lines(
            attack_ip=order.attack_ip, target_ip=order.target_ip,
            xff=order.xff, domain_url=order.domain_url,
        ))
        detail_lines.append("白名单判断：攻击、目标/受害/目的、XFF及IOC域名/URL均须全部通过；公司内网仅在攻击IP角色下按半白名单处理。")
        self._analysis_notes = "\n".join(detail_lines)

        mode = "本地规则" if is_local else "在线AI"
        Toast(self, f"{mode}清洗完成，正在应用内置规则", "ok")
        self._check_history_and_hint(order)
        return True

    def _collect_fields(self) -> dict[str, Any]:
        if self._template_schema:
            custom = {
                label: self._template_rows[label].get()
                for label in self._template_schema
                if label in self._template_rows
            }
            data: dict[str, Any] = {"_custom_fields": custom}
            for label, semantic in self._template_bindings.items():
                if label in custom:
                    data[semantic] = custom[label]
            data["source"] = data.get("source") or self.settings.get("default_source", "")
            data["event_level"] = data.get("event_level") or self.settings.get("default_event_level", "五级")
            return data
        data = {k: row.get() for k, row in self.fields.items()}
        data["source"] = data.get("source") or self.settings.get("default_source", "自定义监测平台")
        return data

    def _check_all_whitelist_gate(self, fields: dict[str, Any], extra: str = "") -> bool:
        """Return True only when every involved IP role passes the exemption gate."""
        del extra
        result = check_alert_whitelist_gate(
            self.wl,
            attack_ip=fields.get("attack_ip", ""),
            target_ip=fields.get("target_ip", ""),
            xff=fields.get("xff", ""),
            domain_url=fields.get("domain_url", ""),
        )
        if result.skip_order:
            detail = (
                "\n\n显式白名单：\n" + _whitelist_items_text(result.matched, reasons=True)
                + "\n\n半白名单：\n" + _whitelist_items_text(result.semi_matched, reasons=True)
            )
            messagebox.showinfo(
                "白名单可忽略~",
                "本次告警中攻击IP、目标/受害/目的IP、XFF及IOC域名/URL均已通过白名单判定。\n\n公司内网攻击IP按半白名单处理；本次未发现其它非白名单指标，免报且不生成工单。"
                + detail,
            )
            Toast(self, "白名单可忽略~", "wl", 2800)
            return True
        return False

    def _check_history_and_hint(self, order: WorkOrder) -> list:
        hits = self.history.find_duplicates(
            attack_ips=extract_ips(order.attack_ip),
            target_ip=order.target_ip,
            attack_name=order.attack_name,
            xff=order.xff,
            domain_url=order.domain_url,
            event_type=order.event_type,
        )
        if hits:
            top = hits[0]
            Toast(
                self,
                f"历史已处置：{top.code}（{top.reason}）",
                "warn",
                3500,
            )
        return hits

    def _build_preview(self) -> None:
        fields = self._collect_fields()
        custom = fields.get("_custom_fields")
        if isinstance(custom, dict):
            if not any(str(value).strip() for value in custom.values()):
                messagebox.showwarning("字段不完整", "当前模板尚未从材料中提取到字段值，请检查样本文本格式或手工填写。")
                return
            extra = "\n".join(f"{key}：{value}" for key, value in custom.items())
            if self._check_all_whitelist_gate(fields, extra):
                self.preview_box.delete("1.0", "end")
                self._last_order = None
                self._generated_output = ""
                return
            alert = self._current_alert or ExtractedAlert()
            order = WorkOrder(
                number=str(fields.get("number") or ""),
                source=str(fields.get("source") or ""),
                time=str(fields.get("time") or alert.time),
                attack_ip=str(fields.get("attack_ip") or alert.attack_ip),
                target_ip=str(fields.get("target_ip") or alert.target_ip),
                xff=str(fields.get("xff") or alert.xff),
                domain_url=str(fields.get("domain_url") or alert.domain_url),
                attack_name=str(fields.get("attack_name") or alert.attack_name),
                event_type=str(fields.get("event_type") or alert.event_type),
                custom_fields={key: str(value) for key, value in custom.items()},
            )
            self._check_history_and_hint(order)
            self._last_order = order
            self._generated_output = order.to_markdown()
            self.result_view_seg.set("生成工单")
            self._show_result_view("生成工单")
            Toast(self, "已按当前模板生成工单", "ok", 1800)
            return
        if self._check_all_whitelist_gate(fields, self.input_box.get("1.0", "end")):
            self.preview_box.delete("1.0", "end")
            self._last_order = None
            self._generated_output = ""
            return
        if not fields.get("attack_ip") and not fields.get("attack_name"):
            messagebox.showwarning("字段不完整", "未能提取攻击IP或攻击名称，请补充材料后重试")
            return

        try:
            date_mmdd = validate_number_date(self.number_date_var.get())
            number, _used = resolve_number(self.settings, date_mmdd, self._manual_seq_raw() or None)
        except ValueError as e:
            messagebox.showwarning("编号", str(e))
            return

        fields["number"] = number
        # 预览保留用户/AI 已填的是否白名单与处置建议
        order = assemble_order(
            fields,
            self.wl,
            auto_whitelist=fields.get("is_whitelist") != "是",
            auto_advice=not bool(fields.get("advice")),
        )
        # 同步规范化后的空字段等，但不强行覆盖用户手改建议
        self.fields["alert_level"].set(order.alert_level)
        self.fields["attack_result"].set(order.attack_result)
        self.fields["event_level"].set(order.event_level)
        self.fields["is_whitelist"].set(order.is_whitelist)
        if not fields.get("advice"):
            self.fields["advice"].set(order.advice)
        self.fields["xff"].set(order.xff)
        self.fields["domain_url"].set(order.domain_url)

        self._check_history_and_hint(order)
        self._last_order = order
        md = order.to_markdown()
        self._generated_output = md
        self.result_view_seg.set("生成工单")
        self._show_result_view("生成工单")
        self.number_preview.configure(text=f"→ {number}")
        Toast(self, f"工单 {number} 已生成", "ok", 1800)

    # ── 配置操作 ──────────────────────────────────────
    def _history_sync_status_text(self) -> str:
        success = str(self.settings.get("history_last_success_at") or "")
        attempt = str(self.settings.get("history_last_sync_at") or "")
        error = str(self.settings.get("history_last_error") or "")
        if success:
            return f"上次成功同步：{success}" + (f"；最近失败：{error[:80]}" if error else "")
        if attempt:
            return f"上次同步尝试：{attempt}" + (f"；失败：{error[:100]}" if error else "")
        return "尚未执行在线同步"

    def _sync_history_settings_from_ui(self) -> bool:
        urls = normalize_sync_urls(self.history_sync_urls_var.get())
        enabled = bool(self.history_sync_enabled_var.get()) if hasattr(self, "history_sync_enabled_var") else False
        if enabled and not urls:
            messagebox.showwarning("告警跟踪同步", "请填写至少一个有效的 http/https 下载链接")
            return False
        try:
            interval = int(self.history_sync_interval_var.get().strip())
        except ValueError:
            messagebox.showwarning("告警跟踪同步", "同步间隔必须是 1 到 1440 之间的分钟数")
            return False
        if not 1 <= interval <= 1440:
            messagebox.showwarning("告警跟踪同步", "同步间隔必须是 1 到 1440 之间的分钟数")
            return False
        self.settings["history_sync_urls"] = urls
        self.settings["history_sync_enabled"] = enabled
        self.settings["history_sync_stale_alert_enabled"] = bool(self.history_stale_alert_var.get()) if hasattr(self, "history_stale_alert_var") else False
        self.settings["history_auto_sync_minutes"] = interval
        self.settings["history_sync_cookie"] = self.history_cookie_var.get().strip()
        self.history_sync_urls_var.set("\n".join(urls))
        return True

    def _add_history_sync_url(self) -> None:
        candidate = self.history_add_url_var.get().strip()
        if not candidate:
            return
        urls = normalize_sync_urls([*normalize_sync_urls(self.history_sync_urls_var.get()), candidate])
        if candidate not in urls:
            messagebox.showwarning("新增链接", "请输入有效的 http/https 链接")
            return
        self.history_sync_urls_var.set("\n".join(urls))
        self.history_add_url_var.set("")

    def _sync_history_now(self) -> None:
        if not self._sync_history_settings_from_ui():
            return
        save_settings(self.settings)
        self._start_history_sync(automatic=False)

    def _open_wps_login(self) -> None:
        url = normalize_sync_urls(self.history_sync_urls_var.get())
        webbrowser.open(url[0] if url else "https://www.kdocs.cn")

    def _clear_history_cookie(self) -> None:
        self.history_cookie_var.set("")
        self.settings["history_sync_cookie"] = ""
        save_settings(self.settings)
        Toast(self, "已清除 WPS 登录态", "ok")

    def _schedule_history_sync(self) -> None:
        if not bool(self.settings.get("history_sync_enabled", False)):
            return
        self._start_history_sync(automatic=True)

    def _start_history_sync(self, *, automatic: bool) -> None:
        urls = normalize_sync_urls(self.settings.get("history_sync_urls"))
        if not urls:
            return
        interval = max(1, min(1440, int(self.settings.get("history_auto_sync_minutes", 5))))
        if not automatic:
            Toast(self, "正在同步告警跟踪表", "info", 1800)

        def worker() -> None:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                results = sync_history_urls(
                    self.history, urls,
                    session_cookie=str(self.settings.get("history_sync_cookie") or ""),
                )
                error = ""
            except Exception as exc:
                results, error = [], str(exc)

            def finish() -> None:
                self.settings["history_last_sync_at"] = now
                if error:
                    self.settings["history_last_error"] = error
                    self._maybe_notify_stale_history_sync(error)
                    if not automatic:
                        messagebox.showerror("告警跟踪同步失败", error)
                else:
                    self.settings["history_last_success_at"] = now
                    self.settings["history_last_error"] = ""
                    self._history_sync_failure_alerted = False
                    added = sum(item.added for item in results)
                    updated = sum(item.updated for item in results)
                    Toast(self, f"告警跟踪已同步：新增 {added}，更新 {updated}", "ok", 2600)
                save_settings(self.settings)
                if hasattr(self, "history_sync_status"):
                    self.history_sync_status.configure(text=self._history_sync_status_text())
                if automatic:
                    delay = max(1, min(1440, int(self.settings.get("history_auto_sync_minutes", interval)))) * 60_000
                    self.after(delay, self._schedule_history_sync)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _maybe_notify_stale_history_sync(self, error: str) -> None:
        if not bool(self.settings.get("history_sync_enabled", False)) or not bool(self.settings.get("history_sync_stale_alert_enabled", False)):
            return
        if self._history_sync_failure_alerted:
            return
        raw = str(self.settings.get("history_last_success_at") or "")
        try:
            last_success = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S") if raw else self._history_sync_started_at
        except ValueError:
            last_success = self._history_sync_started_at
        if (datetime.now() - last_success).total_seconds() < 15 * 60:
            return
        self._history_sync_failure_alerted = True
        messagebox.showwarning("告警跟踪同步超时", f"已超过 15 分钟未成功同步告警跟踪。\n\n最近错误：{error}")

    def _pick_history_xlsx(self) -> None:
        path = filedialog.askopenfilename(
            title="告警跟踪统计表",
            filetypes=[("Excel", "*.xlsx;*.xlsm"), ("全部", "*.*")],
        )
        if path:
            self.history_var.set(path)

    def _pick_network_xlsx(self) -> None:
        path = filedialog.askopenfilename(
            title="选择白名单文件（增量合并）",
            filetypes=[("白名单文件", "*.xlsx;*.xlsm;*.txt;*.csv;*.tsv;*.json;*.html;*.htm"), ("全部", "*.*")],
        )
        if path:
            self.network_var.set(path)

    def _try_load_history_silent(self) -> None:
        path = self.settings.get("history_xlsx", "")
        if path and Path(path).exists():
            try:
                self.history.reload_from_xlsx(path)
            except Exception:
                pass

    def _reload_history(self) -> None:
        path = self.history_var.get().strip()
        if not path:
            messagebox.showwarning("历史表", "请先指定历史跟踪表路径")
            return
        try:
            n = self.history.reload_from_xlsx(path)
            self.settings["history_xlsx"] = path
            save_settings(self.settings)
            self.cfg_status.configure(text=f"已载入历史记录 {n} 条")
            Toast(self, f"历史 {n} 条已载入", "ok")
        except Exception as e:
            messagebox.showerror("载入失败", str(e))

    def _sync_network(self) -> None:
        path = self.network_var.get().strip()
        if not path:
            messagebox.showwarning("白名单文件", "请先指定白名单文件路径")
            return
        try:
            n = merge_rules_from_file(self.wl, path)
            self.settings["network_xlsx"] = path
            save_settings(self.settings)
            self._refresh_whitelist_list()
            self.cfg_status.configure(text=f"白名单文件增量新增 {n} 条规则")
            Toast(self, f"白名单新增 {n} 条", "ok")
        except Exception as e:
            messagebox.showerror("同步失败", str(e))

    def _import_whitelist_file(self) -> None:
        self._pick_network_xlsx()
        if self.network_var.get().strip():
            self._sync_network()

    def _switch_rule_manager(self, choice: str) -> None:
        self.whitelist_manager.pack_forget()
        self.company_manager.pack_forget()
        if choice == "公司网段":
            self.company_manager.pack(fill="both", expand=True)
            self._refresh_company_list()
        else:
            self.whitelist_manager.pack(fill="both", expand=True)
            self._refresh_whitelist_list()

    def _refresh_company_list(self) -> None:
        if not hasattr(self, "company_list"):
            return
        entries = self.company_store.all_entries()
        query = self.company_filter_var.get().strip().casefold()
        rows = [
            item for item in entries
            if not query or query in f"{item.get('rule', '')} {item.get('reason', '')}".casefold()
        ]
        self._company_visible_rules = [str(item.get("rule") or "") for item in rows]
        self._company_selected_rules.intersection_update(self._company_visible_rules)
        lines = [
            f"{'[x]' if str(item.get('rule') or '') in self._company_selected_rules else '[ ]'} [公司网段] {item.get('rule', '')}  -  {item.get('reason', '')}"
            for item in rows
        ]
        self.company_list.configure(state="normal")
        self.company_list.delete("1.0", "end")
        self.company_list.insert("1.0", "\n".join(lines) if lines else "（没有匹配的公司网段）")
        self.company_list.configure(state="disabled")
        suffix = f"，当前显示 {len(rows)} 条" if query else ""
        self.company_count.configure(
            text=_record_count_text(len(entries), len(rows) if query else None, f"，已选 {len(self._company_selected_rules)} 条（仅用于判断内网IP归属）")
        )

    def _toggle_company_row(self, event: tk.Event) -> str:
        try:
            line_no = int(self.company_list.index(f"@{event.x},{event.y}").split(".")[0])
            text = self.company_list.get(f"{line_no}.0", f"{line_no}.end")
            match = re.search(r"\[([ xX])\]\s+\[公司网段\]\s+([^\s]+)", text)
            if not match:
                return "break"
            rule = match.group(2)
            if rule in self._company_selected_rules:
                self._company_selected_rules.remove(rule)
            else:
                self._company_selected_rules.add(rule)
            self._refresh_company_list()
        except Exception:
            pass
        return "break"

    def _select_all_company_rows(self, selected: bool) -> None:
        if selected:
            self._company_selected_rules.update(self._company_visible_rules)
        else:
            self._company_selected_rules.difference_update(self._company_visible_rules)
        self._refresh_company_list()

    def _delete_selected_company_rows(self) -> None:
        selected = set(self._company_selected_rules)
        if not selected:
            messagebox.showinfo("删除公司网段", "请先勾选要删除的公司网段")
            return
        if not messagebox.askyesno("删除公司网段", f"确定删除已勾选的 {len(selected)} 条公司网段？"):
            return
        removed = self.company_store.remove_many(selected)
        self._company_selected_rules.clear()
        self._refresh_company_list()
        Toast(self, f"已删除 {removed} 条公司网段", "ok")

    def _import_company_network_file(self) -> None:
        path = filedialog.askopenfilename(
            title="导入公司网段",
            filetypes=[
                ("公司网段文件", "*.xlsx;*.xlsm;*.csv;*.tsv;*.txt;*.json"),
                ("全部文件", "*.*"),
            ],
        )
        if not path:
            return
        try:
            items = extract_company_rules_from_file(path)
            added = self.company_store.merge_rules(items)
            self._refresh_company_list()
            Toast(self, f"公司网段新增 {added} 条", "ok", 2200)
        except Exception as exc:
            messagebox.showerror("导入公司网段失败", str(exc))

    def _backup_company_json(self) -> None:
        path = filedialog.asksaveasfilename(
            title="备份公司网段 JSON", defaultextension=".json",
            initialfile=f"公司网段备份_{datetime.now():%Y%m%d_%H%M%S}.json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            self.company_store.export_json(Path(path))
            Toast(self, "公司网段 JSON 已备份", "ok")
        except Exception as exc:
            messagebox.showerror("备份公司网段失败", str(exc))

    def _restore_company_json(self) -> None:
        path = filedialog.askopenfilename(
            title="选择公司网段 JSON 备份", filetypes=[("JSON", "*.json"), ("全部文件", "*.*")],
        )
        if not path:
            return
        if not messagebox.askyesno("回滚公司网段", "将用该 JSON 覆盖当前项目的全部公司网段，是否继续？"):
            return
        try:
            count = self.company_store.restore_json(Path(path))
            self._refresh_company_list()
            Toast(self, f"已回滚 {count} 条公司网段", "ok", 2200)
        except Exception as exc:
            messagebox.showerror("回滚公司网段失败", str(exc))

    def _add_company_network(self) -> None:
        network = self.company_rule_var.get().strip()
        department = self.company_department_var.get().strip()
        if not network or not department:
            messagebox.showwarning("添加公司网段", "请同时填写内网 CIDR 和部门名称")
            return
        try:
            if not self.company_store.add(network, department):
                Toast(self, "该公司网段已存在", "info")
                return
            self.company_rule_var.set("")
            self.company_department_var.set("")
            self._refresh_company_list()
            Toast(self, "公司网段已添加", "ok")
        except Exception as exc:
            messagebox.showerror("添加公司网段失败", str(exc))

    def _delete_company_network(self) -> None:
        network = self.company_rule_var.get().strip()
        if not network:
            messagebox.showinfo("删除公司网段", "请在网段输入框填写要删除的 CIDR")
            return
        try:
            if not self.company_store.remove(network):
                messagebox.showwarning("删除公司网段", "没有找到该公司网段")
                return
            self.company_rule_var.set("")
            self._refresh_company_list()
            Toast(self, "公司网段已删除", "ok")
        except Exception as exc:
            messagebox.showerror("删除公司网段失败", str(exc))

    def _backup_whitelist_json(self) -> None:
        path = filedialog.asksaveasfilename(
            title="备份白名单 JSON",
            defaultextension=".json",
            initialfile=f"白名单备份_{datetime.now():%Y%m%d_%H%M%S}.json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            self.wl.export_json(Path(path))
            Toast(self, "白名单 JSON 已备份", "ok")
        except Exception as exc:
            messagebox.showerror("备份失败", str(exc))

    def _restore_whitelist_json(self) -> None:
        path = filedialog.askopenfilename(
            title="选择白名单 JSON 备份",
            filetypes=[("JSON", "*.json"), ("全部文件", "*.*")],
        )
        if not path:
            return
        if not messagebox.askyesno("从 JSON 回滚", "将用该 JSON 覆盖当前全部白名单规则，是否继续？"):
            return
        try:
            count = self.wl.restore_json(Path(path))
            self._refresh_whitelist_list()
            self.cfg_status.configure(text=f"已从 JSON 回滚 {count} 条白名单规则")
            Toast(self, f"已从 JSON 回滚 {count} 条规则", "ok", 2200)
        except Exception as exc:
            messagebox.showerror("JSON 回滚失败", str(exc))

    def _ai_import_whitelist(self) -> None:
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("AI提取白名单", "请先在工单输入区粘贴白名单说明或地址清单")
            return
        self._sync_ai_settings_from_ui()
        snapshot = dict(self.settings)
        def worker() -> None:
            try:
                from .ai_extract import ai_extract_whitelist_rules
                items = ai_extract_whitelist_rules(snapshot, text)
                added = self.wl.merge_rules(items)
                error = ""
            except Exception as exc:
                added, error = 0, str(exc)
            def finish() -> None:
                self._set_whitelist_progress(False)
                if error:
                    messagebox.showerror("AI提取白名单失败", error)
                    return
                self._refresh_whitelist_list()
                Toast(self, f"AI提取并新增 {added} 条白名单", "ok", 2200)
            self.after(0, finish)
        self._set_whitelist_progress(True)
        threading.Thread(target=worker, daemon=True).start()
        Toast(self, "正在让AI分析白名单候选", "info", 1800)

    def _refresh_whitelist_list(self) -> None:
        entries = self.wl.all_entries()
        query = self.wl_filter_var.get().strip().casefold() if hasattr(self, "wl_filter_var") else ""
        probe = query.strip()
        probe_result = None
        if probe:
            try:
                probe_result = self.wl.check(probe)
            except Exception:
                probe_result = None
        rows: list[dict[str, Any]] = []
        for e in entries:
            source = str(e.get("source", "") or "")
            tag = source or "规则"
            line = f"[{tag}] {e.get('rule', '')}  -  {e.get('reason', '')}"
            rule = str(e.get("rule") or "").strip()
            text_match = not query or query in line.casefold()
            ip_match = bool(probe_result and probe_result.matched and rule == probe_result.rule)
            if text_match or ip_match:
                rows.append(e)
        self._whitelist_visible_rules = [str(e.get("rule") or "") for e in rows]
        self._whitelist_selected_rules.intersection_update(self._whitelist_visible_rules)
        lines = []
        for e in rows:
            rule = str(e.get("rule") or "")
            mark = "[x]" if rule in self._whitelist_selected_rules else "[ ]"
            source = str(e.get("source", "") or "")
            lines.append(f"{mark} [{source or '规则'}] {rule}  -  {e.get('reason', '')}")
        if probe_result and probe_result.matched:
            lines.insert(0, f"命中：{probe} -> {probe_result.rule}（{probe_result.reason or '白名单'}）")
        self.wl_list.configure(state="normal")
        self.wl_list.delete("1.0", "end")
        self.wl_list.insert("1.0", "\n".join(lines) if lines else "（没有匹配的规则）")
        self.wl_list.configure(state="disabled")
        self.wl_count.configure(text=_record_count_text(len(entries), len(rows) if query else None) + f"，已选 {len(self._whitelist_selected_rules)} 条")

    def _toggle_whitelist_row(self, event: tk.Event) -> str:
        try:
            line_no = int(self.wl_list.index(f"@{event.x},{event.y}").split(".")[0])
            text = self.wl_list.get(f"{line_no}.0", f"{line_no}.end")
            match = re.search(r"\[([ xX])\]\s+\[[^]]+\]\s+([^\s]+)", text)
            if not match:
                return "break"
            rule = match.group(2)
            if rule in self._whitelist_selected_rules:
                self._whitelist_selected_rules.remove(rule)
            else:
                self._whitelist_selected_rules.add(rule)
            self._refresh_whitelist_list()
        except Exception:
            pass
        return "break"

    def _select_all_whitelist_rows(self, selected: bool) -> None:
        if selected:
            self._whitelist_selected_rules.update(self._whitelist_visible_rules)
        else:
            self._whitelist_selected_rules.difference_update(self._whitelist_visible_rules)
        self._refresh_whitelist_list()

    def _delete_selected_whitelist_rows(self) -> None:
        selected = set(self._whitelist_selected_rules)
        if not selected:
            messagebox.showinfo("删除白名单规则", "请先勾选要删除的规则")
            return
        if not messagebox.askyesno("删除白名单规则", f"确定删除已勾选的 {len(selected)} 条规则？"):
            return
        entries = [e for e in self.wl.all_entries() if str(e.get("rule") or "") not in selected]
        self.wl.save(rules=entries)
        self._whitelist_selected_rules.clear()
        self._refresh_whitelist_list()
        Toast(self, f"已删除 {len(selected)} 条白名单规则", "ok")

    def _add_whitelist(self) -> None:
        rule = self.wl_rule_var.get().strip()
        reason = self.wl_reason_var.get().strip() or "手动添加"
        if not rule:
            return
        try:
            tokens = [part.strip() for part in re.split(r"[,，;；\n]+", rule) if part.strip()]
            added = self.wl.merge_rules([
                {"rule": token, "reason": reason, "source": "手动"} for token in tokens
            ], manual=True)
            if not added:
                Toast(self, "输入规则均已存在", "info")
                return
            self.wl_rule_var.set("")
            self._refresh_whitelist_list()
            Toast(self, f"已添加 {added} 条规则", "ok")
        except Exception as e:
            messagebox.showerror("添加失败", str(e))

    def _del_whitelist(self) -> None:
        rule = self.wl_rule_var.get().strip()
        if not rule:
            messagebox.showinfo("删除规则", "请在规则输入框填写要删除的手动规则")
            return
        removed = self.wl.remove_rule(rule)
        if not removed:
            messagebox.showwarning("删除规则", "没有找到这条白名单规则")
            return
        self.wl_rule_var.set("")
        self._refresh_whitelist_list()
        Toast(self, f"已删除手动规则 {rule}", "ok")

    def _restore_original_whitelist(self) -> None:
        if not messagebox.askyesno(
            "恢复原始白名单",
            "将删除当前全部白名单规则，并从发布包中的白名单 JSON 基线恢复。\n\n确定继续吗？",
        ):
            return
        if not messagebox.askyesno(
            "再次确认",
            "恢复后当前白名单的个性化修改无法自动找回。确定恢复原始白名单？",
        ):
            return
        try:
            count = self.wl.restore_original()
        except Exception as exc:
            messagebox.showerror("恢复原始白名单失败", str(exc))
            return
        self._refresh_whitelist_list()
        self.cfg_status.configure(text=f"已恢复原始白名单 {count} 条规则")
        Toast(self, f"已恢复原始白名单 {count} 条", "ok", 2600)

    def _save_config(self, *, sync_project: bool = True) -> bool:
        if not self._save_ai_profile(silent=True):
            return False
        self._sync_ai_settings_from_ui()
        self._sync_threatbook_settings_from_ui()
        self.settings["theme"] = self._theme
        self.settings["history_xlsx"] = self.history_var.get().strip()
        if not self._sync_history_settings_from_ui():
            return False
        self.settings["network_xlsx"] = self.network_var.get().strip()
        self.settings["default_source"] = self.default_source_var.get()
        self.settings["default_event_level"] = self.default_level_var.get()
        self._capture_window_placement()
        self.settings["close_to_tray"] = bool(self.close_to_tray_var.get())
        self.settings["tray_enabled"] = bool(self.tray_enabled_var.get())
        if hasattr(self, "batch_skip_hist_var"):
            self.settings["batch_skip_history"] = bool(self.batch_skip_hist_var.get())
        self.settings["analysis_mode"] = self._analysis_mode_code()
        self.settings["window_opacity"] = self._window_opacity
        try:
            self._sync_branding_from_ui()
        except ValueError as exc:
            messagebox.showwarning("外观配置", str(exc))
            return False
        self._apply_logo(self.settings.get("logo_path") or "")
        self._apply_brand_text(self.settings)
        selected_project = ""
        if sync_project and hasattr(self, "project_profile_var"):
            candidate = self.project_profile_var.get().strip()
            if candidate and not candidate.startswith("（"):
                selected_project = candidate
                self.settings["active_project_profile"] = candidate
        save_settings(self.settings)
        # 保存后立即同步到工单页和批量上下文。
        if not self._template_schema:
            self.fields["source"].set(self.settings["default_source"])
            self.fields["event_level"].set(self.settings["default_event_level"])
        self._update_batch_context()
        # 托盘开关即时生效
        if self.settings["tray_enabled"]:
            self._setup_tray()
        elif self._tray:
            self._tray.stop()
            self._tray = None
        status = "配置已保存"
        self.cfg_status.configure(text=status)
        Toast(self, status, "ok")
        return True

    def _refresh_project_profiles(self, selected: str = "") -> None:
        names = list_project_profiles()
        self.project_profile_combo.configure(values=names or ["（暂无项目配置）"])
        self.project_profile_var.set(selected if selected in names else (names[0] if names else ""))

    def _restart_after_project_change(self) -> None:
        if getattr(sys, "frozen", False):
            command = [sys.executable]
        else:
            command = [sys.executable, str(APP_ROOT / "main.py")]
        subprocess.Popen(command, cwd=str(APP_ROOT), env=_restart_environment())
        self._really_quit = True
        self._quit_app()

    def _load_profile_and_restart(self, name_or_path: str) -> None:
        try:
            result = load_project_profile(name_or_path)
        except Exception as exc:
            messagebox.showerror("加载项目配置失败", str(exc))
            return
        messagebox.showinfo("项目配置已恢复", f"已加载“{result['name']}”，工具将自动重启并应用全部配置。")
        self._restart_after_project_change()

    def _load_selected_project_profile(self) -> None:
        name = self.project_profile_var.get().strip()
        if not name or name.startswith("（"):
            messagebox.showwarning("项目配置", "请先选择一个项目配置")
            return
        if messagebox.askyesno("加载项目配置", f"将用“{name}”覆盖当前设置、模板和白名单，是否继续？"):
            self._load_profile_and_restart(name)

    def _load_project_profile_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择项目配置文件", filetypes=[("项目配置", "*.json"), ("全部文件", "*.*")]
        )
        if path and messagebox.askyesno("导入项目配置", "将覆盖当前设置、模板和白名单，是否继续？"):
            self._load_profile_and_restart(path)

    def _save_current_project_profile(self) -> None:
        name = simpledialog.askstring(
            "保存项目配置", "配置名称（例如：2027某项目HVV）", parent=self,
            initialvalue=self.project_profile_var.get().strip(),
        )
        if not name:
            return
        try:
            if not self._save_config(sync_project=False):
                return
            include = self._project_bundle_options()
            if include is None:
                return
            path = save_project_profile(name.strip(), self.settings, **include)
            self.settings["active_project_profile"] = name.strip()
            save_settings(self.settings)
            self._refresh_project_profiles(name.strip())
            messagebox.showinfo("项目配置已保存", f"已保存：{path}")
        except Exception as exc:
            messagebox.showerror("保存项目配置失败", str(exc))

    def _project_bundle_options(self) -> dict[str, bool] | None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("另存当前配置包")
        dialog.geometry("560x390")
        dialog.transient(self)
        result: dict[str, bool] | None = None
        ctk.CTkLabel(dialog, text="选择要写入配置 JSON 的数据", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(18, 8))
        ctk.CTkLabel(dialog, text="勾选的内容会随 JSON 移动到其它设备；API Key 属于敏感信息，请确认文件存储和传输风险。", wraplength=510, justify="left").pack(anchor="w", padx=20, pady=(0, 12))
        vars_map = {
            "include_ai_key": ctk.BooleanVar(value=False),
            "include_threatbook_key": ctk.BooleanVar(value=False),
            "include_whitelist": ctk.BooleanVar(value=True),
            "include_company_networks": ctk.BooleanVar(value=True),
        }
        labels = [("include_ai_key", "AI API Key"), ("include_threatbook_key", "微步 API Key"), ("include_whitelist", "白名单规则"), ("include_company_networks", "公司网段信息")]
        for key, label in labels:
            ctk.CTkCheckBox(dialog, text=label, variable=vars_map[key]).pack(anchor="w", padx=28, pady=5)
        ctk.CTkLabel(dialog, text="历史工单缓存、模板和其它普通配置会自动随项目包保存。", text_color=self._colors()["text_dim"]).pack(anchor="w", padx=28, pady=(8, 5))
        buttons = ctk.CTkFrame(dialog, fg_color="transparent"); buttons.pack(fill="x", padx=20, pady=18)
        def accept() -> None:
            nonlocal result
            result = {key: bool(var.get()) for key, var in vars_map.items()}
            result["include_history"] = True
            dialog.destroy()
        ctk.CTkButton(buttons, text="取消", fg_color="#596579", command=dialog.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(buttons, text="确认另存", command=accept).pack(side="right")
        dialog.grab_set(); self.wait_window(dialog)
        return result

    def _restore_blank_profile(self) -> None:
        if not messagebox.askyesno("恢复白板", "将清空外观、API Key、文件路径、模板、历史、白名单和公司网段等全部运行配置。项目 JSON 文件本身不会删除。是否继续？", parent=self):
            return
        if not messagebox.askyesno("再次确认恢复白板", "此操作会清除全部本机运行配置，且当前未另存的数据无法自动恢复。确定继续？", parent=self):
            return
        try:
            restore_blank_workspace()
        except Exception as exc:
            messagebox.showerror("恢复白板失败", str(exc))
            return
        messagebox.showinfo("已恢复白板", "工具将自动重启。")
        self._restart_after_project_change()

    def _on_close(self) -> None:
        self._persist_settings_light()
        close_to_tray = bool(self.settings.get("close_to_tray", True)) and bool(
            self.settings.get("tray_enabled", True)
        )
        if not self._really_quit and close_to_tray:
            if not self._tray or not self._tray.running:
                self._setup_tray()
            if self._tray and self._tray.running:
                self.withdraw()
                try:
                    self._tray.notify("研判工单工具", "仍在托盘运行，右键可退出")
                except Exception:
                    pass
                return
        self._quit_app()
