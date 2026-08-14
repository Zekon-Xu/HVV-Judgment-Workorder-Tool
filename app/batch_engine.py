# -*- coding: utf-8 -*-
"""批量告警：提取 → 白名单拦截 → 历史去重 → 连续编号生成。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .ai_extract import pull_ai_advice, smart_extract
from .extractor import ExtractedAlert
from .history import HistoryStore
from .order_builder import assemble_order
from .settings_store import (
    commit_number,
    resolve_number,
    validate_number_date,
    validate_number_seq,
)
from .template_store import load_template
from .whitelist import WhitelistEngine, check_alert_whitelist_gate, extract_ips

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}
SUPPORTED_EXTS = IMAGE_EXTS | {
    ".html", ".htm", ".mhtml", ".mht", ".txt", ".md", ".log",
    ".csv", ".tsv", ".json", ".xml",
}


@dataclass
class BatchJob:
    """队列中的一条待处理告警。"""

    uid: str
    label: str
    path: str = ""
    text: str = ""
    status: str = "pending"  # pending / done / skip_wl / skip_history / error
    message: str = ""
    number: str = ""
    order_md: str = ""
    selected: bool = True


@dataclass
class BatchResult:
    jobs: list[BatchJob] = field(default_factory=list)
    written: int = 0
    skipped_wl: int = 0
    skipped_history: int = 0
    errors: int = 0


ProgressCb = Callable[[str, BatchJob | None], None]


def split_text_into_alerts(text: str) -> list[str]:
    """将长文本拆成多条告警片段。"""
    text = (text or "").strip()
    if not text:
        return []

    if text.count("编号：") >= 2 or text.count("编号:") >= 2:
        parts = re.split(r"(?=编号\s*[：:])", text)
        chunks = [p.strip() for p in parts if p.strip() and ("攻击" in p or "IP" in p or "ip" in p)]
        if len(chunks) >= 2:
            return chunks

    # 按双空行拆；每段需含 IP 或攻击关键词
    raw_parts = re.split(r"\n\s*\n+", text)
    if len(raw_parts) >= 2:
        chunks = []
        for p in raw_parts:
            p = p.strip()
            if not p:
                continue
            if extract_ips(p) or re.search(r"攻击|告警|源IP|目的IP|暴力|注入|扫描", p):
                chunks.append(p)
        if len(chunks) >= 2:
            return chunks

    return [text]


def jobs_from_paths(paths: list[str]) -> list[BatchJob]:
    jobs: list[BatchJob] = []
    seen: set[str] = set()
    for i, raw in enumerate(paths):
        path = str(raw).strip().strip('"')
        if not path:
            continue
        p = Path(path)
        if not p.exists() or not p.is_file():
            jobs.append(BatchJob(
                uid=f"bad-{i}-{path}",
                label=p.name or path,
                path=path,
                status="error",
                message="文件不存在",
                selected=False,
            ))
            continue
        resolved = str(p.resolve())
        if resolved.casefold() in seen:
            continue
        seen.add(resolved.casefold())
        if p.suffix.lower() not in SUPPORTED_EXTS:
            jobs.append(BatchJob(
                uid=f"skip-{i}-{p.name}",
                label=p.name,
                path=str(p),
                status="error",
                message=f"不支持的类型: {p.suffix}",
                selected=False,
            ))
            continue
        jobs.append(BatchJob(
            uid=f"file-{i}-{resolved}",
            label=p.name,
            path=resolved,
        ))
    return jobs


def jobs_from_text_blob(text: str) -> list[BatchJob]:
    chunks = split_text_into_alerts(text)
    jobs: list[BatchJob] = []
    for i, chunk in enumerate(chunks):
        preview = re.sub(r"\s+", " ", chunk)[:48]
        jobs.append(BatchJob(
            uid=f"text-{i}-{hash(chunk) & 0xFFFF:x}",
            label=f"文本片段#{i + 1} {preview}",
            text=chunk,
        ))
    return jobs


def _extract_job(
    job: BatchJob,
    settings: dict[str, Any],
    template: dict[str, Any] | None = None,
    analysis_mode: str | None = None,
) -> ExtractedAlert:
    return smart_extract(
        settings=settings,
        text=job.text or "",
        path=job.path if job.path else None,
        template=template,
        require_ai=False,
        analysis_mode=analysis_mode,
    )


def process_batch(
    jobs: list[BatchJob],
    *,
    wl: WhitelistEngine,
    history: HistoryStore,
    settings: dict[str, Any],
    source: str,
    event_level: str,
    date_mmdd: str,
    skip_history: bool = True,
    start_seq: str | int | None = None,
    template_name: str | None = None,
    analysis_mode: str | None = None,
    progress: ProgressCb | None = None,
) -> BatchResult:
    """
    对选中的 pending 任务依次生成可复制的工单，不写入文件。
    skip_history=True 时历史命中自动跳过（不弹窗）。
    start_seq 可指定首条序号（如 13 / "013"），之后自动 +1。
    """
    date_mmdd = validate_number_date(date_mmdd)
    result = BatchResult(jobs=jobs)
    # 下一条将使用的序号；None 表示走 settings 自动
    next_manual: int | None = validate_number_seq(start_seq)

    def emit(msg: str, job: BatchJob | None = None) -> None:
        if progress:
            progress(msg, job)

    # Retry pending/error jobs only. Completed and deliberately skipped jobs
    # are terminal so a second click cannot duplicate output.
    for j in jobs:
        if not j.selected:
            continue
        if j.status != "error" or j.message == "文件不存在":
            continue
        j.status = "pending"
        j.message = ""
        j.number = ""
        j.order_md = ""

    work_list = [j for j in jobs if j.selected and j.status == "pending"]
    template = load_template(template_name or settings.get("active_template") or None)
    emit(f"开始批量处理 {len(work_list)} 条…（模板：{template.get('name', '')}）", None)

    for idx, job in enumerate(work_list, 1):
        emit(f"[{idx}/{len(work_list)}] 提取 {job.label}", None)
        try:
            alert = _extract_job(job, settings, template, analysis_mode)
        except Exception as e:
            job.status = "error"
            job.message = f"提取失败: {e}"
            result.errors += 1
            emit(job.message, job)
            continue

        wl_decision = check_alert_whitelist_gate(
            wl, attack_ip=alert.attack_ip, target_ip=alert.target_ip,
            xff=alert.xff, domain_url=alert.domain_url,
        )
        if wl_decision.skip_order:
            job.status = "skip_wl"
            job.message = "所有攻击、目标、XFF及IOC指标均为白名单，免报"
            result.skipped_wl += 1
            emit(f"跳过（白名单）{job.label}", job)
            continue

        if not alert.attack_ip and not alert.attack_name:
            job.status = "error"
            job.message = "未能识别攻击IP/攻击名称"
            result.errors += 1
            emit(f"失败 {job.label}: {job.message}", job)
            continue

        fields = {
            "source": source,
            "time": alert.time,
            "attack_ip": alert.attack_ip,
            "target_ip": alert.target_ip,
            "xff": alert.xff,
            "domain_url": alert.domain_url,
            "alert_level": alert.alert_level,
            "attack_name": alert.attack_name,
            "event_type": alert.event_type,
            "event_level": event_level or alert.event_level or "五级",
            "attack_result": alert.attack_result,
            "advice": pull_ai_advice(alert),
        }
        probe = assemble_order(fields, wl, auto_advice=not bool(fields.get("advice")))
        hits = history.find_duplicates(
            attack_ips=extract_ips(probe.attack_ip),
            target_ip=probe.target_ip,
            attack_name=probe.attack_name,
            xff=probe.xff,
            domain_url=probe.domain_url,
            event_type=probe.event_type,
        )
        if hits and skip_history:
            top = hits[0]
            job.status = "skip_history"
            job.message = f"历史已处置 {top.code}：{top.reason}"
            result.skipped_history += 1
            emit(f"跳过（历史）{job.label} → {top.code}", job)
            continue

        try:
            number, used_seq = resolve_number(settings, date_mmdd, next_manual)
            fields["number"] = number
            order = assemble_order(fields, wl)
            commit_number(settings, date_mmdd, used_seq=used_seq)
            # 下一条从 used+1 起，即使首条是手动指定
            next_manual = used_seq + 1
            job.status = "done"
            job.number = number
            job.order_md = order.to_markdown()
            job.message = f"已生成 {number}"
            result.written += 1
            emit(job.message, job)
        except Exception as e:
            job.status = "error"
            job.message = f"生成失败: {e}"
            result.errors += 1
            emit(job.message, job)

    emit(
        f"完成：生成 {result.written} · 白名单跳过 {result.skipped_wl} · "
        f"历史跳过 {result.skipped_history} · 失败 {result.errors}"
    )
    return result
