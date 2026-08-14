# -*- coding: utf-8 -*-
"""外观品牌：自定义 Logo 加载。
Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image


def load_logo_ctk(path: str | Path, size: tuple[int, int] = (40, 40)):
    """加载为 CTkImage；失败返回 None。"""
    path = Path(path or "")
    if not path.exists():
        return None
    try:
        import customtkinter as ctk

        img = Image.open(path)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA")
        img = img.copy()
        img.thumbnail(size, Image.Resampling.LANCZOS)
        # 居中画到固定画布
        canvas = Image.new("RGBA", size, (0, 0, 0, 0))
        ox = (size[0] - img.width) // 2
        oy = (size[1] - img.height) // 2
        canvas.paste(img, (ox, oy), img if img.mode == "RGBA" else None)
        return ctk.CTkImage(light_image=canvas, dark_image=canvas, size=size)
    except Exception:
        return None

