# -*- coding: utf-8 -*-
"""系统托盘常驻（pystray）。
Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import threading
from typing import Callable

from PIL import Image, ImageDraw


def build_tray_image(size: int = 64) -> Image.Image:
    """生成简易盾牌图标。"""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # 外圈
    draw.ellipse((4, 4, size - 5, size - 5), fill=(45, 90, 180, 255))
    draw.ellipse((12, 12, size - 13, size - 13), fill=(36, 50, 78, 255))
    # 盾牌形近似：圆角矩形 + 三角底
    margin = size // 5
    top = margin
    left = margin + 2
    right = size - margin - 2
    mid_y = size // 2 + 2
    bottom = size - margin + 2
    draw.polygon(
        [
            (left, top + 4),
            (right, top + 4),
            (right, mid_y),
            (size // 2, bottom),
            (left, mid_y),
        ],
        fill=(91, 141, 239, 255),
    )
    draw.polygon(
        [
            (left + 6, top + 10),
            (right - 6, top + 10),
            (right - 6, mid_y - 2),
            (size // 2, bottom - 10),
            (left + 6, mid_y - 2),
        ],
        fill=(62, 207, 142, 255),
    )
    return img


class TrayController:
    """在后台线程运行 pystray，通过回调操作主窗口。"""

    def __init__(
        self,
        *,
        on_show: Callable[[], None],
        on_quit: Callable[[], None],
        title: str = "研判工单自动生成工具",
    ) -> None:
        self.on_show = on_show
        self.on_quit = on_quit
        self.title = title
        self._icon = None
        self._thread: threading.Thread | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running and self._icon is not None

    def start(self) -> bool:
        if self._running:
            return True
        try:
            import pystray
            from pystray import MenuItem as item
        except ImportError:
            return False

        def show(_icon=None, _item=None) -> None:
            self.on_show()

        def quit_app(_icon=None, _item=None) -> None:
            self.stop()
            self.on_quit()

        menu = pystray.Menu(
            item("显示主窗口", show, default=True),
            item("退出", quit_app),
        )
        self._icon = pystray.Icon(
            "work_order_app",
            build_tray_image(),
            self.title,
            menu,
        )
        self._running = True

        def runner() -> None:
            try:
                self._icon.run()
            finally:
                self._running = False

        self._thread = threading.Thread(target=runner, name="tray-icon", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        icon = self._icon
        self._icon = None
        self._running = False
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass

    def notify(self, title: str, message: str) -> None:
        if not self._icon:
            return
        try:
            self._icon.notify(message, title)
        except Exception:
            pass
