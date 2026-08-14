# -*- coding: utf-8 -*-
"""Windows 文件拖放（兼容 CustomTkinter，避免 windnd 闪退）
Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import ctypes
import queue
import sys
from ctypes import wintypes
from typing import Callable

# --- Win32 ---
user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32

WM_DROPFILES = 0x0233
GWL_WNDPROC = -4
GA_ROOT = 2

if ctypes.sizeof(ctypes.c_void_p) == 8:
    LRESULT = ctypes.c_longlong
    LONG_PTR = ctypes.c_longlong
    GetWindowLongPtr = user32.GetWindowLongPtrW
    SetWindowLongPtr = user32.SetWindowLongPtrW
else:
    LRESULT = ctypes.c_long
    LONG_PTR = ctypes.c_long
    GetWindowLongPtr = user32.GetWindowLongW
    SetWindowLongPtr = user32.SetWindowLongW

GetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int]
GetWindowLongPtr.restype = LONG_PTR
SetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
SetWindowLongPtr.restype = LONG_PTR

WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)

shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
shell32.DragQueryFileW.argtypes = [
    wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT
]
shell32.DragQueryFileW.restype = wintypes.UINT
shell32.DragFinish.argtypes = [wintypes.HANDLE]

user32.CallWindowProcW.argtypes = [
    LONG_PTR, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
]
user32.CallWindowProcW.restype = LRESULT
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND


def _resolve_hwnd(widget) -> int:
    """拿到真正顶层窗口 HWND（CTk 的 winfo_id 往往是子控件）。"""
    widget.update_idletasks()
    hwnd = int(widget.winfo_id())
    root = user32.GetAncestor(hwnd, GA_ROOT)
    return int(root or hwnd)


class FileDropTarget:
    """
    在顶层窗口挂接 WM_DROPFILES。
    回调只在 Tk 主线程通过 queue + after 触发，窗口过程里绝不碰 UI。
    """

    def __init__(self, widget, on_files: Callable[[list[str]], None]) -> None:
        self.widget = widget
        self.on_files = on_files
        self._queue: queue.Queue[list[str]] = queue.Queue()
        self._old_proc: int | None = None
        self._new_proc = None  # keep ref
        self._hwnd: int | None = None
        self._poll_id = None
        self._alive = True

    def install(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            hwnd = _resolve_hwnd(self.widget)
            self._hwnd = hwnd

            def py_wnd_proc(h, msg, wp, lp):
                try:
                    if msg == WM_DROPFILES:
                        paths = self._extract_paths(int(wp))
                        shell32.DragFinish(wintypes.HANDLE(wp))
                        if paths:
                            self._queue.put(paths)
                        return LRESULT(0)
                except Exception:
                    try:
                        shell32.DragFinish(wintypes.HANDLE(wp))
                    except Exception:
                        pass
                    return LRESULT(0)
                # 转发给原窗口过程
                try:
                    return user32.CallWindowProcW(
                        LONG_PTR(self._old_proc or 0), h, msg, wp, lp
                    )
                except Exception:
                    return LRESULT(0)

            self._new_proc = WNDPROC(py_wnd_proc)
            shell32.DragAcceptFiles(wintypes.HWND(hwnd), True)
            self._old_proc = int(GetWindowLongPtr(wintypes.HWND(hwnd), GWL_WNDPROC) or 0)
            proc_addr = ctypes.cast(self._new_proc, ctypes.c_void_p).value
            SetWindowLongPtr(wintypes.HWND(hwnd), GWL_WNDPROC, LONG_PTR(proc_addr or 0))
            # 定时从队列取路径，保证在 Tk 主线程处理
            self._poll()
            return True
        except Exception:
            return False

    @staticmethod
    def _extract_paths(hdrop: int) -> list[str]:
        count = shell32.DragQueryFileW(wintypes.HANDLE(hdrop), 0xFFFFFFFF, None, 0)
        out: list[str] = []
        buf = ctypes.create_unicode_buffer(32768)
        for i in range(int(count)):
            n = shell32.DragQueryFileW(
                wintypes.HANDLE(hdrop), i, buf, ctypes.sizeof(buf) // 2
            )
            if n:
                out.append(buf.value)
        return out

    def _poll(self) -> None:
        if not self._alive:
            return
        try:
            while True:
                paths = self._queue.get_nowait()
                try:
                    self.on_files(paths)
                except Exception:
                    pass
        except queue.Empty:
            pass
        try:
            self._poll_id = self.widget.after(80, self._poll)
        except Exception:
            self._alive = False

    def uninstall(self) -> None:
        self._alive = False
        if self._poll_id is not None:
            try:
                self.widget.after_cancel(self._poll_id)
            except Exception:
                pass
        if self._hwnd is not None and self._old_proc is not None:
            try:
                SetWindowLongPtr(
                    wintypes.HWND(self._hwnd), GWL_WNDPROC, LONG_PTR(self._old_proc)
                )
            except Exception:
                pass
        self._hwnd = None
        self._old_proc = None
        self._new_proc = None
