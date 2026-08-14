"""Windows DPAPI protection for API keys stored in local settings."""

from __future__ import annotations

import base64
import ctypes
import sys
from ctypes import wintypes


_PREFIX = "dpapi:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _input_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _crypt(data: bytes, *, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise OSError("DPAPI 仅在 Windows 可用")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    source, source_buffer = _input_blob(data)
    target = _DataBlob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), None, None, None, None, flags, ctypes.byref(target)
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), None, None, None, None, flags, ctypes.byref(target)
        )
    if not ok:
        raise ctypes.WinError()
    del source_buffer
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def protect_secret(value: str) -> str:
    raw = str(value or "")
    if not raw or raw.startswith(_PREFIX):
        return raw
    encrypted = _crypt(raw.encode("utf-8"), protect=True)
    return _PREFIX + base64.b64encode(encrypted).decode("ascii")


def unprotect_secret(value: str) -> str:
    raw = str(value or "")
    if not raw or not raw.startswith(_PREFIX):
        return raw
    try:
        payload = base64.b64decode(raw[len(_PREFIX) :], validate=True)
        return _crypt(payload, protect=False).decode("utf-8")
    except Exception:
        return ""
