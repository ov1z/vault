"""Clipboard access with leak mitigation.

On Windows:
  * copied secrets are excluded from Clipboard History (Win+V) and from
    Cloud Clipboard sync, and from clipboard monitors;
  * the clipboard auto-clears after a delay, but only if it still holds the
    value we set (never clobbers something the user copied afterwards).
On macOS/Linux: copies via pbcopy / wl-copy / xclip / xsel (no history API).
"""

from __future__ import annotations

import subprocess
import sys
import threading

AUTO_CLEAR_SECONDS = 30

# ---------------------------------------------------------------- Windows ----
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def _win_alloc(data: bytes):
    import ctypes
    from ctypes import wintypes

    k = ctypes.windll.kernel32
    k.GlobalAlloc.restype = wintypes.HGLOBAL
    k.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    k.GlobalLock.restype = wintypes.LPVOID
    k.GlobalLock.argtypes = [wintypes.HGLOBAL]
    k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

    handle = k.GlobalAlloc(GMEM_MOVEABLE, len(data))
    if not handle:
        raise OSError("GlobalAlloc failed")
    ptr = k.GlobalLock(handle)
    if not ptr:
        raise OSError("GlobalLock failed")
    ctypes.memmove(ptr, data, len(data))
    k.GlobalUnlock(handle)
    return handle


def _set_clipboard_windows(text: str) -> None:
    import ctypes
    from ctypes import wintypes

    u = ctypes.windll.user32
    u.OpenClipboard.argtypes = [wintypes.HWND]
    u.SetClipboardData.restype = wintypes.HANDLE
    u.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    u.RegisterClipboardFormatW.restype = wintypes.UINT
    u.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]

    payload = text.encode("utf-16-le") + b"\x00\x00"

    if not u.OpenClipboard(None):
        raise OSError("OpenClipboard failed")
    try:
        u.EmptyClipboard()
        if not u.SetClipboardData(CF_UNICODETEXT, _win_alloc(payload)):
            raise OSError("SetClipboardData failed")
        # Keep the secret out of Clipboard History, Cloud Clipboard and monitors.
        zero = b"\x00\x00\x00\x00"
        for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard",
                     "ExcludeClipboardContentFromMonitorProcessing"):
            fmt = u.RegisterClipboardFormatW(name)
            if fmt:
                u.SetClipboardData(fmt, _win_alloc(zero))
    finally:
        u.CloseClipboard()


def _get_clipboard_windows() -> str | None:
    import ctypes
    from ctypes import wintypes

    u = ctypes.windll.user32
    k = ctypes.windll.kernel32
    u.GetClipboardData.restype = wintypes.HANDLE
    u.GetClipboardData.argtypes = [wintypes.UINT]
    k.GlobalLock.restype = wintypes.LPVOID
    k.GlobalLock.argtypes = [wintypes.HGLOBAL]
    k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

    if not u.OpenClipboard(None):
        return None
    try:
        handle = u.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None
        ptr = k.GlobalLock(handle)
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            k.GlobalUnlock(handle)
    finally:
        u.CloseClipboard()


def _clear_windows_if_match(expected: str) -> None:
    import ctypes
    from ctypes import wintypes

    try:
        if _get_clipboard_windows() != expected:
            return  # user copied something else; leave it alone
        u = ctypes.windll.user32
        u.OpenClipboard.argtypes = [wintypes.HWND]
        if u.OpenClipboard(None):
            try:
                u.EmptyClipboard()
            finally:
                u.CloseClipboard()
    except OSError:
        pass


# ------------------------------------------------------------------ POSIX ----
def _set_clipboard_posix(text: str) -> None:
    candidates = (
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    )
    last_err: Exception | None = None
    for cmd in candidates:
        try:
            subprocess.run(cmd, input=text.encode("utf-8"), check=True)
            return
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            last_err = exc
    raise OSError(f"No clipboard tool found ({last_err})")


# ------------------------------------------------------------------- API -----
def copy(text: str, clear_after: int = AUTO_CLEAR_SECONDS) -> None:
    if sys.platform == "win32":
        _set_clipboard_windows(text)
        if clear_after and text:
            t = threading.Timer(clear_after, _clear_windows_if_match, args=(text,))
            t.daemon = True
            t.start()
    else:
        _set_clipboard_posix(text)
