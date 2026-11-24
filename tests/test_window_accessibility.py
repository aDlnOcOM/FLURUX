"""Exercise the caption through a separate Windows assistive technology process."""

import ctypes as ct
import subprocess
import sys
import time
import tkinter as tk
from ctypes import wintypes as wt
from pathlib import Path
from uuid import UUID

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from tkinter import ttk  # noqa: E402

from route_manager.chrome import WindowBar  # noqa: E402
from route_manager.theme import apply_style  # noqa: E402


class Variant(ct.Structure):
    _fields_ = [
        ("vt", ct.c_ushort),
        ("reserved", ct.c_ushort * 3),
        ("number", wt.LONG),
        ("padding", ct.c_byte * (2 * ct.sizeof(ct.c_void_p) - 4)),
    ]


def invoke_accessible_button(handle: int) -> None:
    """Perform IAccessible's default action on a caption control in the other process."""
    ole = ct.windll.ole32
    assert ole.CoInitializeEx(None, 2) in (0, 1)
    obj = ct.c_void_p()
    iid = (ct.c_ubyte * 16).from_buffer_copy(UUID("618736e0-3c3d-11cf-810c-00aa00389b71").bytes_le)
    try:
        result = ct.windll.oleacc.AccessibleObjectFromWindow(
            wt.HWND(handle), wt.DWORD(-4), ct.byref(iid), ct.byref(obj)
        )
        assert result == 0
        table = ct.cast(obj, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
        child = Variant(vt=3, number=0)
        try:
            name = ct.c_void_p()
            getter = ct.WINFUNCTYPE(wt.LONG, ct.c_void_p, Variant, ct.POINTER(ct.c_void_p))(
                table[10]
            )
            assert getter(obj, child, ct.byref(name)) == 0
            try:
                assert ct.wstring_at(name) == "Развернуть"
            finally:
                ct.windll.oleaut32.SysFreeString(name)
            assert ct.WINFUNCTYPE(wt.LONG, ct.c_void_p, Variant)(table[25])(obj, child) == 0
        finally:
            ct.WINFUNCTYPE(wt.ULONG, ct.c_void_p)(table[2])(obj)
    finally:
        ole.CoUninitialize()


def test_assistive_default_action_maximizes_window() -> None:
    """A synchronous accessibility request must return before its Tk callback runs."""
    root = tk.Tk()
    try:
        apply_style(root)
        header = ttk.Frame(root)
        header.pack(fill="x")
        chrome = WindowBar(root, header, root.destroy, "test", False)
        root.update()
        with subprocess.Popen(
            [sys.executable, "-I", __file__, str(chrome.controls[1].winfo_id())]
        ) as client:
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    root.update()
                    chrome.dispatch()
                    if client.poll() is not None and root.state() == "zoomed":
                        break
                    time.sleep(0.01)
                assert client.poll() == 0
                assert root.state() == "zoomed"
            finally:
                if client.poll() is None:
                    client.kill()
    finally:
        root.destroy()


if __name__ == "__main__":
    invoke_accessible_button(int(sys.argv[1]))
