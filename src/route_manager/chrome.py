"""A client-drawn title bar with the native Windows move, size and system menus."""

import ctypes as ct
import tkinter as tk
from collections.abc import Callable
from ctypes import wintypes as wt
from tkinter import ttk
from uuid import UUID

from route_manager.accessibility import named
from route_manager.theme import brand

_word = ct.c_size_t
_result = ct.c_ssize_t
_proc = ct.WINFUNCTYPE(_result, wt.HWND, wt.UINT, _word, _result, _word, _word)
_user = ct.windll.user32
_common = ct.windll.comctl32
_common.SetWindowSubclass.argtypes = [wt.HWND, _proc, _word, _word]
_common.RemoveWindowSubclass.argtypes = [wt.HWND, _proc, _word]
_common.DefSubclassProc.argtypes = [wt.HWND, wt.UINT, _word, _result]
_common.DefSubclassProc.restype = _result
_user.GetAncestor.argtypes = [wt.HWND, wt.UINT]
_user.GetAncestor.restype = wt.HWND
_user.GetSystemMenu.argtypes = [wt.HWND, wt.BOOL]
_user.GetSystemMenu.restype = wt.HMENU
_user.TrackPopupMenu.argtypes = [
    wt.HMENU,
    wt.UINT,
    ct.c_int,
    ct.c_int,
    ct.c_int,
    wt.HWND,
    ct.c_void_p,
]
_user.PostMessageW.argtypes = [wt.HWND, wt.UINT, _word, _result]
_user.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ct.c_int, ct.c_int, ct.c_int, ct.c_int, wt.UINT]
_user.IsZoomed.argtypes = [wt.HWND]


_iid_accessible = (ct.c_ubyte * 16).from_buffer_copy(
    UUID("618736e0-3c3d-11cf-810c-00aa00389b71").bytes_le
)
_oleacc = ct.windll.oleacc
_oleacc.CreateStdAccessibleProxyW.argtypes = [
    wt.HWND,
    wt.LPCWSTR,
    wt.LONG,
    ct.c_void_p,
    ct.POINTER(ct.c_void_p),
]
_oleacc.LresultFromObject.argtypes = [ct.c_void_p, _word, ct.c_void_p]
_oleacc.LresultFromObject.restype = _result
_user.SetWindowTextW.argtypes = [wt.HWND, wt.LPCWSTR]


class WindowBar:
    """Retain the taskbar entry, resize border, system shortcuts and close protocol."""

    def __init__(
        self, root: tk.Tk, heading: ttk.Frame, close: Callable[[], None], version: str, admin: bool
    ) -> None:
        self.root = root
        self.heading = heading
        self.hwnd = 0
        self.callback = _proc(self._window_message)
        self.button_callback = _proc(self._button_message)
        self.buttons_by_handle: dict[int, ttk.Button] = {}
        self.pending_action: int | None = None
        self.press: tuple[int, int] | None = None
        brand(heading)
        ttk.Label(
            heading, text="Системный VPN" if admin else f"v{version}", style="Meta.TLabel"
        ).pack(side="left", padx=(13, 0))
        self.controls: list[ttk.Button] = []
        self.tip = tk.StringVar(master=root)
        group = ttk.Frame(heading)
        group.pack(side="right")
        for glyph, name, command in (
            ("", "Свернуть", root.iconify),
            ("", "Развернуть", self.toggle),
            ("", "Закрыть", close),
        ):
            button = ttk.Button(
                group,
                text=glyph,
                command=command,
                style="Close.Caption.TButton" if name == "Закрыть" else "Caption.TButton",
                width=3,
            )
            named(button, name)
            button.pack(side="left")
            button.bind("<Enter>", self._hint)
            button.bind("<Leave>", self._clear_hint)
            button.bind("<FocusIn>", self._hint)
            button.bind("<FocusOut>", self._clear_hint)
            self.controls.append(button)
        ttk.Label(heading, textvariable=self.tip, style="Muted.TLabel").pack(
            side="right", padx=(5, 12)
        )
        for widget in (heading, *heading.winfo_children()):
            if widget is not group:
                widget.bind("<Button-1>", self._pressed)
                widget.bind("<B1-Motion>", self._drag)
                widget.bind("<ButtonRelease-1>", self._released)
                widget.bind("<Double-Button-1>", self._double)
                widget.bind("<Button-3>", self._menu)
        root.bind("<Alt-space>", self._menu, add="+")
        root.bind("<Map>", self._map, add="+")
        root.bind("<Configure>", self._state, add="+")
        self._zoomed = False
        root.after_idle(self.attach)

    def names(self) -> tuple[str, str, str]:
        """Return localized names synchronized with the actual Windows placement."""
        return ("Свернуть", "Восстановить размер" if self._zoomed else "Развернуть", "Закрыть")

    def _hint(self, event: "tk.Event[tk.Misc]") -> None:
        for button, name in zip(self.controls, self.names(), strict=True):
            if event.widget is button:
                self.tip.set(name)

    def _clear_hint(self, event: "tk.Event[tk.Misc]") -> None:
        self.tip.set("")

    def _map(self, event: "tk.Event[tk.Misc]") -> None:
        if event.widget is self.root:
            self.attach()

    def attach(self) -> None:
        """Replace only the caption area of Tk's Win32 wrapper."""
        hwnd = _user.GetAncestor(self.root.winfo_id(), 2)
        if not hwnd or self.hwnd == hwnd:
            return
        if _common.SetWindowSubclass(hwnd, self.callback, 1, 0):
            self.hwnd = hwnd
            for button, name in zip(self.controls, self.names(), strict=True):
                handle = button.winfo_id()
                if handle not in self.buttons_by_handle and _common.SetWindowSubclass(
                    handle, self.button_callback, 2, 0
                ):
                    self.buttons_by_handle[handle] = button
                    _user.SetWindowTextW(handle, name)
            _user.SetWindowPos(
                hwnd, None, 0, 0, 0, 0, 0x37
            )  # FRAMECHANGED, preserve placement and activation.

    def _window_message(self, hwnd: int, msg: int, wp: int, lp: int, sub: int, ref: int) -> int:
        if msg == 0x83 and lp:  # WM_NCCALCSIZE: the first RECT is common to both parameter forms.
            rect = wt.RECT.from_address(lp)
            left, top = rect.left, rect.top
            _common.DefSubclassProc(hwnd, msg, wp, lp)
            rect.top = top + (max(0, rect.left - left) if _user.IsZoomed(hwnd) else 0)
            return 0
        if msg == 0x84:  # WM_NCHITTEST
            hit = int(_common.DefSubclassProc(hwnd, msg, wp, lp))
            bounds = wt.RECT()
            if not _user.IsZoomed(hwnd) and _user.GetWindowRect(wt.HWND(hwnd), ct.byref(bounds)):
                x, y = ct.c_short(lp & 0xFFFF).value, ct.c_short((lp >> 16) & 0xFFFF).value
                if bounds.top <= y < bounds.top + 5:
                    return 13 if x < bounds.left + 8 else 14 if x >= bounds.right - 8 else 12
            if hit in (2, 3, 8, 9, 20, 21):
                return 1
            return hit
        if msg == 0x82:  # WM_NCDESTROY
            _common.RemoveWindowSubclass(hwnd, self.callback, sub)
            if self.hwnd == hwnd:
                self.hwnd = 0
        return int(_common.DefSubclassProc(hwnd, msg, wp, lp))

    def _button_message(self, hwnd: int, msg: int, wp: int, lp: int, sub: int, ref: int) -> int:
        # Supply the same default MSAA action as a native push button.
        if msg == 0x3D and ct.c_long(lp).value == -4:  # WM_GETOBJECT / OBJID_CLIENT
            obj = ct.c_void_p()
            if (
                _oleacc.CreateStdAccessibleProxyW(
                    hwnd, "Button", -4, ct.byref(_iid_accessible), ct.byref(obj)
                )
                == 0
            ):
                try:
                    return int(_oleacc.LresultFromObject(ct.byref(_iid_accessible), wp, obj))
                finally:
                    table = ct.cast(obj, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
                    ct.WINFUNCTYPE(wt.ULONG, ct.c_void_p)(table[2])(obj)
        # Accessibility clients may send mouse or button messages from a COM call.
        # Queue the action for the normal Tk event loop, outside the synchronous Win32 callback.
        if msg == 0xF5 or (msg in (0x201, 0x202) and _user.InSendMessageEx(None)):
            if msg != 0x201:
                self.pending_action = hwnd
            return 0
        if msg == 0x82:
            _common.RemoveWindowSubclass(hwnd, self.button_callback, sub)
            self.buttons_by_handle.pop(hwnd, None)
        return int(_common.DefSubclassProc(hwnd, msg, wp, lp))

    def dispatch(self) -> None:
        """Invoke a caption command queued by a Windows accessibility client."""
        handle = self.pending_action
        self.pending_action = None
        if handle is not None and handle in self.buttons_by_handle:
            self.buttons_by_handle[handle].invoke()

    def _pressed(self, event: "tk.Event[tk.Misc]") -> None:
        self.press = (event.x_root, event.y_root)

    def _released(self, event: "tk.Event[tk.Misc]") -> None:
        self.press = None

    def _drag(self, event: "tk.Event[tk.Misc]") -> str:
        if (
            self.press
            and self.hwnd
            and (
                abs(event.x_root - self.press[0]) >= _user.GetSystemMetrics(68)
                or abs(event.y_root - self.press[1]) >= _user.GetSystemMetrics(69)
            )
        ):
            self.press = None
            _user.ReleaseCapture()
            point = (event.x_root & 0xFFFF) | ((event.y_root & 0xFFFF) << 16)
            _user.PostMessageW(self.hwnd, 0xA1, 2, point)
        return "break"

    def _double(self, event: "tk.Event[tk.Misc]") -> str:
        self.press = None
        self.toggle()
        return "break"

    def toggle(self) -> None:
        """Maximize the window or restore its last normal bounds."""
        self.root.state("normal" if self.root.state() == "zoomed" else "zoomed")
        self._sync_state()

    def _state(self, event: "tk.Event[tk.Misc]") -> None:
        if event.widget is self.root:
            self._sync_state()

    def _sync_state(self) -> None:
        zoomed = self.root.state() == "zoomed"
        if zoomed == self._zoomed:
            return
        self._zoomed = zoomed
        button = self.controls[1]
        button.configure(text="" if zoomed else "")
        name = self.names()[1]
        named(button, name)
        _user.SetWindowTextW(button.winfo_id(), name)
        if button.instate(["focus"]) or button.instate(["active"]):
            self.tip.set(name)

    def _menu(self, event: "tk.Event[tk.Misc]") -> str:
        if self.hwnd:
            mouse = event.type == tk.EventType.ButtonPress
            x = event.x_root if mouse else self.heading.winfo_rootx()
            y = event.y_root if mouse else self.heading.winfo_rooty() + self.heading.winfo_height()
            menu = _user.GetSystemMenu(self.hwnd, False)
            command = _user.TrackPopupMenu(menu, 0x102, x, y, 0, self.hwnd, None)
            if command:
                _user.PostMessageW(self.hwnd, 0x112, command, 0)
        return "break"
