"""Expose Tk control labels, roles and selection changes to Windows Active Accessibility."""

import ctypes as ct
import tkinter as tk
from ctypes import wintypes as wt
from tkinter import ttk
from uuid import UUID
from weakref import WeakKeyDictionary

_names: WeakKeyDictionary[tk.Misc, str] = WeakKeyDictionary()


def named[W: tk.Misc](widget: W, label: str) -> W:
    """Associate a field, icon or navigation control with its spoken label."""
    _names[widget] = label
    return widget


class _Guid(ct.Structure):
    _fields_ = [("bytes", ct.c_ubyte * 16)]

    @classmethod
    def parse(cls, text: str) -> "_Guid":
        return cls.from_buffer_copy(UUID(text).bytes_le)


class _Variant(ct.Structure):
    # VT_I4 followed by the padding reserved for the largest VARIANT payload.
    _fields_ = [
        ("vt", ct.c_ushort),
        ("reserved", ct.c_ushort * 3),
        ("number", wt.LONG),
        ("padding", ct.c_byte * (2 * ct.sizeof(ct.c_void_p) - 4)),
    ]


_service = _Guid.parse("b5f8350b-0548-48b1-a6ee-88bd00b4a5e7")
_interface = _Guid.parse("6e26e776-04f0-495d-80e4-3330352e3169")
_properties = (_Guid * 4)(
    *[
        _Guid.parse(g)
        for g in (
            "608d3df8-8128-4aa7-a428-f55e49267291",
            "cb905ff2-7bd1-4c05-b3c8-e6c241364d70",
            "a8d4d5b0-0a21-42d0-a5c0-514e984f457b",
            "123fe443-211a-4615-9527-c45a7e93717a",
        )
    ]
)
_client = 0xFFFFFFFC
_roles = {
    "TButton": 43,
    "TCheckbutton": 44,
    "TEntry": 42,
    "TCombobox": 46,
    "TNotebook": 60,
    "Listbox": 33,
    "Treeview": 35,
    "TLabel": 41,
    "Text": 42,
}


class AccessibleControls:
    """Publish visible Tk controls through IAccPropServices on the Tk apartment."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.service = ct.c_void_p()
        self.handles: dict[tk.Misc, int] = {}
        self.previous: dict[int, tuple[str, int, int, str]] = {}
        self.timer: str | None = None
        ole = ct.windll.ole32
        initialized = ole.CoInitializeEx(None, 2)
        self.uninitialize = initialized in (0, 1)
        result = ole.CoCreateInstance(
            ct.byref(_service), None, 1, ct.byref(_interface), ct.byref(self.service)
        )
        if result != 0:
            if self.uninitialize:
                ole.CoUninitialize()
            return
        table = ct.cast(self.service, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
        args = (ct.c_void_p, wt.HWND, wt.DWORD, wt.DWORD)
        # Slots in the IAccPropServices vtable following IUnknown and the identity-string setters.
        self._set_number = ct.WINFUNCTYPE(wt.LONG, *args, _Guid, _Variant)(table[6])
        self._set_text = ct.WINFUNCTYPE(wt.LONG, *args, _Guid, wt.LPCWSTR)(table[7])
        self._clear = ct.WINFUNCTYPE(wt.LONG, *args, ct.POINTER(_Guid), ct.c_int)(table[9])
        self._release = ct.WINFUNCTYPE(wt.ULONG, ct.c_void_p)(table[2])
        root.bind("<Map>", self._map, add="+")
        root.bind("<Destroy>", self._destroy, add="+")
        root.bind("<FocusIn>", self._focus, add="+")
        self.timer = root.after_idle(self._refresh)

    def _map(self, event: "tk.Event[tk.Misc]") -> None:
        widget = event.widget
        if isinstance(widget, tk.Misc) and widget.winfo_class() in _roles:
            self.handles[widget] = widget.winfo_id()
            self._publish(widget)

    def _focus(self, event: "tk.Event[tk.Misc]") -> None:
        hwnd = self.handles.get(event.widget)
        if hwnd:
            self._publish(event.widget)
            ct.windll.user32.NotifyWinEvent(0x8005, wt.HWND(hwnd), _client, 0)

    def _refresh(self) -> None:
        for widget in self.handles:
            if widget.winfo_ismapped():
                self._publish(widget)
        self.timer = self.root.after(400, self._refresh)

    def _publish(self, widget: tk.Misc) -> None:
        kind = widget.winfo_class()
        name = _names.get(widget, "")
        value = ""
        state = 0 if isinstance(widget, ttk.Label) else 0x100000  # STATE_SYSTEM_FOCUSABLE
        if isinstance(widget, ttk.Widget):
            if widget.instate(["disabled"]):
                state |= 1
            if widget.instate(["focus"]):
                state |= 4
            if widget.instate(["readonly"]):
                state |= 0x40
        if isinstance(widget, (ttk.Label, ttk.Checkbutton, ttk.Button)):
            name = name or str(widget.cget("text"))
            if isinstance(widget, ttk.Checkbutton) and widget.instate(["selected"]):
                state |= 0x10
        elif isinstance(widget, ttk.Entry):
            if widget.cget("show"):
                state |= 0x20000000  # STATE_SYSTEM_PROTECTED; never fetch password text.
            else:
                value = widget.get()
        elif isinstance(widget, ttk.Notebook):
            selected = widget.select()  # type: ignore[no-untyped-call]
            if selected:
                value = str(widget.tab(selected, "text"))  # type: ignore[no-untyped-call]
        elif isinstance(widget, tk.Listbox):
            selection = widget.curselection()  # type: ignore[no-untyped-call]
            if selection:
                value = str(widget.get(selection[0]))
        elif isinstance(widget, ttk.Treeview) and widget.selection():
            row_data = widget.item(widget.selection()[0])
            value = " ".join(str(part) for part in (row_data["text"], *row_data["values"]))
        elif isinstance(widget, tk.Text):
            if str(widget.cget("state")) == "disabled":
                state |= 0x40
            if widget.tk.call("focus") == str(widget):
                state |= 4
                value = widget.get("1.0", "end-1c")
        hwnd = self.handles[widget]
        attributes = (name, _roles[kind], state, value)
        previous = self.previous.get(hwnd)
        if previous == attributes:
            return
        for i, (item, event_id) in enumerate(
            zip(attributes, (0x800C, 0x800A, 0x800A, 0x800E), strict=True)
        ):
            if previous is not None and item == previous[i]:
                continue
            if isinstance(item, str):
                self._set_text(self.service, hwnd, _client, 0, _properties[i], item)
            else:
                number = _Variant(vt=3, number=item)
                self._set_number(self.service, hwnd, _client, 0, _properties[i], number)
            if previous is not None:
                ct.windll.user32.NotifyWinEvent(event_id, wt.HWND(hwnd), _client, 0)
        self.previous[hwnd] = attributes

    def _destroy(self, event: "tk.Event[tk.Misc]") -> None:
        hwnd = self.handles.pop(event.widget, None)
        if hwnd:
            self._clear(self.service, hwnd, _client, 0, _properties, len(_properties))
            self.previous.pop(hwnd, None)
        if event.widget is self.root:
            if self.timer:
                self.root.after_cancel(self.timer)
            self._release(self.service)
            if self.uninitialize:
                ct.windll.ole32.CoUninitialize()
