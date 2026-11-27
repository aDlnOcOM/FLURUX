"""Visual system and keyboard behaviour for the FLURUX desktop console."""

import tkinter as tk
from tkinter import ttk

BG = "#101112"
PANEL = "#1b1c1e"
HERO = "#161718"
INPUT = "#101112"
LINE = "#414142"
EDGE = "#777570"
TEXT = "#f0ede6"
MUTED = "#c3c1ba"
ACCENT = "#eed08b"
GOLD_DARK = "#322d21"
DANGER = "#ffc0ad"
INK = "#17150f"
MONO = "Consolas"
DISPLAY = "Bahnschrift"
VERSION = "0.3.5"


def apply_style(root: tk.Tk) -> None:
    """Use a persistent focus outline, native ttk controls and text-labelled states."""
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(
        ".",
        font=("Segoe UI", 10),
        background=BG,
        foreground=TEXT,
        bordercolor=LINE,
        lightcolor=LINE,
        darkcolor=LINE,
        focuscolor=ACCENT,
        selectbackground=ACCENT,
        selectforeground=INK,
    )
    s.configure("Title.TLabel", font=(DISPLAY, 22, "bold"))
    s.configure("Meta.TLabel", font=(MONO, 10), foreground=MUTED)
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("Card.TFrame", background=PANEL)
    s.configure("Surface.TFrame", background=PANEL, borderwidth=1, relief="solid", bordercolor=LINE)
    s.configure("Card.TLabel", background=PANEL, foreground=TEXT)
    s.configure("CardMuted.TLabel", background=PANEL, foreground=MUTED)
    s.configure("CardHeading.TLabel", background=PANEL, font=(DISPLAY, 15, "bold"))
    s.configure("Section.TLabel", font=(DISPLAY, 17, "bold"))
    s.configure("Hero.TFrame", background=HERO)
    s.configure("Hero.TLabel", background=HERO, foreground=TEXT)
    s.configure("HeroTitle.TLabel", background=HERO, font=(DISPLAY, 32, "bold"))
    s.configure("Kicker.TLabel", background=HERO, foreground=ACCENT, font=(MONO, 10, "bold"))
    s.configure("Engine.TLabel", background=HERO, foreground=TEXT, font=(MONO, 10, "bold"))
    for name, fg in (("CardReady", ACCENT), ("CardError", DANGER), ("EngineState", MUTED)):
        s.configure(name + ".TLabel", background=HERO, foreground=fg)
    s.configure(
        "TButton",
        background="#28292b",
        padding=(10, 5),
        relief="flat",
        borderwidth=1,
        bordercolor=EDGE,
        lightcolor="#28292b",
        darkcolor="#28292b",
    )
    s.map(
        "TButton",
        background=[("disabled", PANEL), ("pressed", GOLD_DARK), ("active", "#373736")],
        foreground=[("disabled", "#aba9a2"), ("!disabled", TEXT)],
        bordercolor=[("focus", ACCENT), ("disabled", LINE), ("active", TEXT)],
    )
    s.map(
        "TButton",
        relief=[("focus", "solid")],
        lightcolor=[("focus", ACCENT)],
        darkcolor=[("focus", ACCENT)],
    )
    s.configure(
        "Primary.TButton",
        background=ACCENT,
        foreground=INK,
        font=("Segoe UI", 10, "bold"),
        padding=(15, 6),
    )
    s.map(
        "Primary.TButton",
        background=[
            ("disabled", PANEL),
            ("pressed", "#d0af68"),
            ("active", "#ffe5ad"),
            ("!disabled", ACCENT),
        ],
        foreground=[("disabled", MUTED), ("!disabled", INK)],
        focuscolor=[("focus", INK)],
        lightcolor=[("!disabled", ACCENT)],
        darkcolor=[("!disabled", ACCENT)],
        bordercolor=[("focus", TEXT), ("!disabled", ACCENT)],
    )
    for name in ("Caption.TButton", "Close.Caption.TButton"):
        s.configure(
            name,
            font=("Segoe MDL2 Assets", 11),
            background=BG,
            foreground=TEXT,
            padding=(6, 6),
            borderwidth=0,
        )
        s.map(
            name,
            background=[
                ("active", "#8c3333" if name.startswith("Close") else "#363634"),
                ("!active", BG),
            ],
            foreground=[("!disabled", TEXT)],
        )
    for name in ("TEntry", "TCombobox"):
        s.configure(
            name,
            foreground=TEXT,
            fieldbackground=INPUT,
            insertcolor=TEXT,
            bordercolor=EDGE,
            lightcolor=INPUT,
            darkcolor=INPUT,
            background="#292a2b",
            arrowcolor=ACCENT,
            padding=(7, 5),
            selectforeground=INK,
            selectbackground=ACCENT,
        )
        s.map(
            name,
            foreground=[("disabled", MUTED), ("readonly", TEXT)],
            fieldbackground=[("disabled", BG), ("readonly", INPUT)],
            bordercolor=[("focus", ACCENT)],
            lightcolor=[("focus", ACCENT)],
            darkcolor=[("focus", ACCENT)],
        )
    s.configure("TCheckbutton", indicatorbackground=INPUT, indicatorforeground=ACCENT, padding=3)
    s.map(
        "TCheckbutton",
        background=[("active", GOLD_DARK)],
        indicatorbackground=[("selected", ACCENT)],
        indicatorforeground=[("selected", INK)],
    )
    s.configure("TScrollbar", background=EDGE, troughcolor=INPUT, arrowcolor=TEXT, bordercolor=BG)
    s.configure(
        "Treeview",
        background=INPUT,
        fieldbackground=INPUT,
        foreground=TEXT,
        bordercolor=LINE,
        rowheight=28,
    )
    s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", INK)])
    s.configure(
        "Treeview.Heading", background=PANEL, foreground=MUTED, font=(MONO, 10), padding=(5, 6)
    )
    s.map("Treeview.Heading", background=[("active", GOLD_DARK)])
    s.configure(
        "TNotebook",
        background=BG,
        borderwidth=0,
        lightcolor=BG,
        darkcolor=BG,
        tabmargins=(0, 0, 0, 7),
    )
    for prefix, pad in (("", (10, 5)), ("Main.", (14, 7))):
        style = prefix + "TNotebook.Tab"
        s.configure(
            style,
            padding=pad,
            background=BG,
            foreground=MUTED,
            borderwidth=1,
            font=("Segoe UI", 10),
        )
        s.map(
            style,
            background=[("selected", ACCENT), ("active", PANEL)],
            foreground=[("selected", INK), ("active", TEXT)],
            lightcolor=[("selected", ACCENT)],
            darkcolor=[("selected", ACCENT)],
            bordercolor=[("focus", TEXT), ("selected", ACCENT), ("!selected", EDGE)],
            font=[("selected", ("Segoe UI", 10, "bold"))],
            focuscolor=[("selected", INK)],
            expand=[("selected", (0, 0, 0, 0))],
            padding=[("selected", pad)],
        )
    root.option_add("*TCombobox*Listbox.background", INPUT)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", INK)


def text_navigation(widget: tk.Text) -> None:
    """Move through text fields with Tab and Shift+Tab without inserting characters."""

    def traverse(backwards: bool) -> str:
        next_widget = widget.tk_focusPrev() if backwards else widget.tk_focusNext()
        if next_widget:
            next_widget.focus_set()
        return "break"

    widget.bind("<Tab>", lambda _: traverse(False))
    widget.bind("<Shift-Tab>", lambda _: traverse(True))


def brand(parent: ttk.Frame) -> None:
    """Render the application's F mark and wordmark in the header."""
    mark = tk.Canvas(parent, width=33, height=33, highlightthickness=0, bg=BG, takefocus=False)
    mark.pack(side="left", padx=(0, 10))
    mark.create_polygon(0, 0, 33, 0, 33, 25, 25, 33, 0, 33, fill=ACCENT, outline="")
    mark.create_polygon(
        8,
        8,
        26,
        8,
        23,
        12,
        13,
        12,
        13,
        15,
        23,
        15,
        20,
        19,
        13,
        19,
        13,
        25,
        8,
        25,
        fill=INK,
        outline="",
    )
    ttk.Label(parent, text="FLURUX", style="Title.TLabel").pack(side="left")


class NeonFrame(tk.Canvas):
    """Draw a static bevelled light trace outside the content and its hit targets."""

    def __init__(
        self, parent: tk.Misc, *, surface: str = BG, gold: bool = True, cut: int = 9
    ) -> None:
        super().__init__(
            parent,
            bg=surface,
            width=1,
            height=1,
            highlightthickness=0,
            borderwidth=0,
            takefocus=False,
        )
        self.cut = cut
        self.gold = gold
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.body = ttk.Frame(
            self,
            style="Hero.TFrame"
            if surface == HERO
            else "Card.TFrame"
            if surface == PANEL
            else "TFrame",
        )
        self.body.grid(row=0, column=0, sticky="nsew", padx=6, pady=5)
        self.bind("<Configure>", self._draw)

    def _draw(self, event: "tk.Event[tk.Misc]") -> None:
        right, bottom = event.width - 3, event.height - 3
        if min(right, bottom) < 20:
            return
        self.delete("trace")
        x, y, k = 3, 2, self.cut
        outline = (
            x + k,
            y,
            right - k,
            y,
            right,
            y + k,
            right,
            bottom - k,
            right - k,
            bottom,
            x + k,
            bottom,
            x,
            bottom - k,
            x,
            y + k,
            x + k,
            y,
        )
        halo, mid, line = (
            ("#3c2c15", "#76572c", "#d9b66d") if self.gold else ("#25282a", "#454a4e", "#949b9e")
        )
        for width, color in ((7, halo), (3, mid), (1, line)):
            self.create_line(list(outline), width=width, fill=color, tags="trace")
        arm = min(75, right // 5)
        for segment, colors in (
            (
                (x, y + k + 10, x, y + k, x + k, y, x + k + arm, y),
                ("#776037", "#eabd66", "#fff0bf")
                if self.gold
                else ("#414548", "#7f8588", "#e9e8df"),
            ),
            (
                (
                    right,
                    bottom - k - 10,
                    right,
                    bottom - k,
                    right - k,
                    bottom,
                    right - k - arm,
                    bottom,
                ),
                ("#3c4043", "#747a7e", "#d6d7d4"),
            ),
        ):
            for width, color in zip((5, 3, 1), colors, strict=True):
                self.create_line(list(segment), width=width, fill=color, tags="trace")
