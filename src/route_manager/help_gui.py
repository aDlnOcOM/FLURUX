import tkinter as tk
import webbrowser
from tkinter import ttk

from route_manager.help_topics import ARTICLES, Article, search


class HelpPanel:
    """An offline, keyboard-accessible manual with full-text search."""

    def __init__(self, tabs: ttk.Notebook) -> None:
        self.tabs = tabs
        self.frame = ttk.Frame(tabs, padding=7)
        tabs.add(self.frame, text="Справка")
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x", pady=(0, 7))
        ttk.Label(bar, text="Поиск по справке").pack(side="left", padx=(0, 9))
        self.query = tk.StringVar()
        self.find = ttk.Entry(bar, textvariable=self.query)
        self.find.pack(side="left", fill="x", expand=True)
        ttk.Button(bar, text="Сбросить", command=lambda: self.query.set("")).pack(
            side="left", padx=(5, 0)
        )
        panes = ttk.Panedwindow(self.frame, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes)
        right = ttk.Frame(panes, padding=(12, 0, 0, 0))
        panes.add(left, weight=1)
        panes.add(right, weight=3)
        self.list = tk.Listbox(
            left,
            width=28,
            exportselection=False,
            font=("Segoe UI", 10),
            background="#111c26",
            foreground="#edf4f7",
            selectbackground="#385747",
            selectforeground="white",
            relief="flat",
            highlightthickness=0,
        )
        scroll = ttk.Scrollbar(left, command=self.list.yview)
        scroll.pack(side="right", fill="y")
        self.list.configure(yscrollcommand=scroll.set)
        self.list.pack(fill="both", expand=True)
        self.heading = ttk.Label(right, wraplength=380, style="CardHeading.TLabel")
        self.heading.pack(fill="x", pady=(0, 6))
        self.source = ttk.Button(right, text="Открыть первоисточник", command=self.open_source)
        self.source.pack(side="bottom", anchor="w", pady=(6, 0))
        view = ttk.Frame(right)
        view.pack(fill="both", expand=True)
        self.body = tk.Text(
            view,
            wrap="word",
            width=30,
            height=12,
            background="#111c26",
            foreground="#edf4f7",
            font=("Segoe UI", 11),
            padx=12,
            pady=8,
            spacing3=5,
            relief="flat",
            selectbackground="#385747",
            highlightthickness=0,
        )
        sy = ttk.Scrollbar(view, command=self.body.yview)
        sy.pack(side="right", fill="y")
        self.body.configure(yscrollcommand=sy.set)
        self.body.pack(fill="both", expand=True)
        self.matches: list[Article] = []
        self.active: Article | None = None
        self.query.trace_add("write", self.filter)
        self.list.bind("<<ListboxSelect>>", self.show_selection)
        self.find.bind("<Down>", self.focus_list)
        self.filter()

    def focus_list(self, event: object = None) -> str:
        """Move keyboard focus from the query to its matches."""
        self.list.focus_set()
        return "break"

    def filter(self, *args: str) -> None:
        """Refresh search results including a useful empty state."""
        self.matches = search(self.query.get())
        self.list.delete(0, "end")
        for article in self.matches:
            self.list.insert("end", article.title)
        if self.matches:
            self.list.selection_set(0)
        self.show_selection()

    def show_selection(self, event: object = None) -> None:
        """Render the selected article and its optional primary source."""
        indexes = self.list.curselection()  # type: ignore[no-untyped-call]  # Tk stub
        self.active = self.matches[indexes[0]] if indexes else None
        self.heading.configure(text=self.active.title if self.active else "Совпадений нет")
        self.body.configure(state="normal")
        self.body.delete("1.0", "end")
        self.body.insert(
            "1.0",
            self.active.text if self.active else "Введите название протокола, поля или действия.",
        )
        self.body.configure(state="disabled")
        self.body.yview_moveto(0)
        self.source.configure(state="normal" if self.active and self.active.url else "disabled")

    def open_source(self) -> None:
        """Open a reference only when the reader requests it."""
        if self.active and self.active.url:
            webbrowser.open(self.active.url)

    def show(self, key: str = "home") -> None:
        """Select the precise article from elsewhere in the application."""
        self.tabs.select(self.frame)  # type: ignore[no-untyped-call]  # Tk stub
        self.query.set("")
        index = next((i for i, a in enumerate(ARTICLES) if a.key == key), 0)
        self.list.selection_clear(0, "end")
        self.list.selection_set(index)
        self.list.see(index)
        self.show_selection()
        self.find.focus_set()
