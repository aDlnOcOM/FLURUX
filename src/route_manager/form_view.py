"""Scrollable profile tabs with keyboard navigation for compact windows."""

import tkinter as tk
from tkinter import ttk


class FormView(ttk.Frame):
    """Keep all profile fields reachable while the action bar stays visible."""

    def __init__(self, notebook: ttk.Notebook, title: str) -> None:
        super().__init__(notebook)
        notebook.add(self, text=title)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(
            self,
            bg=ttk.Style().lookup("TFrame", "background"),
            highlightthickness=0,
            width=1,
            height=1,
            takefocus=False,
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scroll = ttk.Scrollbar(self, command=self.canvas.yview)
        self.scroll.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.body = ttk.Frame(self.canvas, padding=8)
        self.item = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self.viewport = (-1, -1, -1)
        self.canvas.bind("<Configure>", self._resize)
        self.body.bind("<Configure>", self._resize)

    def _resize(self, event: "tk.Event[tk.Misc]") -> None:
        width = self.canvas.winfo_width()
        height = self.body.winfo_reqheight()
        viewport = (width, self.canvas.winfo_height(), height)
        if self.viewport == viewport:
            return
        self.viewport = viewport
        self.canvas.itemconfigure(self.item, width=width)
        self.canvas.configure(scrollregion=(0, 0, width, height))
        if height > self.canvas.winfo_height():
            self.scroll.grid()
        else:
            self.scroll.grid_remove()
            self.canvas.yview_moveto(0)

    def enable_navigation(self) -> None:
        """Enable wheel and focus scrolling on the completed tab's controls."""
        for widget in (self.body, self.canvas, *self.body.winfo_children()):
            widget.bind("<MouseWheel>", self._wheel, add="+")
            widget.bind("<FocusIn>", self._reveal, add="+")

    def _wheel(self, event: "tk.Event[tk.Misc]") -> str | None:
        if self.scroll.winfo_ismapped() and not isinstance(event.widget, ttk.Combobox):
            steps = max(1, abs(event.delta) // 120)
            self.canvas.yview_scroll(-steps if event.delta > 0 else steps, "units")
            return "break"
        return None

    def _reveal(self, event: "tk.Event[tk.Misc]") -> None:
        if not self.scroll.winfo_ismapped() or event.widget in (self.body, self.canvas):
            return
        top = event.widget.winfo_rooty() - self.body.winfo_rooty()
        end = top + event.widget.winfo_height()
        offset = self.canvas.canvasy(0)
        height = self.canvas.winfo_height()
        if top < offset or end > offset + height:
            target = top if top < offset else end - height
            self.canvas.yview_moveto(target / max(1, self.body.winfo_height()))
