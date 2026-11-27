"""The standalone zapret2 workspace and component maintenance controls."""

import http.client
import subprocess
import threading
import tkinter as tk
import webbrowser
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from route_manager import zapret_bundle as bundle
from route_manager.accessibility import named
from route_manager.config import STRATEGIES, Settings, parse_domains
from route_manager.runtime import Update
from route_manager.theme import NeonFrame
from route_manager.zapret_presets import FAMILIES, PORT_SETS, PRESETS, QUIC_METHODS

if TYPE_CHECKING:
    from route_manager.gui import App

HINTS = dict(
    zip(
        STRATEGIES.values(),
        (
            "Для сайтов с HTTPS. Сначала попробуйте этот вариант.",
            "Для HTTPS, если разделение TLS не помогло.",
            "Разделение для HTTPS и дополнительная обработка QUIC для HTTP/3.",
            "Перестановка для HTTPS и дополнительная обработка QUIC для HTTP/3.",
        ),
        strict=True,
    )
)


class ZapretPanel(ttk.Frame):
    """Edit, install, verify and operate the same zapret2 session as the connection screen."""

    def __init__(self, parent: ttk.Frame, app: "App", saved: Settings) -> None:
        super().__init__(parent, padding=(4, 5))
        self.app = app
        self.busy = ""
        self.cancel = threading.Event()
        self.installed_folder = bundle.engine_folder().is_dir()
        self.present = (bundle.engine_folder() / "winws2.exe").is_file()
        self.component = tk.StringVar(
            value="Движок найден" if self.present else "Требуется установка"
        )
        self.session_state = tk.StringVar(value="Остановлен")
        self.notice = tk.StringVar(value="Добавьте домены сайтов, для которых нужен zapret2.")
        self.family = tk.StringVar(value=FAMILIES.get(saved.ip_family, FAMILIES["both"]))
        self.port_profile = tk.StringVar(
            value=next(
                (k for k, v in PORT_SETS.items() if v == saved.tcp_ports == saved.udp_ports),
                "Свой набор",
            )
        )
        self.tcp = tk.StringVar(value=saved.tcp_ports)
        self.udp = tk.StringVar(value=saved.udp_ports)
        self.hint = tk.StringVar()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        title = ttk.Frame(self)
        title.grid(row=0, column=0, sticky="ew", pady=(0, 7))
        ttk.Label(title, text="Только zapret2", style="Section.TLabel").pack(side="left")
        ttk.Label(title, textvariable=self.session_state, style="Meta.TLabel").pack(
            side="left", padx=14
        )
        ttk.Button(
            title,
            text="Журнал",
            command=lambda: app.help.tabs.select(app.journal_page),  # type: ignore[no-untyped-call]
        ).pack(side="right")
        ttk.Button(title, text="Сравнить 60", command=lambda: app.diagnostics.open("zapret")).pack(
            side="right", padx=4
        )
        ttk.Button(
            title, text="Тест стратегии", command=lambda: app.diagnostics.open("selected")
        ).pack(side="right")
        self.pages = named(ttk.Notebook(self), "Управление zapret2")
        self.pages.grid(row=1, column=0, sticky="nsew")
        route = ttk.Frame(self.pages, padding=(7, 5))
        extra = ttk.Frame(self.pages, padding=(7, 5))
        engine = ttk.Frame(self.pages, padding=(7, 5))
        library = ttk.Frame(self.pages, padding=(7, 5))
        self.engine = engine
        self.route = route
        for page, label in (
            (route, "Маршрут"),
            (library, "Каталог"),
            (extra, "Порты и исключения"),
            (engine, "Движок"),
        ):
            self.pages.add(page, text=label)
        library.columnconfigure(0, weight=1)
        library.rowconfigure(0, weight=1)
        self.catalog = named(
            ttk.Treeview(library, columns=("family", "ports"), selectmode="browse", height=4),
            "60 профилей zapret2",
        )
        self.catalog.heading("#0", text="Обработка")
        self.catalog.heading("family", text="Семейство IP")
        self.catalog.heading("ports", text="Порты назначения")
        for key in ("#0", "family", "ports"):
            self.catalog.column(key, width=140, minwidth=70)
        for index, preset in enumerate(PRESETS):
            self.catalog.insert(
                "",
                "end",
                iid=str(index),
                text=STRATEGIES[preset.method],
                values=(FAMILIES[preset.family], preset.ports),
            )
            if (preset.method, preset.family, preset.ports) == (
                saved.strategy,
                saved.ip_family,
                saved.tcp_ports,
            ):
                self.catalog.selection_set(str(index))
                self.catalog.see(str(index))
        self.catalog.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(library, orient="vertical", command=self.catalog.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.catalog.configure(yscrollcommand=scroll.set)
        actions = ttk.Frame(library)
        actions.grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Button(
            actions, text="Выбрать профиль", style="Primary.TButton", command=self._apply_preset
        ).pack(side="left")
        ttk.Button(
            actions, text="Проверить профиль", command=lambda: self._apply_preset(test=True)
        ).pack(side="left", padx=6)
        self.catalog.bind("<Return>", self._apply_preset)
        self.catalog.bind("<Double-1>", self._apply_preset)
        route.columnconfigure((0, 1), weight=1, uniform="route")
        route.rowconfigure(0, weight=1)
        left = app._card(route, "Сайты", padding=(0, 0, 4, 0))
        ttk.Label(
            left,
            text="По одному домену в строке, например example.org.",
            style="CardMuted.TLabel",
            wraplength=275,
        ).pack(anchor="w", pady=(7, 5))
        self.domains = named(app._text(left, 4, expand=True), "Домены zapret2")
        self.domains.insert("1.0", saved.domains)
        files = ttk.Frame(left, style="Card.TFrame")
        files.pack(fill="x", pady=(6, 0))
        ttk.Button(files, text="Импорт списка", command=self.import_sites).pack(side="left")
        ttk.Button(files, text="Экспорт", command=self.export_sites).pack(side="left", padx=4)
        right = app._card(route, "Стратегия", column=1, padding=(4, 0, 0, 0))
        choice = named(
            ttk.Combobox(
                right,
                textvariable=app.strategy,
                values=tuple(STRATEGIES.values()),
                state="readonly",
            ),
            "Стратегия zapret2",
        )
        choice.pack(fill="x", pady=(8, 3))
        ttk.Label(right, textvariable=self.hint, style="CardMuted.TLabel", wraplength=285).pack(
            anchor="w"
        )
        self.hint.set(HINTS[app.strategy.get()])
        app.strategy.trace_add("write", self._strategy)
        ttk.Separator(right).pack(fill="x", pady=8)
        ttk.Label(
            right, text="Проверка сайта · по умолчанию первый из списка", style="Card.TLabel"
        ).pack(anchor="w")
        self.target = named(ttk.Entry(right, textvariable=app.target), "Сайт для проверки zapret2")
        self.target.pack(fill="x", pady=(3, 4))
        self.probe = ttk.Button(right, text="Проверить доступ", command=self.check)
        self.probe.pack(anchor="w")
        result = ttk.Label(
            right, textvariable=app.probe_result, style="CardMuted.TLabel", wraplength=280
        )
        result.pack(anchor="w", fill="x", pady=(4, 0))
        result.bind("<Configure>", lambda e: result.configure(wraplength=max(100, e.width - 4)))
        extra.columnconfigure((0, 1), weight=1, uniform="options")
        extra.rowconfigure(0, weight=1)
        exceptions = app._card(extra, "Исключения", padding=(0, 0, 4, 0))
        ttk.Label(
            exceptions,
            text="Поддомены из этого списка пропускаются при обработке.",
            wraplength=280,
            style="CardMuted.TLabel",
        ).pack(anchor="w", pady=6)
        self.excluded = named(app._text(exceptions, 4, expand=True), "Исключения zapret2")
        self.excluded.insert("1.0", saved.exclude_domains)
        ports = app._card(extra, "Порты назначения", column=1, padding=(4, 0, 0, 0))
        app._caption(ports, "Сеть")
        named(
            ttk.Combobox(
                ports, textvariable=self.family, values=tuple(FAMILIES.values()), state="readonly"
            ),
            "Семейство IP",
        ).pack(fill="x")
        app._caption(ports, "Набор портов")
        chooser = named(
            ttk.Combobox(
                ports,
                textvariable=self.port_profile,
                values=(*PORT_SETS, "Свой набор"),
                state="readonly",
            ),
            "Набор портов",
        )
        chooser.pack(fill="x")
        chooser.bind("<<ComboboxSelected>>", self._port_set)
        for label, var in (("TCP для HTTPS", self.tcp), ("UDP для QUIC", self.udp)):
            app._caption(ports, label)
            field = named(ttk.Entry(ports, textvariable=var), label)
            field.pack(fill="x")
            if var is self.udp:
                self.udp_field = field
        ttk.Label(
            ports,
            text="Обычно достаточно порта 443. Дополнительные порты укажите через запятую.",
            style="CardMuted.TLabel",
            wraplength=278,
        ).pack(anchor="w", pady=6)
        self._strategy()
        self.tcp.trace_add("write", self._port_name)
        self.udp.trace_add("write", self._port_name)
        shell = NeonFrame(engine)
        shell.pack(fill="both", expand=True)
        service = ttk.Frame(shell.body, padding=(14, 10))
        service.pack(fill="both", expand=True)
        ttk.Label(service, textvariable=self.component, style="Section.TLabel").pack(anchor="w")
        ttk.Label(
            service,
            text="Windows x64 · сборка 6b4375fa · 3,7 МиБ. Для установки FLURUX проверит семь файлов и запросит разрешение Windows.",
            style="Muted.TLabel",
            wraplength=570,
        ).pack(anchor="w", pady=(4, 11))
        buttons = ttk.Frame(service)
        buttons.pack(anchor="w")
        self.setup = ttk.Button(
            buttons, command=lambda: self.operate("install"), style="Primary.TButton"
        )
        self.setup.pack(side="left")
        self.offline = ttk.Button(buttons, text="Из ZIP…", command=self.from_zip)
        self.offline.pack(side="left", padx=5)
        self.verify = ttk.Button(
            buttons, text="Проверить файлы", command=lambda: self.operate("verify")
        )
        self.verify.pack(side="left")
        self.delete = ttk.Button(service, text="Удалить движок…", command=self.remove)
        self.delete.pack(anchor="w", pady=8)
        ttk.Button(
            service, text="Справка по zapret2", command=lambda: app.help.show("zapret")
        ).pack(anchor="w")
        ttk.Button(
            service,
            text="Скачать ZIP этой версии",
            command=lambda: webbrowser.open(
                f"https://github.com/bol-van/zapret-win-bundle/archive/{bundle.REVISION}.zip"
            ),
        ).pack(anchor="w", pady=(4, 0))
        self.cancel_button = ttk.Button(service, text="Отменить загрузку", command=self.cancel.set)
        footer = ttk.Frame(self)
        self.footer = footer
        footer.grid(row=2, column=0, sticky="ew", pady=(7, 0))
        self.run = ttk.Button(footer, style="Primary.TButton", command=self.primary)
        self.run.pack(side="left")
        self.stop = ttk.Button(footer, text="Остановить", command=app.stop)
        self.stop.pack(side="left", padx=5)
        self.save = ttk.Button(footer, text="Сохранить", command=app.save_zapret)
        self.save.pack(side="left")
        self.component_link = ttk.Button(
            footer, textvariable=self.component, command=self.show_engine
        )
        self.component_link.pack(side="right")
        feedback = ttk.Label(self, textvariable=self.notice, style="Muted.TLabel", wraplength=710)
        feedback.grid(row=3, column=0, sticky="ew", pady=(5, 0))
        feedback.bind("<Configure>", lambda e: feedback.configure(wraplength=max(180, e.width - 4)))

        self.pages.bind("<<NotebookTabChanged>>", self._page_changed)

    def _apply_preset(self, event: object = None, *, test: bool = False) -> None:
        selected = self.catalog.selection()
        if not selected:
            self.notice.set("Выберите строку в каталоге.")
            return
        preset = PRESETS[int(selected[0])]
        self.app.strategy.set(STRATEGIES[preset.method])
        self.family.set(FAMILIES[preset.family])
        self.tcp.set(preset.ports)
        self.udp.set(preset.ports)
        self.notice.set("Выбран профиль · " + preset.label)
        if test:
            self.app.diagnostics.open("selected")
        else:
            self.pages.select(self.route)  # type: ignore[no-untyped-call]

    def _page_changed(self, event: object = None) -> None:
        if self.pages.select() == str(self.engine):  # type: ignore[no-untyped-call]
            self.footer.grid_remove()
        else:
            self.footer.grid()

    def _port_set(self, event: object = None) -> None:
        ports = PORT_SETS.get(self.port_profile.get())
        if ports:
            self.tcp.set(ports)
            self.udp.set(ports)

    def _port_name(self, *args: str) -> None:
        self.port_profile.set(
            next(
                (k for k, v in PORT_SETS.items() if v == self.tcp.get() == self.udp.get()),
                "Свой набор",
            )
        )

    def _strategy(self, *args: str) -> None:
        self.hint.set(HINTS.get(self.app.strategy.get(), ""))
        if hasattr(self, "udp_field"):
            self.udp_field.state(
                ["!disabled"]
                if self.app.strategy.get() in [STRATEGIES[k] for k in QUIC_METHODS]
                else ["disabled"]
            )

    def show_engine(self) -> None:
        """Open the component management page."""
        self.pages.select(self.engine)  # type: ignore[no-untyped-call]

    def primary(self) -> None:
        """Choose the next step for the current component and session state."""
        if not self.present:
            self.show_engine()
            self.operate("install")
        else:
            self.app.start_zapret()

    def import_sites(self) -> None:
        """Merge a UTF-8 domain list into the current draft, validating before changing it."""
        path = filedialog.askopenfilename(
            parent=self, filetypes=[("Список доменов", "*.txt"), ("Все файлы", "*")]
        )
        if not path:
            return
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                raise ValueError("Выберите текстовый файл размером до 64 КБ.")
            sites = parse_domains(self.domains.get("1.0", "end") + "\n" + data.decode("utf-8-sig"))
            if len(",".join(sites)) > 12000:
                raise ValueError("Список превышает 12 000 символов.")
            self.domains.delete("1.0", "end")
            self.domains.insert("1.0", "\n".join(sites))
            self.notice.set(f"Доменов в списке · {len(sites)}. Нажмите «Сохранить».")
        except (OSError, ValueError) as exc:
            self.notice.set(str(exc))

    def export_sites(self) -> None:
        """Export only the normalized website list."""
        try:
            sites = parse_domains(self.domains.get("1.0", "end"))
            if not sites:
                raise ValueError("Список сайтов пуст.")
            path = filedialog.asksaveasfilename(
                parent=self,
                defaultextension=".txt",
                initialfile="zapret-sites.txt",
                filetypes=[("Список доменов", "*.txt")],
            )
            if path:
                Path(path).write_text("\n".join(sites) + "\n", encoding="utf-8")
        except (ValueError, OSError) as exc:
            self.notice.set(str(exc))

    def check(self) -> None:
        """Probe the entered address or the first site using the system route."""
        if not self.app.target.get().strip():
            try:
                sites = parse_domains(self.domains.get("1.0", "end"))
            except ValueError as exc:
                self.notice.set(str(exc))
                return
            if sites:
                self.app.target.set(sites[0])
        self.app.check(False)

    def from_zip(self) -> None:
        """Select an offline copy of the Windows bundle."""
        path = filedialog.askopenfilename(
            parent=self, title="Выберите ZIP сборки zapret2", filetypes=[("ZIP-архив", "*.zip")]
        )
        if path:
            self.operate("install", Path(path))

    def remove(self) -> None:
        """Confirm removal of the machine-wide engine files."""
        if messagebox.askyesno(
            "Удалить движок zapret2?",
            "Это затронет все окна FLURUX на компьютере. Списки сайтов и настройки сохранятся.",
            parent=self,
        ):
            self.operate("remove")

    def operate(self, action: str, source: Path | None = None) -> None:
        """Perform a maintenance job outside the Tk event loop."""
        if (
            self.app.admin
            or self.app.closing
            or self.busy
            or self.app.pending
            or self.app.downloading
            or self.app.diagnostics.busy
        ):
            return
        self.busy = action
        if action == "install":
            self.cancel_button.pack(anchor="w", pady=(4, 0))
        self.cancel.clear()
        self.notice.set(
            {
                "install": "Подготовка установки…",
                "verify": "Проверяем файлы движка…",
                "remove": "Подтвердите удаление в окне Windows.",
            }[action]
        )
        self.app._refresh_controls()

        def progress(message: str) -> None:
            self.app.events.put(Update("zapret", "component-progress", message))

        def worker() -> None:
            try:
                if action == "install":
                    bundle.install(source, self.cancel, progress)
                elif action == "verify":
                    bundle.verify_installed()
                else:
                    bundle.remove()
                event = Update(
                    "zapret",
                    "component-ok",
                    {
                        "install": "Движок готов. Укажите сайты и нажмите «Запустить zapret2».",
                        "verify": "Проверка завершена. Файлы совпадают с комплектом FLURUX.",
                        "remove": "Движок удалён. Списки сайтов сохранены.",
                    }[action],
                )
            except (
                OSError,
                ValueError,
                zipfile.BadZipFile,
                RuntimeError,
                http.client.HTTPException,
                subprocess.SubprocessError,
            ) as exc:
                note = (
                    "Операция отменена в окне Windows."
                    if getattr(exc, "winerror", None) == 1223
                    else str(exc)
                )
                event = Update("zapret", "component-error", note)
            self.app.events.put(event)

        threading.Thread(target=worker, daemon=True).start()

    def update_job(self, event: Update) -> None:
        """Apply progress or completion for the active maintenance operation."""
        self.notice.set(event.message)
        if event.kind == "component-progress":
            if event.message.startswith("Подтвердите"):
                self.cancel_button.pack_forget()
            return
        self.cancel_button.pack_forget()
        if event.kind == "component-ok" and self.busy == "install":
            self.pages.select(self.route)  # type: ignore[no-untyped-call]
            self.domains.focus_set()
        self.installed_folder = bundle.engine_folder().is_dir()
        self.present = (bundle.engine_folder() / "winws2.exe").is_file()
        ok = event.kind == "component-ok"
        self.component.set(
            ("Движок проверен" if ok else "Проверить движок")
            if self.present
            else "Требуется установка"
        )
        self.busy = ""
        self.app._log("zapret", event.message)
        self.app._refresh_controls()

    def controls(self) -> None:
        """Keep the primary action and availability synchronized across the two screens."""
        app = self.app
        active = bool(app.pending) or app.downloading
        pure = bool(app.pending) and app.expected_engines == {"zapret"}
        stopping = app.session is not None and app.session.stop.is_set()
        locked = bool(self.busy) or app.closing or app.admin or app.diagnostics.busy
        self.session_state.set(str(app.status["zapret"].cget("text")))
        self.setup.configure(text="Восстановить движок" if self.present else "Установить движок")
        self.run.configure(
            text="Перезапустить"
            if pure
            else "Запустить zapret2"
            if self.present
            else "Установить движок",
            state="normal"
            if not locked and (not active or (pure and not stopping))
            else "disabled",
        )
        self.stop.configure(state="normal" if pure and not stopping and not locked else "disabled")
        self.probe.configure(
            state="disabled"
            if app.check_running or app.closing or app.diagnostics.busy
            else "normal"
        )
        for button in (self.setup, self.offline, self.verify, self.delete):
            enabled = (
                not locked
                and not active
                and (self.installed_folder or button in (self.setup, self.offline))
            )
            button.configure(state="normal" if enabled else "disabled")
