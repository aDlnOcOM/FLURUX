import os
import subprocess
import threading
import tkinter as tk
import webbrowser
from collections.abc import Mapping
from datetime import datetime
from functools import partial
from pathlib import Path
from queue import Empty, SimpleQueue
from tkinter import filedialog, messagebox, ttk

from route_manager.accessibility import AccessibleControls, named
from route_manager.advanced_gui import AdvancedPanel
from route_manager.chrome import WindowBar
from route_manager.config import (
    MODES,
    STRATEGIES,
    TOR_CHECK,
    TRANSPORTS,
    Settings,
    load_settings,
    prepare_tor,
    prepare_zapret,
    save_settings,
    socks_port,
    validated_url,
    webtunnel_domains,
)
from route_manager.help_gui import HelpPanel
from route_manager.private_files import private_directory
from route_manager.runtime import Session, Update, check_route
from route_manager.security import program_files, protected_path
from route_manager.theme import (
    ACCENT,
    EDGE,
    HERO,
    INK,
    INPUT,
    PANEL,
    TEXT,
    VERSION,
    NeonFrame,
    apply_style,
    text_navigation,
)
from route_manager.tor_bundle import install_bundle, installed_tor

ZAPRET_LINK = "https://github.com/bol-van/zapret-win-bundle"
TOR_LINK = "https://www.torproject.org/download/tor/"
BRIDGE_LINK = "https://support.torproject.org/ru/tor-browser/circumvention/getting-bridges/"
MODE_HELP = {
    "zapret": "Прямой доступ по списку доменов. Пакеты обрабатывает локальный winws2.",
    "tor": "Доступ через Tor для приложений с SOCKS5. Можно открыть отдельное окно Edge.",
    "both": "Обычный браузер использует zapret2. Клиенты SOCKS5 одновременно работают через Tor.",
    "cascade": "zapret2 обрабатывает TLS к мостам WebTunnel на 443. Затем трафик идёт через Tor.",
}


def select_key(values: Mapping[str, str], display: str) -> str:
    """Resolve a combobox label to its configuration key."""
    return next(key for key, label in values.items() if label == display)


class App:
    """Tkinter window for selecting, starting and checking routes."""

    def __init__(self, root: tk.Tk, data: Path, entry: Path, *, admin: bool = False) -> None:
        self.root = root
        self.admin = admin
        legacy_settings = data / "settings.json"
        if admin:
            app_dir = program_files() / "FLURUX"
            protected_path(app_dir)
            data = private_directory(app_dir / "AdminData", admin=True)
        else:
            data = private_directory(Path(os.environ["LOCALAPPDATA"]) / "FLURUX")
        self.data = data
        self.entry = entry
        self.settings_path = data / "settings.json"
        load_error = ""
        try:
            if not admin and legacy_settings != self.settings_path and legacy_settings.exists():
                old = load_settings(legacy_settings)
                if not self.settings_path.exists():
                    save_settings(self.settings_path, old)
            saved = load_settings(self.settings_path)
        except (OSError, ValueError) as exc:
            saved = Settings()
            load_error = str(exc)
        self.events: SimpleQueue[Update] = SimpleQueue()
        self.download_stop = threading.Event()
        self.downloading = False
        self.session: Session | None = None
        self.pending: set[str] = set()
        self.tor_ready = False
        self.tor_port: int | None = None
        self.check_running = False
        self.check_stop = threading.Event()
        self.closing = False
        self.log_count = 0
        self.status: dict[str, ttk.Label] = {}
        self.ready_engines: set[str] = set()
        self.expected_engines: set[str] = set()
        self.overview = tk.StringVar(value="Отключено")
        self.mode = tk.StringVar(value=MODES.get(saved.mode, MODES["both"]))
        self.mode_help = tk.StringVar()
        self.winws = tk.StringVar(value=saved.winws)
        self.strategy = tk.StringVar(value=STRATEGIES.get(saved.strategy, STRATEGIES["split"]))
        cached = installed_tor(data)
        self.tor = tk.StringVar(value=saved.tor or (str(cached) if cached.is_file() else ""))
        self.transport = tk.StringVar(
            value=TRANSPORTS.get(saved.transport, TRANSPORTS["webtunnel"])
        )
        self.port = tk.StringVar(value=saved.socks_port)
        self.target = tk.StringVar(value=saved.target)
        self.probe_result = tk.StringVar(value="Проверка ещё не запускалась.")
        self.bridge_sets = {
            "webtunnel": saved.webtunnel_bridges,
            "obfs4": saved.obfs4_bridges,
            "snowflake": saved.snowflake_bridges,
            "direct": "",
        }
        self.shown_transport = select_key(TRANSPORTS, self.transport.get())
        self.bridge_hint = tk.StringVar()

        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FLURUX.Desktop")
        root.title("FLURUX · Системный VPN" if admin else "FLURUX")
        app_icon = entry.parent / "FLURUX.ico"
        if app_icon.is_file():
            root.iconbitmap(str(app_icon))  # type: ignore[no-untyped-call]  # Tk stubs
        root.geometry(
            f"{min(1080, max(800, root.winfo_screenwidth() - 72))}x{min(690, max(590, root.winfo_screenheight() - 110))}"
        )
        root.minsize(800, 590)
        root.protocol("WM_DELETE_WINDOW", self.close)
        apply_style(root)
        shell = NeonFrame(root, cut=7)
        shell.pack(fill="both", expand=True)
        header = ttk.Frame(shell.body, padding=(13, 2, 1, 2))
        header.pack(fill="x")
        self.chrome = WindowBar(root, header, self.close, VERSION, admin)
        ttk.Separator(shell.body).pack(fill="x")
        outer = ttk.Frame(shell.body, padding=(12, 7, 12, 9))
        outer.pack(fill="both", expand=True)
        tabs = named(ttk.Notebook(outer, style="Main.TNotebook"), "Разделы FLURUX")
        tabs.pack(fill="both", expand=True)
        connection = ttk.Frame(tabs)
        settings = ttk.Frame(tabs)
        journal = ttk.Frame(tabs)
        tabs.add(connection, text="Подключение")
        tabs.add(settings, text="Настройки")
        tabs.add(journal, text="Журнал")
        connection_controls = ttk.Frame(connection)
        settings_controls = ttk.Frame(settings)
        self._connection(connection_controls)
        self._settings(settings_controls, saved.domains)
        if not admin:
            connection_controls.pack(fill="both", expand=True)
            settings_controls.pack(fill="both", expand=True)
        self._journal(journal)
        self.advanced = AdvancedPanel(tabs, data, admin=admin)
        self.user_tabs = {
            "connection": connection,
            "settings": settings,
            "mesh": self.advanced.mesh_page,
        }
        tabs.insert(1, self.advanced.page)
        tabs.insert(2, self.advanced.mesh_page)
        tabs.enable_traversal()
        if admin:
            for name, page in self.user_tabs.items():
                ttk.Label(
                    page,
                    text="Этот раздел открывается в обычном окне FLURUX. Системный VPN продолжит работу в этом окне.",
                    wraplength=530,
                ).pack(anchor="w", padx=14, pady=14)
                ttk.Button(
                    page,
                    text="Открыть в обычном режиме",
                    command=partial(self.open_user_tab, name),
                ).pack(anchor="w", padx=14)
            tabs.select(self.advanced.page)  # type: ignore[no-untyped-call]
        self.help = HelpPanel(tabs)

        def context_help(event: object = None) -> str:
            where = tabs.tab(tabs.select(), "text")  # type: ignore[no-untyped-call]  # Tk stubs
            current = select_key(MODES, self.mode.get())
            key = {
                "Каскады": self.advanced.current["kind"],
                "Mesh": "mesh",
                "Настройки": "settings",
                "Журнал": "journal",
                "Подключение": current if current in ("tor", "zapret") else "both",
            }.get(where, "home")
            self.help.show(key)
            return "break"

        root.bind("<F1>", context_help)
        ttk.Button(
            self.advanced.footer,
            text="Справка · F1",
            command=lambda: self.help.show(self.advanced.current["kind"]),
        ).grid(row=0, column=1, sticky="e", padx=(6, 0))
        self.accessibility = AccessibleControls(root)
        self._mode_changed()
        self._transport_changed()
        self._refresh_controls()
        if load_error:
            self._log("app", f"Настройки не загружены. {load_error}")
        root.after(100, self._poll)

    def open_user_tab(self, tab: str) -> None:
        """Open an ordinary FLURUX window at the selected page via Explorer."""
        exe = self.entry.parent / "FLURUX.exe"
        if not exe.is_file():
            messagebox.showinfo(
                "FLURUX", "Откройте FLURUX в обычном режиме через меню «Пуск».", parent=self.root
            )
            return
        try:
            subprocess.Popen([str(exe), "/ordinary", tab], cwd=exe.parent)
        except OSError as error:
            messagebox.showerror("FLURUX", str(error), parent=self.root)

    def _card(
        self,
        parent: ttk.Frame,
        title: str,
        row: int = 0,
        column: int = 0,
        *,
        padding: tuple[int, ...] = (0, 0, 0, 0),
    ) -> ttk.Frame:
        panel = NeonFrame(parent, surface=PANEL, gold=False, cut=7)
        panel.grid(
            row=row,
            column=column,
            sticky="nsew",
            padx=(padding[0], padding[2]),
            pady=(padding[1], padding[3]),
        )
        card = panel.body
        card.configure(padding=(9, 5))
        heading = ttk.Frame(card, style="Card.TFrame")
        heading.pack(anchor="w")
        tk.Frame(heading, bg=ACCENT, width=3, height=15, takefocus=False).pack(
            side="left", padx=(0, 8)
        )
        ttk.Label(heading, text=title, style="CardHeading.TLabel").pack(side="left")
        return card

    def _connection(self, parent: ttk.Frame) -> None:
        parent.columnconfigure((0, 1), weight=1, uniform="routes")
        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=2)
        hero_frame = NeonFrame(parent, surface=HERO, cut=12)
        hero_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        hero = hero_frame.body
        hero.columnconfigure(0, weight=6, uniform="hero")
        hero.columnconfigure(1, weight=5, uniform="hero")
        hero.rowconfigure(0, weight=1)

        overview = ttk.Frame(hero, style="Hero.TFrame", padding=(20, 10))
        overview.grid(row=0, column=0, sticky="w")
        ttk.Label(overview, text="СОСТОЯНИЕ МАРШРУТА", style="Kicker.TLabel").pack(anchor="w")
        ttk.Label(overview, textvariable=self.overview, style="HeroTitle.TLabel").pack(
            anchor="w", pady=(3, 7)
        )
        engines = ttk.Frame(overview, style="Hero.TFrame")
        engines.pack(anchor="w")
        for column, (engine, title) in enumerate((("tor", "Tor"), ("zapret", "zapret2"))):
            box = ttk.Frame(engines, style="Hero.TFrame")
            box.grid(row=0, column=column, sticky="nw", padx=(0, 18))
            ttk.Label(box, text=title, style="Engine.TLabel").pack(anchor="w")
            label = ttk.Label(box, text="Остановлен", style="EngineState.TLabel", wraplength=144)
            label.pack(anchor="w")
            self.status[engine] = label
        art = tk.Canvas(
            hero, bg=HERO, highlightthickness=0, borderwidth=0, width=1, height=1, takefocus=False
        )
        art.grid(row=0, column=1, sticky="nsew", padx=(0, 4), pady=2)
        self.route_art = tk.PhotoImage(
            master=self.root, file=Path(__file__).with_name("assets") / "route.png"
        )
        image = art.create_image(0, 0, image=self.route_art)
        art.bind("<Configure>", lambda e: art.coords(image, e.width / 2, e.height / 2))

        profile = self._card(parent, "Маршрут", row=1, column=0, padding=(0, 0, 5, 0))
        self._caption(profile, "Режим подключения")
        self.mode_box = self._choice(profile, self.mode, MODES)
        self.mode_box.pack(fill="x")
        self.mode_box.bind("<<ComboboxSelected>>", self._mode_changed)
        instructions = ttk.Label(
            profile, textvariable=self.mode_help, style="CardMuted.TLabel", wraplength=320
        )
        instructions.pack(anchor="w", pady=(7, 8), fill="x")
        instructions.bind(
            "<Configure>", lambda e: instructions.configure(wraplength=max(120, e.width - 4))
        )
        actions = ttk.Frame(profile, style="Card.TFrame")
        actions.pack(fill="x")
        self.start_button = ttk.Button(
            actions, text="Запустить", style="Primary.TButton", command=self.start
        )
        self.start_button.pack(side="left", padx=(0, 6))
        self.stop_button = ttk.Button(actions, text="Остановить", command=self.stop)
        self.stop_button.pack(side="left")
        proxy = ttk.Frame(profile, style="Card.TFrame")
        proxy.pack(fill="x", side="bottom", pady=(7, 0))
        ttk.Separator(proxy).pack(fill="x", pady=(0, 6))
        ttk.Label(proxy, text="Клиенты Tor", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 3))
        client_actions = ttk.Frame(proxy, style="Card.TFrame")
        client_actions.pack(anchor="w")
        self.edge_button = ttk.Button(client_actions, text="Edge через Tor", command=self.open_edge)
        self.edge_button.pack(side="left", padx=(0, 5))
        self.copy_button = ttk.Button(
            client_actions, text="Копировать SOCKS5", command=self.copy_proxy
        )
        self.copy_button.pack(side="left")

        check = self._card(parent, "Проверка доступа", row=1, column=1, padding=(5, 0, 0, 0))
        self._caption(check, "Адрес сайта")
        self.target_field = named(ttk.Entry(check, textvariable=self.target), "Адрес сайта")
        self.target_field.pack(fill="x")
        controls = ttk.Frame(check, style="Card.TFrame")
        controls.pack(fill="x", pady=(8, 5))
        self.direct_check = ttk.Button(
            controls, text="Без SOCKS5", command=lambda: self.check(False)
        )
        self.direct_check.pack(side="left", padx=(0, 6))
        self.tor_check = ttk.Button(controls, text="Через Tor", command=lambda: self.check(True))
        self.tor_check.pack(side="left")
        self.ip_check = ttk.Button(
            check, text="Подтвердить выход Tor", command=lambda: self.check(True, identity=True)
        )
        self.ip_check.pack(anchor="w", pady=(0, 5))
        feedback = ttk.Frame(check, style="Card.TFrame")
        feedback.pack(side="bottom", fill="x")
        ttk.Separator(feedback).pack(fill="x", pady=(0, 6))
        ttk.Label(feedback, text="Результат проверки", style="Card.TLabel").pack(
            anchor="w", pady=(0, 3)
        )
        result = ttk.Label(
            feedback, textvariable=self.probe_result, style="CardMuted.TLabel", wraplength=290
        )
        result.pack(anchor="w", fill="x")
        result.bind("<Configure>", lambda e: result.configure(wraplength=max(120, e.width - 4)))

    def _settings(self, parent: ttk.Frame, domains: str) -> None:
        parent.columnconfigure((0, 1), weight=1, uniform="settings")
        parent.rowconfigure(0, weight=1)
        zapret = self._card(parent, "zapret2", padding=(0, 0, 7, 0))
        tor = self._card(parent, "Tor", column=1, padding=(7, 0, 0, 0))
        self._caption(zapret, "Системный движок")
        ttk.Label(
            zapret,
            text="Помощник FLURUX входит в установщик. Добавьте проверенный комплект zapret2 по инструкции в справке.",
            style="CardMuted.TLabel",
            wraplength=270,
        ).pack(anchor="w")
        self._caption(zapret, "Стратегия")
        self._choice(zapret, self.strategy, STRATEGIES).pack(fill="x")
        self._caption(zapret, "Домены для zapret2")
        self.domains = named(self._text(zapret, 4), "Домены для zapret2")
        self.domains.insert("1.0", domains)
        ttk.Label(
            zapret,
            text="По одному на строку. В каскаде адреса мостов добавляются автоматически.",
            style="CardMuted.TLabel",
            wraplength=275,
        ).pack(anchor="w", pady=(6, 9))
        ttk.Button(
            zapret, text="Сохранить настройки", style="Primary.TButton", command=self.save
        ).pack(anchor="w", pady=(5, 0))

        self.settings_feedback = tk.StringVar()
        ttk.Label(
            zapret, textvariable=self.settings_feedback, style="CardMuted.TLabel", wraplength=260
        ).pack(anchor="w")
        self._file_field(tor, "Файл tor.exe", self.tor, "tor.exe", TOR_LINK)
        self._caption(tor, "Транспорт")
        box = self._choice(tor, self.transport, TRANSPORTS)
        box.pack(fill="x")
        box.bind("<<ComboboxSelected>>", self._transport_changed)
        self._caption(tor, "Строки мостов")
        self.bridges = named(self._text(tor, 4), "Строки мостов")
        self.bridges.insert("1.0", self.bridge_sets[self.shown_transport])
        ttk.Label(
            tor, textvariable=self.bridge_hint, style="CardMuted.TLabel", wraplength=304
        ).pack(anchor="w", pady=(5, 6))
        extra = ttk.Frame(tor, style="Card.TFrame")
        extra.pack(fill="x")
        ttk.Label(extra, text="Порт SOCKS5", style="Card.TLabel").pack(side="left", padx=(0, 5))
        named(ttk.Entry(extra, textvariable=self.port, width=6), "Порт SOCKS5").pack(side="left")
        ttk.Button(extra, text="Получить мосты", command=lambda: webbrowser.open(BRIDGE_LINK)).pack(
            side="right"
        )

    def _journal(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Журнал событий", style="Section.TLabel").pack(
            anchor="w", pady=(0, 6)
        )
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", pady=(0, 7))
        ttk.Button(toolbar, text="Копировать", command=self.copy_log).pack(side="left", padx=(0, 7))
        ttk.Button(toolbar, text="Очистить", command=self.clear_log).pack(side="left")
        log_border = NeonFrame(parent, gold=False)
        log_border.pack(fill="both", expand=True)
        log_frame = log_border.body
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")
        self.journal = named(self._text(log_frame, 12, expand=True), "Журнал событий")
        self.journal.configure(
            yscrollcommand=scrollbar.set, font=("Consolas", 10), state="disabled"
        )
        scrollbar.configure(command=self.journal.yview)

    def _file_field(
        self, parent: ttk.Frame, title: str, variable: tk.StringVar, name: str, link: str
    ) -> None:
        self._caption(parent, title)
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x")
        named(ttk.Entry(row, textvariable=variable, width=17), title).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(row, text="Обзор", command=lambda: self.choose_file(variable, name)).pack(
            side="left", padx=(5, 0)
        )
        ttk.Button(parent, text="Официальная сборка", command=lambda: webbrowser.open(link)).pack(
            anchor="w", pady=(5, 0)
        )

    @staticmethod
    def _choice(parent: ttk.Frame, value: tk.StringVar, values: Mapping[str, str]) -> ttk.Combobox:
        label = (
            "Режим подключения"
            if values is MODES
            else "Стратегия"
            if values is STRATEGIES
            else "Транспорт"
        )
        return named(
            ttk.Combobox(
                parent, textvariable=value, values=tuple(values.values()), state="readonly"
            ),
            label,
        )

    @staticmethod
    def _caption(parent: ttk.Frame, text: str) -> None:
        ttk.Label(parent, text=text, style="Card.TLabel").pack(anchor="w", pady=(8, 3))

    @staticmethod
    def _text(parent: ttk.Frame, height: int, *, expand: bool = False) -> tk.Text:
        text = tk.Text(
            parent,
            font=("Segoe UI", 10),
            height=height,
            width=1,
            wrap="word",
            background=INPUT,
            foreground=TEXT,
            insertbackground=TEXT,
            selectbackground=ACCENT,
            selectforeground=INK,
            highlightthickness=1,
            highlightbackground=EDGE,
            highlightcolor=ACCENT,
            borderwidth=0,
            padx=7,
            pady=6,
            undo=True,
        )
        text.pack(fill="both" if expand else "x", expand=expand)
        text_navigation(text)
        return text

    def _mode_changed(self, event: "tk.Event[tk.Misc] | None" = None) -> None:
        self.mode_help.set(MODE_HELP[select_key(MODES, self.mode.get())])

    def _transport_changed(self, event: "tk.Event[tk.Misc] | None" = None) -> None:
        self.bridge_sets[self.shown_transport] = self.bridges.get("1.0", "end-1c")
        self.shown_transport = select_key(TRANSPORTS, self.transport.get())
        self.bridges.configure(state="normal")
        self.bridges.delete("1.0", "end")
        self.bridges.insert("1.0", self.bridge_sets[self.shown_transport])
        if self.shown_transport == "direct":
            self.bridges.configure(state="disabled")
        hints = {
            "direct": "Прямое подключение к сети Tor.",
            "snowflake": "Пустое поле: мосты из сборки Tor.",
        }
        self.bridge_hint.set(
            hints.get(self.shown_transport, "Вставьте полные строки, по одной на строку.")
        )

    def _settings_snapshot(self) -> Settings:
        self.bridge_sets[self.shown_transport] = self.bridges.get("1.0", "end-1c")
        return Settings(
            mode=select_key(MODES, self.mode.get()),
            winws=self.winws.get().strip(),
            strategy=select_key(STRATEGIES, self.strategy.get()),
            domains=self.domains.get("1.0", "end-1c"),
            tor=self.tor.get().strip(),
            transport=self.shown_transport,
            socks_port=self.port.get().strip(),
            target=self.target.get().strip(),
            webtunnel_bridges=self.bridge_sets["webtunnel"],
            obfs4_bridges=self.bridge_sets["obfs4"],
            snowflake_bridges=self.bridge_sets["snowflake"],
        )

    def choose_file(self, variable: tk.StringVar, name: str) -> None:
        """Select an executable from an extracted distribution."""
        path = filedialog.askopenfilename(
            parent=self.root,
            title=f"Выберите {name}",
            filetypes=[(name, name), ("Исполняемые файлы", "*.exe")],
        )
        if path:
            variable.set(path)

    def save(self) -> None:
        """Save the editable fields, including independent bridge lists."""
        try:
            settings = self._settings_snapshot()
            if settings.mode != "zapret":
                socks_port(settings.socks_port)
            save_settings(self.settings_path, settings)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Настройки", str(exc), parent=self.root)
            return
        self.settings_feedback.set(f"Сохранено в {datetime.now():%H:%M:%S}")
        self._log(
            "app",
            "Настройки сохранены. При активном подключении изменения вступят в силу после перезапуска маршрута.",
        )

    def _get_tor(self) -> None:
        if not messagebox.askokcancel(
            "Первое подключение через Tor",
            "Скачать Tor (23 МБ) с сайта Tor Project и подключиться? FLURUX проверит файл и сохранит его для следующих запусков.",
            parent=self.root,
        ):
            return
        self.downloading = True
        self.download_stop.clear()
        self.status["tor"].configure(text="Загрузка Tor…")
        self._refresh_controls()

        def download() -> None:
            try:
                exe = install_bundle(
                    self.data,
                    self.download_stop,
                    lambda n: self.events.put(Update("tor", "progress", f"Загрузка Tor · {n}%")),
                )
                event = Update("tor", "downloaded", str(exe))
            except (OSError, ValueError) as exc:
                event = Update("tor", "download-error", str(exc))
            self.events.put(event)

        threading.Thread(target=download, daemon=True).start()

    def start(self) -> None:
        """Validate and launch the chosen session."""
        if self.admin or self.closing or self.pending or self.downloading:
            return
        try:
            settings = self._settings_snapshot()
            if settings.mode != "zapret":
                socks_port(settings.socks_port)
            if settings.mode != "zapret" and not settings.tor:
                self._get_tor()
                return
            cascade = settings.mode == "cascade"
            tor = prepare_tor(settings) if settings.mode != "zapret" else None
            bridge_domains = webtunnel_domains(tor) if cascade and tor else ()
            zapret = prepare_zapret(settings, bridge_domains) if settings.mode != "tor" else None
            save_settings(self.settings_path, settings)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Проверьте настройки", str(exc), parent=self.root)
            return
        self.tor_ready = False
        self.tor_port = tor.port if tor else None
        self.pending = {name for name, enabled in (("zapret", zapret), ("tor", tor)) if enabled}
        self.ready_engines.clear()
        self.expected_engines = set(self.pending)
        for engine, label in self.status.items():
            label.configure(
                text="Запуск…" if engine in self.pending else "Остановлен",
                style="EngineState.TLabel",
            )
        self._log("app", f"Выбран режим {MODES[settings.mode]}.")
        self.session = Session(self.data, self.entry, self.events)
        self.session.start(zapret, tor, cascade)
        self._refresh_controls()

    def stop(self) -> None:
        """Request the stop of both managed engines."""
        if self.downloading:
            self.download_stop.set()
            self.status["tor"].configure(text="Отмена загрузки…")
        if self.session:
            self.session.stop.set()
            self.tor_ready = False
        self._refresh_controls()

    def check(self, via_tor: bool, *, identity: bool = False) -> None:
        """Probe a URL or verify that the public endpoint sees a Tor exit."""
        if self.admin or self.closing or self.check_running or (via_tor and not self.tor_ready):
            return
        try:
            url = TOR_CHECK if identity else validated_url(self.target.get())
        except ValueError as exc:
            self.probe_result.set(str(exc))
            return
        self.check_running = True
        self.probe_result.set("Проверка…")
        self._refresh_controls()
        port = self.tor_port if via_tor else None
        route = "Tor" if via_tor else "Без SOCKS5"

        def run() -> None:
            try:
                result = check_route(url, port, tor_check=identity, stop=self.check_stop)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                result = f"Ошибка · {exc}"
            self.events.put(Update("check", "check", f"{route} · {result}"[:450]))

        threading.Thread(target=run, daemon=True).start()

    def copy_proxy(self) -> None:
        """Copy the active proxy address."""
        if self.tor_ready and self.tor_port:
            self._copy(f"socks5h://127.0.0.1:{self.tor_port}")
            self.probe_result.set(f"SOCKS5 · 127.0.0.1:{self.tor_port} · адрес скопирован")

    def open_edge(self) -> None:
        """Open a separate Edge profile configured to use only the Tor SOCKS proxy for browsing."""
        if not self.tor_ready or not self.tor_port:
            return
        candidates = [
            Path(os.environ[key]) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            for key in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")
            if key in os.environ
        ]
        edge = next((path for path in candidates if path.is_file()), None)
        if not edge:
            messagebox.showerror(
                "Microsoft Edge",
                "Edge не найден. Скопируйте SOCKS5 для другого клиента.",
                parent=self.root,
            )
            return
        try:
            url = (
                validated_url(self.target.get())
                if self.target.get().strip()
                else "https://check.torproject.org/"
            )
            subprocess.Popen(
                [
                    str(edge),
                    f"--user-data-dir={self.data / f'edge-{self.tor_port}'}",
                    f"--proxy-server=socks5://127.0.0.1:{self.tor_port}",
                    "--proxy-bypass-list=<-loopback>",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--disable-quic",
                    "--disable-background-networking",
                    "--no-first-run",
                    "--new-window",
                    url,
                ],
                cwd=edge.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError) as exc:
            messagebox.showerror("Microsoft Edge", str(exc), parent=self.root)

    def _refresh_controls(self) -> None:
        active = bool(self.pending) or self.downloading
        stopping = (
            self.download_stop.is_set()
            if self.downloading
            else self.session is not None and self.session.stop.is_set()
        )
        if active and stopping:
            summary = "Остановка"
        elif self.downloading:
            summary = "Загрузка Tor"
        elif self.pending and self.expected_engines == self.ready_engines:
            summary = "Маршрут активен"
        elif any(str(label.cget("text")).startswith("Ошибка") for label in self.status.values()):
            summary = "Ошибка маршрута"
        elif self.pending:
            summary = "Подключение"
        else:
            summary = "Отключено"
        if self.overview.get() != summary:
            self.overview.set(summary)
        self.start_button.configure(state="disabled" if active or self.closing else "normal")
        self.stop_button.configure(state="normal" if active and not stopping else "disabled")
        self.mode_box.configure(state="disabled" if active else "readonly")
        for button in (self.copy_button, self.edge_button):
            button.configure(state="normal" if self.tor_ready else "disabled")
        self.direct_check.configure(state="disabled" if self.check_running else "normal")
        for button in (self.tor_check, self.ip_check):
            button.configure(
                state="normal" if self.tor_ready and not self.check_running else "disabled"
            )

    def _poll(self) -> None:
        self.chrome.dispatch()
        for _ in range(80):
            try:
                event = self.events.get_nowait()
            except Empty:
                break
            if event.kind == "progress":
                if not self.download_stop.is_set():
                    self.status["tor"].configure(text=event.message)
            elif event.kind in ("downloaded", "download-error"):
                self.downloading = False
                self._refresh_controls()
                self.status["tor"].configure(text="Остановлен")
                if not self.closing and not self.download_stop.is_set():
                    if event.kind == "downloaded":
                        self.tor.set(event.message)
                        self.start()
                    else:
                        messagebox.showerror("Загрузка Tor", event.message, parent=self.root)
            elif event.kind == "status":
                if event.ready:
                    self.ready_engines.add(event.engine)
                else:
                    self.ready_engines.discard(event.engine)
                style = "CardReady.TLabel" if event.ready else "EngineState.TLabel"
                if event.message.startswith("Ошибка"):
                    style = "CardError.TLabel"
                self.status[event.engine].configure(text=event.message, style=style)
                if event.engine == "tor":
                    self.tor_ready = (
                        event.ready and self.session is not None and not self.session.stop.is_set()
                    )
                self._refresh_controls()
            elif event.kind == "log":
                self._log(event.engine, event.message)
            elif event.kind == "done":
                self.pending.discard(event.engine)
                self._refresh_controls()
            elif event.kind == "check":
                self.check_running = False
                self.probe_result.set(event.message)
                self._log(event.engine, event.message)
                self._refresh_controls()
        if (
            self.closing
            and not self.pending
            and not self.downloading
            and not self.check_running
            and not (self.advanced.busy or self.advanced.mesh_busy)
        ):
            self.root.destroy()
        else:
            self.root.after(100, self._poll)

    def _log(self, engine: str, message: str) -> None:
        name = {"zapret": "zapret2", "tor": "Tor", "check": "Проверка"}.get(engine, "FLURUX")
        self.journal.configure(state="normal")
        for line in message.splitlines():
            self.journal.insert("end", f"{datetime.now():%H:%M:%S}  {name}  {line}\n")
            self.log_count += 1
        if self.log_count > 500:
            self.journal.delete("1.0", f"{self.log_count - 499}.0")
            self.log_count = 500
        self.journal.see("end")
        self.journal.configure(state="disabled")

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def copy_log(self) -> None:
        """Copy the visible log to the clipboard."""
        self._copy(self.journal.get("1.0", "end-1c"))

    def clear_log(self) -> None:
        """Clear the on-screen journal."""
        self.journal.configure(state="normal")
        self.journal.delete("1.0", "end")
        self.journal.configure(state="disabled")
        self.log_count = 0

    def close(self) -> None:
        """Stop managed processes before closing the window."""
        if self.closing:
            return
        self.closing = True
        self.check_stop.set()
        self.advanced.closing = True
        self.advanced.stop_event.set()
        self.stop()


def launch(data: Path, entry: Path, *, admin: bool = False, tab: str = "") -> None:
    """Run the desktop application on the main thread."""
    root = tk.Tk()
    app = App(root, data, entry, admin=admin)
    if not admin and tab in app.user_tabs:
        app.help.tabs.select(app.user_tabs[tab])  # type: ignore[no-untyped-call]
    root.mainloop()
