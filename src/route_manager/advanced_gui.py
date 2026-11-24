import copy
import os
import threading
import tkinter as tk
from collections.abc import Callable
from functools import partial
from pathlib import Path
from queue import Empty, SimpleQueue
from tkinter import filedialog, messagebox, ttk

from route_manager.form_view import FormView
from route_manager.private_files import clean_sessions, private_directory
from route_manager.profiles import (
    CHAIN_TYPES,
    STRATEGIES,
    TLS_TYPES,
    WG_TYPES,
    Obj,
    load_profiles,
    template,
    update_profile,
    validate,
)
from route_manager.routes import (
    binary,
    command,
    engine_name,
    mesh_peers,
    mesh_select,
    provision,
    start_route,
    synchronize,
)
from route_manager.security import unlock_network


class AdvancedPanel:
    """Edit route profiles and manage their SSH hosts and Tailscale peers."""

    def __init__(self, tabs: ttk.Notebook, data: Path, *, admin: bool = False) -> None:
        self.root = tabs.winfo_toplevel()
        self.admin = admin
        self.cache = data
        self.path = self.cache / "profiles.dpapi"
        self.saved: list[Obj] = []
        self.read_error = ""
        try:
            private_directory(self.cache, admin=admin)
            clean_sessions(private_directory(self.cache / "sessions-v3", admin=admin))
            self.saved = load_profiles(self.path)
            if admin:
                user_path = Path(os.environ["LOCALAPPDATA"]) / "FLURUX" / "profiles.dpapi"
                user_profiles = load_profiles(user_path)
                existing = {p["id"] for p in self.saved}
                self.saved.extend(p for p in user_profiles if p["id"] not in existing)
        except (ValueError, OSError) as error:
            self.read_error = "Хранилище профилей недоступно. " + str(error)
        self.queue: SimpleQueue[tuple[str, object]] = SimpleQueue()
        self.mesh_busy = False
        self.available_exits: set[str] = set()
        self.busy = False
        self.closing = False
        self.stop_event = threading.Event()
        self.modes = list(STRATEGIES)
        self.status = tk.StringVar(
            value=self.read_error or "Выберите стратегию и заполните параметры входа."
        )
        self.title = tk.StringVar()
        self.current: Obj = {}
        self.bindings: list[tuple[Obj, str, tk.StringVar | tk.BooleanVar]] = []
        self.page = ttk.Frame(tabs, padding=6)
        tabs.add(self.page, text="Каскады")
        self.page.columnconfigure(0, weight=1)
        self.page.rowconfigure(1, weight=1)
        form = ttk.Frame(self.page)
        form.grid(row=0, column=0, sticky="ew")
        self.kind = ttk.Combobox(
            form, values=[STRATEGIES[k][0] for k in self.modes], state="readonly", width=40
        )
        self.kind.current(0)
        self.kind.pack(side="left", fill="x", expand=True)
        self.kind.bind("<<ComboboxSelected>>", lambda _: self.new())
        self.new_button = ttk.Button(form, text="Новый профиль", command=self.new)
        self.new_button.pack(side="left", padx=5)
        self.pick = ttk.Combobox(form, state="readonly", width=24)
        self.pick.pack(side="left", fill="x", expand=True)
        self.pick.bind("<<ComboboxSelected>>", self.choose)
        self.editor = ttk.Notebook(self.page)
        self.editor.grid(row=1, column=0, sticky="nsew", pady=6)
        bar = ttk.Frame(self.page)
        bar.grid(row=2, column=0, sticky="ew")
        self.action_buttons = []
        for title, fn in (
            ("Сохранить", self.save),
            ("Настроить узлы по SSH", self.install),
            ("Подключить", self.start),
        ):
            button = ttk.Button(bar, text=title, command=fn)
            button.pack(side="left", padx=2)
            self.action_buttons.append(button)
        self.stop_button = ttk.Button(bar, text="Остановить", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=2)
        unlock = ttk.Button(bar, text="Снять блокировку сети", command=self.unlock)
        unlock.pack(side="left", padx=2)
        self.action_buttons.append(unlock)
        self.footer = ttk.Frame(self.page)
        self.footer.grid(row=3, column=0, sticky="ew")
        self.footer.columnconfigure(0, weight=1)
        self.status_label = ttk.Label(self.footer, textvariable=self.status, wraplength=570)
        self.status_label.grid(row=0, column=0, sticky="w")
        self.mesh_status = tk.StringVar(value="Нажмите «Обновить», чтобы загрузить список узлов.")
        self.mesh_buttons: list[ttk.Button] = []
        self.disabled_fields: list[ttk.Widget] = []
        mesh = ttk.Frame(tabs, padding=10)
        tabs.add(mesh, text="Mesh")
        ttk.Label(mesh, text="Узлы Tailscale").pack(anchor="w")
        self.peers = ttk.Treeview(
            mesh, columns=("ip", "state", "exit"), show="tree headings", height=8
        )
        self.peers.heading("#0", text="Узел")
        for col, title in (("ip", "Адрес"), ("state", "Доступность"), ("exit", "Выход в интернет")):
            self.peers.heading(col, text=title)
            self.peers.column(col, width=110)
        self.peers.pack(fill="both", expand=True, pady=6)
        actions = ttk.Frame(mesh)
        actions.pack(fill="x")
        for title, fn in (
            ("Обновить", self.refresh_mesh),
            ("Проверить путь", self.ping_mesh),
            ("Выбрать выход", self.use_exit),
            ("Отключить выход", self.clear_exit),
        ):
            button = ttk.Button(actions, text=title, command=fn)
            button.pack(side="left", padx=2)
            self.mesh_buttons.append(button)
        ttk.Label(mesh, textvariable=self.mesh_status, wraplength=790).pack(anchor="w")
        self.peers.bind("<<TreeviewSelect>>", lambda _: self._mesh_controls())
        self._mesh_controls()
        self.refresh_names()
        self.edit(copy.deepcopy(self.saved[0]) if self.saved else template(self.modes[0]))
        self.root.after(100, self.poll)

    def refresh_names(self) -> None:
        """Refresh the list of saved profiles."""
        self.pick.configure(values=[p["name"] for p in self.saved])

    def new(self) -> None:
        """Open a fresh profile of the selected type."""
        if not self.busy and not self.closing and self._can_leave():
            self.pick.set("")
            self.edit(template(self.modes[self.kind.current()]))

    def choose(self, event: object = None) -> None:
        """Load one saved profile into the editor."""
        index = self.pick.current()
        if not self.busy and not self.closing and index >= 0 and self._can_leave():
            self.edit(copy.deepcopy(self.saved[index]))

    def _can_leave(self) -> bool:
        for node, key, var in self.bindings:
            node[key] = var.get()
        if self.current == self.baseline or messagebox.askyesno(
            "Несохранённый профиль",
            "Открыть другой профиль и отбросить внесённые изменения?",
            parent=self.root,
        ):
            return True
        self.kind.current(self.modes.index(self.current["kind"]))
        self.pick.set("")
        for i, saved in enumerate(self.saved):
            if saved["id"] == self.current["id"]:
                self.pick.current(i)
        return False

    def edit(self, p: Obj) -> None:
        """Build editable fields appropriate to each endpoint's role."""
        self.current = p
        for key, value in template(p["kind"]).items():
            p.setdefault(key, value)
        self.kind.current(self.modes.index(p["kind"]))
        self.bindings.clear()
        for child in self.editor.winfo_children():
            child.destroy()
        first = FormView(self.editor, "Профиль")
        main = first.body
        pages = [first]
        self.field(main, 0, p, "name", "Название")
        if engine_name(p["kind"]) != "python":
            self.field(main, 1, p, "engine_path", engine_name(p["kind"]) + ".exe", file=True)
        if p["kind"] not in ("ech", "awg", "mesh_exit", "mesh_relay"):
            self.field(main, 2, p, "local_port", "Локальный порт")
        if p["nodes"]:
            sync = tk.BooleanVar(value=p.get("sync_on_connect", True))
            self.bindings.append((p, "sync_on_connect", sync))
            ttk.Checkbutton(
                main,
                variable=sync,
                text="Сверять публичные ключи своих узлов по SSH при подключении",
            ).grid(row=6, column=0, columnspan=3, sticky="w")
        if p["kind"] in ("ech", "dns_tls", "dns_https"):
            self.field(main, 4, p, "access_cidr", "Разрешённая сеть CIDR для своего DNS")
        if p["kind"] in ("psiphon", "awg", "ssh", "ssh_single", "ech"):
            self.field(
                main,
                10,
                p,
                "engine_sha256",
                "SHA-256 из доверенного источника (для неподписанного EXE)",
            )
        if p["kind"] == "psiphon":
            self.field(main, 4, p, "psiphon_config", "Конфигурация Tunnel Core (JSON)", file=True)
            self.field(main, 5, p, "psiphon_servers", "Список серверов (необязательно)", file=True)
        if engine_name(p["kind"]) == "sing-box" and not p["kind"].startswith(("relay_", "dns_")):
            flag = tk.BooleanVar(value=p["system_tun"])
            self.bindings.append((p, "system_tun", flag))
            ttk.Checkbutton(
                main,
                variable=flag,
                text="Системный TUN для приложений Windows (нужны права администратора)",
            ).grid(row=3, column=0, columnspan=3, sticky="w")
            lock = tk.BooleanVar(value=p.get("network_lock", False))
            self.bindings.append((p, "network_lock", lock))
            ttk.Checkbutton(
                main,
                variable=lock,
                text="Блокировать интернет вне TUN, в том числе после остановки",
            ).grid(row=4, column=0, columnspan=3, sticky="w")

        if p["kind"] in {"relay_tcp", "relay_udp", "masque_udp"}:
            self.field(main, 4, p, "target_host", "Фиксированное назначение")
            self.field(main, 5, p, "target_port", "Порт назначения")
        if p["kind"] in ("chain", "socks_udp", "ovpn_http", "ovpn_socks", "tor_http", "tor_socks"):
            plain = tk.BooleanVar(value=p.get("allow_plain_proxy", False))
            self.bindings.append((p, "allow_plain_proxy", plain))
            ttk.Checkbutton(
                main,
                variable=plain,
                text="Разрешить передачу пароля прокси без шифрования первого участка",
            ).grid(row=9, column=0, columnspan=3, sticky="w")
        if p["kind"] in ("relay_tcp", "relay_udp"):
            self.field(main, 7, p, "access_cidr", "Разрешённая исходная сеть CIDR")
        hints = {
            "nested": "Компьютер устанавливает оба VPN. Внутренний туннель достигает выхода через первый.",
            "forwarded": "Входной сервер пересылает трафик во второй VPN. Для своей пары укажите SSH обоих узлов.",
            "mesh_exit": "Укажите адрес или DNS-имя узла Tailscale. После установки подтвердите выход в консоли tailnet.",
            "mesh_relay": "Укажите IP узла Tailscale и адрес SSH. Назначение relay требует разрешения в политике tailnet.",
            "awg": "Системный IPv4-туннель. Клиент AmneziaWG и этот интерфейс запускаются с правами администратора.",
            "ss_ws": "TCP через защищённый WebSocket. На клиенте и сервере используется Xray.",
            "masque_udp": "UDP передаётся внутри HTTPS через HTTP/1.1 Upgrade и капсулы DATAGRAM.",
            "masque_ip": "Для клиента и сервера нужен sing-box с поддержкой CONNECT-IP (1.15).",
        }
        ttk.Label(
            main,
            text=hints.get(
                p["kind"],
                "Для готового узла укажите адрес и реквизиты. Для своего добавьте SSH и нажмите «Настроить узлы по SSH».",
            ),
            wraplength=650,
        ).grid(row=8, column=0, columnspan=3, sticky="w", pady=8)
        for idx, n in enumerate(p["nodes"]):
            page = FormView(self.editor, ("Вход" if idx == 0 else "Выход") + " · " + n["type"])
            pages.append(page)
            frame = page.body
            self.field(frame, 0, n, "host", "Адрес подключения")
            self.field(frame, 1, n, "port", "Порт протокола")
            self.field(frame, 2, n, "ssh", "SSH · user@host или псевдоним")
            if p["kind"] == "chain":
                self.field(frame, 3, n, "type", "Протокол", options=CHAIN_TYPES)
            if p["kind"] == "ovpn_http" and idx == 0:
                self.field(frame, 3, n, "type", "Протокол входа", options=("https", "http"))
            if p["kind"] == "forwarded" and idx == 0:
                self.field(frame, 7, n, "uplink_public", "Публичный ключ шлюза для выхода")
            if n["type"] not in WG_TYPES | {
                "ssh",
                "dot",
                "doh",
                "mesh_exit",
                "mesh_relay",
                "relay_tcp",
                "relay_udp",
            }:
                self.field(frame, 4, n, "username", "Имя пользователя")
                self.field(frame, 5, n, "password", "Пароль / UUID", hidden=True)
            if n["type"] in TLS_TYPES | {"reality"} or p["kind"] in ("chain", "ovpn_http"):
                self.field(frame, 6, n, "tls_name", "Имя TLS / SNI")
            if n["type"] in WG_TYPES:
                self.field(frame, 4, n, "public_key", "Публичный ключ сервера")
            elif n["type"] == "reality":
                self.field(frame, 7, n, "public_key", "Публичный ключ REALITY")
            if n["type"] in WG_TYPES:
                self.field(frame, 5, n, "client_private", "Закрытый ключ клиента", hidden=True)
                self.field(frame, 6, n, "client_public", "Публичный ключ клиента")
            if n["type"] in TLS_TYPES or p["kind"] in ("chain", "ovpn_http"):
                ttk.Button(
                    frame,
                    text="Импорт сертификата PEM",
                    command=partial(self.certificate, n),
                ).grid(row=8, column=1, sticky="w", pady=4)
            for bound_node, key, var in self.bindings:
                if bound_node is n and key == "type":

                    def update_title(
                        *_: str,
                        tab: FormView = page,
                        role: str = "Вход" if idx == 0 else "Выход",
                        protocol: tk.StringVar | tk.BooleanVar = var,
                    ) -> None:
                        self.editor.tab(tab, text=f"{role} · {protocol.get()}")  # type: ignore[no-untyped-call]

                    var.trace_add("write", update_title)
        for page in pages:
            page.enable_navigation()
        for node, key, var in self.bindings:
            node[key] = var.get()
        self.baseline = copy.deepcopy(p)
        self._editing_controls()
        for i, saved in enumerate(self.saved):
            if saved["id"] == p["id"]:
                self.pick.current(i)

    def field(
        self,
        frame: ttk.Frame,
        row: int,
        node: Obj,
        key: str,
        label: str,
        *,
        hidden: bool = False,
        file: bool = False,
        options: tuple[str, ...] = (),
    ) -> None:
        """Bind a single profile field to its editor."""
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=2)
        var = tk.StringVar(value=node[key])
        self.bindings.append((node, key, var))
        if options:
            ttk.Combobox(frame, textvariable=var, values=options, state="readonly").grid(
                row=row, column=1, sticky="ew"
            )
        else:
            ttk.Entry(frame, textvariable=var, show="•" if hidden else "").grid(
                row=row, column=1, sticky="ew", pady=1
            )
        if file:

            def browse() -> None:
                selected = filedialog.askopenfilename(
                    filetypes=[("Программы", "*.exe")]
                    if key == "engine_path"
                    else [("Все файлы", "*")]
                )
                if selected:
                    var.set(selected)

            ttk.Button(frame, text="Обзор", command=browse).grid(row=row, column=2)

    def certificate(self, node: Obj) -> None:
        """Import a trusted public PEM from disk."""
        file = filedialog.askopenfilename(
            filetypes=[("Сертификат PEM", "*.pem *.crt"), ("Все файлы", "*")]
        )
        if file:
            try:
                pem = Path(file).read_text(encoding="ascii")
                if "-----BEGIN CERTIFICATE-----" not in pem or "PRIVATE KEY" in pem:
                    raise ValueError("Нужен публичный сертификат формата PEM.")
                node["certificate"] = pem
                self.status.set("Публичный сертификат добавлен в профиль.")
            except (OSError, ValueError) as err:
                self.status.set(str(err))

    def collect(self) -> Obj:
        """Read a detached snapshot of the displayed settings."""
        for node, key, var in self.bindings:
            node[key] = var.get()
        if not self.current["name"].strip():
            raise ValueError("Введите название профиля.")
        return copy.deepcopy(self.current)

    def store(self, p: Obj) -> None:
        """Persist a profile without changing other entries."""
        if self.read_error:
            raise ValueError(self.read_error)
        stored = update_profile(self.path, p)
        ids = {item["id"] for item in stored}
        inherited = [item for item in self.saved if item["id"] not in ids] if self.admin else []
        self.saved = inherited + stored

    def save(self) -> None:
        """Save the current profile for this Windows user."""
        if self.busy or self.closing:
            return
        try:
            p = self.collect()
            self.store(p)
            self.refresh_names()
            self.pick.current(len(self.saved) - 1)
            self.baseline = copy.deepcopy(p)
            self.status.set("Профиль сохранён.")
        except (OSError, ValueError) as err:
            self.status.set(str(err))

    def notify(self, message: str) -> None:
        """Post a status message from a worker."""
        self.queue.put(("status", message))

    def _editing_controls(self) -> None:
        widgets: list[ttk.Widget] = [self.kind, self.pick, self.new_button, *self.action_buttons]
        if self.busy:
            for page in self.editor.winfo_children():
                if isinstance(page, FormView):
                    widgets.extend(
                        w
                        for w in page.body.winfo_children()
                        if isinstance(w, (ttk.Entry, ttk.Button, ttk.Checkbutton))
                    )
            for widget in widgets:
                if not widget.instate(["disabled"]):
                    widget.state(["disabled"])
                    self.disabled_fields.append(widget)
        else:
            for widget in self.disabled_fields:
                if widget.winfo_exists():
                    widget.state(["!disabled"])
            self.disabled_fields.clear()

    def _mesh_controls(self) -> None:
        selected = self.selected()
        enabled = (True, bool(selected), selected in self.available_exits, True)
        for button, available in zip(self.mesh_buttons, enabled, strict=True):
            button.configure(state="normal" if available and not self.mesh_busy else "disabled")

    def stop(self) -> None:
        """Request cancellation of the active route and give immediate feedback."""
        self.stop_event.set()
        self.stop_button.state(["disabled"])
        self.status.set("Остановка маршрута…")

    def task(self, fn: Callable[[], None], *, mesh: bool = False, stoppable: bool = False) -> None:
        """Run one network operation outside the Tk thread."""
        if (self.mesh_busy if mesh else self.busy) or self.closing:
            return
        if mesh:
            self.mesh_busy = True
            self._mesh_controls()
        else:
            self.busy = True
            self.stop_event.clear()
            self._editing_controls()
            if stoppable:
                self.stop_button.state(["!disabled"])

        def work() -> None:
            try:
                fn()
            except Exception as err:
                self.queue.put(("mesh_status" if mesh else "status", str(err)))
            finally:
                self.queue.put(("mesh_done" if mesh else "done", None))

        threading.Thread(target=work, daemon=True).start()

    def unlock(self) -> None:
        """Release a persistent FLURUX lock, including when the tunnel is offline."""
        if self.busy or self.closing:
            self.status.set("Остановите активный маршрут перед снятием блокировки.")
            return

        def release() -> None:
            unlock_network()
            self.notify("Сетевая блокировка FLURUX снята.")

        self.task(release)

    def install(self) -> None:
        """Provision only nodes named in the current profile."""
        if self.busy or self.closing:
            return
        try:
            p = self.collect()
        except ValueError as err:
            self.status.set(str(err))
            return
        if self.admin:
            self.status.set("Для настройки узлов по SSH запустите FLURUX с обычными правами.")
            return
        hosts = [n["ssh"] + " · " + n["type"] for n in p["nodes"] if n["ssh"]]
        if not hosts:
            self.status.set("Укажите SSH в настройках собственного узла.")
            return
        if not messagebox.askokcancel(
            "Настройка серверов",
            "Установить компоненты и применить конфигурацию на выбранных узлах?\n\n"
            + "\n".join(hosts),
            parent=self.root,
        ):
            return

        def apply() -> None:
            def checkpoint() -> None:
                self.store(copy.deepcopy(p))

            try:
                provision(p, self.notify, checkpoint)
            finally:
                self.queue.put(("edit", p))

        self.status.set("Подключение по SSH…")
        self.task(apply)

    def start(self) -> None:
        """Start the selected route or select a mesh exit."""
        if self.busy or self.closing:
            return
        try:
            p = self.collect()
            validate(p)
            self.store(p)
            self.refresh_names()
        except (OSError, ValueError) as err:
            self.status.set(str(err))
            return

        def work() -> None:
            if self.admin:
                if not (
                    (engine_name(p["kind"]) == "sing-box" and p["system_tun"]) or p["kind"] == "awg"
                ):
                    raise ValueError("Этот режим доступен при запуске с обычными правами.")
            else:
                synchronize(p)
            if self.stop_event.is_set():
                self.notify("Маршрут остановлен.")
                return
            self.store(copy.deepcopy(p))
            self.queue.put(("edit", p))
            if p["kind"] == "mesh_exit":
                if not p["nodes"][0]["host"]:
                    raise ValueError("Укажите Mesh-адрес выходного узла.")
                mesh_select(p["nodes"][0]["host"], p["engine_path"])
                self.notify("Выход Tailscale выбран. Отключение доступно на вкладке Mesh.")
            elif p["kind"] == "mesh_relay":
                self.notify(self.mesh_ping(p["nodes"][0]["host"], p["engine_path"]))
            else:
                start_route(p, self.stop_event, self.notify, self.cache)
                self.notify("Маршрут остановлен.")

        self.status.set("Подключение…")
        self.task(work, stoppable=not p["kind"].startswith("mesh_"))

    def mesh_exe(self) -> str:
        """Reuse a configured Mesh engine path if available."""
        if self.current["kind"].startswith("mesh_"):
            return next(
                (
                    str(var.get())
                    for node, key, var in self.bindings
                    if node is self.current and key == "engine_path"
                ),
                "",
            )
        return next(
            (
                str(p["engine_path"])
                for p in self.saved
                if p["kind"].startswith("mesh_") and p["engine_path"]
            ),
            "",
        )

    def refresh_mesh(self) -> None:
        """Refresh the local peer list."""
        exe = self.mesh_exe()
        self.task(lambda: self.queue.put(("peers", mesh_peers(exe))), mesh=True)

    def selected(self) -> str:
        """Read the selected peer address."""
        items = self.peers.selection()
        return items[0] if items else ""

    def mesh_ping(self, address: str, exe: str) -> str:
        """Show the transport actually observed by Tailscale."""
        if not address or not any(address in (n["ip"], n["name"]) for n in mesh_peers(exe)):
            raise ValueError("Выберите известный узел tailnet.")
        return command([binary("tailscale", exe), "ping", "--c=1", "--timeout=5s", address])

    def ping_mesh(self) -> None:
        """Probe the selected peer."""
        ip, exe = self.selected(), self.mesh_exe()
        self.task(lambda: self.queue.put(("mesh_status", self.mesh_ping(ip, exe))), mesh=True)

    def use_exit(self) -> None:
        """Route the Windows host through the selected peer."""
        ip = self.selected()
        if ip:
            self.change_exit(ip)

    def clear_exit(self) -> None:
        """Explicitly clear the persistent Tailscale exit preference."""
        self.change_exit("")

    def change_exit(self, ip: str) -> None:
        """Change and refresh the daemon preference."""
        exe = self.mesh_exe()

        def apply() -> None:
            mesh_select(ip, exe)
            self.queue.put(("peers", mesh_peers(exe)))
            self.queue.put(
                ("mesh_status", "Выход Tailscale выбран." if ip else "Выход Tailscale отключён.")
            )

        self.task(apply, mesh=True)

    def poll(self) -> None:
        """Apply background results on the main thread."""
        while True:
            try:
                kind, value = self.queue.get_nowait()
            except Empty:
                break
            if kind == "mesh_done":
                self.mesh_busy = False
                self._mesh_controls()
            elif kind == "done":
                self.busy = False
                self.stop_button.state(["disabled"])
                self._editing_controls()
            elif kind == "mesh_status":
                self.mesh_status.set(str(value))
            elif kind == "status":
                self.status.set(str(value))
            elif kind == "edit" and isinstance(value, dict):
                self.refresh_names()
                self.edit(value)
            elif kind == "peers" and isinstance(value, list):
                selected = self.selected()
                self.available_exits = {n["ip"] for n in value if n["online"] and n["exit"]}
                self.peers.delete(*self.peers.get_children())
                for n in value:
                    self.peers.insert(
                        "",
                        "end",
                        iid=n["ip"],
                        text=n["name"],
                        values=(
                            n["ip"],
                            "В сети" if n["online"] else "Офлайн",
                            "Выбран" if n["selected"] else "Доступен" if n["exit"] else "—",
                        ),
                    )
                if selected and self.peers.exists(selected):
                    self.peers.selection_set(selected)
                self.mesh_status.set(f"Узлов в tailnet: {len(value)}")
                self._mesh_controls()
        self.root.after(100, self.poll)
