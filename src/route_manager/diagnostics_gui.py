"""Interactive comparison of application routes with measured results and CSV export."""

import copy
import csv
import threading
import tkinter as tk
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from queue import SimpleQueue
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from route_manager.accessibility import named
from route_manager.benchmark import Benchmark
from route_manager.diagnostic_routes import Case, catalogue, run_case
from route_manager.diagnostics import DEFAULT_UDP, DEFAULT_VIDEO, Result, Targets

if TYPE_CHECKING:
    from route_manager.gui import App

SCOPES = {
    "system": "Системное подключение",
    "active": "Активный маршрут",
    "selected": "Выбранный профиль zapret2",
    "zapret": "Все 60 профилей zapret2",
    "profile": "Профиль из «Каскадов»",
    "all": "Глобальный тест FLURUX",
}


class DiagnosticsPanel(ttk.Frame):
    """Run one cancellable comparison at a time and retain its evidence until the next run."""

    def __init__(self, tabs: ttk.Notebook, app: "App") -> None:
        super().__init__(tabs, padding=(5, 5))
        self.app = app
        self.tabs = tabs
        tabs.add(self, text="Тесты")
        self.busy = False
        self.uses_active = False
        self.active_advanced = False
        self.cancel = threading.Event()
        self.queue: SimpleQueue[tuple[int, list[Result], str]] = SimpleQueue()
        self.results: dict[str, Result] = {}
        self.targets: Targets | None = None
        self.stamp = ""
        self.scope = tk.StringVar(value=SCOPES["system"])
        self.web = tk.StringVar(value=app.target.get() or "https://example.org")
        self.video = tk.StringVar(value=DEFAULT_VIDEO)
        self.udp = tk.StringVar(value=DEFAULT_UDP)
        self.summary = tk.StringVar(value="Выберите маршрут и запустите проверку.")
        self.detail = tk.StringVar(value="Выберите строку результата, чтобы посмотреть измерения.")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Проверка соединения", style="Section.TLabel").pack(side="left")
        ttk.Button(
            header, text="Как читать результаты", command=lambda: app.help.show("diagnostics")
        ).pack(side="right")
        form = ttk.Frame(self)
        form.grid(row=1, column=0, sticky="ew", pady=(5, 4))
        form.columnconfigure((0, 1, 2), weight=1, uniform="targets")
        self.inputs = []
        for col, (label, var) in enumerate(
            (
                ("WEB · адрес сайта", self.web),
                ("VIDEO · тестовый файл", self.video),
                ("GAME · сервер STUN", self.udp),
            )
        ):
            ttk.Label(form, text=label, style="Muted.TLabel").grid(row=0, column=col, sticky="w")
            field = named(ttk.Entry(form, textvariable=var, width=14), label)
            field.grid(row=1, column=col, sticky="ew", padx=(0, 5))
            self.inputs.append(field)
        bar = ttk.Frame(self)
        bar.grid(row=2, column=0, sticky="ew", pady=(2, 6))
        self.pick = named(
            ttk.Combobox(
                bar,
                textvariable=self.scope,
                values=tuple(SCOPES.values()),
                state="readonly",
                width=25,
            ),
            "Что проверить",
        )
        self.pick.pack(side="left")
        self.go = ttk.Button(bar, text="Проверить", style="Primary.TButton", command=self.begin)
        self.go.pack(side="left", padx=4)
        self.every = ttk.Button(bar, text="Глобальный тест", command=lambda: self.open("all"))
        self.every.pack(side="left")
        self.abort = ttk.Button(bar, text="Отменить", command=self.cancel.set, state="disabled")
        self.abort.pack(side="left", padx=4)
        self.exporter = ttk.Button(bar, text="Экспорт CSV", command=self.export, state="disabled")
        self.exporter.pack(side="right")
        body = ttk.Frame(self)
        body.grid(row=3, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        labels = ("Результат", "Соединение", "Пинг, мс", "WEB", "VIDEO, Мбит/с", "GAME")
        self.table = named(
            ttk.Treeview(body, columns=labels, show="tree headings", selectmode="browse", height=5),
            "Сводка тестов маршрутов",
        )
        self.table.heading("#0", text="Стратегия")
        self.table.column("#0", width=235, minwidth=140)
        for label, width in zip(labels, (110, 91, 78, 46, 111, 59), strict=True):
            self.table.heading(label, text=label)
            self.table.column(label, width=width, minwidth=40, stretch=False)
        self.table.grid(row=0, column=0, sticky="nsew")
        for direction in ("vertical", "horizontal"):
            vertical = direction == "vertical"
            scroll = ttk.Scrollbar(
                body, orient=direction, command=self.table.yview if vertical else self.table.xview
            )
            scroll.grid(
                row=0 if vertical else 1,
                column=1 if vertical else 0,
                sticky="ns" if vertical else "ew",
            )
            if vertical:
                self.table.configure(yscrollcommand=scroll.set)
            else:
                self.table.configure(xscrollcommand=scroll.set)
        self.table.bind("<<TreeviewSelect>>", self.selection)
        ttk.Label(self, textvariable=self.summary, style="Meta.TLabel", wraplength=730).grid(
            row=4, column=0, sticky="w", pady=(6, 1)
        )
        details = ttk.Label(self, textvariable=self.detail, style="Muted.TLabel", wraplength=720)
        details.grid(row=5, column=0, sticky="ew")
        details.bind("<Configure>", lambda e: details.configure(wraplength=max(200, e.width - 5)))

    def open(self, scope: str) -> None:
        """Open a contextual test from another page and use the current site list."""
        self.tabs.select(self)  # type: ignore[no-untyped-call]
        if self.busy:
            return
        self.scope.set(SCOPES[scope])
        if scope in ("selected", "zapret") and self.web.get() == "https://example.org":
            candidates = self.app.domains.get("1.0", "end").replace(",", " ").split()
            self.web.set(
                self.app.target.get() or (candidates[0] if candidates else "https://example.org")
            )
        self.begin()

    def begin(self) -> None:
        """Snapshot targets and settings on the Tk thread before launching the worker."""
        app = self.app
        if self.busy or app.closing:
            return
        try:
            scope = next(k for k, v in SCOPES.items() if v == self.scope.get())
            targets = Targets.parse(self.web.get(), self.video.get(), self.udp.get())
            if app.zapret.busy or app.check_running or app.downloading or app.advanced.mesh_busy:
                raise ValueError("Дождитесь окончания текущей операции.")
            active = bool(app.pending or app.advanced.busy)
            settings = app._settings_snapshot()
            if active and scope != "active":
                if (
                    scope == "selected"
                    and app.expected_engines == {"zapret"}
                    and app.running_settings
                    and app.running_settings.strategy == settings.strategy
                    and app.running_settings.ip_family == settings.ip_family
                    and app.running_settings.tcp_ports == settings.tcp_ports
                    and app.running_settings.udp_ports == settings.udp_ports
                    and app.pending
                ):
                    scope = "active"
                else:
                    raise ValueError(
                        "Для сравнения остановите текущий маршрут или выберите «Активный маршрут»."
                    )
            if scope == "active":
                if (
                    app.pending
                    and app.running_settings
                    and app.expected_engines == app.ready_engines
                ):
                    cases = [
                        Case("Активный · " + app.mode.get(), base=app.running_settings, active=True)
                    ]
                elif app.advanced.active_profile:
                    p = copy.deepcopy(app.advanced.active_profile)
                    cases = [Case(p["name"], profile=p, active=True)]
                else:
                    raise ValueError("Сначала запустите маршрут и дождитесь его готовности.")
            else:
                cases = catalogue(
                    settings,
                    copy.deepcopy(app.advanced.saved),
                    scope,
                    app.advanced.collect() if scope == "profile" else None,
                )
        except (OSError, ValueError) as exc:
            self.summary.set(str(exc))
            return
        if scope in ("all", "zapret", "selected", "profile"):
            msg = f"В плане проверок: {len(cases)}. FLURUX временно запустит подходящие маршруты и остановит их после замеров. Для zapret2 Windows запросит разрешение. Для каждой строки загружается до 1 МиБ видеопробы, если задан файл. Продолжить?"
            if not messagebox.askokcancel("Проверка маршрутов", msg, parent=self):
                return
        self.targets = targets
        self.stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        self.cancel.clear()
        self.busy = True
        self.uses_active = scope == "active"
        self.active_advanced = self.uses_active and cases[0].profile is not None
        app.advanced.diagnosing = True
        app._refresh_controls()
        self.go.state(["disabled"])
        self.every.state(["disabled"])
        self.abort.state(["!disabled"])
        self.pick.state(["disabled"])
        self.exporter.state(["disabled"])
        for widget in self.inputs:
            widget.state(["disabled"])
        self.table.delete(*self.table.get_children())
        self.results.clear()
        for i, case in enumerate(cases):
            self._row(str(i), Result(case.name))
        self.summary.set("Начинается проверка…")
        self.detail.set("Результаты будут появляться по мере измерений.")
        threading.Thread(target=self._work, args=(cases, targets, scope), daemon=True).start()

    def _work(self, cases: list[Case], targets: Targets, scope: str) -> None:
        try:
            with ExitStack() as stack:
                bench = Benchmark(stack) if scope in ("all", "zapret") else None
                for i, case in enumerate(cases):
                    if self.cancel.is_set():
                        break
                    self.queue.put((i, [], f"{i + 1} / {len(cases)} · {case.name}"))
                    try:
                        rows = run_case(
                            case,
                            targets,
                            self.cancel,
                            self.app.data,
                            self.app.entry,
                            self.app.admin,
                            bench,
                        )
                    except InterruptedError:
                        break
                    except Exception as exc:
                        if getattr(exc, "winerror", None) == 1223:
                            self.cancel.set()
                            break
                        reason = str(exc)[:390]
                        state = (
                            "Вне фильтра"
                            if reason.startswith("Вне области")
                            else "Нужна настройка"
                            if isinstance(exc, (ValueError, FileNotFoundError))
                            else "Ошибка"
                        )
                        rows = [Result(case.name, status=state, detail=reason)]
                    if self.cancel.is_set():
                        break
                    self.queue.put((i, rows, ""))
        finally:
            self.queue.put((-1, [], ""))

    def _row(self, key: str, row: Result) -> None:
        self.results[key] = row
        if self.table.exists(key):
            self.table.item(key, text=row.name, values=row.cells())
        else:
            self.table.insert("", "end", iid=key, text=row.name, values=row.cells())

    def poll(self) -> None:
        """Update the visible comparison without blocking keyboard navigation."""
        if (
            self.uses_active
            and self.active_advanced
            and (self.app.advanced.stop_event.is_set() or self.app.advanced.active_profile is None)
        ):
            self.cancel.set()
        while not self.queue.empty():
            index, rows, progress = self.queue.get_nowait()
            if index == -1:
                self._finish()
                return
            if progress:
                self.summary.set(progress)
                row = self.results[str(index)]
                row.status = "Проверяется"
                self._row(str(index), row)
            if self.uses_active and self.cancel.is_set():
                continue
            for j, value in enumerate(rows):
                self._row(str(index) if not j else f"{index}-{j}", value)
            self.selection()

    def _finish(self) -> None:
        for key, row in self.results.items():
            if row.status in ("В очереди", "Проверяется"):
                row.status = "Отменено"
                self._row(key, row)
        self.busy = False
        self.uses_active = False
        self.app.advanced.diagnosing = False
        self.app._refresh_controls()
        for w in (self.go, self.every, self.pick, self.exporter, *self.inputs):
            w.state(["!disabled"])
        self.abort.state(["disabled"])
        rows = list(self.results.values())
        count = sum(
            r.http is not None
            or r.ping_ms is not None
            or r.loss is not None
            or r.status == "Узел доступен"
            for r in rows
        )
        self.summary.set(
            f"{'Остановлено' if self.cancel.is_set() else 'Завершено'} · с измерениями {count} из {len(rows)} · WEB {sum(r.cells()[3] == 'Да' for r in rows)} · VIDEO HD {sum(r.mbps is not None and r.mbps >= 5 for r in rows)} · GAME {sum(r.cells()[5] == 'Да*' for r in rows)}"
        )
        if rows and not self.table.selection():
            self.table.selection_set(next(iter(self.results)))
        self.selection()

    def selection(self, event: object = None) -> None:
        """Show the protocol, latency, packet loss and reasons behind the selected row."""
        selected = self.table.selection()
        if selected and (r := self.results.get(selected[0])):
            self.detail.set(r.describe())

    def export(self) -> None:
        """Export measured and skipped rows, endpoints, timestamp and interpretation."""
        if self.busy or not self.targets:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            initialfile="FLURUX-тесты.csv",
            defaultextension=".csv",
            filetypes=[("Отчёт CSV", "*.csv")],
        )
        if not path:
            return
        try:
            with Path(path).open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.writer(stream, delimiter=";")
                writer.writerow(
                    (
                        "Время",
                        "WEB-цель",
                        "VIDEO-цель",
                        "STUN",
                        "Стратегия",
                        "Результат",
                        "Соединение",
                        "Пинг, мс",
                        "WEB",
                        "VIDEO, Мбит/с",
                        "GAME",
                        "Подробности",
                    )
                )
                for row in self.results.values():
                    vals = (
                        self.stamp,
                        self.targets.web,
                        self.targets.video,
                        f"{self.targets.udp_host}:{self.targets.udp_port}"
                        if self.targets.udp_host
                        else "",
                        row.name,
                        *row.cells(),
                        row.describe(),
                    )
                    writer.writerow(
                        [
                            "'" + v if v.lstrip().startswith(("=", "+", "-", "@")) else v
                            for v in vals
                        ]
                    )
            self.detail.set("Отчёт сохранён.")
        except OSError as exc:
            self.detail.set(str(exc))
