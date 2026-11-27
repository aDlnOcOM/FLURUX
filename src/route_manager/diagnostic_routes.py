"""Run connection tests in isolated, sequential sessions and retire each owned worker."""

import copy
import ipaddress
import re
import secrets
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from queue import Empty, SimpleQueue
from time import monotonic
from urllib.parse import urlsplit

from route_manager.benchmark import Benchmark
from route_manager.config import (
    TRANSPORTS,
    Settings,
    domain_name,
    parse_domains,
    port_list,
    prepare_tor,
    prepare_zapret,
    webtunnel_domains,
)
from route_manager.diagnostics import Result, Targets, cancelled, measure, output, stun
from route_manager.profiles import STRATEGIES, Obj, port, validate
from route_manager.routes import binary, mesh_peers, start_route
from route_manager.runtime import Session, Update
from route_manager.zapret_presets import FAMILIES, METHODS, PRESETS, QUIC_METHODS


@dataclass(frozen=True)
class Case:
    """A specific operating mode, saved profile, or visible missing prerequisite."""

    name: str
    base: Settings | None = None
    profile: Obj | None = None
    skip: str = ""
    active: bool = False


def catalogue(
    settings: Settings, profiles: list[Obj], scope: str, current: Obj | None = None
) -> list[Case]:
    """Build the comparison inventory, including strategies without saved endpoints."""
    if scope == "system":
        return [Case("Системное подключение")]
    if scope == "profile" and current is not None:
        return [Case(str(current["name"]), profile=current)]
    if scope == "selected":
        return [
            Case(
                METHODS[settings.strategy] + " · " + FAMILIES[settings.ip_family],
                replace(settings, mode="zapret"),
            )
        ]
    if scope not in ("zapret", "all"):
        raise ValueError("Выберите маршрут для теста.")
    rows = [Case("Системное подключение")]
    for preset in PRESETS:
        rows.append(
            Case(
                preset.label,
                replace(
                    settings,
                    mode="zapret",
                    strategy=preset.method,
                    ip_family=preset.family,
                    tcp_ports=preset.ports,
                    udp_ports=preset.ports,
                ),
            )
        )
    if scope == "all":
        for transport, label in TRANSPORTS.items():
            rows.append(Case("Tor · " + label, replace(settings, mode="tor", transport=transport)))
        rows.extend(
            (
                Case("zapret2 + Tor · текущие параметры", replace(settings, mode="both")),
                Case(
                    "WebTunnel через zapret2",
                    replace(settings, mode="cascade", transport="webtunnel"),
                ),
            )
        )
        for kind, (title, _) in STRATEGIES.items():
            found = [p for p in profiles if p["kind"] == kind]
            rows.extend(
                Case(
                    f"{p['name']} · {title}" if p["name"] != title else title,
                    profile=copy.deepcopy(p),
                )
                for p in found
            )
            if not found:
                rows.append(
                    Case(title, skip="Сохраните профиль этой стратегии во вкладке «Каскады».")
                )
    return rows


def _site_domain(url: str) -> str:
    hostname = urlsplit(url).hostname or ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return domain_name(hostname)
    raise ValueError("Для фильтра zapret2 требуется доменное имя HTTPS-сайта.")


def _scope_reason(url: str, cfg: Settings, active: bool) -> str:
    uri = urlsplit(url)
    if uri.scheme != "https" or str(uri.port or 443) not in port_list(cfg.tcp_ports).split(","):
        return "HTTPS-порт цели отсутствует в фильтре."
    try:
        name = _site_domain(url)
    except ValueError as exc:
        return str(exc)

    def matches(raw: str) -> bool:
        return any(name == item or name.endswith("." + item) for item in parse_domains(raw))

    if matches(cfg.exclude_domains):
        return "Домен входит в исключения."
    if active and not matches(cfg.domains):
        return "Домен отсутствует в списке активного профиля."
    return ""


def _temporary_settings(settings: Settings, targets: Targets) -> Settings:
    if settings.mode in ("tor", "cascade"):
        return settings
    names = []
    for url in (targets.web, targets.video):
        if url:
            try:
                names.append(_site_domain(url))
            except ValueError:
                continue
    return replace(settings, domains="\n".join(dict.fromkeys(names)))


@contextmanager
def basic_session(
    cfg: Settings, cache: Path, entry: Path, stop: threading.Event
) -> Iterator[Callable[[], None]]:
    tor = prepare_tor(cfg) if cfg.mode != "zapret" else None
    cascade = cfg.mode == "cascade"
    zap = (
        prepare_zapret(cfg, webtunnel_domains(tor) if tor and cascade else ())
        if cfg.mode != "tor"
        else None
    )
    q: SimpleQueue[Update] = SimpleQueue()
    session = Session(cache, entry, q)
    pending = {k for k, enabled in (("tor", tor), ("zapret", zap)) if enabled}
    ready: set[str] = set()
    error = ""

    def read(wait: float) -> None:
        nonlocal error
        try:
            event = q.get(timeout=wait)
        except Empty:
            return
        if event.kind == "status" and event.ready:
            ready.add(event.engine)
        elif event.kind == "log":
            error = event.message
        elif event.kind == "done":
            pending.discard(event.engine)

    def alive() -> None:
        while not q.empty():
            read(0)
        if len(pending) != expected:
            raise OSError(error or "Движок завершился во время проверки.")

    expected = len(pending)
    session.start(zap, tor, cascade)
    try:
        limit = monotonic() + (65 if tor else 35)
        while len(ready) < expected:
            cancelled(stop)
            read(0.1)
            alive()
            if monotonic() > limit:
                raise TimeoutError("Движок не сообщил о готовности.")
        yield alive
    finally:
        session.stop.set()
        while pending:
            read(0.15)


@contextmanager
def profile_session(p: Obj, cache: Path, stop: threading.Event) -> Iterator[Callable[[], None]]:
    local = threading.Event()
    ready = threading.Event()
    errors: list[str] = []

    def worker() -> None:
        try:
            start_route(p, local, lambda _: None, cache, ready=ready.set)
        except Exception as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def alive() -> None:
        if not thread.is_alive():
            raise OSError(errors[0] if errors else "Профиль остановлен.")

    try:
        limit = monotonic() + 45
        while not ready.wait(0.1):
            cancelled(stop)
            alive()
            if monotonic() > limit:
                raise TimeoutError("Профиль не запустился за 45 секунд.")
        alive()
        yield alive
    finally:
        local.set()
        thread.join()


def dns_sample(local: int, hostname: str) -> float:
    """Validate a real A response from the local encrypted-DNS forwarding profile."""
    tx = secrets.token_bytes(2)
    question = (
        b"".join(bytes([len(part)]) + part for part in hostname.encode("idna").split(b"."))
        + b"\0\0\1\0\1"
    )
    message = tx + b"\1\0\0\1\0\0\0\0\0\0" + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(("127.0.0.1", local))
        start = monotonic()
        sock.send(message)
        reply = sock.recv(4096)
    if (
        len(reply) < 12
        or reply[:2] != tx
        or not reply[2] & 128
        or reply[3] & 15
        or int.from_bytes(reply[6:8], "big") == 0
    ):
        raise OSError("DNS-ответ не содержит успешного результата.")
    return (monotonic() - start) * 1000


def _profile_test(case: Case, p: Obj, t: Targets, stop: threading.Event) -> Result:
    kind = p["kind"]
    local = port(p["local_port"])
    name = case.name
    if kind.startswith("dns_"):
        dns_ms = dns_sample(local, urlsplit(t.web).hostname or "")
        return Result(
            name,
            kind[4:].upper(),
            "DNS работает",
            dns_ms,
            "DNS",
            detail="Успешный DNS-ответ через локальный резолвер. Это профиль DNS.",
        )
    if kind in ("relay_udp", "masque_udp"):
        if (t.udp_host, t.udp_port) != (p["target_host"], port(p["target_port"])):
            return Result(
                name,
                "UDP",
                "Нужна цель",
                detail="Укажите STUN-сервер, совпадающий с фиксированным назначением профиля.",
            )
        ms, jitter, loss = stun(t, stop, fixed=local)
        return Result(
            name,
            "UDP",
            "Доступен" if ms is not None else "Нет ответа",
            ms,
            "UDP",
            udp_ms=ms,
            jitter=jitter,
            loss=loss,
        )
    if kind == "relay_tcp":
        uri = urlsplit(t.web)
        remote = uri.port or (443 if uri.scheme == "https" else 80)
        if (uri.hostname, remote) != (p["target_host"], port(p["target_port"])):
            return Result(
                name,
                "TCP",
                "Нужна цель",
                detail="Для HTTP(S)-теста укажите URL фиксированного назначения профиля.",
            )
        return measure(
            name, "TCP-реле", t, stop, connect_to=f"{uri.hostname}:{remote}:127.0.0.1:{local}"
        )
    system = bool(p["system_tun"] or kind == "awg")
    return measure(
        name,
        "Системный VPN" if system else "SOCKS5",
        t,
        stop,
        socks=None if system else local,
        udp=not kind.startswith("tor_"),
    )


def run_case(
    case: Case,
    targets: Targets,
    stop: threading.Event,
    cache: Path,
    entry: Path,
    admin: bool,
    bench: Benchmark | None = None,
) -> list[Result]:
    """Exercise the route's actual protocol and return separate legs for parallel routing."""
    cancelled(stop)
    if case.skip:
        return [Result(case.name, status="Нужен профиль", detail=case.skip)]
    if case.base is not None:
        cfg = case.base if case.active else _temporary_settings(case.base, targets)
        web_reason = (
            _scope_reason(targets.web, cfg, case.active) if cfg.mode in ("zapret", "both") else ""
        )
        video_reason = (
            _scope_reason(targets.video, cfg, case.active)
            if targets.video and cfg.mode in ("zapret", "both")
            else ""
        )
        if cfg.mode == "zapret" and web_reason:
            return [Result(case.name, "zapret2", "Вне фильтра", detail=web_reason)]
        if admin:
            return [
                Result(
                    case.name,
                    status="Обычное окно",
                    detail="Базовые сеансы запускаются из обычного окна FLURUX.",
                )
            ]

        def probe() -> list[Result]:
            rows = []
            if cfg.mode in ("zapret", "both"):
                title = case.name + (" · прямой" if cfg.mode == "both" else "")
                if web_reason:
                    rows.append(Result(title, "zapret2", "Вне фильтра", detail=web_reason))
                else:
                    row = measure(
                        title,
                        "zapret2",
                        replace(targets, video="" if video_reason else targets.video),
                        stop,
                        udp=False,
                        follow=False,
                        quic=cfg.strategy in QUIC_METHODS
                        and str(urlsplit(targets.web).port or 443)
                        in port_list(cfg.udp_ports).split(","),
                        family=cfg.ip_family,
                    )
                    row.detail += " · ICMP идёт по системному маршруту. GAME по STUN доступен в системной проверке."
                    if video_reason:
                        row.detail += " · Видеофайл вне фильтра. " + video_reason
                    rows.append(row)
            if cfg.mode != "zapret":
                rows.append(
                    measure(
                        case.name + (" · SOCKS" if cfg.mode == "both" else ""),
                        "Tor SOCKS5",
                        targets,
                        stop,
                        socks=int(cfg.socks_port),
                        udp=False,
                    )
                )
            return rows

        if case.active:
            return probe()
        if bench and cfg.mode == "zapret":
            with bench.running(prepare_zapret(cfg), stop) as alive:
                rows = probe()
                alive()
                return rows
        with basic_session(cfg, cache, entry, stop) as alive:
            rows = probe()
            alive()
            return rows
    p = case.profile
    if p is None:
        return [measure(case.name, "Системный", targets, stop)]
    validate(p)
    kind = p["kind"]
    system = bool(p["system_tun"] or kind == "awg")
    if admin != system:
        return [
            Result(
                case.name,
                status="Другой режим",
                detail="Откройте системный VPN от администратора."
                if system
                else "Проверьте профиль из обычного окна.",
            )
        ]
    if kind == "ech":
        return [
            Result(
                case.name,
                "Firefox",
                "Проверка в Firefox",
                detail="ECH согласует сам Firefox. Настройки профиля проверены. Встроенный HTTP-клиент не может подтвердить ECH браузера.",
            )
        ]
    if kind.startswith("mesh_"):
        peer = next(
            (
                row
                for row in mesh_peers(p["engine_path"])
                if p["nodes"][0]["host"] in (row["name"], row["ip"])
            ),
            None,
        )
        if not peer or not peer["online"]:
            raise OSError("Узел отсутствует или офлайн.")
        rc, data = output(
            [binary("tailscale", p["engine_path"]), "ping", "--c=1", "--timeout=3s", peer["ip"]],
            stop,
            6,
        )
        if rc:
            raise OSError("Узел Mesh не ответил на ping.")
        match = re.search(r"(\d+(?:\.\d+)?)ms\b", data)
        if kind == "mesh_exit" and peer["selected"]:
            row = measure(case.name, "Mesh exit", targets, stop)
            row.detail += " · " + data[-160:]
            return [row]
        return [
            Result(
                case.name,
                "Tailscale",
                "Узел доступен",
                float(match[1]) if match else None,
                "Mesh",
                detail=data[-160:] + " · Для проверки выхода выберите этот узел в Mesh.",
            )
        ]
    if case.active:
        return [_profile_test(case, p, targets, stop)]
    if p.get("network_lock") and system:
        return [
            Result(
                case.name,
                "TUN",
                "Запустите вручную",
                detail="Профиль сохраняет системную блокировку сети. Запустите его и выберите «Активный маршрут».",
            )
        ]
    with profile_session(p, cache, stop) as alive:
        row = _profile_test(case, p, targets, stop)
        alive()
        return [row]
