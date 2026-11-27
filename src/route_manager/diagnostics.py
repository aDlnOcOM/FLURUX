"""Bounded, route-specific network measurements for the desktop comparison table."""

import ctypes as ct
import ipaddress
import secrets
import socket
import statistics
import struct
import subprocess
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from functools import lru_cache
from time import monotonic
from urllib.parse import urlsplit

from route_manager.config import validated_url
from route_manager.profiles import host, port
from route_manager.windows import system_curl

DEFAULT_VIDEO = "https://speed.cloudflare.com/__down?bytes=1048576"
DEFAULT_UDP = "stun.cloudflare.com:3478"


@dataclass(frozen=True)
class Targets:
    """Explicit destinations used by every comparable row."""

    web: str
    video: str
    udp_host: str
    udp_port: int

    @classmethod
    def parse(cls, web: str, video: str, udp: str) -> "Targets":
        """Normalize HTTP(S) URLs and an optional STUN endpoint."""
        pair = urlsplit("//" + udp.strip()) if udp.strip() else None
        if pair and (
            not pair.hostname
            or pair.username is not None
            or pair.path
            or pair.query
            or pair.fragment
        ):
            raise ValueError("Введите адрес STUN в виде имя:порт.")
        return cls(
            validated_url(web),
            validated_url(video) if video.strip() else "",
            host(pair.hostname or "") if pair else "",
            port(pair.port if pair and pair.port is not None else 3478),
        )


@dataclass
class Result:
    """Observed transport and workload results; absent measurements are never scored."""

    name: str
    via: str = ""
    status: str = "В очереди"
    ping_ms: float | None = None
    ping_kind: str = ""
    http: int | None = None
    ttfb_ms: float | None = None
    mbps: float | None = None
    udp_ms: float | None = None
    jitter: float | None = None
    loss: float | None = None
    detail: str = ""

    def cells(self) -> tuple[str, ...]:
        """Render measured values with their units and protocol."""
        web = (
            "Да"
            if self.http is not None and 200 <= self.http < 300
            else "Переход"
            if self.http is not None and 300 <= self.http < 400
            else "Нет"
            if self.http is not None
            else "—"
        )
        video = (
            "—"
            if self.mbps is None
            else f"{self.mbps:.1f} · " + ("HD" if self.mbps >= 5 else "низк.")
        )
        game = (
            "—"
            if self.loss is None
            else "Да*"
            if self.udp_ms is not None
            and self.udp_ms <= 80
            and self.jitter is not None
            and self.jitter <= 20
            and self.loss == 0
            else "Нет*"
        )
        ping = "—" if self.ping_ms is None else f"{self.ping_ms:.0f} {self.ping_kind}"
        return self.status, self.via, ping, web, video, game

    def describe(self) -> str:
        """Explain the evidence behind the summary row."""
        facts = [self.detail] if self.detail else []
        if self.http is not None:
            facts.append(f"HTTP {self.http}" if self.http else "Ответ HTTP не получен")
        if self.ttfb_ms is not None:
            facts.append(f"Первый байт {self.ttfb_ms:.0f} мс")
        if self.mbps is not None:
            facts.append(f"Загрузка {self.mbps:.2f} Мбит/с")
        if self.loss is not None:
            facts.append(f"Потери UDP {self.loss:.0f}%")
        if self.udp_ms is not None:
            facts.append(f"RTT UDP {self.udp_ms:.0f} мс")
        if self.jitter is not None:
            facts.append(f"Джиттер {self.jitter:.0f} мс")
        return " · ".join(facts) or self.status


def cancelled(stop: threading.Event) -> None:
    """Abort a running measurement on request."""
    if stop.is_set():
        raise InterruptedError("Проверка отменена.")


def output(args: list[str], stop: threading.Event, timeout: float) -> tuple[int, str]:
    """Run one bounded probe and reap its process on cancellation or timeout."""
    cancelled(stop)
    with subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    ) as child:
        limit = monotonic() + timeout
        try:
            while True:
                cancelled(stop)
                if monotonic() > limit:
                    raise TimeoutError("Время ожидания истекло.")
                try:
                    data, _ = child.communicate(timeout=0.15)
                    return child.returncode, data.decode("utf-8", "replace").strip()
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()


@lru_cache(maxsize=1)
def http3_available() -> bool:
    """Read the capabilities of the Windows curl used for actual requests."""
    code, data = output([str(system_curl()), "--disable", "--version"], threading.Event(), 4)
    return code == 0 and any(
        "HTTP3" in line.split() for line in data.splitlines() if line.startswith("Features:")
    )


def http_sample(
    url: str,
    socks: int | None,
    stop: threading.Event,
    *,
    video: bool = False,
    quic: bool = False,
    connect_to: str = "",
    family: str = "both",
    follow: bool = True,
) -> tuple[int, float | None, float | None, str]:
    """Request a page or bounded video sample, recording negotiated HTTP version and timing."""
    args = [
        str(system_curl()),
        "--disable",
        "--silent",
        "--globoff",
        "--noproxy",
        "",
        "--proxy",
        f"socks5h://127.0.0.1:{socks}" if socks else "",
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-time",
        "12",
        "--connect-timeout",
        "7",
        "--range",
        f"0-{1048575 if video else 4095}",
        "--max-filesize",
        "1048576",
        "--output",
        "NUL",
        "--write-out",
        "%{http_code}|%{time_starttransfer}|%{size_download}|%{speed_download}|%{http_version}|%{content_type}",
    ]
    if family != "both":
        args.append("-4" if family == "ipv4" else "-6")
    if connect_to:
        args.extend(("--connect-to", connect_to))
    elif follow:
        args.extend(("--location", "--max-redirs", "3"))
    if quic:
        args.append("--http3-only")
    code, data = output([*args, "--", url], stop, 15)
    parts = data.split("|", 5)
    if len(parts) != 6:
        return 0, None, None, f"curl {code}"
    status, ttfb, size, speed, version, mime = parts
    if code and not (code == 63 and not video and int(status) >= 200):
        return 0, None, None, f"curl {code}"
    mbps = (
        float(speed) * 8 / 1e6
        if video
        and int(size) >= 262144
        and 200 <= int(status) < 300
        and "text/html" not in mime.lower()
        and not code
        else None
    )
    return int(status), float(ttfb) * 1000, mbps, "HTTP/" + version


def _read(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("Прокси закрыл соединение.")
        data += chunk
    return data


def _relay(stack: ExitStack, local: int) -> tuple[str, int]:
    control = stack.enter_context(socket.create_connection(("127.0.0.1", local), 2))
    control.sendall(b"\x05\x01\x00")
    if _read(control, 2) != b"\x05\x00":
        raise OSError("SOCKS5 не поддерживает UDP-тест.")
    control.sendall(b"\x05\x03\x00\x01" + b"\0" * 6)
    reply = _read(control, 4)
    if reply[:3] != b"\x05\0\0":
        raise OSError("UDP ASSOCIATE отклонён.")
    if reply[3] == 1:
        addr = socket.inet_ntop(socket.AF_INET, _read(control, 4))
    elif reply[3] == 4:
        addr = socket.inet_ntop(socket.AF_INET6, _read(control, 16))
    else:
        raise OSError("Прокси не вернул локальный UDP-ретранслятор.")
    ip = ipaddress.ip_address(addr)
    if not ip.is_loopback and not ip.is_unspecified:
        raise OSError("Прокси предложил внешний UDP-ретранслятор.")
    return (
        "127.0.0.1"
        if ip.is_unspecified and ip.version == 4
        else "::1"
        if ip.is_unspecified
        else addr,
        struct.unpack("!H", _read(control, 2))[0],
    )


def stun(
    targets: Targets,
    stop: threading.Event,
    *,
    socks: int | None = None,
    fixed: int | None = None,
    family: str = "both",
) -> tuple[float | None, float | None, float]:
    """Measure four STUN Binding round trips, through the SOCKS association when supplied."""
    samples = []
    with ExitStack() as stack:
        peer = (
            _relay(stack, socks)
            if socks
            else ("127.0.0.1", fixed)
            if fixed
            else (targets.udp_host, targets.udp_port)
        )
        ip_family = (
            socket.AF_UNSPEC
            if socks or fixed or family == "both"
            else socket.AF_INET
            if family == "ipv4"
            else socket.AF_INET6
        )
        info = socket.getaddrinfo(*peer, family=ip_family, type=socket.SOCK_DGRAM)
        af, kind, proto, _, dest = next((a for a in info if a[0] == socket.AF_INET), info[0])
        sock = stack.enter_context(socket.socket(af, kind, proto))
        sock.connect(dest)
        name = targets.udp_host.encode("idna")
        prefix = (
            b"\0\0\0\x03" + bytes([len(name)]) + name + struct.pack("!H", targets.udp_port)
            if socks
            else b""
        )
        for _ in range(4):
            cancelled(stop)
            tx = secrets.token_bytes(12)
            request = struct.pack("!HHI", 1, 0, 0x2112A442) + tx
            started = monotonic()
            sock.send(prefix + request)
            while (remaining := 1.0 - (monotonic() - started)) > 0:
                cancelled(stop)
                sock.settimeout(min(0.2, remaining))
                try:
                    packet = sock.recv(2048)
                except TimeoutError:
                    continue
                if socks:
                    if len(packet) < 5 or packet[:3] != b"\0\0\0":
                        continue
                    addrsize = {1: 4, 4: 16, 3: 1 + packet[4]}.get(packet[3])
                    if addrsize is None:
                        continue
                    packet = packet[6 + addrsize :]
                if (
                    len(packet) >= 20
                    and packet[:2] == b"\x01\x01"
                    and packet[4:20] == request[4:]
                    and len(packet) == 20 + int.from_bytes(packet[2:4], "big")
                ):
                    samples.append((monotonic() - started) * 1000)
                    break
            stop.wait(0.06)
    return (
        statistics.median(samples) if samples else None,
        statistics.mean(abs(b - a) for a, b in zip(samples, samples[1:]))
        if len(samples) > 1
        else None,
        (4 - len(samples)) * 25.0,
    )


def icmp(hostname: str) -> float | None:
    """Measure an IPv4 ICMP echo to the web host on the system route."""
    lib = ct.windll.iphlpapi
    lib.IcmpCreateFile.restype = ct.c_void_p
    handle = lib.IcmpCreateFile()
    if handle in (None, ct.c_void_p(-1).value):
        return None
    try:
        address = socket.inet_aton(socket.gethostbyname(hostname))
        reply = ct.create_string_buffer(256)
        count = lib.IcmpSendEcho(
            ct.c_void_p(handle),
            ct.c_uint32(int.from_bytes(address, "little")),
            b"FLURUX",
            6,
            None,
            reply,
            len(reply),
            750,
        )
        _, status, delay = struct.unpack_from("<III", reply)
        return float(delay) if count and not status else None
    except OSError:
        return None
    finally:
        lib.IcmpCloseHandle(ct.c_void_p(handle))


def measure(
    name: str,
    via: str,
    targets: Targets,
    stop: threading.Event,
    *,
    socks: int | None = None,
    udp: bool = True,
    quic: bool = False,
    connect_to: str = "",
    family: str = "both",
    follow: bool = True,
) -> Result:
    """Collect independent evidence for browsing, video and interactive UDP."""
    r = Result(name, via)
    host_name = urlsplit(targets.web).hostname or ""
    notes = []
    if not socks and not connect_to and family != "ipv6":
        r.ping_ms = icmp(host_name)
        r.ping_kind = "ICMP"
    r.http, r.ttfb_ms, _, protocol = http_sample(
        targets.web, socks, stop, connect_to=connect_to, family=family, follow=follow
    )
    notes.append(protocol)
    if targets.video and not connect_to:
        _, _, r.mbps, _ = http_sample(
            targets.video, socks, stop, video=True, family=family, follow=follow
        )
        if r.mbps is None:
            notes.append("Видеозамер недоступен или получено меньше 256 КиБ")
    if targets.udp_host and udp and not connect_to:
        try:
            r.udp_ms, r.jitter, r.loss = stun(targets, stop, socks=socks, family=family)
        except InterruptedError:
            raise
        except OSError:
            notes.append("Проверка UDP недоступна")
        if r.ping_ms is None and r.udp_ms is not None:
            r.ping_ms, r.ping_kind = r.udp_ms, "UDP"
    if quic:
        if http3_available():
            code, _, _, neg = http_sample(
                targets.web, socks, stop, quic=True, family=family, follow=follow
            )
            notes.append(
                "HTTP/3 подтверждён"
                if 200 <= code < 400 and neg.startswith("HTTP/3")
                else "HTTP/3 не подтверждён"
            )
        else:
            notes.append("HTTP/3 не измерен: системный curl без HTTP3")
    r.detail = " · ".join(notes)
    r.status = (
        "Доступен"
        if r.http and 200 <= r.http < 300
        else "Перенаправление"
        if r.http and 300 <= r.http < 400
        else "Частично"
        if r.mbps is not None or r.udp_ms is not None
        else "Сайт недоступен"
    )
    return r
