import json
import os
import re
import socket
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from queue import SimpleQueue

from route_manager.config import (
    TorConfig,
    ZapretConfig,
    torrc,
)
from route_manager.private_files import private_directory, private_session
from route_manager.security import guard_session
from route_manager.windows import (
    managed_process,
    process_exit_code,
    system_curl,
    wait_handle,
)

BOOTSTRAP = re.compile(r"\bBootstrapped (\d+)%")
URL_LOG = re.compile(r"https?://[^\s\]<>]+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Update:
    """A status, log message or check result sent to the GUI thread."""

    engine: str
    kind: str
    message: str
    ready: bool = False


class LogTail:
    """Read complete lines from a child process log without blocking."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0
        self.partial = b""

    def read(self, *, final: bool = False) -> list[str]:
        """Return newly written lines, preserving a trailing partial line."""
        if not self.path.exists():
            return []
        with self.path.open("rb") as handle:
            handle.seek(self.offset)
            chunk = handle.read(65_536)
            self.offset = handle.tell()
        lines = (self.partial + chunk).split(b"\n")
        self.partial = b"" if final else lines.pop()[-8192:]
        return [
            line[:8192].decode("utf-8", errors="replace").strip() for line in lines if line.strip()
        ]


class Session:
    """Run independent routes in background threads and coordinate a cascade."""

    def __init__(self, data: Path, entry: Path, events: SimpleQueue[Update]) -> None:
        self.data = data
        self.entry = entry
        self.events = events
        self.stop = threading.Event()
        self.zapret_ready = threading.Event()
        self.zapret_finished = threading.Event()

    def start(self, zapret: ZapretConfig | None, tor: TorConfig | None, cascade: bool) -> None:
        """Start the configured engines and choose whether Tor waits for zapret2."""
        if zapret:
            threading.Thread(
                target=self._run, args=("zapret", lambda: self._zapret(zapret)), daemon=True
            ).start()
        if tor:
            threading.Thread(
                target=self._run, args=("tor", lambda: self._tor(tor, cascade)), daemon=True
            ).start()

    def emit(self, engine: str, kind: str, message: str, *, ready: bool = False) -> None:
        """Queue an update for the window."""
        self.events.put(Update(engine, kind, message, ready))

    def _run(self, engine: str, action: Callable[[], None]) -> None:
        try:
            action()
            self.emit(engine, "status", "Остановлен")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            message = str(exc)
            if getattr(exc, "winerror", None) == 1223:
                message = "Запуск zapret2 отменён в окне UAC."
            self.emit(engine, "status", "Ошибка запуска или работы")
            self.emit(engine, "log", message)
        finally:
            if engine == "zapret":
                self.zapret_finished.set()
            self.emit(engine, "done", "")

    def _zapret(self, config: ZapretConfig) -> None:
        self.emit("zapret", "status", "Ожидание Windows UAC")
        with guard_session(
            "zapret", [config.strategy, ",".join(config.domains)], self.stop
        ) as worker:
            self.zapret_ready.set()
            self.emit("zapret", "status", "Работает", ready=True)
            while not self.stop.wait(0.15):
                if wait_handle(worker):
                    raise OSError(
                        f"Помощник zapret2 завершился с кодом {process_exit_code(worker)}."
                    )

    def _tor(self, config: TorConfig, cascade: bool) -> None:
        if cascade:
            self.emit("tor", "status", "Ожидание zapret2")
            while not self.zapret_ready.wait(0.15):
                if self.stop.is_set():
                    return
                if self.zapret_finished.is_set():
                    raise OSError("Для каскада сначала должен запуститься zapret2.")
        if self.stop.is_set():
            return
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                sock.bind(("127.0.0.1", config.port))
            except OSError as exc:
                raise OSError(
                    f"Порт SOCKS5 {config.port} занят или недоступен. Выберите другой порт."
                ) from exc
        root = private_directory(Path(os.environ["LOCALAPPDATA"]) / "FLURUX")
        cache = private_directory(root / "tor-state")
        with private_session(root / "sessions-v3") as folder:
            config_file = folder / "torrc"
            config_file.write_text(torrc(config), encoding="ascii")
            log_file = folder / "tor.log"
            tail = LogTail(log_file)
            cwd = config.plugin.parent if config.plugin else config.exe.parent
            args = [str(config.exe), "-f", str(config_file), "--DataDirectory", str(cache)]
            for option, file in (("--GeoIPFile", "geoip"), ("--GeoIPv6File", "geoip6")):
                path = config.exe.parent.parent / "data" / file
                if path.is_file():
                    args.extend((option, str(path)))
            self.emit("tor", "status", "Подключение · 0%")
            with managed_process(args, cwd, log_file) as process:
                while not self.stop.wait(0.15):
                    if cascade and self.zapret_finished.is_set():
                        raise OSError("zapret2 завершился. Каскад Tor остановлен.")
                    code = process.poll()
                    for line in tail.read(final=code is not None):
                        self.emit("tor", "log", URL_LOG.sub("[URL скрыт]", line))
                        match = BOOTSTRAP.search(line)
                        if match and code is None:
                            progress = int(match[1])
                            if progress == 100:
                                self.emit("tor", "status", "Подключён · 100%", ready=True)
                            else:
                                self.emit("tor", "status", f"Подключение · {progress}%")
                    if code is not None:
                        raise OSError(f"Tor завершился с кодом {code}. Подробности в журнале.")


def probe_args(url: str, port: int | None, *, tor_check: bool = False) -> list[str]:
    """Construct a bounded curl request with explicit direct or SOCKS routing."""
    proxy = "" if port is None else f"socks5h://127.0.0.1:{port}"
    args = [
        str(system_curl()),
        "--disable",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--proxy",
        proxy,
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--location",
        "--max-redirs",
        "4",
        "--connect-timeout",
        "22" if port is not None else "8",
        "--max-time",
        "38" if port is not None else "18",
    ]
    if tor_check:
        args.extend(("--max-filesize", "8192"))
    else:
        args.extend(("--output", "NUL", "--write-out", "%{http_code}\n%{time_total}"))
    return [*args, "--", url]


def check_route(url: str, port: int | None, *, tor_check: bool = False) -> str:
    """Return a route test result without changing system proxy settings."""
    output = subprocess.run(
        probe_args(url, port, tor_check=tor_check),
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=43 if port is not None else 22,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if output.returncode:
        detail = output.stderr.strip() or str(output.returncode)
        raise OSError(detail)
    if tor_check:
        status = json.loads(output.stdout)
        if not isinstance(status, dict) or status.get("IsTor") is not True:
            raise ValueError("Tor Project не подтвердил выход через Tor.")
        return f"Tor подтверждён · IP {status.get('IP', 'не указан')}"
    code, duration = output.stdout.strip().splitlines()
    return f"HTTP {code} · {float(duration):.2f} с"
