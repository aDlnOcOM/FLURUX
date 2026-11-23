import base64
import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit

from route_manager.profiles import protect
from route_manager.security import program_files, verify_external

MODES = {
    "zapret": "zapret2",
    "tor": "Tor",
    "both": "zapret2 + Tor",
    "cascade": "WebTunnel через zapret2",
}
STRATEGIES = {"split": "Разделение TLS", "disorder": "Перестановка TLS", "quic": "TLS + QUIC"}
TRANSPORTS = {
    "webtunnel": "WebTunnel",
    "obfs4": "obfs4",
    "snowflake": "Snowflake",
    "direct": "Прямое подключение",
}
TOR_CHECK = "https://check.torproject.org/api/ip"
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True, slots=True)
class Settings:
    """User configuration stored beside the application."""

    mode: str = "both"
    winws: str = ""
    strategy: str = "split"
    domains: str = ""
    tor: str = ""
    transport: str = "webtunnel"
    webtunnel_bridges: str = ""
    obfs4_bridges: str = ""
    snowflake_bridges: str = ""
    socks_port: str = "19050"
    target: str = ""


@dataclass(frozen=True, slots=True)
class TorConfig:
    """Validated Tor executable, transport and local endpoint."""

    exe: Path
    plugin: Path | None
    transport: str
    bridges: tuple[str, ...]
    port: int


@dataclass(frozen=True, slots=True)
class ZapretConfig:
    """Validated executable, packet strategy and DNS suffixes."""

    exe: Path
    strategy: str
    domains: tuple[str, ...]


def load_settings(path: Path) -> Settings:
    """Read saved strings and fill missing fields from defaults."""
    if not path.exists():
        return Settings()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Файл настроек должен содержать объект JSON.")
    encrypted = "protected" in data
    if encrypted:
        data = json.loads(protect(base64.b64decode(data["protected"], validate=True), decrypt=True))
        if not isinstance(data, dict):
            raise ValueError("Повреждён защищённый файл настроек.")
    allowed = {field.name for field in fields(Settings)}
    settings = Settings(
        **{key: value for key, value in data.items() if key in allowed and isinstance(value, str)}
    )
    if not encrypted:
        save_settings(path, settings)
    return settings


def save_settings(path: Path, settings: Settings) -> None:
    """Replace the settings file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        blob = protect(json.dumps(asdict(settings), ensure_ascii=False).encode())
        json.dump({"version": 2, "protected": base64.b64encode(blob).decode()}, handle)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def domain_name(value: str) -> str:
    """Normalize a domain for a zapret host list."""
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Некорректный домен: {value}") from exc
    if (
        len(domain) > 253
        or "." not in domain
        or not all(HOST_LABEL.fullmatch(label) for label in domain.split("."))
    ):
        raise ValueError(f"Укажите домен без URL, порта и маски: {value}")
    return domain


def parse_domains(raw: str) -> tuple[str, ...]:
    """Accept domains separated by spaces, commas or newlines."""
    tokens = re.split(r"[\s,;]+", raw.strip())
    return tuple(dict.fromkeys(domain_name(token) for token in tokens if token))


def parse_bridge_lines(raw: str, transport: str) -> tuple[str, ...]:
    """Accept complete bridge lines for the selected transport."""
    bridges: list[str] = []
    for number, raw_line in enumerate(raw.splitlines(), 1):
        parts = raw_line.split()
        if not parts:
            continue
        if parts[0].lower() == "bridge":
            parts = parts[1:]
        if (
            len(parts) < 3
            or parts[0] != transport
            or any(
                ord(char) < 33 or ord(char) > 126 or char in '#"\\'
                for part in parts
                for char in part
            )
        ):
            raise ValueError(f"Строка моста {number} не соответствует транспорту {transport}.")
        bridges.append(" ".join(parts))
    return tuple(dict.fromkeys(bridges))


def bundled_snowflake(exe: Path) -> tuple[str, ...]:
    """Read Snowflake bridge lines shipped with the selected Expert Bundle."""
    for folder in (exe.parent / "pluggable_transports", exe.parent.parent / "data", exe.parent):
        path = folder / "pt_config.json"
        if path.is_file():
            entries = json.loads(path.read_text(encoding="utf-8"))["bridges"]["snowflake"]
            if isinstance(entries, list) and all(isinstance(entry, str) for entry in entries):
                return parse_bridge_lines("\n".join(entries), "snowflake")
    return ()


def executable(value: str, name: str) -> Path:
    """Resolve a selected binary and reject missing or incorrect files."""
    exe = Path(value).expanduser().resolve()
    if exe.name.lower() != name or not exe.is_file():
        raise ValueError(f"В настройках выберите файл {name} из официальной сборки.")
    return exe


def prepare_tor(settings: Settings) -> TorConfig:
    """Validate Tor settings before a session starts."""
    exe = executable(settings.tor, "tor.exe")
    verify_external(exe, "tor")
    transport = settings.transport
    if transport not in TRANSPORTS:
        raise ValueError("Выберите транспорт Tor.")
    if not settings.socks_port.isascii() or not settings.socks_port.isdecimal():
        raise ValueError("Порт SOCKS5 должен быть целым числом от 1024 до 65535.")
    port = int(settings.socks_port)
    if not 1024 <= port <= 65535:
        raise ValueError("Порт SOCKS5 должен быть целым числом от 1024 до 65535.")
    if transport == "direct":
        return TorConfig(exe, None, transport, (), port)
    bridge_sets = {
        "webtunnel": settings.webtunnel_bridges,
        "obfs4": settings.obfs4_bridges,
        "snowflake": settings.snowflake_bridges,
    }
    bridges = parse_bridge_lines(bridge_sets[transport], transport)
    if not bridges and transport == "snowflake":
        try:
            bridges = bundled_snowflake(exe)
        except (KeyError, OSError, TypeError, ValueError):
            bridges = ()
    if not bridges:
        raise ValueError(f"Вставьте хотя бы одну полную строку моста {transport}.")
    names = (
        ("lyrebird.exe", "snowflake-client.exe") if transport == "snowflake" else ("lyrebird.exe",)
    )
    folders = (
        exe.parent / "pluggable_transports",
        exe.parent.parent / "pluggable_transports",
        exe.parent,
    )
    plugin = next(
        (folder / name for name in names for folder in folders if (folder / name).is_file()), None
    )
    if plugin is None:
        raise ValueError(
            "Распакуйте Tor Expert Bundle целиком. Для моста нужен транспорт из сборки."
        )
    verify_external(plugin, plugin.stem)
    return TorConfig(exe, plugin, transport, bridges, port)


def webtunnel_domains(config: TorConfig) -> tuple[str, ...]:
    """Find the actual TLS names used by configured WebTunnel bridges."""
    if config.transport != "webtunnel":
        raise ValueError("Каскад требует выбрать транспорт WebTunnel.")
    domains: list[str] = []
    for line in config.bridges:
        options = dict(token.split("=", 1) for token in line.split()[2:] if "=" in token)
        target = urlsplit(options.get("url", ""))
        if target.scheme != "https" or not target.hostname:
            raise ValueError("В каждой строке WebTunnel для каскада нужен параметр url=https://…")
        port = urlsplit(f"//{options['addr']}").port if "addr" in options else target.port or 443
        if port != 443:
            raise ValueError("Каскад zapret2 поддерживает мосты WebTunnel на порту 443.")
        domains.append(domain_name(options.get("servername") or target.hostname))
    return tuple(dict.fromkeys(domains))


def prepare_zapret(settings: Settings, bridge_domains: tuple[str, ...] = ()) -> ZapretConfig:
    """Validate the selected winws2 bundle and the list of destinations."""
    exe = program_files() / "FLURUX" / "Security" / "engine" / "winws2.exe"
    if not exe.is_file():
        raise ValueError("Установите FLURUX-Security-x64.msi из архива приложения.")
    if settings.strategy not in STRATEGIES:
        raise ValueError("Выберите стратегию zapret2.")
    domains = tuple(dict.fromkeys((*parse_domains(settings.domains), *bridge_domains)))
    if len(",".join(domains)) > 12000:
        raise ValueError("Суммарная длина списка доменов ограничена 12000 символами.")
    if not domains:
        raise ValueError("Добавьте домены для zapret2 в настройках.")
    required = [
        "lua/zapret-lib.lua",
        "lua/zapret-antidpi.lua",
        "WinDivert.dll",
        "WinDivert64.sys",
        "cygwin1.dll",
    ]
    if settings.strategy == "quic":
        required.append("files/quic_initial_www_google_com.bin")
    missing = [item for item in required if not (exe.parent / item).is_file()]
    if missing:
        raise ValueError("Распакуйте сборку zapret целиком. Не найдены: " + ", ".join(missing))
    return ZapretConfig(exe, settings.strategy, domains)


def validated_url(raw: str) -> str:
    """Accept an HTTP(S) test URL, adding HTTPS to bare domains."""
    value = raw.strip()
    if not value or any(char.isspace() or ord(char) < 32 or char == "\\" for char in value):
        raise ValueError("Укажите адрес сайта для проверки.")
    candidate = value if "://" in value else f"https://{value}"
    result = urlsplit(candidate)
    if result.scheme not in ("http", "https") or not result.hostname or result.username is not None:
        raise ValueError("Укажите URL http:// или https:// без учётных данных.")
    if result.port == 0:
        raise ValueError("Порт сайта должен быть больше нуля.")
    return candidate


def zapret_args(config: ZapretConfig, hostlist: Path) -> list[str]:
    """Build winws2 arguments using the official Lua strategies."""
    hosts = f"--hostlist={hostlist}"
    method = "multidisorder" if config.strategy == "disorder" else "multisplit"
    args = [
        str(config.exe),
        "--wf-tcp-out=443",
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
    ]
    if config.strategy == "quic":
        args.extend(("--wf-udp-out=443", "--blob=quic:@files/quic_initial_www_google_com.bin"))
    args.extend(
        (
            "--filter-tcp=443",
            "--filter-l7=tls",
            hosts,
            "--out-range=-d10",
            "--payload=tls_client_hello",
            f"--lua-desync={method}:pos=1,midsld",
        )
    )
    if config.strategy == "quic":
        args.extend(
            (
                "--new",
                "--filter-udp=443",
                "--filter-l7=quic",
                hosts,
                "--out-range=-d10",
                "--payload=quic_initial",
                "--lua-desync=fake:blob=quic:repeats=6",
            )
        )
    return args


def torrc(config: TorConfig) -> str:
    """Generate a Tor client configuration with a loopback-only SOCKS port."""
    directives = [
        f"SocksPort 127.0.0.1:{config.port}",
        "ClientOnly 1",
        "SafeLogging 1",
        "Log notice stdout",
        "AvoidDiskWrites 1",
    ]
    if config.plugin:
        directives.extend(
            (
                "UseBridges 1",
                f"ClientTransportPlugin {config.transport} exec ./{config.plugin.name}",
            )
        )
        directives.extend(f"Bridge {line}" for line in config.bridges)
    return "\n".join(directives) + "\n"
