import base64
import json
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit

from route_manager.profiles import protect
from route_manager.security import program_files, verify_external
from route_manager.zapret_presets import FAMILIES, METHODS, QUIC_METHODS

MODES = {
    "zapret": "Только zapret2",
    "tor": "Tor",
    "both": "zapret2 + Tor",
    "cascade": "WebTunnel через zapret2",
}
STRATEGIES = METHODS
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

    mode: str = "tor"
    winws: str = ""
    strategy: str = "split"
    domains: str = ""
    exclude_domains: str = ""
    tcp_ports: str = "443"
    udp_ports: str = "443"
    ip_family: str = "both"
    tor: str = ""
    transport: str = "direct"
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

    excluded: tuple[str, ...] = ()
    tcp_ports: str = "443"
    udp_ports: str = "443"
    ip_family: str = "both"


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


def socks_port(value: str) -> int:
    """Validate a Tor listener port before downloading or starting an engine."""
    if (
        not value.isascii()
        or not value.isdecimal()
        or len(value) > 5
        or not 1024 <= int(value) <= 65535
    ):
        raise ValueError("Порт SOCKS5 должен быть целым числом от 1024 до 65535.")
    return int(value)


def prepare_tor(settings: Settings) -> TorConfig:
    """Validate Tor settings before a session starts."""
    exe = executable(settings.tor, "tor.exe")
    verify_external(exe, "tor")
    transport = settings.transport
    if transport not in TRANSPORTS:
        raise ValueError("Выберите транспорт Tor.")
    port = socks_port(settings.socks_port)
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


def port_list(value: str) -> str:
    """Validate and normalize up to sixteen destination ports."""
    items = re.split(r"[\s,;]+", value.strip())
    if not all(
        p.isascii() and p.isdecimal() and len(p) <= 5 and 1 <= int(p) <= 65535 for p in items
    ):
        raise ValueError("Введите порты от 1 до 65535 через запятую.")
    ports = list(dict.fromkeys(str(int(p)) for p in items))
    if len(ports) > 16:
        raise ValueError("Можно задать до 16 портов для каждого протокола.")
    return ",".join(ports)


def zapret_options(
    settings: Settings, bridges: tuple[str, ...] = (), *, require_domains: bool = True
) -> tuple[tuple[str, ...], tuple[str, ...], str, str]:
    """Validate scope, exclusions and ports before starting the worker."""
    if settings.ip_family not in FAMILIES:
        raise ValueError("Выберите IPv4, IPv6 или оба семейства.")
    if settings.strategy not in STRATEGIES:
        raise ValueError("Выберите стратегию zapret2.")
    domains = tuple(dict.fromkeys((*parse_domains(settings.domains), *bridges)))
    excluded = parse_domains(settings.exclude_domains)
    if len(",".join(domains)) + len(",".join(excluded)) > 12000:
        raise ValueError("Оба списка вместе могут содержать до 12 000 символов.")
    if not domains and require_domains:
        raise ValueError("Добавьте хотя бы один сайт в список доменов.")
    tcp = port_list(settings.tcp_ports)
    udp = port_list(settings.udp_ports) if settings.strategy in QUIC_METHODS else "443"
    if bridges and (
        "443" not in tcp.split(",")
        or any(b == e or b.endswith("." + e) for b in bridges for e in excluded)
    ):
        raise ValueError(
            "Для WebTunnel включите TCP-порт 443 и уберите домены мостов из исключений."
        )
    if domains and all(any(d == e or d.endswith("." + e) for e in excluded) for d in domains):
        raise ValueError("Исключения охватывают все выбранные сайты.")
    return domains, excluded, tcp, udp


def prepare_zapret(settings: Settings, bridge_domains: tuple[str, ...] = ()) -> ZapretConfig:
    """Validate the selected winws2 bundle and the list of destinations."""
    exe = program_files() / "FLURUX" / "Security" / "engine" / "winws2.exe"
    if not exe.is_file():
        raise ValueError("Откройте вкладку «zapret2» и нажмите «Установить движок».")
    domains, excluded, tcp, udp = zapret_options(settings, bridge_domains)
    required = [
        "lua/zapret-lib.lua",
        "lua/zapret-antidpi.lua",
        "WinDivert.dll",
        "WinDivert64.sys",
        "cygwin1.dll",
    ]
    if settings.strategy in QUIC_METHODS:
        required.append("files/quic_initial_www_google_com.bin")
    missing = [item for item in required if not (exe.parent / item).is_file()]
    if missing:
        raise ValueError("Распакуйте сборку zapret целиком. Не найдены: " + ", ".join(missing))
    return ZapretConfig(exe, settings.strategy, domains, excluded, tcp, udp, settings.ip_family)


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
    exceptions = (
        ["--hostlist-exclude-domains=" + ",".join(config.excluded)] if config.excluded else []
    )
    method = "multidisorder" if config.strategy in ("disorder", "disorder_quic") else "multisplit"
    args = [
        str(config.exe),
        *([] if config.ip_family == "both" else ["--wf-l3=" + config.ip_family]),
        f"--wf-tcp-out={config.tcp_ports}",
        "--lua-init=@lua/zapret-lib.lua",
        "--lua-init=@lua/zapret-antidpi.lua",
    ]
    if config.strategy in QUIC_METHODS:
        args.extend(
            (
                f"--wf-udp-out={config.udp_ports}",
                "--blob=quic:@files/quic_initial_www_google_com.bin",
            )
        )
    args.extend(
        (
            f"--filter-tcp={config.tcp_ports}",
            "--filter-l7=tls",
            hosts,
            *exceptions,
            "--out-range=-d10",
            "--payload=tls_client_hello",
            f"--lua-desync={method}:pos=1,midsld",
        )
    )
    if config.strategy in QUIC_METHODS:
        args.extend(
            (
                "--new",
                f"--filter-udp={config.udp_ports}",
                "--filter-l7=quic",
                hosts,
                *exceptions,
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
