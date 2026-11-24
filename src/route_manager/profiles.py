import ctypes
import ipaddress
import json
import msvcrt
import os
import re
import secrets
import uuid
from ctypes import wintypes
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

type Obj = dict[str, Any]

# Entry and exit describe the order seen by the client.
STRATEGIES = {
    "ovpn_http": ("OpenVPN TCP через HTTP CONNECT", ("http", "openvpn")),
    "ovpn_socks": ("OpenVPN TCP через SOCKS5", ("socks", "openvpn")),
    "dns_https": ("DNS через HTTPS · DoH", ("doh",)),
    "dns_tls": ("DNS через TLS · DoT", ("dot",)),
    "ech": ("Firefox · ECH и DoH", ("doh",)),
    "psiphon": ("Psiphon · Tunnel Core", ()),
    "ss": ("Shadowsocks", ("ss",)),
    "ssh_single": ("SSH · динамический SOCKS5", ("ssh",)),
    "https": ("HTTPS-прокси с TLS до входа", ("https",)),
    "chain": ("Каскад двух прикладных прокси", ("https", "socks")),
    "tor_http": ("Tor через HTTP CONNECT", ("http",)),
    "tor_socks": ("Tor через SOCKS5", ("socks",)),
    "relay_tcp": ("Ретранслятор фиксированного TCP-порта", ("relay_tcp",)),
    "relay_udp": ("Ретранслятор фиксированного UDP-порта", ("relay_udp",)),
    "nested": ("Два вложенных WireGuard-туннеля", ("wg", "wg")),
    "forwarded": ("WireGuard со вторым VPN на шлюзе", ("wg", "wg")),
    "ssh": ("SSH ProxyJump с локальным SOCKS5", ("ssh", "ssh")),
    "masque_udp": ("MASQUE CONNECT-UDP", ("masque_udp",)),
    "masque_ip": ("MASQUE CONNECT-IP", ("masque_ip",)),
    "socks_udp": ("SOCKS5 с UDP ASSOCIATE", ("socks",)),
    "ss_ws": ("Shadowsocks через WebSocket и TLS", ("ss_ws",)),
    "hy2": ("Hysteria 2", ("hy2",)),
    "awg": ("AmneziaWG", ("awg",)),
    "reality": ("VLESS с REALITY", ("reality",)),
    "mesh_exit": ("Mesh · выходной узел Tailscale", ("mesh_exit",)),
    "mesh_relay": ("Mesh · ретранслятор Tailscale", ("mesh_relay",)),
}
CHAIN_TYPES = ("socks", "http", "https", "hy2")
PORTS = {
    "socks": 1080,
    "http": 3128,
    "dot": 853,
    "ss": 8388,
    "wg": 51820,
    "awg": 51820,
    "ssh": 22,
    "openvpn": 1194,
    "relay_tcp": 8443,
    "relay_udp": 51821,
    "mesh_relay": 40000,
}
TLS_TYPES = {"https", "openvpn", "masque_ip", "masque_udp", "ss_ws", "hy2", "doh", "dot"}
WG_TYPES = {"wg", "awg"}
ENDPOINT_TYPES = {"wg", "openvpn", "masque_ip"}


def template(kind: str) -> Obj:
    """Make an editable profile without contacting any hosts."""
    _, roles = STRATEGIES[kind]
    nodes = []
    for role in roles:
        nodes.append(
            {
                "type": role,
                "host": "",
                "port": PORTS.get(role, 443),
                "ssh": "",
                "username": "routes",
                "managed": False,
                "password": "",
                "tls_name": "",
                "certificate": "",
                "public_key": "",
                "uplink_public": "",
                "client_private": "",
                "client_public": "",
            }
        )
    return {
        "id": uuid.uuid4().hex,
        "kind": kind,
        "name": STRATEGIES[kind][0],
        "local_port": 5353 if kind in ("dns_https", "dns_tls") else 1088,
        "sync_on_connect": True,
        "access_cidr": "",
        "psiphon_config": "",
        "psiphon_servers": "",
        "system_tun": False,
        "network_lock": False,
        "allow_plain_proxy": False,
        "target_host": "",
        "target_port": 443,
        "engine_path": "",
        "engine_sha256": "",
        "nodes": nodes,
    }


def port(value: object) -> int:
    """Validate a network port."""
    if not str(value).isascii() or not str(value).isdigit() or not 1 <= int(str(value)) <= 65535:
        raise ValueError("Порт должен быть числом от 1 до 65535.")
    return int(str(value))


def host(value: str) -> str:
    """Accept an IP literal or an ASCII DNS name."""
    if (
        not isinstance(value, str)
        or not value.isascii()
        or "%" in value
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Адрес содержит недопустимые символы или идентификатор зоны.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (
            not value
            or len(value) > 253
            or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                for part in value.split(".")
            )
        ):
            raise ValueError("Укажите IP-адрес или DNS-имя без схемы и номера порта.") from None
        return value


def ssh_target(value: str) -> str:
    """Accept an explicit OpenSSH config alias or user@host."""
    if not re.fullmatch(r"(?:[a-zA-Z0-9_][\w.-]*@)?[a-zA-Z0-9][a-zA-Z0-9._-]*", value):
        raise ValueError(
            "Укажите SSH-псевдоним или user@host. Порт и ключ можно задать в ~/.ssh/config."
        )
    return value


def validate(p: Obj) -> None:
    """Validate topology before starting a client or connecting to a server."""
    if not re.fullmatch("[0-9a-f]{32}", p["id"]) or p["kind"] not in STRATEGIES:
        raise ValueError("Неизвестный профиль.")
    port(p["local_port"])
    roles = STRATEGIES[p["kind"]][1]
    if len(roles) != len(p["nodes"]):
        raise ValueError("Неверное количество узлов.")
    for role, n in zip(roles, p["nodes"], strict=True):
        if (
            n["type"] != role
            and not (p["kind"] == "chain" and n["type"] in CHAIN_TYPES)
            and not (p["kind"] == "ovpn_http" and role == "http" and n["type"] == "https")
        ):
            raise ValueError("Тип узла несовместим с профилем.")
        host(n["host"])
        port(n["port"])
        if n["ssh"]:
            ssh_target(n["ssh"])
        if n["tls_name"]:
            host(n["tls_name"])
        if any(
            c in str(n[k])
            for c in "\r\n\0"
            for k in (
                "username",
                "password",
                "ssh",
                "public_key",
                "client_private",
                "client_public",
            )
        ):
            raise ValueError("Переносы строк в реквизитах недопустимы.")
    if p.get("network_lock") and p.get("system_tun"):
        try:
            ipaddress.ip_address(p["nodes"][0]["host"])
        except (ValueError, IndexError):
            raise ValueError(
                "Для сетевой блокировки укажите IP входного узла и отдельное TLS-имя."
            ) from None
    if p["kind"] in {"relay_tcp", "relay_udp", "masque_udp"}:
        host(p["target_host"])
        port(p["target_port"])
    if (
        p["kind"] == "chain"
        and p["nodes"][0]["type"] in ("http", "https")
        and p["nodes"][1]["type"] == "hy2"
    ):
        raise ValueError("Hysteria 2 на втором узле требует первого узла с поддержкой UDP.")


def check_proxy_credentials(p: Obj, *, installing: bool = False) -> None:
    """Require informed consent for credentials exposed to the local network."""
    if p.get("allow_plain_proxy") is True:
        return
    for n in p["nodes"]:
        if n["type"] not in ("socks", "http"):
            break
        try:
            loopback = ipaddress.ip_address(n["host"]).is_loopback
        except ValueError:
            loopback = False
        if not loopback and (n["password"] or (installing and n["ssh"])):
            raise ValueError(
                "Пароль прокси будет виден в сети. Выберите HTTPS, SSH или явно разрешите открытый пароль в профиле."
            )


def source_network(value: str) -> str:
    """Validate a restricted source network before changing a server."""
    try:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen:
            return str(network)
    except ValueError:
        pass
    raise ValueError(
        "Укажите разрешённую сеть CIDR, например 198.51.100.42/32. Доступ для всего интернета запрещён."
    )


class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_char))]


def protect(raw: bytes, *, decrypt: bool = False) -> bytes:
    """Protect profile credentials with the Windows user's DPAPI key."""
    data = ctypes.create_string_buffer(raw)
    src = Blob(len(raw), ctypes.cast(data, ctypes.POINTER(ctypes.c_char)))
    dst = Blob()
    dll = ctypes.WinDLL("crypt32", use_last_error=True)
    func = dll.CryptUnprotectData if decrypt else dll.CryptProtectData
    if not func(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(dst.data, dst.size)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(dst.data, ctypes.c_void_p))


def load_profiles(path: Path) -> list[Obj]:
    """Load the current Windows account's encrypted profile collection."""
    if not path.exists():
        return []
    entries = json.loads(protect(path.read_bytes(), decrypt=True))
    if not isinstance(entries, list):
        raise ValueError("Некорректный формат хранилища профилей.")
    for p in entries:
        if (
            not isinstance(p, dict)
            or p.get("kind") not in STRATEGIES
            or not isinstance(p.get("nodes"), list)
            or len(p["nodes"]) != len(STRATEGIES[p["kind"]][1])
            or not isinstance(p.get("name"), str)
            or not re.fullmatch("[0-9a-f]{32}", str(p.get("id", "")))
        ):
            raise ValueError("Некорректная запись в хранилище профилей.")
        defaults = template(p["kind"])
        for key, val in defaults.items():
            p.setdefault(key, val)
        for n, base_node in zip(p["nodes"], defaults["nodes"], strict=True):
            if not isinstance(n, dict):
                raise ValueError("Некорректная запись узла.")
            for key, val in base_node.items():
                n.setdefault(key, val)
    return entries


def save_profiles(path: Path, profiles: list[Obj]) -> None:
    """Atomically replace the encrypted collection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    encrypted = protect(json.dumps(profiles, ensure_ascii=False).encode())
    with NamedTemporaryFile(dir=path.parent, delete=False) as out:
        tmp = Path(out.name)
        try:
            out.write(encrypted)
            out.flush()
            os.fsync(out.fileno())
        finally:
            out.close()
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def update_profile(path: Path, p: Obj) -> list[Obj]:
    """Merge one profile under a cross-process lock before replacing the vault."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(".lock").open("a+b") as lock:
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        try:
            latest = [item for item in load_profiles(path) if item["id"] != p["id"]] + [p]
            save_profiles(path, latest)
            return latest
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def ensure_secrets(p: Obj) -> None:
    """Initialize credentials only for user-managed nodes."""
    for n in p["nodes"]:
        if n["ssh"] and n["type"] not in WG_TYPES | {
            "ssh",
            "doh",
            "dot",
            "mesh_exit",
            "mesh_relay",
            "relay_tcp",
            "relay_udp",
        }:
            if not n["password"]:
                n["password"] = (
                    str(uuid.uuid4()) if n["type"] == "reality" else secrets.token_urlsafe(32)
                )
            if not n["username"]:
                n["username"] = "routes"
