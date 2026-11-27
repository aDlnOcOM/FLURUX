import base64
import ctypes
import gzip
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from time import monotonic

from route_manager.private_files import private_directory, private_session
from route_manager.profiles import (
    Obj,
    check_proxy_credentials,
    ensure_secrets,
    port,
    source_network,
    ssh_target,
    validate,
)
from route_manager.security import (
    check_engine,
    guard_session,
    program_files,
    protected_path,
    verify_external,
)
from route_manager.topology import authority, capsule, client, server, xray_ws
from route_manager.windows import managed_process, wait_handle

type Notify = Callable[[str], None]
SSH_FLAGS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ConnectTimeout=12",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=2",
]


def binary(name: str, supplied: str = "", checksum: str = "") -> str:
    """Locate an explicitly selected or installed Windows engine."""
    if supplied:
        path = Path(supplied).expanduser()
        if path.is_file() and path.suffix.lower() == ".exe":
            path = path.resolve()
            verify_external(path, name, checksum)
            return str(path)
        raise ValueError("Исполняемый файл движка не найден.")
    program = program_files()
    extra = {
        "wg": program / "WireGuard" / "wg.exe",
        "firefox": program / "Mozilla Firefox/firefox.exe",
        "tailscale": program / "Tailscale/tailscale.exe",
        "amneziawg": program / "AmneziaWG/amneziawg.exe",
        "ssh": Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/OpenSSH/ssh.exe",
    }
    if name in extra and extra[name].is_file():
        verify_external(extra[name], name, checksum)
        return str(extra[name])
    candidate = program / "FLURUX" / "engines" / name / (name + ".exe")
    if candidate.is_file():
        verify_external(candidate, name, checksum)
        return str(candidate)
    raise ValueError(f"Не найден {name}.exe. Выберите установленный движок в профиле.")


def command(
    args: list[str], *, data: str | None = None, timeout: int = 25, details: bool = True
) -> str:
    """Run a non-interactive tool while keeping arguments out of exceptions."""
    try:
        result = subprocess.run(
            args,
            input=data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(f"{Path(args[0]).name} не ответил за {timeout} с.") from None
    if result.returncode:
        detail = result.stderr.strip()[-450:] if details else ""
        raise ValueError(f"{Path(args[0]).name}, код {result.returncode}. {detail}")
    return result.stdout.strip()


def keys(p: Obj) -> None:
    """Generate only the client key pairs required by this topology."""
    for i, n in enumerate(p["nodes"]):
        if not n["ssh"] or n["type"] not in {"wg", "awg"} or (p["kind"] == "forwarded" and i == 1):
            continue
        if n["client_private"] and n["client_public"]:
            continue
        if n["client_private"] or n["client_public"]:
            raise ValueError("Укажите обе части клиентской пары WireGuard или очистите оба поля.")
        try:
            wgtool = binary("wg")
        except ValueError:
            wgtool = ""
        if wgtool:
            private = command([wgtool, "genkey"])
            public = command([wgtool, "pubkey"], data=private + "\n")
        else:
            output = command(
                [
                    binary("sing-box", p["engine_path"] if p["kind"] != "awg" else ""),
                    "generate",
                    "wg-keypair",
                ]
            )
            pair = dict(line.split(":", 1) for line in output.splitlines())
            private, public = pair["PrivateKey"].strip(), pair["PublicKey"].strip()
        n.update(client_private=private, client_public=public)


def management_args(n: Obj, via: str = "") -> list[str]:
    """Reach the exit's SSH alias through the configured entry when both are managed."""
    args = [binary("ssh"), *SSH_FLAGS]
    if via:
        proxy = subprocess.list2cmdline([args[0], *SSH_FLAGS, "-W", "[%h]:%p", ssh_target(via)])
        args.extend(["-o", "ProxyCommand=" + proxy])
    return [*args, "-T", ssh_target(n["ssh"])]


def remote(n: Obj, request: Obj, via: str = "") -> Obj:
    """Run the packaged Linux installer over an explicitly configured SSH connection."""
    if request.get("action") == "public":
        instance = request["instance"]
        if not re.fullmatch(r"rm-[0-9a-f]{32}-[01]", instance):
            raise ValueError("Недопустимое имя экземпляра.")
        try:
            result = json.loads(
                command(
                    [
                        *management_args(n, via),
                        "/bin/cat -- /usr/local/lib/flurux/public/" + instance + ".json",
                    ],
                    details=False,
                )
            )
        except ValueError:
            raise ValueError(
                "Не удалось прочитать публичные данные по SSH. Проверьте подключение и повторите настройку узла новой версией."
            ) from None
        if not isinstance(result, dict):
            raise ValueError("Неверный формат публичных данных узла.")
        return result
    worker = Path(__file__).with_name("linux_node.py").read_bytes()
    encoded = base64.b64encode(gzip.compress(worker)).decode("ascii")
    program = f"import base64,gzip;exec(compile(gzip.decompress(base64.b64decode('{encoded}')),'routes-node','exec'))"
    cmd = (
        'if [ "$(id -u)" = 0 ]; then set -- python3; else set -- sudo -n -- python3; fi; exec "$@" -c '
        + shlex.quote(program)
    )
    output = command(
        [*management_args(n, via), cmd],
        data=json.dumps(request) + "\n",
        timeout=620,
    )
    result = json.loads(output)
    if not isinstance(result, dict):
        raise ValueError("Некорректный ответ службы установки.")
    return result


def awg_config(n: Obj, *, serving: bool = False, subnet: int = 0) -> str:
    """Generate matching AmneziaWG 1.x parameters and peer keys."""
    addr = f"10.233.{subnet}."
    private = "@WG_PRIVATE@" if serving else n["client_private"]
    public = n["client_public"] if serving else n["public_key"]
    for k in (public,) if serving else (private, public):
        if len(base64.b64decode(k, validate=True)) != 32:
            raise ValueError("AmneziaWG требует ключи формата WireGuard.")
    fields = [
        "[Interface]",
        f"PrivateKey = {private}",
        f"Address = {addr}{'1/24' if serving else '2/32'}",
        "MTU = 1280",
        "Jc = 4",
        "Jmin = 40",
        "Jmax = 90",
        "S1 = 51",
        "S2 = 64",
        "H1 = 1419229",
        "H2 = 1419233",
        "H3 = 1419239",
        "H4 = 1419241",
    ]
    if serving:
        fields.extend(
            [
                f"ListenPort = {port(n['port'])}",
                f"PostUp = iptables -t nat -A POSTROUTING -s {addr}0/24 ! -o %i -j MASQUERADE",
                f"PostDown = iptables -t nat -D POSTROUTING -s {addr}0/24 ! -o %i -j MASQUERADE",
                "PostUp = iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            ]
        )
    fields += [
        "[Peer]",
        f"PublicKey = {public}",
        f"AllowedIPs = {addr}2/32" if serving else "AllowedIPs = 0.0.0.0/0, ::/0",
    ]
    if not serving:
        fields += [
            f"Endpoint = {authority(n['host'], port(n['port']))}",
            "PersistentKeepalive = 25",
        ]
    return "\n".join(fields) + "\n"


def public_material(material: Obj) -> Obj:
    """Accept only complete public certificates or canonical 32-byte public keys."""
    result: Obj = {}
    for field in ("public_key", "uplink_public", "certificate"):
        if field not in material:
            continue
        value = material[field]
        if not isinstance(value, str) or len(value) > 32768:
            raise ValueError("Неверный формат публичных данных.")
        if field == "certificate":
            if not re.fullmatch(
                r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*",
                value,
            ):
                raise ValueError("Некорректный публичный сертификат.")
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=value)
        else:
            if re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
                raw = base64.urlsafe_b64decode(value + "=")
                canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            elif re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
                raw = base64.b64decode(value)
                canonical = base64.b64encode(raw).decode()
            else:
                raise ValueError("Некорректный публичный ключ.")
            if len(raw) != 32 or value != canonical:
                raise ValueError("Некорректный публичный ключ.")
        result[field] = value
    return result


def provision(p: Obj, notify: Notify, checkpoint: Callable[[], None]) -> None:
    """Prepare all selected hosts before applying their roles from exit to entry."""
    validate(p)
    check_proxy_credentials(p, installing=True)
    if p["kind"] in ("relay_tcp", "relay_udp", "dns_https", "dns_tls", "ech"):
        source_network(p["access_cidr"])
    owned = [(idx, n) for idx, n in enumerate(p["nodes"]) if n["ssh"]]
    if not owned:
        raise ValueError("Заполните SSH для собственного узла.")
    ensure_secrets(p)
    keys(p)
    checkpoint()
    for idx, n in owned:
        notify(f"Синхронизация ключей с {n['ssh']}")
        request = {
            "instance": f"rm-{p['id']}-{idx}",
            "action": "prepare",
            "uplink": p["kind"] == "forwarded" and idx == 0,
            "type": n["type"],
            "name": n["tls_name"] or n["host"],
        }
        via = p["nodes"][0]["ssh"] if idx else ""
        if n["type"] == "ssh":
            command([*management_args(n, via), "true"])
            continue
        material = remote(n, request, via)
        n.update(public_material(material))
        checkpoint()
    for idx, n in reversed(owned):
        kind = n["type"]
        if kind == "ssh":
            continue
        notify(f"Настройка {kind} на {n['ssh']}")
        config: str | Obj = {}
        if kind == "awg":
            config = awg_config(n, serving=True, subnet=int(p["id"][:2], 16))
        elif kind == "ss_ws":
            config = xray_ws(p, serving=True)
        elif kind == "masque_udp":
            config = capsule(p)
        elif kind in ("doh", "dot"):
            config = {"cidr": str(ipaddress.ip_network(p.get("access_cidr", ""), strict=False))}
            if int(config["cidr"].split("/")[1]) == 0:
                raise ValueError("Для своего DNS задайте ограниченную клиентскую сеть CIDR.")
        elif not kind.startswith("mesh_"):
            config = server(p, idx)
        result = remote(
            n,
            {
                "instance": f"rm-{p['id']}-{idx}",
                "action": "deploy",
                "type": kind,
                "port": port(n["port"]),
                "config": config,
                "worker": Path(__file__).with_name("masque_capsule.py").read_text(encoding="utf-8")
                if kind == "masque_udp"
                else "",
            },
            p["nodes"][0]["ssh"] if idx else "",
        )
        n["managed"] = True
        checkpoint()
        notify(result["message"])


def synchronize(p: Obj) -> None:
    """Refresh the installed nodes' public material without applying new services."""
    validate(p)
    check_proxy_credentials(p)
    if p.get("sync_on_connect", True):
        for idx, node in enumerate(p["nodes"]):
            if (
                node.get("managed")
                and node["ssh"]
                and node["type"]
                in {
                    "wg",
                    "awg",
                    "reality",
                    "doh",
                    "dot",
                    "https",
                    "hy2",
                    "openvpn",
                    "ss_ws",
                    "masque_udp",
                    "masque_ip",
                }
            ):
                reply = remote(
                    node,
                    {"instance": f"rm-{p['id']}-{idx}", "action": "public", "type": node["type"]},
                    p["nodes"][0]["ssh"] if idx else "",
                )
                material = public_material(reply)
                required = (
                    "public_key" if node["type"] in ("wg", "awg", "reality") else "certificate"
                )
                if not material.get(required):
                    raise ValueError(
                        "Узел не вернул ожидаемые публичные данные. Повторите настройку по SSH."
                    )
                node.update(material)


def engine_name(kind: str) -> str:
    """Return the Windows program used by a profile."""
    if kind.startswith("tor_"):
        return "tor"
    if kind.startswith("mesh_"):
        return "tailscale"
    return {
        "ss_ws": "xray",
        "masque_udp": "python",
        "awg": "amneziawg",
        "ssh": "ssh",
        "ssh_single": "ssh",
        "ech": "firefox",
        "psiphon": "psiphon-tunnel-core",
    }.get(kind, "sing-box")


def tor_quote(value: str) -> str:
    """Quote one torrc string without permitting new directives."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def setup(p: Obj, folder: Path, cache: Path) -> tuple[list[str], str]:
    """Translate a validated profile to a managed process and local listener description."""
    validate(p)
    check_proxy_credentials(p)
    kind = p["kind"]
    engine = engine_name(kind)
    exe = (
        sys.executable
        if engine == "python"
        else binary(engine, p["engine_path"], p.get("engine_sha256", ""))
    )
    if p["system_tun"] or kind == "awg":
        protected_path(Path(sys.executable))
        protected_path(Path(__file__).resolve())
        if not sys.flags.isolated:
            raise ValueError(
                "Для системного VPN запустите установленный FLURUX через Start-Admin.cmd."
            )
        if engine == "sing-box":
            check_engine(Path(exe), privileged=True)
        elif kind == "awg":
            if Path(exe) != program_files() / "AmneziaWG" / "amneziawg.exe":
                raise ValueError("Выберите установленный в Program Files клиент AmneziaWG.")
            protected_path(Path(exe))
    n = p["nodes"][0] if p["nodes"] else {}
    local = authority("127.0.0.1", port(p["local_port"]))
    if p["system_tun"] and engine != "sing-box":
        raise ValueError("Для этого движка используется его собственный режим подключения.")
    if engine == "firefox":
        name = n["tls_name"] or n["host"]
        prefs = {
            "network.trr.mode": 3,
            "network.trr.uri": "https://" + authority(name, port(n["port"])) + "/dns-query",
            "network.dns.echconfig.enabled": True,
        }
        try:
            prefs["network.trr.bootstrapAddress"] = str(ipaddress.ip_address(n["host"]))
        except ValueError:
            raise ValueError(
                "Для Firefox укажите IP резолвера в поле адреса, а имя сертификата в поле TLS/SNI."
            ) from None
        profile = cache / ("firefox-" + p["id"])
        private_directory(profile)
        if n["certificate"]:
            (profile / "dns-server.pem").write_text(n["certificate"], encoding="ascii")
        (profile / "user.js").write_text(
            "".join(
                "user_pref(" + json.dumps(k) + ", " + json.dumps(v) + ");\n"
                for k, v in prefs.items()
            ),
            encoding="utf-8",
        )
        return [exe, "-no-remote", "-profile", str(profile)], "Firefox · ECH + DoH"
    if engine == "psiphon-tunnel-core":
        native = json.loads(Path(p.get("psiphon_config", "")).read_text(encoding="utf-8-sig"))
        native.update(
            LocalSocksProxyPort=port(p["local_port"]),
            DisableLocalSocksProxy=False,
            DisableLocalHTTPProxy=True,
            ListenInterface="",
            UseUnixDomainSockets=False,
        )
        state = cache / ("psiphon-" + p["id"])
        private_directory(state)
        target = folder / "psiphon.json"
        target.write_text(json.dumps(native), encoding="utf-8")
        args = [exe, "-config", str(target), "-dataRootDirectory", str(state)]
        if p.get("psiphon_servers"):
            args.extend(["-serverList", str(Path(p["psiphon_servers"]).resolve(strict=True))])
        return args, "SOCKS5 " + local
    if engine == "ssh" and kind == "ssh_single":
        return [
            exe,
            *SSH_FLAGS,
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-D",
            local,
            "-p",
            str(port(n["port"])),
            ssh_target(n["ssh"] or n["host"]),
        ], "SOCKS5 " + local
    if engine == "ssh":
        jump = ssh_target(n["ssh"] or n["host"])
        end = p["nodes"][1]
        exit_host = ssh_target(end["ssh"] or end["host"])
        # The proxy child also uses strict host verification and noninteractive auth.
        proxy = subprocess.list2cmdline(
            [exe, *SSH_FLAGS, "-p", str(port(n["port"])), "-W", "[%h]:%p", jump]
        )
        return [
            exe,
            *SSH_FLAGS,
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ProxyCommand=" + proxy,
            "-D",
            local,
            "-p",
            str(port(end["port"])),
            exit_host,
        ], "SOCKS5 " + local
    if engine == "tor":
        option = "HTTPSProxy" if kind == "tor_http" else "Socks5Proxy"
        lines = [
            f"SocksPort {local}",
            f"{option} {authority(n['host'], port(n['port']))}",
            "Log notice stdout",
        ]
        if n["password"]:
            if kind == "tor_http":
                lines.append(
                    "HTTPSProxyAuthenticator " + tor_quote(n["username"] + ":" + n["password"])
                )
            else:
                lines.extend(
                    [
                        "Socks5ProxyUsername " + tor_quote(n["username"]),
                        "Socks5ProxyPassword " + tor_quote(n["password"]),
                    ]
                )
        torrc = folder / "torrc"
        torrc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        state = cache / ("tor-" + p["id"])
        private_directory(state)
        return [exe, "-f", str(torrc), "--DataDirectory", str(state)], "SOCKS5 " + local
    if engine == "amneziawg":
        conf = folder / ("rm" + p["id"][:12] + ".conf")
        conf.write_text(awg_config(n, subnet=int(p["id"][:2], 16)), encoding="ascii")
        return [exe, "/installtunnelservice", str(conf)], "Системный VPN AmneziaWG"
    if engine == "xray":
        conf_data = xray_ws(p)
    elif engine == "python":
        conf_data = capsule(p)
    else:
        conf_data = client(p)
    file = folder / "route.json"
    file.write_text(json.dumps(conf_data), encoding="utf-8")
    if engine == "python":
        return [
            exe,
            "-I",
            str(Path(__file__).with_name("masque_capsule.py")),
            "client",
            str(file),
        ], "UDP " + local
    args = [exe, "run", "-c", str(file)]
    check = (
        [exe, "check", "-c", str(file)]
        if engine == "sing-box"
        else [exe, "run", "-test", "-c", str(file)]
    )
    command(check, details=False)
    if kind in ("dns_https", "dns_tls"):
        return args, "DNS " + local
    if kind.startswith("relay_"):
        return args, kind[6:].upper() + " " + local
    return args, "Системный TUN" if p["system_tun"] else "SOCKS5 " + local


def start_route(
    p: Obj,
    stop: threading.Event,
    notify: Notify,
    cache: Path,
    *,
    ready: Callable[[], None] | None = None,
) -> None:
    """Supervise one route and tear down its processes on stop."""
    if (p["system_tun"] or p["kind"] == "awg") and not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError(
            "Для системного VPN запустите установленный Start-Admin.cmd от администратора."
        )
    cache.mkdir(parents=True, exist_ok=True)
    with private_session(
        cache / "sessions-v3", admin=bool(p["system_tun"] or p["kind"] == "awg")
    ) as folder:
        args, desc = setup(p, folder, cache)
        if p["kind"] == "awg":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise ValueError(
                    "Для системной службы AmneziaWG запустите приложение от администратора."
                )
            name = Path(args[-1]).stem
            sc = str(Path(os.environ["SystemRoot"]) / "System32/sc.exe")
            status = subprocess.run(
                [sc, "query", "AmneziaWGTunnel$" + name],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if status.returncode != 1060:
                raise ValueError(
                    "Уже существует служба этого туннеля или недоступен диспетчер служб."
                )
            command(args)
            try:
                notify(desc + " · служба запущена")
                if ready:
                    ready()
                stop.wait()
            finally:
                command([args[0], "/uninstalltunnelservice", name])
            return
        if p["system_tun"] and not ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError("Для системного TUN запустите приложение от администратора.")
        if not p["system_tun"] and p["kind"] != "ech":
            proto = (
                socket.SOCK_DGRAM
                if p["kind"] in ("relay_udp", "masque_udp")
                else socket.SOCK_STREAM
            )
            with socket.socket(socket.AF_INET, proto) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                probe.bind(("127.0.0.1", port(p["local_port"])))
        with ExitStack() as stack:
            guardian = None
            if p["system_tun"] and p.get("network_lock"):
                first = p["nodes"][0]
                addr = str(ipaddress.ip_address(first["host"]))
                guardian = stack.enter_context(
                    guard_session(
                        "lock",
                        [addr, str(port(first["port"])), "FLURUX-" + p["id"][:12], args[0]],
                        stop,
                    )
                )
                notify(
                    "Блокировка Windows включена. После остановки для выхода в интернет нажмите «Снять блокировку сети»."
                )
            payload = None
            if engine_name(p["kind"]) in ("sing-box", "python"):
                config_file = Path(args[-1])
                payload = config_file.read_bytes()
                config_file.unlink()
                args[-1] = "stdin" if engine_name(p["kind"]) == "sing-box" else "-"
            proc = stack.enter_context(
                managed_process(args, folder, folder / "engine.log", input_data=payload)
            )
            since = monotonic()
            reported = False
            while not stop.wait(0.18):
                if guardian and wait_handle(guardian):
                    raise ValueError("Помощник сетевой блокировки остановился. Туннель закрыт.")
                if proc.poll() is not None:
                    raise ValueError(
                        f"Движок {engine_name(p['kind'])} завершился с кодом {proc.returncode}. Проверьте реквизиты и версию."
                    )
                if not reported and monotonic() - since > 1:
                    notify(desc + " · процесс запущен")
                    if ready:
                        ready()
                    reported = True


def mesh_peers(exe: str = "") -> list[Obj]:
    """Read peer status from the local Tailscale daemon."""
    status = json.loads(command([binary("tailscale", exe), "status", "--json"]))
    if status.get("BackendState") != "Running":
        raise ValueError("Войдите в Tailscale на этом компьютере.")
    rows = []
    for peer in (status.get("Peer") or {}).values():
        ips = peer.get("TailscaleIPs") or []
        if ips:
            rows.append(
                {
                    "ip": str(ipaddress.ip_address(ips[0])),
                    "name": peer.get("DNSName", "").rstrip(".") or peer.get("HostName", ""),
                    "online": bool(peer.get("Online")),
                    "exit": bool(peer.get("ExitNodeOption")),
                    "selected": bool(peer.get("ExitNode")),
                }
            )
    return sorted(rows, key=lambda r: str(r["name"]))


def mesh_select(address: str, exe: str = "") -> None:
    """Change only the local exit preference after checking advertised capabilities."""
    if address and not any(
        (r["ip"] == address or r["name"] == address) and r["exit"] and r["online"]
        for r in mesh_peers(exe)
    ):
        raise ValueError("Этот узел отсутствует среди доступных выходов tailnet.")
    command([binary("tailscale", exe), "set", "--exit-node=" + address])
