"""Standalone SSH worker for a selected Debian/Ubuntu systemd node (Python 3.10+)."""

import base64
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


def run(*args: str, data: str | None = None) -> str:
    """Execute an argument vector and keep credentials out of error messages."""
    proc = subprocess.run(args, input=data, text=True, capture_output=True, timeout=360)
    if proc.returncode:
        raise RuntimeError(f"{Path(args[0]).name} завершился с кодом {proc.returncode}")
    return proc.stdout.strip()


ARCHIVE_HASHES = {
    "sing-box-1.14.4-linux-amd64.tar.gz": "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
    "sing-box-1.14.4-linux-arm64.tar.gz": "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26",
    "sing-box-1.15.0-alpha.13-linux-amd64.tar.gz": "bfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047",
    "sing-box-1.15.0-alpha.13-linux-arm64.tar.gz": "6347b1405ec7e1b02fbed77f3b9ae12ba494cc3eb9f47c4adb6877c807a64bf5",
    "Xray-linux-64.zip": "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
    "Xray-linux-arm64-v8a.zip": "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
}


def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Publish a complete file with its final permissions."""
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            temporary.chmod(mode)
        finally:
            handle.close()
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def public_dir(name: str) -> Path:
    """Create a system-owned, traversable directory containing no private data."""
    root = Path("/usr/local/lib/flurux")
    for directory in (root, root / name):
        directory.mkdir(exist_ok=True)
        if (
            directory.is_symlink()
            or directory.stat().st_uid != 0
            or directory.stat().st_mode & 0o022
        ):
            raise ValueError("Проверьте владельца и права системного каталога FLURUX.")
        directory.chmod(0o755)
    return root / name


def reality_keys(raw: str) -> tuple[str, str]:
    """Accept precisely the two labeled canonical X25519 keys emitted by sing-box."""
    lines = raw.splitlines()
    if len(lines) != 2:
        raise ValueError("Повреждён файл ключей REALITY.")
    keys = {}
    for line in lines:
        match = re.fullmatch(r"(PrivateKey|PublicKey):\s*([A-Za-z0-9_-]{43})", line)
        if not match or match[1] in keys:
            raise ValueError("Повреждён формат ключей REALITY.")
        value = match[2]
        if (
            base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + "=")).decode().rstrip("=")
            != value
        ):
            raise ValueError("Некорректная кодировка ключа REALITY.")
        keys[match[1]] = value
    if keys.get("PrivateKey") == keys.get("PublicKey"):
        raise ValueError("Некорректная пара ключей REALITY.")
    return keys["PrivateKey"], keys["PublicKey"]


def release_binary(folder: Path, name: str, masque: bool) -> Path:
    """Install the pinned upstream binary after checking the release asset digest."""
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise ValueError("Поддерживаются серверы Linux x86-64 и ARM64.")
    version = "1.15.0-alpha.13" if masque else "1.14.4"
    artifacts = {
        "sing-box": ("SagerNet/sing-box", version, f"sing-box-{version}-linux-{arch}.tar.gz"),
        "xray": (
            "XTLS/Xray-core",
            "26.11.9",
            "Xray-linux-" + ("64" if arch == "amd64" else "arm64-v8a") + ".zip",
        ),
    }
    repo, tag, asset = artifacts[name]
    dest = public_dir("engines") / f"{name}-{tag}-{arch}"
    expected = ARCHIVE_HASHES[asset]
    receipt = folder / (dest.name + ".sha256")
    if dest.is_file() and receipt.is_file():
        actual = hashlib.sha256(dest.read_bytes()).hexdigest()
        if receipt.read_text() == expected + " " + actual:
            return dest
    url = f"https://github.com/{repo}/releases/download/v{tag}/{asset}"
    with urllib.request.urlopen(url, timeout=90) as response:
        content = response.read(250_000_001)
    if len(content) > 250_000_000 or hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Архив не совпадает с закреплённым хешем релиза.")
    temp = folder / (dest.name + ".tmp")
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            temp.write_bytes(z.read(next(k for k in z.namelist() if Path(k).name == name)))
    else:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as t:
            member = next(m for m in t if m.isfile() and Path(m.name).name == name)
            src = t.extractfile(member)
            if src is None:
                raise ValueError("В архиве нет исполняемого файла.")
            with temp.open("wb") as out:
                shutil.copyfileobj(src, out)
    payload = temp.read_bytes()
    atomic(dest, payload, 0o755)
    atomic(receipt, (expected + " " + hashlib.sha256(payload).hexdigest()).encode())
    temp.unlink(missing_ok=True)
    return dest


def package(*names: str) -> None:
    """Install distribution packages on the explicitly selected host."""
    run("apt-get", "update", "-qq")
    run("apt-get", "install", "-y", "--no-install-recommends", *names)


def prepare(folder: Path, r: dict[str, Any]) -> dict[str, str]:
    """Create or reuse server keys, returning public material only."""
    kind = r["type"]
    result = {}
    if kind in ("wg", "awg"):
        if not shutil.which("wg"):
            package("wireguard-tools")
        key = folder / "wg.key"
        if not key.exists():
            atomic(key, (run("wg", "genkey") + "\n").encode())
        result["public_key"] = run("wg", "pubkey", data=key.read_text())
        if r.get("uplink"):
            uplink = folder / "wg-uplink.key"
            if not uplink.exists():
                atomic(uplink, (run("wg", "genkey") + "\n").encode())
            result["uplink_public"] = run("wg", "pubkey", data=uplink.read_text())
    if kind == "reality":
        exe = release_binary(folder, "sing-box", False)
        key = folder / "reality.key"
        if not key.exists():
            generated = run(str(exe), "generate", "reality-keypair")
            reality_keys(generated)
            atomic(key, generated.encode())
        _, result["public_key"] = reality_keys(key.read_text())
    if kind in ("hy2", "https", "masque_udp", "masque_ip", "ss_ws", "openvpn", "doh", "dot"):
        if not shutil.which("openssl"):
            package("openssl")
        name = r["name"]
        try:
            ipaddress.ip_address(name)
            san = "IP:" + name
        except ValueError:
            san = "DNS:" + name
        key = folder / "key.pem"
        cert = folder / "cert.pem"
        if not key.exists():
            run(
                "openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(key),
            )
        if (
            not cert.exists()
            or not (folder / "cert.name").exists()
            or (folder / "cert.name").read_text() != name
            or subprocess.run(
                ["openssl", "x509", "-checkend", "604800", "-noout", "-in", str(cert)],
                capture_output=True,
            ).returncode
        ):
            tmp = folder / "next-cert.pem"
            run(
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                str(key),
                "-out",
                str(tmp),
                "-days",
                "365",
                "-subj",
                "/CN=" + name,
                "-addext",
                "subjectAltName=" + san,
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "keyUsage=critical,digitalSignature,keyAgreement",
            )
            tmp.replace(cert)
            (folder / "cert.name").write_text(name)
        result["certificate"] = run("openssl", "x509", "-in", str(cert), "-outform", "PEM") + "\n"
    return result


def forwarding(folder: Path) -> None:
    """Enable IPv4 forwarding for the managed system VPN role."""
    cfg = Path("/etc/sysctl.d") / ("90-" + folder.name + ".conf")
    cfg.write_text("net.ipv4.ip_forward=1\n")
    run("sysctl", "-p", str(cfg))


def mesh(folder: Path, r: dict[str, Any]) -> str:
    """Join an authorized tailnet and configure the requested advertised role."""
    if not shutil.which("tailscale"):
        os_info = dict(
            line.split("=", 1)
            for line in Path("/etc/os-release").read_text().splitlines()
            if "=" in line
        )
        distro = os_info["ID"].strip('"')
        code = os_info["VERSION_CODENAME"].strip('"')
        if distro not in ("ubuntu", "debian") or not re.fullmatch("[a-z]+", code):
            raise ValueError("Автоустановка Tailscale поддерживает Debian и Ubuntu.")
        stem = f"https://pkgs.tailscale.com/stable/{distro}/{code}"
        keyring = Path("/usr/share/keyrings/tailscale-archive-keyring.gpg")
        sources = Path("/etc/apt/sources.list.d/tailscale.list")
        for file, suffix in ((keyring, ".noarmor.gpg"), (sources, ".tailscale-keyring.list")):
            with urllib.request.urlopen(stem + suffix, timeout=30) as res:
                file.write_bytes(res.read())
            file.chmod(0o644)
        package("tailscale")
    run("systemctl", "enable", "--now", "tailscaled")
    status = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True)
    if json.loads(status.stdout or "{}").get("BackendState") != "Running":
        login = subprocess.run(
            ["tailscale", "up", "--timeout=12s"], text=True, capture_output=True, timeout=25
        )
        if login.returncode:
            urls = re.findall(
                r"https://login\.tailscale\.com/[A-Za-z0-9_/-]+", login.stdout + login.stderr
            )
            raise ValueError(
                "Авторизуйте сервер в tailnet и повторите установку. " + " ".join(urls)
            )
    if r["type"] == "mesh_exit":
        forwarding(folder)
        if Path("/proc/sys/net/ipv6/conf/all/forwarding").exists():
            cfg = Path("/etc/sysctl.d") / ("91-" + folder.name + "-v6.conf")
            cfg.write_text("net.ipv6.conf.all.forwarding=1\n")
            run("sysctl", "-p", str(cfg))
        run("tailscale", "set", "--advertise-exit-node")
        return "Выход объявлен. Подтвердите его в консоли tailnet."
    run("tailscale", "set", f"--relay-server-port={int(r['port'])}")
    return (
        "Peer relay включён. Разрешите tailscale.com/cap/relay для нужных узлов в политике tailnet."
    )


def service(folder: Path, start: str, check: list[str], content: str, filename: str) -> None:
    """Validate a staged config, activate it and restore a previous service on failure."""
    unit = folder.name + ".service"
    unitfile = Path("/etc/systemd/system") / unit
    live = folder / filename
    with tempfile.TemporaryDirectory(dir=folder) as d:
        tmp = Path(d) / filename
        tmp.write_text(content)
        for filename_tls in ("cert.pem", "key.pem"):
            if (folder / filename_tls).exists():
                (tmp.parent / filename_tls).symlink_to(folder / filename_tls)
        if check:
            tmp.write_text(
                content.replace(str(Path("/run/credentials") / unit) + "/", str(folder) + "/")
            )
            run(*check, str(tmp))
            tmp.write_text(content)
        old = live.read_bytes() if live.exists() else None
        old_unit = unitfile.read_bytes() if unitfile.exists() else None
        credential_dir = f"/run/credentials/{unit}"
        definition = f"[Unit]\nAfter=network-online.target\n[Service]\nDynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nRestrictSUIDSGID=yes\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nWorkingDirectory={credential_dir}\nLoadCredential={filename}:{live}\nExecStart={start}\nRestart=on-failure\nRestartSec=3\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
        for part in ("cert.pem", "key.pem"):
            if (folder / part).is_file():
                definition = definition.replace(
                    "[Install]", f"LoadCredential={part}:{folder / part}\n[Install]"
                )
        if (folder / "cert.pem").is_file():
            definition += (
                "\n# certificate "
                + hashlib.sha256((folder / "cert.pem").read_bytes()).hexdigest()
                + "\n"
            )
        if (
            old == content.encode()
            and old_unit == definition.encode()
            and subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
        ):
            return
        tmp.replace(live)
        unitfile.write_text(definition)
        try:
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", unit)
            import time

            time.sleep(1.2)
            run("systemctl", "is-active", "--quiet", unit)
            run("systemctl", "enable", unit)
        except Exception:
            run("systemctl", "stop", unit)
            if old is not None:
                live.write_bytes(old)
            else:
                live.unlink(missing_ok=True)
            if old_unit is not None:
                unitfile.write_bytes(old_unit)
            else:
                unitfile.unlink(missing_ok=True)
            run("systemctl", "daemon-reload")
            if old_unit and old:
                run("systemctl", "start", unit)
            raise


def deploy(folder: Path, r: dict[str, Any]) -> str:
    """Apply a previously prepared node configuration."""
    kind = r["type"]
    credentials = Path("/run/credentials") / (folder.name + ".service")
    if kind.startswith("mesh_"):
        return mesh(folder, r)
    if kind == "ssh":
        return "SSH-соединение установлено."
    if kind == "awg":
        if not shutil.which("awg-quick"):
            package("software-properties-common", "iptables")
            run("add-apt-repository", "-y", "ppa:amnezia/ppa")
            package("amneziawg")
        forwarding(folder)
        dev = "rm" + folder.name[3:12] + folder.name[-1]
        quick = Path("/etc/amnezia/amneziawg")
        quick.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest = quick / (dev + ".conf")
        content = (
            r["config"]
            .replace("@WG_PRIVATE@", (folder / "wg.key").read_text().strip())
            .replace("@IFACE@", dev)
        )
        unit = "awg-quick@" + dev
        old = dest.read_text() if dest.exists() else None
        if old != content:
            if old:
                run("systemctl", "stop", unit)
            tmp = dest.with_suffix(".new")
            tmp.write_text(content)
            tmp.replace(dest)
        try:
            run("systemctl", "enable", "--now", unit)
        except Exception:
            if old:
                dest.write_text(old)
                run("systemctl", "start", unit)
            else:
                dest.unlink(missing_ok=True)
            raise
        return "Служба AmneziaWG запущена."
    if kind in ("doh", "dot"):
        policy = ipaddress.ip_network(r["config"]["cidr"])
        if not policy.prefixlen:
            raise ValueError("Требуется ограниченная клиентская сеть.")
        if not shutil.which("dnsdist"):
            package("dnsdist")
        upstream = next(
            (
                str(ipaddress.ip_address(line.split()[1]))
                for line in Path("/etc/resolv.conf").read_text().splitlines()
                if line.startswith("nameserver ")
            ),
            None,
        )
        if not upstream:
            raise ValueError("На сервере отсутствует системный DNS-резолвер.")
        addr = "0.0.0.0:" + str(int(r["port"]))
        listener = "addDOHLocal" if kind == "doh" else "addTLSLocal"
        conf = f'setLocal("127.0.0.1:0")\nsetACL({{"{policy}"}})\nnewServer("{upstream}")\n{listener}("{addr}", "{credentials}/cert.pem", "{credentials}/key.pem")\n'
        service(
            folder,
            f"/usr/bin/dnsdist --supervised -C {credentials}/dnsdist.conf",
            ["/usr/bin/dnsdist", "--check-config", "-C"],
            conf,
            "dnsdist.conf",
        )
        return "Зашифрованный DNS-сервер запущен."
    if kind == "masque_udp":
        raw = r["worker"].encode()
        digest = hashlib.sha256(raw).hexdigest()[:16]
        script = public_dir("engines") / ("capsules-" + digest + ".py")
        atomic(script, raw, 0o644)
        service(
            folder,
            f"/usr/bin/python3 -I {script} server {credentials}/config.json",
            [],
            json.dumps(r["config"]),
            "config.json",
        )
        return "Служба CONNECT-UDP активна."
    name = "xray" if kind == "ss_ws" else "sing-box"
    exe = str(release_binary(folder, name, kind == "masque_ip"))
    config = r["config"]
    if kind == "ss_ws":
        certs = config["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]
        for tls_cert in certs:
            tls_cert.update(
                certificateFile=str(credentials / "cert.pem"), keyFile=str(credentials / "key.pem")
            )
    source = json.dumps(config)
    for marker, filename in (
        ("@WG_PRIVATE@", "wg.key"),
        ("@WG_UPLINK@", "wg-uplink.key"),
        ("@REALITY_PRIVATE@", "reality.key"),
    ):
        if marker in source:
            private = (folder / filename).read_text().strip()
            if filename == "reality.key":
                private, _ = reality_keys(private)
            source = source.replace(marker, private)
    cmd = "run -c"
    check = {"sing-box": [exe, "check", "-c"], "xray": [exe, "run", "-test", "-c"]}[name]
    service(folder, f"{exe} {cmd} {credentials}/config.json", check, source, "config.json")
    return "Служба активна."


def main() -> None:
    """Handle one bounded JSON request on standard input."""
    import fcntl

    os.umask(0o077)
    r = json.loads(sys.stdin.buffer.readline(4_000_000))
    if not re.fullmatch(r"rm-[a-f0-9]{32}-[01]", r["instance"]):
        raise ValueError("Недопустимое имя экземпляра.")
    folder = Path("/etc/routes-manager") / r["instance"]
    if r["action"] not in ("prepare", "deploy"):
        raise ValueError("Неизвестная операция настройки.")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chdir(folder)
    with (folder / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # type: ignore[attr-defined]  # Linux-only worker
        if r["action"] == "prepare":
            out = prepare(folder, r)
            atomic(folder / "pending-public.json", json.dumps(out).encode())
        else:
            out = {"message": deploy(folder, r)}
            atomic(
                public_dir("public") / (folder.name + ".json"),
                (folder / "pending-public.json").read_bytes(),
                0o644,
            )
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stderr.write(str(error) + "\n")
        sys.exit(1)
