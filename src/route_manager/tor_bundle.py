"""Install the pinned Tor Expert Bundle in the current user's FLURUX directory."""

import hashlib
import http.client
import shutil
import tarfile
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

VERSION = "16.0.1"
SHA256 = "9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b"
SIZE = 23767908
FILE = f"tor-expert-bundle-windows-x86_64-{VERSION}.tar.gz"
URLS = (
    f"https://dist.torproject.org/torbrowser/{VERSION}/{FILE}",
    f"https://archive.torproject.org/tor-package-archive/torbrowser/{VERSION}/{FILE}",
)
FILES = frozenset(
    (
        "tor/tor.exe",
        "tor/pluggable_transports/lyrebird.exe",
        "tor/pluggable_transports/pt_config.json",
        "data/geoip",
        "data/geoip6",
    )
)


def installed_tor(data: Path) -> Path:
    """Return the executable path for the version managed by FLURUX."""
    return data / f"tor-bundle-{VERSION}" / "tor" / "tor.exe"


def install_bundle(data: Path, stop: threading.Event, progress: Callable[[int], None]) -> Path:
    """Download an authenticated archive and atomically publish its required files."""
    exe = installed_tor(data)
    if exe.is_file():
        return exe
    with tempfile.TemporaryDirectory(prefix="tor-download-", dir=data) as temp:
        scratch = Path(temp)
        archive = scratch / "bundle.tar.gz"
        for url in URLS:
            if stop.is_set():
                raise InterruptedError("Загрузка отменена.")
            try:
                with urllib.request.urlopen(url, timeout=10) as response, archive.open("wb") as out:
                    total = 0
                    checksum = hashlib.sha256()
                    percent = -1
                    while chunk := response.read1(256 * 1024):
                        if stop.is_set():
                            raise InterruptedError("Загрузка отменена.")
                        total += len(chunk)
                        if total > SIZE:
                            raise ValueError("Размер архива Tor отличается от ожидаемого.")
                        out.write(chunk)
                        checksum.update(chunk)
                        current = total * 100 // SIZE
                        if current != percent:
                            progress(current)
                            percent = current
                if total != SIZE or checksum.hexdigest() != SHA256:
                    raise ValueError("Не удалось подтвердить SHA-256 официального архива Tor.")
                break
            except (
                urllib.error.URLError,
                TimeoutError,
                ConnectionError,
                http.client.HTTPException,
            ):
                continue
        else:
            raise OSError(
                "Оба сервера Tor Project недоступны. Повторите загрузку или укажите tor.exe из распакованного Tor Expert Bundle 16.0.1 в настройках."
            )
        stage = scratch / "unpacked"
        found = set()
        with tarfile.open(archive, mode="r:gz") as bundle:
            for item in bundle:
                if stop.is_set():
                    raise InterruptedError("Загрузка отменена.")
                if item.name not in FILES:
                    continue
                if not item.isreg() or item.name in found:
                    raise ValueError("Некорректный состав архива Tor.")
                source = bundle.extractfile(item)
                if source is None:
                    raise ValueError("Не удалось прочитать компонент Tor.")
                target = stage / item.name
                target.parent.mkdir(exist_ok=True, parents=True)
                with source, target.open("xb") as out:
                    shutil.copyfileobj(source, out)
                found.add(item.name)
        if found != FILES:
            raise ValueError("Архив Tor содержит неполный комплект.")
        try:
            stage.rename(exe.parents[1])
        except FileExistsError:
            if not exe.is_file():
                raise
    return exe
