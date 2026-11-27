"""Acquire verified zapret2 components and give only their bytes to FLURUX Guard."""

import hashlib
import http.client
import json
import mmap
import struct
import subprocess
import threading
import urllib.error
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.request import urlopen

from route_manager.security import guard_path, program_files
from route_manager.windows import close_handle, elevated_process, process_exit_code, wait_handle

REVISION = "6b4375fa04f6bd7017eec379e16e462d3ea8df66"
BASE = f"https://raw.githubusercontent.com/bol-van/zapret-win-bundle/{REVISION}/zapret-winws"
# Wire order is also checked by the native broker against its compiled SHA-256 table.
SIZES = {
    "WinDivert.dll": 47616,
    "WinDivert64.sys": 94144,
    "cygwin1.dll": 2954293,
    "files/quic_initial_www_google_com.bin": 1200,
    "lua/zapret-antidpi.lua": 51866,
    "lua/zapret-lib.lua": 94940,
    "winws2.exe": 657408,
}
CAPACITY = 8 * 1024 * 1024


def engine_folder() -> Path:
    """Locate the shared, machine-protected engine even after a custom desktop install."""
    return program_files() / "FLURUX" / "Security" / "engine"


def manifest() -> dict[str, str]:
    """Read the release manifest from the installed broker or source checkout."""
    source = Path(__file__).resolve().parents[2] / "security" / "zapret-files.json"
    path = source if source.is_file() else engine_folder().parent / "zapret-files.json"
    hashes = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(hashes, dict) or hashes.keys() != SIZES.keys():
        raise ValueError("Повреждён манифест zapret2. Восстановите FLURUX через установщик.")
    return hashes


def verify_installed() -> None:
    """Check the full engine tree and its file hashes without requesting elevation."""
    exe = guard_path()
    result = subprocess.run(
        [exe, "verify-files", engine_folder()],
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise ValueError(
            "Файлы движка отсутствуют, изменены или каталог содержит посторонние файлы."
        )


def _members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    entries = archive.infolist()
    roots = [
        entry.filename.removesuffix("winws2.exe")
        for entry in entries
        if entry.filename.rsplit("/", 1)[-1] == "winws2.exe"
    ]
    official = [prefix for prefix in roots if prefix.rstrip("/").split("/")[-1] == "zapret-winws"]
    roots = official or roots
    if len(roots) != 1:
        raise ValueError("Выберите ZIP проверенной Windows-сборки с одним файлом winws2.exe.")
    root = roots[0]
    result = {}
    for item in entries:
        if item.filename.startswith(root) and (key := item.filename[len(root) :]) in SIZES:
            if key in result or item.file_size != SIZES[key]:
                raise ValueError(f"Неподходящий файл в ZIP: {key}.")
            result[key] = item
    if result.keys() != SIZES.keys():
        raise ValueError("В ZIP отсутствуют компоненты нужной версии zapret2.")
    return result


def acquire(source: Path | None, stop: threading.Event, progress: Callable[[str], None]) -> bytes:
    """Download or import only the seven pinned files, with bounded reads and cancellation."""
    hashes = manifest()
    packet = bytearray()
    if source and source.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Выберите ZIP сборки размером до 128 МБ.")
    archive = zipfile.ZipFile(source) if source else None
    try:
        members = _members(archive) if archive else {}
        for i, (name, size) in enumerate(SIZES.items(), 1):
            if stop.is_set():
                raise InterruptedError("Подготовка движка отменена.")
            progress(f"Получение файлов · {i} из {len(SIZES)} · {name}")
            stream = (
                archive.open(members[name]) if archive else urlopen(f"{BASE}/{name}", timeout=12)
            )
            with stream:
                data = stream.read(size + 1)
            if len(data) != size or hashlib.sha256(data).hexdigest() != hashes[name]:
                raise ValueError(
                    f"Проверка SHA-256 не пройдена: {name}. Нужна сборка {REVISION[:8]}."
                )
            packet.extend(struct.pack("<I", size))
            packet.extend(data)
        return bytes(packet)
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as exc:
        raise OSError(
            "Загрузка прервана. Повторите попытку или установите комплект через «Из ZIP…»."
        ) from exc
    finally:
        if archive:
            archive.close()


def _maintenance(exe: Path, args: list[str]) -> None:
    handle = elevated_process(exe, args, exe.parent)
    try:
        wait_handle(handle, 0xFFFFFFFF)
        code = process_exit_code(handle)
        if code:
            reasons = {
                32: "Движок занят. Остановите zapret2 во всех окнах FLURUX.",
                145: "В каталоге движка есть посторонние файлы. Операция остановлена.",
                23: "Контрольная сумма защищённой копии не совпала.",
                5: "Windows отказала в доступе к каталогу движка.",
            }
            raise OSError(reasons.get(code, f"Помощник FLURUX вернул код Windows {code}."))
    finally:
        close_handle(handle)


def install(source: Path | None, stop: threading.Event, progress: Callable[[str], None]) -> None:
    """Stage verified bytes, then let the protected broker install or repair its fixed folder."""
    exe = guard_path()
    data = acquire(source, stop, progress)
    if stop.is_set():
        raise InterruptedError("Установка отменена.")
    progress("Подтвердите установку в окне Windows.")
    nonce = uuid.uuid4().hex
    with mmap.mmap(-1, CAPACITY, tagname="Local\\FLURUX-engine-" + nonce) as mapping:
        mapping.write(data)
        _maintenance(exe, ["install-engine", nonce])


def remove() -> None:
    """Remove the managed engine files while preserving the user's settings and sites."""
    _maintenance(guard_path(), ["remove-engine"])
