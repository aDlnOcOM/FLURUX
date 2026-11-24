"""Trust checks and the small parameter-only UAC interface to FLURUX Guard."""

import ctypes as ct
import hashlib
import os
import re
import stat
import subprocess
import uuid
import winreg
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes as wt
from pathlib import Path
from threading import Event
from time import monotonic

from route_manager.private_files import adv, kernel, ptr
from route_manager.release_pins import ENGINE_FILES, GUARD_HASH, TOR_FILES
from route_manager.windows import close_handle, elevated_process, process_exit_code, wait_handle

TRUSTED_OWNERS = {
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
}
kernel.CreateEventW.argtypes = [ptr, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel.CreateEventW.restype = wt.HANDLE
kernel.SetEvent.argtypes = [wt.HANDLE]
adv.GetNamedSecurityInfoW.argtypes = [
    wt.LPWSTR,
    ct.c_int,
    wt.DWORD,
    ct.POINTER(ptr),
    ptr,
    ct.POINTER(ptr),
    ptr,
    ct.POINTER(ptr),
]
adv.GetAce.argtypes = [ptr, wt.DWORD, ct.POINTER(ptr)]


def program_files() -> Path:
    """Locate the system-wide 64-bit installation root from HKLM."""
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as key:
        return Path(winreg.QueryValueEx(key, "ProgramFilesDir")[0])


def installed_desktop() -> Path:
    """Read the machine-wide MSI location, including legacy installations."""
    location = ct.create_unicode_buffer(32768)
    size = wt.DWORD(len(location))
    rc = ct.windll.msi.MsiGetProductInfoExW(
        "{670D8AC3-5471-5723-97EF-D5CF18A9614E}",
        None,
        4,
        "InstallLocation",
        location,
        ct.byref(size),
    )
    if rc == 0 and location.value and Path(location.value).is_absolute():
        return Path(location.value)
    return program_files() / "FLURUX"


def sid_name(sid: ptr) -> str:
    """Convert a binary SID in a security descriptor to canonical text."""
    out = wt.LPWSTR()
    if not adv.ConvertSidToStringSidW(sid, ct.byref(out)):
        raise ct.WinError(ct.get_last_error())
    try:
        return str(out.value)
    finally:
        kernel.LocalFree(out)


def protected_path(path: Path) -> None:
    """Reject junctions and effective write grants to nonadministrative principals."""
    root = program_files()
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Укажите полный путь к установленному компоненту.")
    custom = not path.is_relative_to(root)
    if custom:
        root = installed_desktop()
        if not path.is_relative_to(root):
            raise ValueError("Требуется защищённый каталог установленного приложения.")
    ancestors = tuple(reversed(root.parents)) if custom else ()
    for part in (
        *ancestors,
        root,
        *(
            root.joinpath(*path.relative_to(root).parts[:i])
            for i in range(1, len(path.relative_to(root).parts) + 1)
        ),
    ):
        if part.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Ссылки в пути привилегированного компонента запрещены.")
        descriptor, owner, acl = ptr(), ptr(), ptr()
        rc = adv.GetNamedSecurityInfoW(
            str(part), 1, 5, ct.byref(owner), None, ct.byref(acl), None, ct.byref(descriptor)
        )
        if rc:
            raise ct.WinError(rc)
        try:
            if not acl.value or sid_name(owner) not in TRUSTED_OWNERS:
                raise ValueError("Проверьте владельца и права каталога установки.")
            count = ct.c_ushort.from_address(acl.value + 4).value
            for i in range(count):
                ace = ptr()
                if not adv.GetAce(acl, i, ct.byref(ace)) or ace.value is None:
                    raise ct.WinError(ct.get_last_error())
                tag, flags = ct.string_at(ace, 2)
                if flags & 8 or tag == 1:
                    continue
                mask = ct.c_uint32.from_address(ace.value + 4).value
                if tag != 0 or (
                    mask & (0x500D0150 if part in ancestors else 0x500D0156)
                    and sid_name(ptr(ace.value + 8)) not in TRUSTED_OWNERS
                ):
                    raise ValueError(
                        "Права записи привилегированного компонента доступны обычному пользователю."
                    )
        finally:
            kernel.LocalFree(descriptor)


def digest(path: Path) -> str:
    """Calculate the SHA-256 of a complete file."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_engine(path: Path, *, privileged: bool = False) -> None:
    """Check the engine and executable libraries against the release records."""
    checksum = digest(path)
    expected = ENGINE_FILES.get(checksum)
    if not expected or expected.get(path.name.lower()) != checksum:
        raise ValueError("Хеш движка отличается от проверенного релиза FLURUX.")
    if privileged:
        protected_path(path)
    for name, checksum in expected.items():
        member = path.parent / name
        if privileged:
            protected_path(member)
        if member != path and digest(member) != checksum:
            raise ValueError("Хеш компонента движка отличается от проверенного релиза.")
    for member in path.parent.iterdir():
        if (
            member.suffix.lower() in (".dll", ".exe", ".asi", ".local")
            and member.name.lower() not in expected
        ):
            raise ValueError("Рядом с движком найден незарегистрированный исполняемый компонент.")


def verify_external(path: Path, name: str, checksum: str = "") -> None:
    """Require a pinned upstream digest, an operator's pin, or a trusted Windows signature."""
    if path.name.lower() != name.lower() + ".exe":
        raise ValueError("Имя исполняемого файла не соответствует выбранному движку.")
    if name in ("sing-box", "xray"):
        check_engine(path)
        return
    expected = TOR_FILES.get(path.name.lower(), checksum)
    if expected:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", expected) or digest(path) != expected.lower():
            raise ValueError("SHA-256 движка отличается от доверенного значения.")
        return
    directory = ct.create_unicode_buffer(32768)
    if not kernel.GetSystemDirectoryW(directory, len(directory)):
        raise ct.WinError(ct.get_last_error())
    powershell = Path(directory.value) / "WindowsPowerShell/v1.0/powershell.exe"
    # The selected path is data, passed via the environment rather than shell text.
    script = "$s=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath $env:FLURUX_VERIFY_PATH; if ($s.Status -ne 'Valid') { exit 1 }"
    env = dict(
        os.environ, FLURUX_VERIFY_PATH=str(path), PSModulePath=str(powershell.parent / "Modules")
    )
    result = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        env=env,
        capture_output=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise ValueError(
            "Windows не подтвердила Authenticode. Для неподписанного движка введите доверенный SHA-256 в профиле."
        )


def guard_path() -> Path:
    """Locate and verify the installed privileged broker immediately before UAC."""
    exe = program_files() / "FLURUX" / "Security" / "FluruxGuard.exe"
    if not exe.is_file():
        raise ValueError("Установите FLURUX-Security-x64.msi из архива приложения.")
    protected_path(exe)
    if digest(exe) != GUARD_HASH:
        raise ValueError(
            "Версия помощника не совпадает с приложением. Переустановите MSI из этого выпуска."
        )
    return exe


@contextmanager
def guard_session(mode: str, args: list[str], stop: Event) -> Iterator[int]:
    """Wait for verified startup and release the worker on exit or parent death."""
    exe = guard_path()
    nonce = uuid.uuid4().hex
    handles = []
    try:
        for suffix in ("stop", "ready"):
            handle = kernel.CreateEventW(None, True, False, "Local\\FLURUX-" + nonce + "-" + suffix)
            if not handle or ct.get_last_error() == 183:
                if handle:
                    close_handle(handle)
                raise OSError("Не удалось создать уникальное событие Windows.")
            handles.append(handle)
        child = elevated_process(exe, [mode, str(os.getpid()), nonce, *args], exe.parent)
        try:
            deadline = monotonic() + 25
            while not wait_handle(handles[1], 100):
                if wait_handle(child):
                    raise OSError(f"Помощник FLURUX завершился с кодом {process_exit_code(child)}.")
                if stop.is_set() or monotonic() > deadline:
                    raise OSError("Запуск помощника прерван.")
            yield child
        finally:
            kernel.SetEvent(handles[0])
            wait_handle(child, 5000)
            close_handle(child)
    finally:
        for handle in handles:
            close_handle(handle)


def unlock_network() -> None:
    """Explicitly remove only the persistent firewall rules owned by FLURUX."""
    exe = guard_path()
    handle = elevated_process(exe, ["unlock"], exe.parent)
    try:
        if not wait_handle(handle, 15000) or process_exit_code(handle):
            raise OSError(
                "Не удалось снять сетевую блокировку. Остановите активный TUN и повторите."
            )
    finally:
        close_handle(handle)
