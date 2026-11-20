"""Windows-only, owner-restricted directories and leased engine sessions."""

import ctypes as ct
import msvcrt
import os
import re
import shutil
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes as wt
from pathlib import Path

adv = ct.WinDLL("advapi32", use_last_error=True)
kernel = ct.WinDLL("kernel32", use_last_error=True)
ptr = ct.c_void_p
adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ct.POINTER(wt.HANDLE)]
adv.GetTokenInformation.argtypes = [wt.HANDLE, ct.c_int, ptr, wt.DWORD, ct.POINTER(wt.DWORD)]
adv.ConvertSidToStringSidW.argtypes = [ptr, ct.POINTER(wt.LPWSTR)]
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wt.LPCWSTR,
    wt.DWORD,
    ct.POINTER(ptr),
    ptr,
]
kernel.LocalFree.argtypes = [ptr]
kernel.CloseHandle.argtypes = [wt.HANDLE]
kernel.CreateDirectoryW.argtypes = [wt.LPCWSTR, ptr]


class Attributes(ct.Structure):
    _fields_ = [("size", wt.DWORD), ("descriptor", ptr), ("inherit", wt.BOOL)]


def current_sid() -> str:
    """Read the user SID of this process token."""
    token = wt.HANDLE()
    if not adv.OpenProcessToken(wt.HANDLE(-1), 8, ct.byref(token)):
        raise ct.WinError(ct.get_last_error())
    try:
        size = wt.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ct.byref(size))
        buffer = ct.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, 1, buffer, size, ct.byref(size)):
            raise ct.WinError(ct.get_last_error())
        sid = ptr.from_buffer(buffer)
        value = wt.LPWSTR()
        if not adv.ConvertSidToStringSidW(sid, ct.byref(value)):
            raise ct.WinError(ct.get_last_error())
        try:
            return str(value.value)
        finally:
            kernel.LocalFree(value)
    finally:
        kernel.CloseHandle(token)


def safe_directory(path: Path) -> bool:
    """Recognize a real directory without following a Windows junction."""
    info = path.lstat()
    return (
        stat.S_ISDIR(info.st_mode)
        and not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def private_directory(path: Path, *, admin: bool = False) -> Path:
    """Create a directory with inherited access limited to this user and SYSTEM."""
    sid = "BA" if admin else current_sid()
    descriptor = ptr()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})", 1, ct.byref(descriptor), None
    ):
        raise ct.WinError(ct.get_last_error())
    try:
        attrs = Attributes(ct.sizeof(Attributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ct.byref(attrs)):
            if ct.get_last_error() != 183 or not safe_directory(path):
                raise ct.WinError(ct.get_last_error())
            # Repair an existing directory before placing new secrets in it.
            acl = ptr()
            present = wt.BOOL()
            defaulted = wt.BOOL()
            if not adv.GetSecurityDescriptorDacl(
                descriptor, ct.byref(present), ct.byref(acl), ct.byref(defaulted)
            ):
                raise ct.WinError(ct.get_last_error())
            rc = adv.SetNamedSecurityInfoW(
                str(path), 1, wt.DWORD(0x80000004), None, None, acl, None
            )
            if rc:
                raise ct.WinError(rc)
    finally:
        kernel.LocalFree(descriptor)
    return path


def clean_sessions(root: Path) -> None:
    """Remove only recognized sessions whose owner's exclusive lease has ended."""
    for folder in root.glob("session-*"):
        if not re.fullmatch(r"session-[0-9a-f]{32}", folder.name):
            continue
        try:
            if not safe_directory(folder):
                continue
            lease = folder / "lease"
            if lease.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            with lease.open("r+b") as stream:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            shutil.rmtree(folder)
        except OSError:
            continue


@contextmanager
def private_session(root: Path, *, admin: bool = False) -> Iterator[Path]:
    """Keep a private engine configuration alive while holding its exclusive lease."""
    private_directory(root, admin=admin)
    clean_sessions(root)
    folder = private_directory(root / ("session-" + uuid.uuid4().hex), admin=admin)
    try:
        # Publish the lease only after acquiring the lock. No secret is written before this.
        with (folder / "initializing").open("x+b") as stream:
            stream.write(b"1")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            os.link(folder / "initializing", folder / "lease")
            yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)
