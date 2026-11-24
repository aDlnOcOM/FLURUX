import ctypes as ct
import msvcrt
import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes as wt
from pathlib import Path
from time import monotonic, sleep

KERNEL = ct.WinDLL("kernel32", use_last_error=True)
SHELL = ct.WinDLL("shell32", use_last_error=True)
OLE = ct.WinDLL("ole32", use_last_error=True)
WAIT_TIMEOUT = 258


class BasicLimits(ct.Structure):
    _fields_ = [
        ("per_process_time", ct.c_int64),
        ("per_job_time", ct.c_int64),
        ("flags", wt.DWORD),
        ("min_working_set", ct.c_size_t),
        ("max_working_set", ct.c_size_t),
        ("active_process_limit", wt.DWORD),
        ("affinity", ct.c_size_t),
        ("priority", wt.DWORD),
        ("scheduling", wt.DWORD),
    ]


class JobLimits(ct.Structure):
    _fields_ = [
        ("basic", BasicLimits),
        ("io", ct.c_uint64 * 6),
        ("process_memory", ct.c_size_t),
        ("job_memory", ct.c_size_t),
        ("peak_process_memory", ct.c_size_t),
        ("peak_job_memory", ct.c_size_t),
    ]


class JobAccounting(ct.Structure):
    _fields_ = [
        ("times", ct.c_int64 * 4),
        ("page_faults", wt.DWORD),
        ("total_processes", wt.DWORD),
        ("active_processes", wt.DWORD),
        ("terminated_processes", wt.DWORD),
    ]


class ShellExecuteInfo(ct.Structure):
    _fields_ = [
        ("size", wt.DWORD),
        ("mask", wt.ULONG),
        ("window", wt.HWND),
        ("verb", wt.LPCWSTR),
        ("file", wt.LPCWSTR),
        ("parameters", wt.LPCWSTR),
        ("directory", wt.LPCWSTR),
        ("show", ct.c_int),
        ("instance", wt.HINSTANCE),
        ("id_list", ct.c_void_p),
        ("class_name", wt.LPCWSTR),
        ("class_key", wt.HKEY),
        ("hot_key", wt.DWORD),
        ("icon_or_monitor", wt.HANDLE),
        ("process", wt.HANDLE),
    ]


KERNEL.CreateJobObjectW.argtypes = (ct.c_void_p, wt.LPCWSTR)
KERNEL.CreateJobObjectW.restype = wt.HANDLE
KERNEL.SetInformationJobObject.argtypes = (wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD)
KERNEL.SetInformationJobObject.restype = wt.BOOL
KERNEL.AssignProcessToJobObject.argtypes = (wt.HANDLE, wt.HANDLE)
KERNEL.AssignProcessToJobObject.restype = wt.BOOL
KERNEL.TerminateJobObject.argtypes = (wt.HANDLE, wt.UINT)
KERNEL.TerminateJobObject.restype = wt.BOOL
KERNEL.QueryInformationJobObject.argtypes = (
    wt.HANDLE,
    ct.c_int,
    ct.c_void_p,
    wt.DWORD,
    ct.c_void_p,
)
KERNEL.QueryInformationJobObject.restype = wt.BOOL
KERNEL.OpenProcess.argtypes = (wt.DWORD, wt.BOOL, wt.DWORD)
KERNEL.OpenProcess.restype = wt.HANDLE
KERNEL.CloseHandle.argtypes = (wt.HANDLE,)
KERNEL.CloseHandle.restype = wt.BOOL
KERNEL.CreateFileW.argtypes = (
    wt.LPCWSTR,
    wt.DWORD,
    wt.DWORD,
    ct.c_void_p,
    wt.DWORD,
    wt.DWORD,
    wt.HANDLE,
)
KERNEL.CreateFileW.restype = wt.HANDLE
KERNEL.WaitForSingleObject.argtypes = (wt.HANDLE, wt.DWORD)
KERNEL.WaitForSingleObject.restype = wt.DWORD
KERNEL.GetExitCodeProcess.argtypes = (wt.HANDLE, ct.POINTER(wt.DWORD))
KERNEL.GetExitCodeProcess.restype = wt.BOOL
SHELL.ShellExecuteExW.argtypes = (ct.POINTER(ShellExecuteInfo),)
SHELL.ShellExecuteExW.restype = wt.BOOL
OLE.CoInitializeEx.argtypes = (ct.c_void_p, wt.DWORD)
OLE.CoInitializeEx.restype = wt.LONG


def close_handle(handle: int) -> None:
    """Release a Windows handle owned by the caller."""
    KERNEL.CloseHandle(handle)


def wait_handle(handle: int, milliseconds: int = 0) -> bool:
    """Return whether the process handle has signalled termination."""
    result = int(KERNEL.WaitForSingleObject(handle, milliseconds))
    if result not in (0, WAIT_TIMEOUT):
        raise ct.WinError(ct.get_last_error())
    return result == 0


def process_exit_code(handle: int) -> int:
    """Return the exit code of a completed Windows process."""
    code = wt.DWORD()
    if not KERNEL.GetExitCodeProcess(handle, ct.byref(code)):
        raise ct.WinError(ct.get_last_error())
    return code.value


def parent_handle(pid: int) -> int:
    """Open a parent process for waiting only."""
    handle = KERNEL.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
    if not handle:
        raise ct.WinError(ct.get_last_error())
    return int(handle)


def elevated_process(exe: Path, args: list[str], folder: Path) -> int:
    """Start the winws2 worker through UAC and return its process handle."""
    initialized = OLE.CoInitializeEx(None, 0x2 | 0x4) >= 0
    try:
        info = ShellExecuteInfo()
        info.size = ct.sizeof(info)
        info.mask = 0x40 | 0x100 | 0x400  # NOCLOSEPROCESS, NOASYNC, FLAG_NO_UI
        info.verb = "runas"
        info.file = str(exe)
        info.parameters = subprocess.list2cmdline(args)
        info.directory = str(folder)
        info.show = 0  # SW_HIDE
        if not SHELL.ShellExecuteExW(ct.byref(info)) or not info.process:
            raise ct.WinError(ct.get_last_error())
        return int(info.process)
    finally:
        if initialized:
            OLE.CoUninitialize()


def stop_job(job: int) -> None:
    """Wait briefly for children to release files after job termination."""
    try:
        if KERNEL.TerminateJobObject(job, 1):
            accounting = JobAccounting()
            deadline = monotonic() + 2
            while monotonic() < deadline:
                if not KERNEL.QueryInformationJobObject(
                    job, 1, ct.byref(accounting), ct.sizeof(accounting), None
                ):
                    break
                if not accounting.active_processes:
                    break
                sleep(0.04)
    finally:
        close_handle(job)


@contextmanager
def managed_process(
    args: list[str], cwd: Path, output: Path, *, input_data: bytes | None = None
) -> Iterator[subprocess.Popen[bytes]]:
    """Run a child in a job that kills its process tree when closed."""
    job = KERNEL.CreateJobObjectW(None, None)
    if not job:
        raise ct.WinError(ct.get_last_error())
    process: subprocess.Popen[bytes] | None = None
    try:
        limits = JobLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not KERNEL.SetInformationJobObject(job, 9, ct.byref(limits), ct.sizeof(limits)):
            raise ct.WinError(ct.get_last_error())
        # The child can hold the log briefly while Windows tears down the job.
        handle = KERNEL.CreateFileW(str(output), 0x40000000, 0x7, None, 2, 0x80, None)
        if handle == ct.c_void_p(-1).value:
            raise ct.WinError(ct.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_BINARY | os.O_WRONLY)
        except OSError:
            close_handle(handle)
            raise
        with os.fdopen(descriptor, "wb") as log:
            process = subprocess.Popen(
                args,
                cwd=cwd,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        handle = KERNEL.OpenProcess(0x101, False, process.pid)  # SET_QUOTA | TERMINATE
        if not handle:
            raise ct.WinError(ct.get_last_error())
        try:
            if not KERNEL.AssignProcessToJobObject(job, handle):
                raise ct.WinError(ct.get_last_error())
        finally:
            close_handle(handle)
        if input_data is not None and process.stdin is not None:
            try:
                process.stdin.write(input_data)
            finally:
                process.stdin.close()
        yield process
    finally:
        stop_job(job)
        if process:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def system_curl() -> Path:
    """Locate the curl executable supplied with Windows."""
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"
    if not path.is_file():
        raise FileNotFoundError("Не найден системный curl.exe в System32.")
    return path
