"""One explicitly approved Windows helper for sequential zapret2 comparison runs."""

import ctypes as ct
import mmap
import os
import struct
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from ctypes import wintypes as wt
from time import monotonic

from route_manager.config import ZapretConfig
from route_manager.private_files import kernel
from route_manager.security import guard_path
from route_manager.windows import close_handle, elevated_process, process_exit_code, wait_handle
from route_manager.zapret_presets import PRESETS, Preset

kernel.ResetEvent.argtypes = [wt.HANDLE]


class Benchmark:
    """Keep the fixed-profile helper available only for the lifetime of one user-initiated test."""

    def __init__(self, stack: ExitStack) -> None:
        self.stack = stack
        self.process = 0
        self.events: dict[str, int] = {}
        self.scope: tuple[tuple[str, ...], tuple[str, ...]] | None = None

    def _open(self, cfg: ZapretConfig) -> None:
        exe = guard_path()
        nonce = uuid.uuid4().hex
        prefix = "Local\\FLURUX-" + nonce
        with ExitStack() as stack:
            for suffix in ("stop", "ready", "done", "quit", "request"):
                handle = kernel.CreateEventW(
                    None, suffix != "request", False, prefix + "-" + suffix
                )
                if not handle:
                    raise ct.WinError(ct.get_last_error())
                stack.callback(close_handle, handle)
                if ct.get_last_error() == 183:
                    raise OSError("Канал диагностики уже существует.")
                self.events[suffix] = handle
            self.slot = stack.enter_context(mmap.mmap(-1, 8, tagname=prefix + "-slot"))
            self.process = elevated_process(
                exe,
                [
                    "benchmark",
                    str(os.getpid()),
                    nonce,
                    ",".join(cfg.domains),
                    ",".join(cfg.excluded) or "-",
                ],
                exe.parent,
            )
            self.scope = (cfg.domains, cfg.excluded)
            stack.callback(self._close)
            self.stack.enter_context(stack.pop_all())

    def _close(self) -> None:
        kernel.SetEvent(self.events["quit"])
        kernel.SetEvent(self.events["stop"])
        try:
            wait_handle(self.process, 10000)
        finally:
            close_handle(self.process)

    @contextmanager
    def running(self, cfg: ZapretConfig, stop: threading.Event) -> Iterator[Callable[[], None]]:
        """Switch profiles only after the prior engine released its job and file lock."""
        index = PRESETS.index(Preset(cfg.strategy, cfg.ip_family, cfg.tcp_ports))
        if not self.process:
            self._open(cfg)
        if self.scope != (cfg.domains, cfg.excluded):
            raise ValueError("Изменились тестовые адреса.")

        def alive() -> None:
            if wait_handle(self.process):
                raise OSError(
                    f"Помощник диагностики завершился с кодом {process_exit_code(self.process)}."
                )
            if wait_handle(self.events["done"]):
                rc = struct.unpack_from("<I", self.slot, 4)[0]
                raise OSError(f"Движок завершился до окончания измерения. Код Windows {rc}.")

        for key in ("stop", "ready", "done"):
            if not kernel.ResetEvent(self.events[key]):
                raise ct.WinError(ct.get_last_error())
        self.slot[:] = struct.pack("<II", index, 0)
        if not kernel.SetEvent(self.events["request"]):
            raise ct.WinError(ct.get_last_error())
        try:
            limit = monotonic() + 25
            while not wait_handle(self.events["ready"], 100):
                if stop.is_set():
                    raise InterruptedError("Проверка отменена.")
                alive()
                if monotonic() > limit:
                    raise TimeoutError("Движок не сообщил о готовности.")
            alive()
            yield alive
        finally:
            kernel.SetEvent(self.events["stop"])
            while not wait_handle(self.events["done"], 100):
                if wait_handle(self.process):
                    break
