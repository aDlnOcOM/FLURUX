"""Standalone zapret2 settings, bounded package import and GUI lifecycle regressions."""

import hashlib
import os
import sys
import tempfile
import threading
import tkinter as tk
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from route_manager import zapret_bundle as bundle  # noqa: E402
from route_manager.config import MODES, STRATEGIES, Settings, load_settings, zapret_options  # noqa: E402
from route_manager.gui import App  # noqa: E402
from route_manager.runtime import Update  # noqa: E402


class ZapretTests(unittest.TestCase):
    def test_options_and_cascade_scope(self) -> None:
        draft = Settings(
            domains="ПРИМЕР.РФ example.org",
            tcp_ports="443, 8443,443",
            exclude_domains="cdn.example.org",
        )
        names, excluded, tcp, udp = zapret_options(draft)
        self.assertEqual(
            (names, excluded, tcp, udp),
            (("xn--e1afmkfd.xn--p1ai", "example.org"), ("cdn.example.org",), "443,8443", "443"),
        )
        for bad in ("-1", "443-8443", "0", "65536", ""):
            with self.assertRaises(ValueError):
                zapret_options(replace(draft, tcp_ports=bad))
        with self.assertRaises(ValueError):
            zapret_options(replace(draft, domains="x.example.org", exclude_domains="example.org"))
        with self.assertRaises(ValueError):
            zapret_options(replace(draft, tcp_ports="8443"), ("bridge.example.org",))
        with self.assertRaises(ValueError):
            zapret_options(replace(draft, exclude_domains="example.org"), ("bridge.example.org",))

    def test_zip_import_checks_before_elevation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "upstream.zip"
            sizes = {"winws2.exe": 3, "lua/library": 2}
            payload = {"winws2.exe": b"abc", "lua/library": b"de"}
            hashes = {k: hashlib.sha256(v).hexdigest() for k, v in payload.items()}
            with zipfile.ZipFile(archive, "w") as z:
                for k, v in payload.items():
                    z.writestr("bundle/zapret-winws/" + k, v)
                z.writestr("../../untouched.txt", "unselected")
                z.writestr("bundle/blockcheck/zapret2/nfq2/winws2.exe", "unused")
            with (
                patch.object(bundle, "SIZES", sizes),
                patch.object(bundle, "manifest", return_value=hashes),
            ):
                wire = bundle.acquire(archive, threading.Event(), lambda _: None)
                self.assertEqual(wire, b"\x03\0\0\0abc\x02\0\0\0de")
                self.assertFalse((root / "untouched.txt").exists())
                stop = threading.Event()
                stop.set()
                with self.assertRaises(InterruptedError):
                    bundle.acquire(archive, stop, lambda _: None)
                hashes["winws2.exe"] = "0" * 64
                with (
                    patch.object(bundle, "guard_path", return_value=root / "guard"),
                    patch.object(bundle, "_maintenance") as elevate,
                ):
                    with self.assertRaisesRegex(ValueError, "SHA-256"):
                        bundle.install(archive, threading.Event(), lambda _: None)
                    elevate.assert_not_called()


class StandaloneGuiTests(unittest.TestCase):
    def test_standalone_and_restart_share_one_worker(self) -> None:
        with tempfile.TemporaryDirectory() as scratch, patch.dict(os.environ, LOCALAPPDATA=scratch):
            root = tk.Tk()
            try:
                directory = Path(scratch)
                folder = directory / "FLURUX" / "Security" / "engine"
                for name in bundle.SIZES:
                    path = folder / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"fixture")
                with (
                    patch("route_manager.config.program_files", return_value=directory),
                    patch.object(bundle, "engine_folder", return_value=folder),
                ):
                    app = App(root, directory / "legacy", PROJECT / "run.pyw")
                    root.update()
                    app.show_zapret()
                    app.port.set("invalid-tor-port")
                    app.zapret.domains.insert("1.0", "example.org")
                    with (
                        patch("route_manager.gui.Session.start", autospec=True) as run,
                        patch.object(app, "_get_tor") as tor,
                    ):
                        app.zapret.run.invoke()
                        self.assertEqual(app.pending, {"zapret"})
                        self.assertEqual(app.mode.get(), MODES["zapret"])
                        self.assertEqual(run.call_args.args[1].domains, ("example.org",))
                        self.assertEqual(run.call_args.args[2:], (None, False))
                        app.zapret.tcp.set("invalid")
                        app.zapret.run.invoke()
                        self.assertFalse(app.session.stop.is_set())
                        self.assertEqual(run.call_count, 1)
                        app.strategy.set(STRATEGIES["quic"])
                        app.zapret.tcp.set("443,8443")
                        app.zapret.run.invoke()
                        self.assertTrue(app.session and app.session.stop.is_set())
                        self.assertEqual(run.call_count, 1)
                        app.events.put(Update("zapret", "done", ""))
                        app._poll()
                        self.assertEqual(run.call_count, 2)
                        self.assertEqual(run.call_args.args[1].tcp_ports, "443,8443")
                        tor.assert_not_called()
                        self.assertEqual(load_settings(app.settings_path).strategy, "quic")
                        self.assertTrue(app.zapret.verify.instate(["disabled"]))
                        app.zapret.stop.invoke()
                        app.events.put(Update("zapret", "done", ""))
                        app._poll()
                        self.assertFalse(app.pending)
                        self.assertFalse(app.zapret.verify.instate(["disabled"]))
            finally:
                for job in root.tk.call("after", "info"):
                    root.after_cancel(job)
                root.destroy()
