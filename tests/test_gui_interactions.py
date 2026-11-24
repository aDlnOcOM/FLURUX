"""Interaction regressions for the Windows desktop client, using an isolated user data directory."""

import os
import socket
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from collections.abc import Callable
from pathlib import Path
from tkinter import ttk
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from route_manager.config import TRANSPORTS, load_settings  # noqa: E402
from route_manager.form_view import FormView  # noqa: E402
from route_manager.gui import App  # noqa: E402
from route_manager.profiles import STRATEGIES, load_profiles, template  # noqa: E402


class DesktopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, LOCALAPPDATA=str(self.temp)))
        self.root = tk.Tk()
        self.addCleanup(self.cleanup_window)
        self.app = App(self.root, self.temp / "legacy", PROJECT / "run.pyw")
        self.errors: list[BaseException] = []
        self.root.report_callback_exception = lambda exc, value, tb: self.errors.append(value)
        self.root.update()

    def cleanup_window(self) -> None:
        """Remove timers before releasing the test interpreter."""
        try:
            for task in self.root.tk.call("after", "info"):
                self.root.after_cancel(task)
            self.root.destroy()
        except tk.TclError:
            pass
        self.assertFalse(self.errors, self.errors)

    def pump(self, done: Callable[[], bool], timeout: float = 5) -> None:
        """Dispatch Tk events until an observable condition holds."""
        deadline = time.monotonic() + timeout
        while not done() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertTrue(done(), self.errors)

    def test_profile_tabs_fit_and_fields_are_reachable(self) -> None:
        panel = self.app.advanced
        tabs = self.app.help.tabs
        help_button = next(w for w in panel.footer.winfo_children() if isinstance(w, ttk.Button))
        for size in ("800x590", "900x620"):
            self.root.geometry(size)
            for kind in STRATEGIES:
                with self.subTest(size=size, kind=kind):
                    tabs.select(panel.page)
                    panel.edit(template(kind))
                    for page in panel.editor.winfo_children():
                        self.assertIsInstance(page, FormView)
                        panel.editor.select(page)
                        self.root.update()
                        for w in (
                            *panel.action_buttons,
                            panel.stop_button,
                            panel.status_label,
                            help_button,
                        ):
                            self.assertTrue(w.winfo_ismapped())
                            self.assertLessEqual(
                                w.winfo_rootx() + w.winfo_width(),
                                panel.page.winfo_rootx() + panel.page.winfo_width(),
                            )
                            self.assertLessEqual(
                                w.winfo_rooty() + w.winfo_height(),
                                panel.page.winfo_rooty() + panel.page.winfo_height(),
                            )
                        for field in page.body.winfo_children():
                            if isinstance(field, (ttk.Entry, ttk.Checkbutton, ttk.Button)):
                                self.assertLessEqual(
                                    field.winfo_rootx() + field.winfo_width(),
                                    page.canvas.winfo_rootx() + page.canvas.winfo_width() + 1,
                                    str(field),
                                )
                                field.event_generate("<FocusIn>")
                                self.root.update_idletasks()
                                self.assertGreaterEqual(
                                    field.winfo_rooty(), page.canvas.winfo_rooty() - 1
                                )
                                self.assertLessEqual(
                                    field.winfo_rooty() + field.winfo_height(),
                                    page.canvas.winfo_rooty() + page.canvas.winfo_height() + 1,
                                )
                    help_button.invoke()
                    self.assertEqual(self.app.help.active.key, kind)

    def test_select_edit_save_and_discard(self) -> None:
        p = self.app.advanced
        p.kind.current(p.modes.index("ovpn_http"))
        p.kind.event_generate("<<ComboboxSelected>>")
        self.assertEqual(p.current["kind"], "ovpn_http")
        for _, key, var in p.bindings:
            if key == "type":
                var.set("https")
            if key == "name":
                var.set("Проверка профиля")
        self.assertIn("https", p.editor.tab(1, "text"))
        with patch("route_manager.advanced_gui.messagebox.askyesno", return_value=False) as ask:
            p.kind.current(p.modes.index("ssh"))
            p.kind.event_generate("<<ComboboxSelected>>")
        ask.assert_called_once()
        self.assertEqual(p.collect()["name"], "Проверка профиля")
        self.assertEqual(p.modes[p.kind.current()], "ovpn_http")
        p.action_buttons[0].invoke()
        self.assertEqual(load_profiles(p.path)[0]["name"], "Проверка профиля")
        p.new_button.invoke()
        self.assertEqual(p.pick.get(), "")
        p.action_buttons[2].invoke()
        self.assertFalse(p.busy)
        self.assertEqual(len(load_profiles(p.path)), 1)
        p.pick.current(0)
        p.pick.event_generate("<<ComboboxSelected>>")
        self.assertEqual(p.collect()["name"], "Проверка профиля")

    def test_settings_and_port_validation(self) -> None:
        app = self.app
        app.port.set("1")
        with (
            patch("route_manager.gui.messagebox.showerror") as error,
            patch.object(app, "_get_tor") as download,
        ):
            app.start_button.invoke()
            app.save()
            self.assertEqual(error.call_count, 2)
            download.assert_not_called()
        self.assertFalse(app.settings_path.exists())
        app.port.set("19052")
        for key, value in (("webtunnel", "мост 1"), ("obfs4", "мост 2")):
            app.transport.set(TRANSPORTS[key])
            app._transport_changed()
            app.bridges.insert("end", value)
        app.save()
        saved = load_settings(app.settings_path)
        self.assertEqual(
            (saved.webtunnel_bridges, saved.obfs4_bridges, saved.socks_port),
            ("мост 1", "мост 2", "19052"),
        )
        self.assertIn("Сохранено", app.settings_feedback.get())

    def test_late_download_events_after_stop(self) -> None:
        app = self.app
        late_progress, release = threading.Event(), threading.Event()

        def download(data: Path, stop: threading.Event, progress: Callable[[int], None]) -> Path:
            stop.wait(3)
            progress(99)
            late_progress.set()
            release.wait(3)
            return data / "tor.exe"

        with (
            patch("route_manager.gui.messagebox.askokcancel", return_value=True),
            patch("route_manager.gui.install_bundle", side_effect=download) as install,
        ):
            app.start_button.invoke()
            app.stop_button.invoke()
            self.assertTrue(app.stop_button.instate(["disabled"]))
            self.assertTrue(app.start_button.instate(["disabled"]))
            self.pump(lambda: late_progress.is_set() and app.events.empty())
            self.assertIn("Отмена", app.status["tor"].cget("text"))
            release.set()
            self.pump(lambda: not app.downloading)
            install.assert_called_once()
        self.assertEqual(app.tor.get(), "")
        self.assertEqual(app.status["tor"].cget("text"), "Остановлен")
        self.assertFalse(app.start_button.instate(["disabled"]))

    def test_close_while_downloading_does_not_start_tor(self) -> None:
        app = self.app

        def download(data: Path, stop: threading.Event, progress: Callable[[int], None]) -> Path:
            if not stop.wait(3):
                raise TimeoutError("No cancellation request")
            return data / "tor.exe"

        with (
            patch("route_manager.gui.messagebox.askokcancel", return_value=True),
            patch("route_manager.gui.install_bundle", side_effect=download),
            patch("route_manager.gui.Session") as session,
        ):
            app.start_button.invoke()
            self.assertTrue(app.downloading)
            self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))
            self.pump(lambda: not app.downloading)
            session.assert_not_called()
        with self.assertRaises(tk.TclError):
            self.root.winfo_exists()

    def test_close_cancels_live_http_probe(self) -> None:
        app = self.app
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            server.settimeout(3)
            app.target.set(f"http://127.0.0.1:{server.getsockname()[1]}/")
            app.direct_check.invoke()
            with server.accept()[0] as peer:
                peer.settimeout(4)
                self.assertIn(b"GET /", peer.recv(4096))
                self.assertTrue(app.direct_check.instate(["disabled"]))
                self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))
                self.assertTrue(app.closing)
                self.pump(lambda: not app.check_running)
                try:
                    self.assertEqual(peer.recv(1024), b"")
                except ConnectionResetError:
                    pass  # Windows may send RST when the outstanding request is cancelled.
        with self.assertRaises(tk.TclError):
            self.root.winfo_exists()

    def test_mesh_actions_follow_selected_peer(self) -> None:
        p = self.app.advanced
        peers = [
            dict(ip="100.64.0.1", name="one", online=True, exit=False, selected=False),
            dict(ip="100.64.0.2", name="two", online=True, exit=True, selected=False),
        ]
        refresh, ping, select, _ = p.mesh_buttons
        self.assertTrue(ping.instate(["disabled"]))
        with (
            patch("route_manager.advanced_gui.mesh_peers", return_value=peers),
            patch("route_manager.advanced_gui.mesh_select") as choose,
        ):
            refresh.invoke()
            self.pump(lambda: not p.mesh_busy)
            p.peers.selection_set(peers[0]["ip"])
            self.root.update()
            self.assertFalse(ping.instate(["disabled"]))
            self.assertTrue(select.instate(["disabled"]))
            p.peers.selection_set(peers[1]["ip"])
            self.root.update()
            self.assertFalse(select.instate(["disabled"]))
            select.invoke()
            self.assertTrue(refresh.instate(["disabled"]))
            self.pump(lambda: not p.mesh_busy)
            choose.assert_called_once_with(peers[1]["ip"], "")
            self.assertEqual(p.selected(), peers[1]["ip"])
            self.assertIn("выбран", p.mesh_status.get())
