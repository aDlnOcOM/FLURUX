"""Exercise route attribution, real loopback measurements and the desktop comparison."""

import os
import socket
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from route_manager.config import Settings, ZapretConfig, zapret_args  # noqa: E402
from route_manager.diagnostic_routes import Case, catalogue, run_case  # noqa: E402
from route_manager.diagnostics import Result, Targets, http_sample, stun  # noqa: E402
from route_manager.gui import App  # noqa: E402
from route_manager.profiles import STRATEGIES  # noqa: E402
from route_manager.zapret_presets import PRESETS  # noqa: E402


class Payload(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        size = 524288 if self.path == "/file" else 4
        self.send_response(200 if self.path != "/error" else 503)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b"." * size)

    def log_message(self, format: str, *args: object) -> None:
        pass


class MeasurementTests(unittest.TestCase):
    def test_catalogue_has_60_unique_effective_configurations(self) -> None:
        inventory = catalogue(Settings(), [], "all")
        unique = set()
        for preset in PRESETS:
            cfg = ZapretConfig(
                Path("engine.exe"),
                preset.method,
                ("example.org",),
                (),
                preset.ports,
                preset.ports,
                preset.family,
            )
            unique.add(tuple(zapret_args(cfg, Path("hosts.txt"))))
        self.assertEqual(len(unique), 60)
        self.assertEqual(len({p.label for p in PRESETS}), 60)
        self.assertEqual(sum(bool(r.skip) for r in inventory), len(STRATEGIES))
        self.assertEqual(len(catalogue(Settings(), [], "zapret")), 61)

    def test_direct_http_and_video_use_actual_response(self) -> None:
        with ThreadingHTTPServer(("127.0.0.1", 0), Payload) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                stop = threading.Event()
                status, latency, speed, proto = http_sample(base + "/file", None, stop, video=True)
                self.assertEqual(status, 200)
                self.assertIsNotNone(latency)
                self.assertGreater(speed or 0, 0)
                self.assertTrue(proto.startswith("HTTP/"))
                self.assertIsNone(http_sample(base + "/tiny", None, stop, video=True)[2])
                self.assertEqual(http_sample(base + "/error", None, stop)[0], 503)
            finally:
                server.shutdown()
                worker.join(2)

    def test_stun_ignores_wrong_transactions_then_records_four_replies(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
            srv.bind(("127.0.0.1", 0))
            srv.settimeout(3)

            def respond() -> None:
                for _ in range(4):
                    request, peer = srv.recvfrom(200)
                    srv.sendto(b"\x01\x01" + request[2:8] + bytes(12), peer)
                    srv.sendto(b"\x01\x01" + request[2:], peer)

            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            t = Targets.parse("example.org", "", f"127.0.0.1:{srv.getsockname()[1]}")
            ms, jitter, loss = stun(t, threading.Event())
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertIsNotNone(ms)
            self.assertIsNotNone(jitter)
            self.assertEqual(loss, 0)

    def test_refused_socks_udp_does_not_use_direct_route(self) -> None:
        with socket.socket() as proxy, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            proxy.bind(("127.0.0.1", 0))
            proxy.listen()
            target.bind(("127.0.0.1", 0))
            target.settimeout(0.1)

            def refuse() -> None:
                conn, _ = proxy.accept()
                with conn:
                    conn.recv(3)
                    conn.sendall(b"\x05\xff")

            worker = threading.Thread(target=refuse, daemon=True)
            worker.start()
            t = Targets("https://example.org", "", "127.0.0.1", target.getsockname()[1])
            with self.assertRaises(OSError):
                stun(t, threading.Event(), socks=proxy.getsockname()[1])
            worker.join(2)
            with self.assertRaises(TimeoutError):
                target.recv(200)

    def test_active_scope_and_video_are_checked_independently(self) -> None:
        cfg = Settings(
            mode="zapret",
            strategy="quic",
            domains="example.org",
            exclude_domains="excluded.example.org",
            tcp_ports="8443, 9443",
        )
        case = Case("active", cfg, active=True)
        t = Targets.parse("https://www.example.org:9443", "https://cdn.example.org/file", "")
        args = (threading.Event(), Path(), Path(), False)
        with patch(
            "route_manager.diagnostic_routes.measure", return_value=Result("active")
        ) as measure:
            rows = run_case(case, t, *args)
            self.assertEqual(measure.call_args.args[2].video, "")
            self.assertFalse(measure.call_args.kwargs["udp"])
            self.assertFalse(measure.call_args.kwargs["quic"])
            self.assertIn("Видеофайл вне фильтра", rows[0].detail)
            for target in (
                "https://other.test:9443",
                "https://excluded.example.org:9443",
                "https://127.0.0.1:9443",
                "https://example.org",
            ):
                self.assertEqual(
                    run_case(case, replace(t, web=target), *args)[0].status, "Вне фильтра"
                )
            self.assertEqual(measure.call_count, 1)
        self.assertEqual(Result("missing").cells()[2:], ("—", "—", "—", "—"))

    def test_gui_catalogue_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, LOCALAPPDATA=tmp):
            root = tk.Tk()
            try:
                app = App(root, Path(tmp) / "old", PROJECT / "run.pyw")
                app.zapret.catalog.selection_set("59")
                app.zapret._apply_preset()
                settings = app._settings_snapshot()
                self.assertEqual(
                    (settings.strategy, settings.ip_family, settings.tcp_ports),
                    ("disorder_quic", "ipv6", "443,8443,9443"),
                )
                panel = app.diagnostics
                row = Result("результат", "Системный", "Доступен", 10, "UDP", 200, 50, 8, 10, 4, 0)
                with patch("route_manager.diagnostics_gui.run_case", return_value=[row]):
                    panel.begin()
                    end = time.monotonic() + 3
                    while panel.busy and time.monotonic() < end:
                        root.update()
                        panel.poll()
                        time.sleep(0.01)
                self.assertIn("GAME 1", panel.summary.get())
                self.assertEqual(panel.results["0"].ping_ms, 10)
                path = Path(tmp) / "report.csv"
                with patch(
                    "route_manager.diagnostics_gui.filedialog.asksaveasfilename",
                    return_value=str(path),
                ):
                    panel.export()
                report = path.read_text(encoding="utf-8-sig")
                self.assertIn("10 UDP", report)
                self.assertIn("Подробности", report)
            finally:
                root.destroy()
