import sys
import tempfile
import unittest
from pathlib import Path
from queue import SimpleQueue
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from route_manager.config import (  # noqa: E402
    Settings,
    TorConfig,
    ZapretConfig,
    load_settings,
    parse_bridge_lines,
    parse_domains,
    save_settings,
    torrc,
    validated_url,
    webtunnel_domains,
    zapret_args,
)
from route_manager.runtime import Session, Update, probe_args  # noqa: E402


class RouteTests(unittest.TestCase):
    def test_bridge_sets_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_file = Path(directory) / "settings.json"
            settings = Settings(
                webtunnel_bridges="один", obfs4_bridges="другой", socks_port="19051"
            )
            save_settings(settings_file, settings)
            self.assertEqual(load_settings(settings_file), settings)

    def test_bridge_lines_cannot_inject_tor_settings(self) -> None:
        bridge = "webtunnel 192.0.2.1:443 " + "A" * 40 + " url=https://bridge.example.org/path"
        self.assertEqual(parse_bridge_lines(f"Bridge {bridge}\n{bridge}", "webtunnel"), (bridge,))
        with self.assertRaises(ValueError):
            parse_bridge_lines(f"{bridge}\nSocksPort 0.0.0.0:9050", "webtunnel")

    def test_cascade_uses_webtunnel_tls_name(self) -> None:
        bridge = (
            "webtunnel 192.0.2.1:443 "
            + "A" * 40
            + " url=https://a.example.org/path servername=b.example.org"
        )
        config = TorConfig(Path("tor.exe"), Path("lyrebird.exe"), "webtunnel", (bridge,), 19050)
        self.assertEqual(webtunnel_domains(config), ("b.example.org",))
        text = torrc(config)
        self.assertIn("SocksPort 127.0.0.1:19050", text)
        self.assertIn(f"Bridge {bridge}\n", text)

    def test_cascade_stops_when_zapret_fails_to_start(self) -> None:
        events: SimpleQueue[Update] = SimpleQueue()
        session = Session(Path("."), Path("run.pyw"), events)
        tor = TorConfig(Path("tor.exe"), Path("lyrebird.exe"), "webtunnel", (), 19050)
        zapret = ZapretConfig(Path("winws2.exe"), "split", ("example.org",))
        with (
            patch.object(session, "_zapret", side_effect=OSError("test")),
            patch("route_manager.runtime.managed_process") as start,
        ):
            session.start(zapret, tor, cascade=True)
            messages = [events.get(timeout=3) for _ in range(7)]
        start.assert_not_called()
        self.assertTrue(
            any(event.engine == "tor" and "сначала" in event.message for event in messages)
        )

    def test_quic_profile_has_host_scope_for_both_protocols(self) -> None:
        scope = Path("a folder") / "hosts.txt"
        config = ZapretConfig(Path("winws2.exe"), "quic", ("example.org",))
        args = zapret_args(config, scope)
        self.assertEqual(args.count(f"--hostlist={scope}"), 2)
        self.assertIn("--wf-udp-out=443", args)

    def test_domains_are_normalized(self) -> None:
        self.assertEqual(
            parse_domains("пример.рф, EXAMPLE.COM. example.com"),
            ("xn--e1afmkfd.xn--p1ai", "example.com"),
        )
        with self.assertRaises(ValueError):
            parse_domains("https://example.org/a")

    def test_route_check_uses_remote_dns_only_for_tor(self) -> None:
        self.assertIn("socks5h://127.0.0.1:19050", probe_args("https://example.org", 19050))
        direct = probe_args("https://example.org", None)
        self.assertEqual(direct[direct.index("--proxy") + 1], "")
        self.assertEqual(validated_url("example.org/a"), "https://example.org/a")
        with self.assertRaises(ValueError):
            validated_url("https://user:secret@example.org/")
