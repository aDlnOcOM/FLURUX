"""Regression tests for the security boundaries of FLURUX."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from route_manager.config import load_settings
from route_manager.linux_node import reality_keys
from route_manager.private_files import clean_sessions, private_directory, private_session
from route_manager.profiles import check_proxy_credentials, host, template
from route_manager.routes import public_material, remote
from route_manager.topology import client, server


class SecurityTests(unittest.TestCase):
    def test_reality_rejects_malformed_material_without_echo(self) -> None:
        a, b = (base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=") for n in (1, 2))
        self.assertEqual(reality_keys(f"PrivateKey: {a}\nPublicKey: {b}\n"), (a, b))
        for invalid in (
            a,
            f"PrivateKey: {a}",
            f"PrivateKey: {a}\nPrivateKey: {b}",
            f"PublicKey: {a}\nPrivateKey: {a}",
        ):
            with self.assertRaises(ValueError) as error:
                reality_keys(invalid)
            self.assertNotIn(a, str(error.exception))
        with self.assertRaises(ValueError):
            public_material({"public_key": f"PrivateKey: {a}"})
        with self.assertRaises(ValueError):
            public_material({"certificate": a})

    def test_plain_credentials_need_explicit_opt_in(self) -> None:
        p = template("ovpn_http")
        n = p["nodes"][0]
        n.update(host="proxy.example", password="example")
        with self.assertRaises(ValueError):
            check_proxy_credentials(p)
        n["type"] = "https"
        check_proxy_credentials(p)
        n.update(type="http", host="127.0.0.1")
        check_proxy_credentials(p)
        n.update(host="192.0.2.1")
        p["allow_plain_proxy"] = True
        check_proxy_credentials(p)

    def test_relay_requires_a_limited_source_network(self) -> None:
        p = template("relay_udp")
        p.update(target_host="127.0.0.1", target_port=8080)
        for cidr in ("", "0.0.0.0/0", "::/0"):
            p["access_cidr"] = cidr
            with self.assertRaises(ValueError):
                server(p, 0)
        p["access_cidr"] = "192.0.2.77/32"
        rules = server(p, 0)["route"]["rules"]
        self.assertEqual(rules[0]["source_ip_cidr"], ["192.0.2.77/32"])
        self.assertEqual(rules[1]["action"], "reject")

    def test_host_fields_reject_controls_and_ipv6_zones(self) -> None:
        for address in ("fe80::1%zone", "fe80::1%eth0\n", "192.0.2.1\r", "x.test\0"):
            with self.assertRaises(ValueError):
                host(address)
        self.assertEqual(host("2001:db8::1"), "2001:db8::1")

    def test_public_sync_requires_no_admin_command(self) -> None:
        instance = "rm-" + "f" * 32 + "-0"
        with (
            patch("route_manager.routes.management_args", return_value=["ssh.exe", "server"]),
            patch("route_manager.routes.command", return_value="{}") as cli,
        ):
            remote({}, {"action": "public", "instance": instance})
            self.assertEqual(
                cli.call_args.args[0][-1],
                f"/bin/cat -- /usr/local/lib/flurux/public/{instance}.json",
            )
            with self.assertRaises(ValueError):
                remote({}, {"action": "public", "instance": "bad"})

    def test_tun_dns_uses_a_literal_bootstrap_and_tunnel(self) -> None:
        p = template("https")
        p["system_tun"] = True
        p["nodes"][0].update(host="node.example", tls_name="node.example")
        config = client(p)
        dns = config["dns"]["servers"]
        self.assertEqual(dns[0]["type"], "https")
        self.assertEqual(dns[0]["server"], "1.1.1.1")
        self.assertEqual(dns[1]["detour"], config["route"]["final"])
        self.assertEqual(config["route"]["rules"][0]["action"], "hijack-dns")

    def test_plaintext_settings_are_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            secret = "private-bridge-test"
            path.write_text(json.dumps({"obfs4_bridges": secret}))
            self.assertEqual(load_settings(path).obfs4_bridges, secret)
            self.assertNotIn(secret, path.read_text())
            self.assertEqual(load_settings(path).obfs4_bridges, secret)

    def test_live_leases_survive_sweep_and_crashed_leases_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = private_directory(Path(d) / "sessions")
            with private_session(root) as live:
                env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
                code = "import sys,os;from pathlib import Path;from route_manager.private_files import private_session;c=private_session(Path(sys.argv[1]));p=c.__enter__();(p/'route.json').write_text('test');os._exit(0)"
                subprocess.run([sys.executable, "-c", code, str(root)], env=env, check=True)
                self.assertEqual(len(list(root.glob("session-*"))), 2)
                clean_sessions(root)
                self.assertEqual(list(root.glob("session-*")), [live])
            self.assertEqual(list(root.iterdir()), [])
