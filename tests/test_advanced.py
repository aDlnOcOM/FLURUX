import asyncio
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from route_manager.help_topics import ARTICLES, ROUTES, search
from route_manager.masque_capsule import read_int, upgrade, varint
from route_manager.profiles import STRATEGIES, load_profiles, save_profiles, template, validate
from route_manager.routes import management_args, mesh_peers, mesh_select, provision, synchronize
from route_manager.topology import client, server


def configured(kind: str) -> dict:
    """Build a profile for deterministic unit tests."""
    p = template(kind)
    p.update(target_host="192.0.2.1", access_cidr="198.51.100.1/32")
    for i, node in enumerate(p["nodes"]):
        node.update(
            host=f"node{i}.example",
            ssh=f"node{i}",
            public_key=f"public{i}",
            client_public=f"client-public{i}",
            uplink_public=f"uplink{i}",
            client_private=f"client-private{i}",
            password="test",
        )
    return p


class ProfileTests(unittest.TestCase):
    def test_offline_help_covers_every_strategy(self) -> None:
        self.assertEqual(set(ROUTES), set(STRATEGIES))
        self.assertEqual(len(ARTICLES), len({a.key for a in ARTICLES}))
        for key in STRATEGIES:
            validate(configured(key))
            self.assertTrue(any(a.key == key for a in search(STRATEGIES[key][0])))
        self.assertTrue(any(a.key == "install" for a in search("отпечаток SSH")))
        self.assertEqual(search("xyz-no-such-topic"), [])

    def test_windows_profile_vault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "vault"
            p = configured("https")
            p["nodes"][0]["password"] = "test-plaintext-secret"
            save_profiles(file, [p])
            self.assertNotIn(b"test-plaintext-secret", file.read_bytes())
            self.assertEqual(load_profiles(file), [p])
            save_profiles(file, [])
            self.assertEqual(load_profiles(file), [])

    def test_nested_and_gateway_own_different_inner_keys(self) -> None:
        p = configured("nested")
        c = client(p)
        self.assertEqual(c["endpoints"][1]["detour"], "wg0")
        self.assertEqual(c["route"]["final"], "wg1")
        self.assertEqual(server(p, 1)["endpoints"][0]["peers"][0]["public_key"], "client-public1")
        p["kind"] = "forwarded"
        self.assertEqual(len(client(p)["endpoints"]), 1)
        self.assertEqual(server(p, 1)["endpoints"][0]["peers"][0]["public_key"], "uplink0")
        gateway = server(p, 0)
        self.assertEqual(gateway["route"]["rules"][0]["outbound"], "wg1")
        self.assertNotIn("client-private", json.dumps(gateway))

    def test_exit_always_dials_via_entry(self) -> None:
        for kind in ("chain", "ovpn_http", "ovpn_socks"):
            c = client(configured(kind))
            last = next(
                e for e in c["outbounds"] + c["endpoints"] if e["tag"] == c["route"]["final"]
            )
            self.assertEqual(last["detour"], "hop0")
        p = configured("chain")
        p["nodes"][1]["type"] = "hy2"
        with self.assertRaises(ValueError):
            validate(p)

    def test_install_order_and_retry_reuses_credentials(self) -> None:
        p = configured("chain")
        for n in p["nodes"]:
            n["password"] = ""
        calls = []

        def fake_remote(n: dict, r: dict, via: str = "") -> dict:
            calls.append((n["ssh"], r["action"], via))
            return {"message": "OK"} if r["action"] == "deploy" else {}

        with patch("route_manager.routes.remote", side_effect=fake_remote):
            provision(p, lambda _: None, lambda: None)
            expected = copy.deepcopy(p)
            provision(p, lambda _: None, lambda: None)
        self.assertEqual(expected, p)
        self.assertEqual(
            calls[:4],
            [
                ("node0", "prepare", ""),
                ("node1", "prepare", "node0"),
                ("node1", "deploy", "node0"),
                ("node0", "deploy", ""),
            ],
        )
        self.assertTrue(all(n["managed"] for n in p["nodes"]))

    def test_ssh_sync_only_fetches_public_material(self) -> None:
        p = configured("https")
        n = p["nodes"][0]
        n["managed"] = True
        cert = "-----BEGIN CERTIFICATE-----\nMIIBwDCCAWagAwIBAgIUYI2IZpd0xL1ks32dvuVwOPsm8/EwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEyNDE1MTEwOFoXDTI2MTEyNjE1\nMTEwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE2z2kxOaY2/1w9K88osuyse5mhEIeWs5VyoU5MZf/oqXazWuJQlyEp5Xa\nowa39J34ohkpFA89K7/KbHkyUZxKm6OBlTCBkjAdBgNVHQ4EFgQU/hbIm01ajt2/\ny404I6Pi4O6JtJcwHwYDVR0jBBgwFoAU/hbIm01ajt2/y404I6Pi4O6JtJcwDwYD\nVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwEwYDVR0l\nBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgOIMAoGCCqGSM49BAMCA0gAMEUC\nIQCd48lHZX2vUIrlr5W419BdFRcs5XtCM+qExTIEg79MCAIgP+93uD+LoBMYgtzn\nH+UWpE30ha3XzjzJIRvbFPsTt10=\n-----END CERTIFICATE-----\n"
        with patch(
            "route_manager.routes.remote", return_value={"certificate": cert, "password": "other"}
        ) as ssh:
            synchronize(p)
            self.assertEqual(ssh.call_args.args[1]["action"], "public")
            self.assertEqual(n["password"], "test")
            self.assertEqual(n["certificate"], cert)
            p["sync_on_connect"] = False
            synchronize(p)
            self.assertEqual(ssh.call_count, 1)
        with patch("route_manager.routes.binary", return_value="ssh.exe"):
            args = management_args(n, "jump")
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertTrue(any("ProxyCommand" in a and "jump" in a for a in args))

    def test_mesh_exit_requires_online_advertisement(self) -> None:
        status = {
            "BackendState": "Running",
            "Peer": {
                "a": {
                    "TailscaleIPs": ["100.64.0.1"],
                    "DNSName": "box.example.",
                    "Online": True,
                    "ExitNodeOption": True,
                },
                "b": {
                    "TailscaleIPs": ["100.64.0.2"],
                    "HostName": "other",
                    "Online": False,
                    "ExitNodeOption": True,
                },
            },
        }
        with (
            patch("route_manager.routes.binary", return_value="tailscale.exe"),
            patch("route_manager.routes.command", return_value=json.dumps(status)) as cli,
        ):
            self.assertEqual(len(mesh_peers()), 2)
            mesh_select("100.64.0.1")
            self.assertEqual(cli.call_args.args[0][-1], "--exit-node=100.64.0.1")
            with self.assertRaises(ValueError):
                mesh_select("100.64.0.2")
            mesh_select("")
            self.assertEqual(cli.call_args.args[0][-1], "--exit-node=")

    def test_upgrade_and_capsule_length_boundaries(self) -> None:
        self.assertTrue(upgrade({"connection": "keep-alive, Upgrade", "upgrade": "CONNECT-UDP"}))
        self.assertFalse(upgrade({"upgrade": "connect-udp"}))

        async def check() -> None:
            for value in (0, 63, 64, 16383, 16384, 65508, 2**30):
                stream = asyncio.StreamReader()
                stream.feed_data(varint(value))
                stream.feed_eof()
                self.assertEqual(await read_int(stream), value)

        asyncio.run(check())
