import hashlib
import io
import sys
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from route_manager import tor_bundle
from route_manager.config import Settings


class TorDownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stop = threading.Event()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as stream:
            for name in tor_bundle.FILES:
                data = name.encode()
                item = tarfile.TarInfo(name)
                item.size = len(data)
                stream.addfile(item, io.BytesIO(data))
        self.archive = archive.getvalue()
        self.enterContext(patch.object(tor_bundle, "SIZE", len(self.archive)))
        self.enterContext(
            patch.object(tor_bundle, "SHA256", hashlib.sha256(self.archive).hexdigest())
        )

    def test_download_retries_and_reuses_verified_bundle(self) -> None:
        progress = []
        with patch(
            "route_manager.tor_bundle.urllib.request.urlopen",
            side_effect=[URLError("offline"), io.BytesIO(self.archive)],
        ) as fetch:
            path = tor_bundle.install_bundle(self.root, self.stop, progress.append)
            self.assertEqual(path.read_bytes(), b"tor/tor.exe")
            self.assertEqual(progress[-1], 100)
            self.assertEqual(tor_bundle.install_bundle(self.root, self.stop, progress.append), path)
            self.assertEqual(fetch.call_count, 2)

    def test_failed_hash_never_publishes(self) -> None:
        with (
            patch.object(tor_bundle, "SHA256", "0" * 64),
            patch(
                "route_manager.tor_bundle.urllib.request.urlopen",
                return_value=io.BytesIO(self.archive),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                tor_bundle.install_bundle(self.root, self.stop, lambda _: None)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cancel_before_request_leaves_clean_directory(self) -> None:
        self.stop.set()
        with (
            patch("route_manager.tor_bundle.urllib.request.urlopen") as fetch,
            self.assertRaises(InterruptedError),
        ):
            tor_bundle.install_bundle(self.root, self.stop, lambda _: None)
        fetch.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual((Settings().mode, Settings().transport), ("tor", "direct"))
