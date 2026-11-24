"""Check the desktop MSI layout without installing the product on the test machine."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

try:
    import msilib
except ImportError:
    msilib = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    msilib and msilib.AMD64, "The installer is built with Windows CPython 3.12 x64"
)
class InstallerTests(unittest.TestCase):
    def test_shortcuts_repair_and_privileged_component_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            guard = folder / "guard.bin"
            guard.write_bytes(b"installer layout fixture")
            package = folder / "test.msi"
            spec = importlib.util.spec_from_file_location(
                "flurux_build_msi", ROOT / "security/build_msi.py"
            )
            assert spec and spec.loader
            builder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(builder)
            builder.build(guard, package, desktop={Path("FLURUX.exe"): guard}, validator=guard)

            def rows(sql: str, columns: int) -> set[tuple[str, ...]]:
                db = msilib.OpenDatabase(str(package), msilib.MSIDBOPEN_READONLY)
                view = db.OpenView(sql)
                view.Execute(None)
                result = set()
                while record := view.Fetch():
                    result.add(tuple(record.GetString(i + 1) for i in range(columns)))
                view.Close()
                return result

            self.assertEqual(
                rows("SELECT Directory_,Target,WkDir FROM Shortcut", 3),
                {
                    ("ProgramMenuFolder", "[#FLURUX.exe]", "INSTALLDIR"),
                    ("DesktopFolder", "[#FLURUX.exe]", "INSTALLDIR"),
                },
            )
            self.assertEqual(
                rows("SELECT PropertyKey,PropVariantValue FROM MsiShortcutProperty", 2),
                {("System.AppUserModel.ID", "FLURUX.Desktop")},
            )
            self.assertEqual(
                rows("SELECT Directory_Parent FROM Directory WHERE Directory='security_dir'", 1),
                {("flurux_system",)},
            )
            self.assertEqual(
                rows("SELECT Source,Target FROM CustomAction WHERE Action='RecordFolder'", 2),
                {("ARPINSTALLLOCATION", "[INSTALLDIR]")},
            )
            self.assertEqual(rows("SELECT Property FROM AppSearch", 1), {("INSTALLDIR",)})
            self.assertEqual(
                rows("SELECT LockObject FROM MsiLockPermissionsEx", 1), {("INSTALLDIR",)}
            )
            self.assertEqual(
                rows("SELECT Value FROM Property WHERE Property='ALLUSERS'", 1), {("1",)}
            )
