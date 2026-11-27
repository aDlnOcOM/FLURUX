"""Package the first-party app and guard using the Python 3.12 Windows SDK bindings."""

import argparse
import hashlib
import msilib
import re
import tempfile
import uuid
from msilib import schema, sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ID = uuid.UUID("23970cfd-8244-4722-b289-b6df91becb24")


def build(
    guard: Path,
    output: Path,
    desktop: dict[Path, Path] | None = None,
    *,
    validator: Path | None = None,
) -> None:
    """Build a per-machine MSI with isolated code and no third-party engines."""
    if not msilib.AMD64:
        raise ValueError("Use 64-bit Python 3.12.")
    version = "0.3.5" if desktop else "0.3.0"
    output = output.resolve()
    db = msilib.init_database(
        str(output),
        schema,
        "FLURUX" if desktop else "FLURUX Security x64",
        "{" + str(uuid.uuid5(PROJECT_ID, "0.3.0")).upper() + "}",
        version,
        "FLURUX",
    )
    msilib.add_tables(db, sequence)
    msilib.add_data(
        db, "Property", [("ALLUSERS", "1"), ("ARPNOMODIFY", "1"), ("INSTALLLEVEL", "1")]
    )
    feature = msilib.Feature(
        db, "Application", "FLURUX", "Desktop application and security broker", 1
    )
    feature.set_current()
    cab = msilib.CAB("files.cab")
    root = msilib.Directory(db, cab, None, str(ROOT), "TARGETDIR", "SourceDir", 0)
    pf = msilib.Directory(db, cab, root, ".", "ProgramFiles64Folder", ".", 0)
    app = msilib.Directory(db, cab, pf, ".", "INSTALLDIR" if desktop else "appdir", "FLURUX", 0)
    dirs = {Path(): app}
    if desktop:
        if validator is None:
            raise ValueError("The desktop MSI requires its native folder validator.")
        msilib.add_data(db, "Binary", [("FolderCheck", msilib.Binary(str(validator.resolve())))])
        msilib.add_data(
            db, "CustomAction", [("CheckInstallFolder", 1, "FolderCheck", "CheckInstallFolder")]
        )
        msilib.add_data(
            db, "InstallExecuteSequence", [("CheckInstallFolder", "NOT Installed", 1450)]
        )
        # The UAC broker and its engine always live under protected Program Files.
        system = msilib.Directory(db, cab, pf, ".", "flurux_system", "FLURUX", 0)
        dirs[Path("Security")] = msilib.Directory(
            db, cab, system, ".", "security_dir", "Security", 0
        )
        msilib.add_data(db, "Property", [("SecureCustomProperties", "INSTALLDIR")])
        # MSI maintenance can also run from Windows Settings without our bootstrapper.
        msilib.add_data(
            db, "CompLocator", [("ExistingFlurux", "{33120448-451B-5A7A-8A5E-E610FEAC65FD}", 0)]
        )
        msilib.add_data(db, "AppSearch", [("INSTALLDIR", "ExistingFlurux")])
        msilib.add_data(
            db, "CustomAction", [("RecordFolder", 51, "ARPINSTALLLOCATION", "[INSTALLDIR]")]
        )
        msilib.add_data(
            db, "InstallExecuteSequence", [("RecordFolder", 'NOT (REMOVE~="ALL")', 1099)]
        )
        info = db.GetSummaryInformation(1)
        info.SetProperty(msilib.PID_PAGECOUNT, 500)
        info.Persist()
        db.OpenView("DROP TABLE `LockPermissions`").Execute(None)
        db.OpenView(
            "CREATE TABLE `MsiLockPermissionsEx` (`MsiLockPermissionsEx` CHAR(72) NOT NULL, `LockObject` CHAR(72) NOT NULL, `Table` CHAR(32) NOT NULL, `SDDLText` CHAR(0) NOT NULL, `Condition` CHAR(255) PRIMARY KEY `MsiLockPermissionsEx`)"
        ).Execute(None)
        app.start_component(
            "InstallFolderAcl", feature, 0, uuid="{116C7B76-4183-43DB-9EB4-0E89F9AF158D}"
        )
        msilib.add_data(db, "CreateFolder", [(app.logical, "InstallFolderAcl")])
        msilib.add_data(
            db,
            "MsiLockPermissionsEx",
            [
                (
                    "ProtectApplication",
                    app.logical,
                    "CreateFolder",
                    "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
                    "NOT Installed",
                )
            ],
        )
        db.OpenView(
            "CREATE TABLE `MsiShortcutProperty` (`MsiShortcutProperty` CHAR(72) NOT NULL, `Shortcut_` CHAR(72) NOT NULL, `PropertyKey` CHAR(255) NOT NULL, `PropVariantValue` CHAR(255) NOT NULL PRIMARY KEY `MsiShortcutProperty`)"
        ).Execute(None)
    package_files = {
        Path(name): ROOT / name
        for name in ("Start.cmd", "Start-Admin.cmd", "run.pyw", "README.md", "LICENSE")
    }
    for path in sorted((ROOT / "src").rglob("*.py")):
        package_files[path.relative_to(ROOT)] = path
    for asset in (ROOT / "src/route_manager/assets").glob("*.png"):
        package_files[asset.relative_to(ROOT)] = asset
    package_files[Path("Security/FluruxGuard.exe")] = guard
    for name in ("Prepare-Zapret.ps1", "zapret-files.json"):
        package_files[Path("Security") / name] = ROOT / "security" / name
    if desktop:
        package_files.update(desktop)
    with tempfile.TemporaryDirectory() as tmp:
        pins = Path(tmp) / "release_pins.py"
        source = ROOT / "src/route_manager/release_pins.py"
        checksum = hashlib.sha256(guard.read_bytes()).hexdigest()
        pins.write_text(
            re.sub(
                r'GUARD_HASH\s*=\s*["\'][a-f0-9]+["\']',
                f'GUARD_HASH = "{checksum}"',
                source.read_text(encoding="utf-8"),
            ),
            encoding="utf-8",
        )
        package_files[source.relative_to(ROOT)] = pins
        for relative, source_file in package_files.items():
            parent = Path()
            for part in relative.parent.parts:
                child = parent / part
                if child not in dirs:
                    name = "dir_" + str(len(dirs))
                    destination = (
                        part
                        if len(part) <= 8 and "." not in part
                        else dirs[parent].make_short(part) + "|" + part
                    )
                    dst = msilib.Directory(db, cab, dirs[parent], ".", name, destination, 0)
                    dirs[child] = dst
                parent = child
            folder = dirs[parent]
            component = "c_" + uuid.uuid5(PROJECT_ID, relative.as_posix()).hex
            folder.start_component(
                component,
                feature,
                0,
                relative.name,
                "{" + str(uuid.uuid5(PROJECT_ID, "file/" + relative.as_posix())) + "}",
            )
            file_id = folder.add_file(relative.name, str(source_file.resolve()))
            if relative == Path("FLURUX.exe"):
                for shortcut, directory in (
                    ("MenuFLURUX", "ProgramMenuFolder"),
                    ("DesktopFLURUX", "DesktopFolder"),
                ):
                    msilib.Directory(db, cab, root, ".", directory, ".", 0)
                    msilib.add_data(
                        db,
                        "Shortcut",
                        [
                            (
                                shortcut,
                                directory,
                                "FLURUX",
                                component,
                                "[#" + file_id + "]",
                                None,
                                "FLURUX",
                                None,
                                "FluruxIcon.exe",
                                0,
                                1,
                                app.logical,
                            )
                        ],
                    )
                    msilib.add_data(
                        db,
                        "MsiShortcutProperty",
                        [(shortcut + "Id", shortcut, "System.AppUserModel.ID", "FLURUX.Desktop")],
                    )
                msilib.add_data(db, "Property", [("ARPPRODUCTICON", "FluruxIcon.exe")])
                msilib.add_data(
                    db, "Icon", [("FluruxIcon.exe", msilib.Binary(str(source_file.resolve())))]
                )
        cab.commit(db)
        db.Commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("guard", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.guard, args.output)
