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


def build(guard: Path, output: Path) -> None:
    """Build a per-machine MSI with isolated code and no third-party engines."""
    if not msilib.AMD64:
        raise ValueError("Use 64-bit Python 3.12.")
    version = "0.3.0"
    output = output.resolve()
    db = msilib.init_database(
        str(output),
        schema,
        "FLURUX Security x64",
        "{" + str(uuid.uuid5(PROJECT_ID, version)).upper() + "}",
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
    app = msilib.Directory(db, cab, pf, ".", "appdir", "FLURUX", 0)
    dirs = {Path(): app}
    package_files = {
        Path(name): ROOT / name
        for name in ("Start.cmd", "Start-Admin.cmd", "run.pyw", "README.md", "LICENSE")
    }
    for path in sorted((ROOT / "src").rglob("*.py")):
        package_files[path.relative_to(ROOT)] = path
    package_files[Path("Security/FluruxGuard.exe")] = guard
    for name in ("Prepare-Zapret.ps1", "zapret-files.json"):
        package_files[Path("Security") / name] = ROOT / "security" / name
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
                    dst = msilib.Directory(db, cab, dirs[parent], ".", name, part, 0)
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
            folder.add_file(relative.name, str(source_file.resolve()))
        cab.commit(db)
        db.Commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("guard", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.guard, args.output)
