"""Build the x64 offline installer with stock CPython 3.12, MSVC and Windows SDK."""

import argparse
import hashlib
import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.4"
RUNTIME_SHA256 = "93584a7bee14bf6b91a03efdbb128419147279a64934fbc95934c9f53e1191e5"
SOURCE = ROOT / "packaging"


def icon(target: Path) -> None:
    """Write the same multi-size FLURUX mark for Explorer, Setup and Tk."""

    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
        )

    imgs = []
    for size in (16, 32, 48, 64, 128, 256):
        pixels = bytearray()
        for y in range(size):
            pixels.append(0)
            for x in range(size):
                a, b = (x + 0.5) / size, (y + 0.5) / size
                dx = max(0.19 - a, 0, a - 0.81)
                dy = max(0.19 - b, 0, b - 0.81)
                mark = (
                    (0.25 <= a <= 0.39 and 0.23 <= b <= 0.77)
                    or (0.25 <= a <= 0.77 and 0.23 <= b <= 0.36)
                    or (0.25 <= a <= 0.65 and 0.47 <= b <= 0.59)
                )
                pixels.extend(
                    (
                        *((238, 208, 139) if mark else (22, 23, 24)),
                        255 if dx * dx + dy * dy <= 0.185**2 else 0,
                    )
                )
        imgs.append(
            chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels, 9))
            + chunk(b"IEND", b"")
        )
    blobs = [b"\x89PNG\r\n\x1a\n" + png for png in imgs]
    header = bytearray(struct.pack("<HHH", 0, 1, len(blobs)))
    offset = 6 + 16 * len(blobs)
    for size, blob in zip((16, 32, 48, 64, 128, 256), blobs, strict=True):
        header.extend(
            struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
        )
        offset += len(blob)
    target.write_bytes(header + b"".join(blobs))


def runtime_files(temp: Path, archive: Path) -> dict[Path, Path]:
    """Gather the redistributable runtime without site packages, build tools or user code."""
    if sys.version_info[:2] != (3, 12) or struct.calcsize("P") != 8:
        raise RuntimeError("Build using Windows CPython 3.12 x64.")
    with archive.open("rb") as src:
        if hashlib.file_digest(src, "sha256").hexdigest() != RUNTIME_SHA256:
            raise ValueError("Use the pinned CPython 3.12.16 x64 runtime from the README.")
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            rel = Path(member.name)
            if (
                member.isreg()
                and rel.parts[0] == "python"
                and not (
                    {"site-packages", "__pycache__", "test", "tests", "demos"} & set(rel.parts)
                )
                and rel.suffix.lower() not in (".pdb", ".pyc")
            ):
                bundle.extract(member, temp, filter="data")
    base = temp / "python"
    files = {}
    for name in (
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        "python312.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "LICENSE.txt",
    ):
        files[Path("runtime") / name] = base / name
    for path in (base / "DLLs").iterdir():
        if path.suffix.lower() in (".dll", ".pyd") and not path.name.startswith(
            ("_test", "_ctypes_test")
        ):
            files[Path("runtime/DLLs") / path.name] = path
    library = temp / "python312.zip"
    skip = {
        "__pycache__",
        "test",
        "tests",
        "site-packages",
        "idlelib",
        "turtledemo",
        "ensurepip",
        "venv",
        "lib2to3",
        "msilib",
        "__phello__",
    }
    with zipfile.ZipFile(library, "w", zipfile.ZIP_DEFLATED) as bundle:
        for folder, dirs, names in os.walk(base / "Lib"):
            dirs[:] = sorted(d for d in dirs if d not in skip)
            for name in sorted(names):
                path = Path(folder) / name
                if path.suffix == ".py" and name not in ("sitecustomize.py", "usercustomize.py"):
                    bundle.write(path, path.relative_to(base / "Lib").as_posix())
    files[Path("runtime/python312.zip")] = library
    paths = temp / "python312._pth"
    paths.write_text("python312.zip\nDLLs\n.\n", encoding="ascii")
    files[Path("runtime/python312._pth")] = paths
    for tree in ("tcl8.6", "tk8.6", "tcl8"):
        for path in sorted((base / "tcl" / tree).rglob("*")):
            rel = path.relative_to(base)
            if path.is_file() and not {"demos", "tests"} & set(rel.parts):
                files[Path("runtime") / rel] = path
    # Isolated CPython looks for DLLs of the interpreter next to pythonw.exe.
    return files


def compile_gui(
    source: Path,
    target: Path,
    ico: Path,
    package: Path | None = None,
    *,
    max_folder: int | None = None,
) -> None:
    """Compile a statically linked native Windows GUI binary with release resources."""

    def rc_path(p: Path) -> str:
        return p.as_posix().replace('"', '""')

    rc = target.with_suffix(".rc")
    rc.write_text(
        '#include <windows.h>\n1 ICON "'
        + rc_path(ico)
        + '"\n'
        + ('201 RCDATA "' + rc_path(package) + '"\n' if package else "")
        + ('#include "' + rc_path(SOURCE / "setup_dialog.rc") + '"\n' if package else "")
        + '1 VERSIONINFO\n FILEVERSION 0,3,4,0\n PRODUCTVERSION 0,3,4,0\n FILEOS VOS_NT_WINDOWS32\n FILETYPE VFT_APP\n BEGIN\n BLOCK "StringFileInfo" BEGIN BLOCK "040904B0" BEGIN\n'
        + f'VALUE "FileDescription", "FLURUX {"Setup" if package else "Desktop"}\\0"\nVALUE "ProductName", "FLURUX\\0"\nVALUE "FileVersion", "{VERSION}\\0"\nVALUE "ProductVersion", "{VERSION}\\0"\n'
        + 'END END\nBLOCK "VarFileInfo" BEGIN VALUE "Translation", 0x0409, 1200 END\nEND\n',
        encoding="utf-8",
    )
    res = rc.with_suffix(".res")
    subprocess.run(["rc.exe", "/nologo", "/c65001", "/fo", res, rc], check=True)
    subprocess.run(
        [
            "cl.exe",
            "/nologo",
            "/utf-8",
            "/std:c++17",
            "/O2",
            "/W4",
            "/MT",
            "/EHsc",
            "/guard:cf",
            "/DUNICODE",
            "/D_UNICODE",
            *([f"/DFLURUX_MAX_FOLDER={max_folder}"] if max_folder is not None else []),
            str(source),
            str(res),
            "/Fo" + str(target.with_suffix(".obj")),
            "/Fe" + str(target),
            "/link",
            "/SUBSYSTEM:WINDOWS",
            "/DYNAMICBASE",
            "/HIGHENTROPYVA",
            "/NXCOMPAT",
            "/DEPENDENTLOADFLAG:0x800",
            "/Brepro",
            "user32.lib",
            "shell32.lib",
            "msi.lib",
            "ole32.lib",
            "oleaut32.lib",
            "advapi32.lib",
            "uuid.lib",
        ],
        check=True,
    )


def build_setup(guard: Path, runtime: Path, output: Path) -> None:
    """Build launcher, runtime MSI and single-file Setup without adding Python packages."""
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        temp = Path(tmp)
        ico = temp / "FLURUX.ico"
        icon(ico)
        app = temp / "FLURUX.exe"
        compile_gui(SOURCE / "launcher.cpp", app, ico)
        files = runtime_files(temp, runtime)
        files.update({Path("FLURUX.exe"): app, Path("FLURUX.ico"): ico})
        spec = importlib.util.spec_from_file_location("build_msi", ROOT / "security/build_msi.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("Missing MSI builder")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        msi = temp / "FLURUX-Desktop-x64.msi"
        paths = [*files, *(p.relative_to(ROOT) for p in (ROOT / "src").rglob("*.py"))]
        paths.extend(p.relative_to(ROOT) for p in (ROOT / "src/route_manager/assets").glob("*.png"))
        # Win32 MAX_PATH includes the separator, longest relative filename, and terminator.
        max_folder = 258 - max(len(str(p).encode("utf-16le")) // 2 for p in paths)
        validator = temp / "folder_check.dll"
        subprocess.run(
            [
                "cl.exe",
                "/nologo",
                "/utf-8",
                "/std:c++17",
                "/O2",
                "/W4",
                "/MT",
                "/EHsc",
                "/LD",
                "/guard:cf",
                "/DUNICODE",
                "/D_UNICODE",
                f"/DFLURUX_MAX_FOLDER={max_folder}",
                str(SOURCE / "folder_check.cpp"),
                "/Fo" + str(temp / "folder_check.obj"),
                "/Fe" + str(validator),
                "/link",
                "/Brepro",
                "/DEPENDENTLOADFLAG:0x800",
                "/DYNAMICBASE",
                "/HIGHENTROPYVA",
                "/NXCOMPAT",
                "msi.lib",
                "shell32.lib",
                "ole32.lib",
                "uuid.lib",
            ],
            cwd=temp,
            check=True,
        )
        module.build(guard.resolve(), msi, desktop=files, validator=validator)
        installer = temp / "FLURUX-Setup.exe"
        compile_gui(SOURCE / "setup.cpp", installer, ico, msi, max_folder=max_folder)
        # Copy out of the private build directory so a shared release inherits its destination ACL.
        staged = output.with_name("." + uuid.uuid4().hex + ".tmp")
        try:
            shutil.copyfile(installer, staged)
            staged.replace(output)
        finally:
            staged.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("guard", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("output", type=Path)
    opts = parser.parse_args()
    build_setup(opts.guard, opts.runtime, opts.output)
