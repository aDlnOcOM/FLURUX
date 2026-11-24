import sys
from pathlib import Path


def main() -> None:
    """Launch the Windows GUI."""
    if sys.version_info < (3, 12):
        from tkinter import messagebox

        messagebox.showerror("FLURUX", "Для запуска нужен Python 3.12 или новее.")
        return

    root = Path(__file__).resolve().parent
    import ctypes

    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if admin:
        import winreg
        from tkinter import messagebox

        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion", 0, access
        ) as key:
            program = Path(winreg.QueryValueEx(key, "ProgramFilesDir")[0])
        installed = program / "FLURUX"
        location = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(len(location))
        rc = ctypes.windll.msi.MsiGetProductInfoExW(
            "{670D8AC3-5471-5723-97EF-D5CF18A9614E}",
            None,
            4,
            "InstallLocation",
            location,
            ctypes.byref(size),
        )
        if rc == 0 and location.value and Path(location.value).is_absolute():
            installed = Path(location.value)
        interpreter = Path(sys.executable).resolve()
        if (
            not sys.flags.isolated
            or root != installed
            or not (
                interpreter.is_relative_to(program)
                or interpreter == installed / "runtime" / "pythonw.exe"
            )
        ):
            messagebox.showerror(
                "FLURUX",
                "Для системного VPN запустите установленный FLURUX от имени администратора.",
            )
            return
    sys.path.insert(0, str(root / "src"))

    from route_manager.gui import launch

    tab = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == "--tab" else ""
    launch(root / "data", Path(__file__).resolve(), admin=admin, tab=tab)


if __name__ == "__main__":
    main()
