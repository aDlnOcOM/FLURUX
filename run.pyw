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
    if ctypes.windll.shell32.IsUserAnAdmin():
        import winreg
        from tkinter import messagebox
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion",0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
            installed=Path(winreg.QueryValueEx(key,"ProgramFilesDir")[0])
        if not sys.flags.isolated or root!=installed/"FLURUX" or not Path(sys.executable).resolve().is_relative_to(installed):
            messagebox.showerror("FLURUX","Для системного VPN запустите Start-Admin.cmd в установленном через MSI каталоге Program Files/FLURUX. Для остальных режимов откройте приложение с обычными правами.")
            return
    sys.path.insert(0, str(root / "src"))

    from route_manager.gui import launch

    launch(root / "data", Path(__file__).resolve(), admin=bool(ctypes.windll.shell32.IsUserAnAdmin()))


if __name__ == "__main__":
    main()
