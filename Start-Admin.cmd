@echo off
setlocal
rem Run this installed file with "Run as administrator" for TUN or AmneziaWG.
rem Only system-wide Python installations are considered.
for %%V in (314 313 312) do (
    if exist "%ProgramW6432%\Python%%V\pythonw.exe" (
        start "" "%ProgramW6432%\Python%%V\pythonw.exe" -I -B "%~dp0run.pyw"
        exit /b 0
    )
)
echo Install a system-wide Python 3.12, 3.13 or 3.14 with Tk in Program Files.
pause
exit /b 1
