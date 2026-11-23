@echo off
setlocal
cd /d "%~dp0"
where py.exe >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import sys; raise SystemExit(sys.version_info < (3, 12))" >nul 2>&1
    if not errorlevel 1 (
        start "" pyw -3 "%~dp0run.pyw"
        exit /b 0
    )
)
where python.exe >nul 2>&1
if not errorlevel 1 (
    python -c "import sys; raise SystemExit(sys.version_info < (3, 12))" >nul 2>&1
    if not errorlevel 1 (
        start "" pythonw "%~dp0run.pyw"
        exit /b 0
    )
)
where uv.exe >nul 2>&1
if not errorlevel 1 (
    uv run python "%~dp0run.pyw"
    if not errorlevel 1 exit /b 0
)
echo Python 3.12+ is required. Install it from https://www.python.org/downloads/windows/
pause
exit /b 1
