@echo off
setlocal EnableExtensions
title GDG CTF Lite

rem Always run from the folder that contains this file, even with spaces in the path.
cd /d "%~dp0"

echo.
echo   GDG CTF Lite - organizer launcher
echo   ---------------------------------
echo.

rem ---------------------------------------------------------------
rem Find a suitable Python. Prefer the Windows launcher (py -3).
rem ---------------------------------------------------------------
set "PYTHON="

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
    if not errorlevel 1 set "PYTHON=py -3"
)

if not defined PYTHON (
    where python >nul 2>nul
    if not errorlevel 1 (
        python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
        if not errorlevel 1 set "PYTHON=python"
    )
)

if not defined PYTHON (
    echo   Python 3.10 or newer was not found.
    echo.
    echo   Install it from:
    echo     https://www.python.org/downloads/
    echo.
    echo   During installation, tick "Add python.exe to PATH".
    echo   Then double-click this file again.
    echo.
    pause
    exit /b 1
)

rem ---------------------------------------------------------------
rem First run: create .venv and install dependencies.
rem Later runs: reuse .venv; repair only if the imports are broken.
rem ---------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo   [1/3] Creating the Python virtual environment...
    %PYTHON% -m venv .venv
    if errorlevel 1 goto :setup_failed

    echo   [2/3] Updating pip...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>nul

    echo   [3/3] Installing Flask and Waitress...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto :setup_failed
) else (
    ".venv\Scripts\python.exe" -c "import flask, waitress" >nul 2>nul
    if errorlevel 1 (
        echo   [1/2] Repairing dependencies...
        ".venv\Scripts\python.exe" -m pip install -r requirements.txt
        if errorlevel 1 goto :setup_failed
    )
)

rem ---------------------------------------------------------------
rem Optional: "START_GDG_CTF.bat reset" clears the test database.
rem The organizer password and flag secrets in instance\secrets.json
rem are deliberately kept.
rem ---------------------------------------------------------------
if /I "%~1"=="reset" (
    echo.
    echo   This deletes instance\ctf.db:
    echo   teams, solves, hints, submissions, and audit rows.
    echo   The organizer password and flag secrets are kept.
    echo.
    choice /c YN /n /m "  Reset the test event now? [Y/N] "
    if errorlevel 2 goto :run
    if exist "instance\ctf.db" del /q "instance\ctf.db"
    if exist "instance\ctf.db-wal" del /q "instance\ctf.db-wal"
    if exist "instance\ctf.db-shm" del /q "instance\ctf.db-shm"
    echo   Test database removed.
    echo.
)

:run
echo.
echo   Starting the scoreboard and both challenges...
echo   Keep this window open. Press Ctrl+C to stop the event.
echo.
echo   The LAN URL and organizer password location are printed below.
echo.

".venv\Scripts\python.exe" -u run_all.py
set "EXITCODE=%ERRORLEVEL%"

echo.
if not "%EXITCODE%"=="0" (
    echo   The event stopped with exit code %EXITCODE%.
    echo   Check the messages above, then see docs\HOSTING.md.
) else (
    echo   Event stopped.
)
echo.
pause
exit /b %EXITCODE%

:setup_failed
echo.
echo   Setup failed. Check your internet connection and try again.
echo.
echo   Manual steps are in README.md under "Quick start".
echo   Common fixes are in docs\HOSTING.md under "Troubleshooting".
echo.
pause
exit /b 1
