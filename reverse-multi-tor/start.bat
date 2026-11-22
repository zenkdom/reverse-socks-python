@echo off
setlocal enabledelayedexpansion

echo ==========================================================
echo          Multi-Tor Reverse Cluster (Windows)
echo ==========================================================

REM 1. Generate torrc for Windows (10 ports)
python generate_torrc.py --count 10 --start-port 9050 --output torrc
echo [*] Configuration file torrc generated (ports 9050..9059).

REM 2. Look for tor.exe in local folder or PATH
set TOR_EXE=
if exist "%~dp0tor.exe" set TOR_EXE=%~dp0tor.exe
if exist "%~dp0bin\tor.exe" set TOR_EXE=%~dp0bin\tor.exe
if "%TOR_EXE%"=="" (
    where tor.exe >nul 2>nul
    if !errorlevel! equ 0 set TOR_EXE=tor.exe
)

if "%TOR_EXE%"=="" (
    echo.
    echo [!] WARNING: tor.exe was not found on your Windows system!
    echo.
    echo Agents will connect to the Control Server on port 9000,
    echo but require local Tor ports (9050..9059) to route internet traffic.
    echo.
    echo Recommended setup:
    echo 1. Run the cluster on your Linux server:
    echo    cd reverse-multi-tor ^&^& sudo ./start_cluster.sh
    echo.
    echo 2. For Windows testing:
    echo    Download Tor Expert Bundle for Windows and place tor.exe in:
    echo    %~dp0
    echo.
    set /p RUN_ANYWAY="Do you want to start the agents without Tor? (y/n): "
    if /i not "!RUN_ANYWAY!"=="y" exit /b 1
) else (
    echo [*] Found Tor: !TOR_EXE!
    echo [*] Starting Tor daemon with ports 9050..9059...
    start "Tor Daemon Cluster" /min "!TOR_EXE!" -f "%~dp0torrc"
    echo [*] Waiting for Tor ports to initialize (3 sec)...
    timeout /t 3 /nobreak > nul
)

echo.
echo [*] Starting 10 Reverse Agents...
python cluster.py --config config.json
pause
