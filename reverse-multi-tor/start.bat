@echo off
chcp 65001 > nul
setlocal enabledelayedexpansion

echo ==========================================================
echo          Multi-Tor Reverse Cluster (Windows)
echo ==========================================================

REM 1. Generate torrc for Windows (10 ports)
python generate_torrc.py --count 10 --start-port 9050 --output torrc
echo [*] Конфигурационный файл torrc сгенерирован (порты 9050..9059).

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
    echo [!] ВНИМАНИЕ: tor.exe не найден на вашем Windows-компьютере!
    echo.
    echo Агенты cluster.py подключаются к серверу Control (порт 9000),
    echo но для выхода в интернет каждому агенту нужен локальный порт Tor ^(9050..9099^).
    echo Без запущенного Tor вы будете получать ошибку: "Tor connection refused by local port".
    echo.
    echo Как это запустить:
    echo 1. ОСНОВНОЙ ВАРИАНТ (РЕКОМЕНДУЕТСЯ):
    echo    Запустите кластер на вашем Linux/Ubuntu сервере:
    echo    cd reverse-multi-tor ^&^& sudo ./start_cluster.sh
    echo    (На Ubuntu Tor устанавливается штатно одной командой apt install tor)
    echo.
    echo 2. ДЛЯ ТЕСТА НА WINDOWS:
    echo    Скачайте Tor Expert Bundle для Windows и положите tor.exe в эту папку:
    echo    %~dp0
    echo.
    set /p RUN_ANYWAY="Хотите всё равно запустить Python-агентов без Tor? (y/n): "
    if /i not "!RUN_ANYWAY!"=="y" exit /b 1
) else (
    echo [*] Найден Tor: !TOR_EXE!
    echo [*] Запуск Tor daemon с портами 9050..9059...
    start "Tor Daemon Cluster" /min "!TOR_EXE!" -f "%~dp0torrc"
    echo [*] Ожидание инициализации Tor портов (3 сек)...
    timeout /t 3 /nobreak > nul
)

echo.
echo [*] Запуск 10 Reverse-агентов...
python cluster.py --config config.json
pause
