@echo off
setlocal enabledelayedexpansion
title CyberDefenseAI - Autonomous Cyber Defense SOC System
color 0B

echo ======================================================================
echo          CYBERDEFENSE AI - AUTONOMOUS SOC DEFENSE SYSTEM
echo ======================================================================
echo.

cd /d "%~dp0"
set "ROOT_DIR=%~dp0"

:: Check virtual environment
if not exist "%ROOT_DIR%.venv\Scripts\python.exe" (
    where python >nul 2>nul
    if errorlevel 1 (
        where py >nul 2>nul
        if errorlevel 1 (
            echo [!] ERROR: Python 3.10+ was not found in your system PATH.
            echo Please install Python 3.10+ from https://www.python.org/ and check "Add Python to PATH".
            pause
            goto end
        ) else (
            set "PY_EXEC=py -3"
        )
    ) else (
        set "PY_EXEC=python"
    )
    echo [*] Initializing virtual environment in %ROOT_DIR%.venv using !PY_EXEC!...
    !PY_EXEC! -m venv "%ROOT_DIR%.venv"
    echo [*] Installing production dependencies...
    "%ROOT_DIR%.venv\Scripts\python.exe" -m pip install -r requirements.txt
)

echo [OK] Environment verified.
echo.
echo Select Mode:
echo   [1] Start Live Backend and Real-Time SOC Dashboard
echo   [2] Run Synthetic Attack Simulation Harness (5 Scenarios)
echo   [3] Run Complete PyTest Verification Suite
echo   [4] Launch Dashboard and Automatically Run Simulation (Default)
echo.
set "MODE="
set /p MODE="Enter selection [1-4] (default: 4): "
if "%MODE%"=="" set MODE=4

if "%MODE%"=="1" (
    echo.
    netstat -ano | findstr /C:":8000 " | findstr "LISTENING" > nul
    if errorlevel 1 (
        echo [*] Starting FastAPI Backend on http://127.0.0.1:8000 ...
        start http://127.0.0.1:8000
        .\.venv\Scripts\python.exe -m uvicorn cyberdefense.api:app --host 127.0.0.1 --port 8000 --reload
    ) else (
        echo [*] FastAPI Backend is already running on http://127.0.0.1:8000
        start http://127.0.0.1:8000
        echo Press any key to exit...
        pause > nul
    )
    goto end
)

if "%MODE%"=="2" (
    echo.
    echo [*] Running Synthetic Attack Simulation Harness...
    .\.venv\Scripts\python.exe simulate_attacks.py
    pause
    goto end
)

if "%MODE%"=="3" (
    echo.
    echo [*] Running PyTest Verification Suite...
    .\.venv\Scripts\python.exe -m pytest -v --tb=short tests/
    pause
    goto end
)

if "%MODE%"=="4" (
    echo.
    echo [*] Checking Backend Status...
    netstat -ano | findstr /C:":8000 " | findstr "LISTENING" > nul
    if errorlevel 1 (
        echo [*] Starting FastAPI Backend in background...
        start "CyberDefenseAI Backend" /min .\.venv\Scripts\python.exe -m uvicorn cyberdefense.api:app --host 127.0.0.1 --port 8000
        echo [*] Waiting 3 seconds for server initialization...
        ping 127.0.0.1 -n 4 > nul
    ) else (
        echo [*] Backend is already online on http://127.0.0.1:8000
    )
    start http://127.0.0.1:8000
    echo [*] Launching Synthetic Attack Generator...
    .\.venv\Scripts\python.exe simulate_attacks.py
    echo.
    echo [OK] Live system is running on http://127.0.0.1:8000
    echo Press any key to exit...
    pause
    goto end
)

:end
