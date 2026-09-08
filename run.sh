#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "======================================================================"
echo "         CYBERDEFENSE AI - AUTONOMOUS SOC DEFENSE SYSTEM"
echo "======================================================================"
echo ""

if [ ! -f ".venv/bin/python" ]; then
    echo "[*] Initializing virtual environment in .venv..."
    python3 -m venv .venv
    echo "[*] Installing dependencies..."
    .venv/bin/pip install -r requirements.txt
fi

echo "[OK] Environment verified."
echo ""
echo "Select Mode:"
echo "  [1] Start Live Backend & Real-Time SOC Dashboard"
echo "  [2] Run Synthetic Attack Simulation Harness (5 Scenarios)"
echo "  [3] Run Complete PyTest Verification Suite"
echo "  [4] Launch Dashboard and Automatically Run Simulation (Default)"
echo ""
read -p "Enter selection [1-4] (default: 4): " MODE
MODE=${MODE:-4}

if [ "$MODE" = "1" ]; then
    echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
    python3 -m webbrowser "http://127.0.0.1:8000" 2>/dev/null || true
    .venv/bin/python -m uvicorn cyberdefense.api:app --host 127.0.0.1 --port 8000 --reload
fi

if [ "$MODE" = "2" ]; then
    echo "[*] Running Synthetic Attack Simulation Harness..."
    .venv/bin/python simulate_attacks.py
fi

if [ "$MODE" = "3" ]; then
    echo "[*] Running PyTest Verification Suite..."
    .venv/bin/python -m pytest -v --tb=short tests/
fi

if [ "$MODE" = "4" ]; then
    echo "[*] Starting FastAPI Backend in background..."
    .venv/bin/python -m uvicorn cyberdefense.api:app --host 127.0.0.1 --port 8000 &
    PID=$!
    sleep 2
    python3 -m webbrowser "http://127.0.0.1:8000" 2>/dev/null || true
    echo "[*] Launching Synthetic Attack Generator..."
    .venv/bin/python simulate_attacks.py
    echo ""
    echo "[OK] Live system is running on http://127.0.0.1:8000 (PID: $PID)"
    wait $PID
fi
