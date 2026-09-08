"""
CyberDefenseAI Configuration Settings
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
STATIC_DIR = BASE_DIR / "cyberdefense" / "static"
TEMPLATES_DIR = BASE_DIR / "cyberdefense" / "templates"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

HOST = os.getenv("CYBER_HOST", "127.0.0.1")
PORT = int(os.getenv("CYBER_PORT", "8000"))

# Optional Live Threat Intel API Keys (Falls back silently to Local Threat DB)
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

# Internal IP Networks for False-Positive Whitelisting / Context
INTERNAL_VULN_SCANNERS = {"10.0.0.254", "192.168.1.254"}
INTERNAL_LOAD_BALANCERS = {"10.0.0.1", "192.168.1.1"}
