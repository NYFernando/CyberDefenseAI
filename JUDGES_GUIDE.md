# CyberDefenseAI — Competition Judges & Evaluation Guide

> **Project**: Autonomous AI-Powered Cyber Defense System  

Welcome, Judges! This guide provides everything you need to evaluate, inspect, and verify the **CyberDefenseAI** autonomous cyber defense system in under 2 minutes.

---

> [!NOTE]
> **Prerequisites**: Python 3.10+ in system PATH, port 8000 free (or set `CYBER_PORT=xxxx`), and internet connection on initial launch to download pip dependencies into the virtual environment. Windows users should run `run.bat`; macOS/Linux users should run `run.sh` (or `bash run.sh` if extracted from a ZIP).

---

## ⚡ 2-Minute Quick Verification (Choose Your Preferred Method)

### Option 1: The Visual In-Browser Evaluation (Recommended)
1. **Launch the System**:
   - **Windows**: Double-click `run.bat` and press **Enter** (Default: Option 4).
   - **macOS / Linux**: Run `chmod +x run.sh && ./run.sh` and press **Enter** (Default: Option 4).
2. The interactive SOC Command Center automatically launches in your browser at **`http://127.0.0.1:8000`**.
3. **Run the Demonstration**:
   - In the top navigation bar, click **`Simulate 5 Attacks`**.
   - **Observe Real-Time Autonomous Defense**:
     - Signals stream in over WebSockets without manual page refresh.
     - Incidents appear in the queue classified by severity (**P1 Critical** / **P2 High**) with MITRE ATT&CK techniques (`T1110`, `T1566`, `T1486`, `T1048`, `T1203`).
     - Real-time containment counters update: **Quarantined Hosts**, **Blocked IPs**, and **SOAR Executed**.
   - **Inspect Deep Forensic Evidence**:
     - Click **`Inspect`** on any incident card to view AI triage reasoning, threat intel scores, and executed containment commands.
     - Click **`Report`** to open the full executive forensic investigation report (with one-click Print / PDF export).
   - **Verify Containment & 100% Reversibility**:
     - Click the **`Containment`** tab to view active firewall blocks and quarantined endpoints.
     - Click **`Revert`** on any rule to test the rollback mechanism—the rule safely undoes and status updates immediately.
   - **Reset Anytime**:
     - Click **`Reset`** in the top bar to wipe the pipeline state back to a clean slate and re-run scenarios as many times as you like.

---

### Option 2: Command-Line Attack Simulation Harness
In any terminal with the environment activated:
```powershell
python simulate_attacks.py
```
**What It Verifies**:
- Executes 5 real-world attack scenarios (SSH Brute Force, Emotet Phishing, WannaCry Ransomware, DNS Tunneling, RCE exploit).
- Normalizes logs across 4 different formats (Auth Log, JSON, Suricata EVE, Snort fast).
- Enriches indicators against the local offline threat database in < 25ms.
- Dispatches SOAR containment playbooks.
- Compiles executive forensic reports directly to `reports/`.
- Prints a clear green execution summary confirming all 5/5 scenarios were triaged and contained.

---

### Option 3: Automated PyTest Regression Suite
Run the comprehensive test suite:
```powershell
pytest -v --tb=short tests/
```
**What It Verifies**:
- **32 unit and integration tests** passing with 0 errors and 0 warnings:
  - Event ingestion and normalization (`tests/test_ingestion.py`)
  - Threat intelligence enrichment and whitelist filters (`tests/test_threat_intel.py`)
  - AI triage classification and false-positive suppression (`tests/test_ai_triage.py`)
  - SOAR action execution and state reversibility (`tests/test_soar_engine.py`)
  - Forensic report generation (`tests/test_forensic_reporter.py`)
  - REST API lifecycle and WebSocket streaming (`tests/test_api_and_pipeline.py`)

---

### Option 4: Unified One-Command Verification Audit
Run the automated end-to-end audit script:
```powershell
python test_all_live.py
```
This tests all 12 live REST endpoints, forensic report endpoints, manual overrides, containment rollbacks, and WebSocket handshakes against the active engine.

---

## 🏗️ Architectural Grading Checklist

| Evaluation Criterion | Implementation Details | Verified |
|---|---|---|
| **Multi-Format Ingestion** | Ingests JSON, RFC 3164/5424 Syslog, Suricata EVE, Snort Fast, and Linux/Windows Auth logs into a unified Pydantic schema with asynchronous queue processing. | `32/32 Tests PASS` |
| **100% Offline-First Threat Intel** | Built-in high-fidelity local database (`threat_db_data.py`) with IP reputation, malicious SHA-256 hashes, domains, and whitelists. Operates completely air-gapped without paid API keys. Pluggable fallback for VirusTotal & AbuseIPDB. | `Verified Offline` |
| **Explainable AI Triage & MITRE ATT&CK** | Maps attacks to MITRE tactics & techniques (`T1110`, `T1566`, `T1486`, `T1048`, `T1046`, `T1203`). Dynamic P1–P4 severity classifier. Autonomous false-positive elimination for authorized vulnerability scanners (e.g. Nessus). | `Verified (< 25ms)` |
| **Stateful Reversible SOAR Engine** | Autonomous containment playbooks (Quarantine Host, Block IP, Kill Process, Revoke Token). Every action is tracked statefully and can be reversed on-demand with one click. | `100% Reversible` |
| **Autonomous Forensic Reports** | Automated timeline reconstruction, IOC extraction, and remediation roadmaps rendered in both Markdown (`.md`) and high-fidelity, printable HTML (`.html`) with `@media print` PDF support. | `Generated in reports/` |
| **Zero-Dependency Web UI** | Bespoke dark-mode interface inspired by Linear and Stripe Radar. Single-row bento metrics, tabular figures, and **zero external CDN dependencies** (Tailwind CSS bundled locally in `tailwind.min.js`). | `100% Self-Contained` |
| **Cross-Platform Portability** | Native 1-click startup scripts for Windows (`run.bat` with `%~dp0` dynamic binding) and macOS/Linux (`run.sh`). | `Windows / Mac / Linux` |

---

## 📁 Repository Structure

```
CyberDefenseAI/
├── cyberdefense/                  # Core SOC Engine Package
│   ├── ingestion.py               # Async multi-format log normalizer
│   ├── threat_intel.py            # Offline-first threat intelligence database
│   ├── threat_db_data.py          # Curated IOCs (IPs, hashes, domains, whitelists)
│   ├── ai_triage.py               # MITRE ATT&CK mapper & explainable triage engine
│   ├── soar_engine.py             # Reversible SOAR containment engine
│   ├── forensic_reporter.py       # Autonomous HTML & Markdown report compiler
│   ├── pipeline.py                # End-to-end unified orchestration pipeline
│   ├── api.py                     # FastAPI REST & WebSocket server
│   ├── models.py                  # Pydantic data schemas
│   ├── config.py                  # System configuration & directory paths
│   └── static\                    # Self-contained web dashboard assets
│       ├── index.html             # Clean tactical dark command center
│       ├── styles.css             # Restrained CSS design tokens
│       ├── dashboard.js           # Reactive WebSocket controller & simulator
│       └── tailwind.min.js        # Local Tailwind bundle (Zero CDN dependencies)
├── tests\                         # PyTest Exhaustive Test Suite (32 tests)
├── reports\                       # Generated executive investigation reports
├── simulate_attacks.py            # 5-scenario synthetic attack demonstration harness
├── test_all_live.py               # Live end-to-end API & WebSocket verification
├── run.bat                        # Windows 1-click launch script
├── run.sh                         # macOS/Linux 1-click launch script
├── requirements.txt               # Production Python dependencies
├── pytest.ini                     # Test configuration
├── .gitignore                     # Production packaging rules
├── README.md                      # Comprehensive system documentation
└── JUDGES_GUIDE.md                # This judge evaluation guide
```

---

## 🎯 Summary
Every tier of **CyberDefenseAI** has been designed to operate reliably, quickly, and completely offline. Enjoy testing the system!
