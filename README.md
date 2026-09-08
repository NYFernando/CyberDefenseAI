# CyberDefenseAI — Autonomous AI-Powered Cyber Defense System

> **Project**: Autonomous AI-Powered Cyber Defense System  
> **Target Environment**: Windows / Linux / macOS | **Python**: 3.10+  
> **Repository**: `https://github.com/NYFernando/CyberDefenseAI`  

---

## Executive Overview

**CyberDefenseAI** is an autonomous, competition-grade Security Operations Center (SOC) platform engineered to ingest, enrich, triage, contain, and report cyber incidents in real time.

Built with an **offline-first** threat intelligence database, the system operates completely air-gapped without requiring external paid API keys, while retaining pluggable connectors for live threat intelligence (VirusTotal, AbuseIPDB) with silent fallback.

```
                                  [Alert Sources]
                 (JSON / Syslog / Suricata & Snort / Auth Logs)
                                        │
                                        ▼
                       [Async Event Ingestion Engine]
                                        │
                         Unified Schema Normalization
                                        │
                                        ▼
                  [Threat Intelligence Enrichment Engine]
                ├── Local Threat DB (Offline-First: IPs, Hashes, Domains)
                └── Pluggable External Connectors (VirusTotal / AbuseIPDB)
                                        │
                                        ▼
                   [AI Triage & Classification Engine]
                ├── MITRE ATT&CK Tactic & Technique Mapper
                ├── Dynamic Severity Classifier (P1-P4)
                └── False-Positive Elimination Engine + Explainable Rationale
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
       [Automated SOAR Engine]                [Autonomous Forensic Reporter]
    ├── P1/P2: Host Quarantine,              ├── Timeline Reconstruction
    │   Firewall Block, Token Revoke,        ├── IOC Attribution
    │   Process Kill                         └── Executive Printable HTML &
    └── P3/P4: Telemetry Log, Ticket             Markdown Reports
    └── Stateful Reversible Registry                        │
                    │                                       ▼
                    └───────────────────┬───────────────────┘
                                        ▼
                      [FastAPI REST & WebSocket Server]
                                        │
                                        ▼
                    [Real-Time SOC Command Web Dashboard]
               (Dark Mode, Live Feed, MITRE Matrix, SOAR Controls)
```

---

## Core Capabilities

### 1. Multi-Format Event Normalization
- **JSON / REST Alerts**: Extracts nested identifiers, attacker/victim IPs, ports, and SHA-256 hashes.
- **Syslog (RFC 3164 & RFC 5424)**: Parses headers, hostnames, PIDs, and message payloads with regex IP/port extraction.
- **Suricata & Snort Alerts**: Ingests Suricata EVE JSON (`event_type: alert`) and Snort fast-alert strings (`[**] [1:1000001:1] ...`).
- **Authentication Logs**: Normalizes Linux `sshd` password failures and Windows Security Event logs (Event IDs 4625 / 4672).

### 2. Offline-First Threat Intelligence
- **Local Threat Database (`threat_db_data.py`)**:
  - **Malicious IPs**: Known C2 gateways, Tor exit nodes, and automated botnets (e.g. `198.51.100.23`, `203.0.113.50`, `185.220.101.5`, `45.33.32.156`, `192.0.2.144`).
  - **Malicious Hashes (SHA-256)**: WannaCry (`ed01eb...`), Emotet (`4f952f...`), Cobalt Strike (`b5d3a2...`), LockBit 3.0 (`3a4f6b...`), DNSCat2 (`7b8c9d...`).
  - **Malicious Domains**: C2 endpoints, exfiltration domains, and phishing gateways.
  - **Whitelisted Entities**: Internal vulnerability scanners (Nessus `10.0.0.254`), penetration testing gateways, and core routers.
- **Pluggable Connectors**: Optional `VT_API_KEY` and `ABUSEIPDB_API_KEY` environment variables. If missing or unreachable, the system silently falls back to the high-fidelity local database with zero downtime.

### 3. Explainable AI Triage & MITRE ATT&CK Mapping
- **Tactics & Techniques Covered**:
  - `T1110` (Credential Access — Brute Force / Credential Stuffing)
  - `T1566` (Initial Access — Phishing / Weaponized Macro Attachment)
  - `T1486` (Impact — Data Encrypted for Impact / Ransomware)
  - `T1048` (Exfiltration — Exfiltration Over Alternative Protocol / DNS Tunneling)
  - `T1046` (Discovery — Network Service Discovery / Port Scans)
  - `T1203` (Execution — Exploitation for Client Execution / Remote Code Execution)
- **Dynamic Severity Scoring (P1-P4)**:
  - **P1 (Critical)**: Ransomware, confirmed weaponized hash execution, data exfiltration, remote root exploit.
  - **P2 (High)**: High-frequency brute force attacks with threat intel match, credential theft.
  - **P3 (Medium)**: Reconnaissance port sweeps, untrusted external DNS queries.
  - **P4 (Low)**: Routine scans, whitelisted compliance scans.
- **False-Positive Elimination**: Whitelisted compliance scanners (e.g., Nessus `10.0.0.254`) are autonomously suppressed to P4 with detailed justification rationale.
- **Explainable Rationale**: Every decision generates a clear narrative explaining triggering indicators, MITRE techniques, and calculated confidence scores (up to 99%).

### 4. Automated SOAR Response Engine (100% Reversible)
- **Automated Playbooks**:
  - `P1 / P2`: Quarantine compromised internal host, enforce perimeter firewall block rule on attacker IP, kill malicious processes by PID/name, and revoke targeted account sessions.
  - `P3 / P4`: Log telemetry and generate Tier 1 SOC monitoring ticket.
- **Stateful Reversibility**:
  - Every containment action is tracked in the active containment registry.
  - Any action can be reversed on demand via the dashboard or REST API (`/api/soar/revert/{action_id}`).
  - Entire incidents can be uncontained with a single click (`/api/soar/revert_incident/{incident_id}`).

### 5. Autonomous Executive Forensic Reports
- Generates both **Markdown (`.md`)** and self-contained, printable **HTML (`.html`)** reports saved in `reports/`.
- Each report includes:
  - Executive incident summary and MITRE ATT&CK classification
  - Explainable AI triage rationale
  - Root-cause analysis and adversary vector reconstruction
  - Full Indicators of Compromise (IOC) attribution (IPs, hashes, domains, accounts)
  - SOAR containment audit trail with rollback commands
  - Comprehensive timeline from detection to containment
  - Strategic remediation and hardening roadmap
  - One-click print / PDF export stylesheet (`@media print`)

### 6. Real-Time Dark-Mode SOC Command Dashboard
- High-density tactical cybersecurity dashboard located at `http://127.0.0.1:8000`.
- **Live Metrics Bar**: Ingested alert count, active P1/P2 incidents, quarantined hosts, and firewall block counts.
- **Incident Queue**: Filter by severity (P1/P2/P3/All), with deep investigation modal.
- **MITRE ATT&CK Matrix View**: Visual heatmap cards grouped by tactic with hit counts.
- **Active Containment Registry**: Live view of all active network blocks and host quarantines with one-click "Undo / Revert" buttons.
- **Real-Time Telemetry Stream**: Streaming feed over WebSockets.
- **Manual SOAR Override Console**: Allows human analysts to quarantine any host or block any IP manually.

---

## 5 Synthetic Attack Scenarios (`simulate_attacks.py`)

The bundled test harness executes 5 realistic enterprise attack scenarios against the pipeline:

| # | Scenario Name | MITRE ID | Ingestion Format | Target | Severity | Automated SOAR Actions |
|---|---|---|---|---|---|---|
| **1** | SSH Credential Stuffing | `T1110` | Linux `auth.log` | `10.0.0.15` | **P1/P2** | Firewall Block IP, Quarantine Host, Kill `sshd`, Revoke `admin` |
| **2** | Spear-Phishing (Emotet Dropper) | `T1566` | JSON / REST | `10.0.0.42` | **P1** | Firewall Block IP, Quarantine Host, Kill `WINWORD.EXE`, Revoke `cfo` |
| **3** | Ransomware Mass-Encryption | `T1486` | Suricata EVE | `10.0.0.99` | **P1** | Firewall Block C2, Quarantine Database Host |
| **4** | DNS Tunneling Exfiltration | `T1048` | JSON / DNS | `10.0.0.77` | **P1** | Firewall Block IP, Quarantine Host, Terminate `dnscat2` |
| **5** | Reconnaissance to RCE Probe | `T1203` | Snort Fast | `10.0.0.10` | **P1** | Firewall Block IP, Quarantine Web Host |

---

## ⚙️ System Requirements & Pre-Flight Notes

Before running CyberDefenseAI, please ensure your environment meets the following conditions:

1. **Python 3.10+ in System PATH**:
   - Requires Python 3.10, 3.11, 3.12, 3.13, or 3.14.
   - On Windows, ensure **"Add python.exe to PATH"** was checked during Python installation.
2. **First-Time Dependency Installation**:
   - While the SOC engine and threat intelligence database operate **100% offline**, an active internet connection is required on the **initial launch** so `pip` can download the core packages listed in `requirements.txt` (`fastapi`, `uvicorn`, `pydantic`, `httpx`, `websockets`, `jinja2`, `pytest`).
3. **Port 8000 Availability**:
   - The backend binds by default to `http://127.0.0.1:8000`. Ensure port 8000 is not in use by Docker or another local server.
   - *Custom Port*: You can override the port at any time by setting the `CYBER_PORT` environment variable (e.g., `set CYBER_PORT=8080` or `export CYBER_PORT=8080`).
4. **Operating System Notes**:
   - **Windows**: Simply run `run.bat`. It automatically initializes the virtual environment, installs dependencies, and avoids PowerShell `ExecutionPolicy` restrictions.
   - **Linux / macOS**: If cloned via git, permissions are pre-configured. If you downloaded the repository as a **ZIP archive** from GitHub, run `chmod +x run.sh` (or execute via `bash run.sh`) to ensure execution permissions.

---

## Quickstart Guide for Judges

### Option A: One-Click Launch (Windows)
Double-click `run.bat` or run in Command Prompt:
```cmd
run.bat
```
- Select **Option [4]** (or press Enter) to automatically start the backend server, open the SOC Dashboard in your browser (`http://127.0.0.1:8000`), and run the 5 synthetic attack scenarios.

### Option B: One-Click Launch (Linux / macOS)
In terminal:
```bash
chmod +x run.sh
./run.sh
```
- Select **Option [4]** to launch the backend, open your default browser, and run the attack simulator.

### Option C: In-Browser Demo (Zero Terminal Needed)
1. Launch the server (via `run.bat`, `run.sh`, or `python -m uvicorn cyberdefense.api:app --port 8000`).
2. Open **`http://127.0.0.1:8000`** in any browser.
3. In the top navigation bar, click:
   - **`Simulate 5 Attacks`** — runs all 5 scenarios with live WebSocket streaming, instant triage, automated containment, and report generation.
   - **`Reset`** — clears all incidents and containment rules back to a clean slate so you can re-run the demo anytime.

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health status, uptime, and containment metric counts |
| `POST` | `/api/ingest` | Ingest raw alert payload (JSON, Syslog, Suricata, Snort, Auth Log) |
| `POST` | `/api/simulate` | Trigger all 5 attack scenarios through the pipeline |
| `POST` | `/api/reset` | Reset all incidents, alerts, and SOAR containment to clean slate |
| `GET` | `/api/alerts` | Query normalized alerts (supports `severity`, `source_ip` filters) |
| `GET` | `/api/incidents` | List incidents with triage, MITRE mapping, and status |
| `GET` | `/api/incidents/{id}` | Inspect full incident data, AI rationale, and SOAR actions |
| `GET` | `/api/soar/actions` | Retrieve all executed response actions |
| `GET` | `/api/soar/summary` | Real-time counts of active quarantines, blocks, and tokens |
| `POST` | `/api/soar/override` | Manually trigger host quarantine, firewall block, or token revoke |
| `POST` | `/api/soar/revert/{id}` | Safely revert / undo a specific containment action |
| `POST` | `/api/soar/revert_incident/{id}` | Revert all active containment actions for an incident |
| `GET` | `/api/mitre/matrix` | Aggregated MITRE ATT&CK coverage matrix |
| `GET` | `/api/reports/{id}/html` | View / print self-contained executive HTML report |
| `GET` | `/api/reports/{id}/markdown` | View raw Markdown forensic report |
| `WS` | `/ws` | Real-time WebSocket event stream |

---

## Project Structure

```
CyberDefenseAI/
├── .venv/                           # Virtual environment (auto-created)
├── cyberdefense\
│   ├── __init__.py
│   ├── config.py                    # Paths, fallback settings, ports
│   ├── models.py                    # Pydantic Unified Event Schema & SOAR models
│   ├── threat_db_data.py            # Curated 100% offline threat intelligence dataset
│   ├── threat_intel.py              # Offline-first enrichment engine + VT/AbuseIPDB fallback
│   ├── ai_triage.py                 # MITRE mapping, P1-P4 classifier, FP suppression
│   ├── soar_engine.py               # Automated response engine & reversible containment
│   ├── forensic_reporter.py         # Autonomous Markdown & HTML report generator
│   ├── ingestion.py                 # Async queue & multi-format parsers
│   ├── pipeline.py                  # End-to-end event orchestrator & WebSocket broadcaster
│   ├── api.py                       # FastAPI REST API & WebSocket endpoints
│   └── static\
│       ├── index.html               # Real-time dark-mode SOC incident command dashboard
│       ├── styles.css               # Tactical cyber SOC aesthetic
│       └── dashboard.js             # Reactive WebSocket & REST dashboard logic
├── reports\                         # Generated forensic incident reports (.html and .md)
├── tests\
│   ├── test_ingestion.py            # Multi-format parsing & queue tests
│   ├── test_threat_intel.py         # Local DB lookups & enrichment tests
│   ├── test_ai_triage.py            # MITRE mapping & false-positive filter tests
│   ├── test_soar_engine.py          # Playbook execution & reversibility tests
│   ├── test_forensic_reporter.py    # Report generation tests
│   └── test_api_and_pipeline.py     # End-to-end REST & pipeline integration tests
├── simulate_attacks.py              # 5-scenario synthetic attack demonstration harness
├── requirements.txt                 # Pinned dependencies
├── pytest.ini                       # Pytest configuration
├── run.bat                          # One-click Windows runner
└── README.md                        # Project documentation
```
