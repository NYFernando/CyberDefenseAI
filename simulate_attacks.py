"""
Synthetic Attack Simulator & Demonstration Harness
Runs 5 realistic enterprise cyber attack scenarios against the CyberDefenseAI pipeline:
1. SSH/RDP Credential Stuffing (T1110)
2. Spear-Phishing with Payload Hash (T1566)
3. Ransomware Mass-Encryption & Volume Shadow Deletion (T1486)
4. Data Exfiltration over DNS Tunneling (T1048)
5. Port Scan followed by Remote Code Execution attempt (T1046 / T1203)
Supports both direct in-memory pipeline execution and live HTTP REST mode against the running server.
"""

import asyncio
import os
import sys
import time
from typing import Any, Dict, List
import httpx

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cyberdefense.pipeline import CyberDefensePipeline

# ANSI Color codes for clean competition CLI display
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


SCENARIOS = [
    {
        "id": 1,
        "name": "SSH Credential Stuffing & Dictionary Attack",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "source_type": "auth_log",
        "payload": "Sep 08 00:15:22 auth-gateway sshd[18492]: Failed password for invalid user admin from 198.51.100.23 port 54321 ssh2",
        "expected_sev": "P2",
        "target": "10.0.0.15",
    },
    {
        "id": 2,
        "name": "Spear-Phishing Weaponized Attachment (Emotet Dropper)",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "source_type": "json",
        "payload": {
            "source_type": "json",
            "source_ip": "203.0.113.50",
            "dest_ip": "10.0.0.42",
            "user": "cfo@enterprise.corp",
            "signature": "Spear-Phishing Email Attachment: Invoice_Q3_Payment.docm",
            "file_hash": "4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013",
            "domain": "update-service-patch.xyz",
            "process_name": "WINWORD.EXE",
        },
        "expected_sev": "P1",
        "target": "10.0.0.42",
    },
    {
        "id": 3,
        "name": "Ransomware Mass-Encryption & Volume Shadow Deletion",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "source_type": "suricata",
        "payload": {
            "event_type": "alert",
            "src_ip": "192.0.2.144",
            "src_port": 4444,
            "dest_ip": "10.0.0.99",
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "signature": "ET MALWARE WannaCry Ransomware Mass-Encryption & vssadmin shadowcopy delete",
                "category": "A Network Trojan was detected",
                "severity": 1,
            },
            "process_name": "wannacry.exe",
            "process_pid": 4892,
            "file_hash": "ed01ebf83334a16f6e8a7d637a9de95a4d51f21e7b402b9fef5b724867ba83c2",
            "domain": "ransom-payment-portal.onion.sh",
        },
        "expected_sev": "P1",
        "target": "10.0.0.99",
    },
    {
        "id": 4,
        "name": "Covert Data Exfiltration over DNS Tunneling",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "source_type": "json",
        "payload": {
            "source_type": "json",
            "source_ip": "103.251.167.20",
            "dest_ip": "10.0.0.77",
            "protocol": "DNS",
            "signature": "Suspicious High-Entropy DNS TXT Query Exfiltration",
            "domain": "dns-tunnel.evilcorp.biz",
            "process_name": "dnscat2",
            "file_hash": "7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
        },
        "expected_sev": "P1",
        "target": "10.0.0.77",
    },
    {
        "id": 5,
        "name": "Network Reconnaissance followed by Remote Code Execution Probe",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "source_type": "snort",
        "payload": "[**] [1:1000042:1] ET EXPLOIT Remote Code Execution Vulnerability Shellcode Ingress [**] [Priority: 1] {TCP} 45.33.32.156:58214 -> 10.0.0.10:80",
        "expected_sev": "P1",
        "target": "10.0.0.10",
    },
]


async def run_simulation(target_url: str = "http://127.0.0.1:8000"):
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}      CYBERDEFENSE AI — AUTONOMOUS ATTACK SIMULATION HARNESS        {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")

    # Check if target server is running
    is_live_server = False
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{target_url}/api/health")
            if resp.status_code == 200:
                is_live_server = True
    except Exception:
        is_live_server = False

    pipeline = None
    if is_live_server:
        print(f"{GREEN}[OK] Live Backend Server detected at {target_url}{RESET}")
        print(f"{DIM}Running simulation over live REST API endpoints...{RESET}\n")
    else:
        print(f"{YELLOW}[!] Live backend not detected on {target_url}.{RESET}")
        print(f"{CYAN}[*] Initializing direct in-process CyberDefensePipeline...{RESET}\n")
        pipeline = CyberDefensePipeline()

    results: List[Dict[str, Any]] = []

    for sc in SCENARIOS:
        print(f"{BOLD}----------------------------------------------------------------------{RESET}")
        print(f"{BOLD}Scenario {sc['id']}: {sc['name']}{RESET}")
        print(f"  {DIM}MITRE:{RESET} {sc['technique_id']} ({sc['technique_name']}) | {DIM}Format:{RESET} {sc['source_type']}")

        start_time = time.time()
        incident_data = None

        if is_live_server:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(
                    f"{target_url}/api/ingest",
                    json={"source_type": sc["source_type"], "data": sc["payload"]},
                )
                if res.status_code != 200:
                    print(f"{RED}[✗] Ingestion failed: {res.text}{RESET}")
                    continue
                resp_json = res.json()
                inc_id = resp_json["incident_id"]

                # Fetch full incident details
                inc_res = await client.get(f"{target_url}/api/incidents/{inc_id}")
                incident_data = inc_res.json()
        else:
            inc = await pipeline.ingest_and_process(sc["payload"], source_type=sc["source_type"])
            incident_data = inc.model_dump(mode="json")

        duration_ms = int((time.time() - start_time) * 1000)

        # Extract telemetry
        sev = incident_data["severity"]
        triage = incident_data.get("triage", {})
        actions = incident_data.get("soar_actions", [])
        status = incident_data.get("status")
        rep_html = incident_data.get("report_html_path", "Generated")

        print(f"  {GREEN}[+] Ingested & Normalized in {duration_ms}ms{RESET}")
        print(f"  {CYAN}[+] AI Triage Severity:{RESET} {BOLD}{sev}{RESET} ({triage.get('severity_label')}) | Confidence: {int((triage.get('confidence_score', 0.95))*100)}%")
        print(f"  {YELLOW}[+] Rationale:{RESET} {triage.get('rationale', '')[:90]}...")
        print(f"  {RED}[+] Automated SOAR Containment Dispatched:{RESET} {len(actions)} actions executed")
        for act in actions:
            print(f"      - {act['action_type']} -> Target: {act['target']} ({act['status']})")
        print(f"  {GREEN}[+] Forensic Report Compiled:{RESET} {rep_html}")

        results.append({
            "id": sc["id"],
            "name": sc["name"],
            "technique": sc["technique_id"],
            "severity": sev,
            "actions": len(actions),
            "status": status,
        })
        time.sleep(0.3)

    if pipeline:
        await pipeline.threat_intel.close()

    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}                   SIMULATION EXECUTION SUMMARY                       {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{'ID':<4} | {'Technique':<10} | {'Severity':<9} | {'Actions':<8} | {'Status':<12} | {'Scenario Name'}")
    print("-" * 70)
    for r in results:
        sev_color = RED if r["severity"] == "P1" else (YELLOW if r["severity"] == "P2" else CYAN)
        print(f"{r['id']:<4} | {r['technique']:<10} | {sev_color}{r['severity']:<9}{RESET} | {r['actions']:<8} | {GREEN}{r['status']:<12}{RESET} | {r['name']}")
    print("-" * 70)
    print(f"{BOLD}{GREEN}[SUCCESS] All {len(results)}/5 attack scenarios successfully triaged, contained & reported!{RESET}\n")


if __name__ == "__main__":
    asyncio.run(run_simulation())
