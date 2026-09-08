import asyncio
import json
import httpx
import websockets

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws"

async def test_full_system():
    print("[*] Testing Live CyberDefenseAI System End-to-End...")
    
    # 1. Test HTTP Client
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=5.0) as client:
        # Health check
        res = await client.get("/api/health")
        assert res.status_code == 200, f"Health check failed: {res.status_code}"
        health = res.json()
        print(f"  [OK] Health Check: status={health['status']}, alerts={health['total_alerts']}, incidents={health['total_incidents']}")

        # Fetch Incidents
        res = await client.get("/api/incidents")
        assert res.status_code == 200
        incidents = res.json()
        print(f"  [OK] Incidents Endpoint: found {len(incidents)} incidents")
        assert len(incidents) > 0, "No incidents found!"
        first_inc = incidents[0]
        inc_id = first_inc["incident_id"]

        # Fetch Single Incident Detail
        res = await client.get(f"/api/incidents/{inc_id}")
        assert res.status_code == 200
        inc_detail = res.json()
        print(f"  [OK] Incident Detail ({inc_id[:8]}...): severity={inc_detail['severity']}, mitre={inc_detail['mitre_technique_id']}")

        # Fetch Reports
        res_html = await client.get(f"/api/reports/{inc_id}/html")
        assert res_html.status_code == 200
        assert "Autonomous Incident Investigation Report" in res_html.text
        print(f"  [OK] Forensic HTML Report: 200 OK ({len(res_html.text)} bytes)")

        res_md = await client.get(f"/api/reports/{inc_id}/markdown")
        assert res_md.status_code == 200
        assert "Autonomous SOC Incident Investigation Report" in res_md.text
        print(f"  [OK] Forensic Markdown Report: 200 OK ({len(res_md.text)} bytes)")

        # Fetch SOAR Summary & Actions
        res = await client.get("/api/soar/summary")
        assert res.status_code == 200
        soar_summary = res.json()
        print(f"  [OK] SOAR Summary: {soar_summary['total_actions']} actions, {soar_summary['quarantined_count']} quarantined hosts, {soar_summary['blocked_ips_count']} blocked IPs")

        res = await client.get("/api/soar/actions")
        assert res.status_code == 200
        actions = res.json()
        print(f"  [OK] SOAR Actions Registry: {len(actions)} entries")

        # Test Manual Override
        override_payload = {
            "action_type": "BLOCK_FIREWALL_IP",
            "target": "203.0.113.199",
            "reason": "End-to-End Verification Test Block"
        }
        res = await client.post("/api/soar/override", json=override_payload)
        assert res.status_code == 200
        override_act = res.json()
        override_id = override_act["action_id"]
        print(f"  [OK] Manual SOAR Override: action_id={override_id}, status={override_act['status']}")

        # Test Revert of that action
        res = await client.post(f"/api/soar/revert/{override_id}")
        assert res.status_code == 200
        reverted_act = res.json()
        assert reverted_act["status"] == "REVERTED"
        print(f"  [OK] SOAR Revert Action: successfully reverted action {override_id[:8]}...")

        # Test MITRE Matrix
        res = await client.get("/api/mitre/matrix")
        assert res.status_code == 200
        matrix = res.json()
        print(f"  [OK] MITRE Matrix: {matrix['total_coverage']} techniques mapped across {len(matrix['tactics'])} tactics")

        # Test Alert Ingestion
        test_alert = {
            "source_type": "auth_log",
            "data": "Sep 08 07:55:00 test-host sshd[9999]: Failed password for invalid user root from 198.51.100.23 port 44444 ssh2"
        }
        res = await client.post("/api/ingest", json=test_alert)
        assert res.status_code == 200
        ingest_res = res.json()
        print(f"  [OK] Live Alert Ingestion: status={ingest_res['status']}, incident_id={ingest_res['incident_id']}")

    # 2. Test WebSocket
    async with websockets.connect(WS_URL) as ws:
        msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
        parsed = json.loads(msg)
        assert parsed["event"] == "INIT_STATE"
        print(f"  [OK] WebSocket Connected & Handshake Verified: received INIT_STATE with {len(parsed['data'].get('incidents', []))} incidents")

    print("\n[ALL LIVE VERIFICATIONS PASSED - 100% OPERATIONAL]")

if __name__ == "__main__":
    asyncio.run(test_full_system())
