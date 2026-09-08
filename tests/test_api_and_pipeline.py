"""
Integration Tests for REST API Endpoints and CyberDefensePipeline
"""

import pytest
from fastapi.testclient import TestClient
from cyberdefense.api import app, pipeline


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert "timestamp" in data


def test_api_ingest_and_triage_flow(client):
    payload = {
        "source_type": "json",
        "data": {
            "source_ip": "198.51.100.23",
            "dest_ip": "10.0.0.15",
            "signature": "ET SCAN Potential SSH Brute Force Ingress",
            "user": "root",
            "protocol": "TCP",
        },
    }
    resp = client.post("/api/ingest", json=payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "PROCESSED"
    assert res_data["severity"] in ("P1", "P2")
    assert res_data["mitre_technique"] == "T1110"
    assert res_data["actions_executed"] >= 1

    incident_id = res_data["incident_id"]

    # Verify incident retrieval
    inc_resp = client.get(f"/api/incidents/{incident_id}")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert inc_data["incident_id"] == incident_id
    assert inc_data["mitre_technique_id"] == "T1110"


def test_list_alerts_and_incidents(client):
    # Ingest one more alert
    client.post(
        "/api/ingest",
        json={
            "source_type": "json",
            "data": {
                "source_ip": "203.0.113.50",
                "dest_ip": "10.0.0.42",
                "signature": "Spear-Phishing Invoice Macro Delivery",
                "file_hash": "4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013",
            },
        },
    )

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 1

    inc_resp = client.get("/api/incidents")
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) >= 1


def test_soar_endpoints_and_reversibility(client):
    # 1. Manual SOAR Trigger
    override_payload = {
        "action_type": "BLOCK_FIREWALL_IP",
        "target": "185.220.101.99",
        "reason": "Suspicious Tor Node Active Connection",
    }
    trigger_resp = client.post("/api/soar/override", json=override_payload)
    assert trigger_resp.status_code == 200
    action_data = trigger_resp.json()
    action_id = action_data["action_id"]
    assert action_data["status"] == "EXECUTED"

    # 2. Check summary
    sum_resp = client.get("/api/soar/summary")
    assert sum_resp.status_code == 200
    assert sum_resp.json()["blocked_ips_count"] >= 1

    # 3. Revert Action
    revert_resp = client.post(f"/api/soar/revert/{action_id}")
    assert revert_resp.status_code == 200
    assert revert_resp.json()["status"] == "REVERTED"


def test_mitre_matrix_endpoint(client):
    resp = client.get("/api/mitre/matrix")
    assert resp.status_code == 200
    matrix = resp.json()
    assert "tactics" in matrix
    assert "techniques" in matrix
    assert matrix["total_coverage"] >= 1


def test_forensic_report_endpoints(client):
    # Ingest test incident
    ing_resp = client.post(
        "/api/ingest",
        json={
            "source_type": "json",
            "data": {
                "source_ip": "192.0.2.144",
                "dest_ip": "10.0.0.99",
                "signature": "Ransomware encryption shadowcopy delete",
            },
        },
    )
    inc_id = ing_resp.json()["incident_id"]

    # HTML Report
    html_resp = client.get(f"/api/reports/{inc_id}/html")
    assert html_resp.status_code == 200
    assert "<html" in html_resp.text

    # Markdown Report
    md_resp = client.get(f"/api/reports/{inc_id}/markdown")
    assert md_resp.status_code == 200
    assert "Autonomous SOC Incident Investigation Report" in md_resp.text
