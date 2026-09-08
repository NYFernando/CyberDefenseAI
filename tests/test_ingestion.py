"""
Unit Tests for Ingestion & Event Normalization Engine
"""

import pytest
from cyberdefense.ingestion import AlertIngestionEngine
from cyberdefense.models import UnifiedAlert


@pytest.fixture
def ingestion_engine():
    return AlertIngestionEngine()


def test_parse_json_standard(ingestion_engine):
    payload = {
        "source_ip": "198.51.100.23",
        "dest_ip": "10.0.0.15",
        "source_port": 54321,
        "dest_port": 22,
        "protocol": "TCP",
        "signature": "SSH Brute Force Attempt",
        "user": "root",
    }
    alert = ingestion_engine.normalize(payload)
    assert isinstance(alert, UnifiedAlert)
    assert alert.source_ip == "198.51.100.23"
    assert alert.dest_ip == "10.0.0.15"
    assert alert.source_port == 54321
    assert alert.dest_port == 22
    assert alert.protocol == "TCP"
    assert alert.signature == "SSH Brute Force Attempt"
    assert alert.user == "root"


def test_parse_json_aliases(ingestion_engine):
    payload = {
        "src": "203.0.113.50",
        "dst": "10.0.0.42",
        "sport": "443",
        "dport": "8080",
        "proto": "udp",
        "alert_name": "Suspicious UDP Burst",
        "account": "svc-backup",
        "sha256": "4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013",
    }
    alert = ingestion_engine.normalize(payload)
    assert alert.source_ip == "203.0.113.50"
    assert alert.dest_ip == "10.0.0.42"
    assert alert.source_port == 443
    assert alert.dest_port == 8080
    assert alert.protocol == "UDP"
    assert alert.signature == "Suspicious UDP Burst"
    assert alert.user == "svc-backup"
    assert alert.file_hash == "4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013"


def test_parse_syslog_rfc(ingestion_engine):
    syslog_msg = "<34>Oct 11 22:14:15 edge-router firewall[4502]: Inbound drop connection from 198.51.100.23 port 49152 to 10.0.0.1"
    alert = ingestion_engine.normalize(syslog_msg, source_type="syslog")
    assert alert.source_type == "syslog"
    assert alert.source_ip == "198.51.100.23"
    assert alert.dest_ip == "10.0.0.1"
    assert alert.source_port == 49152
    assert "firewall" in alert.signature.lower()


def test_parse_suricata_eve(ingestion_engine):
    eve_payload = {
        "event_type": "alert",
        "src_ip": "192.0.2.144",
        "src_port": 4444,
        "dest_ip": "10.0.0.99",
        "dest_port": 445,
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Ransomware Communication",
            "category": "Trojan",
            "severity": 1,
        },
    }
    alert = ingestion_engine.normalize(eve_payload)
    assert alert.source_type == "suricata"
    assert alert.source_ip == "192.0.2.144"
    assert alert.dest_ip == "10.0.0.99"
    assert alert.dest_port == 445
    assert "ET MALWARE Ransomware Communication" in alert.signature


def test_parse_snort_fast(ingestion_engine):
    snort_str = "[**] [1:1000042:1] ET EXPLOIT Remote Code Execution Vulnerability Shellcode Ingress [**] [Priority: 1] {TCP} 45.33.32.156:58214 -> 10.0.0.10:80"
    alert = ingestion_engine.normalize(snort_str, source_type="snort")
    assert alert.source_type == "snort"
    assert alert.source_ip == "45.33.32.156"
    assert alert.dest_ip == "10.0.0.10"
    assert alert.source_port == 58214
    assert alert.dest_port == 80
    assert "Remote Code Execution" in alert.signature


def test_parse_auth_log(ingestion_engine):
    auth_str = "Sep 08 00:15:22 srv sshd[18492]: Failed password for invalid user admin from 198.51.100.23 port 54321 ssh2"
    alert = ingestion_engine.normalize(auth_str, source_type="auth_log")
    assert alert.source_type == "auth_log"
    assert alert.source_ip == "198.51.100.23"
    assert alert.user == "admin"
    assert alert.source_port == 54321


@pytest.mark.asyncio
async def test_async_queue_flow(ingestion_engine):
    payload = {"source_ip": "1.2.3.4", "signature": "Test Queue Alert"}
    submitted = await ingestion_engine.submit(payload)
    assert ingestion_engine.ingested_count == 1

    dequeued = await ingestion_engine.get_next()
    assert dequeued.alert_id == submitted.alert_id
    assert dequeued.signature == "Test Queue Alert"
