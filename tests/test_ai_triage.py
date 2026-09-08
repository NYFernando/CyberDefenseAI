"""
Unit Tests for AI Triage & Classification Engine
"""

import pytest
from cyberdefense.ai_triage import AITriageEngine
from cyberdefense.models import (
    SeverityLevel,
    ThreatIntelEnrichment,
    UnifiedAlert,
)


@pytest.fixture
def triage_engine():
    return AITriageEngine()


def test_triage_ransomware_t1486(triage_engine):
    alert = UnifiedAlert(
        signature="ET MALWARE Ransomware Mass-Encryption and vssadmin shadowcopy delete",
        process_name="vssadmin.exe",
        source_ip="192.0.2.144",
        dest_ip="10.0.0.99",
    )
    decision = triage_engine.triage(alert, enrichment=None)
    assert decision.mitre_technique_id == "T1486"
    assert decision.mitre_tactic == "Impact"
    assert decision.severity == SeverityLevel.P1
    assert decision.is_false_positive is False
    assert "T1486" in decision.rationale


def test_triage_brute_force_t1110(triage_engine):
    alert = UnifiedAlert(
        signature="Failed password for invalid user root",
        source_ip="198.51.100.23",
        dest_ip="10.0.0.15",
    )
    decision = triage_engine.triage(alert, enrichment=None)
    assert decision.mitre_technique_id == "T1110"
    assert decision.mitre_tactic == "Credential Access"
    assert decision.severity in (SeverityLevel.P1, SeverityLevel.P2)


def test_triage_phishing_t1566(triage_engine):
    alert = UnifiedAlert(
        signature="Phishing Attachment Delivered: Malicious Macro docm",
        source_ip="203.0.113.50",
        dest_ip="10.0.0.42",
        file_hash="4f952f4c3bf5e15645a859e9a4e8d3568c07e05f013238645e59b20756784013",
    )
    enrichment = ThreatIntelEnrichment(
        file_hash_intel={"is_malicious": True, "malware_family": "Emotet", "threat_score": 96}
    )
    decision = triage_engine.triage(alert, enrichment=enrichment)
    assert decision.mitre_technique_id == "T1566"
    assert decision.severity == SeverityLevel.P1  # Elevated to P1 due to confirmed malware hash
    assert decision.confidence_score >= 0.95


def test_triage_dns_exfiltration_t1048(triage_engine):
    alert = UnifiedAlert(
        signature="Suspicious DNS Tunneling Data Exfiltration",
        domain="dns-tunnel.evilcorp.biz",
        source_ip="103.251.167.20",
        dest_ip="10.0.0.77",
    )
    decision = triage_engine.triage(alert, enrichment=None)
    assert decision.mitre_technique_id == "T1048"
    assert decision.mitre_tactic == "Exfiltration"
    assert decision.severity == SeverityLevel.P1


def test_triage_port_scan_t1046(triage_engine):
    alert = UnifiedAlert(
        signature="TCP SYN Port Scan Reconnaissance",
        source_ip="45.33.32.156",
        dest_ip="10.0.0.10",
    )
    decision = triage_engine.triage(alert, enrichment=None)
    assert decision.mitre_technique_id == "T1046"
    assert decision.mitre_tactic == "Discovery"
    assert decision.severity in (SeverityLevel.P2, SeverityLevel.P3)


def test_triage_false_positive_elimination(triage_engine):
    alert = UnifiedAlert(
        signature="SYN Port Scan from Nessus probe",
        source_ip="10.0.0.254",
        dest_ip="10.0.0.15",
    )
    enrichment = ThreatIntelEnrichment(
        source_ip_intel={
            "is_whitelisted": True,
            "role": "Internal Vulnerability Scanner (Nessus Enterprise)",
        }
    )
    decision = triage_engine.triage(alert, enrichment=enrichment)
    assert decision.is_false_positive is True
    assert decision.severity == SeverityLevel.P4
    assert "whitelisted source" in decision.rationale.lower()
    assert decision.confidence_score >= 0.98
