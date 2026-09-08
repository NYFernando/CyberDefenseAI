"""
Unit Tests for Autonomous Forensic Report Generator
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest
from cyberdefense.forensic_reporter import ForensicReportGenerator
from cyberdefense.models import (
    ActionStatus,
    ActionType,
    Incident,
    SeverityLevel,
    SOARAction,
    TriageDecision,
    UnifiedAlert,
)


@pytest.fixture
def temp_reports_dir(tmp_path):
    return tmp_path / "test_reports"


def test_generate_forensic_report(temp_reports_dir):
    generator = ForensicReportGenerator(reports_dir=temp_reports_dir)

    incident = Incident(
        incident_id="test-inc-99",
        title="ET MALWARE WannaCry Ransomware Mass-Encryption",
        severity=SeverityLevel.P1,
        status="CONTAINED",
        mitre_tactic="Impact",
        mitre_technique_id="T1486",
        mitre_technique_name="Data Encrypted for Impact",
        threat_actor_ip="192.0.2.144",
        target_host="10.0.0.99",
        triage=TriageDecision(
            severity=SeverityLevel.P1,
            severity_label="Critical",
            confidence_score=0.99,
            mitre_tactic="Impact",
            mitre_technique_id="T1486",
            mitre_technique_name="Data Encrypted for Impact",
            rationale="Verified ransomware mass-encryption via local threat database match.",
            recommended_action="Isolate host immediately.",
        ),
        alerts=[
            UnifiedAlert(
                signature="ET MALWARE WannaCry Ransomware",
                source_ip="192.0.2.144",
                dest_ip="10.0.0.99",
                file_hash="ed01ebf83334a16f6e8a7d637a9de95a4d51f21e7b402b9fef5b724867ba83c2",
                domain="ransom-payment-portal.onion.sh",
            )
        ],
        soar_actions=[
            SOARAction(
                incident_id="test-inc-99",
                action_type=ActionType.BLOCK_FIREWALL_IP,
                target="192.0.2.144",
                status=ActionStatus.EXECUTED,
            ),
            SOARAction(
                incident_id="test-inc-99",
                action_type=ActionType.QUARANTINE_HOST,
                target="10.0.0.99",
                status=ActionStatus.EXECUTED,
            ),
        ],
    )

    report = generator.generate_report(incident)

    assert Path(report.markdown_path).exists()
    assert Path(report.html_path).exists()

    md_content = Path(report.markdown_path).read_text(encoding="utf-8")
    assert "T1486" in md_content
    assert "192.0.2.144" in md_content
    assert "ed01ebf83334a16f6e8a7d637a9de95a4d51f21e7b402b9fef5b724867ba83c2" in md_content
    assert "QUARANTINE_HOST" in md_content

    html_content = Path(report.html_path).read_text(encoding="utf-8")
    assert "<html" in html_content
    assert "Autonomous Incident Investigation Report" in html_content
    assert "@media print" in html_content
