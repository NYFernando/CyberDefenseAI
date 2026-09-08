"""
Unit Tests for Automated SOAR Response Engine and Reversibility
"""

import pytest
from cyberdefense.models import (
    ActionStatus,
    ActionType,
    SeverityLevel,
    TriageDecision,
    UnifiedAlert,
)
from cyberdefense.soar_engine import SOAREngine


@pytest.fixture
def soar_engine():
    return SOAREngine()


def test_soar_dispatch_p1_critical(soar_engine):
    alert = UnifiedAlert(
        signature="Active Ransomware Execution",
        source_ip="192.0.2.144",
        dest_ip="10.0.0.99",
        process_name="wannacry.exe",
        process_pid=4892,
        user="dbadmin",
    )
    triage = TriageDecision(
        severity=SeverityLevel.P1,
        severity_label="Critical",
        is_false_positive=False,
        confidence_score=0.99,
        mitre_tactic="Impact",
        mitre_technique_id="T1486",
        mitre_technique_name="Data Encrypted for Impact",
        rationale="Active ransomware confirmed.",
        recommended_action="Isolate host and kill process.",
    )

    actions = soar_engine.dispatch_playbook("INC-001", alert, triage)
    action_types = [a.action_type for a in actions]

    assert ActionType.BLOCK_FIREWALL_IP in action_types
    assert ActionType.QUARANTINE_HOST in action_types
    assert ActionType.TERMINATE_PROCESS in action_types
    assert ActionType.REVOKE_USER_TOKEN in action_types

    assert "192.0.2.144" in soar_engine.firewall_blocked_ips
    assert "10.0.0.99" in soar_engine.quarantined_hosts
    assert "dbadmin" in soar_engine.revoked_tokens


def test_soar_dispatch_p3_medium(soar_engine):
    alert = UnifiedAlert(
        signature="Port Scan Probe",
        source_ip="45.33.32.156",
        dest_ip="10.0.0.10",
    )
    triage = TriageDecision(
        severity=SeverityLevel.P3,
        severity_label="Medium",
        is_false_positive=False,
        confidence_score=0.85,
        mitre_tactic="Discovery",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        rationale="Reconnaissance detected.",
        recommended_action="Log and ticket.",
    )

    actions = soar_engine.dispatch_playbook("INC-002", alert, triage)
    action_types = [a.action_type for a in actions]

    assert ActionType.LOG_TELEMETRY in action_types
    assert ActionType.CREATE_TICKET in action_types
    assert ActionType.QUARANTINE_HOST not in action_types


def test_soar_false_positive_no_containment(soar_engine):
    alert = UnifiedAlert(
        signature="Nessus Compliance Probe",
        source_ip="10.0.0.254",
        dest_ip="10.0.0.15",
    )
    triage = TriageDecision(
        severity=SeverityLevel.P4,
        severity_label="Low",
        is_false_positive=True,
        confidence_score=0.99,
        mitre_tactic="Discovery",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        rationale="Authorized compliance scan.",
        recommended_action="Ignore.",
    )

    actions = soar_engine.dispatch_playbook("INC-003", alert, triage)
    assert len(actions) == 1
    assert actions[0].action_type == ActionType.LOG_TELEMETRY
    assert len(soar_engine.quarantined_hosts) == 0
    assert len(soar_engine.firewall_blocked_ips) == 0


def test_soar_action_reversibility(soar_engine):
    act = soar_engine.execute_action(
        incident_id="INC-004",
        action_type=ActionType.BLOCK_FIREWALL_IP,
        target="198.51.100.23",
    )
    assert act.status == ActionStatus.EXECUTED
    assert "198.51.100.23" in soar_engine.firewall_blocked_ips

    # Revert action
    reverted = soar_engine.revert_action(act.action_id)
    assert reverted.status == ActionStatus.REVERTED
    assert "198.51.100.23" not in soar_engine.firewall_blocked_ips


def test_soar_revert_entire_incident(soar_engine):
    soar_engine.execute_action("INC-005", ActionType.QUARANTINE_HOST, "10.0.0.50")
    soar_engine.execute_action("INC-005", ActionType.BLOCK_FIREWALL_IP, "203.0.113.1")
    soar_engine.execute_action("INC-005", ActionType.REVOKE_USER_TOKEN, "alice")

    assert "10.0.0.50" in soar_engine.quarantined_hosts
    assert "203.0.113.1" in soar_engine.firewall_blocked_ips
    assert "alice" in soar_engine.revoked_tokens

    reverted_list = soar_engine.revert_incident_containment("INC-005")
    assert len(reverted_list) == 3

    assert "10.0.0.50" not in soar_engine.quarantined_hosts
    assert "203.0.113.1" not in soar_engine.firewall_blocked_ips
    assert "alice" not in soar_engine.revoked_tokens
