"""
Pydantic Data Models for CyberDefenseAI
Defines the Unified Event Schema, Threat Intelligence, Triage Decisions,
SOAR Actions, and Forensic Incident representations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class SeverityLevel(str, Enum):
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low


class ActionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    REVERTED = "REVERTED"
    FAILED = "FAILED"


class ActionType(str, Enum):
    QUARANTINE_HOST = "QUARANTINE_HOST"
    BLOCK_FIREWALL_IP = "BLOCK_FIREWALL_IP"
    REVOKE_USER_TOKEN = "REVOKE_USER_TOKEN"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    LOG_TELEMETRY = "LOG_TELEMETRY"
    CREATE_TICKET = "CREATE_TICKET"


class ThreatIntelEnrichment(BaseModel):
    source_ip_intel: Optional[Dict[str, Any]] = None
    dest_ip_intel: Optional[Dict[str, Any]] = None
    file_hash_intel: Optional[Dict[str, Any]] = None
    domain_intel: Optional[Dict[str, Any]] = None
    geo_intel: Optional[Dict[str, Any]] = None
    provider: str = "local_threat_db"
    query_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TriageDecision(BaseModel):
    severity: SeverityLevel
    severity_label: str  # "Critical", "High", "Medium", "Low"
    is_false_positive: bool = False
    confidence_score: float = Field(default=0.95, ge=0.0, le=1.0)
    mitre_tactic: str = "Initial Access"
    mitre_technique_id: str = "T1110"
    mitre_technique_name: str = "Brute Force"
    rationale: str
    recommended_action: str


class SOARAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    action_type: ActionType
    target: str
    status: ActionStatus = ActionStatus.EXECUTED
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reverted_at: Optional[datetime] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    is_reversible: bool = True
    rollback_command: Optional[str] = None


class UnifiedAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str = "json"  # json, syslog, suricata, snort, auth_log, custom
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    signature: str
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    raw_payload: Any = Field(default_factory=dict)
    enrichment: Optional[ThreatIntelEnrichment] = None
    triage: Optional[TriageDecision] = None
    soar_actions: List[SOARAction] = Field(default_factory=list)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "ACTIVE"  # ACTIVE, CONTAINED, REVERTED, CLOSED, FALSE_POSITIVE
    severity: SeverityLevel
    alerts: List[UnifiedAlert] = Field(default_factory=list)
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    target_host: Optional[str] = None
    threat_actor_ip: Optional[str] = None
    compromised_user: Optional[str] = None
    triage: Optional[TriageDecision] = None
    soar_actions: List[SOARAction] = Field(default_factory=list)
    report_markdown_path: Optional[str] = None
    report_html_path: Optional[str] = None


class IncidentReport(BaseModel):
    incident_id: str
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    markdown_path: str
    html_path: str
    summary: str
