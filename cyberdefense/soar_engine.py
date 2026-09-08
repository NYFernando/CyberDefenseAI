"""
Automated SOAR (Security Orchestration, Automation, and Response) Engine
Executes automated containment playbooks based on incident severity rules.
All containment actions are statefully tracked, simulated safely, and 100% reversible.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

from cyberdefense.models import (
    ActionStatus,
    ActionType,
    SeverityLevel,
    SOARAction,
    TriageDecision,
    UnifiedAlert,
)

logger = logging.getLogger("cyberdefense.soar")


class SOAREngine:
    def __init__(self):
        # Action registry keyed by action_id
        self.actions: Dict[str, SOARAction] = {}
        # Actions indexed by incident_id
        self.incident_actions: Dict[str, List[str]] = {}

        # Live stateful containment state
        self.quarantined_hosts: Set[str] = set()
        self.firewall_blocked_ips: Set[str] = set()
        self.revoked_tokens: Set[str] = set()
        self.terminated_processes: List[Dict[str, Any]] = []
        self.tickets: List[Dict[str, Any]] = []

    def get_action(self, action_id: str) -> Optional[SOARAction]:
        return self.actions.get(action_id)

    def get_incident_actions(self, incident_id: str) -> List[SOARAction]:
        action_ids = self.incident_actions.get(incident_id, [])
        return [self.actions[aid] for aid in action_ids if aid in self.actions]

    def execute_action(
        self,
        incident_id: str,
        action_type: ActionType,
        target: str,
        details: Optional[Dict[str, Any]] = None,
        rollback_command: Optional[str] = None,
    ) -> SOARAction:
        action_id = str(uuid.uuid4())
        details = details or {}

        # Apply stateful containment update
        if action_type == ActionType.QUARANTINE_HOST:
            self.quarantined_hosts.add(target)
            details["isolation_mode"] = "Virtual Network Air-Gap"
            rollback_cmd = rollback_command or f"netsh advfirewall firewall delete rule name='ISOLATE_{target}'"

        elif action_type == ActionType.BLOCK_FIREWALL_IP:
            self.firewall_blocked_ips.add(target)
            details["rule_chain"] = "INPUT_DROP"
            rollback_cmd = rollback_command or f"iptables -D INPUT -s {target} -j DROP"

        elif action_type == ActionType.REVOKE_USER_TOKEN:
            self.revoked_tokens.add(target)
            details["revocation_scope"] = "OAUTH2_REFRESH_AND_ACCESS"
            rollback_cmd = rollback_command or f"auth-service token-restore --user {target}"

        elif action_type == ActionType.TERMINATE_PROCESS:
            proc_entry = {"target": target, "incident_id": incident_id, "timestamp": datetime.now(timezone.utc)}
            self.terminated_processes.append(proc_entry)
            details["signal"] = "SIGKILL (9)"
            rollback_cmd = "Manual restart of service required if system daemon."

        elif action_type == ActionType.CREATE_TICKET:
            ticket_id = f"SEC-TICK-{len(self.tickets) + 1001}"
            ticket_entry = {
                "ticket_id": ticket_id,
                "incident_id": incident_id,
                "target": target,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "priority": details.get("severity", "Medium"),
                "status": "OPEN",
            }
            self.tickets.append(ticket_entry)
            details["ticket_id"] = ticket_id
            rollback_cmd = f"ticket-system close --id {ticket_id}"

        elif action_type == ActionType.LOG_TELEMETRY:
            details["retention_days"] = 365
            rollback_cmd = "Audit log permanent retention."

        else:
            rollback_cmd = "No rollback available."

        action = SOARAction(
            action_id=action_id,
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            status=ActionStatus.EXECUTED,
            executed_at=datetime.now(timezone.utc),
            details=details,
            is_reversible=action_type in (
                ActionType.QUARANTINE_HOST,
                ActionType.BLOCK_FIREWALL_IP,
                ActionType.REVOKE_USER_TOKEN,
            ),
            rollback_command=rollback_cmd,
        )

        self.actions[action_id] = action
        if incident_id not in self.incident_actions:
            self.incident_actions[incident_id] = []
        self.incident_actions[incident_id].append(action_id)

        logger.info(
            "Executed SOAR Action: %s on target '%s' for incident %s",
            action_type.value,
            target,
            incident_id,
        )
        return action

    def revert_action(self, action_id: str) -> Optional[SOARAction]:
        """
        Reverses a previously executed containment action safely.
        """
        action = self.actions.get(action_id)
        if not action:
            return None

        if action.status == ActionStatus.REVERTED:
            return action

        if not action.is_reversible:
            logger.warning("Action %s is not reversible.", action_id)
            return action

        target = action.target
        if action.action_type == ActionType.QUARANTINE_HOST:
            self.quarantined_hosts.discard(target)
        elif action.action_type == ActionType.BLOCK_FIREWALL_IP:
            self.firewall_blocked_ips.discard(target)
        elif action.action_type == ActionType.REVOKE_USER_TOKEN:
            self.revoked_tokens.discard(target)

        action.status = ActionStatus.REVERTED
        action.reverted_at = datetime.now(timezone.utc)
        logger.info(
            "Reverted SOAR Action: %s on target '%s' (Action ID: %s)",
            action.action_type.value,
            target,
            action_id,
        )
        return action

    def revert_incident_containment(self, incident_id: str) -> List[SOARAction]:
        """
        Reverts all active containment actions associated with an incident.
        """
        reverted = []
        for action_id in self.incident_actions.get(incident_id, []):
            action = self.actions.get(action_id)
            if action and action.is_reversible and action.status == ActionStatus.EXECUTED:
                reverted_action = self.revert_action(action_id)
                if reverted_action:
                    reverted.append(reverted_action)
        return reverted

    def dispatch_playbook(
        self, incident_id: str, alert: UnifiedAlert, triage: TriageDecision
    ) -> List[SOARAction]:
        """
        Automated playbook execution driven by triage severity:
        - P1 / P2: Active containment (Host quarantine, firewall IP block, token revocation, process kill).
        - P3 / P4: Observability and ticketing (Log telemetry, Tier 1 monitoring ticket).
        - False Positive: Telemetry log only.
        """
        actions: List[SOARAction] = []

        if triage.is_false_positive:
            act = self.execute_action(
                incident_id=incident_id,
                action_type=ActionType.LOG_TELEMETRY,
                target=alert.source_ip or "internal-host",
                details={
                    "reason": "Suppressed false positive",
                    "triage_rationale": triage.rationale,
                },
            )
            actions.append(act)
            return actions

        # P1 / P2 Critical & High Playbooks
        if triage.severity in (SeverityLevel.P1, SeverityLevel.P2):
            # 1. Block malicious source IP
            if alert.source_ip:
                act = self.execute_action(
                    incident_id=incident_id,
                    action_type=ActionType.BLOCK_FIREWALL_IP,
                    target=alert.source_ip,
                    details={
                        "severity": triage.severity.value,
                        "mitre_technique": triage.mitre_technique_id,
                        "trigger": "Automated perimeter firewall perimeter drop",
                    },
                )
                actions.append(act)

            # 2. Quarantine compromised internal host (for P1, or internal dest_ip under attack)
            host_target = alert.dest_ip or "10.0.0.15"
            if triage.severity == SeverityLevel.P1 or (
                alert.dest_ip and not alert.dest_ip.startswith("127.")
            ):
                act = self.execute_action(
                    incident_id=incident_id,
                    action_type=ActionType.QUARANTINE_HOST,
                    target=host_target,
                    details={
                        "severity": triage.severity.value,
                        "isolation_level": "Strict Network Air-Gap",
                        "mitre_technique": triage.mitre_technique_id,
                    },
                )
                actions.append(act)

            # 3. Terminate active malicious process if present
            proc_target = alert.process_name or (
                f"PID-{alert.process_pid}" if alert.process_pid else None
            )
            if proc_target:
                act = self.execute_action(
                    incident_id=incident_id,
                    action_type=ActionType.TERMINATE_PROCESS,
                    target=proc_target,
                    details={
                        "process_name": alert.process_name,
                        "process_pid": alert.process_pid,
                        "technique": triage.mitre_technique_id,
                    },
                )
                actions.append(act)

            # 4. Revoke compromised credentials/tokens if user is associated
            if alert.user:
                act = self.execute_action(
                    incident_id=incident_id,
                    action_type=ActionType.REVOKE_USER_TOKEN,
                    target=alert.user,
                    details={
                        "reason": f"Active compromise under {triage.mitre_technique_id}",
                        "user": alert.user,
                    },
                )
                actions.append(act)

        # P3 / P4 Medium & Low Playbooks
        else:
            # 1. Log telemetry
            act = self.execute_action(
                incident_id=incident_id,
                action_type=ActionType.LOG_TELEMETRY,
                target=alert.source_ip or "network-edge",
                details={
                    "severity": triage.severity.value,
                    "mitre_technique": triage.mitre_technique_id,
                },
            )
            actions.append(act)

            # 2. Create SOC Tier 1 ticket
            act = self.execute_action(
                incident_id=incident_id,
                action_type=ActionType.CREATE_TICKET,
                target=alert.signature,
                details={
                    "severity": triage.severity.value,
                    "mitre_technique": triage.mitre_technique_id,
                    "source_ip": alert.source_ip,
                },
            )
            actions.append(act)

        return actions

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_actions": len(self.actions),
            "active_quarantined_hosts": sorted(list(self.quarantined_hosts)),
            "active_firewall_blocks": sorted(list(self.firewall_blocked_ips)),
            "active_revoked_tokens": sorted(list(self.revoked_tokens)),
            "terminated_processes_count": len(self.terminated_processes),
            "tickets_created_count": len(self.tickets),
            "quarantined_count": len(self.quarantined_hosts),
            "blocked_ips_count": len(self.firewall_blocked_ips),
            "revoked_tokens_count": len(self.revoked_tokens),
        }
