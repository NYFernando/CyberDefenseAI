"""
CyberDefenseAI Pipeline Orchestrator
Coordinates end-to-end flow: Ingest -> Normalize -> Threat Intel Enrichment
-> AI Triage -> Automated SOAR Execution -> Forensic Reporting -> Real-Time Broadcast.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, List, Optional
import uuid

from cyberdefense.ai_triage import AITriageEngine
from cyberdefense.forensic_reporter import ForensicReportGenerator
from cyberdefense.ingestion import AlertIngestionEngine
from cyberdefense.models import (
    Incident,
    SeverityLevel,
    SOARAction,
    UnifiedAlert,
)
from cyberdefense.soar_engine import SOAREngine
from cyberdefense.threat_intel import ThreatIntelEngine

logger = logging.getLogger("cyberdefense.pipeline")


class CyberDefensePipeline:
    def __init__(
        self,
        threat_intel: Optional[ThreatIntelEngine] = None,
        triage_engine: Optional[AITriageEngine] = None,
        soar_engine: Optional[SOAREngine] = None,
        forensic_reporter: Optional[ForensicReportGenerator] = None,
        ingestion_engine: Optional[AlertIngestionEngine] = None,
    ):
        self.threat_intel = threat_intel or ThreatIntelEngine()
        self.triage_engine = triage_engine or AITriageEngine()
        self.soar_engine = soar_engine or SOAREngine()
        self.forensic_reporter = forensic_reporter or ForensicReportGenerator()
        self.ingestion = ingestion_engine or AlertIngestionEngine()

        # Data Stores
        self.alerts: List[UnifiedAlert] = []
        self.incidents: Dict[str, Incident] = {}
        # Correlation index: (threat_actor_ip, technique_id) -> incident_id
        self._correlation_index: Dict[str, str] = {}

        # WebSocket / event subscribers
        self._subscribers: List[asyncio.Queue] = []
        self._worker_task: Optional[asyncio.Task] = None
        self._running: bool = False

    async def start_worker(self):
        """Starts the background worker consuming from ingestion queue."""
        self._running = True
        self._worker_task = asyncio.create_task(self._process_queue_loop())
        logger.info("CyberDefensePipeline background worker started.")

    async def stop_worker(self):
        """Gracefully shuts down the background worker."""
        self._running = False
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await asyncio.wait_for(self._worker_task, timeout=0.5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        await self.threat_intel.close()
        logger.info("CyberDefensePipeline background worker stopped.")

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, event_type: str, data: Any):
        dead_queues = []
        payload = {"event": event_type, "data": data}
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            self.unsubscribe(dq)

    async def _process_queue_loop(self):
        while self._running:
            try:
                alert = await asyncio.wait_for(self.ingestion.get_next(), timeout=0.5)
                await self.process_alert(alert)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if not self._running:
                    break
                continue
            except Exception as ex:
                logger.error("Error processing alert in pipeline: %s", ex, exc_info=True)

    async def process_alert(self, alert: UnifiedAlert) -> Incident:
        """
        Main synchronous/asynchronous processing pipeline for a single UnifiedAlert:
        1. Threat Intelligence Enrichment
        2. AI Triage & MITRE Mapping
        3. Incident Correlation / Generation
        4. SOAR Playbook Execution
        5. Autonomous Forensic Report Generation
        6. Real-Time Broadcast
        """
        # 1. Threat Intel Enrichment
        enrichment = await self.threat_intel.enrich_all(
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            file_hash=alert.file_hash,
            domain=alert.domain,
        )
        alert.enrichment = enrichment

        # 2. AI Triage
        triage = self.triage_engine.triage(alert, enrichment)
        alert.triage = triage

        # 3. Incident Correlation & Creation
        correlation_key = f"{alert.source_ip or 'internal'}:{triage.mitre_technique_id}"
        existing_incident_id = self._correlation_index.get(correlation_key)

        if existing_incident_id and existing_incident_id in self.incidents:
            incident = self.incidents[existing_incident_id]
            incident.alerts.append(alert)
            incident.updated_at = datetime.now(timezone.utc)
            # Escalate severity if incoming alert is higher
            if triage.severity == SeverityLevel.P1 and incident.severity != SeverityLevel.P1:
                incident.severity = SeverityLevel.P1
            alert.incident_id = incident.incident_id
        else:
            incident_id = str(uuid.uuid4())
            alert.incident_id = incident_id
            incident = Incident(
                incident_id=incident_id,
                title=alert.signature,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                status="ACTIVE",
                severity=triage.severity,
                alerts=[alert],
                mitre_tactic=triage.mitre_tactic,
                mitre_technique_id=triage.mitre_technique_id,
                mitre_technique_name=triage.mitre_technique_name,
                target_host=alert.dest_ip or "10.0.0.15",
                threat_actor_ip=alert.source_ip,
                compromised_user=alert.user,
                triage=triage,
            )
            self.incidents[incident_id] = incident
            self._correlation_index[correlation_key] = incident_id

        # 4. Automated SOAR Playbook Execution
        soar_actions = self.soar_engine.dispatch_playbook(
            incident_id=incident.incident_id, alert=alert, triage=triage
        )
        alert.soar_actions = soar_actions
        incident.soar_actions.extend(soar_actions)

        # Update incident status
        if triage.is_false_positive:
            incident.status = "FALSE_POSITIVE"
        elif any(act.action_type.value in ("QUARANTINE_HOST", "BLOCK_FIREWALL_IP") for act in soar_actions):
            incident.status = "CONTAINED"
        else:
            incident.status = "ACTIVE"

        # 5. Autonomous Forensic Report Generation
        try:
            report = self.forensic_reporter.generate_report(incident)
            incident.report_markdown_path = report.markdown_path
            incident.report_html_path = report.html_path
        except Exception as ex:
            logger.error("Failed to generate forensic report for %s: %s", incident.incident_id, ex)

        # Store alert
        self.alerts.append(alert)

        # 6. Real-Time Broadcast to UI & WebSockets
        await self.broadcast("ALERT_INGESTED", alert.model_dump(mode="json"))
        await self.broadcast("INCIDENT_UPDATED", incident.model_dump(mode="json"))
        await self.broadcast("SOAR_STATE", self.soar_engine.get_summary())

        return incident

    async def ingest_and_process(
        self, raw_data: Any, source_type: Optional[str] = None
    ) -> Incident:
        """
        Direct ingestion and execution helper used by the API and simulation harness.
        """
        alert = self.ingestion.normalize(raw_data, source_type=source_type)
        return await self.process_alert(alert)
