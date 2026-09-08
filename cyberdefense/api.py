"""
FastAPI REST and WebSocket API Server for CyberDefenseAI
Provides incident querying, ingestion endpoints, real-time WebSocket telemetry,
manual SOAR overrides, and interactive report rendering.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cyberdefense.config import REPORTS_DIR, STATIC_DIR
from cyberdefense.models import ActionType, SeverityLevel
from cyberdefense.pipeline import CyberDefensePipeline

logger = logging.getLogger("cyberdefense.api")

# Singleton pipeline instance
pipeline = CyberDefensePipeline()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: start background ingestion worker
    await pipeline.start_worker()
    yield
    # Shutdown: stop background worker
    await pipeline.stop_worker()


app = FastAPI(
    title="CyberDefenseAI - Autonomous SOC Defense System",
    description="Real-time ingestion, offline threat intelligence, MITRE ATT&CK triage, and automated SOAR containment.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IngestRequest(BaseModel):
    source_type: Optional[str] = "json"
    data: Any


class ManualOverrideRequest(BaseModel):
    action_type: ActionType
    target: str
    incident_id: Optional[str] = None
    reason: Optional[str] = "Manual SOC Analyst Trigger"


@app.get("/api/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(pipeline.alerts),
        "total_incidents": len(pipeline.incidents),
        "soar_summary": pipeline.soar_engine.get_summary(),
    }


@app.post("/api/ingest")
async def ingest_alert(req: IngestRequest):
    """
    Ingests an alert payload (JSON, Syslog, Suricata, Auth Log) and runs it through the pipeline.
    """
    try:
        incident = await pipeline.ingest_and_process(req.data, source_type=req.source_type)
        return {
            "status": "PROCESSED",
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
            "mitre_technique": incident.mitre_technique_id,
            "actions_executed": len(incident.soar_actions),
        }
    except Exception as ex:
        logger.error("Ingestion failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=400, detail=str(ex))


@app.get("/api/alerts")
async def list_alerts(
    limit: int = Query(default=100, le=500),
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
):
    filtered = pipeline.alerts
    if severity:
        filtered = [a for a in filtered if a.triage and a.triage.severity.value == severity]
    if source_ip:
        filtered = [a for a in filtered if a.source_ip == source_ip]

    # Return newest first
    reversed_alerts = list(reversed(filtered))[:limit]
    return [a.model_dump(mode="json") for a in reversed_alerts]


@app.get("/api/incidents")
async def list_incidents(
    limit: int = Query(default=50, le=200),
    status: Optional[str] = None,
    severity: Optional[str] = None,
):
    incidents_list = list(pipeline.incidents.values())
    if status:
        incidents_list = [inc for inc in incidents_list if inc.status == status]
    if severity:
        incidents_list = [inc for inc in incidents_list if inc.severity.value == severity]

    # Return newest first
    reversed_inc = list(reversed(incidents_list))[:limit]
    return [inc.model_dump(mode="json") for inc in reversed_inc]


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    if incident_id not in pipeline.incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    return pipeline.incidents[incident_id].model_dump(mode="json")


@app.get("/api/soar/actions")
async def list_soar_actions():
    actions = list(pipeline.soar_engine.actions.values())
    return [act.model_dump(mode="json") for act in reversed(actions)]


@app.get("/api/soar/summary")
async def get_soar_summary():
    return pipeline.soar_engine.get_summary()


@app.post("/api/soar/override")
async def trigger_manual_override(req: ManualOverrideRequest):
    inc_id = req.incident_id or "MANUAL-OVERRIDE"
    action = pipeline.soar_engine.execute_action(
        incident_id=inc_id,
        action_type=req.action_type,
        target=req.target,
        details={"operator_reason": req.reason, "source": "SOC_ANALYST_OVERRIDE"},
    )
    await pipeline.broadcast("SOAR_ACTION_TRIGGERED", action.model_dump(mode="json"))
    await pipeline.broadcast("SOAR_STATE", pipeline.soar_engine.get_summary())
    return action.model_dump(mode="json")


@app.post("/api/soar/revert/{action_id}")
async def revert_soar_action(action_id: str):
    action = pipeline.soar_engine.revert_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await pipeline.broadcast("SOAR_ACTION_REVERTED", action.model_dump(mode="json"))
    await pipeline.broadcast("SOAR_STATE", pipeline.soar_engine.get_summary())
    return action.model_dump(mode="json")


@app.post("/api/soar/revert_incident/{incident_id}")
async def revert_incident_actions(incident_id: str):
    reverted = pipeline.soar_engine.revert_incident_containment(incident_id)
    if incident_id in pipeline.incidents:
        pipeline.incidents[incident_id].status = "REVERTED"
        await pipeline.broadcast("INCIDENT_UPDATED", pipeline.incidents[incident_id].model_dump(mode="json"))
    await pipeline.broadcast("SOAR_STATE", pipeline.soar_engine.get_summary())
    return [act.model_dump(mode="json") for act in reverted]


@app.get("/api/mitre/matrix")
async def get_mitre_matrix():
    tactics: Dict[str, Dict[str, Any]] = {}
    technique_counts: Dict[str, Dict[str, Any]] = {}

    for inc in pipeline.incidents.values():
        tactic = inc.mitre_tactic
        tid = inc.mitre_technique_id
        tname = inc.mitre_technique_name
        sev = inc.severity.value

        if tactic not in tactics:
            tactics[tactic] = {"count": 0, "techniques": set()}
        tactics[tactic]["count"] += 1
        tactics[tactic]["techniques"].add(tid)

        if tid not in technique_counts:
            technique_counts[tid] = {
                "technique_id": tid,
                "name": tname,
                "tactic": tactic,
                "count": 0,
                "severities": {},
            }
        technique_counts[tid]["count"] += 1
        technique_counts[tid]["severities"][sev] = technique_counts[tid]["severities"].get(sev, 0) + 1

    formatted_tactics = [
        {"tactic": k, "count": v["count"], "techniques": sorted(list(v["techniques"]))}
        for k, v in tactics.items()
    ]

    return {
        "tactics": formatted_tactics,
        "techniques": list(technique_counts.values()),
        "total_coverage": len(technique_counts),
    }


@app.get("/api/reports/{incident_id}/html", response_class=HTMLResponse)
async def get_incident_html_report(incident_id: str):
    report_file = REPORTS_DIR / f"{incident_id}.html"
    if not report_file.exists():
        if incident_id in pipeline.incidents:
            pipeline.forensic_reporter.generate_report(pipeline.incidents[incident_id])
        else:
            raise HTTPException(status_code=404, detail="Forensic report not found")
    return HTMLResponse(content=report_file.read_text(encoding="utf-8"))


@app.post("/api/simulate")
async def run_in_browser_simulation():
    """
    Executes all 5 attack scenarios through the pipeline,
    broadcasting every update live over WebSockets for judges.
    """
    from simulate_attacks import SCENARIOS
    executed = []
    for sc in SCENARIOS:
        inc = await pipeline.ingest_and_process(sc["payload"], source_type=sc["source_type"])
        executed.append({
            "id": sc["id"],
            "name": sc["name"],
            "technique": sc["technique_id"],
            "severity": inc.severity.value,
            "status": inc.status,
            "actions": len(inc.soar_actions),
            "incident_id": inc.incident_id,
        })
        await asyncio.sleep(0.15)
    return {"status": "SUCCESS", "scenarios": executed}


@app.post("/api/reset")
async def reset_demo_state():
    """
    Resets the SOC pipeline state (alerts, incidents, containment registry)
    so judges can test from a clean slate.
    """
    pipeline.alerts.clear()
    pipeline.incidents.clear()
    pipeline._correlation_index.clear()
    pipeline.soar_engine.actions.clear()
    pipeline.soar_engine.incident_actions.clear()
    pipeline.soar_engine.quarantined_hosts.clear()
    pipeline.soar_engine.firewall_blocked_ips.clear()
    pipeline.soar_engine.revoked_tokens.clear()
    pipeline.soar_engine.terminated_processes.clear()
    pipeline.soar_engine.tickets.clear()

    await pipeline.broadcast("SOAR_STATE", pipeline.soar_engine.get_summary())
    await pipeline.broadcast("INIT_STATE", {
        "incidents": [],
        "alerts": [],
        "actions": [],
        "soar_summary": pipeline.soar_engine.get_summary(),
    })
    return {"status": "RESET_COMPLETE"}


@app.get("/api/reports/{incident_id}/markdown", response_class=PlainTextResponse)
async def get_incident_markdown_report(incident_id: str):
    report_file = REPORTS_DIR / f"{incident_id}.md"
    if not report_file.exists():
        if incident_id in pipeline.incidents:
            pipeline.forensic_reporter.generate_report(pipeline.incidents[incident_id])
        else:
            raise HTTPException(status_code=404, detail="Forensic report not found")
    return PlainTextResponse(content=report_file.read_text(encoding="utf-8"))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    queue = pipeline.subscribe()
    try:
        # Send initial baseline state upon connection
        init_payload = {
            "event": "INIT_STATE",
            "data": {
                "alerts": [a.model_dump(mode="json") for a in list(reversed(pipeline.alerts))[:50]],
                "incidents": [inc.model_dump(mode="json") for inc in list(reversed(list(pipeline.incidents.values())))[:50]],
                "soar_summary": pipeline.soar_engine.get_summary(),
                "actions": [act.model_dump(mode="json") for act in list(reversed(list(pipeline.soar_engine.actions.values())))[:50]],
            },
        }
        await websocket.send_json(init_payload)

        # Stream updates reactively
        while True:
            msg = await queue.get()
            await websocket.send_json(msg)
    except WebSocketDisconnect:
        pipeline.unsubscribe(queue)
    except Exception as ex:
        logger.debug("WebSocket exception: %s", ex)
        pipeline.unsubscribe(queue)


# Mount static assets for SOC Dashboard UI
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
