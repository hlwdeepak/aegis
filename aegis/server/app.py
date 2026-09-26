from __future__ import annotations
import os
import uuid
import asyncio
from typing import Optional, Literal
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from aegis.models.signal import Signal
from aegis.graph.entity_graph import EntityGraph
from aegis.collectors.live_process import LiveProcessCollector
from aegis.collectors.live_network import LiveNetworkCollector
from aegis.collectors.live_persistence import LivePersistenceCollector
from aegis.collectors.synthetic_attack import generate_scenario_signals, AttackScenarioType
from aegis.engine.rules import run_rules
from aegis.engine.scoring import generate_executive_metrics, overall_posture_score, category_status
from aegis.engine.mitre import get_mitre_summary
from aegis.containment.responder import IncidentResponder
from aegis.storage.database import SecurityDatabase

app = FastAPI(title="Aegis-X Autonomous EDR & SOC Platform", version="2.0.0")

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# State
database = SecurityDatabase()
responder = IncidentResponder()
current_graph = EntityGraph()
current_incidents = []
active_websockets: list[WebSocket] = []


class ScanRequest(BaseModel):
    mode: Literal["live", "simulation", "hybrid"] = "hybrid"
    scenario: Optional[AttackScenarioType] = "all_threats"


class ContainmentRequest(BaseModel):
    actions: Optional[list[str]] = ["suspend", "quarantine", "sever_network", "kill"]


def execute_scan(mode: str = "hybrid", scenario: Optional[str] = "all_threats"):
    global current_graph, current_incidents
    graph = EntityGraph()
    signals: list[Signal] = []

    # 1. Collect live signals
    if mode in ["live", "hybrid"]:
        try:
            p_collector = LiveProcessCollector(sample_limit=80)
            signals.extend(p_collector.collect())
        except Exception as e:
            print(f"[Collector Error - Process]: {e}")

        try:
            n_collector = LiveNetworkCollector()
            signals.extend(n_collector.collect())
        except Exception as e:
            print(f"[Collector Error - Network]: {e}")

        try:
            pers_collector = LivePersistenceCollector()
            signals.extend(pers_collector.collect())
        except Exception as e:
            print(f"[Collector Error - Persistence]: {e}")

    # 2. Inject simulation scenario if specified
    if mode in ["simulation", "hybrid"] and scenario:
        sim_signals = generate_scenario_signals(scenario)
        signals.extend(sim_signals)

    # 3. Build graph
    for sig in signals:
        graph.add_signal(sig)

    # 4. Run declarative correlation rules
    incidents = run_rules(graph)

    # 5. Compute metrics & save
    metrics = generate_executive_metrics(graph, incidents)
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    database.record_scan(scan_id, metrics["score"], len(incidents), len(graph.entities()), metrics)

    for inc in incidents:
        database.record_incident(scan_id, inc.to_dict())

    current_graph = graph
    current_incidents = incidents
    return {
        "scan_id": scan_id,
        "metrics": metrics,
        "incidents": [inc.to_dict() for inc in incidents],
        "entity_count": len(graph.entities()),
        "signal_count": len(signals),
    }


# Initial warm-up scan
execute_scan(mode="hybrid", scenario="all_threats")


@app.get("/api/status")
def get_system_status():
    metrics = generate_executive_metrics(current_graph, current_incidents)
    return {
        "metrics": metrics,
        "incident_count": len(current_incidents),
        "entity_count": len(current_graph.entities()),
        "active_containments": len(responder.audit_log),
    }


@app.get("/api/incidents")
def get_incidents():
    return [inc.to_dict() for inc in current_incidents]


@app.get("/api/graph")
def get_graph():
    return current_graph.to_vis_graph(current_incidents)


@app.get("/api/mitre-matrix")
def get_mitre_matrix():
    return get_mitre_summary(current_incidents)


@app.get("/api/audit-log")
def get_audit_log():
    return database.get_recent_audits(50)


@app.post("/api/scan")
async def trigger_scan(req: ScanRequest):
    result = execute_scan(mode=req.mode, scenario=req.scenario)
    # Broadcast to WebSockets
    await broadcast_event({
        "type": "SCAN_COMPLETED",
        "score": result["metrics"]["score"],
        "incidents": len(result["incidents"]),
        "tier": result["metrics"]["posture_tier"],
    })
    return result


@app.post("/api/contain/{incident_id}")
async def contain_incident_endpoint(incident_id: str, req: ContainmentRequest):
    target_inc = next((inc for inc in current_incidents if inc.incident_id == incident_id), None)
    if not target_inc:
        raise HTTPException(status_code=404, detail="Incident ID not found")

    result = responder.contain_incident(target_inc, req.actions)
    database.record_audit(incident_id, "CONTAINMENT_EXECUTED", f"Actions: {', '.join(result['actions_executed'])}")
    database.update_incident_status(incident_id, target_inc.status)

    await broadcast_event({
        "type": "INCIDENT_CONTAINED",
        "incident_id": incident_id,
        "status": target_inc.status,
    })
    return result


@app.post("/api/simulate/{scenario}")
async def simulate_threat(scenario: AttackScenarioType):
    result = execute_scan(mode="simulation", scenario=scenario)
    await broadcast_event({
        "type": "ATTACK_SIMULATED",
        "scenario": scenario,
        "incidents": len(result["incidents"]),
    })
    return result


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            # Heartbeat / keepalive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        active_websockets.remove(websocket)


async def broadcast_event(data: dict):
    for ws in list(active_websockets):
        try:
            await ws.send_json(data)
        except Exception:
            if ws in active_websockets:
                active_websockets.remove(ws)


@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>Aegis-X SOC Server Active</h1>")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
