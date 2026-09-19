"""SignalForge HTTP API.

The API keeps DEMO_MODE deterministic and exposes the same contracts that live
adapters and UiPath consume.  Mutating operational actions remain auditable and
approval-gated.
"""
from __future__ import annotations

import json
import queue
import time
import uuid
from typing import Any, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ConfigDict

from .config import DEMO_MODE, FRONTEND_ORIGIN, LAB_MODE, OPENAI_API_KEY, PRODUCTION_MODE, SIGNALFORGE_MODE
from .database.db import (clear_lab_events, delete_entity, get_incident, get_response, init_db, list_audit,
                          list_entities, list_incidents, list_lab_events, save_entity, save_lab_event, save_response)
from .rules.engine import RULES, STATES, evaluate
from .services.pipeline import SCENARIOS, enrich, investigate

app = FastAPI(title="SignalForge SOC Automation Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000"], allow_methods=["*"], allow_headers=["*"])
init_db()
LAB_CONTROLLER_URL = __import__("os").getenv("LAB_CONTROLLER_URL", "")
LAB_EVENT_WINDOW: dict[str, list[dict[str, Any]]] = {}
EVENT_SUBSCRIBERS: list[queue.Queue] = []
AUTOMATION_CLAIMS: dict[str, dict[str, Any]] = {}

@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "REQ-" + uuid.uuid4().hex[:12].upper())
    response = await call_next(request); response.headers["x-request-id"] = request_id; response.headers["x-content-type-options"] = "nosniff"; response.headers["x-frame-options"] = "DENY"; return response

class Alert(BaseModel):
    model_config = ConfigDict(extra="allow")
    source_ip: str = Field(..., min_length=3, max_length=64)
    destination_ip: str = Field(..., min_length=3, max_length=64)
    event_type: str = Field(..., min_length=2, max_length=100)
    failed_attempts: int = Field(0, ge=0, le=1_000_000)
    username: Optional[str] = Field(None, max_length=256)
    usernames: list[str] = Field(default_factory=list)
    hostname: Optional[str] = Field(None, max_length=256)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    timestamp: Optional[str] = None
    asset_type: Optional[str] = None
    asset_criticality: int = Field(3, ge=1, le=5)
    description: str = Field("", max_length=4000)
    unique_ports: int = Field(0, ge=0, le=65535)

class EnrichRequest(BaseModel): source_ip: str = Field(..., min_length=3, max_length=64)
class RiskRequest(BaseModel): alert: dict[str, Any]; threat_intelligence: Optional[dict[str, Any]] = None
class EntityRequest(BaseModel): model_config = ConfigDict(extra="allow"); id: Optional[str] = None
class ApprovalRequest(BaseModel): actor: str = Field("demo-analyst", min_length=1, max_length=120); note: str = Field("", max_length=1000)
class LabEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str = Field(default_factory=lambda: "EVT-" + uuid.uuid4().hex[:12].upper())
    timestamp: str = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())
    source_ip: str = Field(..., min_length=3, max_length=64)
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str = Field(..., min_length=2, max_length=80)
    username: Optional[str] = None
    target_asset: str = Field("AUTH-SERVER-01", min_length=2, max_length=120)
    asset_criticality: int = Field(5, ge=1, le=5)
    raw_source: str = Field("lab-target", min_length=2, max_length=120)
    scenario: Optional[str] = None

def error(code: str, message: str): return JSONResponse(status_code=400, content={"error": {"code": code, "message": message, "request_id": "generated"}})

@app.get("/health")
def health(): return {"status": "ok", "service": "signalforge-backend", "version": app.version}

@app.get("/system/status")
def status():
    return {"mode": SIGNALFORGE_MODE, "database": "sqlite", "rule_engine": {"status": "ready", "rules": len(RULES), "states": list(STATES)}, "ai": "fallback" if DEMO_MODE else ("configured" if OPENAI_API_KEY else "UNAVAILABLE"), "providers": providers_status(), "lab": lab_status()}

def providers_status():
    status = "LAB_FIXTURE" if LAB_MODE else "DEMO_FIXTURE" if DEMO_MODE else "UNAVAILABLE"; mode = "LAB_MODE" if LAB_MODE else "DEMO_MODE" if DEMO_MODE else "LIVE_MODE"
    return {name: {"provider": name, "status": status, "mode": mode} for name in ("VirusTotal", "AbuseIPDB", "NVD", "GeoIP", "MITRE", "OpenAI", "Outlook")}

@app.get("/providers/status")
def provider_status(): return {"items": list(providers_status().values())}

def lab_status():
    if not LAB_MODE:
        return {"environment": SIGNALFORGE_MODE, "isolation": "NOT_ACTIVE", "target": "DISABLED", "attacker": "DISABLED", "c2": "DISABLED", "telemetry": "DISABLED", "controller": "DISABLED", "network": "DISABLED"}
    components = {"target": "NOT_CONNECTED", "attacker": "NOT_CONNECTED", "c2": "NOT_CONNECTED", "telemetry": "CONNECTED", "controller": "NOT_CONNECTED", "network": "ISOLATED"}
    if LAB_CONTROLLER_URL:
        try:
            remote = httpx.get(f"{LAB_CONTROLLER_URL}/status", timeout=1.5)
            if remote.is_success: components.update(remote.json().get("components", {}))
        except httpx.HTTPError: pass
    return {"environment": "LAB_MODE", "isolation": "ISOLATED", **components}

@app.get("/lab/status")
def lab_health(): return lab_status()

def publish_lab(payload: dict[str, Any]):
    for subscriber in list(EVENT_SUBSCRIBERS):
        try: subscriber.put_nowait(payload)
        except queue.Full: pass

@app.get("/events/stream")
def event_stream():
    subscriber: queue.Queue = queue.Queue(maxsize=100)
    EVENT_SUBSCRIBERS.append(subscriber)
    def stream():
        try:
            while True:
                try: payload = subscriber.get(timeout=15)
                except queue.Empty: payload = {"event_type": "HEARTBEAT", "timestamp": time.time()}
                yield f"data: {json.dumps(payload, default=str)}\n\n"
        finally:
            if subscriber in EVENT_SUBSCRIBERS: EVENT_SUBSCRIBERS.remove(subscriber)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.post("/auth/login")
def login(payload: dict[str, str]): return {"access_token": "demo-session" if DEMO_MODE else "configuration-required", "token_type": "bearer", "role": "SOC_ANALYST", "demo": DEMO_MODE}
@app.get("/users/me")
def me(): return {"id": "demo-analyst", "username": "demo-analyst", "role": "SOC_ANALYST", "demo": DEMO_MODE}

@app.post("/alerts")
def create_alert(alert: Alert): return {"alert": alert.model_dump(), "status": "accepted", "fingerprint": uuid.uuid5(uuid.NAMESPACE_URL, str(alert.model_dump())).hex}
@app.post("/investigate")
def run_investigation(alert: Alert): return investigate(alert.model_dump())
@app.get("/incidents")
def incidents():
    items = list_incidents(); return {"items": items, "total": len(items)}
@app.get("/incidents/{incident_id}")
def incident(incident_id: str):
    item = get_incident(incident_id)
    if not item: raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "Incident not found"})
    return item
@app.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, payload: dict[str, Any]):
    item = get_incident(incident_id)
    if not item: raise HTTPException(404, "Incident not found")
    item["lifecycle"] = payload.get("lifecycle", item.get("lifecycle", "TRIAGED")); return item

@app.post("/enrich")
def enrichment(req: EnrichRequest): return enrich({"source_ip": req.source_ip, "event_type": "manual_lookup"})
@app.post("/risk/score")
def score(req: RiskRequest): return evaluate(req.alert, req.threat_intelligence if req.threat_intelligence is not None else enrich(req.alert))
@app.post("/rules/evaluate")
def rule_eval(req: RiskRequest): return evaluate(req.alert, req.threat_intelligence if req.threat_intelligence is not None else enrich(req.alert))
@app.get("/rules")
def rules(): return {"items": RULES, "total": len(RULES), "enabled": sum(r["enabled"] for r in RULES), "states": list(STATES)}
@app.get("/rules/{rule_id}")
def rule(rule_id: str):
    if rule_id == "metrics": return rule_metrics()
    found = next((r for r in RULES if r["id"] == rule_id), None)
    if not found: raise HTTPException(404, "Rule not found")
    return found
@app.get("/rules/metrics")
def rule_metrics():
    items = list_incidents(); counts = {r["id"]: 0 for r in RULES}
    for incident_item in items:
        for rule_result in incident_item.get("rule_results", []):
            if rule_result.get("state") == "TRIGGERED": counts[rule_result["rule_id"]] += 1
    return {"items": [{"rule_id": r["id"], "name": r["name"], "category": r["category"], "trigger_count": counts[r["id"]]} for r in RULES]}

@app.get("/assets")
def assets(): return {"items": list_entities("assets")}
@app.post("/assets")
def create_asset(payload: EntityRequest): return save_entity("assets", {**payload.model_dump(exclude_none=True), "id": payload.id or "AST-" + uuid.uuid4().hex[:8].upper()})
@app.patch("/assets/{entity_id}")
def update_asset(entity_id: str, payload: dict[str, Any]): return save_entity("assets", {**payload, "id": entity_id})
@app.get("/accounts")
def accounts(): return {"items": list_entities("accounts")}
@app.post("/accounts")
def create_account(payload: EntityRequest): return save_entity("accounts", {**payload.model_dump(exclude_none=True), "id": payload.id or "ACC-" + uuid.uuid4().hex[:8].upper()})
@app.get("/allowlist")
def allowlist(): return {"items": list_entities("allowlist_entries")}
@app.post("/allowlist")
def create_allowlist(payload: EntityRequest): return save_entity("allowlist_entries", {**payload.model_dump(exclude_none=True), "id": payload.id or "ALW-" + uuid.uuid4().hex[:8].upper()})
@app.delete("/allowlist/{entity_id}")
def remove_allowlist(entity_id: str): return {"deleted": delete_entity("allowlist_entries", entity_id)}

@app.post("/responses/recommend")
def recommend(req: RiskRequest):
    result = evaluate(req.alert, req.threat_intelligence or enrich(req.alert)); response = {"id": "RSP-" + uuid.uuid4().hex[:8].upper(), "incident_id": req.alert.get("incident_id"), "action": "BLOCK_IOC" if result["severity"] in ("HIGH", "CRITICAL") else "REVIEW_AUTH_LOGS", "severity": result["severity"], "reason": "Generated from deterministic evidence", "approval_required": result["severity"] in ("HIGH", "CRITICAL"), "approval_status": "PENDING" if result["severity"] in ("HIGH", "CRITICAL") else "NOT_REQUIRED", "execution_status": "NOT_EXECUTED"}; return save_response(response)
@app.get("/responses")
def responses(): return {"items": list_entities("responses")}
@app.post("/responses/{response_id}/approve")
def approve(response_id: str, request: ApprovalRequest):
    item = get_response(response_id)
    if not item: raise HTTPException(404, "Response not found")
    item.update({"approval_status": "APPROVED", "approved_by": request.actor, "approval_note": request.note, "execution_status": "SIMULATED"}); return save_response(item)
@app.post("/responses/{response_id}/reject")
def reject(response_id: str, request: ApprovalRequest):
    item = get_response(response_id)
    if not item: raise HTTPException(404, "Response not found")
    item.update({"approval_status": "REJECTED", "rejected_by": request.actor, "rejection_note": request.note}); return save_response(item)

@app.post("/reports/generate")
def report(req: RiskRequest): return {"status": "generated", "format": "html", "filename": "incident-report.html", "mode": "DEMO_FIXTURE" if DEMO_MODE else "LIVE"}
@app.post("/notifications/send")
def notification(req: RiskRequest): return {"status": "stored", "mode": "DEMO_EMAIL_MODE" if DEMO_MODE else "UNAVAILABLE", "preview": {"subject": "SOC incident notification", "body": "Analyst review requested"}}
@app.get("/audit")
def audit(): return {"items": list_audit()}

def _lab_alert(event: dict[str, Any]) -> dict[str, Any]:
    source = event["source_ip"]; history = LAB_EVENT_WINDOW.setdefault(source, [])
    cutoff = time.time() - 300
    history[:] = [item for item in history if item.get("_received", time.time()) >= cutoff]
    history.append({**event, "_received": time.time()})
    failures = [item for item in history if item.get("event_type") == "AUTH_FAILURE"]
    usernames = sorted({item.get("username") for item in failures if item.get("username")})
    ports = sorted({item.get("destination_port") for item in history if item.get("event_type") == "NETWORK_CONNECTION" and item.get("destination_port")})
    event_type = event["event_type"]
    if len(failures) >= 10: event_type = "ssh_brute_force"
    elif len(usernames) >= 5: event_type = "credential_stuffing"
    if len(ports) >= 10: event_type = "port_scan"
    if event["event_type"] == "VULNERABILITY_EXPLOIT_ATTEMPT": event_type = "cve_exploit"
    if event["event_type"] == "C2_BEACON": event_type = "c2_beacon"
    privileged = str(event.get("username", "")).lower() in {"root", "admin", "security_admin", "administrator"}
    return {
        "source_ip": source, "destination_ip": event.get("destination_ip") or "172.30.0.20", "event_type": event_type,
        "failed_attempts": len(failures), "usernames": usernames, "username": event.get("username"),
        "privilege": "admin" if privileged else event.get("user_role"), "unique_ports": len(ports),
        "asset_criticality": event.get("asset_criticality", 5), "asset_type": event.get("asset_type", "authentication_server" if event.get("target_asset") == "AUTH-SERVER-01" else "critical_application"),
        "hostname": event.get("target_asset"), "malware_communication": event["event_type"] == "C2_BEACON", "c2_signal": event["event_type"] == "C2_BEACON",
        "malicious_ioc": event["event_type"] in {"C2_BEACON", "VULNERABILITY_EXPLOIT_ATTEMPT"}, "cve": event.get("cve"), "cvss": event.get("cvss"),
        "exploit_behavior": event["event_type"] == "VULNERABILITY_EXPLOIT_ATTEMPT", "alert_count": len(history),
        "allowlisted": event.get("scenario") == "allowlisted_scanner", "allowlist_match": "AUTHORIZED-SCANNER" if event.get("scenario") == "allowlisted_scanner" else None,
        "description": "LAB SIMULATION: telemetry aggregated from isolated target activity", "scenario": event.get("scenario"), "iocs": [{"type": "lab", "value": event.get("target_asset")}]
    }

@app.post("/lab/events")
def ingest_lab_event(event: LabEvent):
    payload = event.model_dump(); save_lab_event(payload, processed=False)
    publish_lab({"kind": "TELEMETRY", **payload})
    alert = _lab_alert(payload)
    risk = evaluate(alert, {})
    publish_lab({"kind": "RISK_UPDATED", "event_id": payload["event_id"], "risk": risk, "timestamp": payload["timestamp"]})
    incident = None
    meaningful = risk["severity"] in {"HIGH", "CRITICAL"} or alert["alert_count"] >= 20 or payload["event_type"] in {"VULNERABILITY_EXPLOIT_ATTEMPT", "C2_BEACON"} or (payload["event_type"] == "NETWORK_CONNECTION" and alert["unique_ports"] >= 10)
    if meaningful:
        incident = investigate(alert, payload.get("scenario"))
        save_lab_event(payload, incident["incident_id"], processed=True)
        publish_lab({"kind": "INCIDENT_CREATED", "event_id": payload["event_id"], "incident_id": incident["incident_id"], "risk": incident["risk"], "timestamp": payload["timestamp"]})
    else:
        save_lab_event(payload, processed=True)
    return {"accepted": True, "event_id": payload["event_id"], "risk": risk, "incident": incident}

@app.get("/lab/events")
def lab_events(limit: int = 200): return {"items": list_lab_events(max(1, min(limit, 1000)))}

@app.post("/lab/reset")
def reset_lab(clear_events: bool = True):
    LAB_EVENT_WINDOW.clear(); removed = clear_lab_events() if clear_events else 0
    if LAB_CONTROLLER_URL:
        try: httpx.post(f"{LAB_CONTROLLER_URL}/reset", timeout=3)
        except httpx.HTTPError: pass
    publish_lab({"kind": "LAB_RESET", "removed_events": removed, "timestamp": time.time()})
    return {"reset": True, "removed_events": removed, "preserved_incidents": True}

@app.post("/lab/scenarios/{scenario}")
def run_lab_scenario(scenario: str):
    allowed = {"normal_login", "brute_force", "credential_stuffing", "port_scan", "c2_simulation", "cve_lab", "privileged_account", "allowlisted_scanner", "alert_burst"}
    if scenario not in allowed: raise HTTPException(404, "Unknown lab scenario")
    if not LAB_MODE: raise HTTPException(409, "LAB_MODE is not active")
    if not LAB_CONTROLLER_URL: raise HTTPException(503, "Lab controller is not connected; start docker-compose.lab.yml")
    try:
        response = httpx.post(f"{LAB_CONTROLLER_URL}/scenarios/{scenario}", timeout=10)
        response.raise_for_status(); return response.json()
    except httpx.HTTPError as exc: raise HTTPException(503, f"Lab controller unavailable: {exc}")

@app.get("/automation/inbox")
def automation_inbox():
    items = [i for i in list_incidents() if i.get("risk", {}).get("severity") in {"HIGH", "CRITICAL"}]
    return {"items": [{"incident_id": i["incident_id"], "severity": i["risk"]["severity"], "status": AUTOMATION_CLAIMS.get(i["incident_id"], {}).get("status", "UNCLAIMED")} for i in items]}
@app.post("/automation/claim")
def automation_claim(payload: dict[str, str]):
    incident_id = payload.get("incident_id"); if_missing = not incident_id or not get_incident(incident_id)
    if if_missing: raise HTTPException(404, "Incident not found")
    AUTOMATION_CLAIMS[incident_id] = {"status": "CLAIMED", "claimed_by": payload.get("worker", "uipath")}; return {"incident_id": incident_id, **AUTOMATION_CLAIMS[incident_id]}
@app.post("/automation/complete")
def automation_complete(payload: dict[str, str]):
    incident_id = payload.get("incident_id"); if_missing = not incident_id or not get_incident(incident_id)
    if if_missing: raise HTTPException(404, "Incident not found")
    AUTOMATION_CLAIMS[incident_id] = {"status": "COMPLETED", "completed_by": payload.get("worker", "uipath"), "report": payload.get("report", "generated")}; return {"incident_id": incident_id, **AUTOMATION_CLAIMS[incident_id]}

@app.post("/demo/run/{scenario}")
def demo(scenario: str):
    if scenario not in SCENARIOS: raise HTTPException(404, "Unknown scenario")
    alert = dict(SCENARIOS[scenario]); alert["scenario"] = scenario; return investigate(alert, scenario)
@app.post("/demo/run-all")
def demo_all(): return {"items": [investigate(dict(alert, scenario=name), name) for name, alert in SCENARIOS.items()]}

@app.get("/dashboard/metrics")
def metrics():
    items = list_incidents(); severity = {s: sum(1 for i in items if i["risk"]["severity"] == s) for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}; avg = round(sum(i["risk"]["score"] for i in items) / len(items), 1) if items else 0
    return {"total_incidents": len(items), "open_incidents": sum(1 for i in items if i.get("lifecycle") not in ("CLOSED", "RESOLVED")), "average_risk": avg, "severity_distribution": severity, "automation_success_rate": 100 if items else 0, "time_saved_seconds": max(0, len(items) * 855), "rule_count": len(RULES), "provider_availability": 100 if DEMO_MODE else 0, "incidents_per_day": [{"day": "Today", "count": len(items)}]}
@app.get("/analytics")
def analytics(): return metrics()
@app.get("/analytics/rules")
def analytics_rules(): return rule_metrics()
