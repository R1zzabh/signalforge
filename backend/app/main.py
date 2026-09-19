"""SignalForge HTTP API.

The API keeps DEMO_MODE deterministic and exposes the same contracts that live
adapters and UiPath consume.  Mutating operational actions remain auditable and
approval-gated.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict

from .config import DEMO_MODE, FRONTEND_ORIGIN, OPENAI_API_KEY
from .database.db import (delete_entity, get_incident, get_response, init_db, list_audit,
                          list_entities, list_incidents, save_entity, save_response)
from .rules.engine import RULES, STATES, evaluate
from .services.pipeline import SCENARIOS, enrich, investigate

app = FastAPI(title="SignalForge SOC Automation Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000"], allow_methods=["*"], allow_headers=["*"])
init_db()

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

def error(code: str, message: str): return JSONResponse(status_code=400, content={"error": {"code": code, "message": message, "request_id": "generated"}})

@app.get("/health")
def health(): return {"status": "ok", "service": "signalforge-backend", "version": app.version}

@app.get("/system/status")
def status():
    mode = "DEMO" if DEMO_MODE else "LIVE"
    return {"mode": mode, "database": "sqlite", "rule_engine": {"status": "ready", "rules": len(RULES), "states": list(STATES)}, "ai": "fallback" if DEMO_MODE else ("configured" if OPENAI_API_KEY else "UNAVAILABLE"), "providers": providers_status()}

def providers_status():
    return {name: {"provider": name, "status": "DEMO_FIXTURE" if DEMO_MODE else "UNAVAILABLE", "mode": "DEMO" if DEMO_MODE else "LIVE"} for name in ("VirusTotal", "AbuseIPDB", "NVD", "GeoIP", "MITRE", "OpenAI", "Outlook")}

@app.get("/providers/status")
def provider_status(): return {"items": list(providers_status().values())}

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
