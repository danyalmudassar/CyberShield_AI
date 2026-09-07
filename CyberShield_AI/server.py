"""Authenticated scan jobs, replayable SSE, and owner-checked PDF downloads.

Browser sessions: POST /api/v1/auth/login, GET /api/v1/auth/me,
POST /api/v1/auth/logout. Create jobs with POST /api/scans; observe them at
GET /api/scans/{scan_id} and /events, download via /report.

The legacy filename download remains authenticated and checks registered
ownership, basename-only PDF paths and realpath containment.
Local entry point: uvicorn server:app --host 127.0.0.1 --port 8000
"""

import time
import sqlite3
from uuid import uuid4
from services.telemetry import event, observe_request, request_metrics

import sys
import os
import json
import asyncio
import logging
from typing import Literal
from contextlib import asynccontextmanager
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Query, Request, Response, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, ConfigDict, Field

from models import ScanState
from services.scan_store import ScanStore, TERMINAL_STATES, QueueCapacityError
from services.scan_worker import ScanWorker
from utils.target_policy import normalize_target, validate_target

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cybershield_server")

@asynccontextmanager
async def lifespan(app):
    initialize_auth()
    store = ScanStore(os.getenv("CYBERSHIELD_DB", os.path.join(os.path.dirname(__file__), "data", "scans.sqlite3")))
    app.state.scan_store = store
    worker = ScanWorker(store, _serialize_state)
    app.state.scan_worker = worker
    worker.start()
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(title="CyberShield AI API", version="1.1.0", lifespan=lifespan)

# Enable CORS for Next.js frontend (localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CYBERSHIELD_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def private_response_headers(request, call_next):
    request_id = uuid4().hex
    started = time.monotonic()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers['X-Request-ID'] = request_id
    finally:
        duration = round(time.monotonic() - started, 6)
        route = getattr(request.scope.get('route'), 'path', 'unmatched')
        method = request.method if request.method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS') else 'OTHER'
        observe_request(route, method, status, duration)
        event('http_response', request_id=request_id, route=route, method=method,
              status=status, duration_seconds=duration)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=1, max_length=2048)
    authorized: bool = False
    scope_type: Literal["passive_only", "full_pentest"] = "passive_only"
    contact_email: str = Field(default="", max_length=254)
    execution_mode: Literal["live", "rules_only", "demo"] = "live"
    strict_live: bool = False
    max_duration_seconds: int = Field(default=300, ge=1, le=900, strict=True)
    max_stage_seconds: int = Field(default=120, ge=1, le=300, strict=True)
    ai_model: str | None = Field(default=None, max_length=100, pattern=r"^[a-zA-Z0-9_.:/-]+$")


from utils.auth_manager import (
    authenticate_user, register_user,
    create_token,
    revoke_token,
    get_current_user,
    require_user,
    COOKIE_NAME, SESSION_SECONDS, initialize_auth,
    request_token, enforce_request_origin, check_login_limit,
)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    delivery: Literal["cookie", "bearer"] = "cookie"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)


def operator(request: Request):
    """All scan/report endpoints require an authenticated identity."""
    user = require_user(request)
    return None if user.role == "admin" else user.email


def scan_store(request: Request):
    store = getattr(request.app.state, "scan_store", None)
    if store is None:
        raise HTTPException(503, "Scan worker not initialized")
    return store


def _serialize_finding(f) -> dict:
    """Helper to convert Finding dataclass object to JSON dict."""
    return {
        "finding_id": getattr(f, "finding_id", ""),
        "check_id": getattr(f, "check_id", ""),
        "title": getattr(f, "title", ""),
        "severity": getattr(f, "severity", "Info"),
        "cvss_score": getattr(f, "cvss_score", 0.0),
        "cvss_vector": getattr(f, "cvss_vector", ""),
        "owasp_top10": getattr(f, "owasp_top10", ""),
        "wstg_id": getattr(f, "wstg_id", ""),
        "cwe_id": getattr(f, "cwe_id", ""),
        "pisf_control": getattr(f, "pisf_control", ""),
        "description": getattr(f, "description", ""),
        "evidence": getattr(f, "evidence", ""),
        "business_impact": getattr(f, "business_impact", ""),
        "remediation": getattr(f, "remediation", ""),
        "remediation_priority": getattr(f, "remediation_priority", "MONTH 1"),
        "provenance": getattr(f, "provenance", "OFFLINE_VERIFIER"),
        "check_status": getattr(f, "check_status", "UNKNOWN"),
        "url": getattr(f, "url", ""),
        "parameter": getattr(f, "parameter", ""),
    }




def _serialize_visual(v) -> dict | None:
    if not v:
        return None
    return {
        "admin_panel_detected": getattr(v, "admin_panel_detected", False),
        "https_padlock": getattr(v, "https_padlock", False),
        "captcha_present": getattr(v, "captcha_present", False),
        "third_party_scripts": getattr(v, "third_party_scripts", []),
        "suspicious_elements": getattr(v, "suspicious_elements", []),
        "sensitive_info_exposed": getattr(v, "sensitive_info_exposed", []),
        "cookie_consent": getattr(v, "cookie_consent", False),
        "mixed_content": getattr(v, "mixed_content", False),
        "visual_findings": getattr(v, "visual_findings", []),
        "status": getattr(v, "status", "success"),
    }


def _serialize_pisf(p) -> dict | None:
    if not p:
        return None
    controls_data = []
    for c in getattr(p, "controls", []):
        controls_data.append({
            "control_id": getattr(c, "control_id", 0),
            "name": getattr(c, "name", ""),
            "domain": getattr(c, "domain", ""),
            "status": getattr(c, "status", "NOT_ASSESSABLE"),
            "evidence": getattr(c, "evidence", ""),
            "recommendation": getattr(c, "recommendation", ""),
            "international_mapping": getattr(c, "international_mapping", {}),
        })
    return {
        "overall_score": getattr(p, "overall_score", 0.0),
        "compliant_controls": getattr(p, "compliant_controls", 0),
        "total_controls": getattr(p, "total_controls", 12),
        "assessable_controls_count": getattr(p, "assessable_controls_count", 0),
        "controls": controls_data,
        "status": getattr(p, "status", "success"),
        "assessment_type": "technical_assessment",
        "mapping_status": "project_defined_unverified",
    }


def _serialize_state(state: ScanState) -> dict:
    return {
        "domain": state.domain,
        "authorized": state.authorized,
        "scope_type": state.scope_type,
        "execution_mode": state.execution_mode,
        "strict_live": state.strict_live,
        "timestamp": state.timestamp,
        "scan_progress": state.scan_progress,
        "all_findings": [_serialize_finding(f) for f in state.all_findings],
        "visual": _serialize_visual(state.visual),
        "pisf": _serialize_pisf(state.pisf),
        "security_score": state.report.security_posture_score if state.report else 0.0,
        "executive_summary": state.report.executive_summary if state.report else "",
        "pdf_path": os.path.basename(state.report.pdf_path) if state.report and state.report.pdf_path else None,
        "report_status": state.report.status if state.report else "unavailable",
        "ai_model_used": getattr(state.report, "ai_model_used", "OFFLINE_DETERMINISTIC") if state.report else "OFFLINE_DETERMINISTIC",
        "fallback_triggered": getattr(state.report, "fallback_triggered", False) if state.report else False,
    }



@app.get("/api/health")
def health():
    return {"status": "online", "system": "CyberShield AI Backend Bridge"}


def _operational_status(request):
    worker = getattr(request.app.state, 'scan_worker', None)
    store = getattr(request.app.state, 'scan_store', None)
    state = worker.readiness() if worker is not None else {'ready': False}
    counts = {}
    database_ready = False
    if store is not None:
        try:
            from contextlib import closing
            from pathlib import Path
            with closing(sqlite3.connect(Path(store.path).resolve().as_uri() + '?mode=ro', uri=True, timeout=1)) as conn:
                counts = dict(conn.execute('SELECT status, COUNT(*) FROM scans GROUP BY status'))
            database_ready = True
        except sqlite3.Error:
            pass
    return {'ready': state['ready'] and database_ready, 'worker': state,
            'database_ready': database_ready, 'scans_by_status': counts,
            'max_pending': store.max_pending if store is not None else None}


@app.get('/api/ready')
def readiness(request: Request, response: Response):
    ready = _operational_status(request)['ready']
    response.status_code = 200 if ready else 503
    return {'status': 'ready' if ready else 'not_ready'}


@app.get('/api/operations')
def operations(request: Request, user=Depends(require_user)):
    if user.role != 'admin':
        raise HTTPException(403, 'Administrator access required')
    return {**_operational_status(request), 'http_requests': request_metrics()}


@app.post("/api/v1/auth/login")
@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    enforce_request_origin(request, browser_login=req.delivery == "cookie")
    check_login_limit(req.email, request.client.host if request.client else "unknown")
    user = authenticate_user(req.email, req.password)
    if not user:
        raise HTTPException(401, "Invalid email or password")
    return _issue_session(user, request, response, req.delivery)


def _issue_session(user, request, response, delivery="cookie"):
    # Rotate an existing browser session on reauthentication/account switch.
    previous = request.cookies.get(COOKIE_NAME)
    if previous:
        revoke_token(previous)
    token = create_token(user.user_id, user.email, user.role)
    result = {"user_id": user.user_id, "email": user.email, "role": user.role}
    response.headers["Cache-Control"] = "no-store"
    if delivery == "bearer":
        result["token"] = token
    else:
        response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS,
                            httponly=True, samesite="strict", path="/api",
                            secure=os.getenv("CYBERSHIELD_COOKIE_SECURE", "true").lower() != "false")
    return result


@app.post("/api/v1/auth/register", status_code=201)
@app.post("/api/auth/register", status_code=201)
def register(req: RegisterRequest, request: Request, response: Response):
    enforce_request_origin(request, browser_login=True)
    check_login_limit(req.email, request.client.host if request.client else "unknown")
    user = register_user(req.email, req.password)
    return _issue_session(user, request, response)


@app.post("/api/v1/auth/logout")
@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user=Depends(require_user)):
    if user.user_id == "usr_operator_api":
        raise HTTPException(400, "Static API tokens must be rotated in deployment configuration")
    revoke_token(request_token(request))
    response.delete_cookie(COOKIE_NAME, path="/api", httponly=True, samesite="strict",
                           secure=os.getenv("CYBERSHIELD_COOKIE_SECURE", "true").lower() != "false")
    response.headers["Cache-Control"] = "no-store"
    return {"status": "logged_out"}


@app.get("/api/v1/auth/me")
@app.get("/api/auth/me")
def get_me(user=Depends(require_user)):
    return {
        "user_id": user.user_id,
        "email": user.email,
        "role": user.role,
    }


@app.post("/api/scans", status_code=202)
def create_scan(req: ScanRequest, owner=Depends(operator), store=Depends(scan_store), idempotency_key: str | None = Header(default=None)):
    if os.getenv("CYBERSHIELD_DEMO_ONLY", "false").lower() == "true" and req.execution_mode != "demo":
        raise HTTPException(403, "This instance is configured for fixture-only demonstrations")
    if not req.authorized:
        raise HTTPException(403, "Explicit target authorization is required")
    if req.execution_mode == "demo" and req.strict_live:
        raise HTTPException(422, "Demo cannot use strict-live policy")
    try:
        target = normalize_target(req.domain) if req.execution_mode == "demo" else validate_target(req.domain, allow_private=os.getenv("CYBERSHIELD_ALLOW_PRIVATE", "false").lower() == "true")
        # The present scanners operate on hosts; reject narrower scopes rather
        # than silently discarding a user-supplied path.
        from urllib.parse import urlsplit
        parts = urlsplit(target.url)
        if parts.path not in ("", "/") or parts.query:
            raise ValueError("This scanner currently supports whole-host scope only")
        config = req.model_dump()
        config["domain"] = target.authority
        config["target_url"] = target.url
        config["scope_target"] = req.domain.strip()
        if idempotency_key and len(idempotency_key) > 128:
            raise ValueError("Idempotency key is too long")
        return store.create_scan(config, owner or "admin@cybershield.ai", idempotency_key)
    except QueueCapacityError as exc:
        raise HTTPException(429, str(exc), headers={"Retry-After": "5"}) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/api/scans")
def list_scans(owner=Depends(operator), store=Depends(scan_store)):
    return store.list_scans(owner=owner)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, owner=Depends(operator), store=Depends(scan_store)):
    scan = store.get_scan(scan_id, owner)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, owner=Depends(operator), store=Depends(scan_store)):
    scan = store.cancel_scan(scan_id, owner)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request, after: int = Query(0, ge=0), owner=Depends(operator), store=Depends(scan_store)):
    get_scan(scan_id, owner, store)
    try:
        cursor = max(after, int(request.headers.get("last-event-id", "0")))
    except ValueError as exc:
        raise HTTPException(400, "Invalid event cursor") from exc
    async def stream():
        nonlocal cursor
        heartbeat = 0
        while not await request.is_disconnected():
            # Recheck persistent revocation/expiry before releasing each batch.
            if get_current_user(request) is None:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Session expired. Sign in again.', 'code': 'AUTH_REQUIRED'})}\n\n"
                break
            rows = store.events_after(scan_id, cursor)
            for row in rows:
                cursor = row['id']
                yield f"id: {cursor}\ndata: {json.dumps(row)}\n\n"
                if row.get('type') == 'complete':
                    return
            current = store.get_scan(scan_id, owner)
            if current is None or current['status'] in TERMINAL_STATES:
                # Covers interrupted jobs after restart and the brief gap
                # between terminal state persistence and terminal event write.
                yield f"data: {json.dumps({'type': 'complete', 'status': current['status'] if current else 'failed', 'state': current['result'] if current else None, 'error': current['error'] if current else 'Scan unavailable'})}\n\n"
                break
            heartbeat += 1
            if heartbeat >= 30:
                yield ": heartbeat\n\n"
                heartbeat = 0
            await asyncio.sleep(0.5)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: str, owner=Depends(operator), store=Depends(scan_store)):
    scan = get_scan(scan_id, owner, store)
    filename = (scan.get('result') or {}).get('pdf_path')
    if not filename:
        raise HTTPException(404, "Report unavailable")
    return download_report(filename, owner, store)


@app.get("/api/scan/stream")
def retired_stream():
    raise HTTPException(410, "Create a scan with POST /api/scans, then subscribe to its events")


# Server-owned directory for all generated PDF reports.
# Files outside this directory can never be served regardless of caller input.
_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(_SERVER_DIR, "reports")


@app.get("/api/reports/download")
def download_report(
    filename: str = Query(..., description="Basename of the PDF report (no path separators)"),
    owner=Depends(operator),
    store=Depends(scan_store),
):
    """Serve a generated PDF audit report by opaque filename.

    Security constraints enforced here:
    - ``filename`` must be a plain basename (no ``/``, ``\\", or leading ``.``).
    - Must end with ``.pdf``.
    - Resolved real path must remain inside REPORTS_DIR (symlink-safe).
    - Caller must be authorized to access the scan owning this PDF.
    """
    # 1. Reject any path separators or leading dots (traversal / hidden-file attempts).
    if os.sep in filename or "/" in filename or "\\" in filename or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid report filename")

    # 2. Require .pdf extension.
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF reports can be downloaded")

    # 3. Resolve full path and verify containment (guards against symlink escape).
    resolved = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    reports_real = os.path.realpath(REPORTS_DIR)
    if not resolved.startswith(reports_real + os.sep) and resolved != reports_real:
        logger.warning("Report download rejected: path escape attempt for filename=%r", filename)
        raise HTTPException(status_code=404, detail="PDF report file not found")

    # 4. File must exist.
    if not os.path.isfile(resolved):
        raise HTTPException(status_code=404, detail="PDF report file not found")

    # 5. Enforce strict report ownership authorization & scan registration
    matching = store.get_scan_by_pdf(filename)
    if matching is None:
        raise HTTPException(status_code=404, detail="PDF report not registered to any scan")

    scan_owner = matching.get("owner")
    if not scan_owner:
        raise HTTPException(status_code=403, detail="PDF report has no valid owner")

    if owner is not None:
        if scan_owner != owner:
            raise HTTPException(status_code=403, detail="You do not have permission to download this report")

    return FileResponse(resolved, media_type="application/pdf", filename=filename)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
