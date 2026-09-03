"""
CyberShield AI — FastAPI Backend Bridge & SSE Streaming Server
================================================================
Exposes REST and Server-Sent Events (SSE) endpoints for the Next.js 15
frontend to trigger scans, stream real-time progress, and download reports.

Endpoints:
  POST /api/scan/start    — Initiates a background scan
  GET  /api/scan/stream   — SSE stream pushing live agent progress & final state
  GET  /api/reports/{path} — Serves generated PDF audit reports

Usage:
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
import os
import json
import asyncio
import logging
from typing import AsyncGenerator
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel

from models import ScanState
from agents.orchestrator import run_full_scan

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cybershield_server")

app = FastAPI(title="CyberShield AI API", version="1.0.0")

# Enable CORS for Next.js frontend (localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str
    authorized: bool = True
    scope_type: str = "passive_only"  # passive_only | full_pentest
    contact_email: str = ""
    use_mock: bool = False


# Active scan event queues keyed by domain/scan_id
_scan_event_queues: dict[str, asyncio.Queue] = {}


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
        "controls": controls_data,
        "status": getattr(p, "status", "success"),
    }


def _serialize_state(state: ScanState) -> dict:
    return {
        "domain": state.domain,
        "authorized": state.authorized,
        "scope_type": state.scope_type,
        "timestamp": state.timestamp,
        "scan_progress": state.scan_progress,
        "all_findings": [_serialize_finding(f) for f in state.all_findings],
        "visual": _serialize_visual(state.visual),
        "pisf": _serialize_pisf(state.pisf),
        "security_score": state.report.security_posture_score if state.report else 0.0,
        "executive_summary": state.report.executive_summary if state.report else "",
        "pdf_path": state.report.pdf_path if state.report else None,
        "ai_model_used": getattr(state.report, "ai_model_used", "OFFLINE_DETERMINISTIC") if state.report else "OFFLINE_DETERMINISTIC",
        "fallback_triggered": getattr(state.report, "fallback_triggered", False) if state.report else False,
    }



@app.get("/api/health")
def health():
    return {"status": "online", "system": "CyberShield AI Backend Bridge"}


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    """Start scan and stream progress via SSE."""
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    return {
        "status": "initiated",
        "domain": domain,
        "message": f"Scan initiated for {domain}",
    }


@app.get("/api/scan/stream")
async def stream_scan(
    domain: str = Query(..., description="Target domain name"),
    authorized: bool = Query(True),
    scope_type: str = Query("passive_only"),
    contact_email: str = Query(""),
    use_mock: bool = Query(False),
    ai_model: str = Query("gemma4:31b-cloud"),
):
    """SSE endpoint: Streams real-time scan progress to frontend."""
    if ai_model:
        os.environ["LLM_MODEL"] = ai_model
        os.environ["QWEN_MODEL"] = ai_model

    queue = asyncio.Queue()

    loop = asyncio.get_event_loop()

    def progress_callback(stage: str, msg: str):
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "progress", "stage": stage, "message": msg}
        )

    clean_domain = domain.strip().lower()
    for prefix in ["https://", "http://", "www."]:
        if clean_domain.startswith(prefix):
            clean_domain = clean_domain[len(prefix):]
    clean_domain = clean_domain.split("/")[0].strip()
    if not clean_domain:
        clean_domain = "target.local"

    async def run_scan_async():
        try:
            state = await loop.run_in_executor(
                None,
                lambda: run_full_scan(
                    domain=clean_domain,
                    authorized=authorized,
                    scope_type=scope_type,
                    contact_email=contact_email,
                    use_mock=use_mock,
                    progress_callback=progress_callback,
                )
            )
            # Send final state payload
            serialized = _serialize_state(state)
            await queue.put({"type": "complete", "state": serialized})
        except Exception as err:
            logger.error("Scan error: %s", err)
            await queue.put({"type": "error", "message": str(err)})

    # Launch scan in background task
    asyncio.create_task(run_scan_async())

    async def event_generator() -> AsyncGenerator[str, None]:
        while True:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=15.0)
                yield f"data: {json.dumps(data)}\n\n"
                if data.get("type") in ("complete", "error"):
                    break
            except asyncio.TimeoutError:
                # SSE Heartbeat comment to keep HTTP connection alive during long operations
                yield ": heartbeat\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/reports/download")
def download_report(pdf_path: str = Query(...)):
    """Serve PDF report file for download."""
    if not os.path.isabs(pdf_path):
        pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), pdf_path)

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report file not found")

    filename = os.path.basename(pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename=filename)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
