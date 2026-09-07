"""
CyberShield AI — Reconnaissance Agent
======================================
Executes passive & active reconnaissance phase:
  1. DNS Reconnaissance (A, MX, TXT, NS, SPF, DMARC)
  2. SSL/TLS Certificate & Cipher Check
  3. HTTP Security Headers Scan (6 OWASP headers)
  4. Technology Stack Fingerprinting
  5. AI Reasoning & Threat Analysis via utils.ai_provider (default: gemma4:31b-cloud)

Output: Structured dictionary containing all findings, scores, and AI reasoning.
"""

import sys
import os
import json
import logging
from typing import Dict, Any, List, Optional

# Fix import path when running from agents/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Finding, DnsResult, SslResult, HeaderResult, TechResult
from utils.dns_recon import run_dns_recon
from utils.ssl_checker import run_ssl_check
from utils.header_scanner import run_header_scan
from utils.tech_fingerprint import run_tech_fingerprint
from utils.ai_provider import call_llm_json, configured_model
from utils.http_client import check_target_reachability

logger = logging.getLogger(__name__)

# Project Root & Mocks Path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK_QWEN_PATH = os.path.join(PROJECT_ROOT, "mocks", "mock_qwen_response.json")


def _load_mock_qwen() -> Dict[str, Any]:
    """Load mock analysis from mocks/mock_qwen_response.json."""
    try:
        if os.path.exists(MOCK_QWEN_PATH):
            with open(MOCK_QWEN_PATH, "r") as f:
                return json.load(f)
    except Exception as err:
        logger.error("Failed to load mock Qwen analysis: %s", err)
    return {
        "status": "mock",
        "executive_summary": "Reconnaissance completed via mock fallback.",
        "findings": []
    }


def _build_ai_prompt(recon_data: Dict[str, Any]) -> str:
    """Build AI prompt from reconnaissance data."""
    domain = recon_data.get("domain", "target")
    headers = recon_data.get("headers", {})
    ssl_info = recon_data.get("ssl", {})
    tech = recon_data.get("tech", {})
    dns = recon_data.get("dns", {})

    # Read missing_headers from the real model field (HeaderResult.missing_headers).
    # Prefer the dataclass attribute; fall back gracefully for dict inputs.
    if isinstance(headers, dict):
        missing_headers = headers.get("missing_headers", [])
    else:
        missing_headers = getattr(headers, "missing_headers", [])

    server_hdr = headers.get("server_header", "Unknown") if isinstance(headers, dict) else getattr(headers, "server_header", "Unknown")
    valid_ssl = ssl_info.get("valid", False) if isinstance(ssl_info, dict) else getattr(ssl_info, "valid", False)
    if isinstance(tech, dict):
        detected_tech = tech.get("technologies") or tech.get("detected_technologies") or []
    else:
        detected_tech = getattr(tech, "technologies", None) or getattr(tech, "detected_technologies", [])

    if isinstance(dns, dict):
        mx_records = dns.get("mx_records") or dns.get("mx") or []
    else:
        mx_records = getattr(dns, "mx_records", None) or getattr(dns, "mx", [])

    prompt = (
        f"Perform cybersecurity analysis for target domain: '{domain}'.\n"
        f"Recon Data:\n"
        f"- Missing Security Headers: {missing_headers}\n"
        f"- Server Banner: {server_hdr}\n"
        f"- SSL Valid: {valid_ssl}\n"
        f"- Detected Tech Stack: {detected_tech}\n"
        f"- MX Records Present: {bool(mx_records)}\n\n"
        f"Return JSON format with keys: 'executive_summary', 'critical_findings', 'recommendations'."
    )
    return prompt


def _call_qwen_analysis(prompt: str, use_mock: bool = False, strict_live: bool = False) -> Dict[str, Any]:
    """Send recon prompt to model-agnostic LLM provider (gemma4:31b-cloud default)."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    system_prompt = (
        "You are CyberShield AI, a cybersecurity analysis engine. "
        "Analyze the reconnaissance data and provide security findings in structured JSON format."
    )
    return call_llm_json(prompt, system_prompt=system_prompt, use_mock=use_mock, timeout=30, strict_live=strict)


def _generate_findings_from_recon(
    domain: str, dns_res: Any, ssl_res: Any, hdr_res: Any, tech_res: Any, use_mock: bool = False
) -> List[Finding]:
    """Generate standardized Finding objects from raw recon results."""
    findings: List[Finding] = []
    prov = "MOCK_FALLBACK" if use_mock else "OFFLINE_VERIFIER"
    chk_st = "MOCK_FALLBACK" if use_mock else "VULNERABLE"

    # SSL Findings
    # Only create a finding when the probe itself succeeded (status != "error").
    # A failed probe (connection refused, DNS failure, timeout) means the
    # certificate state is NOT_ASSESSABLE — it must not appear as a confirmed
    # "Invalid or Missing SSL Certificate" finding.
    ssl_valid = ssl_res.get("valid", False) if isinstance(ssl_res, dict) else getattr(ssl_res, "valid", False)
    ssl_status = ssl_res.get("status", "success") if isinstance(ssl_res, dict) else getattr(ssl_res, "status", "success")
    if not ssl_valid and ssl_status != "error":
        findings.append(
            Finding(
                finding_id=f"CYBERSHIELD-R001",
                check_id="R-001",
                title="Invalid or Missing SSL Certificate",
                severity="High",
                cvss_score=7.5,
                owasp_top10="A02:2021 – Cryptographic Failures",
                wstg_id="WSTG-CRYP-01",
                cwe_id="CWE-295",
                pisf_control="Control 4: Cryptography",
                description=f"Target domain '{domain}' lacks a valid SSL/TLS certificate.",
                evidence=str(ssl_res.get("error", "SSL invalid") if isinstance(ssl_res, dict) else getattr(ssl_res, "error", "SSL invalid")),
                remediation="Provision a valid TLS certificate (e.g. via Let's Encrypt) and enable HTTPS.",
                remediation_priority="WEEK 1",
                provenance=prov,
                check_status=chk_st,
            )
        )

    # Missing Security Headers Findings
    # Read from the real missing_headers field (now present on HeaderResult).
    if isinstance(hdr_res, dict):
        missing_headers = hdr_res.get("missing_headers", [])
    else:
        missing_headers = getattr(hdr_res, "missing_headers", [])

    if missing_headers:
        findings.append(
            Finding(
                finding_id="CYBERSHIELD-R002",
                check_id="R-002",
                title=f"Missing Critical Security Headers ({len(missing_headers)})",
                severity="Medium",
                cvss_score=5.4,
                owasp_top10="A05:2021 – Security Misconfiguration",
                wstg_id="WSTG-CONF-07",
                cwe_id="CWE-693",
                pisf_control="Control 6: Operations Security",
                description=f"Target missing standard security headers: {', '.join(missing_headers)}",
                evidence=f"Missing: {', '.join(missing_headers)}",
                remediation="Configure web server (Nginx/Apache) to append security headers.",
                remediation_priority="MONTH 1",
                provenance=prov,
                check_status=chk_st,
            )
        )

    # Exposed Server Header
    server_hdr = hdr_res.get("server_header") if isinstance(hdr_res, dict) else getattr(hdr_res, "server_header", None)
    if server_hdr:
        findings.append(
            Finding(
                finding_id="CYBERSHIELD-R003",
                check_id="R-003",
                title="Server Information Disclosure Banner",
                severity="Low",
                cvss_score=3.7,
                owasp_top10="A05:2021 – Security Misconfiguration",
                wstg_id="WSTG-INFO-02",
                cwe_id="CWE-200",
                pisf_control="Control 6: Operations Security",
                description=f"Web server discloses software banner: {server_hdr}",
                evidence=f"Server: {server_hdr}",
                remediation="Obscure or disable the 'Server' HTTP header in production.",
                remediation_priority="MONTH 3",
                provenance=prov,
                check_status=chk_st,
            )
        )

    return findings


from utils.target_policy import target_scoped

@target_scoped
def run_recon(
    domain: str,
    use_mock: bool = False,
    strict_live: bool = False,
    use_ai: bool = True,
) -> Dict[str, Any]:
    """Execute complete reconnaissance stage for a target domain.

    Args:
        domain: Domain name or IP address.
        use_mock: If True, use built-in mock data for testing.
        strict_live: If True, raise RuntimeError on mock usage or LLM API failure.
        use_ai: If False, skip AI calls and return deterministic rules provenance.

    Returns:
        dict with keys: dns, ssl, headers, tech, findings, ai_analysis, data_sources.
    """
    logger.info("[recon_agent] Starting reconnaissance for %s (use_mock=%s, strict_live=%s, use_ai=%s)", domain, use_mock, strict_live, use_ai)
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")

    if use_mock and strict:
        raise RuntimeError("STRICT_LIVE_MODE: Mock recon execution is disabled in strict live mode.")

    # Pre-flight reachability check for live execution
    if not use_mock:
        reachable, reach_err = check_target_reachability(domain, timeout=3)
        if not reachable:
            logger.warning("[recon_agent] Target %s is completely unreachable (%s). Short-circuiting recon sub-scanners.", domain, reach_err)
            if strict:
                raise RuntimeError(f"STRICT_LIVE_MODE: Recon target {domain} is unreachable: {reach_err}")

            dns_res = DnsResult(status="error")
            ssl_res = SslResult(valid=False, status="error")
            hdr_res = HeaderResult(status="error")
            tech_res = TechResult(status="error")
            findings = _generate_findings_from_recon(domain, dns_res, ssl_res, hdr_res, tech_res, use_mock=use_mock)
            ai_analysis = {"status": "disabled", "executive_summary": "AI reasoning disabled.", "_provenance": "DETERMINISTIC_RULES"}
            active_model = "disabled"

            return {
                "domain": domain,
                "dns": dns_res,
                "ssl": ssl_res,
                "headers": hdr_res,
                "tech": tech_res,
                "findings": findings,
                "ai_analysis": ai_analysis,
                "data_sources": {
                    "recon_dns": "degraded",
                    "recon_ssl": "degraded",
                    "recon_headers": "degraded",
                    "recon_tech": "degraded",
                    "recon_ai": active_model,
                },
                "fallback_triggered": True,
            }

    # 1. Execute Core Scanners
    from utils.target_policy import normalize_target
    dns_host = normalize_target(domain).host
    dns_res = run_dns_recon(dns_host, use_mock=use_mock, strict_live=strict)
    ssl_res = run_ssl_check(domain, use_mock=use_mock, strict_live=strict)
    hdr_res = run_header_scan(domain, use_mock=use_mock, strict_live=strict)
    tech_res = run_tech_fingerprint(domain, use_mock=use_mock, strict_live=strict)

    # 2. Build Finding Objects
    findings = _generate_findings_from_recon(domain, dns_res, ssl_res, hdr_res, tech_res, use_mock=use_mock)

    # 3. AI Reasoning
    if use_ai:
        recon_payload = {
            "domain": domain,
            "dns": dns_res,
            "ssl": ssl_res,
            "headers": hdr_res,
            "tech": tech_res,
        }
        prompt = _build_ai_prompt(recon_payload)
        ai_analysis = _call_qwen_analysis(prompt, use_mock=use_mock, strict_live=strict)
        active_model = ai_analysis.get("_model_used", configured_model()) if ai_analysis.get("_provenance") == "LLM_REASONING" else "unavailable"
    else:
        ai_analysis = {
            "status": "disabled",
            "executive_summary": "AI reasoning disabled in rules_only mode.",
            "_provenance": "DETERMINISTIC_RULES",
        }
        active_model = "disabled"

    def _get_status(res: Any) -> str:
        if res is None:
            return "error"
        if isinstance(res, dict):
            return res.get("status", "unknown")
        return getattr(res, "status", "unknown")

    def _source_label(res: Any, is_mock: bool) -> str:
        if is_mock:
            return "mock"
        st = _get_status(res)
        if st == "success":
            return "live"
        elif st == "warning":
            return "degraded"
        elif st == "error":
            return "error"
        return "unknown"

    data_sources = {
        "recon_dns": _source_label(dns_res, use_mock),
        "recon_ssl": _source_label(ssl_res, use_mock),
        "recon_headers": _source_label(hdr_res, use_mock),
        "recon_tech": _source_label(tech_res, use_mock),
        "recon_ai": "mock" if use_mock else active_model,
    }

    dns_failed = not use_mock and _get_status(dns_res) in ("error", "unknown")
    ssl_failed = not use_mock and _get_status(ssl_res) in ("error", "unknown")
    hdr_failed = not use_mock and _get_status(hdr_res) in ("error", "unknown")
    tech_failed = not use_mock and _get_status(tech_res) in ("error", "unknown")

    fallback_triggered = use_mock or dns_failed or ssl_failed or hdr_failed or tech_failed or (
        isinstance(ai_analysis, dict) and ai_analysis.get("_fallback_triggered", False)
    )

    return {
        "domain": domain,
        "dns": dns_res,
        "ssl": ssl_res,
        "headers": hdr_res,
        "tech": tech_res,
        "findings": findings,
        "ai_analysis": ai_analysis,
        "data_sources": data_sources,
        "fallback_triggered": fallback_triggered,
    }
