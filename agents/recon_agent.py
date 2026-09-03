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
from utils.ai_provider import call_llm_json

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

    missing_headers = headers.get("missing_headers", []) if isinstance(headers, dict) else getattr(headers, "missing_headers", [])
    server_hdr = headers.get("server_header", "Unknown") if isinstance(headers, dict) else getattr(headers, "server_header", "Unknown")
    valid_ssl = ssl_info.get("valid", False) if isinstance(ssl_info, dict) else getattr(ssl_info, "valid", False)
    detected_tech = tech.get("detected_technologies", []) if isinstance(tech, dict) else getattr(tech, "detected_technologies", [])

    prompt = (
        f"Perform cybersecurity analysis for target domain: '{domain}'.\n"
        f"Recon Data:\n"
        f"- Missing Security Headers: {missing_headers}\n"
        f"- Server Banner: {server_hdr}\n"
        f"- SSL Valid: {valid_ssl}\n"
        f"- Detected Tech Stack: {detected_tech}\n"
        f"- MX Records Present: {bool(dns.get('mx') if isinstance(dns, dict) else getattr(dns, 'mx', []))}\n\n"
        f"Return JSON format with keys: 'executive_summary', 'critical_findings', 'recommendations'."
    )
    return prompt


def _call_qwen_analysis(prompt: str, use_mock: bool = False) -> Dict[str, Any]:
    """Send recon prompt to model-agnostic LLM provider (gemma4:31b-cloud default)."""
    system_prompt = (
        "You are CyberShield AI, a cybersecurity analysis engine. "
        "Analyze the reconnaissance data and provide security findings in structured JSON format."
    )
    return call_llm_json(prompt, system_prompt=system_prompt, use_mock=use_mock, timeout=30)


def _generate_findings_from_recon(
    domain: str,
    dns_res: Any,
    ssl_res: Any,
    hdr_res: Any,
    tech_res: Any
) -> List[Finding]:
    """Generate standardized Finding objects from raw recon results."""
    findings: List[Finding] = []

    # SSL Findings
    ssl_valid = ssl_res.get("valid", False) if isinstance(ssl_res, dict) else getattr(ssl_res, "valid", False)
    if not ssl_valid:
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
            )
        )

    # Missing Security Headers Findings
    missing_headers = hdr_res.get("missing_headers", []) if isinstance(hdr_res, dict) else getattr(hdr_res, "missing_headers", [])
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
            )
        )

    return findings


def run_recon(domain: str, use_mock: bool = False) -> Dict[str, Any]:
    """Execute complete reconnaissance stage for a target domain.

    Args:
        domain: Domain name or IP address.
        use_mock: If True, use built-in mock data for testing.

    Returns:
        dict with keys: dns, ssl, headers, tech, findings, ai_analysis, data_sources.
    """
    logger.info("[recon_agent] Starting reconnaissance for %s (use_mock=%s)", domain, use_mock)

    # 1. Execute Core Scanners
    dns_res = run_dns_recon(domain, use_mock=use_mock)
    ssl_res = run_ssl_check(domain, use_mock=use_mock)
    hdr_res = run_header_scan(domain, use_mock=use_mock)
    tech_res = run_tech_fingerprint(domain, use_mock=use_mock)

    # 2. Build Finding Objects
    findings = _generate_findings_from_recon(domain, dns_res, ssl_res, hdr_res, tech_res)

    # 3. AI Reasoning
    recon_payload = {
        "domain": domain,
        "dns": dns_res,
        "ssl": ssl_res,
        "headers": hdr_res,
        "tech": tech_res,
    }
    prompt = _build_ai_prompt(recon_payload)
    ai_analysis = _call_qwen_analysis(prompt, use_mock=use_mock)

    data_sources = {
        "dns": "mock" if use_mock else "live",
        "ssl": "mock" if use_mock else "live",
        "headers": "mock" if use_mock else "live",
        "tech": "mock" if use_mock else "live",
        "ai": "mock" if use_mock else "gemma4:31b-cloud",
    }

    return {
        "domain": domain,
        "dns": dns_res,
        "ssl": ssl_res,
        "headers": hdr_res,
        "tech": tech_res,
        "findings": findings,
        "ai_analysis": ai_analysis,
        "data_sources": data_sources,
    }
