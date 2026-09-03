"""
CyberShield AI — Threat Intelligence Agent
==========================================
Queries threat intelligence sources and maps CVE vulnerabilities:
  1. NIST NVD API / AI CVE Lookup via utils.ai_provider (default: gemma4:31b-cloud)
  2. VirusTotal Domain & IP Reputation Analysis
  3. Shodan Exposed Port & Banner Intelligence

Output: Structured dictionary containing ThreatResult, CVE Findings, and Source Stats.
"""

import sys
import os
import json
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple

# Fix import path when running from agents/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ThreatResult, Finding
from utils.ai_provider import call_llm_json

logger = logging.getLogger(__name__)

# Environment Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# Project Root & Mocks Path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK_THREAT_PATH = os.path.join(PROJECT_ROOT, "mocks", "mock_threat_response.json")


def _load_mock_threat_data() -> Dict[str, Any]:
    """Load mock threat intelligence data as fallback."""
    try:
        if os.path.exists(MOCK_THREAT_PATH):
            with open(MOCK_THREAT_PATH, "r") as f:
                return json.load(f)
    except Exception as err:
        logger.error("Failed to load mock threat response: %s", err)
    return {
        "status": "mock",
        "cve_matches": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "Critical",
                "cvss": 10.0,
                "description": "Apache Log4j2 JNDI remote code execution vulnerability.",
                "affected_software": "Log4j"
            }
        ],
        "shodan": {"open_ports": [80, 443]},
        "virustotal": {"malicious_votes": 0}
    }
def _query_virustotal_online(domain: str, strict_live: bool = False) -> Dict[str, Any]:
    """Query VirusTotal v3 API for domain reputation."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: VIRUSTOTAL_API_KEY is not configured in environment.")
        return {}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious_votes": stats.get("malicious", 0),
                "suspicious_votes": stats.get("suspicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "_provenance": "EXTERNAL_API",
            }
        elif strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: VirusTotal API returned HTTP {resp.status_code}")
    except Exception as err:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: VirusTotal API request failed: {err}")
        logger.warning("VirusTotal API query failed for %s: %s", domain, err)
    return {}


def _query_shodan_online(domain: str, strict_live: bool = False) -> Dict[str, Any]:
    """Query Shodan Host API for open ports and banners."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    if not api_key:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: SHODAN_API_KEY is not configured in environment.")
        return {}
    try:
        import socket
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "_provenance": "EXTERNAL_API",
            }
        elif strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Shodan API returned HTTP {resp.status_code}")
    except Exception as err:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Shodan API request failed: {err}")
        logger.warning("Shodan API query failed for %s: %s", domain, err)
    return {}


def _query_nvd_online(tech_versions: List[str], strict_live: bool = False) -> List[Dict[str, Any]]:
    """Query NIST NVD API v2 for software versions."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    cves = []
    headers = {"User-Agent": "CyberShield-AI/1.0"}
    for tech in tech_versions[:3]:  # Limit to top 3 for speed
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}"
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities[:3]:
                    cve_obj = item.get("cve", {})
                    cve_id = cve_obj.get("id", "CVE-UNKNOWN")
                    metrics = cve_obj.get("metrics", {})
                    cvss = 7.5
                    severity = "High"
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss = cvss_data.get("baseScore", 7.5)
                        severity = cvss_data.get("baseSeverity", "High").capitalize()
                    
                    descriptions = cve_obj.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else "NIST NVD vulnerability"

                    cves.append({
                        "cve_id": cve_id,
                        "severity": severity,
                        "cvss": cvss,
                        "description": desc,
                        "affected_software": tech,
                        "_provenance": "EXTERNAL_API",
                    })
            elif strict:
                raise RuntimeError(f"STRICT_LIVE_MODE: NVD API returned HTTP {resp.status_code} for {tech}")
        except Exception as err:
            if strict:
                raise RuntimeError(f"STRICT_LIVE_MODE: NVD API lookup failed for {tech}: {err}")
            logger.warning("NVD API lookup failed for %s: %s", tech, err)
    return cves


def _query_nvd_ai(tech_versions: List[str], use_mock: bool = False, strict_live: bool = False) -> List[Dict[str, Any]]:
    """Query AI (gemma4:31b-cloud) for CVE intelligence if NVD API yields no results."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    if not tech_versions or use_mock:
        if strict and use_mock:
            raise RuntimeError("STRICT_LIVE_MODE: Mock threat intelligence fallback is disabled.")
        mock_cves = _load_mock_threat_data().get("cve_matches", [])
        for m in mock_cves:
            if isinstance(m, dict):
                m["_provenance"] = "MOCK_FALLBACK"
        return mock_cves

    version_list = "\n".join(f"- {v}" for v in tech_versions)
    prompt = (
        f"Identify known CVE vulnerabilities for the following software versions:\n"
        f"{version_list}\n\n"
        f"Return JSON format: [{{\"cve_id\": \"CVE-...\", \"severity\": \"Critical|High|Medium|Low\", \"cvss\": 8.5, \"description\": \"...\", \"affected_software\": \"...\"}}]"
    )
    system_prompt = "You are a CVE database specialist. Return structured CVE entries in JSON format."
    
    res = call_llm_json(prompt, system_prompt=system_prompt, use_mock=use_mock, timeout=10, strict_live=strict)
    prov = res.get("_provenance", "MOCK_FALLBACK" if use_mock else "LLM_REASONING") if isinstance(res, dict) else ("MOCK_FALLBACK" if use_mock else "LLM_REASONING")
    
    matches = []
    if isinstance(res, list):
        matches = res
    elif isinstance(res, dict) and "cve_matches" in res:
        matches = res["cve_matches"]
    else:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: Failed to obtain CVE intelligence from LLM API.")
        matches = _load_mock_threat_data().get("cve_matches", [])

    for m in matches:
        if isinstance(m, dict):
            m["_provenance"] = prov
    return matches


def _generate_cve_findings(cve_list: List[Dict[str, Any]]) -> List[Finding]:
    """Convert raw CVE dict entries to standardized Finding objects."""
    findings = []
    for idx, cve in enumerate(cve_list, start=1):
        cve_id = cve.get("cve_id", f"CVE-2026-{idx:04d}")
        sev = cve.get("severity", "Medium")
        score = float(cve.get("cvss", 5.0))
        desc = cve.get("description", "Vulnerability detected")
        sw = cve.get("affected_software", "Software component")
        prov = cve.get("_provenance", "LLM_REASONING")

        findings.append(
            Finding(
                finding_id=f"CYBERSHIELD-T{idx:03d}",
                check_id="T-004",
                title=f"Known Vulnerability: {cve_id}",
                severity=sev,
                cvss_score=score,
                owasp_top10="A06:2021 – Vulnerable and Outdated Components",
                wstg_id="WSTG-INFO-02",
                cwe_id="CWE-1104",
                pisf_control="Control 8: System Acquisition & Development",
                description=f"Component '{sw}' is subject to known vulnerability {cve_id}: {desc}",
                evidence=f"CVE: {cve_id}, CVSS: {score}, Software: {sw}",
                remediation=f"Update {sw} to a patched version that resolves {cve_id}.",
                remediation_priority="WEEK 1" if sev in ("Critical", "High") else "MONTH 1",
                provenance=prov,
            )
        )
    return findings


def run_threat_intel(
    domain: str,
    recon_data: Optional[Dict[str, Any]] = None,
    use_mock: bool = False,
    strict_live: bool = False,
) -> Dict[str, Any]:
    """Execute complete threat intelligence phase.

    Args:
        domain: Target domain or IP.
        recon_data: Optional data from recon stage containing tech stack.
        use_mock: If True, use built-in mock threat response.
        strict_live: If True, raise RuntimeError on API failure instead of silent fallback.

    Returns:
        dict with keys: threat_result, findings, data_sources.
    """
    logger.info("[threat_intel_agent] Gathering threat intel for %s (use_mock=%s, strict_live=%s)", domain, use_mock, strict_live)
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")

    if use_mock and strict:
        raise RuntimeError("STRICT_LIVE_MODE: Mock mode execution is disabled in strict live mode.")

    # 1. Extract Tech Stack
    tech_versions = []
    if recon_data and isinstance(recon_data, dict):
        tech_info = recon_data.get("tech", {})
        if isinstance(tech_info, dict):
            tech_versions = tech_info.get("detected_technologies", [])

    # 2. Fetch CVEs (Online NVD API first, then AI gemma4:31b-cloud)
    cves = []
    if not use_mock and tech_versions:
        cves = _query_nvd_online(tech_versions, strict_live=strict)
    
    if not cves:
        cves = _query_nvd_ai(tech_versions, use_mock=use_mock, strict_live=strict)

    # 3. Fetch VirusTotal & Shodan live intelligence if keys available
    vt_data = _query_virustotal_online(domain, strict_live=strict) if not use_mock else {}
    shodan_data = _query_shodan_online(domain, strict_live=strict) if not use_mock else {}

    # 4. Create Finding Objects
    findings = _generate_cve_findings(cves)

    # 5. Construct ThreatResult
    threat_res = ThreatResult(
        cve_matches=cves,
        status="success"
    )

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()

    data_sources = {
        "nvd": "mock" if use_mock else ("online" if any(c.get("_provenance") == "EXTERNAL_API" for c in cves) else "ai"),
        "virustotal": "mock" if use_mock or not vt_key else ("live" if vt_data else "mock"),
        "shodan": "mock" if use_mock or not shodan_key else ("live" if shodan_data else "mock"),
        "ai": "gemma4:31b-cloud"
    }

    fallback_triggered = use_mock or any(
        isinstance(c, dict) and c.get("_provenance") == "MOCK_FALLBACK" for c in cves
    )

    return {
        "domain": domain,
        "threat_result": threat_res,
        "virustotal": vt_data,
        "shodan": shodan_data,
        "findings": findings,
        "data_sources": data_sources,
        "fallback_triggered": fallback_triggered,
    }
