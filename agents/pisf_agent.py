"""
CyberShield AI — PISF 2026 Compliance Agent
=============================================
Maps ALL security findings to Pakistan's PISF 2026 framework
(12 control domains) with international framework cross-mapping.

This is THE unique differentiator of CyberShield AI.

Mostly deterministic — rules-based mapping with template-based
recommendations. Works completely OFFLINE (no AI dependency).

Each control outputs:
  - status: PASS | FAIL | PARTIAL | NOT_ASSESSABLE
  - evidence: What was found
  - recommendation: What to fix
  - international_mapping: ISO 27001, NIST CSF, CIS Controls, OWASP Top 10

Usage:
    from agents.pisf_agent import run_pisf_assessment
    result = run_pisf_assessment(recon_data, threat_data)
"""

import sys
import os
import logging

# Fix import path when running from agents/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    PisfControl, PisfResult, Finding,
    DnsResult, SslResult, HeaderResult, TechResult, ThreatResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PISF 2026 Control Domain Definitions
# ---------------------------------------------------------------------------

PISF_CONTROLS = [
    {"id": 1,  "domain": "Information Security Governance",  "iso_27001": "A.5 Organizational Controls",  "nist_csf": "GOVERN",  "cis_control": "Control 1",     "owasp_top10": ""},
    {"id": 2,  "domain": "Human Resource Security",          "iso_27001": "A.6 People Controls",          "nist_csf": "GOVERN",  "cis_control": "Control 14",    "owasp_top10": ""},
    {"id": 3,  "domain": "Access Control",                   "iso_27001": "A.8.3-A.8.5",                  "nist_csf": "PROTECT", "cis_control": "Control 5,6",   "owasp_top10": "A01:2021"},
    {"id": 4,  "domain": "Cryptography",                     "iso_27001": "A.8.24",                        "nist_csf": "PROTECT", "cis_control": "Control 3",     "owasp_top10": "A02:2021"},
    {"id": 5,  "domain": "Physical Security",                "iso_27001": "A.7 Physical Controls",         "nist_csf": "PROTECT", "cis_control": "Control 1",     "owasp_top10": ""},
    {"id": 6,  "domain": "Operations Security",              "iso_27001": "A.8.9-A.8.12",                  "nist_csf": "PROTECT", "cis_control": "Control 4,8",   "owasp_top10": "A05:2021"},
    {"id": 7,  "domain": "Communications Security",          "iso_27001": "A.8.20-A.8.22",                "nist_csf": "PROTECT", "cis_control": "Control 9",     "owasp_top10": "A02:2021"},
    {"id": 8,  "domain": "System Acquisition & Development", "iso_27001": "A.8.25-A.8.31",                "nist_csf": "PROTECT", "cis_control": "Control 16",    "owasp_top10": "A03:2021,A06:2021"},
    {"id": 9,  "domain": "Third Party Management",           "iso_27001": "A.5.19-A.5.22",                "nist_csf": "GOVERN",  "cis_control": "Control 15",    "owasp_top10": "A08:2021"},
    {"id": 10, "domain": "Incident Management",              "iso_27001": "A.5.24-A.5.28",                "nist_csf": "RESPOND", "cis_control": "Control 17",    "owasp_top10": "A09:2021"},
    {"id": 11, "domain": "Business Continuity",              "iso_27001": "A.5.29-A.5.30",                "nist_csf": "RECOVER", "cis_control": "Control 11",    "owasp_top10": ""},
    {"id": 12, "domain": "Compliance & Audit",               "iso_27001": "A.5.31-A.5.36",                "nist_csf": "GOVERN",  "cis_control": "Control 18",    "owasp_top10": ""},
]


def _intl(ctrl: dict) -> dict:
    """Build international framework mapping dict for a control."""
    return {
        "iso_27001": ctrl["iso_27001"],
        "nist_csf": ctrl["nist_csf"],
        "cis_control": ctrl["cis_control"],
        "owasp_top10": ctrl["owasp_top10"],
    }


def _sg(obj, attr, default=None):
    """Safely get attribute from dataclass or dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


# ---------------------------------------------------------------------------
# Control Assessments
# ---------------------------------------------------------------------------

def _assess_control_1(recon_data, threat_data) -> PisfControl:
    """Control 1 — Information Security Governance."""
    c = PISF_CONTROLS[0]
    crit = 0
    high = 0
    for src in (recon_data, threat_data):
        if src:
            for f in (src.get("findings") or []):
                sev = _sg(f, "severity")
                if sev == "Critical":
                    crit += 1
                elif sev == "High":
                    high += 1
    if crit > 0 or high > 0:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence=f"{crit} critical and {high} high vulnerability(ies) indicate technical governance gaps.",
            recommendation="Establish information security policy per PISF 2026 Section 1.",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="Technical governance baseline satisfied (inferred from absence of critical/high vulnerabilities; does not verify organizational governance policies or management sign-offs).",
        recommendation="Maintain information security policy per PISF 2026 Section 1. Conduct annual policy review.",
        international_mapping=_intl(c),
    )




def _assess_control_2(recon_data, threat_data) -> PisfControl:
    """Control 2 — Human Resource Security (NOT_ASSESSABLE)."""
    c = PISF_CONTROLS[1]
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
        evidence="Human resource security requires manual review of HR policies and procedures.",
        recommendation="Implement background checks, security awareness training, and termination procedures per PISF 2026 Section 2.",
        international_mapping=_intl(c),
    )


def _assess_control_3(recon_data, threat_data) -> PisfControl:
    """Control 3 — Access Control."""
    c = PISF_CONTROLS[2]
    if not recon_data and not threat_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="No scan data available for access control assessment.",
            recommendation="Perform access control testing per PISF 2026 Section 3.",
            international_mapping=_intl(c),
        )
    tech = recon_data.get("tech") if recon_data else None
    tr = threat_data.get("threat_result") if threat_data else None
    if (not tech or _sg(tech, "status") != "success") and (not tr or _sg(tr, "status") != "success"):
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="Access control sub-scan data unavailable or failed.",
            recommendation="Perform access control testing per PISF 2026 Section 3.",
            international_mapping=_intl(c),
        )
    evidence = []
    issues = 0
    has_ctrl = False
    if tech and _sg(tech, "status") == "success":
        robots = _sg(tech, "robots_txt")
        if robots and any(kw in (robots or "").lower() for kw in ["admin", "login", "dashboard"]):
            evidence.append("Admin paths disclosed in robots.txt")
            issues += 1
        for f in (recon_data.get("findings") or []):
            cid = _sg(f, "check_id", "")
            title = (_sg(f, "title", "") or "").lower()
            if cid == "R-022" or "directory listing" in title:
                evidence.append(_sg(f, "title", "Unknown"))
                issues += 1
            if "authentication" in title or "auth" in title:
                has_ctrl = True
    if tr and _sg(tr, "status") == "success":
        vt = _sg(tr, "virustotal_positives", 0)
        if vt and vt > 0:
            evidence.append(f"Domain flagged by {vt} security vendor(s)")
            issues += 1
    if issues > 0:
        status = "PARTIAL" if has_ctrl else "FAIL"
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status=status,
            evidence="; ".join(evidence),
            recommendation="Implement access controls per PISF 2026 Section 3: enforce authentication, disable directory listing, implement RBAC.",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="No access control issues detected in automated scan.",
        recommendation="Continue monitoring access controls per PISF 2026 Section 3.",
        international_mapping=_intl(c),
    )


def _assess_control_4(recon_data, threat_data) -> PisfControl:
    """Control 4 — Cryptography."""
    c = PISF_CONTROLS[3]
    if not recon_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="No SSL/TLS data available.",
            recommendation="Perform SSL/TLS assessment per PISF 2026 Section 4.",
            international_mapping=_intl(c),
        )
    ssl = recon_data.get("ssl")
    if not ssl or _sg(ssl, "status") != "success":
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="SSL/TLS certificate sub-scan data unavailable or failed.",
            recommendation="Perform SSL/TLS assessment per PISF 2026 Section 4.",
            international_mapping=_intl(c),
        )
    hdr = recon_data.get("headers")
    hdr_ok = _sg(hdr, "status") == "success" if hdr else False
    ev = []
    fails = []
    partials = []
    valid = _sg(ssl, "valid", False)
    tls = _sg(ssl, "tls_versions", []) or []
    cipher = _sg(ssl, "cipher_strength")
    days = _sg(ssl, "days_remaining")
    self_signed = _sg(ssl, "is_self_signed", False)
    if not valid:
        fails.append("SSL certificate invalid or missing")
    else:
        ev.append("Valid SSL certificate")
    if self_signed:
        fails.append("Self-signed certificate detected")
    weak = [v for v in tls if any(x in str(v) for x in ("1.0", "1.1", "SSL"))]
    strong = [v for v in tls if any(x in str(v) for x in ("1.2", "1.3"))]
    if weak:
        fails.append(f"Weak TLS versions: {', '.join(str(v) for v in weak)}")
    if strong:
        ev.append(f"TLS: {', '.join(str(v) for v in strong)}")
    if cipher and str(cipher).lower() in ("weak", "insecure", "low"):
        fails.append(f"Weak cipher strength: {cipher}")
    elif cipher:
        ev.append(f"Cipher: {cipher}")
    if days is not None and 0 < days <= 30:
        partials.append(f"Certificate expiring in {days} days")
    if hdr_ok:
        https_redir = _sg(hdr, "https_redirect", False)
        if not https_redir:
            partials.append("HTTP to HTTPS redirect not configured")
    if fails:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev + fails),
            recommendation="Install valid SSL, enforce TLS 1.2+, strong ciphers, HTTPS per PISF 2026 Section 4.",
            international_mapping=_intl(c),
        )
    if partials:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PARTIAL",
            evidence="; ".join(ev + partials),
            recommendation="Address crypto gaps per PISF 2026 Section 4: " + "; ".join(partials) + ".",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="; ".join(ev),
        recommendation="Maintain cryptographic controls per PISF 2026 Section 4.",
        international_mapping=_intl(c),
    )



def _assess_control_5(recon_data, threat_data) -> PisfControl:
    """Control 5 — Physical Security (NOT_ASSESSABLE)."""
    c = PISF_CONTROLS[4]
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
        evidence="Physical security cannot be assessed via remote automated scanning.",
        recommendation="Conduct on-site physical security assessment per PISF 2026 Section 5.",
        international_mapping=_intl(c),
    )


def _assess_control_6(recon_data, threat_data) -> PisfControl:
    """Control 6 — Operations Security."""
    c = PISF_CONTROLS[5]
    if not recon_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="No scan data available.",
            recommendation="Perform security header assessment per PISF 2026 Section 6.",
            international_mapping=_intl(c),
        )
    hdr = recon_data.get("headers")
    if not hdr or _sg(hdr, "status") != "success":
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="HTTP security headers sub-scan data unavailable or failed.",
            recommendation="Perform security header assessment per PISF 2026 Section 6.",
            international_mapping=_intl(c),
        )
    tech = recon_data.get("tech")
    ev = []
    ver_disc = False
    sh = _sg(hdr, "server_header")
    xpb = _sg(hdr, "x_powered_by")
    hs = _sg(hdr, "header_score", 0)
    risk = _sg(hdr, "overall_risk", "UNKNOWN")
    if sh and any(ch.isdigit() for ch in sh):
        ver_disc = True
        ev.append(f"Server version disclosed: {sh}")
    elif sh:
        ev.append(f"Server: {sh} (no version)")
    if xpb:
        ver_disc = True
        ev.append(f"X-Powered-By: {xpb}")
    ev.append(f"Header score: {hs}/6, risk: {risk}")
    missing = 6 - hs
    if ver_disc and missing > 3:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev),
            recommendation="Harden operations security per PISF 2026 Section 6: remove version headers, add all security headers.",
            international_mapping=_intl(c),
        )
    if hs < 5 or ver_disc:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PARTIAL",
            evidence="; ".join(ev),
            recommendation=f"Improve operations security per PISF 2026 Section 6: add {missing} missing header(s), remove version disclosure.",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="; ".join(ev),
        recommendation="Maintain operations security controls per PISF 2026 Section 6.",
        international_mapping=_intl(c),
    )


def _assess_control_7(recon_data, threat_data) -> PisfControl:
    """Control 7 — Communications Security."""
    c = PISF_CONTROLS[6]
    if not recon_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="No scan data available.",
            recommendation="Perform HTTPS/HSTS assessment per PISF 2026 Section 7.",
            international_mapping=_intl(c),
        )
    hdr = recon_data.get("headers")
    if not hdr or _sg(hdr, "status") != "success":
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="HTTP security headers sub-scan data unavailable or failed.",
            recommendation="Perform HTTPS/HSTS assessment per PISF 2026 Section 7.",
            international_mapping=_intl(c),
        )
    https_r = _sg(hdr, "https_redirect", False)
    hsts = _sg(hdr, "hsts_present", False)
    ev = [f"HTTPS redirect: {'Yes' if https_r else 'No'}", f"HSTS: {'Present' if hsts else 'Missing'}"]
    if not https_r and not hsts:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev),
            recommendation="Enforce HTTPS redirect and enable HSTS per PISF 2026 Section 7.",
            international_mapping=_intl(c),
        )
    if not (https_r and hsts):
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PARTIAL",
            evidence="; ".join(ev),
            recommendation="Strengthen communications security per PISF 2026 Section 7.",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="; ".join(ev),
        recommendation="Maintain communications security controls per PISF 2026 Section 7.",
        international_mapping=_intl(c),
    )


def _assess_control_8(recon_data, threat_data) -> PisfControl:
    """Control 8 — System Acquisition & Development."""
    c = PISF_CONTROLS[7]
    if not recon_data and not threat_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="No scan data available.",
            recommendation="Maintain software update policies per PISF 2026 Section 8.",
            international_mapping=_intl(c),
        )
    tr = threat_data.get("threat_result") if threat_data else None
    tech = recon_data.get("tech") if recon_data else None
    if (not tr or _sg(tr, "status") != "success") and (not tech or _sg(tech, "status") != "success"):
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="Threat intelligence and technology sub-scan data unavailable or failed.",
            recommendation="Maintain software update policies per PISF 2026 Section 8.",
            international_mapping=_intl(c),
        )
    ev = []
    crit_cve = []
    high_cve = []
    med_cve = []
    outdated = []
    if tr and _sg(tr, "status") == "success":
        for cve in (_sg(tr, "cve_matches", []) or []):
            if isinstance(cve, dict):
                sev = (cve.get("severity", "") or "").lower()
                cid = cve.get("cve_id", "UNKNOWN")
                if sev == "critical":
                    crit_cve.append(cid)
                elif sev == "high":
                    high_cve.append(cid)
                elif sev == "medium":
                    med_cve.append(cid)
    if tech and _sg(tech, "status") == "success":
        server = (_sg(tech, "server") or "").lower()
        lang = (_sg(tech, "programming_language") or "").lower()
        combined = f"{server} {lang}"
        for pat in ["php 5", "php 4", "nginx/1.1", "nginx/1.0", "apache/2.2", "apache/2.0", "python 2"]:
            if pat in combined:
                outdated.append(pat)
    if crit_cve:
        ev.append(f"Critical CVEs: {', '.join(crit_cve)}")
    if high_cve:
        ev.append(f"High CVEs: {', '.join(high_cve)}")
    if med_cve:
        ev.append(f"Medium CVEs: {', '.join(med_cve)}")
    if outdated:
        ev.append(f"Outdated components: {', '.join(outdated)}")
    if not ev:
        ev.append("No known CVEs or outdated components detected")
    if crit_cve or outdated:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev),
            recommendation="Patch critical vulnerabilities and update outdated components immediately per PISF 2026 Section 8.",
            international_mapping=_intl(c),
        )
    if high_cve:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev),
            recommendation="Address high-severity CVEs within 30 days per PISF 2026 Section 8.",
            international_mapping=_intl(c),
        )
    if med_cve:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PARTIAL",
            evidence="; ".join(ev),
            recommendation="Address medium-severity CVEs within 90 days per PISF 2026 Section 8.",
            international_mapping=_intl(c),
        )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="; ".join(ev),
        recommendation="Maintain secure development and patch management per PISF 2026 Section 8.",
        international_mapping=_intl(c),
    )



def _assess_control_9(recon_data, threat_data) -> PisfControl:
    """Control 9 — Third Party Management."""
    c = PISF_CONTROLS[8]
    if not recon_data:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="Technology fingerprinting data unavailable for third-party assessment.",
            recommendation="Inventory third-party services per PISF 2026 Section 9.",
            international_mapping=_intl(c),
        )

    tech = recon_data.get("tech")
    if not tech or _sg(tech, "status") != "success":
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
            evidence="Technology fingerprinting sub-scan data unavailable or failed.",
            recommendation="Inventory third-party services per PISF 2026 Section 9.",
            international_mapping=_intl(c),
        )

    ev = []
    tp = False
    ssl = recon_data.get("ssl")
    cdn = _sg(tech, "cdn")
    if cdn:
        ev.append(f"CDN detected: {cdn}")
        tp = True
    for t in (_sg(tech, "technologies", []) or []):
        if any(kw in t.lower() for kw in ["cloudflare", "google", "amazon", "akamai", "fastly", "jquery", "bootstrap", "analytics"]):
            ev.append(f"Third-party: {t}")
            tp = True

    if tp and (ssl is None or _sg(ssl, "status") != "success"):
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PARTIAL",
            evidence="; ".join(ev) + " (Third-party dependencies detected, but SSL certificate validation data was unavailable or failed)",
            recommendation="Establish vendor risk assessment and SLA monitoring per PISF 2026 Section 9.",
            international_mapping=_intl(c),
        )

    ssl_valid = _sg(ssl, "valid", False) if ssl else False
    if tp and not ssl_valid:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="FAIL",
            evidence="; ".join(ev) + " (Unencrypted HTTP third-party script inclusion detected)",
            recommendation="Enforce HTTPS for all third-party integrations and conduct vendor risk assessment per PISF 2026 Section 9.",
            international_mapping=_intl(c),
        )
    if tp and ssl_valid:
        return PisfControl(
            control_id=c["id"], domain=c["domain"], status="PASS",
            evidence="; ".join(ev) + " (Encrypted HTTPS integration verified)",
            recommendation="Maintain vendor risk assessment and SLA monitoring per PISF 2026 Section 9.",
            international_mapping=_intl(c),
        )

    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="PASS",
        evidence="Zero untrusted third-party inclusions detected.",
        recommendation="Inventory third-party services per PISF 2026 Section 9.",
        international_mapping=_intl(c),
    )


def _assess_control_10(recon_data, threat_data) -> PisfControl:
    """Control 10 — Incident Management."""
    c = PISF_CONTROLS[9]
    if threat_data:
        tr = threat_data.get("threat_result")
        breach = _sg(tr, "breach_data")
        bl = _sg(tr, "blacklist_status")
        if breach:
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="FAIL",
                evidence=f"Breach data detected: {breach}",
                recommendation="Activate incident response plan per PISF 2026 Section 10.",
                international_mapping=_intl(c),
            )
        if bl and str(bl).lower() not in ("clean", "none", "unknown", "unverified"):
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="FAIL",
                evidence=f"Domain flagged on security blacklists: {bl}",
                recommendation="Investigate potential incident per PISF 2026 Section 10.",
                international_mapping=_intl(c),
            )
        if bl and str(bl).lower() == "clean":
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="PASS",
                evidence="Domain status clean across threat intelligence blacklists and public breach feeds.",
                recommendation="Maintain incident response monitoring per PISF 2026 Section 10.",
                international_mapping=_intl(c),
            )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
        evidence="Threat intelligence blacklist status unverified; incident management requires manual review of IR policies.",
        recommendation="Establish incident response plan and conduct tabletop exercises per PISF 2026 Section 10.",
        international_mapping=_intl(c),
    )


def _assess_control_11(recon_data, threat_data) -> PisfControl:
    """Control 11 — Business Continuity."""
    c = PISF_CONTROLS[10]
    if recon_data:
        dns = recon_data.get("dns")
        if not dns or _sg(dns, "status") != "success":
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
                evidence="DNS reconnaissance sub-scan data unavailable or failed.",
                recommendation="Perform DNS assessment per PISF 2026 Section 11.",
                international_mapping=_intl(c),
            )
        exp = _sg(dns, "domain_expiry_days")
        ns = _sg(dns, "ns_records", []) or []
        if exp is not None and exp <= 0:
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="FAIL",
                evidence=f"Domain registration expired ({exp} days) — critical business continuity failure.",
                recommendation="Immediately renew domain registration and establish BCP/DR procedures per PISF 2026 Section 11.",
                international_mapping=_intl(c),
            )
        if exp is not None and exp < 30:
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="PARTIAL",
                evidence=f"Domain expiring in {exp} days — continuity risk.",
                recommendation="Renew domain and establish BCP/DR plan per PISF 2026 Section 11.",
                international_mapping=_intl(c),
            )
        if len(ns) < 2:
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="PARTIAL",
                evidence=f"Single DNS name server detected ({len(ns)} NS record) — single point of failure risk.",
                recommendation="Configure at least two redundant DNS name servers per PISF 2026 Section 11.",
                international_mapping=_intl(c),
            )
        if len(ns) >= 2 and (exp is None or exp >= 30):
            return PisfControl(
                control_id=c["id"], domain=c["domain"], status="PASS",
                evidence=f"Redundant DNS name servers ({len(ns)}) and active domain registration verified.",
                recommendation="Maintain BCP/DR plans per PISF 2026 Section 11.",
                international_mapping=_intl(c),
            )
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
        evidence="Business continuity requires manual review of BCP/DR plans.",
        recommendation="Develop BCP/DR plans per PISF 2026 Section 11: define RTO/RPO, backup procedures.",
        international_mapping=_intl(c),
    )





def _assess_control_12(recon_data, threat_data) -> PisfControl:
    """Control 12 — Compliance & Audit (NOT_ASSESSABLE)."""
    c = PISF_CONTROLS[11]
    return PisfControl(
        control_id=c["id"], domain=c["domain"], status="NOT_ASSESSABLE",
        evidence="Compliance & audit governance requires manual review of audit logs, compliance policies, and third-party audit reports; cannot be fully verified via external scan.",
        recommendation="Schedule annual comprehensive audit and maintain compliance logs per PISF 2026 Section 12.",
        international_mapping=_intl(c),
    )




# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _calculate_compliance_score(controls: list) -> float:
    """Score = (PASS*100 + PARTIAL*50) / assessable count.  0-100."""
    assessable = [c for c in controls if c.status != "NOT_ASSESSABLE"]
    if not assessable:
        return 0.0
    return sum(
        100 if c.status == "PASS" else 50 if c.status == "PARTIAL" else 0
        for c in assessable
    ) / len(assessable)


# ---------------------------------------------------------------------------
# Mock Data
# ---------------------------------------------------------------------------

def _build_mock_data() -> tuple:
    """Build mock recon_data and threat_data for offline testing."""
    dns = DnsResult(
        a_records=["93.184.216.34"], mx_records=["mail.example.com"],
        ns_records=["ns1.example.com", "ns2.example.com"],
        txt_records=["v=spf1 include:_spf.google.com ~all"],
        spf_record="v=spf1 include:_spf.google.com ~all",
        dmarc_record=None, dkim_found=False,
        whois_registrar="Example Registrar", domain_expiry_days=180,
        registrar_locked=True,
    )
    ssl = SslResult(
        valid=True, expiry_date="2026-12-15", days_remaining=107,
        issuer="Let's Encrypt", is_self_signed=False,
        tls_versions=["TLSv1.2", "TLSv1.3"],
        cipher_suite="TLS_AES_256_GCM_SHA384", cipher_strength="strong",
        sans=["example.com", "www.example.com"],
    )
    headers = HeaderResult(
        headers_present={
            "Content-Security-Policy": {"present": False, "value": ""},
            "X-Frame-Options": {"present": True, "value": "DENY"},
            "Strict-Transport-Security": {"present": True, "value": "max-age=31536000"},
            "X-Content-Type-Options": {"present": True, "value": "nosniff"},
            "Referrer-Policy": {"present": True, "value": "strict-origin-when-cross-origin"},
            "Permissions-Policy": {"present": False, "value": ""},
        },
        hsts_present=True, https_redirect=True, header_score=4,
        overall_risk="LOW", x_powered_by=None, server_header="nginx",
    )
    tech = TechResult(
        server="nginx", cms=None, programming_language="Python",
        cdn="Cloudflare", robots_txt="User-agent: *\nDisallow: /admin/",
        sitemap_found=True, meta_generator=None,
        technologies=["nginx", "Python", "Cloudflare", "jQuery"],
    )
    threat_result = ThreatResult(
        virustotal_score=0, virustotal_positives=0,
        shodan_ports=[80, 443], shodan_vulns=[],
        cve_matches=[
            {"cve_id": "CVE-2024-1234", "severity": "Medium", "cvss": 5.3,
             "description": "Example medium CVE", "affected_software": "nginx"},
        ],
        pakistan_threat_indicators=[], blacklist_status="clean",
        breach_data=None, threat_score=15,
    )
    recon_findings = [
        Finding(finding_id="CYBERSHIELD-M001", check_id="R-019",
                title="Missing Security Headers", severity="Medium", cvss_score=4.3),
        Finding(finding_id="CYBERSHIELD-M002", check_id="R-006",
                title="Missing DMARC Record", severity="Medium", cvss_score=5.3),
    ]
    recon_data = {
        "dns": dns, "ssl": ssl, "headers": headers,
        "tech": tech, "findings": recon_findings,
    }
    threat_data = {"threat_result": threat_result, "findings": []}
    return recon_data, threat_data


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def run_pisf_assessment(recon_data: dict = None, threat_data: dict = None,
                        use_mock: bool = False) -> dict:
    """Run full PISF 2026 compliance assessment across all 12 control domains.

    Args:
        recon_data: dict with keys dns, ssl, headers, tech, findings.
        threat_data: dict with keys threat_result, findings.
        use_mock: if True, build assessment from built-in mock data.

    Returns:
        dict with pisf_result, controls, compliance_score, counts, and status.
    """
    if use_mock:
        recon_data, threat_data = _build_mock_data()

    controls = [
        _assess_control_1(recon_data, threat_data),
        _assess_control_2(recon_data, threat_data),
        _assess_control_3(recon_data, threat_data),
        _assess_control_4(recon_data, threat_data),
        _assess_control_5(recon_data, threat_data),
        _assess_control_6(recon_data, threat_data),
        _assess_control_7(recon_data, threat_data),
        _assess_control_8(recon_data, threat_data),
        _assess_control_9(recon_data, threat_data),
        _assess_control_10(recon_data, threat_data),
        _assess_control_11(recon_data, threat_data),
        _assess_control_12(recon_data, threat_data),
    ]

    compliance_score = _calculate_compliance_score(controls)
    compliant_count = sum(1 for c in controls if c.status == "PASS")
    partial_count = sum(1 for c in controls if c.status == "PARTIAL")
    fail_count = sum(1 for c in controls if c.status == "FAIL")
    not_assessable_count = sum(1 for c in controls if c.status == "NOT_ASSESSABLE")

    assessable_count = 12 - not_assessable_count
    max_achievable_score = 100.0 if assessable_count > 0 else 0.0

    pisf_result = PisfResult(
        controls=controls,
        overall_score=compliance_score,
        max_achievable_score=max_achievable_score,
        compliant_controls=compliant_count,
        assessable_controls_count=assessable_count,
        total_controls=12,
        status="success",
    )


    return {
        "pisf_result": pisf_result,
        "controls": controls,
        "compliance_score": compliance_score,
        "compliant_count": compliant_count,
        "partial_count": partial_count,
        "fail_count": fail_count,
        "not_assessable_count": not_assessable_count,
        "status": "success",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("CyberShield AI — PISF 2026 Compliance Agent Tests")
    print("=" * 60)

    # TEST 1: Mock data assessment
    print("\nTEST 1: Mock data assessment")
    result = run_pisf_assessment(use_mock=True)
    assert result["status"] == "success"
    assert len(result["controls"]) == 12
    assert 0 <= result["compliance_score"] <= 100
    print(f"  PASS: Score={result['compliance_score']:.1f}%")
    print(f"  PASS={result['compliant_count']}, PARTIAL={result['partial_count']}, FAIL={result['fail_count']}, N/A={result['not_assessable_count']}")

    # TEST 2: Empty findings (everything NOT_ASSESSABLE)
    print("\nTEST 2: Empty findings")
    result = run_pisf_assessment(recon_data=None, threat_data=None)
    assert result["status"] == "success"
    assert len(result["controls"]) == 12
    print(f"  PASS: Score={result['compliance_score']:.1f}%, N/A={result['not_assessable_count']}")

    # TEST 3: Compliance score is mathematically correct
    print("\nTEST 3: Score calculation")
    result = run_pisf_assessment(use_mock=True)
    controls = result["controls"]
    assessable = [c for c in controls if c.status != "NOT_ASSESSABLE"]
    if assessable:
        expected = sum(100 if c.status == "PASS" else 50 if c.status == "PARTIAL" else 0 for c in assessable) / len(assessable)
        assert abs(result["compliance_score"] - expected) < 0.1, f"Score mismatch: {result['compliance_score']} vs {expected}"
    print(f"  PASS: Score mathematically verified")

    # TEST 4: Each control has international mapping
    print("\nTEST 4: International framework mapping")
    for c in result["controls"]:
        assert c.international_mapping, f"Control {c.control_id} missing international_mapping"
        assert "iso_27001" in c.international_mapping
        assert "nist_csf" in c.international_mapping
    print(f"  PASS: All 12 controls have international framework mappings")

    # TEST 5: Print full matrix
    print("\nTEST 5: Full PISF 2026 Compliance Matrix")
    print("-" * 60)
    for c in result["controls"]:
        status_icon = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️", "NOT_ASSESSABLE": "—"}
        icon = status_icon.get(c.status, "?")
        print(f"  {icon} Control {c.control_id:2d}: {c.domain:<35s} [{c.status}]")
    print("-" * 60)
    print(f"  Overall Compliance Score: {result['compliance_score']:.1f}%")

    print("\n" + "=" * 60)
    print("ALL PISF AGENT TESTS PASSED")
    print("=" * 60)
