"""
CyberShield AI — Report Agent (PTES Phase 7)
===============================================
Assembles structured security audit report from all agent outputs
and generates professional PDF using FPDF2.

Two output modes:
  1. Dict mode (always works): Template-based, no AI needed
  2. PDF artifact: deterministic summary with evidence and provenance

Report Sections:
  1. Executive Summary
  2. Scope & Methodology
  3. Findings Summary (by severity)
  4. Detailed Findings (CVSSv3.1 + OWASP + WSTG + CWE + PISF)
  5. PISF 2026 Compliance Matrix
  6. ISO 27001 Alignment
  7. Remediation Roadmap

Usage:
    from agents.report_agent import generate_report
    result = generate_report(scan_state_dict)
"""

import sys
import os
import logging
from datetime import datetime
from dataclasses import fields
from uuid import uuid4

# Fix import path when running from agents/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ReportData, Finding, PisfControl, PisfResult, is_live_confirmed_vulnerability

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


# ---------------------------------------------------------------------------
# Helper: safe ASCII conversion for PDF
# ---------------------------------------------------------------------------

def _safe_ascii(text: str) -> str:
    """Replace non-ASCII characters with safe equivalents for built-in fonts."""
    if not text:
        return ""
    replacements = {
        "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u2026": "...",
        "\u00e9": "e", "\u00e8": "e", "\u00ea": "e", "\u00eb": "e",
        "\u00e0": "a", "\u00e2": "a", "\u00e4": "a", "\u00e7": "c",
        "\u00f4": "o", "\u00f6": "o", "\u00fc": "u", "\u00f9": "u",
        "\u00ee": "i", "\u00ef": "i", "\u00e6": "ae", "\u0153": "oe",
        "\u2265": ">=", "\u2264": "<=", "\u2192": "->", "\u2713": "[OK]",
        "\u2717": "[X]", "\u26a0": "[!]", "\u2705": "[OK]", "\u274c": "[X]",
        "\u2716": "[X]", "\ufe0f": "",
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Final pass: strip any remaining non-ASCII
    return text.encode("ascii", "replace").decode("ascii")


# ---------------------------------------------------------------------------
# 1. Executive Summary
# ---------------------------------------------------------------------------

def _build_executive_summary(domain: str, findings: list, pisf_result: PisfResult,
                             ai_analysis: dict = None) -> str:
    """Build factual summary from assessed evidence, never model-generated counts."""
    confirmed_findings = [f for f in findings if is_live_confirmed_vulnerability(f)]
    total = len(confirmed_findings)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in confirmed_findings:
        sev = f.severity if isinstance(f, Finding) else getattr(f, "severity", "Info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    score = pisf_result.overall_score if pisf_result else 0.0
    pass_count = pisf_result.compliant_controls if pisf_result else 0
    assessable_count = getattr(pisf_result, "assessable_controls_count", 10) if pisf_result else 10
    total_count = getattr(pisf_result, "total_controls", 12) if pisf_result else 12
    non_assessable_count = total_count - assessable_count

    summary = (
        f"Security assessment of {domain} recorded {len(findings)} findings, "
        f"including {total} confirmed live vulnerabilities: "
        f"{severity_counts['Critical']} Critical, {severity_counts['High']} High, "
        f"{severity_counts['Medium']} Medium, {severity_counts['Low']} Low. "
        f"Project-defined PISF technical score: {score:.0f}% ({pass_count} of {assessable_count} assessable controls compliant; {non_assessable_count} controls marked NOT_ASSESSABLE due to scope boundaries). "
        f"Immediate action required on {severity_counts['Critical'] + severity_counts['High']} "
        f"critical/high findings."
    )
    if _calculate_security_score(findings, pisf_result) is None:
        summary = summary[:summary.index("Project-defined PISF technical score:")] + "PISF assessment unavailable; security score unavailable because control evidence is insufficient."
    summary += " This project-defined mapping is not a compliance certification."
    return summary


# ---------------------------------------------------------------------------
# 2. Scope & Methodology
# ---------------------------------------------------------------------------

def _build_scope_methodology(domain: str, scope_type: str, timestamp: str) -> str:
    """Build scope and methodology section text."""
    frameworks = [
        "PTES (Penetration Testing Execution Standard) — 7-Phase Model",
        "OWASP Web Security Testing Guide (WSTG) v4.2",
        "NIST SP 800-115 — Technical Guide to Information Security Testing",
        "PISF 2026 — Pakistan Information Security Framework",
        "CVSSv3.1 — Common Vulnerability Scoring System",
        "ISO/IEC 27001:2022 — Information Security Management",
        "CWE — Common Weakness Enumeration",
    ]
    fw_list = "\n".join(f"  - {fw}" for fw in frameworks)
    scope_label = {"passive_only": "Passive Reconnaissance Only", "full_pentest": "Full Penetration Test"}.get(scope_type, scope_type)

    text = (
        f"Target: {domain}\n"
        f"Scope: {scope_label}\n"
        f"Assessment Date: {timestamp}\n"
        f"Tool: CyberShield AI — Automated Security Assessment Engine\n\n"
        f"Frameworks Applied:\n{fw_list}\n\n"
        f"This report was generated by CyberShield AI using a multi-agent pipeline "
        f"that combines reconnaissance, threat intelligence, visual analysis, "
        f"and compliance mapping to deliver a comprehensive security posture assessment."
    )
    return text


# ---------------------------------------------------------------------------
# 3. Findings Summary
# ---------------------------------------------------------------------------

def _build_findings_summary(findings: list) -> dict:
    """Count findings by severity and return summary dict."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else getattr(f, "severity", "Info")
        if sev in counts:
            counts[sev] += 1
    counts["Total"] = len(findings)
    return counts


# ---------------------------------------------------------------------------
# 4. Remediation Roadmap
# ---------------------------------------------------------------------------

def _build_remediation_roadmap(findings: list) -> dict:
    """Build time-phased remediation roadmap from findings."""
    week_1 = []
    month_1 = []
    month_3 = []

    for f in findings:
        sev = f.severity if isinstance(f, Finding) else getattr(f, "severity", "Info")
        title = f.title if isinstance(f, Finding) else getattr(f, "title", "Unknown")
        remediation = f.remediation if isinstance(f, Finding) else getattr(f, "remediation", "")

        entry = {"title": title, "remediation": remediation}

        if sev in ("Critical", "High"):
            week_1.append(entry)
        elif sev == "Medium":
            month_1.append(entry)
        else:
            month_3.append(entry)

    return {
        "Week 1 — Immediate (Critical/High)": week_1,
        "Month 1 — Short-term (Medium)": month_1,
        "Month 3 — Long-term (Low/Improvements)": month_3,
    }


# ---------------------------------------------------------------------------
# 5. Security Score
# ---------------------------------------------------------------------------

def _calculate_security_score(findings: list, pisf_result: PisfResult) -> float | None:
    """Calculate weighted security score (0-100).

    Finding penalties: Critical=-15, High=-10, Medium=-5, Low=-2.
    Final = raw_score * 0.6 + pisf_score * 0.4.

    Only confirmed live vulnerabilities (via is_live_confirmed_vulnerability)
    count against the score. Candidate CVEs, mock data, incomplete checks,
    and probe errors are excluded. Missing or wholly unassessable control
    evidence yields None rather than a measured score.
    """
    if (pisf_result is None or pisf_result.status != "success"
            or not any(control.status in ("PASS", "PARTIAL", "FAIL")
                       for control in pisf_result.controls)):
        return None
    raw = 100.0
    for f in findings:
        if not is_live_confirmed_vulnerability(f):
            continue
        sev = f.severity if isinstance(f, Finding) else getattr(f, "severity", "Info")
        if sev == "Critical":
            raw -= 15
        elif sev == "High":
            raw -= 10
        elif sev == "Medium":
            raw -= 5
        elif sev == "Low":
            raw -= 2
    raw = max(0.0, raw)

    pisf_score = pisf_result.overall_score if pisf_result else 0.0
    final = (raw * 0.6) + (pisf_score * 0.4)
    return round(max(0.0, min(100.0, final)), 1)



# ---------------------------------------------------------------------------
# 6. PDF Generation
# ---------------------------------------------------------------------------

def _generate_pdf(report_data: ReportData, domain: str) -> str:
    """Generate professional PDF report using fpdf2 with built-in fonts only.

    Returns the file path of the generated PDF.
    """
    from fpdf import FPDF

    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}_{uuid4().hex}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)

    # ---- Cover Page ----
    pdf.add_page()
    if report_data.fallback_triggered:
        pdf.set_fill_color(255, 235, 235)
        pdf.set_text_color(180, 0, 0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 10, _safe_ascii("[!] WARNING: DEGRADED EXECUTION MODE / MOCK FALLBACK TRIGGERED DURING SCAN"), fill=True, border=1, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    pdf.set_font("Helvetica", "B", 28)
    pdf.ln(40 if report_data.fallback_triggered else 50)
    pdf.cell(0, 15, _safe_ascii("CyberShield AI"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 18)
    pdf.cell(0, 12, _safe_ascii("Security Assessment Report"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _safe_ascii(domain), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(15)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, _safe_ascii(f"Date: {datetime.now().strftime('%B %d, %Y')}"), new_x="LMARGIN", new_y="NEXT", align="C")
    score_label = "Unavailable" if report_data.security_posture_score is None else f"{report_data.security_posture_score:.1f}/100"
    pdf.cell(0, 8, _safe_ascii(f"Security Score: {score_label}"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(30)
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 6, _safe_ascii("Generated by CyberShield AI — Multi-Agent Security Assessment Engine"),
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 6, _safe_ascii("Frameworks: PTES | OWASP WSTG v4.2 | NIST SP 800-115 | PISF 2026 | CVSSv3.1"),
             new_x="LMARGIN", new_y="NEXT", align="C")

    # ---- Executive Summary ----
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("1. Executive Summary"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(0, 6, _safe_ascii(report_data.executive_summary))

    # ---- Scope & Methodology ----
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("2. Scope & Methodology"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, _safe_ascii(report_data.scope_methodology))

    if report_data.data_sources:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, _safe_ascii("Data Sources Execution Audit:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", "", 9)
        for k, v in report_data.data_sources.items():
            pdf.cell(0, 5, _safe_ascii(f"  - {k}: {v}"), new_x="LMARGIN", new_y="NEXT")

    # ---- Findings Summary ----
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("3. Findings Summary"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Summary table header
    col_w = [40, 30]
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(col_w[0], 8, "Severity", border=1, align="C")
    pdf.cell(col_w[1], 8, "Count", border=1, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    for sev, count in report_data.findings_summary.items():
        if sev in ("Total", "ai_model_used", "fallback_triggered"):
            continue
        pdf.cell(col_w[0], 7, _safe_ascii(sev), border=1, align="C")
        pdf.cell(col_w[1], 7, str(count), border=1, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(col_w[0], 7, "TOTAL", border=1)
    pdf.cell(col_w[1], 7, str(report_data.findings_summary.get("Total", 0)), border=1, align="C",
             new_x="LMARGIN", new_y="NEXT")

    # ---- Detailed Findings ----
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("4. Detailed Findings"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    for i, finding in enumerate(report_data.detailed_findings, 1):
        # Check if we need a new page (rough estimate)
        if pdf.get_y() > 230:
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, _safe_ascii(f"  {i}. [{finding.severity}] {finding.title}"),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", "", 9)
        details = [
            f"  Finding ID  : {finding.finding_id}",
            f"  Check ID    : {finding.check_id}",
            f"  CVSS Score  : {finding.cvss_score}",
            f"  Evidence URL: {finding.url or 'N/A'}",
            f"  Provenance  : {getattr(finding, 'provenance', 'OFFLINE_VERIFIER')}",
            f"  Check Status: {getattr(finding, 'check_status', 'SUCCESS')}",
            f"  OWASP Top10 : {finding.owasp_top10 or 'N/A'}",
            f"  WSTG ID     : {finding.wstg_id or 'N/A'}",
            f"  CWE ID      : {finding.cwe_id or 'N/A'}",
            f"  PISF Ctrl   : {finding.pisf_control or 'N/A'}",
        ]
        for line in details:
            pdf.cell(0, 5, _safe_ascii(line), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        if finding.evidence:
            pdf.cell(0, 5, _safe_ascii(f"  Evidence: {finding.evidence[:120]}"),
                     new_x="LMARGIN", new_y="NEXT")
        if finding.remediation:
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, _safe_ascii(f"  Remediation: {finding.remediation[:200]}"))
        pdf.ln(3)

    # ---- PISF 2026 Compliance Matrix ----
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("5. PISF 2026 Compliance Matrix"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Table header
    pisf_col_w = [18, 60, 30, 80]
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(pisf_col_w[0], 8, "Control", border=1, align="C")
    pdf.cell(pisf_col_w[1], 8, "Domain", border=1, align="C")
    pdf.cell(pisf_col_w[2], 8, "Status", border=1, align="C")
    pdf.cell(pisf_col_w[3], 8, "Evidence", border=1, align="C",
             new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8)
    for ctrl in report_data.pisf_matrix:
        evidence_text = _safe_ascii(ctrl.evidence[:55]) if ctrl.evidence else ""
        pdf.cell(pisf_col_w[0], 7, f"Ctrl {ctrl.control_id}", border=1, align="C")
        pdf.cell(pisf_col_w[1], 7, _safe_ascii(ctrl.domain[:35]), border=1)
        pdf.cell(pisf_col_w[2], 7, _safe_ascii(ctrl.status), border=1, align="C")
        pdf.cell(pisf_col_w[3], 7, evidence_text, border=1,
                 new_x="LMARGIN", new_y="NEXT")

    # ---- Remediation Roadmap ----
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, _safe_ascii("6. Remediation Roadmap"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    roadmap = report_data.remediation_roadmap
    for phase, items in roadmap.items():
        if pdf.get_y() > 250:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, _safe_ascii(phase), new_x="LMARGIN", new_y="NEXT")
        if not items:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(0, 6, "  No findings in this phase.", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font("Helvetica", "", 10)
            for item in items:
                title = item.get("title", "Unknown")
                rem = item.get("remediation", "")[:100]
                pdf.cell(0, 6, _safe_ascii(f"  - {title}"), new_x="LMARGIN", new_y="NEXT")
                if rem:
                    pdf.set_font("Helvetica", "I", 9)
                    pdf.cell(0, 5, _safe_ascii(f"    Action: {rem}"), new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 10)
        pdf.ln(4)

    # ---- Footer on every page ----
    # (fpdf2 handles this via the output; we add a simple text footer)

    pdf.output(filepath)
    return filepath


# ---------------------------------------------------------------------------
# 7. Mock Data Construction
# ---------------------------------------------------------------------------

def _build_mock_findings() -> list:
    """Build realistic mock findings for offline testing."""
    return [
        Finding(
            finding_id="CYBERSHIELD-001", check_id="R-011",
            title="Invalid SSL Certificate",
            severity="Critical", cvss_score=9.1,
            owasp_top10="A02:2021", wstg_id="WSTG-CRYP-01",
            cwe_id="CWE-295", pisf_control="Control 4",
            evidence="No SSL certificate found",
            remediation="Install valid SSL certificate from trusted CA",
            remediation_priority="WEEK 1",
            provenance="MOCK_FALLBACK",
        ),
        Finding(
            finding_id="CYBERSHIELD-002", check_id="R-019",
            title="Missing Security Headers",
            severity="High", cvss_score=6.5,
            owasp_top10="A05:2021", wstg_id="WSTG-CONF-07",
            cwe_id="CWE-693", pisf_control="Control 6",
            evidence="0/6 security headers present",
            remediation="Configure all 6 security headers",
            remediation_priority="WEEK 1",
            provenance="MOCK_FALLBACK",
        ),
        Finding(
            finding_id="CYBERSHIELD-003", check_id="R-006",
            title="Missing DMARC Record",
            severity="Medium", cvss_score=5.4,
            owasp_top10="A07:2021", wstg_id="WSTG-INFO-10",
            cwe_id="CWE-290", pisf_control="Control 4",
            evidence="No DMARC TXT record found at _dmarc subdomain",
            remediation="Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com",
            remediation_priority="MONTH 1",
            provenance="MOCK_FALLBACK",
        ),
        Finding(
            finding_id="CYBERSHIELD-004", check_id="R-017",
            title="Missing HSTS Header",
            severity="Medium", cvss_score=5.4,
            owasp_top10="A02:2021", wstg_id="WSTG-CONF-07",
            cwe_id="CWE-319", pisf_control="Control 5",
            evidence="Strict-Transport-Security header not found in response",
            remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            remediation_priority="WEEK 1",
            provenance="MOCK_FALLBACK",
        ),
        Finding(
            finding_id="CYBERSHIELD-005", check_id="R-020",
            title="Server Version Information Disclosure",
            severity="Low", cvss_score=3.7,
            owasp_top10="A05:2021", wstg_id="WSTG-INFO-02",
            cwe_id="CWE-200", pisf_control="Control 6",
            evidence="Server header: nginx/1.19.0",
            remediation="Remove or obscure the Server header version information",
            remediation_priority="MONTH 3",
            provenance="MOCK_FALLBACK",
        ),
        Finding(
            finding_id="CYBERSHIELD-006", check_id="R-022",
            title="robots.txt Discloses Sensitive Paths",
            severity="Low", cvss_score=3.1,
            owasp_top10="A01:2021", wstg_id="WSTG-INFO-03",
            cwe_id="CWE-538", pisf_control="Control 6",
            evidence="robots.txt contains Disallow directives for sensitive directories",
            remediation="Remove sensitive paths from robots.txt; use authentication instead",
            remediation_priority="MONTH 3",
            provenance="MOCK_FALLBACK",
        ),
    ]



def _build_mock_pisf_result() -> PisfResult:
    """Build mock PISF result with 12 controls for testing."""
    controls = [
        PisfControl(control_id=1, domain="Information Security Governance",
                     status="NOT_ASSESSABLE", evidence="Requires manual policy review"),
        PisfControl(control_id=2, domain="Human Resource Security",
                     status="NOT_ASSESSABLE", evidence="Requires manual HR policy review"),
        PisfControl(control_id=3, domain="Access Control",
                     status="PASS", evidence="No access control issues detected"),
        PisfControl(control_id=4, domain="Cryptography",
                     status="FAIL", evidence="SSL certificate invalid or missing"),
        PisfControl(control_id=5, domain="Physical Security",
                     status="NOT_ASSESSABLE", evidence="Cannot be assessed remotely"),
        PisfControl(control_id=6, domain="Operations Security",
                     status="FAIL", evidence="Header score: 0/6, risk: HIGH"),
        PisfControl(control_id=7, domain="Communications Security",
                     status="FAIL", evidence="HTTPS redirect: No, HSTS: Missing"),
        PisfControl(control_id=8, domain="System Acquisition & Development",
                     status="PARTIAL", evidence="No known CVEs detected"),
        PisfControl(control_id=9, domain="Third Party Management",
                     status="NOT_ASSESSABLE", evidence="No third-party dependencies detected"),
        PisfControl(control_id=10, domain="Incident Management",
                     status="NOT_ASSESSABLE", evidence="Requires manual IR policy review"),
        PisfControl(control_id=11, domain="Business Continuity",
                     status="NOT_ASSESSABLE", evidence="Requires manual BCP/DR review"),
        PisfControl(control_id=12, domain="Compliance & Audit",
                     status="PARTIAL", evidence="Automated PISF 2026 assessment performed"),
    ]
    pass_count = sum(1 for c in controls if c.status == "PASS")
    assessable = [c for c in controls if c.status != "NOT_ASSESSABLE"]
    score = 0.0
    if assessable:
        score = sum(100 if c.status == "PASS" else 50 if c.status == "PARTIAL" else 0
                    for c in assessable) / len(assessable)
    return PisfResult(
        controls=controls,
        overall_score=score,
        compliant_controls=pass_count,
        total_controls=12,
        status="success",
    )


# ---------------------------------------------------------------------------
# 8. Main Entry Point
# ---------------------------------------------------------------------------

def generate_report(scan_data: dict = None, use_mock: bool = False) -> dict:
    """Assemble security audit report and generate PDF.

    Args:
        scan_data: dict containing scan results (domain, findings, pisf_result, ai_analysis).
        use_mock: mark demo execution; fixtures are used only without supplied scan data.

    Returns:
        dict with report (ReportData), pdf_path, security_score, findings_summary, status.
    """
    if scan_data is None and use_mock:
        domain = "testphp.vulnweb.com"
        findings = _build_mock_findings()
        pisf_result = _build_mock_pisf_result()
        ai_analysis = None
        scope_type = "passive_only"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    elif hasattr(scan_data, "domain"):
        domain = getattr(scan_data, "domain", "target")
        findings = getattr(scan_data, "all_findings", [])
        pisf_result = getattr(scan_data, "pisf", None)
        if pisf_result is None:
            pisf_result = getattr(scan_data, "pisf_result", None)
        ai_analysis = getattr(scan_data, "ai_analysis", None)
        scope_type = getattr(scan_data, "scope_type", "passive_only")
        timestamp = getattr(scan_data, "timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        scan_data = scan_data or {}
        domain = scan_data.get("domain", "unknown")
        # Collect findings from multiple sources with deduplication
        raw_findings = []
        raw_findings.extend(scan_data.get("all_findings", []))
        raw_findings.extend(scan_data.get("findings", []))
        raw_findings.extend(scan_data.get("pentest_findings", []))
        if scan_data.get("recon_result") and isinstance(scan_data["recon_result"], dict):
            raw_findings.extend(scan_data["recon_result"].get("findings", []))

        findings = raw_findings
        pisf_result = scan_data.get("pisf") or scan_data.get("pisf_result")
        ai_analysis = scan_data.get("ai_analysis")
        scope_type = scan_data.get("scope_type", "passive_only")
        timestamp = scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Normalize serialized findings before deduplication, preserving evidence and provenance.
    normalized = []
    seen_keys = set()
    finding_fields = {item.name for item in fields(Finding)}
    for finding in findings:
        if isinstance(finding, dict):
            finding = Finding(**{key: value for key, value in finding.items() if key in finding_fields})
        key = (finding.finding_id, finding.check_id, finding.title, finding.url, finding.parameter)
        if key not in seen_keys:
            seen_keys.add(key)
            normalized.append(finding)
    findings = normalized
    if isinstance(pisf_result, dict):
        values = {key: value for key, value in pisf_result.items() if key in {item.name for item in fields(PisfResult)}}
        values["controls"] = [PisfControl(**control) if isinstance(control, dict) else control
                              for control in values.get("controls", [])]
        pisf_result = PisfResult(**values)

    # Build report sections
    executive_summary = _build_executive_summary(domain, findings, pisf_result, ai_analysis)
    scope_methodology = _build_scope_methodology(domain, scope_type, timestamp)
    findings_summary = _build_findings_summary(findings)
    remediation_roadmap = _build_remediation_roadmap(findings)
    security_score = _calculate_security_score(findings, pisf_result)

    ai_model_used = "OFFLINE_DETERMINISTIC"
    fallback_triggered = use_mock
    data_sources = dict(scan_data.get("data_sources") or {}) if isinstance(scan_data, dict) else dict(getattr(scan_data, "data_sources", {}) or {})
    if isinstance(scan_data, dict):
        ai_model_used = scan_data.get("ai_model_used", "OFFLINE_DETERMINISTIC")
        fb_direct = scan_data.get("fallback_triggered", False)
        fb_ai = scan_data.get("ai_analysis", {}).get("_fallback_triggered", False) if isinstance(scan_data.get("ai_analysis"), dict) else False
        fb_recon = scan_data.get("recon_result", {}).get("fallback_triggered", False) if isinstance(scan_data.get("recon_result"), dict) else False
        fb_threat = scan_data.get("threat_result", {}).get("fallback_triggered", False) if isinstance(scan_data.get("threat_result"), dict) else False
        fb_visual = scan_data.get("visual_result", {}).get("fallback_triggered", False) if isinstance(scan_data.get("visual_result"), dict) else False
        fb_pentest = scan_data.get("pentest_result", {}).get("fallback_triggered", False) if isinstance(scan_data.get("pentest_result"), dict) else False
        fb_pisf = (scan_data.get("pisf_result", {}).get("status") != "success") if isinstance(scan_data.get("pisf_result"), dict) else False
        fb_finding = any(getattr(f, "provenance", "") == "MOCK_FALLBACK" for f in findings)
        fallback_triggered = fallback_triggered or fb_direct or fb_ai or fb_recon or fb_threat or fb_visual or fb_pentest or fb_pisf or fb_finding

        # Merge data_sources across sub-agents with consistent unconditional namespacing
        for agent_prefix, res_key in (
            ("recon", "recon_result"),
            ("threat_intel", "threat_result"),
            ("visual", "visual_result"),
            ("pentest", "pentest_result"),
        ):
            sub_res = scan_data.get(res_key)
            if isinstance(sub_res, dict) and "data_sources" in sub_res and isinstance(sub_res["data_sources"], dict):
                for k, v in sub_res["data_sources"].items():
                    key_name = k if k.startswith(f"{agent_prefix}_") else f"{agent_prefix}_{k}"
                    data_sources[key_name] = v

    elif hasattr(scan_data, "ai_model_used"):
        ai_model_used = getattr(scan_data, "ai_model_used", "OFFLINE_DETERMINISTIC")
        fallback_triggered = getattr(scan_data, "fallback_triggered", False) or use_mock

    if isinstance(scan_data, dict):
        mode = scan_data.get("mode", scan_data.get("execution_mode", "demo" if use_mock else "live"))
        scan_id = scan_data.get("scan_id", "")
    else:
        mode = getattr(scan_data, "mode", getattr(scan_data, "execution_mode", "demo" if use_mock else "live"))
        scan_id = getattr(scan_data, "scan_id", "")
    scope_methodology += f"\nExecution Mode: {mode}"
    if scan_id:
        scope_methodology += f"\nScan ID: {scan_id}"

    # Assemble ReportData
    report_data = ReportData(
        executive_summary=executive_summary,
        scope_methodology=scope_methodology,
        findings_summary=findings_summary,
        detailed_findings=findings,
        pisf_matrix=pisf_result.controls if pisf_result else [],
        remediation_roadmap=remediation_roadmap,
        security_posture_score=security_score,
        ai_model_used=ai_model_used,
        fallback_triggered=fallback_triggered,
        data_sources=data_sources,
        status="success",
    )


    # Generate PDF
    pdf_path = None
    try:
        pdf_path = _generate_pdf(report_data, domain)
        report_data.pdf_path = pdf_path
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        pdf_path = None
        report_data.status = "error"

    return {
        "report": report_data,
        "pdf_path": pdf_path,
        "security_score": security_score,
        "findings_summary": findings_summary,
        "status": report_data.status,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("CyberShield AI — Report Agent Tests")
    print("=" * 60)

    # TEST 1: Mock report generation
    print("\nTEST 1: Mock report generation")
    result = generate_report(use_mock=True)
    assert result["status"] == "success"
    assert result["report"] is not None
    assert 0 <= result["security_score"] <= 100
    print(f"  PASS: Security score={result['security_score']:.1f}")
    print(f"  Findings: {result['findings_summary']}")

    # TEST 2: PDF generated
    print("\nTEST 2: PDF generation")
    assert result["pdf_path"] is not None
    assert os.path.exists(result["pdf_path"])
    file_size = os.path.getsize(result["pdf_path"])
    assert file_size > 0, "PDF file is empty"
    print(f"  PASS: PDF at {result['pdf_path']} ({file_size} bytes)")

    # TEST 3: Report has all required fields
    print("\nTEST 3: Report structure")
    report = result["report"]
    assert report.executive_summary != ""
    assert report.scope_methodology != ""
    assert len(report.detailed_findings) > 0
    assert len(report.pisf_matrix) == 12
    print(f"  PASS: {len(report.detailed_findings)} findings, 12 PISF controls")

    print("\n" + "=" * 60)
    print("ALL REPORT AGENT TESTS PASSED")
    print("=" * 60)
