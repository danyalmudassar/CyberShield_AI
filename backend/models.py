"""
CyberShield AI — Data Models (Schema Authority)
================================================
Every data structure used across the entire CyberShield AI pipeline
is defined here. All agents and utils import from this file.
This ensures consistent data shapes and makes the project
understandable by any coding agent or developer.

Check ID prefixes:
  R-xxx  — Reconnaissance checks (DNS, SSL, Headers, Tech)
  T-xxx  — Threat intelligence checks
  V-xxx  — Visual security checks
  P-xxx  — Pentest/active checks
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class DnsResult:
    """DNS reconnaissance results (Check IDs: R-001 to R-010).

    Holds all DNS-related data gathered during passive reconnaissance,
    including record types, email security records, and WHOIS data.
    """

    a_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None           # R-005
    dmarc_record: Optional[str] = None         # R-006
    dkim_found: bool = False                    # R-007
    whois_registrar: Optional[str] = None       # R-008
    whois_creation_date: Optional[str] = None
    whois_expiry_date: Optional[str] = None
    domain_expiry_days: Optional[int] = None    # R-009
    registrar_locked: Optional[bool] = None     # R-010
    status: str = "success"                     # success | warning | error


@dataclass
class SslResult:
    """SSL/TLS certificate results (Check IDs: R-011 to R-016).

    Captures certificate validity, expiry, issuer details, TLS version
    support, and Subject Alternative Names gathered from the target.

    ``status`` distinguishes probe outcome from certificate validity:
      - ``"success"`` means the probe ran; ``valid`` reflects the cert.
      - ``"error"``   means the probe itself failed (connection refused,
        DNS failure, timeout). A failed probe is NOT_ASSESSABLE, not a
        confirmed certificate defect.
    """

    valid: bool = False                         # R-011
    expiry_date: Optional[str] = None           # R-012
    days_remaining: Optional[int] = None
    issuer: Optional[str] = None                # R-013
    is_self_signed: bool = False
    tls_versions: list[str] = field(default_factory=list)   # R-014
    cipher_suite: Optional[str] = None          # R-015
    cipher_strength: Optional[str] = None
    sans: list[str] = field(default_factory=list)           # R-016
    error: Optional[str] = None                 # probe failure message (status="error" only)
    status: str = "success"


@dataclass
class HeaderResult:
    """HTTP security header results (Check IDs: R-017 to R-019, R-025).

    Tracks which security-relevant HTTP response headers are present or
    absent, computes a header score, and records information-disclosure
    headers such as Server and X-Powered-By.
    """

    headers_present: dict = field(default_factory=dict)   # header_name: {present, value}
    missing_headers: list[str] = field(default_factory=list)  # names of absent security headers
    hsts_present: bool = False                 # R-017
    https_redirect: Optional[bool] = False               # R-018
    header_score: int = 0                      # R-019: 0-6
    overall_risk: str = "HIGH"                 # HIGH | MEDIUM | LOW
    x_powered_by: Optional[str] = None         # R-025
    server_header: Optional[str] = None
    status: str = "success"


@dataclass
class TechResult:
    """Technology fingerprinting results (Check IDs: R-020 to R-024).

    Identifies server software, CMS, programming language, CDN presence,
    robots.txt content, sitemap availability, and meta generator tags.
    """

    server: Optional[str] = None               # R-020
    cms: Optional[str] = None                  # R-021
    programming_language: Optional[str] = None
    cdn: Optional[str] = None
    robots_txt: Optional[str] = None           # R-022
    sitemap_found: bool = False                # R-023
    meta_generator: Optional[str] = None       # R-024
    technologies: list[str] = field(default_factory=list)
    status: str = "success"


@dataclass
class ThreatResult:
    """Threat intelligence results (Check IDs: T-001 to T-007).

    Aggregates external threat intelligence: VirusTotal reputation,
    Shodan port/vuln data, CVE matches, Pakistan-region threat indicators,
    blacklist status, and breach data feeds.
    """

    virustotal_score: Optional[int] = None     # T-001
    virustotal_positives: int = 0
    virustotal_url_scan: Optional[dict] = None # T-002
    shodan_ports: list[int] = field(default_factory=list)    # T-003
    shodan_vulns: list[str] = field(default_factory=list)
    cve_matches: list[dict] = field(default_factory=list)    # T-004
    pakistan_threat_indicators: list[str] = field(default_factory=list)  # T-005
    blacklist_status: Optional[str] = None     # T-006
    breach_data: Optional[dict] = None         # T-007
    threat_score: int = 0                      # 0-100
    status: str = "success"


@dataclass
class VisualResult:
    """Visual security analysis results (Check IDs: V-001 to V-008).

    Stores findings from Playwright-driven browser analysis: admin panel
    detection, HTTPS padlock, CAPTCHA presence, third-party scripts,
    suspicious UI elements, sensitive information exposure, and
    mixed-content issues.
    """

    screenshot_path: Optional[str] = None
    admin_panel_detected: bool = False         # V-001
    https_padlock: bool = False                # V-002
    captcha_present: bool = False              # V-003
    third_party_scripts: list[str] = field(default_factory=list)      # V-004
    suspicious_elements: list[str] = field(default_factory=list)      # V-005
    sensitive_info_exposed: list[str] = field(default_factory=list)   # V-006
    cookie_consent: bool = False               # V-007
    mixed_content: bool = False                # V-008
    visual_findings: list[dict] = field(default_factory=list)
    status: str = "success"


@dataclass
class Finding:
    """Individual security finding with full framework mapping.

    Each finding is enriched with cross-framework references (OWASP, WSTG,
    CWE, PISF 2026, ISO 27001, NIST CSF) to support compliance reporting
    alongside technical remediation guidance.
    """

    finding_id: str = ""                       # e.g., CYBERSHIELD-001
    check_id: str = ""                         # e.g., R-011, P-006
    title: str = ""
    severity: str = "Info"                     # Critical | High | Medium | Low | Info
    cvss_score: float = 0.0                    # CVSSv3.1: 0.0-10.0
    cvss_vector: str = ""                      # e.g., CVSS:3.1/AV:N/AC:L/...
    owasp_top10: str = ""                      # e.g., A03:2021 – Injection
    wstg_id: str = ""                          # e.g., WSTG-INPV-05
    cwe_id: str = ""                           # e.g., CWE-89
    pisf_control: str = ""                     # e.g., Control 8
    iso_27001_control: str = ""                # e.g., A.8.28
    nist_csf_function: str = ""                # e.g., PROTECT
    description: str = ""
    url: str = ""
    parameter: str = ""
    payload_used: str = ""
    evidence: str = ""
    business_impact: str = ""
    remediation: str = ""
    remediation_priority: str = ""             # WEEK 1 | MONTH 1 | MONTH 3
    provenance: str = "OFFLINE_VERIFIER"       # OFFLINE_VERIFIER | LLM_REASONING | MOCK_FALLBACK
    check_status: str = "SUCCESS"              # SUCCESS | VULNERABLE | INCOMPLETE | UNREACHABLE | ERROR | UNVERIFIED_CANDIDATE | MOCK_FALLBACK
    references: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Normalize legacy findings without promoting explicit non-confirmed evidence.

        Legacy successful checks with non-Info severity imply a vulnerability.
        Explicit statuses remain authoritative; severity alone cannot upgrade them.
        Failed probes remain informational and mock/AI provenance stays unconfirmed.
        """
        if self.severity:
            sev_cap = self.severity.strip().capitalize()
            if sev_cap in ("Critical", "High", "Medium", "Low", "Info"):
                self.severity = sev_cap

        # Invariant 1: Probe-level failure/unreachability FIRST precedence.
        # Errored or Unreachable probes CANNOT be High/Critical vulnerabilities -> Force severity to Info.
        if self.check_status in ("UNREACHABLE", "ERROR"):
            self.severity = "Info"

        # Invariant 2: Provenance alignment for non-errored probes.
        elif self.provenance in ("MOCK_FALLBACK", "MOCK", "FIXTURE", "DEMO"):
            self.check_status = "MOCK_FALLBACK"
        elif self.provenance == "LLM_REASONING":
            self.check_status = "UNVERIFIED_CANDIDATE"

        # Legacy SUCCESS findings infer confirmation from non-Info severity only.
        elif self.severity in ("Critical", "High", "Medium", "Low"):
            if self.check_status == "SUCCESS":
                self.check_status = "VULNERABLE"

        # Invariant 4: Info severity clean findings cannot be VULNERABLE -> Auto-correct to SUCCESS
        elif self.severity == "Info" and self.check_status == "VULNERABLE":
            self.check_status = "SUCCESS"


def is_live_confirmed_vulnerability(finding) -> bool:
    """Return True ONLY if finding/dict represents an explicitly confirmed live vulnerability.

    Excludes empty data, missing severity, INCOMPLETE checks, mock fallback data,
    unverified LLM candidates, probe errors, and clean/safe checks.
    Inspects BOTH check_status and provenance/_provenance.
    """
    if not finding:
        return False

    # Extract check_status and provenance
    if isinstance(finding, dict):
        chk_st = finding.get("check_status")
        prov = finding.get("provenance") or finding.get("_provenance") or ""
        sev = finding.get("severity") or ""
    else:
        chk_st = getattr(finding, "check_status", None)
        prov = getattr(finding, "provenance", None) or getattr(finding, "_provenance", None) or ""
        sev = getattr(finding, "severity", "") or ""

    # Reject mock or LLM reasoning provenance immediately
    if prov in ("MOCK_FALLBACK", "LLM_REASONING", "MOCK", "FIXTURE", "DEMO"):
        return False

    # Reject non-vulnerable statuses
    if chk_st in ("UNVERIFIED_CANDIDATE", "MOCK_FALLBACK", "NOT_ASSESSABLE", "SAFE", "PASS", "SUCCESS", "UNKNOWN", "UNREACHABLE", "ERROR", "INCOMPLETE"):
        return False

    # Require explicit VULNERABLE or CONFIRMED check_status
    if chk_st in ("VULNERABLE", "CONFIRMED"):
        return True

    return False





@dataclass
class PisfControl:
    """PISF 2026 compliance control result.

    Represents the assessment outcome for a single PISF 2026 control domain,
    including cross-mappings to ISO 27001, NIST CSF, CIS Controls, and
    OWASP Top 10.
    """

    control_id: int = 0
    domain: str = ""
    status: str = "NOT_ASSESSABLE"             # PASS | FAIL | PARTIAL | NOT_ASSESSABLE
    evidence: str = ""
    recommendation: str = ""
    international_mapping: dict = field(default_factory=dict)
    # {"iso_27001": "...", "nist_csf": "...", "cis_control": "...", "owasp_top10": "..."}


@dataclass
class PisfResult:
    """Complete PISF 2026 compliance assessment.

    Aggregates all 12 control domain results into an overall score and
    summary counts for compliant vs. non-compliant controls.
    """

    controls: list[PisfControl] = field(default_factory=list)
    overall_score: float = 0.0                 # 0-100
    max_achievable_score: float = 100.0        # Theoretical max score based on assessable domains
    compliant_controls: int = 0
    assessable_controls_count: int = 10
    total_controls: int = 12
    status: str = "success"



@dataclass
class ReportData:
    """Complete security audit report.

    Holds all sections required for a professional PDF report: executive
    summary, methodology, findings, PISF compliance matrix, remediation
    roadmap, overall security posture score, and AI engine execution provenance.
    """

    executive_summary: str = ""
    scope_methodology: str = ""
    findings_summary: dict = field(default_factory=dict)
    detailed_findings: list[Finding] = field(default_factory=list)
    pisf_matrix: list[PisfControl] = field(default_factory=list)
    remediation_roadmap: dict = field(default_factory=dict)
    security_posture_score: Optional[float] = None  # 0-100; None when evidence is unavailable
    pdf_path: Optional[str] = None
    ai_model_used: str = "OFFLINE_DETERMINISTIC"
    fallback_triggered: bool = False
    data_sources: dict = field(default_factory=dict)
    status: str = "success"



@dataclass
class EngagementDetails:
    """Pre-engagement / authorization details (PTES Phase 1).

    Records the explicit authorization decision before any scanning begins.
    The pipeline_action field controls whether the agent graph proceeds
    (PROCEED) or halts (STOP) immediately after this phase.
    """

    target_domain: str = ""
    authorized: bool = False
    scope_type: str = "passive_only"           # passive_only | full_pentest
    contact_email: str = ""
    timestamp: str = ""
    auth_status: str = "PENDING"               # GRANTED | DENIED | PENDING
    pipeline_action: str = "STOP"             # PROCEED | STOP


@dataclass
class ScanState:
    """Master state object passed between all agents in the graph.

    This is the single shared data container that flows through every node
    in the LangGraph agent pipeline. Each agent reads from and writes to
    its relevant sub-fields; the orchestrator uses scan_progress to track
    which agents have completed and whether live or mock data was used.
    """

    domain: str = ""
    authorized: bool = False
    scope_type: str = "passive_only"
    timestamp: str = ""
    engagement: Optional[EngagementDetails] = None
    recon: Optional[DnsResult] = None
    ssl: Optional[SslResult] = None
    headers: Optional[HeaderResult] = None
    tech: Optional[TechResult] = None
    threats: Optional[ThreatResult] = None
    visual: Optional[VisualResult] = None
    pentest_findings: list[Finding] = field(default_factory=list)
    pisf: Optional[PisfResult] = None
    report: Optional[ReportData] = None
    all_findings: list[Finding] = field(default_factory=list)
    execution_mode: str = "live"              # live | rules_only | demo
    strict_live: bool = False
    owner_id: str = "usr_default_dev"
    owner_email: str = "dev@cybershield.ai"
    scan_progress: dict = field(default_factory=dict)
    # {"recon": "live", "threats": "mock", "visual": "skipped", ...}

    @property
    def report_path(self) -> Optional[str]:
        """Convenience accessor for the generated PDF report filepath."""
        return self.report.pdf_path if self.report else None


if __name__ == "__main__":
    # Smoke-test: instantiate every dataclass with default values
    _ = DnsResult()
    _ = SslResult()
    _ = HeaderResult()
    _ = TechResult()
    _ = ThreatResult()
    _ = VisualResult()
    _ = Finding()
    _ = PisfControl()
    _ = PisfResult()
    _ = ReportData()
    _ = EngagementDetails()
    _ = ScanState()

    # Verify nested instantiation inside ScanState
    state = ScanState(
        domain="testphp.vulnweb.com",
        authorized=True,
        scope_type="passive_only",
        timestamp=datetime.now().isoformat(),
        engagement=EngagementDetails(
            target_domain="testphp.vulnweb.com",
            authorized=True,
            pipeline_action="PROCEED",
        ),
        recon=DnsResult(a_records=["44.228.249.3"]),
        ssl=SslResult(valid=False, status="warning"),
        headers=HeaderResult(header_score=0, overall_risk="HIGH"),
        tech=TechResult(server="nginx/1.19.0"),
        threats=ThreatResult(threat_score=72),
        visual=VisualResult(admin_panel_detected=True),
        pisf=PisfResult(overall_score=17.0, compliant_controls=2),
        report=ReportData(security_posture_score=28.0),
        pentest_findings=[
            Finding(
                finding_id="CYBERSHIELD-001",
                check_id="P-006",
                title="SQL Injection in search parameter",
                severity="Critical",
                cvss_score=9.8,
            )
        ],
    )
    assert state.domain == "testphp.vulnweb.com"
    assert state.recon is not None
    assert state.pentest_findings[0].severity == "Critical"

    print("PASS: All models created successfully")
