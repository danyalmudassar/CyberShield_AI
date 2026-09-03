"""
CyberShield AI — Visual Security Agent
========================================
Browser-level visual security analysis using pure HTTP requests.
Implements V-001 through V-008 checks defined in VisualResult model.

Checks:
  V-001: Admin panel detection          (common admin paths)
  V-002: HTTPS / TLS enforcement        (HTTP→HTTPS redirect + HSTS)
  V-003: CAPTCHA presence               (reCAPTCHA, hCaptcha, Cloudflare Turnstile)
  V-004: Third-party script inventory   (cross-origin <script src> tags)
  V-005: Suspicious UI elements         (hidden auto-submit forms, obfuscated inputs)
  V-006: Sensitive info in page source  (emails, phones, internal paths, API keys)
  V-007: Cookie consent banner          (GDPR compliance indicators)
  V-008: Mixed content                  (HTTP resources on HTTPS pages)

Usage:
    from agents.visual_agent import run_visual_scan
    result = run_visual_scan("testphp.vulnweb.com")
"""

import os
import re
import sys
import json
import logging
from urllib.parse import urlparse

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import VisualResult, Finding

logger = logging.getLogger(__name__)

_TIMEOUT = 3
_USER_AGENT = "CyberShield-AI/1.0 (Security Audit Tool)"
_HEADERS = {"User-Agent": _USER_AGENT}


def _get(url: str, allow_redirects: bool = True, timeout: int = _TIMEOUT):
    """Safe GET returning (response, error_str)."""
    try:
        resp = requests.get(
            url, timeout=timeout, headers=_HEADERS,
            allow_redirects=allow_redirects, verify=False
        )
        return resp, None
    except Exception as exc:
        return None, str(exc)


def _base_url(domain: str) -> str:
    if domain.startswith("http"):
        return domain.rstrip("/")
    return f"http://{domain}"


def _https_url(domain: str) -> str:
    d = domain.replace("http://", "").replace("https://", "").rstrip("/")
    return f"https://{d}"


# ---------------------------------------------------------------------------
# V-001: Admin panel detection
# ---------------------------------------------------------------------------
_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/administrator", "/administrator/",
    "/phpmyadmin", "/phpmyadmin/",
    "/cpanel", "/panel", "/controlpanel",
    "/manage", "/manager", "/management",
    "/dashboard", "/backend", "/portal",
    "/siteadmin", "/webadmin", "/adminpanel",
]

_ADMIN_INDICATORS = re.compile(
    r"(admin\s+panel|administration|login\s+to\s+admin|administrator\s+login|"
    r"admin\s+login|management\s+console|control\s+panel|phpmyadmin|"
    r"wp-admin|cPanel)",
    re.IGNORECASE,
)


def _check_v001_admin_panel(domain: str) -> tuple[bool, list[str]]:
    """Check for exposed admin panels. Returns (found, list_of_urls)."""
    base = _base_url(domain)
    found_panels = []

    for path in _ADMIN_PATHS:
        url = f"{base}{path}"
        resp, err = _get(url)
        if resp is None or resp.status_code >= 400:
            continue

        # Must look like a real admin page, not a generic 404
        if _ADMIN_INDICATORS.search(resp.text) or "login" in resp.text.lower():
            if resp.status_code in (200, 301, 302):
                found_panels.append(url)
                if len(found_panels) >= 3:
                    break

    return bool(found_panels), found_panels


# ---------------------------------------------------------------------------
# V-002: HTTPS enforcement and HSTS
# ---------------------------------------------------------------------------
def _check_v002_https(domain: str) -> tuple[bool, str]:
    """
    Returns (https_enforced, detail_str).
    True if HTTP redirects to HTTPS AND HSTS header present.
    """
    http_url = _base_url(domain)
    https_url = _https_url(domain)

    # Step 1: Check HTTP → HTTPS redirect
    resp_http, err = _get(http_url, allow_redirects=False)
    if resp_http and resp_http.status_code in (301, 302, 307, 308):
        location = resp_http.headers.get("Location", "")
        if location.startswith("https://"):
            # Step 2: Check HSTS on HTTPS
            resp_https, _ = _get(https_url)
            if resp_https:
                hsts = resp_https.headers.get("Strict-Transport-Security", "")
                if hsts:
                    return True, f"HTTP→HTTPS redirect active; HSTS: {hsts}"
                else:
                    return False, "HTTP redirects to HTTPS but no HSTS header found"
            return True, "HTTP redirects to HTTPS (HSTS not verified)"

    # Step 3: Check if site works on HTTPS at all
    resp_https, err2 = _get(https_url, timeout=8)
    if resp_https and resp_https.status_code < 400:
        hsts = resp_https.headers.get("Strict-Transport-Security", "")
        if hsts:
            return True, f"HTTPS available with HSTS: {hsts}"
        return False, "HTTPS available but HTTP→HTTPS redirect missing and no HSTS"

    if resp_http is None and resp_https is None:
        return False, f"UNREACHABLE: Target failed to respond on HTTP/HTTPS ({err or err2 or 'connection error'})"

    return False, f"No HTTPS enforcement: {err or err2 or 'HTTP site only'}"


# ---------------------------------------------------------------------------
# V-003: CAPTCHA presence
# ---------------------------------------------------------------------------
_CAPTCHA_PATTERNS = re.compile(
    r"(recaptcha|hcaptcha|turnstile\.cloudflare|captcha\.js|"
    r"g-recaptcha|h-captcha|cf-turnstile|data-sitekey|"
    r"grecaptcha|hcaptcha\.com|challenges\.cloudflare\.com)",
    re.IGNORECASE,
)

_LOGIN_PATHS = ["/login", "/wp-login.php", "/signin", "/admin/login", "/"]


def _check_v003_captcha(domain: str) -> tuple[bool, list[str]]:
    """Returns (captcha_found, list_of_pages_with_captcha)."""
    base = _base_url(domain)
    found_on = []

    for path in _LOGIN_PATHS:
        url = f"{base}{path}"
        resp, _ = _get(url)
        if resp is None or resp.status_code >= 400:
            continue

        if _CAPTCHA_PATTERNS.search(resp.text):
            found_on.append(path)

    return bool(found_on), found_on


# ---------------------------------------------------------------------------
# V-004: Third-party script inventory
# ---------------------------------------------------------------------------
_SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def _check_v004_third_party_scripts(domain: str) -> list[str]:
    """Returns list of cross-origin script URLs found on the homepage."""
    base = _base_url(domain)
    resp, _ = _get(base)
    if resp is None:
        return []

    parsed_base = urlparse(base)
    base_host = parsed_base.netloc.lower()

    third_party = []
    for match in _SCRIPT_SRC_PATTERN.finditer(resp.text):
        src = match.group(1)
        if src.startswith("//") or src.startswith("http"):
            # Normalize
            if src.startswith("//"):
                src = f"https:{src}"
            parsed_src = urlparse(src)
            src_host = parsed_src.netloc.lower()
            # Strip www. for comparison
            src_host_clean = src_host.replace("www.", "")
            base_host_clean = base_host.replace("www.", "")
            if src_host_clean and src_host_clean != base_host_clean:
                if src not in third_party:
                    third_party.append(src)

    return third_party[:20]  # Cap at 20


# ---------------------------------------------------------------------------
# V-005: Suspicious UI elements
# ---------------------------------------------------------------------------
_HIDDEN_AUTOSUBMIT = re.compile(
    r'<form[^>]*(style\s*=\s*["\'][^"\']*display\s*:\s*none|hidden|'
    r'onload\s*=\s*["\'].*submit)[^>]*>',
    re.IGNORECASE,
)
_HIDDEN_INPUT_SENSITIVE = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*(name=["\'](?:token|csrf|auth|key|secret|password|pass)["\'])',
    re.IGNORECASE,
)
_SUSPICIOUS_REDIRECTS = re.compile(
    r"(window\.location\s*=|window\.location\.href\s*=|document\.location\s*=)",
    re.IGNORECASE,
)
_IFRAME_HIDDEN = re.compile(
    r'<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width=["\']0["\']|height=["\']0["\'])',
    re.IGNORECASE,
)


def _check_v005_suspicious_elements(domain: str) -> list[str]:
    """Returns list of suspicious UI element descriptions found."""
    base = _base_url(domain)
    resp, _ = _get(base)
    if resp is None:
        return []

    body = resp.text
    suspicious = []

    if _HIDDEN_AUTOSUBMIT.search(body):
        suspicious.append("Hidden auto-submitting form detected")
    if _HIDDEN_INPUT_SENSITIVE.search(body):
        suspicious.append("Hidden input with sensitive name (token/password/key)")
    if _SUSPICIOUS_REDIRECTS.search(body):
        count = len(_SUSPICIOUS_REDIRECTS.findall(body))
        suspicious.append(f"JavaScript redirect ({count} occurrence(s)) detected in page source")
    if _IFRAME_HIDDEN.search(body):
        suspicious.append("Hidden iframe (0px or display:none) detected")

    # Check for data-collection pixel trackers
    pixel_pattern = re.compile(r'<img[^>]+(width=["\']1["\']|height=["\']1["\'])[^>]*>', re.IGNORECASE)
    if pixel_pattern.search(body):
        suspicious.append("1x1 tracking pixel detected")

    return suspicious


# ---------------------------------------------------------------------------
# V-006: Sensitive information in page source
# ---------------------------------------------------------------------------
_EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)
_PHONE_PATTERN = re.compile(
    r'(\+92[\s\-]?\d{3}[\s\-]?\d{7}|\+\d{1,3}[\s\-]?\d{9,15}|\b0\d{2,3}[\s\-]\d{7,8}\b)'
)
_INTERNAL_PATH_PATTERN = re.compile(
    r'(/var/www/|/home/\w+|/etc/|C:\\\\|D:\\\\|/srv/|/opt/|/usr/local/)',
    re.IGNORECASE,
)
_API_KEY_PATTERN = re.compile(
    r'(api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|bearer\s+[A-Za-z0-9._\-]{20,})',
    re.IGNORECASE,
)
_COMMENT_CREDENTIALS = re.compile(
    r'<!--[^>]*(password|passwd|pwd|secret|credential|token)[^>]*-->',
    re.IGNORECASE,
)


def _check_v006_sensitive_info(domain: str) -> list[str]:
    """Returns list of sensitive data found in page source."""
    base = _base_url(domain)
    resp, _ = _get(base)
    if resp is None:
        return []

    body = resp.text
    sensitive = []

    emails = _EMAIL_PATTERN.findall(body)
    if emails:
        # Filter out common false positives
        real_emails = [e for e in emails if not any(fp in e.lower() for fp in ["example.com", "test.com", "domain.com", "your@"])]
        if real_emails:
            sensitive.append(f"Email addresses exposed: {', '.join(real_emails[:3])}")

    phones = _PHONE_PATTERN.findall(body)
    if phones:
        sensitive.append(f"Phone numbers in source: {', '.join(str(p) for p in phones[:2])}")

    if _INTERNAL_PATH_PATTERN.search(body):
        matches = _INTERNAL_PATH_PATTERN.findall(body)
        sensitive.append(f"Internal server paths exposed: {', '.join(set(matches[:3]))}")

    if _API_KEY_PATTERN.search(body):
        sensitive.append("Potential API key or access token pattern detected in page source")

    if _COMMENT_CREDENTIALS.search(body):
        sensitive.append("Credentials mentioned in HTML comments")

    return sensitive


# ---------------------------------------------------------------------------
# V-007: Cookie consent banner (GDPR)
# ---------------------------------------------------------------------------
_COOKIE_CONSENT_PATTERNS = re.compile(
    r"(cookie\s+consent|we\s+use\s+cookies|cookie\s+policy|cookieconsent|"
    r"gdpr|privacy\s+notice|accept\s+cookies|manage\s+cookies|"
    r"cookie\s+banner|cookiebanner|cookie-banner|onetrust|cookielaw|"
    r"cc-window|cnzz|cookie\s+notice)",
    re.IGNORECASE,
)


def _check_v007_cookie_consent(domain: str) -> bool:
    """Returns True if cookie consent banner detected."""
    base = _base_url(domain)
    resp, _ = _get(base)
    if resp is None:
        return False

    return bool(_COOKIE_CONSENT_PATTERNS.search(resp.text))


# ---------------------------------------------------------------------------
# V-008: Mixed content detection
# ---------------------------------------------------------------------------
_HTTP_RESOURCE_PATTERN = re.compile(
    r'(src|href|action|data-src)\s*=\s*["\']http://([^"\']+)["\']',
    re.IGNORECASE,
)


def _check_v008_mixed_content(domain: str) -> tuple[bool, list[str]]:
    """
    Returns (mixed_content_found, list_of_http_resources).
    Only meaningful when page is served over HTTPS.
    """
    https_url = _https_url(domain)
    resp, err = _get(https_url, timeout=8)
    if resp is None or resp.status_code >= 400:
        return False, []

    mixed = []
    for match in _HTTP_RESOURCE_PATTERN.finditer(resp.text):
        attr = match.group(1)
        resource_url = f"http://{match.group(2)}"
        # Ignore relative references and localhost
        if "localhost" not in resource_url and "127.0.0.1" not in resource_url:
            mixed.append(f"{attr}={resource_url}")
            if len(mixed) >= 10:
                break

    return bool(mixed), mixed


# ---------------------------------------------------------------------------
# Visual findings to Finding objects
# ---------------------------------------------------------------------------
def _build_findings(domain: str, visual: VisualResult, base: str, provenance: str = "OFFLINE_VERIFIER") -> list[Finding]:
    """Convert VisualResult fields into Finding objects for the pipeline."""
    findings = []

    if visual.admin_panel_detected:
        findings.append(Finding(
            finding_id="CYBERSHIELD-V001",
            check_id="V-001",
            title="Admin panel exposed publicly",
            severity="High",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            owasp_top10="A05:2021 – Security Misconfiguration",
            wstg_id="WSTG-CONF-05",
            cwe_id="CWE-16",
            pisf_control="Control 3: Access Control",
            iso_27001_control="A.5.15: Access control",
            nist_csf_function="PROTECT",
            description="Admin/management panels are publicly accessible without VPN or IP restriction.",
            url=base,
            evidence=f"Admin panels found: {', '.join(visual.suspicious_elements[:3]) or base + '/admin'}",
            business_impact="Direct entry point for brute-force and credential stuffing attacks on admin accounts",
            remediation="Restrict admin paths to specific IP ranges or VPN; implement MFA on admin logins",
            remediation_priority="WEEK 1",
            provenance=provenance,
            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        ))

    if not visual.https_padlock:
        findings.append(Finding(
            finding_id="CYBERSHIELD-V002",
            check_id="V-002",
            title="HTTPS not enforced or HSTS missing",
            severity="High",
            cvss_score=7.4,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp_top10="A02:2021 – Cryptographic Failures",
            wstg_id="WSTG-CRYP-01",
            cwe_id="CWE-319",
            pisf_control="Control 7: Cryptography",
            iso_27001_control="A.8.24: Use of cryptography",
            nist_csf_function="PROTECT",
            description="Site does not enforce HTTPS via HTTP→HTTPS redirect or is missing HSTS header.",
            url=base,
            evidence="HTTP→HTTPS redirect absent or Strict-Transport-Security header not present",
            business_impact="Man-in-the-middle attacks can intercept session cookies and credentials in transit",
            remediation="Enable HTTP→HTTPS permanent redirect (301); add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            remediation_priority="WEEK 1",
            provenance=provenance,
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
        ))

    if visual.third_party_scripts:
        high_risk = [s for s in visual.third_party_scripts if any(
            kw in s.lower() for kw in ["analytics", "facebook", "twitter", "pixel", "track", "ads"]
        )]
        if len(visual.third_party_scripts) > 5 or high_risk:
            findings.append(Finding(
                finding_id="CYBERSHIELD-V004",
                check_id="V-004",
                title=f"Excessive third-party scripts ({len(visual.third_party_scripts)} found)",
                severity="Medium",
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
                owasp_top10="A06:2021 – Vulnerable and Outdated Components",
                wstg_id="WSTG-CONF-01",
                cwe_id="CWE-829",
                pisf_control="Control 8: System Acquisition and Development",
                iso_27001_control="A.8.28: Secure coding",
                nist_csf_function="PROTECT",
                description=f"{len(visual.third_party_scripts)} third-party scripts loaded, including tracking/analytics.",
                url=base,
                evidence=f"Third-party scripts: {'; '.join(visual.third_party_scripts[:5])}",
                business_impact="Supply chain attack — compromised third-party CDN can inject malicious code affecting all users",
                remediation="Implement Subresource Integrity (SRI) on all external scripts; use Content-Security-Policy",
                remediation_priority="MONTH 1",
                provenance=provenance,
                references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
            ))

    if visual.sensitive_info_exposed:
        findings.append(Finding(
            finding_id="CYBERSHIELD-V006",
            check_id="V-006",
            title="Sensitive information exposed in page source",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            owasp_top10="A01:2021 – Broken Access Control",
            wstg_id="WSTG-INFO-01",
            cwe_id="CWE-200",
            pisf_control="Control 6: Information Security Policies",
            iso_27001_control="A.8.9: Configuration management",
            nist_csf_function="PROTECT",
            description=f"Sensitive data found in page source: {'; '.join(visual.sensitive_info_exposed[:3])}",
            url=base,
            evidence=f"Sensitive patterns in page source: {'; '.join(visual.sensitive_info_exposed[:5])}",
            business_impact="Exposed emails enable phishing; internal paths aid enumeration; API keys enable unauthorized API access",
            remediation="Remove sensitive data from client-facing HTML/JS; use server-side rendering for data",
            remediation_priority="MONTH 1",
            provenance=provenance,
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        ))

    if visual.mixed_content:
        findings.append(Finding(
            finding_id="CYBERSHIELD-V008",
            check_id="V-008",
            title="Mixed content — HTTP resources on HTTPS page",
            severity="Medium",
            cvss_score=4.3,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
            owasp_top10="A02:2021 – Cryptographic Failures",
            wstg_id="WSTG-CRYP-01",
            cwe_id="CWE-319",
            pisf_control="Control 7: Cryptography",
            iso_27001_control="A.8.24: Use of cryptography",
            nist_csf_function="PROTECT",
            description="HTTPS page loads resources over insecure HTTP, undermining transport security.",
            url=_https_url(domain),
            evidence=f"HTTP resources on HTTPS page: {'; '.join(visual.suspicious_elements[:3]) or 'detected'}",
            business_impact="HTTP resources can be intercepted and replaced with malicious content by MitM attackers",
            remediation="Update all resource URLs to HTTPS; use protocol-relative URLs (//); enforce CSP upgrade-insecure-requests",
            remediation_priority="MONTH 1",
            provenance=provenance,
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
        ))

    return findings



# ---------------------------------------------------------------------------
# Mock data loader
# ---------------------------------------------------------------------------
def _load_mock() -> dict:
    mock_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "mocks", "mock_visual.json",
    )
    if os.path.exists(mock_path):
        with open(mock_path) as f:
            return json.load(f)
    # Minimal inline fallback
    return {
        "admin_panel_detected": False,
        "https_padlock": True,
        "captcha_present": False,
        "third_party_scripts": ["https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"],
        "suspicious_elements": [],
        "sensitive_info_exposed": [],
        "cookie_consent": False,
        "mixed_content": False,
        "visual_findings": [],
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run_visual_scan(domain: str, use_mock: bool = False) -> dict:
    """Run visual security analysis against the target domain.

    Args:
        domain: Target domain (e.g. "testphp.vulnweb.com").
        use_mock: If True, return canned mock results.

    Returns:
        Dict with visual_result (VisualResult), findings (list[Finding]), status, data_sources.
    """
    base = _base_url(domain)

    # ── MOCK MODE ────────────────────────────────────────────────────────────
    if use_mock:
        mock = _load_mock()
        visual = VisualResult(
            screenshot_path=mock.get("screenshot_path"),
            admin_panel_detected=mock.get("admin_panel_detected", False),
            https_padlock=mock.get("https_padlock", True),
            captcha_present=mock.get("captcha_present", False),
            third_party_scripts=mock.get("third_party_scripts", []),
            suspicious_elements=mock.get("suspicious_elements", []),
            sensitive_info_exposed=mock.get("sensitive_info_exposed", []),
            cookie_consent=mock.get("cookie_consent", False),
            mixed_content=mock.get("mixed_content", False),
            visual_findings=mock.get("visual_findings", []),
            status="mock",
        )
        findings = _build_findings(domain, visual, base, provenance="MOCK_FALLBACK")

        return {
            "visual_result": visual,
            "findings": findings,
            "status": "mock",
            "data_sources": {"visual": "mock"},
            "fallback_triggered": True,
        }

    # ── LIVE MODE ─────────────────────────────────────────────────────────────
    logger.info("[visual_agent] Starting visual scan of %s", domain)

    # Suppress SSL warnings for target probing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    visual_findings_list = []
    errors = []

    # V-001: Admin panel
    try:
        admin_detected, admin_urls = _check_v001_admin_panel(domain)
        if admin_detected:
            visual_findings_list.append({"check": "V-001", "detail": f"Admin panels: {admin_urls}"})
        logger.info("[V-001] admin_panel=%s urls=%s", admin_detected, admin_urls)
    except Exception as e:
        admin_detected, admin_urls = False, []
        errors.append(f"V-001: {e}")
        logger.warning("[V-001] Error: %s", e)

    # V-002: HTTPS enforcement
    try:
        https_ok, https_detail = _check_v002_https(domain)
        if not https_ok:
            visual_findings_list.append({"check": "V-002", "detail": https_detail})
        logger.info("[V-002] https_enforced=%s detail=%s", https_ok, https_detail)
    except Exception as e:
        https_ok = False
        errors.append(f"V-002: {e}")
        logger.warning("[V-002] Error: %s", e)

    # V-003: CAPTCHA
    try:
        captcha_found, captcha_pages = _check_v003_captcha(domain)
        logger.info("[V-003] captcha=%s pages=%s", captcha_found, captcha_pages)
    except Exception as e:
        captcha_found, captcha_pages = False, []
        errors.append(f"V-003: {e}")
        logger.warning("[V-003] Error: %s", e)

    # V-004: Third-party scripts
    try:
        third_party = _check_v004_third_party_scripts(domain)
        logger.info("[V-004] third_party_scripts=%d", len(third_party))
    except Exception as e:
        third_party = []
        errors.append(f"V-004: {e}")
        logger.warning("[V-004] Error: %s", e)

    # V-005: Suspicious elements
    try:
        suspicious = _check_v005_suspicious_elements(domain)
        if suspicious:
            visual_findings_list.append({"check": "V-005", "detail": suspicious})
        logger.info("[V-005] suspicious_elements=%s", suspicious)
    except Exception as e:
        suspicious = []
        errors.append(f"V-005: {e}")
        logger.warning("[V-005] Error: %s", e)

    # V-006: Sensitive info
    try:
        sensitive = _check_v006_sensitive_info(domain)
        if sensitive:
            visual_findings_list.append({"check": "V-006", "detail": sensitive})
        logger.info("[V-006] sensitive_info=%s", sensitive)
    except Exception as e:
        sensitive = []
        errors.append(f"V-006: {e}")
        logger.warning("[V-006] Error: %s", e)

    # V-007: Cookie consent
    try:
        cookie_consent = _check_v007_cookie_consent(domain)
        logger.info("[V-007] cookie_consent=%s", cookie_consent)
    except Exception as e:
        cookie_consent = False
        errors.append(f"V-007: {e}")
        logger.warning("[V-007] Error: %s", e)

    # V-008: Mixed content
    try:
        mixed_content, mixed_resources = _check_v008_mixed_content(domain)
        if mixed_content:
            visual_findings_list.append({"check": "V-008", "detail": f"HTTP resources: {mixed_resources[:3]}"})
        logger.info("[V-008] mixed_content=%s resources=%d", mixed_content, len(mixed_resources))
    except Exception as e:
        mixed_content, mixed_resources = False, []
        errors.append(f"V-008: {e}")
        logger.warning("[V-008] Error: %s", e)

    # Build VisualResult
    visual = VisualResult(
        screenshot_path=None,
        admin_panel_detected=admin_detected,
        https_padlock=https_ok,
        captcha_present=captcha_found,
        third_party_scripts=third_party,
        suspicious_elements=suspicious + ([f"Mixed content: {r}" for r in mixed_resources[:3]] if mixed_resources else []),
        sensitive_info_exposed=sensitive,
        cookie_consent=cookie_consent,
        mixed_content=mixed_content,
        visual_findings=visual_findings_list,
        status="success" if not errors else "partial",
    )

    # If V-002 returned UNREACHABLE, do not report false-positive High finding
    is_unreachable = any(vf.get("status") == "unreachable" for vf in visual_findings_list if isinstance(vf, dict))
    if is_unreachable and not visual.https_padlock:
        # Override https_padlock to True for finding generation so false-positive High isn't added
        visual_for_findings = VisualResult(**{**visual.__dict__, "https_padlock": True})
        findings = _build_findings(domain, visual_for_findings, base, provenance="OFFLINE_VERIFIER")
        findings.append(Finding(
            finding_id="CYBERSHIELD-V002",
            check_id="V-002",
            title="HTTPS check incomplete — target unreachable",
            severity="Info",
            description="Target did not respond to HTTP/HTTPS probes during visual analysis.",
            url=base,
            evidence="Target failed to respond to probes",
            provenance="OFFLINE_VERIFIER",
        ))
    else:
        findings = _build_findings(domain, visual, base, provenance="OFFLINE_VERIFIER")

    return {
        "visual_result": visual,
        "findings": findings,
        "status": visual.status,
        "data_sources": {"visual": visual.status},
        "errors": errors,
        "fallback_triggered": use_mock or bool(errors),
    }


# ---------------------------------------------------------------------------
# CLI test block
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=" * 60)
    print("CyberShield AI — Visual Agent Tests (V-001 to V-008)")
    print("=" * 60)

    targets = ["testphp.vulnweb.com", "example.com"]

    for target in targets:
        print(f"\n{'─'*60}")
        print(f"Target: {target}")
        print(f"{'─'*60}")
        result = run_visual_scan(target)

        visual = result["visual_result"]
        print(f"  Status          : {result['status']}")
        print(f"  V-001 Admin panel: {visual.admin_panel_detected}")
        print(f"  V-002 HTTPS padlock: {visual.https_padlock}")
        print(f"  V-003 CAPTCHA   : {visual.captcha_present}")
        print(f"  V-004 3rd-party scripts: {len(visual.third_party_scripts)}")
        print(f"  V-005 Suspicious: {visual.suspicious_elements}")
        print(f"  V-006 Sensitive : {visual.sensitive_info_exposed}")
        print(f"  V-007 Cookie consent: {visual.cookie_consent}")
        print(f"  V-008 Mixed content: {visual.mixed_content}")
        print(f"  Visual findings : {len(visual.visual_findings)}")
        print(f"  Pipeline findings: {len(result['findings'])}")
        for f in result["findings"]:
            print(f"    [{f.severity}] {f.check_id}: {f.title}")

        # Assertions
        assert hasattr(visual, "admin_panel_detected"), "Missing field: admin_panel_detected"
        assert hasattr(visual, "https_padlock"), "Missing field: https_padlock"
        assert hasattr(visual, "captcha_present"), "Missing field: captcha_present"
        assert isinstance(visual.third_party_scripts, list), "third_party_scripts must be list"
        assert isinstance(visual.suspicious_elements, list), "suspicious_elements must be list"
        assert isinstance(visual.sensitive_info_exposed, list), "sensitive_info_exposed must be list"
        assert isinstance(visual.visual_findings, list), "visual_findings must be list"
        assert all(hasattr(f, "check_id") for f in result["findings"]), "All findings must have check_id"
        print(f"  PASS: All assertions passed for {target}")

    print("\n" + "=" * 60)
    print("ALL VISUAL AGENT TESTS PASSED")
    print("=" * 60)
