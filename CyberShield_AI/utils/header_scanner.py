"""
CyberShield AI — HTTP Security Header Scanner
================================================
Check IDs: R-017 to R-019, R-025
Analyzes HTTP response headers for security best practices.

R-017: HSTS present             R-019: 6-header completeness score
R-018: HTTPS redirect check     R-025: X-Powered-By disclosure

Scoring: 0-6 (each security header = +1)
  <3 = HIGH risk, 3-4 = MEDIUM risk, 5-6 = LOW risk

Usage:
    from utils.header_scanner import run_header_scan
    result = run_header_scan("example.com")
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import HeaderResult
from utils.http_client import get, get_headers, safe_request, target_http_urls

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

MOCK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "mocks",
    "mock_headers.json",
)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_security_headers(domain: str) -> dict:
    """Fetch response headers and check each of the 6 security headers (R-019)."""
    headers = None
    for url in target_http_urls(domain):
        try:
            headers = get_headers(url, timeout=(3, 5))
            break
        except Exception:
            continue
    if headers is None:
        raise RuntimeError("Security headers could not be assessed: all requests failed")

    result = {}
    for name in SECURITY_HEADERS:
        # Case-insensitive lookup
        value = None
        for k, v in headers.items():
            if k.lower() == name.lower():
                value = v
                break
        result[name] = {"present": value is not None, "value": value}

    return {"headers_present": result, "raw_headers": headers}


def check_hsts(headers: dict) -> bool:
    """R-017: Returns True if Strict-Transport-Security is present with max-age."""
    for k, v in headers.items():
        if k.lower() == "strict-transport-security":
            return "max-age" in v.lower() if v else False
    return False


def check_https_redirect(domain: str) -> bool | None:
    """R-018: Check whether http:// redirects to https://."""
    if "://" in domain and domain.startswith("https://"):
        return None  # HTTP origin was not included in the explicit target.
    url = domain if "://" in domain else f"http://{domain}"
    resp, err = safe_request(url, timeout=(3, 5))
    if resp is not None:
        return resp.url.startswith("https://")
    return False


def check_info_disclosure(headers: dict) -> dict:
    """R-025: Detect X-Powered-By and Server header disclosure."""
    x_powered_by = None
    server_header = None
    for k, v in headers.items():
        if k.lower() == "x-powered-by":
            x_powered_by = v
        if k.lower() == "server":
            server_header = v
    return {"x_powered_by": x_powered_by, "server_header": server_header}


def calculate_score(headers_present: dict) -> tuple:
    """Count present security headers and determine risk level."""
    score = sum(1 for info in headers_present.values() if info.get("present"))
    if score < 3:
        risk = "HIGH"
    elif score <= 4:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return (score, risk)


# ---------------------------------------------------------------------------
# Mock loader
# ---------------------------------------------------------------------------

def _load_mock() -> HeaderResult:
    """Load mock header scan results from JSON."""
    with open(MOCK_PATH, "r") as f:
        data = json.load(f)
    return HeaderResult(
        headers_present=data.get("headers_present", {}),
        hsts_present=data.get("hsts_present", False),
        https_redirect=data.get("https_redirect", False),
        header_score=data.get("header_score", 0),
        overall_risk=data.get("overall_risk", "HIGH"),
        x_powered_by=data.get("x_powered_by"),
        server_header=data.get("server_header"),
        status=data.get("status", "success"),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_header_scan(domain: str, use_mock: bool = False, strict_live: bool = False) -> HeaderResult:
    """Run full header security scan for *domain*.

    Args:
        domain: Target domain name (no scheme).
        use_mock: If True, return cached mock data immediately.
        strict_live: If True, raise RuntimeError on mock usage or execution errors.

    Returns:
        HeaderResult with all checks populated, including ``missing_headers``.
    """
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    if use_mock and strict:
        raise RuntimeError("STRICT_LIVE_MODE: Mock header scan execution is disabled in strict live mode.")

    if use_mock:
        return _load_mock()

    try:
        # 1. Check all 6 security headers
        sec = check_security_headers(domain)
        headers_present = sec["headers_present"]
        raw_headers = sec["raw_headers"]

        # 2. Compute missing_headers list (names where present == False)
        missing = [name for name, info in headers_present.items() if not info.get("present")]

        # 3. HSTS check (R-017)
        hsts = check_hsts(raw_headers)

        # 4. HTTPS redirect (R-018)
        https_redir = check_https_redirect(domain)

        # 5. Info disclosure (R-025)
        disclosure = check_info_disclosure(raw_headers)

        # 6. Score (R-019)
        score, risk = calculate_score(headers_present)

        return HeaderResult(
            headers_present=headers_present,
            missing_headers=missing,
            hsts_present=hsts,
            https_redirect=https_redir,
            header_score=score,
            overall_risk=risk,
            x_powered_by=disclosure["x_powered_by"],
            server_header=disclosure["server_header"],
            status="success",
        )
    except Exception as exc:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Header scan failed for {domain}: {exc}")
        # Return an honest error result — do NOT load mock data, which would
        # silently report zero missing headers and hide the scan failure.
        return HeaderResult(
            status="error",
            missing_headers=[],
            header_score=0,
            overall_risk="HIGH",
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — Header Scanner Tests")
    print("=" * 50)

    # TEST 1: Mock mode
    print("\nTEST 1: Mock mode")
    result = run_header_scan("testphp.vulnweb.com", use_mock=True)
    assert result.header_score == 0
    assert result.overall_risk == "HIGH"
    print(f"  PASS: Mock — score={result.header_score}, risk={result.overall_risk}")

    # TEST 2: google.com (should have good headers)
    print("\nTEST 2: google.com (live)")
    result = run_header_scan("google.com")
    assert result.header_score >= 1, f"Expected score >= 1 for google.com, got {result.header_score}"
    print(f"  PASS: score={result.header_score}/6, risk={result.overall_risk}")

    # TEST 3: testphp.vulnweb.com (should have poor headers)
    print("\nTEST 3: testphp.vulnweb.com (live)")
    result = run_header_scan("testphp.vulnweb.com")
    assert result.header_score <= 3, f"Expected score <= 3, got {result.header_score}"
    print(f"  PASS: score={result.header_score}/6, risk={result.overall_risk}")

    print("\nALL HEADER SCANNER TESTS PASSED")
