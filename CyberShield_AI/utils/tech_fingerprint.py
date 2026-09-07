"""
CyberShield AI — Technology Fingerprinting Module
===================================================
Check IDs: R-020 to R-024
Identifies technologies, CMS, server software, and exposed metadata.

R-020: Server version disclosure   R-023: sitemap.xml check
R-021: Tech stack (CMS/server)     R-024: Meta generator tag
R-022: robots.txt analysis

Usage:
    from utils.tech_fingerprint import run_tech_fingerprint
    result = run_tech_fingerprint("example.com")
"""

import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import TechResult
from utils.http_client import get, get_headers, safe_request

MOCK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "mocks",
    "mock_tech.json",
)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def detect_server(headers: dict) -> tuple:
    """R-020: Extract Server and X-Powered-By from response headers.

    Returns:
        (server_str, language_str) — either may be None.
    """
    server_str = None
    language_str = None
    for k, v in headers.items():
        if k.lower() == "server":
            server_str = v
        if k.lower() == "x-powered-by":
            language_str = v
    return (server_str, language_str)


def detect_cms(html: str, headers: dict) -> str:
    """R-021: Identify CMS from HTML markers and header clues."""
    if html:
        lower_html = html.lower()
        if "/wp-content/" in lower_html or "/wp-includes/" in lower_html or \
           'meta name="generator" content="wordpress' in lower_html:
            return "WordPress"
        if "/media/jui/" in lower_html or "/components/com_" in lower_html:
            return "Joomla"
        if "drupal.settings" in lower_html or "/sites/default/" in lower_html:
            return "Drupal"
        if "cdn.shopify.com" in lower_html:
            return "Shopify"

    # Header-based clues
    for k, v in headers.items():
        if k.lower() == "x-powered-by" and v:
            low = v.lower()
            if "prestashop" in low:
                return "PrestaShop"
    return None


def check_robots_txt(domain: str) -> str:
    """R-022: Fetch robots.txt — return content or None."""
    resp, _ = safe_request(f"https://{domain}/robots.txt", timeout=(3, 5))
    if resp is not None and resp.status_code == 200:
        return resp.text
    resp, _ = safe_request(f"http://{domain}/robots.txt", timeout=(3, 5))
    if resp is not None and resp.status_code == 200:
        return resp.text
    return None


def check_sitemap(domain: str) -> bool:
    """R-023: Return True if sitemap.xml exists and contains XML."""
    resp, _ = safe_request(f"https://{domain}/sitemap.xml", timeout=(3, 5))
    if resp is not None and resp.status_code == 200 and "<" in resp.text[:500]:
        return True
    resp, _ = safe_request(f"http://{domain}/sitemap.xml", timeout=(3, 5))
    if resp is not None and resp.status_code == 200 and "<" in resp.text[:500]:
        return True
    return False


def get_meta_generator(html: str) -> str:
    """R-024: Parse <meta name="generator" content="..."> from HTML."""
    if not html:
        return None
    match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def detect_technologies(html: str, headers: dict) -> list:
    """Aggregate technology strings from HTML and header signals."""
    techs = set()

    # --- HTML / script-based detection ---
    if html:
        low = html.lower()
        if "jquery" in low:
            techs.add("jQuery")
        if "bootstrap" in low:
            techs.add("Bootstrap")
        if "react" in low and ("react.development" in low or "react.production" in low or "react-dom" in low):
            techs.add("React")
        if "angular" in low and ("angular.min.js" in low or "ng-app" in low):
            techs.add("Angular")
        if "vue" in low and ("vue.js" in low or "vue.min.js" in low or "__vue__" in low):
            techs.add("Vue.js")

    # --- Header-based detection ---
    for k, v in headers.items():
        lk = k.lower()
        lv = v.lower() if v else ""
        if lk == "server":
            if "nginx" in lv:
                techs.add("nginx")
            if "apache" in lv:
                techs.add("Apache")
            if "iis" in lv or "microsoft" in lv:
                techs.add("IIS")
        if lk == "cf-ray" or lk == "cf-cache-status":
            techs.add("Cloudflare")
        if lk == "x-powered-by":
            if "php" in lv:
                techs.add("PHP")
            if "asp.net" in lv:
                techs.add("ASP.NET")
            if "express" in lv:
                techs.add("Express")

    return sorted(techs)


# ---------------------------------------------------------------------------
# Mock loader
# ---------------------------------------------------------------------------

def _load_mock() -> TechResult:
    """Load mock tech fingerprint results from JSON."""
    with open(MOCK_PATH, "r") as f:
        data = json.load(f)
    return TechResult(
        server=data.get("server"),
        cms=data.get("cms"),
        programming_language=data.get("programming_language"),
        cdn=data.get("cdn"),
        robots_txt=data.get("robots_txt"),
        sitemap_found=data.get("sitemap_found", False),
        meta_generator=data.get("meta_generator"),
        technologies=data.get("technologies", []),
        status=data.get("status", "success"),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_tech_fingerprint(domain: str, use_mock: bool = False, strict_live: bool = False) -> TechResult:
    """Run full technology fingerprint for *domain*.

    Args:
        domain: Target domain name (no scheme).
        use_mock: If True, return cached mock data immediately.
        strict_live: If True, raise RuntimeError on mock usage or execution errors.

    Returns:
        TechResult with all checks populated.
    """
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    if use_mock and strict:
        raise RuntimeError("STRICT_LIVE_MODE: Mock tech fingerprint execution is disabled in strict live mode.")

    if use_mock:
        return _load_mock()

    try:
        # Fetch homepage — try https first (testphp.vulnweb.com has HTTPS)
        html = ""
        headers = {}
        resp, err = safe_request(f"https://{domain}", timeout=(3, 5))
        if resp is not None:
            html = resp.text
        else:
            resp, err = safe_request(f"http://{domain}", timeout=(3, 5))
            if resp is not None:
                html = resp.text

        # Grab headers separately
        try:
            headers = get_headers(f"https://{domain}", timeout=(3, 5))
        except Exception:
            try:
                headers = get_headers(f"http://{domain}", timeout=(3, 5))
            except Exception:
                headers = {}

        # Run all detections
        server_str, lang_str = detect_server(headers)
        cms = detect_cms(html, headers)
        robots = check_robots_txt(domain)
        sitemap = check_sitemap(domain)
        meta_gen = get_meta_generator(html)
        techs = detect_technologies(html, headers)

        # Detect CDN from headers
        cdn = None
        for k, v in headers.items():
            if k.lower() in ("cf-ray", "cf-cache-status"):
                cdn = "Cloudflare"
            if k.lower() == "x-amz-cf-id":
                cdn = "Amazon CloudFront"

        return TechResult(
            server=server_str,
            cms=cms,
            programming_language=lang_str,
            cdn=cdn,
            robots_txt=robots,
            sitemap_found=sitemap,
            meta_generator=meta_gen,
            technologies=techs,
            status="success",
        )
    except Exception as exc:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Tech fingerprinting failed for {domain}: {exc}")
        return TechResult(status="error", technologies=[])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — Tech Fingerprint Tests")
    print("=" * 50)

    # TEST 1: Mock mode
    print("\nTEST 1: Mock mode")
    result = run_tech_fingerprint("testphp.vulnweb.com", use_mock=True)
    assert result.server == "nginx/1.19.0"
    assert len(result.technologies) >= 1
    print(f"  PASS: Mock — server={result.server}, tech={result.technologies}")

    # TEST 2: Live testphp.vulnweb.com (HTTPS)
    print("\nTEST 2: testphp.vulnweb.com (live)")
    result = run_tech_fingerprint("testphp.vulnweb.com")
    assert result.status == "success"
    print(f"  PASS: server={result.server}, cms={result.cms}, tech={result.technologies}")

    # TEST 3: google.com
    print("\nTEST 3: google.com (live)")
    result = run_tech_fingerprint("google.com")
    assert result.status == "success"
    print(f"  PASS: server={result.server}, tech={result.technologies}")

    print("\nALL TECH FINGERPRINT TESTS PASSED")
