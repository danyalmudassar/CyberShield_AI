"""
CyberShield AI — Shared HTTP Client
=====================================
Single HTTP client used by ALL utils — ensures consistent timeouts,
retries, error handling, and User-Agent across the project.
Eliminates duplicated HTTP logic.

Usage:
    from utils.http_client import get, get_headers, safe_request

    response = get("https://example.com")
    headers = get_headers("https://example.com")
    response, error = safe_request("https://example.com")
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_USER_AGENT = "CyberShield-AI/1.0 (Security Audit Tool)"
_DEFAULT_TIMEOUT = 5

_session = None


def get_session() -> requests.Session:
    """Returns a configured requests.Session with pooling, UA, timeout adapter."""
    global _session
    if _session is not None:
        return _session

    session = requests.Session()

    retry_strategy = Retry(
        total=1,
        connect=1,
        read=1,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({"User-Agent": _USER_AGENT})

    _session = session
    return session


def get(url: str, timeout: int = _DEFAULT_TIMEOUT, **kwargs) -> requests.Response:
    """GET request with retry logic. Raises on failure after retries."""
    session = get_session()
    try:
        response = session.get(url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as exc:
        raise requests.exceptions.RequestException(
            f"GET {url} failed after retries: {exc}"
        ) from exc


def get_headers(url: str, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """Returns response headers only (HEAD request, falls back to GET)."""
    session = get_session()
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        return dict(response.headers)
    except requests.exceptions.RequestException:
        pass

    try:
        response = session.get(url, timeout=timeout, stream=True)
        response.raise_for_status()
        response.close()
        return dict(response.headers)
    except requests.exceptions.RequestException as exc:
        raise requests.exceptions.RequestException(
            f"get_headers {url} failed: {exc}"
        ) from exc


def safe_request(url: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple:
    """Returns (response, None) on success, (None, error_msg) on failure. Never raises."""
    try:
        response = get(url, timeout=timeout)
        return (response, None)
    except Exception as exc:
        return (None, str(exc))


if __name__ == "__main__":
    print("TEST 1: GET google.com")
    resp = get("https://google.com")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    print(f"  PASS: status={resp.status_code}")

    print("TEST 2: safe_request on invalid domain")
    resp, err = safe_request("https://thisdoesnotexist99999.com")
    assert resp is None, "Expected None response"
    assert err is not None, "Expected error message"
    print(f"  PASS: error={err[:60]}...")

    print("TEST 3: get_headers google.com")
    headers = get_headers("https://google.com")
    assert len(headers) > 0, "Expected non-empty headers"
    print(f"  PASS: got {len(headers)} headers")

    print("ALL HTTP CLIENT TESTS PASSED")
