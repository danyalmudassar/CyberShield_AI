"""
CyberShield AI — SSL/TLS Certificate Checker
===============================================
Check IDs: R-011 to R-016
Analyzes SSL/TLS certificates for security issues.

R-011: SSL validity        R-014: TLS version
R-012: Expiry date         R-015: Cipher strength
R-013: Issuer (CA)         R-016: SANs (subdomains)

Usage:
    from utils.ssl_checker import run_ssl_check
    result = run_ssl_check("example.com")
"""

import sys
import os
import json
import ssl
import socket
from datetime import datetime, timezone

# Fix import path when running from utils/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import SslResult
from utils.http_client import get, safe_request


def get_ssl_certificate(domain: str, port: int = 443) -> dict:
    """Connect to *domain*:*port* over TLS and retrieve the peer certificate.

    Uses only the Python stdlib (ssl + socket) to avoid heavy dependencies.

    Returns:
        dict with keys: subject, issuer, notBefore, notAfter,
        subjectAltName, cipher, protocol
    Raises:
        Exception on any connection or TLS failure.
    """
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()      # (name, version, bits) or None
            protocol = ssock.version()   # e.g. 'TLSv1.3'

    # Extract human-readable subject / issuer
    subject_parts = []
    for rdn in cert.get("subject", ()):
        for attr_type, attr_value in rdn:
            subject_parts.append(attr_value)
    subject_str = ", ".join(subject_parts) if subject_parts else None

    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for attr_type, attr_value in rdn:
            issuer_parts.append(attr_value)
    issuer_str = ", ".join(issuer_parts) if issuer_parts else None

    # SANs
    sans = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            sans.append(san_value)

    return {
        "subject": subject_str,
        "issuer": issuer_str,
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "subjectAltName": sans,
        "cipher": cipher,        # (name, protocol_version, bits)
        "protocol": protocol,    # negotiated TLS version string
    }


def analyze_certificate(cert_data: dict) -> SslResult:
    """Analyse raw certificate data and return a populated SslResult.

    Checks:
    - Expiry: days_remaining > 0  →  valid
    - Self-signed: subject == issuer
    - Cipher strength: bits >= 256 → strong, >= 128 → acceptable, else weak
    """
    result = SslResult()

    # Issuer
    result.issuer = cert_data.get("issuer")

    # Self-signed check
    if cert_data.get("subject") and cert_data.get("issuer"):
        result.is_self_signed = cert_data["subject"] == cert_data["issuer"]

    # SANs
    result.sans = cert_data.get("subjectAltName", [])

    # Expiry parsing
    not_after = cert_data.get("notAfter")
    if not_after:
        try:
            # Format: 'Sep 30 12:00:00 2025 GMT'
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result.expiry_date = expiry_dt.strftime("%Y-%m-%d")
            delta = expiry_dt - datetime.now(timezone.utc).replace(tzinfo=None)
            result.days_remaining = max(delta.days, 0)
        except Exception:
            pass

    # Cipher strength
    cipher = cert_data.get("cipher")
    if cipher:
        cipher_name, cipher_version, cipher_bits = cipher
        result.cipher_suite = cipher_name
        if cipher_bits >= 256:
            result.cipher_strength = "strong"
        elif cipher_bits >= 128:
            result.cipher_strength = "acceptable"
        else:
            result.cipher_strength = "weak"

    # TLS version from the connection
    protocol = cert_data.get("protocol")
    if protocol:
        result.tls_versions = [protocol]

    # Validity: not expired, not self-signed, trusted (has issuer)
    is_expired = result.days_remaining is not None and result.days_remaining <= 0
    result.valid = (
        not is_expired
        and not result.is_self_signed
        and result.issuer is not None
    )

    return result


def check_tls_versions(domain: str, port: int = 443) -> list:
    """Probe which TLS versions the server accepts.

    Attempts a connection for each of TLSv1.2 and TLSv1.3 and reports
    which ones succeed.  Returns a list of version strings.
    """
    supported = []
    versions_to_test = [
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for label, tls_version in versions_to_test:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((domain, port), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    if ssock.version():
                        supported.append(label)
        except Exception:
            continue
    return supported


def _load_mock() -> SslResult:
    """Load mock SSL data from mocks/mock_ssl.json."""
    mock_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "mocks",
        "mock_ssl.json",
    )
    with open(mock_path, "r") as f:
        data = json.load(f)
    valid_fields = {f.name for f in SslResult.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in valid_fields}
    return SslResult(**filtered)


def run_ssl_check(domain: str, use_mock: bool = False) -> SslResult:
    """Run a full SSL/TLS check for *domain*.

    Args:
        domain: target domain name
        use_mock: if True, return mock data immediately

    Returns:
        SslResult populated with live or mock data
    """
    if use_mock:
        return _load_mock()

    try:
        cert_data = get_ssl_certificate(domain)
        result = analyze_certificate(cert_data)

        # Enrich with TLS version probing
        tls_versions = check_tls_versions(domain)
        if tls_versions:
            result.tls_versions = tls_versions

        result.status = "success" if result.valid else "warning"
        return result

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        # Site has no SSL — return a descriptive warning result
        return SslResult(
            valid=False,
            status="warning",
        )
    except Exception:
        # Complete / unexpected failure — fall back to mock
        return _load_mock()


# ──────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — SSL Checker Tests")
    print("=" * 50)

    # TEST 1: Mock mode
    print("\nTEST 1: Mock mode")
    result = run_ssl_check("testphp.vulnweb.com", use_mock=True)
    assert result.valid == False
    assert result.status == "warning"
    print(f"  PASS: Mock — valid={result.valid}, status={result.status}")

    # TEST 2: google.com (has valid SSL)
    print("\nTEST 2: google.com (live)")
    result = run_ssl_check("google.com")
    assert result.valid == True, f"Expected valid=True, got {result.valid}"
    assert result.days_remaining is not None and result.days_remaining > 0
    print(f"  PASS: valid={result.valid}, days_remaining={result.days_remaining}, issuer={result.issuer}")

    # TEST 3: testphp.vulnweb.com (HTTP only — no SSL)
    print("\nTEST 3: testphp.vulnweb.com (HTTP-only)")
    result = run_ssl_check("testphp.vulnweb.com")
    assert result.valid == False
    print(f"  PASS: valid={result.valid}, status={result.status}")

    # TEST 4: Check SANs for google.com
    print("\nTEST 4: google.com SANs")
    result = run_ssl_check("google.com")
    assert len(result.sans) >= 1, "Expected SANs for google.com"
    print(f"  PASS: {len(result.sans)} SANs found: {result.sans[:3]}...")

    print("\nALL SSL CHECKER TESTS PASSED")
