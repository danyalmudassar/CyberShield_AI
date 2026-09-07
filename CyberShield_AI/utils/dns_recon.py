"""
CyberShield AI — DNS Reconnaissance Module
============================================
Check IDs: R-001 to R-010
Performs DNS enumeration and WHOIS lookup for target domains.

R-001: DNS A records       R-006: DMARC policy
R-002: MX records          R-007: DKIM setup
R-003: NS records          R-008: WHOIS details
R-004: TXT records         R-009: Domain expiry
R-005: SPF analysis        R-010: Registrar lock

Usage:
    from utils.dns_recon import run_dns_recon
    result = run_dns_recon("example.com")
"""

import sys
import os
import json
from datetime import datetime

# Fix import path when running from utils/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import DnsResult
from utils.http_client import get, safe_request

import dns.resolver
from utils.whois_client import lookup_whois
from utils.target_policy import scoped_dns_name


def get_dns_records(domain: str) -> dict:
    """Query A, MX, NS, TXT records for *domain* using dnspython.

    Each record type is queried independently so a single failure
    (e.g. no MX records) does not prevent the others from succeeding.

    Returns:
        dict with keys: a_records, mx_records, ns_records, txt_records
    """
    domain = scoped_dns_name(domain)
    result = {
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
    }

    # A records
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # MX records
    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = [r.to_text() for r in answers]
    except Exception:
        pass

    # NS records
    try:
        answers = dns.resolver.resolve(domain, "NS")
        result["ns_records"] = [r.to_text().rstrip(".") for r in answers]
    except Exception:
        pass

    # TXT records
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        result["txt_records"] = [r.to_text().strip('"') for r in answers]
    except Exception:
        pass

    return result


def get_whois_info(domain: str) -> dict:
    """Perform a WHOIS lookup and extract registrar / date / lock info.

    Returns:
        dict with keys: whois_registrar, whois_creation_date,
        whois_expiry_date, domain_expiry_days, registrar_locked
    """
    info = {
        "whois_registrar": None,
        "whois_creation_date": None,
        "whois_expiry_date": None,
        "domain_expiry_days": None,
        "registrar_locked": None,
    }
    try:
        w = lookup_whois(domain)
        info["whois_registrar"] = w.registrar if hasattr(w, "registrar") else None

        # Creation date (may be a list)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation:
            info["whois_creation_date"] = creation.strftime("%Y-%m-%d") if hasattr(creation, "strftime") else str(creation)

        # Expiry date
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0] if expiry else None
        if expiry and hasattr(expiry, "strftime"):
            info["whois_expiry_date"] = expiry.strftime("%Y-%m-%d")
            delta = expiry - datetime.now()
            info["domain_expiry_days"] = max(delta.days, 0)

        # Registrar lock
        status = w.status if hasattr(w, "status") else None
        if status:
            statuses = status if isinstance(status, list) else [status]
            info["registrar_locked"] = any("clientTransferProhibited" in s for s in statuses)
    except Exception:
        pass

    return info


def analyze_email_security(domain: str, txt_records: list) -> dict:
    """Scan TXT records for SPF, and query DNS for DMARC / DKIM.

    Args:
        domain: the target domain
        txt_records: list of TXT record strings already retrieved

    Returns:
        dict with keys: spf_record, dmarc_record, dkim_found
    """
    domain = scoped_dns_name(domain)
    result = {
        "spf_record": None,
        "dmarc_record": None,
        "dkim_found": False,
    }

    # SPF — look for TXT record starting with v=spf1
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            result["spf_record"] = record
            break

    # DMARC — query _dmarc.<domain>
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            text = r.to_text().strip('"')
            if text.lower().startswith("v=dmarc1"):
                result["dmarc_record"] = text
                break
    except Exception:
        pass

    # DKIM — try common selectors
    selectors = ["google", "default", "selector1", "selector2", "k1"]
    for selector in selectors:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            if answers:
                result["dkim_found"] = True
                break
        except Exception:
            continue

    return result


def _load_mock() -> DnsResult:
    """Load mock DNS data from mocks/mock_dns.json."""
    mock_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "mocks",
        "mock_dns.json",
    )
    with open(mock_path, "r") as f:
        data = json.load(f)
    # Only pass fields that DnsResult accepts (skip 'domain')
    valid_fields = {f.name for f in DnsResult.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in valid_fields}
    return DnsResult(**filtered)


def run_dns_recon(domain: str, use_mock: bool = False, strict_live: bool = False) -> DnsResult:
    """Run full DNS reconnaissance for *domain*.

    Args:
        domain: target domain name
        use_mock: if True, return mock data immediately
        strict_live: if True, raise RuntimeError on mock usage or execution errors

    Returns:
        DnsResult populated with live or mock data
    """
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    if use_mock and strict:
        raise RuntimeError("STRICT_LIVE_MODE: Mock DNS recon execution is disabled in strict live mode.")

    if use_mock:
        return _load_mock()

    try:
        dns_data = get_dns_records(domain)
        whois_data = get_whois_info(domain)
        email_data = analyze_email_security(domain, dns_data.get("txt_records", []))

        # Determine status
        has_any = (
            dns_data["a_records"]
            or dns_data["mx_records"]
            or dns_data["ns_records"]
        )
        has_all = (
            dns_data["a_records"]
            and dns_data["ns_records"]
        )

        if has_all:
            status = "success"
        elif has_any:
            status = "warning"
        else:
            status = "error"

        return DnsResult(
            a_records=dns_data["a_records"],
            mx_records=dns_data["mx_records"],
            ns_records=dns_data["ns_records"],
            txt_records=dns_data["txt_records"],
            spf_record=email_data["spf_record"],
            dmarc_record=email_data["dmarc_record"],
            dkim_found=email_data["dkim_found"],
            whois_registrar=whois_data["whois_registrar"],
            whois_creation_date=whois_data["whois_creation_date"],
            whois_expiry_date=whois_data["whois_expiry_date"],
            domain_expiry_days=whois_data["domain_expiry_days"],
            registrar_locked=whois_data["registrar_locked"],
            status=status,
        )
    except Exception as exc:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: DNS recon failed for {domain}: {exc}")
        return DnsResult(status="error")


# ──────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — DNS Recon Tests")
    print("=" * 50)

    # TEST 1: Mock mode
    print("\nTEST 1: Mock mode")
    result = run_dns_recon("testphp.vulnweb.com", use_mock=True)
    assert len(result.a_records) >= 1, f"Expected A records, got {result.a_records}"
    assert result.status == "success"
    print(f"  PASS: Mock — A={result.a_records}, NS={result.ns_records}")

    # TEST 2: Live google.com
    print("\nTEST 2: Live google.com")
    result = run_dns_recon("google.com")
    assert len(result.a_records) >= 1, "Expected A records for google.com"
    assert len(result.mx_records) >= 1, "Expected MX records for google.com"
    print(f"  PASS: A={result.a_records[:2]}, MX={result.mx_records[:2]}")

    # TEST 3: Non-existent domain
    print("\nTEST 3: Non-existent domain")
    result = run_dns_recon("thisshouldnotexist99999.xyz")
    assert result.a_records == [] or result.status in ("warning", "error")
    print(f"  PASS: status={result.status}")

    # TEST 4: Verify SPF check on google.com
    print("\nTEST 4: google.com SPF")
    result = run_dns_recon("google.com")
    assert result.spf_record is not None, "Expected SPF for google.com"
    print(f"  PASS: SPF found — {result.spf_record[:50]}...")

    print("\nALL DNS RECON TESTS PASSED")
