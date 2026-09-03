"""
CyberShield AI — Pre-Engagement Authorization Module (PTES Phase 1)
=====================================================================
Implements the authorization gate required before any security scanning.
Following PTES Phase 1, NIST SP 800-115 Planning phase, and Pakistan's
PECA 2016 legal requirements.

No scanning can proceed without explicit authorization.

Usage:
    from agents.pre_engagement import collect_engagement_details, validate_authorization
    
    details = collect_engagement_details("example.com", True, "passive_only", "admin@example.com")
    if validate_authorization(details):
        # proceed with scanning
    else:
        # pipeline blocked
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import EngagementDetails


def _is_valid_domain(domain: str) -> bool:
    """Basic domain validation: non-empty, contains at least one dot, no spaces."""
    if not domain:
        return False
    if " " in domain:
        return False
    if "." not in domain:
        return False
    return True


def _clean_domain(domain: str) -> str:
    """Strip common URL prefixes and trailing slashes from a domain string."""
    cleaned = domain.strip()
    for prefix in ("https://", "http://", "www."):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix):]
    cleaned = cleaned.rstrip("/")
    return cleaned


def collect_engagement_details(
    domain: str,
    authorized: bool,
    scope_type: str = "passive_only",
    contact_email: str = "",
) -> EngagementDetails:
    """Collect and validate pre-engagement authorization details.

    Args:
        domain: Target domain to assess.
        authorized: Whether explicit authorization has been granted.
        scope_type: 'passive_only' or 'full_pentest'.
        contact_email: Point-of-contact email for the engagement.

    Returns:
        An EngagementDetails dataclass reflecting the authorization decision.
    """
    # Clean the domain
    cleaned = _clean_domain(domain) if domain else ""

    # Validate domain
    domain_valid = _is_valid_domain(cleaned)

    # Determine auth_status
    if not domain or not domain_valid:
        auth_status = "ERROR"
    elif authorized:
        auth_status = "GRANTED"
    else:
        auth_status = "DENIED"

    # Determine pipeline_action
    if authorized and domain_valid:
        pipeline_action = "PROCEED"
    else:
        pipeline_action = "STOP"

    return EngagementDetails(
        target_domain=cleaned,
        authorized=authorized,
        scope_type=scope_type,
        contact_email=contact_email,
        timestamp=datetime.now().isoformat(),
        auth_status=auth_status,
        pipeline_action=pipeline_action,
    )


def validate_authorization(details: EngagementDetails) -> bool:
    """Return True only when the engagement is fully authorized and valid.

    Checks:
        - details.authorized is True
        - details.target_domain is non-empty and passes basic validation
        - details.pipeline_action is 'PROCEED'
    """
    if not details.authorized:
        return False
    if not details.target_domain or not _is_valid_domain(details.target_domain):
        return False
    if details.pipeline_action != "PROCEED":
        return False
    return True


def generate_engagement_document(details: EngagementDetails) -> str:
    """Generate a formatted authorization record document.

    Returns a printable string containing the full engagement record
    with PECA 2016 legal notice.
    """
    return (
        "========================================\n"
        "CYBERSHIELD AI — AUTHORIZATION RECORD\n"
        "========================================\n"
        f"Target Domain: {details.target_domain}\n"
        f"Authorization: {details.auth_status}\n"
        f"Scope: {details.scope_type}\n"
        f"Contact: {details.contact_email}\n"
        f"Timestamp: {details.timestamp}\n"
        f"Pipeline: {details.pipeline_action}\n"
        "========================================\n"
        "\n"
        "Legal Notice:\n"
        "This security assessment is conducted in compliance with PECA 2016 \n"
        "(Prevention of Electronic Crimes Act) of Pakistan. Unauthorized \n"
        "access to computer systems is a criminal offense under Section 3-6.\n"
        "\n"
        "By authorizing this scan, the requester confirms they have legal \n"
        "authority to test the target domain.\n"
        "========================================"
    )


def get_authorization_summary(details: EngagementDetails) -> str:
    """Return a concise one-line summary of the authorization decision."""
    if details.auth_status == "GRANTED":
        return (
            f"[GRANTED] {details.target_domain} — "
            f"{details.scope_type} scan authorized at {details.timestamp}"
        )
    elif details.auth_status == "ERROR":
        return (
            f"[ERROR] {details.target_domain or '(empty)'} — "
            f"invalid domain, pipeline STOPPED"
        )
    else:
        return (
            f"[DENIED] {details.target_domain} — "
            f"authorization denied, pipeline STOPPED"
        )


if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — Pre-Engagement Module Tests")
    print("=" * 50)

    # TEST 1: Authorized scan
    print("\nTEST 1: Authorized domain")
    details = collect_engagement_details("example.com", True, "passive_only", "admin@example.com")
    assert details.auth_status == "GRANTED", f"Expected GRANTED, got {details.auth_status}"
    assert details.pipeline_action == "PROCEED", f"Expected PROCEED, got {details.pipeline_action}"
    assert validate_authorization(details) == True
    print(f"  PASS: {get_authorization_summary(details)}")

    # TEST 2: Denied scan
    print("\nTEST 2: Unauthorized (denied)")
    details = collect_engagement_details("example.com", False, "full_pentest", "test@test.com")
    assert details.auth_status == "DENIED"
    assert details.pipeline_action == "STOP"
    assert validate_authorization(details) == False
    print(f"  PASS: {get_authorization_summary(details)}")

    # TEST 3: Invalid domain
    print("\nTEST 3: Empty domain")
    details = collect_engagement_details("", True)
    assert details.pipeline_action == "STOP"
    assert validate_authorization(details) == False
    print(f"  PASS: Invalid domain blocked")

    # TEST 4: Domain with http:// prefix (should be stripped)
    print("\nTEST 4: Domain with http:// prefix")
    details = collect_engagement_details("https://example.com", True, "passive_only", "a@b.com")
    assert details.target_domain == "example.com", f"Expected 'example.com', got '{details.target_domain}'"
    assert details.pipeline_action == "PROCEED"
    print(f"  PASS: URL prefix stripped → {details.target_domain}")

    # TEST 5: Engagement document generation
    print("\nTEST 5: Engagement document")
    details = collect_engagement_details("banoqabil.pk", True, "passive_only", "test@banoqabil.pk")
    doc = generate_engagement_document(details)
    assert "AUTHORIZATION RECORD" in doc
    assert "banoqabil.pk" in doc
    assert "PECA 2016" in doc
    print(f"  PASS: Document generated ({len(doc)} chars)")

    print("\n" + "=" * 50)
    print("ALL PRE-ENGAGEMENT TESTS PASSED")
    print("=" * 50)
