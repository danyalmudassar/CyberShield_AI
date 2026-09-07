"""
CyberShield AI — Target Scope Enforcement Tests
=================================================
Task 08: Enforce scope boundaries across all transports, HTTP redirects, and DNS resolutions.
"""

import pytest
from unittest.mock import patch, MagicMock

from utils.target_policy import validate_target, validate_redirect, TargetPolicyError
from utils.http_client import get, check_target_reachability
from utils.ssl_checker import run_ssl_check


def test_redirect_leaving_origin_blocked():
    """HTTP redirects leaving the authorized target origin must be blocked immediately."""
    with pytest.raises(TargetPolicyError, match="Redirect leaves the authorized origin"):
        validate_redirect("https://example.com/page1", "https://evil.com/phish")

    with pytest.raises(TargetPolicyError, match="Redirect leaves the authorized origin"):
        validate_redirect("https://example.com/page1", "http://example.com/page1")


def test_redirect_to_metadata_endpoint_blocked():
    """Redirects targeting cloud metadata endpoints (169.254.169.254) must be blocked."""
    with pytest.raises(TargetPolicyError):
        validate_redirect("https://example.com/page1", "http://169.254.169.254/latest/meta-data")


def test_metadata_ip_blocked():
    """Direct targeting of metadata or link-local IPs must fail validation."""
    for blocked in ("169.254.169.254", "100.100.100.200", "http://[fe80::1]"):
        with pytest.raises(TargetPolicyError, match="blocked"):
            validate_target(blocked, allow_private=True)


def test_private_lab_requires_explicit_flag():
    """RFC1918 and loopback targets are rejected unless allow_private=True."""
    for private in ("127.0.0.1", "10.0.0.1", "192.168.1.1"):
        with pytest.raises(TargetPolicyError, match="Nonpublic targets require"):
            validate_target(private, allow_private=False)

        assert validate_target(private, allow_private=True).addresses


def test_reachability_blocks_out_of_scope_target():
    """check_target_reachability must fail closed when target is out of scope."""
    reachable, reason = check_target_reachability("169.254.169.254")
    assert not reachable
    assert "Target policy blocked target" in reason


def test_ssl_check_validates_target_policy():
    """run_ssl_check must fail closed when passed an invalid or metadata target."""
    result = run_ssl_check("169.254.169.254", use_mock=False, strict_live=False)
    assert result.status == "error"
    assert result.valid is False

    with pytest.raises(RuntimeError, match="STRICT_LIVE_MODE"):
        run_ssl_check("169.254.169.254", use_mock=False, strict_live=True)
