"""
CyberShield AI — Shared pytest fixtures (tests/conftest.py)
===========================================================
Provides:
  - ``block_outbound``: opt-in fixture that patches socket.create_connection
    to prevent accidental network calls in offline unit tests.
  - Pre-built HeaderResult / SslResult fixtures used across contract tests.
"""

import socket
import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import HeaderResult, SslResult, DnsResult, TechResult


# ---------------------------------------------------------------------------
# Network guard
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def block_outbound(request):
    """Automatically block outbound network connections for all tests unless marked @pytest.mark.live or @pytest.mark.integration.

    Allows local AF_UNIX socketpair communication required for asyncio loop wakeups.
    """
    if "live" in request.keywords or "integration" in request.keywords:
        yield
        return

    def _blocked(*args, **kwargs):
        raise RuntimeError(
            "Network access is not allowed in unit tests. "
            "Use mock data or mark test with @pytest.mark.live or @pytest.mark.integration."
        )

    orig_connect = socket.socket.connect
    orig_send = socket.socket.send
    orig_sendto = socket.socket.sendto
    orig_sendall = socket.socket.sendall
    orig_sendmsg = getattr(socket.socket, "sendmsg", None)

    def _guard_connect(self, *args, **kwargs):
        if hasattr(socket, "AF_UNIX") and getattr(self, "family", None) == socket.AF_UNIX:
            return orig_connect(self, *args, **kwargs)
        _blocked()

    def _guard_send(self, *args, **kwargs):
        if hasattr(socket, "AF_UNIX") and getattr(self, "family", None) == socket.AF_UNIX:
            return orig_send(self, *args, **kwargs)
        _blocked()

    def _guard_sendto(self, *args, **kwargs):
        if hasattr(socket, "AF_UNIX") and getattr(self, "family", None) == socket.AF_UNIX:
            return orig_sendto(self, *args, **kwargs)
        _blocked()

    def _guard_sendall(self, *args, **kwargs):
        if hasattr(socket, "AF_UNIX") and getattr(self, "family", None) == socket.AF_UNIX:
            return orig_sendall(self, *args, **kwargs)
        _blocked()

    def _guard_sendmsg(self, *args, **kwargs):
        if hasattr(socket, "AF_UNIX") and getattr(self, "family", None) == socket.AF_UNIX and orig_sendmsg:
            return orig_sendmsg(self, *args, **kwargs)
        _blocked()

    socket.socket.connect = _guard_connect
    socket.socket.send = _guard_send
    socket.socket.sendto = _guard_sendto
    socket.socket.sendall = _guard_sendall
    if orig_sendmsg:
        socket.socket.sendmsg = _guard_sendmsg

    try:
        with patch("socket.create_connection", side_effect=_blocked), \
             patch("socket.getaddrinfo", side_effect=_blocked), \
             patch("socket.gethostbyname", side_effect=_blocked), \
             patch("socket.gethostbyname_ex", side_effect=_blocked):
            yield
    finally:
        socket.socket.connect = orig_connect
        socket.socket.send = orig_send
        socket.socket.sendto = orig_sendto
        socket.socket.sendall = orig_sendall
        if orig_sendmsg:
            socket.socket.sendmsg = orig_sendmsg


# ---------------------------------------------------------------------------
# HeaderResult fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def all_headers_missing():
    """HeaderResult where all 6 security headers are absent."""
    headers_present = {
        "Content-Security-Policy":   {"present": False, "value": None},
        "X-Frame-Options":           {"present": False, "value": None},
        "Strict-Transport-Security": {"present": False, "value": None},
        "X-Content-Type-Options":    {"present": False, "value": None},
        "Referrer-Policy":           {"present": False, "value": None},
        "Permissions-Policy":        {"present": False, "value": None},
    }
    return HeaderResult(
        headers_present=headers_present,
        missing_headers=[
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ],
        hsts_present=False,
        https_redirect=False,
        header_score=0,
        overall_risk="HIGH",
        status="success",
    )


@pytest.fixture()
def all_headers_present():
    """HeaderResult where all 6 security headers are present."""
    headers_present = {
        "Content-Security-Policy":   {"present": True, "value": "default-src 'self'"},
        "X-Frame-Options":           {"present": True, "value": "DENY"},
        "Strict-Transport-Security": {"present": True, "value": "max-age=31536000"},
        "X-Content-Type-Options":    {"present": True, "value": "nosniff"},
        "Referrer-Policy":           {"present": True, "value": "no-referrer"},
        "Permissions-Policy":        {"present": True, "value": "geolocation=()"},
    }
    return HeaderResult(
        headers_present=headers_present,
        missing_headers=[],
        hsts_present=True,
        https_redirect=True,
        header_score=6,
        overall_risk="LOW",
        status="success",
    )


# ---------------------------------------------------------------------------
# SslResult fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def valid_ssl():
    """SslResult for a target with a valid, non-expired certificate."""
    return SslResult(
        valid=True,
        expiry_date="2027-01-01",
        days_remaining=480,
        issuer="Let's Encrypt",
        is_self_signed=False,
        tls_versions=["TLSv1.2", "TLSv1.3"],
        status="success",
    )


@pytest.fixture()
def invalid_ssl():
    """SslResult for a target that has an actual invalid/expired certificate."""
    return SslResult(
        valid=False,
        error="certificate has expired",
        status="success",  # probe succeeded; cert is genuinely invalid
    )


@pytest.fixture()
def unreachable_ssl():
    """SslResult when the TLS probe itself could not connect."""
    return SslResult(
        valid=False,
        error="Connection refused",
        status="error",   # probe failed — result is NOT_ASSESSABLE
    )


# ---------------------------------------------------------------------------
# DnsResult / TechResult fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def dns_with_mx():
    """DnsResult that includes MX records."""
    return DnsResult(
        a_records=["1.2.3.4"],
        mx_records=["mail.example.com"],
        status="success",
    )


@pytest.fixture()
def empty_tech():
    """TechResult with no detected technologies (unknown stack)."""
    return TechResult(technologies=[], status="success")


@pytest.fixture()
def known_tech():
    """TechResult with a detected technology stack."""
    return TechResult(
        server="nginx/1.24.0",
        technologies=["nginx 1.24.0", "PHP 8.1"],
        status="success",
    )


@pytest.fixture(autouse=True)
def isolated_auth_configuration(tmp_path, monkeypatch):
    """Explicit test-only accounts and databases; never use deployment sessions."""
    monkeypatch.setenv("CYBERSHIELD_AUTH_DB", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("CYBERSHIELD_DB", str(tmp_path / "scans.sqlite3"))
    monkeypatch.setenv("CYBERSHIELD_ADMIN_PASSWORD", "Test-admin-password-2026")
    monkeypatch.setenv("CYBERSHIELD_OPERATOR_PASSWORD", "Test-operator-password-2026")
    monkeypatch.setenv("CYBERSHIELD_COOKIE_SECURE", "false")
    monkeypatch.setenv("CYBERSHIELD_ORIGINS", "http://localhost:3000")
    monkeypatch.delenv("CYBERSHIELD_API_TOKEN", raising=False)
