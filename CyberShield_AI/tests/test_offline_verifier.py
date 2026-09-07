"""
CyberShield AI — Offline Pipeline Unit Tests
==============================================
Tests the anonymizer and deterministic header verifier using static mock fixtures.
"""

import pytest
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.anonymizer import sanitize_text, sanitize_scan_payload
from utils.header_verifier import parse_and_verify_headers


def test_anonymizer_domain_and_ip_replacement():
    raw_input = "Scan target https://admin.internal-site.org on IP 203.0.113.45 with api_key=secret123"
    sanitized = sanitize_text(raw_input)
    
    assert "https://target.local" in sanitized
    assert "192.0.2.1" in sanitized
    assert "secret123" not in sanitized
    assert "[REDACTED_CREDENTIAL]" in sanitized


def test_anonymizer_ipv6_and_bare_domain():
    raw = "Target site internal-corp.com resolved to 2001:db8:85a3::8a2e:370:7334 with admin@corp.com"
    clean = sanitize_text(raw)

    assert "internal-corp.com" not in clean
    assert "target.local" in clean
    assert "2001:db8::1" in clean
    assert "user@target.local" in clean


def test_anonymizer_compound_tld():
    raw = "Server hosting example.co.uk and service.com.pk"
    clean = sanitize_text(raw)

    assert "example.co.uk" not in clean
    assert "service.com.pk" not in clean
    assert "target.local.uk" not in clean
    assert "target.local" in clean


def test_error_message_redaction():
    raw_error = "OpenAI API Exception: Invalid key provided api_key=sk-proj-1234567890abcdef"
    clean_error = sanitize_text(raw_error)

    assert "sk-proj-1234567890abcdef" not in clean_error
    assert "[REDACTED_CREDENTIAL]" in clean_error




def test_anonymizer_payload_dict():
    payload = {
        "domain": "https://secret-service.com",
        "ip": "198.51.100.12",
        "api_key": "my-secret-token-value",
        "details": {
            "email": "admin@company.com"
        }
    }
    cleaned = sanitize_scan_payload(payload)
    
    assert cleaned["api_key"] == "[REDACTED_CREDENTIAL]"
    assert "https://target.local" in cleaned["domain"]
    assert "192.0.2.1" in cleaned["ip"]
    assert "admin@company.com" not in cleaned["details"]["email"]


def test_header_verifier_missing_headers():
    mock_headers = {
        "Content-Type": "text/html",
        "Server": "nginx/1.18.0"
    }
    res = parse_and_verify_headers(mock_headers)
    
    assert res["total_headers_checked"] == 6
    assert res["headers_passed"] == 0
    assert res["headers_missing"] == 6
    assert res["score_percentage"] == 0.0
    assert len(res["findings"]) == 6


def test_header_verifier_full_headers():
    mock_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()"
    }
    res = parse_and_verify_headers(mock_headers)
    
    assert res["headers_passed"] == 6
    assert res["headers_missing"] == 0
    assert res["score_percentage"] == 100.0
    assert len(res["findings"]) == 0


if __name__ == "__main__":
    pytest.main(["-v", __file__])
