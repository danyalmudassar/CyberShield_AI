"""
CyberShield AI — PISF Control Branch Reachability Test Suite
============================================================
Systematically asserts that every status (PASS, PARTIAL, FAIL, NOT_ASSESSABLE)
across all 12 PISF controls is reachable with deterministic input data.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import DnsResult, SslResult, HeaderResult, TechResult, ThreatResult, Finding
from agents.pisf_agent import (
    _assess_control_1, _assess_control_2, _assess_control_3, _assess_control_4,
    _assess_control_5, _assess_control_6, _assess_control_7, _assess_control_8,
    _assess_control_9, _assess_control_10, _assess_control_11, _assess_control_12,
    _calculate_compliance_score
)


# Control 1
def test_control_1_fail():
    recon = {"findings": [Finding(severity="Critical")]}
    assert _assess_control_1(recon, None).status == "FAIL"

def test_control_1_pass():
    recon_clean = {"findings": [Finding(severity="Low")]}
    assert _assess_control_1(recon_clean, None).status == "PASS"


# Control 2 — HR Security (Permanently manual governance control by design; no automated evaluation path)
def test_control_2_not_assessable():
    assert _assess_control_2(None, None).status == "NOT_ASSESSABLE"


# Control 3
def test_control_3_not_assessable():
    assert _assess_control_3(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_3({"tech": TechResult(status="error")}, {"threat_result": ThreatResult(status="error")}).status == "NOT_ASSESSABLE"

def test_control_3_fail():
    recon_fail = {"tech": TechResult(robots_txt="Disallow: /admin/login")}
    assert _assess_control_3(recon_fail, None).status == "FAIL"

def test_control_3_pass():
    recon_pass = {"tech": TechResult(robots_txt="Disallow: /tmp/")}
    assert _assess_control_3(recon_pass, None).status == "PASS"


# Control 4
def test_control_4_not_assessable():
    assert _assess_control_4(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_4({"ssl": SslResult(status="error")}, None).status == "NOT_ASSESSABLE"

def test_control_4_fail():
    recon_fail = {"ssl": SslResult(valid=False), "headers": HeaderResult()}
    assert _assess_control_4(recon_fail, None).status == "FAIL"

def test_control_4_partial():
    recon_part = {"ssl": SslResult(valid=True, days_remaining=15, tls_versions=["TLSv1.3"]), "headers": HeaderResult(https_redirect=True)}
    assert _assess_control_4(recon_part, None).status == "PARTIAL"

def test_control_4_pass_with_errored_hdr():
    # Verify that an errored/missing header sub-scan doesn't trigger false PARTIAL when SSL is valid
    recon_pass = {"ssl": SslResult(valid=True, days_remaining=90, tls_versions=["TLSv1.3"]), "headers": HeaderResult(status="error")}
    assert _assess_control_4(recon_pass, None).status == "PASS"

def test_control_4_pass():
    recon_pass = {"ssl": SslResult(valid=True, days_remaining=90, tls_versions=["TLSv1.3"]), "headers": HeaderResult(https_redirect=True)}
    assert _assess_control_4(recon_pass, None).status == "PASS"


# Control 5 — Physical Security (Permanently manual facility control by design; no automated evaluation path)
def test_control_5_not_assessable():
    assert _assess_control_5(None, None).status == "NOT_ASSESSABLE"


# Control 6
def test_control_6_not_assessable():
    assert _assess_control_6(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_6({"headers": HeaderResult(status="error")}, None).status == "NOT_ASSESSABLE"

def test_control_6_fail():
    recon_fail = {"headers": HeaderResult(server_header="Apache/2.4.41", header_score=1)}
    assert _assess_control_6(recon_fail, None).status == "FAIL"

def test_control_6_pass_with_errored_tech():
    # Verify operations security passes when headers are clean even if tech sub-scan failed
    recon_pass = {"headers": HeaderResult(server_header="nginx", header_score=6), "tech": TechResult(status="error")}
    assert _assess_control_6(recon_pass, None).status == "PASS"

def test_control_6_pass():
    recon_pass = {"headers": HeaderResult(server_header="nginx", header_score=6)}
    assert _assess_control_6(recon_pass, None).status == "PASS"


# Control 7
def test_control_7_not_assessable():
    assert _assess_control_7(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_7({"headers": HeaderResult(status="error")}, None).status == "NOT_ASSESSABLE"

def test_control_7_fail():
    recon_fail = {"headers": HeaderResult(https_redirect=False, hsts_present=False)}
    assert _assess_control_7(recon_fail, None).status == "FAIL"

def test_control_7_pass_with_errored_ssl():
    # Verify communications security passes when HTTP headers (HTTPS/HSTS) are clean even if SSL sub-scan failed
    recon_pass = {"headers": HeaderResult(https_redirect=True, hsts_present=True), "ssl": SslResult(status="error")}
    assert _assess_control_7(recon_pass, None).status == "PASS"

def test_control_7_pass():
    recon_pass = {"headers": HeaderResult(https_redirect=True, hsts_present=True)}
    assert _assess_control_7(recon_pass, None).status == "PASS"


# Control 8
def test_control_8_not_assessable():
    assert _assess_control_8(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_8({"tech": TechResult(status="error")}, {"threat_result": ThreatResult(status="error")}).status == "NOT_ASSESSABLE"

def test_control_8_fail():
    threat_fail = {"threat_result": ThreatResult(cve_matches=[{"cve_id": "CVE-2024-0001", "severity": "Critical"}])}
    assert _assess_control_8(None, threat_fail).status == "FAIL"

def test_control_8_pass():
    threat_pass = {"threat_result": ThreatResult(cve_matches=[])}
    recon_pass = {"tech": TechResult(server="nginx/1.24", programming_language="Python 3.12")}
    assert _assess_control_8(recon_pass, threat_pass).status == "PASS"


# Control 9
def test_control_9_not_assessable():
    assert _assess_control_9(None, None).status == "NOT_ASSESSABLE"
    assert _assess_control_9({"tech": TechResult(status="error")}, None).status == "NOT_ASSESSABLE"

def test_control_9_partial():
    recon_part = {"tech": TechResult(cdn="Cloudflare", technologies=["jQuery"]), "ssl": None}
    assert _assess_control_9(recon_part, None).status == "PARTIAL"

    recon_part_err = {"tech": TechResult(cdn="Cloudflare", technologies=["jQuery"]), "ssl": SslResult(status="error")}
    assert _assess_control_9(recon_part_err, None).status == "PARTIAL"

def test_control_9_fail():
    recon_fail = {"tech": TechResult(cdn="Cloudflare"), "ssl": SslResult(valid=False)}
    assert _assess_control_9(recon_fail, None).status == "FAIL"

def test_control_9_pass_with_errored_ssl():
    # Verify zero third-party scripts detected passes even if SSL sub-scan failed
    recon_pass = {"tech": TechResult(), "ssl": SslResult(status="error")}
    assert _assess_control_9(recon_pass, None).status == "PASS"

def test_control_9_pass():
    recon_pass = {"tech": TechResult(cdn="Cloudflare"), "ssl": SslResult(valid=True)}
    assert _assess_control_9(recon_pass, None).status == "PASS"



# Control 10
def test_control_10_not_assessable():
    threat_na = {"threat_result": ThreatResult(blacklist_status=None)}
    assert _assess_control_10(None, threat_na).status == "NOT_ASSESSABLE"
    assert _assess_control_10(None, None).status == "NOT_ASSESSABLE"

def test_control_10_fail():
    threat_fail = {"threat_result": ThreatResult(blacklist_status="blacklisted")}
    assert _assess_control_10(None, threat_fail).status == "FAIL"

def test_control_10_pass():
    threat_pass = {"threat_result": ThreatResult(blacklist_status="clean")}
    assert _assess_control_10(None, threat_pass).status == "PASS"


# Control 11
def test_control_11_not_assessable():
    assert _assess_control_11({"dns": None}, None).status == "NOT_ASSESSABLE"
    assert _assess_control_11({"dns": DnsResult(status="error")}, None).status == "NOT_ASSESSABLE"
    assert _assess_control_11(None, None).status == "NOT_ASSESSABLE"

def test_control_11_fail():
    recon_fail = {"dns": DnsResult(domain_expiry_days=-5, ns_records=["ns1.example.com"])}
    assert _assess_control_11(recon_fail, None).status == "FAIL"

def test_control_11_partial():
    recon_spof = {"dns": DnsResult(domain_expiry_days=180, ns_records=["ns1.example.com"])}
    assert _assess_control_11(recon_spof, None).status == "PARTIAL"

def test_control_11_pass():
    recon_pass = {"dns": DnsResult(domain_expiry_days=180, ns_records=["ns1.example.com", "ns2.example.com"])}
    assert _assess_control_11(recon_pass, None).status == "PASS"


# Control 12
def test_control_12_not_assessable():
    assert _assess_control_12(None, None).status == "NOT_ASSESSABLE"


# Compliance Score Calculation
def test_dynamic_compliance_score_calculation():
    from models import PisfControl
    controls = [
        PisfControl(status="PASS"),            # 100
        PisfControl(status="PASS"),            # 100
        PisfControl(status="PARTIAL"),         # 50
        PisfControl(status="FAIL"),            # 0
        PisfControl(status="NOT_ASSESSABLE"),  # Excluded
        PisfControl(status="NOT_ASSESSABLE"),  # Excluded
    ]
    score = _calculate_compliance_score(controls)
    assert score == 62.5


if __name__ == "__main__":
    pytest.main(["-v", __file__])
