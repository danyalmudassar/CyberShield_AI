"""
CyberShield AI — Offline Deterministic Header & Security Config Parser
========================================================================
Parses HTTP response headers and security attributes programmatically without external network calls.
"""

from typing import Dict, Any, List

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {"min_age": 31536000, "severity": "High", "cwe": "CWE-319"},
    "X-Frame-Options": {"allowed": ["DENY", "SAMEORIGIN"], "severity": "Medium", "cwe": "CWE-1021"},
    "X-Content-Type-Options": {"expected": "nosniff", "severity": "Medium", "cwe": "CWE-693"},
    "Content-Security-Policy": {"severity": "High", "cwe": "CWE-1021"},
    "Referrer-Policy": {"severity": "Low", "cwe": "CWE-200"},
    "Permissions-Policy": {"severity": "Low", "cwe": "CWE-693"}
}


def parse_and_verify_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Deterministically analyze a dictionary of HTTP response headers against security baseline rules.
    """
    norm_headers = {k.lower(): str(v) for k, v in headers.items()} if headers else {}
    findings: List[Dict[str, Any]] = []

    missing_count = 0
    passed_count = 0

    for header_name, rules in REQUIRED_SECURITY_HEADERS.items():
        h_lower = header_name.lower()
        if h_lower not in norm_headers:
            missing_count += 1
            findings.append({
                "check_id": f"HDR-{header_name.upper()}-MISSING",
                "header": header_name,
                "status": "MISSING",
                "severity": rules["severity"],
                "cwe_id": rules["cwe"],
                "description": f"The security header '{header_name}' is not configured."
            })
        else:
            header_value = norm_headers[h_lower]
            passed_count += 1
            if "expected" in rules and header_value.lower() != rules["expected"]:
                findings.append({
                    "check_id": f"HDR-{header_name.upper()}-INVALID",
                    "header": header_name,
                    "status": "INVALID",
                    "severity": rules["severity"],
                    "cwe_id": rules["cwe"],
                    "description": f"Expected '{rules['expected']}', but found '{header_value}'."
                })

    header_score = round((passed_count / len(REQUIRED_SECURITY_HEADERS)) * 100, 1)

    return {
        "total_headers_checked": len(REQUIRED_SECURITY_HEADERS),
        "headers_passed": passed_count,
        "headers_missing": missing_count,
        "score_percentage": header_score,
        "findings": findings
    }
