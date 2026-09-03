"""
CyberShield AI — Anonymization & Data Sanitization Module
==========================================================
Strips specific domain names, public IP addresses, email addresses,
and authentication secrets from scan data prior to report rendering or external analysis.
"""

import re
from typing import Dict, Any, Union

# Standard RFC 5737 documentation IPs and safe replacement constants
SAFE_DOMAIN = "target.local"
SAFE_IP = "192.0.2.1"
SAFE_IPV6 = "2001:db8::1"
REDACTED_SECRET = "[REDACTED_CREDENTIAL]"

DOMAIN_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?', re.IGNORECASE)
BARE_DOMAIN_REGEX = re.compile(
    r'\b[a-zA-Z0-9.-]+\.(?:co\.uk|com\.pk|org\.pk|gov\.pk|edu\.pk|net\.pk|co\.jp|com|org|net|gov|edu|io|co|ai|pk|de|uk|info)\b',
    re.IGNORECASE
)
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
BEARER_KEY_REGEX = re.compile(r'(Bearer\s+|api_key=|key=|token=)[A-Za-z0-9._-]+', re.IGNORECASE)


def sanitize_text(text: str) -> str:
    """Sanitize raw text by replacing URLs, IPs, emails, and credentials with safe placeholders."""
    if not text:
        return ""
    
    # 1. Mask Authorization keys & tokens
    text = BEARER_KEY_REGEX.sub(rf'\1{REDACTED_SECRET}', text)
    
    # 2. Replace URLs with schemes
    text = DOMAIN_REGEX.sub(f'https://{SAFE_DOMAIN}', text)

    # 3. Replace bare domain names
    text = BARE_DOMAIN_REGEX.sub(SAFE_DOMAIN, text)
    
    # 4. Replace IPv4 and IPv6 addresses
    text = IPV4_REGEX.sub(SAFE_IP, text)
    text = IPV6_REGEX.sub(SAFE_IPV6, text)
    
    # 5. Replace email addresses
    text = EMAIL_REGEX.sub(f'user@{SAFE_DOMAIN}', text)
    
    return text



def sanitize_scan_payload(data: Union[Dict[str, Any], list, str]) -> Union[Dict[str, Any], list, str]:
    """Recursively sanitize dictionary or list scan payload."""
    if isinstance(data, str):
        return sanitize_text(data)
    elif isinstance(data, dict):
        sanitized = {}
        for key, val in data.items():
            if key in ("api_key", "token", "password", "secret", "authorization"):
                sanitized[key] = REDACTED_SECRET
            else:
                sanitized[key] = sanitize_scan_payload(val)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_scan_payload(item) for item in data]
    return data
