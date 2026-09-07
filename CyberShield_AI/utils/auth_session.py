"""
CyberShield AI — Authenticated Session Manager
===============================================
Manages authenticated HTTP sessions for web application scanning.
Handles CSRF token extraction, credential submission, and explicit login verification.
"""

import re
import logging
import requests
from typing import Optional, Dict, Any

from utils.http_client import get_session
from utils.target_policy import normalize_target

logger = logging.getLogger(__name__)

_DEFAULT_HEADERS = {
    "User-Agent": "CyberShield-AI/1.0 (Security Assessment Engine; +https://cybershield.ai)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def create_authenticated_session(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    csrf_field: Optional[str] = None,
    success_indicator: Optional[str] = None,
    extra_fields: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    allow_private: bool = False,
) -> Optional[requests.Session]:
    """
    Attempts to establish an authenticated requests.Session.

    Args:
        login_url: Full URL of the login endpoint (e.g. http://localhost:8080/login.php)
        username: Username/email to authenticate with
        password: Password to authenticate with
        username_field: HTML input field name for username
        password_field: HTML input field name for password
        csrf_field: Optional HTML input field name containing CSRF token (e.g. 'user_token')
        success_indicator: Required for verification; must be absent before login and present after login
        extra_fields: Optional static form fields (e.g. {'Login': 'Login'})
        timeout: Timeout per HTTP request in seconds
        allow_private: Whether private lab IP ranges are permitted

    Returns:
        Authenticated requests.Session on success, or None if authentication fails.
    """
    session = get_session(login_url, allow_private=allow_private)
    session.headers.update(_DEFAULT_HEADERS)

    authenticated = False
    try:
        validated = normalize_target(login_url)
        # Step 1: GET login page to obtain initial session cookies & CSRF token
        get_resp = session.get(validated.url, timeout=timeout)
        if get_resp.status_code >= 400:
            logger.warning(f"[auth_session] Login page GET failed with HTTP {get_resp.status_code} at {login_url}")
            return None

        # Extract CSRF token if specified
        csrf_value = None
        if csrf_field:
            # Pattern matching name='csrf_field' value='...' or value="..."
            match = re.search(
                rf"name=['\"]?{re.escape(csrf_field)}['\"]?\s+value=['\"]([^'\"]+)['\"]",
                get_resp.text,
                re.IGNORECASE,
            )
            if not match:
                # Try reversed attribute order value="..." name="..."
                match = re.search(
                    rf"value=['\"]([^'\"]+)['\"]\s+name=['\"]?{re.escape(csrf_field)}['\"]?",
                    get_resp.text,
                    re.IGNORECASE,
                )
            if match:
                csrf_value = match.group(1)
                logger.debug("[auth_session] Extracted configured CSRF field")
            else:
                logger.warning(f"[auth_session] CSRF field '{csrf_field}' defined but token not found in HTML body")

        # Step 2: Construct payload & POST login request
        payload = {
            username_field: username,
            password_field: password,
        }
        if csrf_value and csrf_field:
            payload[csrf_field] = csrf_value

        if extra_fields:
            payload.update(extra_fields)

        post_resp = session.post(validated.url, data=payload, timeout=timeout, allow_redirects=True)

        # Step 3: Explicit login verification — NEVER assume success
        if post_resp.status_code >= 400:
            logger.warning(f"[auth_session] Login POST failed with HTTP {post_resp.status_code}")
            return None

        if not success_indicator or not success_indicator.strip():
            logger.warning("[auth_session] Login cannot be verified without a success indicator")
            return None
        marker = success_indicator.casefold()
        if marker in get_resp.text.casefold() or marker not in post_resp.text.casefold():
            logger.warning("[auth_session] Login success indicator did not establish a state change")
            return None

        logger.info(f"[auth_session] Successfully authenticated at {login_url} (Cookies: {list(session.cookies.keys())})")
        authenticated = True
        return session

    except Exception as exc:
        logger.error(f"[auth_session] Exception during authentication attempt: {exc}")
        return None

    finally:
        if not authenticated:
            session.close()
