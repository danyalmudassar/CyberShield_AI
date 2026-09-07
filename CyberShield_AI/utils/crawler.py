"""
CyberShield AI — Deep Link & Form Crawler
==========================================
Discovers same-domain endpoints and form targets for depth-controlled pentesting.
"""

import logging
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from typing import List, Set, Tuple
from utils.http_client import guarded_session
from utils.target_policy import normalize_target, TargetPolicyError

logger = logging.getLogger(__name__)

def discover_endpoints(
    session: requests.Session,
    base_url: str,
    max_depth: int = 2,
    max_pages: int = 15,
    timeout: float = 3.0,
) -> List[str]:
    """
    Crawls links (<a href>) and forms (<form action>) starting from base_url.

    Args:
        session: Active requests.Session (authenticated or unauthenticated)
        base_url: Starting URL (e.g. http://localhost:8080)
        max_depth: Maximum link depth to traverse
        max_pages: Hard cap on total discovered endpoints
        timeout: Timeout per page fetch in seconds

    Returns:
        List of unique, fully-qualified same-domain URLs discovered.
    """
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"

    origin = normalize_target(base_url).origin
    session = guarded_session(session, base_url)
    base_domain = urlparse(base_url).netloc.lower()

    # URL patterns that would destroy the authenticated session — never visit these
    _SESSION_DESTROYERS = ("logout", "signout", "sign-out", "log-out", "logoff", "log_off")

    visited: Set[str] = set()
    to_visit: List[Tuple[str, int]] = [(base_url, 0)]
    discovered: List[str] = []

    while to_visit and len(discovered) < max_pages:
        current_url, depth = to_visit.pop(0)

        # Skip URLs that would destroy the session (e.g. /logout.php)
        url_lower = current_url.lower()
        if any(killer in url_lower for killer in _SESSION_DESTROYERS):
            logger.debug(f"[crawler] Skipping session-destroying URL: {current_url}")
            continue

        # Clean query strings for visited deduplication to avoid infinite loops on dynamic params
        clean_visited_key = current_url.split("#")[0]
        if clean_visited_key in visited or depth > max_depth:
            continue

        visited.add(clean_visited_key)
        discovered.append(current_url)

        try:
            resp = session.get(current_url, timeout=timeout)
            if resp.status_code >= 400 or not resp.text:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract <a> href and <form> action attributes
            found_nodes = soup.find_all(["a", "form"])
            for node in found_nodes:
                target = node.get("href") or node.get("action")
                if not target or target.startswith("javascript:") or target.startswith("mailto:") or target.startswith("#"):
                    continue

                full_target = urljoin(current_url, target).split("#")[0]
                target_parsed = urlparse(full_target)

                # Ensure strict same-domain crawling
                try:
                    in_scope = normalize_target(full_target).origin == origin
                except TargetPolicyError:
                    in_scope = False
                if in_scope:
                    if full_target not in visited:
                        to_visit.append((full_target, depth + 1))

        except Exception as exc:
            logger.debug(f"[crawler] Skipped URL {current_url} due to error: {exc}")
            continue

    logger.info(f"[crawler] Discovered {len(discovered)} unique endpoints on {base_domain} (max_depth={max_depth})")
    return discovered
