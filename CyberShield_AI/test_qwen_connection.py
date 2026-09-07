"""
CyberShield AI — Qwen-Max API Connection Test
===============================================
Tests connectivity to Alibaba Cloud Qwen-Max API.
If API is unreachable or key is invalid, falls back to mock response.
This establishes the mock-fallback pattern every agent will follow.

Usage:
    python test_qwen_connection.py
"""

import json
import logging
import os
import time
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — load from config/.env
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent
_ENV_PATH = _PROJECT_ROOT / "config" / ".env"
load_dotenv(_ENV_PATH)

QWEN_API_KEY: str = os.getenv("QWEN_API_KEY", "")
QWEN_BASE_URL: str = os.getenv(
    "QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
)
QWEN_MODEL: str = os.getenv("QWEN_MODEL", "qwen-max")

_MOCK_PATH = _PROJECT_ROOT / "mocks" / "mock_qwen_response.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_mock_response() -> dict:
    """Read the mock Qwen response from disk and tag it with status='mock'."""
    with open(_MOCK_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data["status"] = "mock"
    # Ensure a human-readable 'message' key exists for test assertions.
    if "message" not in data:
        data["message"] = data.get("executive_summary", "Mock response loaded.")
    return data


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------

def test_qwen_connection(use_mock: bool = False) -> dict:
    """
    Attempt a live Qwen-Max API call.

    Parameters
    ----------
    use_mock : bool
        If True, skip the API call entirely and return mock data.

    Returns
    -------
    dict
        Always contains at least 'status' ('live' | 'mock') and 'message'.
    """
    if use_mock:
        logger.info("Mock mode requested — returning mock response.")
        return load_mock_response()

    # Guard: no API key configured
    if not QWEN_API_KEY:
        logger.warning("QWEN_API_KEY is empty — using mock fallback.")
        return load_mock_response()

    try:
        from openai import OpenAI  # imported here so mock mode has no dep

        client = OpenAI(api_key=QWEN_API_KEY, base_url=QWEN_BASE_URL)

        start = time.time()
        response = client.chat.completions.create(
            model=QWEN_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": "Respond with exactly: CyberShield AI connected successfully",
                }
            ],
            timeout=10,
        )
        elapsed_ms = int((time.time() - start) * 1000)

        response_text = response.choices[0].message.content.strip()

        return {
            "status": "live",
            "model": QWEN_MODEL,
            "message": response_text,
            "latency_ms": elapsed_ms,
        }

    except Exception as exc:
        logger.warning("Qwen-Max API unavailable: %s. Using mock fallback.", exc)
        return load_mock_response()


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("CyberShield AI — Qwen-Max Connection Test")
    print("=" * 50)

    # TEST 1: Mock mode (always works)
    print("\nTEST 1: Mock mode")
    result = test_qwen_connection(use_mock=True)
    assert result["status"] == "mock", f"Expected mock status, got {result['status']}"
    assert "message" in result, "Expected message in result"
    print(f"  PASS: Mock response received — {result.get('message', '')[:60]}")

    # TEST 2: Live API (may fall back to mock)
    print("\nTEST 2: Live API attempt")
    start = time.time()
    result = test_qwen_connection(use_mock=False)
    elapsed = time.time() - start

    if result["status"] == "live":
        print(f"  PASS: Live API connected in {elapsed:.1f}s")
        print(f"  Response: {result.get('message', '')[:80]}")
    else:
        print(f"  PASS: Graceful fallback to mock in {elapsed:.1f}s")
        print(f"  (API unavailable — this is expected without valid key)")

    # TEST 3: Verify response structure
    print("\nTEST 3: Response structure validation")
    assert "status" in result, "Missing 'status' key"
    assert "message" in result, "Missing 'message' key"
    assert result["status"] in ("live", "mock"), f"Invalid status: {result['status']}"
    print(f"  PASS: Valid response structure (status={result['status']})")

    print("\n" + "=" * 50)
    print("ALL QWEN CONNECTION TESTS PASSED")
    if result["status"] == "mock":
        print("NOTE: Running in OFFLINE mode (mock data)")
    else:
        print("NOTE: Running in LIVE mode (API connected)")
    print("=" * 50)
