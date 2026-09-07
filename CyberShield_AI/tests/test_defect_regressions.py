"""
CyberShield AI — Regression tests for four confirmed defects
=============================================================

1. Timeout process isolation: run_full_scan with deadline must hard-kill the
   stage process promptly and terminate without thread/process leaks.

2. DNS pinning thread-safety: concurrent dns_bound contexts on different
   threads must not cross-contaminate each other, and exiting threads must not raise.

3. ContextVar model propagation: real orchestrator stage execution must see the
   requested AI model name inside stage workers.

4. Authentic Endpoint Authorization: operator() and get_current_user() must reject
   unauthenticated requests when authentication is required.
"""

import sys
import os
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import ScanState, Finding
from agents.orchestrator import run_full_scan, ScanFailed
from utils.auth_manager import get_current_user, authenticate_user, create_token
from utils.ai_provider import model_context, configured_model
import utils.http_client as http_client_mod
from utils.http_client import dns_bound
from server import operator
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# 1. Real Orchestrator Timeout & Process Isolation
# ---------------------------------------------------------------------------

def _hung_recon_for_test(*args, **kwargs):
    """Module-level hung recon fixture — must be at module scope to be picklable."""
    import time as _time
    _time.sleep(2.0)
    return {}

def test_stage_timeout_returns_promptly():
    """
    A scan with a small max_duration_seconds must raise ScanFailed with TIMED_OUT status.
    Uses CYBERSHIELD_STAGE_ISOLATION=thread so mocked stage functions are visible in-process.
    Verifies that the deadline triggers within 0.80 s.
    """
    import os
    from unittest.mock import patch

    def slow_recon(*args, **kwargs):
        time.sleep(5.0)
        return {}

    with patch.dict(os.environ, {"CYBERSHIELD_STAGE_ISOLATION": "thread"}), \
         patch("agents.orchestrator.run_recon", side_effect=slow_recon):
        t0 = time.time()
        with pytest.raises(ScanFailed) as exc_info:
            run_full_scan(
                domain="example.com",
                authorized=True,
                execution_mode="demo",
                max_duration_seconds=0.05,
            )
        elapsed = time.time() - t0

    assert "deadline exceeded" in str(exc_info.value).lower()
    assert exc_info.value.state.scan_progress.get("status") == "TIMED_OUT"
    assert elapsed < 0.80, f"Timeout took {elapsed:.3f}s — deadline check was not timely."


def _is_pid_dead(pid: int) -> bool:
    import os
    try:
        os.kill(pid, 0)
        return False
    except (ProcessLookupError, OSError):
        return True


def test_real_orchestrator_terminates_process_isolated_child_on_timeout():
    """
    Test the real orchestrator in process-isolation mode using an importable child-stage fixture.
    Verifies that when a deadline expires, the real orchestrator hard-kills the exact child process
    that was spawned, and that the child process is confirmed dead.
    """
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    from agents.orchestrator import _process_isolation_stage_fixture

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        pid_file = tmp.name

    try:
        # Patch run_recon with the importable top-level stage fixture.
        # Ensure default process-isolation mode is active (unset CYBERSHIELD_STAGE_ISOLATION).
        env_dict = dict(os.environ)
        env_dict.pop("CYBERSHIELD_STAGE_ISOLATION", None)

        import functools
        stage_fn = functools.partial(_process_isolation_stage_fixture, pid_file=pid_file)

        with patch.dict(os.environ, env_dict, clear=True), \
             patch("agents.orchestrator.run_recon", stage_fn):
            with pytest.raises(ScanFailed) as exc_info:
                run_full_scan(
                    domain="example.com",
                    authorized=True,
                    execution_mode="demo",
                    max_duration_seconds=2.0,
                )

        assert exc_info.value.state.scan_progress.get("status") == "TIMED_OUT"

        # Verify child process started and wrote its PID
        pid_text = Path(pid_file).read_text().strip()
        assert pid_text.isdigit(), f"Expected child PID in file, got: {pid_text!r}"
        child_pid = int(pid_text)
        assert child_pid > 0

        # Assert that the exact child process spawned by orchestrator has exited/is dead
        assert _is_pid_dead(child_pid), f"Child process {child_pid} was NOT terminated by orchestrator!"
    finally:
        if os.path.exists(pid_file):
            os.remove(pid_file)


def test_real_orchestrator_terminates_process_isolated_child_on_cancellation():
    """
    Test that when cancellation is requested, the real orchestrator hard-kills the exact child process
    that was spawned, and confirms the child process has exited.
    """
    import tempfile, functools
    from pathlib import Path
    from unittest.mock import patch
    from agents.orchestrator import _process_isolation_stage_fixture

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        pid_file = tmp.name

    try:
        env_dict = dict(os.environ)
        env_dict.pop("CYBERSHIELD_STAGE_ISOLATION", None)

        stage_fn = functools.partial(_process_isolation_stage_fixture, pid_file=pid_file)

        def cancel_check():
            # Trigger cancellation once the child process has written its PID file
            if os.path.exists(pid_file) and Path(pid_file).read_text().strip().isdigit():
                return True
            return False

        with patch.dict(os.environ, env_dict, clear=True), \
             patch("agents.orchestrator.run_recon", stage_fn):
            with pytest.raises(ScanFailed) as exc_info:
                run_full_scan(
                    domain="example.com",
                    authorized=True,
                    execution_mode="demo",
                    cancellation_check=cancel_check,
                )

        assert exc_info.value.state.scan_progress.get("status") == "CANCELLED"

        pid_text = Path(pid_file).read_text().strip()
        assert pid_text.isdigit()
        child_pid = int(pid_text)
        assert child_pid > 0

        assert _is_pid_dead(child_pid), f"Child process {child_pid} was NOT terminated on cancellation!"
    finally:
        if os.path.exists(pid_file):
            os.remove(pid_file)


def test_real_orchestrator_rejects_unpicklable_stage_in_process_mode():
    """
    In process isolation mode (default), passing an unpicklable stage (e.g. local closure)
    must raise TypeError rather than silently falling back to detached thread execution.
    """
    from unittest.mock import patch

    def unpicklable_local_stage(*args, **kwargs):
        return {}

    env_dict = dict(os.environ)
    env_dict.pop("CYBERSHIELD_STAGE_ISOLATION", None)

    with patch.dict(os.environ, env_dict, clear=True), \
         patch("agents.orchestrator.run_recon", side_effect=unpicklable_local_stage):
        with pytest.raises(TypeError) as exc_info:
            run_full_scan(
                domain="example.com",
                authorized=True,
                execution_mode="demo",
            )

    assert "not picklable for process-isolated execution" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 2. Real Orchestrator Model ContextVar Propagation
# ---------------------------------------------------------------------------

def _sample_recon_stage(*args, **kwargs):
    return {
        "domain": "example.com",
        "dns": {"model": configured_model()}, "ssl": {}, "headers": {}, "tech": {},
        "findings": [Finding(title="ModelCheck", severity="Low", description=configured_model())],
        "ai_analysis": {}, "data_sources": {}, "fallback_triggered": False,
    }


def test_model_contextvar_visible_in_real_orchestrator():
    """
    When model_context() is set or ai_model is specified, the real stage process
    wrapper in orchestrator sees the model selection.
    """
    with patch("agents.orchestrator.run_recon", _sample_recon_stage):
        with model_context("custom-gemini-test"):
            state = run_full_scan("example.com", authorized=True, execution_mode="demo")

    assert state is not None
    assert isinstance(state.recon, dict) and state.recon.get("model") == "custom-gemini-test", (
        f"Stage process saw model '{state.recon.get('model') if isinstance(state.recon, dict) else None}' instead of 'custom-gemini-test'."
    )


# ---------------------------------------------------------------------------
# 3. Thread-Safe DNS Pinning (Warning-Free Exception Handling)
# ---------------------------------------------------------------------------

def test_dns_bound_concurrent_contexts_do_not_cross_contaminate():
    """
    Two threads each pin a different host. Each thread must see only its own
    mapping; neither must influence the other.
    """
    results_a: list = []
    results_b: list = []
    barrier = threading.Barrier(2)

    def thread_a():
        with dns_bound("host-a.test", ("10.0.0.1",)):
            barrier.wait()
            time.sleep(0.05)
            resolved = http_client_mod._thread_aware_getaddrinfo("host-a.test", 443)
            results_a.extend(r[4][0] for r in resolved)

    def thread_b():
        with dns_bound("host-b.test", ("10.0.0.2",)):
            barrier.wait()
            time.sleep(0.05)
            resolved = http_client_mod._thread_aware_getaddrinfo("host-b.test", 443)
            results_b.extend(r[4][0] for r in resolved)

    ta = threading.Thread(target=thread_a)
    tb = threading.Thread(target=thread_b)
    ta.start()
    tb.start()
    ta.join(timeout=5)
    tb.join(timeout=5)

    assert results_a, "Thread A produced no results"
    assert results_b, "Thread B produced no results"
    assert "10.0.0.1" in results_a
    assert "10.0.0.2" not in results_a
    assert "10.0.0.2" in results_b
    assert "10.0.0.1" not in results_b


def test_dns_bound_restores_after_nested_context():
    """Nested dns_bound contexts restore correctly on exit."""
    with dns_bound("outer.test", ("192.0.2.1",)):
        outer_result = http_client_mod._thread_aware_getaddrinfo("outer.test", 80)
        with dns_bound("outer.test", ("192.0.2.99",)):
            inner_result = http_client_mod._thread_aware_getaddrinfo("outer.test", 80)
        after_inner = http_client_mod._thread_aware_getaddrinfo("outer.test", 80)

    assert any(r[4][0] == "192.0.2.1" for r in outer_result)
    assert any(r[4][0] == "192.0.2.99" for r in inner_result)
    assert any(r[4][0] == "192.0.2.1" for r in after_inner)


def test_dns_bound_no_cross_thread_leak_after_exit():
    """
    After dns_bound exits in thread A, thread B must NOT see thread A's binding.
    The test worker thread handles resolution exceptions cleanly without pytest warnings.
    """
    with dns_bound("leak.test", ("1.2.3.4",)):
        pass

    results: list = []

    def thread_b():
        try:
            resolved = http_client_mod._thread_aware_getaddrinfo("leak.test", 80)
            results.extend(r[4][0] for r in resolved)
        except Exception:
            pass  # Expected when network guard blocks un-bound lookup

    tb = threading.Thread(target=thread_b)
    tb.start()
    tb.join(timeout=5)
    assert "1.2.3.4" not in results


# ---------------------------------------------------------------------------
# 4. Authentication Enforcement & Loopback Protection
# ---------------------------------------------------------------------------

def _make_mock_request(auth_header: str = "", token_param: str = "", client_host: str = "127.0.0.1"):
    """Build a minimal mock FastAPI Request for auth tests."""
    mock = MagicMock()
    mock.client = MagicMock()
    mock.client.host = client_host
    mock.method = "GET"

    headers_data = {}
    if auth_header:
        headers_data["authorization"] = auth_header
    mock.headers.get = lambda key, default="": headers_data.get(key.lower(), default)
    mock.headers.__contains__ = lambda key: key.lower() in headers_data

    params_data = {}
    if token_param:
        params_data["token"] = token_param
    mock.query_params.get = lambda key, default=None: params_data.get(key, default)

    return mock


def test_get_current_user_returns_none_without_token():
    request = _make_mock_request(client_host="127.0.0.1")
    identity = get_current_user(request)
    assert identity is None


def test_get_current_user_returns_none_for_external_no_token():
    request = _make_mock_request(client_host="203.0.113.1")
    assert get_current_user(request) is None


def test_get_current_user_rejects_invalid_token():
    request = _make_mock_request(auth_header="Bearer totally_invalid_token_xyz_abc123", client_host="127.0.0.1")
    assert get_current_user(request) is None


def test_get_current_user_accepts_valid_token():
    identity_from_login = authenticate_user("operator@cybershield.ai", "Test-operator-password-2026")
    assert identity_from_login is not None

    from utils.auth_manager import create_token
    u = identity_from_login
    token = create_token(u.user_id, u.email, u.role)

    request = _make_mock_request(auth_header=f"Bearer {token}")
    identity = get_current_user(request)
    assert identity is not None
    assert identity.email == "operator@cybershield.ai"
    assert identity.role == "operator"


def test_operator_requires_auth_when_enabled(monkeypatch):
    """
    When CYBERSHIELD_REQUIRE_AUTH=true, operator() must raise 401 for unauthenticated
    loopback requests instead of granting 'local' owner identity.
    """
    monkeypatch.setenv("CYBERSHIELD_REQUIRE_AUTH", "true")
    request = _make_mock_request(client_host="127.0.0.1")

    with pytest.raises(HTTPException) as exc_info:
        operator(request)
    assert exc_info.value.status_code == 401
    assert "Authentication required" in exc_info.value.detail
