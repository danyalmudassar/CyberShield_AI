"""
CyberShield AI — Scan Deadlines & Force-Stop Tests
===================================================
Task 11: Enforce scan deadline timeouts and force-stop cancellation.
"""

import time
import pytest
from agents.orchestrator import run_full_scan, ScanFailed


def test_scan_deadline_expiration():
    """Scan exceeding max_duration_seconds must be marked TIMED_OUT and raise ScanFailed."""
    with pytest.raises(ScanFailed) as exc_info:
        run_full_scan(
            domain="example.com",
            authorized=True,
            execution_mode="demo",
            max_duration_seconds=0.0001,
        )
    assert exc_info.value.state.scan_progress["status"] == "TIMED_OUT"


def test_force_stop_cancellation():
    """Scan with active cancellation flag must set status CANCELLED and stop execution."""
    cancelling = True

    def cancellation_check():
        return cancelling

    with pytest.raises(ScanFailed) as exc_info:
        run_full_scan(
            domain="example.com",
            authorized=True,
            execution_mode="demo",
            cancellation_check=cancellation_check,
        )
    assert exc_info.value.state.scan_progress["status"] == "CANCELLED"


@pytest.mark.parametrize('value', [0, -1, float('inf'), float('nan'), True])
def test_library_cannot_disable_scan_deadline(value):
    with pytest.raises(ValueError, match='max_duration_seconds'):
        run_full_scan('example.invalid', execution_mode='demo', max_duration_seconds=value)


def test_stage_limit_expires_before_total_budget_and_kills_child(tmp_path, monkeypatch):
    import functools
    import multiprocessing as mp
    from pathlib import Path
    from agents import orchestrator
    from agents.orchestrator import _process_isolation_stage_fixture
    pid_file = tmp_path / 'stage.pid'
    monkeypatch.delenv('CYBERSHIELD_STAGE_ISOLATION', raising=False)
    monkeypatch.setattr(orchestrator, 'run_recon', functools.partial(_process_isolation_stage_fixture, pid_file=str(pid_file)))
    # Wall-clock movement must not extend monotonic scan or stage budgets.
    monkeypatch.setattr(time, 'time', lambda: -10**9)
    before = time.monotonic()
    with pytest.raises(ScanFailed, match='Stage deadline') as exc:
        run_full_scan('example.invalid', authorized=True, execution_mode='demo',
                      max_duration_seconds=15, max_stage_seconds=2)
    assert exc.value.state.scan_progress['status'] == 'TIMED_OUT'
    assert time.monotonic() - before < 6
    assert pid_file.read_text().strip().isdigit()
    assert int(pid_file.read_text()) not in [child.pid for child in mp.active_children()]
