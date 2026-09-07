"""Queue admission and durable terminal-state regressions."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from services.scan_store import ScanStore, QueueCapacityError


def test_pending_capacity_is_atomic_and_idempotent(tmp_path):
    store = ScanStore(tmp_path / 'jobs.db', max_pending=2)
    first = store.create_scan({}, owner='alice', idempotency_key='retry')
    store.create_scan({}, owner='bob')
    assert store.create_scan({}, owner='alice', idempotency_key='retry')['id'] == first['id']
    with pytest.raises(QueueCapacityError, match='capacity'):
        store.create_scan({})
    store.cancel_scan(first['id'])
    def submit(_):
        try:
            return store.create_scan({})['id']
        except QueueCapacityError as exc:
            assert 'capacity' in str(exc)
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(submit, range(12)))
    assert len([x for x in admitted if x]) == 1


def test_finalization_resolves_cancel_race_and_persists_one_terminal_event(tmp_path):
    store = ScanStore(tmp_path / 'jobs.db')
    job = store.create_scan({})
    store.claim_next()
    store.cancel_scan(job['id'])
    saved = store.finish_scan(job['id'], 'completed', result={'scan_progress': {'status': 'COMPLETED'}, 'evidence': ['kept']})
    assert saved['status'] == saved['result']['scan_progress']['status'].lower() == 'cancelled'
    assert saved['result']['evidence'] == ['kept']
    # Stale completion cannot overwrite cancellation or emit another final event.
    again = store.finish_scan(job['id'], 'completed', result={'evidence': ['late']})
    assert again == saved
    events = store.events_after(job['id'])
    assert len(events) == 1
    assert events[0]['status'] == 'cancelled' and events[0]['state'] == saved['result']


def test_terminal_event_failure_rolls_back_terminal_state(tmp_path, monkeypatch):
    store = ScanStore(tmp_path / 'jobs.db')
    job = store.create_scan({})
    store.claim_next()
    def fail(*args):
        raise RuntimeError('simulated event write failure')
    monkeypatch.setattr(store, '_append_event', fail)
    with pytest.raises(RuntimeError, match='event write'):
        store.finish_scan(job['id'], 'completed', result={'scan_progress': {'status': 'COMPLETED'}})
    assert store.get_scan(job['id'])['status'] == 'running'
    assert store.events_after(job['id']) == []


def test_restart_records_terminal_event_and_preserves_partial_evidence(tmp_path):
    path = tmp_path / 'jobs.db'
    store = ScanStore(path)
    active = store.create_scan({})
    store.claim_next()
    store.update_scan(active['id'], 'running', result={'scan_progress': {'status': 'RUNNING'}, 'evidence': ['partial']})
    queued = store.create_scan({})
    reopened = ScanStore(path)
    assert reopened.interrupt_running() == 1
    assert reopened.interrupt_running() == 0
    saved = reopened.get_scan(active['id'])
    assert saved['status'] == saved['result']['scan_progress']['status'].lower() == 'interrupted'
    assert saved['result']['evidence'] == ['partial']
    events = reopened.events_after(active['id'])
    assert len(events) == 1 and events[0]['status'] == 'interrupted'
    assert reopened.get_scan(queued['id'])['status'] == 'queued'


def wait_for(predicate, timeout=10):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate(), 'Condition was not reached before test deadline'


def test_concurrency_limit_and_duplicate_manager_start(tmp_path):
    from threading import Event, Lock
    from models import ScanState
    from services.scan_worker import ScanWorker
    store = ScanStore(tmp_path / 'jobs.db')
    jobs = [store.create_scan({}) for _ in range(3)]
    release, lock = Event(), Lock()
    active = peak = entered = 0
    def runner(**kwargs):
        nonlocal active, peak, entered
        with lock:
            active += 1
            entered += 1
            peak = max(peak, active)
        try:
            assert release.wait(5)
            return ScanState(scan_progress={'status': 'COMPLETED'})
        finally:
            with lock:
                active -= 1
    serialize = lambda state: {'scan_progress': state.scan_progress}
    worker = ScanWorker(store, serialize, runner=runner, max_workers=2)
    other = ScanWorker(ScanStore(store.path), serialize, runner=runner)
    worker.start()
    try:
        wait_for(lambda: entered == 2)
        assert store.get_scan(jobs[2]['id'])['status'] == 'queued'
        worker.start()  # Idempotent: must not interrupt its own active jobs.
        with pytest.raises(RuntimeError, match='already owns'):
            other.start()
        with pytest.raises(RuntimeError, match='already owns'):
            other.run_once()
        assert [store.get_scan(job['id'])['status'] for job in jobs] == ['running', 'running', 'queued']
        release.set()
        wait_for(lambda: all(store.get_scan(job['id'])['status'] == 'completed' for job in jobs))
        assert peak == 2 and entered == 3
    finally:
        release.set()
        worker.stop()
    assert not worker.thread.is_alive()
    assert not any(t.is_alive() for t in worker.active_threads)
    assert other.run_once() is False  # Ownership was released after quiescence.


def test_shutdown_keeps_ownership_until_execution_stops(tmp_path):
    from threading import Event
    from models import ScanState
    from services.scan_worker import ScanWorker
    release, entered = Event(), Event()
    store = ScanStore(tmp_path / 'jobs.db')
    job = store.create_scan({})
    def runner(**kwargs):
        entered.set()
        release.wait(5)
        return ScanState(scan_progress={'status': 'COMPLETED'})
    serialize = lambda state: {'scan_progress': state.scan_progress}
    worker = ScanWorker(store, serialize, runner=runner, max_workers=1)
    other = ScanWorker(store, serialize, runner=runner)
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RuntimeError, match='ownership retained'):
            worker.stop(timeout=0.01)
        with pytest.raises(RuntimeError, match='already owns'):
            other.start()
    finally:
        release.set()
        worker.stop()
    saved = store.get_scan(job['id'])
    assert saved['status'] == 'interrupted'
    assert saved['result']['scan_progress']['status'] == 'INTERRUPTED'
    assert len([e for e in store.events_after(job['id']) if e['type'] == 'complete']) == 1


@pytest.mark.parametrize('count', [0, -1, 17, True, 1.5])
def test_invalid_worker_bounds_fail_closed(tmp_path, count):
    from services.scan_worker import ScanWorker
    with pytest.raises(ValueError, match='between 1 and 16'):
        ScanWorker(ScanStore(tmp_path / 'jobs.db'), dict, max_workers=count)


def _worker_process_for_crash_test(db_path, pid_file):
    """Runs a real worker and real spawned stage, without network or providers."""
    import functools
    import time
    from unittest.mock import patch
    from agents.orchestrator import run_full_scan, _process_isolation_stage_fixture
    from services.scan_worker import ScanWorker
    from server import _serialize_state
    stage = functools.partial(_process_isolation_stage_fixture, pid_file=pid_file)
    with patch('agents.orchestrator.run_recon', stage):
        worker = ScanWorker(ScanStore(db_path), _serialize_state, runner=run_full_scan, max_workers=1)
        worker.start()
        while True:
            time.sleep(0.1)


def _pid_still_executing(pid):
    import os
    from pathlib import Path
    try:
        os.kill(pid, 0)
        # A container init may not immediately reap an adopted zombie. It cannot execute.
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except (ProcessLookupError, FileNotFoundError):
        return False


def test_killed_worker_stops_spawned_stage_and_restart_recovers_queue(tmp_path, monkeypatch):
    import multiprocessing as mp
    import os
    from models import ScanState
    from services.scan_worker import ScanWorker
    monkeypatch.delenv('CYBERSHIELD_STAGE_ISOLATION', raising=False)
    monkeypatch.setenv('CYBERSHIELD_MP_METHOD', 'spawn')
    path, pid_file = tmp_path / 'jobs.db', tmp_path / 'child.pid'
    store = ScanStore(path)
    active = store.create_scan({'domain': 'example.invalid', 'authorized': True, 'execution_mode': 'demo',
                                'max_duration_seconds': 20, 'max_stage_seconds': 15})
    process = mp.get_context('spawn').Process(target=_worker_process_for_crash_test, args=(str(path), str(pid_file)))
    process.start()
    child_pid = None
    try:
        wait_for(lambda: pid_file.exists() and pid_file.read_text().strip().isdigit(), timeout=15)
        child_pid = int(pid_file.read_text())
        assert _pid_still_executing(child_pid)
        queued = store.create_scan({'domain': 'example.invalid'})
        process.kill()  # Abrupt API/worker loss, bypassing graceful shutdown.
        process.join(timeout=5)
        assert not process.is_alive()
        wait_for(lambda: not _pid_still_executing(child_pid), timeout=5)
        seen = []
        def runner(**kwargs):
            seen.append(kwargs)
            return ScanState(scan_progress={'status': 'COMPLETED'})
        reopened = ScanStore(path)
        restarted = ScanWorker(reopened, lambda state: {'scan_progress': state.scan_progress}, runner=runner)
        restarted.start()
        try:
            wait_for(lambda: reopened.get_scan(queued['id'])['status'] == 'completed')
        finally:
            restarted.stop()
        assert len(seen) == 1  # The interrupted scan is never automatically rerun.
        assert reopened.get_scan(active['id'])['status'] == 'interrupted'
        assert [e['status'] for e in reopened.events_after(active['id']) if e['type'] == 'complete'] == ['interrupted']
    finally:
        if process.is_alive():
            process.kill()
        process.join(timeout=5)
        if child_pid and _pid_still_executing(child_pid):
            import signal
            os.kill(child_pid, signal.SIGKILL)


def test_real_api_demo_result_and_event_survive_service_restart(tmp_path, monkeypatch):
    import time
    from fastapi.testclient import TestClient
    import server
    monkeypatch.setenv('CYBERSHIELD_API_TOKEN', 'recovery-test-operator')
    monkeypatch.delenv('CYBERSHIELD_STAGE_ISOLATION', raising=False)
    headers = {'Authorization': 'Bearer recovery-test-operator'}
    with TestClient(server.app, headers=headers) as client:
        response = client.post('/api/scans', json={'domain': 'example.invalid', 'authorized': True,
                               'execution_mode': 'demo', 'max_duration_seconds': 30, 'max_stage_seconds': 10})
        assert response.status_code == 202
        scan_id = response.json()['id']
        wait_for(lambda: client.get(f'/api/scans/{scan_id}').json()['status'] == 'completed', timeout=30)
        job = client.get(f'/api/scans/{scan_id}').json()
        events = client.get(f'/api/scans/{scan_id}/events')
        assert events.text.count('"type": "complete"') == 1
        pdf = client.get(f'/api/scans/{scan_id}/report')
        assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF')
    with TestClient(server.app, headers=headers) as restarted:
        assert restarted.get(f'/api/scans/{scan_id}').json() == job
        assert len(restarted.get('/api/scans').json()) == 1
        replay = restarted.get(f'/api/scans/{scan_id}/events')
        assert replay.text == events.text
