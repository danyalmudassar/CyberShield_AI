from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import server
from models import ScanState
from services.scan_store import ScanStore
from services.scan_worker import ScanWorker


@pytest.fixture
def api(tmp_path, monkeypatch):
    store = ScanStore(tmp_path / 'scans.db')
    monkeypatch.setattr(server.app.state, 'scan_store', store, raising=False)
    monkeypatch.setenv('CYBERSHIELD_API_TOKEN', 'test-lifecycle-token')
    client = TestClient(server.app, headers={"Authorization": "Bearer test-lifecycle-token"})
    return client, store


def request_config():
    return {'domain': 'example.invalid', 'authorized': True, 'execution_mode': 'demo'}


def test_authorization_required_and_mode_validated(api):
    client, store = api
    assert client.post('/api/scans', json={'domain': 'example.invalid', 'execution_mode': 'demo'}).status_code == 403
    assert client.post('/api/scans', json={**request_config(), 'execution_mode': 'typo'}).status_code == 422
    assert client.post('/api/scans', json={**request_config(), 'strict_live': True}).status_code == 422
    assert store.list_scans() == []


def test_create_is_idempotent_and_sse_reconnect_does_not_execute(api):
    client, store = api
    first = client.post('/api/scans', json=request_config(), headers={'Idempotency-Key': 'one'})
    again = client.post('/api/scans', json=request_config(), headers={'Idempotency-Key': 'one'})
    assert first.status_code == 202
    assert first.json()['id'] == again.json()['id']
    scan_id = first.json()['id']
    calls = []
    def runner(**kwargs):
        calls.append(kwargs)
        kwargs['progress_callback']('recon', 'Recon completed')
        return ScanState(domain=kwargs['domain'], execution_mode='demo', scan_progress={'status': 'COMPLETED'})
    worker = ScanWorker(store, server._serialize_state, runner=runner)
    assert worker.run_once()
    assert not worker.run_once()
    one = client.get(f'/api/scans/{scan_id}/events')
    two = client.get(f'/api/scans/{scan_id}/events', headers={'Last-Event-ID': '2'})
    assert one.status_code == two.status_code == 200
    assert '"type": "complete"' in two.text
    assert len(calls) == 1
    assert calls[0]['execution_mode'] == 'demo'
    assert len(client.get('/api/scans').json()) == 1
    assert client.get('/api/scan/stream?domain=example.invalid').status_code == 410


def test_cancelled_queue_never_runs(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    response = client.post(f"/api/scans/{job['id']}/cancel")
    assert response.json()['status'] == 'cancelled'
    runner = lambda **kwargs: pytest.fail('cancelled scan executed')
    assert not ScanWorker(store, server._serialize_state, runner=runner).run_once()
    stream = client.get(f"/api/scans/{job['id']}/events")
    assert 'cancelled' in stream.text


def test_worker_failure_and_restart_are_observable(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    def runner(**kwargs):
        raise RuntimeError('fixture failure')
    assert ScanWorker(store, server._serialize_state, runner).run_once()
    assert client.get(f"/api/scans/{job['id']}").json()['status'] == 'failed'
    next_job = client.post('/api/scans', json=request_config()).json()
    store.claim_next()
    assert store.interrupt_running() == 1
    stream = client.get(f"/api/scans/{next_job['id']}/events")
    assert 'interrupted' in stream.text


def test_operator_token_and_origin_enforced(api, monkeypatch):
    client, store = api
    monkeypatch.setenv('CYBERSHIELD_API_TOKEN', 'test-operator')
    assert client.get('/api/scans').status_code == 401
    headers = {'Authorization': 'Bearer test-operator'}
    assert client.get('/api/scans', headers=headers).status_code == 200
    headers['Origin'] = 'https://untrusted.invalid'
    assert client.post('/api/scans', headers=headers, json=request_config()).status_code == 403


def test_no_report_and_unknown_scan_return_404(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    assert client.get(f"/api/scans/{job['id']}/report").status_code == 404
    assert client.get('/api/scans/missing').status_code == 404
    assert client.get('/api/scans/missing/events').status_code == 404


def test_worker_honors_cancel_race(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    def runner(**kwargs):
        store.cancel_scan(job['id'])
        return ScanState(scan_progress={'status': 'COMPLETED'})
    assert ScanWorker(store, server._serialize_state, runner).run_once()
    saved = store.get_scan(job['id'])
    assert saved['status'] == 'cancelled'
    assert saved['result']['scan_progress']['status'] == 'CANCELLED'


def test_invalid_result_cannot_strand_running_job(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    worker = ScanWorker(store, lambda state: {'bad': float('nan')}, runner=lambda **kw: ScanState(scan_progress={'status': 'COMPLETED'}))
    assert worker.run_once()
    assert store.get_scan(job['id'])['status'] == 'failed'
    assert store.get_scan(job['id'])['result'] is None


def test_failure_state_serialization_cannot_strand_job(api):
    from agents.orchestrator import ScanFailed
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    def runner(**kw):
        raise ScanFailed('fixture strict failure', ScanState(scan_progress={'status': 'FAILED'}))
    def broken_serializer(state):
        raise TypeError('unserializable')
    assert ScanWorker(store, broken_serializer, runner).run_once()
    assert store.get_scan(job['id'])['status'] == 'failed'


def test_demo_only_instance_rejects_live(api, monkeypatch):
    client, store = api
    monkeypatch.setenv('CYBERSHIELD_DEMO_ONLY', 'true')
    assert client.post('/api/scans', json={**request_config(), 'execution_mode': 'live'}).status_code == 403


def test_api_duration_bounds_are_persisted_and_reach_runner(api):
    client, store = api
    config = {**request_config(), 'max_duration_seconds': 20, 'max_stage_seconds': 5}
    response = client.post('/api/scans', json=config)
    assert response.status_code == 202
    seen = []
    def runner(**kwargs):
        seen.append(kwargs)
        return ScanState(scan_progress={'status': 'COMPLETED'})
    assert ScanWorker(store, server._serialize_state, runner=runner).run_once()
    assert seen[0]['max_duration_seconds'] == 20 and seen[0]['max_stage_seconds'] == 5
    assert client.get(f"/api/scans/{response.json()['id']}").json()['config']['max_stage_seconds'] == 5


@pytest.mark.parametrize('field,value', [('max_duration_seconds', 0), ('max_duration_seconds', 901),
    ('max_stage_seconds', 0), ('max_stage_seconds', 301), ('max_duration_seconds', True), ('max_stage_seconds', 1.5)])
def test_api_rejects_unbounded_or_invalid_deadlines(api, field, value):
    client, store = api
    assert client.post('/api/scans', json={**request_config(), field: value}).status_code == 422
    assert store.list_scans() == []


def test_api_queue_full_preserves_idempotent_retry(api):
    client, store = api
    store.max_pending = 1
    first = client.post('/api/scans', json=request_config(), headers={'Idempotency-Key': 'one'})
    assert first.status_code == 202
    assert client.post('/api/scans', json=request_config(), headers={'Idempotency-Key': 'one'}).json()['id'] == first.json()['id']
    full = client.post('/api/scans', json=request_config())
    assert full.status_code == 429 and full.headers['retry-after'] == '5'
    assert len(store.list_scans()) == 1


def test_terminal_sse_event_is_not_duplicated(api):
    client, store = api
    job = client.post('/api/scans', json=request_config()).json()
    worker = ScanWorker(store, server._serialize_state,
                        runner=lambda **kwargs: ScanState(scan_progress={'status': 'COMPLETED'}))
    worker.run_once()
    stream = client.get(f"/api/scans/{job['id']}/events")
    assert stream.text.count('"type": "complete"') == 1
