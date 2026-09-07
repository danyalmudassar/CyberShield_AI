import json
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
import server
from services import telemetry
from services.scan_store import ScanStore
from services.scan_worker import ScanWorker


@pytest.fixture
def client():
    with TestClient(server.app) as client:
        yield client


def login(client, role):
    response = client.post('/api/v1/auth/login',
                           headers={'Origin': 'http://localhost:3000', 'X-CyberShield-Request': '1'},
                           json={'email': role + '@cybershield.ai', 'password': f'Test-{role}-password-2026'})
    assert response.status_code == 200


def test_readiness_tracks_worker_health_without_exposing_inventory(client):
    for _ in range(30):
        if client.get('/api/ready').status_code == 200:
            break
        time.sleep(.05)
    assert client.get('/api/ready').json() == {'status': 'ready'}
    worker = server.app.state.scan_worker
    worker.stop_event.set()
    assert client.get('/api/ready').status_code == 503
    assert client.get('/api/health').status_code == 200


def test_readiness_detects_stalled_worker(tmp_path):
    from unittest.mock import Mock
    worker = ScanWorker(ScanStore(tmp_path / 'jobs.db'), dict)
    worker.thread = Mock()
    worker.thread.is_alive.return_value = True
    worker._lock_file = object()
    worker.last_poll = time.monotonic() - 60
    assert worker.readiness()['ready'] is False
    worker.last_poll = time.monotonic()
    assert worker.readiness()['ready'] is True


def test_readiness_detects_missing_database_without_creating_it(client, tmp_path):
    missing = tmp_path / 'absent.sqlite3'
    with patch.object(server.app.state.scan_store, 'path', str(missing)):
        assert client.get('/api/ready').status_code == 503
    assert not missing.exists()


def test_operations_requires_admin_and_reports_queue(client):
    assert client.get('/api/operations').status_code == 401
    login(client, 'operator')
    assert client.get('/api/operations').status_code == 403
    login(client, 'admin')
    status = client.get('/api/operations').json()
    assert status['database_ready'] is True
    assert status['max_pending'] == 100
    assert status['worker']['max_workers'] == 2
    assert status['http_requests']


def test_request_telemetry_omits_url_query_credentials_and_supplied_ids(client):
    with patch.object(telemetry.logger, 'info') as logged:
        response = client.get('/missing/private-user?token=secret-query', headers={'Authorization': 'Bearer secret-token', 'X-Request-ID': 'injected-id'})
    assert response.status_code == 404
    assert len(response.headers['X-Request-ID']) == 32
    events = [json.loads(call.args[0]) for call in logged.call_args_list]
    record = next(item for item in events if item['event'] == 'http_response')
    assert record['route'] == 'unmatched'
    assert record['request_id'] == response.headers['X-Request-ID']
    serialized = json.dumps(events)
    for secret in ('secret-query', 'secret-token', 'private-user', 'injected-id'):
        assert secret not in serialized


def test_request_histogram_is_cumulative_and_uses_fixed_labels():
    with telemetry._lock:
        saved = telemetry._requests.copy()
        telemetry._requests.clear()
    try:
        telemetry.observe_request('/api/scans/{scan_id}', 'GET', 200, .2)
        series = telemetry.request_metrics()[0]
        assert series['count'] == 1
        assert series['duration_buckets']['0.1'] == 0
        assert series['duration_buckets']['0.25'] == 1
        assert series['duration_buckets']['+Inf'] == 1
    finally:
        with telemetry._lock:
            telemetry._requests.clear()
            telemetry._requests.update(saved)


def test_worker_failure_has_scan_correlation_without_exception_secrets(tmp_path):
    store = ScanStore(tmp_path / 'jobs.db')
    job = store.create_scan({'domain': 'private-target.invalid'})
    def fail(**kwargs):
        raise RuntimeError('secret-provider-token')
    worker = ScanWorker(store, dict, runner=fail)
    with patch.object(telemetry.logger, 'info') as logged:
        assert worker.run_once()
    events = [json.loads(call.args[0]) for call in logged.call_args_list]
    assert [item['event'] for item in events] == ['scan_started', 'scan_execution_failed', 'scan_finished']
    assert all(item['scan_id'] == job['id'] for item in events)
    assert events[-1]['status'] == 'failed'
    assert 'secret-provider-token' not in json.dumps(events)
    assert 'private-target.invalid' not in json.dumps(events)
