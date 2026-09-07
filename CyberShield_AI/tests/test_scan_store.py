from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest

from services.scan_store import ScanStore


def test_scan_survives_reopen_with_result_and_owner(tmp_path):
    path = tmp_path / 'jobs.sqlite3'
    store = ScanStore(path)
    scan = store.create_scan({'target': 'https://example.test', 'nested': {'x': [1]}}, owner='alice')
    assert str(UUID(scan['id'])) == scan['id']
    assert scan['status'] == 'queued'
    assert scan['created_at'] == scan['updated_at']
    assert store.get_scan(scan['id'], owner='bob') is None
    store.claim_next()
    store.update_scan(scan['id'], 'completed', result={'findings': []})
    reopened = ScanStore(path)
    saved = reopened.get_scan(scan['id'], owner='alice')
    assert saved['result'] == {'findings': []}
    assert saved['started_at'] and saved['finished_at']
    assert saved['config'] == scan['config']
    assert reopened.list_scans(owner='alice') == [saved]
    assert reopened.list_scans(owner='bob') == []


def test_idempotency_is_atomic_and_scoped_to_owner(tmp_path):
    store = ScanStore(tmp_path / 'jobs.sqlite3')
    with ThreadPoolExecutor(max_workers=8) as pool:
        scans = list(pool.map(lambda _: store.create_scan({'b': 2, 'a': 1}, owner='alice', idempotency_key='key'), range(24)))
    assert len({scan['id'] for scan in scans}) == 1
    assert store.create_scan({'a': 1, 'b': 2}, owner='alice', idempotency_key='key')['id'] == scans[0]['id']
    with pytest.raises(ValueError, match='different'):
        store.create_scan({'a': 2}, owner='alice', idempotency_key='key')
    assert store.create_scan({'a': 2}, owner='bob', idempotency_key='key')['id'] != scans[0]['id']


def test_claim_is_atomic_and_restart_interrupts_only_active_jobs(tmp_path):
    path = tmp_path / 'jobs.sqlite3'
    store = ScanStore(path)
    scan = store.create_scan({})
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda _: store.claim_next(), range(16)))
    assert [c['id'] for c in claims if c] == [scan['id']]
    queued = store.create_scan({})
    cancelling = store.create_scan({})
    store.update_scan(cancelling['id'], 'running')
    store.cancel_scan(cancelling['id'])
    reopened = ScanStore(path)
    assert reopened.interrupt_running() == 2
    assert reopened.get_scan(scan['id'])['status'] == 'interrupted'
    assert reopened.get_scan(cancelling['id'])['status'] == 'interrupted'
    assert reopened.get_scan(queued['id'])['status'] == 'queued'


def test_ordered_events_persist_and_replay_without_duplicates(tmp_path):
    path = tmp_path / 'jobs.sqlite3'
    store = ScanStore(path)
    scan = store.create_scan({})
    with ThreadPoolExecutor(max_workers=8) as pool:
        events = list(pool.map(lambda n: store.append_event(scan['id'], {'type': 'progress', 'data': {'n': n}, 'id': 999}), range(30)))
    assert sorted(e['id'] for e in events) == list(range(1, 31))
    replay = ScanStore(path).events_after(scan['id'], after=10)
    assert [e['id'] for e in replay] == list(range(11, 31))
    assert all(e['type'] == 'progress' for e in replay)
    other = store.create_scan({})
    assert store.append_event(other['id'], {'type': 'start'})['id'] == 1
    with pytest.raises(KeyError):
        store.append_event('missing', {'type': 'start'})


def test_cancellation_and_terminal_states(tmp_path):
    store = ScanStore(tmp_path / 'jobs.sqlite3')
    queued = store.create_scan({})
    assert store.cancel_scan(queued['id'])['status'] == 'cancelled'
    assert store.claim_next() is None
    running = store.create_scan({})
    store.claim_next()
    assert store.cancel_scan(running['id'])['status'] == 'cancelling'
    store.update_scan(running['id'], 'cancelled')
    assert store.cancel_scan(running['id'])['status'] == 'cancelled'
    with pytest.raises(ValueError):
        store.update_scan(running['id'], 'running')
    assert store.cancel_scan('missing') is None


def test_rejects_non_json_without_creating_scan(tmp_path):
    store = ScanStore(tmp_path / 'jobs.sqlite3')
    with pytest.raises((TypeError, ValueError)):
        store.create_scan({'bad': float('nan')})
    assert store.list_scans() == []


def test_partial_results_are_terminal_and_preserved(tmp_path):
    store = ScanStore(tmp_path / 'jobs.sqlite3')
    scan = store.create_scan({})
    store.claim_next()
    result = {'status': 'partial', 'findings': [], 'errors': ['DNS unavailable']}
    saved = store.update_scan(scan['id'], 'partial', result=result)
    assert saved['status'] == 'partial'
    assert saved['finished_at']
    assert saved['result'] == result
    assert store.cancel_scan(scan['id'])['status'] == 'partial'
    with pytest.raises(ValueError):
        store.update_scan(scan['id'], 'running')
