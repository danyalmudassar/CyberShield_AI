import fcntl
import json
import sqlite3
from pathlib import Path

import pytest
from services import backup
from services.scan_store import ScanStore


@pytest.fixture
def source(tmp_path):
    data = tmp_path / 'source'
    data.mkdir()
    reports = data / 'reports'
    reports.mkdir()
    (reports / 'result.pdf').write_bytes(b'%PDF-1.4\nfixture report')
    store = ScanStore(data / 'scans.sqlite3')
    job = store.create_scan({'domain': 'example.invalid'}, owner='operator@cybershield.ai')
    store.claim_next()
    store.finish_scan(job['id'], 'completed', {'pdf_path': 'result.pdf', 'findings': []})
    auth = data / 'auth.sqlite3'
    with sqlite3.connect(auth) as conn:
        conn.executescript('CREATE TABLE users(id TEXT PRIMARY KEY); CREATE TABLE sessions(digest TEXT); CREATE TABLE login_limits(bucket TEXT); INSERT INTO users VALUES ("operator"); INSERT INTO sessions VALUES ("old-digest");')
    return store, auth, reports, tmp_path / 'bundle'


def make(source):
    store, auth, reports, bundle = source
    backup.create(store.path, auth, reports, bundle, offline=True)
    return bundle


def test_backup_restores_evidence_revokes_sessions_and_stops_old_queue(source, tmp_path):
    store, _, reports, _ = source
    completed = store.list_scans()[0]
    queued = store.create_scan({'domain': 'example.invalid'})
    bundle = make(source)
    destination = tmp_path / 'restored'
    before = backup.verify(bundle)
    assert backup.restore(bundle, destination) == {'sessions_revoked': 1, 'pending_scans_stopped': 1}
    restored = ScanStore(destination / 'data/scans.sqlite3')
    assert restored.get_scan(completed['id']) == completed
    assert restored.events_after(completed['id']) == store.events_after(completed['id'])
    assert restored.get_scan(queued['id'])['status'] == 'cancelled'
    assert restored.claim_next() is None
    assert (destination / 'reports/result.pdf').read_bytes() == (reports / 'result.pdf').read_bytes()
    with sqlite3.connect(destination / 'data/auth.sqlite3') as conn:
        assert conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
    assert backup.verify(bundle) == before
    assert destination.stat().st_mode & 0o777 == 0o700


def test_active_worker_blocks_backup(source):
    store, auth, reports, bundle = source
    with open(store.path + '.worker.lock', 'a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match='active scan worker'):
            backup.create(store.path, auth, reports, bundle, offline=True)
    assert not bundle.exists()


def test_offline_acknowledgement_required(source):
    store, auth, reports, bundle = source
    with pytest.raises(ValueError, match='--offline'):
        backup.create(store.path, auth, reports, bundle)


@pytest.mark.parametrize('change', ['corrupt', 'missing', 'symlink', 'traversal'])
def test_invalid_bundle_never_publishes_restore(source, tmp_path, change):
    bundle = make(source)
    pdf = bundle / 'reports/result.pdf'
    if change == 'corrupt':
        pdf.write_bytes(b'changed')
    elif change == 'missing':
        pdf.unlink()
    elif change == 'symlink':
        pdf.unlink()
        pdf.symlink_to(source[2] / 'result.pdf')
    else:
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['files']['../outside.pdf'] = {'size': 1, 'sha256': 'bad'}
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        backup.restore(bundle, tmp_path / 'restore')
    assert not (tmp_path / 'restore').exists()


def test_existing_destination_is_preserved(source, tmp_path):
    bundle = make(source)
    destination = tmp_path / 'existing'
    destination.mkdir()
    (destination / 'important').write_text('keep')
    with pytest.raises(ValueError, match='already exists'):
        backup.restore(bundle, destination)
    assert (destination / 'important').read_text() == 'keep'


def test_missing_referenced_pdf_prevents_backup_publication(source):
    store, auth, reports, bundle = source
    (reports / 'result.pdf').unlink()
    with pytest.raises(ValueError, match='regular file'):
        backup.create(store.path, auth, reports, bundle, offline=True)
    assert not bundle.exists()


def test_wal_commits_are_included(source):
    store = source[0]
    with sqlite3.connect(store.path) as keeper:
        keeper.execute('PRAGMA journal_mode=WAL')
        queued = store.create_scan({'domain': 'wal.example.invalid'})
        assert Path(store.path + '-wal').stat().st_size > 0
        bundle = make(source)
        with sqlite3.connect(bundle / 'data/scans.sqlite3') as conn:
            assert conn.execute('SELECT status FROM scans WHERE id=?', (queued['id'],)).fetchone() == ('queued',)


def test_copy_failure_leaves_no_published_bundle(source, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('simulated storage full')
    monkeypatch.setattr(backup.shutil, 'copyfile', fail)
    with pytest.raises(OSError, match='storage full'):
        make(source)
    assert not source[3].exists()
    assert not list(source[3].parent.glob('.cybershield-staging-*'))


def test_recovered_running_job_is_interrupted(source, tmp_path):
    store = source[0]
    job = store.create_scan({})
    store.claim_next()
    bundle = make(source)
    backup.restore(bundle, tmp_path / 'recovered')
    restored = ScanStore(tmp_path / 'recovered/data/scans.sqlite3')
    assert restored.get_scan(job['id'])['status'] == 'interrupted'
    assert restored.events_after(job['id'])[-1]['type'] == 'complete'


def test_restored_api_login_history_sse_and_pdf(tmp_path, monkeypatch):
    import os
    from fastapi.testclient import TestClient
    from fpdf import FPDF
    import server
    from utils import auth_manager as auth

    reports = tmp_path / 'reports'
    reports.mkdir()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', size=12)
    pdf.cell(text='Offline recovery acceptance report')
    expected_pdf = bytes(pdf.output())
    (reports / 'acceptance.pdf').write_bytes(expected_pdf)
    monkeypatch.setattr(server, 'REPORTS_DIR', str(reports))
    store = ScanStore(os.environ['CYBERSHIELD_DB'])
    job = store.create_scan({'domain': 'example.invalid'}, owner='operator@cybershield.ai')
    store.claim_next()
    store.finish_scan(job['id'], 'completed', {'pdf_path': 'acceptance.pdf', 'findings': []})
    route = '/api/scans/' + job['id']
    headers = {'Origin': 'http://localhost:3000', 'X-CyberShield-Request': '1'}
    credentials = {'email': 'operator@cybershield.ai', 'password': 'Test-operator-password-2026'}
    with TestClient(server.app) as client:
        assert client.post('/api/v1/auth/login', json=credentials, headers=headers).status_code == 200
        old_session = client.cookies.get(auth.COOKIE_NAME)
        expected_job = client.get(route).json()
        expected_events = client.get(route + '/events').text
        assert client.get(route + '/report').content == expected_pdf
    bundle = tmp_path / 'acceptance-bundle'
    backup.create(store.path, os.environ['CYBERSHIELD_AUTH_DB'], reports, bundle, offline=True)
    restored = tmp_path / 'acceptance-restored'
    backup.restore(bundle, restored)
    monkeypatch.setenv('CYBERSHIELD_DB', str(restored / 'data/scans.sqlite3'))
    monkeypatch.setenv('CYBERSHIELD_AUTH_DB', str(restored / 'data/auth.sqlite3'))
    monkeypatch.setattr(server, 'REPORTS_DIR', str(restored / 'reports'))
    with TestClient(server.app) as client:
        assert client.get('/api/v1/auth/me', headers={'Authorization': 'Bearer ' + old_session}).status_code == 401
        assert client.post('/api/v1/auth/login', json=credentials, headers=headers).status_code == 200
        assert client.get(route).json() == expected_job
        assert client.get(route + '/events').text == expected_events
        assert client.get(route + '/report').content == expected_pdf
        assert len(client.get('/api/scans').json()) == 1
