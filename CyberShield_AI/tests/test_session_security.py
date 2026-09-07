"""Real SQLite sessions and API boundaries; no authentication bypass fixtures."""
import hashlib
import os
import sqlite3
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import server
from services.scan_store import ScanStore
from utils import auth_manager as auth

PASSWORD = 'Test-operator-password-2026'
BROWSER = {'Origin': 'http://localhost:3000', 'X-CyberShield-Request': '1'}


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Authentication uses its real database. Workers are not needed to test access.
    store = ScanStore(tmp_path / 'jobs.db')
    monkeypatch.setattr(server.app.state, 'scan_store', store, raising=False)
    with TestClient(server.app, base_url='http://localhost:3000') as client:
        yield client


def login(client, **overrides):
    data = {'email': 'operator@cybershield.ai', 'password': PASSWORD, **overrides}
    return client.post('/api/v1/auth/login', json=data, headers=BROWSER)


def token():
    return auth.create_token('usr_operator', 'operator@cybershield.ai', 'operator')


def test_no_default_accounts_or_passwords(monkeypatch):
    monkeypatch.delenv('CYBERSHIELD_ADMIN_PASSWORD')
    monkeypatch.delenv('CYBERSHIELD_OPERATOR_PASSWORD')
    assert auth.authenticate_user('admin@cybershield.ai', 'admin123') is None
    assert auth.authenticate_user('operator@cybershield.ai', 'operator123') is None
    with pytest.raises(ValueError, match='unconfigured'):
        token()


def test_weak_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv('CYBERSHIELD_OPERATOR_PASSWORD', 'operator123')
    with pytest.raises(ValueError, match='12 to 256'):
        auth.initialize_auth()


def test_password_hashes_are_salted_and_session_secrets_are_not_stored(monkeypatch):
    monkeypatch.setenv('CYBERSHIELD_ADMIN_PASSWORD', PASSWORD)
    issued = token()
    with sqlite3.connect(os.environ['CYBERSHIELD_AUTH_DB']) as db:
        hashes = [row[0] for row in db.execute('SELECT password_hash FROM users')]
        digest, = db.execute('SELECT digest FROM sessions').fetchone()
    assert len(set(hashes)) == 2
    assert all(h.startswith('pbkdf2_sha256$600000$') and PASSWORD not in h for h in hashes)
    assert digest == hashlib.sha256(issued.encode()).hexdigest() and digest != issued
    assert os.stat(os.environ['CYBERSHIELD_AUTH_DB']).st_mode & 0o777 == 0o600


def test_sessions_survive_reinitialization_and_revocation_persists():
    issued = token()
    auth._configured.clear()  # Simulate a fresh API process initialization.
    assert auth.verify_token(issued).email == 'operator@cybershield.ai'
    auth.revoke_token(issued)
    auth._configured.clear()
    assert auth.verify_token(issued) is None


def test_exact_expiration_boundary(monkeypatch):
    now = 1_000_000.0
    monkeypatch.setattr(auth.time, 'time', lambda: now)
    issued = token()
    now += auth.SESSION_SECONDS - 1
    assert auth.verify_token(issued) is not None
    now += 1
    assert auth.verify_token(issued) is None


@pytest.mark.parametrize('new_password', ['', 'Rotated-operator-password-2026'])
def test_credential_removal_and_rotation_revoke_sessions(monkeypatch, new_password):
    issued = token()
    monkeypatch.setenv('CYBERSHIELD_OPERATOR_PASSWORD', new_password)
    assert auth.verify_token(issued) is None
    assert auth.authenticate_user('operator@cybershield.ai', PASSWORD) is None


def test_session_count_is_bounded():
    issued = [token() for _ in range(21)]
    assert auth.verify_token(issued[0]) is None
    assert auth.verify_token(issued[-1]) is not None
    with sqlite3.connect(os.environ['CYBERSHIELD_AUTH_DB']) as db:
        assert db.execute('SELECT count(*) FROM sessions').fetchone()[0] == 20


def test_browser_cookie_login_logout_and_tokenless_json(client):
    response = login(client)
    assert response.status_code == 200
    assert 'token' not in response.json()
    cookie = response.headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'samesite=strict' in cookie and 'path=/api' in cookie
    assert response.headers['cache-control'] == 'no-store'
    issued = client.cookies.get(auth.COOKIE_NAME)
    assert client.get('/api/v1/auth/me').status_code == 200
    assert client.post('/api/v1/auth/logout', headers=BROWSER).status_code == 200
    assert client.get('/api/v1/auth/me').status_code == 401
    assert auth.verify_token(issued) is None


def test_secure_cookie_is_deployment_default(client, monkeypatch):
    monkeypatch.delenv('CYBERSHIELD_COOKIE_SECURE')
    response = login(client)
    assert '; secure' in response.headers['set-cookie'].lower()


@pytest.mark.parametrize('headers', [{}, {'Origin': 'http://localhost:3000'},
    {'Origin': 'https://evil.invalid', 'X-CyberShield-Request': '1'}])
def test_cookie_login_requires_origin_and_csrf_header(client, headers):
    response = client.post('/api/v1/auth/login', json={'email': 'operator@cybershield.ai', 'password': PASSWORD}, headers=headers)
    assert response.status_code == 403
    assert auth.COOKIE_NAME not in client.cookies


def test_cookie_mutations_reject_missing_or_foreign_origin(client):
    assert login(client).status_code == 200
    for headers in ({}, {'Origin': 'https://evil.invalid', 'X-CyberShield-Request': '1'}):
        assert client.post('/api/v1/auth/logout', headers=headers).status_code == 403
    assert client.get('/api/v1/auth/me').status_code == 200


def test_invalid_header_and_query_never_fall_back_to_cookie(client):
    assert login(client).status_code == 200
    for header in ('Bearer invalid', 'Basic anything'):
        assert client.get('/api/scans', headers={'Authorization': header}).status_code == 401
    issued = client.cookies.get(auth.COOKIE_NAME)
    assert client.get('/api/scans', params={'token': issued}).status_code == 401


def test_explicit_bearer_delivery_and_anonymous_denial(client, monkeypatch):
    monkeypatch.setenv('CYBERSHIELD_REQUIRE_AUTH', 'false')
    assert client.get('/api/scans').status_code == 401
    result = login(client, delivery='bearer')
    assert result.status_code == 200
    assert auth.COOKIE_NAME not in client.cookies
    headers = {'Authorization': 'Bearer ' + result.json()['token']}
    assert client.get('/api/scans', headers=headers).status_code == 200
    assert client.post('/api/v1/auth/logout', headers=headers).status_code == 200
    assert client.get('/api/scans', headers=headers).status_code == 401


def test_login_limit_persists_and_expires(client, monkeypatch):
    now = 1_000_000.0
    monkeypatch.setattr(auth.time, 'time', lambda: now)
    for _ in range(5):
        assert login(client, password='wrong-password').status_code == 401
    auth._configured.clear()
    response = login(client)
    assert response.status_code == 429 and response.headers['retry-after'] == '60'
    now += 60
    assert login(client).status_code == 200


def test_operator_cannot_read_cancel_stream_or_download_another_owners_scan(client, monkeypatch, tmp_path):
    store = client.app.state.scan_store
    job = store.create_scan({'domain': 'example.invalid'}, owner='admin@cybershield.ai')
    pdf = tmp_path / 'admin.pdf'
    pdf.write_bytes(b'%PDF-test')
    monkeypatch.setattr(server, 'REPORTS_DIR', str(tmp_path))
    store.update_scan(job['id'], 'running')
    store.update_scan(job['id'], 'completed', result={'pdf_path': 'admin.pdf'})
    assert login(client).status_code == 200
    assert client.get('/api/scans').json() == []
    for suffix in ('', '/events', '/report'):
        assert client.get(f"/api/scans/{job['id']}{suffix}").status_code == 404
    assert client.post(f"/api/scans/{job['id']}/cancel", headers=BROWSER).status_code == 404
    assert client.get('/api/reports/download?filename=admin.pdf').status_code == 403


@pytest.mark.asyncio
async def test_open_event_stream_stops_after_logout(tmp_path):
    issued = token()
    store = ScanStore(tmp_path / 'stream.db')
    job = store.create_scan({'domain': 'example.invalid'}, owner='operator@cybershield.ai')
    request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'query_string': b'',
                       'headers': [(b'authorization', f'Bearer {issued}'.encode())]})
    request.is_disconnected = AsyncMock(return_value=False)
    response = await server.scan_events(job['id'], request, 0, 'operator@cybershield.ai', store)
    iterator = response.body_iterator
    first = await anext(iterator)
    assert 'AUTH_REQUIRED' not in first
    auth.revoke_token(issued)
    next_event = await anext(iterator)
    assert 'AUTH_REQUIRED' in next_event
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_reauthentication_rotates_cookie_session(client):
    assert login(client).status_code == 200
    old = client.cookies.get(auth.COOKIE_NAME)
    assert login(client, email='admin@cybershield.ai', password='Test-admin-password-2026').status_code == 200
    assert client.cookies.get(auth.COOKIE_NAME) != old
    assert auth.verify_token(old) is None
    assert client.get('/api/v1/auth/me').json()['role'] == 'admin'


def test_static_api_credential_is_operator_and_requires_configuration_rotation(client, monkeypatch):
    monkeypatch.setenv('CYBERSHIELD_API_TOKEN', 'test-static-operator-credential')
    headers = {'Authorization': 'Bearer test-static-operator-credential'}
    assert client.get('/api/v1/auth/me', headers=headers).json()['role'] == 'operator'
    assert client.post('/api/v1/auth/logout', headers=headers).status_code == 400
    monkeypatch.delenv('CYBERSHIELD_API_TOKEN')
    assert client.get('/api/scans', headers=headers).status_code == 401


def test_mounted_password_secret_and_rotation(tmp_path, monkeypatch):
    secret = tmp_path / 'operator-password'
    secret.write_text(PASSWORD + '\n')
    monkeypatch.delenv('CYBERSHIELD_OPERATOR_PASSWORD')
    monkeypatch.setenv('CYBERSHIELD_OPERATOR_PASSWORD_FILE', str(secret))
    assert auth.authenticate_user('operator@cybershield.ai', PASSWORD) is not None
    issued = token()
    secret.write_text('Rotated-secret-password-2026\n')
    assert auth.verify_token(issued) is None
    assert auth.authenticate_user('operator@cybershield.ai', 'Rotated-secret-password-2026') is not None


def test_password_source_conflict_fails_closed(tmp_path, monkeypatch):
    secret = tmp_path / 'secret'
    secret.write_text(PASSWORD)
    monkeypatch.setenv('CYBERSHIELD_OPERATOR_PASSWORD_FILE', str(secret))
    with pytest.raises(ValueError, match='not both'):
        auth.initialize_auth()


@pytest.mark.parametrize('contents', ['', 'short', 'x' * 300, 'x' * 256 + '\r\ntrailing'])
def test_invalid_password_secret_fails_startup(tmp_path, monkeypatch, contents):
    secret = tmp_path / 'secret'
    secret.write_text(contents)
    monkeypatch.delenv('CYBERSHIELD_OPERATOR_PASSWORD')
    monkeypatch.setenv('CYBERSHIELD_OPERATOR_PASSWORD_FILE', str(secret))
    with pytest.raises(ValueError, match='12 to 256'):
        auth.initialize_auth()
