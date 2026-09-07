import os
import sqlite3

import pytest
from fastapi.testclient import TestClient
import server
from utils import auth_manager as auth

PASSWORD = 'New-account-password-2026'
HEADERS = {'Origin': 'http://localhost:3000', 'X-CyberShield-Request': '1'}

@pytest.fixture
def client():
    with TestClient(server.app, base_url='http://localhost:3000') as client:
        yield client

def register(client, email='analyst@example.com', **extra):
    return client.post('/api/v1/auth/register', headers=HEADERS,
                       json={'email': email, 'password': PASSWORD, **extra})

def test_register_creates_operator_with_private_session_and_hash(client):
    response = register(client, 'Analyst@Example.com')
    assert response.status_code == 201
    assert response.json()['role'] == 'operator'
    assert response.json()['email'] == 'analyst@example.com'
    assert 'token' not in response.json()
    assert 'HttpOnly' in response.headers['set-cookie']
    assert client.get('/api/v1/auth/me').json()['email'] == 'analyst@example.com'
    with sqlite3.connect(os.environ['CYBERSHIELD_AUTH_DB']) as conn:
        encoded, = conn.execute('SELECT password_hash FROM users WHERE email=?', ('analyst@example.com',)).fetchone()
    assert encoded.startswith('pbkdf2_sha256$600000$') and PASSWORD not in encoded

def test_duplicate_email_cannot_replace_password(client):
    assert register(client).status_code == 201
    assert register(client, 'ANALYST@example.com').status_code == 409
    assert auth.authenticate_user('analyst@example.com', PASSWORD)

@pytest.mark.parametrize('email', ['admin@cybershield.ai', 'operator@cybershield.ai'])
def test_bootstrap_identities_are_reserved(client, email):
    assert register(client, email).status_code == 409

def test_role_injection_is_rejected(client):
    assert register(client, role='admin').status_code == 422

@pytest.mark.parametrize('email', ['invalid', 'a@b', 'a..b@example.com'])
def test_invalid_email_is_rejected(client, email):
    assert register(client, email).status_code == 422

def test_short_password_is_rejected(client):
    response = client.post('/api/v1/auth/register', headers=HEADERS, json={'email':'a@example.com','password':'short'})
    assert response.status_code == 422

def test_registration_requires_trusted_origin(client):
    response = client.post('/api/v1/auth/register', headers={'Origin':'https://evil.invalid'}, json={'email':'a@example.com','password':PASSWORD})
    assert response.status_code == 403

def test_registered_account_survives_initialization_and_can_login(client):
    assert register(client).status_code == 201
    assert client.post('/api/v1/auth/logout', headers=HEADERS).status_code == 200
    auth._configured.clear()
    auth.initialize_auth()
    response = client.post('/api/v1/auth/login', headers=HEADERS, json={'email':'analyst@example.com','password':PASSWORD})
    assert response.status_code == 200

def test_registered_users_have_separate_history(client):
    assert register(client, 'one@example.com').status_code == 201
    store = server.app.state.scan_store
    job = store.create_scan({'domain':'example.com','execution_mode':'demo'}, owner='one@example.com')
    assert register(client, 'two@example.com').status_code == 201
    assert client.get('/api/scans').json() == []
    assert client.get('/api/scans/'+job['id']).status_code in (403,404)

def test_registration_can_be_disabled(client, monkeypatch):
    monkeypatch.setenv('CYBERSHIELD_ALLOW_SIGNUP','false')
    assert register(client).status_code == 403

def test_registration_is_rate_limited(client):
    for _ in range(5):
        register(client)
    assert register(client).status_code == 429
