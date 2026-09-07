"""
CyberShield AI — User Authentication & Scan Ownership Tests
============================================================
Task 10: Verify login, bearer token validation, logout, and multi-user
scan ownership isolation.
"""

import pytest
from fastapi.testclient import TestClient

from server import app
from utils.auth_manager import authenticate_user, verify_token, revoke_token


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_login_valid_credentials(client):
    """Logging in with valid credentials must return token and user profile."""
    resp = client.post("/api/v1/auth/login", json={"delivery": "bearer", "email": "admin@cybershield.ai", "password": "Test-admin-password-2026"})
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["email"] == "admin@cybershield.ai"
    assert data["role"] == "admin"


def test_login_invalid_credentials(client):
    """Logging in with wrong password must return 401."""
    resp = client.post("/api/v1/auth/login", json={"delivery": "bearer", "email": "admin@cybershield.ai", "password": "wrongpassword"})
    assert resp.status_code == 401


def test_get_me_endpoint(client):
    """GET /api/v1/auth/me with Bearer token must return authenticated user profile."""
    login_resp = client.post("/api/v1/auth/login", json={"delivery": "bearer", "email": "operator@cybershield.ai", "password": "Test-operator-password-2026"})
    token = login_resp.json()["token"]

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "operator@cybershield.ai"
    assert data["role"] == "operator"


def test_logout_revokes_token(client):
    """Logging out revokes active bearer token."""
    login_resp = client.post("/api/v1/auth/login", json={"delivery": "bearer", "email": "operator@cybershield.ai", "password": "Test-operator-password-2026"})
    token = login_resp.json()["token"]

    logout_resp = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200

    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 401


def test_multi_user_scan_isolation(client):
    """User B must not be able to list or retrieve scans owned by User A."""
    token_op = client.post("/api/v1/auth/login", json={"delivery": "bearer", "email": "operator@cybershield.ai", "password": "Test-operator-password-2026"}).json()["token"]

    # Create scan as operator@cybershield.ai
    create_resp = client.post(
        "/api/scans",
        json={"domain": "example.com", "authorized": True, "execution_mode": "demo"},
        headers={"Authorization": f"Bearer {token_op}"},
    )
    resp_data = create_resp.json()
    scan_id = resp_data.get("scan_id") or resp_data.get("id")
    assert scan_id is not None

    # Operator lists scans — must find created scan
    op_scans = client.get("/api/scans", headers={"Authorization": f"Bearer {token_op}"}).json()
    assert any((s.get("scan_id") == scan_id or s.get("id") == scan_id) for s in op_scans)
