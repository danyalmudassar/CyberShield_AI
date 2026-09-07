"""Configured credentials and persistent, revocable opaque sessions.

No default accounts/passwords are enabled. Passwords use salted PBKDF2-SHA256;
only session-token digests are stored. Browser sessions use HttpOnly cookies.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import re
import sqlite3
import threading
import time

from fastapi import HTTPException, Request

COOKIE_NAME = 'cybershield_session'
PASSWORD_ITERATIONS = 600_000
SESSION_SECONDS = 8 * 60 * 60
_config_lock = threading.Lock()
_configured = {}


@dataclass(frozen=True)
class UserIdentity:
    user_id: str
    email: str
    role: str
    issued_at: float
    expires_at: float = 0.0


def _hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), PASSWORD_ITERATIONS).hex()
    return f'pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest}'


def _verify_password(password, encoded):
    try:
        algorithm, count, salt, digest = encoded.split('$')
        if algorithm != 'pbkdf2_sha256' or int(count) != PASSWORD_ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(count)).hex()
        return hmac.compare_digest(actual, digest)
    except (ValueError, TypeError):
        return False


@contextmanager
def _database():
    scan_db = os.getenv('CYBERSHIELD_DB', str(Path(__file__).resolve().parents[1] / 'data' / 'scans.sqlite3'))
    path = Path(os.getenv('CYBERSHIELD_AUTH_DB', str(Path(scan_db).with_name('auth.sqlite3'))))
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create privately from the outset, without changing the process umask.
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys=ON')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
                password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS sessions (
                digest TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                issued_at REAL NOT NULL, expires_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS session_user ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS login_limits (
                bucket TEXT PRIMARY KEY, started REAL NOT NULL, attempts INTEGER NOT NULL);
        ''')
        with conn:
            yield conn, str(path)
    finally:
        conn.close()


def _configured_password(role):
    name = f'CYBERSHIELD_{role.upper()}_PASSWORD'
    value, filename = os.getenv(name, ''), os.getenv(name + '_FILE', '')
    if not filename:
        return value
    if value:
        raise ValueError('Configure a password value or a password file, not both')
    try:
        with open(filename, encoding='utf-8') as secret:
            value = secret.read(259)
    except (OSError, UnicodeError) as exc:
        raise ValueError('Could not read configured password secret file') from exc
    if len(value) > 258:
        raise ValueError('Password secret files must contain 12 to 256 characters')
    value = value.rstrip('\r\n')
    if not 12 <= len(value) <= 256:
        raise ValueError('Password secret files must contain 12 to 256 characters')
    return value


def initialize_auth():
    """Synchronize explicitly configured accounts; rotation revokes sessions."""
    credentials = [(f'usr_{role}', f'{role}@cybershield.ai', role,
                    _configured_password(role))
                   for role in ('admin', 'operator')]
    for _, _, _, password in credentials:
        if password and not 12 <= len(password) <= 256:
            raise ValueError('Configured account passwords must contain 12 to 256 characters')
    fingerprint = hashlib.sha256(repr(credentials).encode()).digest()
    with _config_lock, _database() as (conn, path):
        # Include inode so replacing/deleting a test or deployment DB reinitializes it.
        key = (path, os.stat(path).st_ino)
        if _configured.get(key) == fingerprint:
            return
        for user_id, email, role, password in credentials:
            row = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
            if not password:
                conn.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
                conn.execute('UPDATE users SET enabled=0 WHERE id=?', (user_id,))
                continue
            if row and row['enabled'] and _verify_password(password, row['password_hash']):
                continue
            conn.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            conn.execute('''INSERT INTO users VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash, enabled=1''',
                         (user_id, email, role, _hash_password(password)))
        _configured[key] = fingerprint


def register_user(email, password):
    """Create an operator account; reserved bootstrap identities cannot be claimed."""
    if os.getenv('CYBERSHIELD_ALLOW_SIGNUP', 'true').lower() not in ('true', '1'):
        raise HTTPException(403, 'Registration is disabled. Contact the workspace administrator.')
    email = email.strip().lower()
    local, separator, domain = email.partition('@')
    if (not separator or len(email) > 254 or len(local) > 64
            or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)
            or local.startswith('.') or local.endswith('.') or '..' in local
            or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', domain)):
        raise HTTPException(422, 'Enter a valid email address.')
    if not 12 <= len(password) <= 256:
        raise HTTPException(422, 'Use a password containing 12 to 256 characters.')
    if email in ('admin@cybershield.ai', 'operator@cybershield.ai'):
        raise HTTPException(409, 'This email is unavailable. Sign in or use another email.')
    initialize_auth()
    user_id = 'usr_' + secrets.token_hex(16)
    encoded = _hash_password(password)
    try:
        with _database() as (conn, _):
            conn.execute('INSERT INTO users (id,email,role,password_hash,enabled) VALUES (?,?,?,?,1)',
                         (user_id, email, 'operator', encoded))
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'This email is unavailable. Sign in or use another email.') from None
    return UserIdentity(user_id, email, 'operator', time.time())


def authenticate_user(email, password):
    initialize_auth()
    with _database() as (conn, _):
        row = conn.execute('SELECT * FROM users WHERE email=? AND enabled=1', (email.strip().lower(),)).fetchone()
    if row is None:
        # Match the password KDF cost without creating a usable default account.
        hashlib.pbkdf2_hmac('sha256', password.encode(), b'unknown-account', PASSWORD_ITERATIONS)
        return None
    if not _verify_password(password, row['password_hash']):
        return None
    return UserIdentity(row['id'], row['email'], row['role'], time.time())


def create_token(user_id, email, role, expires_in=SESSION_SECONDS):
    initialize_auth()
    token, now = secrets.token_urlsafe(32), time.time()
    with _database() as (conn, _):
        user = conn.execute('SELECT * FROM users WHERE id=? AND enabled=1', (user_id,)).fetchone()
        if not user or user['email'] != email or user['role'] != role:
            raise ValueError('Cannot create a session for an unconfigured identity')
        conn.execute('DELETE FROM sessions WHERE expires_at<=?', (now,))
        # Keep per-account session storage bounded; oldest sessions are evicted.
        conn.execute('''DELETE FROM sessions WHERE digest IN (
            SELECT digest FROM sessions WHERE user_id=? ORDER BY issued_at DESC LIMIT -1 OFFSET 19)''', (user_id,))
        conn.execute('INSERT INTO sessions VALUES (?, ?, ?, ?)',
                     (hashlib.sha256(token.encode()).hexdigest(), user_id, now, now + min(expires_in, SESSION_SECONDS)))
    return token


def verify_token(token):
    if not isinstance(token, str) or not 20 <= len(token) <= 256:
        return None
    initialize_auth()
    now = time.time()
    with _database() as (conn, _):
        conn.execute('DELETE FROM sessions WHERE expires_at<=?', (now,))
        row = conn.execute('''SELECT u.id, u.email, u.role, s.issued_at, s.expires_at
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.digest=? AND u.enabled=1 AND s.expires_at>?''',
                           (hashlib.sha256(token.encode()).hexdigest(), now)).fetchone()
    return UserIdentity(row['id'], row['email'], row['role'], row['issued_at'], row['expires_at']) if row else None


def revoke_token(token):
    if not isinstance(token, str):
        return
    with _database() as (conn, _):
        conn.execute('DELETE FROM sessions WHERE digest=?', (hashlib.sha256(token.encode()).hexdigest(),))


def check_login_limit(email, peer):
    """Atomic per-account and peer limits, shared across API processes/restarts."""
    now = time.time()
    buckets = [(f'account:{email.strip().lower()}', 5), (f'peer:{peer}', 30)]
    with _database() as (conn, _):
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('DELETE FROM login_limits WHERE started<=?', (now - 60,))
        for value, limit in buckets:
            bucket = hashlib.sha256(value.encode()).hexdigest()
            row = conn.execute('SELECT attempts FROM login_limits WHERE bucket=?', (bucket,)).fetchone()
            if row and row['attempts'] >= limit:
                raise HTTPException(429, 'Too many login attempts. Try again shortly.', headers={'Retry-After': '60'})
        for value, _ in buckets:
            bucket = hashlib.sha256(value.encode()).hexdigest()
            conn.execute('''INSERT INTO login_limits VALUES (?, ?, 1)
                ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1''', (bucket, now))


def request_token(request):
    # An explicit invalid Authorization header never falls back to a cookie.
    header = request.headers.get('authorization')
    if header is not None:
        scheme, _, value = header.partition(' ')
        return value.strip() if scheme.lower() == 'bearer' else ''
    return request.cookies.get(COOKIE_NAME, '')


def get_current_user(request: Request):
    # URL tokens are intentionally unsupported, including SSE and PDF URLs.
    if request.query_params.get('token') is not None:
        return None
    token = request_token(request)
    if not token:
        return None
    api_token = os.getenv('CYBERSHIELD_API_TOKEN', '')
    if request.headers.get('authorization') and api_token and hmac.compare_digest(api_token.encode(), token.encode()):
        return UserIdentity('usr_operator_api', 'operator@cybershield.ai', 'operator', time.time())
    return verify_token(token)


def enforce_request_origin(request, *, browser_login=False):
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    allowed = {origin.strip() for origin in os.getenv('CYBERSHIELD_ORIGINS',
                'http://localhost:3000,http://127.0.0.1:3000').split(',')}
    origin = request.headers.get('origin')
    if origin is not None and origin not in allowed:
        raise HTTPException(403, 'Untrusted request origin')
    cookie_auth = bool(request.cookies.get(COOKIE_NAME)) and not request.headers.get('authorization')
    if browser_login or cookie_auth:
        if origin not in allowed or request.headers.get('x-cybershield-request') != '1':
            raise HTTPException(403, 'Browser request verification required')


def require_user(request: Request):
    user = get_current_user(request)
    if user is None:
        raise HTTPException(401, 'Authentication required')
    enforce_request_origin(request)
    return user
