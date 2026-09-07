# Authentication and browser sessions

All scan, history, event-stream and report routes require authentication, including
loopback requests. `CYBERSHIELD_REQUIRE_AUTH=false` does not enable anonymous
access. Health and login remain public. Administrator sessions may access all
scans; operators can access only scans owned by `operator@cybershield.ai`.

## Configure accounts

Set `CYBERSHIELD_OPERATOR_PASSWORD` and/or `CYBERSHIELD_ADMIN_PASSWORD` to a unique
password of 12–256 characters. Account emails are `operator@cybershield.ai` and
`admin@cybershield.ai`. There are no built-in passwords. Unset accounts are disabled;
weak configured passwords stop startup. The local launcher prompts privately for
an operator password when neither account is configured and stdin is a terminal.
Noninteractive startup requires an explicitly configured password.

Passwords are stored as independently salted PBKDF2-HMAC-SHA256 hashes with 600,000
iterations, following the [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Use deployment secret management for the configuration variables. Do not commit
passwords, environment files, or databases.

The backend also accepts `CYBERSHIELD_OPERATOR_PASSWORD_FILE` and
`CYBERSHIELD_ADMIN_PASSWORD_FILE`. A file must be readable by the runtime user and
contain 12–256 password characters (a trailing newline is allowed). Configuring
both the value and file for one account fails startup. File password rotation
revokes prior sessions when the backend synchronizes configuration. Compose
mounts the operator secret read-only; password contents are not image layers or
container environment values. Keep the host secret directory private.

## Sessions and browser requests

Browser login uses `POST /api/v1/auth/login` with JSON `email` and `password`.
The response contains identity, not a token. It sets the `cybershield_session`
HttpOnly, SameSite=Strict cookie scoped to `/api`. Secure is enabled by default;
the loopback HTTP launcher and local Compose demo explicitly set `CYBERSHIELD_COOKIE_SECURE=false`.
HTTPS deployments must retain Secure cookies.

Sessions are opaque random 256-bit credentials. Only their SHA-256 digests are
stored in SQLite. The database defaults to `auth.sqlite3` beside `CYBERSHIELD_DB`;
`CYBERSHIELD_AUTH_DB` selects another path. New auth files are created mode 0600.
Keep this database on a persistent private volume alongside the scan database.
Sessions survive an API restart, expire absolutely after eight hours, and are
limited to 20 per account (oldest evicted). There is no idle-expiry timer yet.
Removing or changing an account password revokes its existing sessions when the
API initializes/synchronizes that configuration. Restart the API after changing
deployment environment variables.

Cookie login and state-changing cookie requests require an exact allowed Origin
from `CYBERSHIELD_ORIGINS` and `X-CyberShield-Request: 1`. Do not configure wildcard
origins. API responses use `Cache-Control: no-store`. The dashboard clears legacy
localStorage tokens; identity is restored through `/api/v1/auth/me`. SSE and PDF
URLs never contain credentials. Logout deletes the server session, clears the
cookie and clears visible private dashboard state. Open event streams recheck
revocation/expiry before every event batch. Invalid Authorization headers cannot
fall back to a browser cookie. See [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## Command-line clients and rate limits

A non-browser client may explicitly request `delivery: "bearer"` during login to
receive an opaque token, then send `Authorization: Bearer ...`. URL query tokens
are rejected on every protected endpoint. A configured `CYBERSHIELD_API_TOKEN`
continues to authenticate as an operator via the Authorization header only; it
cannot grant administrator access. Static API tokens must be rotated in deployment
configuration, and `/auth/logout` rejects static-token logout rather than claiming
that a nonrevocable credential has been revoked.

Login attempts are limited atomically in SQLite to five per normalized account
and thirty per immediate peer address per 60 seconds, including successful logins.
Limits persist across API restarts; rejection returns 429 and `Retry-After: 60`.
Behind the dashboard proxy, peer limits are shared by users of that proxy. These
limits are a local baseline, not a distributed abuse-prevention service.

## Verification and release boundary

`tests/test_session_security.py` exercises real SQLite storage, expiry, credential
rotation, cookies, CSRF, URL-token rejection, rate limiting, ownership and revocation
of an already-open event stream. API test fixtures configure test-only passwords
and temporary databases; production authentication is never bypassed for tests.

This release still targets one API process and a local/team deployment. SSO/MFA,
account provisioning beyond the two configured roles, idle session expiry,
deployment TLS/recovery and a complete production acceptance matrix are separate
work. Session hardening alone does not establish public multi-tenant readiness.
