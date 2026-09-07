# Local release verification

The backend and frontend are separate Git repositories. Each owns its own
`.github/workflows/ci.yml`; every workflow command runs from that repository's
root. Push, pull-request and manual workflow events run these checks. The jobs
have read-only repository permissions, a 15-minute timeout, and no deployment
step or provider credentials.

## Backend

Use Python 3.12. From the backend repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
python -m pytest -m 'not live and not integration'
```

CI uses the same install and pytest commands in a fresh Python 3.12 runner.
Dependency installation requires package-registry access. `requirements.txt` is
a complete transitive hash lock generated from `requirements.in`. The separate
`requirements-runtime.txt` omits legacy Gradio and test/browser tooling. Both target
Python 3.12/Linux; other platforms need their own validation. See
[container release instructions](../../docs/container-release.md) for regeneration
and clean-environment verification.

`pytest.ini` collects `tests/` and excludes `live` and `integration` markers.
The legacy `tests/test_pisf_agent.py` stub is explicitly ignored; assessment
regressions are in `tests/test_pisf_reachability.py`. This exclusion remains
visible in configuration rather than being added by CI.

For ordinary tests, the autouse fixture in `tests/conftest.py` blocks socket
connections, sends, and DNS resolution. It permits local Unix sockets needed by
asyncio, and releases the guard for tests explicitly marked `live` or
`integration`. Fixtures mock provider and target responses, while API tests can
exercise in-process requests and temporary SQLite databases. The socket guard
is a Python test fixture, not a network sandbox: subprocesses and unrelated
native transports are outside its coverage. CI does not opt into live-provider,
container, browser, or external-target tests and does not install browser
binaries.

## Frontend

Use Node.js 22. From the frontend repository root:

```bash
npm ci
npx --no-install tsc --noEmit
NEXT_TELEMETRY_DISABLED=1 npm run build
```

`npm ci` installs the checked-in lockfile. The type check uses the installed
TypeScript executable and cannot fetch a replacement through `npx`. The build
checks production compilation; it does not start the backend or execute a scan.
This workflow does not provide component tests, browser interaction tests, or
a deployment smoke test. Those require separately recorded verification.

## Recording evidence

Record the backend and frontend revisions together with command output and any
manual browser checks when preparing a release. A checked-in workflow does not
establish that hosted CI has run successfully. These files were prepared for
execution; no remote GitHub Actions run is claimed here. Branch protection and
required-check configuration must be set in repository settings separately.

Passing these checks establishes the covered offline behaviors and frontend
compilation. It does not establish production deployment readiness, live scan
accuracy, transport-level target isolation, or authenticated browser coverage.


## Target transport acceptance

The target transport tests exercise real request preparation, redirect processing,
scope propagation into a spawned stage, pinned socket destinations, and bounded
WHOIS referrals. Run the real loopback TLS test separately:

```bash
python -m pytest tests/test_transport_local.py -m integration -q
```

It starts only a temporary local TLS server and uses the installed `openssl`
command to generate a short-lived test certificate. No external provider or
target is contacted. See [target-scope-policy.md](target-scope-policy.md) for the
actual transport contract and deployment limitations.


## Authentication/session acceptance

```bash
python -m pytest tests/test_session_security.py -q
```

These tests exercise persistent session hashes, credential rotation, absolute
expiry, session limits, login rate limits, cookie/CSRF rules, ownership, and
revocation of an open SSE stream. Test-only configured accounts and databases
are isolated by an autouse fixture; no default deployment accounts are enabled.

Optional browser acceptance requires preinstalled Python Playwright and Chromium
and a dedicated fixture-only local instance. Set `CYBERSHIELD_BROWSER_PASSWORD`
through the environment to that instance's configured operator password, then run:

```bash
CYBERSHIELD_BROWSER_URL=http://127.0.0.1:3200 python scripts/verify_session_browser.py
```

`CYBERSHIELD_CHROMIUM` selects the installed browser executable (default
`/snap/bin/chromium`); `CYBERSHIELD_BROWSER_OUTPUT` selects the artifact directory.
The script creates one demo scan, tests the actual PDF button and logout, records
JSON results and screenshots, and never performs an external target scan. To run
a second dashboard beside an existing development instance, give it a separate
`CYBERSHIELD_NEXT_DIST_DIR` inside the frontend directory as well as distinct ports.
