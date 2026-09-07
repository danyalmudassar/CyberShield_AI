# Local container release

This release path is a fixture-only local demonstration. It does not authorize or
perform external target scans. Use Docker Compose v2+ with Linux containers.
The verified host uses Docker 29.6.1 / Compose 5.3.1 and x86-64 Linux.

## Configure and start

From the project root in Bash, create a private directory and a unique operator
password (12–256 characters). The file is readable inside the container by UID
10001; the enclosing host directory is accessible only to your account. Do not
put the secret in either backend/frontend build context or version control.

```bash
mkdir -p .release-secrets
chmod 700 .release-secrets
read -rsp 'Operator password: ' CYBERSHIELD_OPERATOR_PASSWORD
printf '%s' "$CYBERSHIELD_OPERATOR_PASSWORD" > .release-secrets/operator_password
chmod 644 .release-secrets/operator_password
unset CYBERSHIELD_OPERATOR_PASSWORD
export CYBERSHIELD_OPERATOR_PASSWORD_FILE="$PWD/.release-secrets/operator_password"
docker compose up --build -d --wait
```

Open http://127.0.0.1:3300 and sign in as `operator@cybershield.ai`. Select Demo and
confirm authorization. `CYBERSHIELD_UI_PORT` selects another loopback port. The
secret path must be visible to the Docker daemon; some packaged Docker installs
use a private `/tmp`, so keep it in the project directory as above. Changing the
password file requires backend recreation to reliably replace a bind mount.

```bash
docker compose up -d --force-recreate backend
docker compose down
```

`down` stops this Compose project and preserves named data/report volumes. Do not
use `down -v` unless you intentionally want to delete its databases and reports.
Keep the same project name and secret to recover the same deployment. Health checks
verify worker/database readiness through `/api/ready`, not every scanner or
report-generation capability. An unhealthy container is reported but not
automatically restarted by this Compose configuration.

## Packaging and boundaries

- Backend: Python 3.12, runtime-only hash lock, one Uvicorn API process, UID 10001.
- Dashboard: Node 22, `npm ci`, Next.js standalone production output, UID 1000.
  The backend rewrite address is set during the image build, defaulting to
  `http://backend:8000`; changing only a runtime variable does not rebuild rewrites.
- Both base images use explicit registry digests. Both services have read-only root
  filesystems, dropped Linux capabilities, bounded memory/CPU/PIDs and a 64 MiB
  temporary directory. Docker init forwards signals and reaps child processes.
- The backend has no published port and is attached only to an internal network.
  The frontend also has a bridge network for its loopback published port; frontend
  egress is not blocked. This is not a general infrastructure egress guarantee.
- Backend limits: 1 GiB, 2 CPUs, 128 PIDs; frontend: 512 MiB, 1 CPU, 64 PIDs.
  Scan and auth databases share a persistent data volume; PDFs have their own volume.
- This HTTP demo explicitly disables Secure cookies. Public deployment requires
  TLS, Secure cookies, trusted origins, secret provisioning and backup/recovery
  acceptance. No remote registry publication or public deployment is performed.
- `no-new-privileges` is not enabled in this portable local configuration: the
  verified host rejects executable startup with that option. A deployment using
  it must first validate compatibility with its container runtime/security profile.

## Dependency maintenance

`CyberShield_AI/requirements.in` contains direct application/development pins.
`requirements.txt` locks all 74 resolved packages with SHA-256 hashes.
`requirements-runtime.in` omits legacy Gradio and test/browser dependencies;
`requirements-runtime.txt` locks its 39 packages to versions in the full lock.
The runtime image intentionally does not include the legacy Gradio entry point.

Regenerate with uv 0.8.22 from `CyberShield_AI/`, then inspect changes and perform
fresh installation/tests. Do not hand-edit generated locks.

```bash
uv pip compile requirements.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --no-emit-index-url --output-file requirements.txt --quiet
uv pip compile requirements-runtime.in --constraint requirements.txt --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --no-emit-index-url --output-file requirements-runtime.txt --quiet
python3.12 -m venv /tmp/cybershield-fresh
/tmp/cybershield-fresh/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
/tmp/cybershield-fresh/bin/python -m pip check
/tmp/cybershield-fresh/bin/python -m pytest tests/ -q
```

Hash verification ensures the selected package artifacts match the lock; it is
not a vulnerability audit. Updates require new locks, rebuilt images and tests.
The frontend uses its existing `package-lock.json`. CI now installs hashed Python
requirements, runs `pip check`, and builds the backend/frontend images; execution
of those updated hosted workflows remains a separate check.

## Local acceptance evidence — 2026-09-07

Both images built successfully, including `npm ci` and the Next.js production
build. A fresh Python virtual environment installed the full hash lock and passed
`pip check`. Runtime inspection confirmed non-root service users, read-only roots,
dropped capabilities, memory/PID quotas, no backend published port and an internal
backend network.

Actual API acceptance through the containerized dashboard verified anonymous 401,
configured cookie login, one completed demo, valid PDF bytes and exactly one
terminal SSE event. Forcing backend container recreation preserved the same
session, result, PDF bytes and exact event replay through the named volumes.

Real Chromium acceptance passed all six grouped checks with zero page errors:
anonymous launch prevention; configured login/HttpOnly session; demo/SSE without
URL tokens; PDF button/download; refresh recovery; CSRF protection and revoking
logout. Reproduction script: `CyberShield_AI/scripts/verify_session_browser.py`,
using `CYBERSHIELD_BROWSER_URL=http://127.0.0.1:3300` and an explicitly supplied
`CYBERSHIELD_BROWSER_PASSWORD`. Temporary results/screenshots:
`/tmp/cybershield-container-acceptance/`. Tests used project
`cybershield-release-check`; unrelated existing containers/services were untouched.

Final fresh-environment suite: **326 passed**, 1 integration test deselected,
2 dependency deprecation warnings in 105.48s. The final backend rebuild repeated
API/recreation acceptance successfully (9175-byte PDF). `git diff --check` passed
in both repositories. Verification containers were stopped without deleting their
volumes; missing secret-path configuration was confirmed to fail closed.

## Backup and recovery

The runtime includes `python -m services.backup` and a volume-ready `/app/backups`
directory. See the [backup/restore runbook](backup-restore.md) for offline snapshots,
integrity checks, session revocation and the separate `compose.restore.yaml`
deployment. The snapshot must remain private and have an independent off-host copy.
