# Offline backup and recovery

This is a tested local recovery path for the current release on Linux/POSIX.
Stop every API process, worker and independent database/report writer before
creating a backup. The CLI requires `--offline` and holds the existing worker
ownership lock during export; that lock cannot exclude unrelated SQLite writers.
Do not copy an active SQLite main file alone: committed data may remain in WAL.
The CLI uses the [SQLite backup API](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup)
to create standalone database snapshots.

## What is included

A version-1 directory bundle contains `data/scans.sqlite3`, `data/auth.sqlite3`,
all top-level PDFs from the report directory, and `manifest.json` with SHA-256
hashes and sizes. Referenced PDFs must exist and begin with a PDF header. Database
integrity/foreign keys, required tables, file inventory and hashes are checked.
A missing report, corrupted bundle, unsafe file path or symlink stops publication.
Unreferenced top-level PDFs are retained; non-PDF regular files are not backed up.
Nested report directories are rejected rather than silently omitted.

Bundles are staged privately, flushed and published only after validation.
Destinations must not exist. Backup/restore never overwrites an existing deployment.
The source bundle stays unchanged during restore; the restored copy contains a
`restore.json` summary instead of a manifest whose hashes would no longer match.

Account password hashes and session digests are sensitive. Output directories are
0700 and files are 0600. Hashes detect accidental corruption, not malicious changes
to both data and manifest. Keep bundles in trusted encrypted storage with restricted
access. Encryption, external copies, scheduled retention and key management are
operator responsibilities; no automated pruning or off-host copying is implemented.
Deployment password files, environment values, source code and model credentials
are not included. Preserve the matching release and secret provisioning separately.

## Local filesystem commands

After stopping the application, from `backend/`:

```bash
python -m services.backup create --offline \
  --scan-db data/scans.sqlite3 --auth-db data/auth.sqlite3 --reports reports \
  --destination /secure/backups/cybershield-20260907
python -m services.backup verify /secure/backups/cybershield-20260907
python -m services.backup restore /secure/backups/cybershield-20260907 \
  --destination /secure/recovery/cybershield-20260907
```

Destination parent directories must already exist and be private. The CLI returns
nonzero on failure. Restore creates new `data/` and `reports/` directories under
the destination. Point a separate instance at these copies, or deploy them into
new volumes as below. Do not replace an active instance's files.

Restore deletes all saved sessions: operators must log in again. It cancels queued
jobs and interrupts running/cancelling jobs with persisted completion events.
Historical completed evidence/events remain unchanged. This prevents a stale backup
from launching previously queued scans without new authorization. Login limits and
accounts are preserved; configured passwords are still required at startup.

## Docker Compose backup

Use the same Compose project name as your deployment. The examples explicitly use
`cybershield`; substitute your actual project name throughout. Keep
`CYBERSHIELD_OPERATOR_PASSWORD_FILE` configured as described in
[container-release.md](container-release.md). Build the image containing the CLI,
then stop the backend before export. This creates downtime; the frontend may remain
running but API requests will fail until the backend starts again.

```bash
docker compose -p cybershield build backend
docker compose -p cybershield stop backend
export CYBERSHIELD_BACKUP_VOLUME=cybershield_backups
docker compose -p cybershield run --rm --no-deps \
  -v "$CYBERSHIELD_BACKUP_VOLUME:/app/backups" backend \
  python -m services.backup create --offline \
  --scan-db /app/data/scans.sqlite3 --auth-db /app/data/auth.sqlite3 \
  --reports /app/reports --destination /app/backups/snapshot-20260907
docker compose -p cybershield run --rm --no-deps \
  -v "$CYBERSHIELD_BACKUP_VOLUME:/app/backups" backend \
  python -m services.backup verify /app/backups/snapshot-20260907
docker compose -p cybershield up -d --wait backend
```

Choose a new snapshot name on every run. The named backup volume is local to this
Docker host; it does not protect against loss of that host. An independent,
encrypted off-host copy is required for disaster recovery.

## Restore into a separate Compose deployment

This requires Docker/Compose support for volume subpaths; the recorded drill used
Docker 29.6.1 and Compose 5.3.1. Restore into a new directory inside the backup
volume. The operation does not read or change the original deployment volumes.

```bash
export CYBERSHIELD_RESTORE_DIRECTORY=restored-20260907
docker compose -p cybershield run --rm --no-deps \
  -v "$CYBERSHIELD_BACKUP_VOLUME:/app/backups" backend \
  python -m services.backup restore /app/backups/snapshot-20260907 \
  --destination "/app/backups/$CYBERSHIELD_RESTORE_DIRECTORY"
export CYBERSHIELD_UI_PORT=3301
docker compose -p cybershield-recovered -f compose.yaml -f compose.restore.yaml \
  up --build -d --wait
```

The override mounts only the restored data/report subdirectories. Compose merges
volume declarations by their container target, so these replace the default mounts
rather than mounting both at one path. See [Compose merge rules](https://docs.docker.com/reference/compose-file/merge/#unique-resources).
Use a separate project and free loopback port. Never mount one restored database
into two API workers/deployments at once. Sign in at http://127.0.0.1:3301 with the
configured password, check history, replay events and download a known PDF before
cutover. Keep the original deployment/volumes for rollback until acceptance passes.
The restored deployment remains fixture-only, as specified by the base Compose file.

```bash
docker compose -p cybershield-recovered -f compose.yaml -f compose.restore.yaml down
```

Do not use `down -v` or prune volumes during recovery. The external backup volume
contains both the immutable snapshot and the writable restored instance. Preserve
a separate immutable copy before adopting the recovery instance for ongoing use.
There is no automatic cutover, scheduler, retention deletion or cross-version
schema migration in this release.

## Verification — 2026-09-07

- 13 backup regression/acceptance tests passed: offline acknowledgement, active
  worker exclusion, WAL content, interrupted publication, corruption/missing files,
  symlink/path rejection, existing destination preservation, session revocation,
  queued/running recovery and a real API login/history/SSE/PDF round trip.
- Full backend suite: **339 passed**, 1 integration test deselected, 2 dependency
  deprecation warnings in 105.76s.
- Actual container drill used the stopped previous demo's data/report volumes:
  exported and verified five files, restored into a new volume directory and
  revoked two historical sessions. A new backend serving restored volume subpaths
  verified all three completed scans, exact event payloads and PDF bytes after login.
- Both images built successfully for the separate Compose recovery deployment.
  Its loopback dashboard proxy passed configured login, all three historical PDF
  downloads and logout; mount inspection confirmed restored subpaths replaced
  original volumes. No frontend source changed and no fresh browser UI claim is made.
- Temporary drill scripts/logs are under `/tmp/cybershield-backup-*`; durable
  automated coverage is in `backend/tests/test_backup.py`.

These checks cover local backup/recovery. They do not establish off-host disaster
recovery, scheduled backup freshness, retention compliance or public deployment.

Verification containers were stopped after the drill. Original deployment volumes
and the separate drill backup/recovery volume were retained; unrelated running
services were untouched. Both repositories passed `git diff --check`.
