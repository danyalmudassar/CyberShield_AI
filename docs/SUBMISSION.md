# CyberShield submission guide

## What to demonstrate

CyberShield provides an authenticated security-assessment dashboard, explicit
live/rules-only/demo modes, persistent scan history, streamed progress, evidence
provenance, a project-defined technical control matrix and PDF reports. The tested
submission path uses fixture-only Demo mode and requires no model API key.

## Start locally

From the repository root, with Python 3.12 and Node.js 22:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r backend/requirements.txt
npm --prefix frontend ci
.venv/bin/python run_local.py
```

The launcher privately prompts for an operator password of 12–256 characters.
Open http://127.0.0.1:3000 and sign in as `operator@cybershield.ai`. Use the password
you configured; no default account password is enabled. For alternate occupied
ports, add `--api-port 8100 --ui-port 3100` to the launcher and open port 3100.
The [container guide](container-release.md) provides the verified Docker alternative.

## Three-minute walkthrough

1. Open `/login`; sign in or use **Create an account** to register an operator, then show the workspace.
2. Keep **Demo** selected, confirm authorization and select **Start demo assessment**.
3. Show assessment activity and evidence/status distinctions, then open **Reports**.
4. Select **Download PDF**; return to **Overview** and reopen the scan from **Recent assessments**.
5. Log out and explain that report/history access requires authentication.

Label the demonstration as fixture-only. `rules_only` is network-active and skips
AI; it is not offline. Only run live checks against explicitly authorized targets.

## Evidence you can cite

- Hosted backend/frontend workflow results are linked in [CI release evidence](hosted-ci-release.md).
- Actual container login, demo, PDF and restart recovery are recorded in
  [container-release.md](container-release.md).
- Backup/restore restored three completed scans with matching events/PDF bytes;
  historical sessions were revoked. See [backup-restore.md](backup-restore.md).
- The local DVWA/Juice Shop smoke ran only cookie-header and directory-listing
  checks, plus one verified DVWA fixture login. It is not a full scanner benchmark.
  DVWA exposed a directory listing; Juice Shop did not on the checked paths.

## Be precise about limitations

Do not present historical 92.3% recall as a fresh result, or the technical control
matrix as certification/full authoritative compliance. All 24 active checks,
authenticated SPA/JWT scanning and cross-application recall are not fully validated.
Public production deployment still needs TLS, independent encrypted backups,
retention and operational alerting. The submitted local demo and CI verification
are the established release boundary.

Do not upload `.env` files, `.release-secrets`, runtime databases, generated private
reports, virtual environments or node_modules. Submit the repository/source archive
and the verification links, not local credentials.

The redesigned login/dashboard screenshots and browser verification are in [UI redesign](ui-redesign.md).
