# Contributing to CyberShield

## Repository layout

- `CyberShield_AI/`: FastAPI API, agents, transports, persistent jobs and Python tests.
- `frontend/`: Next.js App Router UI, login/signup and assessment workspace.
- `deploy/cloud/`: HTTPS gateway and private ECS configuration helper.
- `docs/`: deployment, recovery, verification and submission guides.
- `.github/workflows/`: required automated backend/frontend checks.

## Development

Use Python 3.12 and Node.js 22. Follow the root README to install the hash-locked
Python dependencies and `npm ci` frontend dependencies. Never commit passwords,
API keys, session tokens, private reports or runtime databases.

Create a focused feature/fix branch. Preserve execution mode and provenance
contracts: demo is offline; rules-only permits authorized network probes but no
AI calls; failed live checks must not substitute fixtures. Registered users must
never gain administrator privileges or access another user's scan/report.

## Before opening a pull request

```bash
cd CyberShield_AI
python -m pytest -q
cd ../frontend
npx tsc --noEmit
npm run build
cd ..
python -m unittest discover -s deploy/cloud -p 'test_*.py' -v
```

Use real browser checks for UI changes: desktop/mobile layouts, keyboard access,
signup/login, errors, demo scan progress, report download and logout. Use fixture
mode or explicitly authorized local labs. Do not scan unrelated public targets.

Explain the user-visible problem, resulting behavior and verification in the PR.
Attach sanitized screenshots when the UI changes. Backend/frontend CI checks must
pass before merging; do not weaken tests just to make the checks pass.

## Reporting problems

Use the issue templates for reproducible non-sensitive bugs and feature requests.
Do not disclose credentials, private reports or exploitable vulnerability details
in public issues. Arrange a private disclosure channel with the repository owner
before sharing sensitive details. No bounty or response SLA is implied.
