# Repository structure

CyberShield uses one Git repository for both services. Run Git commands from the project root; the backend and frontend are ordinary directories, not submodules or nested repositories.

| Location | Contents |
| --- | --- |
| `backend/` | FastAPI API, agents, models, persistence, Python tests and service Dockerfile |
| `frontend/` | Next.js routes, UI components, proxy handlers, assets and service Dockerfile |
| `deploy/cloud/` | HTTPS gateway and private server configuration helper |
| `deploy/monitor/` | Production health monitor and behavior tests |
| `docs/` | Shared setup, deployment, recovery and dated verification guides |
| `backend/docs/` | Backend authentication, assessment, scope and worker policies |
| `.github/` | Root workflows and contribution templates |
| `compose*.yaml` | Local, cloud and recovery deployment configurations |
| `run_local.py` | Coordinated local launcher |

## Local-only data

Runtime databases belong under `backend/data/` and generated reports under `backend/reports/`; both are ignored. Use `backend/config/.env` for local provider configuration, with placeholder names documented in the tracked `.env.example`. Never commit real secrets.

`artifacts/` holds local presentation exports and submission archives. `docs/local/` holds local session notes and draft design material. `.local/` holds migration backups, including the previous nested Git histories. These locations are intentionally ignored and are not required to clone, build or run the application.

## Common commands

From the root, install Python dependencies into `.venv` using `backend/requirements.txt`, run `npm --prefix frontend ci`, and start `.venv/bin/python run_local.py`. See the root README for password configuration and authorized live mode.

Run backend tests from `backend/` with the configured Python environment. Build the frontend with `npm --prefix frontend run build`. CI lives only in `.github/workflows/` and uses these same service roots.

## Migration note

The former `CyberShield_AI/` service directory is now `backend/`. The GitHub repository URL remains unchanged. Update local scripts and IDE working directories to the new path. Railway must use `/backend` for the backend service and `/frontend` for the frontend, with `Dockerfile` relative to each root. Existing Railway report-volume mount paths remain `/app/reports`.
