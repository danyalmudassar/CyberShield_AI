# CyberShield backend

Run the local stack using `../run_local.py`; see the root README for setup.

Standalone local API:

```bash
CYBERSHIELD_DEMO_ONLY=true python -m uvicorn server:app --host 127.0.0.1 --port 8000
```

Use one process per database. Lifecycle startup recovers abandoned running jobs as `interrupted` and resumes queued work.

## Configuration

| Variable | Purpose |
|---|---|
| `CYBERSHIELD_DB` | SQLite path; defaults to `data/scans.sqlite3` |
| `CYBERSHIELD_DEMO_ONLY` | `true` rejects live/rules-only submissions |
| `CYBERSHIELD_ORIGINS` | Comma-separated trusted browser origins |
| `CYBERSHIELD_API_TOKEN` | Optional single-team bearer credential; session authentication remains required |
| `CYBERSHIELD_ALLOW_PRIVATE` | Explicit opt-in to private/loopback lab target preflight |
| `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL` | Default AI routing; requests may select a model independently |
| `STRICT_LIVE_MODE` | Deployment strict-live policy; incompatible with demo |

Credentials are read from environment or existing local `config/.env`, never returned by the API. Private-target preflight is not a complete egress control.

## API

- `POST /api/scans`: create a job; requires `authorized: true`. Optional `Idempotency-Key` makes retries safe.
- `GET /api/scans`: recent scan history.
- `GET /api/scans/{id}`: configuration, status, result.
- `GET /api/scans/{id}/events?after=N`: persisted SSE events; also accepts `Last-Event-ID`.
- `POST /api/scans/{id}/cancel`: cancel queued work/request cancellation of active work.
- `GET /api/scans/{id}/report`: retrieve that scan's PDF.
- Legacy scan-starting GET endpoint returns 410. Legacy filename download is retained for local compatibility with directory-containment validation.

`POST` input: `domain`, `authorized`, `scope_type` (`passive_only`/`full_pentest`), `execution_mode` (`live`/`rules_only`/`demo`), `strict_live`, optional `contact_email`, optional `ai_model`.

Terminal job states: `completed`, `partial`, `failed`, `cancelled`, `interrupted`, `timed_out`. A partial scan is not a clean bill of health.

Run `python -m pytest -q` for offline tests. See [assessment policy](docs/assessment-policy.md) before interpreting control scores.
