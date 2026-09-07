# Railway deployment

Railway replaces Alibaba ECS as the planned hosting destination. The application is deployed in fixture demo mode on Railway. Review your plan's
compute, volume and usage limits when changing this deployment.

## Project and services

Connect GitHub repository `danyalmudassar/CyberShield_AI`, branch `master`, to a
Railway project. Create two services from that repository in the same environment:

| Setting | backend | frontend |
| --- | --- | --- |
| Root directory | `/CyberShield_AI` | `/frontend` |
| Builder | existing Dockerfile | existing Dockerfile |
| PORT variable | `8000` | `3000` |
| Replicas | 1 | 1 |
| Healthcheck path | `/api/ready` | `/api/ready` |
| Public domain | none | generate Railway domain, target port 3000 |

No Caddy service or ECS security group is needed. Railway provides public HTTPS.
Set variables and the volume before launching the backend. The frontend readiness
check proxies to the backend, so bring the backend up first.

## Persistent backend storage

Attach ONE Railway volume to backend at `/app/reports`. Keep the existing fixed
PDF directory and place both SQLite databases in its `data` subdirectory. Do not
mount a volume at `/app` because it hides application code.

Set backend variables:

```dotenv
PORT=8000
RAILWAY_RUN_UID=0
CYBERSHIELD_DB=/app/reports/data/scans.sqlite3
CYBERSHIELD_AUTH_DB=/app/reports/data/auth.sqlite3
CYBERSHIELD_REQUIRE_AUTH=true
CYBERSHIELD_COOKIE_SECURE=true
CYBERSHIELD_ALLOW_SIGNUP=true
CYBERSHIELD_DEMO_ONLY=true
CYBERSHIELD_MP_METHOD=spawn
CYBERSHIELD_MAX_CONCURRENT_SCANS=1
CYBERSHIELD_MAX_PENDING_SCANS=20
```

Railway mounts volumes as root. `RAILWAY_RUN_UID=0` is Railway's documented
compatibility setting for this existing non-root image; it means this deployment
runs the backend as root inside the container. The local Compose deployment
continues to use its non-root user. Do not expose the backend publicly.

Also set privately in Railway Variables:

- `CYBERSHIELD_OPERATOR_PASSWORD`: a new strong password of at least 12 characters.
- `CYBERSHIELD_ORIGINS`: the exact frontend HTTPS origin, with no trailing slash,
  for example `https://YOUR-FRONTEND.up.railway.app`. Do not use a wildcard.

Use the default backend Docker command (port 8000). Verify the private network
supports IPv4 for this environment, since the image binds `0.0.0.0`. If an older
IPv6-only environment is used, configure its start command to bind `::` instead:

```text
python -m uvicorn server:app --host :: --port 8000 --workers 1 --no-proxy-headers --no-access-log
```

## Frontend connection

Read backend's private hostname from Railway Settings / Networking. Before
building frontend, set its `CYBERSHIELD_API_URL` variable to the private HTTP URL,
for example `http://backend.railway.internal:8000`. Use the actual displayed name.
The existing frontend Dockerfile declares this ARG for the build. Next.js embeds
rewrites at build time: changing the value requires a rebuild, not just a restart.
No browser should call that private hostname directly; `/api/*` goes through Next.

Generate the frontend domain and copy its exact HTTPS origin into backend's
`CYBERSHIELD_ORIGINS`, then redeploy backend. Open `/login` or `/signup` on the
frontend domain. Configured operator email is `operator@cybershield.ai`.

## Acceptance before sharing

1. Both services pass `/api/ready`; public frontend `/api/ready` returns success.
2. Signup/login works and unauthenticated scan requests are rejected.
3. Run a demo assessment, follow progress and download a PDF.
4. Restart backend and verify the same account, history and PDF still exist.
5. Logout and confirm protected requests are rejected.
6. Configure volume backups; persistence alone does not protect against deletion.

Keep a single backend replica for this SQLite/worker design. Do not delete the
volume when redeploying. Demo is fixture-only, not a network isolation guarantee:
Railway backend networking may allow outbound traffic. Live assessment and AI
provider configuration are separate follow-up steps for authorized target scopes.

## Official references

- https://docs.railway.com/builds/dockerfiles
- https://docs.railway.com/volumes
- https://docs.railway.com/networking/private-networking
- https://docs.railway.com/deployments/healthchecks

## Deployed instance — 7 September 2026

- Public frontend: https://cybershield-frontend-production-c850.up.railway.app
- Services: `cybershield-backend`, `cybershield-frontend` in the supplied project.
- Backend volume: `/app/reports`, including `data/scans.sqlite3` and `data/auth.sqlite3`.
- Initial release uploaded with Railway CLI from the verified release checkout;
  GitHub automatic deployments have NOT been connected. The service directories
  contain `railway.json` with Dockerfile builds and `/api/ready` health checks.
- Existing Ubuntu services and their existing volume were not modified.
- Public HTTPS readiness, browser login, rejected bad credentials, demo assessment,
  PDF bytes, mobile layouts and logout verified on the deployed URL.

For a manual update from the repository root, use explicit service selectors:

```bash
railway up ./CyberShield_AI --path-as-root --project 19a3339d-74e5-4865-90c4-59ecc486d098 --environment production --service cybershield-backend --detach
railway up ./frontend --path-as-root --project 19a3339d-74e5-4865-90c4-59ecc486d098 --environment production --service cybershield-frontend --detach
```

Never upload local secret files or databases. Use a clean checkout. Poll deployment
status and rerun the acceptance flow after uploads; detach does not imply success.
