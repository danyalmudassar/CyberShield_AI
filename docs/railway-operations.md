# Railway operations

Public app: https://cybershield-frontend-production-c850.up.railway.app.
Only cybershield-backend, cybershield-frontend and the backend reports volume
are managed here; the other services in the Railway project are unrelated.

## Automatic deployment

Both services connect to danyalmudassar/CyberShield_AI, branch master, with root
directories /backend and /frontend. Both use /api/ready and a 300-second
healthcheck timeout. Wait for CI is enabled on both GitHub triggers. Keep one
backend replica for SQLite worker ownership.

Railway now rejects setting railwayConfigFile because Config as Code is deprecated.
Remote service settings are configured directly. Do not assume the legacy JSON
files alone configure remote services; synchronize service settings or migrate
explicitly to Railway Infrastructure as Code.

Merge reviewed changes after backend/frontend CI passes. Verify both Railway
deployments reach SUCCESS for the merged commit and run the public monitor.
A push or queued deployment is not proof that the update is running. Roll back
by redeploying a previously successful Railway deployment, preserving the volume.
Code rollback does not roll back data.

## AI configuration

Backend uses LLM_PROVIDER=dashscope, LLM_MODEL=qwen3.6-plus and
DASHSCOPE_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1.
DASHSCOPE_API_KEY is a private Railway variable. Never copy its value to GitHub,
logs or browser configuration. Workspace default in the model selector sends no
override, so backend configuration applies. Qwen is also an explicit choice.
Other providers require their own credentials/configuration.

Verify a bounded provider JSON request from the deployed backend. A provider
connectivity test alone does not establish end-to-end target assessment accuracy.

## Backups

Daily and weekly Railway backups are enabled on volume instance
352ea15f-1d88-41cb-9629-5f394c27ad47 at /app/reports. The volume includes PDFs and
both SQLite databases under data/. Railway reports six-day daily retention and
27-day weekly retention. Native backups incur incremental storage usage under
the existing plan.

Baseline backup 9a972547-f865-464e-8a1f-7a4cf122ab99 was created 2026-09-07.
Inspect schedules and recent backups in the service Backups tab. Deleting or
wiping a volume also removes its backups. Native backups are retained in the same
project/environment, not as an independent off-provider copy.

To recover, review a chosen snapshot and the staged replacement volume before
deployment; preserve the original volume. Verify database integrity, accounts,
history and PDF downloads. Native snapshots restore historical sessions too;
revoke restored sessions before reopening access. Application offline restore
already performs revocation; see backup-restore.md. Do not run the offline
backup command against a running worker. No new production restore drill is
claimed by this configuration change.

## Monitoring and response

Production health monitor runs on GitHub approximately every 15 minutes and
supports manual dispatch. GitHub schedules may be delayed. It checks readiness
JSON (200/ready), login HTML (200) and unauthenticated scan access (401), without
application credentials. Three failures fail the workflow with a runbook reference.
GitHub Actions notification preferences control receipt of workflow failures;
no email/SMS/webhook recipients are provisioned here. The configured incident
signal is a failed workflow, not guaranteed delivery to an external pager.

On failure inspect Railway deployment state and backend logs, then volume and
worker readiness. Anonymous /api/scans returning 200 is an authentication
regression: restrict access and investigate. Before restarting a locked database,
confirm only one backend replica exists. Railway CPU/memory/HTTP metrics and the
existing administrator-only /api/operations endpoint support diagnosis. Operator
accounts cannot access that administrator endpoint.

```bash
python deploy/monitor/check_health.py https://cybershield-frontend-production-c850.up.railway.app
python -m unittest discover -s deploy/monitor -p 'test_*.py' -v
```

Sources: [Railway backups](https://docs.railway.com/volumes/backups),
[GitHub autodeploy and Wait for CI](https://docs.railway.com/deployments/github-autodeploys),
[Railway service CLI](https://docs.railway.com/cli/service).
