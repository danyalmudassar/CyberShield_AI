# Operational signals and incident checks

This local slice answers three questions: can the worker accept execution, is the
queue saturating, and which requests/scans are failing or slow? It adds no external
collector, paid telemetry service or automatic alert delivery.

## Readiness versus liveness

`GET /api/health` remains a public process-liveness response. `GET /api/ready`
returns only `{"status":"ready"}` (200) or `{"status":"not_ready"}` (503).
Readiness requires a live manager, retained worker ownership, no shutdown request,
a successful poll within five seconds and a readable scan database. The five-second
threshold is a local diagnostic default, not a measured availability SLO. A slow or
locked database may make the worker unready; inspect it before restarting blindly.
A full queue does not make existing history/PDF requests unavailable.

Docker backend health now uses readiness; the frontend healthcheck verifies the
same route through its proxy. Docker reports unhealthy state but does not itself
restart an unhealthy process in this Compose setup. External supervision/alerting
remains an operator deployment decision.

## Administrator snapshot

`GET /api/operations` requires an authenticated administrator. Anonymous callers
receive 401 and ordinary operators/static API tokens receive 403. It reports:

- Worker readiness, last successful poll age, active workers and worker capacity.
- Database reachability, scan counts by status and configured pending-job capacity.
- Process-local HTTP counts, duration sums and cumulative duration histograms,
  grouped only by route template, normalized method and status class.

Use the configured admin account/session flow; no default admin password exists.
Do not expose credentials in query parameters. HTTP metrics reset on API restart,
while scan counts come from persistent storage and are not per-window rates. The
snapshot request itself is counted after the snapshot is assembled. Histogram
bounds are 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 seconds and +Inf. Durations measure
response-header latency, not complete SSE connection lifetime or PDF transfer time.
No per-provider latency, distributed traces or Prometheus export is implemented.

## Structured events

The `cybershield.operations` logger emits JSON lines with UTC timestamps:

- `http_response`: generated request ID, matched route template, normalized method,
  response status and duration. Responses carry `X-Request-ID`; caller-supplied IDs
  are not trusted. Unmatched URLs use the fixed `unmatched` route label.
- `scan_started`, `scan_finished`: scan ID, final persisted status and elapsed time.
- `scan_execution_failed`: scan ID and exception class, never the exception text.
- `worker_poll_failed`: exception class for unsuccessful manager iterations.

The field allowlist excludes headers, query strings, bodies, passwords, cookies,
email addresses and raw target URLs. Request IDs and scan IDs are correlation
fields in logs, never metric labels. This is request and job correlation, not a
cross-process distributed trace. The application still has existing diagnostic
agent logs; the allowlist guarantee applies to these new operational events only.
Local launch/Docker disable Uvicorn access logging so it cannot duplicate raw URLs
outside this controlled HTTP telemetry. Direct Uvicorn invocations should include
`--no-access-log` to retain that behavior.

## Local runbook

1. **Readiness 503:** check whether shutdown is underway, the manager is alive and
   the database volume is mounted/readable. Search `worker_poll_failed` events.
   Do not start a second manager against the same SQLite database.
2. **Queue saturation / HTTP 429:** compare queued + running + cancelling counts
   with `max_pending`, then inspect active workers and recent `scan_finished`
   durations/statuses. Do not increase capacity without confirming resource limits.
3. **Failed or timed-out scan:** use its ID to correlate lifecycle events and the
   owner-authorized saved result/events. Do not rerun active probes automatically.
4. **HTTP 5xx or slow responses:** find the generated request ID and route, inspect
   the status-class counters and histogram, then confirm database/worker health.
5. **Database/report loss:** stop writers and use the tested
   [backup/restore runbook](../../docs/backup-restore.md). Never repair by deleting
   the database or restarting jobs with uncertain authorization.

Alert thresholds and delivery should be set from deployment traffic and an agreed
SLO; no untested paging thresholds or notification channels are configured here.
Hosted CI must verify the exact published commit, not a prior successful workflow.
