# CyberShield AI completion plan

Date: 2026-09-06
Status: Proposed implementation roadmap; implementation has not started.

## Completion target

Deliver a deployable first release for one security team. An authenticated operator can define an authorized target and scope, run an assessment, reconnect without duplicating work, inspect evidence and coverage, revisit scan history, and download a report that matches the displayed results. Failed probes, AI suggestions, and demo fixtures cannot masquerade as confirmed target vulnerabilities.

This scope is an explicit planning assumption. Public multi-tenant SaaS, billing, autonomous learning, and extensive enterprise integrations are separate releases. Preserve the existing Python backend, Next.js dashboard, deterministic assessment rules, and useful tests.

## Baseline and evidence

- Two independent Git repositories: `CyberShield_AI/` and `frontend/`. The workspace root is not their shared Git repository. Track backend/frontend commit pairs for each release; decide deliberately if a later monorepo migration is useful.
- Existing uncommitted frontend change: `frontend/app/page.tsx`. Preserve and review it before implementation.
- Verified during the project review: 45 offline tests passed (`test_offline_verifier.py` and `test_pisf_reachability.py`); frontend TypeScript check passed.
- Full backend suite, production frontend build, browser flows, and live benchmarks have not been verified in this review.
- Reproduced without network access: `HeaderResult` missing-header evidence is lost by recon; `TechResult` input bypasses NVD and produces a canned Log4j finding.
- Current API starts work from the SSE GET endpoint, mutates process-wide model settings, and serves caller-supplied file paths.
- Current visual analysis uses HTTP/HTML checks. Browser screenshots, authenticated dashboard scans, and durable scan history remain incomplete.

## Architecture decisions

1. Keep deterministic probes as the evidence source. AI can explain evidence and propose follow-up checks; only a verifier can promote a suggestion to a confirmed finding.
2. Keep domain dataclasses initially. Add explicit API request/response schemas and generate TypeScript types from OpenAPI; avoid a wholesale model rewrite.
3. Use three explicit modes: `live`, `rules_only`, and `demo`. Rules-only still performs authorized target probes but makes no AI calls. Demo uses fixtures and makes no network calls. Strict-live is an execution policy, not a fourth data source.
4. Create scans with POST, store each scan under an opaque ID, and use GET only for retrieving status, events, and reports.
5. For the first release, use SQLite on a persistent volume and a separate bounded worker process. Persist jobs and events; mark interrupted jobs explicitly after restart. Reconnecting resumes observation, not an interrupted active probe.
6. Put the dashboard and API behind one HTTPS origin. Prefer an established OIDC provider for operator sign-in; validate identity at the backend and enforce scan/report ownership. Local demo access must be explicit and restricted to fixture execution.
7. Record target scope, execution limits, credentials references, and model configuration per scan. Never change shared environment variables to service a request.
8. Validate targets and redirects centrally. Public deployment blocks private/link-local/metadata destinations. Explicit private lab scopes remain available to authorized operators through deployment policy.
9. Report the project's PISF mapping as a technical assessment with assessable coverage and manual evidence requirements. Validate framework editions, mappings, and any compliance wording against primary publications before release.

## File ownership map

Paths below are workspace-relative. New modules are proposed files.

| Files | Responsibility |
|---|---|
| `CyberShield_AI/models.py` | Evidence, finding, assessment, and report domain models |
| `CyberShield_AI/api/schemas.py`, `api/scans.py`, `api/reports.py`, `api/auth.py` | Typed API contracts, jobs, protected report access, operator identity |
| `CyberShield_AI/services/scan_store.py`, `services/scan_worker.py` | Durable jobs/events and bounded execution |
| `CyberShield_AI/utils/target_policy.py`, `utils/http_client.py` | Scope enforcement and shared request policy |
| `CyberShield_AI/utils/ai_provider.py`, `utils/anonymizer.py` | Per-scan model routing and outgoing-data sanitization |
| `CyberShield_AI/utils/auth_session.py`, `utils/crawler.py` | Authenticated access and endpoint discovery |
| `CyberShield_AI/agents/*.py` | Existing pipeline stages, detection, scoring, reporting |
| `frontend/lib/api-types.ts`, `lib/api-client.ts`, `app/hooks/useScan.ts` | Generated types, API access, reconnectable scan state |
| `frontend/app/page.tsx`, `app/components/*.tsx` | Operator workflows and evidence rendering |
| `CyberShield_AI/tests/`, `frontend/tests/` | Isolated regression tests, API and browser tests |
| `CyberShield_AI/deploy/`, `frontend/Dockerfile` | Service images and deployment configuration |
| `docs/plans/`, backend/frontend README files | Cross-project plan, verified setup, release instructions |

Each task below is an implementation slice. Split it further if it cannot be reviewed in one focused session. Add regression tests before changing incorrect behavior; run the listed verification; inspect the diff; checkpoint the relevant repository without including unrelated changes.

## Phase 0 — Reproducible development baseline

### 01. Make installation and test discovery reproducible

**Files:** backend `requirements.txt`, new development dependency lock/input files, `pytest.ini`, `tests/conftest.py`; frontend `package.json` and existing lockfile.

- [ ] Declare all direct imports, including FastAPI, Uvicorn, BeautifulSoup, and test tooling; select supported runtime versions and lock resolved dependencies.
- [ ] Block outbound network in ordinary unit tests, mark live/container tests explicitly, and inspect the currently excluded `test_pisf_agent.py` before fixing or retiring it with a documented reason.
- [ ] Add frontend typecheck/lint/test scripts and document clean installation commands.

**Acceptance:** Fresh environments import both entry points, collect the intended tests, and run offline without credentials or external traffic. Existing failures are recorded individually rather than hidden by new ignores.

**Verification:** Clean dependency installation; backend `python -m pytest -m 'not integration and not live'`; frontend `npm ci` and `npm run typecheck`.

**Dependencies:** None. **Size:** Medium.

## Phase 1 — Trustworthy findings and scores

### 02. Repair recon data contracts

**Files:** `models.py`, `agents/recon_agent.py`, `utils/header_scanner.py`, new `tests/test_recon_contracts.py`.

- [ ] Read header presence, technology lists, and MX records from actual model fields; define one canonical representation for missing headers.
- [ ] Align recon check IDs with the registry and stop treating an unreachable TLS probe as a confirmed invalid certificate.

**Acceptance:** Missing-header fixtures produce findings; failed probes produce unknown/error results; populated dataclasses reach the AI summary accurately.

**Verification:** Regression tests for all-missing headers, valid TLS, unreachable TLS, MX records, and technology values.

**Dependencies:** 01. **Size:** Medium.

### 03. Remove fabricated CVEs from live threat intelligence

**Files:** `agents/threat_intel_agent.py`, `models.py`, new `tests/test_threat_contracts.py`.

- [ ] Consume `TechResult.technologies`; normalize software/version evidence and retain external source references.
- [ ] Distinguish candidate CVEs from verified applicability. Unknown versions, no results, missing API credentials, and timeouts remain explicit unknown/unavailable states.
- [ ] Populate VirusTotal and Shodan model fields consistently; align the demo fixture filename with the file actually present.

**Acceptance:** A normal live dataclass input reaches the intended lookup; an unknown stack never creates a canned Log4j finding; keyword matches and LLM guesses do not become confirmed vulnerabilities without applicability evidence.

**Verification:** Mocked NVD/VT/Shodan success, empty result, unavailable credentials, malformed response, and version mismatch tests; assert no fixture loader runs in live mode.

**Dependencies:** 02. **Size:** Medium.

### 04. Separate execution modes and preserve provenance

**Files:** `models.py`, `agents/orchestrator.py`, `utils/ai_provider.py`, new `tests/test_execution_modes.py`.

- [ ] Define mode/policy values and carry them through every pipeline stage; remove implicit transitions from live data to demo fixtures.
- [ ] Propagate strict-live errors; remove the duplicate `call_llm_json` definition; record actual model/provider usage and per-source degradation.

**Acceptance:** Demo has zero network calls; rules-only has zero AI calls; strict-live fails explicitly; degraded live scans preserve real evidence without substituted demo findings.

**Verification:** Fault injection at every stage, including failure of both a primary operation and its error handling; check terminal state and provenance.

**Dependencies:** 02–03. **Size:** Medium; split provider and orchestrator changes into separate commits.

### 05. Make the report match the scan

**Files:** `agents/report_agent.py`, `models.py`, new `tests/test_report_consistency.py`.

- [ ] Stop discarding the supplied target/findings in demo report generation; preserve scan identity, scope, timestamp, and selected mode.
- [ ] Build dashboard/report summaries from the same deduplicated assessment; preserve unknown checks, evidence URLs, and provenance.
- [ ] Report PDF failure explicitly and use scan IDs for collision-free artifacts.

**Acceptance:** Report and dashboard have identical finding IDs, counts, target, score, and coverage. No mock PISF matrix is inserted into a live report. PDF failure cannot be presented as a ready download.

**Verification:** Snapshot structured report data, inspect generated PDFs for live/degraded/demo cases, and compare two simultaneous same-target reports.

**Dependencies:** 04. **Size:** Medium.

### 06. Validate the compliance mapping and scoring policy

**Files:** `agents/pisf_agent.py`, `models.py`, `agents/report_agent.py`, `tests/test_pisf_reachability.py`, new `docs/assessment-policy.md` in the backend.

- [ ] Verify framework names, versions, references, and mappings against primary publications; retain citations and retrieval dates.
- [ ] Identify which controls require manual organizational evidence; prevent absence of detected vulnerabilities from automatically proving governance compliance.
- [ ] Version the scoring formula; report assessed/total controls, unknown checks, and provisional scores when evidence is incomplete. Validate CVSS score/vector consistency where supplied.

**Acceptance:** Every control has a documented evidence rule and reference; unavailable evidence cannot produce a pass; demo/unverified findings cannot affect a live technical score.

**Verification:** Branch tests, missing-data tests, duplicate-finding tests, score/vector fixtures, and review of one complete assessment report against the policy.

**Dependencies:** 03–05. **Size:** Medium, with research and rule edits as separate steps.

**Checkpoint A:** A complete fixture-driven assessment produces consistent findings, provenance, coverage, and PDF output; all live-error scenarios remain honest.

## Phase 2 — Secure and durable scan execution

### 07. Constrain report downloads immediately

**Files:** `server.py`, new `api/reports.py`, new `tests/test_report_access.py`.

- [ ] Remove caller-selected filesystem paths; resolve opaque artifact IDs through server-owned metadata.
- [ ] Enforce canonical report-directory containment, reject symlinks escaping that directory, and require PDF artifacts registered by the application.

**Acceptance:** Absolute paths, traversal, unregistered files, and escaping symlinks cannot be downloaded. Ownership checks are added in task 10 before any external release.

**Verification:** API tests using temporary files and symlinks; verify valid registered PDFs still download.

**Dependencies:** 01; implement early alongside Phase 1 if the API is already exposed. **Size:** Small.

### 08. Centralize authorization and target policy

**Files:** `agents/pre_engagement.py`, new `utils/target_policy.py`, `utils/http_client.py`, `api/schemas.py`, new `tests/test_target_policy.py`.

- [ ] Require explicit authorization, valid scope, and a normalized URL preserving scheme/port; store the authorization record.
- [ ] Check resolved destinations, redirects, and scope boundaries before requests; address DNS rebinding with connection-level enforcement or a controlled egress proxy.
- [ ] Define private-lab access as an operator/deployment policy and separate passive requests from intrusive test categories.

**Acceptance:** Authorization defaults to false; invalid domains and out-of-scope redirects are rejected; public jobs cannot reach metadata/private destinations; approved local lab targets remain testable.

**Verification:** Synthetic DNS/redirect tests, IPv4/IPv6 cases, DNS-answer changes, scope boundary cases, and authorization-denied requests.

**Dependencies:** 01, 04. **Size:** Medium; roll request-policy adoption through probe families incrementally.

### 09. Persist scan jobs and event streams

**Files:** new `services/scan_store.py`, `services/scan_worker.py`, `api/scans.py`, `api/schemas.py`, `tests/test_scan_lifecycle.py`; thin integration in `server.py`.

- [ ] Create a scan once using `POST /api/scans`; return `scan_id`; store owner, configuration, state, ordered events, and artifact metadata.
- [ ] Implement status and event reads at `/api/scans/{id}` and `/api/scans/{id}/events`; support event sequence replay and idempotent submission keys.
- [ ] Execute queued work with bounded concurrency; persist completed results and explicitly classify interrupted jobs after restart.

**Acceptance:** Repeated submission with the same key creates one job; reconnecting never runs another scan; history survives restart; event replay is ordered and deduplicated.

**Verification:** API/worker integration tests with fake scans, multiple subscribers, reconnect, duplicate POST, and process restart.

**Dependencies:** 04, 07–08. **Size:** Large; implement store, worker, and API as three reviewed substeps.

### 10. Protect scan and report ownership

**Files:** new `api/auth.py`, `api/scans.py`, `api/reports.py`, `server.py`, new `tests/test_operator_access.py`.

- [ ] Integrate backend-validated OIDC identity; configure exact trusted origins and secure browser sessions.
- [ ] Enforce owner/team permissions on submission, history, event streams, cancellation, and downloads; protect cookie-authenticated mutations against CSRF.
- [ ] Add per-operator submission limits and audit records containing identity, scope, action, and outcome without secrets.

**Acceptance:** Unauthenticated users cannot launch scans; one operator cannot access another operator's restricted jobs or artifacts; authorization statements are attributable and retained.

**Verification:** Two-identity API tests, expired/invalid sessions, CSRF tests, and rate-limit tests.

**Dependencies:** 09. **Size:** Medium.

### 11. Bound and cancel work

**Files:** `services/scan_worker.py`, `agents/orchestrator.py`, `utils/http_client.py`, new `tests/test_scan_limits.py`; incremental adoption in scanner modules.

- [ ] Enforce scan/stage deadlines, request budgets, target rate limits, crawl limits, and response size limits.
- [ ] Implement cooperative cancellation checked before each new probe and a worker-level timeout for unresponsive tasks.
- [ ] Retain partial evidence and distinguish cancelled, timed out, failed, interrupted, and completed states.

**Acceptance:** Cancellation stops new probes within five seconds; in-flight work remains bounded by configured timeouts; queue saturation is visible and cannot create unbounded threads.

**Verification:** Slow fake targets, cancellation during each stage, exhausted budgets, worker termination, and concurrent jobs with different configurations.

**Dependencies:** 09–10. **Size:** Medium per probe-family adoption batch.

**Checkpoint B:** An authenticated user can create, observe, cancel, and revisit one durable job; access control and egress policies hold under adversarial API tests.

## Phase 3 — Complete the operator workflow

### 12. Add a typed dashboard API client

**Files:** new `frontend/lib/api-types.ts`, `lib/api-client.ts`, `app/hooks/useScan.ts`; existing `app/page.tsx` and `app/components/ScanConfig.tsx`.

- [ ] Generate types from the backend OpenAPI schema; remove `any` from scan API boundaries.
- [ ] Replace hardcoded localhost URLs with same-origin routing/configuration; create jobs with POST and subscribe by ID.
- [ ] Clean up streams and timers on unmount; replay events without duplicates and expose cancellation and terminal errors.

**Acceptance:** Refresh/reconnect observes the same scan; deployment works beyond localhost; retry limits remain effective even when connections repeatedly open then fail.

**Verification:** Typecheck and browser tests for create/reconnect/refresh/cancel/error flows using a fake backend worker.

**Dependencies:** 09–11. **Size:** Medium.

### 13. Render evidence, uncertainty, and report readiness accurately

**Files:** frontend `FindingsTable.tsx`, `VisualAudit.tsx`, `PisfGrid.tsx`, `ReportDownload.tsx`, `app/page.tsx`.

- [ ] Fix top-level fallback-field consumption and visual `{check, detail}` rendering; distinguish unknown checks from safe or vulnerable results.
- [ ] Display provenance, evidence URL, check status, assessed coverage, and manual-control requirements; distinguish no findings from no completed assessment.
- [ ] Download only ready artifacts through protected IDs; show PDF errors and score limitations.

**Acceptance:** The UI matches API/report fixtures for clean, vulnerable, partial, unreachable, cancelled, and demo scans; no unknown state receives a green pass badge.

**Verification:** Component tests for each state and browser checks of result tabs and PDF downloads.

**Dependencies:** 05–06, 12. **Size:** Medium.

### 14. Add scan history and comparison

**Files:** backend `api/scans.py`, `services/scan_store.py`; new frontend `app/history/page.tsx`, `app/scans/[id]/page.tsx`, `app/components/ScanComparison.tsx`.

- [ ] List owned scans with target, time, scope, status, mode, and coverage; open stored results.
- [ ] Compare stable finding fingerprints between compatible scans and display new, persistent, and no-longer-observed findings.

**Acceptance:** Historical scans are usable after restart; comparisons disclose differing scope/coverage and never classify an untested issue as fixed.

**Verification:** Stored-result browser tests and comparison tests for scope changes, incomplete scans, and reordered findings.

**Dependencies:** 12–13. **Size:** Medium.

### 15. Make provider selection real and private

**Files:** backend `utils/ai_provider.py`, `utils/anonymizer.py`, `api/schemas.py`; frontend `ScanConfig.tsx`; provider contract tests.

- [ ] Supply immutable provider/model configuration per job; use a backend capability registry so the UI offers configured routes.
- [ ] Validate provider response schemas; treat target content as untrusted prompt data and keep AI suggestions separate from verified findings.
- [ ] Sanitize outgoing payloads, log actual usage/failure, and make permitted data sharing explicit in deployment configuration.

**Acceptance:** Simultaneous scans cannot change each other's model; rules-only contacts no provider; keys and sensitive target values are absent from logs and redacted outbound fixtures.

**Verification:** Mock provider success, malformed JSON, timeout, missing key, model mismatch, injected page instructions, and concurrent configuration tests.

**Dependencies:** 04, 10, 12. **Size:** Medium.

**Checkpoint C:** The complete dashboard workflow works through the deployed API contract, including history, honest results, provider selection, and report access.

## Phase 4 — Complete scanner coverage

### 16. Connect authenticated assessments

**Files:** `utils/auth_session.py`, `agents/pentest_agent.py`, `agents/orchestrator.py`, `api/schemas.py`; frontend `ScanConfig.tsx`; authentication contract tests.

- [ ] Add form/CSRF, bearer-token, and pre-established-cookie input methods with explicit success verification.
- [ ] Pass credentials references from the dashboard through the job to the scanner; protect queued secrets, prohibit logging, and delete them after execution/expiry.
- [ ] Expose login failure and session expiry; do not silently present an unauthenticated scan as authenticated.

**Acceptance:** A protected fixture is scanned only after verified login; bad credentials produce an explicit authentication failure; credentials never appear in events, stored result JSON, or PDFs.

**Verification:** Controlled login fixtures for successful form login, wrong credentials returning HTTP 200, CSRF failure, JWT auth, and mid-scan expiry.

**Dependencies:** 08–11, 12, 15. **Size:** Large; separate credential lifecycle, backend authentication, and UI commits.

### 17. Improve general endpoint discovery

**Files:** `utils/crawler.py`, `agents/pentest_agent.py`, new `utils/endpoint_catalog.py`, new `tests/test_endpoint_discovery.py`.

- [ ] Crawl authorized public pages as well as authenticated pages; retain form methods, fields, and parameters in a structured endpoint catalog.
- [ ] Add operator-supplied OpenAPI specifications for API endpoints; bound traversal and maintain central scope policy through redirects.
- [ ] Separate generic discovery from explicit application-specific profiles; avoid logout and known destructive actions.

**Acceptance:** Generic HTML/forms and API fixtures produce usable probe targets without DVWA-only path assumptions; out-of-scope links are never requested.

**Verification:** Fixtures for query parameters, relative form actions, redirects, logout links, JSON APIs, duplicate URLs, and budget limits.

**Dependencies:** 08, 11, 16. **Size:** Medium.

### 18. Implement browser-backed visual analysis

**Files:** new `utils/browser_runner.py`, existing `agents/visual_agent.py`, `models.py`, new `tests/test_browser_analysis.py`.

- [ ] Add an isolated Playwright context per job, screenshots, rendered DOM, browser resource observations, and authenticated context where configured.
- [ ] Apply scope/egress policy to all browser subrequests; bound execution time, downloads, pages, and screenshot artifacts.
- [ ] Keep HTTP-only checks clearly labeled and mark browser-dependent checks unavailable when browser setup fails.

**Acceptance:** JavaScript-rendered fixture evidence and a protected screenshot are available; HTTP-only fallback never claims a browser observation; artifacts follow report access/retention rules.

**Verification:** Local browser fixtures for rendered content, mixed resources, sensitive display, authentication, cross-origin requests, and browser crash.

**Dependencies:** 07–11, 16–17. **Size:** Medium.

### 19. Validate all 24 active check types

**Files:** `agents/pentest_agent.py`, new `checks/registry.py`, focused `tests/checks/` fixtures, backend `docs/check-coverage.md`.

- [ ] Inventory each check's inputs, supported target types, baseline comparison, positive evidence, limitations, and possible side effects.
- [ ] Work in four batches of six checks. For each check add vulnerable, patched, unrelated-error, timeout, and unsupported-target cases before changing detection logic.
- [ ] Introduce a stable finding fingerprint and separate execution status from vulnerability verdict where current severity-based invariants conflate them. Require explicit scope selection for intrusive categories.

**Acceptance:** Every check has a documented support boundary and fixture coverage; failed requests cannot become clean passes; application-specific tuning is labeled. Unsupported scenarios remain not-assessable.

**Verification:** Per-check deterministic fixture tests and bounded local integration cases, including negative controls. Compare registry count with executed/successful/skipped/error counts.

**Dependencies:** 02–04, 08, 11, 17. **Size:** Four medium batches, each reviewed separately.

### 20. Publish reproducible benchmark evidence

**Files:** `tests/evaluate_dvwa_ground_truth.py`, `tests/evaluate_juiceshop_cross_validation.py`, new `tests/benchmarks/` manifests/results, frontend `BenchmarkWidget.tsx`.

- [ ] Pin local benchmark images and settings; record ground-truth rationale, scanner revision, auth mode, scope, and known target-specific tuning.
- [ ] Compute confusion matrices from saved findings; include patched/negative fixtures and an independent holdout scenario not used to tune detection.
- [ ] Load dashboard metrics from versioned result artifacts; label date/target/scope and remove unsupported static claims such as an unimplemented local CVE index.

**Acceptance:** Another developer can reproduce counts from the stored artifacts. Incomplete evaluations cannot become clean negatives or performance claims. Report per-check coverage and measured precision/recall without promising a universal percentage.

**Verification:** Fresh local benchmark run, independent arithmetic recalculation, artifact-schema checks, and dashboard rendering against those artifacts.

**Dependencies:** 16–19. **Size:** Medium per target.

**Checkpoint D:** All 24 check types have evidence-backed support boundaries; authenticated/browser workflows pass controlled integration tests; benchmark claims are reproducible.

## Phase 5 — Release engineering

### 21. Package the release

**Files:** backend `Dockerfile`, `deploy/compose.yaml`, `deploy/proxy.conf`, `config/.env.example`; frontend `Dockerfile`; repository README files.

- [ ] Build pinned, non-root service images with required Playwright browser dependencies; configure same-origin HTTPS routing and SSE buffering/timeouts.
- [ ] Persist jobs/reports, configure OIDC and secrets through deployment settings, and provide local demo configuration using fixtures only.
- [ ] Document both UIs: Next.js is the supported release interface; keep Gradio as a local diagnostic interface with shared modes and honest statuses.

**Acceptance:** A clean checkout starts using documented configuration; health/readiness checks identify unavailable workers/storage; no credentials are embedded in images.

**Verification:** Clean image build, fresh-volume installation, real proxy SSE smoke test, stored-report restart test, and production frontend build.

**Dependencies:** Checkpoints A–D. **Size:** Medium, separated into backend, frontend, and composition commits.

### 22. Add continuous verification in both repositories

**Files:** each repository's `.github/workflows/ci.yml`; backend integration markers; frontend browser test configuration.

- [ ] Run offline backend tests, API contracts, frontend lint/typecheck/tests/build on changes; keep external-provider tests separately opt-in.
- [ ] Run controlled container/browser integration tests in a dedicated job and preserve failure artifacts.
- [ ] Check secrets and dependencies; publish a release manifest pairing backend/frontend revisions and schema versions.

**Acceptance:** CI exercises meaningful negative and failure paths, detects API type drift, and blocks a release with failed required checks.

**Verification:** Successful CI run plus deliberate temporary failing test/type-contract change proving the gate rejects it; remove the deliberate failure afterward.

**Dependencies:** 01, 12–13, 20–21. **Size:** Medium.

### 23. Add operational visibility and recovery

**Files:** `services/scan_worker.py`, new `utils/telemetry.py`, backend `deploy/` scripts, `docs/operations.md`.

- [ ] Emit structured redacted logs keyed by scan/stage/check; measure queue depth, durations, timeouts, provider failures, and report-generation failures.
- [ ] Define retention for jobs, events, credentials, screenshots, and PDFs; implement scheduled cleanup and storage limits.
- [ ] Document and test database/artifact backup, restore, worker restart, and release rollback.

**Acceptance:** An operator can diagnose a failed scan without exposing credentials; expired artifacts become unavailable; backup restoration recovers matching job/report records.

**Verification:** Forced worker/PDF/provider failures, retention-clock tests, and a restore drill into a clean volume.

**Dependencies:** 09–11, 21. **Size:** Medium per logging, retention, and recovery slice.

### 24. Run the release acceptance matrix

**Files:** new backend `docs/release-checklist.md`, `docs/known-limitations.md`, updated README files and root architecture summary.

- [ ] Exercise demo, rules-only, live, strict-live failure, denied authorization, unreachable target, authenticated target, browser failure, cancellation, reconnect, restart, and concurrent model selections.
- [ ] Review representative PDFs and dashboard results together; remove stale claims from UI/docs and document scanner limits and manual assessment requirements.
- [ ] Run the gates below and record exact revisions, commands, outcomes, and remaining non-blocking limitations.

**Acceptance:** All release gates pass and no unresolved issue can fabricate evidence, bypass scope/access controls, expose local files, or silently duplicate scans.

**Verification:** Signed-off checklist backed by test artifacts, benchmark manifests, deployment smoke-test output, and recovery-drill results.

**Dependencies:** 22–23 and all prior checkpoints. **Size:** Medium.

## Release gates

- [ ] Clean installation and production build succeed from documented dependency versions.
- [ ] All required offline, API, component, browser, and controlled integration tests pass; no accidental public-target traffic occurs in CI.
- [ ] No mock finding enters a live assessment; missing evidence remains visibly unknown.
- [ ] Every active check has positive, negative, failed-probe, and unsupported-input coverage, with a documented scope boundary.
- [ ] Authorization is explicit; target scope, identity, report ownership, and egress restrictions are enforced.
- [ ] Submission is idempotent; reconnect does not duplicate execution; cancellation and restart produce truthful states.
- [ ] UI, stored results, scores, and PDFs agree; unknown coverage and manual controls are visible.
- [ ] Historical results, benchmark claims, and provider attribution are traceable to their source and revision.
- [ ] Secret handling, retention, backup/restore, and rollback are tested.
- [ ] Framework mappings are sourced and technical-assessment language accurately describes what the product can establish.

## Dependency summary

`01 → 02–06 → Checkpoint A`

`01 → 07`; `04 → 08 → 09 → 10 → 11 → Checkpoint B`

`A + B → 12–15 → Checkpoint C`

`B + C → 16 → 17 → 18/19 → 20 → Checkpoint D`

`A + B + C + D → 21 → 22/23 → 24 → Release`

Framework-source research for task 06 and the report containment fix in task 07 can begin early. Shared schema changes must land before frontend consumers. This roadmap does not authorize live testing of external targets or deployment to an external environment.

## Milestones and scope control

| Milestone | Tasks | Observable outcome |
|---|---|---|
| M1: Trustworthy assessment | 01–07 | Real evidence and consistent scoring/reporting; protected artifact resolution |
| M2: Reliable execution | 08–11 | Scoped, authenticated, durable, cancellable jobs |
| M3: Complete dashboard | 12–15 | Typed operator flow, history, accurate states, per-scan AI settings |
| M4: Validated scanner | 16–20 | Auth/browser coverage and reproducible detection evidence |
| M5: Deployable release | 21–24 | Packaged services, passing CI, operational recovery, documented limits |

Use milestone acceptance rather than a fixed calendar promise. The largest uncertainties are validating 24 probe types, completing browser/JWT coverage, and substantiating compliance mappings. Estimate delivery dates after M1 establishes a clean baseline and task 19 inventories the actual detection gaps.

## Later releases

These are explicit extensions to the first-release scope, not silently dropped features from the broader vision:

- Alibaba-managed deployment and integrations with AnalyticDB/PAI where a measured requirement justifies them.
- Cross-scan retrieval/memory beyond deterministic history comparison, with tenant isolation and evidence retention controls.
- AI-assisted adaptive test selection with bounded scope, verification, and human control of intrusive actions.
- Nuclei and DefectDojo ingestion/export using documented evidence/provenance contracts.
- Multi-tenant administration, billing, custom branding, scheduled assessments, and enterprise integrations.

If the intended completion target includes the original cloud-hackathon architecture in full, promote the relevant items into a separate follow-on plan after the reliable first release. Nothing in the current code review establishes those integrations as already complete.

## First implementation batch

Start with tasks **01, 02, 03, and 07**: establish a trustworthy baseline, fix the two reproduced data-contract defects, remove fabricated live CVEs, and close arbitrary report-file access. These changes address the clearest correctness and exposure problems before expanding features.
