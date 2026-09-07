# CyberShield AI — Self-Verification & Quality Audit Checklist

Use this checklist during development, code reviews, and automated verification runs across all agent modules (`recon`, `threat_intel`, `visual`, `pentest`, `pisf`, `report`, and `orchestrator`).

---

### 1. Coverage Verification (Mechanical Inspection)
- When asserting complete coverage of fields or parameters (e.g., `provenance=`, `check_status=`, `strict_live=`), verify using explicit file inspection or exact grep counts:
  ```bash
  grep -c "Finding(" backend/agents/pentest_agent.py
  grep -c "provenance=" backend/agents/pentest_agent.py
  ```
- Ensure every instantiated finding sets explicit `provenance` and `check_status`.

---

### 2. Test Count Arithmetic
- Ensure that claimed unit test additions correspond 1:1 with `pytest` execution counts.
- Run tests directly to confirm exact collection:
  ```bash
  python3 -m pytest backend/tests/test_agent_audit_and_fallback.py
  ```

---

### 3. Silent-Default Prevention & Explicit Statuses
- Never permit missing or degraded data to silently default to `"success"`, `"pass"`, or confirmed safe outcomes.
- Force missing, unconfigured, or failing data to map to explicit non-passing statuses (`NOT_ASSESSABLE`, `UNREACHABLE`, `ERROR`, `unknown`, `degraded`, or `mock`).

---

### 4. Secret & Credential Sanitization
- Sanitize error messages and exception tracebacks before logging or raising exceptions to prevent secret exposure (e.g., API keys in URL query strings):
  ```python
  clean_exc = sanitize_text(str(err))
  ```
- Ensure regex redaction patterns (`BEARER_KEY_REGEX`) target specific credential patterns (e.g., `api_key=`, `token=`) without corrupting non-sensitive key names (e.g., `primary_key=id`).

---

### 5. `strict_live` & Fail-Fast Propagation
- Propagate `strict_live` mode to all sub-scanners and external queries.
- In `strict_live` mode, raise a `RuntimeError` immediately upon target unreachability or API failures instead of swallowing errors or falling back to mock data.

---

### 6. Comprehensive Fallback Signal Aggregation
- Explicitly aggregate all agent fallback flags (`fb_recon`, `fb_threat`, `fb_visual`, `fb_pentest`, `fb_pisf`, `fb_finding`) in `orchestrator.py` and `report_agent.py`.
- Ensure top-level report `fallback_triggered` evaluates to `True` if any sub-agent or probe degraded.

---

### 7. Unconditional & Collision-Proof Data Sources Namespacing
- Always prefix `data_sources` keys with their parent agent namespace (e.g., `recon_dns`, `threat_intel_nvd`, `visual_scan`, `pentest_probes`).
- Enforce clean, order-independent prefix checks at the report merge layer:
  ```python
  key_name = k if k.startswith(f"{agent_prefix}_") else f"{agent_prefix}_{k}"
  ```

---

### 8. Dataclass Invariant Order & Precedence
- Ensure `Finding.__post_init__` evaluates status precedence deterministically:
  - `UNREACHABLE` or `ERROR` probe status forces `severity = "Info"`.
  - Confirmed non-Info severities (`Critical`, `High`, `Medium`, `Low`) force `check_status = "VULNERABLE"`.
  - Clean `Info` findings auto-correct `check_status = "SUCCESS"`.

---

### 9. Network Isolation in Unit Tests
- All automated unit tests must execute in complete offline isolation (~5s total runtime) using mock dependencies (`unittest.mock.patch`).

---

### 10. Mandatory Mocking for Network Probing Helpers
- Every new network-probing helper (`_probe_*`, `_check_*`, `safe_request`, `requests.*`, `urllib.*`) MUST be explicitly included in unit test mocking context managers (`unittest.mock.patch`).
- Never rely solely on top-level flags in unit tests — verify that inner network routines cannot trigger live internet calls during `pytest` execution.
