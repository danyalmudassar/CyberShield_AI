"""
CyberShield AI — OWASP Juice Shop Cross-Validation Benchmark
=============================================================
PURPOSE: Validate whether Phase 2 improvements (auth + crawler) are
genuinely general, or only DVWA-specific calibration.

RULES FOR THIS SCRIPT (to keep the test honest):
  ALLOWED: Use auth_session.py, crawler.py, run_pentest() unchanged
  ALLOWED: Adapt login method for Juice Shop (JSON vs form-POST) — this
           is a general auth mechanism change, not per-check detection
  NOT ALLOWED: Add any Juice Shop-specific detection strings or paths
               to pentest_agent.py check functions
  NOT ALLOWED: Pre-tune any check to Juice Shop's response format
"""

import sys, os, requests, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.pentest_agent import run_pentest, _CHECK_TITLES

JUICESHOP_BASE = "http://localhost:3001"

# Ground-Truth: conservative, from OWASP Juice Shop published challenge list
JUICESHOP_GROUND_TRUTH = {
    "P-001": (True,  "YES"),  # Default creds: admin@juice-sh.op / admin123
    "P-002": (False, "NO"),   # No traditional brute-lockout (JWT auth, not session)
    "P-003": (False, "NO"),   # No session fixation (JWT-based)
    "P-004": (False, "NO"),   # No insecure cookies (JWT in header)
    "P-005": (True,  "NO"),   # JWT weak secret challenge
    "P-006": (True,  "NO"),   # SQLi GET: /rest/products/search?q=' (unauthenticated)
    "P-007": (True,  "YES"),  # SQLi POST: login endpoint injectable
    "P-008": (True,  "NO"),   # XSS challenge exists (DOM-based)
    "P-009": (True,  "YES"),  # Stored XSS via reviews/feedback
    "P-010": (True,  "NO"),   # DOM XSS challenge
    "P-011": (False, "NO"),   # No OS command injection (Node.js app)
    "P-012": (False, "NO"),   # No LDAP
    "P-013": (False, "NO"),   # No XML/XXE endpoints
    "P-014": (True,  "NO"),   # Directory traversal: /ftp/ exposed
    "P-015": (False, "NO"),   # No LFI (Node.js, no PHP include())
    "P-016": (True,  "YES"),  # IDOR: access other users' orders
    "P-017": (False, "NO"),   # CSRF: SPA + JWT, no traditional form POST
    "P-018": (True,  "NO"),   # Open redirect: /redirect?to=
    "P-019": (False, "NO"),   # No known SSRF challenge
    "P-020": (True,  "NO"),   # Directory listing: /ftp/ browsable
    "P-021": (True,  "NO"),   # Security misconfig: /api-docs exposed
    "P-022": (True,  "NO"),   # Backup files: /ftp/package.json.bak
    "P-023": (True,  "NO"),   # Sensitive files: /ftp/ exposes various
    "P-024": (False, "NO"),   # HTTP method tampering: REST handles methods cleanly
}

def evaluate_juiceshop():
    print("=" * 85)
    print("CyberShield AI - Cross-Validation: OWASP Juice Shop (localhost:3001)")
    print("=" * 85)
    print()
    print("RULES: Same scanner, no per-app detection code added.")
    print("       Auth adapts to JSON login (general mechanism, not DVWA-specific).")
    print()

    # Check Juice Shop is reachable
    try:
        r = requests.get(JUICESHOP_BASE, timeout=5)
        print(f"[OK] Juice Shop reachable: HTTP {r.status_code}")
    except Exception as e:
        print(f"[ERROR] Cannot reach Juice Shop at {JUICESHOP_BASE}: {e}")
        print("Run: docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop")
        return

    # Try JSON login
    token = None
    try:
        lr = requests.post(
            f"{JUICESHOP_BASE}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123"},
            timeout=10,
        )
        if lr.status_code == 200:
            token = lr.json().get("authentication", {}).get("token")
            print(f"[OK] Juice Shop auth: JWT token obtained" if token else "[WARN] No token in response")
        else:
            print(f"[WARN] Auth failed: HTTP {lr.status_code}")
    except Exception as e:
        print(f"[WARN] Auth error: {e}")

    # Build auth_credentials for run_pentest
    # NOTE: run_pentest's create_authenticated_session uses form-POST by default.
    # Juice Shop uses JSON POST — so we pass auth_credentials but auth_session.py
    # will fail (form-POST wont work). We instead inject the pre-obtained session
    # directly by setting session cookies on the scanner.
    # This is the ONLY per-app adaptation allowed.
    auth_credentials = None
    if token:
        # Juice Shop uses Authorization: Bearer header, not cookies.
        # auth_session.py creates a cookie-based session — it won't apply here.
        # So we run without auth_credentials (unauthenticated crawl) but manually
        # test auth-required endpoints in the ground-truth comparison.
        print("[NOTE] Juice Shop uses JWT Bearer auth (not cookie). Crawler will run")
        print("       unauthenticated. Auth-required checks will likely show as FN.")
        print("       This is the honest baseline for architecture-only (no JWT support yet).")

    print()

    t0 = time.time()
    result = run_pentest(
        domain="localhost:3001",
        authorized=True,
        use_mock=False,
        auth_credentials=None,  # honest: auth_session.py doesn't support JSON/JWT yet
    )
    elapsed = time.time() - t0
    print(f"[TIMING] Full scan: {elapsed:.1f}s")
    print()

    findings_by_id = {f.check_id: f for f in result.get("findings", [])}

    header = f"{'ID':<6} | {'Check Title':<32} | {'JuiceShop GT':<14} | {'Auth':<6} | {'Scanner':<14} | {'Cat':<6}"
    print(header)
    print("-" * 80)

    tp_list, fp_list, tn_list, fn_list = [], [], [], []
    all_ids = sorted(JUICESHOP_GROUND_TRUTH.keys(), key=lambda x: int(x.split("-")[1]))
    for cid in all_ids:
        has_vuln, auth_req = JUICESHOP_GROUND_TRUTH[cid]
        title = _CHECK_TITLES.get(cid, cid)
        finding = findings_by_id.get(cid)
        scanner_detected = False
        scan_str = "NO DATA"
        if finding:
            sev = getattr(finding, "severity", "Info")
            cs = getattr(finding, "check_status", "SUCCESS")
            if cs == "UNREACHABLE":
                scan_str = "UNREACHABLE"
            elif sev != "Info":
                scanner_detected = True
                scan_str = "VULNERABLE"
            else:
                scan_str = "CLEAN"
        gt_str = "VULN" if has_vuln else "CLEAN"
        if has_vuln and scanner_detected:     cat = "TP"; tp_list.append(cid)
        elif not has_vuln and scanner_detected: cat = "FP"; fp_list.append(cid)
        elif not has_vuln and not scanner_detected: cat = "TN"; tn_list.append(cid)
        else:                                  cat = "FN"; fn_list.append(cid)
        print(f"{cid:<6} | {title:<32} | {gt_str:<14} | {auth_req:<6} | {scan_str:<14} | {cat:<6}")

    print("-" * 80)
    tp, fp, tn, fn = len(tp_list), len(fp_list), len(tn_list), len(fn_list)
    total = tp + fp + tn + fn
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    print(f"TP={tp} {tp_list}  FP={fp} {fp_list}  TN={tn} {tn_list}  FN={fn} {fn_list}  Total={total}/24")
    print(f"Precision={precision:.1f}%  Recall={recall:.1f}%  F1={f1:.1f}%")
    print()
    print("COMPARISON:")
    print(f"  DVWA unauth  (Phase 1) : Recall=15.4%  [baseline]")
    print(f"  DVWA auth    (Phase 2) : Recall=92.3%  [61.5% arch + 30.8% DVWA-specific]")
    print(f"  Juice Shop   (no tuning): Recall={recall:.1f}%  [architecture-only test]")
    print()
    if recall >= 50:
        print("-> Architecture GENERALIZES: recall >= 50% without per-app tuning")
    elif recall >= 25:
        print("-> PARTIAL generalization: some arch benefit, detection still narrow")
    else:
        print("-> Architecture does NOT generalize well beyond DVWA")
        print("   (expected if Juice Shop uses different response formats — JWT/JSON/SPA)")
    print("=" * 85)

if __name__ == "__main__":
    evaluate_juiceshop()
