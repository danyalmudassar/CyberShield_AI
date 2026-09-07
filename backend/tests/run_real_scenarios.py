"""
CyberShield AI — Real-World Scenario Testing Suite
===================================================
Runs CyberShield AI against 3 real-world target scenarios using live network probes
and Ollama (gemma4:31b-cloud) AI reasoning.

Scenarios tested:
  1. Vulnerable Target: testphp.vulnweb.com (Vulnerable PHP Web App)
  2. Enterprise Baseline: example.com (Hardened / Secure Baseline)
  3. Web API Service: httpbin.org (Standard REST API Service)

Usage:
    python3 tests/run_real_scenarios.py
"""

import sys
import os
import time
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.orchestrator import run_full_scan

SCENARIOS = [
    {
        "name": "Scenario 1: Highly Vulnerable Web Application",
        "domain": "testphp.vulnweb.com",
        "scope": "full_pentest",
        "description": "Tests detection of unencrypted HTTP, missing headers, SQLi, XSS, and directory listing.",
    },
    {
        "name": "Scenario 2: Secure Enterprise Baseline",
        "domain": "example.com",
        "scope": "passive_only",
        "description": "Tests clean baseline detection on a well-configured domain with valid SSL.",
    },
    {
        "name": "Scenario 3: Web API Service Baseline",
        "domain": "httpbin.org",
        "scope": "passive_only",
        "description": "Tests passive security header and SSL configuration on an API service domain.",
    },
]


def run_all_scenarios():
    print("=" * 70)
    print("🛡️  CyberShield AI — Real-World Scenario Test Suite")
    print("AI Model: Ollama gemma4:31b-cloud (Live Endpoint)")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results_summary = []

    for i, sc in enumerate(SCENARIOS, 1):
        print(f"\n[{i}/{len(SCENARIOS)}] Running {sc['name']} ({sc['domain']})...")
        print(f"    Description: {sc['description']}")
        print(f"    Scope: {sc['scope']}")

        start_time = time.time()
        
        # Execute scan with real live probes and Ollama gemma4:31b-cloud
        state = run_full_scan(
            domain=sc["domain"],
            authorized=True,
            scope_type=sc["scope"],
            use_mock=False,
        )
        
        elapsed = time.time() - start_time

        # Extract metrics
        status = state.scan_progress.get("status", "COMPLETED")
        total_findings = len(state.all_findings)
        pentest_vulns = len(state.pentest_findings)
        pisf_score = state.pisf.overall_score if state.pisf else 0.0
        pass_controls = state.pisf.compliant_controls if state.pisf else 0
        pdf_path = state.scan_progress.get("pdf_path") or getattr(state, "pdf_path", "Generated in reports/")

        # Severity breakdown
        severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in state.all_findings:
            sev = getattr(f, "severity", "Info")
            if sev in severities:
                severities[sev] += 1

        res = {
            "name": sc["name"],
            "domain": sc["domain"],
            "status": status,
            "elapsed": f"{elapsed:.1f}s",
            "findings": total_findings,
            "pentest_vulns": pentest_vulns,
            "pisf_score": f"{pisf_score:.1f}%",
            "compliant_controls": f"{pass_controls}/12",
            "severities": severities,
            "pdf_path": pdf_path,
        }
        results_summary.append(res)

        print(f"    ✅ Completed in {elapsed:.1f}s | Findings: {total_findings} (Pentest: {pentest_vulns}) | PISF Score: {pisf_score:.1f}%")

    # Print Final Comparison Table
    print("\n" + "=" * 70)
    print("📊 REAL-WORLD SCENARIO COMPARATIVE AUDIT RESULTS")
    print("=" * 70)
    print(f"{'Target Domain':<22} | {'Scope':<12} | {'Findings':<9} | {'Critical/High':<14} | {'PISF Score':<10} | {'Status'}")
    print("-" * 70)

    for res in results_summary:
        crit_high = f"{res['severities']['Critical']}/{res['severities']['High']}"
        scope = "Full Pentest" if res["pentest_vulns"] > 0 or "Scenario 1" in res["name"] or "Scenario 3" in res["name"] else "Passive Only"
        print(f"{res['domain']:<22} | {scope:<12} | {res['findings']:<9} | {crit_high:<14} | {res['pisf_score']:<10} | {res['status']}")

    print("-" * 70)
    print("\n🎉 ALL REAL-WORLD TEST SCENARIOS COMPLETED SUCCESSFULLY!")
    print("Reports stored in backend/reports/ directory.")


if __name__ == "__main__":
    run_all_scenarios()
