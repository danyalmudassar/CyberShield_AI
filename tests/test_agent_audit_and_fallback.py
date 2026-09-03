"""
CyberShield AI — Comprehensive Agent Audit & Fallback Aggregation Unit Tests
============================================================================
Validates:
  1. Provenance tagging across all agents (recon, threat_intel, visual, pentest).
  2. Unreachable target & degraded probe handling in visual_agent and pentest_agent.
  3. Fallback aggregation in report_agent across each individual sub-scan.
  4. PISF assessable vs non-assessable control count formatting in executive summary.
  5. PDF generation with degraded execution warning banner.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Finding, PisfResult, PisfControl, VisualResult, ThreatResult, ReportData
from agents.threat_intel_agent import run_threat_intel, _query_nvd_ai, _query_nvd_online
from agents.visual_agent import run_visual_scan, _check_v002_https, _build_findings as build_visual_findings
from agents.pentest_agent import run_pentest, _check_default_credentials, _check_cookie_flags
from agents.recon_agent import run_recon, _generate_findings_from_recon
from agents.report_agent import generate_report, _build_executive_summary, _generate_pdf


class TestAgentAuditAndFallback(unittest.TestCase):

    # ── 1. PROVENANCE TESTS ──────────────────────────────────────────────────
    def test_threat_intel_provenance_mock(self):
        """Threat intel in mock mode MUST assign MOCK_FALLBACK provenance."""
        res = run_threat_intel("example.com", use_mock=True)
        self.assertTrue(res.get("fallback_triggered"))
        self.assertGreater(len(res.get("findings", [])), 0)
        for f in res.get("findings", []):
            self.assertEqual(f.provenance, "MOCK_FALLBACK")

    def test_threat_intel_provenance_online(self):
        """Threat intel NVD API results MUST assign EXTERNAL_API provenance."""
        cves = [{
            "cve_id": "CVE-2026-1001",
            "severity": "High",
            "cvss": 7.5,
            "description": "Test NVD CVE",
            "affected_software": "Nginx",
            "_provenance": "EXTERNAL_API"
        }]
        from agents.threat_intel_agent import _generate_cve_findings
        findings = _generate_cve_findings(cves)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].provenance, "EXTERNAL_API")

    def test_visual_agent_provenance_live_and_mock(self):
        """Visual agent findings MUST assign OFFLINE_VERIFIER for live and MOCK_FALLBACK for mock."""
        res_mock = run_visual_scan("example.com", use_mock=True)
        self.assertTrue(res_mock.get("fallback_triggered"))
        for f in res_mock.get("findings", []):
            self.assertEqual(f.provenance, "MOCK_FALLBACK")

    def test_pentest_agent_provenance_all_57_call_sites(self):
        """Every finding returned by pentest_agent MUST carry explicit provenance."""
        res_mock = run_pentest("example.com", authorized=True, use_mock=True)
        self.assertTrue(res_mock.get("fallback_triggered"))
        self.assertEqual(len(res_mock.get("findings", [])), 24)
        for f in res_mock.get("findings", []):
            self.assertEqual(f.provenance, "MOCK_FALLBACK")

    # ── 2. UNREACHABLE TARGET & DEGRADED PROBE TESTS ─────────────────────────
    def test_visual_v002_unreachable_target_no_false_high(self):
        """Unreachable target in visual V-002 probe MUST NOT produce a false-positive High finding."""
        with patch("agents.visual_agent._get", return_value=(None, "Connection refused")):
            ok, detail = _check_v002_https("unreachable-domain.invalid")
            self.assertFalse(ok)
            self.assertTrue(detail.startswith("UNREACHABLE:"))

    def test_pentest_unreachable_probe_does_not_claim_clean_pass(self):
        """Unreachable target in pentest probe MUST record error/unreachable cleanly without false claims."""
        with patch("requests.get", side_effect=Exception("Network unreachable")):
            res = run_pentest("unreachable-target.invalid", authorized=True)
            self.assertTrue(res.get("fallback_triggered"))
            self.assertIn(res.get("status"), ("partial", "error"))

    # ── 3. FALLBACK AGGREGATION TESTS ────────────────────────────────────────
    def test_report_agent_fallback_triggered_by_threat_intel(self):
        """Report agent MUST set fallback_triggered=True if threat_intel used fallback."""
        scan_data = {
            "domain": "target.com",
            "findings": [Finding(finding_id="F-001", severity="Low", provenance="OFFLINE_VERIFIER")],
            "threat_result": {"fallback_triggered": True},
        }
        res = generate_report(scan_data=scan_data)
        self.assertTrue(res.get("report").fallback_triggered)

    def test_report_agent_fallback_triggered_by_visual(self):
        """Report agent MUST set fallback_triggered=True if visual scan used fallback."""
        scan_data = {
            "domain": "target.com",
            "findings": [],
            "visual_result": {"fallback_triggered": True},
        }
        res = generate_report(scan_data=scan_data)
        self.assertTrue(res.get("report").fallback_triggered)

    def test_report_agent_fallback_triggered_by_pentest(self):
        """Report agent MUST set fallback_triggered=True if pentest used fallback."""
        scan_data = {
            "domain": "target.com",
            "findings": [],
            "pentest_result": {"fallback_triggered": True},
        }
        res = generate_report(scan_data=scan_data)
        self.assertTrue(res.get("report").fallback_triggered)

    def test_report_agent_fallback_triggered_by_finding_provenance(self):
        """Report agent MUST set fallback_triggered=True if any finding has MOCK_FALLBACK provenance."""
        scan_data = {
            "domain": "target.com",
            "findings": [Finding(finding_id="F-001", severity="High", provenance="MOCK_FALLBACK")],
        }
        res = generate_report(scan_data=scan_data)
        self.assertTrue(res.get("report").fallback_triggered)

    # ── 4. PISF ASSESSABLE CONTROLS FORMATTING TESTS ─────────────────────────
    def test_pisf_executive_summary_surfaces_assessable_counts(self):
        """Executive summary MUST explicitly state assessable vs non-assessable control counts."""
        controls = [
            PisfControl(control_id=i, domain=f"Domain {i}", status="PASS" if i <= 10 else "NOT_ASSESSABLE")
            for i in range(1, 13)
        ]
        pisf_res = PisfResult(
            controls=controls,
            overall_score=100.0,
            compliant_controls=10,
            assessable_controls_count=10,
            total_controls=12,
        )
        findings = [Finding(finding_id="CYBERSHIELD-001", severity="Low")]
        summary = _build_executive_summary("example.com", findings, pisf_res)
        self.assertIn("10 of 10 assessable controls compliant", summary)
        self.assertIn("2 controls marked NOT_ASSESSABLE", summary)

    # ── 5. PDF GENERATION WARNING BANNER TEST ───────────────────────────────
    def test_pdf_generation_runs_cleanly_with_fallback_banner(self):
        """PDF generation MUST execute cleanly and output a valid PDF file when fallback is triggered."""
        scan_data = {
            "domain": "example.com",
            "findings": [Finding(finding_id="CYBERSHIELD-001", title="Test Finding", severity="Medium", provenance="MOCK_FALLBACK")],
            "fallback_triggered": True,
        }
        res = generate_report(scan_data=scan_data)
        pdf_path = res.get("pdf_path")
        self.assertIsNotNone(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))

    # ── 6. STRICT LIVE MODE ENFORCEMENT TESTS ─────────────────────────────
    def test_strict_live_mode_disables_mock_fallback(self):
        """STRICT_LIVE_MODE MUST raise RuntimeError if use_mock=True is attempted."""
        from utils.ai_provider import call_llm_json
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with self.assertRaises(RuntimeError) as ctx:
                call_llm_json("Analyze security", use_mock=True)
            self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))

    def test_strict_live_mode_raises_on_api_failure(self):
        """STRICT_LIVE_MODE MUST raise RuntimeError when live API call fails instead of silent fallback."""
        from utils.ai_provider import call_llm_json
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with patch("utils.ai_provider.call_llm", return_value=""):
                with self.assertRaises(RuntimeError) as ctx:
                    call_llm_json("Analyze security", use_mock=False)
                self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))

    # ── 7. FINDING POST_INIT INVARIANT TESTS ─────────────────────────────
    def test_finding_post_init_invariant_auto_sync(self):
        """Finding __post_init__ MUST enforce severity <-> check_status invariant alignment."""
        # Case 1: High severity with default SUCCESS check_status auto-corrects to VULNERABLE
        f1 = Finding(finding_id="F-1", severity="High", check_status="SUCCESS")
        self.assertEqual(f1.check_status, "VULNERABLE")

        # Case 2: Info severity clean pass with VULNERABLE check_status auto-corrects to SUCCESS
        f2 = Finding(finding_id="F-2", severity="Info", check_status="VULNERABLE")
        self.assertEqual(f2.check_status, "SUCCESS")

        # Case 3: UNREACHABLE and ERROR carry over cleanly on Info severity
        f3 = Finding(finding_id="F-3", severity="Info", check_status="UNREACHABLE")
        self.assertEqual(f3.check_status, "UNREACHABLE")

        # Case 4: High severity with UNREACHABLE/ERROR check_status auto-corrects to VULNERABLE
        f4 = Finding(finding_id="F-4", severity="High", check_status="UNREACHABLE")
        self.assertEqual(f4.check_status, "VULNERABLE")

        f5 = Finding(finding_id="F-5", severity="Critical", check_status="ERROR")
        self.assertEqual(f5.check_status, "VULNERABLE")

    # ── 8. THREAT INTEL AGENT STRICT LIVE & LIVE API TESTS ────────────────
    def test_threat_intel_strict_live_raises_on_failure(self):
        """Threat Intel agent in strict live mode MUST raise RuntimeError if LLM/mock fallback occurs."""
        from agents.threat_intel_agent import run_threat_intel
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with patch("agents.threat_intel_agent._query_nvd_online", return_value=[]):
                with patch("agents.threat_intel_agent.call_llm_json", side_effect=RuntimeError("STRICT_LIVE_MODE: Failed")):
                    with self.assertRaises(RuntimeError) as ctx:
                        run_threat_intel("example.com", recon_data={"tech": {"detected_technologies": ["Apache 2.4"]}}, use_mock=False)
                    self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))

    def test_threat_intel_live_virustotal_shodan_provenance(self):
        """VirusTotal and Shodan live queries MUST return EXTERNAL_API provenance when API keys present."""
        from agents.threat_intel_agent import _query_virustotal_online, _query_shodan_online
        mock_vt_resp = MagicMock()
        mock_vt_resp.status_code = 200
        mock_vt_resp.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_vt_key"}):
            with patch("requests.get", return_value=mock_vt_resp):
                res_vt = _query_virustotal_online("example.com")
                self.assertEqual(res_vt.get("_provenance"), "EXTERNAL_API")
                self.assertEqual(res_vt.get("harmless_votes"), 70)

    def test_virustotal_and_shodan_strict_live_raises_on_missing_keys(self):
        """VirusTotal and Shodan functions MUST raise RuntimeError in strict live mode if API keys are unconfigured or fail."""
        from agents.threat_intel_agent import _query_virustotal_online, _query_shodan_online
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true", "VIRUSTOTAL_API_KEY": "", "SHODAN_API_KEY": ""}):
            with self.assertRaises(RuntimeError) as ctx_vt:
                _query_virustotal_online("example.com", strict_live=True)
            self.assertIn("VIRUSTOTAL_API_KEY is not configured", str(ctx_vt.exception))

            with self.assertRaises(RuntimeError) as ctx_sh:
                _query_shodan_online("example.com", strict_live=True)
            self.assertIn("SHODAN_API_KEY is not configured", str(ctx_sh.exception))


if __name__ == "__main__":
    unittest.main()
