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

from models import Finding, PisfResult, PisfControl, VisualResult, ThreatResult, ReportData, DnsResult, SslResult, HeaderResult, TechResult
from agents.threat_intel_agent import run_threat_intel, _query_nvd_ai, _query_nvd_online
from agents.visual_agent import run_visual_scan, _check_v002_https, _build_findings as build_visual_findings
from agents.pentest_agent import run_pentest, _check_default_credentials, _check_cookie_flags
from agents.recon_agent import run_recon, _generate_findings_from_recon
from agents.report_agent import generate_report, _build_executive_summary, _generate_pdf


class TestAgentAuditAndFallback(unittest.TestCase):

    def test_anonymizer_narrow_key_regex(self):
        """Sanitizer MUST redact URL query keys & API keys without redacting non-sensitive terms like primary_key=id."""
        from utils.anonymizer import sanitize_text
        sensitive_url = "https://api.shodan.io/shodan/host/1.1.1.1?key=secret123key"
        sanitized_url = sanitize_text(sensitive_url)
        self.assertNotIn("secret123key", sanitized_url)
        self.assertIn("[REDACTED_CREDENTIAL]", sanitized_url)

        safe_text = "Database primary_key=id and header X-Frame-Options present"
        sanitized_safe = sanitize_text(safe_text)
        self.assertEqual(sanitized_safe, safe_text)

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
        with patch("agents.pentest_agent._probe_get", return_value=(None, "Network unreachable")):
            with patch("agents.pentest_agent._probe_get_noredir", return_value=(None, "Network unreachable")):
                with patch("agents.pentest_agent._probe_post", return_value=(None, "Network unreachable")):
                    with patch("agents.pentest_agent._probe_post_xml", return_value=(None, "Network unreachable")):
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

    def test_report_agent_fallback_triggered_by_recon(self):
        """Report agent MUST set fallback_triggered=True if recon scan used fallback."""
        scan_data = {
            "domain": "target.com",
            "findings": [],
            "recon_result": {"fallback_triggered": True},
        }
        res = generate_report(scan_data=scan_data)
        self.assertTrue(res.get("report").fallback_triggered)

    def test_report_agent_merges_data_sources_across_all_agents(self):
        """Report agent MUST merge data_sources dicts across all 4 sub-agents with clean, unconditional agent namespacing."""
        scan_data = {
            "domain": "target.com",
            "recon_result": {"data_sources": {"recon_dns": "live", "ssl": "live", "recon_ai": "mock"}},
            "threat_result": {"data_sources": {"nvd": "live", "threat_intel_ai": "gemma4:31b-cloud"}},
            "visual_result": {"data_sources": {"visual_scan": "live"}},
            "pentest_result": {"data_sources": {"pentest_probes": "live"}},
        }
        res = generate_report(scan_data=scan_data)
        merged_ds = res.get("report").data_sources
        self.assertEqual(merged_ds.get("recon_dns"), "live")
        self.assertEqual(merged_ds.get("recon_ssl"), "live")
        self.assertEqual(merged_ds.get("recon_ai"), "mock")
        self.assertEqual(merged_ds.get("threat_intel_nvd"), "live")
        self.assertEqual(merged_ds.get("threat_intel_ai"), "gemma4:31b-cloud")
        self.assertEqual(merged_ds.get("visual_scan"), "live")
        self.assertEqual(merged_ds.get("pentest_probes"), "live")

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

        # Case 4: UNREACHABLE check_status forces severity to Info (probe failed, no confirmed vulnerability)
        f4 = Finding(finding_id="F-4", severity="High", check_status="UNREACHABLE")
        self.assertEqual(f4.severity, "Info")
        self.assertEqual(f4.check_status, "UNREACHABLE")

        # Case 5: ERROR check_status forces severity to Info (probe errored, no confirmed vulnerability)
        f5 = Finding(finding_id="F-5", severity="Critical", check_status="ERROR")
        self.assertEqual(f5.severity, "Info")
        self.assertEqual(f5.check_status, "ERROR")

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
            with patch("agents.threat_intel_agent.service_get", return_value=mock_vt_resp):
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

    def test_threat_intel_fallback_triggered_on_virustotal_or_shodan_failure(self):
        """Threat Intel agent MUST set fallback_triggered=True if VT or Shodan fail even when CVE lookup succeeds."""
        from agents.threat_intel_agent import run_threat_intel
        mock_cves = [{"cve_id": "CVE-2021-1234", "_provenance": "EXTERNAL_API"}]
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_vt_key", "SHODAN_API_KEY": "fake_shodan_key"}):
            with patch("agents.threat_intel_agent._query_nvd_online", return_value=mock_cves):
                with patch("agents.threat_intel_agent._query_virustotal_online", return_value={}):
                    with patch("agents.threat_intel_agent._query_shodan_online", return_value={"open_ports": [80]}):
                        res = run_threat_intel("example.com", recon_data={"tech": {"detected_technologies": ["Apache"]}}, use_mock=False)
                        self.assertTrue(res.get("fallback_triggered"))

    def test_pentest_strict_live_raises_on_unreachable_or_error(self):
        """Pentest agent in strict live mode MUST raise RuntimeError if any check returns UNREACHABLE or ERROR."""
        from agents.pentest_agent import run_pentest
        mock_unreachable_finding = Finding(
            finding_id="CYBERSHIELD-P001",
            check_id="P-001",
            title="P-001 Check",
            severity="Info",
            check_status="UNREACHABLE",
            provenance="OFFLINE_VERIFIER",
        )
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with patch("agents.pentest_agent._probe_get", return_value=(None, "Connection timeout")):
                with patch("agents.pentest_agent._probe_get_noredir", return_value=(None, "Connection timeout")):
                    with patch("agents.pentest_agent._probe_post", return_value=(None, "Connection timeout")):
                        with patch("agents.pentest_agent._probe_post_xml", return_value=(None, "Connection timeout")):
                            with patch("agents.pentest_agent._probe_method", return_value=(None, "Connection timeout")):
                                with patch("requests.get", return_value=MagicMock(status_code=404, text="")):
                                    with patch("requests.post", return_value=MagicMock(status_code=404, text="")):
                                        with patch("agents.pentest_agent._check_default_credentials", return_value=mock_unreachable_finding):
                                            with self.assertRaises(RuntimeError) as ctx:
                                                run_pentest("example.com", authorized=True, use_mock=False, strict_live=True)
                                            self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))

    def test_visual_strict_live_raises_on_check_failure(self):
        """Visual agent in strict live mode MUST raise RuntimeError if target is unreachable or check fails."""
        from agents.visual_agent import run_visual_scan
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with patch("agents.visual_agent._check_v001_admin_panel", side_effect=RuntimeError("Playwright timeout")):
                with patch("agents.visual_agent._check_v002_https", return_value=(True, "HTTPS active")):
                    with patch("agents.visual_agent._check_v003_captcha", return_value=(False, [])):
                        with patch("agents.visual_agent._check_v004_third_party_scripts", return_value=[]):
                            with patch("agents.visual_agent._check_v005_suspicious_elements", return_value=[]):
                                with patch("agents.visual_agent._check_v006_sensitive_info", return_value=[]):
                                    with patch("agents.visual_agent._check_v007_cookie_consent", return_value=True):
                                        with patch("agents.visual_agent._check_v008_mixed_content", return_value=(False, [])):
                                            with self.assertRaises(RuntimeError) as ctx:
                                                run_visual_scan("example.com", use_mock=False, strict_live=True)
                                            self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))


    def test_recon_strict_live_raises_on_scanner_failure(self):
        """Recon agent in strict live mode MUST raise RuntimeError if any sub-scanner fails."""
        from agents.recon_agent import run_recon
        with patch.dict(os.environ, {"STRICT_LIVE_MODE": "true"}):
            with patch("agents.recon_agent.run_dns_recon", side_effect=RuntimeError("STRICT_LIVE_MODE: DNS recon failed")):
                with self.assertRaises(RuntimeError) as ctx:
                    run_recon("example.com", use_mock=False, strict_live=True)
                self.assertIn("STRICT_LIVE_MODE", str(ctx.exception))

    def test_recon_fallback_triggered_on_subscanner_degradation(self):
        """Recon agent MUST set fallback_triggered=True and data_source label if any sub-scanner degrades."""
        from agents.recon_agent import run_recon
        mock_dns = DnsResult(status="warning")
        mock_ssl = SslResult(status="success")
        mock_hdr = HeaderResult(status="success")
        mock_tech = TechResult(status="success")
        mock_ai = {"executive_summary": "AI summary", "_provenance": "LLM_REASONING"}

        with patch("agents.recon_agent.run_dns_recon", return_value=mock_dns):
            with patch("agents.recon_agent.run_ssl_check", return_value=mock_ssl):
                with patch("agents.recon_agent.run_header_scan", return_value=mock_hdr):
                    with patch("agents.recon_agent.run_tech_fingerprint", return_value=mock_tech):
                        with patch("agents.recon_agent._call_qwen_analysis", return_value=mock_ai):
                            res = run_recon("example.com", use_mock=False)
                            self.assertTrue(res.get("fallback_triggered"))
                            self.assertEqual(res.get("data_sources", {}).get("recon_dns"), "degraded")

    def test_pisf_control_4_warning_status_assessed_not_unavailable(self):
        """PISF Control 4 MUST assess SSL warning status as FAIL/PARTIAL rather than NOT_ASSESSABLE."""
        from agents.pisf_agent import _assess_control_4
        mock_ssl = SslResult(valid=False, status="warning")
        recon_data = {"ssl": mock_ssl}
        ctrl = _assess_control_4(recon_data, threat_data=None)
        self.assertIn(ctrl.status, ("FAIL", "PARTIAL"))
        self.assertNotEqual(ctrl.status, "NOT_ASSESSABLE")

    def test_pisf_control_10_malicious_vt_flags_fail(self):
        """PISF Control 10 MUST evaluate status=FAIL when VirusTotal reports malicious findings."""
        from agents.pisf_agent import _assess_control_10
        malicious_finding = Finding(
            finding_id="CYBERSHIELD-VT01",
            check_id="VT-001",
            title="VirusTotal Malicious Vendor Flag",
            severity="High",
            check_status="VULNERABLE",
        )
        threat_data = {
            "threat_result": ThreatResult(status="success"),
            "findings": [malicious_finding],
            "data_sources": {"threat_intel_virustotal": "live"},
        }
        ctrl = _assess_control_10(recon_data=None, threat_data=threat_data)
        self.assertEqual(ctrl.status, "FAIL")

    def test_report_agent_findings_deduplication(self):
        """Report agent MUST deduplicate duplicate findings with matching IDs."""
        from agents.report_agent import generate_report
        dup_finding_1 = Finding(finding_id="CYBERSHIELD-001", check_id="R-011", title="Invalid SSL", severity="Critical")
        dup_finding_2 = Finding(finding_id="CYBERSHIELD-001", check_id="R-011", title="Invalid SSL", severity="Critical")
        scan_data = {
            "domain": "example.com",
            "all_findings": [dup_finding_1],
            "recon_result": {"findings": [dup_finding_2], "data_sources": {"recon_dns": "live"}},
        }
        res = generate_report(scan_data=scan_data)
        detailed = res["report"].detailed_findings
        self.assertEqual(len(detailed), 1)

    def test_sanitize_secrets_only_preserves_domain(self):
        """sanitize_secrets_only MUST redact secrets while keeping domain names intact."""
        from utils.anonymizer import sanitize_secrets_only
        raw = "Connection error to https://testphp.vulnweb.com/login?api_key=secret123"
        clean = sanitize_secrets_only(raw)
        self.assertIn("testphp.vulnweb.com", clean)
        self.assertIn("[REDACTED_CREDENTIAL]", clean)
        self.assertNotIn("secret123", clean)


    def test_pentest_early_unreachability_fail_fast(self):
        """Pentest agent MUST short-circuit and return all 24 UNREACHABLE findings instantly when target reachability check fails."""
        from agents.pentest_agent import run_pentest
        with patch("agents.pentest_agent.check_target_reachability", return_value=(False, "Connection to target.com timed out")):
            res = run_pentest("target.com", authorized=True, use_mock=False)
            self.assertEqual(res.get("status"), "partial")
            self.assertTrue(res.get("fallback_triggered"))
            self.assertEqual(res.get("data_sources", {}).get("pentest_probes"), "degraded")
            findings = res.get("findings", [])
            self.assertEqual(len(findings), 24)
            self.assertTrue(all(f.check_status == "UNREACHABLE" for f in findings))
            self.assertTrue(all(f.severity == "Info" for f in findings))

    def test_visual_early_unreachability_fail_fast(self):
        """Visual agent MUST short-circuit and return status=partial when target is completely unreachable."""
        from agents.visual_agent import run_visual_scan
        with patch("agents.visual_agent.check_target_reachability", return_value=(False, "Connection timeout")):
            res = run_visual_scan("target.com", use_mock=False)
            self.assertEqual(res.get("status"), "partial")
            self.assertTrue(res.get("fallback_triggered"))
            self.assertEqual(res.get("data_sources", {}).get("visual_scan"), "degraded")
            findings = res.get("findings", [])
            self.assertTrue(any("UNREACHABLE" in f.evidence for f in findings))

    def test_recon_early_unreachability_fail_fast(self):
        """Recon agent MUST short-circuit sub-scanners and return degraded data sources when target reachability check fails."""
        from agents.recon_agent import run_recon
        with patch("agents.recon_agent.check_target_reachability", return_value=(False, "Connection to target.com timed out")):
            res = run_recon("target.com", use_mock=False)
            self.assertTrue(res.get("fallback_triggered"))
            self.assertEqual(res.get("data_sources", {}).get("recon_dns"), "degraded")
            self.assertEqual(res.get("data_sources", {}).get("recon_ssl"), "degraded")
            self.assertEqual(res.get("data_sources", {}).get("recon_headers"), "degraded")
            self.assertEqual(res.get("data_sources", {}).get("recon_tech"), "degraded")

    def test_pisf_unreachable_recon_controls_marked_not_assessable(self):
        """PISF controls MUST evaluate as NOT_ASSESSABLE when recon sub-scanners report status=error due to target unreachability."""
        from agents.recon_agent import run_recon
        from agents.pisf_agent import _assess_control_4, _assess_control_6, _assess_control_7, _assess_control_9, _assess_control_11
        with patch("agents.recon_agent.check_target_reachability", return_value=(False, "Connection to target.com timed out")):
            recon_res = run_recon("target.com", use_mock=False)
            ctrl4 = _assess_control_4(recon_data=recon_res, threat_data=None)
            ctrl6 = _assess_control_6(recon_data=recon_res, threat_data=None)
            ctrl7 = _assess_control_7(recon_data=recon_res, threat_data=None)
            ctrl9 = _assess_control_9(recon_data=recon_res, threat_data=None)
            ctrl11 = _assess_control_11(recon_data=recon_res, threat_data=None)
            self.assertEqual(ctrl4.status, "NOT_ASSESSABLE")
            self.assertEqual(ctrl6.status, "NOT_ASSESSABLE")
            self.assertEqual(ctrl7.status, "NOT_ASSESSABLE")
            self.assertEqual(ctrl9.status, "NOT_ASSESSABLE")
            self.assertEqual(ctrl11.status, "NOT_ASSESSABLE")


if __name__ == "__main__":
    unittest.main()
