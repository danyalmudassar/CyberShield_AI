"""
CyberShield AI — Threat Intelligence Contract Tests
=====================================================
Task 03: Verify that run_threat_intel does not fabricate CVE findings
when the tech stack is unknown in live mode, that the mock filename is
correct, and that LLM-sourced CVEs are marked UNVERIFIED_CANDIDATE.

All tests run entirely offline using unittest.mock to prevent network calls.
"""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.threat_intel_agent import run_threat_intel, MOCK_THREAT_PATH, _generate_cve_findings, _query_nvd_ai
from models import TechResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _recon_with_tech(tech_list):
    """Build recon_data dict using the legacy 'detected_technologies' dict key."""
    return {"tech": {"detected_technologies": tech_list}}


def _recon_with_tech_dataclass(tech_list):
    """Build recon_data dict using a real TechResult dataclass (field: .technologies).

    This is the path the real orchestrator takes — recon_agent returns a
    TechResult object, not a plain dict.
    """
    return {"tech": TechResult(technologies=tech_list, status="success")}


def _no_network(*args, **kwargs):
    raise RuntimeError("Network access not allowed in this test")


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestThreatContracts:

    def test_empty_stack_live_produces_zero_cve_findings(self):
        """Empty tech stack in live mode must produce zero CVE findings.

        Before the fix, an empty list triggered _query_nvd_ai which asked the
        LLM to 'identify known CVEs' without any evidence, producing fabricated
        findings. The guard must short-circuit both NVD and LLM calls.
        """
        with patch("agents.threat_intel_agent._query_nvd_online") as mock_nvd, \
             patch("agents.threat_intel_agent._query_nvd_ai") as mock_ai, \
             patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                recon_data=_recon_with_tech([]),  # no tech stack
                use_mock=False,
            )

        # Neither NVD nor LLM should have been called
        mock_nvd.assert_not_called()
        mock_ai.assert_not_called()

        # No CVE findings should be produced
        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        assert len(cve_findings) == 0, (
            f"Expected 0 CVE findings for unknown stack, got {len(cve_findings)}: "
            f"{[f.title for f in cve_findings]}"
        )

        # data_sources should reflect the no-stack state
        assert result["data_sources"]["threat_intel_nvd"] == "no_stack_detected"

    def test_known_stack_nvd_returns_results_tagged_external_api(self):
        """When NVD returns keyword search results they are tagged EXTERNAL_API and UNVERIFIED_CANDIDATE."""
        nvd_cve = [{
            "cve_id": "CVE-2023-1234",
            "severity": "High",
            "cvss": 8.1,
            "description": "Test vuln",
            "affected_software": "nginx 1.24.0",
            "_provenance": "EXTERNAL_API",
        }]

        with patch("agents.threat_intel_agent._query_nvd_online", return_value=nvd_cve), \
             patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                recon_data=_recon_with_tech(["nginx 1.24.0"]),
                use_mock=False,
            )

        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        assert len(cve_findings) == 1
        assert cve_findings[0].provenance == "EXTERNAL_API"
        assert cve_findings[0].check_status == "UNVERIFIED_CANDIDATE"

    def test_known_stack_nvd_empty_llm_tagged_unverified_candidate(self):
        """When NVD returns nothing, LLM is called; results must be UNVERIFIED_CANDIDATE."""
        llm_cve = [{
            "cve_id": "CVE-2022-9999",
            "severity": "Medium",
            "cvss": 6.5,
            "description": "LLM-suggested vuln",
            "affected_software": "nginx 1.24.0",
            "_provenance": "LLM_REASONING",
        }]

        with patch("agents.threat_intel_agent._query_nvd_online", return_value=[]), \
             patch("agents.threat_intel_agent._query_nvd_ai", return_value=llm_cve), \
             patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                recon_data=_recon_with_tech(["nginx 1.24.0"]),
                use_mock=False,
            )

        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        assert len(cve_findings) == 1
        assert cve_findings[0].provenance == "LLM_REASONING"
        assert cve_findings[0].check_status == "UNVERIFIED_CANDIDATE", (
            "LLM-sourced CVEs must not be presented as confirmed VULNERABLE findings"
        )

    def test_mock_mode_loads_correct_file(self):
        """Mock mode must load mock_threat_intel.json (not the wrong filename)."""
        # The MOCK_THREAT_PATH constant must point to the file that actually exists.
        assert os.path.exists(MOCK_THREAT_PATH), (
            f"Mock file not found at {MOCK_THREAT_PATH}. "
            "This was a known bug: code referenced mock_threat_response.json "
            "but the actual file is mock_threat_intel.json."
        )

    def test_mock_mode_findings_tagged_mock_fallback(self):
        """Findings from mock mode must be tagged MOCK_FALLBACK, not VULNERABLE."""
        with patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                recon_data=_recon_with_tech([]),
                use_mock=True,
            )

        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        for f in cve_findings:
            assert f.check_status == "MOCK_FALLBACK", (
                f"Finding {f.finding_id} in mock mode has check_status={f.check_status!r}, "
                "expected MOCK_FALLBACK"
            )

    def test_nvd_exception_produces_no_fabricated_findings(self):
        """If the NVD HTTP request fails, _query_nvd_online catches it internally
        and returns []. Thereafter _query_nvd_ai is called. If the LLM also
        returns [], no CVE findings should be produced.
        """
        with patch("agents.threat_intel_agent.service_get", side_effect=Exception("connection timeout")), \
             patch("agents.threat_intel_agent._query_nvd_ai", return_value=[]), \
             patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                recon_data=_recon_with_tech(["nginx 1.24.0"]),
                use_mock=False,
            )

        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        assert len(cve_findings) == 0, (
            f"Expected 0 CVE findings when NVD fails and LLM returns empty, "
            f"got {len(cve_findings)}: {[f.title for f in cve_findings]}"
        )

    def test_tech_result_dataclass_triggers_nvd_lookup(self):
        """TechResult.technologies (dataclass field) must be read, not only dict keys.

        Before the fix the extraction code read tech_info.get('detected_technologies')
        which silently returned [] for a TechResult object, so NVD was never called
        even when the tech stack was populated.
        """
        nvd_cve = [{
            "cve_id": "CVE-2023-9999",
            "severity": "High",
            "cvss": 8.0,
            "description": "Test vuln via TechResult",
            "affected_software": "Apache/2.4.51",
            "_provenance": "EXTERNAL_API",
        }]

        with patch("agents.threat_intel_agent._query_nvd_online", return_value=nvd_cve) as mock_nvd, \
             patch("agents.threat_intel_agent._query_virustotal_online", return_value={}), \
             patch("agents.threat_intel_agent._query_shodan_online", return_value={}):

            result = run_threat_intel(
                domain="example.com",
                # TechResult dataclass — field is .technologies, not a dict key
                recon_data=_recon_with_tech_dataclass(["Apache/2.4.51"]),
                use_mock=False,
            )

        # NVD must have been called with the tech list from the dataclass field
        mock_nvd.assert_called_once()
        nvd_args = mock_nvd.call_args[0][0]  # first positional arg: tech_versions
        assert "Apache/2.4.51" in nvd_args, (
            f"NVD call did not receive the correct tech list from TechResult.technologies: {nvd_args}"
        )

        cve_findings = [f for f in result["findings"] if f.check_id == "T-004"]
        assert len(cve_findings) == 1

    def test_llm_malformed_response_returns_empty_not_mock_cves(self):
        """_query_nvd_ai with a malformed LLM response must return [] in live mode.

        Before the fix, an unexpected LLM response (e.g. a plain string or dict
        without 'cve_matches') fell through to _load_mock_threat_data(), which
        returned mock CVEs tagged LLM_REASONING and treated as live findings.
        """
        # call_llm_json returns an unexpected structure (not list, not cve_matches dict)
        bad_llm_response = {"error": "LLM unavailable", "message": "timeout"}

        with patch("agents.threat_intel_agent.call_llm_json", return_value=bad_llm_response):
            result = _query_nvd_ai(
                tech_versions=["nginx 1.24.0"],
                use_mock=False,
                strict_live=False,
            )

        assert result == [], (
            f"Expected [] when LLM returns malformed response in live mode, "
            f"got {result!r} — this was the mock-CVE-injection bug"
        )

    def test_mock_provenance_finding_is_not_live_vulnerability(self):
        """Finding with provenance='MOCK_FALLBACK' must set check_status='MOCK_FALLBACK' and fail is_live_confirmed_vulnerability."""
        from models import Finding, is_live_confirmed_vulnerability

        mock_finding = Finding(
            finding_id="CYBERSHIELD-P006",
            check_id="P-006",
            title="Mock SQL Injection",
            severity="Critical",
            provenance="MOCK_FALLBACK",
        )

        assert mock_finding.check_status == "MOCK_FALLBACK", (
            f"Expected check_status='MOCK_FALLBACK' when provenance='MOCK_FALLBACK', got {mock_finding.check_status!r}"
        )
        assert is_live_confirmed_vulnerability(mock_finding) is False, (
            "is_live_confirmed_vulnerability must return False for MOCK_FALLBACK findings"
        )

    def test_empty_data_and_incomplete_not_live_vulnerability(self):
        """is_live_confirmed_vulnerability must return False for empty data, missing status, or INCOMPLETE status."""
        from models import is_live_confirmed_vulnerability

        assert is_live_confirmed_vulnerability(None) is False
        assert is_live_confirmed_vulnerability({}) is False
        assert is_live_confirmed_vulnerability({"severity": "Critical"}) is False
        assert is_live_confirmed_vulnerability({"check_status": "INCOMPLETE"}) is False
        assert is_live_confirmed_vulnerability({"check_status": "SAFE"}) is False
        assert is_live_confirmed_vulnerability({"check_status": "UNREACHABLE"}) is False

        # Only explicitly confirmed live findings return True
        live_finding = {"check_status": "VULNERABLE", "provenance": "OFFLINE_VERIFIER"}
        assert is_live_confirmed_vulnerability(live_finding) is True

    def test_errored_probe_llm_provenance_precedence(self):
        """An errored probe must keep severity='Info' and check_status='ERROR' even with LLM provenance."""
        from models import Finding

        errored_finding = Finding(
            finding_id="CYBERSHIELD-P001",
            check_id="P-001",
            title="Errored Probe",
            severity="Critical",
            check_status="ERROR",
            provenance="LLM_REASONING",
        )

        assert errored_finding.severity == "Info", f"Expected severity 'Info' for errored probe, got {errored_finding.severity!r}"
        assert errored_finding.check_status == "ERROR", f"Expected check_status 'ERROR' for errored probe, got {errored_finding.check_status!r}"

    def test_udp_sendto_blocked_by_network_guard(self):
        """Unconnected UDP socket.sendto must raise RuntimeError via the autouse block_outbound fixture."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with pytest.raises(RuntimeError, match="Network access is not allowed"):
            sock.sendto(b"probe", ("8.8.8.8", 53))
        sock.close()

    def test_unix_socketpair_allowed_by_network_guard(self):
        """Local AF_UNIX socketpairs must be allowed for asyncio thread wakeups."""
        import socket
        if hasattr(socket, "AF_UNIX"):
            s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            s1.send(b"wakeup")
            msg = s2.recv(1024)
            assert msg == b"wakeup"
            s1.close()
            s2.close()
