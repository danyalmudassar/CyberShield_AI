"""
CyberShield AI — Execution Mode & Provenance Isolation Tests
============================================================
Task 04: Verify live, rules_only, and demo execution modes, strict-live
failure propagation, and ensure live failures never substitute demo fixtures.
Tests run through real agent code while mocking network/provider boundaries.
"""

import sys
import os
from unittest.mock import patch, MagicMock
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.orchestrator import run_full_scan
from agents.recon_agent import run_recon
from agents.threat_intel_agent import run_threat_intel
from utils.ssl_checker import run_ssl_check
from utils.ai_provider import call_llm_json
from models import ScanState, Finding, DnsResult, SslResult, HeaderResult, TechResult


def test_invalid_execution_mode_raises_value_error():
    """Passing an invalid execution_mode must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid execution_mode"):
        run_full_scan(
            domain="example.com",
            authorized=True,
            execution_mode="unauthorized_mode",
        )


def test_demo_mode_executes_offline_fixtures():
    """Demo mode must run with use_mock=True, make 0 network calls, and tag findings MOCK_FALLBACK."""
    state = run_full_scan(
        domain="example.com",
        authorized=True,
        execution_mode="demo",
    )

    assert state.execution_mode == "demo"
    assert state.scan_progress["status"] == "COMPLETED"

    # All findings produced in demo mode must carry MOCK_FALLBACK provenance
    mock_findings = [f for f in state.all_findings if f.provenance == "MOCK_FALLBACK"]
    assert len(mock_findings) > 0, "Demo mode must produce MOCK_FALLBACK findings"
    assert len(state.all_findings) == len(mock_findings), (
        "All findings in demo mode must carry MOCK_FALLBACK provenance"
    )


def test_demo_mode_raises_in_strict_live():
    """Demo mode execution must raise RuntimeError if strict_live is enabled."""
    with pytest.raises(RuntimeError, match="STRICT_LIVE_MODE"):
        run_full_scan(
            domain="example.com",
            authorized=True,
            execution_mode="demo",
            strict_live=True,
        )


def test_rules_only_mode_executes_zero_ai_calls():
    """Real recon and threat intel agent code in rules_only mode must make ZERO AI calls."""
    with patch("agents.recon_agent.check_target_reachability", return_value=(True, "")), \
         patch("agents.recon_agent.run_dns_recon", return_value=DnsResult(status="success")), \
         patch("agents.recon_agent.run_ssl_check", return_value=SslResult(valid=True, status="success")), \
         patch("agents.recon_agent.run_header_scan", return_value=HeaderResult(status="success")), \
         patch("agents.recon_agent.run_tech_fingerprint", return_value=TechResult(status="success")), \
         patch("utils.ai_provider.call_llm_json") as mock_ai:

        recon_res = run_recon("example.com", use_mock=False, strict_live=False, use_ai=False)

        assert mock_ai.call_count == 0, f"Expected 0 AI calls in rules_only mode, got {mock_ai.call_count}"
        assert recon_res["ai_analysis"]["_provenance"] == "DETERMINISTIC_RULES"
        assert recon_res["data_sources"]["recon_ai"] == "disabled"

        threat_res = run_threat_intel("example.com", recon_data=recon_res, use_mock=False, strict_live=False, use_ai=False)
        assert mock_ai.call_count == 0
        assert threat_res["data_sources"]["threat_intel_ai"] == "disabled"


def test_live_mode_failure_never_loads_fixtures():
    """When a live probe or LLM provider call fails, fixture loading is suppressed."""
    with patch("agents.recon_agent.check_target_reachability", return_value=(True, "")), \
         patch("agents.recon_agent.run_dns_recon", return_value=DnsResult(status="error")), \
         patch("agents.recon_agent.run_ssl_check", return_value=SslResult(valid=False, status="error")), \
         patch("agents.recon_agent.run_header_scan", return_value=HeaderResult(status="error")), \
         patch("agents.recon_agent.run_tech_fingerprint", return_value=TechResult(status="error")), \
         patch("utils.ai_provider.call_llm", return_value=""):

        recon_res = run_recon("example.com", use_mock=False, strict_live=False, use_ai=True)

        # Confirm no fixture findings with MOCK_FALLBACK were returned
        mock_findings = [f for f in recon_res["findings"] if getattr(f, "provenance", "") == "MOCK_FALLBACK"]
        assert len(mock_findings) == 0, "Live failures must not inject MOCK_FALLBACK findings"
        assert recon_res["ai_analysis"].get("_provenance") != "MOCK_FALLBACK"


def test_strict_live_propagates_probe_failures():
    """Under strict_live=True, lower-level probe exceptions (e.g. refused connection) must raise RuntimeError."""
    with pytest.raises(RuntimeError, match="STRICT_LIVE_MODE"):
        run_ssl_check("refused.example.com", use_mock=False, strict_live=True)


def test_actual_model_attribution():
    """Data sources attribution must reflect actual model usage or 'disabled' / 'mock'."""
    with patch("agents.recon_agent.check_target_reachability", return_value=(True, "")), \
         patch("agents.recon_agent.run_dns_recon", return_value=DnsResult(status="success")), \
         patch("agents.recon_agent.run_ssl_check", return_value=SslResult(valid=True, status="success")), \
         patch("agents.recon_agent.run_header_scan", return_value=HeaderResult(status="success")), \
         patch("agents.recon_agent.run_tech_fingerprint", return_value=TechResult(status="success")), \
         patch("agents.recon_agent._call_qwen_analysis", return_value={"_provenance": "LLM_REASONING"}):

        res_live = run_recon("example.com", use_mock=False, strict_live=False, use_ai=True)
        assert res_live["data_sources"]["recon_ai"] != "disabled"
        assert res_live["data_sources"]["recon_ai"] != "mock"

        res_rules = run_recon("example.com", use_mock=False, strict_live=False, use_ai=False)
        assert res_rules["data_sources"]["recon_ai"] == "disabled"
