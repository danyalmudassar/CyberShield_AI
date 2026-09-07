import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from unittest.mock import patch

import pytest

from agents.orchestrator import run_full_scan, ScanFailed
from models import DnsResult, SslResult, HeaderResult, TechResult
from utils.ai_provider import model_context, configured_model


def boundaries(stack):
    stack.enter_context(patch('agents.recon_agent.check_target_reachability', return_value=(True, '')))
    for name, value in [('run_dns_recon', DnsResult()), ('run_ssl_check', SslResult(valid=True)), ('run_header_scan', HeaderResult()), ('run_tech_fingerprint', TechResult(technologies=['fixture 1.0']))]:
        stack.enter_context(patch('agents.recon_agent.' + name, return_value=value))
    stack.enter_context(patch('agents.threat_intel_agent._query_nvd_online', return_value=[]))
    stack.enter_context(patch('agents.threat_intel_agent._query_virustotal_online', return_value={}))
    stack.enter_context(patch('agents.threat_intel_agent._query_shodan_online', return_value={}))
    stack.enter_context(patch('agents.visual_agent.check_target_reachability', return_value=(False, 'fixture unavailable')))
    stack.enter_context(patch('agents.report_agent._generate_pdf', return_value='/tmp/fixture.pdf'))


def test_rules_only_through_orchestrator_never_calls_ai():
    # Force thread-based stage execution so in-process patches (boundaries) are visible
    # to stage functions — spawned subprocesses do not inherit monkeypatched modules.
    with patch.dict(os.environ, {"CYBERSHIELD_STAGE_ISOLATION": "thread"}):
        with ExitStack() as stack:
            boundaries(stack)
            recon_ai = stack.enter_context(patch('agents.recon_agent.call_llm_json', side_effect=AssertionError('AI forbidden')))
            threat_ai = stack.enter_context(patch('agents.threat_intel_agent.call_llm_json', side_effect=AssertionError('AI forbidden')))
            state = run_full_scan('example.invalid', authorized=True, execution_mode='rules_only')
    recon_ai.assert_not_called()
    threat_ai.assert_not_called()
    assert state.scan_progress['recon'] == 'completed'
    assert state.scan_progress['visual'] == 'partial'
    assert state.scan_progress['status'] == 'PARTIAL'
    assert state.report.ai_model_used == 'OFFLINE_DETERMINISTIC'
    assert all(f.provenance != 'MOCK_FALLBACK' for f in state.all_findings)


def test_strict_returned_error_has_inspectable_failed_state():
    # Force thread-based stage execution so in-process patches (boundaries) are visible.
    with patch.dict(os.environ, {"CYBERSHIELD_STAGE_ISOLATION": "thread"}):
        with ExitStack() as stack:
            boundaries(stack)
            stack.enter_context(patch('agents.recon_agent.run_dns_recon', return_value=DnsResult(status='error')))
            with pytest.raises(ScanFailed) as exc:
                run_full_scan('example.invalid', authorized=True, execution_mode='rules_only', strict_live=True)
    assert exc.value.state.scan_progress['status'] == 'FAILED'
    assert exc.value.state.scan_progress['recon'] == 'failed'
    assert exc.value.state.report is None


def test_cancellation_has_inspectable_state():
    with patch.dict(os.environ, {"CYBERSHIELD_STAGE_ISOLATION": "thread"}):
        with ExitStack() as stack:
            boundaries(stack)
            with pytest.raises(ScanFailed) as exc:
                run_full_scan('example.invalid', authorized=True, execution_mode='demo', cancellation_check=lambda: True)
    assert exc.value.state.scan_progress['status'] == 'CANCELLED'


def test_model_selection_is_thread_local_and_restored():
    from threading import Barrier
    barrier = Barrier(2)
    previous = configured_model()
    def inspect(model):
        with model_context(model):
            barrier.wait(timeout=5)
            return configured_model()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(inspect, 'model-a')
        b = pool.submit(inspect, 'model-b')
        assert a.result() == 'model-a'
        assert b.result() == 'model-b'
    assert configured_model() == previous
