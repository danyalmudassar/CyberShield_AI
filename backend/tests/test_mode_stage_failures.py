"""Fail-closed orchestration of returned stage failures, with no network."""
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agents.orchestrator import ScanFailed, run_full_scan


import os


@pytest.fixture
def stages():
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"CYBERSHIELD_STAGE_ISOLATION": "thread"}))
        mocked = {}
        for name in ('run_recon', 'run_threat_intel', 'run_visual_scan', 'run_pentest', 'run_pisf_assessment'):
            mocked[name] = stack.enter_context(patch('agents.orchestrator.' + name, return_value={'status': 'success', 'findings': []}))
        mocked['generate_report'] = stack.enter_context(patch('agents.orchestrator.generate_report', return_value={'status': 'success', 'report': SimpleNamespace(security_posture_score=0)}))
        yield mocked


@pytest.mark.parametrize('function,stage,payload', [
    ('run_pisf_assessment', 'pisf', {'status': 'error'}),
    ('run_pisf_assessment', 'pisf', None),
    ('run_visual_scan', 'visual', None),
    ('generate_report', 'report', None),
    ('generate_report', 'report', {'status': 'success', 'report': None}),
    ('generate_report', 'report', {'status': 'partial', 'report': SimpleNamespace(security_posture_score=0)}),
    ('run_recon', 'recon', {'dns': {'status': 'error'}}),
])
def test_strict_returned_failure_preserves_state(stages, function, stage, payload):
    stages[function].return_value = payload
    with pytest.raises(ScanFailed) as exc:
        run_full_scan('example.invalid', authorized=True, strict_live=True, execution_mode='rules_only')
    assert exc.value.state.scan_progress['status'] == 'FAILED'
    assert exc.value.state.scan_progress[stage] == 'failed'
    assert exc.value.state.engagement.authorized is True


@pytest.mark.parametrize('payload', [
    {'status': 'mock'},
    {'findings': [SimpleNamespace(provenance='MOCK_FALLBACK', severity='High')]},
    {'ai_analysis': {'_provenance': 'MOCK_FALLBACK'}},
])
@pytest.mark.parametrize('strict', [False, True])
def test_fixture_return_never_enters_live_findings(stages, payload, strict):
    stages['run_threat_intel'].return_value = payload
    if strict:
        with pytest.raises(ScanFailed) as exc:
            run_full_scan('example.invalid', authorized=True, strict_live=True)
        state = exc.value.state
    else:
        state = run_full_scan('example.invalid', authorized=True)
    assert state.scan_progress['threat_intel'] == 'failed'
    assert not state.all_findings


def test_demo_still_allows_fixtures(stages):
    stages['run_recon'].return_value = {'status': 'mock', 'findings': []}
    state = run_full_scan('example.invalid', authorized=True, execution_mode='demo')
    assert state.scan_progress['recon'] == 'mock'
    assert state.scan_progress['status'] == 'COMPLETED'


def test_missing_report_not_completed_in_demo(stages):
    stages['generate_report'].return_value = {'status': 'success', 'report': None}
    state = run_full_scan('example.invalid', authorized=True, execution_mode='demo')
    assert state.scan_progress['report'] == 'failed'
    assert state.scan_progress['status'] == 'FAILED'
