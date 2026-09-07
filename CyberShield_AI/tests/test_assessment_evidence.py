"""Evidence statuses must survive construction and report serialization."""
from dataclasses import asdict
import pytest
from models import Finding, is_live_confirmed_vulnerability

@pytest.mark.parametrize("status", ["INCOMPLETE", "UNKNOWN", "NOT_ASSESSABLE", "SAFE", "PASS"])
def test_explicit_nonconfirmed_status_survives_report_roundtrip(status):
    restored = Finding(**asdict(Finding(severity="High", check_status=status)))
    assert restored.check_status == status
    assert not is_live_confirmed_vulnerability(restored)

def test_legacy_successful_finding_retains_confirmation():
    assert Finding(severity="High").check_status == "VULNERABLE"

from unittest.mock import Mock, patch
from agents import pentest_agent as pentest


@pytest.mark.parametrize('check', [pentest._check_idor, pentest._check_ssrf])
def test_failed_probes_are_not_clean(check):
    with patch.object(pentest, '_probe_get', return_value=(None, 'timeout')):
        assert check('https://example.com').check_status == 'UNREACHABLE'


@pytest.mark.parametrize('check', [pentest._check_idor, pentest._check_ssrf])
def test_partial_probes_are_incomplete(check):
    good = Mock(status_code=200, text='ordinary public page')
    replies = iter([(good, ''), (good, '')])
    with patch.object(pentest, '_probe_get', side_effect=lambda *a, **k: next(replies, (None, 'timeout'))):
        assert check('https://example.com').check_status == 'INCOMPLETE'


def test_public_profile_difference_is_only_a_candidate():
    replies = [Mock(status_code=200, text='Public name Alice ' * 20),
               Mock(status_code=200, text='Public name Bob ' * 20)]
    with patch.object(pentest, '_probe_get', side_effect=[(r, '') for r in replies]):
        finding = pentest._check_idor('https://example.com')
    assert finding.check_status == 'UNVERIFIED_CANDIDATE'
    assert not is_live_confirmed_vulnerability(finding)


@pytest.mark.parametrize('strict', [False, True])
def test_incomplete_checks_degrade_aggregate(strict):
    check = lambda domain: Finding(check_id='P-020', check_status='INCOMPLETE')
    with patch.object(pentest, '_ALL_CHECK_FUNCTIONS', {'P-020': check}), patch.object(pentest, 'check_target_reachability', return_value=(True, '')):
        if strict:
            with pytest.raises(RuntimeError, match='STRICT_LIVE_MODE'):
                pentest.run_pentest.__wrapped__('https://example.com', authorized=True, strict_live=True)
        else:
            result = pentest.run_pentest.__wrapped__('https://example.com', authorized=True)
            assert result['status'] == 'partial'
            assert result['tested_count'] == 1
            assert result['completed_count'] == 0
            assert result['total_checks'] == 1


def test_preflight_failure_does_not_count_skipped_checks_as_tested():
    with patch.object(pentest, 'check_target_reachability', return_value=(False, 'timeout')):
        result = pentest.run_pentest.__wrapped__('https://example.com', authorized=True)
    assert result['tested_count'] == 0
    assert result['skipped_count'] == result['total_checks']

@pytest.mark.parametrize('target', ['https://example.com', 'https://example.com:8443', 'http://example.com:8080'])
def test_recon_http_helpers_preserve_explicit_origin(target):
    from utils import header_scanner, tech_fingerprint
    observed = []
    def response(url, **kwargs):
        observed.append(url)
        return Mock(status_code=200, text='<html>safe</html>', url=url), None
    def headers(url, **kwargs):
        observed.append(url)
        return {}
    with patch.object(header_scanner, 'get_headers', side_effect=headers), patch.object(tech_fingerprint, 'safe_request', side_effect=response), patch.object(tech_fingerprint, 'get_headers', side_effect=headers):
        header_scanner.check_security_headers(target)
        tech_fingerprint.run_tech_fingerprint(target)
    assert observed
    from urllib.parse import urlsplit
    assert all(urlsplit(url).netloc == urlsplit(target).netloc and urlsplit(url).scheme == urlsplit(target).scheme for url in observed)


def test_explicit_https_does_not_probe_unauthorized_http_redirect():
    from utils.header_scanner import check_https_redirect
    with patch('utils.header_scanner.safe_request') as request:
        assert check_https_redirect('https://example.com:8443') is None
    request.assert_not_called()


def test_bare_host_retains_both_http_candidates():
    from utils.http_client import target_http_urls
    assert target_http_urls('example.com:8443', '/robots.txt') == [
        'https://example.com:8443/robots.txt', 'http://example.com:8443/robots.txt']


def test_header_connection_failure_does_not_invent_missing_headers():
    from utils.header_scanner import run_header_scan
    with patch('utils.header_scanner.get_headers', side_effect=RuntimeError('timeout')):
        result = run_header_scan('https://example.com')
    assert result.status == 'error'
    assert result.missing_headers == []


def test_unassessed_redirect_does_not_become_a_failed_control():
    from models import HeaderResult
    from agents.pisf_agent import _assess_control_7
    control = _assess_control_7({'headers': HeaderResult(https_redirect=None)}, None)
    assert control.status == 'NOT_ASSESSABLE'
    assert 'outside the assessed origin' in control.evidence
