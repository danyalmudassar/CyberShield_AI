"""Offline target syntax, authorization, address and redirect regressions."""
import socket
from unittest.mock import patch

import pytest

from agents.pre_engagement import collect_engagement_details, validate_authorization


def test_authorization_requires_boolean_and_known_scope():
    for authorization, scope in [(False, 'passive_only'), ('true', 'passive_only'), (1, 'passive_only'), (True, 'everything')]:
        details = collect_engagement_details('example.com', authorization, scope)
        assert details.pipeline_action == 'STOP'
        assert not validate_authorization(details)


def test_preengagement_accepts_explicit_local_lab_without_dns():
    details = collect_engagement_details('http://localhost:8080/lab', True)
    assert details.target_domain == 'localhost:8080'
    assert validate_authorization(details)


@pytest.mark.parametrize('raw,url,host,port', [
    ('HTTPS://WWW.Example.COM:8443/a?b=1#section', 'https://www.example.com:8443/a?b=1', 'www.example.com', 8443),
    ('example.com', 'https://example.com/', 'example.com', 443),
    ('http://[::1]:8080/lab', 'http://[::1]:8080/lab', '::1', 8080),
    ('https://bücher.example', 'https://xn--bcher-kva.example/', 'xn--bcher-kva.example', 443),
])
def test_normalize(raw, url, host, port):
    from utils.target_policy import normalize_target
    target = normalize_target(raw)
    assert (target.url, target.host, target.port) == (url, host, port)


@pytest.mark.parametrize('raw', ['', 'foo', 'ftp://example.com', 'https://a@b.com', 'https://example.com:0', 'https://example.com:65536', 'https://example.com:', 'https://a..com', 'https://example.com..', 'http://[v1.example.com]', 'https://-a.com', 'https://a_b.com', 'https://127.1', '2130706433', 'http://[fe80::1%25eth0]', 'https://example.com\\@evil.com', 'https://exam\nple.com', 'https://example.com/%0afoo'])
def test_invalid_syntax(raw):
    from utils.target_policy import normalize_target
    with pytest.raises(ValueError):
        normalize_target(raw)
    assert not validate_authorization(collect_engagement_details(raw, True))


def dns_result(*addresses):
    return [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443)) for address in addresses]


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '192.168.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1'])
def test_labs_require_explicit_policy(address):
    from utils.target_policy import validate_target
    target = f'http://[{address}]' if ':' in address else address
    with pytest.raises(ValueError):
        validate_target(target)
    assert validate_target(target, allow_private=True).addresses


@pytest.mark.parametrize('address', ['169.254.169.254', '169.254.1.2', 'fe80::1', '::ffff:169.254.169.254', '0.0.0.0', '::', '224.0.0.1', 'ff02::1', '100.100.100.200', 'fd00:ec2::254'])
def test_always_blocked_even_in_lab(address):
    from utils.target_policy import validate_target
    target = f'http://[{address}]' if ':' in address else address
    with pytest.raises(ValueError):
        validate_target(target, allow_private=True)


def test_dns_requires_every_address_public():
    from utils.target_policy import validate_target
    with patch('utils.target_policy.socket.getaddrinfo', return_value=dns_result('8.8.8.8', '10.0.0.1')):
        with pytest.raises(ValueError):
            validate_target('example.com')
    with patch('utils.target_policy.socket.getaddrinfo', return_value=dns_result('8.8.8.8', '2606:4700:4700::1111')):
        assert len(validate_target('example.com').addresses) == 2


@pytest.mark.parametrize('response', [[], socket.gaierror('unavailable')])
def test_dns_failure_fails_closed(response):
    from utils.target_policy import validate_target
    kwargs = {'side_effect': response} if isinstance(response, Exception) else {'return_value': response}
    with patch('utils.target_policy.socket.getaddrinfo', **kwargs):
        with pytest.raises(ValueError):
            validate_target('example.com')


def test_redirect_same_origin_and_revalidation():
    from utils.target_policy import validate_redirect
    with patch('utils.target_policy.socket.getaddrinfo', return_value=dns_result('8.8.8.8')):
        assert validate_redirect('https://example.com/a', '../b').url == 'https://example.com/b'
        for location in ['https://evil.com', '//evil.com', 'http://example.com', 'https://example.com:8443']:
            with pytest.raises(ValueError):
                validate_redirect('https://example.com/a', location)
    with patch('utils.target_policy.socket.getaddrinfo', return_value=dns_result('127.0.0.1')):
        with pytest.raises(ValueError):
            validate_redirect('https://example.com/a', '/b')
