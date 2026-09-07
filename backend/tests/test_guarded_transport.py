"""Exercise real request preparation, redirect handling and pinned connections.

Only DNS and the wire exchange are faked. Policy/session/adapter code is real.
"""
import socket
from urllib.parse import urlsplit

import pytest
import requests
from requests.adapters import HTTPAdapter

from utils import http_client as http
from utils.target_policy import TargetPolicyError, scope_for_target, target_scope

PUBLIC = '93.184.216.34'


@pytest.fixture
def transport(monkeypatch):
    wire, connects = [], []
    answers = [PUBLIC]
    responses = []

    def resolve(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port)) for ip in answers]

    class Socket:
        def __init__(self, *args): pass
        def settimeout(self, value): pass
        def setsockopt(self, *args): pass
        def connect(self, endpoint): connects.append(endpoint)
        def close(self): pass

    def exchange(adapter, request, **kwargs):
        url = urlsplit(request.url)
        connection_type = http.PinnedHTTPSConnection if url.scheme == 'https' else http.PinnedHTTPConnection
        conn = connection_type(url.hostname, url.port or (443 if url.scheme == 'https' else 80), timeout=1)
        conn._new_conn().close()
        wire.append(request)
        status, headers, body = responses.pop(0) if responses else (200, {}, b'OK')
        response = requests.Response()
        response.status_code, response.headers = status, requests.structures.CaseInsensitiveDict(headers)
        response.url, response.request = request.url, request
        response._content, response._content_consumed = body, True
        return response

    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    monkeypatch.setattr(socket, 'socket', Socket)
    monkeypatch.setattr(HTTPAdapter, 'send', exchange)
    return wire, connects, answers, responses


@pytest.mark.parametrize('url', ['http://169.254.169.254/', 'http://100.100.100.200/',
                                'http://127.0.0.1/', 'http://[::1]/'])
def test_blocked_literal_never_reaches_wire(transport, url):
    with pytest.raises(TargetPolicyError):
        http.get(url)
    assert transport[0] == transport[1] == []


def test_private_dns_never_reaches_wire(transport):
    transport[2][:] = ['127.0.0.1']
    with pytest.raises(TargetPolicyError):
        http.get('https://example.com/')
    assert not transport[0] and not transport[1]


@pytest.mark.parametrize('location', ['https://other.example/', 'http://169.254.169.254/',
                                    'http://example.com/', 'https://example.com:444/', 'file:///etc/passwd'])
def test_redirect_blocked_before_second_request(transport, location):
    transport[3].append((302, {'Location': location}, b''))
    with pytest.raises(TargetPolicyError):
        http.get('https://example.com/')
    assert len(transport[0]) == len(transport[1]) == 1


def test_same_origin_redirect_rechecks_dns_and_blocks_rebinding(transport):
    wire, connects, answers, responses = transport
    responses.append((302, {'Location': '/next'}, b''))
    session = http.get_session('https://example.com')
    session.hooks['response'].append(lambda response, **kwargs: answers.__setitem__(slice(None), ['127.0.0.1']))
    with pytest.raises(TargetPolicyError):
        session.get('https://example.com')
    assert len(wire) == len(connects) == 1


def test_each_redirect_uses_new_checked_address_and_original_hostname(transport):
    wire, connects, answers, responses = transport
    responses.append((302, {'Location': '/next'}, b''))
    session = http.get_session('https://example.com')
    session.hooks['response'].append(lambda response, **kwargs: answers.__setitem__(slice(None), ['93.184.216.35']))
    assert session.get('https://example.com').status_code == 200
    assert connects == [(PUBLIC, 443), ('93.184.216.35', 443)]
    assert [urlsplit(item.url).hostname for item in wire] == ['example.com', 'example.com']


def test_scan_scope_rejects_other_public_host_before_connect(transport):
    with target_scope(scope_for_target('example.com')):
        with pytest.raises(TargetPolicyError, match='scan scope'):
            http.get('https://other.example')
    assert not transport[0]


def test_session_scope_guards_prepared_requests(transport):
    session = http.get_session('https://example.com')
    prepared = requests.Request('GET', 'https://other.example').prepare()
    with pytest.raises(TargetPolicyError, match='session scope'):
        session.send(prepared)
    assert not transport[0]


def test_proxy_and_host_override_cannot_bypass_scope(transport):
    with pytest.raises(TargetPolicyError):
        http.get('https://example.com', proxies={'https': 'http://127.0.0.1:8888'})
    with pytest.raises(TargetPolicyError):
        http.get('https://example.com', headers={'Host': 'other.example'})
    assert not transport[0]


def test_explicit_lab_policy_is_local_and_not_sent_as_header(transport):
    http.get('http://127.0.0.1:8080', allow_private=True)
    assert transport[1] == [('127.0.0.1', 8080)]
    assert 'X-Allow-Private-Lab' not in transport[0][0].headers
    with target_scope(scope_for_target('127.0.0.1:8080', allow_private=False)):
        with pytest.raises(TargetPolicyError):
            http.get('http://127.0.0.1:8080', allow_private=True)
    assert len(transport[0]) == 1


def test_untrusted_session_rejected_and_cookie_jars_separate():
    with pytest.raises(TargetPolicyError):
        http.guarded_session(requests.Session())
    first, second = http.get_session(), http.get_session()
    first.cookies.set('session', 'secret')
    assert not second.cookies
    assert not first.trust_env


def test_demo_policy_blocks_before_dns_or_transport(transport):
    with target_scope(scope_for_target('example.com', offline=True)):
        with pytest.raises(TargetPolicyError, match='demo'):
            http.get('https://example.com')
    assert not transport[0]


def test_import_does_not_monkeypatch_global_dns():
    assert socket.getaddrinfo is not http._thread_aware_getaddrinfo


def test_scanner_helpers_cannot_bypass_scope(transport):
    from agents.pentest_agent import _probe_get, _probe_post, _probe_post_xml, _probe_method
    from agents.visual_agent import _get
    with target_scope(scope_for_target('example.com')):
        calls = [lambda: _probe_get('https://outside.example'),
                 lambda: _probe_post('https://outside.example', {'secret': 'value'}),
                 lambda: _probe_post_xml('https://outside.example', '<xml/>'),
                 lambda: _probe_method('https://outside.example', 'PUT'),
                 lambda: _get('https://outside.example')]
        for call in calls:
            response, error = call()
            assert response is None and error
    assert not transport[0]


def test_authenticated_session_rejects_off_scope_login_and_redirect(transport):
    from utils.auth_session import create_authenticated_session
    with target_scope(scope_for_target('example.com')):
        assert create_authenticated_session('https://outside.example/login', 'user', 'secret') is None
        assert not transport[0]
        transport[3].extend([(200, {}, b'login page'), (307, {'Location': 'https://outside.example/login'}, b'')])
        assert create_authenticated_session('https://example.com/login', 'user', 'secret') is None
        assert len(transport[0]) == 2
        assert all(urlsplit(req.url).hostname == 'example.com' for req in transport[0])


def test_crawler_checks_form_and_link_origins(transport):
    from utils.crawler import discover_endpoints
    transport[3].append((200, {'Content-Type': 'text/html'}, b'''
        <a href="/inside">ok</a><a href="http://example.com/wrong-scheme">no</a>
        <a href="https://outside.example/">no</a><form action="https://example.com:444/">no</form>'''))
    session = http.get_session('https://example.com')
    urls = discover_endpoints(session, 'https://example.com/', max_pages=5)
    assert urls == ['https://example.com/', 'https://example.com/inside']
    assert len(transport[0]) == 2


def test_tls_probe_blocked_before_socket(transport):
    from utils.ssl_checker import get_ssl_certificate
    with target_scope(scope_for_target('example.com')):
        with pytest.raises(TargetPolicyError):
            get_ssl_certificate('outside.example')
    assert not transport[1]


def test_service_egress_is_explicit_and_does_not_expand_target_scope(transport):
    with target_scope(scope_for_target('example.com')):
        http.service_get('nvd', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        with pytest.raises(TargetPolicyError):
            http.service_get('nvd', 'https://outside.example')
        with pytest.raises(TargetPolicyError):
            http.get('https://services.nvd.nist.gov')
    assert len(transport[0]) == 1
    with target_scope(scope_for_target('example.com', offline=True)):
        with pytest.raises(TargetPolicyError):
            http.service_get('nvd', 'https://services.nvd.nist.gov')
    assert len(transport[0]) == 1


def test_explicit_port_and_scheme_scope_cannot_expand(transport):
    with target_scope(scope_for_target('http://example.com:8080')):
        http.get('http://example.com:8080/')
        for url in ['https://example.com:8080/', 'http://example.com/', 'http://example.com:9090/']:
            with pytest.raises(TargetPolicyError):
                http.get(url)
    assert len(transport[0]) == 1


def test_ipv6_pinning_uses_full_socket_address(transport):
    transport[2][:] = ['2606:4700:4700::1111']
    http.get('https://example.com')
    assert transport[1] == [('2606:4700:4700::1111', 443, 0, 0)]


def test_header_cannot_grant_private_lab_access(transport):
    with pytest.raises(TargetPolicyError):
        http.get('http://127.0.0.1', headers={'X-Allow-Private-Lab': 'true'})
    assert not transport[0]


def test_nvd_keyword_parameters_are_encoded_without_changing_origin(transport):
    from agents.threat_intel_agent import _query_nvd_online
    from urllib.parse import parse_qs
    transport[3].append((200, {'Content-Type': 'application/json'}, b'{"vulnerabilities": []}'))
    assert _query_nvd_online(['nginx 1.24 & x=1']) == []
    assert len(transport[0]) == 1
    url = urlsplit(transport[0][0].url)
    assert url.hostname == 'services.nvd.nist.gov'
    assert parse_qs(url.query) == {'keywordSearch': ['nginx 1.24 & x=1']}


def test_no_follow_probe_preserves_redirect_evidence_without_following(transport):
    transport[3].append((302, {'Location': 'https://outside.example/'}, b''))
    response = http.get('https://example.com', allow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'] == 'https://outside.example/'
    assert len(transport[0]) == 1


def test_second_redirect_hop_cannot_change_scheme(transport):
    transport[3].extend([(302, {'Location': '/step'}, b''),
                         (302, {'Location': 'http://example.com/final'}, b'')])
    with http.get_session('example.com') as session:
        with pytest.raises(TargetPolicyError):
            session.get('https://example.com')
    assert len(transport[0]) == 2
