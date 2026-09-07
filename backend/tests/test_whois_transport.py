import socket

import pytest

from utils import whois_client as client
from utils.target_policy import TargetPolicyError, scope_for_target, target_scope


def test_whois_metadata_referral_is_never_connected(monkeypatch):
    connects = []
    monkeypatch.setattr(socket, 'getaddrinfo', lambda host, port, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port))])

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def sendall(self, query): assert query == b'com\r\n'
        def recv(self, size):
            if getattr(self, 'done', False): return b''
            self.done = True
            return b'refer: 169.254.169.254\r\n'

    def connect(target, timeout):
        connects.append(target)
        return Connection()

    monkeypatch.setattr(client, 'open_pinned_connection', connect)
    with pytest.raises(TargetPolicyError):
        client.lookup_whois('example.com')
    assert len(connects) == 1
    assert connects[0].host == 'whois.iana.org'
    assert connects[0].port == 43


def test_whois_referral_count_is_bounded(monkeypatch):
    queries = []
    def query(server, domain):
        queries.append((server, domain))
        return f'Registrar: Test Registrar\nrefer: referral{len(queries)}.example\n'
    monkeypatch.setattr(client, '_query_server', query)
    result = client.lookup_whois('example.com')
    assert len(queries) == 3
    assert queries[0] == ('whois.iana.org', 'com')
    assert result.registrar == 'Test Registrar'


def test_whois_demo_and_outside_target_never_query(monkeypatch):
    def forbidden(*args): pytest.fail('WHOIS must not start a network query')
    monkeypatch.setattr(client, '_query_server', forbidden)
    for scope, domain in [(scope_for_target('example.com', offline=True), 'example.com'),
                          (scope_for_target('example.com'), 'outside.example')]:
        with target_scope(scope), pytest.raises(TargetPolicyError):
            client.lookup_whois(domain)


def test_dns_query_cannot_leave_scan_scope(monkeypatch):
    import dns.resolver
    from utils.dns_recon import get_dns_records, analyze_email_security
    def forbidden(*args, **kwargs): pytest.fail('Out-of-scope DNS query was sent')
    monkeypatch.setattr(dns.resolver, 'resolve', forbidden)
    with target_scope(scope_for_target('example.com')):
        with pytest.raises(TargetPolicyError):
            get_dns_records('outside.example')
        with pytest.raises(TargetPolicyError):
            analyze_email_security('outside.example', [])
