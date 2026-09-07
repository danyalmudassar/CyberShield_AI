"""Bounded WHOIS infrastructure egress, separate from target HTTP scope.

Start at IANA, then follow at most two registry/registrar referrals. Each hop
uses public-only DNS validation and IP-pinned port 43 sockets; never invoke the
python-whois package's network client or a shell command.
"""
import ipaddress
import re

from whois.parser import WhoisEntry

from utils.http_client import open_pinned_connection
from utils.target_policy import TargetPolicyError, current_scope, normalize_target, validate_target

_MAX_BYTES = 256 * 1024


def _query_server(host, query):
    # WHOIS referrals are hostnames, never arbitrary URLs, ports or credentials.
    normalized = normalize_target(host)
    if host.lower().rstrip('.') != normalized.host:
        raise TargetPolicyError('Invalid WHOIS referral host')
    target = validate_target(f'https://{normalized.host}:43', allow_private=False)
    chunks, size = [], 0
    with open_pinned_connection(target, timeout=3) as connection:
        connection.sendall((query + '\r\n').encode('ascii'))
        while True:
            chunk = connection.recv(min(4096, _MAX_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_BYTES:
                raise TargetPolicyError('WHOIS response exceeded size limit')
            chunks.append(chunk)
    return b''.join(chunks).decode('utf-8', 'replace')


def lookup_whois(domain):
    target = normalize_target(domain)
    scope = current_scope()
    if scope:
        if scope.offline:
            raise TargetPolicyError('Network requests are disabled in demo mode')
        if not any(host == target.host for _, host, _ in scope.origins):
            raise TargetPolicyError('WHOIS query leaves authorized target scope')
    try:
        ipaddress.ip_address(target.host)
    except ValueError:
        pass
    else:
        raise TargetPolicyError('Domain WHOIS is not assessed for IP targets')
    server, query, visited, records = 'whois.iana.org', target.host.rsplit('.', 1)[-1], set(), []
    for hop in range(3):
        if server in visited:
            break
        visited.add(server)
        response = _query_server(server, query)
        if hop:
            records.append(response)
        match = re.search(r'^(?:refer|whois|Registrar WHOIS Server):\s*(\S+)', response, re.I | re.M)
        if not match:
            break
        server, query = match.group(1).lower().rstrip('.'), target.host
    if not records:
        raise TargetPolicyError('WHOIS registry returned no usable registration data')
    return WhoisEntry.load(target.host, '\n'.join(records))
