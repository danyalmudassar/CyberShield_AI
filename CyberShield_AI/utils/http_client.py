"""Scope-checked HTTP sessions with IP-pinned TCP connections.

The URL and TLS hostname stay unchanged. Only the socket destination is pinned;
no global DNS monkeypatch, environment proxy, or cross-scan cookie jar is used.
Every send (including redirects and prepared requests) revalidates scope and DNS.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import ipaddress
import socket

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from urllib3.util.retry import Retry

from utils.target_policy import (
    TargetPolicyError, TargetScope, ValidatedTarget, current_scope,
    normalize_target, scope_for_target, validate_scoped_target,
)

_USER_AGENT = "CyberShield-AI/1.0 (Security Audit Tool)"
_DEFAULT_TIMEOUT = 5
_connection_target = ContextVar("connection_target", default=None)
_follow_redirects = ContextVar("follow_redirects", default=True)


def open_pinned_connection(target: ValidatedTarget, timeout=5, source_address=None, socket_options=None):
    """Connect directly to checked IP literals without a second DNS lookup."""
    if not target.addresses:
        raise TargetPolicyError("Connection requires validated IP addresses")
    last_error = None
    for address in target.addresses:
        ip = ipaddress.ip_address(address)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            for option in socket_options or ():
                sock.setsockopt(*option)
            if source_address:
                sock.bind(source_address)
            endpoint = (str(ip), target.port, 0, 0) if ip.version == 6 else (str(ip), target.port)
            sock.connect(endpoint)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise last_error or OSError("No usable target address")


class _PinnedConnection:
    def _new_conn(self):
        target = _connection_target.get()
        if target is None or self.host.lower().rstrip('.') != target.host or self.port != target.port:
            raise TargetPolicyError("Connection has no matching validated target")
        try:
            return open_pinned_connection(target, timeout=self.timeout,
                                          source_address=self.source_address,
                                          socket_options=self.socket_options)
        except OSError as exc:
            raise NewConnectionError(self, "Connection to validated address failed") from exc


class PinnedHTTPConnection(_PinnedConnection, HTTPConnection):
    pass


class PinnedHTTPSConnection(_PinnedConnection, HTTPSConnection):
    pass


class _HTTPPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection


class _HTTPSPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


class ScopeAdapter(HTTPAdapter):
    def __init__(self, scope):
        self.scope = scope
        super().__init__(max_retries=Retry(total=1, connect=1, read=0, redirect=0))

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {'http': _HTTPPool, 'https': _HTTPSPool}

    def send(self, request, **kwargs):
        if any((kwargs.get('proxies') or {}).values()):
            raise TargetPolicyError("Proxies are disabled for target assessments")
        target = validate_scoped_target(request.url, scope=self.scope)
        # Host overrides must not move virtual-host routing outside the scope.
        host = request.headers.get('Host')
        if host and normalize_target(f'{target.scheme}://{host}').origin != target.origin:
            raise TargetPolicyError("Host header leaves the authorized origin")
        request.headers.pop('X-Allow-Private-Lab', None)
        token = _connection_target.set(target)
        try:
            return super().send(request, **kwargs)
        finally:
            _connection_target.reset(token)


class ScopedSession(requests.Session):
    """A cookie jar restricted to its initial authorized origin(s)."""
    def __init__(self, target=None, allow_private=False):
        super().__init__()
        self.trust_env = False
        self.max_redirects = 5
        self.scope = scope_for_target(target, allow_private) if target else None
        self.headers.update({'User-Agent': _USER_AGENT})
        self._install_adapters()

    def _install_adapters(self):
        for scheme in ('http://', 'https://'):
            self.mount(scheme, ScopeAdapter(self.scope))

    def send(self, request, **kwargs):
        if self.scope is None:
            # Standalone sessions bind on first use. Scan scopes are additionally
            # enforced by the transport, so the first URL cannot broaden them.
            private = current_scope().allow_private if current_scope() else False
            self.scope = scope_for_target(request.url, private)
            for adapter in self.adapters.values():
                adapter.scope = self.scope
        kwargs.setdefault('timeout', _DEFAULT_TIMEOUT)
        token = _follow_redirects.set(kwargs.get('allow_redirects', True))
        try:
            return super().send(request, **kwargs)
        finally:
            _follow_redirects.reset(token)

    def get_redirect_target(self, response):
        following = super().get_redirect_target(response)
        if following and _follow_redirects.get():
            from urllib.parse import urljoin
            try:
                destination = normalize_target(urljoin(response.url, following))
                if destination.origin != normalize_target(response.url).origin:
                    raise TargetPolicyError("Redirect leaves the authorized origin")
            except BaseException:
                response.close()
                raise
        return following


def get_session(target=None, allow_private=False):
    """Create a fresh guarded session; never share authentication across scans."""
    return ScopedSession(target=target, allow_private=allow_private)


def guarded_session(session, target=None, allow_private=False):
    """Accept only guarded sessions; never trust a caller's unguarded transport."""
    if session is None:
        return get_session(target, allow_private)
    if not isinstance(session, ScopedSession):
        raise TargetPolicyError("Scanner requires a scope-checked HTTP session")
    return session


def request(method, url, *, timeout=_DEFAULT_TIMEOUT, allow_private=False, session=None, **kwargs):
    s = guarded_session(session, url, allow_private)
    try:
        return s.request(method, url, timeout=timeout, **kwargs)
    finally:
        if session is None:
            # Non-streaming bodies are read by requests before returning. A
            # streaming response owns its socket and caller must close it.
            s.close()


def get(url, timeout=_DEFAULT_TIMEOUT, allow_private=False, **kwargs):
    response = request('GET', url, timeout=timeout, allow_private=allow_private, **kwargs)
    response.raise_for_status()
    return response


def get_headers(url, timeout=_DEFAULT_TIMEOUT, allow_private=False):
    try:
        with request('HEAD', url, timeout=timeout, allow_private=allow_private, allow_redirects=True) as response:
            response.raise_for_status()
            return dict(response.headers)
    except requests.RequestException:
        with get(url, timeout=timeout, allow_private=allow_private) as response:
            return dict(response.headers)


def safe_request(url, timeout=_DEFAULT_TIMEOUT, allow_private=False):
    try:
        return get(url, timeout=timeout, allow_private=allow_private), None
    except Exception as exc:
        return None, str(exc)


def check_target_reachability(domain, timeout=3, allow_private=False):
    from utils.anonymizer import sanitize_secrets_only
    candidates = [domain] if '://' in domain else [f'https://{domain}', f'http://{domain}']
    last_error = 'Target failed to respond'
    for url in candidates:
        try:
            with request('GET', url, timeout=timeout, allow_private=allow_private,
                         allow_redirects=True, verify=False) as response:
                return True, ''
        except TargetPolicyError as exc:
            last_error = f'Target policy blocked target: {exc}'
        except Exception as exc:
            last_error = sanitize_secrets_only(str(exc))
    return False, last_error


# Compatibility helpers for callers/tests inspecting scoped DNS data. They no
# longer replace socket.getaddrinfo; real HTTP/TLS use open_pinned_connection.
_dns_bindings = ContextVar('dns_bindings', default={})


@contextmanager
def dns_bound(host, addresses):
    token = _dns_bindings.set({**_dns_bindings.get(), host.lower(): tuple(addresses)})
    try:
        yield
    finally:
        _dns_bindings.reset(token)


def _thread_aware_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    addresses = _dns_bindings.get().get(host.lower(), ())
    if not addresses:
        return socket.getaddrinfo(host, port, family, type, proto, flags)
    return [(socket.AF_INET6 if ':' in address else socket.AF_INET,
             type or socket.SOCK_STREAM, proto or socket.IPPROTO_TCP, '',
             (address, port, 0, 0) if ':' in address else (address, port))
            for address in addresses
            if family in (0, socket.AF_INET6 if ':' in address else socket.AF_INET)]


_SERVICE_ORIGINS = {
    'nvd': 'https://services.nvd.nist.gov',
    'virustotal': 'https://www.virustotal.com',
    'shodan': 'https://api.shodan.io',
}


def service_get(service, url, **kwargs):
    """Separate, fixed-origin intelligence egress; never a target-scope bypass."""
    from utils.target_policy import target_scope
    origin = _SERVICE_ORIGINS[service]
    if normalize_target(url).origin != normalize_target(origin).origin:
        raise TargetPolicyError('Intelligence request leaves the configured service origin')
    active = current_scope()
    if active and active.offline:
        raise TargetPolicyError('Network requests are disabled in demo mode')
    with target_scope(scope_for_target(origin)):
        return get(url, **kwargs)
