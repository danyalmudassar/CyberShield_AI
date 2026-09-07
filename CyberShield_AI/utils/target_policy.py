"""Target syntax and preflight egress policy.

This module does not send HTTP requests. DNS validation is a preflight check,
not DNS rebinding protection: a transport must connect to the checked address,
retain TLS hostname verification, and apply policy on every request/redirect.
The policy scopes redirects to the exact origin; it does not define path scopes.
"""
from dataclasses import dataclass, replace
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit


class TargetPolicyError(ValueError):
    """The target is malformed, out of scope, or resolves to a blocked address."""


@dataclass(frozen=True)
class ValidatedTarget:
    """Normalized URL, unbracketed host, effective port and checked IP strings.

    Empty ``addresses`` means DNS has not been checked, never permission to
    connect. ``authority`` preserves an explicit port and brackets IPv6 hosts.
    """
    url: str
    host: str
    port: int
    scheme: str
    addresses: tuple[str, ...] = ()

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port

    @property
    def authority(self) -> str:
        return urlsplit(self.url).netloc


def normalize_target(target: str) -> ValidatedTarget:
    """Pure syntax normalization; default bare hosts to HTTPS, preserve ports.

    Accept domains, localhost, IPv4, and bracketed IPv6. Reject credentials,
    ambiguous numeric hosts, zone identifiers, controls, and non-HTTP schemes.
    Paths/queries are preserved; fragments are removed as they are not sent.
    """
    if not isinstance(target, str) or not target.strip():
        raise TargetPolicyError('Target must be a nonempty string')
    if any(ord(char) < 32 or ord(char) == 127 for char in target):
        raise TargetPolicyError('Control characters are not allowed')
    target = target.strip()
    if any(char.isspace() for char in target) or '\\' in target or re.search(r'%(?:0[0-9a-f]|1[0-9a-f]|7f)', target, re.I):
        raise TargetPolicyError('Whitespace, controls and backslashes are not allowed')
    value = target if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', target) else 'https://' + target
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise TargetPolicyError('Invalid target authority') from exc
    if parsed.scheme not in ('http', 'https') or not host:
        raise TargetPolicyError('An HTTP(S) target host is required')
    if parsed.username is not None or parsed.password is not None or '%' in host:
        raise TargetPolicyError('Credentials and host escapes are not allowed')
    if parsed.netloc.endswith(':') or explicit_port == 0:
        raise TargetPolicyError('Port must be between 1 and 65535')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if '[' in parsed.netloc or ']' in parsed.netloc or host.endswith('..'):
            raise TargetPolicyError('Invalid host syntax')
        try:
            host = host.removesuffix('.').encode('idna').decode('ascii').lower()
        except UnicodeError as exc:
            raise TargetPolicyError('Invalid domain name') from exc
        labels = host.split('.')
        if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
            raise TargetPolicyError('Invalid domain name')
        if host != 'localhost' and (len(labels) < 2 or not re.search('[a-z]', labels[-1])):
            raise TargetPolicyError('A fully qualified domain is required')
        # Reject inet_aton-compatible numeric aliases, including hexadecimal.
        if all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', label) for label in labels):
            raise TargetPolicyError('Ambiguous numeric address')
        authority = host
    else:
        host = str(address)
        authority = f'[{host}]' if address.version == 6 else host
    if explicit_port is not None:
        authority += f':{explicit_port}'
    port = explicit_port or (443 if parsed.scheme == 'https' else 80)
    url = urlunsplit((parsed.scheme, authority, parsed.path or '/', parsed.query, ''))
    return ValidatedTarget(url=url, host=host, port=port, scheme=parsed.scheme)


_LAB_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
    '::1/128', 'fc00::/7',
))
_METADATA = {ipaddress.ip_address('100.100.100.200'), ipaddress.ip_address('fd00:ec2::254')}


def _check_address(value: str, allow_private: bool) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetPolicyError('Resolver returned an invalid address') from exc
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    if effective.is_link_local or effective.is_multicast or effective.is_unspecified or effective in _METADATA:
        raise TargetPolicyError('Link-local, metadata and non-unicast targets are blocked')
    private_lab = any(effective in network for network in _LAB_NETWORKS)
    if not effective.is_global and not (allow_private is True and private_lab):
        raise TargetPolicyError('Nonpublic targets require an explicit supported private lab policy')
    return str(address)


def validate_target(target: str, allow_private: bool = False, resolve: bool = True) -> ValidatedTarget:
    """Normalize and validate literal IPs or every DNS answer; fail closed.

    ``resolve=False`` skips DNS for names only (pure input validation). Literal
    IP restrictions still apply. ``allow_private=True`` permits RFC1918, ULA
    and loopback labs, but never metadata, link-local or multicast addresses.
    """
    normalized = normalize_target(target)
    try:
        ipaddress.ip_address(normalized.host)
    except ValueError:
        if not resolve:
            return normalized
        try:
            answers = socket.getaddrinfo(normalized.host, normalized.port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise TargetPolicyError('Target DNS resolution failed') from exc
        addresses = tuple(dict.fromkeys(_check_address(answer[4][0], allow_private) for answer in answers))
        if not addresses:
            raise TargetPolicyError('Target DNS returned no addresses')
    else:
        addresses = (_check_address(normalized.host, allow_private),)
    return replace(normalized, addresses=addresses)


def validate_redirect(current_url: str, next_url: str, allow_private: bool = False) -> ValidatedTarget:
    """Resolve a Location, require the same origin, and recheck destination DNS."""
    current = normalize_target(current_url)
    if not isinstance(next_url, str) or not next_url or any(ord(c) < 32 or ord(c) == 127 for c in next_url):
        raise TargetPolicyError('Invalid redirect location')
    following = normalize_target(urljoin(current.url, next_url))
    if following.origin != current.origin:
        raise TargetPolicyError('Redirect leaves the authorized origin')
    return validate_target(following.url, allow_private=allow_private)


# The scanner accepts a whole host, not a path prefix. Bare hosts authorize
# HTTP:80 and HTTPS:443; an explicit port authorizes that port for both schemes.
# An explicit URL authorizes only its exact origin. Redirects remain same-origin.
from contextlib import contextmanager
from contextvars import ContextVar


@dataclass(frozen=True)
class TargetScope:
    origins: tuple[tuple[str, str, int], ...]
    allow_private: bool = False
    offline: bool = False


_active_scope = ContextVar("target_scope", default=None)


def scope_for_target(target: str, allow_private: bool = False, offline: bool = False) -> TargetScope:
    normalized = normalize_target(target)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target.strip()):
        origins = (normalized.origin,)
    else:
        port = urlsplit(normalized.url).port
        origins = (("http", normalized.host, port or 80), ("https", normalized.host, port or 443))
    return TargetScope(origins, allow_private, offline)


def current_scope():
    return _active_scope.get()


@contextmanager
def target_scope(scope: TargetScope):
    token = _active_scope.set(scope)
    try:
        yield
    finally:
        _active_scope.reset(token)


def validate_scoped_target(url: str, *, scope=None, allow_private=None) -> ValidatedTarget:
    active = current_scope()
    normalized = normalize_target(url)
    if active is not None:
        if active.offline:
            raise TargetPolicyError("Network requests are disabled in demo mode")
        if normalized.origin not in active.origins:
            raise TargetPolicyError("Request leaves the authorized scan scope")
    if scope is not None and normalized.origin not in scope.origins:
        raise TargetPolicyError("Request leaves the authorized session scope")
    # A per-call flag cannot expand an enclosing scan's deployment policy.
    private = active.allow_private if active is not None else (
        scope.allow_private if scope is not None else allow_private is True
    )
    return validate_target(normalized.url, allow_private=private)


def target_scoped(function):
    """Give direct agent calls the same host policy as orchestrated stages."""
    import functools
    import inspect
    signature = inspect.signature(function)

    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        if current_scope() is not None:
            return function(*args, **kwargs)
        arguments = signature.bind(*args, **kwargs)
        arguments.apply_defaults()
        import os
        policy = scope_for_target(
            arguments.arguments['domain'],
            allow_private=os.getenv('CYBERSHIELD_ALLOW_PRIVATE', 'false').lower() == 'true',
            offline=arguments.arguments.get('use_mock', False),
        )
        with target_scope(policy):
            return function(*args, **kwargs)
    return wrapped



def scoped_dns_name(domain: str) -> str:
    """DNS/WHOIS may query the authorized name, not follow discovered hosts.

    DNS uses the deployment's configured resolver. MX/NS/TXT answers are
    evidence only and are never used as permission to connect to another host.
    """
    name = normalize_target(domain).host
    active = current_scope()
    if active:
        if active.offline:
            raise TargetPolicyError("Network requests are disabled in demo mode")
        if not any(host == name for _, host, _ in active.origins):
            raise TargetPolicyError("DNS query leaves the authorized scan scope")
    return name
