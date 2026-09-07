# Target scope and transport policy

Implemented 2026-09-07. This describes application-level target egress, not an OS network sandbox or full production certification.

## Authorized target

- A bare host authorizes HTTP on port 80 and HTTPS on port 443.
- A bare host with an explicit port authorizes HTTP/HTTPS on that port only.
- An explicit URL authorizes that exact scheme, hostname, and effective port.
- API targets remain whole-host assessments: path prefixes and queries are rejected at scan creation.
- The API persists the original `scope_target`; the worker carries that policy into every spawned stage. Direct calls to scan agents also establish a scope.
- Demo scope forbids target and intelligence transport calls before DNS or socket creation.

## HTTP, TLS, sessions and redirects

All target HTTP probes use `ScopedSession` / `ScopeAdapter`. This includes header and technology scans, visual HTTP checks, pentest helpers and specialized probes, reachability, crawler requests, and authenticated login requests.

Every prepared request is checked at the adapter boundary. Every DNS answer must satisfy address policy. New TCP connections go directly to validated IP literals, without a second name lookup. The URL, Host header, and TLS server hostname remain the original hostname; normal certificate verification is preserved. Diagnostic callers that explicitly request `verify=False` still use the same address/scope restrictions.

Each redirect is checked before following it. A no-follow probe may retain the original redirect response as evidence without contacting the destination. Scheme changes, different hosts, different ports, non-HTTP URLs, and metadata destinations are rejected. Same-origin redirects revalidate DNS before the next send. A previously established pooled connection remains bound to its original checked address; a DNS answer becoming private blocks the next request even if a connection is reusable.

No global `socket.getaddrinfo` replacement is installed. HTTP adapters use dedicated connection classes. Compatibility DNS-binding helpers remain for existing callers/tests but are not the production socket mechanism.

Sessions are newly created per caller; authentication cookies are not shared globally. A caller-supplied ordinary `requests.Session` is rejected. Sessions bind to their configured origin(s), and enclosing scan policy can only narrow access. Host-header overrides cannot route requests to another virtual host. Environment proxies and explicit proxies are disabled for target transport. Private-lab policy is not transmitted in an HTTP header.

## Private labs and infrastructure egress

`CYBERSHIELD_ALLOW_PRIVATE=true` is an explicit deployment permission for supported RFC1918, loopback and ULA lab ranges. It never permits link-local, cloud metadata, multicast, unspecified or other unsupported nonpublic addresses. A per-call flag cannot broaden an enclosing scan policy.

DNS record collection queries only the authorized name (plus its email-security record names), using the deployment's configured DNS resolver. Discovered MX/NS/TXT values are evidence, not newly authorized network targets.

WHOIS starts at IANA and follows at most two registry/registrar referrals. Every port-43 connection uses public-only address validation and direct IP pinning. Each response is limited to 256 KiB and each socket operation has a timeout. The Python WHOIS package is used only to parse records; its network client is not invoked. Registry infrastructure is separate from the scanned site's HTTP origin.

NVD, VirusTotal and Shodan use an explicit service-origin allowlist and the same pinned HTTP transport. A service request cannot choose another origin or broaden subsequent target requests. AI provider endpoints remain operator configuration governed by the existing execution-mode policy; this is not a general-purpose firewall around third-party SDKs.

## Verification

```bash
python -m pytest -q
python -m pytest tests/test_transport_local.py -m integration -q
```

The ordinary suite tests policy, real Requests preparation/redirect code, adapter enforcement, socket destinations, caller-session rejection, crawler links/forms, credential redirects, provider separation, WHOIS metadata referrals, and scope propagation into a real spawned stage. DNS and wire exchanges are mocked for those tests.

The separately selected integration test starts a temporary loopback TLS server with a locally generated certificate. It verifies actual Requests/urllib3 socket behavior, trusted certificate validation, SNI, Host preservation, same-origin redirects, metadata redirect blocking, and ignored proxy environment variables. It requires the local `openssl` executable and makes no external-target requests.

Public deployment still requires credential/session hardening, deployment-level egress controls, operational recovery validation, and the wider release acceptance matrix. These changes do not validate scanner vulnerability coverage or establish an authoritative PISF crosswalk.
