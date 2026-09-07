"""Check public readiness, login delivery and authentication without credentials."""
import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "CyberShield-Uptime/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.headers.get_content_type(), response.read(65537)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.headers.get_content_type(), error.read(65537)


def check(base_url, transport=fetch):
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Supply an HTTPS origin without credentials, query or path")
    results = []
    for path in ("/api/ready", "/login", "/api/scans"):
        try:
            status, content_type, body = transport(base_url.rstrip("/") + path)
            if path == "/api/ready":
                ok = status == 200 and len(body) <= 65536 and json.loads(body).get("status") == "ready"
            elif path == "/login":
                ok = status == 200 and content_type == "text/html"
            else:
                ok = status == 401
            results.append({"path": path, "status": status, "ok": bool(ok)})
        except (OSError, ValueError, AttributeError) as error:
            results.append({"path": path, "ok": False, "error_type": type(error).__name__})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    args = parser.parse_args()
    try:
        results = check(args.origin)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"checks": results}, indent=2))
    return 0 if all(result["ok"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
