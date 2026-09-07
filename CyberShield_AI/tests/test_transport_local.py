"""Real loopback HTTP/TLS acceptance; no external targets or providers."""
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from utils.http_client import get_session
from utils.target_policy import TargetPolicyError

pytestmark = pytest.mark.integration


def test_real_http_redirect_scope_and_tls_hostname(tmp_path, monkeypatch):
    openssl = shutil.which('openssl')
    assert openssl, 'Local TLS acceptance requires the openssl command'
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                   check=True, capture_output=True)
    seen, sni_names = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers['Host']))
            if self.path == '/escape':
                self.send_response(302)
                self.send_header('Location', 'http://169.254.169.254/latest/meta-data')
                self.end_headers()
            elif self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/final')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'local transport verified')
        def log_message(self, *args): pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_servername_callback(lambda sock, name, ctx: sni_names.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'https://localhost:{server.server_port}'
    # The scanner must ignore inherited proxies; IP pinning cannot be enforced
    # against a remotely resolving proxy.
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    try:
        with get_session(origin, allow_private=True) as session:
            response = session.get(origin + '/redirect', verify=str(cert), timeout=2)
            assert response.content == b'local transport verified'
            assert [path for path, _ in seen] == ['/redirect', '/final']
            assert all(host == f'localhost:{server.server_port}' for _, host in seen)
            assert sni_names and all(name == 'localhost' for name in sni_names)
            with pytest.raises(TargetPolicyError):
                session.get(origin + '/escape', verify=str(cert), timeout=2)
            assert [path for path, _ in seen] == ['/redirect', '/final', '/escape']
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
