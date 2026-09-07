#!/usr/bin/env python3
"""Start the local CyberShield dashboard and durable scan API together."""
import argparse
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-live', action='store_true', help='Enable authorized live/rules-only assessments (default: fixtures only)')
    parser.add_argument('--api-port', type=int, default=8000)
    parser.add_argument('--ui-port', type=int, default=3000)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    backend, frontend = root / 'CyberShield_AI', root / 'frontend'
    npm = shutil.which('npm')
    if not npm or not (frontend / 'node_modules' / 'next').exists():
        parser.error('Install Node.js dependencies with: cd frontend && npm ci')
    if args.api_port == args.ui_port or any(not 1024 <= n <= 65535 for n in (args.api_port, args.ui_port)):
        parser.error('Choose distinct ports between 1024 and 65535')
    env = dict(os.environ)
    env['CYBERSHIELD_API_URL'] = f'http://127.0.0.1:{args.api_port}'
    env['CYBERSHIELD_ORIGINS'] = f'http://127.0.0.1:{args.ui_port},http://localhost:{args.ui_port}'
    env['CYBERSHIELD_DEMO_ONLY'] = 'false' if args.allow_live else 'true'
    env['CYBERSHIELD_REQUIRE_AUTH'] = 'true'
    # Both services bind to loopback; deployed HTTPS instances keep Secure=true.
    env['CYBERSHIELD_COOKIE_SECURE'] = 'false'
    configured = [env.get(f'CYBERSHIELD_{role}_PASSWORD', '') for role in ('ADMIN', 'OPERATOR')]
    if not any(configured):
        if not sys.stdin.isatty():
            parser.error('Set CYBERSHIELD_OPERATOR_PASSWORD (12–256 characters) before starting without a terminal')
        password = getpass.getpass('Set operator password (12–256 characters): ')
        confirmation = getpass.getpass('Confirm operator password: ')
        if password != confirmation or not 12 <= len(password) <= 256:
            parser.error('Passwords must match and contain 12–256 characters')
        env['CYBERSHIELD_OPERATOR_PASSWORD'] = password
        configured = [password]
    if any(password and not 12 <= len(password) <= 256 for password in configured):
        parser.error('Configured passwords must contain 12–256 characters')
    children = []
    try:
        children.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', str(args.api_port), '--no-access-log'], cwd=backend, env=env))
        children.append(subprocess.Popen([npm, 'run', 'dev', '--', '--hostname', '127.0.0.1', '--port', str(args.ui_port)], cwd=frontend, env=env, start_new_session=True))
        print(f'\nCyberShield: http://127.0.0.1:{args.ui_port}', flush=True)
        print('Mode: ' + ('authorized live scans enabled' if args.allow_live else 'fixture-only demonstration'), flush=True)
        print('Keep this terminal open. Press Ctrl+C to stop both services.\n', flush=True)
        while all(child.poll() is None for child in children):
            time.sleep(0.5)
        return next((child.returncode for child in children if child.returncode), 0)
    except KeyboardInterrupt:
        return 0
    finally:
        import signal
        for i, child in enumerate(children):
            if child.poll() is None:
                if i == 1:
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
        for child in children:
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == '__main__':
    raise SystemExit(main())
