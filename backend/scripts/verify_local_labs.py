"""Opt-in, read-only local lab smoke. Not a vulnerability recall benchmark."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agents.pentest_agent import _check_cookie_flags, _check_directory_listing
from utils.auth_session import create_authenticated_session
from utils.target_policy import target_scope, scope_for_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authorized-local-labs', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def expired(*_):
        raise SystemExit('Local lab acceptance exceeded 45 seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(45)
    results = []
    for name, url in [('DVWA', 'http://127.0.0.1:8080'), ('Juice Shop', 'http://127.0.0.1:3001')]:
        with target_scope(scope_for_target(url, allow_private=True)):
            checks = [_check_cookie_flags(url), _check_directory_listing(url)]
            row = {'lab': name, 'target': url, 'checks': [asdict(f) for f in checks]}
            if name == 'DVWA':
                session = create_authenticated_session(url + '/login.php', 'admin', 'password',
                            csrf_field='user_token', success_indicator='Logout', extra_fields={'Login': 'Login'})
                row['fixture_login_verified'] = session is not None
                if session is not None:
                    session.close()
            results.append(row)
    signal.alarm(0)
    artifact = {'created_at': datetime.now(timezone.utc).isoformat(),
                'scope': 'Two read-only check types per local lab; one DVWA fixture login. No recall claim.',
                'results': results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + '\n')
    print(json.dumps([{'lab': row['lab'], 'checks': {f['check_id']: f['check_status'] for f in row['checks']},
                       'fixture_login_verified': row.get('fixture_login_verified')} for row in results], indent=2))
    if any(row.get('fixture_login_verified') is False for row in results) or any(
        f['check_status'] in ('UNREACHABLE', 'ERROR') for row in results for f in row['checks']
    ):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
