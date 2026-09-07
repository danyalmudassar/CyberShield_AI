#!/usr/bin/env python3
"""Create a private cloud configuration; never creates billable cloud resources."""
import argparse
import getpass
import os
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, help='Public DNS name pointing to this server, without https://')
    args = parser.parse_args()
    domain = args.domain.lower().strip()
    if len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', domain):
        parser.error('Supply a DNS hostname such as security.example.com; no scheme, port or path.')
    root = Path(__file__).resolve().parents[2]
    config = root / '.cloud.env'
    private = root / 'deploy/cloud/runtime'
    secret = private / 'operator_password'
    if config.exists() or secret.exists():
        parser.error('Cloud configuration already exists. Refusing to overwrite credentials.')
    password = getpass.getpass('Set operator password (12–256 characters): ')
    if not 12 <= len(password) <= 256 or '\n' in password or '\r' in password:
        parser.error('Use 12–256 characters with no newlines.')
    if password != getpass.getpass('Confirm operator password: '):
        parser.error('Passwords do not match.')
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    private.chmod(0o700)
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write(password)
    # Docker bind-mount secrets are readable by the non-root container UID;
    # the 0700 host parent prevents other local users from traversing to the file.
    secret.chmod(0o644)
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(f'CYBERSHIELD_DOMAIN={domain}\nCYBERSHIELD_OPERATOR_PASSWORD_FILE=./deploy/cloud/runtime/operator_password\n')
    print('Private configuration saved. Start the stack with:')
    print('docker compose --env-file .cloud.env -p cybershield-cloud -f compose.cloud.yaml up -d --build --wait')
    print(f'After DNS and certificate provisioning, open https://{domain}/login')
    print('Account: operator@cybershield.ai. Keep your configured password private.')


if __name__ == '__main__':
    main()
