"""Offline, local backup bundles. Run with `python -m services.backup --help`.

Stop every API/writer before creation. A worker lock prevents accidental worker
startup but cannot exclude independent SQLite writers. Bundles contain secrets
(password hashes and session digests); keep them in private, encrypted storage.
"""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile


@contextmanager
def _database(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        yield conn


def _regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected a regular file: {path.name}')
    return path


def _digest(path):
    with _regular(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _check_database(path, tables):
    with _database(path) as conn:
        if conn.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Database integrity check failed')
        if conn.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Database foreign-key check failed')
        actual = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables <= actual:
            raise ValueError('Unsupported database schema')


def _check_reports(root):
    with _database(root / 'data/scans.sqlite3') as conn:
        for (raw,) in conn.execute('SELECT result FROM scans WHERE result IS NOT NULL'):
            result = json.loads(raw)
            name = result.get('pdf_path') if isinstance(result, dict) else None
            if name:
                if not isinstance(name, str) or '/' in name or '\\' in name or name.startswith('.') or not name.endswith('.pdf'):
                    raise ValueError('Unsafe report reference in scan database')
                with _regular(root / 'reports' / name).open('rb') as report:
                    if report.read(4) != b'%PDF':
                        raise ValueError('Referenced report is not a PDF')


def verify(bundle):
    root = Path(bundle)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Bundle must be a real directory')
    manifest = json.loads(_regular(root / 'manifest.json').read_text())
    if manifest.get('format') != 1 or not isinstance(manifest.get('files'), dict):
        raise ValueError('Unsupported backup format')
    files = manifest['files']
    if not {'data/scans.sqlite3', 'data/auth.sqlite3'} <= files.keys():
        raise ValueError('Bundle is missing databases')
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Bundle contains a symlink or special file')
        if path.is_file() and path != root / 'manifest.json':
            actual.add(path.relative_to(root).as_posix())
    if actual != set(files):
        raise ValueError('Bundle file inventory mismatch')
    for name, metadata in files.items():
        parts = Path(name).parts
        if name not in ('data/scans.sqlite3', 'data/auth.sqlite3') and not (
            len(parts) == 2 and parts[0] == 'reports' and parts[1].endswith('.pdf')
            and not parts[1].startswith('.') and '\\' not in name
        ):
            raise ValueError('Unsafe bundle file path')
        path = root / name
        if path.stat().st_size != metadata['size'] or _digest(path) != metadata['sha256']:
            raise ValueError('Bundle checksum mismatch')
    _check_database(root / 'data/scans.sqlite3', {'scans', 'scan_events'})
    _check_database(root / 'data/auth.sqlite3', {'users', 'sessions', 'login_limits'})
    _check_reports(root)
    return manifest


@contextmanager
def _destination(destination):
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('Destination already exists; choose a new directory')
    with tempfile.TemporaryDirectory(prefix='.cybershield-staging-', dir=destination.parent) as temporary:
        root = Path(temporary)
        yield root
        for path in root.rglob('*'):
            if path.is_file():
                path.chmod(0o600)
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
            elif path.is_dir():
                path.chmod(0o700)
        for directory in [p for p in root.rglob('*') if p.is_dir()] + [root]:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if destination.exists() or destination.is_symlink():
            raise ValueError('Destination already exists; choose a new directory')
        root.rename(destination)
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def create(scan_db, auth_db, reports, destination, *, offline=False):
    if not offline:
        raise ValueError('Stop all API/writer processes and supply --offline')
    scan_db, auth_db = _regular(scan_db).resolve(), _regular(auth_db).resolve()
    reports = Path(reports)
    if reports.is_symlink() or not reports.is_dir():
        raise ValueError('Reports must be a real directory')
    target = Path(destination).resolve()
    if target == reports.resolve() or reports.resolve() in target.parents:
        raise ValueError('Backup destination cannot be inside reports')
    fd = os.open(str(scan_db) + '.worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Stop the active scan worker before backup') from exc
        with _destination(destination) as root:
            (root / 'data').mkdir(mode=0o700)
            (root / 'reports').mkdir(mode=0o700)
            for source, name in [(scan_db, 'scans.sqlite3'), (auth_db, 'auth.sqlite3')]:
                with _database(source) as src, closing(sqlite3.connect(root / 'data' / name)) as dst:
                    src.backup(dst)
                    dst.execute('PRAGMA journal_mode=DELETE')
            for source in reports.iterdir():
                if source.suffix == '.pdf':
                    shutil.copyfile(_regular(source), root / 'reports' / source.name)
                elif source.is_symlink() or not source.is_file():
                    raise ValueError('Reports directory contains a symlink or nested directory')
            files = {p.relative_to(root).as_posix(): {'size': p.stat().st_size, 'sha256': _digest(p)}
                     for p in root.rglob('*') if p.is_file()}
            manifest = {'format': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'files': files}
            (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            verify(root)
    return manifest


def restore(bundle, destination):
    verify(bundle)
    with _destination(destination) as root:
        shutil.copytree(bundle, root, dirs_exist_ok=True, symlinks=True)
        verify(root)  # Verify the copied bytes before opening restored databases for writes.
        with closing(sqlite3.connect(root / 'data/auth.sqlite3')) as conn:
            with conn:
                revoked = conn.execute('DELETE FROM sessions').rowcount
        from services.scan_store import ScanStore
        store = ScanStore(root / 'data/scans.sqlite3')
        with _database(store.path) as conn:
            pending = conn.execute("SELECT id, status FROM scans WHERE status IN ('queued','running','cancelling')").fetchall()
        for scan_id, status in pending:
            store.finish_scan(scan_id, 'cancelled' if status == 'queued' else 'interrupted',
                              error='Restored backup: explicit new authorization required before another scan')
        # Remove WAL dependence before publishing the restored directory.
        with closing(sqlite3.connect(store.path)) as conn:
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            conn.execute('PRAGMA journal_mode=DELETE')
        _check_reports(root)
        # Restored databases intentionally differ from the immutable source bundle.
        (root / 'manifest.json').unlink()
        summary = {'sessions_revoked': revoked, 'pending_scans_stopped': len(pending)}
        (root / 'restore.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    backup = commands.add_parser('create')
    for name in ('scan-db', 'auth-db', 'reports', 'destination'):
        backup.add_argument('--' + name, required=True, type=Path)
    backup.add_argument('--offline', action='store_true', help='Confirm every API/writer has been stopped')
    check = commands.add_parser('verify')
    check.add_argument('bundle', type=Path)
    recover = commands.add_parser('restore')
    recover.add_argument('bundle', type=Path)
    recover.add_argument('--destination', required=True, type=Path)
    args = vars(parser.parse_args())
    command = args.pop('command')
    try:
        result = {'create': create, 'verify': verify, 'restore': restore}[command](**args)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as exc:
        parser.exit(1, f'Backup operation failed: {exc}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
