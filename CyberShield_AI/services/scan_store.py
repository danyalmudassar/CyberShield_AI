"""SQLite-backed scan queue and replayable events.

Each operation owns its connection. Write transactions use BEGIN IMMEDIATE so
queue claims, idempotency checks, and per-scan event numbering are atomic across
threads and processes. Configurations must contain JSON values, never secrets.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4


TERMINAL_STATES = frozenset({'completed', 'partial', 'failed', 'cancelled', 'interrupted', 'timed_out'})
TRANSITIONS = {
    'queued': {'running', 'cancelled'},
    'running': TERMINAL_STATES | {'cancelling'},
    'cancelling': TERMINAL_STATES,
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class QueueCapacityError(RuntimeError):
    """Admission refused without creating a scan or changing an existing job."""


class ScanStore:
    def __init__(self, path, max_pending=None):
        self.max_pending = int(os.getenv('CYBERSHIELD_MAX_PENDING_SCANS', '100')) if max_pending is None else max_pending
        if isinstance(self.max_pending, bool) or not isinstance(self.max_pending, int) or not 1 <= self.max_pending <= 10000:
            raise ValueError('Pending scan capacity must be between 1 and 10000')
        self.path = str(path)
        if self.path == ':memory:':
            raise ValueError('ScanStore requires a persistent database path')
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    idempotency_key TEXT,
                    config TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    result TEXT,
                    error TEXT,
                    UNIQUE(owner, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS scans_queue ON scans(status, created_at);
                CREATE INDEX IF NOT EXISTS scans_owner ON scans(owner, created_at);
                CREATE TABLE IF NOT EXISTS scan_events (
                    scan_id TEXT NOT NULL REFERENCES scans(id),
                    sequence INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(scan_id, sequence)
                );
            ''')

    @contextmanager
    def _connection(self, write=False):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA busy_timeout=30000')
            conn.execute('PRAGMA foreign_keys=ON')
            if write:
                conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _scan(row):
        if row is None:
            return None
        scan = dict(row)
        for key in ('config', 'result', 'error'):
            scan[key] = json.loads(scan[key]) if scan[key] is not None else None
        return scan

    def create_scan(self, config, owner='local', idempotency_key=None):
        if not isinstance(config, dict):
            raise ValueError('Scan configuration must be an object')
        payload = _json(config)
        with self._connection(write=True) as conn:
            if idempotency_key is not None:
                row = conn.execute('SELECT * FROM scans WHERE owner=? AND idempotency_key=?',
                                   (owner, idempotency_key)).fetchone()
                if row:
                    if row['config'] != payload:
                        raise ValueError('Idempotency key already used with different configuration')
                    return self._scan(row)
            pending = conn.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running','cancelling')").fetchone()[0]
            if pending >= self.max_pending:
                raise QueueCapacityError('Pending scan capacity reached; retry after an active scan finishes')
            scan_id, now = str(uuid4()), _now()
            conn.execute('''INSERT INTO scans
                (id, owner, idempotency_key, config, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'queued', ?, ?)''',
                (scan_id, owner, idempotency_key, payload, now, now))
            return self._scan(conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())

    def get_scan(self, scan_id, owner=None):
        with self._connection() as conn:
            if owner is None:
                return self._scan(conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())
            return self._scan(conn.execute('SELECT * FROM scans WHERE id=? AND owner=?',
                                           (scan_id, owner)).fetchone())

    def list_scans(self, owner=None, limit=50):
        if not isinstance(limit, int) or not 0 <= limit <= 1000:
            raise ValueError('limit must be between 0 and 1000')
        with self._connection() as conn:
            if owner is None:
                rows = conn.execute('SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ?',
                                    (limit,)).fetchall()
            else:
                rows = conn.execute('SELECT * FROM scans WHERE owner=? ORDER BY created_at DESC, id DESC LIMIT ?',
                                    (owner, limit)).fetchall()
            return [self._scan(row) for row in rows]

    def get_scan_by_pdf(self, pdf_filename):
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM scans WHERE result IS NOT NULL").fetchall()
            for row in rows:
                scan = self._scan(row)
                if scan.get('result') and scan['result'].get('pdf_path') == pdf_filename:
                    return scan
            return None

    def update_scan(self, scan_id, status, result=None, error=None):
        """Internal worker operation; preserve stored evidence when omitted."""
        result_json = _json(result) if result is not None else None
        error_json = _json(error) if error is not None else None
        with self._connection(write=True) as conn:
            row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if row is None:
                raise KeyError(scan_id)
            if status != row['status'] and status not in TRANSITIONS.get(row['status'], ()):
                raise ValueError(f"Invalid scan transition: {row['status']} -> {status}")
            now = _now()
            conn.execute('''UPDATE scans SET status=?, updated_at=?,
                started_at=COALESCE(started_at, ?), finished_at=COALESCE(finished_at, ?),
                result=COALESCE(?, result), error=COALESCE(?, error) WHERE id=?''',
                (status, now, now if status == 'running' else None,
                 now if status in TERMINAL_STATES else None, result_json, error_json, scan_id))
            return self._scan(conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())

    @staticmethod
    def _append_event(conn, scan_id, event):
        payload = dict(event)
        sequence = conn.execute('SELECT COALESCE(MAX(sequence), 0) + 1 FROM scan_events WHERE scan_id=?',
                                (scan_id,)).fetchone()[0]
        payload['id'] = sequence
        conn.execute('INSERT INTO scan_events(scan_id, sequence, payload) VALUES (?, ?, ?)',
                     (scan_id, sequence, _json(payload)))
        return payload

    def append_event(self, scan_id, event):
        if not isinstance(event, dict):
            raise ValueError('Event must be an object')
        with self._connection(write=True) as conn:
            if conn.execute('SELECT 1 FROM scans WHERE id=?', (scan_id,)).fetchone() is None:
                raise KeyError(scan_id)
            return self._append_event(conn, scan_id, event)

    def _finish_scan(self, conn, scan_id, status, result, error):
        row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
        if row is None:
            raise KeyError(scan_id)
        if row['status'] in TERMINAL_STATES:
            return self._scan(row)
        if status not in TRANSITIONS.get(row['status'], ()):
            raise ValueError(f"Invalid scan transition: {row['status']} -> {status}")
        if row['status'] == 'cancelling' and status != 'interrupted':
            status = 'cancelled'
        if result is None:
            result = json.loads(row['result']) if row['result'] else None
        if isinstance(result, dict):
            result = dict(result)
            progress = result.get('scan_progress')
            result['scan_progress'] = {**(progress if isinstance(progress, dict) else {}), 'status': status.upper()}
        now = _now()
        conn.execute('UPDATE scans SET status=?, updated_at=?, finished_at=?, result=?, error=? WHERE id=?',
                     (status, now, now, _json(result) if result is not None else None,
                      _json(error) if error is not None else None, scan_id))
        self._append_event(conn, scan_id, {'type': 'complete', 'status': status, 'state': result,
                                         'message': error or f'Scan {status}', 'error': error})
        return self._scan(conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())

    def finish_scan(self, scan_id, status, result=None, error=None):
        """Commit result, terminal status and replayable event in one transaction."""
        if status not in TERMINAL_STATES:
            raise ValueError('finish_scan requires a terminal status')
        with self._connection(write=True) as conn:
            return self._finish_scan(conn, scan_id, status, result, error)

    def events_after(self, scan_id, after=0):
        with self._connection() as conn:
            rows = conn.execute('SELECT payload FROM scan_events WHERE scan_id=? AND sequence>? ORDER BY sequence',
                                (scan_id, after)).fetchall()
            return [json.loads(row['payload']) for row in rows]

    def interrupt_running(self):
        """Exclusive worker startup recovery; never restart partially executed scans."""
        with self._connection(write=True) as conn:
            rows = conn.execute("SELECT id FROM scans WHERE status IN ('running','cancelling')").fetchall()
            for row in rows:
                self._finish_scan(conn, row['id'], 'interrupted', None, 'Worker stopped before scan completion')
            return len(rows)

    def claim_next(self):
        with self._connection(write=True) as conn:
            row = conn.execute("SELECT * FROM scans WHERE status='queued' ORDER BY created_at, id LIMIT 1").fetchone()
            if row is None:
                return None
            now = _now()
            conn.execute("UPDATE scans SET status='running', started_at=?, updated_at=? WHERE id=?",
                         (now, now, row['id']))
            return self._scan(conn.execute('SELECT * FROM scans WHERE id=?', (row['id'],)).fetchone())

    def cancel_scan(self, scan_id, owner=None):
        with self._connection(write=True) as conn:
            if owner is None:
                row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            else:
                row = conn.execute('SELECT * FROM scans WHERE id=? AND owner=?', (scan_id, owner)).fetchone()
            if row is None:
                return None
            status = {'queued': 'cancelled', 'running': 'cancelling'}.get(row['status'])
            if status == 'cancelled':
                return self._finish_scan(conn, scan_id, 'cancelled', None, None)
            if status:
                now = _now()
                conn.execute('UPDATE scans SET status=?, updated_at=?, finished_at=? WHERE id=?',
                             (status, now, now if status == 'cancelled' else None, scan_id))
                row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            return self._scan(row)
