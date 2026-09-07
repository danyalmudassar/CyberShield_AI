import os
import logging
import json
import time
import fcntl
from pathlib import Path
from threading import Event, Thread, Lock

from agents.orchestrator import run_full_scan, ScanFailed
from services.scan_store import TERMINAL_STATES
from utils.anonymizer import sanitize_secrets_only

from services.telemetry import event

logger = logging.getLogger(__name__)


class ScanWorker:
    def __init__(self, store, serialize, runner=run_full_scan, max_workers=None):
        self.store, self.serialize, self.runner = store, serialize, runner
        if max_workers is None:
            max_workers = int(os.getenv("CYBERSHIELD_MAX_CONCURRENT_SCANS", "2"))
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 16:
            raise ValueError('Concurrent scan workers must be between 1 and 16')
        self.max_workers = max_workers
        self._lifecycle_lock = Lock()
        self._lock_file = None
        self.stop_event = Event()
        self.active_threads = []
        self.thread = None
        self.last_poll = None

    def _acquire_ownership(self):
        if self._lock_file is not None:
            raise RuntimeError('This worker is already executing')
        path = str(Path(self.store.path).resolve()) + '.worker.lock'
        handle = open(path, 'a+b')
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise RuntimeError('Another worker already owns this scan database') from exc
        self._lock_file = handle

    def _release_ownership(self):
        if self._lock_file is not None:
            self._lock_file.close()
            self._lock_file = None

    def start(self):
        with self._lifecycle_lock:
            if self.thread and self.thread.is_alive():
                return
            self._acquire_ownership()
            try:
                self.store.interrupt_running()
                self.stop_event.clear()
                self.active_threads = []
                self.thread = Thread(target=self._loop, daemon=True, name='cybershield-worker-manager')
                self.thread.start()
            except BaseException:
                self._release_ownership()
                raise

    def stop(self, timeout=10):
        self.stop_event.set()
        deadline = time.monotonic() + timeout
        with self._lifecycle_lock:
            if self.thread:
                self.thread.join(timeout=max(0, deadline - time.monotonic()))
            for thread in self.active_threads:
                thread.join(timeout=max(0, deadline - time.monotonic()))
            if (self.thread and self.thread.is_alive()) or any(t.is_alive() for t in self.active_threads):
                # Keep exclusive ownership while any old execution remains alive.
                raise RuntimeError('Worker shutdown deadline exceeded; database ownership retained')
            self._release_ownership()

    def readiness(self):
        age = None if self.last_poll is None else max(0, time.monotonic() - self.last_poll)
        return {"ready": bool(self.thread and self.thread.is_alive() and self._lock_file
                              and not self.stop_event.is_set() and age is not None and age < 5),
                "poll_age_seconds": age, "active_workers": sum(t.is_alive() for t in self.active_threads),
                "max_workers": self.max_workers}

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self.active_threads = [t for t in self.active_threads if t.is_alive()]
                if len(self.active_threads) < self.max_workers:
                    job = self.store.claim_next()
                    if job:
                        t = Thread(target=self._run_job, args=(job,), daemon=True, name=f"cybershield-worker-{job['id'][:8]}")
                        self.active_threads.append(t)
                        t.start()
                    else:
                        self.stop_event.wait(0.1)
                else:
                    self.stop_event.wait(0.1)
                self.last_poll = time.monotonic()
            except Exception as exc:
                event("worker_poll_failed", error_type=type(exc).__name__)
                self.stop_event.wait(1)

    def run_once(self):
        """Synchronous single-job execution, exclusive with background workers."""
        with self._lifecycle_lock:
            self._acquire_ownership()
            try:
                job = self.store.claim_next()
                if job is None:
                    return False
                self._run_job(job)
                return True
            finally:
                self._release_ownership()

    def _run_job(self, job):
        scan_id, owner = job['id'], job['owner']
        started = time.monotonic()
        event('scan_started', scan_id=scan_id)
        self.store.append_event(scan_id, {'type': 'progress', 'stage': 'queued', 'message': 'Scan started', 'status': 'running'})
        def cancelled():
            current = self.store.get_scan(scan_id, owner)
            return self.stop_event.is_set() or current is None or current['status'] in ('cancelling', 'cancelled')
        def progress(stage, message):
            self.store.append_event(scan_id, {'type': 'progress', 'stage': stage, 'message': message})
        result, error, status = None, None, 'failed'
        try:
            config = dict(job['config'])
            state = self.runner(**config, progress_callback=progress, cancellation_check=cancelled, event_callback=lambda event: self.store.append_event(scan_id, event))
            result = self.serialize(state)
            result['scan_id'] = scan_id
            status = {'COMPLETED': 'completed', 'PARTIAL': 'partial', 'CANCELLED': 'cancelled', 'TIMED_OUT': 'timed_out'}.get(state.scan_progress.get('status'), 'failed')
        except ScanFailed as exc:
            try:
                result = self.serialize(exc.state)
                result['scan_id'] = scan_id
            except Exception as serialization_error:
                logger.warning('Failed to serialize partial scan %s: %s', scan_id, type(serialization_error).__name__)
                result = None
            scan_status = exc.state.scan_progress.get('status') if exc.state else ''
            if scan_status == 'CANCELLED':
                status = 'cancelled'
            elif scan_status == 'TIMED_OUT':
                status = 'timed_out'
            else:
                status = 'failed'
            error = sanitize_secrets_only(str(exc))
        except Exception as exc:
            error = sanitize_secrets_only(str(exc))
            event('scan_execution_failed', scan_id=scan_id, error_type=type(exc).__name__)
        try:
            json.dumps(result, allow_nan=False)
        except (TypeError, ValueError):
            result, status, error = None, 'failed', 'Scan result could not be serialized'
        if cancelled():
            status = 'interrupted' if self.stop_event.is_set() else 'cancelled'
        saved = self.store.finish_scan(scan_id, status, result=result, error=error)
        event('scan_finished', scan_id=scan_id, status=saved['status'],
              duration_seconds=round(time.monotonic() - started, 6))
