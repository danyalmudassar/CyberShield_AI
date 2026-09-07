"""
CyberShield AI — Worker Pool Concurrency Tests
================================================
Task 09: Bounded worker pool managing MAX_CONCURRENT_SCANS
with scan queueing and execution bounds.
"""

import time
import pytest
from models import ScanState
from services.scan_store import ScanStore
from services.scan_worker import ScanWorker


def mock_slow_runner(**kwargs):
    time.sleep(0.2)
    return ScanState(scan_progress={"status": "COMPLETED"})


def test_bounded_worker_concurrency(tmp_path):
    store = ScanStore(tmp_path / "scans.db")
    config = {"domain": "example.invalid", "authorized": True, "execution_mode": "demo"}

    job1 = store.create_scan(config, owner="test")
    job2 = store.create_scan(config, owner="test")
    job3 = store.create_scan(config, owner="test")

    def dummy_serialize(state):
        return {"scan_progress": state.scan_progress, "status": "completed"}

    # Limit to max 2 concurrent workers
    worker_pool = ScanWorker(store, dummy_serialize, runner=mock_slow_runner, max_workers=2)
    worker_pool.start()

    time.sleep(0.5)

    # All 3 jobs should complete eventually without deadlock
    time.sleep(0.5)
    worker_pool.stop()

    assert store.get_scan(job1["id"], owner="test")["status"] == "completed"
    assert store.get_scan(job2["id"], owner="test")["status"] == "completed"
    assert store.get_scan(job3["id"], owner="test")["status"] == "completed"
