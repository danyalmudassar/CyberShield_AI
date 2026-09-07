# Scan limits, exclusive workers and restart recovery

This slice is verified on Linux/Python 3.12 with a local SQLite database and the
`spawn` multiprocessing method. One API/worker manager owns each scan database;
it runs several scans concurrently. This is not a distributed worker service.

## Admission and runtime limits

| Setting | Default | Accepted bounds |
|---|---:|---|
| `CYBERSHIELD_MAX_CONCURRENT_SCANS` | 2 | Integer 1–16 |
| `CYBERSHIELD_MAX_PENDING_SCANS` | 100 | Integer 1–10,000 |
| API `max_duration_seconds` | 300 | Integer 1–900 |
| API `max_stage_seconds` | 120 | Integer 1–300 |

Pending capacity counts queued, running and cancelling jobs. Capacity checks and
insertion use one SQLite write transaction, including simultaneous submissions.
A full queue returns HTTP 429 with `Retry-After: 5` and creates no job. An existing
idempotency-key retry returns its original job even when the queue is full.
Terminal jobs do not consume pending capacity; history/disk retention is separate.

Both duration fields are optional in POST `/api/scans`, are saved in the job's
configuration, and are forwarded to the real orchestrator. Existing queued jobs
that omit these fields use the current defaults. Booleans, fractional
API durations, zero and out-of-range values are rejected. Direct Python callers
may use positive finite fractional durations for testing, with the same maximums.
Neither caller can disable the deadline with zero/negative/NaN/infinity.

The total scan budget starts when pipeline execution begins, excluding queue wait
and API admission/preflight. Each stage has a separate budget, bounded by the
remaining scan budget. Deadlines use [monotonic time](https://docs.python.org/3.12/library/time.html#time.monotonic),
so wall-clock changes cannot extend a scan. Expiry ends the scan as `TIMED_OUT`,
including partial evidence available at that point; it does not promise a PDF.
Checks poll at short intervals; process startup, IPC and termination/reaping add
small overhead beyond the configured duration. These are execution deadlines,
not real-time scheduling guarantees or per-request/probe throttles.

## Worker ownership and shutdown

A POSIX advisory [file lock](https://docs.python.org/3.12/library/fcntl.html#fcntl.flock)
at `<resolved scan database path>.worker.lock` is acquired before startup recovery.
Starting another manager or synchronous `run_once()` against that database fails
without marking the existing manager's jobs interrupted. Starting the same active
manager twice is idempotent. Do not delete the lock file while a worker is running;
the OS lock, not file existence, represents ownership.

Shutdown signals cancellation and joins all active workers against one shared
10-second budget. Ownership is released only once they have stopped. If shutdown
cannot finish, it raises an explicit error and retains ownership; another manager
cannot start over continuing execution. Custom in-process test runners must obey
cancellation themselves. Production defaults use stoppable stage processes.

## Stage processes and abrupt worker loss

Cancellation/deadline handling terminates and reaps the active stage. Pipe cleanup
also runs if process startup fails. Nonserializable stages continue to fail
explicitly; the existing `CYBERSHIELD_STAGE_ISOLATION=thread` path is for explicit
in-memory tests and does **not** provide hard termination.

On Linux, stages install [PR_SET_PDEATHSIG/SIGKILL](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)
so loss of their creating thread/process stops them even during native code that
holds the Python GIL. A multiprocessing-parent sentinel watchdog also detects
parent loss and the registration race. The real crash test kills the worker
process, checks that its exact stage PID no longer executes, then starts another
manager. A container init may need to reap an adopted zombie; zombies cannot run
probes. Container/service supervision should still reap processes and enforce
CPU/memory/egress limits. Arbitrary stage-created subprocess trees and non-Linux
native-code behavior are not covered by this Linux acceptance result.

## Durable results and replay

A single transaction writes the terminal status, result and terminal SSE event.
Failure to write the event rolls the state update back as well. Finalization checks
cancellation inside this transaction: cancellation already requested wins over a
late success result. A repeated/stale finalizer cannot overwrite an existing
terminal result or emit another completion event. Embedded result status matches
the database status. Queued cancellation also records a terminal event.

Exclusive startup marks previously running/cancelling jobs `interrupted`, preserves
any already-persisted evidence, and records a replayable completion event in the
same transaction. It does not silently rerun those scans. Queued jobs resume;
completed/failed/cancelled/timed-out jobs remain unchanged. Repeating recovery is
idempotent. Recovery cannot reconstruct findings held only in a crashed process's
memory. SSE emits an available terminal event once; reconnection after that event
can still return a terminal snapshot without executing the scan again.

## Verification

```bash
python -m pytest tests/test_worker_recovery.py tests/test_scan_lifecycle.py tests/test_scan_deadlines.py -q
```

Coverage includes atomic admission under concurrent submission, actual peak worker
concurrency, exclusive startup, shutdown lock retention, cancel/finalize races,
transaction rollback, abrupt worker loss with a real spawned stage, stage/scan
budgets, and a real authenticated API demo scan whose PDF/result/event survive an
application lifespan restart. These tests use local fixtures, not external targets
or model calls. Production container packaging, backups/restore, retention,
per-probe limits and wider deployed acceptance remain separate work.
