"""Worker lease fencing tests — zombie-worker protection."""
from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path

import pytest

from src.agents.worker_lease import (
    WorkerLease,
    WorkerLeaseStore,
    WorkerWatchdog,
    watchdog_for,
)


# ---------------------------------------------------------------------------
# store basics


def test_lease_acquire_and_renew(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    lease = store.acquire("w1", pid=12345, ttl_seconds=30)
    assert lease.sequence == 1
    assert lease.pid == 12345
    renewed = store.renew("w1", ttl_seconds=30)
    assert renewed is not None
    assert renewed.sequence == 2
    loaded = store.load("w1")
    assert loaded is not None
    assert loaded.sequence == 2


def test_lease_renew_missing_returns_none(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    assert store.renew("nope") is None


def test_lease_update_pid_corrects_fence_target(tmp_path: Path) -> None:
    """The supervisor records its own pid at acquire; update_pid swaps in the
    real agent subprocess pid so the watchdog fences the agent, not itself."""
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    store.acquire("w1", pid=os.getpid(), ttl_seconds=30)
    updated = store.update_pid("w1", pid=4242)
    assert updated is not None
    assert updated.pid == 4242
    # A pid correction must not rewind or bump the monotonic fencing token,
    # nor extend liveness.
    assert updated.sequence == 1
    loaded = store.load("w1")
    assert loaded is not None
    assert loaded.pid == 4242


def test_lease_update_pid_missing_returns_none(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    assert store.update_pid("nope", pid=4242) is None


def test_lease_release_delete(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    store.acquire("w1", pid=1)
    store.release("w1")
    assert store.load("w1") is None


def test_lease_path_rejects_traversal(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    with pytest.raises(ValueError):
        store.acquire("../evil", pid=1)
    with pytest.raises(ValueError):
        store.acquire("a/b", pid=1)
    with pytest.raises(ValueError):
        store.acquire("..", pid=1)


def test_lease_partial_write_is_lost(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    lease_path = tmp_path / "audit-1" / "leases" / "w1.json"
    lease_path.write_text("{ not json")
    assert store.load("w1") is None  # corrupted -> lost


def test_lease_schema_validation(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    lease_path = tmp_path / "audit-1" / "leases" / "w1.json"
    lease_path.write_text(json.dumps({
        "schema_version": "wrong", "audit_id": "a", "worker_id": "w1",
        "sequence": 1, "renewed_ns": 1, "expires_ns": 1, "pid": 1, "meta": {},
    }))
    assert store.load("w1") is None


def test_worker_lease_round_trip() -> None:
    lease = WorkerLease(
        audit_id="a", worker_id="w1", sequence=3, renewed_ns=10, expires_ns=20,
        pid=99, meta={"task": "slice-3"},
    )
    back = WorkerLease.from_dict(lease.as_dict())
    assert back.sequence == 3 and back.pid == 99 and back.meta == {"task": "slice-3"}


# ---------------------------------------------------------------------------
# watchdog behavior — no actual process killing in unit tests


def _wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_watchdog_fires_when_lease_expired(tmp_path: Path) -> None:
    """Lease stops renewing → on_lost fires; no actual kill in-process."""
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    store.acquire("w1", pid=os.getpid(), ttl_seconds=0.3)
    fired = threading.Event()
    seen: list = []

    def on_lost(lease):
        seen.append(lease)
        fired.set()

    # target_pid=None: on_lost runs but _reap skips process-kill (no suicide).
    wd = WorkerWatchdog(store, "w1", on_lost=on_lost,
                        watch_interval=0.05, consecutive_lost=1)
    wd.start()
    try:
        assert _wait_for(fired.is_set, timeout=5.0)
        assert seen and seen[0] is not None
        assert seen[0].worker_id == "w1"
    finally:
        wd.stop()


def test_watchdog_ignores_healthy_renewals(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    store.acquire("w1", pid=os.getpid(), ttl_seconds=1.0)
    fired = threading.Event()
    wd = WorkerWatchdog(store, "w1", on_lost=lambda *_: fired.set(),
                        watch_interval=0.05, consecutive_lost=3)
    wd.start()
    time.sleep(0.2)
    store.renew("w1", ttl_seconds=5.0)  # healthy renew before first expiry
    time.sleep(0.25)
    assert not fired.is_set()
    wd.stop()


def test_watchdog_missing_lease_reaps(tmp_path: Path) -> None:
    store = WorkerLeaseStore(tmp_path, audit_id="audit-1")
    fired = threading.Event()
    wd = WorkerWatchdog(store, "w1", on_lost=lambda *_: fired.set(),
                        watch_interval=0.05, consecutive_lost=2)
    wd.start()
    assert _wait_for(fired.is_set, timeout=3.0)
    wd.stop()


def test_watchdog_for_helper(tmp_path: Path) -> None:
    wd = watchdog_for("audit-x", "w1", control_state_root=tmp_path)
    assert wd.worker_id == "w1"
    wd.stop()  # no-op before start
