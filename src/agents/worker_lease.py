"""Worker lease fencing: reap zombie workers when their lease dies.

Research basis (QM ``src/runs/worker.ts`` heartbeat + abort-on-lost-lease):
    a worker renews a lease at ~`ttl/3`; when the supervisor stops renewing
    the lease expires.  After `consecutive_lost` missed renewals a watchdog
    reaps the agent subprocess (SIGTERM → 2s → SIGKILL).

    This covers the *graceful* paths (Ctrl-C, a wedged renew loop, explicit
    shutdown).  A supervisor *crash or OOM-kill* cannot be fenced by a thread
    that dies with the supervisor, so that half is handled by the kernel:
    runtime.py's ``_stream_process`` spawns every agent with PR_SET_PDEATHSIG,
    so the agent is SIGKILLed the instant its parent exits.  The durable lease
    here records the real agent pid (via ``update_pid``) for the watchdog's reap.

Design:
  1. Supervisor-only writers — lease files live under
     ``<control-state>/<audit-id>/leases/<worker>.json``.
  2. Monotonic fencing token — a stale writer cannot rewind the sequence.
  3. Consecutive-miss tolerance — transient fsync hiccups don't reap workers.
  4. Process-group reap.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

__all__ = [
    "WorkerLease",
    "WorkerLeaseStore",
    "WorkerWatchdog",
    "watchdog_for",
]


_LEASE_SCHEMA = "angerona.worker-lease/v1"
_DEFAULT_TTL_SECONDS = 60.0
_DEFAULT_WATCH_INTERVAL_SECONDS = 5.0


@dataclass(frozen=True)
class WorkerLease:
    audit_id: str
    worker_id: str
    sequence: int
    renewed_ns: int
    expires_ns: int
    pid: int
    meta: dict

    def as_dict(self) -> dict:
        return {
            "schema_version": _LEASE_SCHEMA,
            "audit_id": self.audit_id,
            "worker_id": self.worker_id,
            "sequence": self.sequence,
            "renewed_ns": self.renewed_ns,
            "expires_ns": self.expires_ns,
            "pid": self.pid,
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "WorkerLease":
        if str(raw.get("schema_version")) != _LEASE_SCHEMA:
            raise ValueError(f"lease schema mismatch: {raw.get('schema_version')!r}")
        return cls(
            audit_id=str(raw["audit_id"]),
            worker_id=str(raw["worker_id"]),
            sequence=int(raw["sequence"]),
            renewed_ns=int(raw["renewed_ns"]),
            expires_ns=int(raw["expires_ns"]),
            pid=int(raw["pid"]),
            meta=dict(raw.get("meta") or {}),
        )


class WorkerLeaseStore:
    """Supervisor-side durable per-worker lease store (tmp+rename+fsync)."""

    def __init__(self, root: str | Path, *, audit_id: str) -> None:
        self._root = Path(root) / audit_id / "leases"
        self._root.mkdir(parents=True, exist_ok=True)
        os.chmod(self._root, 0o700)
        self._lock = threading.Lock()

    def _path(self, worker_id: str) -> Path:
        if not worker_id or any(c in worker_id for c in ("/", "\x00")) or worker_id in {".", ".."}:
            raise ValueError(f"invalid worker id for lease: {worker_id!r}")
        return self._root / f"{worker_id}.json"

    def acquire(
        self,
        worker_id: str,
        *,
        pid: int,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
        meta: dict | None = None,
    ) -> WorkerLease:
        if ttl_seconds <= 0:
            raise ValueError("lease TTL must be positive")
        now = time.monotonic_ns()
        lease = WorkerLease(
            audit_id=self._root.parent.name,
            worker_id=worker_id,
            sequence=1,
            renewed_ns=now,
            expires_ns=now + int(ttl_seconds * 1_000_000_000),
            pid=pid,
            meta=dict(meta or {}),
        )
        self._write(lease)
        return lease

    def renew(self, worker_id: str, *, ttl_seconds: float = _DEFAULT_TTL_SECONDS) -> WorkerLease | None:
        path = self._path(worker_id)
        with self._lock:
            prior = self._read(path)
            if prior is None:
                return None
            now = time.monotonic_ns()
            lease = WorkerLease(
                audit_id=prior.audit_id,
                worker_id=worker_id,
                sequence=prior.sequence + 1,
                renewed_ns=now,
                expires_ns=now + int(ttl_seconds * 1_000_000_000),
                pid=prior.pid,
                meta=dict(prior.meta),
            )
            self._write(lease)
            return lease

    def update_pid(self, worker_id: str, pid: int) -> WorkerLease | None:
        """Correct the recorded fence target once the agent subprocess spawns.

        The supervisor cannot know the agent pid when it calls ``acquire`` — the
        subprocess is spawned later, inside the worker thread — so it records its
        own pid as a placeholder.  This swaps in the real agent pid so the
        watchdog's ``_reap`` fences the agent rather than returning early at the
        ``target == os.getpid()`` suicide guard.

        The sequence and expiry are preserved: a pid correction is not a renewal
        and must not extend liveness or rewind the monotonic fencing token.
        """
        path = self._path(worker_id)
        with self._lock:
            prior = self._read(path)
            if prior is None:
                return None
            if prior.pid == int(pid):
                return prior  # already fenced to the right target; avoid fsync churn
            lease = WorkerLease(
                audit_id=prior.audit_id,
                worker_id=worker_id,
                sequence=prior.sequence,
                renewed_ns=prior.renewed_ns,
                expires_ns=prior.expires_ns,
                pid=int(pid),
                meta=dict(prior.meta),
            )
            self._write(lease)
            return lease

    def release(self, worker_id: str) -> None:
        with self._lock:
            self._path(worker_id).unlink(missing_ok=True)

    def load(self, worker_id: str) -> WorkerLease | None:
        return self._read(self._path(worker_id))

    def _write(self, lease: WorkerLease) -> None:
        path = self._path(lease.worker_id)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(lease.as_dict(), sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read(self, path: Path) -> WorkerLease | None:
        try:
            return WorkerLease.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None


class WorkerWatchdog:
    """Worker-side watchdog that reaps the agent process when the lease dies."""

    def __init__(
        self,
        store: WorkerLeaseStore,
        worker_id: str,
        *,
        on_lost: Callable[[WorkerLease | None], None] | None = None,
        watch_interval: float = _DEFAULT_WATCH_INTERVAL_SECONDS,
        consecutive_lost: int = 2,
        target_pid: int | None = None,
    ) -> None:
        if watch_interval <= 0:
            raise ValueError("watch_interval must be positive")
        if consecutive_lost < 1:
            raise ValueError("consecutive_lost must be >= 1")
        self._store = store
        self.worker_id = worker_id
        self._on_lost = on_lost
        self._watch_interval = float(watch_interval)
        self._consecutive_lost = int(consecutive_lost)
        self._target_pid = target_pid
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("watchdog already started")
        self._thread = threading.Thread(
            target=self._run, name=f"angerona-watchdog-{self.worker_id}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._watch_interval + 1.0)
            self._thread = None

    def _run(self) -> None:
        misses = 0
        last_sequence = 0
        while not self._stop.is_set():
            time.sleep(self._watch_interval)
            if self._stop.is_set():
                break
            try:
                lease = self._store.load(self.worker_id)
                if lease is None:
                    misses += 1
                else:
                    now = time.monotonic_ns()
                    fence_regressed = lease.sequence < last_sequence
                    expired = now > lease.expires_ns
                    if fence_regressed or expired:
                        misses += 1
                    else:
                        misses = 0
                        last_sequence = lease.sequence
                if misses >= self._consecutive_lost:
                    self._reap(self._store.load(self.worker_id))
                    return
            except Exception:  # noqa: BLE001 — a read hiccup must never kill a worker
                continue

    def _reap(self, lease: WorkerLease | None) -> None:
        if self._on_lost is not None:
            try:
                self._on_lost(lease)
            except Exception:  # noqa: BLE001
                pass
        target = self._target_pid or (lease.pid if lease else None)
        if target is None or target == os.getpid():
            return  # avoid suicide loops in tests / caller handles finalization
        try:
            os.killpg(target, signal.SIGTERM)
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return
        # Wait for the leader to actually exit; process groups persist
        # even when the leader is gone, so we check the PID itself.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(target, 0)
            except OSError:
                return
            time.sleep(0.05)
        try:
            os.killpg(target, signal.SIGKILL)
        except OSError:
            pass
        # One last PID re-check to confirm the leader is truly gone; a
        # zombie leader here would keep burning tokens.
        for _ in range(20):
            try:
                os.kill(target, 0)
            except OSError:
                return
            time.sleep(0.05)


def watchdog_for(
    audit_id: str,
    worker_id: str,
    *,
    control_state_root: str | Path,
    on_lost: Callable[[WorkerLease | None], None] | None = None,
    target_pid: int | None = None,
) -> WorkerWatchdog:
    """Convenience builder wiring a store + watchdog for a worker."""
    store = WorkerLeaseStore(Path(control_state_root), audit_id=audit_id)
    return WorkerWatchdog(store, worker_id, on_lost=on_lost, target_pid=target_pid)
