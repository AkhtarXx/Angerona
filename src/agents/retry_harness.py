"""Provider-neutral, crash-aware retry policy for subscription CLI agents.

Only trusted infrastructure channels (typed error events and process stderr) can
authorize a retry.  The ledger is workspace-confined, atomically replaced under
an OS lock, and hash-chained so a crash cannot silently reset the retry budget.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterator, Mapping, Sequence

from ..observability import ledger_for_workspace
from ..secure_artifacts import SecureArtifactStore


DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY_SECONDS = 1.0
DEFAULT_MAX_DELAY_SECONDS = 30.0
DEFAULT_JITTER_RATIO = 0.25
DEFAULT_MIN_REMAINING_SECONDS = 5.0
MAX_LEDGER_BYTES = 1_000_000
MAX_LEDGER_RECORDS = 256

_DENY_RE = re.compile(
    r"(?i)(?:auth(?:entication|orization)?|unauthorized|forbidden|invalid[_ -]?api[_ -]?key|"
    r"permission denied|billing|insufficient[_ -]?(?:credit|fund|quota)|"
    r"quota[_ -]?(?:exceeded|exhausted|limit[_ -]?(?:reached|exceeded))|"
    r"usage[_ -]?(?:exhausted|limit[_ -]?(?:reached|exceeded))|"
    r"(?:monthly[_ -]?)?spend[_ -]?limit[_ -]?(?:reached|exceeded)|"
    r"credits?[_ -]?(?:exhausted|insufficient)|balance[_ -]?too[_ -]?low|"
    r"credit[_ -]?balance[_ -]?(?:too[_ -]?low|exhausted|insufficient)|"
    r"invalid[_ -]?request|malformed|unsupported model|model not found|"
    r"context[_ -]?(?:length|window)|maximum context length|prompt is too long)"
)
_RATE_LIMIT_RE = re.compile(
    r"(?i)(?:rate[_ -]?limit|too many requests|(?:http|status)[ /:=_-]*429|\b429\b)"
)
_OVERLOADED_RE = re.compile(
    r"(?i)(?:overload(?:ed)?|at capacity|capacity temporarily|try again later|"
    r"temporarily unavailable)"
)
_SERVER_RE = re.compile(
    r"(?i)(?:internal server error|bad gateway|service unavailable|gateway timeout|"
    r"(?:http|status)[ /:=_-]*5\d\d|\b50[0234]\b)"
)
_NETWORK_RE = re.compile(
    r"(?i)(?:connection (?:reset|refused|closed|aborted)|econnreset|econnrefused|"
    r"socket hang up|network (?:error|unreachable)|name resolution|dns failure|"
    r"temporary failure in name resolution|broken pipe|tls handshake|i/o timeout|"
    r"request timed out|mcp.{0,80}(?:timeout|unavailable|disconnected))"
)
_RETRY_AFTER_RE = re.compile(
    r"(?i)retry[_ -]?after"
    r"(?P<field_unit>[_ -]?(?:milliseconds?|ms|seconds?|secs?|s))?"
    r"[\"']?\s*[:=]?\s*[\"']?(?P<value>[0-9]+(?:\.[0-9]+)?)"
    r"\s*(?P<suffix_unit>milliseconds?|ms|seconds?|secs?|s)?"
)


class RetryStateError(RuntimeError):
    """The durable retry ledger is corrupt, incompatible, or unsafe."""


class RetryLeaseBusy(RetryStateError):
    """Another identical dispatch still owns the execution lease."""


@dataclass(frozen=True)
class TransientFailure:
    category: str
    source: str
    retry_after_seconds: float | None = None


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS
    max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS
    jitter_ratio: float = DEFAULT_JITTER_RATIO
    min_remaining_seconds: float = DEFAULT_MIN_REMAINING_SECONDS

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "RetryPolicy":
        return cls(
            max_attempts=_bounded_int(
                env.get("ANGERONA_TRANSIENT_MAX_ATTEMPTS"),
                DEFAULT_MAX_ATTEMPTS, 1, 5,
            ),
            base_delay_seconds=_bounded_float(
                env.get("ANGERONA_TRANSIENT_BASE_DELAY_SECONDS"),
                DEFAULT_BASE_DELAY_SECONDS, 0.0, 60.0,
            ),
            max_delay_seconds=_bounded_float(
                env.get("ANGERONA_TRANSIENT_MAX_DELAY_SECONDS"),
                DEFAULT_MAX_DELAY_SECONDS, 0.0, 60.0,
            ),
            jitter_ratio=_bounded_float(
                env.get("ANGERONA_TRANSIENT_JITTER_RATIO"),
                DEFAULT_JITTER_RATIO, 0.0, 1.0,
            ),
            min_remaining_seconds=_bounded_float(
                env.get("ANGERONA_TRANSIENT_MIN_REMAINING_SECONDS"),
                DEFAULT_MIN_REMAINING_SECONDS, 0.0, 60.0,
            ),
        )

    def delay_seconds(
        self,
        *,
        failed_attempt: int,
        dispatch_key: str,
        retry_after_seconds: float | None,
    ) -> float:
        exponent = max(0, min(10, failed_attempt - 1))
        ceiling = min(
            self.max_delay_seconds,
            self.base_delay_seconds * (2**exponent),
        )
        digest = hashlib.sha256(
            f"{dispatch_key}\0{failed_attempt}".encode("ascii", errors="ignore")
        ).digest()
        unit = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        jittered = ceiling * (1.0 - self.jitter_ratio + self.jitter_ratio * unit)
        retry_after = max(0.0, retry_after_seconds or 0.0)
        return min(self.max_delay_seconds, max(jittered, retry_after))


def _bounded_int(value: str | None, default: int, lower: int, upper: int) -> int:
    try:
        parsed = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    return max(lower, min(upper, parsed))


def _bounded_float(
    value: str | None, default: float, lower: float, upper: float
) -> float:
    try:
        parsed = float(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        parsed = default
    return max(lower, min(upper, parsed))


def _event_text(event: Mapping[str, object]) -> str:
    try:
        return json.dumps(event, ensure_ascii=True, sort_keys=True, default=str)[:20_000]
    except (TypeError, ValueError):
        return str(event)[:20_000]


def _clamp_retry_after(value: float, *, milliseconds: bool = False) -> float | None:
    if value != value or value in (float("inf"), float("-inf")):
        return None
    if milliseconds:
        value /= 1000.0
    return max(0.0, min(60.0, value))


def _retry_after_seconds(text: str) -> float | None:
    """Parse textual delay hints without borrowing units from another field."""

    hints: list[float] = []
    for match in _RETRY_AFTER_RE.finditer(text):
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        unit = (match.group("suffix_unit") or match.group("field_unit") or "").lower()
        parsed = _clamp_retry_after(value, milliseconds="ms" in unit or "millisecond" in unit)
        if parsed is not None:
            hints.append(parsed)
    return max(hints) if hints else None


def _structured_retry_after_seconds(event: Mapping[str, object]) -> float | None:
    """Extract independently typed retry hints and conservatively keep the maximum."""

    hints: list[float] = []
    pending: list[object] = [event]
    visited = 0
    while pending and visited < 256:
        node = pending.pop()
        visited += 1
        if isinstance(node, Mapping):
            for raw_key, value in node.items():
                key = re.sub(r"[ -]+", "_", str(raw_key).strip().lower())
                if key in {"retry_after", "retry_after_seconds", "retry_after_secs"}:
                    parsed: float | None = None
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        parsed = _clamp_retry_after(float(value))
                    elif isinstance(value, str):
                        try:
                            parsed = _clamp_retry_after(float(value.strip()))
                        except ValueError:
                            try:
                                date = parsedate_to_datetime(value)
                                if date.tzinfo is None:
                                    date = date.replace(tzinfo=timezone.utc)
                                parsed = _clamp_retry_after(
                                    date.timestamp() - datetime.now(timezone.utc).timestamp()
                                )
                            except (TypeError, ValueError, OverflowError):
                                parsed = None
                    if parsed is not None:
                        hints.append(parsed)
                elif key in {"retry_after_ms", "retry_after_milliseconds"}:
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        parsed = _clamp_retry_after(float(value), milliseconds=True)
                    elif isinstance(value, str):
                        try:
                            parsed = _clamp_retry_after(float(value.strip()), milliseconds=True)
                        except ValueError:
                            parsed = None
                    else:
                        parsed = None
                    if parsed is not None:
                        hints.append(parsed)
                if isinstance(value, (Mapping, list, tuple)):
                    pending.append(value)
        elif isinstance(node, (list, tuple)):
            pending.extend(node[:256])
    textual = _retry_after_seconds(_event_text(event))
    if textual is not None:
        hints.append(textual)
    return max(hints) if hints else None


def classify_transient_failure(
    *,
    returncode: int,
    events: Sequence[Mapping[str, object]],
    stderr: str,
) -> TransientFailure | None:
    """Classify only trusted process/provider failure evidence.

    Assistant/model text is intentionally absent.  Every typed error event is
    evaluated independently, and permanent/auth/quota/context errors veto retry.
    """

    payloads: list[tuple[str, str, float | None]] = [
        ("typed_error", _event_text(event), _structured_retry_after_seconds(event))
        for event in events
        if event.get("type") == "error"
    ]
    if stderr.strip():
        stderr_text = stderr[-20_000:]
        payloads.append(("stderr", stderr_text, _retry_after_seconds(stderr_text)))
    if any(_DENY_RE.search(text) for _source, text, _retry_after in payloads):
        return None

    classifiers = (
        ("rate_limit", _RATE_LIMIT_RE),
        ("overloaded", _OVERLOADED_RE),
        ("server_error", _SERVER_RE),
        ("network_error", _NETWORK_RE),
    )
    matched: list[tuple[str, str, float | None]] = []
    for source, text, retry_after in payloads:
        for category, pattern in classifiers:
            if pattern.search(text):
                matched.append((category, source, retry_after))
                break
    if matched:
        retry_hints = [hint for _category, _source, hint in matched if hint is not None]
        return TransientFailure(
            category=matched[0][0],
            source=matched[0][1],
            retry_after_seconds=max(retry_hints) if retry_hints else None,
        )
    if returncode == 124:
        return TransientFailure(category="timeout", source="returncode")
    if returncode == os.EX_TEMPFAIL:
        return TransientFailure(category="temporary_exit", source="returncode")
    return None


def retry_recovery_task(task: str, failure: TransientFailure, attempt: int) -> str:
    return (
        "# ANGERONA TRANSIENT RECOVERY\n"
        f"The previous agent process ended because of a temporary {failure.category} "
        f"infrastructure failure (retry attempt {attempt}). The provider error is not "
        "binary evidence. Continue the same task in a fresh process. Inspect current "
        "workspace notes and artifacts first, preserve verified work, and do not repeat "
        "completed analysis or destructive actions.\n\n"
        f"# ORIGINAL CONTINUATION TASK\n{task}"
    )


def dispatch_key(
    *,
    agent_family: str,
    model_name: str,
    cwd: str,
    task: str,
    system_prompt: str,
    execution_contract_sha256: str = "",
) -> str:
    digest = hashlib.sha256()
    for value in (
        agent_family,
        model_name,
        str(Path(cwd).resolve()),
        task,
        system_prompt,
        execution_contract_sha256,
    ):
        digest.update(value.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()[:32]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"), default=str,
    ).encode("utf-8")


class RetrySession:
    def __init__(
        self,
        ledger: "RetryLedger",
        state: dict,
        session_id: str,
        attempts_used: int,
        transient_retries_used: int,
        resumed_after_crash: bool,
        duplicate_suppressed: bool = False,
        wall_deadline_unix_ns: int | None = None,
    ) -> None:
        self.ledger = ledger
        self.state = state
        self.session_id = session_id
        self.attempts_used = attempts_used
        self.transient_retries_used = transient_retries_used
        self.resumed_after_crash = resumed_after_crash
        self.duplicate_suppressed = duplicate_suppressed
        self.wall_deadline_unix_ns = wall_deadline_unix_ns

    def record(self, kind: str, **data: object) -> None:
        records = self.state["records"]
        if len(records) >= MAX_LEDGER_RECORDS:
            raise RetryStateError("retry ledger record limit exceeded")
        body = {
            "sequence": len(records) + 1,
            "previous_sha256": records[-1]["sha256"] if records else None,
            "time_ns": time.time_ns(),
            "session_id": self.session_id,
            "kind": kind,
            "data": data,
        }
        body["sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        records.append(body)
        self.ledger._save(self.state)
        self.ledger._observe(kind, data)

    def start_attempt(self, *, launch_kind: str) -> int:
        self.attempts_used += 1
        self.record(
            "attempt_started",
            attempt=self.attempts_used,
            launch_kind=launch_kind,
        )
        return self.attempts_used


class RetryLedger:
    """One deterministic dispatch ledger and cross-process execution lease."""

    def __init__(
        self,
        workspace_root: str | Path,
        key: str,
        *,
        mirror_root: str | Path | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", key):
            raise ValueError("invalid retry dispatch key")
        self.key = key
        self._lease_fd: int | None = None
        self._lease_contended = False
        self._closed = False
        self.store = SecureArtifactStore(
            workspace_root, f"raw/agent_retries/{key}"
        )
        self.mirror_root = (
            Path(mirror_root).expanduser().resolve()
            if mirror_root is not None
            else None
        )
        self.observability = (
            ledger_for_workspace(self.mirror_root)
            if self.mirror_root is not None
            else None
        )

    def _observe(self, kind: str, data: Mapping[str, object]) -> None:
        if self.observability is None:
            return
        self.observability.emit(
            component="retry_harness",
            category="retry",
            action=kind,
            attributes={"dispatch_key": self.key, **dict(data)},
        )

    def _load(self) -> dict:
        try:
            raw = self.store.read_bytes("state.json")
        except FileNotFoundError:
            return {"schema_version": 1, "dispatch_key": self.key, "records": []}
        if len(raw) > MAX_LEDGER_BYTES:
            raise RetryStateError("retry ledger is oversized")
        try:
            state = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RetryStateError("retry ledger is not valid JSON") from exc
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != 1
            or state.get("dispatch_key") != self.key
            or not isinstance(state.get("records"), list)
            or len(state["records"]) > MAX_LEDGER_RECORDS
        ):
            raise RetryStateError("retry ledger schema mismatch")
        previous = None
        for sequence, record in enumerate(state["records"], 1):
            if not isinstance(record, dict):
                raise RetryStateError("retry ledger record is invalid")
            digest = record.get("sha256")
            body = {key: value for key, value in record.items() if key != "sha256"}
            expected = hashlib.sha256(_canonical_bytes(body)).hexdigest()
            if (
                record.get("sequence") != sequence
                or record.get("previous_sha256") != previous
                or digest != expected
            ):
                raise RetryStateError("retry ledger hash chain is corrupt")
            previous = digest
        return state

    def _save(self, state: Mapping[str, object]) -> None:
        payload = json.dumps(
            state, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2
        ).encode("utf-8")
        if len(payload) > MAX_LEDGER_BYTES:
            raise RetryStateError("retry ledger would exceed its size limit")
        self.store.replace_bytes_atomic("state.json", payload)
        # Workspace state is an observability mirror only. The authoritative
        # ledger and lease live in the supervisor-only control store so a model
        # cannot forge a crash-resume anchor by recomputing public hashes.
        if (
            self.mirror_root is not None
            and self.mirror_root != self.store.workspace_root
        ):
            try:
                with SecureArtifactStore(
                    self.mirror_root,
                    f"raw/agent_retries/{self.key}",
                ) as mirror:
                    mirror.replace_bytes_atomic("state.json", payload)
            except (OSError, ValueError):
                pass

    @contextmanager
    def locked_session(
        self, *, lock_timeout_seconds: float = 30.0
    ) -> Iterator[RetrySession]:
        session = self.acquire_session(
            lock_timeout_seconds=lock_timeout_seconds
        )
        try:
            yield session
        finally:
            self.close()

    def _acquire_lease(self, timeout_seconds: float) -> None:
        filename = ".retry-ledger.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(filename, flags, 0o600, dir_fd=self.store.dir_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RetryStateError("retry ledger lock is not a regular file")
            try:
                import fcntl
            except ImportError as exc:
                raise RetryStateError("timed retry leases require fcntl") from exc
            deadline = time.monotonic() + max(0.0, timeout_seconds)
            contended = False
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    contended = True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RetryLeaseBusy(
                            "identical dispatch lease is still active"
                        ) from exc
                    time.sleep(min(0.05, remaining))
            self._lease_fd = descriptor
            self._lease_contended = contended
        except Exception:
            os.close(descriptor)
            raise

    def acquire_session(
        self,
        *,
        lock_timeout_seconds: float = 30.0,
        wall_deadline_unix_ns: int | None = None,
    ) -> RetrySession:
        """Acquire the per-dispatch lease until :meth:`close` is called."""

        if self._lease_fd is not None:
            raise RetryStateError("retry ledger lease is already active")
        if self._closed:
            raise RetryStateError("retry ledger is closed")
        self._acquire_lease(
            max(0.0, min(30.0, float(lock_timeout_seconds)))
        )
        try:
            state = self._load()
            records = state["records"]
            terminal = {
                "success", "permanent_failure", "exhausted",
                "duplicate_suppressed",
            }
            last_session_id = records[-1]["session_id"] if records else None
            session_records = [
                record for record in records
                if record.get("session_id") == last_session_id
            ]
            is_terminal = bool(
                session_records and session_records[-1].get("kind") in terminal
            )
            predecessor_completed_while_waiting = bool(
                is_terminal and self._lease_contended
            )
            if predecessor_completed_while_waiting:
                session_id = uuid.uuid4().hex
                session = RetrySession(
                    self, state, session_id, 0, 0, False, True,
                    wall_deadline_unix_ns,
                )
                session.record(
                    "session_started",
                    wall_deadline_unix_ns=wall_deadline_unix_ns,
                )
                session.record(
                    "duplicate_suppressed",
                    predecessor_session_id=last_session_id,
                )
                return session
            if not session_records or is_terminal:
                session_id = uuid.uuid4().hex
                attempts_used = 0
                transient_retries_used = 0
                resumed = False
                durable_deadline = wall_deadline_unix_ns
            else:
                session_id = str(last_session_id)
                attempts_used = sum(
                    record.get("kind") == "attempt_started"
                    for record in session_records
                )
                # Every scheduled retry is preceded by an attempt_started, so
                # max(scheduled, attempts_used) would always equal attempts_used
                # and over-count the budget by one whenever a crash lands
                # mid-attempt. The durable count of scheduled retries is exactly
                # the number of retries already consumed.
                transient_retries_used = sum(
                    record.get("kind") == "transient_retry_scheduled"
                    for record in session_records
                )
                resumed = attempts_used > 0
                started_record = next(
                    (record for record in session_records if record.get("kind") == "session_started"),
                    None,
                )
                stored_deadline = (
                    (started_record.get("data") or {}).get("wall_deadline_unix_ns")
                    if started_record is not None else None
                )
                durable_deadline = (
                    int(stored_deadline)
                    if isinstance(stored_deadline, int) and not isinstance(stored_deadline, bool)
                    else wall_deadline_unix_ns
                )
            session = RetrySession(
                self, state, session_id, attempts_used,
                transient_retries_used, resumed,
                wall_deadline_unix_ns=durable_deadline,
            )
            if not session_records or is_terminal:
                session.record(
                    "session_started",
                    wall_deadline_unix_ns=durable_deadline,
                )
            elif resumed:
                session.record(
                    "session_resumed",
                    attempts_used=attempts_used,
                    wall_deadline_unix_ns=durable_deadline,
                )
            return session
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        descriptor = getattr(self, "_lease_fd", None)
        if descriptor is not None:
            self._lease_fd = None
            try:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        if not getattr(self, "_closed", True):
            self._closed = True
            self.store.close()

    def __enter__(self) -> "RetryLedger":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def sleep_before_retry(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)
