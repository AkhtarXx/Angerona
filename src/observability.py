"""Structured, crash-durable observability for Angerona audit runs.

The authoritative ledger lives outside the model-writable workspace.  A readable
JSONL mirror is maintained under ``raw/observability`` for operators and the web UI.
Every record carries trace/span correlation, a monotonic sequence, and a SHA-256
predecessor link.  Payload content is represented by bounded, secret-safe metadata.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping, Sequence


OBSERVABILITY_SCHEMA_VERSION = 1
DEFAULT_MAX_EVENTS = 1_000_000
DEFAULT_ATTRIBUTE_BYTES = 64 * 1024
DEFAULT_ATTRIBUTE_DEPTH = 8
DEFAULT_ATTRIBUTE_ITEMS = 512
DEFAULT_STRING_CHARS = 4096
DEFAULT_TREE_FILES = 100_000
DEFAULT_TREE_HASH_BYTES = 1024 * 1024 * 1024

_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_HEX_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SECRET_KEY_RE = re.compile(
    r"(?:^|[_-])(?:auth(?:orization)?|bearer|cookie|credential|password|passwd|"
    r"private[_-]?key|secret|session|token|api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE_RES = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(?:token|secret|password|api[_-]?key)\s*[=:]\s*\S+"),
)
_CONTENT_KEY_RE = re.compile(
    r"(?:^|[_-])(?:content|input|message|output|prompt|report|response|result|task|text)(?:$|[_-])",
    re.IGNORECASE,
)
_CURRENT_SPAN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "angerona_observability_span", default=None
)
_CURRENT_PARENT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "angerona_observability_parent", default=None
)
_SUPPRESS: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "angerona_observability_suppress", default=False
)
_CACHE_LOCK = threading.RLock()
_LEDGER_CACHE: weakref.WeakValueDictionary[tuple[int, str], "ObservabilityLedger"] = (
    weakref.WeakValueDictionary()
)


class ObservabilityError(RuntimeError):
    """Raised when required telemetry cannot be committed or validated."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8", errors="surrogatepass")


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except ValueError:
        value = int(default)
    return max(minimum, value)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _redacted_descriptor(value: object) -> dict[str, object]:
    raw = (
        bytes(value)
        if isinstance(value, (bytes, bytearray, memoryview))
        else str(value).encode("utf-8", errors="surrogatepass")
    )
    return {
        "redacted": True,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def content_descriptor(
    value: str | bytes | bytearray | memoryview | None,
    *,
    preview_chars: int = 0,
) -> dict[str, object]:
    """Describe model/tool content without persisting its raw bytes."""

    if value is None:
        return {"present": False, "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    raw = (
        bytes(value)
        if isinstance(value, (bytes, bytearray, memoryview))
        else str(value).encode("utf-8", errors="surrogatepass")
    )
    result: dict[str, object] = {
        "present": True,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if isinstance(value, str):
        result["chars"] = len(value)
        if preview_chars > 0:
            result["preview"] = _sanitize_string(value[:preview_chars], preview_chars)
    return result


def _sanitize_string(value: str, limit: int) -> str | dict[str, object]:
    if any(pattern.search(value) for pattern in _SECRET_VALUE_RES):
        return _redacted_descriptor(value)
    if len(value) <= limit:
        return value
    raw = value.encode("utf-8", errors="surrogatepass")
    return {
        "truncated": True,
        "chars": len(value),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "preview": value[:limit],
    }


def sanitize_attributes(
    value: object,
    *,
    key: str = "",
    depth: int = 0,
    max_depth: int = DEFAULT_ATTRIBUTE_DEPTH,
    max_items: int = DEFAULT_ATTRIBUTE_ITEMS,
    string_chars: int = DEFAULT_STRING_CHARS,
) -> object:
    """Return a bounded JSON value with credential-like fields irreversibly redacted."""

    if _SECRET_KEY_RE.search(key):
        return _redacted_descriptor(value)
    if depth >= max_depth:
        return _redacted_descriptor(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _sanitize_string(value, string_chars)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _redacted_descriptor(value)
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        items = sorted(((str(k), v) for k, v in value.items()), key=lambda row: row[0])
        for item_key, item_value in items[:max_items]:
            output[item_key] = sanitize_attributes(
                item_value,
                key=item_key,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                string_chars=string_chars,
            )
        if len(items) > max_items:
            output["_truncated_items"] = len(items) - max_items
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        rows = list(value)
        output = [
            sanitize_attributes(
                item,
                key=key,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                string_chars=string_chars,
            )
            for item in rows[:max_items]
        ]
        if len(rows) > max_items:
            output.append({"_truncated_items": len(rows) - max_items})
        return output
    return _sanitize_string(str(value), string_chars)


def external_event_descriptor(value: object, *, depth: int = 0) -> object:
    """Preserve protocol metadata while replacing external prose/bytes with identities."""

    if depth >= DEFAULT_ATTRIBUTE_DEPTH:
        return _redacted_descriptor(value)
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for raw_key, child in sorted(value.items(), key=lambda row: str(row[0])):
            key = str(raw_key)
            if _SECRET_KEY_RE.search(key):
                output[key] = _redacted_descriptor(child)
            elif _CONTENT_KEY_RE.search(key):
                if isinstance(child, (str, bytes, bytearray, memoryview)) or child is None:
                    output[key] = content_descriptor(child)
                else:
                    output[key] = content_descriptor(_canonical_bytes(sanitize_attributes(child)))
            else:
                output[key] = external_event_descriptor(child, depth=depth + 1)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [external_event_descriptor(item, depth=depth + 1) for item in list(value)[:DEFAULT_ATTRIBUTE_ITEMS]]
    return sanitize_attributes(value, depth=depth)


def _validate_name(label: str, value: str) -> str:
    text = str(value or "").strip()
    if not _NAME_RE.fullmatch(text):
        raise ObservabilityError(f"invalid {label}: {text!r}")
    return text


def _workspace_identity(workspace_root: Path) -> tuple[str, str | None]:
    run_meta = workspace_root / "run.json"
    try:
        payload = json.loads(run_meta.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    stable = str(payload.get("observability_id") or "").strip()
    trace_id = str(payload.get("trace_id") or "").strip()
    if not _HEX_ID_RE.fullmatch(stable):
        stable = hashlib.sha256(
            str(workspace_root).encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:32]
    if not _HEX_ID_RE.fullmatch(trace_id):
        trace_id = None
    return stable, trace_id


def resolve_workspace_root(path: str | Path) -> Path:
    """Resolve an audit root from its root, code directory, or candidate descendant."""

    configured = (os.environ.get("ANGERONA_AGENT_WORKSPACE_ROOT") or "").strip()
    # An explicit run/candidate path wins.  The environment is only a fallback;
    # otherwise a stale variable can silently correlate a new run to an old one.
    candidates = [Path(path)]
    if configured:
        candidates.append(Path(configured))
    for candidate in candidates:
        current = candidate.expanduser().absolute()
        if current.is_file():
            current = current.parent
        for _ in range(12):
            if (current / "run.json").is_file() and all(
                (current / name).is_dir() for name in ("code", "docs", "raw")
            ):
                return current.resolve()
            if current.parent == current:
                break
            current = current.parent
    return Path(path).expanduser().resolve()


def observability_control_root(workspace_root: str | Path) -> Path:
    root = resolve_workspace_root(workspace_root)
    configured = (os.environ.get("ANGERONA_AGENT_CONTROL_STATE_DIR") or "").strip()
    if configured:
        base = Path(configured).expanduser().resolve()
    else:
        state_home = Path(
            os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
        ).expanduser().resolve()
        base = state_home / "angerona" / "agent-control"
    identity, _trace_id = _workspace_identity(root)
    target = (base / "workspaces" / identity / "observability").resolve()
    if _is_relative_to(target, root):
        raise ObservabilityError("observability authority must be outside the model workspace")
    target.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = os.stat(target, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ObservabilityError("observability control root is not a directory")
    os.chmod(target, 0o700)
    return target


def observability_policy_contract(env: Mapping[str, str] | None = None) -> dict[str, object]:
    source = env if env is not None else os.environ

    def read(name: str, default: int) -> int:
        try:
            return max(1, int((source.get(name) or str(default)).strip()))
        except ValueError:
            return default

    return {
        "schema_version": OBSERVABILITY_SCHEMA_VERSION,
        "required": str(source.get("ANGERONA_OBSERVABILITY_REQUIRED", "1")).lower()
        not in {"0", "false", "no", "off"},
        "max_events": read("ANGERONA_OBSERVABILITY_MAX_EVENTS", DEFAULT_MAX_EVENTS),
        "max_attribute_bytes": read(
            "ANGERONA_OBSERVABILITY_MAX_ATTRIBUTE_BYTES", DEFAULT_ATTRIBUTE_BYTES
        ),
        "tree_max_files": read(
            "ANGERONA_OBSERVABILITY_TREE_MAX_FILES", DEFAULT_TREE_FILES
        ),
        "tree_hash_bytes": read(
            "ANGERONA_OBSERVABILITY_TREE_HASH_BYTES", DEFAULT_TREE_HASH_BYTES
        ),
        "raw_payloads_persisted": False,
        "child_telemetry_trust": "untrusted_child",
        "authority": "external_supervisor_sqlite",
        "workspace_mirror_authoritative": False,
    }


@dataclass(frozen=True)
class TreeEntry:
    kind: str
    mode: int
    size: int
    mtime_ns: int
    sha256: str | None = None
    link_target: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "sha256": self.sha256,
            "link_target": self.link_target,
        }


def capture_tree(
    root: str | Path,
    *,
    max_files: int | None = None,
    max_hash_bytes: int | None = None,
) -> dict[str, TreeEntry]:
    """Capture a bounded, no-follow metadata/content identity for change debugging."""

    base = Path(root).expanduser().absolute()
    file_limit = max_files or _env_int(
        "ANGERONA_OBSERVABILITY_TREE_MAX_FILES", DEFAULT_TREE_FILES
    )
    byte_limit = max_hash_bytes or _env_int(
        "ANGERONA_OBSERVABILITY_TREE_HASH_BYTES", DEFAULT_TREE_HASH_BYTES
    )
    output: dict[str, TreeEntry] = {}
    hashed = 0
    root_info = os.stat(base, follow_symlinks=False)
    if stat.S_ISLNK(root_info.st_mode):
        output["."] = TreeEntry(
            "symlink",
            stat.S_IMODE(root_info.st_mode),
            root_info.st_size,
            root_info.st_mtime_ns,
            link_target=os.readlink(base),
        )
        return output
    if not stat.S_ISDIR(root_info.st_mode):
        raise ObservabilityError("workspace observation root is not a directory")
    output["."] = TreeEntry(
        "directory",
        stat.S_IMODE(root_info.st_mode),
        root_info.st_size,
        root_info.st_mtime_ns,
    )
    stack = [(base, PurePosixPath("."))]
    while stack:
        directory, relative_dir = stack.pop()
        with os.scandir(directory) as rows:
            entries = sorted(rows, key=lambda row: row.name)
        for row in entries:
            relative = (
                PurePosixPath(row.name)
                if relative_dir == PurePosixPath(".")
                else relative_dir / row.name
            )
            name = relative.as_posix()
            if name == "raw/observability" or name.startswith("raw/observability/"):
                continue
            if len(output) >= file_limit:
                raise ObservabilityError("workspace observation file limit exceeded")
            info = row.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                output[name] = TreeEntry("directory", mode, 0, info.st_mtime_ns)
                stack.append((Path(row.path), relative))
            elif stat.S_ISREG(info.st_mode):
                digest: str | None = None
                if hashed + info.st_size <= byte_limit:
                    h = hashlib.sha256()
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(row.path, flags)
                    try:
                        while True:
                            chunk = os.read(descriptor, 1024 * 1024)
                            if not chunk:
                                break
                            h.update(chunk)
                    finally:
                        os.close(descriptor)
                    digest = h.hexdigest()
                    hashed += info.st_size
                output[name] = TreeEntry(
                    "file", mode, info.st_size, info.st_mtime_ns, sha256=digest
                )
            elif stat.S_ISLNK(info.st_mode):
                output[name] = TreeEntry(
                    "symlink",
                    mode,
                    info.st_size,
                    info.st_mtime_ns,
                    link_target=os.readlink(row.path),
                )
            else:
                output[name] = TreeEntry("special", mode, info.st_size, info.st_mtime_ns)
    return output


class ObservabilityLedger:
    """External authoritative trace ledger with a non-authoritative workspace mirror."""

    def __init__(self, workspace_root: str | Path) -> None:
        import fcntl

        self.workspace_root = resolve_workspace_root(workspace_root)
        self.control_root = observability_control_root(self.workspace_root)
        self.db_path = self.control_root / "events.sqlite3"
        self.max_events = _env_int("ANGERONA_OBSERVABILITY_MAX_EVENTS", DEFAULT_MAX_EVENTS)
        self.max_attribute_bytes = _env_int(
            "ANGERONA_OBSERVABILITY_MAX_ATTRIBUTE_BYTES", DEFAULT_ATTRIBUTE_BYTES
        )
        self._lock = threading.RLock()
        self._closed = False
        init_fd = os.open(
            self.control_root / "ledger-init.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        fcntl.flock(init_fd, fcntl.LOCK_EX)
        try:
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._ensure_schema()
            _identity, configured_trace = _workspace_identity(self.workspace_root)
            existing = self._meta("trace_id")
            if existing and not _HEX_ID_RE.fullmatch(existing):
                raise ObservabilityError("observability trace id is malformed")
            self.trace_id = existing or configured_trace or uuid.uuid4().hex
            if not existing:
                self._set_meta("trace_id", self.trace_id)
        finally:
            try:
                fcntl.flock(init_fd, fcntl.LOCK_UN)
            finally:
                os.close(init_fd)

    def _ensure_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    time_ns INTEGER NOT NULL,
                    monotonic_ns INTEGER NOT NULL,
                    trace_id TEXT NOT NULL,
                    span_id TEXT NOT NULL,
                    parent_span_id TEXT,
                    component TEXT NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL,
                    trust TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    thread_id INTEGER NOT NULL,
                    attributes_json TEXT NOT NULL,
                    previous_sha256 TEXT,
                    sha256 TEXT NOT NULL UNIQUE
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS events_trace_span ON events(trace_id, span_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS events_component ON events(component, category, action)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS child_imports (
                    child_sha256 TEXT PRIMARY KEY,
                    imported_sequence INTEGER NOT NULL
                )
                """
            )
        schema = self._meta("schema_version")
        if schema and schema != str(OBSERVABILITY_SCHEMA_VERSION):
            raise ObservabilityError("unsupported observability schema version")
        if not schema:
            self._set_meta("schema_version", str(OBSERVABILITY_SCHEMA_VERSION))

    def _meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else str(row[0])

    def _set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def child_environment(self, *, parent_span_id: str | None = None) -> dict[str, str]:
        parent = parent_span_id or _CURRENT_SPAN.get() or ""
        return {
            "ANGERONA_TRACE_ID": self.trace_id,
            "ANGERONA_PARENT_SPAN_ID": parent,
            "ANGERONA_OBSERVABILITY_CHILD_SESSION": (
                parent if _HEX_ID_RE.fullmatch(parent) else uuid.uuid4().hex
            ),
            "ANGERONA_OBSERVABILITY_WORKSPACE": str(self.workspace_root),
            "ANGERONA_OBSERVABILITY_SCHEMA_VERSION": str(OBSERVABILITY_SCHEMA_VERSION),
        }

    def _event_body(
        self,
        *,
        sequence: int,
        time_ns: int,
        monotonic_ns: int,
        span_id: str,
        parent_span_id: str | None,
        component: str,
        category: str,
        action: str,
        phase: str,
        status: str,
        duration_ms: float | None,
        trust: str,
        pid: int,
        thread_id: int,
        attributes: object,
        previous_sha256: str | None,
    ) -> dict[str, object]:
        return {
            "schema_version": OBSERVABILITY_SCHEMA_VERSION,
            "sequence": sequence,
            "time_ns": time_ns,
            "monotonic_ns": monotonic_ns,
            "trace_id": self.trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "component": component,
            "category": category,
            "action": action,
            "phase": phase,
            "status": status,
            "duration_ms": duration_ms,
            "trust": trust,
            "pid": pid,
            "thread_id": thread_id,
            "attributes": attributes,
            "previous_sha256": previous_sha256,
        }

    def emit(
        self,
        *,
        component: str,
        category: str,
        action: str,
        phase: str = "event",
        status: str = "ok",
        attributes: Mapping[str, object] | None = None,
        span_id: str | None = None,
        parent_span_id: str | None = None,
        duration_ms: float | None = None,
        trust: str = "trusted_host",
    ) -> dict[str, object]:
        if _SUPPRESS.get():
            return {}
        component = _validate_name("component", component)
        category = _validate_name("category", category)
        action = _validate_name("action", action)
        phase = _validate_name("phase", phase)
        status = _validate_name("status", status)
        trust = _validate_name("trust", trust)
        active_span = span_id or _CURRENT_SPAN.get() or uuid.uuid4().hex
        if not _HEX_ID_RE.fullmatch(active_span):
            raise ObservabilityError("span id must be 32 lowercase hex characters")
        parent = parent_span_id if parent_span_id is not None else _CURRENT_PARENT.get()
        if parent is not None and not _HEX_ID_RE.fullmatch(parent):
            raise ObservabilityError("parent span id must be 32 lowercase hex characters")
        clean = sanitize_attributes(dict(attributes or {}))
        attributes_raw = _canonical_bytes(clean)
        if len(attributes_raw) > self.max_attribute_bytes:
            clean = {
                "truncated": True,
                "bytes": len(attributes_raw),
                "sha256": hashlib.sha256(attributes_raw).hexdigest(),
            }
            attributes_raw = _canonical_bytes(clean)
        now_ns = time.time_ns()
        monotonic_ns = time.monotonic_ns()
        pid = os.getpid()
        thread_id = threading.get_ident()
        with self._lock:
            token = _SUPPRESS.set(True)
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self._conn.execute(
                        "SELECT sequence, sha256 FROM events ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()
                    sequence = 1 if row is None else int(row[0]) + 1
                    previous = None if row is None else str(row[1])
                    if sequence > self.max_events:
                        raise ObservabilityError("observability event limit exceeded")
                    body = self._event_body(
                        sequence=sequence,
                        time_ns=now_ns,
                        monotonic_ns=monotonic_ns,
                        span_id=active_span,
                        parent_span_id=parent,
                        component=component,
                        category=category,
                        action=action,
                        phase=phase,
                        status=status,
                        duration_ms=duration_ms,
                        trust=trust,
                        pid=pid,
                        thread_id=thread_id,
                        attributes=clean,
                        previous_sha256=previous,
                    )
                    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
                    self._conn.execute(
                        """
                        INSERT INTO events(
                            sequence, time_ns, monotonic_ns, trace_id, span_id,
                            parent_span_id, component, category, action, phase, status,
                            duration_ms, trust, pid, thread_id, attributes_json,
                            previous_sha256, sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sequence,
                            now_ns,
                            monotonic_ns,
                            self.trace_id,
                            active_span,
                            parent,
                            component,
                            category,
                            action,
                            phase,
                            status,
                            duration_ms,
                            trust,
                            pid,
                            thread_id,
                            json.dumps(
                                clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                            ),
                            previous,
                            digest,
                        ),
                    )
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise
            finally:
                _SUPPRESS.reset(token)
        event = {**body, "sha256": digest}
        try:
            self._append_mirror(event)
        except (OSError, ValueError):
            self._set_meta("mirror_dirty", "1")
        return event

    def start_span(
        self,
        *,
        component: str,
        category: str,
        action: str,
        attributes: Mapping[str, object] | None = None,
        parent_span_id: str | None = None,
        trust: str = "trusted_host",
    ) -> "TraceSpan":
        return TraceSpan(
            self,
            component=component,
            category=category,
            action=action,
            attributes=dict(attributes or {}),
            parent_span_id=parent_span_id,
            trust=trust,
        ).start()

    @contextmanager
    def span(self, **kwargs: object) -> Iterator["TraceSpan"]:
        current = self.start_span(**kwargs)  # type: ignore[arg-type]
        try:
            yield current
        except BaseException as exc:
            current.finish(status="error", attributes={"exception": type(exc).__name__})
            raise
        else:
            current.finish()

    def record_tree_delta(
        self,
        before: Mapping[str, TreeEntry],
        after: Mapping[str, TreeEntry],
        *,
        component: str,
        parent_span_id: str | None = None,
    ) -> int:
        changed = 0
        for path in sorted(set(before) | set(after)):
            old = before.get(path)
            new = after.get(path)
            if old == new:
                continue
            if old is None:
                action = "created"
            elif new is None:
                action = "deleted"
            else:
                action = "modified"
            self.emit(
                component=component,
                category="filesystem",
                action=action,
                attributes={
                    "path": path,
                    "before": None if old is None else old.as_dict(),
                    "after": None if new is None else new.as_dict(),
                },
                parent_span_id=parent_span_id,
            )
            changed += 1
        return changed

    def import_child_spools(
        self,
        root: str | Path,
        *,
        parent_span_id: str | None = None,
    ) -> int:
        """Import valid child JSONL records as explicitly untrusted observations."""

        import fcntl

        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(self.control_root / "child-import.lock", lock_flags, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        imported = 0
        try:
            spools = self._read_child_spools()
            for source_name, raw in spools:
                imported += self._import_child_spool(
                    source_name,
                    raw,
                    parent_span_id=parent_span_id,
                )
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        return imported

    def _read_child_spools(self) -> list[tuple[str, bytes]]:
        """Read bounded regular child files through a no-follow directory handle."""

        try:
            directory_fd = self._open_mirror_dir()
        except OSError:
            # Low-level runtime harnesses may operate on an isolated candidate
            # directory rather than a full RunWorkspace, or the candidate root
            # may have been swapped and already rejected by the runtime guard.
            return []
        rows: list[tuple[str, bytes]] = []
        try:
            names = sorted(
                name
                for name in os.listdir(directory_fd)
                if re.fullmatch(r"child-[A-Za-z0-9_.-]{1,240}\.jsonl", str(name))
            )
            for name in names:
                descriptor = -1
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_fd,
                    )
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                        continue
                    chunks: list[bytes] = []
                    remaining = info.st_size
                    while remaining:
                        chunk = os.read(descriptor, min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    if remaining == 0:
                        rows.append((name, b"".join(chunks)))
                except OSError:
                    continue
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
        finally:
            os.close(directory_fd)
        return rows

    def _import_child_spool(
        self,
        source_name: str,
        raw: bytes,
        *,
        parent_span_id: str | None,
    ) -> int:
        imported = 0
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeError:
            return 0
        previous: str | None = None
        expected_sequence = 1
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                break
            if not isinstance(record, dict):
                break
            digest = str(record.get("sha256") or "")
            body = dict(record)
            body.pop("sha256", None)
            if (
                record.get("sequence") != expected_sequence
                or record.get("previous_sha256") != previous
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or hashlib.sha256(_canonical_bytes(body)).hexdigest() != digest
            ):
                break
            exists = self._conn.execute(
                "SELECT 1 FROM child_imports WHERE child_sha256 = ?", (digest,)
            ).fetchone()
            if exists is None:
                event = self.emit(
                    component="mcp_child",
                    category="child_report",
                    action="imported",
                    attributes={"source_file": source_name, "record": record},
                    span_id=uuid.uuid4().hex,
                    parent_span_id=parent_span_id,
                    trust="untrusted_child",
                )
                with self._conn:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO child_imports(child_sha256, imported_sequence) "
                        "VALUES (?, ?)",
                        (digest, int(event["sequence"])),
                    )
                imported += 1
            previous = digest
            expected_sequence += 1
        return imported

    def _open_mirror_dir(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(self.workspace_root, flags)
        try:
            raw_fd = os.open("raw", flags, dir_fd=root_fd)
        finally:
            os.close(root_fd)
        try:
            try:
                os.mkdir("observability", 0o700, dir_fd=raw_fd)
            except FileExistsError:
                pass
            mirror_fd = os.open("observability", flags, dir_fd=raw_fd)
        finally:
            os.close(raw_fd)
        if not stat.S_ISDIR(os.fstat(mirror_fd).st_mode):
            os.close(mirror_fd)
            raise ObservabilityError("observability mirror is not a directory")
        return mirror_fd

    def _append_mirror(self, event: Mapping[str, object]) -> None:
        import fcntl

        directory_fd = self._open_mirror_dir()
        lock_fd = -1
        event_fd = -1
        try:
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            lock_fd = os.open(
                ".mirror.lock", os.O_RDWR | os.O_CREAT | nofollow, 0o600, dir_fd=directory_fd
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            event_fd = os.open(
                "events.jsonl",
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | nofollow,
                0o600,
                dir_fd=directory_fd,
            )
            payload = _canonical_bytes(event) + b"\n"
            view = memoryview(payload)
            while view:
                written = os.write(event_fd, view)
                view = view[written:]
            os.fsync(event_fd)
            os.fsync(directory_fd)
        finally:
            if event_fd >= 0:
                os.close(event_fd)
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(directory_fd)

    def _rows(self, *, since: int = 0, limit: int = 1000) -> list[sqlite3.Row]:
        self._conn.row_factory = sqlite3.Row
        return list(
            self._conn.execute(
                "SELECT * FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
                (max(0, int(since)), max(1, int(limit))),
            ).fetchall()
        )

    @staticmethod
    def _row_event(row: sqlite3.Row) -> dict[str, object]:
        return {
            "schema_version": OBSERVABILITY_SCHEMA_VERSION,
            "sequence": int(row["sequence"]),
            "time_ns": int(row["time_ns"]),
            "monotonic_ns": int(row["monotonic_ns"]),
            "trace_id": str(row["trace_id"]),
            "span_id": str(row["span_id"]),
            "parent_span_id": row["parent_span_id"],
            "component": str(row["component"]),
            "category": str(row["category"]),
            "action": str(row["action"]),
            "phase": str(row["phase"]),
            "status": str(row["status"]),
            "duration_ms": row["duration_ms"],
            "trust": str(row["trust"]),
            "pid": int(row["pid"]),
            "thread_id": int(row["thread_id"]),
            "attributes": json.loads(str(row["attributes_json"])),
            "previous_sha256": row["previous_sha256"],
            "sha256": str(row["sha256"]),
        }

    def events(self, *, since: int = 0, limit: int = 1000) -> list[dict[str, object]]:
        return [self._row_event(row) for row in self._rows(since=since, limit=limit)]

    def verify(self) -> dict[str, object]:
        previous: str | None = None
        count = 0
        self._conn.row_factory = sqlite3.Row
        for row in self._conn.execute("SELECT * FROM events ORDER BY sequence"):
            event = self._row_event(row)
            expected_sequence = count + 1
            if event["sequence"] != expected_sequence:
                raise ObservabilityError("observability sequence is not contiguous")
            if event["previous_sha256"] != previous:
                raise ObservabilityError("observability predecessor hash mismatch")
            body = dict(event)
            digest = str(body.pop("sha256"))
            if hashlib.sha256(_canonical_bytes(body)).hexdigest() != digest:
                raise ObservabilityError("observability event hash mismatch")
            if event["trace_id"] != self.trace_id:
                raise ObservabilityError("observability trace id changed")
            previous = digest
            count += 1
        return {
            "valid": True,
            "schema_version": OBSERVABILITY_SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "events": count,
            "head_sha256": previous,
            "authority": str(self.db_path),
            "workspace_mirror": str(self.workspace_root / "raw" / "observability" / "events.jsonl"),
        }

    def rebuild_mirror(self) -> None:
        import fcntl

        directory_fd = self._open_mirror_dir()
        temporary = f".events.{uuid.uuid4().hex}.tmp"
        descriptor = -1
        lock_fd = -1
        try:
            lock_fd = os.open(
                ".mirror.lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
            self._conn.row_factory = sqlite3.Row
            for row in self._conn.execute("SELECT * FROM events ORDER BY sequence"):
                payload = _canonical_bytes(self._row_event(row)) + b"\n"
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(temporary, "events.jsonl", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
            self._set_meta("mirror_dirty", "0")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(directory_fd)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except (AttributeError, OSError, sqlite3.Error):
            pass


class TraceSpan:
    def __init__(
        self,
        ledger: ObservabilityLedger,
        *,
        component: str,
        category: str,
        action: str,
        attributes: dict[str, object],
        parent_span_id: str | None,
        trust: str,
    ) -> None:
        self.ledger = ledger
        self.component = component
        self.category = category
        self.action = action
        self.attributes = attributes
        self.parent_span_id = parent_span_id if parent_span_id is not None else _CURRENT_SPAN.get()
        self.trust = trust
        self.span_id = uuid.uuid4().hex
        self.started_ns = 0
        self._token: contextvars.Token[str | None] | None = None
        self._parent_token: contextvars.Token[str | None] | None = None
        self._finished = False

    def start(self) -> "TraceSpan":
        self.started_ns = time.monotonic_ns()
        self.ledger.emit(
            component=self.component,
            category=self.category,
            action=self.action,
            phase="start",
            status="running",
            attributes=self.attributes,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            trust=self.trust,
        )
        self._token = _CURRENT_SPAN.set(self.span_id)
        self._parent_token = _CURRENT_PARENT.set(self.parent_span_id)
        return self

    def event(
        self,
        action: str,
        *,
        category: str | None = None,
        status: str = "ok",
        attributes: Mapping[str, object] | None = None,
        trust: str | None = None,
    ) -> dict[str, object]:
        return self.ledger.emit(
            component=self.component,
            category=category or self.category,
            action=action,
            status=status,
            attributes=attributes,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            trust=trust or self.trust,
        )

    def finish(
        self,
        *,
        status: str = "ok",
        attributes: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if self._finished:
            return {}
        self._finished = True
        duration_ms = (time.monotonic_ns() - self.started_ns) / 1_000_000
        try:
            return self.ledger.emit(
                component=self.component,
                category=self.category,
                action=self.action,
                phase="end",
                status=status,
                duration_ms=round(duration_ms, 3),
                attributes=attributes,
                span_id=self.span_id,
                parent_span_id=self.parent_span_id,
                trust=self.trust,
            )
        finally:
            if self._token is not None:
                try:
                    _CURRENT_SPAN.reset(self._token)
                except ValueError:
                    pass
                self._token = None
            if self._parent_token is not None:
                try:
                    _CURRENT_PARENT.reset(self._parent_token)
                except ValueError:
                    pass
                self._parent_token = None


def ledger_for_workspace(workspace: str | Path) -> ObservabilityLedger:
    root = resolve_workspace_root(workspace)
    key = (os.getpid(), str(root))
    with _CACHE_LOCK:
        ledger = _LEDGER_CACHE.get(key)
        if ledger is None or ledger._closed:
            ledger = ObservabilityLedger(root)
            _LEDGER_CACHE[key] = ledger
        return ledger


def current_span_id() -> str | None:
    return _CURRENT_SPAN.get()


def emit_observation(
    workspace: str | Path,
    *,
    component: str,
    category: str,
    action: str,
    status: str = "ok",
    attributes: Mapping[str, object] | None = None,
    trust: str = "trusted_host",
) -> dict[str, object]:
    return ledger_for_workspace(workspace).emit(
        component=component,
        category=category,
        action=action,
        status=status,
        attributes=attributes,
        trust=trust,
    )


class ChildTraceSpool:
    """Best-effort child-process telemetry; records are never trusted as authority."""

    def __init__(self, workspace_root: str | Path, *, component: str, session_id: str) -> None:
        from .secure_artifacts import SecureArtifactStore

        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.component = _validate_name("component", component)
        if not _HEX_ID_RE.fullmatch(session_id):
            raise ObservabilityError("child observability session id is malformed")
        self.session_id = session_id
        self.trace_id = (os.environ.get("ANGERONA_TRACE_ID") or uuid.uuid4().hex).strip()
        if not _HEX_ID_RE.fullmatch(self.trace_id):
            raise ObservabilityError("child trace id is malformed")
        parent = (os.environ.get("ANGERONA_PARENT_SPAN_ID") or "").strip()
        self.parent_span_id = parent if _HEX_ID_RE.fullmatch(parent) else None
        self.store = SecureArtifactStore(self.workspace_root, "raw/observability")
        # One provider launch can host several MCP processes.  Per-process files
        # avoid independent writers racing the same local sequence/hash chain.
        component_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.component)
        self.filename = f"child-{session_id}-{component_slug}-{os.getpid()}.jsonl"
        self.sequence = 0
        self.previous_sha256: str | None = None
        try:
            raw = self.store.read_bytes(self.filename)
        except FileNotFoundError:
            raw = b""
        for line in raw.splitlines():
            try:
                record = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                raise ObservabilityError("child observability spool is malformed")
            digest = str(record.get("sha256") or "") if isinstance(record, dict) else ""
            body = dict(record) if isinstance(record, dict) else {}
            body.pop("sha256", None)
            if (
                body.get("sequence") != self.sequence + 1
                or body.get("previous_sha256") != self.previous_sha256
                or hashlib.sha256(_canonical_bytes(body)).hexdigest() != digest
            ):
                raise ObservabilityError("child observability spool chain is invalid")
            self.sequence += 1
            self.previous_sha256 = digest

    def emit(
        self,
        *,
        category: str,
        action: str,
        status: str = "ok",
        attributes: Mapping[str, object] | None = None,
        duration_ms: float | None = None,
    ) -> dict[str, object]:
        category = _validate_name("category", category)
        action = _validate_name("action", action)
        status = _validate_name("status", status)
        clean = sanitize_attributes(dict(attributes or {}))
        body: dict[str, object] = {
            "schema_version": OBSERVABILITY_SCHEMA_VERSION,
            "sequence": self.sequence + 1,
            "time_ns": time.time_ns(),
            "trace_id": self.trace_id,
            "session_id": self.session_id,
            "parent_span_id": self.parent_span_id,
            "component": self.component,
            "category": category,
            "action": action,
            "status": status,
            "duration_ms": duration_ms,
            "trust": "untrusted_child",
            "pid": os.getpid(),
            "attributes": clean,
            "previous_sha256": self.previous_sha256,
        }
        digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        record = {**body, "sha256": digest}
        with self.store.exclusive_lock():
            self.store.append_line(
                self.filename,
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            )
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.filename, flags, dir_fd=self.store.dir_fd)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(self.store.dir_fd)
        self.sequence += 1
        self.previous_sha256 = digest
        return record

    def close(self) -> None:
        self.store.close()


def child_observer_from_env(component: str) -> ChildTraceSpool | None:
    workspace = (
        os.environ.get("ANGERONA_OBSERVABILITY_WORKSPACE")
        or os.environ.get("ANGERONA_AGENT_WORKSPACE_ROOT")
        or os.environ.get("ANGERONA_RUN_CWD")
        or ""
    ).strip()
    session = (os.environ.get("ANGERONA_OBSERVABILITY_CHILD_SESSION") or "").strip()
    if not workspace or not _HEX_ID_RE.fullmatch(session):
        return None
    try:
        return ChildTraceSpool(workspace, component=component, session_id=session)
    except (OSError, ValueError, ObservabilityError):
        return None
