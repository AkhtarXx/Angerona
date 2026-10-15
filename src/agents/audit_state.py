"""Crash-safe, append-only state for pausing and resuming a whole audit.

Snapshots are immutable, content-addressed JSON records linked by hash.  A crash
can leave only an ignored temporary file; a corrupt committed snapshot or broken
chain fails closed.  A separate OS lease prevents two processes from resuming the
same workspace concurrently, while immutable control records provide cooperative
pause/resume at committed execution boundaries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..observability import content_descriptor, ledger_for_workspace
from ..secure_artifacts import SecureArtifactStore


SCHEMA_VERSION = 1
_SNAPSHOT_RE = re.compile(r"^snapshot-(\d{12})-([0-9a-f]{64})\.json$")
_CONTROL_RE = re.compile(r"^control-(\d{20})-([0-9a-f]{64})\.json$")
_OPERATOR_INSTRUCTION_RE = re.compile(
    r"^operator-instruction-(\d{20})-([0-9a-f]{64})\.json$"
)
_BLOB_RE = re.compile(r"^blob-([0-9a-f]{64})\.bin$")
_CONTEXT_POLICY_RE = re.compile(
    r"^context-policy-(\d{12})-([0-9a-f]{64})\.json$"
)
_LEASE_NAME = ".audit-run.lease"
_HEAD_NAME = "audit-head.json"
_CONTEXT_POLICY_HEAD_NAME = "context-policy-head.json"
_WORKSPACE_ROOTS = (".",)
# Large Android audits materialize a per-worker `android_artifacts/` tree that
# alone can exceed 35k files / ~2.5 GiB (full JADX + apktool decompilation). The
# old 20k-file / 2 GiB quotas aborted every worker before it produced a single
# analysis round ("model-visible workspace exceeds manifest file quota"). Raise
# both so legitimate large-APK audits don't fail-closed on the manifest capture.
_MAX_MANIFEST_FILES = 250_000
_MAX_MANIFEST_BYTES = 256 * 1024 * 1024 * 1024
_MAX_IDENTITY_INPUT_BYTES = 16 * 1024 * 1024 * 1024
# Bulk deterministic decompilation trees (full JADX + apktool) are model-READABLE
# (workers shell/read into them on demand per the prompt) but must NOT be
# content-addressed into every worker's manifest blob set: a single tree is
# ~35k files / ~2.5 GiB, so per-round capture is both slow and quota-risky.
# Excluded subtrees stay model-readable; their files are simply not re-hashed
# per checkpoint. Keys are directory names matched directly under a workspace
# root's `code/` (the worker model-visible tree).
_MANIFEST_EXCLUDE_BULK_DIRS = frozenset({"android_artifacts"})
_MAX_OPERATOR_INSTRUCTIONS = 32
_MAX_OPERATOR_INSTRUCTION_CHARS = 2_000
_MAX_OPERATOR_INSTRUCTION_RECORD_BYTES = 16_384
_OPERATOR_INSTRUCTION_SCOPES = frozenset(
    {"all", "future-dispatches", "final-report"}
)


class AuditStateError(RuntimeError):
    """Committed resume state is absent, corrupt, incompatible, or unsafe."""


class AuditLeaseError(AuditStateError):
    """Another live process already owns this workspace."""


@dataclass(frozen=True)
class AuditSnapshot:
    generation: int
    digest: str
    path: Path
    payload: dict[str, Any]


@dataclass(frozen=True)
class ContextPolicySnapshot:
    version: int
    digest: str
    genesis_digest: str
    base_contract_sha256: str
    initial_windows: dict[str, int]
    windows: dict[str, int]
    profiles: dict[str, dict[str, str]]


class ContextPolicyController:
    """Thread-safe bridge from trusted runtime observations to future dispatches."""

    def __init__(
        self,
        store: "AuditStateStore",
        *,
        base_contract_sha256: str,
        snapshot: ContextPolicySnapshot,
    ) -> None:
        if snapshot.base_contract_sha256 != base_contract_sha256:
            raise AuditStateError("context policy controller base contract mismatch")
        self.store = store
        self.base_contract_sha256 = base_contract_sha256
        self._snapshot = snapshot
        self._lock = threading.Lock()

    def window(self, agent: str) -> int | None:
        with self._lock:
            return self._snapshot.windows.get(agent)

    def observe(
        self, agent: str, observations: Sequence[Mapping[str, Any]]
    ) -> list[ContextPolicySnapshot]:
        promoted: list[ContextPolicySnapshot] = []
        with self._lock:
            for observation in observations:
                snapshot, changed = self.store.promote_context_window(
                    base_contract_sha256=self.base_contract_sha256,
                    agent=agent,
                    observation=observation,
                )
                self._snapshot = snapshot
                if changed:
                    promoted.append(snapshot)
        return promoted

    def observe_and_apply(
        self,
        agent: str,
        observation: Mapping[str, Any],
        apply_window: Callable[[int], Any],
    ) -> tuple[list[ContextPolicySnapshot], Any]:
        """Commit evidence and apply its authoritative window atomically.

        The apply callback intentionally runs while the controller lock is held.
        That gives concurrent dispatches a linearization point: no newer policy
        transition can land between arbitration and mutation of the live recovery
        environment. Cross-audit profile persistence happens inside the apply
        callback under its own OS-level profile lock.
        """

        with self._lock:
            snapshot, changed = self.store.promote_context_window(
                base_contract_sha256=self.base_contract_sha256,
                agent=agent,
                observation=observation,
            )
            self._snapshot = snapshot
            window = snapshot.windows.get(agent)
            if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
                raise AuditStateError(
                    f"context policy has no valid window for agent {agent!r}"
                )
            applied = apply_window(window)
            return ([snapshot] if changed else []), applied

    def snapshot(self) -> ContextPolicySnapshot:
        with self._lock:
            return self._snapshot


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _sha256_file(
    path: Path,
    *,
    expected_size: int | None = None,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        initial = os.fstat(handle.fileno())
        expected = int(initial.st_size)
        if expected > _MAX_IDENTITY_INPUT_BYTES:
            raise AuditStateError(f"identity input exceeds size limit: {path}")
        if expected_size is not None and expected != expected_size:
            raise AuditStateError(f"identity input size changed before hashing: {path}")
        while size <= expected:
            chunk = handle.read(min(1024 * 1024, expected - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > expected:
                raise AuditStateError(f"identity input grew while hashing: {path}")
            digest.update(chunk)
        final = os.fstat(handle.fileno())
        if size != expected or final.st_size != expected:
            raise AuditStateError(f"identity input changed while hashing: {path}")
    return digest.hexdigest(), size


def _canonical_relative_path(value: str) -> tuple[str, ...]:
    candidate = Path(value)
    parts = candidate.parts
    if (
        candidate.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or candidate.as_posix() != value
    ):
        raise AuditStateError(f"invalid critical artifact path: {value}")
    return parts


def _sha256_file_beneath(
    root: Path,
    relative: str,
    *,
    missing_ok: bool = False,
    expected_size: int | None = None,
) -> tuple[str, int] | None:
    """Hash one regular workspace file without following any path symlink."""

    parts = _canonical_relative_path(relative)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    descriptors: list[int] = []
    file_fd: int | None = None
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise AuditStateError(
                f"critical artifact is not a regular file: {relative}"
            )
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = None
            digest = hashlib.sha256()
            size = 0
            initial = os.fstat(handle.fileno())
            expected = int(initial.st_size)
            if expected > _MAX_IDENTITY_INPUT_BYTES:
                raise AuditStateError(
                    f"identity input exceeds size limit: {relative}"
                )
            if expected_size is not None and expected != expected_size:
                raise AuditStateError(
                    f"identity input size changed before hashing: {relative}"
                )
            while size <= expected:
                chunk = handle.read(min(1024 * 1024, expected - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > expected:
                    raise AuditStateError(
                        f"identity input grew while hashing: {relative}"
                    )
                digest.update(chunk)
            final = os.fstat(handle.fileno())
            if size != expected or final.st_size != expected:
                raise AuditStateError(
                    f"identity input changed while hashing: {relative}"
                )
            return digest.hexdigest(), size
    except FileNotFoundError:
        if missing_ok:
            return None
        raise AuditStateError(f"required critical artifact is missing: {relative}")
    except AuditStateError:
        raise
    except OSError as exc:
        raise AuditStateError(
            f"cannot safely open critical artifact {relative}: {exc}"
        ) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_file_beneath(root: Path, relative: str) -> bytes:
    """Read one regular workspace file without following any path symlink.

    Mirrors the O_NOFOLLOW + dir_fd traversal and before/after size re-validation
    of :func:`_sha256_file_beneath` so a caller that has just verified a path as
    a regular file (a separate os.walk+lstat pass) cannot be raced between the
    check and the read: a swapped symlink would otherwise leak its target's bytes
    into the blob store, and a swapped FIFO would block read_bytes() indefinitely.
    """

    parts = _canonical_relative_path(relative)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    descriptors: list[int] = []
    file_fd: int | None = None
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise AuditStateError(
                f"workspace file is not a regular file: {relative}"
            )
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = None
            initial = os.fstat(handle.fileno())
            expected = int(initial.st_size)
            if expected > _MAX_IDENTITY_INPUT_BYTES:
                raise AuditStateError(
                    f"workspace file exceeds size limit: {relative}"
                )
            chunks: list[bytes] = []
            size = 0
            while size <= expected:
                chunk = handle.read(min(1024 * 1024, expected - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > expected:
                    raise AuditStateError(
                        f"workspace file grew while reading: {relative}"
                    )
                chunks.append(chunk)
            final = os.fstat(handle.fileno())
            if size != expected or final.st_size != expected:
                raise AuditStateError(
                    f"workspace file changed while reading: {relative}"
                )
            return b"".join(chunks)
    except FileNotFoundError:
        raise AuditStateError(f"required workspace file is missing: {relative}")
    except AuditStateError:
        raise
    except OSError as exc:
        raise AuditStateError(
            f"cannot safely open workspace file {relative}: {exc}"
        ) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def build_audit_identity(
    *,
    workspace_root: str | Path,
    binary: str | Path,
    critical_artifacts: Sequence[str] = (),
    required_artifacts: Sequence[str] = (),
) -> dict[str, Any]:
    """Fingerprint the exact target and stable deterministic inputs for resume."""

    root = Path(workspace_root).expanduser().resolve()
    target = Path(binary).expanduser().resolve()
    if not target.is_file():
        raise AuditStateError(f"audit target is unavailable: {target}")
    binary_hash, binary_size = _sha256_file(target)
    artifacts: list[dict[str, Any]] = []
    required = set(required_artifacts)
    for relative in sorted(set(critical_artifacts) | required):
        parts = _canonical_relative_path(relative)
        measured = _sha256_file_beneath(
            root,
            relative,
            missing_ok=relative not in required,
        )
        if measured is None:
            continue
        digest, size = measured
        artifacts.append({
            "path": "/".join(parts), "sha256": digest, "size": size,
        })
    return {
        "binary_path": str(target),
        "binary_sha256": binary_hash,
        "binary_size": binary_size,
        "critical_artifacts": artifacts,
    }


class AuditStateStore:
    """Immutable snapshot chain plus pause controls and a process lease."""

    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.store = SecureArtifactStore(self.workspace_root, "audit_state")
        self.observability = ledger_for_workspace(self.workspace_root)
        self._thread_lock = threading.RLock()
        self._lease_fd: int | None = None
        self._latest_cache: AuditSnapshot | None = None
        self._verified_blobs: set[str] = set()

    @property
    def path(self) -> Path:
        return self.store.path

    def _snapshot_records(self) -> list[tuple[int, str, str]]:
        records: list[tuple[int, str, str]] = []
        for name in self.store.list_names():
            match = _SNAPSHOT_RE.fullmatch(name)
            if match:
                records.append((int(match.group(1)), match.group(2), name))
        records.sort()
        return records

    def _load_head(self) -> tuple[int, str] | None:
        try:
            raw = self.store.read_bytes(_HEAD_NAME)
        except FileNotFoundError:
            return None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditStateError("audit head is corrupt") from exc
        if (
            not isinstance(doc, dict)
            or doc.get("schema_version") != SCHEMA_VERSION
            or not isinstance(doc.get("generation"), int)
            or doc["generation"] < 1
            or not re.fullmatch(r"[0-9a-f]{64}", str(doc.get("snapshot_sha256") or ""))
        ):
            raise AuditStateError("audit head schema mismatch")
        return doc["generation"], str(doc["snapshot_sha256"])

    def _write_head(self, generation: int, digest: str) -> None:
        raw = _canonical_bytes({
            "schema_version": SCHEMA_VERSION,
            "generation": generation,
            "snapshot_sha256": digest,
        })
        self.store.replace_bytes_atomic(_HEAD_NAME, raw)

    def _decode_snapshot(self, generation: int, expected_digest: str, name: str) -> dict[str, Any]:
        raw = self.store.read_bytes(name)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected_digest:
            raise AuditStateError(f"audit snapshot checksum mismatch: {name}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditStateError(f"audit snapshot is invalid JSON: {name}") from exc
        if (
            not isinstance(doc, dict)
            or doc.get("schema_version") != SCHEMA_VERSION
            or doc.get("generation") != generation
            or not isinstance(doc.get("payload"), dict)
        ):
            raise AuditStateError(f"audit snapshot schema mismatch: {name}")
        return doc

    def load_latest(self) -> AuditSnapshot | None:
        """Load and validate the complete parent chain; never silently roll back."""

        head = self._load_head()
        records = self._snapshot_records()
        if not records:
            if head is not None:
                raise AuditStateError("audit head exists but all snapshots are missing")
            return None
        if head is None:
            # Backward compatibility for pre-head snapshots. New snapshots always
            # require the durable head, so deleting it can never look like legacy.
            generation, digest, name = records[-1]
            latest_probe = self._decode_snapshot(generation, digest, name)
            if latest_probe.get("head_required") is True:
                raise AuditStateError("audit head is missing; refusing silent rollback")
            generations = [record[0] for record in records]
            if len(generations) != len(set(generations)):
                raise AuditStateError("legacy audit state has duplicate generations")
        else:
            generation, digest = head
            name = f"snapshot-{generation:012d}-{digest}.json"
            if (generation, digest, name) not in records:
                raise AuditStateError("audit head references a missing snapshot")
            latest_probe = None
        by_identity = {
            (record_generation, record_digest): record_name
            for record_generation, record_digest, record_name in records
        }
        latest_doc = self._decode_snapshot(generation, digest, name)
        current = latest_doc
        current_generation = generation
        while current_generation > 1:
            parent_digest = current.get("parent_sha256")
            previous_name = by_identity.get((current_generation - 1, parent_digest))
            if not isinstance(parent_digest, str) or previous_name is None:
                raise AuditStateError("audit snapshot chain is incomplete")
            current_generation -= 1
            current = self._decode_snapshot(
                current_generation, parent_digest, previous_name
            )
        if current.get("parent_sha256") is not None:
            raise AuditStateError("root audit snapshot unexpectedly has a parent")
        snapshot = AuditSnapshot(
            generation=generation,
            digest=digest,
            path=self.store.file_path(name),
            payload=deepcopy(latest_doc["payload"]),
        )
        self._latest_cache = snapshot
        return snapshot

    # ------------------------------------------------------- context policy

    def _context_policy_records(self) -> list[tuple[int, str, str]]:
        records: list[tuple[int, str, str]] = []
        for name in self.store.list_names():
            match = _CONTEXT_POLICY_RE.fullmatch(name)
            if match:
                records.append((int(match.group(1)), match.group(2), name))
        records.sort()
        return records

    def _load_context_policy_head(self) -> tuple[int, str, str] | None:
        try:
            raw = self.store.read_bytes(_CONTEXT_POLICY_HEAD_NAME)
        except FileNotFoundError:
            return None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditStateError("context policy head is corrupt") from exc
        version = doc.get("version") if isinstance(doc, dict) else None
        digest = doc.get("sha256") if isinstance(doc, dict) else None
        base = doc.get("base_contract_sha256") if isinstance(doc, dict) else None
        if (
            not isinstance(version, int)
            or version < 0
            or doc.get("schema_version") != 1
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(base, str)
            or re.fullmatch(r"[0-9a-f]{64}", base) is None
        ):
            raise AuditStateError("context policy head has an invalid schema")
        return version, digest, base

    def _write_context_policy_head(
        self, version: int, digest: str, base_contract_sha256: str
    ) -> None:
        self.store.replace_bytes_atomic(
            _CONTEXT_POLICY_HEAD_NAME,
            _canonical_bytes({
                "schema_version": 1,
                "version": version,
                "sha256": digest,
                "base_contract_sha256": base_contract_sha256,
            }),
        )

    def _decode_context_policy(self, version: int, digest: str, name: str) -> dict[str, Any]:
        try:
            raw = self.store.read_bytes(name)
        except OSError as exc:
            raise AuditStateError("context policy head references a missing record") from exc
        if hashlib.sha256(raw).hexdigest() != digest:
            raise AuditStateError("context policy record checksum mismatch")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditStateError("context policy record is corrupt") from exc
        if (
            not isinstance(doc, dict)
            or doc.get("schema_version") != 1
            or doc.get("record_type") != "context_policy"
            or doc.get("version") != version
        ):
            raise AuditStateError("context policy record has an invalid schema")
        return doc

    @staticmethod
    def _context_windows(value: object) -> dict[str, int]:
        if not isinstance(value, Mapping) or not value:
            raise AuditStateError("context policy windows are invalid")
        windows: dict[str, int] = {}
        for agent, raw in value.items():
            if not isinstance(agent, str) or not agent:
                raise AuditStateError("context policy has an invalid agent key")
            try:
                window = int(raw)
            except (TypeError, ValueError) as exc:
                raise AuditStateError("context policy window is not numeric") from exc
            if not 1_024 <= window <= 10_000_000:
                raise AuditStateError("context policy window is outside safe bounds")
            windows[agent] = window
        return windows

    @staticmethod
    def _context_profiles(value: object) -> dict[str, dict[str, str]]:
        if not isinstance(value, Mapping) or not value:
            raise AuditStateError("context policy profiles are invalid")
        profiles: dict[str, dict[str, str]] = {}
        for agent, raw in value.items():
            if not isinstance(agent, str) or not isinstance(raw, Mapping):
                raise AuditStateError("context policy profile has an invalid schema")
            model_name = raw.get("model_name")
            if not isinstance(model_name, str) or not model_name:
                raise AuditStateError("context policy profile is missing its model")
            profiles[agent] = {"model_name": model_name}
        return profiles

    @staticmethod
    def _validate_context_evidence(
        observation: Mapping[str, Any], *, agent: str, model_name: str
    ) -> tuple[int, int]:
        if (
            observation.get("source") != "typed_provider_error"
            or observation.get("agent_family") != agent
            or observation.get("model_name") != model_name
        ):
            raise AuditStateError("context observation identity is not trusted")
        try:
            limit = int(observation.get("context_limit_tokens"))
            total = int(observation.get("requested_total_tokens"))
            requested_input = int(observation.get("requested_input_tokens"))
            requested_output = int(observation.get("requested_output_tokens"))
            configured = int(observation.get("configured_context_window_tokens"))
        except (TypeError, ValueError) as exc:
            raise AuditStateError("context observation is incomplete") from exc
        if (
            not 1_024 <= limit <= 10_000_000
            or not 1_024 <= configured <= 10_000_000
            or total <= limit
            or total > 20_000_000
            or requested_input < 0
            or requested_output < 0
            or abs(total - requested_input - requested_output) > max(100, total // 100)
        ):
            raise AuditStateError("context observation is incoherent")
        return limit, configured

    def load_context_policy(self, *, required: bool = False) -> ContextPolicySnapshot | None:
        """Validate the complete versioned policy chain and return its committed tip."""

        head = self._load_context_policy_head()
        records = self._context_policy_records()
        if head is None:
            if records or required:
                raise AuditStateError("required context policy head is missing")
            return None
        head_version, head_digest, head_base = head
        decoded: dict[tuple[int, str], dict[str, Any]] = {}
        for record_version, record_digest, record_name in records:
            doc = self._decode_context_policy(
                record_version, record_digest, record_name
            )
            if doc.get("base_contract_sha256") != head_base:
                raise AuditStateError("context policy base contract changed")
            decoded[(record_version, record_digest)] = doc
        if (head_version, head_digest) not in decoded:
            raise AuditStateError("context policy head references a missing record")
        roots = [
            (digest, doc) for (version, digest), doc in decoded.items()
            if version == 0
        ]
        if len(roots) != 1:
            raise AuditStateError("context policy must have exactly one genesis")
        chain: list[tuple[str, dict[str, Any]]] = [roots[0]]
        used = {(0, roots[0][0])}
        version = 0
        digest = roots[0][0]
        while True:
            children = [
                (child_digest, child_doc)
                for (child_version, child_digest), child_doc in decoded.items()
                if child_version == version + 1
                and child_doc.get("parent_sha256") == digest
            ]
            if not children:
                break
            if len(children) != 1:
                raise AuditStateError("context policy has divergent transition branches")
            digest, doc = children[0]
            version += 1
            chain.append((digest, doc))
            used.add((version, digest))
        if used != set(decoded):
            raise AuditStateError("context policy contains an unlinked transition")
        if (head_version, head_digest) not in used:
            raise AuditStateError("context policy head is not part of the committed chain")
        genesis = chain[0][1]
        if genesis.get("parent_sha256") is not None or genesis.get("transition") is not None:
            raise AuditStateError("context policy genesis is invalid")
        initial = self._context_windows(genesis.get("initial_windows"))
        windows = self._context_windows(genesis.get("windows"))
        profiles = self._context_profiles(genesis.get("profiles"))
        if windows != initial or set(profiles) != set(initial):
            raise AuditStateError("context policy genesis identities do not match")
        previous_digest = chain[0][0]
        for expected_version, (record_digest, doc) in enumerate(chain[1:], start=1):
            if doc.get("version") != expected_version or doc.get("parent_sha256") != previous_digest:
                raise AuditStateError("context policy transition order is invalid")
            if self._context_profiles(doc.get("profiles")) != profiles:
                raise AuditStateError("context policy profiles changed")
            if self._context_windows(doc.get("initial_windows")) != initial:
                raise AuditStateError("context policy initial windows changed")
            transition = doc.get("transition")
            if not isinstance(transition, Mapping):
                raise AuditStateError("context policy transition is missing")
            agent = transition.get("agent")
            if not isinstance(agent, str) or agent not in profiles:
                raise AuditStateError("context policy transition agent is invalid")
            observed, configured = self._validate_context_evidence(
                transition.get("observation") if isinstance(transition.get("observation"), Mapping) else {},
                agent=agent,
                model_name=profiles[agent]["model_name"],
            )
            if transition.get("from_tokens") != windows[agent] or transition.get("to_tokens") != observed:
                raise AuditStateError("context policy transition does not match its parent")
            if observed == windows[agent]:
                raise AuditStateError("context policy contains a no-op transition")
            if configured != windows[agent] and observed >= windows[agent]:
                raise AuditStateError("stale context evidence attempted to relax the policy")
            expected_windows = dict(windows)
            expected_windows[agent] = observed
            if self._context_windows(doc.get("windows")) != expected_windows:
                raise AuditStateError("context policy transition windows are inconsistent")
            windows = expected_windows
            previous_digest = record_digest
        return ContextPolicySnapshot(
            version=version,
            digest=digest,
            genesis_digest=chain[0][0],
            base_contract_sha256=head_base,
            initial_windows=initial,
            windows=windows,
            profiles=profiles,
        )

    def initialize_context_policy(
        self,
        *,
        base_contract_sha256: str,
        initial_windows: Mapping[str, int],
        profiles: Mapping[str, Mapping[str, str]],
    ) -> ContextPolicySnapshot:
        """Create the immutable genesis policy, or verify an existing identical one."""

        with self._thread_lock, self.store.exclusive_lock():
            existing = self.load_context_policy()
            normalized_windows = self._context_windows(initial_windows)
            normalized_profiles = self._context_profiles(profiles)
            if existing is not None:
                if (
                    existing.base_contract_sha256 != base_contract_sha256
                    or existing.initial_windows != normalized_windows
                    or existing.profiles != normalized_profiles
                ):
                    raise AuditStateError("context policy genesis does not match this audit")
                return existing
            if re.fullmatch(r"[0-9a-f]{64}", base_contract_sha256) is None:
                raise AuditStateError("context policy base contract hash is invalid")
            doc = {
                "schema_version": 1,
                "record_type": "context_policy",
                "version": 0,
                "parent_sha256": None,
                "base_contract_sha256": base_contract_sha256,
                "initial_windows": normalized_windows,
                "windows": normalized_windows,
                "profiles": normalized_profiles,
                "transition": None,
                "created_ns": time.time_ns(),
            }
            raw = _canonical_bytes(doc)
            digest = hashlib.sha256(raw).hexdigest()
            name = f"context-policy-{0:012d}-{digest}.json"
            self.store.write_bytes_atomic(name, raw)
            self._write_context_policy_head(0, digest, base_contract_sha256)
            created = self.load_context_policy(required=True)
            assert created is not None
            return created

    def promote_context_window(
        self,
        *,
        base_contract_sha256: str,
        agent: str,
        observation: Mapping[str, Any],
    ) -> tuple[ContextPolicySnapshot, bool]:
        """Commit a conservative provider-observed limit before future dispatches use it."""

        with self._thread_lock, self.store.exclusive_lock():
            current = self.load_context_policy(required=True)
            assert current is not None
            if current.base_contract_sha256 != base_contract_sha256 or agent not in current.profiles:
                raise AuditStateError("context observation does not belong to this audit")
            observed, configured = self._validate_context_evidence(
                observation,
                agent=agent,
                model_name=current.profiles[agent]["model_name"],
            )
            previous = current.windows[agent]
            if observed == previous:
                return current, False
            # A concurrent call may have started under an older policy. Such
            # stale evidence may still tighten the current limit, but it may
            # never expand it. Upward learning is accepted only from a call
            # that was dispatched under the current committed window.
            if configured != previous and observed >= previous:
                return current, False
            windows = dict(current.windows)
            windows[agent] = observed
            version = current.version + 1
            doc = {
                "schema_version": 1,
                "record_type": "context_policy",
                "version": version,
                "parent_sha256": current.digest,
                "base_contract_sha256": base_contract_sha256,
                "initial_windows": current.initial_windows,
                "windows": windows,
                "profiles": current.profiles,
                "transition": {
                    "agent": agent,
                    "from_tokens": previous,
                    "to_tokens": observed,
                    "observation": dict(observation),
                },
                "created_ns": time.time_ns(),
            }
            raw = _canonical_bytes(doc)
            digest = hashlib.sha256(raw).hexdigest()
            name = f"context-policy-{version:012d}-{digest}.json"
            self.store.write_bytes_atomic(name, raw)
            self._write_context_policy_head(version, digest, base_contract_sha256)
            promoted = self.load_context_policy(required=True)
            assert promoted is not None
            return promoted, True

    def checkpoint(self, payload: Mapping[str, Any]) -> AuditSnapshot:
        """Commit one immutable state transition under the cross-process store lock."""

        with self._thread_lock, self.store.exclusive_lock():
            self._validate_blob_references(payload)
            # HEAD is the commit point. Validate its target and complete ancestry
            # before every append; a cached payload must never hide deleted state.
            latest = self.load_latest()
            generation = 1 if latest is None else latest.generation + 1
            doc = {
                "schema_version": SCHEMA_VERSION,
                "head_required": True,
                "generation": generation,
                "parent_sha256": latest.digest if latest else None,
                "created_ns": time.time_ns(),
                "payload": deepcopy(dict(payload)),
            }
            raw = _canonical_bytes(doc)
            digest = hashlib.sha256(raw).hexdigest()
            name = f"snapshot-{generation:012d}-{digest}.json"
            self.store.write_bytes_atomic(name, raw)
            self._write_head(generation, digest)
            snapshot = AuditSnapshot(
                generation=generation,
                digest=digest,
                path=self.store.file_path(name),
                payload=deepcopy(doc["payload"]),
            )
            self._latest_cache = snapshot
            self.observability.emit(
                component="audit_state",
                category="checkpoint",
                action="committed",
                attributes={
                    "generation": generation,
                    "snapshot_sha256": digest,
                    "parent_sha256": latest.digest if latest else None,
                    "payload": content_descriptor(raw),
                },
            )
            return snapshot

    def _validate_blob_references(self, value: object) -> None:
        """Fail closed if any content-addressed reference is absent or corrupt."""

        if isinstance(value, Mapping):
            if {"name", "sha256", "size"}.issubset(value):
                self.get_blob(value)
            for child in value.values():
                self._validate_blob_references(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._validate_blob_references(child)

    def put_blob(self, data: bytes) -> dict[str, Any]:
        """Persist immutable large state once and return a verified portable ref."""

        digest = hashlib.sha256(data).hexdigest()
        name = f"blob-{digest}.bin"
        with self._thread_lock, self.store.exclusive_lock():
            # Never trust the in-process verification cache as existence or
            # integrity proof. A blob can be deleted/corrupted by another
            # process after the first check. The atomic content-addressed write
            # repairs either case and revalidates the bytes on every reuse.
            try:
                self.store.write_bytes_atomic(name, data)
            except OSError as exc:
                raise AuditStateError(
                    f"audit state blob conflicts with its content address: {name}"
                ) from exc
            raw = self.store.read_bytes(name)
            if len(raw) != len(data) or hashlib.sha256(raw).hexdigest() != digest:
                raise AuditStateError(f"audit state blob write verification failed: {name}")
            self._verified_blobs.add(name)
        reference = {"name": name, "sha256": digest, "size": len(data)}
        self.observability.emit(
            component="audit_state",
            category="artifact",
            action="blob_committed",
            attributes=reference,
        )
        return reference

    def get_blob(self, reference: Mapping[str, Any]) -> bytes:
        """Load a content-addressed state blob and fail closed on substitution."""

        name = str(reference.get("name") or "")
        match = _BLOB_RE.fullmatch(name)
        expected_digest = str(reference.get("sha256") or "")
        expected_size = reference.get("size")
        if not match or match.group(1) != expected_digest:
            raise AuditStateError("audit state contains an invalid blob reference")
        try:
            raw = self.store.read_bytes(name)
        except OSError as exc:
            raise AuditStateError(f"audit state blob is missing or unreadable: {name}") from exc
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise AuditStateError(f"audit state blob checksum mismatch: {name}")
        self._verified_blobs.add(name)
        return raw

    def _workspace_files(self, *, allow_non_regular: bool = False) -> dict[str, Path]:
        files: dict[str, Path] = {}
        for root_name in _WORKSPACE_ROOTS:
            top = self.workspace_root
            if not top.is_dir():
                raise AuditStateError(f"model-visible workspace root is missing: {root_name}/")
            for directory, dirnames, filenames in os.walk(top, followlinks=False):
                directory_path = Path(directory)
                if directory_path == self.workspace_root and "audit_state" in dirnames:
                    dirnames.remove("audit_state")
                if (
                    directory_path == self.workspace_root / "raw"
                    and "observability" in dirnames
                ):
                    # This is a live, non-authoritative mirror of supervisor-only
                    # state. Snapshotting it makes exact restore race new events.
                    dirnames.remove("observability")
                # Skip bulk deterministic decompilation trees from the content-
                # addressed file set (see _MANIFEST_EXCLUDE_BULK_DIRS). The
                # directory itself is still listed in `directories` by
                # capture_workspace's separate walk, so it remains model-readable.
                if directory_path == self.workspace_root / "code":
                    for bulk in _MANIFEST_EXCLUDE_BULK_DIRS:
                        if bulk in dirnames:
                            dirnames.remove(bulk)
                for dirname in list(dirnames):
                    candidate = directory_path / dirname
                    if candidate.is_symlink():
                        relative = candidate.relative_to(self.workspace_root).as_posix()
                        dirnames.remove(dirname)
                        if allow_non_regular:
                            files[relative] = candidate
                        else:
                            raise AuditStateError(
                                f"model-visible workspace contains a symlink: {relative}"
                            )
                for filename in filenames:
                    candidate = directory_path / filename
                    relative = candidate.relative_to(self.workspace_root).as_posix()
                    info = candidate.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        if allow_non_regular:
                            files[relative] = candidate
                            continue
                        raise AuditStateError(
                            f"model-visible workspace contains a non-regular file: {relative}"
                        )
                    files[relative] = candidate
                    if len(files) > _MAX_MANIFEST_FILES:
                        raise AuditStateError("model-visible workspace exceeds manifest file quota")
        return files

    def capture_workspace(self) -> dict[str, Any]:
        """Content-address every file the worker model is allowed to observe."""

        entries: list[dict[str, Any]] = []
        total = 0
        for relative in sorted(self._workspace_files()):
            # _workspace_files() completed a separate lstat walk before this
            # read; open the file again through O_NOFOLLOW + dir_fd and re-check
            # its size so a concurrent untrusted writer cannot swap the verified
            # regular file for a symlink (leaking target bytes into the blob
            # store) or a FIFO (blocking the checkpoint with no timeout).
            raw = _read_file_beneath(self.workspace_root, relative)
            total += len(raw)
            if total > _MAX_MANIFEST_BYTES:
                raise AuditStateError("model-visible workspace exceeds manifest byte quota")
            entries.append({"path": relative, "blob": self.put_blob(raw)})
        directories: list[str] = []
        for directory, dirnames, _filenames in os.walk(self.workspace_root, followlinks=False):
            directory_path = Path(directory)
            if directory_path == self.workspace_root and "audit_state" in dirnames:
                dirnames.remove("audit_state")
            if directory_path == self.workspace_root / "raw" and "observability" in dirnames:
                dirnames.remove("observability")
            if directory_path == self.workspace_root / "code":
                # Record the bulk dir as model-readable but do not descend into
                # its (tens of thousands of) children — they are not restored.
                for bulk in _MANIFEST_EXCLUDE_BULK_DIRS:
                    if bulk in dirnames:
                        directories.append(
                            (directory_path / bulk)
                            .relative_to(self.workspace_root)
                            .as_posix()
                        )
                        dirnames.remove(bulk)
            if directory_path != self.workspace_root:
                directories.append(directory_path.relative_to(self.workspace_root).as_posix())
        return {
            "schema_version": SCHEMA_VERSION,
            "roots": list(_WORKSPACE_ROOTS),
            "file_count": len(entries),
            "total_bytes": total,
            "directories": sorted(directories),
            "files": entries,
        }

    def restore_workspace(self, manifest: Mapping[str, Any]) -> None:
        """Restore exactly the committed model-visible tree; quarantine crash residue."""

        if (
            manifest.get("schema_version") != SCHEMA_VERSION
            or manifest.get("roots") != list(_WORKSPACE_ROOTS)
            or not isinstance(manifest.get("files"), list)
            or not isinstance(manifest.get("directories"), list)
        ):
            raise AuditStateError("worker workspace manifest schema mismatch")
        expected: dict[str, bytes] = {}
        expected_directories: set[str] = set()
        for item in manifest["directories"]:
            relative_dir = Path(str(item or ""))
            if (
                relative_dir.is_absolute()
                or ".." in relative_dir.parts
                or not relative_dir.parts
                or relative_dir.parts[0] == "audit_state"
            ):
                raise AuditStateError("worker workspace manifest directory is unsafe")
            expected_directories.add(relative_dir.as_posix())
        total = 0
        for entry in manifest["files"]:
            if not isinstance(entry, Mapping):
                raise AuditStateError("worker workspace manifest entry is invalid")
            relative = Path(str(entry.get("path") or ""))
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or not relative.parts
                or relative.parts[0] == "audit_state"
            ):
                raise AuditStateError("worker workspace manifest path is unsafe")
            key = relative.as_posix()
            if key in expected:
                raise AuditStateError("worker workspace manifest contains duplicate paths")
            blob = entry.get("blob")
            if not isinstance(blob, Mapping):
                raise AuditStateError("worker workspace manifest blob is invalid")
            raw = self.get_blob(blob)
            total += len(raw)
            if len(expected) >= _MAX_MANIFEST_FILES or total > _MAX_MANIFEST_BYTES:
                raise AuditStateError("worker workspace manifest exceeds restore quota")
            expected[key] = raw
        if len(expected) != manifest.get("file_count") or total != manifest.get("total_bytes"):
            raise AuditStateError("worker workspace manifest totals do not match")

        current = self._workspace_files(allow_non_regular=True)
        current_directories: set[str] = set()
        for directory, dirnames, _filenames in os.walk(
            self.workspace_root, followlinks=False
        ):
            directory_path = Path(directory)
            if directory_path == self.workspace_root and "audit_state" in dirnames:
                dirnames.remove("audit_state")
            if directory_path == self.workspace_root / "raw" and "observability" in dirnames:
                dirnames.remove("observability")
            if directory_path == self.workspace_root:
                continue
            relative_directory = directory_path.relative_to(self.workspace_root)
            if "audit_state" not in relative_directory.parts:
                current_directories.add(relative_directory.as_posix())
        extras = sorted(set(current) - set(expected))
        extra_directories = current_directories - expected_directories
        if extras or extra_directories:
            quarantine = (
                self.workspace_root.parent
                / ".angerona-recovery"
                / self.workspace_root.name
                / uuid.uuid4().hex
            )
            top_extra_directories = sorted(
                (
                    relative for relative in extra_directories
                    if not any(
                        parent in extra_directories
                        for parent in Path(relative).parents
                        if parent.as_posix() != "."
                    )
                ),
                key=lambda value: (len(Path(value).parts), value),
            )
            moved_directories: list[Path] = []
            for relative in top_extra_directories:
                source = self.workspace_root / relative
                destination = quarantine / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                moved_directories.append(Path(relative))
            for relative in extras:
                if any(Path(relative).is_relative_to(directory) for directory in moved_directories):
                    continue
                source = current[relative]
                destination = quarantine / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)

        for relative in sorted(expected_directories, key=lambda value: len(Path(value).parts)):
            with SecureArtifactStore(self.workspace_root, relative):
                pass

        for relative, raw in expected.items():
            rel = Path(relative)
            parent = rel.parent.as_posix()
            store_root = self.workspace_root
            store_relative = parent
            if parent == ".":
                store_root = self.workspace_root.parent
                store_relative = self.workspace_root.name
            with SecureArtifactStore(store_root, store_relative) as destination_store:
                destination_store.replace_bytes_atomic(rel.name, raw)

        # Verify the restored view independently of the write path.
        restored = self._workspace_files()
        if set(restored) != set(expected):
            raise AuditStateError("worker workspace restore produced a different file set")
        for relative, raw in expected.items():
            if _sha256_file(restored[relative]) != (hashlib.sha256(raw).hexdigest(), len(raw)):
                raise AuditStateError(f"worker workspace restore mismatch: {relative}")

    def _write_control(self, action: str, reason: str = "") -> Path:
        if action not in {"pause", "resume"}:
            raise ValueError("audit control action must be pause or resume")
        with self._thread_lock, self.store.exclusive_lock():
            previous_ns = 0
            for existing_name in self.store.list_names():
                match = _CONTROL_RE.fullmatch(existing_name)
                if match:
                    previous_ns = max(previous_ns, int(match.group(1)))
            doc = {
                "schema_version": SCHEMA_VERSION,
                "action": action,
                "created_ns": max(time.time_ns(), previous_ns + 1),
                "reason": str(reason)[:2_000],
                "actor_pid": os.getpid(),
                "actor_host": socket.gethostname(),
            }
            raw = _canonical_bytes(doc)
            digest = hashlib.sha256(raw).hexdigest()
            name = f"control-{doc['created_ns']:020d}-{digest}.json"
            self.store.write_bytes_atomic(name, raw)
            path = self.store.file_path(name)
        self.observability.emit(
            component="audit_state",
            category="control",
            action=action,
            attributes={
                "reason": content_descriptor(str(reason)),
                "record_sha256": digest,
                "created_ns": doc["created_ns"],
            },
        )
        return path

    def request_pause(self, reason: str = "") -> Path:
        return self._write_control("pause", reason)

    def request_resume(self, reason: str = "") -> Path:
        return self._write_control("resume", reason)

    def request_operator_instruction(
        self,
        instruction: str,
        *,
        scope: str = "all",
    ) -> Path:
        """Append one controller-authored instruction for future safe points.

        Instructions refine audit focus, but they never replace the immutable run
        contract, target identity, authorization, safety policy, or completion gates.
        The append-only record is checksummed and lives outside worker workspaces.
        """

        text = str(instruction).strip()
        if not text:
            raise ValueError("operator instruction must not be empty")
        if len(text) > _MAX_OPERATOR_INSTRUCTION_CHARS:
            raise ValueError(
                "operator instruction exceeds "
                f"{_MAX_OPERATOR_INSTRUCTION_CHARS} characters"
            )
        normalized_scope = str(scope).strip().lower()
        if normalized_scope not in _OPERATOR_INSTRUCTION_SCOPES:
            raise ValueError(
                "operator instruction scope must be one of: "
                + ", ".join(sorted(_OPERATOR_INSTRUCTION_SCOPES))
            )
        with self._thread_lock, self.store.exclusive_lock():
            records = [
                name
                for name in self.store.list_names()
                if _OPERATOR_INSTRUCTION_RE.fullmatch(name)
            ]
            if len(records) >= _MAX_OPERATOR_INSTRUCTIONS:
                raise AuditStateError("operator instruction record limit reached")
            previous_ns = max(
                (
                    int(match.group(1))
                    for name in records
                    if (match := _OPERATOR_INSTRUCTION_RE.fullmatch(name))
                ),
                default=0,
            )
            doc = {
                "schema_version": SCHEMA_VERSION,
                "kind": "operator_instruction",
                "created_ns": max(time.time_ns(), previous_ns + 1),
                "scope": normalized_scope,
                "instruction": text,
                "actor_pid": os.getpid(),
                "actor_host": socket.gethostname(),
            }
            raw = _canonical_bytes(doc)
            if len(raw) > _MAX_OPERATOR_INSTRUCTION_RECORD_BYTES:
                raise ValueError("operator instruction record exceeds byte limit")
            digest = hashlib.sha256(raw).hexdigest()
            name = (
                f"operator-instruction-{doc['created_ns']:020d}-{digest}.json"
            )
            self.store.write_bytes_atomic(name, raw)
            path = self.store.file_path(name)
        self.observability.emit(
            component="audit_state",
            category="operator_instruction",
            action="submitted",
            attributes={
                "scope": normalized_scope,
                "instruction": content_descriptor(text),
                "record_sha256": digest,
                "created_ns": doc["created_ns"],
            },
        )
        return path

    def operator_instructions(self) -> list[dict[str, Any]]:
        """Return every verified operator instruction in creation order."""

        records: list[tuple[int, str, str]] = []
        for name in self.store.list_names():
            match = _OPERATOR_INSTRUCTION_RE.fullmatch(name)
            if match:
                records.append((int(match.group(1)), match.group(2), name))
        records.sort()
        if len(records) > _MAX_OPERATOR_INSTRUCTIONS:
            raise AuditStateError("operator instruction record limit exceeded")
        decoded: list[dict[str, Any]] = []
        for created_ns, expected_digest, name in records:
            raw = self.store.read_bytes(name)
            if len(raw) > _MAX_OPERATOR_INSTRUCTION_RECORD_BYTES:
                raise AuditStateError(
                    f"operator instruction record exceeds byte limit: {name}"
                )
            if hashlib.sha256(raw).hexdigest() != expected_digest:
                raise AuditStateError(
                    f"operator instruction checksum mismatch: {name}"
                )
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise AuditStateError(
                    f"operator instruction is invalid: {name}"
                ) from exc
            instruction = doc.get("instruction") if isinstance(doc, dict) else None
            if (
                not isinstance(doc, dict)
                or doc.get("schema_version") != SCHEMA_VERSION
                or doc.get("kind") != "operator_instruction"
                or doc.get("created_ns") != created_ns
                or doc.get("scope") not in _OPERATOR_INSTRUCTION_SCOPES
                or not isinstance(instruction, str)
                or not instruction.strip()
                or instruction != instruction.strip()
                or len(instruction) > _MAX_OPERATOR_INSTRUCTION_CHARS
            ):
                raise AuditStateError(
                    f"operator instruction schema mismatch: {name}"
                )
            decoded.append(
                {
                    **doc,
                    "record_sha256": expected_digest,
                    "record_name": name,
                }
            )
        return decoded

    def pause_requested(self) -> bool:
        records: list[tuple[int, str, str]] = []
        for name in self.store.list_names():
            match = _CONTROL_RE.fullmatch(name)
            if match:
                records.append((int(match.group(1)), match.group(2), name))
        if not records:
            return False
        _, expected_digest, name = max(records)
        raw = self.store.read_bytes(name)
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise AuditStateError(f"audit control checksum mismatch: {name}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditStateError(f"audit control is invalid: {name}") from exc
        if (
            not isinstance(doc, dict)
            or doc.get("schema_version") != SCHEMA_VERSION
            or doc.get("action") not in {"pause", "resume"}
        ):
            raise AuditStateError(f"audit control schema mismatch: {name}")
        return doc["action"] == "pause"

    def acquire_lease(self) -> None:
        """Hold a non-blocking OS lease for the lifetime of one active audit."""

        if self._lease_fd is not None:
            return
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - supported runtime is POSIX
            raise AuditLeaseError("cross-process audit leases require fcntl") from exc
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_LEASE_NAME, flags, 0o600, dir_fd=self.store.dir_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise AuditLeaseError("audit lease is not a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AuditLeaseError("audit workspace is already active") from exc
            lease = _canonical_bytes({
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "acquired_ns": time.time_ns(),
            })
            os.ftruncate(descriptor, 0)
            view = memoryview(lease)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            self._lease_fd = descriptor
            descriptor = -1
            self.observability.emit(
                component="audit_state",
                category="lease",
                action="acquired",
                attributes={"pid": os.getpid(), "host": socket.gethostname()},
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def lease_active(self) -> bool:
        try:
            import fcntl
        except ImportError:  # pragma: no cover
            return True
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_LEASE_NAME, flags, 0o600, dir_fd=self.store.dir_fd)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False
        finally:
            os.close(descriptor)

    def release_lease(self) -> None:
        if self._lease_fd is None:
            return
        try:
            import fcntl

            fcntl.flock(self._lease_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lease_fd)
            self._lease_fd = None
        self.observability.emit(
            component="audit_state",
            category="lease",
            action="released",
            attributes={"pid": os.getpid()},
        )

    def validate_identity(
        self,
        identity: Mapping[str, Any],
        *,
        binary_override: str | Path | None = None,
    ) -> str:
        """Verify target and deterministic inputs before model-visible state is reused."""

        target = Path(binary_override or str(identity.get("binary_path") or "")).expanduser().resolve()
        expected_hash = str(identity.get("binary_sha256") or "")
        expected_size = identity.get("binary_size")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_size > _MAX_IDENTITY_INPUT_BYTES
        ):
            raise AuditStateError("resume target identity has an invalid size")
        if not target.is_file():
            raise AuditStateError(f"resume target is unavailable: {target}")
        try:
            actual_hash, actual_size = _sha256_file(
                target, expected_size=expected_size
            )
        except AuditStateError as exc:
            if "size changed before hashing" in str(exc):
                raise AuditStateError(
                    "resume target does not match the checkpointed binary "
                    "(size mismatch rejected before hashing)"
                ) from exc
            raise
        if actual_hash != expected_hash or actual_size != expected_size:
            raise AuditStateError("resume target does not match the checkpointed binary")
        for record in identity.get("critical_artifacts") or []:
            if not isinstance(record, Mapping):
                raise AuditStateError("resume identity contains an invalid artifact record")
            relative = str(record.get("path") or "")
            try:
                _canonical_relative_path(relative)
            except AuditStateError as exc:
                raise AuditStateError("resume identity contains an unsafe artifact path")
            expected_artifact_size = record.get("size")
            if (
                isinstance(expected_artifact_size, bool)
                or not isinstance(expected_artifact_size, int)
                or expected_artifact_size < 0
                or expected_artifact_size > _MAX_IDENTITY_INPUT_BYTES
            ):
                raise AuditStateError(
                    f"resume artifact has an invalid checkpointed size: {relative}"
                )
            try:
                measured = _sha256_file_beneath(
                    self.workspace_root,
                    relative,
                    expected_size=expected_artifact_size,
                )
            except AuditStateError as exc:
                if "size changed before hashing" in str(exc):
                    raise AuditStateError(
                        f"resume artifact changed: {relative} "
                        "(size mismatch rejected before hashing)"
                    ) from exc
                raise
            assert measured is not None
            digest, size = measured
            if digest != record.get("sha256") or size != record.get("size"):
                raise AuditStateError(f"resume artifact changed: {relative}")
        return str(target)

    def close(self) -> None:
        self.release_lease()
        self.store.close()

    def __enter__(self) -> "AuditStateStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass
