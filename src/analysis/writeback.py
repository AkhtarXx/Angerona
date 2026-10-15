"""Transactional, target-bound, reversible IDA/Ghidra write-back plans."""

from __future__ import annotations

import hashlib
import json
import base64
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


WRITEBACK_SCHEMA_VERSION = "angerona.writeback/v1"
ALLOWED_KINDS = {"rename", "comment", "type", "patch"}
MAX_MUTATIONS = 100_000
MAX_PATCH_BYTES = 4096
_PATCH_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def _normalize_patch_hex(value: str, field_name: str) -> str:
    """Validate and normalize a strictly hex-encoded byte string."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty hex string")
    if len(value) % 2 != 0 or not _PATCH_HEX_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be an even-length hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - guarded by regex
        raise ValueError(f"{field_name} is not decodable hex") from exc
    if not decoded:
        raise ValueError(f"{field_name} must encode at least one byte")
    if len(decoded) > MAX_PATCH_BYTES:
        raise ValueError(f"{field_name} exceeds {MAX_PATCH_BYTES}-byte patch limit")
    return decoded.hex()


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()


@dataclass(frozen=True)
class WritebackMutation:
    kind: str
    address: int
    new_value: str
    old_value: str | None = None
    repeatable: bool = False
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in ALLOWED_KINDS:
            raise ValueError(f"unsupported write-back mutation {self.kind!r}")
        if self.address < 0 or not isinstance(self.new_value, str):
            raise ValueError("write-back address/value is invalid")
        if self.kind == "patch":
            normalized_new = _normalize_patch_hex(self.new_value, "new_value")
            object.__setattr__(self, "new_value", normalized_new)
            if self.old_value is not None:
                normalized_old = _normalize_patch_hex(self.old_value, "old_value")
                if len(normalized_old) != len(normalized_new):
                    raise ValueError("patch old_value and new_value must decode to equal lengths")
                object.__setattr__(self, "old_value", normalized_old)

    @classmethod
    def patch(
        cls,
        normalized_hex: str,
        address: int,
        *,
        original_hex: str | None = None,
        evidence_ids: tuple[str, ...] = (),
    ) -> "WritebackMutation":
        """Build a byte-patch mutation with strict hex validation.

        ``normalized_hex`` is the replacement bytes as hex (case-insensitive,
        even length, non-empty, <= MAX_PATCH_BYTES decoded). ``original_hex``,
        when provided, is the expected bytes currently at ``address`` and must
        decode to the same length — it enables verify-then-apply and rollback.
        """
        return cls(
            "patch",
            address,
            _normalize_patch_hex(normalized_hex, "normalized_hex"),
            None if original_hex is None else _normalize_patch_hex(original_hex, "original_hex"),
            False,
            tuple(evidence_ids),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "address": f"0x{self.address:x}",
            "new_value": self.new_value,
            "old_value": self.old_value,
            "repeatable": self.repeatable,
            "evidence_ids": list(self.evidence_ids),
        }

    def inverse(self) -> "WritebackMutation":
        if self.old_value is None:
            raise ValueError("cannot invert a mutation without its previous value")
        return WritebackMutation(
            self.kind, self.address, self.old_value, self.new_value,
            self.repeatable, self.evidence_ids,
        )


@dataclass
class WritebackPlan:
    target_sha256: str
    engine: str
    mutations: list[WritebackMutation]
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = WRITEBACK_SCHEMA_VERSION
    plan_id: str = ""

    def __post_init__(self) -> None:
        self.target_sha256 = self.target_sha256.lower()
        if len(self.target_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.target_sha256):
            raise ValueError("target_sha256 must be a SHA-256 digest")
        if self.engine not in {"ida", "ghidra"}:
            raise ValueError("write-back engine must be ida or ghidra")
        if len(self.mutations) > MAX_MUTATIONS:
            raise ValueError("write-back mutation count exceeds safety limit")
        identities = [(row.kind, row.address, row.repeatable) for row in self.mutations]
        if len(identities) != len(set(identities)):
            raise ValueError("write-back plan contains conflicting duplicate targets")
        expected = self.compute_plan_id()
        if self.plan_id and self.plan_id != expected:
            raise ValueError("write-back plan digest mismatch")
        self.plan_id = expected

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_sha256": self.target_sha256,
            "engine": self.engine,
            "mutations": [row.as_dict() for row in self.mutations],
            "metadata": dict(self.metadata),
        }

    def compute_plan_id(self) -> str:
        return _canonical_sha(self._unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "plan_id": self.plan_id}

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "WritebackPlan":
        return cls(
            str(row.get("target_sha256") or ""),
            str(row.get("engine") or ""),
            [WritebackMutation(
                str(item["kind"]), int(str(item["address"]), 0), str(item.get("new_value") or ""),
                item.get("old_value"), bool(item.get("repeatable", False)),
                tuple(item.get("evidence_ids") or ()),
            ) for item in row.get("mutations") or []],
            dict(row.get("metadata") or {}),
            str(row.get("schema_version") or WRITEBACK_SCHEMA_VERSION),
            str(row.get("plan_id") or ""),
        )


@dataclass(frozen=True)
class WritebackReceipt:
    plan_id: str
    target_sha256: str
    engine: str
    status: str
    applied: tuple[WritebackMutation, ...]
    error: str | None = None

    @property
    def rollback_plan(self) -> WritebackPlan:
        if any(row.old_value is None for row in self.applied):
            raise ValueError("receipt lacks old values required for rollback")
        return WritebackPlan(
            self.target_sha256,
            self.engine,
            [row.inverse() for row in reversed(self.applied)],
            {"rollback_of": self.plan_id},
        )


class WritebackAdapter(Protocol):
    def read(self, mutation: WritebackMutation) -> str: ...
    def apply(self, mutation: WritebackMutation) -> None: ...


class WritebackTransaction:
    """Apply atomically at the logical layer, rolling back partial failures."""

    def __init__(self, adapter: WritebackAdapter) -> None:
        self.adapter = adapter

    @staticmethod
    def verify_target(plan: WritebackPlan, target: str | Path) -> None:
        digest = hashlib.sha256(Path(target).read_bytes()).hexdigest()
        if digest != plan.target_sha256:
            raise ValueError("write-back target hash does not match plan")

    def apply(self, plan: WritebackPlan) -> WritebackReceipt:
        applied: list[WritebackMutation] = []
        try:
            for mutation in plan.mutations:
                old_value = self.adapter.read(mutation)
                if (
                    mutation.kind == "patch"
                    and mutation.old_value is not None
                    and old_value.lower() != mutation.old_value.lower()
                ):
                    raise ValueError(
                        f"patch precondition failed at 0x{mutation.address:x}: "
                        "on-disk bytes do not match old_value"
                    )
                concrete = WritebackMutation(
                    mutation.kind, mutation.address, mutation.new_value, old_value,
                    mutation.repeatable, mutation.evidence_ids,
                )
                self.adapter.apply(concrete)
                applied.append(concrete)
        except Exception as exc:
            rollback_errors: list[str] = []
            for mutation in reversed(applied):
                try:
                    self.adapter.apply(mutation.inverse())
                except Exception as rollback_exc:  # noqa: BLE001
                    rollback_errors.append(str(rollback_exc))
            error = str(exc)
            if rollback_errors:
                error += "; rollback errors: " + "; ".join(rollback_errors)
            return WritebackReceipt(
                plan.plan_id, plan.target_sha256, plan.engine,
                "rollback_failed" if rollback_errors else "rolled_back",
                tuple(applied), error,
            )
        return WritebackReceipt(
            plan.plan_id, plan.target_sha256, plan.engine, "applied", tuple(applied)
        )


class PatchWritebackAdapter:
    """Direct binary-file adapter for ``patch`` mutations.

    LIMITATION: mutation addresses are treated as raw file offsets (1:1 VA ==
    file offset). This holds for contiguous, non-paged flat images (raw dumps,
    some firmware). It does NOT model section RVA/file-offset translation for
    PE/ELF on-disk images; callers must pre-translate addresses for those.

    Patching is in-place (same-length writes only, enforced by the mutation
    validation) with fsync after every write. The file is opened O_RDWR |
    O_NOFOLLOW so symlinks are rejected.
    """

    def __init__(self, binary_path: str | Path, dry_run: bool = False) -> None:
        self.path = Path(binary_path)
        self.dry_run = dry_run
        if self.path.is_symlink():
            raise ValueError(f"refusing to patch symlink: {self.path}")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._fd = os.open(self.path, flags)
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __enter__(self) -> "PatchWritebackAdapter":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def __del__(self) -> None:  # best-effort fd hygiene
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _require_patch(mutation: WritebackMutation) -> bytes:
        if mutation.kind != "patch":
            raise ValueError(f"PatchWritebackAdapter only handles 'patch', got {mutation.kind!r}")
        decoded = bytes.fromhex(mutation.new_value)
        if not decoded or len(decoded) > MAX_PATCH_BYTES:
            raise ValueError("patch payload violates size constraints")
        return decoded

    def _offset(self, mutation: WritebackMutation, length: int) -> int:
        offset = mutation.address  # addresses are 1:1 file offsets (documented above)
        size = os.fstat(self._fd).st_size
        if offset < 0 or offset + length > size:
            raise ValueError(
                f"patch range 0x{offset:x}..0x{offset + length:x} outside file size 0x{size:x}"
            )
        return offset

    def read(self, mutation: WritebackMutation) -> str:
        new_bytes = self._require_patch(mutation)
        offset = self._offset(mutation, len(new_bytes))
        os.lseek(self._fd, offset, os.SEEK_SET)
        chunks = bytearray()
        remaining = len(new_bytes)
        while remaining > 0:  # bounded: never more than MAX_PATCH_BYTES
            chunk = os.read(self._fd, remaining)
            if not chunk:
                raise ValueError(f"short read at 0x{offset:x}")
            chunks.extend(chunk)
            remaining -= len(chunk)
        return bytes(chunks).hex()

    def apply(self, mutation: WritebackMutation) -> None:
        new_bytes = self._require_patch(mutation)
        if mutation.old_value is not None:
            if len(bytes.fromhex(mutation.old_value)) != len(new_bytes):
                raise ValueError("patch old/new length mismatch")
        if self.dry_run:
            self.read(mutation)  # validate range readability; write nothing
            return
        current = self.read(mutation)
        if mutation.old_value is not None and current != mutation.old_value.lower():
            raise ValueError(
                f"patch precondition failed at 0x{mutation.address:x}: "
                "on-disk bytes do not match old_value"
            )
        offset = self._offset(mutation, len(new_bytes))
        os.lseek(self._fd, offset, os.SEEK_SET)
        written = 0
        while written < len(new_bytes):
            count = os.write(self._fd, new_bytes[written:])
            if count <= 0:
                raise OSError(f"write stalled at 0x{offset + written:x}")
            written += count
        os.fsync(self._fd)


def verify_patch(plan: WritebackPlan, target: str | Path) -> None:
    """Verify every patch mutation's ``old_value`` matches the bytes on disk.

    This is the precondition for applying a patch plan: if any declared
    ``old_value`` does not match, the apply must not proceed. Patch mutations
    without an ``old_value`` are range-checked only (they are non-reversible).
    Non-patch mutations are ignored here.
    """
    path = Path(target)
    if path.is_symlink():
        raise ValueError(f"refusing to verify symlink: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        size = os.fstat(fd).st_size
        for mutation in plan.mutations:
            if mutation.kind != "patch":
                continue
            new_len = len(bytes.fromhex(mutation.new_value))
            offset = mutation.address
            if offset < 0 or offset + new_len > size:
                raise ValueError(
                    f"patch at 0x{offset:x} exceeds target size 0x{size:x}"
                )
            if mutation.old_value is None:
                continue
            os.lseek(fd, offset, os.SEEK_SET)
            actual = os.read(fd, new_len)
            if actual.hex() != mutation.old_value.lower():
                raise ValueError(
                    f"patch precondition failed at 0x{offset:x}: "
                    "on-disk bytes do not match old_value"
                )
    finally:
        os.close(fd)


def write_plan(plan: WritebackPlan, destination: str | Path) -> None:
    """Write the engine-neutral plan consumed by IDA/Ghidra adapters."""
    Path(destination).write_text(json.dumps(plan.as_dict(), indent=2, sort_keys=True))


def write_ghidra_plan(plan: WritebackPlan, destination: str | Path) -> None:
    """Write a dependency-free TSV bundle consumed by GhidraWriteback.java."""
    if plan.engine != "ghidra":
        raise ValueError("Ghidra plan exporter requires engine='ghidra'")
    lines = [
        f"schema\t{plan.schema_version}",
        f"target_sha256\t{plan.target_sha256}",
        f"plan_id\t{plan.plan_id}",
    ]
    for mutation in plan.mutations:
        encoded = base64.b64encode(mutation.new_value.encode("utf-8")).decode("ascii")
        lines.append(
            f"mutation\t{mutation.kind}\t0x{mutation.address:x}\t"
            f"{1 if mutation.repeatable else 0}\t{encoded}"
        )
    Path(destination).write_text("\n".join(lines) + "\n")
