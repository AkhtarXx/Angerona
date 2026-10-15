"""Fail-closed readiness validation for model-visible binary exports.

The export tree is the deterministic evidence base shared by the supervisor and
workers.  A directory merely containing ``analysis.json`` is not enough: the
manifest, prompt-injection scan, and content-addressed evidence ledger must agree
with every required artifact before any agent is dispatched.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any


class AuditReadinessError(RuntimeError):
    """The deterministic export is absent, incomplete, corrupt, or inconsistent."""


SCHEMA_VERSION = 1
READINESS_FILENAME = "AUDIT_READINESS.json"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 48
MAX_JSON_NODES = 500_000
MAX_JSON_STRING = 1 * 1024 * 1024
MAX_ARTIFACTS = 100_000
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXPORT_BYTES = 16 * 1024 * 1024 * 1024
REQUIRED_EXPORT_ARTIFACTS = frozenset({
    "EXPORT_MANIFEST.json",
    "EVIDENCE_LEDGER.json",
    "analysis.json",
    "all_decompiled.c",
    "functions.csv",
    "injection_scan.json",
})


def _open_beneath(root: Path, relative: str):
    candidate = Path(relative)
    parts = candidate.parts
    if (
        candidate.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or candidate.as_posix() != relative
    ):
        raise AuditReadinessError(f"unsafe export artifact path: {relative!r}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current)
        mode = os.fstat(file_fd).st_mode
        if not stat.S_ISREG(mode):
            os.close(file_fd)
            raise AuditReadinessError(f"export artifact is not a regular file: {relative}")
        return os.fdopen(file_fd, "rb")
    except AuditReadinessError:
        raise
    except OSError as exc:
        raise AuditReadinessError(
            f"cannot safely open export artifact {relative}: {exc}"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _stable_file(
    root: Path,
    relative: str,
    *,
    capture: bool = False,
    max_bytes: int = MAX_ARTIFACT_BYTES,
):
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    with _open_beneath(root, relative) as handle:
        initial = os.fstat(handle.fileno())
        expected = int(initial.st_size)
        if expected > max_bytes:
            raise AuditReadinessError(
                f"export artifact exceeds {max_bytes} bytes: {relative}"
            )
        total = 0
        while total <= expected:
            chunk = handle.read(min(1024 * 1024, expected - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > expected:
                raise AuditReadinessError(f"export artifact grew while validating: {relative}")
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        final = os.fstat(handle.fileno())
        if total != expected or final.st_size != expected:
            raise AuditReadinessError(f"export artifact changed while validating: {relative}")
    return digest.hexdigest(), total, b"".join(chunks) if capture else None


def _load_json(root: Path, relative: str) -> tuple[Any, str, int]:
    digest, size, raw = _stable_file(
        root, relative, capture=True, max_bytes=MAX_JSON_BYTES
    )

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def parse_int(value: str) -> int:
        if len(value.lstrip("-")) > 128:
            raise ValueError("integer literal exceeds 128 digits")
        return int(value)

    def parse_float(value: str) -> float:
        if len(value) > 128:
            raise ValueError("floating-point literal exceeds 128 characters")
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("invalid floating-point literal")
        return parsed

    try:
        value = json.loads(
            raw or b"",
            object_pairs_hook=pairs_hook,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise AuditReadinessError(f"invalid export JSON {relative}: {exc}") from exc

    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise AuditReadinessError(f"export JSON resource limits exceeded: {relative}")
        if isinstance(current, str) and len(current) > MAX_JSON_STRING:
            raise AuditReadinessError(f"export JSON string exceeds limit: {relative}")
        if isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str) or len(key) > MAX_JSON_STRING:
                    raise AuditReadinessError(f"export JSON key exceeds limit: {relative}")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value, digest, size


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditReadinessError(f"invalid non-negative integer for {label}")
    return value


def validate_audit_readiness(
    code_dir: str | Path,
    *,
    binary: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a complete export and return a deterministic readiness record."""

    requested_root = Path(code_dir).absolute()
    if requested_root.is_symlink():
        raise AuditReadinessError("export root symlink refused")
    try:
        root = requested_root.resolve(strict=True)
    except OSError as exc:
        raise AuditReadinessError("export root is unavailable") from exc
    if not root.is_dir():
        raise AuditReadinessError("export root is not a directory")

    manifest, manifest_sha, _ = _load_json(root, "EXPORT_MANIFEST.json")
    ledger, ledger_sha, ledger_size = _load_json(root, "EVIDENCE_LEDGER.json")
    injection, _, _ = _load_json(root, "injection_scan.json")
    if not isinstance(manifest, dict) or not isinstance(ledger, dict):
        raise AuditReadinessError("export manifest and evidence ledger must be objects")
    if not isinstance(injection, dict) or injection.get("status") != "ok":
        raise AuditReadinessError("prompt-injection scan is absent or failed")

    manifest_status = str(manifest.get("status") or "")
    if manifest_status not in {"ok", "partial"}:
        raise AuditReadinessError(
            f"export manifest is not agent-ready: {manifest_status or 'missing status'}"
        )
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise AuditReadinessError("export manifest counts are missing")
    functions = _nonnegative_int(counts.get("functions"), "functions")
    decompiled = _nonnegative_int(
        counts.get("decompiled_functions"), "decompiled_functions"
    )
    if functions < 1 or decompiled > functions:
        raise AuditReadinessError("export has no analyzable functions or invalid coverage")
    expected_manifest_status = "ok" if decompiled == functions else "partial"
    if manifest_status != expected_manifest_status:
        raise AuditReadinessError(
            "export manifest status disagrees with decompilation coverage: "
            f"expected {expected_manifest_status}, got {manifest_status}"
        )

    ledger_manifest = ledger.get("manifest")
    if not isinstance(ledger_manifest, dict):
        raise AuditReadinessError("evidence ledger manifest binding is missing")
    if (
        ledger_manifest.get("status") != manifest_status
        or ledger_manifest.get("counts") != counts
        or ledger_manifest.get("effective_max_functions")
        != manifest.get("effective_max_functions")
    ):
        raise AuditReadinessError("evidence ledger disagrees with export manifest")

    artifacts = ledger.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise AuditReadinessError("evidence ledger artifact list is invalid or excessive")
    artifact_count = _nonnegative_int(
        ledger.get("artifact_count"), "ledger artifact_count"
    )
    if artifact_count != len(artifacts):
        raise AuditReadinessError("evidence ledger artifact count is inconsistent")
    identities: dict[str, tuple[str, int]] = {}
    identities["EVIDENCE_LEDGER.json"] = (ledger_sha, ledger_size)
    total_bytes = 0
    for record in artifacts:
        if not isinstance(record, dict):
            raise AuditReadinessError("evidence ledger contains a malformed artifact")
        relative = str(record.get("path") or "")
        if relative in identities:
            raise AuditReadinessError(f"duplicate evidence artifact: {relative}")
        expected_digest = record.get("sha256")
        expected_size = _nonnegative_int(
            record.get("size_bytes"), f"artifact size {relative!r}"
        )
        if not isinstance(expected_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_digest
        ):
            raise AuditReadinessError(
                f"evidence artifact digest is invalid: {relative}"
            )
        digest, size, _ = _stable_file(root, relative)
        if digest != expected_digest or size != expected_size:
            raise AuditReadinessError(f"evidence artifact identity mismatch: {relative}")
        identities[relative] = (digest, size)
        total_bytes += size
        if total_bytes > MAX_EXPORT_BYTES:
            raise AuditReadinessError(
                f"export evidence exceeds {MAX_EXPORT_BYTES} aggregate bytes"
            )

    missing = sorted(REQUIRED_EXPORT_ARTIFACTS - identities.keys())
    if missing:
        raise AuditReadinessError(
            "required export artifacts are missing from the ledger: " + ", ".join(missing)
        )
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list) or len(manifest_files) > MAX_ARTIFACTS:
        raise AuditReadinessError("export manifest file inventory is invalid")
    normalized_files: set[str] = set()
    for value in manifest_files:
        if not isinstance(value, str) or value in normalized_files:
            raise AuditReadinessError("export manifest has invalid or duplicate file paths")
        relative = Path(value)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.as_posix() != value
            or value not in identities
        ):
            raise AuditReadinessError(f"unbound export manifest artifact: {value!r}")
        normalized_files.add(value)
    unlisted_required = sorted(
        (
            REQUIRED_EXPORT_ARTIFACTS
            - {"EVIDENCE_LEDGER.json", "EXPORT_MANIFEST.json"}
        )
        - normalized_files
    )
    if unlisted_required:
        raise AuditReadinessError(
            "required artifacts are absent from the export manifest: "
            + ", ".join(unlisted_required)
        )
    expected_ledger_paths = normalized_files | {"EXPORT_MANIFEST.json"}
    actual_ledger_paths = set(identities) - {"EVIDENCE_LEDGER.json"}
    if actual_ledger_paths != expected_ledger_paths:
        missing_from_manifest = sorted(actual_ledger_paths - expected_ledger_paths)
        missing_from_ledger = sorted(expected_ledger_paths - actual_ledger_paths)
        raise AuditReadinessError(
            "export manifest and evidence ledger inventories disagree"
            f"; unlisted={missing_from_manifest}; unledgered={missing_from_ledger}"
        )

    target_identity: dict[str, Any] = {}
    ledger_binary = ledger.get("binary")
    if not isinstance(ledger_binary, dict):
        raise AuditReadinessError("evidence ledger target identity is missing")
    expected_target_sha = str(ledger_binary.get("sha256") or "")
    expected_target_size = ledger_binary.get("size_bytes")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_target_sha):
        raise AuditReadinessError("evidence ledger target digest is invalid")
    expected_target_size = _nonnegative_int(expected_target_size, "target size")
    if binary is not None:
        binary_path = Path(binary).expanduser().resolve(strict=True)
        binary_digest = hashlib.sha256()
        size = 0
        with binary_path.open("rb") as handle:
            initial = os.fstat(handle.fileno())
            expected = int(initial.st_size)
            while size <= expected:
                chunk = handle.read(min(1024 * 1024, expected - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > expected:
                    raise AuditReadinessError("target binary grew during readiness check")
                binary_digest.update(chunk)
            final = os.fstat(handle.fileno())
        if size != expected or final.st_size != expected:
            raise AuditReadinessError("target binary changed during readiness check")
        if binary_digest.hexdigest() != expected_target_sha or size != expected_target_size:
            raise AuditReadinessError("export evidence belongs to a different target binary")
        target_identity = {"sha256": binary_digest.hexdigest(), "size_bytes": size}
    else:
        target_identity = {
            "sha256": expected_target_sha,
            "size_bytes": expected_target_size,
        }

    limitations: list[dict[str, Any]] = []
    if decompiled < functions:
        limitations.append({
            "code": (
                "decompilation_unavailable" if decompiled == 0
                else "decompilation_partial"
            ),
            "functions": functions,
            "decompiled_functions": decompiled,
            "decompilation_ratio": round(decompiled / functions, 6),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ready_with_limitations" if limitations else "ready",
        "agent_dispatch_allowed": True,
        "target": target_identity,
        "export": {
            "manifest_sha256": manifest_sha,
            "ledger_sha256": ledger_sha,
            "manifest_status": manifest_status,
            "artifact_count": len(artifacts),
            "total_bytes": total_bytes,
        },
        "coverage": {
            "functions": functions,
            "decompiled_functions": decompiled,
            "decompilation_ratio": round(decompiled / functions, 6),
        },
        "limitations": limitations,
    }


def write_audit_readiness(
    code_dir: str | Path,
    *,
    binary: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(code_dir)
    result = validate_audit_readiness(root, binary=binary)
    target = root / READINESS_FILENAME
    temporary = root / f".{READINESS_FILENAME}.tmp"
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    return result
