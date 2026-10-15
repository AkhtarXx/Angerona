"""Durable, content-addressed raw function evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any


RAW_FUNCTION_EVIDENCE_SCHEMA = "angerona/raw-function-evidence/v1"
VALIDATION_POLICY_SCHEMA = "angerona/function-result-validation/v1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_verified_copy(source: Path, destination: Path) -> dict[str, Any]:
    before_sha = sha256_path(source)
    before_size = source.stat().st_size
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(f".{destination.name}.{os.getpid()}.copying")
    try:
        with source.open("rb") as src, tmp.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
            dst.flush()
            os.fsync(dst.fileno())
        after_sha = sha256_path(source)
        after_size = source.stat().st_size
        copied_sha = sha256_path(tmp)
        copied_size = tmp.stat().st_size
        if not (
            before_sha == after_sha == copied_sha
            and before_size == after_size == copied_size
        ):
            raise RuntimeError(f"source raced during verified copy: {source}")
        os.replace(tmp, destination)
        _fsync_dir(destination.parent)
        return {"bytes": copied_size, "sha256": copied_sha}
    finally:
        tmp.unlink(missing_ok=True)


def validate_attempt_evidence(
    evidence: Any, *, target_sha256: str, expected_entry: str,
) -> dict[str, Any]:
    result = getattr(evidence, "result", None)
    raw = getattr(evidence, "raw_canonical_bytes", None)
    raw_sha = getattr(evidence, "raw_result_sha256", None)
    receipt = getattr(evidence, "attempt_receipt", None)
    if not isinstance(result, dict) or not isinstance(raw, bytes) or not isinstance(receipt, dict):
        raise ValueError("engine did not return a durable function evidence envelope")
    expected_raw = canonical_bytes(result)
    expected_sha = sha256_bytes(expected_raw)
    if raw != expected_raw or raw_sha != expected_sha:
        raise ValueError("engine raw result bytes/hash mismatch")
    normalized = expected_entry.lower().replace("0x", "")
    if receipt.get("schema") != "angerona/ghidra-function-attempt/v1":
        raise ValueError("engine attempt receipt schema mismatch")
    if receipt.get("target_sha256") != target_sha256:
        raise ValueError("engine attempt target SHA mismatch")
    requested = str(receipt.get("requested_entry") or "").lower().replace("0x", "")
    returned = str(receipt.get("returned_entry") or "").lower().replace("0x", "")
    if requested != normalized or returned != normalized:
        raise ValueError("engine attempt entry binding mismatch")
    if receipt.get("raw_result_sha256") != expected_sha or receipt.get("returncode") != 0:
        raise ValueError("engine attempt result/returncode mismatch")
    exporter_sha = str(receipt.get("exporter_sha256") or "")
    ghidra_identity = receipt.get("ghidra_identity")
    if len(exporter_sha) != 64 or not isinstance(ghidra_identity, dict):
        raise ValueError("engine attempt lacks exporter/Ghidra identity")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("engine attempt receipt hash mismatch")
    return result


def persist_raw_result(
    reconstruction_root: Path,
    *,
    target_sha256: str,
    entry: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    raw = canonical_bytes(result)
    result_sha = sha256_bytes(raw)
    safe_entry = entry.lower().replace("0x", "").replace("/", "_")
    relative = Path("raw_function_evidence") / safe_entry / f"{result_sha}.json"
    destination = reconstruction_root / relative
    if destination.is_file():
        if sha256_path(destination) != result_sha:
            raise RuntimeError(f"raw evidence hash collision at {destination}")
    else:
        atomic_bytes(destination, raw)
    return {
        "schema": RAW_FUNCTION_EVIDENCE_SCHEMA,
        "target_sha256": target_sha256,
        "entry": entry,
        "path": relative.as_posix(),
        "bytes": len(raw),
        "sha256": result_sha,
    }


def load_raw_result(reconstruction_root: Path, descriptor: dict[str, Any]) -> dict[str, Any]:
    relative = Path(str(descriptor.get("path") or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("raw evidence path escapes reconstruction root")
    path = reconstruction_root / relative
    expected = str(descriptor.get("sha256") or "")
    if not path.is_file() or sha256_path(path) != expected:
        raise ValueError("raw evidence file/hash mismatch")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or sha256_bytes(canonical_bytes(result)) != expected:
        raise ValueError("raw evidence canonical hash mismatch")
    return result
