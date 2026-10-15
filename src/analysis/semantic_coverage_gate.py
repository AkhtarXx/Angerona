"""Fail-closed coverage gate for evidence-bound semantic reconstruction."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


SCHEMA = "angerona/semantic-coverage-gate/v1"
CHECKPOINT_SCHEMA = "angerona/semantic-ai-checkpoint/v2"


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


def _queue_rows(queue: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    with queue.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (TypeError, ValueError) as exc:
                issues.append({"code": "INVALID_QUEUE_JSON", "line": line_number, "detail": str(exc)})
                continue
            unit_id = str(row.get("unit_id") or "") if isinstance(row, dict) else ""
            if not unit_id or not row.get("input_manifest_sha256"):
                issues.append({"code": "INVALID_QUEUE_IDENTITY", "line": line_number})
                continue
            if unit_id in seen:
                issues.append({"code": "DUPLICATE_QUEUE_UNIT", "line": line_number, "unit_id": unit_id})
                continue
            seen.add(unit_id)
            rows.append(row)
    return rows, issues


def build_semantic_coverage_gate(
    queue: str | Path,
    ai_output_dir: str | Path,
    *,
    output_path: str | Path | None = None,
    expected_model_alias: str | None = None,
) -> dict[str, Any]:
    queue_path = Path(queue).resolve()
    ai_output = Path(ai_output_dir).resolve()
    rows, issues = _queue_rows(queue_path)
    status_counts: dict[str, int] = {}

    for unit in rows:
        unit_id = str(unit["unit_id"])
        checkpoint_path = ai_output / "checkpoints" / f"{unit_id}.json"
        if not checkpoint_path.is_file():
            status_counts["missing"] = status_counts.get("missing", 0) + 1
            issues.append({"code": "MISSING_CHECKPOINT", "unit_id": unit_id})
            continue
        try:
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError) as exc:
            status_counts["invalid"] = status_counts.get("invalid", 0) + 1
            issues.append({"code": "INVALID_CHECKPOINT", "unit_id": unit_id, "detail": str(exc)})
            continue

        status = str(checkpoint.get("checkpoint_status") or "missing")
        status_counts[status] = status_counts.get(status, 0) + 1
        identity_key = "function_id" if unit.get("function_id") else "method_id"
        binding_ok = bool(
            checkpoint.get("schema") == CHECKPOINT_SCHEMA
            and checkpoint.get("unit_id") == unit_id
            and checkpoint.get("input_manifest_sha256") == unit["input_manifest_sha256"]
            and checkpoint.get(identity_key) == unit.get(identity_key)
        )
        if expected_model_alias is not None:
            binding_ok = binding_ok and checkpoint.get("model_alias") == expected_model_alias
        if not binding_ok:
            issues.append({"code": "CHECKPOINT_BINDING_MISMATCH", "unit_id": unit_id})
            continue
        if status != "ok":
            issues.append({"code": f"UNRESOLVED_{status.upper()}", "unit_id": unit_id})
            continue

        result = checkpoint.get("result")
        if not isinstance(result, dict) or result.get("status") != "reconstructed":
            issues.append({"code": "OK_WITHOUT_RECONSTRUCTION", "unit_id": unit_id})
            continue
        if result.get("input_manifest_sha256") != unit["input_manifest_sha256"]:
            issues.append({"code": "RESULT_BINDING_MISMATCH", "unit_id": unit_id})
            continue
        if result.get(identity_key) != unit.get(identity_key):
            issues.append({"code": "RESULT_IDENTITY_MISMATCH", "unit_id": unit_id})
            continue
        if result.get("evidence_requests"):
            issues.append({"code": "OK_WITH_OPEN_EVIDENCE", "unit_id": unit_id})
            continue

        response_blob = checkpoint.get("response_blob")
        response_sha = str(checkpoint.get("response_sha256") or "")
        if not response_blob or not response_sha or not checkpoint.get("request_id") or not checkpoint.get("resolved_model"):
            issues.append({"code": "MISSING_PROVIDER_RECEIPT", "unit_id": unit_id})
            continue
        response_path = (ai_output / str(response_blob)).resolve()
        try:
            response_path.relative_to(ai_output)
        except ValueError:
            issues.append({"code": "RESPONSE_PATH_ESCAPE", "unit_id": unit_id})
            continue
        if not response_path.is_file() or _sha_bytes(response_path.read_bytes()) != response_sha:
            issues.append({"code": "RESPONSE_HASH_MISMATCH", "unit_id": unit_id})

    gate = {
        "schema": SCHEMA,
        "queue_path": str(queue_path),
        "queue_sha256": _sha_bytes(queue_path.read_bytes()),
        "ai_output_dir": str(ai_output),
        "expected_model_alias": expected_model_alias,
        "units_expected": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "issues": issues,
        "coverage_complete": bool(rows) and not issues and status_counts.get("ok", 0) == len(rows),
    }
    gate["manifest_sha256"] = _sha_bytes(_canonical(gate))
    if output_path is not None:
        _atomic(Path(output_path).resolve(), json.dumps(gate, indent=2, sort_keys=True).encode() + b"\n")
    return gate
