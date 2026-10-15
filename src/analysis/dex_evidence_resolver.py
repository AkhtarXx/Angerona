"""Resolve DEX semantic evidence requests against sealed ABL method artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "angerona/dex-evidence-resolution/v1"
WORK_SCHEMAS = {"angerona/semantic-method-work-unit/v3", "angerona/semantic-method-work-unit/v4"}


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"non-object JSON row at {path}:{line_number}")
            rows.append(row)
    return rows


def _validated_input(item: dict[str, Any]) -> tuple[Path, int]:
    path = Path(str(item.get("path") or "")).resolve()
    expected = str(item.get("sha256") or "")
    if not path.is_file() or not expected:
        raise ValueError(f"missing evidence artifact: {path}")
    if _sha_path(path) != expected:
        raise ValueError(f"evidence artifact hash mismatch: {path}")
    return path, path.stat().st_size


def _smali_body(unit: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    matches = [row for row in unit.get("inputs") or [] if row.get("kind") == "smali-method-body"]
    if len(matches) != 1:
        raise ValueError(f"unit {unit.get('unit_id')} has no unique smali body")
    path, _ = _validated_input(matches[0])
    return path.read_text(encoding="utf-8", errors="strict"), matches[0]


def _reference_lines(body: str, target: str) -> list[str]:
    field_reference = "(" not in target
    result: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if target not in stripped:
            continue
        opcode = stripped.split(None, 1)[0] if stripped else ""
        if field_reference and opcode.startswith(("sput", "iput")):
            continue
        if not field_reference and not opcode.startswith("invoke-"):
            continue
        result.append(stripped)
    return result


def _related_inputs(
    request_id: str,
    request_kind: str,
    related: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for unit in related:
        for item in unit.get("inputs") or []:
            path, _ = _validated_input(item)
            key = (str(path), str(item["sha256"]))
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "kind": f"resolved-{request_kind}-{item['kind']}",
                "path": str(path),
                "sha256": item["sha256"],
                "request_id": request_id,
                "related_method_id": unit["method_id"],
                "related_qualified_name": unit["qualified_name"],
            })
    return result


def _evidence_key(kind: str, target: str) -> str:
    return _sha_bytes(_canonical({"kind": kind, "target": target}))


def _resolved_evidence_keys(unit: dict[str, Any]) -> set[str]:
    keys = {str(row) for row in unit.get("resolved_evidence_keys") or [] if row}
    for item in unit.get("inputs") or []:
        if item.get("kind") != "dex-evidence-resolution-receipt":
            continue
        path, _ = _validated_input(item)
        receipt = json.loads(path.read_text(encoding="utf-8"))
        for request in receipt.get("requests") or []:
            if str(request.get("status") or "").startswith("resolved"):
                keys.add(_evidence_key(str(request.get("kind") or ""), str(request.get("target") or "")))
    return keys


def resolve_dex_evidence_requests(
    primary_queue: str | Path,
    primary_ai_output: str | Path,
    evidence_ai_output: str | Path,
    output_dir: str | Path,
    *,
    max_evidence_bytes: int = 262144,
) -> dict[str, Any]:
    primary_path = Path(primary_queue).resolve()
    primary_ai = Path(primary_ai_output).resolve()
    evidence_ai = Path(evidence_ai_output).resolve()
    output = Path(output_dir).resolve()
    work_path = output / "DEX_EVIDENCE_WORK_UNITS.jsonl"
    primary_units = _load_jsonl(primary_path)
    prior_units = _load_jsonl(work_path)
    all_units = {str(row["unit_id"]): row for row in [*primary_units, *prior_units]}
    primary_schemas = {str(row.get("schema") or "") for row in primary_units}
    if len(primary_schemas) != 1 or not primary_schemas.issubset(WORK_SCHEMAS):
        raise ValueError("DEX evidence resolver received an unsupported primary work unit")
    primary_schema = next(iter(primary_schemas))
    if any(row.get("schema") != primary_schema for row in all_units.values()):
        raise ValueError("DEX evidence lineage mixes work-unit schemas")

    bodies: dict[str, str] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    by_class: dict[str, list[dict[str, Any]]] = {}
    for unit in primary_units:
        body, _ = _smali_body(unit)
        bodies[str(unit["unit_id"])] = body
        by_name.setdefault(str(unit["qualified_name"]), []).append(unit)
        by_class.setdefault(str(unit.get("class_descriptor") or ""), []).append(unit)

    method_receipt_inputs = [
        item for unit in primary_units for item in unit.get("inputs") or []
        if item.get("kind") == "dex-method-receipt"
    ]
    if not method_receipt_inputs:
        raise ValueError("primary queue exposes no DEX method receipts")
    method_receipt_dir = Path(str(method_receipt_inputs[0]["path"])).resolve().parent
    method_inventory: dict[str, list[dict[str, Any]]] = {}
    for receipt_path in sorted(method_receipt_dir.glob("*.json")):
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes)
        qualified_name = str(receipt.get("qualified_name") or "")
        if not qualified_name:
            continue
        method_inventory.setdefault(qualified_name, []).append({
            "method_id": receipt.get("method_id"),
            "qualified_name": qualified_name,
            "defined": bool(receipt.get("defined")),
            "code_offset": receipt.get("code_offset"),
            "status": receipt.get("status"),
            "path": str(receipt_path),
            "sha256": _sha_bytes(receipt_bytes),
        })
    primary_queue_sha = _sha_path(primary_path)

    latest: dict[str, tuple[int, int, dict[str, Any], dict[str, Any], Path]] = {}
    for ai_dir in (primary_ai, evidence_ai):
        checkpoint_dir = ai_dir / "checkpoints"
        if not checkpoint_dir.is_dir():
            continue
        for checkpoint_path in checkpoint_dir.glob("*.json"):
            try:
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError):
                continue
            unit = all_units.get(str(checkpoint.get("unit_id") or ""))
            if not unit or checkpoint.get("input_manifest_sha256") != unit.get("input_manifest_sha256"):
                continue
            method_id = str(unit["method_id"])
            depth = int(unit.get("evidence_depth") or 0)
            attempt = int(checkpoint.get("attempt") or 0)
            candidate = (depth, attempt, unit, checkpoint, checkpoint_path)
            if method_id not in latest or candidate[:2] > latest[method_id][:2]:
                latest[method_id] = candidate

    request_rows: list[dict[str, Any]] = []
    new_units: dict[str, dict[str, Any]] = {str(row["unit_id"]): row for row in prior_units}
    subject_rows: list[dict[str, Any]] = []
    for method_id, (depth, _attempt, subject, checkpoint, checkpoint_path) in sorted(latest.items()):
        if checkpoint.get("checkpoint_status") != "needs_evidence":
            continue
        requests = (checkpoint.get("result") or {}).get("evidence_requests") or []
        parent_evidence_keys = _resolved_evidence_keys(subject)
        newly_resolved_keys: list[str] = []
        resolved_inputs: list[dict[str, Any]] = []
        resolved_request_ids: list[str] = []
        subject_request_rows: list[dict[str, Any]] = []
        for request in requests:
            if not isinstance(request, dict):
                continue
            request_kind = str(request.get("kind") or "")
            target = str(request.get("target") or "")
            request_id = _sha_bytes(_canonical({
                "subject_unit_id": subject["unit_id"],
                "response_sha256": checkpoint.get("response_sha256"),
                "request": request,
            }))
            related: list[dict[str, Any]] = []
            matches: list[dict[str, Any]] = []
            direct_inputs: list[dict[str, Any]] = []
            inventory_matches: list[dict[str, Any]] = []
            if request_kind == "caller" and target:
                for candidate in primary_units:
                    lines = _reference_lines(bodies[str(candidate["unit_id"])], target)
                    if lines:
                        related.append(candidate)
                        matches.append({
                            "method_id": candidate["method_id"],
                            "qualified_name": candidate["qualified_name"],
                            "reference_lines": lines,
                        })
            elif request_kind == "callee" and target:
                related = list(by_name.get(target, []))
                matches = [{
                    "method_id": row["method_id"],
                    "qualified_name": row["qualified_name"],
                } for row in related]
                inventory_matches = list(method_inventory.get(target, []))
                if not related and any(row.get("code_offset") for row in inventory_matches):
                    raise ValueError(f"code-bearing callee missing from primary queue: {target}")
                for row in inventory_matches:
                    direct_inputs.append({
                        "kind": "resolved-callee-dex-method-receipt",
                        "path": row["path"],
                        "sha256": row["sha256"],
                        "request_id": request_id,
                        "related_method_id": row["method_id"],
                        "related_qualified_name": row["qualified_name"],
                    })
            elif request_kind == "type" and target:
                related = list(by_class.get(target, []))
                matches = [{
                    "method_id": row["method_id"],
                    "qualified_name": row["qualified_name"],
                } for row in related]

            status = "pending"
            if request_kind == "caller":
                status = "resolved-complete" if related else "resolved-no-callers"
            elif request_kind == "callee" and related:
                status = "resolved-body"
            elif request_kind == "callee" and inventory_matches:
                status = "resolved-no-code"
            elif request_kind == "callee":
                status = "resolved-not-in-dex"
            elif request_kind == "type" and related:
                status = "resolved-type"
            if request_kind == "runtime":
                status = "runtime-required"
            evidence_key = _evidence_key(request_kind, target)
            if status.startswith("resolved") and evidence_key in parent_evidence_keys:
                status = "stalled-already-resolved"
            row = {
                "schema": "angerona/dex-evidence-request/v1",
                "request_id": request_id,
                "subject_unit_id": subject["unit_id"],
                "subject_method_id": method_id,
                "evidence_depth": depth,
                "kind": request_kind,
                "target": target,
                "reason": str(request.get("reason") or ""),
                "status": status,
                "evidence_key": evidence_key,
                "matches": matches,
                "inventory_matches": inventory_matches,
                "search_scope": {
                    "primary_queue_sha256": primary_queue_sha,
                    "code_methods_scanned": len(primary_units),
                    "dex_methods_in_inventory": sum(len(rows) for rows in method_inventory.values()),
                    "complete": True,
                },
            }
            request_rows.append(row)
            subject_request_rows.append(row)
            if status.startswith("resolved"):
                resolved_request_ids.append(request_id)
                newly_resolved_keys.append(evidence_key)
                resolved_inputs.extend(_related_inputs(request_id, request_kind, related))
                resolved_inputs.extend(direct_inputs)

        resolution_receipt = {
            "schema": "angerona/dex-evidence-subject-resolution/v1",
            "subject_unit_id": subject["unit_id"],
            "subject_method_id": method_id,
            "parent_checkpoint": str(checkpoint_path),
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "search_scope": {
                "primary_queue_sha256": primary_queue_sha,
                "code_methods_scanned": len(primary_units),
                "dex_methods_in_inventory": sum(len(rows) for rows in method_inventory.values()),
                "complete": True,
            },
            "requests": subject_request_rows,
        }
        receipt_bytes = json.dumps(resolution_receipt, indent=2, sort_keys=True).encode() + b"\n"
        receipt_sha = _sha_bytes(receipt_bytes)
        receipt_path = output / "receipts" / f"{receipt_sha}.json"
        if not receipt_path.is_file():
            _atomic(receipt_path, receipt_bytes)

        combined: list[dict[str, Any]] = []
        seen_inputs: set[tuple[str, str]] = set()
        for item in [*(subject.get("inputs") or []), *resolved_inputs, {
            "kind": "dex-evidence-resolution-receipt",
            "path": str(receipt_path),
            "sha256": receipt_sha,
        }]:
            path, _ = _validated_input(item)
            key = (str(path), str(item["sha256"]))
            if key in seen_inputs:
                continue
            seen_inputs.add(key)
            combined.append(item)
        evidence_bytes = sum(Path(str(item["path"])).stat().st_size for item in combined)
        subject_state = {
            "method_id": method_id,
            "parent_unit_id": subject["unit_id"],
            "evidence_depth": depth,
            "resolved_requests": len(resolved_request_ids),
            "pending_requests": sum(not row["status"].startswith("resolved") for row in subject_request_rows),
            "evidence_bytes": evidence_bytes,
            "scheduled": False,
        }
        if not resolved_request_ids:
            subject_state["reason"] = "no-new-static-evidence"
            subject_rows.append(subject_state)
            continue
        if evidence_bytes > max_evidence_bytes:
            subject_state["reason"] = "evidence-budget-exceeded-partition-required"
            subject_rows.append(subject_state)
            continue

        manifest = {
            "schema": "angerona/dex-evidence-input-manifest/v1",
            "method_id": method_id,
            "parent_unit_id": subject["unit_id"],
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "evidence_depth": depth + 1,
            "resolved_request_ids": sorted(resolved_request_ids),
            "resolved_evidence_keys": sorted(parent_evidence_keys | set(newly_resolved_keys)),
            "inputs": combined,
        }
        manifest_sha = _sha_bytes(_canonical(manifest))
        unit_id = _sha_bytes(
            f"{method_id}\0{manifest_sha}\0dex-evidence-reanalysis-v1".encode()
        )
        new_unit = {
            "schema": primary_schema,
            "unit_id": unit_id,
            "unit_kind": "dex_method_evidence_reanalysis",
            "state": "pending",
            "method_id": method_id,
            "qualified_name": subject["qualified_name"],
            "class_descriptor": subject.get("class_descriptor"),
            "class_evidence_disposition": subject.get("class_evidence_disposition"),
            "inputs": combined,
            "input_manifest_sha256": manifest_sha,
            "evidence_depth": depth + 1,
            "parent_unit_id": subject["unit_id"],
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "resolved_request_ids": sorted(resolved_request_ids),
            "resolved_evidence_keys": sorted(parent_evidence_keys | set(newly_resolved_keys)),
            "evidence_requests": [row for row in subject_request_rows if not row["status"].startswith("resolved")],
            "unresolved_reasons": [row["reason"] for row in subject_request_rows if not row["status"].startswith("resolved")],
        }
        new_units[unit_id] = new_unit
        subject_state["scheduled"] = True
        subject_state["unit_id"] = unit_id
        subject_rows.append(subject_state)

    work_bytes = b"".join(_canonical(row) for row in sorted(new_units.values(), key=lambda row: row["unit_id"]))
    request_bytes = b"".join(_canonical(row) for row in sorted(request_rows, key=lambda row: row["request_id"]))
    manifest = {
        "schema": SCHEMA,
        "primary_queue": str(primary_path),
        "primary_queue_sha256": primary_queue_sha,
        "primary_units": len(primary_units),
        "latest_methods": len(latest),
        "requests": len(request_rows),
        "resolved_requests": sum(row["status"].startswith("resolved") for row in request_rows),
        "pending_requests": sum(not row["status"].startswith("resolved") for row in request_rows),
        "evidence_work_units": len(new_units),
        "new_or_updated_subjects": sum(row["scheduled"] for row in subject_rows),
        "subjects": subject_rows,
        "request_stream_sha256": _sha_bytes(request_bytes),
        "work_stream_sha256": _sha_bytes(work_bytes),
        "max_evidence_bytes": max_evidence_bytes,
    }
    manifest["manifest_sha256"] = _sha_bytes(_canonical(manifest))
    _atomic(output / "DEX_EVIDENCE_REQUESTS.jsonl", request_bytes)
    _atomic(work_path, work_bytes)
    _atomic(output / "DEX_EVIDENCE_RESOLUTION.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    return manifest
