"""Build a bounded, resumable consolidation DAG for native function fragments."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .evidence_signing import sign_document, verify_document
from .native_ownership_manifest import (
    bind_native_output_directory,
    native_routing_context,
    native_routing_targets,
    publish_native_lane_receipt,
)

SCHEMA = "angerona/native-consolidation-input/v1"
WORK_UNIT_SCHEMA = "angerona/native-consolidation-work-unit/v1"
AI_CHECKPOINT_SCHEMA = "angerona/semantic-ai-checkpoint/v2"
TERMINAL_STATES = {"ok", "needs_evidence", "irrecoverable"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_units(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("schema") != "angerona/native-semantic-work-unit/v1":
                raise ValueError(f"unexpected native fragment schema at line {line_number}")
            rows.append(row)
    return rows


def _terminal_descriptor(
    checkpoint_path: Path,
    unit_id: str,
    function_id: str,
    input_manifest_sha256: str,
    routing_binding: dict[str, Any],
) -> dict[str, Any] | None:
    if not checkpoint_path.is_file():
        return None
    if checkpoint_path.is_symlink():
        return None
    try:
        payload = checkpoint_path.read_bytes()
        checkpoint = json.loads(payload)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if (
        checkpoint.get("schema") != AI_CHECKPOINT_SCHEMA
        or checkpoint.get("unit_id") != unit_id
        or checkpoint.get("function_id") != function_id
        or checkpoint.get("input_manifest_sha256") != input_manifest_sha256
        or checkpoint.get("checkpoint_status") not in TERMINAL_STATES
        or not isinstance(checkpoint.get("result"), dict)
        or checkpoint.get("native_routing") != routing_binding
        or not verify_document(checkpoint, require_signature=True)
    ):
        return None
    return {
        "path": str(checkpoint_path),
        "sha256": _sha_bytes(payload),
        "bytes": len(payload),
        "kind": "native-ai-checkpoint",
        "checkpoint_status": checkpoint["checkpoint_status"],
        "evidence_requests": list(checkpoint["result"].get("evidence_requests") or []),
    }


def _groups(rows: list[dict[str, Any]], maximum: int) -> list[list[dict[str, Any]]]:
    result: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_bytes = 0
    for row in rows:
        size = int(row["bytes"])
        if current and current_bytes + size > maximum:
            result.append(current)
            current = []
            current_bytes = 0
        current.append(row)
        current_bytes += size
    if current:
        result.append(current)
    return result


def _unit(
    function: dict[str, Any],
    function_manifest: dict[str, str],
    descriptors: list[dict[str, Any]],
    *,
    stage: int,
    partition: int,
    final: bool,
    routing_binding: dict[str, Any],
) -> dict[str, Any]:
    subject = {
        "function_id": function["function_id"],
        "stage": stage,
        "partition": partition,
        "final": final,
        "inputs": [row["sha256"] for row in descriptors],
        "native_routing": routing_binding,
    }
    unit_id = _sha_bytes(_canonical(subject))
    inputs = [{"kind": "native-function-manifest", **function_manifest}]
    inputs.extend({
        "kind": row["kind"], "path": row["path"], "sha256": row["sha256"]
    } for row in descriptors)
    input_manifest_sha = _sha_bytes(_canonical({
        "unit_id": unit_id,
        "inputs": [{"kind": row["kind"], "sha256": row["sha256"]} for row in inputs],
    }))
    return {
        "schema": WORK_UNIT_SCHEMA,
        "unit_id": unit_id,
        "unit_kind": "native_function_consolidation" if final else "native_function_consolidation_fragment",
        "function_id": function["function_id"],
        "target_sha256": function["target_sha256"],
        "entry": function["entry"],
        "qualified_name": function["qualified_name"],
        "signature": function["signature"],
        "consolidation_stage": stage,
        "consolidation_partition": partition,
        "final_function_reconstruction": final,
        "input_manifest_sha256": input_manifest_sha,
        "native_routing": routing_binding,
        "inputs": inputs,
        "state": "pending",
        "attempt": 0,
    }


def build_native_consolidation_queue(
    native_queue: str | Path,
    fragment_ai_output: str | Path,
    consolidation_ai_output: str | Path,
    output_dir: str | Path,
    *,
    ownership_manifest: str | Path,
    native_universe: str | Path,
    lane_epoch_id: str,
    max_input_bytes: int = 262144,
) -> dict[str, Any]:
    if max_input_bytes < 65536:
        raise ValueError("max_input_bytes must be at least 65536")
    queue_supplied = Path(native_queue).expanduser().absolute()
    if queue_supplied.is_symlink() or not queue_supplied.is_file():
        raise ValueError("native fragment queue must be a non-symlink regular file")
    queue_path = queue_supplied.resolve(strict=True)
    fragment_ai = Path(fragment_ai_output).resolve()
    consolidation_ai = Path(consolidation_ai_output).resolve()
    _routing, selected, policy_events, routing_binding = native_routing_context(
        ownership_manifest, native_universe,
    )
    app_targets, excluded_targets, hold_targets = native_routing_targets(selected, policy_events)
    output = bind_native_output_directory(
        output_dir, lane="native-consolidation-input", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding,
    )
    units = _load_units(queue_path)
    for row in units:
        if row.get("native_routing") != routing_binding:
            raise ValueError("native fragment routing binding mismatch")
        if str(row.get("target_sha256") or "") not in app_targets:
            raise ValueError("native fragment target is not in exact app-owned queue")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in units:
        grouped.setdefault(str(row["function_id"]), []).append(row)

    queue: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    for function_id, rows in sorted(grouped.items()):
        rows.sort(key=lambda row: (int(row["fragment_index"]), row["unit_id"]))
        first = rows[0]
        manifest_input = next(item for item in first["inputs"] if item["kind"] == "native-function-manifest")
        function_manifest = {"path": str(Path(manifest_input["path"]).resolve()), "sha256": manifest_input["sha256"]}
        function = {
            "function_id": function_id,
            "target_sha256": first["target_sha256"],
            "entry": first["entry"],
            "qualified_name": first["qualified_name"],
            "signature": first["signature"],
        }
        leaves = []
        for row in rows:
            descriptor = _terminal_descriptor(
                fragment_ai / "checkpoints" / f"{row['unit_id']}.json",
                row["unit_id"], function_id, row["input_manifest_sha256"],
                routing_binding,
            )
            if descriptor is not None:
                leaves.append(descriptor)
        if len(leaves) != len(rows):
            functions.append({**function, "state": "waiting-fragments", "ready": len(leaves), "expected": len(rows)})
            continue

        descriptors = leaves
        stage = 1
        final_checkpoint = None
        while True:
            partitions = _groups(descriptors, max_input_bytes)
            if len(partitions) == 1:
                final_unit = _unit(
                    function, function_manifest, partitions[0], stage=stage,
                    partition=0, final=True, routing_binding=routing_binding,
                )
                final_checkpoint = _terminal_descriptor(
                    consolidation_ai / "checkpoints" / f"{final_unit['unit_id']}.json",
                    final_unit["unit_id"], function_id, final_unit["input_manifest_sha256"],
                    routing_binding,
                )
                if final_checkpoint is None:
                    queue.append(final_unit)
                    functions.append({**function, "state": "final-pending", "stage": stage})
                else:
                    checkpoint_status = final_checkpoint["checkpoint_status"]
                    final_state = {
                        "ok": "consolidated",
                        "needs_evidence": "evidence-needed",
                        "irrecoverable": "irrecoverable",
                    }[checkpoint_status]
                    functions.append({
                        **function, "state": final_state, "stage": stage,
                        "checkpoint_status": checkpoint_status,
                        "final_checkpoint": final_checkpoint["path"],
                        "final_checkpoint_sha256": final_checkpoint["sha256"],
                        "evidence_requests": final_checkpoint["evidence_requests"],
                    })
                break

            next_descriptors = []
            missing = False
            for partition_index, partition in enumerate(partitions):
                intermediate = _unit(
                    function, function_manifest, partition,
                    stage=stage, partition=partition_index, final=False,
                    routing_binding=routing_binding,
                )
                descriptor = _terminal_descriptor(
                    consolidation_ai / "checkpoints" / f"{intermediate['unit_id']}.json",
                    intermediate["unit_id"], function_id, intermediate["input_manifest_sha256"],
                    routing_binding,
                )
                if descriptor is None:
                    queue.append(intermediate)
                    missing = True
                else:
                    next_descriptors.append(descriptor)
            if missing:
                functions.append({
                    **function, "state": "intermediate-pending", "stage": stage,
                    "partitions": len(partitions),
                })
                break
            descriptors = next_descriptors
            stage += 1

    queue.sort(key=lambda row: row["unit_id"])
    queue_payload = b"".join(_canonical(row) for row in queue)
    _atomic(output / "NATIVE_CONSOLIDATION_WORK_UNITS.jsonl", queue_payload)
    evidence_units = []
    for function in functions:
        if function["state"] != "evidence-needed":
            continue
        for index, request in enumerate(function.get("evidence_requests") or []):
            subject = {
                "function_id": function["function_id"],
                "checkpoint_sha256": function["final_checkpoint_sha256"],
                "index": index,
                "request": request,
                "native_routing": routing_binding,
            }
            evidence_units.append({
                "schema": "angerona/native-evidence-request/v1",
                "unit_id": _sha_bytes(_canonical(subject)),
                "function_id": function["function_id"],
                "source_checkpoint": function["final_checkpoint"],
                "source_checkpoint_sha256": function["final_checkpoint_sha256"],
                "request": request,
                "state": "pending",
                "attempt": 0,
            })
    evidence_units.sort(key=lambda row: row["unit_id"])
    _atomic(output / "NATIVE_EVIDENCE_REQUESTS.jsonl", b"".join(_canonical(row) for row in evidence_units))
    manifest_body = {
        "schema": SCHEMA,
        "lane_epoch_id": lane_epoch_id,
        "native_routing": routing_binding,
        "expected_app_owned_targets": sorted(app_targets),
        "excluded_targets": sorted(excluded_targets),
        "hold_targets": sorted(hold_targets),
        "native_queue": str(queue_path),
        "native_queue_sha256": _sha_path(queue_path),
        "max_input_bytes": max_input_bytes,
        "functions_seen": len(grouped),
        "functions_consolidated": sum(row["state"] == "consolidated" for row in functions),
        "functions_needing_evidence": sum(row["state"] == "evidence-needed" for row in functions),
        "work_units": len(queue),
        "work_unit_queue_path": str((output / "NATIVE_CONSOLIDATION_WORK_UNITS.jsonl").resolve()),
        "work_unit_queue_sha256": _sha_bytes(queue_payload),
        "evidence_request_units": len(evidence_units),
        "functions": functions,
        "semantic_complete": (
            bool(not app_targets and not hold_targets)
            or bool(functions) and all(row["state"] == "consolidated" for row in functions)
        ),
    }
    manifest_body["manifest_sha256"] = _sha_bytes(_canonical(manifest_body))
    manifest = sign_document(manifest_body)
    if manifest.get("trust") != "operator_signed":
        raise ValueError("native consolidation input requires operator signing")
    _atomic(output / "NATIVE_CONSOLIDATION_INPUT.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    publish_native_lane_receipt(
        output / "NATIVE_CONSOLIDATION_QUEUE_COMPLETION_RECEIPT.json",
        lane="native-consolidation-queue", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={str(row["target_sha256"]) for row in units},
        excluded_targets=excluded_targets, hold_targets=hold_targets,
        semantic_complete=bool(manifest["semantic_complete"]),
        input_bindings=[
            {"path": str(queue_path), "sha256": _sha_path(queue_path)},
            {"path": str((output / "NATIVE_CONSOLIDATION_WORK_UNITS.jsonl").resolve()),
             "sha256": _sha_path(output / "NATIVE_CONSOLIDATION_WORK_UNITS.jsonl")},
            {"path": str((output / "NATIVE_CONSOLIDATION_INPUT.json").resolve()),
             "sha256": _sha_path(output / "NATIVE_CONSOLIDATION_INPUT.json")},
        ],
        counts={
            "functions_seen": len(grouped), "work_units": len(queue),
            "evidence_request_units": len(evidence_units),
        },
    )
    return manifest
