"""Resolve native semantic evidence requests against sealed Ghidra artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .evidence_signing import sign_document, verify_document
from .native_ownership_manifest import (
    bind_native_output_directory,
    native_routing_context,
    native_routing_targets,
    publish_native_lane_receipt,
)

SCHEMA = "angerona/native-evidence-resolution/v1"
RECEIPT_SCHEMA = "angerona/native-evidence-resolution-receipt/v1"
WORK_UNIT_SCHEMA = "angerona/native-consolidation-work-unit/v1"


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


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _entry(value: str) -> str | None:
    match = re.search(r"(?:0x)?([0-9a-fA-F]{6,16})", value)
    return match.group(1).lower().lstrip("0") if match else None


def _manifest_artifacts(
    manifest_path: Path,
    manifest: dict[str, Any],
    native_input: Path,
) -> list[dict[str, Any]]:
    rows = [{
        "kind": "resolved-native-function-manifest",
        "path": str(manifest_path),
        "sha256": _sha_path(manifest_path),
        "bytes": manifest_path.stat().st_size,
    }]
    for stream in manifest.get("streams") or []:
        for chunk in stream.get("chunks") or []:
            path = (native_input / chunk["path"]).resolve()
            if (
                native_input.resolve() not in path.parents
                or path.is_symlink()
                or not path.is_file()
                or _sha_path(path) != chunk["sha256"]
            ):
                raise ValueError(f"native evidence chunk mismatch: {path}")
            rows.append({
                "kind": f"resolved-native-{stream['kind']}",
                "path": str(path),
                "sha256": chunk["sha256"],
                "bytes": path.stat().st_size,
            })
    return rows


def resolve_native_evidence_requests(
    request_queue: str | Path,
    native_input_dir: str | Path,
    output_dir: str | Path,
    *,
    ownership_manifest: str | Path,
    native_universe: str | Path,
    lane_epoch_id: str,
    max_evidence_bytes: int = 262144,
) -> dict[str, Any]:
    requests_supplied = Path(request_queue).expanduser().absolute()
    if requests_supplied.is_symlink() or not requests_supplied.is_file():
        raise ValueError("native evidence request queue must be a non-symlink regular file")
    requests_path = requests_supplied.resolve(strict=True)
    native_input = Path(native_input_dir).resolve()
    _routing, selected, policy_events, routing_binding = native_routing_context(
        ownership_manifest, native_universe,
    )
    app_targets, excluded_targets, hold_targets = native_routing_targets(selected, policy_events)
    output = bind_native_output_directory(
        output_dir, lane="native-evidence-resolution", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding,
    )
    requests = _load_jsonl(requests_path)
    for row in requests:
        function_id = str(row.get("function_id") or "")
        parts = function_id.split(":")
        target_sha = parts[1] if len(parts) > 2 else ""
        if row.get("native_routing") != routing_binding or target_sha not in app_targets:
            raise ValueError("native evidence request is outside exact app-owned routing")
    manifests: dict[str, tuple[Path, dict[str, Any]]] = {}
    by_target_entry: dict[tuple[str, str], str] = {}
    by_target_name: dict[tuple[str, str], list[str]] = {}
    semantic_input_path = native_input / "NATIVE_SEMANTIC_INPUT.json"
    if semantic_input_path.is_symlink() or not semantic_input_path.is_file():
        raise ValueError("signed native semantic input manifest is required")
    semantic_input = json.loads(semantic_input_path.read_text(encoding="utf-8"))
    if (
        not verify_document(semantic_input, require_signature=True)
        or semantic_input.get("native_routing") != routing_binding
    ):
        raise ValueError("native semantic input signature/routing mismatch")
    manifest_descriptors = semantic_input.get("functions") or []
    for descriptor in manifest_descriptors:
        supplied_path = native_input / str(descriptor.get("manifest") or "")
        if supplied_path.is_symlink():
            raise ValueError("native function manifest cannot be a symlink")
        path = supplied_path.resolve()
        if (
            native_input.resolve() not in path.parents
            or path.is_symlink()
            or not path.is_file()
            or _sha_path(path) != descriptor.get("manifest_sha256")
        ):
            raise ValueError("native function manifest set is not conserved")
        payload = json.loads(path.read_bytes())
        function_id = str(payload.get("function_id") or "")
        target_sha = str(payload.get("target_sha256") or "")
        entry = str(payload.get("entry") or "").lower().lstrip("0")
        name = str(payload.get("name") or "")
        if function_id and target_sha and entry:
            manifests[function_id] = (path, payload)
            by_target_entry[(target_sha, entry)] = function_id
            by_target_name.setdefault((target_sha, name), []).append(function_id)

    receipts = []
    resolved_by_function: dict[str, list[dict[str, Any]]] = {}
    source_checkpoint_by_function: dict[str, dict[str, str]] = {}
    for row in requests:
        source_path = Path(row["source_checkpoint"]).resolve()
        source_bytes = source_path.read_bytes()
        if _sha_bytes(source_bytes) != row["source_checkpoint_sha256"]:
            raise ValueError(f"source checkpoint hash mismatch: {source_path}")
        source_checkpoint = json.loads(source_bytes)
        if (
            not verify_document(source_checkpoint, require_signature=True)
            or source_checkpoint.get("native_routing") != routing_binding
        ):
            raise ValueError(f"source AI checkpoint routing/signature mismatch: {source_path}")
        function_id = str(row["function_id"])
        target_sha = function_id.split(":")[1]
        source_manifest_row = manifests.get(function_id)
        if source_manifest_row is None:
            state, reason, evidence = "pending", "source-function-manifest-not-ready", []
        else:
            source_manifest_path, source_manifest = source_manifest_row
            ghidra_checkpoint_path = Path(source_manifest["checkpoint_path"]).resolve()
            ghidra_checkpoint = json.loads(ghidra_checkpoint_path.read_bytes())
            ghidra_result = ghidra_checkpoint.get("result") or {}
            request = row.get("request") or {}
            kind = str(request.get("kind") or "")
            target = str(request.get("target") or "")
            target_ids: list[str] = []
            if kind == "callee":
                parsed_entry = _entry(target)
                if parsed_entry:
                    matched = by_target_entry.get((target_sha, parsed_entry))
                    if matched:
                        target_ids.append(matched)
                else:
                    for name in ghidra_result.get("callees") or []:
                        target_ids.extend(by_target_name.get((target_sha, str(name)), []))
            elif kind == "caller":
                for name in ghidra_result.get("callers") or []:
                    target_ids.extend(by_target_name.get((target_sha, str(name)), []))
            elif kind in {"pcode", "disassembly"}:
                target_ids.append(function_id)

            evidence = []
            for target_id in sorted(set(target_ids)):
                manifest_path, manifest = manifests[target_id]
                evidence.extend(_manifest_artifacts(manifest_path, manifest, native_input))
            deduplicated = {item["sha256"]: item for item in evidence}
            evidence = [deduplicated[digest] for digest in sorted(deduplicated)]
            total_bytes = sum(int(item["bytes"]) for item in evidence)
            if evidence and total_bytes <= max_evidence_bytes:
                state, reason = "resolved", "sealed-static-evidence-attached"
            elif evidence:
                state, reason = "partial", "resolved-evidence-exceeds-bounded-input"
                evidence = []
            elif kind in {"type", "runtime"}:
                state, reason = "pending", f"{kind}-evidence-requires-independent-resolution"
            else:
                state, reason = "pending", "requested-function-evidence-not-ready"

            source_checkpoint_by_function[function_id] = {
                "path": str(source_path),
                "sha256": row["source_checkpoint_sha256"],
                "manifest_path": str(source_manifest_path),
                "manifest_sha256": _sha_path(source_manifest_path),
                "target_sha256": target_sha,
                "entry": source_manifest["entry"],
                "qualified_name": source_manifest["name"],
                "signature": source_manifest["signature"],
            }
        receipt_body = {
            "schema": RECEIPT_SCHEMA,
            "native_routing": routing_binding,
            "unit_id": row["unit_id"],
            "function_id": function_id,
            "request": row.get("request"),
            "source_checkpoint_sha256": row["source_checkpoint_sha256"],
            "state": state,
            "reason": reason,
            "evidence": evidence,
        }
        receipt_body["receipt_sha256"] = _sha_bytes(_canonical(receipt_body))
        receipt = sign_document(receipt_body)
        if receipt.get("trust") != "operator_signed":
            raise ValueError("native evidence receipt requires operator signing")
        published_receipt_path = output / "receipts" / f"{row['unit_id']}.json"
        _atomic(published_receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
        receipt["published_path"] = str(published_receipt_path.resolve())
        receipt["published_file_sha256"] = _sha_path(published_receipt_path)
        receipts.append(receipt)
        if state == "resolved":
            resolved_by_function.setdefault(function_id, []).extend(evidence)

    work_units = []
    for function_id, evidence in sorted(resolved_by_function.items()):
        source = source_checkpoint_by_function[function_id]
        unique = {item["sha256"]: item for item in evidence}
        inputs = [
            {"kind": "native-function-manifest", "path": source["manifest_path"], "sha256": source["manifest_sha256"]},
            {"kind": "native-ai-checkpoint", "path": source["path"], "sha256": source["sha256"]},
        ]
        inputs.extend({"kind": item["kind"], "path": item["path"], "sha256": item["sha256"]} for item in unique.values())
        subject = {
            "function_id": function_id,
            "inputs": [item["sha256"] for item in inputs],
            "native_routing": routing_binding,
        }
        unit_id = _sha_bytes(_canonical(subject))
        input_manifest_sha = _sha_bytes(_canonical({"unit_id": unit_id, "inputs": inputs}))
        work_units.append({
            "schema": WORK_UNIT_SCHEMA,
            "unit_id": unit_id,
            "unit_kind": "native_function_consolidation",
            "function_id": function_id,
            "target_sha256": source["target_sha256"],
            "entry": source["entry"],
            "qualified_name": source["qualified_name"],
            "signature": source["signature"],
            "consolidation_stage": 1000,
            "consolidation_partition": 0,
            "final_function_reconstruction": True,
            "input_manifest_sha256": input_manifest_sha,
            "native_routing": routing_binding,
            "inputs": inputs,
            "state": "pending",
            "attempt": 0,
        })
    work_units.sort(key=lambda row: row["unit_id"])
    work_unit_payload = b"".join(_canonical(row) for row in work_units)
    _atomic(output / "NATIVE_EVIDENCE_REANALYSIS_WORK_UNITS.jsonl", work_unit_payload)
    manifest_body = {
        "schema": SCHEMA,
        "lane_epoch_id": lane_epoch_id,
        "native_routing": routing_binding,
        "expected_app_owned_targets": sorted(app_targets),
        "excluded_targets": sorted(excluded_targets),
        "hold_targets": sorted(hold_targets),
        "requests": len(receipts),
        "state_counts": {
            state: sum(row["state"] == state for row in receipts)
            for state in ("resolved", "partial", "pending")
        },
        "reanalysis_work_units": len(work_units),
        "work_unit_queue_path": str((output / "NATIVE_EVIDENCE_REANALYSIS_WORK_UNITS.jsonl").resolve()),
        "work_unit_queue_sha256": _sha_bytes(work_unit_payload),
        "receipts": [{
            "unit_id": row["unit_id"], "state": row["state"],
            "receipt_payload_sha256": row.get("payload_sha256"),
            "receipt_file_sha256": row["published_file_sha256"],
            "receipt_path": row["published_path"],
        } for row in receipts],
        "complete": bool(receipts) and all(row["state"] == "resolved" for row in receipts),
    }
    manifest_body["manifest_sha256"] = _sha_bytes(_canonical(manifest_body))
    manifest = sign_document(manifest_body)
    if manifest.get("trust") != "operator_signed":
        raise ValueError("native evidence resolution manifest requires operator signing")
    _atomic(output / "NATIVE_EVIDENCE_RESOLUTION.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    processed_targets = {
        str(row.get("function_id") or "").split(":")[1]
        for row in requests if len(str(row.get("function_id") or "").split(":")) > 2
    }
    publish_native_lane_receipt(
        output / "NATIVE_EVIDENCE_LANE_COMPLETION_RECEIPT.json",
        lane="native-evidence-resolution", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets=processed_targets, excluded_targets=excluded_targets,
        hold_targets=hold_targets, semantic_complete=bool(manifest["complete"]),
        input_bindings=[
            {"path": str(requests_path), "sha256": _sha_path(requests_path)},
            {"path": str(semantic_input_path), "sha256": _sha_path(semantic_input_path)},
            {"path": str((output / "NATIVE_EVIDENCE_REANALYSIS_WORK_UNITS.jsonl").resolve()),
             "sha256": _sha_path(output / "NATIVE_EVIDENCE_REANALYSIS_WORK_UNITS.jsonl")},
            {"path": str((output / "NATIVE_EVIDENCE_RESOLUTION.json").resolve()),
             "sha256": _sha_path(output / "NATIVE_EVIDENCE_RESOLUTION.json")},
        ],
        counts={"requests": len(receipts), "state_counts": manifest["state_counts"]},
    )
    return manifest
