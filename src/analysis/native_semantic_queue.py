"""Build exhaustive, content-addressed native semantic-analysis work units."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from .evidence_signing import sign_document, verify_document
from .native_ownership_manifest import (
    bind_native_output_directory,
    native_routing_context,
    native_routing_targets,
    publish_native_lane_receipt,
)
from .reconstruction_receipt import FUNCTION_EXPORT_SCHEMA, _canonical_bytes
from .native_range_authority import (
    sanitize_restricted_text,
    validate_launch_authority,
    validate_restricted_evidence,
)


SCHEMA = "angerona/native-semantic-input/v1"
FUNCTION_EVIDENCE_SCHEMA = "angerona/native-function-evidence/v1"
WORK_UNIT_SCHEMA = "angerona/native-semantic-work-unit/v1"


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


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


def _text_chunks(text: str, maximum: int) -> list[bytes]:
    chunks: list[bytes] = []
    current = bytearray()
    for character in text:
        encoded = character.encode("utf-8")
        if current and len(current) + len(encoded) > maximum:
            chunks.append(bytes(current))
            current.clear()
        current.extend(encoded)
    if current:
        chunks.append(bytes(current))
    return chunks


def _jsonl_chunks(items: Iterable[Any], maximum: int) -> list[bytes]:
    chunks: list[bytes] = []
    current = bytearray()
    for item in items:
        row = _canonical_bytes(item)
        if current and len(current) + len(row) > maximum:
            chunks.append(bytes(current))
            current.clear()
        current.extend(row)
    if current:
        chunks.append(bytes(current))
    return chunks


def _publish_stream(
    output: Path,
    kind: str,
    source: bytes,
    chunks: list[bytes],
    *,
    item_count: int | None,
) -> dict[str, Any]:
    rows = []
    offset = 0
    for index, chunk in enumerate(chunks):
        digest = _sha_bytes(chunk)
        suffix = "txt" if kind == "decompiled" else "jsonl"
        relative = Path("blobs") / kind / f"{digest}.{suffix}"
        destination = output / relative
        if not destination.is_file() or _sha_path(destination) != digest:
            _atomic(destination, chunk)
        rows.append({
            "index": index,
            "byte_start": offset,
            "byte_end": offset + len(chunk),
            "bytes": len(chunk),
            "sha256": digest,
            "path": relative.as_posix(),
        })
        offset += len(chunk)
    return {
        "kind": kind,
        "encoding": "utf-8" if kind == "decompiled" else "canonical-jsonl",
        "bytes": len(source),
        "sha256": _sha_bytes(source),
        "item_count": item_count,
        "chunks": rows,
        "byte_partition_complete": offset == len(source),
    }


def build_native_semantic_queue(
    production_root: str | Path,
    output_dir: str | Path,
    *,
    ownership_manifest: str | Path,
    native_universe: str | Path,
    lane_epoch_id: str,
    max_chunk_bytes: int = 32768,
) -> dict[str, Any]:
    """Seal every valid v3 Ghidra page into bounded, lossless AI work units."""
    if max_chunk_bytes < 4096:
        raise ValueError("max_chunk_bytes must be at least 4096")
    source_root = Path(production_root).resolve()
    routing, selected, policy_events, routing_binding = native_routing_context(
        ownership_manifest, native_universe,
    )
    app_targets, excluded_targets, hold_targets = native_routing_targets(selected, policy_events)
    selected_by_sha = {str(row["target_sha256"]): row for row in selected}
    output = bind_native_output_directory(
        output_dir, lane="native-semantic-input", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding,
    )
    checkpoints: list[Path] = []
    checkpoint_set_bindings: list[dict[str, Any]] = []
    for record in selected:
        target_sha = str(record["target_sha256"])
        reconstruction = source_root / "targets" / target_sha / "reconstruction"
        ledger_path = reconstruction / "RECONSTRUCTION_QUALITY_LEDGER.json"
        if ledger_path.is_symlink() or not ledger_path.is_file():
            raise ValueError(f"missing signed reconstruction ledger for app-owned target {target_sha}")
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        if (
            not verify_document(ledger, require_signature=True)
            or ledger.get("target_sha256") != target_sha
            or ledger.get("native_routing") != routing_binding
        ):
            raise ValueError(f"invalid reconstruction ledger for app-owned target {target_sha}")
        manifest_relative = str(ledger.get("checkpoint_manifest_path") or "")
        checkpoint_manifest_supplied = reconstruction / manifest_relative
        if checkpoint_manifest_supplied.is_symlink():
            raise ValueError("checkpoint ownership manifest cannot be a symlink")
        checkpoint_manifest_path = checkpoint_manifest_supplied.resolve()
        if reconstruction.resolve() not in checkpoint_manifest_path.parents:
            raise ValueError("checkpoint manifest escapes reconstruction root")
        if checkpoint_manifest_path.is_symlink() or not checkpoint_manifest_path.is_file():
            raise ValueError(f"missing checkpoint ownership manifest for {target_sha}")
        if _sha_path(checkpoint_manifest_path) != ledger.get("checkpoint_manifest_sha256"):
            raise ValueError(f"checkpoint ownership manifest hash mismatch for {target_sha}")
        checkpoint_manifest = json.loads(checkpoint_manifest_path.read_text(encoding="utf-8"))
        if (
            not verify_document(checkpoint_manifest, require_signature=True)
            or checkpoint_manifest.get("target_sha256") != target_sha
            or checkpoint_manifest.get("native_routing") != routing_binding
            or checkpoint_manifest.get("payload_sha256")
            != ledger.get("checkpoint_manifest_payload_sha256")
        ):
            raise ValueError(f"invalid checkpoint ownership manifest for {target_sha}")
        target_checkpoints = []
        for descriptor in checkpoint_manifest.get("rows") or []:
            relative = str(descriptor.get("path") or "") if isinstance(descriptor, dict) else ""
            candidate_supplied = reconstruction / relative
            if candidate_supplied.is_symlink():
                raise ValueError(f"owned checkpoint cannot be a symlink: {relative}")
            candidate = candidate_supplied.resolve()
            if (
                not relative.startswith("function_exports/")
                or reconstruction.resolve() not in candidate.parents
                or candidate.is_symlink()
                or not candidate.is_file()
                or _sha_path(candidate) != descriptor.get("sha256")
            ):
                raise ValueError(f"invalid owned checkpoint descriptor for {target_sha}: {relative}")
            target_checkpoints.append(candidate)
        checkpoints.extend(target_checkpoints)
        checkpoint_set_bindings.append({
            "target_sha256": target_sha,
            "quality_ledger_path": str(ledger_path.resolve()),
            "quality_ledger_sha256": _sha_path(ledger_path),
            "checkpoint_manifest_path": str(checkpoint_manifest_path),
            "checkpoint_manifest_sha256": _sha_path(checkpoint_manifest_path),
            "checkpoint_count": len(target_checkpoints),
            "analysis_scope": record.get("analysis_scope"),
            "range_authority_sha256": record.get("range_authority_sha256"),
            "partition_sha256": record.get("partition_sha256"),
            "native_launch_authority_token": record.get("native_launch_authority_token"),
        })
    functions: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []

    for checkpoint_path in checkpoints:
        try:
            checkpoint_bytes = checkpoint_path.read_bytes()
            checkpoint = json.loads(checkpoint_bytes)
            if checkpoint.get("schema") != FUNCTION_EXPORT_SCHEMA or checkpoint.get("status") != "ok":
                continue
            if checkpoint.get("native_routing") != routing_binding:
                raise ValueError("function checkpoint routing binding mismatch")
            target_sha = str(checkpoint.get("target_sha256") or "").lower()
            entry = str(checkpoint.get("entry") or "").lower()
            result = checkpoint.get("result")
            if len(target_sha) != 64 or not isinstance(result, dict):
                raise ValueError("invalid target identity or result")
            if target_sha not in app_targets:
                raise ValueError("checkpoint target is not in exact app-owned queue")
            route_row = selected_by_sha[target_sha]
            validate_launch_authority(route_row)
            analysis_scope = str(route_row.get("analysis_scope") or "")
            range_authority_sha256 = route_row.get("range_authority_sha256")
            checkpoint_toolchain = checkpoint.get("toolchain_identity") or {}
            address_bias = int(checkpoint_toolchain.get("native_address_bias") or 0)
            allowed = [
                (int(row["address"]) + address_bias,
                 int(row["address"]) + address_bias + int(row["size"]))
                for row in route_row.get("allowed_executable_ranges") or []
            ]
            if analysis_scope == "selective_ranges":
                entry_value = int(entry, 16)
                if not any(start <= entry_value < end for start, end in allowed):
                    raise ValueError("function checkpoint entry is outside signed allowed ranges")
                if checkpoint_toolchain.get("native_range_authority_sha256") != range_authority_sha256:
                    raise ValueError("function checkpoint range authority mismatch")
                if (
                    checkpoint_toolchain.get("native_launch_authority_token")
                    != route_row.get("native_launch_authority_token")
                    or checkpoint_toolchain.get("native_partition_sha256")
                    != route_row.get("partition_sha256")
                ):
                    raise ValueError("function checkpoint launch/partition authority mismatch")
                attempt = checkpoint.get("attempt_receipt") or {}
                if (
                    attempt.get("native_launch_authority_token")
                    != route_row.get("native_launch_authority_token")
                    or not attempt.get("project_receipt_sha256")
                    or not attempt.get("project_receipt_payload_sha256")
                ):
                    raise ValueError("function checkpoint lacks signed Ghidra project lineage")
            if str(result.get("entry") or "").lower() != entry:
                raise ValueError("checkpoint/result entry mismatch")
            if checkpoint.get("result_sha256") != _sha_bytes(_canonical_bytes(result)):
                raise ValueError("result hash mismatch")
            if not isinstance(result.get("decompilation_complete"), bool):
                raise ValueError("missing decompilation completeness state")
            disassembly = result.get("disassembly")
            pcode = result.get("pcode")
            if not isinstance(disassembly, list) or not disassembly:
                raise ValueError("missing disassembly evidence")
            if analysis_scope == "selective_ranges" and any(
                not any(
                    start <= int(str(item.get("address") or item.get("addr") or "0"), 16) < end
                    for start, end in allowed
                )
                for item in disassembly if isinstance(item, dict)
            ):
                raise ValueError("function evidence contains excluded-range instructions")
            if not isinstance(pcode, list):
                raise ValueError("missing P-code evidence")

            allowed_rows = route_row.get("allowed_executable_ranges") or []
            evidence_validation = validate_restricted_evidence(
                result, allowed_rows, bias=address_bias,
            ) if analysis_scope == "selective_ranges" else {
                "schema": "angerona/native-restricted-evidence-validation/v1",
                "valid": True, "violation_count": 0, "violations": [],
            }
            if not evidence_validation["valid"]:
                raise ValueError("function evidence contains an out-of-authority address stream")

            decompiled_text = result.get("decompiled") if isinstance(result.get("decompiled"), str) else ""
            text_receipt = None
            if analysis_scope == "selective_ranges":
                decompiled_text, text_receipt = sanitize_restricted_text(
                    decompiled_text, allowed_rows, bias=address_bias,
                )
            decompiled_bytes = decompiled_text.encode("utf-8")
            disassembly_bytes = b"".join(_canonical_bytes(item) for item in disassembly)
            pcode_bytes = b"".join(_canonical_bytes(item) for item in pcode)
            streams = [
                _publish_stream(
                    output, "decompiled", decompiled_bytes,
                    _text_chunks(decompiled_text, max_chunk_bytes), item_count=None,
                ),
                _publish_stream(
                    output, "disassembly", disassembly_bytes,
                    _jsonl_chunks(disassembly, max_chunk_bytes), item_count=len(disassembly),
                ),
                _publish_stream(
                    output, "pcode", pcode_bytes,
                    _jsonl_chunks(pcode, max_chunk_bytes), item_count=len(pcode),
                ),
            ]
            if not all(stream["byte_partition_complete"] for stream in streams):
                raise ValueError("evidence stream partition failed")

            function_id = f"elf:{target_sha}:0x{entry.lstrip('0') or '0'}"
            manifest = {
                "schema": FUNCTION_EVIDENCE_SCHEMA,
                "function_id": function_id,
                "target_sha256": target_sha,
                "entry": entry,
                "name": str(result.get("name") or ""),
                "signature": str(result.get("signature") or ""),
                "decompilation_complete": result["decompilation_complete"],
                "checkpoint_path": str(checkpoint_path),
                "checkpoint_sha256": _sha_bytes(checkpoint_bytes),
                "result_sha256": checkpoint["result_sha256"],
                "native_routing": routing_binding,
                "analysis_scope": analysis_scope,
                "range_authority_sha256": range_authority_sha256,
                "native_address_bias": address_bias,
                "partition_sha256": route_row.get("partition_sha256"),
                "native_launch_authority_token": route_row.get("native_launch_authority_token"),
                "restricted_evidence_validation": evidence_validation,
                "restricted_decompiled_receipt": text_receipt,
                "streams": streams,
            }
            manifest_bytes = _canonical_bytes(manifest)
            manifest_sha = _sha_bytes(manifest_bytes)
            manifest_relative = Path("functions") / target_sha / f"{entry}-{manifest_sha[:16]}.json"
            _atomic(output / manifest_relative, manifest_bytes)
            fragment_count = max((len(stream["chunks"]) for stream in streams), default=0)
            functions.append({
                "function_id": function_id,
                "manifest": manifest_relative.as_posix(),
                "manifest_sha256": manifest_sha,
                "fragment_count": fragment_count,
            })

            for fragment_index in range(fragment_count):
                selected = [
                    (stream, stream["chunks"][fragment_index])
                    for stream in streams if fragment_index < len(stream["chunks"])
                ]
                subject = {
                    "function_id": function_id,
                    "manifest_sha256": manifest_sha,
                    "fragment_kind": "evidence-window",
                    "fragment_index": fragment_index,
                    "fragment_sha256": {
                        stream["kind"]: chunk["sha256"] for stream, chunk in selected
                    },
                    "native_routing": routing_binding,
                    "analysis_scope": analysis_scope,
                    "range_authority_sha256": range_authority_sha256,
                    "native_address_bias": address_bias,
                    "partition_sha256": route_row.get("partition_sha256"),
                    "native_launch_authority_token": route_row.get("native_launch_authority_token"),
                }
                unit_id = _sha_bytes(_canonical_bytes(subject))
                inputs = [{
                    "kind": "native-function-manifest",
                    "path": str(output / manifest_relative),
                    "sha256": manifest_sha,
                }]
                inputs.extend({
                    "kind": f"native-{stream['kind']}-chunk",
                    "path": str(output / chunk["path"]),
                    "sha256": chunk["sha256"],
                } for stream, chunk in selected)
                units.append({
                    "schema": WORK_UNIT_SCHEMA,
                    "unit_id": unit_id,
                    "unit_kind": "native_function_fragment",
                    "function_id": function_id,
                    "target_sha256": target_sha,
                    "entry": entry,
                    "qualified_name": str(result.get("name") or entry),
                    "signature": str(result.get("signature") or ""),
                    "fragment_kind": "evidence-window",
                    "fragment_index": fragment_index,
                    "fragment_count": fragment_count,
                    "input_manifest_sha256": manifest_sha,
                    "native_routing": routing_binding,
                    "analysis_scope": analysis_scope,
                    "range_authority_sha256": range_authority_sha256,
                    "native_address_bias": address_bias,
                    "partition_sha256": route_row.get("partition_sha256"),
                    "native_launch_authority_token": route_row.get("native_launch_authority_token"),
                    "inputs": inputs,
                    "state": "pending",
                    "attempt": 0,
                })
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            rejected.append({"path": str(checkpoint_path), "reason": str(exc)})

    functions.sort(key=lambda row: row["function_id"])
    units.sort(key=lambda row: row["unit_id"])
    queue_payload = b"".join(_canonical_bytes(unit) for unit in units)
    _atomic(output / "NATIVE_SEMANTIC_WORK_UNITS.jsonl", queue_payload)
    manifest_body = {
        "schema": SCHEMA,
        "source_root": str(source_root),
        "lane_epoch_id": lane_epoch_id,
        "native_routing": routing_binding,
        "checkpoint_set_bindings": checkpoint_set_bindings,
        "expected_app_owned_targets": sorted(app_targets),
        "excluded_targets": sorted(excluded_targets),
        "hold_targets": sorted(hold_targets),
        "max_chunk_bytes": max_chunk_bytes,
        "checkpoint_files_seen": len(checkpoints),
        "functions_ready": len(functions),
        "work_units": len(units),
        "work_unit_queue_path": str((output / "NATIVE_SEMANTIC_WORK_UNITS.jsonl").resolve()),
        "work_unit_queue_sha256": _sha_bytes(queue_payload),
        "rejected": rejected,
        "functions": functions,
        "all_ready_functions_partitioned": not rejected and all(row["fragment_count"] > 0 for row in functions),
        "semantic_complete": bool(not app_targets and not rejected and not hold_targets),
    }
    manifest_body["manifest_sha256"] = _sha_bytes(_canonical_bytes(manifest_body))
    manifest = sign_document(manifest_body)
    if manifest.get("trust") != "operator_signed":
        raise ValueError("native semantic input manifest requires operator signing")
    _atomic(output / "NATIVE_SEMANTIC_INPUT.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    publish_native_lane_receipt(
        output / "NATIVE_SEMANTIC_QUEUE_COMPLETION_RECEIPT.json",
        lane="native-semantic-queue", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={row["target_sha256"] for row in checkpoint_set_bindings},
        excluded_targets=excluded_targets, hold_targets=hold_targets,
        semantic_complete=bool(not rejected),
        input_bindings=checkpoint_set_bindings + [
            {"path": str((output / "NATIVE_SEMANTIC_WORK_UNITS.jsonl").resolve()),
             "sha256": _sha_path(output / "NATIVE_SEMANTIC_WORK_UNITS.jsonl")},
            {"path": str((output / "NATIVE_SEMANTIC_INPUT.json").resolve()),
             "sha256": _sha_path(output / "NATIVE_SEMANTIC_INPUT.json")},
        ],
        counts={
            "checkpoint_files_seen": len(checkpoints),
            "functions_ready": len(functions), "work_units": len(units),
            "rejected": len(rejected),
        },
    )
    return manifest
