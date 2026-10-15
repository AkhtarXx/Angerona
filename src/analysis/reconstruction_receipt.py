"""Fail-closed, engine-neutral reconstruction accounting.

Decompiler output is evidence, not recovered original source.  This module
binds that evidence to the input bytes, partitions executable ranges, records
one content-addressed receipt per discovered function, and emits durable work
units for every semantic gap.  A target is never complete merely because an
engine process returned zero.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Callable, Iterable

from .evidence_signing import sign_document, verify_document
from .native_range_authority import validate_restricted_evidence
from .native_elf import parse_elf
from .raw_function_evidence import (
    VALIDATION_POLICY_SCHEMA,
    load_raw_result,
    persist_raw_result,
    validate_attempt_evidence,
)
from .schema_validation import canonical_order_rows


SCHEMA = "angerona/executable-target/v3"
FUNCTION_SCHEMA = "angerona/function-receipt/v3"
WORK_UNIT_SCHEMA = "angerona/work-unit/v2"
FUNCTION_EXPORT_SCHEMA = "angerona/function-export-checkpoint/v3"
FUNCTION_CLASSIFICATION_SCHEMA = "angerona/function-classification/v1"
CHECKPOINT_OWNERSHIP_SCHEMA = "angerona/function-checkpoint-ownership/v1"
REPAIR_MANIFEST_SCHEMA = "angerona/function-repair-manifest/v1"
REPAIR_QUEUE_SCHEMA = "angerona/function-repair-unit/v1"
QUALITY_LEDGER_SCHEMA = "angerona/reconstruction-quality-ledger/v1"
TERMINAL_WORK_STATES = {"resolved", "partial", "irrecoverable"}

_INVALID_FUNCTION_POLICY = {
    "schema": FUNCTION_CLASSIFICATION_SCHEMA,
    "architecture": "AARCH64",
    "instruction_alignment": 4,
    "maximum_body_size": 3,
    "required_markers": ["Control flow encountered bad instruction data", "halt_baddata()"],
    "required_unwind_blocks": [".eh_frame", ".eh_frame_hdr"],
}

_FUNCTION_VALIDATION_POLICY = {
    "schema": VALIDATION_POLICY_SCHEMA,
    "required_schema": "angerona/1",
    "required_mode": "function",
    "required_fields": ["entry", "decompilation_complete", "disassembly", "pcode"],
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(path, json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def _address(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError("empty address")
    return int(text, 16)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _normalise_ranges(function: dict[str, Any]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for row in function.get("body_ranges") or []:
        if not isinstance(row, dict):
            continue
        try:
            start = _address(row.get("start"))
            end = _address(row.get("end"))
        except (TypeError, ValueError):
            continue
        if row.get("end_inclusive", False):
            end += 1
        elif end <= start and int(row.get("size") or 0) > 0:
            end = start + int(row["size"])
        if end > start:
            result.append((start, end))
    if result:
        return sorted(set(result))
    try:
        start = _address(function.get("entry"))
        size = int(function.get("size") or 0)
    except (TypeError, ValueError):
        return []
    return [(start, start + size)] if size > 0 else []


def invalid_function_classifier_identity() -> dict[str, Any]:
    policy_sha = _sha256_bytes(_canonical_bytes(_INVALID_FUNCTION_POLICY))
    return {"schema": FUNCTION_CLASSIFICATION_SCHEMA, "policy_sha256": policy_sha}


def _function_validation_facts(result: Any, expected_entry: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    facts: dict[str, Any] = {
        "schema": VALIDATION_POLICY_SCHEMA,
        "policy_sha256": _sha256_bytes(_canonical_bytes(_FUNCTION_VALIDATION_POLICY)),
        "expected_entry": expected_entry,
        "result_is_object": isinstance(result, dict),
    }
    if not isinstance(result, dict):
        errors.append("Ghidra returned a non-object function result")
        return facts, errors
    returned_entry = str(result.get("entry") or "").lower()
    disassembly = result.get("disassembly")
    pcode = result.get("pcode")
    decompiled = result.get("decompiled")
    facts.update({
        "result_schema": result.get("schema"),
        "result_mode": result.get("mode"),
        "returned_entry": returned_entry,
        "entry_matches": returned_entry == expected_entry,
        "decompilation_complete_is_boolean": isinstance(result.get("decompilation_complete"), bool),
        "decompilation_complete": result.get("decompilation_complete"),
        "disassembly_is_list": isinstance(disassembly, list),
        "disassembly_count": len(disassembly) if isinstance(disassembly, list) else None,
        "pcode_is_list": isinstance(pcode, list),
        "pcode_count": len(pcode) if isinstance(pcode, list) else None,
        "body_size": result.get("size"),
        "body_ranges": result.get("body_ranges") or [],
        "bad_instruction_marker": isinstance(decompiled, str) and "Control flow encountered bad instruction data" in decompiled,
        "halt_baddata_marker": isinstance(decompiled, str) and "halt_baddata()" in decompiled,
    })
    if result.get("schema") != "angerona/1":
        errors.append("Ghidra result schema mismatch")
    if result.get("mode") != "function":
        errors.append("Ghidra result mode mismatch")
    if returned_entry != expected_entry:
        errors.append(f"Ghidra function mismatch: requested {expected_entry}, got {returned_entry}")
    if not isinstance(result.get("decompilation_complete"), bool):
        errors.append("Ghidra result lacks a boolean decompilation_complete field")
    if not isinstance(disassembly, list):
        errors.append("Ghidra result lacks disassembly evidence")
    if not isinstance(pcode, list):
        errors.append("Ghidra result lacks P-code evidence")
    return facts, errors


def _exported_function(analysis: dict[str, Any], function: dict[str, Any]) -> bool:
    entry = str(function.get("entry") or "").lower().replace("0x", "")
    name = str(function.get("name") or "")
    for row in analysis.get("exports") or []:
        if not isinstance(row, dict):
            continue
        row_entry = str(row.get("entry") or row.get("address") or "").lower().replace("0x", "")
        if (entry and row_entry == entry) or (name and row.get("name") == name):
            return True
    return False


def _function_validation_decision(
    result: dict[str, Any],
    entry: str,
    analysis: dict[str, Any],
    exec_ranges: list[tuple[int, int]],
    classifier: dict[str, Any],
    function_index: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[str], dict[str, Any] | None]:
    """Validate an envelope, then accept only an exact strict invalid predicate."""
    facts, validation_errors = _function_validation_facts(result, entry)
    classification = None
    if not validation_errors:
        base = dict(function_index.get(entry) or {})
        base.update(result)
        classification = _invalid_function_classification(
            base, analysis, exec_ranges, classifier,
        )
    if classification is None and not str(result.get("disassembly") or "").strip():
        validation_errors.append(
            "Ghidra result lacks non-empty disassembly evidence"
        )
    return facts, validation_errors, classification


def _invalid_function_classification(
    function: dict[str, Any],
    analysis: dict[str, Any],
    exec_ranges: list[tuple[int, int]],
    classifier_identity: dict[str, Any],
) -> dict[str, Any] | None:
    processor = str((analysis.get("metadata") or {}).get("processor") or "").upper()
    if "AARCH64" not in processor:
        return None
    name = str(function.get("name") or "")
    ranges = _normalise_ranges(function)
    body_size = sum(end - start for start, end in ranges)
    disassembly = function.get("disassembly")
    pcode = function.get("pcode")
    decompiled = function.get("decompiled")
    xrefs = function.get("xrefs_to")
    if not (
        re.fullmatch(r"FUN_[0-9a-fA-F]+", name)
        and not function.get("is_external")
        and not function.get("is_thunk")
        and not _exported_function(analysis, function)
        and ranges
        and _inside_exec(ranges, exec_ranges)
        and 0 < body_size < 4
        and disassembly == []
        and pcode == []
        and function.get("decompilation_complete") is True
        and isinstance(decompiled, str)
        and "Control flow encountered bad instruction data" in decompiled
        and "halt_baddata()" in decompiled
        and function.get("callers") == []
        and function.get("callees") == []
        and isinstance(xrefs, list)
    ):
        return None
    unwind_xrefs = 0
    data_xrefs = 0
    for row in xrefs:
        if not isinstance(row, dict) or str(row.get("from_function") or ""):
            return None
        reference_type = f"{row.get('type') or ''} {row.get('engine_reference_type') or ''}".upper()
        if any(token in reference_type for token in ("CALL", "JUMP", "FLOW", "BRANCH")):
            return None
        block = str(row.get("from_memory_block") or "")
        if block == ".text" or bool(row.get("from_executable_block")):
            return None
        if block in {".eh_frame", ".eh_frame_hdr"}:
            unwind_xrefs += 1
        else:
            data_xrefs += 1
    if unwind_xrefs == 0:
        return None
    return {
        "schema": FUNCTION_CLASSIFICATION_SCHEMA,
        "classification": "invalid_function_entry",
        "reason": "aarch64-subinstruction-unwind-candidate",
        "architecture": "AARCH64",
        "instruction_alignment": 4,
        "body_size": body_size,
        "body_ranges": function.get("body_ranges") or [],
        "disassembly_count": 0,
        "pcode_count": 0,
        "decompilation_complete": True,
        "analyzer_generated_name": True,
        "bad_instruction_marker": True,
        "halt_baddata_marker": True,
        "unwind_xref_count": unwind_xrefs,
        "nonflow_data_xref_count": data_xrefs,
        "code_flow_xref_count": 0,
        "exported": False,
        "classifier_identity_sha256": _toolchain_sha(classifier_identity),
    }


def _inside_exec(ranges: Iterable[tuple[int, int]], exec_ranges: list[tuple[int, int]]) -> bool:
    return any(start < exec_end and end > exec_start
               for start, end in ranges for exec_start, exec_end in exec_ranges)


def _instruction_digest(elf: Any, data: bytes, ranges: list[tuple[int, int]]) -> str | None:
    digest = hashlib.sha256()
    seen = False
    for start, end in ranges:
        raw = elf.read_at(data, start, end - start)
        if raw is None or len(raw) != end - start:
            return None
        digest.update(f"{start:x}:{end - start}:".encode())
        digest.update(raw)
        seen = True
    return digest.hexdigest() if seen else None


def _work_id(target_id: str, kind: str, subject: str) -> str:
    return hashlib.sha256(f"{target_id}\0{kind}\0{subject}".encode()).hexdigest()


def _partition_exec_ranges(
    exec_ranges: list[tuple[int, int]],
    function_ranges: dict[str, list[tuple[int, int]]],
    thunk_ids: set[str],
    invalid_ids: set[str],
) -> list[dict[str, Any]]:
    partition: list[dict[str, Any]] = []
    for exec_start, exec_end in exec_ranges:
        changes: dict[int, dict[str, set[str]]] = {
            exec_start: {"add": set(), "remove": set()},
            exec_end: {"add": set(), "remove": set()},
        }
        for function_id, ranges in function_ranges.items():
            for start, end in ranges:
                left, right = max(start, exec_start), min(end, exec_end)
                if right <= left:
                    continue
                changes.setdefault(left, {"add": set(), "remove": set()})["add"].add(function_id)
                changes.setdefault(right, {"add": set(), "remove": set()})["remove"].add(function_id)
        active: set[str] = set()
        cursor = exec_start
        for point in sorted(changes):
            if point > cursor:
                if not active:
                    state = "unclassified_executable"
                elif len(active) > 1:
                    state = "overlapping_or_ambiguous"
                elif next(iter(active)) in thunk_ids:
                    state = "thunk_or_plt"
                elif next(iter(active)) in invalid_ids:
                    state = "analyzer_invalid_entry"
                else:
                    state = "function_body"
                owners = sorted(active)
                partition.append({
                    "start": _hex(cursor),
                    "end": _hex(point),
                    "size": point - cursor,
                    "state": state,
                    "owner_count": len(owners),
                    "function_ids": owners[:64],
                    "owners_truncated": len(owners) > 64,
                })
            active.difference_update(changes[point]["remove"])
            active.update(changes[point]["add"])
            cursor = point
    return partition


def _artifact_manifest(export_dir: Path) -> list[dict[str, Any]]:
    names = (
        "analysis.json", "functions.csv", "CALL_SUMMARY.json", "EVIDENCE_LEDGER.json",
        "EXPORT_MANIFEST.json", "all_decompiled.c", "anchor_instructions.json",
        "FUNCTION_REPAIR_MANIFEST.json", "FUNCTION_REPAIR_QUEUE.jsonl",
    )
    result = []
    for name in names:
        path = export_dir / name
        if path.is_file():
            result.append({
                "path": name,
                "bytes": path.stat().st_size,
                "sha256": _sha256_path(path),
            })
    return result


def _toolchain_sha(identity: dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_bytes(identity))


def _checkpoint_name(entry: str) -> str:
    return entry.lower().replace("0x", "").replace("/", "_") + ".json"


def _analysis_function_index(analysis_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("entry") or "").lower(): row
        for row in analysis_data.get("functions") or []
        if isinstance(row, dict) and str(row.get("entry") or "")
    }


def _checkpoint_result_valid(checkpoint: dict[str, Any]) -> bool:
    result = checkpoint.get("result")
    if not isinstance(result, dict):
        return False
    if checkpoint.get("result_sha256") != _sha256_bytes(_canonical_bytes(result)):
        return False
    return str(result.get("entry") or "").lower() == str(checkpoint.get("entry") or "").lower()


def _attempt_project_provenance_sha(attempt_receipt: Any) -> str | None:
    if not isinstance(attempt_receipt, dict):
        return None
    project = {
        "project_name": attempt_receipt.get("project_name"),
        "project_key": attempt_receipt.get("project_key"),
        "exporter_schema": attempt_receipt.get("exporter_schema"),
        "exporter_sha256": attempt_receipt.get("exporter_sha256"),
        "ghidra_identity": attempt_receipt.get("ghidra_identity"),
        "project_receipt_sha256": attempt_receipt.get("project_receipt_sha256"),
        "project_receipt_payload_sha256": attempt_receipt.get("project_receipt_payload_sha256"),
        "native_launch_authority_token": attempt_receipt.get("native_launch_authority_token"),
    }
    if not all(project.get(key) for key in ("project_name", "project_key", "exporter_schema", "exporter_sha256")):
        return None
    if not isinstance(project["ghidra_identity"], dict):
        return None
    return _sha256_bytes(_canonical_bytes(project))


def _load_signed_checkpoint_ownership(
    reconstruction_root: Path, target_sha: str, identity_sha: str,
) -> dict[str, str]:
    """Load checkpoint hashes owned by a prior signed ledger or migration."""
    owned: dict[str, str] = {}
    ledger_path = reconstruction_root / "RECONSTRUCTION_QUALITY_LEDGER.json"
    if ledger_path.is_file():
        try:
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            if not verify_document(ledger, require_signature=True):
                return {}
            if ledger.get("target_sha256") != target_sha:
                return {}
            relative = str(ledger.get("checkpoint_manifest_path") or "")
            manifest_path = (reconstruction_root / relative).resolve()
            if reconstruction_root.resolve() not in manifest_path.parents:
                return {}
            if _sha256_path(manifest_path) != ledger.get("checkpoint_manifest_sha256"):
                return {}
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not verify_document(manifest, require_signature=True):
                return {}
            if (
                manifest.get("schema") != CHECKPOINT_OWNERSHIP_SCHEMA
                or manifest.get("target_sha256") != target_sha
                or manifest.get("toolchain_identity_sha256") != identity_sha
                or manifest.get("payload_sha256") != ledger.get("checkpoint_manifest_payload_sha256")
            ):
                return {}
            for row in manifest.get("rows") or []:
                if isinstance(row, dict) and row.get("path") and row.get("sha256"):
                    owned[str(row["path"])] = str(row["sha256"])
        except (OSError, ValueError, TypeError):
            return {}
    migration_path = reconstruction_root.parent / "MIGRATION_OUTPUT_MANIFEST.json"
    if migration_path.is_file():
        try:
            migration = json.loads(migration_path.read_text(encoding="utf-8"))
            if (
                verify_document(migration, require_signature=True)
                and migration.get("target_sha256") == target_sha
            ):
                for row in migration.get("files") or []:
                    path = str(row.get("path") or "") if isinstance(row, dict) else ""
                    prefix = "reconstruction/"
                    if path.startswith(prefix + "function_exports/") and row.get("sha256"):
                        owned[path[len(prefix):]] = str(row["sha256"])
        except (OSError, ValueError, TypeError):
            return {}
    return owned


def _validated_ok_checkpoint(
    checkpoint: dict[str, Any],
    *, checkpoint_path: Path, reconstruction_root: Path, target_sha: str,
    toolchain_identity: dict[str, Any], analysis_data: dict[str, Any],
    function_index: dict[str, dict[str, Any]], exec_ranges: list[tuple[int, int]],
    classifier_identity: dict[str, Any], owned_checkpoint_hashes: dict[str, str],
) -> bool:
    """Admit OK only when the complete durable engine-evidence chain verifies."""
    if checkpoint.get("status") != "ok" or not _checkpoint_result_valid(checkpoint):
        return False
    if checkpoint.get("target_sha256") != target_sha:
        return False
    if checkpoint.get("toolchain_identity_sha256") != _toolchain_sha(toolchain_identity):
        return False
    if checkpoint.get("native_routing") != toolchain_identity.get("native_routing"):
        return False
    if checkpoint.get("schema") != toolchain_identity.get("checkpoint_schema"):
        return False
    try:
        relative_checkpoint = checkpoint_path.resolve().relative_to(
            reconstruction_root.resolve()
        ).as_posix()
    except ValueError:
        return False
    if owned_checkpoint_hashes.get(relative_checkpoint) != _sha256_path(checkpoint_path):
        return False
    if checkpoint.get("validation_policy") != _FUNCTION_VALIDATION_POLICY:
        return False
    attempt_receipt = checkpoint.get("attempt_receipt")
    project_sha = _attempt_project_provenance_sha(attempt_receipt)
    if project_sha is None or checkpoint.get("project_provenance_sha256") != project_sha:
        return False
    if attempt_receipt.get("exporter_schema") != toolchain_identity.get("exporter_schema"):
        return False
    if attempt_receipt.get("exporter_sha256") != toolchain_identity.get("exporter_sha256"):
        return False
    if (
        attempt_receipt.get("native_launch_authority_token")
        != toolchain_identity.get("native_launch_authority_token")
    ):
        return False
    if toolchain_identity.get("native_analysis_scope") == "selective_ranges":
        project_receipt_path = Path(str(attempt_receipt.get("project_receipt_path") or ""))
        try:
            if project_receipt_path.is_symlink() or not project_receipt_path.is_file():
                return False
            if _sha256_path(project_receipt_path) != attempt_receipt.get("project_receipt_sha256"):
                return False
            project_receipt = json.loads(project_receipt_path.read_text())
            if (
                not verify_document(project_receipt, require_signature=True)
                or project_receipt.get("payload_sha256")
                != attempt_receipt.get("project_receipt_payload_sha256")
                or project_receipt.get("target_sha256") != target_sha
                or project_receipt.get("range_authority_sha256")
                != toolchain_identity.get("native_range_authority_sha256")
                or project_receipt.get("native_launch_authority_token")
                != toolchain_identity.get("native_launch_authority_token")
                or project_receipt.get("partition_sha256")
                != toolchain_identity.get("native_partition_sha256")
            ):
                return False
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False
    ghidra_identity = attempt_receipt.get("ghidra_identity") or {}
    expected_status = toolchain_identity.get("status")
    if expected_status is not None and ghidra_identity.get("status") != expected_status:
        return False
    descriptor = checkpoint.get("raw_evidence")
    if not isinstance(descriptor, dict):
        return False
    try:
        raw_result = load_raw_result(reconstruction_root, descriptor)
        raw_bytes = _canonical_bytes(raw_result)
        evidence = SimpleNamespace(
            result=raw_result,
            raw_canonical_bytes=raw_bytes,
            raw_result_sha256=_sha256_bytes(raw_bytes),
            attempt_receipt=attempt_receipt,
        )
        validated = validate_attempt_evidence(
            evidence, target_sha256=target_sha,
            expected_entry=str(checkpoint.get("entry") or "").lower(),
        )
    except Exception:  # noqa: BLE001 - checkpoint admission is fail-closed
        return False
    if _canonical_bytes(validated) != _canonical_bytes(checkpoint.get("result")):
        return False
    facts, errors, classification = _function_validation_decision(
        validated, str(checkpoint.get("entry") or "").lower(), analysis_data,
        exec_ranges, classifier_identity, function_index,
    )
    return bool(
        not errors
        and classification is None
        and validated.get("decompilation_complete") is True
        and checkpoint.get("validation_facts") == facts
        and checkpoint.get("validation_errors") == []
    )


def _validated_invalid_checkpoint(
    checkpoint: dict[str, Any],
    *,
    analysis_data: dict[str, Any],
    function_index: dict[str, dict[str, Any]],
    exec_ranges: list[tuple[int, int]],
    classifier_identity: dict[str, Any],
) -> bool:
    if checkpoint.get("status") != "invalid_function_entry" or not _checkpoint_result_valid(checkpoint):
        return False
    result = checkpoint["result"]
    classification = checkpoint.get("classification")
    if not isinstance(classification, dict):
        return False
    if classification.get("schema") != FUNCTION_CLASSIFICATION_SCHEMA:
        return False
    if classification.get("classifier_identity_sha256") != _toolchain_sha(classifier_identity):
        return False
    base_row = function_index.get(str(result.get("entry") or checkpoint.get("entry") or "").lower())
    if base_row is None:
        return False
    merged = dict(base_row)
    merged.update(result)
    recomputed = _invalid_function_classification(
        merged, analysis_data, exec_ranges, classifier_identity,
    )
    return bool(
        recomputed is not None
        and _canonical_bytes(recomputed) == _canonical_bytes(classification)
    )


def _load_function_overrides(
    reconstruction_root: Path,
    target_sha: str,
    toolchain_identity: dict[str, Any],
    classifier_identity: dict[str, Any],
    analysis_data: dict[str, Any],
    exec_ranges: list[tuple[int, int]],
    checkpoint_ownership: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    root = reconstruction_root / "function_exports"
    if not root.is_dir():
        return result
    identity_sha = _toolchain_sha(toolchain_identity)
    owned = checkpoint_ownership
    if owned is None:
        owned = _load_signed_checkpoint_ownership(
            reconstruction_root, target_sha, identity_sha,
        )
    function_index = _analysis_function_index(analysis_data)
    for path in sorted(root.glob("*.json")):
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(checkpoint, dict) or checkpoint.get("schema") != FUNCTION_EXPORT_SCHEMA:
            continue
        if checkpoint.get("target_sha256") != target_sha:
            continue
        if checkpoint.get("toolchain_identity_sha256") != identity_sha:
            continue
        status = checkpoint.get("status")
        function = checkpoint.get("result")
        if status not in {"ok", "invalid_function_entry"} or not _checkpoint_result_valid(checkpoint):
            continue
        if status == "ok":
            if not _validated_ok_checkpoint(
                checkpoint, checkpoint_path=path,
                reconstruction_root=reconstruction_root,
                target_sha=target_sha, toolchain_identity=toolchain_identity,
                analysis_data=analysis_data, function_index=function_index,
                exec_ranges=exec_ranges, classifier_identity=classifier_identity,
                owned_checkpoint_hashes=owned,
            ):
                continue
        else:
            if not _validated_invalid_checkpoint(
                checkpoint,
                analysis_data=analysis_data,
                function_index=function_index,
                exec_ranges=exec_ranges,
                classifier_identity=classifier_identity,
            ):
                continue
        entry = str(function.get("entry") or checkpoint.get("entry") or "").lower()
        if entry:
            result[entry] = {
                "result": function,
                "checkpoint": checkpoint,
                "checkpoint_path": path.relative_to(reconstruction_root).as_posix(),
            }
    return result


def build_reconstruction_receipt(
    binary: str | Path,
    analysis: dict[str, Any] | str | Path,
    export_dir: str | Path,
    *,
    toolchain_identity: dict[str, Any] | None = None,
    classifier_identity: dict[str, Any] | None = None,
    checkpoint_ownership: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build and atomically publish exhaustive target/function accounting.

    Existing REDump documents do not prove that embedded decompilation text is
    untruncated.  Such functions are deliberately ``decompiled_partial`` until
    a paged exporter supplies ``decompilation_complete=true`` per function.
    """
    binary_path = Path(binary).resolve()
    export_root = Path(export_dir).resolve()
    if isinstance(analysis, (str, Path)):
        analysis_path = Path(analysis)
        analysis_input_path = str(analysis_path.resolve())
        analysis_input_sha = _sha256_path(analysis_path)
        analysis_data = json.loads(analysis_path.read_text(encoding="utf-8"))
    else:
        analysis_input_path = ""
        analysis_data = analysis
        analysis_input_sha = _sha256_bytes(_canonical_bytes(analysis_data))
    if not isinstance(analysis_data, dict):
        raise ValueError("analysis must be a JSON object")

    binary_data = binary_path.read_bytes()
    target_sha = _sha256_bytes(binary_data)
    metadata = analysis_data.get("metadata") or {}
    recorded_sha = str(metadata.get("sha256") or "").lower()
    if recorded_sha and recorded_sha != target_sha:
        raise ValueError(f"analysis target hash mismatch: {recorded_sha} != {target_sha}")
    elf = parse_elf(binary_data)
    if elf is None:
        raise ValueError(f"target is not a supported ELF: {binary_path}")

    raw_exec = [(int(start), int(start) + int(size)) for start, size in elf.exec_ranges() if size]
    exec_ranges = sorted(raw_exec)
    if not exec_ranges:
        raise ValueError("ELF has no file-backed executable ranges")
    target_id = f"elf:{target_sha}"
    reconstruction_root = export_root / "reconstruction"
    functions_root = reconstruction_root / "functions"
    blobs_root = reconstruction_root / "blobs" / "decompiled"

    identity = toolchain_identity or {}
    classifier = classifier_identity or invalid_function_classifier_identity()
    overrides = _load_function_overrides(
        reconstruction_root, target_sha, identity, classifier, analysis_data, exec_ranges,
        checkpoint_ownership,
    )
    summaries: list[dict[str, Any]] = []
    function_ranges: dict[str, list[tuple[int, int]]] = {}
    thunk_ids: set[str] = set()
    invalid_ids: set[str] = set()
    work_units: list[dict[str, Any]] = []
    discovered = analysis_data.get("functions") or []
    for index, original_function in enumerate(discovered):
        function = dict(original_function) if isinstance(original_function, dict) else original_function
        if not isinstance(function, dict):
            continue
        entry_text = str(function.get("entry") or f"unknown-{index}")
        try:
            entry = _address(function.get("entry"))
            entry_text = _hex(entry)
        except (TypeError, ValueError):
            entry = None
        override_row = overrides.get(str(function.get("entry") or "").lower())
        override_evidence = None
        override_checkpoint: dict[str, Any] = {}
        if override_row is not None:
            override = override_row["result"]
            override_evidence = override_row["checkpoint_path"]
            override_checkpoint = override_row["checkpoint"]
            function.update(override)
        function_id = f"{target_id}:{entry_text}"
        ranges = _normalise_ranges(function)
        executable = _inside_exec(ranges, exec_ranges)
        if executable:
            function_ranges[function_id] = ranges
        is_external = bool(function.get("is_external"))
        is_thunk = bool(function.get("is_thunk"))
        decompiled = function.get("decompiled")
        decompiled_text = decompiled if isinstance(decompiled, str) else ""
        decompiled_sha = _sha256_bytes(decompiled_text.encode()) if decompiled_text else None
        decompiled_blob = None
        if decompiled_text:
            decompiled_blob = f"blobs/decompiled/{decompiled_sha}.c"
            blob_path = reconstruction_root / decompiled_blob
            if not blob_path.is_file():
                _atomic_bytes(blob_path, decompiled_text.encode())

        disassembly = function.get("disassembly")
        disassembly_blob = None
        disassembly_sha = None
        if isinstance(disassembly, list) and disassembly:
            disassembly_bytes = _canonical_bytes(disassembly)
            disassembly_sha = _sha256_bytes(disassembly_bytes)
            disassembly_blob = f"blobs/disassembly/{disassembly_sha}.json"
            disassembly_path = reconstruction_root / disassembly_blob
            if not disassembly_path.is_file():
                _atomic_bytes(disassembly_path, disassembly_bytes)

        pcode = function.get("pcode")
        pcode_blob = None
        pcode_sha = None
        if isinstance(pcode, list) and pcode:
            pcode_bytes = _canonical_bytes(pcode)
            pcode_sha = _sha256_bytes(pcode_bytes)
            pcode_blob = f"blobs/pcode/{pcode_sha}.json"
            pcode_path = reconstruction_root / pcode_blob
            if not pcode_path.is_file():
                _atomic_bytes(pcode_path, pcode_bytes)

        losses: list[str] = []
        invalid_classification = override_checkpoint.get("classification")
        if override_checkpoint.get("status") == "invalid_function_entry" and isinstance(invalid_classification, dict):
            status, terminal = "analyzer_invalid_entry", True
            invalid_ids.add(function_id)
            losses.append("ghidra-analyzer-created-non-function-entry")
        elif is_external:
            status, terminal = "external_reference", True
        elif is_thunk and executable:
            status, terminal = "thunk_or_plt", True
            thunk_ids.add(function_id)
        elif decompiled_text and bool(function.get("decompilation_complete")):
            status, terminal = "semantic_reconstructed", True
        elif decompiled_text:
            status, terminal = "decompiled_partial", False
            losses.append("exporter-does-not-prove-full-decompilation-text")
        elif pcode_blob:
            status, terminal = "pcode_only", False
            losses.append("semantic-decompilation-unavailable")
        elif disassembly_blob:
            status, terminal = "disassembly_only", False
            losses.append("semantic-decompilation-unavailable")
        elif executable:
            status, terminal = "decompilation_missing", False
            losses.append("no-semantic-reconstruction")
        else:
            status, terminal = "boundary_ambiguous", False
            losses.append("function-has-no-file-backed-executable-range")

        instruction_sha = _instruction_digest(elf, binary_data, ranges) if ranges else None
        if executable and instruction_sha is None:
            terminal = False
            losses.append("instruction-bytes-not-file-backed")
        function_receipt = {
            "schema": FUNCTION_SCHEMA,
            "function_id": function_id,
            "target_id": target_id,
            "entry": entry_text,
            "name": str(function.get("name") or ""),
            "signature": str(function.get("signature") or ""),
            "body_ranges": [
                {"start": _hex(start), "end": _hex(end), "size": end - start}
                for start, end in ranges
            ],
            "instruction_bytes_sha256": instruction_sha,
            "status": status,
            "terminal": terminal,
            "decompilation_blob": decompiled_blob,
            "decompilation_sha256": decompiled_sha,
            "disassembly_blob": disassembly_blob,
            "disassembly_sha256": disassembly_sha,
            "pcode_blob": pcode_blob,
            "pcode_sha256": pcode_sha,
            "call_edges": {
                "callers": sorted(str(x) for x in function.get("callers") or []),
                "callees": sorted(str(x) for x in function.get("callees") or []),
            },
            "unresolved_indirect_calls": [],
            "losses": losses,
            "attempt_lineage": list(function.get("attempt_lineage") or []),
            "function_export_checkpoint": override_evidence,
            "function_export_checkpoint_sha256": (
                _sha256_bytes(_canonical_bytes(override_checkpoint)) if override_checkpoint else None
            ),
            "classification": invalid_classification if isinstance(invalid_classification, dict) else None,
        }
        receipt_name = f"{entry_text.replace('0x', '').replace('/', '_')}-{_sha256_bytes(function_id.encode())[:12]}.json"
        receipt_path = functions_root / receipt_name
        receipt_bytes = _canonical_bytes(function_receipt)
        _atomic_bytes(receipt_path, receipt_bytes)
        summaries.append({
            "function_id": function_id,
            "entry": entry_text,
            "name": function_receipt["name"],
            "status": status,
            "terminal": terminal,
            "receipt": f"functions/{receipt_name}",
            "receipt_sha256": _sha256_bytes(receipt_bytes),
        })
        if not terminal:
            subject = function_id
            work_units.append({
                "schema": WORK_UNIT_SCHEMA,
                "unit_id": _work_id(target_id, "function_reconstruction", subject),
                "unit_kind": "function_reconstruction",
                "target_id": target_id,
                "subject": subject,
                "input_manifest_sha256": "__BOUND_AFTER_RECEIPT__",
                "state": "pending",
                "attempt": 0,
                "required_evidence": [
                    item for item in (
                        f"functions/{receipt_name}", override_evidence,
                        decompiled_blob, disassembly_blob, pcode_blob,
                    ) if item
                ],
                "unresolved_reasons": losses,
            })

    partition = _partition_exec_ranges(exec_ranges, function_ranges, thunk_ids, invalid_ids)
    for row in partition:
        if row["state"] not in {"unclassified_executable", "overlapping_or_ambiguous"}:
            continue
        subject = f"{row['start']}:{row['end']}:{row['state']}"
        work_units.append({
            "schema": WORK_UNIT_SCHEMA,
            "unit_id": _work_id(target_id, "executable_range_classification", subject),
            "unit_kind": "executable_range_classification",
            "target_id": target_id,
            "subject": subject,
            "input_manifest_sha256": "__BOUND_AFTER_RECEIPT__",
            "state": "pending",
            "attempt": 0,
            "required_evidence": [],
            "unresolved_reasons": [row["state"]],
        })

    executable_bytes = sum(end - start for start, end in exec_ranges)
    partition_bytes = sum(int(row["size"]) for row in partition)
    state_counts: dict[str, int] = {}
    for summary in summaries:
        state_counts[summary["status"]] = state_counts.get(summary["status"], 0) + 1
    range_state_bytes: dict[str, int] = {}
    for row in partition:
        state = str(row["state"])
        range_state_bytes[state] = range_state_bytes.get(state, 0) + int(row["size"])

    receipt = {
        "schema": SCHEMA,
        "target_id": target_id,
        "content_sha256": target_sha,
        "content_bytes": len(binary_data),
        "source_path": str(binary_path),
        "format": "elf",
        "toolchain_identity": identity,
        "source_analysis": {
            "input_path": analysis_input_path,
            "input_sha256": analysis_input_sha,
            "schema": analysis_data.get("schema"),
            "mode": analysis_data.get("mode"),
            "metadata": metadata,
        },
        "executable_ranges": [
            {"start": _hex(start), "end": _hex(end), "size": end - start}
            for start, end in exec_ranges
        ],
        "byte_coverage": partition,
        "coverage_summary": {
            "executable_bytes": executable_bytes,
            "partition_bytes": partition_bytes,
            "byte_partition_complete": executable_bytes > 0 and partition_bytes == executable_bytes,
            "state_bytes": range_state_bytes,
        },
        "functions_discovered": len(summaries),
        "functions_terminal": sum(bool(row["terminal"]) for row in summaries),
        "functions_valid_candidates": sum(row["status"] != "analyzer_invalid_entry" for row in summaries),
        "functions_invalid_entries": sum(row["status"] == "analyzer_invalid_entry" for row in summaries),
        "functions_semantically_reconstructed": sum(row["status"] == "semantic_reconstructed" for row in summaries),
        "functions_repair_pending": sum(not bool(row["terminal"]) for row in summaries),
        "function_state_counts": state_counts,
        "functions": summaries,
        "artifacts": _artifact_manifest(export_root),
        "pending_work_units": len(work_units),
        "exhaustive_accounting": False,
        "semantic_complete": False,
        "semantic_complete_for_valid_candidates": False,
        "completion_reason": (
            "pending reconstruction/classification work"
            if work_units else "all executable bytes and functions terminal"
        ),
    }
    if not work_units and receipt["coverage_summary"]["byte_partition_complete"]:
        receipt["exhaustive_accounting"] = True
        receipt["semantic_complete_for_valid_candidates"] = all(
            row["status"] in {"semantic_reconstructed", "thunk_or_plt", "external_reference"}
            for row in summaries if row["status"] != "analyzer_invalid_entry"
        )
        receipt["semantic_complete"] = bool(
            receipt["semantic_complete_for_valid_candidates"]
            and receipt["functions_invalid_entries"] == 0
        )
        receipt["completion_reason"] = (
            "semantic reconstruction complete"
            if receipt["semantic_complete"] else "terminal accounting contains semantic limitations"
        )

    receipt_bytes = _canonical_bytes(receipt)
    receipt_sha = _sha256_bytes(receipt_bytes)
    receipt["receipt_sha256"] = receipt_sha
    for unit in work_units:
        unit["input_manifest_sha256"] = receipt_sha
    queue_payload = b"".join(_canonical_bytes(unit) for unit in sorted(work_units, key=lambda x: x["unit_id"]))
    _atomic_bytes(reconstruction_root / "WORK_UNITS.jsonl", queue_payload)
    _atomic_json(reconstruction_root / "RECONSTRUCTION_RECEIPT.json", receipt)
    return receipt


def materialize_ghidra_functions(
    engine: Any,
    binary: str | Path,
    analysis: dict[str, Any] | str | Path,
    export_dir: str | Path,
    *,
    toolchain_identity: dict[str, Any],
    classifier_identity: dict[str, Any] | None = None,
    timeout: int = 300,
    max_attempts: int = 3,
    entries: set[str] | None = None,
    analysis_scope: str = "whole_target",
    allowed_exec_ranges: list[dict[str, Any]] | None = None,
    native_launch_authority_token: str | None = None,
    allow_error_retry: bool = False,
    repair_epoch_id: str = "",
    audit_epoch_id: str = "",
    audit_timestamp_utc: str = "",
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Materialize every Ghidra function as an atomic resumable checkpoint."""
    binary_path = Path(binary).resolve()
    export_root = Path(export_dir).resolve()
    if isinstance(analysis, (str, Path)):
        analysis_data = json.loads(Path(analysis).read_text(encoding="utf-8"))
    else:
        analysis_data = analysis
    if not isinstance(analysis_data, dict):
        raise ValueError("analysis must be a JSON object")
    binary_sha = _sha256_path(binary_path)
    binary_data = binary_path.read_bytes()
    elf = parse_elf(binary_data)
    if elf is None:
        raise ValueError(f"target is not a supported ELF: {binary_path}")
    exec_ranges = [
        (int(start), int(start) + int(size)) for start, size in elf.exec_ranges() if size
    ]
    if analysis_scope == "selective_ranges":
        if not entries or not allowed_exec_ranges:
            raise ValueError("selective reconstruction requires entries and allowed executable ranges")
        exec_ranges = sorted(
            (int(row["address"]), int(row["address"]) + int(row["size"]))
            for row in allowed_exec_ranges
        )
    elif analysis_scope != "whole_target":
        raise ValueError("unsupported native analysis scope")
    recorded_sha = str((analysis_data.get("metadata") or {}).get("sha256") or "").lower()
    if recorded_sha and recorded_sha != binary_sha:
        raise ValueError("analysis target hash does not match binary")
    address_bias = int(
        str((analysis_data.get("metadata") or {}).get("image_base") or "0"), 16,
    ) if analysis_scope == "selective_ranges" else 0
    if analysis_scope == "selective_ranges":
        exec_ranges = [(start + address_bias, end + address_bias) for start, end in exec_ranges]
    toolchain_identity = {
        **toolchain_identity,
        "native_address_domain": "ELF_VIRTUAL_ADDRESS",
        "native_address_bias": address_bias,
    }
    identity_sha = _toolchain_sha(toolchain_identity)
    classifier = classifier_identity or invalid_function_classifier_identity()
    classifier_sha = _toolchain_sha(classifier)
    checkpoint_root = export_root / "reconstruction" / "function_exports"
    checkpoint_root.mkdir(parents=True, exist_ok=True)
    requested_entries = {item.lower() for item in entries} if entries is not None else None
    requested_entry_values = {
        int(item, 16) for item in requested_entries or set()
    }

    candidates = []
    candidate_universe: list[str] = []
    for function in analysis_data.get("functions") or []:
        if not isinstance(function, dict) or function.get("is_external") or function.get("is_thunk"):
            continue
        entry = str(function.get("entry") or "").lower()
        if not entry:
            continue
        try:
            entry_value = int(entry, 16)
        except ValueError:
            continue
        selected_entry = requested_entries is None or (
            entry_value in requested_entry_values
            or entry_value - address_bias in requested_entry_values
        )
        if analysis_scope == "whole_target" or selected_entry:
            candidate_universe.append(entry)
        if not selected_entry:
            continue
        candidates.append((entry, function))
    candidate_universe = sorted(set(candidate_universe))
    candidate_universe_sha = _sha256_bytes(_canonical_bytes({
        "target_sha256": binary_sha,
        "entries": candidate_universe,
    }))
    function_index = _analysis_function_index(analysis_data)
    signed_checkpoint_ownership = _load_signed_checkpoint_ownership(
        export_root / "reconstruction", binary_sha, identity_sha,
    )
    fresh_checkpoint_ownership: dict[str, str] = {}

    completed = 0
    classified_invalid = 0
    failed = 0
    cache_hits = 0
    for index, (entry, _function) in enumerate(candidates, 1):
        checkpoint_path = checkpoint_root / _checkpoint_name(entry)
        previous: dict[str, Any] = {}
        if checkpoint_path.is_file():
            try:
                previous = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                previous = {}
        previous_attempts = int(previous.get("attempt") or 0)
        previous_sha = _sha256_bytes(_canonical_bytes(previous)) if previous else None
        valid = bool(
            previous.get("schema") == FUNCTION_EXPORT_SCHEMA
            and previous.get("target_sha256") == binary_sha
            and previous.get("toolchain_identity_sha256") == identity_sha
            and previous.get("entry") == entry
        )
        previous_ok_admissible = bool(
            valid and previous.get("status") == "ok"
            and _validated_ok_checkpoint(
                previous, checkpoint_path=checkpoint_path,
                reconstruction_root=export_root / "reconstruction",
                target_sha=binary_sha, toolchain_identity=toolchain_identity,
                analysis_data=analysis_data, function_index=function_index,
                exec_ranges=exec_ranges, classifier_identity=classifier,
                owned_checkpoint_hashes=signed_checkpoint_ownership,
            )
        )
        previous_invalid_admissible = bool(
            valid
            and previous.get("status") == "invalid_function_entry"
            and _validated_invalid_checkpoint(
                previous,
                analysis_data=analysis_data,
                function_index=function_index,
                exec_ranges=exec_ranges,
                classifier_identity=classifier,
            )
        )
        previous_admissible = previous_ok_admissible or previous_invalid_admissible
        if previous_admissible:
            result = previous.get("result")
            if isinstance(result, dict):
                if previous.get("status") == "ok":
                    completed += 1
                else:
                    classified_invalid += 1
                cache_hits += 1
                if progress_callback:
                    progress_callback({
                        "completed": index, "expected": len(candidates),
                        "entry": entry, "cache_hit": True, "failed": False,
                        "classification": (
                            "invalid_function_entry"
                            if previous.get("status") == "invalid_function_entry" else None
                        ),
                    })
                continue
        repair_epochs = {
            str(row.get("repair_epoch_id") or "")
            for row in previous.get("attempt_lineage") or [] if isinstance(row, dict)
        }
        repair_epochs.add(str(previous.get("repair_epoch_id") or ""))
        queued_non_admissible = bool(
            valid
            and not previous_admissible
            and previous.get("status") in {"error", "ok", "invalid_function_entry"}
        )
        repair_override = bool(
            queued_non_admissible and allow_error_retry
            and requested_entries is not None and repair_epoch_id and repair_epoch_id not in repair_epochs
        )
        if (
            valid and previous.get("status") in {"ok", "invalid_function_entry"}
            and not previous_admissible and not repair_override
        ):
            failed += 1
            continue
        if valid and previous_attempts >= max_attempts and not repair_override:
            failed += 1
            continue

        attempt = previous_attempts + 1 if valid else 1
        raw_evidence = None
        attempt_receipt = None
        validation_facts: dict[str, Any] = {}
        validation_errors: list[str] = []
        post_return = False
        try:
            if hasattr(engine, "decompile_function_evidence"):
                evidence = engine.decompile_function_evidence(
                    binary_path, entry, timeout=timeout,
                    native_authority_token=native_launch_authority_token,
                )
                result = evidence.result
                attempt_receipt = evidence.attempt_receipt
                post_return = True
                result = validate_attempt_evidence(
                    evidence, target_sha256=binary_sha, expected_entry=entry,
                )
                expected_range_authority = (
                    toolchain_identity.get("native_range_authority_sha256")
                    if analysis_scope == "selective_ranges" else None
                )
                if (
                    (attempt_receipt or {}).get("range_authority_sha256")
                    != expected_range_authority
                    or result.get("range_authority_sha256") != expected_range_authority
                ):
                    raise RuntimeError("Ghidra result range authority mismatch")
                if analysis_scope == "selective_ranges" and (
                    (attempt_receipt or {}).get("native_launch_authority_token")
                    != native_launch_authority_token
                    or not (attempt_receipt or {}).get("project_receipt_sha256")
                    or not (attempt_receipt or {}).get("project_receipt_payload_sha256")
                ):
                    raise RuntimeError("Ghidra result lacks project/launch authority")
                if analysis_scope == "selective_ranges":
                    validation = validate_restricted_evidence(
                        result, allowed_exec_ranges or [],
                        bias=int(toolchain_identity.get("native_address_bias") or 0),
                    )
                    if not validation["valid"]:
                        raise RuntimeError("Ghidra result contains out-of-authority address evidence")
            else:
                raise RuntimeError("engine lacks durable function evidence API")
            if isinstance(result, dict):
                raw_evidence = persist_raw_result(
                    export_root / "reconstruction",
                    target_sha256=binary_sha,
                    entry=entry,
                    result=result,
                )
            validation_facts, validation_errors, classification = _function_validation_decision(
                result, entry, analysis_data, exec_ranges, classifier, function_index,
            )
            if validation_errors:
                raise RuntimeError("; ".join(validation_errors))
            if classification is None and result.get("decompilation_complete") is not True:
                validation_errors.append("Ghidra decompilation is not semantically complete")
                raise RuntimeError(validation_errors[-1])
            project_provenance_sha = _attempt_project_provenance_sha(attempt_receipt)
            if project_provenance_sha is None:
                validation_errors.append("Ghidra attempt lacks project/tool provenance")
                raise RuntimeError(validation_errors[-1])
            result_bytes = _canonical_bytes(result)
            lineage = list(previous.get("attempt_lineage") or [])
            if previous:
                lineage.append({
                    "checkpoint_sha256": previous_sha,
                    "attempt": previous_attempts,
                    "status": previous.get("status"),
                    "repair_epoch_id": repair_epoch_id,
                })
            checkpoint = {
                "schema": FUNCTION_EXPORT_SCHEMA,
                "target_sha256": binary_sha,
                "entry": entry,
                "toolchain_identity": toolchain_identity,
                "toolchain_identity_sha256": identity_sha,
                "native_routing": toolchain_identity.get("native_routing"),
                "attempt": attempt,
                "status": "invalid_function_entry" if classification else "ok",
                "result_sha256": _sha256_bytes(result_bytes),
                "result": result,
                "classification": classification,
                "classifier_identity": classifier if classification else None,
                "supersedes_checkpoint_sha256": previous_sha,
                "attempt_lineage": lineage,
                "repair_epoch_id": repair_epoch_id or None,
                "raw_evidence": raw_evidence,
                "attempt_receipt": attempt_receipt,
                "project_provenance_sha256": project_provenance_sha,
                "validation_policy": _FUNCTION_VALIDATION_POLICY,
                "validation_facts": validation_facts,
                "validation_errors": validation_errors,
            }
            _atomic_json(checkpoint_path, checkpoint)
            fresh_checkpoint_ownership[
                checkpoint_path.relative_to(export_root / "reconstruction").as_posix()
            ] = _sha256_path(checkpoint_path)
            if classification:
                classified_invalid += 1
            else:
                completed += 1
        except Exception as exc:
            checkpoint = {
                "schema": FUNCTION_EXPORT_SCHEMA,
                "target_sha256": binary_sha,
                "entry": entry,
                "toolchain_identity": toolchain_identity,
                "toolchain_identity_sha256": identity_sha,
                "native_routing": toolchain_identity.get("native_routing"),
                "attempt": attempt,
                "status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc)[-4000:],
                "supersedes_checkpoint_sha256": previous_sha,
                "attempt_lineage": [
                    *list(previous.get("attempt_lineage") or []),
                    *([{
                        "checkpoint_sha256": previous_sha,
                        "attempt": previous_attempts,
                        "status": previous.get("status"),
                        "repair_epoch_id": repair_epoch_id,
                    }] if previous else []),
                ],
                "repair_epoch_id": repair_epoch_id or None,
                "post_return_error": post_return,
                "raw_evidence": raw_evidence,
                "attempt_receipt": attempt_receipt,
                "validation_policy": _FUNCTION_VALIDATION_POLICY,
                "validation_facts": validation_facts,
                "validation_errors": validation_errors or [str(exc)[-4000:]],
            }
            _atomic_json(checkpoint_path, checkpoint)
            failed += 1
        if progress_callback:
            progress_callback({
                "completed": index,
                "expected": len(candidates),
                "entry": entry,
                "cache_hit": False,
                "failed": checkpoint.get("status") == "error",
                "classification": (
                    "invalid_function_entry"
                    if checkpoint.get("status") == "invalid_function_entry" else None
                ),
            })

    manifest_rows: list[dict[str, Any]] = []
    repair_rows: list[dict[str, Any]] = []
    checkpoint_ownership_rows: list[dict[str, Any]] = []
    checkpoint_entries: set[str] = set()
    checkpoint_status_counts = {"ok": 0, "invalid_function_entry": 0, "error": 0, "unknown": 0}
    function_index = _analysis_function_index(analysis_data)
    reconstruction_root = export_root / "reconstruction"
    for path in sorted(checkpoint_root.glob("*.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(row, dict) or row.get("schema") != FUNCTION_EXPORT_SCHEMA:
            continue
        if row.get("target_sha256") != binary_sha or row.get("toolchain_identity_sha256") != identity_sha:
            continue
        entry_value = str(row.get("entry") or "").lower()
        if entry_value:
            checkpoint_entries.add(entry_value)
        original_status = str(row.get("status") or "unknown")
        invalid_checkpoint_valid = bool(
            original_status != "invalid_function_entry"
            or _validated_invalid_checkpoint(
                row,
                analysis_data=analysis_data,
                function_index=function_index,
                exec_ranges=exec_ranges,
                classifier_identity=classifier,
            )
        )
        ok_checkpoint_valid = bool(
            original_status != "ok" or _validated_ok_checkpoint(
                row, checkpoint_path=path, reconstruction_root=reconstruction_root,
                target_sha=binary_sha, toolchain_identity=toolchain_identity,
                analysis_data=analysis_data, function_index=function_index,
                exec_ranges=exec_ranges, classifier_identity=classifier,
                owned_checkpoint_hashes={
                    **signed_checkpoint_ownership, **fresh_checkpoint_ownership,
                },
            )
        )
        status_value = original_status if invalid_checkpoint_valid and ok_checkpoint_valid else "unknown"
        if status_value not in checkpoint_status_counts:
            status_value = "unknown"
        checkpoint_status_counts[status_value] += 1
        checkpoint_ownership_rows.append({
            "path": path.relative_to(reconstruction_root).as_posix(),
            "sha256": _sha256_path(path),
            "entry": entry_value,
            "status": status_value,
        })
        corrupted_ok = original_status == "ok" and not ok_checkpoint_valid
        invalid_classification_mismatch = (
            original_status == "invalid_function_entry" and not invalid_checkpoint_valid
        )
        if original_status not in {"error", "invalid_function_entry"} and not corrupted_ok:
            continue
        repair_reason = row.get("error")
        if corrupted_ok:
            repair_reason = "ok checkpoint result integrity validation failed"
        elif invalid_classification_mismatch:
            repair_reason = "invalid checkpoint predicate mismatch"
        descriptor = {
            "entry": row.get("entry"),
            "checkpoint_path": path.relative_to(reconstruction_root).as_posix(),
            "checkpoint_sha256": _sha256_path(path),
            "attempt": row.get("attempt"),
            "error_type": row.get("error_type"),
            "error": repair_reason,
            "disposition": (
                "classified_invalid"
                if original_status == "invalid_function_entry" and invalid_checkpoint_valid
                else "repair_pending"
            ),
            "predicate_facts": row.get("classification"),
            "raw_result_sha256": row.get("result_sha256"),
        }
        manifest_rows.append(descriptor)
        if descriptor["disposition"] == "repair_pending":
            repair_rows.append({
                "schema": REPAIR_QUEUE_SCHEMA,
                "unit_id": _work_id(f"elf:{binary_sha}", "function_repair", str(row.get("entry") or "")),
                "target_sha256": binary_sha,
                "entry": row.get("entry"),
                "source_checkpoint_sha256": descriptor["checkpoint_sha256"],
                "repair_epoch_id": repair_epoch_id,
                "state": "pending",
                "reason": descriptor["error"],
                "required_evidence": [descriptor["checkpoint_path"]],
            })
    repair_rows = canonical_order_rows(
        "angerona/canonical-unit-jsonl/v1", "$rows", repair_rows,
        context="native function repair queue",
    )
    queue_payload = b"".join(_canonical_bytes(row) for row in repair_rows)
    queue_path = reconstruction_root / "FUNCTION_REPAIR_QUEUE.jsonl"
    _atomic_bytes(queue_path, queue_payload)
    analysis_sha = _sha256_path(Path(analysis)) if isinstance(analysis, (str, Path)) else _sha256_bytes(_canonical_bytes(analysis_data))
    universe_set = set(candidate_universe)
    missing_entries = sorted(universe_set - checkpoint_entries)
    extra_entries = sorted(checkpoint_entries - universe_set)
    conservation = {
        "candidate_universe_count": len(candidate_universe),
        "candidate_universe_sha256": candidate_universe_sha,
        "checkpoint_ok_count": checkpoint_status_counts["ok"],
        "checkpoint_invalid_count": checkpoint_status_counts["invalid_function_entry"],
        "checkpoint_error_count": checkpoint_status_counts["error"],
        "checkpoint_unknown_count": checkpoint_status_counts["unknown"],
        "repair_queue_count": len(repair_rows),
        "terminal_count": checkpoint_status_counts["ok"] + checkpoint_status_counts["invalid_function_entry"],
        "pending_count": len(repair_rows),
        "missing_checkpoint_count": len(missing_entries),
        "extra_checkpoint_count": len(extra_entries),
        "missing_entries": missing_entries,
        "extra_entries": extra_entries,
        "queue_matches_pending": len(repair_rows) == (
            checkpoint_status_counts["error"] + checkpoint_status_counts["unknown"]
        ),
    }
    conservation["conserved"] = bool(
        conservation["queue_matches_pending"]
        and conservation["checkpoint_unknown_count"] == 0
        and conservation["missing_checkpoint_count"] == 0
        and conservation["extra_checkpoint_count"] == 0
        and conservation["terminal_count"] + conservation["pending_count"] == len(candidate_universe)
    )
    manifest = sign_document({
        "schema": REPAIR_MANIFEST_SCHEMA,
        "target_sha256": binary_sha,
        "analysis_sha256": analysis_sha,
        "exporter_identity_sha256": identity_sha,
        "classifier_identity_sha256": classifier_sha,
        "repair_epoch_id": repair_epoch_id,
        "audit_epoch_id": audit_epoch_id,
        "audit_timestamp_utc": audit_timestamp_utc,
        "candidate_universe_count": len(candidate_universe),
        "candidate_universe_sha256": candidate_universe_sha,
        "queue_conservation": conservation,
        "repair_queue_path": queue_path.relative_to(reconstruction_root).as_posix(),
        "repair_queue_sha256": _sha256_path(queue_path),
        "rows": manifest_rows,
    })
    manifest_path = reconstruction_root / "FUNCTION_REPAIR_MANIFEST.json"
    _atomic_json(manifest_path, manifest)

    checkpoint_manifest = sign_document({
        "schema": CHECKPOINT_OWNERSHIP_SCHEMA,
        "target_sha256": binary_sha,
        "toolchain_identity_sha256": identity_sha,
                "native_routing": toolchain_identity.get("native_routing"),
        "candidate_universe_count": len(candidate_universe),
        "candidate_universe_sha256": candidate_universe_sha,
        "rows": sorted(checkpoint_ownership_rows, key=lambda row: row["path"]),
    })
    if checkpoint_manifest.get("trust") != "operator_signed":
        raise RuntimeError("checkpoint ownership manifest requires operator signing")
    checkpoint_manifest_path = reconstruction_root / "FUNCTION_CHECKPOINT_MANIFEST.json"
    _atomic_json(checkpoint_manifest_path, checkpoint_manifest)
    current_checkpoint_ownership = {
        row["path"]: row["sha256"] for row in checkpoint_ownership_rows
    }

    receipt = build_reconstruction_receipt(
        binary_path,
        analysis,
        export_root,
        toolchain_identity=toolchain_identity,
        classifier_identity=classifier,
        checkpoint_ownership=current_checkpoint_ownership,
    )
    ledger = sign_document({
        "schema": QUALITY_LEDGER_SCHEMA,
        "target_sha256": binary_sha,
        "audit_epoch_id": audit_epoch_id,
        "audit_timestamp_utc": audit_timestamp_utc,
        "candidate_universe_count": len(candidate_universe),
        "candidate_universe_sha256": candidate_universe_sha,
        "reconstruction_receipt_path": "RECONSTRUCTION_RECEIPT.json",
        "reconstruction_receipt_sha256": _sha256_path(reconstruction_root / "RECONSTRUCTION_RECEIPT.json"),
        "repair_manifest_path": manifest_path.relative_to(reconstruction_root).as_posix(),
        "repair_manifest_sha256": _sha256_path(manifest_path),
        "repair_queue_path": queue_path.relative_to(reconstruction_root).as_posix(),
        "repair_queue_sha256": _sha256_path(queue_path),
        "checkpoint_manifest_path": checkpoint_manifest_path.relative_to(reconstruction_root).as_posix(),
        "checkpoint_manifest_sha256": _sha256_path(checkpoint_manifest_path),
        "checkpoint_manifest_payload_sha256": checkpoint_manifest.get("payload_sha256"),
        "toolchain_identity_sha256": identity_sha,
                "native_routing": toolchain_identity.get("native_routing"),
        "classifier_identity_sha256": classifier_sha,
        "counts": {
            "functions_discovered": receipt["functions_discovered"],
            "valid_candidates": receipt["functions_valid_candidates"],
            "semantic_reconstructed": receipt["functions_semantically_reconstructed"],
            "invalid_entries": receipt["functions_invalid_entries"],
            "repair_pending": len(repair_rows),
            "terminal": receipt["functions_terminal"],
        },
        "queue_conservation": conservation,
    })
    ledger_path = reconstruction_root / "RECONSTRUCTION_QUALITY_LEDGER.json"
    ledger_archive = reconstruction_root / "quality-ledgers"
    previous_ledger_sha = ""
    previous_ledger_path = ""
    previous_sequence = 0
    if ledger_path.is_file():
        try:
            previous_bytes = ledger_path.read_bytes()
            previous_document = json.loads(previous_bytes)
            previous_ledger_sha = _sha256_bytes(previous_bytes)
            previous_sequence = int(previous_document.get("sequence") or 0)
            archive_path = ledger_archive / f"{previous_sequence:08d}-{previous_ledger_sha}.json"
            if not archive_path.is_file():
                _atomic_bytes(archive_path, previous_bytes)
            previous_ledger_path = archive_path.relative_to(reconstruction_root).as_posix()
        except (OSError, ValueError, TypeError):
            raise RuntimeError("existing quality ledger is unreadable; refusing to break ledger chain")
    ledger_body = {key: value for key, value in ledger.items()
                   if key not in {"payload_sha256", "signature", "signature_key_id", "trust"}}
    ledger = sign_document({
        **ledger_body,
        "sequence": previous_sequence + 1,
        "previous_ledger_sha256": previous_ledger_sha,
        "previous_ledger_path": previous_ledger_path,
    })
    _atomic_json(ledger_path, ledger)
    coverage_summary = receipt.get("coverage_summary") or {}
    state_bytes = coverage_summary.get("state_bytes") or {}
    unresolved_exec_bytes = sum(
        int(value or 0) for key, value in state_bytes.items()
        if any(marker in str(key) for marker in ("unclassified", "ambiguous", "partial", "uncovered"))
    )
    function_states = receipt.get("function_state_counts") or {}
    partial_function_count = sum(
        int(value or 0) for key, value in function_states.items()
        if key not in {"semantic_reconstructed", "external_reference", "thunk_or_plt", "analyzer_invalid_entry"}
    )
    exec_range_conserved = bool(
        coverage_summary.get("byte_partition_complete")
        and int(coverage_summary.get("partition_bytes") or 0)
        == int(coverage_summary.get("executable_bytes") or -1)
        and unresolved_exec_bytes == 0
    )
    target_semantic_complete = bool(
        receipt.get("semantic_complete")
        and receipt.get("exhaustive_accounting")
        and int(receipt.get("pending_work_units") or 0) == 0
        and partial_function_count == 0
        and exec_range_conserved
    )
    return {
        "target_id": receipt["target_id"],
        "scheduled": len(candidates),
        "completed": completed,
        "ok": completed,
        "classified_invalid": classified_invalid,
        "failed": failed,
        "cache_hits": cache_hits,
        "pending_work_units": receipt["pending_work_units"],
        "semantic_complete": receipt["semantic_complete"],
        "target_semantic_complete": target_semantic_complete,
        "executable_range_conservation_complete": exec_range_conserved,
        "unresolved_executable_bytes": unresolved_exec_bytes,
        "partial_function_count": partial_function_count,
        "target_pending_work_units": int(receipt.get("pending_work_units") or 0),
        "semantic_complete_for_valid_candidates": receipt["semantic_complete_for_valid_candidates"],
        "repair_pending": len(repair_rows),
        "terminal": completed + classified_invalid,
        "receipt_sha256": receipt["receipt_sha256"],
        "quality_ledger_sha256": _sha256_path(ledger_path),
        "quality_ledger_trust": ledger["trust"],
        "queue_conservation_complete": conservation["conserved"],
        "candidate_universe_count": len(candidate_universe),
        "candidate_universe_sha256": candidate_universe_sha,
    }


def append_work_unit_event(reconstruction_root: str | Path, event: dict[str, Any]) -> None:
    """Append and fsync one state transition under an inter-process lock."""
    root = Path(reconstruction_root)
    unit_id = str(event.get("unit_id") or "")
    state = str(event.get("state") or "")
    if not unit_id or state not in {"running", "retryable", *TERMINAL_WORK_STATES}:
        raise ValueError("event requires a unit_id and valid state")
    payload = _canonical_bytes({"schema": WORK_UNIT_SCHEMA, **event})
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".work-unit-events.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        journal = root / "WORK_UNIT_EVENTS.jsonl"
        fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(root)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
