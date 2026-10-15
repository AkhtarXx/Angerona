"""Fail-closed adjudication ledger for AI-generated security candidates."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from src.analysis.audit_lineage import (
    CHECKPOINT_SCHEMA,
    load_audit_epoch,
    open_trusted_artifact,
    open_verified_artifact,
    output_is_in_epoch,
    verify_checkpoint_set,
)
from src.analysis.clean_audit_routing import verify_clean_apk_routing_plan
from src.analysis.evidence_signing import verify_document, verify_document_identity
from src.analysis.schema_validation import require_int_field, require_list_field


SCHEMA = "angerona/security-candidate-ledger/v1"
CANDIDATE_SCHEMA = "angerona/security-candidate/v1"
PROOF_UNIT_SCHEMA = "angerona/security-proof-work-unit/v1"
AI_CHECKPOINT_SCHEMA = CHECKPOINT_SCHEMA
PROOF_STAGES = (
    "complete_function_and_call_context",
    "attacker_controlled_source_to_sink",
    "guards_and_mitigations",
    "abi_types_constants_and_layout",
    "packaged_build_and_runtime_reachability",
    "independent_engine_or_expert_corroboration",
    "matching_build_runtime_reproduction",
)
CLASS_PROOF_STAGE = "complete_class_and_cross_chunk_context"
CHECKPOINT_SET_INPUT_SCHEMA = "angerona/security-checkpoint-set-input/v1"
OCCURRENCE_SCHEMA = "angerona/security-occurrence/v1"
REQUIRED_BASE_LANES = {"class", "method", "native"}
TERMINAL_STATUSES = {"ok", "irrecoverable", "terminal_inconclusive"}
RETRYABLE_STATUSES = {"error", "transport_error"}
SECURITY_ROLES = {"source", "sink", "guard", "transform"}
CLEAN_CROSS_SCHEMA = "angerona/clean-cross-layer-merge-receipt/v1"
CLEAN_NATIVE_SCHEMA = "angerona/clean-native-acceptance-receipt/v1"


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


def _verify_clean_adjudication_gate(
    *, clean_plan: str | Path, clean_cross_merge_receipt: str | Path,
    clean_native_acceptance_receipt: str | Path, epoch_path: Path,
    epoch: dict[str, Any],
) -> dict[str, Any]:
    plan_path, plan_payload = open_trusted_artifact(
        clean_plan, epoch["trusted_read_roots"],
    )
    plan = verify_clean_apk_routing_plan(plan_path)
    if _sha_path(plan_path) != _sha_bytes(plan_payload):
        raise ValueError("clean audit plan changed during trusted verification")
    epoch_descriptor = {
        "path": str(epoch_path), "sha256": _sha_path(epoch_path),
        "epoch_id": epoch["epoch_id"],
    }
    if plan.get("audit_epoch") != epoch_descriptor or not plan.get("external_native_routing"):
        raise ValueError("security adjudication requires the exact epoch-bound clean/native plan")
    native_path, native_payload = open_trusted_artifact(
        clean_native_acceptance_receipt, epoch["trusted_read_roots"],
    )
    native_descriptor = {"path": str(native_path), "sha256": _sha_bytes(native_payload)}
    native = json.loads(native_payload)
    if (
        native.get("schema") != CLEAN_NATIVE_SCHEMA
        or not verify_document(native, require_signature=True)
        or native.get("plan_id") != plan["plan_id"]
        or native.get("routing_set_id") != plan["routing_set_id"]
        or native.get("audit_epoch") != epoch_descriptor
        or native.get("lane_complete") is not True
        or native.get("semantic_complete") is not True
        or native.get("root_conserved") is not True
        or require_int_field(
            native, "hold_target_count", context="native acceptance", minimum=0,
        ) != 0
        or require_int_field(
            native, "excluded_leakage_count", context="native acceptance", minimum=0,
        ) != 0
    ):
        raise ValueError("security adjudication rejects incomplete native acceptance")
    cross_path, cross_payload = open_trusted_artifact(
        clean_cross_merge_receipt, epoch["trusted_read_roots"],
    )
    cross_descriptor = {"path": str(cross_path), "sha256": _sha_bytes(cross_payload)}
    cross = json.loads(cross_payload)
    if (
        cross.get("schema") != CLEAN_CROSS_SCHEMA
        or not verify_document(cross, require_signature=True)
        or cross.get("plan_id") != plan["plan_id"]
        or cross.get("routing_set_id") != plan["routing_set_id"]
        or cross.get("audit_epoch") != epoch_descriptor
        or cross.get("status") != "COMPLETE"
        or require_int_field(
            cross, "hold_count", context="clean cross-layer receipt", minimum=0,
        ) != 0
        or cross.get("native_acceptance_receipt") != native_descriptor
        or (cross.get("parent_receipts") or {}).get("native_acceptance") != native_descriptor
    ):
        raise ValueError("security adjudication rejects incomplete or non-parent clean merge")
    open_verified_artifact(cross.get("cross_layer_graph"), epoch["trusted_read_roots"])
    return {
        "clean_plan": {"path": str(plan_path), "sha256": _sha_bytes(plan_payload)},
        "clean_cross_merge_receipt": cross_descriptor,
        "clean_native_acceptance_receipt": native_descriptor,
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
    }


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


def _normalise_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _validate_candidate_schema(candidate: Any) -> dict[str, Any]:
    if not isinstance(candidate, dict) or set(candidate) != {
        "title", "severity", "confidence", "evidence", "required_proof",
    }:
        raise ValueError("security candidate has an invalid schema")
    if not str(candidate.get("title") or "").strip():
        raise ValueError("security candidate has no title")
    if candidate.get("severity") not in {"critical", "high", "medium", "low"}:
        raise ValueError("security candidate has invalid severity")
    if candidate.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError("security candidate has invalid confidence")
    if not isinstance(candidate.get("required_proof"), list) or any(
        not isinstance(value, str) or not value.strip()
        for value in candidate.get("required_proof") or []
    ):
        raise ValueError("security candidate has invalid required_proof")
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("security candidate has no occurrence evidence")
    for occurrence in evidence:
        if not isinstance(occurrence, dict) or set(occurrence) != {
            "schema", "occurrence_id", "artifact_sha256", "entity_id", "semantic_role",
            "byte_start", "byte_end", "line_start", "line_end",
            "instruction_start", "instruction_end", "excerpt_sha256",
        }:
            raise ValueError("security candidate occurrence has an invalid schema")
        if occurrence.get("schema") != OCCURRENCE_SCHEMA:
            raise ValueError("security candidate occurrence has an unknown schema")
        if not re.fullmatch(r"[0-9a-f]{64}", str(occurrence.get("artifact_sha256") or "")):
            raise ValueError("security candidate occurrence has an invalid artifact SHA-256")
        if not str(occurrence.get("entity_id") or ""):
            raise ValueError("security candidate occurrence has no entity identity")
        if occurrence.get("semantic_role") not in SECURITY_ROLES:
            raise ValueError("security candidate occurrence has an invalid semantic role")
        excerpt_sha256 = str(occurrence.get("excerpt_sha256") or "")
        if excerpt_sha256 and not re.fullmatch(r"[0-9a-f]{64}", excerpt_sha256):
            raise ValueError("security candidate occurrence has an invalid excerpt SHA-256")
    return candidate


def _verify_occurrence(
    occurrence: dict[str, Any],
    artifact: bytes,
    *,
    entity_id: str,
    indexed: dict[str, Any],
) -> dict[str, Any]:
    if set(occurrence) != {
        "schema", "occurrence_id", "artifact_sha256", "entity_id", "semantic_role",
        "byte_start", "byte_end", "line_start", "line_end",
        "instruction_start", "instruction_end", "excerpt_sha256",
    } or occurrence.get("schema") != OCCURRENCE_SCHEMA:
        raise ValueError("unknown security occurrence schema")
    if str(occurrence.get("entity_id") or "") != entity_id:
        raise ValueError("security occurrence entity identity mismatch")
    role = str(occurrence.get("semantic_role") or "")
    if role not in SECURITY_ROLES:
        raise ValueError("security occurrence semantic role is invalid")
    if occurrence.get("occurrence_id") != indexed.get("occurrence_id"):
        raise ValueError("security occurrence ID is absent from the sealed index")
    for field in (
        "artifact_sha256", "entity_id", "byte_start", "byte_end", "line_start",
        "line_end", "instruction_start", "instruction_end", "excerpt_sha256",
    ):
        claimed = occurrence.get(field)
        if field == "excerpt_sha256" and not claimed:
            continue
        if claimed != indexed.get(field):
            raise ValueError(f"security occurrence differs from sealed index field {field}")
    role_candidates = indexed.get("semantic_role_candidates") or []
    if role_candidates and role not in role_candidates:
        raise ValueError("security occurrence role contradicts sealed candidate anchors")
    start = occurrence.get("byte_start")
    end = occurrence.get("byte_end")
    if (
        not isinstance(start, int) or isinstance(start, bool)
        or not isinstance(end, int) or isinstance(end, bool)
        or start < 0 or end <= start or end > len(artifact)
    ):
        raise ValueError("security occurrence byte range is invalid")
    excerpt = artifact[start:end]
    excerpt_sha256 = _sha_bytes(excerpt)
    claimed_excerpt_sha256 = str(occurrence.get("excerpt_sha256") or "")
    if claimed_excerpt_sha256 and excerpt_sha256 != claimed_excerpt_sha256:
        raise ValueError("security occurrence excerpt hash mismatch")

    line_start = occurrence.get("line_start")
    line_end = occurrence.get("line_end")
    instruction_start = str(occurrence.get("instruction_start") or "").strip()
    instruction_end = str(occurrence.get("instruction_end") or "").strip()
    has_lines = isinstance(line_start, int) and not isinstance(line_start, bool) \
        and isinstance(line_end, int) and not isinstance(line_end, bool) \
        and line_start > 0 and line_end >= line_start
    has_instructions = bool(instruction_start and instruction_end)
    if not has_lines and not has_instructions:
        raise ValueError("security occurrence has no exact line or instruction range")
    if has_lines:
        lines = artifact.splitlines(keepends=True)
        if line_end > len(lines):
            raise ValueError("security occurrence line range exceeds artifact")
        line_byte_start = sum(len(line) for line in lines[:line_start - 1])
        line_byte_end = sum(len(line) for line in lines[:line_end])
        if start < line_byte_start or end > line_byte_end:
            raise ValueError("security occurrence byte and line ranges disagree")
    if has_instructions:
        excerpt_text = excerpt.decode("utf-8", errors="strict")
        first = excerpt_text.find(instruction_start)
        last = excerpt_text.find(instruction_end, max(0, first))
        if first < 0 or last < first:
            raise ValueError("security occurrence instruction range is not in the exact excerpt")
    canonical_occurrence = {**occurrence, "excerpt_sha256": excerpt_sha256}
    return {
        "schema": OCCURRENCE_SCHEMA,
        "occurrence_sha256": _sha_bytes(_canonical(canonical_occurrence)),
        "artifact_sha256": occurrence["artifact_sha256"],
        "entity_id": entity_id,
        "semantic_role": role,
        "byte_start": start,
        "byte_end": end,
        "line_start": line_start,
        "line_end": line_end,
        "instruction_start": instruction_start or None,
        "instruction_end": instruction_end or None,
        "excerpt_sha256": excerpt_sha256,
    }


def _verify_response(
    checkpoint: dict[str, Any], root: Path, allowed_roots: list[str],
) -> tuple[bool, str | None]:
    blob = checkpoint.get("response_blob")
    digest = checkpoint.get("response_sha256")
    if not blob or not digest:
        return False, "raw-response-not-sealed"
    path = (root / str(blob)).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return False, "response-path-escapes-root"
    try:
        open_verified_artifact({"path": str(path), "sha256": digest}, allowed_roots)
    except (OSError, ValueError, TypeError):
        return False, "raw-response-hash-mismatch"
    return True, None


def _collect_evidence(
    items: Iterable[Any],
    evidence_by_sha: dict[str, list[dict[str, Any]]],
    issues: list[str],
    visited: set[Path],
    allowed_roots: list[str],
    sealed_checkpoint_paths: set[Path],
    occurrence_by_id: dict[str, dict[str, Any]],
) -> None:
    for item in items:
        if not isinstance(item, dict) or not item.get("path") or not item.get("sha256"):
            issues.append("malformed-evidence-manifest-row")
            continue
        evidence_path = Path(str(item["path"])).resolve()
        digest = str(item["sha256"])
        try:
            evidence_path, _payload = open_verified_artifact(item, allowed_roots)
        except (OSError, ValueError, TypeError):
            issues.append(f"evidence-hash-mismatch:{evidence_path}")
            continue
        kind = str(item.get("kind") or "")
        evidence_by_sha.setdefault(digest, []).append({
            "path": str(evidence_path), "kind": kind,
            "artifact_sha256": item.get("artifact_sha256"),
        })
        if kind == "security-occurrence-index":
            try:
                index = json.loads(_payload)
            except (TypeError, ValueError, json.JSONDecodeError):
                issues.append(f"occurrence-index-invalid:{evidence_path}")
                continue
            rows = require_list_field(index, "rows", context="security occurrence index")
            if (
                index.get("schema") != "angerona/security-occurrence-index/v1"
                or require_int_field(
                    index, "row_count", context="security occurrence index", minimum=0,
                ) != len(rows)
                or (index.get("artifact") or {}).get("sha256") != item.get("artifact_sha256")
                or index.get("entity_id") != item.get("entity_id")
            ):
                issues.append(f"occurrence-index-schema-or-count:{evidence_path}")
                continue
            for row in rows:
                occurrence_id = str(row.get("occurrence_id") or "")
                body = {key: value for key, value in row.items() if key != "occurrence_id"}
                if not occurrence_id or occurrence_id != _sha_bytes(_canonical(body)):
                    issues.append(f"occurrence-index-row-hash:{evidence_path}")
                    continue
                if occurrence_id in occurrence_by_id:
                    if occurrence_by_id[occurrence_id] != row:
                        issues.append(f"conflicting-occurrence-id:{occurrence_id}")
                    continue
                occurrence_by_id[occurrence_id] = row
        if evidence_path in visited or "checkpoint" not in kind:
            continue
        if evidence_path not in sealed_checkpoint_paths:
            issues.append(f"nested-checkpoint-not-in-sealed-set:{evidence_path}")
            continue
        visited.add(evidence_path)
        try:
            nested = json.loads(evidence_path.read_bytes())
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            issues.append(f"nested-checkpoint-invalid:{evidence_path}")
            continue
        if nested.get("schema") != AI_CHECKPOINT_SCHEMA:
            issues.append(f"nested-checkpoint-schema:{evidence_path}")
            continue
        _collect_evidence(
            nested.get("evidence_manifest") or [], evidence_by_sha, issues, visited,
            allowed_roots, sealed_checkpoint_paths, occurrence_by_id,
        )


def _load_queue_units(path: Path, allowed_roots: list[str], expected_sha: str) -> list[dict[str, Any]]:
    _verified, payload = open_verified_artifact(
        {"path": str(path), "sha256": expected_sha}, allowed_roots,
    )
    units: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(payload.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        unit = json.loads(line)
        unit_id = str(unit.get("unit_id") or "")
        if not unit_id or unit_id in seen:
            raise ValueError(f"missing or duplicate unit ID at queue line {line_number}")
        seen.add(unit_id)
        units.append(unit)
    return units


def _verified_checkpoint_inventory(
    checkpoint_sets: Iterable[dict[str, Any]],
    audit_epoch_path: Path,
    epoch: dict[str, Any],
    ai_roots: set[Path],
) -> tuple[list[tuple[Path, Path]], dict[str, Any], set[Path]]:
    descriptors = list(checkpoint_sets)
    if not descriptors:
        raise ValueError("security adjudication requires signed checkpoint sets")
    epoch_queues = {
        str(Path(str(row["path"])).resolve()): (name, str(row["sha256"]))
        for name, row in (epoch.get("queues") or {}).items() if isinstance(row, dict)
    }
    seen_queues: set[Path] = set()
    seen_units: set[str] = set()
    seen_checkpoints: set[Path] = set()
    lanes: dict[str, dict[str, int]] = {}
    checkpoint_files: list[tuple[Path, Path]] = []
    unit_rows: dict[str, tuple[dict[str, Any], str]] = {}
    checkpoint_status: dict[str, str] = {}

    for descriptor in descriptors:
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {
                "schema", "lane", "queue_path", "queue_sha256",
                "manifest_path", "manifest_sha256",
            }
            or descriptor.get("schema") != CHECKPOINT_SET_INPUT_SCHEMA
        ):
            raise ValueError("invalid security checkpoint-set input descriptor")
        lane = str(descriptor.get("lane") or "")
        if lane not in REQUIRED_BASE_LANES | {"derived"}:
            raise ValueError(f"invalid security checkpoint-set lane: {lane}")
        queue_path = Path(str(descriptor.get("queue_path") or "")).resolve()
        manifest_path = Path(str(descriptor.get("manifest_path") or "")).resolve()
        if _sha_path(queue_path) != descriptor.get("queue_sha256"):
            raise ValueError(f"checkpoint-set input queue hash mismatch: {queue_path}")
        if _sha_path(manifest_path) != descriptor.get("manifest_sha256"):
            raise ValueError(f"checkpoint-set input manifest hash mismatch: {manifest_path}")
        if queue_path in seen_queues:
            raise ValueError(f"duplicate checkpoint-set queue: {queue_path}")
        seen_queues.add(queue_path)
        manifest = verify_checkpoint_set(manifest_path, queue_path, audit_epoch_path)
        if manifest.get("generation_state") != "SEALED":
            raise ValueError(f"checkpoint set is not sealed: {manifest_path}")
        registered = epoch_queues.get(str(queue_path))
        if registered is not None:
            expected_lane = (
                "class" if registered[0] == "class"
                else "native" if registered[0].startswith("native")
                else "method"
            )
            if lane != expected_lane:
                raise ValueError(f"epoch queue lane mismatch: {queue_path}")
        elif lane != "derived":
            raise ValueError(f"non-epoch queue must be lineage-verified derived work: {queue_path}")
        units = _load_queue_units(queue_path, epoch["trusted_read_roots"], str(manifest["queue_sha256"]))
        by_id = {str(unit["unit_id"]): unit for unit in units}
        lane_row = lanes.setdefault(lane, {
            "queues": 0, "expected_units": 0, "sealed_units": 0,
            "terminal_units": 0, "needs_evidence_units": 0,
            "resolved_by_derived_units": 0,
        })
        lane_row["queues"] += 1
        lane_row["expected_units"] += len(units)
        entries = require_list_field(manifest, "entries", context="checkpoint set")
        lane_row["sealed_units"] += len(entries)
        for entry in entries:
            unit_id = str(entry.get("unit_id") or "")
            if unit_id in seen_units or unit_id not in by_id:
                raise ValueError(f"duplicate or unknown checkpoint-set unit: {unit_id}")
            seen_units.add(unit_id)
            checkpoint_path = Path(str(entry.get("checkpoint_path") or "")).resolve()
            checkpoint_root = checkpoint_path.parent.parent
            if checkpoint_root not in ai_roots:
                raise ValueError(f"sealed checkpoint root was not supplied: {checkpoint_root}")
            if checkpoint_path in seen_checkpoints:
                raise ValueError(f"duplicate sealed checkpoint path: {checkpoint_path}")
            seen_checkpoints.add(checkpoint_path)
            checkpoint_files.append((checkpoint_root, checkpoint_path))
            status = str(entry.get("checkpoint_status") or "")
            checkpoint_status[unit_id] = status
            unit_rows[unit_id] = (by_id[unit_id], lane)
            if status in TERMINAL_STATUSES:
                lane_row["terminal_units"] += 1
            elif status == "needs_evidence":
                lane_row["needs_evidence_units"] += 1
            elif status in RETRYABLE_STATUSES:
                raise ValueError(f"retryable checkpoint entered adjudication: {unit_id}:{status}")
            else:
                raise ValueError(f"unresolved checkpoint entered adjudication: {unit_id}:{status}")

    missing_epoch_queues = sorted(set(epoch_queues) - {str(path) for path in seen_queues})
    if missing_epoch_queues:
        raise ValueError(f"authoritative epoch queues lack checkpoint sets: {missing_epoch_queues}")
    if not REQUIRED_BASE_LANES.issubset(lanes):
        raise ValueError(
            f"missing authoritative security lanes: {sorted(REQUIRED_BASE_LANES - set(lanes))}"
        )

    children: dict[str, list[str]] = {}
    roots: set[str] = set()
    for unit_id, (unit, lane) in unit_rows.items():
        if lane == "derived":
            bindings = unit.get("parent_bindings") or []
            if not isinstance(bindings, list) or not bindings:
                raise ValueError(f"derived unit has no sealed parent set: {unit_id}")
            for binding in bindings:
                parent = str(binding.get("unit_id") or "") if isinstance(binding, dict) else ""
                if not parent or parent not in unit_rows:
                    raise ValueError(f"derived unit has an absent immediate parent: {unit_id}")
                children.setdefault(parent, []).append(unit_id)
        else:
            if unit.get("parent_bindings") or unit.get("parent_unit_id"):
                raise ValueError(f"base unit unexpectedly has parents: {unit_id}")
            roots.add(unit_id)
    for unit_id, status in checkpoint_status.items():
        if status != "needs_evidence":
            continue
        direct_children = children.get(unit_id) or []
        if not direct_children:
            raise ValueError(f"needs-evidence checkpoint has no sealed derived child: {unit_id}")
        lane = unit_rows[unit_id][1]
        lanes[lane]["resolved_by_derived_units"] += 1
    for parent_id, direct_children in children.items():
        for child_id in direct_children:
            derivation_kind = str(unit_rows[child_id][0].get("derivation_kind") or "")
            parent_status = checkpoint_status.get(parent_id)
            if derivation_kind == "evidence" and parent_status != "needs_evidence":
                raise ValueError(f"evidence work descends from a non-requesting checkpoint: {parent_id}")
            if derivation_kind == "consolidation" and parent_status not in TERMINAL_STATUSES:
                raise ValueError(f"consolidation descends from a non-terminal checkpoint: {parent_id}")
            if derivation_kind not in {"evidence", "consolidation"}:
                raise ValueError(f"derived unit has unknown derivation kind: {child_id}")
    for unit_id in seen_units:
        if not children.get(unit_id) and checkpoint_status[unit_id] not in TERMINAL_STATUSES:
            raise ValueError(f"non-terminal leaf checkpoint: {unit_id}")
    for lane, row in lanes.items():
        row["effective_terminal_units"] = (
            row["terminal_units"] + row["resolved_by_derived_units"]
        )
        if row["effective_terminal_units"] != row["expected_units"]:
            raise ValueError(
                f"lane terminal accounting mismatch: {lane}: "
                f"{row['effective_terminal_units']}/{row['expected_units']}"
            )
    sealed_roots = {root for root, _path in checkpoint_files}
    if sealed_roots != ai_roots:
        raise ValueError(
            "AI output roots do not exactly match signed checkpoint-set roots: "
            f"sealed={sorted(map(str, sealed_roots))} supplied={sorted(map(str, ai_roots))}"
        )

    matrix = {
        "schema": "angerona/security-checkpoint-coverage/v1",
        "audit_epoch_id": epoch["epoch_id"],
        "queue_count": len(seen_queues),
        "unit_count": len(seen_units),
        "checkpoint_count": len(checkpoint_files),
        "lanes": lanes,
        "coverage_complete": True,
        "terminal_complete": True,
        "duplicate_units": 0,
        "mixed_epoch": False,
    }
    return checkpoint_files, matrix, seen_checkpoints


def build_security_candidate_ledger(
    ai_output_dirs: Iterable[str | Path],
    output_dir: str | Path,
    class_consolidation_dir: str | Path | None = None,
    *,
    audit_epoch: str | Path,
    checkpoint_sets: Iterable[dict[str, Any]],
    clean_plan: str | Path,
    clean_cross_merge_receipt: str | Path,
    clean_native_acceptance_receipt: str | Path,
) -> dict[str, Any]:
    epoch_path = Path(audit_epoch).resolve()
    epoch = load_audit_epoch(epoch_path)
    output = output_is_in_epoch(output_dir, epoch)
    output.mkdir(parents=True, exist_ok=True)
    clean_acceptance = _verify_clean_adjudication_gate(
        clean_plan=clean_plan,
        clean_cross_merge_receipt=clean_cross_merge_receipt,
        clean_native_acceptance_receipt=clean_native_acceptance_receipt,
        epoch_path=epoch_path, epoch=epoch,
    )
    ai_roots = {Path(value).resolve() for value in ai_output_dirs}
    checkpoint_files, coverage_matrix, sealed_checkpoint_paths = _verified_checkpoint_inventory(
        checkpoint_sets, epoch_path, epoch, ai_roots,
    )

    consolidation_by_class: dict[str, dict[str, Any]] = {}
    consolidation_issues: list[dict[str, str]] = []
    if class_consolidation_dir is not None:
        consolidation_root = Path(class_consolidation_dir).resolve()
        manifest_path = consolidation_root / "CLASS_CONSOLIDATION_MANIFEST.json"
        try:
            _manifest_path, manifest_bytes = open_trusted_artifact(
                manifest_path, epoch["trusted_read_roots"],
            )
            manifest = json.loads(manifest_bytes)
            if manifest.get("schema") != "angerona/class-consolidation-manifest/v1":
                raise ValueError("unknown class consolidation manifest schema")
            if not verify_document_identity(manifest):
                raise ValueError("class consolidation manifest self hash mismatch")
            for descriptor in manifest.get("receipts") or []:
                path = Path(str(descriptor.get("path") or "")).resolve()
                try:
                    path, receipt_bytes = open_verified_artifact(
                        descriptor, epoch["trusted_read_roots"],
                    )
                except (OSError, ValueError, TypeError):
                    raise ValueError(f"class consolidation receipt hash mismatch: {path}")
                receipt = json.loads(receipt_bytes)
                if receipt.get("schema") != "angerona/class-consolidation-receipt/v1":
                    raise ValueError(f"unknown class consolidation receipt schema: {path}")
                class_id = str(receipt.get("class_id") or "")
                if not class_id or class_id != descriptor.get("class_id"):
                    raise ValueError(f"class consolidation identity mismatch: {path}")
                consolidation_by_class[class_id] = {
                    "path": str(path),
                    "sha256": descriptor["sha256"],
                    "disposition": receipt.get("disposition"),
                    "reportable_security_complete": bool(receipt.get("reportable_security_complete")),
                }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            consolidation_issues.append({"path": str(manifest_path), "reason": str(exc)})

    records: dict[str, dict[str, Any]] = {}
    checkpoint_issues: list[dict[str, str]] = []
    checkpoints_with_candidates = 0
    for root, checkpoint_path in checkpoint_files:
        try:
            checkpoint_bytes = checkpoint_path.read_bytes()
            checkpoint = json.loads(checkpoint_bytes)
            if checkpoint.get("schema") != AI_CHECKPOINT_SCHEMA:
                raise ValueError("unknown checkpoint schema")
            result = checkpoint.get("result")
            if not isinstance(result, dict):
                continue
            candidates = result.get("security_candidates") or []
            if not isinstance(candidates, list):
                raise ValueError("security_candidates is not a list")
            if candidates:
                checkpoints_with_candidates += 1
            response_valid, response_issue = _verify_response(
                checkpoint, root, epoch["trusted_read_roots"],
            )
            evidence_by_sha: dict[str, list[dict[str, Any]]] = {}
            occurrence_by_id: dict[str, dict[str, Any]] = {}
            evidence_issues: list[str] = []
            _collect_evidence(
                checkpoint.get("evidence_manifest") or [],
                evidence_by_sha, evidence_issues, set(),
                epoch["trusted_read_roots"], sealed_checkpoint_paths, occurrence_by_id,
            )
            if evidence_issues:
                raise ValueError(f"sealed checkpoint evidence is invalid: {evidence_issues[0]}")
            indexed_artifacts = {
                str(row.get("artifact_sha256") or "")
                for path_rows in evidence_by_sha.values() for row in path_rows
                if row.get("kind") == "security-occurrence-index"
            }
            model_visible_artifacts = {
                digest for digest, path_rows in evidence_by_sha.items()
                if any(
                    row.get("kind") != "security-occurrence-index"
                    and "checkpoint" not in str(row.get("kind") or "")
                    and not str(row.get("kind") or "").endswith("-authoritative-source")
                    for row in path_rows
                )
            }
            if not model_visible_artifacts.issubset(indexed_artifacts):
                missing_indexes = sorted(model_visible_artifacts - indexed_artifacts)
                raise ValueError(f"model-visible artifacts lack sealed occurrence indexes: {missing_indexes[:3]}")

            entity_id = str(
                checkpoint.get("function_id")
                or checkpoint.get("method_id")
                or checkpoint.get("class_id")
                or ""
            )
            entity_kind = (
                "function" if checkpoint.get("function_id")
                else "method" if checkpoint.get("method_id")
                else "class" if checkpoint.get("class_id")
                else "unknown"
            )
            for candidate in candidates:
                candidate = _validate_candidate_schema(candidate)
                title = str(candidate.get("title") or "").strip()
                dedup_subject = {"entity_id": entity_id, "title": _normalise_title(title)}
                if entity_kind == "class":
                    dedup_subject["entity_kind"] = entity_kind
                candidate_id = _sha_bytes(_canonical(dedup_subject))
                citations = candidate.get("evidence") if isinstance(candidate.get("evidence"), list) else []
                citation_checks = []
                for citation in citations:
                    artifact_sha = str(citation.get("artifact_sha256") or "") if isinstance(citation, dict) else ""
                    location = citation if isinstance(citation, dict) else {}
                    paths = evidence_by_sha.get(artifact_sha, [])
                    authoritative_paths = [
                        row for row in paths
                        if "checkpoint" not in str(row.get("kind") or "")
                        and row.get("kind") != "security-occurrence-index"
                    ]
                    content_match = False
                    matched_path = None
                    occurrence_check = None
                    indexed = occurrence_by_id.get(str(location.get("occurrence_id") or ""))
                    for path_row in authoritative_paths:
                        if indexed is None:
                            break
                        artifact_path = Path(path_row["path"])
                        try:
                            occurrence_check = _verify_occurrence(
                                location, artifact_path.read_bytes(), entity_id=entity_id,
                                indexed=indexed,
                            )
                        except (UnicodeDecodeError, ValueError, TypeError):
                            continue
                        else:
                            content_match = True
                            matched_path = str(artifact_path)
                            break
                    citation_checks.append({
                        "artifact_sha256": artifact_sha,
                        "occurrence": occurrence_check,
                        "manifest_match": bool(authoritative_paths),
                        "content_match": content_match,
                        "matched_path": matched_path,
                    })
                citation_valid = bool(citation_checks) and all(
                    row["manifest_match"] and row["content_match"] for row in citation_checks
                )
                reconstruction = result.get("reconstruction") if isinstance(result.get("reconstruction"), dict) else {}
                class_lineage_valid = (
                    entity_kind != "class"
                    or (
                        checkpoint.get("prompt_contract") in {
                            "angerona/dex-class-prompt/compact-semantic-range/v5",
                            "angerona/dex-class-consolidation-prompt/v1",
                        }
                        and isinstance(reconstruction.get("reviewed_range"), dict)
                    )
                )
                lineage_valid = (
                    response_valid
                    and not evidence_issues
                    and bool(entity_id)
                    and bool(title)
                    and class_lineage_valid
                )
                status = (
                    "EVIDENCE_BOUND_CANDIDATE"
                    if lineage_valid and citation_valid
                    else "REJECTED_UNSUPPORTED_AI_CLAIM"
                )
                occurrence = {
                    "checkpoint_path": str(checkpoint_path),
                    "checkpoint_sha256": _sha_bytes(checkpoint_bytes),
                    "unit_id": checkpoint.get("unit_id"),
                    "request_id": checkpoint.get("request_id"),
                    "resolved_model": checkpoint.get("resolved_model"),
                    "checkpoint_status": checkpoint.get("checkpoint_status"),
                    "prompt_contract": checkpoint.get("prompt_contract"),
                    "input_manifest_sha256": checkpoint.get("input_manifest_sha256"),
                    "reviewed_range": reconstruction.get("reviewed_range"),
                    "response_valid": response_valid,
                    "response_issue": response_issue,
                    "evidence_issues": evidence_issues,
                    "citation_checks": citation_checks,
                }
                existing = records.get(candidate_id)
                if existing is None:
                    consolidation = consolidation_by_class.get(entity_id) if entity_kind == "class" else None
                    class_stage_state = (
                        "complete" if consolidation and consolidation["reportable_security_complete"]
                        else "inconclusive" if consolidation and consolidation["disposition"] == "STATIC_INCONCLUSIVE"
                        else "pending"
                    )
                    records[candidate_id] = {
                        "schema": CANDIDATE_SCHEMA,
                        "candidate_id": candidate_id,
                        "entity_id": entity_id,
                        "entity_kind": entity_kind,
                        "title": title,
                        "severity_claimed": str(candidate.get("severity") or ""),
                        "confidence_claimed": str(candidate.get("confidence") or ""),
                        "status": status,
                        "ai_only": True,
                        "confirmed": False,
                        "occurrences": [occurrence],
                        "model_required_proof": sorted(set(str(x) for x in candidate.get("required_proof") or [])),
                        "proof_stages": [
                            {
                                "stage": stage,
                                "state": class_stage_state if stage == CLASS_PROOF_STAGE else "pending",
                                "evidence": (
                                    [{"path": consolidation["path"], "sha256": consolidation["sha256"]}]
                                    if stage == CLASS_PROOF_STAGE and consolidation else []
                                ),
                            }
                            for stage in (
                                ((CLASS_PROOF_STAGE,) + PROOF_STAGES)
                                if entity_kind == "class" else PROOF_STAGES
                            )
                        ],
                        "class_consolidation": consolidation,
                    }
                else:
                    existing["occurrences"].append(occurrence)
                    if existing["status"] != "EVIDENCE_BOUND_CANDIDATE" and status == "EVIDENCE_BOUND_CANDIDATE":
                        existing["status"] = status
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            checkpoint_issues.append({"path": str(checkpoint_path), "reason": str(exc)})

    if checkpoint_issues:
        first = checkpoint_issues[0]
        raise ValueError(
            f"sealed checkpoint candidate validation failed: {first['path']}: {first['reason']}"
        )

    validation_issues: list[dict[str, str]] = []
    receipt_root = output / "validation" / "receipts"
    for receipt_path in sorted(receipt_root.glob("*.json")):
        try:
            receipt_bytes = receipt_path.read_bytes()
            receipt = json.loads(receipt_bytes)
            if receipt.get("schema") != "angerona/security-validation-receipt/v1":
                raise ValueError("unknown validation receipt schema")
            candidate_id = str(receipt.get("candidate_id") or "")
            candidate = records.get(candidate_id)
            if candidate is None:
                raise ValueError("validation receipt candidate is not in current ledger")
            disposition = str(receipt.get("disposition") or "")
            if disposition not in {"reportable", "suppressed", "not_applicable", "deferred"}:
                raise ValueError("invalid validation disposition")
            for evidence in receipt.get("evidence") or []:
                path = Path(str(evidence.get("path") or "")).resolve()
                try:
                    open_verified_artifact(evidence, epoch["trusted_read_roots"])
                except (OSError, ValueError, TypeError):
                    raise ValueError(f"validation evidence hash mismatch: {path}")
            report_path = Path(str(receipt.get("report_path") or "")).resolve()
            try:
                open_verified_artifact(
                    {"path": str(report_path), "sha256": receipt.get("report_sha256")},
                    epoch["trusted_read_roots"],
                )
            except (OSError, ValueError, TypeError):
                raise ValueError("validation report hash mismatch")
            candidate["validation"] = {
                "receipt_path": str(receipt_path),
                "receipt_sha256": _sha_bytes(receipt_bytes),
                "disposition": disposition,
                "method": receipt.get("method"),
                "report_path": str(report_path),
                "report_sha256": receipt["report_sha256"],
                "remaining_proof_gap": receipt.get("remaining_proof_gap"),
            }
            candidate["status"] = {
                "reportable": "STATIC_REPORTABLE",
                "suppressed": "SUPPRESSED_FALSE_POSITIVE",
                "not_applicable": "NOT_APPLICABLE",
                "deferred": "DEFERRED_VALIDATION",
            }[disposition]
            candidate["confirmed"] = False
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            validation_issues.append({"path": str(receipt_path), "reason": str(exc)})

    candidates = sorted(records.values(), key=lambda row: row["candidate_id"])
    for candidate in candidates:
        consolidation = candidate.get("class_consolidation")
        if (
            candidate.get("entity_kind") == "class"
            and consolidation
            and consolidation.get("disposition") == "STATIC_INCONCLUSIVE"
        ):
            candidate["status"] = "STATIC_INCONCLUSIVE"
            candidate["confirmed"] = False
    proof_units = []
    for candidate in candidates:
        if candidate["status"] not in {"EVIDENCE_BOUND_CANDIDATE", "STATIC_REPORTABLE"}:
            continue
        for stage_row in candidate["proof_stages"]:
            if stage_row.get("state") != "pending":
                continue
            stage = stage_row["stage"]
            subject = f"{candidate['candidate_id']}:{stage}"
            proof_units.append({
                "schema": PROOF_UNIT_SCHEMA,
                "unit_id": _sha_bytes(subject.encode()),
                "candidate_id": candidate["candidate_id"],
                "entity_id": candidate["entity_id"],
                "stage": stage,
                "state": "pending",
                "required_evidence": (
                    ["sealed class consolidation receipt covering every declared source chunk"]
                    if stage == CLASS_PROOF_STAGE else []
                ),
            })

    ledger = {
        "schema": SCHEMA,
        "audit_epoch_id": epoch["epoch_id"],
        "audit_epoch_path": str(epoch_path),
        "audit_epoch_sha256": _sha_path(epoch_path),
        "clean_acceptance": clean_acceptance,
        "coverage_matrix": coverage_matrix,
        "checkpoint_files": len(checkpoint_files),
        "checkpoints_with_candidates": checkpoints_with_candidates,
        "checkpoint_issues": checkpoint_issues,
        "candidates": candidates,
        "candidate_state_counts": {
            state: sum(row["status"] == state for row in candidates)
            for state in sorted({row["status"] for row in candidates})
        },
        "validation_issues": validation_issues,
        "class_consolidation_issues": consolidation_issues,
        "class_consolidation_receipts": len(consolidation_by_class),
        "current_candidates_validated": bool(candidates) and all("validation" in row for row in candidates),
        "proof_work_units": len(proof_units),
        "confirmed_findings": 0,
        "absence_of_candidates_proves_safety": False,
        "adjudication_complete": False,
    }
    unsigned = _canonical(ledger)
    ledger["ledger_sha256"] = _sha_bytes(unsigned)
    _atomic(output / "SECURITY_CANDIDATE_LEDGER.json", json.dumps(ledger, indent=2, sort_keys=True).encode() + b"\n")
    _atomic(output / "SECURITY_PROOF_WORK_UNITS.jsonl", b"".join(_canonical(row) for row in proof_units))
    return ledger
