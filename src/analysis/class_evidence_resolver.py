from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from src.analysis.audit_lineage import (
    load_audit_epoch,
    open_epoch_queue,
    open_trusted_artifact,
    open_verified_artifact,
    verify_checkpoint_set,
    write_derived_queue_lineage,
)
from src.analysis.dex_evidence_resolver import _smali_body
from src.analysis.evidence_signing import with_document_identity
from src.analysis.schema_validation import optional_int_field, require_int_field


SCHEMA = "angerona/class-evidence-resolution/v1"
WORK_SCHEMA = "angerona/jadx-class-chunk-work-unit/v1"
PROMPT_CONTRACT = "angerona/dex-class-prompt/compact-semantic-range/v5"
_DESCRIPTOR = re.compile(r"L[^;\s]+;")
MAX_EVIDENCE_DEPTH = 3
_CHAIN_FIELDS = ("class_id", "chunk_index", "source_sha256", "byte_start", "byte_end")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


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
    finally:
        temporary.unlink(missing_ok=True)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not row.get("unit_id"):
            raise ValueError(f"invalid work unit at {path}:{line_number}")
        result.append(row)
    return result


def _validated_input(
    item: dict[str, Any], allowed_roots: list[str],
) -> tuple[Path, int]:
    path, payload = open_verified_artifact(item, allowed_roots)
    return path, len(payload)


def _evidence_key(kind: str, target: str) -> str:
    return _sha_bytes(_canonical({"kind": kind.strip().lower(), "target": target.strip()}))


def _target_parts(target: str, descriptors: list[str]) -> tuple[str, str]:
    match = _DESCRIPTOR.search(target)
    descriptor = match.group(0) if match else (descriptors[0] if descriptors else "")
    remainder = target[match.end():].strip() if match else target.strip()
    remainder = remainder.removeprefix("->").strip()
    member = remainder.split()[0] if remainder else ""
    return descriptor, member


def _caller_lines(body: str, descriptor: str, member: str) -> list[str]:
    result: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if descriptor and descriptor not in stripped:
            continue
        if member and f"->{member}" not in stripped and member not in stripped:
            continue
        opcode = stripped.split(None, 1)[0] if stripped else ""
        if opcode.startswith(("sput", "iput")):
            continue
        if opcode.startswith(("invoke-", "sget", "iget", "new-instance", "const-class", "check-cast", "instance-of")):
            result.append(stripped)
    return result


def _dex_inputs(
    request_id: str, kind: str, related: list[dict[str, Any]], allowed_roots: list[str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    accepted = {"dex-method-receipt", "smali-overlay", "smali-method-body"}
    for unit in related:
        for item in unit.get("inputs") or []:
            if item.get("kind") not in accepted:
                continue
            path, _ = _validated_input(item, allowed_roots)
            key = (str(path), str(item["sha256"]))
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "kind": f"resolved-{kind}-{item['kind']}",
                "path": str(path),
                "sha256": item["sha256"],
                "request_id": request_id,
                "related_method_id": unit["method_id"],
                "related_qualified_name": unit["qualified_name"],
            })
    return result


def _class_inputs(
    request_id: str, related: list[dict[str, Any]], allowed_roots: list[str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for unit in related:
        for item in unit.get("inputs") or []:
            if item.get("kind") != "jadx-class-source-chunk":
                continue
            path, _ = _validated_input(item, allowed_roots)
            key = (str(path), str(item["sha256"]))
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "kind": "resolved-adjacent-chunk-jadx-class-source-chunk",
                "path": str(path),
                "sha256": item["sha256"],
                "request_id": request_id,
                "related_class_id": unit["class_id"],
                "related_chunk_index": unit["chunk_index"],
            })
    return result


def _validate_evidence_chain(
    primary_units: list[dict[str, Any]],
    prior_units: list[dict[str, Any]],
    set_manifests: list[tuple[Path, dict[str, Any], list[dict[str, Any]]]],
    *,
    max_evidence_depth: int,
) -> None:
    all_units = {str(row["unit_id"]): row for row in [*primary_units, *prior_units]}
    owner_by_unit: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
    for set_path, set_manifest, generation_units in set_manifests:
        entries = {str(row["unit_id"]): row for row in set_manifest.get("entries") or []}
        for unit in generation_units:
            unit_id = str(unit["unit_id"])
            if unit_id in owner_by_unit or unit_id not in entries:
                raise ValueError(f"ambiguous or missing checkpoint-set ownership: {unit_id}")
            owner_by_unit[unit_id] = (set_path, set_manifest, entries[unit_id])
    primary_ids = {str(row["unit_id"]) for row in primary_units}
    for unit in primary_units:
        unit_id = str(unit["unit_id"])
        if (
            optional_int_field(
                unit, "evidence_depth", default=0,
                context=f"primary class unit {unit_id}", minimum=0,
            ) != 0
            or str(unit.get("root_unit_id") or unit_id) != unit_id
            or unit.get("parent_unit_id")
        ):
            raise ValueError(f"invalid primary class lineage root: {unit_id}")
    child_by_parent: dict[str, str] = {}
    unit_by_root_depth: dict[tuple[str, int], str] = {}
    for unit in prior_units:
        unit_id = str(unit["unit_id"])
        parent_id = str(unit.get("parent_unit_id") or "")
        root_id = str(unit.get("root_unit_id") or "")
        depth = require_int_field(
            unit, "evidence_depth", context=f"derived class unit {unit_id}", minimum=1,
        )
        if not parent_id or parent_id not in all_units:
            raise ValueError(f"derived class unit has no authenticated parent: {unit_id}")
        parent = all_units[parent_id]
        parent_root = str(parent.get("root_unit_id") or parent["unit_id"])
        parent_depth = optional_int_field(
            parent, "evidence_depth", default=0,
            context=f"parent class unit {parent_id}", minimum=0,
        )
        if (
            root_id not in primary_ids
            or root_id != parent_root
            or depth != parent_depth + 1
            or depth < 1
            or depth > max_evidence_depth
        ):
            raise ValueError(f"non-linear class evidence depth/root: {unit_id}")
        for field in _CHAIN_FIELDS:
            if unit.get(field) != parent.get(field):
                raise ValueError(f"class evidence subject changed at {field}: {unit_id}")
        parent_set_path, _parent_set, parent_entry = owner_by_unit[parent_id]
        if (
            unit.get("source_checkpoint_set_sha256") != _sha_path(parent_set_path)
            or unit.get("parent_response_sha256") != parent_entry.get("response_sha256")
        ):
            raise ValueError(f"class evidence unit is not bound to its immediate parent receipt: {unit_id}")
        if parent_id in child_by_parent:
            raise ValueError(f"forked class evidence parent: {parent_id}")
        root_depth = (root_id, depth)
        if root_depth in unit_by_root_depth:
            raise ValueError(f"multiple class evidence units at root/depth {root_depth}")
        child_by_parent[parent_id] = unit_id
        unit_by_root_depth[root_depth] = unit_id


def resolve_class_evidence_requests(
    class_queue: str | Path,
    primary_checkpoint_set: str | Path,
    evidence_checkpoint_sets: list[str | Path],
    dex_method_queue: str | Path,
    dex_code_method_accounting: str | Path,
    audit_epoch: str | Path,
    output_dir: str | Path,
    *,
    max_evidence_bytes: int = 262144,
    max_evidence_depth: int = MAX_EVIDENCE_DEPTH,
) -> dict[str, Any]:
    epoch_path = Path(audit_epoch).resolve()
    epoch = load_audit_epoch(epoch_path)
    allowed_roots = list(epoch["trusted_read_roots"])
    if max_evidence_depth < 0 or max_evidence_depth > MAX_EVIDENCE_DEPTH:
        raise ValueError(f"max evidence depth must be between 0 and {MAX_EVIDENCE_DEPTH}")
    class_path, _class_payload = open_epoch_queue(class_queue, epoch, "class")
    dex_path, _dex_payload = open_epoch_queue(dex_method_queue, epoch, "dex_method")
    output = Path(output_dir).resolve()
    try:
        output.relative_to(Path(epoch["epoch_output_root"]))
    except ValueError as exc:
        raise ValueError("class evidence output escapes epoch output root") from exc
    output.mkdir(parents=True, exist_ok=True)
    primary_units = _load_jsonl(class_path)
    dex_units = _load_jsonl(dex_path)
    if any(row.get("schema") != WORK_SCHEMA for row in primary_units):
        raise ValueError("class evidence lineage contains an unsupported work-unit schema")
    primary_set_path, _primary_set_payload = open_trusted_artifact(
        primary_checkpoint_set, allowed_roots,
    )
    primary_set = verify_checkpoint_set(primary_set_path, class_path, epoch_path)
    set_manifests: list[tuple[Path, dict[str, Any], list[dict[str, Any]]]] = [
        (primary_set_path, primary_set, primary_units),
    ]
    prior_units: list[dict[str, Any]] = []
    for value in evidence_checkpoint_sets:
        set_path, set_bytes = open_trusted_artifact(value, allowed_roots)
        set_payload = json.loads(set_bytes)
        queue_path, _queue_payload = open_verified_artifact(
            {
                "path": str(set_payload.get("queue_path") or ""),
                "sha256": str(set_payload.get("queue_sha256") or ""),
            },
            allowed_roots,
        )
        verified_set = verify_checkpoint_set(set_path, queue_path, epoch_path)
        generation_units = _load_jsonl(queue_path)
        if any(row.get("schema") != WORK_SCHEMA for row in generation_units):
            raise ValueError(f"evidence checkpoint set has unsupported work units: {set_path}")
        prior_units.extend(generation_units)
        set_manifests.append((set_path, verified_set, generation_units))
    all_units = {str(row["unit_id"]): row for row in [*primary_units, *prior_units]}
    if len(all_units) != len(primary_units) + len(prior_units):
        raise ValueError("duplicate unit identity across sealed class evidence generations")
    _validate_evidence_chain(
        primary_units, prior_units, set_manifests,
        max_evidence_depth=max_evidence_depth,
    )

    accounting_path, accounting_payload = open_verified_artifact(
        epoch["dex_code_method_accounting"], allowed_roots,
    )
    supplied_accounting_path, _ = open_trusted_artifact(
        dex_code_method_accounting, allowed_roots,
    )
    if supplied_accounting_path != accounting_path:
        raise ValueError("class evidence DEX accounting is not bound to the audit epoch")
    accounting = json.loads(accounting_payload)
    if not accounting.get("exhaustive_code_method_accounting"):
        raise ValueError("class evidence requires exhaustive raw DEX code-method accounting")
    accounted_code_ids = set(str(value) for value in accounting.get("code_method_ids") or [])
    if accounted_code_ids != {str(row["method_id"]) for row in dex_units}:
        raise ValueError("DEX semantic queue differs from epoch accounting code-method set")
    method_table = {
        str(row["qualified_name"]): row for row in accounting.get("method_accounting_rows") or []
    }
    parent_set_descriptors = [
        {"path": str(path), "sha256": _sha_path(path)} for path, _manifest, _units in set_manifests
    ]
    primary_by_class: dict[str, list[dict[str, Any]]] = {}
    for unit in primary_units:
        primary_by_class.setdefault(str(unit["class_id"]), []).append(unit)

    bodies: dict[str, str] = {}
    dex_by_class: dict[str, list[dict[str, Any]]] = {}
    for unit in dex_units:
        body, _ = _smali_body(unit)
        bodies[str(unit["unit_id"])] = body
        dex_by_class.setdefault(str(unit.get("class_descriptor") or ""), []).append(unit)

    latest: dict[str, tuple[int, int, dict[str, Any], dict[str, Any], Path, str]] = {}
    for set_path, set_manifest, generation_units in set_manifests:
        generation_by_id = {str(row["unit_id"]): row for row in generation_units}
        for entry in set_manifest.get("entries") or []:
            checkpoint_path, checkpoint_payload = open_verified_artifact(
                {"path": entry["checkpoint_path"], "sha256": entry["checkpoint_sha256"]},
                allowed_roots,
            )
            checkpoint = json.loads(checkpoint_payload)
            unit = all_units.get(str(checkpoint.get("unit_id") or ""))
            if not unit or str(unit["unit_id"]) not in generation_by_id:
                raise ValueError(f"sealed checkpoint unit is absent from its generation: {checkpoint_path}")
            if checkpoint.get("prompt_contract") != PROMPT_CONTRACT:
                raise ValueError(f"sealed class checkpoint prompt mismatch: {checkpoint_path}")
            root_unit_id = str(unit.get("root_unit_id") or unit["unit_id"])
            candidate = (
                optional_int_field(
                    unit, "evidence_depth", default=0,
                    context=f"class unit {unit['unit_id']}", minimum=0,
                ),
                require_int_field(
                    checkpoint,
                    "semantic_attempt" if "semantic_attempt" in checkpoint else "attempt",
                    context="sealed class checkpoint", minimum=0,
                ),
                unit,
                checkpoint,
                checkpoint_path,
                str(set_path),
            )
            if root_unit_id not in latest or candidate[:2] > latest[root_unit_id][:2]:
                latest[root_unit_id] = candidate

    new_by_id: dict[str, dict[str, Any]] = {}
    request_rows: list[dict[str, Any]] = []
    subject_rows: list[dict[str, Any]] = []
    immediate_parent_sets: dict[tuple[str, str], dict[str, str]] = {}
    class_queue_sha = _sha_path(class_path)
    dex_queue_sha = _sha_path(dex_path)
    for root_unit_id, (depth, _attempt, subject, checkpoint, checkpoint_path, source_set_path) in sorted(latest.items()):
        if checkpoint.get("checkpoint_status") != "needs_evidence":
            continue
        source_set_sha = _sha_path(Path(source_set_path))
        if depth >= max_evidence_depth:
            subject_rows.append({
                "root_unit_id": root_unit_id,
                "class_id": subject["class_id"],
                "chunk_index": subject["chunk_index"],
                "evidence_depth": depth,
                "resolved_requests": 0,
                "pending_requests": len((checkpoint.get("result") or {}).get("evidence_requests") or []),
                "evidence_bytes": 0,
                "scheduled": False,
                "reason": "maximum-evidence-depth-reached",
            })
            continue
        requests = (checkpoint.get("result") or {}).get("evidence_requests") or []
        existing_keys = set(str(value) for value in subject.get("resolved_evidence_keys") or [])
        resolved_ids: list[str] = []
        resolved_keys: list[str] = []
        resolved_inputs: list[dict[str, Any]] = []
        subject_requests: list[dict[str, Any]] = []
        descriptors = [str(value) for value in subject.get("class_descriptors") or []]
        for request in requests:
            if not isinstance(request, dict):
                continue
            kind = str(request.get("kind") or "").strip()
            target = str(request.get("target") or "").strip()
            descriptor, member = _target_parts(target, descriptors)
            request_id = _sha_bytes(_canonical({
                "audit_epoch_id": epoch["epoch_id"],
                "source_checkpoint_set_sha256": source_set_sha,
                "dex_code_method_accounting_sha256": epoch["dex_code_method_accounting"]["sha256"],
                "root_unit_id": root_unit_id,
                "response_sha256": checkpoint.get("response_sha256"),
                "request": request,
            }))
            related: list[dict[str, Any]] = []
            matches: list[dict[str, Any]] = []
            direct_inputs: list[dict[str, Any]] = []
            status = "pending"
            if kind == "caller":
                for candidate in dex_units:
                    lines = _caller_lines(bodies[str(candidate["unit_id"])], descriptor, member)
                    if lines:
                        related.append(candidate)
                        matches.append({
                            "method_id": candidate["method_id"],
                            "qualified_name": candidate["qualified_name"],
                            "reference_lines": lines,
                        })
                direct_inputs = _dex_inputs(request_id, kind, related, allowed_roots)
                status = (
                    "resolved-direct-static-references"
                    if related
                    else "observed-no-direct-static-reference"
                )
            elif kind in {"callee", "method-smali"}:
                related = [
                    row for row in dex_by_class.get(descriptor, [])
                    if not member or f"->{member}" in str(row.get("qualified_name") or "")
                ]
                matches = [{"method_id": row["method_id"], "qualified_name": row["qualified_name"]} for row in related]
                direct_inputs = _dex_inputs(request_id, kind, related, allowed_roots)
                qualified_matches = [
                    row for name, row in method_table.items()
                    if name.startswith(f"{descriptor}->{member}") or name == f"{descriptor}->{member}"
                ]
                if related:
                    status = "resolved-body"
                elif qualified_matches:
                    matches = qualified_matches
                    status = "resolved-terminal-noncode-method"
                else:
                    status = "resolved-not-in-packaged-dex-method-table"
            elif kind == "type":
                related = list(dex_by_class.get(descriptor, []))
                matches = [{"method_id": row["method_id"], "qualified_name": row["qualified_name"]} for row in related]
                direct_inputs = _dex_inputs(request_id, kind, related, allowed_roots)
                table_matches = [row for name, row in method_table.items() if name.startswith(f"{descriptor}->")]
                if related:
                    status = "resolved-type"
                elif table_matches:
                    matches = table_matches
                    status = "resolved-type-terminal-noncode-methods"
                else:
                    status = "resolved-type-absent-from-packaged-dex-method-table"
            elif kind == "adjacent-chunk":
                siblings = primary_by_class.get(str(subject["class_id"]), [])
                index = int(subject["chunk_index"])
                related_chunks = [row for row in siblings if abs(int(row["chunk_index"]) - index) == 1]
                matches = [{"class_id": row["class_id"], "chunk_index": row["chunk_index"]} for row in related_chunks]
                direct_inputs = _class_inputs(request_id, related_chunks, allowed_roots)
                status = "resolved-adjacent" if related_chunks else "resolved-no-adjacent"
            elif kind == "runtime":
                status = "runtime-required"
            evidence_key = _evidence_key(kind, target)
            if status.startswith("resolved") and evidence_key in existing_keys:
                status = "stalled-already-resolved"
            row = {
                "schema": "angerona/class-evidence-request/v1",
                "request_id": request_id,
                "root_unit_id": root_unit_id,
                "subject_unit_id": subject["unit_id"],
                "subject_class_id": subject["class_id"],
                "subject_chunk_index": subject["chunk_index"],
                "evidence_depth": depth,
                "kind": kind,
                "target": target,
                "reason": str(request.get("reason") or ""),
                "status": status,
                "evidence_key": evidence_key,
                "matches": matches,
                "search_scope": {
                    "audit_epoch_id": epoch["epoch_id"],
                    "dex_code_method_accounting_sha256": epoch["dex_code_method_accounting"]["sha256"],
                    "apk_sha256": accounting["apk"]["sha256"],
                    "dex_method_table_entries": accounting["method_receipts"],
                    "class_queue_sha256": class_queue_sha,
                    "dex_method_queue_sha256": dex_queue_sha,
                    "dex_code_methods_scanned": len(dex_units),
                    "method_table_complete": True,
                    "code_body_scan_complete": True,
                    "semantic_callgraph_complete": False,
                    "complete": kind not in {"caller", "runtime"},
                    "authority": "exact packaged APK DEX method table plus direct opcode-text references in code-bearing methods",
                    "limitations": ["indirect dispatch", "reflection", "runtime decoding", "native-only dispatch", "server behavior"],
                },
            }
            request_rows.append(row)
            subject_requests.append(row)
            if status.startswith("resolved"):
                resolved_ids.append(request_id)
                resolved_keys.append(evidence_key)
                resolved_inputs.extend(direct_inputs)

        resolution = {
            "schema": "angerona/class-evidence-subject-resolution/v1",
            "root_unit_id": root_unit_id,
            "subject_unit_id": subject["unit_id"],
            "subject_class_id": subject["class_id"],
            "subject_chunk_index": subject["chunk_index"],
            "parent_checkpoint": str(checkpoint_path),
            "parent_checkpoint_sha256": _sha_path(checkpoint_path),
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "source_checkpoint_set": source_set_path,
            "source_checkpoint_set_sha256": source_set_sha,
            "audit_epoch_id": epoch["epoch_id"],
            "dex_code_method_accounting_sha256": epoch["dex_code_method_accounting"]["sha256"],
            "requests": subject_requests,
            "search_scope": {
                "class_queue_sha256": class_queue_sha,
                "dex_method_queue_sha256": dex_queue_sha,
                "dex_code_methods_scanned": len(dex_units),
                "method_table_complete": True,
                "code_body_scan_complete": True,
                "semantic_callgraph_complete": False,
                "complete": all(row["kind"] not in {"caller", "runtime"} for row in subject_requests),
                "authority": "exact packaged APK DEX method table and code-bearing methods only",
            },
        }
        resolution_bytes = json.dumps(resolution, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        resolution_sha = _sha_bytes(resolution_bytes)
        resolution_path = output / "receipts" / f"{resolution_sha}.json"
        if not resolution_path.is_file():
            _atomic(resolution_path, resolution_bytes)
        combined: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        parent_item = {
            "kind": "class-parent-checkpoint",
            "path": str(checkpoint_path),
            "sha256": _sha_path(checkpoint_path),
        }
        receipt_item = {
            "kind": "class-evidence-resolution-receipt",
            "path": str(resolution_path),
            "sha256": resolution_sha,
        }
        for item in [*(subject.get("inputs") or []), parent_item, *resolved_inputs, receipt_item]:
            path, _ = _validated_input(item, allowed_roots)
            key = (str(path), str(item["sha256"]))
            if key in seen:
                continue
            seen.add(key)
            combined.append(item)
        evidence_bytes = sum(Path(str(item["path"])).stat().st_size for item in combined)
        subject_state = {
            "root_unit_id": root_unit_id,
            "class_id": subject["class_id"],
            "chunk_index": subject["chunk_index"],
            "evidence_depth": depth,
            "resolved_requests": len(resolved_ids),
            "pending_requests": sum(not row["status"].startswith("resolved") for row in subject_requests),
            "evidence_bytes": evidence_bytes,
            "scheduled": False,
        }
        if not resolved_ids:
            subject_state["reason"] = "no-new-static-evidence"
            subject_rows.append(subject_state)
            continue
        if evidence_bytes > max_evidence_bytes:
            subject_state["reason"] = "evidence-budget-exceeded-partition-required"
            subject_rows.append(subject_state)
            continue
        manifest = {
            "schema": "angerona/class-evidence-input-manifest/v1",
            "audit_epoch_id": epoch["epoch_id"],
            "source_checkpoint_set_sha256": source_set_sha,
            "dex_code_method_accounting_sha256": epoch["dex_code_method_accounting"]["sha256"],
            "class_id": subject["class_id"],
            "root_unit_id": root_unit_id,
            "parent_unit_id": subject["unit_id"],
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "source_checkpoint_set_sha256": source_set_sha,
            "evidence_depth": depth + 1,
            "evidence_generation": PROMPT_CONTRACT,
            "resolved_request_ids": sorted(resolved_ids),
            "resolved_evidence_keys": sorted(existing_keys | set(resolved_keys)),
            "inputs": combined,
        }
        manifest_sha = _sha_bytes(_canonical(manifest))
        unit_id = _sha_bytes(
            f"{epoch['epoch_id']}\0{root_unit_id}\0{manifest_sha}\0class-evidence-v2".encode("utf-8")
        )
        new_unit = {
            **{key: subject[key] for key in (
                "class_id", "class_descriptors", "source_relative_path", "source_sha256",
                "source_bytes", "chunk_index", "chunk_count", "byte_start", "byte_end",
            )},
            "schema": WORK_SCHEMA,
            "unit_id": unit_id,
            "unit_kind": "jadx_class_evidence_reanalysis",
            "state": "pending",
            "inputs": combined,
            "input_manifest_sha256": manifest_sha,
            "root_unit_id": root_unit_id,
            "root_unit_ids": [root_unit_id],
            "parent_unit_id": subject["unit_id"],
            "parent_response_sha256": checkpoint.get("response_sha256"),
            "source_checkpoint_set_sha256": source_set_sha,
            "parent_bindings": [{
                "checkpoint_set_sha256": source_set_sha,
                "unit_id": subject["unit_id"],
                "response_sha256": checkpoint.get("response_sha256"),
            }],
            "derivation_kind": "evidence",
            "evidence_depth": depth + 1,
            "resolved_request_ids": sorted(resolved_ids),
            "resolved_evidence_keys": sorted(existing_keys | set(resolved_keys)),
            "evidence_requests": [row for row in subject_requests if not row["status"].startswith("resolved")],
            "unresolved_reasons": [row["reason"] for row in subject_requests if not row["status"].startswith("resolved")],
        }
        new_by_id[unit_id] = new_unit
        parent_key = (source_set_path, source_set_sha)
        immediate_parent_sets[parent_key] = {
            "path": source_set_path,
            "sha256": source_set_sha,
        }
        subject_state["scheduled"] = True
        subject_state["unit_id"] = unit_id
        subject_rows.append(subject_state)

    work_bytes = b"".join(_canonical(row) for row in sorted(new_by_id.values(), key=lambda row: row["unit_id"]))
    request_bytes = b"".join(_canonical(row) for row in sorted(request_rows, key=lambda row: row["request_id"]))
    manifest = {
        "schema": SCHEMA,
        "audit_epoch_id": epoch["epoch_id"],
        "input_checkpoint_sets": parent_set_descriptors,
        "parent_checkpoint_sets": sorted(
            immediate_parent_sets.values(), key=lambda row: (row["path"], row["sha256"]),
        ),
        "dex_code_method_accounting": epoch["dex_code_method_accounting"],
        "class_queue": str(class_path),
        "class_queue_sha256": class_queue_sha,
        "dex_method_queue": str(dex_path),
        "dex_method_queue_sha256": dex_queue_sha,
        "primary_class_units": len(primary_units),
        "dex_code_methods_scanned": len(dex_units),
        "latest_roots": len(latest),
        "requests": len(request_rows),
        "resolved_requests": sum(row["status"].startswith("resolved") for row in request_rows),
        "pending_requests": sum(not row["status"].startswith("resolved") for row in request_rows),
        "evidence_work_units": len(new_by_id),
        "new_or_updated_subjects": sum(row["scheduled"] for row in subject_rows),
        "subjects": subject_rows,
        "request_stream_sha256": _sha_bytes(request_bytes),
        "work_stream_sha256": _sha_bytes(work_bytes),
        "max_evidence_bytes": max_evidence_bytes,
        "max_evidence_depth": max_evidence_depth,
    }
    generation_sha = _sha_bytes(work_bytes)
    queue_path = output / "queues" / f"{generation_sha}.jsonl"
    if new_by_id:
        _atomic(queue_path, work_bytes)
        manifest["generation"] = {
            "queue_path": str(queue_path),
            "queue_sha256": generation_sha,
            "unit_count": len(new_by_id),
        }
    manifest = with_document_identity(manifest)
    manifest_bytes = _canonical(manifest)
    manifest_path = output / "manifests" / f"{_sha_bytes(manifest_bytes)}.json"
    _atomic(manifest_path, manifest_bytes)
    if new_by_id:
        lineage = write_derived_queue_lineage(
            queue_path,
            epoch_path,
            derivation_manifest={"path": str(manifest_path), "sha256": _sha_path(manifest_path)},
            parent_checkpoint_sets=manifest["parent_checkpoint_sets"],
            unit_count=len(new_by_id),
        )
    _atomic(output / "CLASS_EVIDENCE_REQUESTS.jsonl", request_bytes)
    _atomic(output / "CLASS_EVIDENCE_RESOLUTION.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return manifest
