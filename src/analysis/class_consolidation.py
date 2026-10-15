from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from src.analysis.audit_lineage import (
    load_audit_epoch,
    open_trusted_artifact,
    verify_checkpoint_set,
    write_derived_queue_lineage,
)
from src.analysis.evidence_signing import with_document_identity
from src.analysis.schema_validation import optional_int_field, require_int_field


SCHEMA = "angerona/class-consolidation-manifest/v1"
WORK_SCHEMA = "angerona/jadx-class-consolidation-work-unit/v1"
RECEIPT_SCHEMA = "angerona/class-consolidation-receipt/v1"
CHECKPOINT_SCHEMA = "angerona/semantic-ai-checkpoint/v2"
CLASS_PROMPT = "angerona/dex-class-prompt/compact-semantic-range/v5"
CONSOLIDATION_PROMPT = "angerona/dex-class-consolidation-prompt/v1"


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


def _checkpoint(
    root: Path,
    path: Path,
    unit: dict[str, Any],
    prompt_contract: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    payload = path.read_bytes()
    row = json.loads(payload)
    if (
        row.get("schema") != CHECKPOINT_SCHEMA
        or row.get("unit_id") != unit["unit_id"]
        or row.get("class_id") != unit["class_id"]
        or row.get("input_manifest_sha256") != unit["input_manifest_sha256"]
        or row.get("prompt_contract") != prompt_contract
    ):
        return None
    response_blob = row.get("response_blob")
    response_sha = row.get("response_sha256")
    response_path = (root / str(response_blob or "")).resolve()
    try:
        response_path.relative_to(root)
    except ValueError:
        return None
    if not response_path.is_file() or _sha_path(response_path) != response_sha:
        return None
    return {
        "row": row,
        "path": str(path),
        "sha256": _sha_bytes(payload),
        "response_path": str(response_path),
        "response_sha256": response_sha,
        "attempt": require_int_field(
            row, "semantic_attempt" if "semantic_attempt" in row else "attempt",
            context="class consolidation checkpoint", minimum=0,
        ),
    }


def _write_receipt(output: Path, receipt: dict[str, Any]) -> tuple[str, str]:
    payload = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    digest = _sha_bytes(payload)
    path = output / "receipts" / f"{receipt['class_id']}-{digest}.json"
    if not path.is_file():
        _atomic(path, payload)
    return str(path), digest


def build_class_consolidation(
    class_queue: str | Path,
    primary_ai_output: str | Path,
    evidence_work_queue: str | Path,
    evidence_ai_output: str | Path,
    evidence_resolution: str | Path,
    consolidation_ai_output: str | Path,
    dex_method_queue: str | Path,
    apk_path: str | Path,
    output_dir: str | Path,
    *,
    audit_epoch: str | Path,
    parent_checkpoint_sets: list[str | Path],
    max_input_bytes: int = 262144,
) -> dict[str, Any]:
    class_path = Path(class_queue).resolve()
    primary_ai = Path(primary_ai_output).resolve()
    evidence_path = Path(evidence_work_queue).resolve()
    evidence_ai = Path(evidence_ai_output).resolve()
    resolution_path = Path(evidence_resolution).resolve()
    consolidation_ai = Path(consolidation_ai_output).resolve()
    dex_path = Path(dex_method_queue).resolve()
    apk = Path(apk_path).resolve()
    output = Path(output_dir).resolve()
    epoch_path = Path(audit_epoch).resolve()
    epoch = load_audit_epoch(epoch_path)
    parent_set_descriptors: list[dict[str, str]] = []
    checkpoint_owners: dict[str, dict[str, str]] = {}
    for value in parent_checkpoint_sets:
        set_path, set_bytes = open_trusted_artifact(value, epoch["trusted_read_roots"])
        raw_set = json.loads(set_bytes)
        verified_set = verify_checkpoint_set(set_path, raw_set["queue_path"], epoch_path)
        set_sha = _sha_path(set_path)
        parent_set_descriptors.append({"path": str(set_path), "sha256": set_sha})
        for entry in verified_set.get("entries") or []:
            checkpoint_path = str(Path(str(entry["checkpoint_path"])).resolve())
            if checkpoint_path in checkpoint_owners:
                raise ValueError(f"checkpoint belongs to multiple signed sets: {checkpoint_path}")
            checkpoint_owners[checkpoint_path] = {
                "checkpoint_set_sha256": set_sha,
                "unit_id": str(entry["unit_id"]),
                "response_sha256": str(entry.get("response_sha256") or ""),
            }
    primary_units = _load_jsonl(class_path)
    evidence_units = [
        row for row in _load_jsonl(evidence_path)
        if row.get("evidence_generation") == CLASS_PROMPT
    ]
    all_units = {str(row["unit_id"]): row for row in [*primary_units, *evidence_units]}
    primary_by_root = {str(row["unit_id"]): row for row in primary_units}
    latest: dict[str, tuple[int, int, dict[str, Any], dict[str, Any]]] = {}
    for ai_root in (primary_ai, evidence_ai):
        for checkpoint_path in (ai_root / "checkpoints").glob("*.json"):
            try:
                raw = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError):
                continue
            unit = all_units.get(str(raw.get("unit_id") or ""))
            if not unit:
                continue
            descriptor = _checkpoint(ai_root, checkpoint_path, unit, CLASS_PROMPT)
            if descriptor is None:
                continue
            root_unit_id = str(unit.get("root_unit_id") or unit["unit_id"])
            candidate = (
                optional_int_field(
                    unit, "evidence_depth", default=0,
                    context=f"class unit {unit['unit_id']}", minimum=0,
                ), descriptor["attempt"], unit, descriptor,
            )
            if root_unit_id not in latest or candidate[:2] > latest[root_unit_id][:2]:
                latest[root_unit_id] = candidate

    terminal_inconclusive: set[str] = set()
    if resolution_path.is_file():
        resolution = json.loads(resolution_path.read_text(encoding="utf-8"))
        for subject in resolution.get("subjects") or []:
            if (
                not subject.get("scheduled")
                and subject.get("reason") == "no-new-static-evidence"
                and require_int_field(
                    subject, "pending_requests",
                    context="class evidence subject", minimum=0,
                ) > 0
            ):
                terminal_inconclusive.add(str(subject["root_unit_id"]))

    dex_by_class: dict[str, set[str]] = {}
    for unit in _load_jsonl(dex_path):
        descriptor = str(unit.get("class_descriptor") or "")
        digest = str(unit.get("dex_sha256") or "")
        if descriptor and digest:
            dex_by_class.setdefault(descriptor, set()).add(digest)

    classes: dict[str, list[dict[str, Any]]] = {}
    for unit in primary_units:
        classes.setdefault(str(unit["class_id"]), []).append(unit)
    apk_sha = _sha_path(apk)
    queue: list[dict[str, Any]] = []
    class_rows: list[dict[str, Any]] = []
    receipt_rows: list[dict[str, Any]] = []
    for class_id, units in sorted(classes.items()):
        units.sort(key=lambda row: int(row["chunk_index"]))
        first = units[0]
        if [int(row["chunk_index"]) for row in units] != list(range(len(units))):
            raise ValueError(f"non-contiguous chunk indexes for {class_id}")
        cursor = 0
        for unit in units:
            if int(unit["byte_start"]) != cursor:
                raise ValueError(f"chunk byte gap/overlap for {class_id}")
            cursor = int(unit["byte_end"])
            if unit["source_sha256"] != first["source_sha256"]:
                raise ValueError(f"source identity mismatch for {class_id}")
        if cursor != int(first["source_bytes"]):
            raise ValueError(f"source byte coverage mismatch for {class_id}")
        chunk_rows: list[dict[str, Any]] = []
        root_states: list[str] = []
        checkpoint_inputs: list[dict[str, Any]] = []
        for primary in units:
            root_id = str(primary["unit_id"])
            current = latest.get(root_id)
            if current is None:
                root_states.append("waiting")
                continue
            _depth, _attempt, current_unit, descriptor = current
            checkpoint_status = str(descriptor["row"].get("checkpoint_status") or "")
            if checkpoint_status == "ok":
                state = "resolved"
            elif root_id in terminal_inconclusive or checkpoint_status in {"irrecoverable", "terminal_inconclusive"}:
                state = "static-inconclusive"
            elif checkpoint_status == "needs_evidence":
                state = "evidence-needed"
            else:
                state = "waiting"
            root_states.append(state)
            checkpoint_inputs.append({
                "kind": "class-chunk-checkpoint",
                "path": descriptor["path"],
                "sha256": descriptor["sha256"],
                "root_unit_id": root_id,
                "chunk_index": primary["chunk_index"],
                "parent_binding": checkpoint_owners.get(str(Path(descriptor["path"]).resolve())),
            })
            if checkpoint_inputs[-1]["parent_binding"] is None:
                raise ValueError(f"class checkpoint is absent from signed parent sets: {descriptor['path']}")
            chunk_rows.append({
                "root_unit_id": root_id,
                "latest_unit_id": current_unit["unit_id"],
                "chunk_index": primary["chunk_index"],
                "byte_start": primary["byte_start"],
                "byte_end": primary["byte_end"],
                "state": state,
                "checkpoint_path": descriptor["path"],
                "checkpoint_sha256": descriptor["sha256"],
                "response_path": descriptor["response_path"],
                "response_sha256": descriptor["response_sha256"],
            })
        base = {
            "class_id": class_id,
            "class_descriptors": first.get("class_descriptors") or [],
            "source_relative_path": first["source_relative_path"],
            "source_sha256": first["source_sha256"],
            "source_bytes": first["source_bytes"],
            "chunk_count": len(units),
            "resolved_chunks": sum(state == "resolved" for state in root_states),
            "inconclusive_chunks": sum(state == "static-inconclusive" for state in root_states),
            "evidence_needed_chunks": sum(state == "evidence-needed" for state in root_states),
            "waiting_chunks": sum(state == "waiting" for state in root_states),
        }
        disposition = "waiting"
        final_descriptor = None
        if len(root_states) == len(units) and all(state == "resolved" for state in root_states):
            if len(units) == 1:
                disposition = "CONSOLIDATED_SINGLE_CHUNK"
            else:
                source_receipts = [
                    item for item in first.get("inputs") or []
                    if item.get("kind") == "jadx-class-source-receipt"
                ]
                if len(source_receipts) != 1:
                    raise ValueError(f"missing source receipt for {class_id}")
                inputs = [source_receipts[0], *checkpoint_inputs]
                input_bytes = sum(Path(str(item["path"])).stat().st_size for item in inputs)
                if input_bytes > max_input_bytes:
                    disposition = "PARTITION_REQUIRED"
                else:
                    manifest = {
                        "schema": "angerona/class-consolidation-input-manifest/v1",
                        "class_id": class_id,
                        "source_sha256": first["source_sha256"],
                        "chunk_count": len(units),
                        "inputs": inputs,
                    }
                    manifest_sha = _sha_bytes(_canonical(manifest))
                    unit_id = _sha_bytes(f"{class_id}\0{manifest_sha}\0class-consolidation-v1".encode("utf-8"))
                    work_unit = {
                        "schema": WORK_SCHEMA,
                        "unit_id": unit_id,
                        "unit_kind": "jadx_class_consolidation",
                        "state": "pending",
                        "class_id": class_id,
                        "class_descriptors": first.get("class_descriptors") or [],
                        "source_relative_path": first["source_relative_path"],
                        "source_sha256": first["source_sha256"],
                        "source_bytes": first["source_bytes"],
                        "chunk_index": 0,
                        "chunk_count": len(units),
                        "byte_start": 0,
                        "byte_end": first["source_bytes"],
                        "inputs": inputs,
                        "input_manifest_sha256": manifest_sha,
                        "final_class_consolidation": True,
                        "evidence_requests": [],
                        "unresolved_reasons": ["whole-class-consolidation-pending"],
                        "parent_bindings": sorted(
                            [dict(item["parent_binding"]) for item in checkpoint_inputs],
                            key=lambda row: (row["checkpoint_set_sha256"], row["unit_id"]),
                        ),
                        "root_unit_ids": sorted(str(item["root_unit_id"]) for item in checkpoint_inputs),
                        "evidence_depth": 1 + max(
                            optional_int_field(
                                latest[str(item["root_unit_id"])][2],
                                "evidence_depth", default=0,
                                context=f"class unit {item['root_unit_id']}", minimum=0,
                            )
                            for item in checkpoint_inputs
                        ),
                        "derivation_kind": "consolidation",
                    }
                    final_descriptor = _checkpoint(
                        consolidation_ai,
                        consolidation_ai / "checkpoints" / f"{unit_id}.json",
                        work_unit,
                        CONSOLIDATION_PROMPT,
                    )
                    if final_descriptor is None:
                        queue.append(work_unit)
                        disposition = "CONSOLIDATION_PENDING"
                    else:
                        status = final_descriptor["row"].get("checkpoint_status")
                        disposition = {
                            "ok": "CONSOLIDATED_MULTI_CHUNK",
                            "needs_evidence": "EVIDENCE_NEEDED",
                            "irrecoverable": "STATIC_INCONCLUSIVE",
                            "terminal_inconclusive": "STATIC_INCONCLUSIVE",
                        }.get(str(status), "CONSOLIDATION_PENDING")
        elif any(state == "static-inconclusive" for state in root_states):
            disposition = "STATIC_INCONCLUSIVE"
        elif any(state == "evidence-needed" for state in root_states):
            disposition = "EVIDENCE_NEEDED"

        row = {**base, "disposition": disposition}
        if disposition in {"CONSOLIDATED_SINGLE_CHUNK", "CONSOLIDATED_MULTI_CHUNK", "STATIC_INCONCLUSIVE"}:
            dex_hashes = sorted({digest for descriptor in base["class_descriptors"] for digest in dex_by_class.get(descriptor, set())})
            receipt = {
                "schema": RECEIPT_SCHEMA,
                "apk_path": str(apk),
                "apk_sha256": apk_sha,
                "dex_sha256": dex_hashes,
                **base,
                "disposition": disposition,
                "coverage": {
                    "byte_start": 0,
                    "byte_end": first["source_bytes"],
                    "contiguous": True,
                    "all_declared_chunks_accounted": len(chunk_rows) == len(units),
                },
                "chunks": chunk_rows,
                "final_checkpoint": (
                    {
                        "path": final_descriptor["path"],
                        "sha256": final_descriptor["sha256"],
                        "response_sha256": final_descriptor["response_sha256"],
                    }
                    if final_descriptor is not None else None
                ),
                "reportable_security_complete": disposition.startswith("CONSOLIDATED"),
                "limitations": (
                    [] if disposition.startswith("CONSOLIDATED")
                    else ["static or runtime evidence remained unresolved; this class cannot support a confirmed finding"]
                ),
            }
            receipt_path, receipt_sha = _write_receipt(output, receipt)
            row["receipt_path"] = receipt_path
            row["receipt_sha256"] = receipt_sha
            receipt_rows.append({"class_id": class_id, "path": receipt_path, "sha256": receipt_sha, "disposition": disposition})
        class_rows.append(row)

    queue.sort(key=lambda row: row["unit_id"])
    queue_bytes = b"".join(_canonical(row) for row in queue)
    used_parent_set_hashes = {
        str(binding["checkpoint_set_sha256"])
        for unit in queue for binding in unit.get("parent_bindings") or []
    }
    used_parent_sets = [
        row for row in parent_set_descriptors if row["sha256"] in used_parent_set_hashes
    ]
    if queue and {row["sha256"] for row in used_parent_sets} != used_parent_set_hashes:
        raise ValueError("class consolidation DAG references an undeclared parent set")
    manifest = {
        "schema": SCHEMA,
        "audit_epoch_id": epoch["epoch_id"],
        "parent_checkpoint_sets": sorted(
            used_parent_sets, key=lambda row: (row["path"], row["sha256"]),
        ),
        "apk_path": str(apk),
        "apk_sha256": apk_sha,
        "class_queue": str(class_path),
        "class_queue_sha256": _sha_path(class_path),
        "dex_method_queue": str(dex_path),
        "dex_method_queue_sha256": _sha_path(dex_path),
        "classes_seen": len(class_rows),
        "class_state_counts": {
            state: sum(row["disposition"] == state for row in class_rows)
            for state in sorted({row["disposition"] for row in class_rows})
        },
        "work_units": len(queue),
        "work_stream_sha256": _sha_bytes(queue_bytes),
        "receipts": receipt_rows,
        "classes": class_rows,
        "max_input_bytes": max_input_bytes,
        "coverage_terminal": bool(class_rows) and all(row["disposition"] in {
            "CONSOLIDATED_SINGLE_CHUNK", "CONSOLIDATED_MULTI_CHUNK", "STATIC_INCONCLUSIVE",
        } for row in class_rows),
        "semantic_complete": bool(class_rows) and all(row["disposition"].startswith("CONSOLIDATED") for row in class_rows),
    }
    if queue:
        manifest["generation"] = {
            "queue_path": str(output / "CLASS_CONSOLIDATION_WORK_UNITS.jsonl"),
            "queue_sha256": _sha_bytes(queue_bytes),
            "unit_count": len(queue),
        }
    manifest = with_document_identity(manifest)
    _atomic(output / "CLASS_CONSOLIDATION_WORK_UNITS.jsonl", queue_bytes)
    _atomic(output / "CLASS_CONSOLIDATION_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    if queue:
        write_derived_queue_lineage(
            output / "CLASS_CONSOLIDATION_WORK_UNITS.jsonl",
            epoch_path,
            derivation_manifest={
                "path": str(output / "CLASS_CONSOLIDATION_MANIFEST.json"),
                "sha256": _sha_path(output / "CLASS_CONSOLIDATION_MANIFEST.json"),
            },
            parent_checkpoint_sets=manifest["parent_checkpoint_sets"],
            unit_count=len(queue),
        )
    return manifest


def verify_class_consolidation(output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir).resolve()
    manifest = json.loads((output / "CLASS_CONSOLIDATION_MANIFEST.json").read_text(encoding="utf-8"))
    issues: list[str] = []
    work = (output / "CLASS_CONSOLIDATION_WORK_UNITS.jsonl").read_bytes()
    if _sha_bytes(work) != manifest.get("work_stream_sha256"):
        issues.append("work-stream-hash-mismatch")
    for receipt in manifest.get("receipts") or []:
        path = Path(str(receipt["path"]))
        if not path.is_file() or _sha_path(path) != receipt.get("sha256"):
            issues.append(f"receipt-hash-mismatch:{path}")
            continue
        row = json.loads(path.read_text(encoding="utf-8"))
        chunks = sorted(row.get("chunks") or [], key=lambda value: int(value["chunk_index"]))
        cursor = 0
        for chunk in chunks:
            if int(chunk["byte_start"]) != cursor:
                issues.append(f"chunk-gap:{row['class_id']}")
            cursor = int(chunk["byte_end"])
            checkpoint = Path(str(chunk["checkpoint_path"]))
            if not checkpoint.is_file() or _sha_path(checkpoint) != chunk["checkpoint_sha256"]:
                issues.append(f"checkpoint-hash:{checkpoint}")
        if cursor != int(row["source_bytes"]):
            issues.append(f"source-byte-coverage:{row['class_id']}")
        if row.get("apk_sha256") != manifest.get("apk_sha256"):
            issues.append(f"apk-lineage:{row['class_id']}")
    return {
        "schema": "angerona/class-consolidation-verification/v1",
        "manifest": str(output / "CLASS_CONSOLIDATION_MANIFEST.json"),
        "classes_seen": manifest.get("classes_seen"),
        "receipt_count": len(manifest.get("receipts") or []),
        "work_units": manifest.get("work_units"),
        "issue_count": len(issues),
        "issues": issues,
        "valid": not issues,
    }
