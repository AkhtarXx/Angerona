"""Independent verifier for v3 DEX semantic method evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src.analysis.schema_validation import require_int_field


QUEUE_SCHEMAS = {
    "angerona/semantic-method-work-unit/v3": ("angerona/jadx-method-evidence/v3", "angerona/semantic-method-input-manifest/v1", "v3"),
    "angerona/semantic-method-work-unit/v4": ("angerona/jadx-method-evidence/v4", "angerona/semantic-method-input-manifest/v2", "v4"),
}


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_semantic_method_evidence(
    queue: str | Path,
    summary: str | Path,
    *,
    allowed_root: str | Path,
) -> dict[str, Any]:
    queue_path = Path(queue).resolve()
    summary_path = Path(summary).resolve()
    root = Path(allowed_root).resolve()
    summary_row = json.loads(summary_path.read_text(encoding="utf-8"))
    issues: list[dict[str, Any]] = []
    queue_schema = str(summary_row.get("schema") or "").replace("jadx-method-evidence", "semantic-method-work-unit")
    version_contract = QUEUE_SCHEMAS.get(queue_schema)
    if version_contract is None or summary_row.get("schema") != version_contract[0]:
        issues.append({"code": "SUMMARY_SCHEMA_MISMATCH"})
    if _sha(queue_path) != summary_row.get("work_units_sha256"):
        issues.append({"code": "WORK_STREAM_HASH_MISMATCH"})

    artifact_hashes: dict[Path, str] = {}
    unit_ids: set[str] = set()
    method_ids: set[str] = set()
    previous_unit_id: str | None = None
    rows = 0
    with queue_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            rows += 1
            try:
                unit = json.loads(line)
            except (TypeError, ValueError) as exc:
                issues.append({"code": "INVALID_JSON", "line": line_number, "detail": str(exc)})
                continue
            unit_id = str(unit.get("unit_id") or "")
            method_id = str(unit.get("method_id") or "")
            if unit.get("schema") != queue_schema:
                issues.append({"code": "QUEUE_SCHEMA_MISMATCH", "line": line_number})
                continue
            if not unit_id or unit_id in unit_ids:
                issues.append({"code": "DUPLICATE_OR_MISSING_UNIT", "line": line_number, "unit_id": unit_id})
                continue
            if previous_unit_id is not None and unit_id <= previous_unit_id:
                issues.append({
                    "code": "NON_CANONICAL_UNIT_ORDER", "line": line_number,
                    "unit_id": unit_id, "previous_unit_id": previous_unit_id,
                })
                continue
            if not method_id or method_id in method_ids:
                issues.append({"code": "DUPLICATE_OR_MISSING_METHOD", "line": line_number, "method_id": method_id})
                continue
            unit_ids.add(unit_id)
            previous_unit_id = unit_id
            method_ids.add(method_id)

            inputs = unit.get("inputs")
            if not isinstance(inputs, list):
                issues.append({"code": "INVALID_INPUT_LIST", "unit_id": unit_id})
                continue
            by_kind: dict[str, list[dict[str, Any]]] = {}
            input_valid = True
            for item in inputs:
                if not isinstance(item, dict) or not item.get("kind") or not item.get("path") or not item.get("sha256"):
                    issues.append({"code": "INVALID_INPUT", "unit_id": unit_id})
                    input_valid = False
                    continue
                path = Path(str(item["path"])).resolve()
                try:
                    path.relative_to(root)
                except ValueError:
                    issues.append({"code": "INPUT_PATH_ESCAPE", "unit_id": unit_id, "path": str(path)})
                    input_valid = False
                    continue
                if not path.is_file():
                    issues.append({"code": "MISSING_INPUT", "unit_id": unit_id, "path": str(path)})
                    input_valid = False
                    continue
                actual = artifact_hashes.setdefault(path, _sha(path))
                if actual != item["sha256"]:
                    issues.append({"code": "INPUT_HASH_MISMATCH", "unit_id": unit_id, "path": str(path)})
                    input_valid = False
                by_kind.setdefault(str(item["kind"]), []).append(item)
            required = {"dex-method-receipt", "smali-overlay", "smali-method-body"}
            if not required.issubset(by_kind) or any(len(by_kind[kind]) != 1 for kind in required if kind in by_kind):
                issues.append({"code": "REQUIRED_INPUT_SET_MISMATCH", "unit_id": unit_id})
                input_valid = False
            if not input_valid:
                continue

            if queue_schema.endswith("/v4"):
                for reference_item in by_kind.get("jadx-class-source-reference", []):
                    reference_path = Path(str(reference_item["path"])).resolve()
                    reference = json.loads(reference_path.read_text(encoding="utf-8"))
                    source_blob = Path(str(reference.get("source_blob") or "")).resolve()
                    try:
                        source_blob.relative_to(root)
                    except ValueError:
                        issues.append({"code": "SOURCE_BLOB_PATH_ESCAPE", "unit_id": unit_id})
                        input_valid = False
                        continue
                    if not source_blob.is_file() or _sha(source_blob) != reference.get("source_sha256"):
                        issues.append({"code": "SOURCE_BLOB_HASH_MISMATCH", "unit_id": unit_id})
                        input_valid = False
                    else:
                        try:
                            source_bytes = require_int_field(
                                reference, "source_bytes",
                                context="JADX source reference", minimum=0,
                            )
                        except ValueError as exc:
                            issues.append({"code": "SOURCE_BLOB_SIZE_INVALID", "unit_id": unit_id, "detail": str(exc)})
                            input_valid = False
                        else:
                            if source_blob.stat().st_size != source_bytes:
                                issues.append({"code": "SOURCE_BLOB_SIZE_MISMATCH", "unit_id": unit_id})
                                input_valid = False
                if not input_valid:
                    continue

            method_receipt = json.loads(Path(by_kind["dex-method-receipt"][0]["path"]).read_text(encoding="utf-8"))
            overlay = json.loads(Path(by_kind["smali-overlay"][0]["path"]).read_text(encoding="utf-8"))
            if method_receipt.get("method_id") != method_id or overlay.get("method_id") != method_id:
                issues.append({"code": "METHOD_ID_BINDING_MISMATCH", "unit_id": unit_id})
                continue
            body = by_kind["smali-method-body"][0]
            smali_root = Path(by_kind["smali-overlay"][0]["path"]).resolve().parent.parent
            expected_body = (smali_root / str(overlay.get("smali_blob") or "")).resolve()
            if Path(body["path"]).resolve() != expected_body or body["sha256"] != overlay.get("smali_sha256"):
                issues.append({"code": "SMALI_BODY_BINDING_MISMATCH", "unit_id": unit_id})
                continue
            dex_sha = str(method_receipt.get("dex_sha256") or "")
            input_manifest = {
                "schema": version_contract[1],
                "dex_sha256": dex_sha,
                "method_id": method_id,
                "qualified_name": unit.get("qualified_name"),
                "inputs": inputs,
            }
            manifest_sha = hashlib.sha256(_canonical(input_manifest)).hexdigest()
            if manifest_sha != unit.get("input_manifest_sha256"):
                issues.append({"code": "INPUT_MANIFEST_MISMATCH", "unit_id": unit_id})
                continue
            expected_unit = hashlib.sha256(
                f"{dex_sha}\0{method_id}\0{manifest_sha}\0semantic-reconstruction-{version_contract[2]}".encode()
            ).hexdigest()
            if expected_unit != unit_id:
                issues.append({"code": "UNIT_ID_MISMATCH", "unit_id": unit_id})

    try:
        expected_rows = require_int_field(
            summary_row, "code_method_work_units", context="method evidence summary", minimum=0,
        )
    except ValueError as exc:
        issues.append({"code": "WORK_UNIT_COUNT_INVALID", "observed": rows, "detail": str(exc)})
    else:
        if rows != expected_rows:
            issues.append({"code": "WORK_UNIT_COUNT_MISMATCH", "observed": rows})
    if not summary_row.get("all_code_methods_have_smali_body"):
        issues.append({"code": "SUMMARY_SMALI_BODY_GATE_FALSE"})
    return {
        "schema": "angerona/semantic-method-evidence-validation/v1",
        "queue_sha256": _sha(queue_path),
        "summary_sha256": _sha(summary_path),
        "units": rows,
        "unique_methods": len(method_ids),
        "unique_artifacts_rehashed": len(artifact_hashes),
        "issues": issues,
        "valid": not issues and rows > 0,
    }
