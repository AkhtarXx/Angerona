"""Migrate authenticated snapshot raw function evidence into an isolated target tree."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from .evidence_signing import canonical_payload, sign_document
from .native_elf import parse_elf
from .raw_function_evidence import atomic_verified_copy, persist_raw_result, sha256_path
from .reconstruction_receipt import (
    FUNCTION_CLASSIFICATION_SCHEMA,
    FUNCTION_EXPORT_SCHEMA,
    _analysis_function_index,
    _atomic_json,
    _canonical_bytes,
    _function_validation_decision,
    _FUNCTION_VALIDATION_POLICY,
    _sha256_bytes,
    _toolchain_sha,
    invalid_function_classifier_identity,
)


MIGRATION_SCHEMA = "angerona/raw-evidence-migration/v1"


def _verify_signed_document(document: dict[str, Any], key: SigningKey) -> bool:
    body = {k: v for k, v in document.items() if k not in {"payload_sha256", "signature", "signature_key_id"}}
    payload = canonical_payload(body)
    if document.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
        return False
    try:
        key.verify_key.verify(payload, bytes.fromhex(str(document.get("signature") or "")))
        expected_id = hashlib.sha256(bytes(key.verify_key)).hexdigest()[:16]
        return document.get("signature_key_id") == expected_id and document.get("trust") == "operator_signed"
    except Exception:  # noqa: BLE001
        return False


def migrate_signed_snapshot(
    *, snapshot: Path, output_root: Path, target_sha256: str,
    epoch_id: str, pinned_key_path: Path,
) -> dict[str, Any]:
    snapshot = snapshot.resolve()
    output_root = output_root.resolve()
    if output_root.exists():
        raise ValueError("migration output already exists")
    if snapshot == output_root or snapshot in output_root.parents or output_root in snapshot.parents:
        raise ValueError("migration output must be isolated from snapshot")
    if not epoch_id.strip():
        raise ValueError("explicit migration epoch is required")
    key = SigningKey(pinned_key_path.read_bytes()[:32])
    receipt_path = snapshot / "SNAPSHOT_RECEIPT.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not _verify_signed_document(receipt, key):
        raise ValueError("snapshot receipt signature verification failed")
    if receipt.get("target_sha256") != target_sha256:
        raise ValueError("snapshot target SHA mismatch")
    manifest_path = snapshot / "FILE_SHA256_MANIFEST.json"
    if sha256_path(manifest_path) != (receipt.get("file_manifest") or {}).get("sha256"):
        raise ValueError("snapshot manifest file hash mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    unsigned_manifest = {k: v for k, v in manifest.items() if k != "payload_sha256"}
    if manifest.get("payload_sha256") != hashlib.sha256(canonical_payload(unsigned_manifest)).hexdigest():
        raise ValueError("snapshot manifest payload hash mismatch")
    authenticated = {
        str(row.get("snapshot_path")): row for row in manifest.get("files") or []
        if isinstance(row, dict)
    }
    for relative, row in authenticated.items():
        path = snapshot / relative
        if not path.is_file() or sha256_path(path) != row.get("sha256"):
            raise ValueError(f"snapshot file hash mismatch: {relative}")

    target = snapshot / "target_binary/libstumble.so"
    analysis_path = snapshot / "analysis/analysis.json"
    for required_relative, required_path in (
        ("target_binary/libstumble.so", target),
        ("analysis/analysis.json", analysis_path),
    ):
        required_row = authenticated.get(required_relative)
        if not isinstance(required_row, dict):
            raise ValueError(
                f"required snapshot input is not authenticated: {required_relative}"
            )
        required_sha256 = sha256_path(required_path)
        if required_row.get("sha256") != required_sha256:
            raise ValueError(
                f"authenticated snapshot input hash mismatch: {required_relative}"
            )
    if sha256_path(target) != target_sha256:
        raise ValueError("snapshot target binary hash mismatch")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    if str((analysis.get("metadata") or {}).get("sha256") or "") != target_sha256:
        raise ValueError("snapshot analysis target binding mismatch")
    binary_data = target.read_bytes()
    elf = parse_elf(binary_data)
    if elf is None:
        raise ValueError("snapshot target is not ELF")
    exec_ranges = [(int(start), int(start) + int(size)) for start, size in elf.exec_ranges() if size]
    function_index = _analysis_function_index(analysis)
    classifier = invalid_function_classifier_identity()

    output_cp = output_root / "reconstruction/function_exports"
    output_cp.mkdir(parents=True)
    source_cp = snapshot / "function_exports"
    pinned_exporter_identity_sha = ""
    for source in sorted(source_cp.glob("*.json")):
        relative = f"function_exports/{source.name}"
        row = authenticated.get(relative)
        if row is None or sha256_path(source) != row.get("sha256"):
            raise ValueError(f"checkpoint is not authenticated: {source.name}")
        checkpoint = json.loads(source.read_text(encoding="utf-8"))
        if checkpoint.get("schema") != FUNCTION_EXPORT_SCHEMA:
            raise ValueError(f"checkpoint schema mismatch: {source.name}")
        if checkpoint.get("target_sha256") != target_sha256:
            raise ValueError(f"checkpoint target SHA mismatch: {source.name}")
        identity = checkpoint.get("toolchain_identity")
        identity_sha = checkpoint.get("toolchain_identity_sha256")
        if not isinstance(identity, dict) or identity_sha != _toolchain_sha(identity):
            raise ValueError(f"checkpoint exporter identity invalid: {source.name}")
        if not pinned_exporter_identity_sha:
            pinned_exporter_identity_sha = str(identity_sha)
        elif identity_sha != pinned_exporter_identity_sha:
            raise ValueError("snapshot contains mixed exporter identities")
        atomic_verified_copy(source, output_cp / source.name)

    rows: list[dict[str, Any]] = []
    for checkpoint_path in sorted(output_cp.glob("*.json")):
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if checkpoint.get("schema") != FUNCTION_EXPORT_SCHEMA or checkpoint.get("status") != "error":
            continue
        entry = str(checkpoint.get("entry") or "").lower()
        prior_sha = sha256_path(checkpoint_path)
        raw_relative = f"raw_func_cache/func_{entry}.json"
        raw_row = authenticated.get(raw_relative)
        lineage = list(checkpoint.get("attempt_lineage") or [])
        lineage.append({
            "checkpoint_sha256": prior_sha,
            "attempt": checkpoint.get("attempt"),
            "status": checkpoint.get("status"),
            "migration_epoch_id": epoch_id,
        })
        provenance_body = {
            "schema": "angerona/signed-snapshot-import/v1",
            "target_sha256": target_sha256,
            "entry": entry,
            "migration_epoch_id": epoch_id,
            "source_checkpoint_path": f"function_exports/{checkpoint_path.name}",
            "source_checkpoint_sha256": prior_sha,
            "snapshot_receipt_sha256": sha256_path(receipt_path),
            "snapshot_manifest_sha256": sha256_path(manifest_path),
            "snapshot_signature_key_id": receipt.get("signature_key_id"),
            "snapshot_trust": receipt.get("trust"),
            "raw_snapshot_relative_path": raw_relative,
            "raw_snapshot_source_sha256": (
                raw_row.get("sha256") if isinstance(raw_row, dict) else None
            ),
        }
        provenance_receipt = {
            **provenance_body,
            "receipt_sha256": _sha256_bytes(_canonical_bytes(provenance_body)),
        }
        if raw_row is None:
            migrated = {
                **checkpoint,
                "supersedes_checkpoint_sha256": prior_sha,
                "attempt_lineage": lineage,
                "migration_epoch_id": epoch_id,
                "migration_disposition": "DEFERRED_NEEDS_ENGINE",
                "evidence_origin": "signed-snapshot-import",
                "snapshot_import_receipt": provenance_receipt,
                "validation_policy": _FUNCTION_VALIDATION_POLICY,
                "validation_facts": {},
                "validation_errors": ["signed snapshot contains no authenticated raw function result"],
            }
            _atomic_json(checkpoint_path, migrated)
            rows.append({
                "entry": entry,
                "disposition": "DEFERRED_NEEDS_ENGINE",
                "prior_checkpoint_sha256": prior_sha,
                "migrated_checkpoint_sha256": sha256_path(checkpoint_path),
            })
            continue
        raw_path = snapshot / raw_relative
        if sha256_path(raw_path) != raw_row.get("sha256"):
            raise ValueError(f"raw evidence hash mismatch: {entry}")
        result = json.loads(raw_path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("schema") != "angerona/1":
            raise ValueError(f"raw evidence schema mismatch: {entry}")
        if result.get("mode") != "function" or str(result.get("entry") or "").lower() != entry:
            raise ValueError(f"raw evidence mode/entry mismatch: {entry}")
        raw_evidence = persist_raw_result(
            output_root / "reconstruction", target_sha256=target_sha256,
            entry=entry, result=result,
        )
        facts, validation_errors, classification = _function_validation_decision(
            result, entry, analysis, exec_ranges, classifier, function_index,
        )
        result_sha = _sha256_bytes(_canonical_bytes(result))
        common = {
            **checkpoint,
            "result": result if classification else None,
            "result_sha256": result_sha if classification else None,
            "raw_evidence": raw_evidence,
            "validation_facts": facts,
            "validation_errors": validation_errors,
            "supersedes_checkpoint_sha256": prior_sha,
            "attempt_lineage": lineage,
            "migration_epoch_id": epoch_id,
            "evidence_origin": "signed-snapshot-import",
            "snapshot_import_receipt": provenance_receipt,
            "snapshot_receipt_sha256": sha256_path(receipt_path),
            "snapshot_manifest_sha256": sha256_path(manifest_path),
            "validation_policy": _FUNCTION_VALIDATION_POLICY,
        }
        if classification is not None:
            migrated = {
                **common,
                "status": "invalid_function_entry",
                "classification": classification,
                "classifier_identity": classifier,
                "migration_disposition": "classified_invalid",
                "error": None,
                "error_type": None,
            }
            disposition = "classified_invalid"
        else:
            migrated = {
                **common,
                "status": "error",
                "migration_disposition": "repair_pending",
            }
            disposition = "repair_pending"
        _atomic_json(checkpoint_path, migrated)
        rows.append({
            "entry": entry,
            "disposition": disposition,
            "prior_checkpoint_sha256": prior_sha,
            "migrated_checkpoint_sha256": sha256_path(checkpoint_path),
            "raw_evidence_sha256": raw_evidence["sha256"],
        })

    os.environ["ANGERONA_SIGNING_KEY_PATH"] = str(pinned_key_path)
    output_files = []
    for path in sorted((output_root / "reconstruction").rglob("*.json")):
        output_files.append({
            "path": path.relative_to(output_root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_path(path),
        })
    output_manifest = sign_document({
        "schema": "angerona/raw-evidence-migration-output-manifest/v1",
        "epoch_id": epoch_id,
        "target_sha256": target_sha256,
        "exporter_identity_sha256": pinned_exporter_identity_sha,
        "files": output_files,
    })
    output_manifest_path = output_root / "MIGRATION_OUTPUT_MANIFEST.json"
    _atomic_json(output_manifest_path, output_manifest)
    migration_receipt = sign_document({
        "schema": MIGRATION_SCHEMA,
        "epoch_id": epoch_id,
        "target_sha256": target_sha256,
        "source_snapshot": str(snapshot),
        "source_snapshot_receipt_sha256": sha256_path(receipt_path),
        "source_manifest_sha256": sha256_path(manifest_path),
        "output_root": str(output_root),
        "classifier_identity_sha256": _toolchain_sha(classifier),
        "exporter_identity_sha256": pinned_exporter_identity_sha,
        "output_manifest_path": output_manifest_path.name,
        "output_manifest_sha256": sha256_path(output_manifest_path),
        "output_manifest_payload_sha256": output_manifest.get("payload_sha256"),
        "output_file_count": len(output_files),
        "rows": rows,
    })
    _atomic_json(output_root / "RAW_EVIDENCE_MIGRATION_RECEIPT.json", migration_receipt)
    return migration_receipt
