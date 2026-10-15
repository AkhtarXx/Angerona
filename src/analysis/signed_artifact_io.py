"""Canonical immutable I/O and validation for signed clean-audit artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .audit_lineage import open_verified_artifact
from .evidence_signing import canonical_payload, sign_document, verify_document
from .schema_validation import require_int_field


EXTRACTED_ENTITY_MANIFEST_SCHEMA = "angerona/extracted-entity-manifest/v1"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_signed_bytes(document: dict[str, Any]) -> bytes:
    return canonical_payload(document) + b"\n"


def write_signed_canonical(path: str | Path, body: dict[str, Any]) -> dict[str, str]:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = sign_document(body)
    if not verify_document(document, require_signature=True):
        raise ValueError("operator signing is required for canonical audit artifacts")
    payload = canonical_signed_bytes(document)
    if destination.exists():
        if destination.read_bytes() != payload:
            raise FileExistsError(f"refusing to replace immutable signed artifact: {destination}")
        return {"path": str(destination), "sha256": sha256_bytes(payload)}
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"path": str(destination), "sha256": sha256_bytes(payload)}


def load_signed_canonical(
    descriptor: dict[str, Any], roots: Iterable[str | Path], *, schema: str,
) -> tuple[Path, dict[str, Any]]:
    path, payload = open_verified_artifact(descriptor, roots)
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"signed {schema} artifact is not JSON") from exc
    if canonical_signed_bytes(document) != payload:
        raise ValueError(
            f"signed {schema} artifact has a noncanonical encoding; explicit signed migration is required"
        )
    if document.get("schema") != schema or not verify_document(document, require_signature=True):
        raise ValueError(f"signed {schema} artifact has an invalid schema/signature")
    return path, document


def extracted_manifest_bindings(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": plan["plan_id"],
        "routing_set_id": plan["routing_set_id"],
        "routing_plan_binding": {
            "plan_id": plan["plan_id"],
            "payload_sha256": plan.get("payload_sha256"),
            "signature_key_id": plan.get("signature_key_id"),
        },
        "ownership_policy": plan["ownership_policy"],
        "ownership_policy_id": plan["ownership_policy"]["policy_id"],
        "audit_epoch": plan.get("audit_epoch"),
    }


def validate_extracted_entity_manifest(
    document: dict[str, Any], plan: dict[str, Any],
) -> dict[str, Any]:
    if document.get("schema") != EXTRACTED_ENTITY_MANIFEST_SCHEMA:
        raise ValueError("unknown extracted entity manifest schema")
    for key, expected in extracted_manifest_bindings(plan).items():
        if document.get(key) != expected:
            raise ValueError(f"extracted entity manifest has mixed {key}")
    entities = document.get("entities")
    sources = document.get("source_artifacts")
    parents = document.get("parent_bindings")
    if not isinstance(entities, list) or not isinstance(sources, list) or not isinstance(parents, list):
        raise ValueError("extracted entity manifest sets must be arrays")
    entity_ids = [str(row.get("entity_id") or "") for row in entities if isinstance(row, dict)]
    if (
        len(entity_ids) != len(entities) or not all(entity_ids)
        or len(entity_ids) != len(set(entity_ids))
        or require_int_field(
            document, "entity_count", context="extracted entity manifest", minimum=0,
        ) != len(entities)
    ):
        raise ValueError("extracted entity manifest membership is incomplete or duplicated")
    if document.get("source_set_sha256") != sha256_bytes(canonical_payload(sources)):
        raise ValueError("extracted entity manifest source-set hash mismatch")
    normalized_parents = sorted(parents, key=lambda row: (str(row.get("path")), str(row.get("sha256"))))
    if parents != normalized_parents or len({(row.get("path"), row.get("sha256")) for row in parents}) != len(parents):
        raise ValueError("extracted entity manifest parent bindings are noncanonical or duplicated")
    return document


def migrate_legacy_extracted_entity_manifest(
    source_descriptor: dict[str, Any], roots: Iterable[str | Path],
    plan: dict[str, Any], output_path: str | Path,
) -> dict[str, str]:
    """Explicitly re-sign one legacy encoded manifest; normal reads never call this."""
    source_path, source_payload = open_verified_artifact(source_descriptor, roots)
    try:
        legacy = json.loads(source_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("legacy extracted manifest is not JSON") from exc
    if (
        legacy.get("schema") != EXTRACTED_ENTITY_MANIFEST_SCHEMA
        or not verify_document(legacy, require_signature=True)
        or legacy.get("plan_id") != plan["plan_id"]
        or legacy.get("routing_set_id") != plan["routing_set_id"]
        or legacy.get("ownership_policy_id") != plan["ownership_policy"]["policy_id"]
    ):
        raise ValueError("legacy extracted manifest signature/lineage is invalid")
    generated = {"payload_sha256", "signature", "signature_key_id", "trust"}
    body = {key: value for key, value in legacy.items() if key not in generated}
    sources = body.get("source_artifacts") or []
    body.update(extracted_manifest_bindings(plan))
    body["source_set_sha256"] = sha256_bytes(canonical_payload(sources))
    body["parent_bindings"] = sorted(
        [row for row in sources if isinstance(row, dict) and set(row) == {"path", "sha256"}],
        key=lambda row: (row["path"], row["sha256"]),
    )
    body["signed_migration"] = {
        "schema": "angerona/extracted-entity-manifest-migration/v1",
        "source": source_descriptor,
        "source_path": str(source_path),
        "reason": "legacy-noncanonical-encoding-and-missing-epoch-bindings",
    }
    descriptor = write_signed_canonical(output_path, body)
    _path, migrated = load_signed_canonical(
        descriptor, roots, schema=EXTRACTED_ENTITY_MANIFEST_SCHEMA,
    )
    validate_extracted_entity_manifest(migrated, plan)
    return descriptor
