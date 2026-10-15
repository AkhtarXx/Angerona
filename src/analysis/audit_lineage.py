"""Immutable audit epochs and fail-closed semantic checkpoint lineage."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from src.analysis.evidence_signing import (
    OPERATOR_SIGNED,
    canonical_payload,
    load_ed25519_private,
    sign_document,
    verify_document,
    verify_document_identity,
    with_document_identity,
)
from src.analysis.schema_validation import (
    canonical_order_rows,
    canonical_order_values,
    optional_int_field,
    require_canonical_ordered_field,
    require_dict_field,
    require_int_field,
    require_int_value,
    require_list_field,
)


EPOCH_SCHEMA = "angerona/audit-epoch/v1"
ANDROID_EPOCH_SCHEMA = "angerona/audit-epoch/v3"
CHECKPOINT_SCHEMA = "angerona/semantic-ai-checkpoint/v3"
CHECKPOINT_SET_SCHEMA = "angerona/semantic-checkpoint-set/v1"
DERIVED_QUEUE_SCHEMA = "angerona/derived-semantic-queue/v2"
APPLICATION_SURFACE_DERIVED_QUEUE_SCHEMA = "angerona/application-surface-derived-queue/v1"
TERMINAL_STATUSES = {"ok", "needs_evidence", "irrecoverable", "terminal_inconclusive"}
MAX_CLASS_EVIDENCE_DEPTH = 3
DERIVED_SUBJECT_FIELDS = (
    "class_id", "class_descriptors", "source_relative_path", "source_sha256",
    "source_bytes", "chunk_index", "chunk_count", "byte_start", "byte_end",
)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: str | Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def atomic_write(path: str | Path, payload: bytes, *, immutable: bool = False) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if immutable and destination.read_bytes() == payload:
            return
        if immutable:
            raise ValueError(f"immutable artifact already exists with different content: {destination}")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _normal_path(path: str | Path) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise ValueError(f"artifact path is not absolute: {raw}")
    lexical = Path(os.path.abspath(raw))
    resolved = raw.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"symlinked artifact path is forbidden: {raw}")
    return resolved


def _within(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def open_trusted_artifact(
    path: str | Path, allowed_roots: Iterable[str | Path],
) -> tuple[Path, bytes]:
    roots = [_normal_path(root) for root in allowed_roots]
    verified = _normal_path(path)
    if not _within(verified, roots):
        raise ValueError(f"artifact escapes trusted roots: {verified}")
    if not verified.is_file():
        raise ValueError(f"artifact is not a regular file: {verified}")
    return verified, verified.read_bytes()


def open_verified_artifact(
    item: dict[str, Any], allowed_roots: Iterable[str | Path],
) -> tuple[Path, bytes]:
    if not isinstance(item, dict) or not item.get("path") or not item.get("sha256"):
        raise ValueError("malformed artifact descriptor")
    path, payload = open_trusted_artifact(str(item["path"]), allowed_roots)
    actual = sha256_bytes(payload)
    if actual != str(item["sha256"]):
        raise ValueError(f"artifact hash mismatch: {path}")
    return path, payload


def open_epoch_queue(
    queue: str | Path, epoch: dict[str, Any], queue_name: str,
) -> tuple[Path, bytes]:
    descriptor = (epoch.get("queues") or {}).get(queue_name)
    if not isinstance(descriptor, dict):
        raise ValueError(f"audit epoch has no {queue_name!r} queue descriptor")
    expected_path, payload = open_verified_artifact(
        descriptor, epoch["trusted_read_roots"],
    )
    supplied_path = _normal_path(queue)
    if supplied_path != expected_path:
        raise ValueError(
            f"{queue_name} queue is not the exact audit-epoch queue: {supplied_path}"
        )
    return expected_path, payload


def create_audit_epoch(
    output_path: str | Path,
    *,
    apk: str | Path,
    inventory_manifest: str | Path,
    class_queue: str | Path,
    dex_method_queue: str | Path,
    epoch_output_root: str | Path,
    trusted_read_roots: Iterable[str | Path],
    model_alias: str,
    allowed_resolved_models: Iterable[str],
    dex_code_method_accounting: str | Path | None = None,
    native_queues: Iterable[str | Path] = (),
    operator_verify_key: str | Path,
    max_derived_depth: int = MAX_CLASS_EVIDENCE_DEPTH,
) -> dict[str, Any]:
    roots = sorted({str(_normal_path(root)) for root in trusted_read_roots})
    output_root = _normal_path(epoch_output_root)
    if str(output_root) not in roots:
        roots.append(str(output_root))
        roots.sort()
    verify_key_path = _normal_path(operator_verify_key)
    if _within(verify_key_path, [output_root]):
        raise ValueError("operator verify key must be outside the audit output root")
    verify_key = verify_key_path.read_bytes()
    if len(verify_key) != 32:
        raise ValueError("operator verify key must contain exactly 32 public-key bytes")
    signing_key, signing_key_id = load_ed25519_private()
    verify_key_id = hashlib.sha256(verify_key).hexdigest()[:16]
    if signing_key is None or bytes(signing_key.verify_key) != verify_key:
        raise ValueError("operator verify key does not match ANGERONA_SIGNING_KEY_PATH")
    if signing_key_id != verify_key_id:
        raise ValueError("operator signing and verify key IDs differ")
    if max_derived_depth < 1 or max_derived_depth > 32:
        raise ValueError("max_derived_depth must be between 1 and 32")
    if str(verify_key_path) not in roots:
        roots.append(str(verify_key_path))
        roots.sort()

    def artifact(path: str | Path) -> dict[str, str]:
        verified = _normal_path(path)
        if not _within(verified, [Path(root) for root in roots]):
            raise ValueError(f"epoch artifact escapes trusted roots: {verified}")
        return {"path": str(verified), "sha256": sha256_path(verified)}

    queues = {
        "class": artifact(class_queue),
        "dex_method": artifact(dex_method_queue),
    }
    for index, native_queue in enumerate(native_queues):
        queue_name = "native" if index == 0 else f"native_{index}"
        queues[queue_name] = artifact(native_queue)

    body: dict[str, Any] = {
        "schema": ANDROID_EPOCH_SCHEMA if dex_code_method_accounting is not None else EPOCH_SCHEMA,
        "apk": artifact(apk),
        "inventory_manifest": artifact(inventory_manifest),
        "queues": queues,
        "prompt_contracts": {
            "class": "angerona/dex-class-prompt/compact-semantic-range/v5",
            "class_consolidation": "angerona/dex-class-consolidation-prompt/v1",
        },
        "model_alias": model_alias,
        "allowed_resolved_models": sorted(set(allowed_resolved_models)),
        "trusted_read_roots": roots,
        "epoch_output_root": str(output_root),
        "operator_verify_key": {
            "path": str(verify_key_path),
            "sha256": sha256_bytes(verify_key),
            "key_id": verify_key_id,
        },
        "max_derived_depth": max_derived_depth,
    }
    if dex_code_method_accounting is not None:
        body["dex_code_method_accounting"] = artifact(dex_code_method_accounting)
    if not body["allowed_resolved_models"]:
        raise ValueError("at least one resolved model ID must be pinned")
    epoch = {**body, "epoch_id": sha256_bytes(canonical(body))}
    payload = canonical(epoch)
    atomic_write(output_path, payload, immutable=True)
    return epoch


def load_audit_epoch(path: str | Path) -> dict[str, Any]:
    epoch_path = _normal_path(path)
    epoch = json.loads(epoch_path.read_bytes())
    if not isinstance(epoch, dict) or epoch.get("schema") not in {EPOCH_SCHEMA, ANDROID_EPOCH_SCHEMA}:
        raise ValueError("unknown audit epoch schema")
    if epoch.get("schema") == ANDROID_EPOCH_SCHEMA and not epoch.get("dex_code_method_accounting"):
        raise ValueError("Android audit epoch v2 requires raw DEX accounting")
    unsigned = {key: value for key, value in epoch.items() if key != "epoch_id"}
    if epoch.get("epoch_id") != sha256_bytes(canonical(unsigned)):
        raise ValueError("audit epoch identity mismatch")
    roots = epoch.get("trusted_read_roots") or []
    if not roots:
        raise ValueError("audit epoch has no trusted read roots")
    for root in roots:
        _normal_path(root)
    for descriptor in [
        epoch.get("apk"), epoch.get("inventory_manifest"),
        *(epoch.get("queues") or {}).values(),
        *([epoch.get("dex_code_method_accounting")] if epoch.get("dex_code_method_accounting") else []),
        epoch.get("operator_verify_key"),
    ]:
        open_verified_artifact(descriptor, roots)
    verify_descriptor = epoch.get("operator_verify_key") or {}
    verify_path = _normal_path(str(verify_descriptor.get("path") or ""))
    if _within(verify_path, [_normal_path(str(epoch.get("epoch_output_root") or ""))]):
        raise ValueError("operator verify key is inside the audit output root")
    verify_bytes = verify_path.read_bytes()
    if (
        len(verify_bytes) != 32
        or verify_descriptor.get("key_id") != hashlib.sha256(verify_bytes).hexdigest()[:16]
    ):
        raise ValueError("operator verify key binding is invalid")
    configured_verify = os.environ.get("ANGERONA_VERIFY_KEY_PATH")
    if not configured_verify or _normal_path(configured_verify) != verify_path:
        raise ValueError("ANGERONA_VERIFY_KEY_PATH does not match the audit epoch")
    require_int_field(
        epoch, "max_derived_depth", context="audit epoch", minimum=1, maximum=32,
    )
    output_root = _normal_path(str(epoch.get("epoch_output_root") or ""))
    if not _within(output_root, [_normal_path(root) for root in roots]):
        raise ValueError("epoch output root is not trusted")
    if epoch.get("dex_code_method_accounting"):
        from src.analysis.dex_inventory_accounting import verify_dex_code_method_accounting
        verify_dex_code_method_accounting(
            epoch["dex_code_method_accounting"]["path"],
            allowed_roots=epoch["trusted_read_roots"],
            verification_root=str(output_root / "dex-accounting-verification-cache"),
        )
    return epoch


def queue_matches_epoch(queue: str | Path, epoch: dict[str, Any]) -> str:
    queue_path = _normal_path(queue)
    digest = sha256_path(queue_path)
    surface_lineage_path = queue_path.with_name(queue_path.name + ".lineage.json")
    if surface_lineage_path.is_file():
        _surface_path, surface_payload = open_trusted_artifact(
            surface_lineage_path, [epoch["epoch_output_root"]],
        )
        try:
            surface_schema = json.loads(surface_payload).get("schema")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("derived queue lineage is not JSON") from exc
        if surface_schema == APPLICATION_SURFACE_DERIVED_QUEUE_SCHEMA:
            _verify_application_surface_derived_queue(queue_path, epoch)
            return digest
        if surface_schema == "angerona/dynamic-security-derived-queue/v1":
            from src.analysis.dynamic_security_planner import verify_dynamic_security_queue
            return verify_dynamic_security_queue(queue_path, epoch)
    for item in (epoch.get("queues") or {}).values():
        if not isinstance(item, dict):
            continue
        if str(item.get("path")) == str(queue_path):
            verified_path, payload = open_verified_artifact(
                item, epoch["trusted_read_roots"],
            )
            if verified_path != queue_path:
                raise ValueError("epoch queue path identity mismatch")
            return sha256_bytes(payload)
    lineage_path = queue_path.with_name(queue_path.name + ".lineage.json")
    if lineage_path.is_file():
        _lineage_path, lineage_payload = open_trusted_artifact(
            lineage_path, [epoch["epoch_output_root"]],
        )
        try:
            lineage_schema = json.loads(lineage_payload).get("schema")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("derived queue lineage is not JSON") from exc
        if lineage_schema == APPLICATION_SURFACE_DERIVED_QUEUE_SCHEMA:
            _verify_application_surface_derived_queue(queue_path, epoch)
            return digest
        if lineage_schema == "angerona/dynamic-security-derived-queue/v1":
            from src.analysis.dynamic_security_planner import verify_dynamic_security_queue
            return verify_dynamic_security_queue(queue_path, epoch)
    _verify_derived_queue_lineage(queue_path, epoch, set(), {}, {})
    return digest


def _verify_application_surface_derived_queue(
    queue_path: Path, epoch: dict[str, Any],
) -> dict[str, Any]:
    queue_path = _normal_path(queue_path)
    digest = sha256_path(queue_path)
    output_root = _normal_path(str(epoch["epoch_output_root"]))
    if not _within(queue_path, [output_root]):
        raise ValueError("application-surface queue escapes epoch output root")
    lineage_path = queue_path.with_name(queue_path.name + ".lineage.json")
    _path, payload = open_trusted_artifact(lineage_path, [output_root])
    lineage = json.loads(payload)
    if (
        lineage.get("schema") != APPLICATION_SURFACE_DERIVED_QUEUE_SCHEMA
        or not verify_document(lineage, require_signature=True)
    ):
        raise ValueError("application-surface derived queue signature/schema is invalid")
    if not verify_document_identity(lineage):
        raise ValueError("application-surface derived queue self-hash mismatch")
    units = _load_queue(queue_path)
    if lineage.get("audit_epoch_id") != epoch["epoch_id"]:
        raise ValueError("application-surface lineage audit_epoch_id mismatch")
    if lineage.get("queue_path") != str(queue_path):
        raise ValueError("application-surface lineage queue_path mismatch")
    if lineage.get("queue_sha256") != digest:
        raise ValueError("application-surface lineage queue_sha256 mismatch")
    if require_int_field(
        lineage, "unit_count", context="application-surface lineage", minimum=0,
    ) != len(units):
        raise ValueError("application-surface lineage unit_count mismatch")
    if lineage.get("derivation_semantics") != "ownership-neutral-application-surface":
        raise ValueError("application-surface lineage derivation_semantics mismatch")
    manifest_path, manifest_payload = open_verified_artifact(
        lineage.get("derivation_manifest"), epoch["trusted_read_roots"],
    )
    manifest = json.loads(manifest_payload)
    if manifest.get("schema") != "angerona/application-surface-queue/v1":
        raise ValueError("application-surface queue manifest schema mismatch")
    if not verify_document(manifest, require_signature=True):
        raise ValueError("application-surface queue manifest signature mismatch")
    expected_manifest_fields = {
        "queue": {"path": str(queue_path), "sha256": digest},
        "plan_id": lineage.get("plan_id"),
        "routing_plan": lineage.get("routing_plan"),
        "routing_set_id": lineage.get("routing_set_id"),
        "ownership_policy": lineage.get("ownership_policy"),
        "occurrence_index": lineage.get("occurrence_index"),
        "source_extracted_manifests": lineage.get("source_extracted_manifests"),
    }
    for field, expected in expected_manifest_fields.items():
        if manifest.get(field) != expected:
            raise ValueError(f"application-surface queue manifest {field} mismatch")
    audit_epoch = require_dict_field(
        manifest, "audit_epoch", context="application-surface queue manifest",
    )
    if audit_epoch.get("epoch_id") != epoch["epoch_id"]:
        raise ValueError("application-surface queue manifest audit_epoch mismatch")
    if manifest.get("ownership_claimed") is not False:
        raise ValueError("application-surface queue manifest ownership_claimed must be false")
    if require_int_field(
        manifest, "code_entity_unit_count",
        context="application-surface queue manifest", minimum=0,
    ) != 0:
        raise ValueError("application-surface queue manifest contains code-owned units")
    if require_canonical_ordered_field(
        manifest, "unit_ids", context="application-surface queue manifest",
    ) != [str(unit["unit_id"]) for unit in units]:
        raise ValueError("application-surface queue manifest unit_ids mismatch")
    if str(manifest_path) != lineage["derivation_manifest"]["path"]:
        raise ValueError("application-surface queue manifest path mismatch")
    _plan_path, plan_payload = open_verified_artifact(
        lineage.get("routing_plan"), epoch["trusted_read_roots"],
    )
    plan = json.loads(plan_payload)
    if (
        plan.get("schema") != "angerona/clean-apk-routing-plan/v1"
        or not verify_document(plan, require_signature=True)
        or not verify_document_identity(plan)
        or plan.get("plan_id") != lineage.get("plan_id")
        or plan.get("routing_set_id") != lineage.get("routing_set_id")
        or plan.get("ownership_policy") != lineage.get("ownership_policy")
        or plan.get("audit_epoch", {}).get("epoch_id") != epoch["epoch_id"]
    ):
        raise ValueError("application-surface derived queue routing plan is invalid")
    _policy_path, policy_payload = open_verified_artifact(
        lineage.get("ownership_policy"), epoch["trusted_read_roots"],
    )
    policy = json.loads(policy_payload)
    if (
        policy.get("schema") != "angerona/audit-ownership-policy/v1"
        or not verify_document(policy, require_signature=True)
        or not verify_document_identity(policy)
        or policy.get("policy_id") != lineage.get("ownership_policy", {}).get("policy_id")
    ):
        raise ValueError("application-surface derived queue ownership policy is invalid")
    _occurrence_path, occurrence_payload = open_verified_artifact(
        lineage.get("occurrence_index"), epoch["trusted_read_roots"],
    )
    occurrence_index = json.loads(occurrence_payload)
    if (
        occurrence_index.get("schema") != "angerona/application-surface-occurrence-index/v1"
        or not verify_document(occurrence_index, require_signature=True)
        or occurrence_index.get("plan_id") != lineage.get("plan_id")
        or occurrence_index.get("routing_set_id") != lineage.get("routing_set_id")
        or occurrence_index.get("ownership_policy") != lineage.get("ownership_policy")
        or occurrence_index.get("audit_epoch", {}).get("epoch_id") != epoch["epoch_id"]
    ):
        raise ValueError("application-surface occurrence index lineage is invalid")
    occurrence_rows = require_canonical_ordered_field(
        occurrence_index, "occurrences", context="application-surface occurrence index",
    )
    if require_int_field(
        occurrence_index, "occurrence_count",
        context="application-surface occurrence index", minimum=0,
    ) != len(occurrence_rows):
        raise ValueError("application-surface occurrence count mismatch")
    occurrences = {str(row.get("occurrence_id") or ""): row for row in occurrence_rows}
    if len(occurrences) != len(occurrence_rows) or "" in occurrences:
        raise ValueError("application-surface occurrence index identities are duplicated")
    artifact_cache: dict[tuple[str, str], bytes] = {}
    for occurrence in occurrence_rows:
        artifact = occurrence.get("artifact")
        key = (str((artifact or {}).get("path") or ""), str((artifact or {}).get("sha256") or ""))
        if key not in artifact_cache:
            _artifact_path, artifact_cache[key] = open_verified_artifact(
                artifact, epoch["trusted_read_roots"],
            )
        start, end = occurrence.get("byte_start"), occurrence.get("byte_end")
        if (
            not isinstance(start, int) or isinstance(start, bool)
            or not isinstance(end, int) or isinstance(end, bool)
            or start < 0 or end <= start or end > len(artifact_cache[key])
            or sha256_bytes(artifact_cache[key][start:end]) != occurrence.get("excerpt_sha256")
        ):
            raise ValueError("application-surface occurrence bytes/hash are invalid")
    for unit in units:
        unit_occurrences = require_canonical_ordered_field(
            unit, "occurrences", context=f"application-surface unit {unit['unit_id']}",
        )
        require_canonical_ordered_field(
            unit, "occurrence_ids", context=f"application-surface unit {unit['unit_id']}",
        )
        if (
            [row.get("occurrence_id") for row in unit_occurrences] != unit.get("occurrence_ids")
            or any(occurrences.get(str(row.get("occurrence_id") or "")) != row for row in unit_occurrences)
        ):
            raise ValueError("application-surface unit occurrence membership differs from signed index")
    parents = require_canonical_ordered_field(
        lineage, "parent_receipts", context="application-surface lineage",
    )
    manifest_parents = require_canonical_ordered_field(
        manifest, "parent_receipts", context="application-surface queue manifest",
    )
    require_canonical_ordered_field(
        lineage, "source_extracted_manifests", context="application-surface lineage",
    )
    require_canonical_ordered_field(
        manifest, "source_extracted_manifests",
        context="application-surface queue manifest",
    )
    if not parents or parents != manifest_parents:
        raise ValueError("application-surface exact parent receipt set mismatch")
    if lineage.get("parent_set_sha256") != sha256_bytes(canonical_payload(parents)):
        raise ValueError("application-surface parent-set hash mismatch")
    parent_keys = {(str(row.get("path") or ""), str(row.get("sha256") or "")) for row in parents}
    if len(parent_keys) != len(parents) or any(not all(key) for key in parent_keys):
        raise ValueError("application-surface parent receipts are duplicated or malformed")
    expected_parent_schemas = {
        "angerona/deterministic-artifact-parse-receipt/v1",
        "angerona/dex-ownership-index-receipt/v1",
        "angerona/hermes-ownership-index-receipt/v1",
    }
    observed_parent_schemas: set[str] = set()
    observed_source_manifests: list[dict[str, Any]] = []
    for parent in parents:
        _parent_path, parent_payload = open_verified_artifact(parent, epoch["trusted_read_roots"])
        parent_document = json.loads(parent_payload)
        if (
            parent_document.get("schema") not in expected_parent_schemas
            or parent_document.get("schema") in observed_parent_schemas
            or not verify_document(parent_document, require_signature=True)
            or parent_document.get("plan_id") != lineage.get("plan_id")
            or parent_document.get("routing_set_id") != lineage.get("routing_set_id")
            or parent_document.get("ownership_policy") != lineage.get("ownership_policy")
            or parent_document.get("audit_epoch", {}).get("epoch_id") != epoch["epoch_id"]
        ):
            raise ValueError("application-surface parent receipt has mixed lineage")
        observed_parent_schemas.add(str(parent_document["schema"]))
        source_manifest = parent_document.get("extracted_entity_manifest")
        if not isinstance(source_manifest, dict):
            raise ValueError("application-surface parent lacks extracted manifest descriptor")
        open_verified_artifact(source_manifest, epoch["trusted_read_roots"])
        observed_source_manifests.append(source_manifest)
    if observed_parent_schemas != expected_parent_schemas:
        raise ValueError("application-surface derived queue lacks an exact lane parent set")
    expected_sources = sorted(
        lineage.get("source_extracted_manifests") or [],
        key=lambda row: (str(row.get("path")), str(row.get("sha256"))),
    )
    if sorted(observed_source_manifests, key=lambda row: (row["path"], row["sha256"])) != expected_sources:
        raise ValueError("application-surface derived queue source manifests differ from lane parents")
    return {
        "lineage_path": str(lineage_path), "lineage_sha256": sha256_bytes(payload),
        "derivation_manifest_path": str(manifest_path),
        "derivation_manifest_sha256": sha256_bytes(manifest_payload), "receipt": lineage,
    }


def _verify_derived_queue_lineage(
    queue_path: Path,
    epoch: dict[str, Any],
    visiting: set[tuple[str, str]],
    lineage_memo: dict[tuple[str, str], dict[str, Any]],
    set_memo: dict[tuple[str, str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    queue_path = _normal_path(queue_path)
    digest = sha256_path(queue_path)
    queue_key = (str(queue_path), digest)
    if queue_key in lineage_memo:
        return lineage_memo[queue_key]
    if queue_key in visiting:
        raise ValueError(f"derived queue ancestry cycle: {queue_path}")
    visiting.add(queue_key)
    output_root = _normal_path(str(epoch["epoch_output_root"]))
    if not _within(queue_path, [output_root]):
        raise ValueError(f"derived queue escapes epoch output root: {queue_path}")
    lineage_path = _normal_path(queue_path.with_name(queue_path.name + ".lineage.json"))
    if not _within(lineage_path, [output_root]):
        raise ValueError("derived queue lineage escapes epoch output root")
    lineage_path, lineage_payload = open_trusted_artifact(
        lineage_path, [output_root],
    )
    lineage = json.loads(lineage_payload)
    if lineage.get("schema") != DERIVED_QUEUE_SCHEMA:
        raise ValueError(f"derived queue lacks a valid lineage receipt: {queue_path}")
    if not verify_document(lineage, require_signature=True):
        raise ValueError("derived queue lineage operator signature is invalid")
    if not verify_document_identity(lineage):
        raise ValueError("derived queue lineage self-hash mismatch")
    if (
        lineage.get("audit_epoch_id") != epoch["epoch_id"]
        or lineage.get("queue_path") != str(queue_path)
        or lineage.get("queue_sha256") != digest
    ):
        raise ValueError("derived queue lineage identity mismatch")

    queue_units = _load_queue(queue_path)
    if require_int_field(
        lineage, "unit_count", context="derived queue lineage", minimum=0,
    ) != len(queue_units):
        raise ValueError("derived queue lineage unit count mismatch")
    manifest_path, manifest_payload = open_verified_artifact(
        lineage.get("derivation_manifest"), epoch["trusted_read_roots"],
    )
    derivation = json.loads(manifest_payload)
    if derivation.get("schema") not in {
        "angerona/class-evidence-resolution/v1",
        "angerona/class-consolidation-manifest/v1",
    }:
        raise ValueError(f"unknown derived queue manifest schema: {manifest_path}")
    if not verify_document_identity(derivation):
        raise ValueError("derived queue manifest self-hash mismatch")
    generation = require_dict_field(
        derivation, "generation", context="derived queue manifest",
    )
    if derivation.get("audit_epoch_id") != epoch["epoch_id"]:
        raise ValueError("derived queue manifest audit_epoch_id mismatch")
    if generation.get("queue_path") != str(queue_path):
        raise ValueError("derived queue manifest generation.queue_path mismatch")
    if generation.get("queue_sha256") != digest:
        raise ValueError("derived queue manifest generation.queue_sha256 mismatch")
    if require_int_field(
        generation, "unit_count", context="derived queue manifest generation", minimum=0,
    ) != len(queue_units):
        raise ValueError("derived queue manifest generation.unit_count mismatch")
    lineage_parents = require_canonical_ordered_field(
        lineage, "parent_checkpoint_sets", context="derived queue lineage",
    )
    manifest_parents = require_canonical_ordered_field(
        derivation, "parent_checkpoint_sets", context="derived queue manifest",
    )
    if lineage_parents != manifest_parents or not lineage_parents:
        raise ValueError("derived queue parent checkpoint sets mismatch or empty")
    parent_keys = {
        (str(row.get("path") or ""), str(row.get("sha256") or ""))
        for row in lineage_parents
    }
    parent_hashes = {parent_digest for _path, parent_digest in parent_keys if parent_digest}
    if len(parent_keys) != len(lineage_parents) or len(parent_hashes) != len(lineage_parents):
        raise ValueError("derived queue parent checkpoint sets are not unique")
    parent_owners: dict[
        str,
        tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]],
    ] = {}
    for parent in lineage_parents:
        parent_path, parent_payload = open_verified_artifact(parent, epoch["trusted_read_roots"])
        parent_set = json.loads(parent_payload)
        parent_queue = _normal_path(str(parent_set.get("queue_path") or ""))
        verified_parent = _verify_checkpoint_set_with_epoch(
            parent_path,
            parent_payload,
            parent_queue,
            epoch,
            visiting,
            lineage_memo,
            set_memo,
        )
        parent_entries = {
            str(entry.get("unit_id") or ""): entry
            for entry in require_list_field(
                verified_parent, "entries", context="parent checkpoint set",
            )
        }
        parent_units = {
            str(unit["unit_id"]): unit for unit in _load_queue(parent_queue)
        }
        if list(parent_entries) != list(parent_units):
            raise ValueError(
                f"derived queue parent unit accounting changed: {parent_path}"
            )
        parent_owners[str(parent["sha256"])] = (parent_entries, parent_units)

    edges: list[dict[str, str]] = []
    child_ids = {str(unit["unit_id"]) for unit in queue_units}
    for unit in queue_units:
        unit_id = str(unit["unit_id"])
        bindings = unit.get("parent_bindings") or []
        if not isinstance(bindings, list) or not bindings:
            raise ValueError(f"derived unit has no canonical parent bindings: {unit_id}")
        ordered_bindings = canonical_order_rows(
            "angerona/canonical-derived-unit/v1", "parent_bindings", bindings,
            context=f"derived unit {unit_id}",
        )
        if bindings != ordered_bindings:
            raise ValueError(f"derived unit parent bindings are not canonical: {unit_id}")
        binding_keys: set[tuple[str, str]] = set()
        parents: list[dict[str, Any]] = []
        parent_roots: set[str] = set()
        parent_depths: list[int] = []
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {
                "checkpoint_set_sha256", "unit_id", "response_sha256",
            }:
                raise ValueError(f"derived unit has malformed parent binding: {unit_id}")
            source_set_sha = str(binding.get("checkpoint_set_sha256") or "")
            parent_id = str(binding.get("unit_id") or "")
            binding_key = (source_set_sha, parent_id)
            if binding_key in binding_keys:
                raise ValueError(f"derived unit repeats a parent binding: {unit_id}")
            binding_keys.add(binding_key)
            parent_owner = parent_owners.get(source_set_sha)
            if parent_owner is None:
                raise ValueError(f"derived unit has unknown parent set: {unit_id}")
            parent_entries, parent_units = parent_owner
            parent_entry = parent_entries.get(parent_id)
            parent_unit = parent_units.get(parent_id)
            if parent_entry is None or parent_unit is None:
                raise ValueError(f"derived unit parent is absent from its set: {unit_id}")
            if (
                not binding.get("response_sha256")
                or binding.get("response_sha256") != parent_entry.get("response_sha256")
            ):
                raise ValueError(f"derived unit parent response binding mismatch: {unit_id}")
            parents.append(parent_unit)
            parent_depths.append(optional_int_field(
                parent_unit, "evidence_depth", default=0,
                context=f"parent unit {parent_id}", minimum=0,
            ))
            parent_roots.update(
                str(value) for value in (
                    parent_unit.get("root_unit_ids")
                    or [parent_unit.get("root_unit_id") or parent_unit["unit_id"]]
                ) if value
            )
            edges.append({
                "parent_checkpoint_set_sha256": source_set_sha,
                "parent_unit_id": parent_id,
                "child_unit_id": unit_id,
            })
        depth = require_int_field(
            unit, "evidence_depth", context=f"derived unit {unit_id}", minimum=1,
        )
        raw_roots = unit.get("root_unit_ids") or []
        roots = canonical_order_values(
            "angerona/canonical-derived-unit/v1", "root_unit_ids", raw_roots,
            context=f"derived unit {unit_id}",
        )
        if (
            not roots
            or roots != sorted(parent_roots)
            or depth != max(parent_depths) + 1
            or depth < 1
            or depth > int(epoch["max_derived_depth"])
        ):
            raise ValueError(f"derived unit has invalid root/depth lineage: {unit_id}")
        for field in ("class_id", "method_id", "function_id", "target_sha256", "source_sha256"):
            parent_values = {parent.get(field) for parent in parents if parent.get(field) is not None}
            if len(parent_values) > 1 or (parent_values and unit.get(field) not in parent_values):
                raise ValueError(f"derived unit changed subject identity field {field}: {unit_id}")
        if unit_id in {edge["parent_unit_id"] for edge in edges if edge["child_unit_id"] == unit_id}:
            raise ValueError(f"derived queue contains a self-cycle: {unit_id}")
    edges.sort(key=lambda row: (
        row["child_unit_id"], row["parent_checkpoint_set_sha256"], row["parent_unit_id"],
    ))
    if edges != (lineage.get("parent_edges") or []):
        raise ValueError("derived queue signed parent-edge DAG mismatch")
    if lineage.get("parent_edge_sha256") != sha256_bytes(canonical_payload(edges)):
        raise ValueError("derived queue parent-edge DAG hash mismatch")
    if {edge["parent_checkpoint_set_sha256"] for edge in edges} != parent_hashes:
        raise ValueError("derived queue parent-set declaration is not exactly used by DAG edges")
    if any(edge["parent_unit_id"] in child_ids for edge in edges):
        raise ValueError("derived queue references a same-generation parent")
    result = {
        "lineage_path": str(lineage_path),
        "lineage_sha256": sha256_bytes(lineage_payload),
        "derivation_manifest_path": str(manifest_path),
        "derivation_manifest_sha256": sha256_bytes(manifest_payload),
        "receipt": lineage,
    }
    visiting.remove(queue_key)
    lineage_memo[queue_key] = result
    return result


def verify_derived_queue_lineage(
    queue: str | Path, epoch_path: str | Path,
) -> dict[str, Any]:
    epoch = load_audit_epoch(epoch_path)
    return _verify_derived_queue_lineage(Path(queue), epoch, set(), {}, {})


def write_derived_queue_lineage(
    queue: str | Path,
    epoch_path: str | Path,
    *,
    derivation_manifest: dict[str, Any],
    parent_checkpoint_sets: list[dict[str, Any]],
    unit_count: int,
) -> dict[str, Any]:
    epoch = load_audit_epoch(epoch_path)
    queue_path = output_is_in_epoch(Path(queue).parent, epoch) / Path(queue).name
    queue_path = _normal_path(queue_path)
    roots = epoch["trusted_read_roots"]
    open_verified_artifact(derivation_manifest, roots)
    for item in parent_checkpoint_sets:
        open_verified_artifact(item, roots)
    queue_units = _load_queue(queue_path)
    parent_edges: list[dict[str, str]] = []
    for unit in queue_units:
        for binding in require_list_field(
            unit, "parent_bindings", context=f"derived unit {unit['unit_id']}",
        ):
            parent_edges.append({
                "parent_checkpoint_set_sha256": str(binding.get("checkpoint_set_sha256") or ""),
                "parent_unit_id": str(binding.get("unit_id") or ""),
                "child_unit_id": str(unit["unit_id"]),
            })
    parent_edges.sort(key=lambda row: (
        row["child_unit_id"], row["parent_checkpoint_set_sha256"], row["parent_unit_id"],
    ))
    if not parent_edges or any(not all(row.values()) for row in parent_edges):
        raise ValueError("derived queue has incomplete parent-edge bindings")
    body = {
        "schema": DERIVED_QUEUE_SCHEMA,
        "audit_epoch_id": epoch["epoch_id"],
        "queue_path": str(queue_path),
        "queue_sha256": sha256_path(queue_path),
        "unit_count": require_int_value(unit_count, field="derived queue unit_count", minimum=0),
        "derivation_manifest": derivation_manifest,
        "parent_checkpoint_sets": sorted(
            parent_checkpoint_sets, key=lambda row: (str(row["path"]), str(row["sha256"])),
        ),
        "parent_edges": parent_edges,
        "parent_edge_sha256": sha256_bytes(canonical_payload(parent_edges)),
        "max_depth": max(require_int_field(
            unit, "evidence_depth", context=f"derived unit {unit['unit_id']}", minimum=1,
        ) for unit in queue_units),
    }
    receipt = sign_document(with_document_identity(body))
    if receipt.get("trust") != OPERATOR_SIGNED:
        raise ValueError("derived queue lineage signing requires ANGERONA_SIGNING_KEY_PATH")
    atomic_write(
        queue_path.with_name(queue_path.name + ".lineage.json"), canonical(receipt), immutable=True,
    )
    return receipt


def output_is_in_epoch(output: str | Path, epoch: dict[str, Any]) -> Path:
    raw = Path(output)
    raw.mkdir(parents=True, exist_ok=True)
    resolved = _normal_path(raw)
    root = _normal_path(str(epoch["epoch_output_root"]))
    if not _within(resolved, [root]):
        raise ValueError(f"semantic output escapes epoch output root: {resolved}")
    return resolved


def _extract_response_result(response: dict[str, Any], class_prefill: bool) -> dict[str, Any]:
    if response.get("stop_reason") == "max_tokens":
        raise ValueError("stored response was truncated at max_tokens")
    text = "\n".join(
        str(row.get("text") or "") for row in response.get("content") or []
        if isinstance(row, dict) and row.get("type") == "text"
    ).strip()
    candidates = [text]
    if class_prefill and not text.startswith("{"):
        candidates.append("{" + text)
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            if "surface_review" in value:
                if set(value) != {
                    "class_id", "input_manifest_sha256", "status", "surface_review",
                    "security_candidates", "evidence_requests", "limitations",
                } or value.get("security_candidates") != []:
                    raise ValueError("application-surface response violates strict non-adjudicating schema")
                review = value.get("surface_review")
                if (
                    not isinstance(review, dict)
                    or set(review) != {
                        "language", "adjudication_status", "reviewed_range", "summary", "observations",
                    }
                    or review.get("language") != "android-application-surface"
                    or review.get("adjudication_status") != "not_adjudicated"
                    or not isinstance(review.get("observations"), list)
                ):
                    raise ValueError("application-surface response review schema is invalid")
                for observation in review["observations"]:
                    if (
                        not isinstance(observation, dict)
                        or set(observation) != {"category", "statement", "occurrence_ids", "confidence"}
                        or observation.get("category") not in {
                            "manifest", "configuration", "network", "webview", "cordova",
                            "permission", "component", "endpoint", "certificate",
                        }
                        or observation.get("confidence") not in {"high", "medium", "low"}
                        or not str(observation.get("statement") or "").strip()
                        or not isinstance(observation.get("occurrence_ids"), list)
                        or not observation["occurrence_ids"]
                    ):
                        raise ValueError("application-surface response observation schema is invalid")
                requests = value.get("evidence_requests")
                limitations = value.get("limitations")
                if (
                    not isinstance(requests, list) or not isinstance(limitations, list)
                    or any(
                        not isinstance(request, dict)
                        or set(request) != {"kind", "target", "reason"}
                        or request.get("kind") not in {"manifest", "resource", "configuration", "certificate", "runtime"}
                        or not str(request.get("target") or "").strip()
                        or not str(request.get("reason") or "").strip()
                        for request in requests
                    )
                    or any(not isinstance(item, str) or not item.strip() for item in limitations)
                ):
                    raise ValueError("application-surface response request/limitation schema is invalid")
            return value
    raise ValueError("stored response does not contain one valid JSON object")


def verify_semantic_checkpoint(
    checkpoint_path: str | Path,
    unit: dict[str, Any],
    epoch: dict[str, Any],
    checkpoint_root: str | Path,
    *,
    allow_retryable: bool = False,
    allow_history: bool = False,
) -> dict[str, Any]:
    root = output_is_in_epoch(checkpoint_root, epoch)
    path = _normal_path(checkpoint_path)
    payload = path.read_bytes()
    checkpoint = json.loads(payload)
    if allow_history:
        history_root = root / "checkpoint-history" / str(checkpoint.get("unit_id") or "")
        if (
            not _within(path, [history_root])
            or path.parent != history_root
            or path.name != f"{sha256_bytes(payload)}.json"
        ):
            raise ValueError(f"checkpoint escapes exact history directory: {path}")
    else:
        checkpoints_root = root / "checkpoints"
        if not _within(path, [checkpoints_root]) or path.parent != checkpoints_root:
            raise ValueError(f"checkpoint escapes exact checkpoint directory: {path}")
    queue_sha = queue_matches_epoch(str(checkpoint.get("queue_path") or ""), epoch)
    expected_prompt = (
        "angerona/application-surface-prompt/occurrence-bound-concise/v2"
        if unit.get("schema") == "angerona/application-surface-work-unit/v1"
        else (
            "angerona/dynamic-security-prompt/graph-derived-untrusted-knowledge/v2"
            if unit.get("knowledge_pack")
            else "angerona/dynamic-security-prompt/graph-derived-hypotheses/v1"
        )
        if unit.get("schema") == "angerona/dynamic-security-work-unit/v1"
        else epoch["prompt_contracts"]["class_consolidation"]
        if unit.get("unit_kind") == "jadx_class_consolidation"
        else epoch["prompt_contracts"]["class"] if unit.get("class_id") else checkpoint.get("prompt_contract")
    )
    identities = [key for key in ("method_id", "function_id", "class_id") if unit.get(key)]
    if checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        raise ValueError("checkpoint is not hardened schema v3")
    if checkpoint.get("audit_epoch_id") != epoch["epoch_id"]:
        raise ValueError("checkpoint audit epoch mismatch")
    if checkpoint.get("queue_sha256") != queue_sha:
        raise ValueError("checkpoint queue hash mismatch")
    if checkpoint.get("unit_id") != unit.get("unit_id"):
        raise ValueError("checkpoint unit mismatch")
    if checkpoint.get("input_manifest_sha256") != unit.get("input_manifest_sha256"):
        raise ValueError("checkpoint input manifest mismatch")
    for field in (
        "knowledge_pack", "knowledge_pack_id",
        "knowledge_retrieval", "knowledge_retrieval_id",
    ):
        if checkpoint.get(field) != unit.get(field):
            raise ValueError(f"checkpoint {field} binding mismatch")
    if len(identities) != 1 or checkpoint.get(identities[0]) != unit.get(identities[0]):
        raise ValueError("checkpoint subject identity mismatch")
    if checkpoint.get("model_alias") != epoch.get("model_alias"):
        raise ValueError("checkpoint model alias mismatch")
    if expected_prompt and checkpoint.get("prompt_contract") != expected_prompt:
        raise ValueError("checkpoint prompt contract mismatch")
    status = str(checkpoint.get("checkpoint_status") or "")
    retryable = allow_retryable and status in {"error", "transport_error"}
    if status not in TERMINAL_STATUSES and not retryable:
        raise ValueError("checkpoint is not terminal")

    roots = list(epoch["trusted_read_roots"])
    manifest = checkpoint.get("evidence_manifest") or []
    verified_evidence: dict[tuple[str, str], str] = {}
    for item in manifest:
        evidence_path, _ = open_verified_artifact(item, roots)
        verified_evidence[(str(evidence_path), str(item["sha256"]))] = str(item.get("kind") or "")
    for item in unit.get("inputs") or []:
        input_path = _normal_path(str(item["path"]))
        key = (str(input_path), str(item["sha256"]))
        if item.get("kind") != "smali-overlay" and key not in verified_evidence:
            raise ValueError(f"checkpoint omits authoritative unit input: {input_path}")
        open_verified_artifact(item, roots)

    # Reconstruct the exact evidence presentation and request independently.
    # The import is deliberately local to avoid a module-import cycle.
    from src.analysis.semantic_ai_controller import _evidence, _prompt, _validate_result

    expected_evidence, expected_manifest = _evidence(
        unit, root / "presentation-receipts", list(epoch["trusted_read_roots"]),
    )
    if canonical(expected_manifest) != canonical(manifest):
        raise ValueError("checkpoint evidence manifest differs from deterministic unit evidence")
    expected_prompt_text = _prompt(unit, expected_evidence, expected_manifest)
    retry_suffix = str(checkpoint.get("prompt_retry_suffix") or "")
    semantic_attempt = require_int_field(
        checkpoint, "semantic_attempt", context="semantic checkpoint", minimum=0,
    )
    if semantic_attempt > 1 and not retry_suffix:
        raise ValueError("retried checkpoint lacks a reproducible prompt retry suffix")
    expected_prompt_text += retry_suffix

    request_blob = str(checkpoint.get("request_blob") or "")
    if not request_blob or Path(request_blob).is_absolute() or ".." in Path(request_blob).parts:
        raise ValueError("invalid request blob path")
    request_path, request_bytes = open_verified_artifact(
        {"path": str(root / request_blob), "sha256": checkpoint.get("request_sha256")}, [root],
    )
    request = json.loads(request_bytes)
    if request.get("model") != epoch.get("model_alias"):
        raise ValueError(f"stored request model mismatch: {request_path}")
    expected_messages = [{"role": "user", "content": expected_prompt_text}]
    if unit.get("class_id"):
        expected_messages.append({"role": "assistant", "content": "{"})
    expected_request = {
        "model": epoch["model_alias"],
        "max_tokens": require_int_field(
            checkpoint, "max_tokens", context="semantic checkpoint", minimum=1,
        ),
        "temperature": 0.1,
        "system": "You are a skeptical senior Android reverse engineer. Return evidence-bound JSON only.",
        "messages": expected_messages,
    }
    if canonical(request) != canonical(expected_request):
        raise ValueError("stored request differs from deterministic work-unit request")

    if retryable:
        stored_max_attempts = require_int_field(
            checkpoint, "max_attempts", context="retryable checkpoint", minimum=1,
        )
        stored_ceiling = require_int_field(
            checkpoint, "max_token_ceiling", context="retryable checkpoint", minimum=1,
        )
        stored_max_tokens = require_int_field(
            checkpoint, "max_tokens", context="retryable checkpoint", minimum=1,
        )
        if (
            semantic_attempt > stored_max_attempts
            or stored_ceiling < stored_max_tokens
        ):
            raise ValueError("retryable checkpoint attempt/token policy mismatch")
        response_blob = str(checkpoint.get("response_blob") or "")
        if response_blob:
            if Path(response_blob).is_absolute() or ".." in Path(response_blob).parts:
                raise ValueError("invalid retryable response blob path")
            _, response_bytes = open_verified_artifact(
                {"path": str(root / response_blob), "sha256": checkpoint.get("response_sha256")},
                [root],
            )
            response = json.loads(response_bytes)
            resolved = str(response.get("model") or "")
            if resolved != checkpoint.get("resolved_model"):
                raise ValueError("retryable checkpoint resolved model differs from response")
            if resolved not in set(epoch.get("allowed_resolved_models") or []):
                raise ValueError(f"unapproved retryable resolved model: {resolved}")
            if response.get("stop_reason") != checkpoint.get("response_stop_reason"):
                raise ValueError("retryable checkpoint stop reason differs from response")
            if status == "error":
                try:
                    extracted = _extract_response_result(response, bool(unit.get("class_id")))
                    _validate_result(extracted, unit)
                except Exception as exc:
                    if (
                        checkpoint.get("error_type") != type(exc).__name__
                        or checkpoint.get("error") != str(exc)[-4000:]
                    ):
                        raise ValueError(
                            "semantic-error checkpoint differs from deterministic validation failure"
                        ) from exc
                else:
                    raise ValueError("semantic-error checkpoint wraps a valid model result")
        elif checkpoint.get("response_sha256") or checkpoint.get("resolved_model"):
            raise ValueError("retryable checkpoint has incomplete response identity")
        elif status == "error":
            raise ValueError("semantic-error checkpoint lacks a stored model response")
        expected_error_class = (
            "transport_retryable" if status == "transport_error" else "semantic_retryable"
        )
        if checkpoint.get("error_class") != expected_error_class:
            raise ValueError("retryable checkpoint error classification mismatch")
        return {
            "checkpoint": checkpoint,
            "checkpoint_path": str(path),
            "checkpoint_sha256": sha256_bytes(payload),
        }

    if status == "terminal_inconclusive":
        stored_max_attempts = require_int_field(
            checkpoint, "max_attempts", context="terminal checkpoint", minimum=1,
        )
        if (
            checkpoint.get("terminal_reason") != "semantic-attempts-exhausted"
            or checkpoint.get("error_class") != "terminal_inconclusive"
            or semantic_attempt != stored_max_attempts
        ):
            raise ValueError("terminal checkpoint does not prove semantic-attempt exhaustion")
        source = checkpoint.get("terminal_source_checkpoint")
        if not isinstance(source, dict) or not source.get("blob") or not source.get("sha256"):
            raise ValueError("terminal checkpoint lacks an exact archived retry source")
        source_blob = Path(str(source["blob"]))
        if source_blob.is_absolute() or ".." in source_blob.parts:
            raise ValueError("invalid terminal source checkpoint path")
        expected_blob = Path("checkpoint-history") / str(unit["unit_id"]) / f"{source['sha256']}.json"
        if source_blob != expected_blob:
            raise ValueError("terminal source checkpoint path is not content addressed")
        source_path, source_payload = open_verified_artifact(
            {"path": str(root / source_blob), "sha256": source["sha256"]}, [root],
        )
        source_verified = verify_semantic_checkpoint(
            source_path,
            unit,
            epoch,
            root,
            allow_retryable=True,
            allow_history=True,
        )
        source_checkpoint = source_verified["checkpoint"]
        if (
            source_checkpoint.get("checkpoint_status") != "error"
            or require_int_field(
                source_checkpoint, "semantic_attempt",
                context="terminal source checkpoint", minimum=0,
            ) != stored_max_attempts
            or require_int_field(
                source_checkpoint, "attempt",
                context="terminal source checkpoint", minimum=1,
            ) != require_int_field(
                checkpoint, "attempt", context="terminal checkpoint", minimum=1,
            )
            or source_checkpoint.get("max_attempts") != checkpoint.get("max_attempts")
            or source_checkpoint.get("max_token_ceiling")
            != checkpoint.get("max_token_ceiling")
            or source_checkpoint.get("request_sha256") != checkpoint.get("request_sha256")
            or source_checkpoint.get("response_sha256") != checkpoint.get("response_sha256")
            or sha256_bytes(source_payload) != source["sha256"]
        ):
            raise ValueError("terminal checkpoint differs from its exhausted retry source")
        if (
            source_checkpoint.get("response_stop_reason") == "max_tokens"
            and require_int_field(
                source_checkpoint, "max_tokens",
                context="terminal source checkpoint", minimum=1,
            ) != require_int_field(
                source_checkpoint, "max_token_ceiling",
                context="terminal source checkpoint", minimum=1,
            )
        ):
            raise ValueError("truncated terminal source did not reach its token ceiling")
        return {
            "checkpoint": checkpoint,
            "checkpoint_path": str(path),
            "checkpoint_sha256": sha256_bytes(payload),
        }

    if status != "terminal_inconclusive":
        response_blob = str(checkpoint.get("response_blob") or "")
        if not response_blob or Path(response_blob).is_absolute() or ".." in Path(response_blob).parts:
            raise ValueError("invalid response blob path")
        _, response_bytes = open_verified_artifact(
            {"path": str(root / response_blob), "sha256": checkpoint.get("response_sha256")}, [root],
        )
        response = json.loads(response_bytes)
        resolved = str(response.get("model") or "")
        if resolved != checkpoint.get("resolved_model"):
            raise ValueError("checkpoint resolved model differs from response")
        if resolved not in set(epoch.get("allowed_resolved_models") or []):
            raise ValueError(f"unapproved resolved model: {resolved}")
        extracted = _extract_response_result(response, bool(unit.get("class_id")))
        if unit.get("schema") in {
            "angerona/dynamic-security-work-unit/v1",
            "angerona/application-surface-work-unit/v1",
        }:
            from src.analysis.semantic_ai_controller import _validate_result
            _validate_result(extracted, unit)
        if (
            unit.get("schema") == "angerona/application-surface-work-unit/v1"
            and "surface_review" not in extracted
        ):
            raise ValueError("application-surface checkpoint contains a non-surface response")
        if unit.get("schema") == "angerona/application-surface-work-unit/v1":
            review = extracted["surface_review"]
            if review.get("reviewed_range") != {
                "source_sha256": unit.get("source_sha256"),
                "byte_start": unit.get("byte_start"), "byte_end": unit.get("byte_end"),
            }:
                raise ValueError("application-surface checkpoint reviewed range mismatch")
            allowed_occurrences = set(unit.get("occurrence_ids") or [])
            for observation in review.get("observations") or []:
                cited = observation.get("occurrence_ids") if isinstance(observation, dict) else None
                if (
                    not isinstance(cited, list) or not cited or len(cited) != len(set(cited))
                    or cited != sorted(cited)
                    or not set(cited).issubset(allowed_occurrences)
                ):
                    raise ValueError("application-surface checkpoint cites an unknown occurrence")
        if canonical(extracted) != canonical(checkpoint.get("result")):
            raise ValueError("checkpoint result differs from stored model response")
        if extracted.get("input_manifest_sha256") != unit.get("input_manifest_sha256"):
            raise ValueError("response input manifest mismatch")
        if extracted.get(identities[0]) != unit.get(identities[0]):
            raise ValueError("response subject identity mismatch")
        model_status = str(extracted.get("status") or "")
        if model_status == "reconstructed":
            expected_status = "needs_evidence" if extracted.get("evidence_requests") else "ok"
        elif model_status in {"needs_evidence", "irrecoverable"}:
            expected_status = model_status
        else:
            raise ValueError(f"invalid terminal model status: {model_status}")
        if status != expected_status:
            raise ValueError(
                f"checkpoint status/result correlation mismatch: {status} != {expected_status}"
            )
    return {
        "checkpoint": checkpoint,
        "checkpoint_path": str(path),
        "checkpoint_sha256": sha256_bytes(payload),
    }


def _load_queue(queue: str | Path) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    seen: set[str] = set()
    with Path(queue).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            unit = json.loads(line)
            unit_id = str(unit.get("unit_id") or "")
            if not unit_id or unit_id in seen:
                raise ValueError(f"missing or duplicate unit ID at queue line {line_number}")
            seen.add(unit_id)
            units.append(unit)
    ordered = canonical_order_rows(
        "angerona/canonical-unit-jsonl/v1", "$rows", units,
        context=f"queue {Path(queue)}",
    )
    if units != ordered:
        raise ValueError(f"queue rows are not in canonical unit_id order: {queue}")
    return units


def _verify_checkpoint_set_with_epoch(
    manifest_path: Path,
    manifest_bytes: bytes,
    queue: str | Path,
    epoch: dict[str, Any],
    visiting: set[tuple[str, str]],
    lineage_memo: dict[tuple[str, str], dict[str, Any]],
    set_memo: dict[tuple[str, str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    manifest_digest = sha256_bytes(manifest_bytes)
    queue_path = _normal_path(queue)
    queue_sha = sha256_path(queue_path)
    memo_key = (str(manifest_path), manifest_digest, str(queue_path), queue_sha)
    if memo_key in set_memo:
        return set_memo[memo_key]
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != CHECKPOINT_SET_SCHEMA:
        raise ValueError("unknown checkpoint-set schema")
    if not verify_document(manifest, require_signature=True):
        raise ValueError("checkpoint-set operator signature is invalid")
    if not verify_document_identity(manifest):
        raise ValueError("checkpoint-set self hash mismatch")
    if manifest.get("epoch_id") != epoch["epoch_id"]:
        raise ValueError("checkpoint-set epoch mismatch")
    if (
        manifest.get("queue_path") != str(queue_path)
        or manifest.get("queue_sha256") != queue_sha
        or manifest.get("generation_state") != "SEALED"
    ):
        raise ValueError("checkpoint-set queue identity or seal mismatch")
    registered = {
        (str(row.get("path")), str(row.get("sha256")))
        for row in (epoch.get("queues") or {}).values() if isinstance(row, dict)
    }
    if (str(queue_path), queue_sha) in registered:
        matching = next(
            row for row in (epoch.get("queues") or {}).values()
            if isinstance(row, dict)
            and str(row.get("path")) == str(queue_path)
            and str(row.get("sha256")) == queue_sha
        )
        open_verified_artifact(matching, epoch["trusted_read_roots"])
    else:
        lineage = _verify_derived_queue_lineage(
            queue_path, epoch, visiting, lineage_memo, set_memo,
        )
        if (
            manifest.get("queue_lineage_path") != lineage["lineage_path"]
            or manifest.get("queue_lineage_sha256") != lineage["lineage_sha256"]
            or manifest.get("derivation_manifest_path")
            != lineage["derivation_manifest_path"]
            or manifest.get("derivation_manifest_sha256")
            != lineage["derivation_manifest_sha256"]
        ):
            raise ValueError("checkpoint set does not pin current derived queue lineage")
    units = _load_queue(queue_path)
    by_id = {str(unit["unit_id"]): unit for unit in units}
    entries = require_list_field(manifest, "entries", context="checkpoint set")
    require_canonical_ordered_field(manifest, "entries", context="checkpoint set")
    entry_ids = [str(row.get("unit_id") or "") for row in entries]
    unit_stream = b"".join((unit_id + "\n").encode() for unit_id in entry_ids)
    if (
        len(entries) != len(by_id)
        or entry_ids != list(by_id)
        or require_int_field(
            manifest, "expected_units", context="checkpoint set", minimum=0,
        ) != len(by_id)
        or manifest.get("unit_id_stream_sha256") != sha256_bytes(unit_stream)
    ):
        raise ValueError("checkpoint-set unit accounting mismatch")
    root = Path(str(entries[0]["checkpoint_path"])).parent.parent if entries else Path("/")
    for entry in entries:
        verified = verify_semantic_checkpoint(
            str(entry["checkpoint_path"]), by_id[str(entry["unit_id"])], epoch, root,
        )
        if verified["checkpoint_sha256"] != entry.get("checkpoint_sha256"):
            raise ValueError(f"sealed checkpoint changed: {entry['unit_id']}")
    set_memo[memo_key] = manifest
    return manifest


def seal_checkpoint_set(
    queue: str | Path,
    checkpoint_root: str | Path,
    epoch_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    epoch = load_audit_epoch(epoch_path)
    queue_sha = queue_matches_epoch(queue, epoch)
    root = output_is_in_epoch(checkpoint_root, epoch)
    units = _load_queue(queue)
    expected = {str(unit["unit_id"]): unit for unit in units}
    entries = []
    current_epoch_files: set[str] = set()
    for path in sorted((root / "checkpoints").glob("*.json")):
        try:
            row = json.loads(path.read_bytes())
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
        if row.get("schema") != CHECKPOINT_SCHEMA or row.get("audit_epoch_id") != epoch["epoch_id"]:
            continue
        unit_id = str(row.get("unit_id") or "")
        if unit_id not in expected:
            raise ValueError(f"extra checkpoint in epoch: {unit_id}")
        if unit_id in current_epoch_files:
            raise ValueError(f"duplicate checkpoint in epoch: {unit_id}")
        current_epoch_files.add(unit_id)
        verified = verify_semantic_checkpoint(path, expected[unit_id], epoch, root)
        checkpoint = verified["checkpoint"]
        entries.append({
            "unit_id": unit_id,
            "checkpoint_path": verified["checkpoint_path"],
            "checkpoint_sha256": verified["checkpoint_sha256"],
            "request_sha256": checkpoint.get("request_sha256"),
            "response_sha256": checkpoint.get("response_sha256"),
            "input_manifest_sha256": checkpoint.get("input_manifest_sha256"),
            "checkpoint_status": checkpoint.get("checkpoint_status"),
            "resolved_model": checkpoint.get("resolved_model"),
        })
    missing = sorted(set(expected) - current_epoch_files)
    if missing:
        raise ValueError(f"checkpoint barrier incomplete: {len(entries)}/{len(expected)}; missing={missing[:3]}")
    entries.sort(key=lambda row: row["unit_id"])
    status_counts = {
        status: sum(row["checkpoint_status"] == status for row in entries)
        for status in sorted({str(row["checkpoint_status"]) for row in entries})
    }
    unit_stream = b"".join((row["unit_id"] + "\n").encode() for row in entries)
    body = {
        "schema": CHECKPOINT_SET_SCHEMA,
        "epoch_id": epoch["epoch_id"],
        "epoch_manifest_sha256": sha256_path(epoch_path),
        "queue_path": str(_normal_path(queue)),
        "queue_sha256": queue_sha,
        "expected_units": len(expected),
        "unit_id_stream_sha256": sha256_bytes(unit_stream),
        "entries": entries,
        "status_counts": status_counts,
        "generation_state": "SEALED",
        "semantic_complete": status_counts.get("ok", 0) == len(expected),
    }
    registered = {
        (str(row.get("path")), str(row.get("sha256")))
        for row in (epoch.get("queues") or {}).values() if isinstance(row, dict)
    }
    if (str(_normal_path(queue)), queue_sha) not in registered:
        lineage = _verify_derived_queue_lineage(
            _normal_path(queue), epoch, set(), {}, {},
        )
        body.update({
            "queue_lineage_path": lineage["lineage_path"],
            "queue_lineage_sha256": lineage["lineage_sha256"],
            "derivation_manifest_path": lineage["derivation_manifest_path"],
            "derivation_manifest_sha256": lineage["derivation_manifest_sha256"],
        })
    manifest = sign_document(with_document_identity(body))
    if manifest.get("trust") != OPERATOR_SIGNED:
        raise ValueError("checkpoint-set sealing requires ANGERONA_SIGNING_KEY_PATH")
    atomic_write(output_path, canonical(manifest), immutable=True)
    return manifest


def verify_checkpoint_set(
    manifest_path: str | Path, queue: str | Path, epoch_path: str | Path,
) -> dict[str, Any]:
    epoch = load_audit_epoch(epoch_path)
    strict_manifest_path, manifest_bytes = open_trusted_artifact(
        manifest_path, epoch["trusted_read_roots"],
    )
    return _verify_checkpoint_set_with_epoch(
        strict_manifest_path, manifest_bytes, queue, epoch, set(), {}, {},
    )
