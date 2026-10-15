"""Signed, fail-closed routing and ownership plans for clean Android audits.

This module does not decompile content.  It conserves every APK member into one
signed disposition before any parser, decompiler, or model lane is allowed to
start.  Code ownership is deliberately decided after deterministic extraction.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable
import zipfile

from .audit_lineage import load_audit_epoch, open_verified_artifact
from .apk_content_manifest import SCHEMA as APK_CONTENT_MANIFEST_SCHEMA, apk_content_manifest_sha256
from .evidence_signing import (
    GENERATED_DOCUMENT_FIELDS, canonical_payload, verify_document,
    verify_document_identity, with_document_identity,
)
from .native_ownership_manifest import native_routing_context, native_routing_targets
from .application_surface import COMPONENT_SCHEMA
from .signed_artifact_io import (
    load_signed_canonical, validate_extracted_entity_manifest, write_signed_canonical,
)
from .schema_validation import require_int_field, require_list_field


POLICY_SCHEMA = "angerona/audit-ownership-policy/v1"
PLAN_SCHEMA = "angerona/clean-apk-routing-plan/v1"
ROUTING_MANIFEST_SCHEMA = "angerona/clean-apk-routing-manifest/v1"
COVERAGE_SCHEMA = "angerona/clean-apk-routing-coverage/v1"
EXECUTION_SCHEMA = "angerona/clean-audit-execution-spec/v1"
NATIVE_ROUTING_SCHEMA = "angerona/native-ownership-routing/v1"
ENTITY_MANIFEST_SCHEMA = "angerona/extracted-entity-ownership/v1"
EXTRACTED_MANIFEST_SCHEMA = "angerona/extracted-entity-manifest/v1"

_HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")
_KOTLIN_BUILTINS_HEADER = bytes.fromhex("00000003000000010000000000000007")
_ARCHIVES = {"zip", "archive", "apk", "jar", "7z", "rar", "tar", "gzip"}
_DEX = {"dex"}
_TEXT_SUFFIXES = {
    ".xml", ".json", ".txt", ".cfg", ".conf", ".ini", ".properties",
    ".yaml", ".yml", ".toml", ".csv", ".html", ".htm", ".css",
}


def _canonical(value: Any) -> bytes:
    return canonical_payload(value)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normal(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=True)


def _within(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == payload:
            return
        raise FileExistsError(f"refusing to replace immutable audit artifact: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _signed_file(path: Path, body: dict[str, Any]) -> dict[str, Any]:
    return write_signed_canonical(path, body)


def _verify_descriptor(descriptor: Any, roots: list[Path]) -> tuple[Path, bytes]:
    if not isinstance(descriptor, dict):
        raise ValueError("artifact descriptor must be an object")
    return open_verified_artifact(descriptor, roots)


def _verify_evidence(items: Any, roots: list[Path], context: str) -> None:
    if not isinstance(items, list) or not items:
        raise ValueError(f"{context} requires hash-bound evidence")
    for descriptor in items:
        _verify_descriptor(descriptor, roots)


def seal_ownership_policy(spec_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    """Normalize and sign an operator-authored ownership policy specification."""
    spec = json.loads(_normal(spec_path).read_bytes())
    if not isinstance(spec, dict):
        raise ValueError("ownership policy specification must be an object")
    forbidden = GENERATED_DOCUMENT_FIELDS | {"policy_id", "schema"}
    if forbidden.intersection(spec):
        raise ValueError("policy specification contains generated fields")
    body = {"schema": POLICY_SCHEMA, **spec}
    overrides = body.get("operator_overrides") or []
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in overrides:
        if not isinstance(raw, dict):
            raise ValueError("operator override must be an object")
        row = {key: value for key, value in raw.items() if key != "override_id"}
        override_id = _sha(_canonical(row))
        if raw.get("override_id") not in {None, override_id}:
            raise ValueError("operator override identity mismatch")
        if override_id in seen:
            raise ValueError("duplicate operator override")
        seen.add(override_id)
        normalized.append({**row, "override_id": override_id})
    body["operator_overrides"] = sorted(normalized, key=lambda row: row["override_id"])
    body = with_document_identity(body)
    descriptor = _signed_file(Path(output_path).resolve(), body)
    return {**body, "descriptor": descriptor}


def load_ownership_policy(
    path: str | Path, trusted_roots: Iterable[str | Path],
) -> dict[str, Any]:
    roots = [_normal(root) for root in trusted_roots]
    policy_path = _normal(path)
    if not _within(policy_path, roots):
        raise ValueError("ownership policy escapes trusted roots")
    policy = json.loads(policy_path.read_bytes())
    if policy.get("schema") != POLICY_SCHEMA:
        raise ValueError("unknown ownership policy schema")
    if not verify_document(policy, require_signature=True):
        raise ValueError("ownership policy signature is invalid")
    if not verify_document_identity(policy):
        raise ValueError("ownership policy identity mismatch")

    fingerprints: dict[str, str] = {}
    for row in policy.get("artifact_fingerprints") or []:
        digest = str(row.get("sha256") or "")
        disposition = str(row.get("disposition") or "")
        if len(digest) != 64 or disposition not in {"APP_OWNED", "EXCLUDED_THIRD_PARTY"}:
            raise ValueError("invalid exact artifact fingerprint")
        if disposition == "EXCLUDED_THIRD_PARTY" and not row.get("library_identity"):
            raise ValueError("third-party fingerprint lacks an exact library identity")
        _verify_evidence(row.get("evidence"), roots, f"fingerprint {digest}")
        if digest in fingerprints:
            raise ValueError("duplicate or conflicting exact artifact fingerprint")
        fingerprints[digest] = disposition

    override_by_id: dict[str, dict[str, Any]] = {}
    exact_targets: dict[tuple[str, str], str] = {}
    for row in policy.get("operator_overrides") or []:
        override_id = str(row.get("override_id") or "")
        unsigned = {key: value for key, value in row.items() if key != "override_id"}
        if override_id != _sha(_canonical(unsigned)) or override_id in override_by_id:
            raise ValueError("invalid or duplicate operator override identity")
        if row.get("disposition") not in {"APP_OWNED", "EXCLUDED_THIRD_PARTY", "HOLD"}:
            raise ValueError("invalid operator override disposition")
        target = (str(row.get("target_kind") or ""), str(row.get("target_id") or ""))
        if not all(target) or target in exact_targets:
            raise ValueError("operator override is ambiguous or not exact")
        if not str(row.get("reason") or "").strip():
            raise ValueError("operator override lacks a reason")
        _verify_evidence(row.get("evidence"), roots, f"override {override_id}")
        exact_targets[target] = override_id
        override_by_id[override_id] = row
    for override_id, row in override_by_id.items():
        parent = row.get("parent_override_id")
        visited = {override_id}
        while parent:
            if parent in visited or parent not in override_by_id:
                raise ValueError("operator override lineage is cyclic or missing")
            visited.add(parent)
            parent = override_by_id[parent].get("parent_override_id")

    components: set[str] = set()
    for row in policy.get("manifest_component_roots") or []:
        name = str(row.get("component_name") or "")
        if not name or name in components:
            raise ValueError("manifest component root is empty or duplicated")
        _verify_evidence(row.get("evidence"), roots, f"manifest component {name}")
        components.add(name)
    return policy


def _policy_decision(
    policy: dict[str, Any], *, target_kind: str, target_id: str, digest: str | None,
) -> tuple[str | None, dict[str, Any] | None]:
    matches = [
        row for row in policy.get("operator_overrides") or []
        if row.get("target_kind") == target_kind and row.get("target_id") == target_id
    ]
    if len(matches) > 1:
        raise ValueError("ambiguous operator override")
    if matches:
        return str(matches[0]["disposition"]), {
            "basis": "signed-operator-override", "override_id": matches[0]["override_id"],
        }
    if digest:
        matches = [row for row in policy.get("artifact_fingerprints") or [] if row.get("sha256") == digest]
        dispositions = {str(row.get("disposition")) for row in matches}
        if len(dispositions) > 1:
            raise ValueError("conflicting fingerprint ownership")
        if matches:
            return str(matches[0]["disposition"]), {
                "basis": "exact-library-fingerprint",
                "library_identity": matches[0].get("library_identity"),
            }
    return None, None


def _hermes_or_js(name: str, prefix: bytes) -> bool:
    lower = name.lower()
    return (
        prefix.startswith(_HERMES_MAGIC)
        or lower.endswith((".hbc", ".hermes"))
        or lower.endswith("index.android.bundle")
    )


def _parser_candidate(name: str, classification: str, prefix: bytes = b"") -> bool:
    lower = name.lower()
    suffix = Path(lower).suffix
    return (
        classification in {
            "android_binary_xml", "xml", "json", "text", "protobuf", "arsc",
            "png", "jpeg", "gif", "webp", "sqlite", "certificate",
            "kotlin_builtins_metadata",
        }
        or suffix in _TEXT_SUFFIXES
        or lower == "resources.arsc"
        or lower.startswith(("res/", "assets/", "meta-inf/"))
        or lower == "androidmanifest.xml"
        or (lower.endswith(".kotlin_builtins") and prefix.startswith(_KOTLIN_BUILTINS_HEADER))
    )


def _load_native_routing(
    descriptor: dict[str, Any] | None, universe_descriptor: dict[str, Any] | None,
    roots: list[Path], apk_sha256: str,
) -> tuple[dict[str, str], dict[str, Any] | None]:
    if descriptor is None:
        return {}, None
    if universe_descriptor is None:
        raise ValueError("external native routing requires its signed target universe")
    path, payload = _verify_descriptor(descriptor, roots)
    universe_path, universe_payload = _verify_descriptor(universe_descriptor, roots)
    document, selected, events, binding = native_routing_context(path, universe_path)
    universe_document = json.loads(universe_payload)
    if universe_document.get("apk_sha256") != apk_sha256:
        raise ValueError("external native routing belongs to another APK")
    app, excluded, hold = native_routing_targets(selected, events)
    decisions = {
        **{digest: "APP_OWNED" for digest in app},
        **{digest: "EXCLUDED_THIRD_PARTY" for digest in excluded},
        **{digest: "HOLD" for digest in hold},
    }
    if len(decisions) != require_int_field(
        document, "target_count", context="external native routing", minimum=0,
    ):
        raise ValueError("external native routing target conservation is incomplete")
    return decisions, {
        "ownership_manifest": {"path": str(path), "sha256": _sha(payload)},
        "native_universe": {"path": str(universe_path), "sha256": _sha(universe_payload)},
        "routing_binding": binding,
        "expected_app_owned_target_sha256": sorted(app),
        "excluded_target_sha256": sorted(excluded),
        "hold_target_sha256": sorted(hold),
    }


def build_clean_apk_routing_plan(
    *, apk: str | Path, inventory_manifest: str | Path,
    ownership_policy: str | Path, output_dir: str | Path,
    trusted_roots: Iterable[str | Path],
    native_routing: dict[str, Any] | None = None,
    native_universe: dict[str, Any] | None = None,
    execution_spec: dict[str, Any] | None = None,
    audit_epoch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and sign an exhaustive routing set; no worker is started here."""
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    roots = [_normal(root) for root in trusted_roots]
    if not _within(output, roots):
        raise ValueError("routing output escapes trusted roots")
    apk_path = _normal(apk)
    manifest_path = _normal(inventory_manifest)
    if not _within(apk_path, roots) or not _within(manifest_path, roots):
        raise ValueError("APK or inventory manifest escapes trusted roots")
    manifest_payload = manifest_path.read_bytes()
    manifest = json.loads(manifest_payload)
    if manifest.get("schema") != APK_CONTENT_MANIFEST_SCHEMA:
        raise ValueError("unsupported APK inventory manifest")
    if manifest.get("manifest_sha256") != apk_content_manifest_sha256(manifest):
        raise ValueError("APK inventory manifest self-hash mismatch")
    apk_sha = _sha_path(apk_path)
    if manifest.get("apk_sha256") != apk_sha:
        raise ValueError("APK inventory belongs to another APK")
    if not manifest.get("archive_byte_partition_complete"):
        raise ValueError("APK byte partition is incomplete")
    policy = load_ownership_policy(ownership_policy, roots)
    policy_path = _normal(ownership_policy)
    native_decisions, native_descriptor = _load_native_routing(
        native_routing, native_universe, roots, apk_sha,
    )

    execution_descriptor = None
    if execution_spec is not None:
        spec_path, spec_payload = _verify_descriptor(execution_spec, roots)
        spec = json.loads(spec_payload)
        if spec.get("schema") != EXECUTION_SCHEMA or not verify_document(spec, require_signature=True):
            raise ValueError("execution specification is unsigned or unknown")
        execution_descriptor = {"path": str(spec_path), "sha256": _sha(spec_payload)}

    epoch_descriptor = None
    if audit_epoch is not None:
        epoch_path, epoch_payload = _verify_descriptor(audit_epoch, roots)
        epoch = load_audit_epoch(epoch_path)
        epoch_descriptor = {
            "path": str(epoch_path), "sha256": _sha(epoch_payload),
            "epoch_id": epoch["epoch_id"],
        }

    entries = require_list_field(manifest, "entries", context="APK content manifest")
    if len(entries) != manifest.get("entry_count"):
        raise ValueError("APK inventory entry count mismatch")
    indexes = [int(row.get("central_directory_index", -1)) for row in entries]
    if sorted(indexes) != list(range(len(entries))):
        raise ValueError("APK inventory central-directory indexes are not exhaustive")

    partitions: dict[str, list[dict[str, Any]]] = {
        "APP_OWNED": [], "EXCLUDED_THIRD_PARTY": [], "HOLD": [], "FILTER_PENDING": [],
    }
    with zipfile.ZipFile(apk_path) as archive:
        infos = archive.infolist()
        if len(infos) != len(entries):
            raise ValueError("APK central directory changed since inventory")
        for entry in entries:
            index = int(entry["central_directory_index"])
            info = infos[index]
            if info.filename != entry.get("name"):
                raise ValueError("APK entry name/order differs from inventory")
            payload = b""
            if not entry.get("is_directory") and not entry.get("encrypted"):
                payload = archive.read(info)
                if _sha(payload) != entry.get("content_sha256"):
                    raise ValueError("APK entry content differs from inventory")
            digest = entry.get("content_sha256")
            decision, basis = _policy_decision(
                policy, target_kind="apk-entry", target_id=str(entry["entry_id"]), digest=digest,
            )
            route = ""
            reason = ""
            classification = str(entry.get("classification") or "")
            lower_name = str(entry.get("name") or "").lower()
            if classification == "opaque_binary" and payload.startswith(b"\x1f\x8b\x08"):
                classification = "gzip"
            elif lower_name.endswith(".kotlin_builtins") and payload.startswith(_KOTLIN_BUILTINS_HEADER):
                classification = "kotlin_builtins_metadata"
            if entry.get("encrypted") or entry.get("limitations"):
                disposition, route, reason = "HOLD", "none", "encrypted-or-unreadable-member"
            elif entry.get("is_directory"):
                disposition, route, reason = "APP_OWNED", "archive-structure-only", "structural-directory-entry"
            elif classification in _ARCHIVES:
                disposition, route, reason = "HOLD", "none", "nested-archive-requires-new-signed-child-plan"
            elif classification == "elf":
                native = native_decisions.get(str(digest or ""))
                if native == "APP_OWNED":
                    disposition, route, reason = "FILTER_PENDING", "external-signed-native-app-owned-queue", "external-native-ownership"
                elif native == "EXCLUDED_THIRD_PARTY":
                    disposition, route, reason = "EXCLUDED_THIRD_PARTY", "none", "external-native-exact-fingerprint"
                else:
                    disposition, route, reason = "HOLD", "none", "native-ownership-missing-or-held"
            elif decision in {"EXCLUDED_THIRD_PARTY", "HOLD"}:
                disposition, route, reason = decision, "none", str((basis or {}).get("basis") or "signed-policy")
            elif classification in _DEX:
                disposition = "APP_OWNED" if decision == "APP_OWNED" else "FILTER_PENDING"
                route, reason = "dex-index-then-ownership-filter-before-app-only-decompile", "dex-container"
            elif _hermes_or_js(str(entry.get("name") or ""), payload[:16]):
                disposition = "APP_OWNED" if decision == "APP_OWNED" else "FILTER_PENDING"
                route, reason = "hermes-index-then-module-ownership-filter-before-app-only-decompile", "hermes-or-js-bytecode"
            elif _parser_candidate(str(entry.get("name") or ""), classification, payload[:16]):
                disposition = "APP_OWNED" if decision == "APP_OWNED" else "FILTER_PENDING"
                route, reason = "deterministic-parser-then-ownership-filter-then-ai", "recognized-noncode-container"
            elif decision == "APP_OWNED":
                disposition, route, reason = "HOLD", "none", "unsupported-app-owned-content-requires-explicit-parser"
            else:
                disposition, route, reason = "HOLD", "none", "unknown-packed-or-unsupported-content"
            row = {
                "entry_id": entry["entry_id"], "name": entry["name"],
                "central_directory_index": index, "classification": classification,
                "content_sha256": digest, "content_bytes": require_int_field(
                    entry, "content_bytes", context=f"APK entry {index}", minimum=0,
                ),
                "disposition": disposition, "route": route, "reason": reason,
                "ownership_basis": basis,
            }
            partitions[disposition].append(row)

    elf_digests = {
        str(row.get("content_sha256") or "") for row in entries
        if row.get("classification") == "elf"
    }
    if native_descriptor is not None and set(native_decisions) != elf_digests:
        raise ValueError("external native routing does not exactly conserve APK ELF targets")

    all_ids = [row["entry_id"] for rows in partitions.values() for row in rows]
    expected_ids = [row["entry_id"] for row in entries]
    if len(all_ids) != len(set(all_ids)) or set(all_ids) != set(expected_ids):
        raise ValueError("routing partitions do not exactly conserve APK entries")
    routing_set_body = {
        "apk_sha256": apk_sha,
        "inventory_manifest_sha256": _sha(manifest_payload),
        "ownership_policy_id": policy["policy_id"],
        "rows": sorted(
            [row for rows in partitions.values() for row in rows],
            key=lambda row: row["central_directory_index"],
        ),
    }
    routing_set_id = _sha(_canonical(routing_set_body))
    descriptors: dict[str, dict[str, Any]] = {}
    filenames = {
        "APP_OWNED": "APP_OWNED_MANIFEST.json",
        "EXCLUDED_THIRD_PARTY": "EXCLUDED_MANIFEST.json",
        "HOLD": "HOLD_MANIFEST.json",
        "FILTER_PENDING": "FILTER_PENDING_MANIFEST.json",
    }
    for disposition, rows in partitions.items():
        descriptors[disposition] = _signed_file(output / filenames[disposition], {
            "schema": ROUTING_MANIFEST_SCHEMA, "routing_set_id": routing_set_id,
            "disposition": disposition, "entry_count": len(rows),
            "content_bytes": sum(row["content_bytes"] for row in rows),
            "entries": sorted(rows, key=lambda row: row["central_directory_index"]),
        })
    coverage = {
        "schema": COVERAGE_SCHEMA, "routing_set_id": routing_set_id,
        "apk_entry_count": len(entries), "partition_entry_count": len(all_ids),
        "apk_member_content_bytes": sum(require_int_field(
            row, "content_bytes", context="APK inventory entry", minimum=0,
        ) for row in entries),
        "partition_content_bytes": sum(row["content_bytes"] for rows in partitions.values() for row in rows),
        "archive_partition_bytes": manifest.get("archive_partition_bytes"),
        "apk_bytes": manifest.get("apk_bytes"),
        "archive_byte_partition_complete": bool(manifest.get("archive_byte_partition_complete")),
        "entry_membership_exact": set(all_ids) == set(expected_ids) and len(all_ids) == len(expected_ids),
        "duplicate_entry_ids": len(all_ids) - len(set(all_ids)),
        "disposition_counts": {key: len(value) for key, value in sorted(partitions.items())},
        "conservation_complete": True,
        "final_audit_complete": not partitions["HOLD"] and not partitions["FILTER_PENDING"],
    }
    coverage_descriptor = _signed_file(output / "COVERAGE_ACCOUNTING.json", coverage)
    surface_dependencies = ["deterministic_parse", "dex_index", "hermes_index"]
    ownership_dependencies = [*surface_dependencies, "application_surface"]
    if native_descriptor is not None:
        ownership_dependencies.append("native_external")
    cross_dependencies = ["ownership_filter", "app_reconstruction", "ai_review", "surface_semantic"]
    if native_descriptor is not None:
        cross_dependencies.append("native_acceptance")
    plan_body = {
        "schema": PLAN_SCHEMA, "routing_set_id": routing_set_id,
        "apk": {"path": str(apk_path), "sha256": apk_sha},
        "inventory_manifest": {"path": str(manifest_path), "sha256": _sha(manifest_payload)},
        "ownership_policy": {"path": str(policy_path), "sha256": _sha_path(policy_path), "policy_id": policy["policy_id"]},
        "trusted_roots": sorted(str(root) for root in roots),
        "output_root": str(output), "partition_manifests": descriptors,
        "coverage_accounting": coverage_descriptor,
        "external_native_routing": native_descriptor,
        "execution_spec": execution_descriptor,
        "audit_epoch": epoch_descriptor,
        "lanes": {
            "deterministic_parse": {
                "input_routes": ["deterministic-parser-then-ownership-filter-then-ai"],
                "completion_schema": "angerona/deterministic-artifact-parse-receipt/v1", "independent": True,
            },
            "dex_index": {
                "input_routes": ["dex-index-then-ownership-filter-before-app-only-decompile"],
                "completion_schema": "angerona/dex-ownership-index-receipt/v1", "independent": True,
            },
            "hermes_index": {
                "input_routes": ["hermes-index-then-module-ownership-filter-before-app-only-decompile"],
                "completion_schema": "angerona/hermes-ownership-index-receipt/v1", "independent": True,
            },
            "native_external": {
                "externally_managed": True, "independent": True,
                "available": native_descriptor is not None,
            },
            **({
                "native_acceptance": {
                    "depends_on": ["native_external"],
                    "completion_schema": "angerona/clean-native-acceptance-receipt/v1",
                },
            } if native_descriptor is not None else {}),
            "application_surface": {
                "depends_on": surface_dependencies,
                "completion_schema": "angerona/application-surface-completion-receipt/v1",
                "ownership_neutral": True,
            },
            "surface_semantic": {
                "depends_on": ["application_surface"],
                "completion_schema": "angerona/application-surface-semantic-completion-receipt/v1",
                "may_run_with_code_hold": True, "code_ownership_claimed": False,
            },
            "ownership_filter": {
                "depends_on": ownership_dependencies,
                "completion_schema": "angerona/clean-ownership-filter-receipt/v1",
            },
            "app_reconstruction": {
                "depends_on": ["ownership_filter"],
                "completion_schema": "angerona/app-owned-reconstruction-receipt/v1",
            },
            "ai_review": {
                "depends_on": ["ownership_filter", "app_reconstruction"],
                "completion_schema": "angerona/app-owned-ai-review-receipt/v1",
            },
            "cross_layer_merge": {
                "depends_on": cross_dependencies,
                "completion_schema": "angerona/clean-cross-layer-merge-receipt/v1",
            },
            "dynamic_security_plan": {
                "depends_on": ["cross_layer_merge"],
                "completion_schema": "angerona/dynamic-security-planning-completion-receipt/v1",
                "planner_semantics": "sealed-graph-derived-no-predefined-vulnerability-domains",
                "confirmation_semantics": "hypotheses-only-independent-proof-required",
            },
        },
        "conservation_complete": True,
        "third_party_processing": "FULLY_EXCLUDED",
        "unknown_processing": "HOLD",
    }
    plan_body = with_document_identity(plan_body)
    plan_descriptor = _signed_file(output / "ARTIFACT_ROUTING_PLAN.json", plan_body)
    return {**plan_body, "descriptor": plan_descriptor}


def verify_clean_apk_routing_plan(path: str | Path) -> dict[str, Any]:
    plan_path = _normal(path)
    plan = json.loads(plan_path.read_bytes())
    if plan.get("schema") != PLAN_SCHEMA or not verify_document(plan, require_signature=True):
        raise ValueError("routing plan is unsigned or unknown")
    if not verify_document_identity(plan):
        raise ValueError("routing plan identity mismatch")
    roots = [_normal(root) for root in plan.get("trusted_roots") or []]
    if not roots or not _within(plan_path, roots):
        raise ValueError("routing plan escapes its trust roots")
    _verify_descriptor(plan.get("apk"), roots)
    _verify_descriptor(plan.get("inventory_manifest"), roots)
    policy_path, policy_bytes = _verify_descriptor(plan.get("ownership_policy"), roots)
    policy = load_ownership_policy(policy_path, roots)
    if policy.get("policy_id") != plan["ownership_policy"].get("policy_id"):
        raise ValueError("routing plan policy binding mismatch")
    if _sha(policy_bytes) != plan["ownership_policy"]["sha256"]:
        raise ValueError("routing plan policy bytes mismatch")
    coverage_path, coverage_bytes = _verify_descriptor(plan.get("coverage_accounting"), roots)
    coverage = json.loads(coverage_bytes)
    if not verify_document(coverage, require_signature=True):
        raise ValueError("coverage accounting is unsigned")
    rows: list[dict[str, Any]] = []
    for disposition in ("APP_OWNED", "EXCLUDED_THIRD_PARTY", "HOLD", "FILTER_PENDING"):
        item_path, item_bytes = _verify_descriptor(plan.get("partition_manifests", {}).get(disposition), roots)
        document = json.loads(item_bytes)
        if (
            document.get("schema") != ROUTING_MANIFEST_SCHEMA
            or not verify_document(document, require_signature=True)
            or document.get("routing_set_id") != plan.get("routing_set_id")
            or document.get("disposition") != disposition
            or document.get("entry_count") != len(document.get("entries") or [])
        ):
            raise ValueError(f"invalid signed routing partition: {item_path}")
        rows.extend(document["entries"])
    ids = [row.get("entry_id") for row in rows]
    if (
        len(ids) != len(set(ids))
        or len(ids) != coverage.get("apk_entry_count")
        or coverage.get("partition_entry_count") != len(ids)
        or not coverage.get("entry_membership_exact")
        or not coverage.get("archive_byte_partition_complete")
        or not coverage.get("conservation_complete")
        or coverage.get("routing_set_id") != plan.get("routing_set_id")
        or not plan.get("conservation_complete")
    ):
        raise ValueError("signed routing conservation is incomplete")
    if plan.get("third_party_processing") != "FULLY_EXCLUDED" or plan.get("unknown_processing") != "HOLD":
        raise ValueError("routing plan weakens fail-closed dispositions")
    if plan.get("audit_epoch"):
        epoch_path, epoch_payload = _verify_descriptor(plan["audit_epoch"], roots)
        epoch = load_audit_epoch(epoch_path)
        if (
            plan["audit_epoch"].get("epoch_id") != epoch.get("epoch_id")
            or plan["audit_epoch"].get("sha256") != _sha(epoch_payload)
        ):
            raise ValueError("routing plan audit epoch binding mismatch")
    return plan


def classify_extracted_entities(
    *, plan: dict[str, Any], extracted_manifest: str | Path, ownership_policy: str | Path,
    component_definition_receipt: str | Path,
    output_dir: str | Path, trusted_roots: Iterable[str | Path],
) -> dict[str, Any]:
    """Partition extracted Java/method/JS entities without package-name guessing."""
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    roots = [_normal(root) for root in trusted_roots]
    manifest_path = _normal(extracted_manifest)
    if not _within(manifest_path, roots):
        raise ValueError("extracted entity manifest escapes trusted roots")
    manifest_descriptor = {"path": str(manifest_path), "sha256": _sha_path(manifest_path)}
    _manifest_path, manifest = load_signed_canonical(
        manifest_descriptor, roots, schema=EXTRACTED_MANIFEST_SCHEMA,
    )
    validate_extracted_entity_manifest(manifest, plan)
    payload = manifest_path.read_bytes()
    policy = load_ownership_policy(ownership_policy, roots)
    component_path = _normal(component_definition_receipt)
    component_descriptor = {"path": str(component_path), "sha256": _sha_path(component_path)}
    _verified_component, component_payload = open_verified_artifact(component_descriptor, roots)
    component_receipt = json.loads(component_payload)
    expected_policy = {"path": str(_normal(ownership_policy)), "sha256": _sha_path(_normal(ownership_policy)), "policy_id": policy["policy_id"]}
    if (
        component_receipt.get("schema") != COMPONENT_SCHEMA
        or not verify_document(component_receipt, require_signature=True)
        or component_receipt.get("plan_id") != manifest.get("plan_id")
        or component_receipt.get("routing_set_id") != manifest.get("routing_set_id")
        or component_receipt.get("ownership_policy") != expected_policy
    ):
        raise ValueError("manifest component definition receipt lineage mismatch")
    resolved_components = {
        str(row["normalized_name"]): str((row.get("definition") or {}).get("entity_id") or "")
        for row in component_receipt.get("components") or []
        if row.get("is_signed_policy_root") and row.get("resolution") == "EXACT_DEFINITION"
    }
    unresolved_policy_components = [
        {"normalized_name": row.get("normalized_name"), "resolution": row.get("resolution")}
        for row in component_receipt.get("components") or []
        if row.get("is_signed_policy_root") and row.get("resolution") != "EXACT_DEFINITION"
    ]
    partitions = {"APP_OWNED": [], "EXCLUDED_THIRD_PARTY": [], "HOLD": []}
    seen: set[str] = set()
    allowed_kinds = {"class", "method", "js_module", "resource", "config", "text"}

    def canonical_class(value: str) -> str:
        if value.startswith("L") and value.endswith(";"):
            value = value[1:-1].replace("/", ".")
        return value

    for entity in manifest.get("entities") or []:
        entity_id = str(entity.get("entity_id") or "")
        kind = str(entity.get("entity_kind") or "")
        digest = str(entity.get("artifact_sha256") or "")
        qualified = str(entity.get("qualified_name") or "")
        if not entity_id or entity_id in seen or kind not in allowed_kinds or len(digest) != 64:
            raise ValueError("extracted entity identity is incomplete or duplicated")
        seen.add(entity_id)
        artifact_path, artifact_payload = _verify_descriptor(entity.get("artifact"), roots)
        if _sha(artifact_payload) != digest:
            raise ValueError(f"extracted entity artifact binding mismatch: {artifact_path}")
        fingerprint = str(entity.get("entity_fingerprint_sha256") or digest)
        if len(fingerprint) != 64:
            raise ValueError("extracted entity fingerprint is invalid")
        forced_disposition = entity.get("forced_disposition")
        if forced_disposition not in {None, "HOLD"}:
            raise ValueError("extracted entity contains an invalid forced disposition")
        if forced_disposition == "HOLD":
            decision, basis = "HOLD", {"basis": "deterministic-parser-forced-hold"}
        else:
            decision, basis = _policy_decision(
                policy, target_kind=kind, target_id=entity_id, digest=fingerprint,
            )
        if (
            kind in {"resource", "config", "text"}
            and decision != "EXCLUDED_THIRD_PARTY"
            and str(entity.get("parse_status") or "") not in {
                "json-validated", "xml-validated", "utf8-validated", "apktool-decoded-utf8",
            }
        ):
            decision, basis = "HOLD", {"basis": "deterministic-parser-did-not-produce-model-visible-text"}
        if decision is None and kind in {"class", "method"}:
            owner_class = canonical_class(str(entity.get("declaring_class") or qualified.split("->", 1)[0]))
            exact_roots = [
                root for root, root_entity_id in resolved_components.items()
                if root_entity_id and (
                    (kind == "class" and entity_id == root_entity_id)
                    or (kind == "method" and owner_class == canonical_class(root))
                )
            ]
            if len(exact_roots) == 1:
                decision, basis = "APP_OWNED", {
                    "basis": "signed-manifest-component-exact-dex-definition",
                    "component": exact_roots[0],
                    "component_definition_receipt": component_descriptor,
                    "root_entity_id": resolved_components[exact_roots[0]],
                }
        if decision is None:
            decision, basis = "HOLD", {"basis": "ownership-unresolved-no-package-guess"}
        partitions[decision].append({**entity, "ownership_disposition": decision, "ownership_basis": basis})
    if not _within(output, roots):
        raise ValueError("entity ownership output escapes trusted roots")
    output.mkdir(parents=True, exist_ok=True)
    set_id = _sha(_canonical({
        "source_sha256": _sha(payload), "policy_id": policy["policy_id"],
        "component_definition_receipt_sha256": component_descriptor["sha256"],
        "entity_ids": sorted(seen),
    }))
    descriptors = {}
    for disposition, rows in partitions.items():
        descriptors[disposition] = _signed_file(output / f"{disposition}_ENTITIES.json", {
            "schema": ENTITY_MANIFEST_SCHEMA, "ownership_set_id": set_id,
            "plan_id": manifest.get("plan_id"),
            "routing_set_id": manifest.get("routing_set_id"),
            "source_manifest": {"path": str(manifest_path), "sha256": _sha(payload)},
            "ownership_policy_id": policy["policy_id"], "disposition": disposition,
            "component_definition_receipt": component_descriptor,
            "entity_count": len(rows), "entities": sorted(rows, key=lambda row: row["entity_id"]),
        })
    return {
        "ownership_set_id": set_id, "entity_count": len(seen), "manifests": descriptors,
        "component_definition_receipt": component_descriptor,
        "resolved_policy_component_roots": len(resolved_components),
        "unresolved_policy_components": unresolved_policy_components,
    }
