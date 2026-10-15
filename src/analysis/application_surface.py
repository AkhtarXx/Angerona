"""Ownership-neutral Android application-surface accounting.

This module deliberately does not infer source ownership.  It binds manifest
component names to exact DEX definitions when possible and builds a separate
surface queue for configuration and externally reachable application behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .audit_lineage import open_verified_artifact
from .evidence_signing import (
    canonical_payload, sign_document, verify_document, with_document_identity,
)
from .signed_artifact_io import (
    load_signed_canonical, validate_extracted_entity_manifest, write_signed_canonical,
)
from .schema_validation import canonical_order_rows, canonical_order_values


COMPONENT_SCHEMA = "angerona/manifest-component-definition-receipt/v1"
SURFACE_SCHEMA = "angerona/application-surface-manifest/v1"
OCCURRENCE_SCHEMA = "angerona/application-surface-occurrence-index/v1"
QUEUE_SCHEMA = "angerona/application-surface-queue/v1"
EXTRACTED_SCHEMA = "angerona/extracted-entity-manifest/v1"
RELATIONSHIP_SCHEMA = "angerona/dex-relationship-index/v1"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_TEXT_BYTES = 4 * 1024 * 1024
# Lossless byte-stream splitting keeps each model-visible scope bounded while
# the signed occurrence/queue manifests continue to conserve the whole source.
CHUNK_BYTES = 4 * 1024

_SURFACE_BASENAMES = {
    "androidmanifest.xml", "network_security_config.xml", "backup_rules.xml",
    "data_extraction_rules.xml", "file_paths.xml", "config.xml", "cordova.xml",
    "index.html", "package.json", "assetlinks.json",
}
_SURFACE_SUFFIXES = {
    ".xml", ".json", ".html", ".htm",
    ".css", ".scss", ".properties", ".conf", ".cfg", ".ini", ".pem",
    ".cer", ".crt", ".der", ".p12", ".pfx", ".jks", ".bks",
}
_TEXT_MEDIA_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript")
_RESOURCE_REF = re.compile(r"@(?:[A-Za-z0-9_.]+:)?([A-Za-z0-9_]+)/([A-Za-z0-9_.-]+)")
_URL = re.compile(rb"(?i)\b(?:https?|wss?)://[^\s\"'<>\\]+")
_CSP = re.compile(rb"(?is)(?:content-security-policy|default-src|script-src|connect-src)[^\r\n<>]{0,4096}")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _descriptor(path: Path, payload: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha(payload)}


def _write_signed(path: Path, body: dict[str, Any]) -> dict[str, str]:
    return write_signed_canonical(path, body)


def _load_signed(descriptor: dict[str, Any], roots: Iterable[str | Path], schema: str) -> dict[str, Any]:
    _path, document = load_signed_canonical(descriptor, roots, schema=schema)
    return document


def _binding(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": plan["plan_id"],
        "routing_set_id": plan["routing_set_id"],
        "ownership_policy": plan["ownership_policy"],
        "audit_epoch": plan.get("audit_epoch"),
    }


def _assert_binding(document: dict[str, Any], plan: dict[str, Any]) -> None:
    for key, value in _binding(plan).items():
        if document.get(key) != value:
            raise ValueError(f"application-surface dependency has mixed {key}")


def _assert_extracted_binding(document: dict[str, Any], plan: dict[str, Any]) -> None:
    validate_extracted_entity_manifest(document, plan)


def _normalize_component(package_name: str, raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("manifest component name is empty")
    if value.startswith("."):
        return package_name + value
    if "." not in value:
        return f"{package_name}.{value}" if package_name else value
    return value


def _descriptor_name(java_name: str) -> str:
    return "L" + java_name.replace(".", "/") + ";"


def _find_occurrences(payload: bytes, needle: str, artifact: dict[str, str], role: str) -> list[dict[str, Any]]:
    raw = needle.encode("utf-8")
    result: list[dict[str, Any]] = []
    cursor = 0
    while raw:
        offset = payload.find(raw, cursor)
        if offset < 0:
            break
        row = {
            "artifact": artifact, "byte_start": offset, "byte_end": offset + len(raw),
            "excerpt_sha256": _sha(raw), "semantic_role": role,
        }
        row["occurrence_id"] = "surface-occurrence:" + _sha(canonical_payload(row))
        result.append(row)
        cursor = offset + len(raw)
    return result


def _entity_artifact(entity: dict[str, Any]) -> dict[str, str] | None:
    for key in ("artifact", "source_artifact", "decoded_artifact", "content_artifact"):
        value = entity.get(key)
        if isinstance(value, dict) and value.get("path") and value.get("sha256"):
            return {"path": str(value["path"]), "sha256": str(value["sha256"])}
    path = entity.get("artifact_path") or entity.get("path")
    digest = entity.get("artifact_sha256") or entity.get("sha256")
    return {"path": str(path), "sha256": str(digest)} if path and digest else None


def _collect_dependencies(
    extracted_manifests: list[dict[str, Any]], roots: list[str], plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    relationship_descriptors: set[tuple[str, str]] = set()
    for descriptor in extracted_manifests:
        manifest = _load_signed(descriptor, roots, EXTRACTED_SCHEMA)
        _assert_extracted_binding(manifest, plan)
        for entity in manifest.get("entities") or []:
            if not isinstance(entity, dict) or not entity.get("entity_id"):
                raise ValueError("extracted manifest has malformed entity")
            entities.append(entity)
        for source in manifest.get("source_artifacts") or []:
            relation = source.get("relationship_index") if isinstance(source, dict) else None
            if not isinstance(relation, dict):
                continue
            key = (str(relation.get("path") or ""), str(relation.get("sha256") or ""))
            if not all(key) or key in relationship_descriptors:
                continue
            document = _load_signed(relation, roots, RELATIONSHIP_SCHEMA)
            _assert_binding(document, plan)
            relationships.append({"descriptor": relation, "document": document})
            relationship_descriptors.add(key)
    ids = [str(row["entity_id"]) for row in entities]
    if len(ids) != len(set(ids)):
        raise ValueError("extracted entity membership contains duplicates")
    return entities, relationships


def _manifest_components(root: ET.Element, package_name: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    application = root.find("application")
    if application is None:
        return rows
    for kind, node in (("application", application), ("appComponentFactory", application)):
        attribute = ANDROID_NS + ("appComponentFactory" if kind == "appComponentFactory" else "name")
        raw = node.attrib.get(attribute)
        if raw:
            rows.append({"kind": kind, "raw_name": raw, "normalized_name": _normalize_component(package_name, raw)})
    for tag in ("activity", "activity-alias", "service", "receiver", "provider", "instrumentation"):
        nodes = list(application.findall(tag))
        if tag == "instrumentation":
            nodes.extend(root.findall(tag))
        for node in nodes:
            raw = node.attrib.get(ANDROID_NS + "name")
            if raw:
                rows.append({"kind": tag, "raw_name": raw, "normalized_name": _normalize_component(package_name, raw)})
            target = node.attrib.get(ANDROID_NS + "targetActivity")
            if target:
                rows.append({"kind": "activity-alias-target", "raw_name": target, "normalized_name": _normalize_component(package_name, target)})
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in rows:
        unique[(row["kind"], row["raw_name"], row["normalized_name"])] = row
    return [unique[key] for key in sorted(unique)]


def _manifest_surface_facts(root: ET.Element, package_name: str) -> dict[str, Any]:
    application = root.find("application")
    components = []
    if application is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in application.findall(tag):
                raw_name = str(node.attrib.get(ANDROID_NS + "name") or "")
                filters = []
                for intent in node.findall("intent-filter"):
                    filters.append({
                        "actions": sorted(str(item.attrib.get(ANDROID_NS + "name") or "") for item in intent.findall("action")),
                        "categories": sorted(str(item.attrib.get(ANDROID_NS + "name") or "") for item in intent.findall("category")),
                        "data": [dict(sorted(item.attrib.items())) for item in intent.findall("data")],
                    })
                components.append({
                    "kind": tag,
                    "normalized_name": _normalize_component(package_name, raw_name) if raw_name else "",
                    "exported": node.attrib.get(ANDROID_NS + "exported"),
                    "permission": node.attrib.get(ANDROID_NS + "permission"),
                    "authorities": node.attrib.get(ANDROID_NS + "authorities"),
                    "grant_uri_permissions": node.attrib.get(ANDROID_NS + "grantUriPermissions"),
                    "intent_filters": filters,
                })
    return {
        "package": package_name,
        "uses_permissions": sorted({
            str(node.attrib.get(ANDROID_NS + "name") or "")
            for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")
            for node in root.findall(tag)
            if node.attrib.get(ANDROID_NS + "name")
        }),
        "application": ({
            "debuggable": application.attrib.get(ANDROID_NS + "debuggable"),
            "uses_cleartext_traffic": application.attrib.get(ANDROID_NS + "usesCleartextTraffic"),
            "network_security_config": application.attrib.get(ANDROID_NS + "networkSecurityConfig"),
            "allow_backup": application.attrib.get(ANDROID_NS + "allowBackup"),
            "backup_agent": application.attrib.get(ANDROID_NS + "backupAgent"),
            "full_backup_content": application.attrib.get(ANDROID_NS + "fullBackupContent"),
            "data_extraction_rules": application.attrib.get(ANDROID_NS + "dataExtractionRules"),
        } if application is not None else {}),
        "components": components,
    }


def _policy_roots(policy: dict[str, Any]) -> set[str]:
    roots: set[str] = set()
    for key in ("manifest_component_roots", "application_roots", "component_roots"):
        for value in policy.get(key) or []:
            if isinstance(value, str):
                roots.add(value)
            elif isinstance(value, dict):
                name = value.get("normalized_name") or value.get("component_name") or value.get("name")
                if name:
                    roots.add(str(name))
    return roots


def _safe_text(entity: dict[str, Any], payload: bytes) -> str | None:
    if len(payload) > MAX_TEXT_BYTES:
        return None
    media = str(entity.get("media_type") or entity.get("content_type") or "").lower()
    route = str(entity.get("parser_route") or entity.get("route") or "").lower()
    if media.startswith(_TEXT_MEDIA_PREFIXES) or any(token in route for token in ("xml", "json", "html", "css", "javascript", "text")):
        try:
            return payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    suffix = Path(str(entity.get("qualified_name") or entity.get("path") or "")).suffix.lower()
    if suffix in {".xml", ".json", ".map", ".html", ".htm", ".js", ".mjs", ".cjs", ".css", ".scss", ".properties", ".conf", ".cfg", ".ini", ".txt"}:
        try:
            return payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    return None


def _utf8_chunks(text: str) -> Iterable[tuple[int, bytes]]:
    start = 0
    chunk = bytearray()
    for character in text:
        encoded = character.encode("utf-8")
        if chunk and len(chunk) + len(encoded) > CHUNK_BYTES:
            yield start, bytes(chunk)
            start += len(chunk)
            chunk.clear()
        chunk.extend(encoded)
    if chunk:
        yield start, bytes(chunk)


def _surface_seed(entity: dict[str, Any]) -> bool:
    if str(entity.get("entity_kind") or "") in {"class", "method", "js_module", "native_target"}:
        return False
    name = str(entity.get("qualified_name") or entity.get("path") or "").replace("\\", "/").lower()
    base = Path(name).name
    suffix = Path(base).suffix
    if base in _SURFACE_BASENAMES:
        return True
    if suffix in _SURFACE_SUFFIXES and any(marker in name for marker in (
        "manifest", "network", "security", "backup", "provider", "paths", "config",
        "cordova", "webview", "www/", "assets/", "res/xml/", "certificate", "cert",
    )):
        return True
    return False


def _reference_keys(entity: dict[str, Any]) -> set[str]:
    name = str(entity.get("qualified_name") or entity.get("path") or "").replace("\\", "/")
    result: set[str] = set()
    match = re.search(r"(?:^|/)res/([^/]+)/([^/.]+)", name)
    if match:
        result.add(f"{match.group(1).split('-')[0]}/{match.group(2)}")
    return result


def build_application_surface(
    *, plan: dict[str, Any], extracted_manifests: list[dict[str, Any]],
    parent_lane_receipts: list[dict[str, Any]], routing_plan: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    if not isinstance(plan.get("audit_epoch"), dict) or not plan["audit_epoch"].get("epoch_id"):
        raise ValueError("application-surface generation requires an immutable audit epoch")
    roots = [str(item) for item in plan.get("trusted_roots") or []]
    if not roots:
        raise ValueError("application-surface generation requires trusted roots")
    entities, relationships = _collect_dependencies(extracted_manifests, roots, plan)
    manifest_candidates = [row for row in entities if str(row.get("qualified_name") or "").lower().endswith("androidmanifest.xml")]
    if len(manifest_candidates) != 1:
        raise ValueError("application surface requires exactly one final merged AndroidManifest.xml entity")
    manifest_entity = manifest_candidates[0]
    manifest_artifact = _entity_artifact(manifest_entity)
    if not manifest_artifact:
        raise ValueError("manifest entity lacks exact artifact descriptor")
    _manifest_path, manifest_payload = open_verified_artifact(manifest_artifact, roots)
    try:
        manifest_root = ET.fromstring(manifest_payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ET.ParseError) as exc:
        raise ValueError("final merged AndroidManifest.xml is not strict decoded XML") from exc
    package_name = str(manifest_root.attrib.get("package") or "")
    manifest_surface_facts = _manifest_surface_facts(manifest_root, package_name)

    definitions: dict[str, list[dict[str, Any]]] = {}
    relationship_descriptors = []
    for relationship in relationships:
        relationship_descriptors.append(relationship["descriptor"])
        for row in (
            relationship["document"].get("class_definitions")
            or relationship["document"].get("definitions")
            or relationship["document"].get("classes")
            or []
        ):
            descriptor = str(row.get("descriptor") or "")
            if descriptor:
                definitions.setdefault(descriptor, []).append({
                    "entity_id": row.get("entity_id"), "dex_artifact": relationship["document"].get("dex_artifact"),
                    "relationship_index": relationship["descriptor"], "definition_byte_start": row.get("definition_byte_start"),
                    "definition_byte_end": row.get("definition_byte_end"), "definition_sha256": row.get("definition_sha256"),
                })
    policy_descriptor = plan["ownership_policy"]
    policy = _load_signed(policy_descriptor, roots, "angerona/audit-ownership-policy/v1")
    policy_names = _policy_roots(policy)
    component_rows: list[dict[str, Any]] = []
    component_occurrences: list[dict[str, Any]] = []
    for component in _manifest_components(manifest_root, package_name):
        descriptor = _descriptor_name(component["normalized_name"])
        matches = definitions.get(descriptor, [])
        if len(matches) == 1 and matches[0].get("entity_id") and matches[0].get("definition_sha256"):
            resolution = "EXACT_DEFINITION"
            definition = matches[0]
            unresolved_reason = None
        elif matches:
            resolution = "PROTECTED_NAME_UNRESOLVED"
            definition = None
            unresolved_reason = "ambiguous-or-incomplete-dex-definition-evidence"
        else:
            resolution = "PROTECTED_NAME_UNRESOLVED"
            definition = None
            unresolved_reason = "no-exact-dex-definition"
        occurrences = _find_occurrences(manifest_payload, component["raw_name"], manifest_artifact, "manifest-component-name")
        if not occurrences:
            raise ValueError("normalized manifest component lacks exact manifest occurrence")
        component_occurrences.extend(occurrences)
        component_rows.append({
            **component, "descriptor": descriptor, "resolution": resolution,
            "unresolved_reason": unresolved_reason,
            "definition": definition, "definition_candidates": matches if len(matches) > 1 else [],
            "is_signed_policy_root": component["normalized_name"] in policy_names,
            "manifest_occurrence_ids": canonical_order_values(
                COMPONENT_SCHEMA, "manifest_occurrence_ids",
                [row["occurrence_id"] for row in occurrences],
                context=f"manifest component {component['normalized_name']}",
            ),
        })
    component_occurrences = list({
        row["occurrence_id"]: row for row in component_occurrences
    }.values())
    output = Path(output_dir).resolve()
    binding = _binding(plan)
    component_descriptor = _write_signed(output / "MANIFEST_COMPONENT_DEFINITION_RECEIPT.json", {
        "schema": COMPONENT_SCHEMA, **binding, "manifest_entity_id": manifest_entity["entity_id"],
        "manifest_artifact": manifest_artifact, "relationship_indexes": relationship_descriptors,
        "manifest_transform_receipt": manifest_entity.get("axml_transform_receipt"),
        "components": component_rows, "component_count": len(component_rows),
        "resolution_counts": {status: sum(row["resolution"] == status for row in component_rows) for status in (
            "EXACT_DEFINITION", "PROTECTED_NAME_UNRESOLVED")},
        "ownership_semantics": "exact-definition-corroboration-only-no-package-or-path-inference",
    })

    entity_by_id = {str(row["entity_id"]): row for row in entities}
    selected = {str(row["entity_id"]) for row in entities if _surface_seed(row)}
    selected.add(str(manifest_entity["entity_id"]))
    resource_index: dict[str, set[str]] = {}
    for row in entities:
        for key in _reference_keys(row):
            resource_index.setdefault(key, set()).add(str(row["entity_id"]))
    changed = True
    while changed:
        changed = False
        for entity_id in list(selected):
            entity = entity_by_id[entity_id]
            artifact = _entity_artifact(entity)
            if not artifact:
                continue
            _path, payload = open_verified_artifact(artifact, roots)
            text = _safe_text(entity, payload)
            if text is None:
                continue
            for resource_type, resource_name in _RESOURCE_REF.findall(text):
                for candidate in resource_index.get(f"{resource_type}/{resource_name}", set()):
                    if candidate not in selected:
                        selected.add(candidate)
                        changed = True

    occurrence_rows = list(component_occurrences)
    surface_rows: list[dict[str, Any]] = []
    queue_rows: list[dict[str, Any]] = []
    for entity_id in sorted(selected):
        entity = entity_by_id[entity_id]
        artifact = _entity_artifact(entity)
        if not artifact:
            raise ValueError("application-surface entity lacks exact artifact descriptor")
        _path, payload = open_verified_artifact(artifact, roots)
        text = _safe_text(entity, payload)
        integrated_excluded = str(entity.get("ownership") or entity.get("disposition") or "") == "FULLY_EXCLUDED"
        surface_rows.append({
            "entity_id": entity_id, "artifact": artifact,
            "qualified_name": entity.get("qualified_name"), "parser_route": entity.get("parser_route") or entity.get("route"),
            "parser_metadata": entity.get("parser_metadata") or entity.get("metadata") or {},
            "transform_receipt": entity.get("axml_transform_receipt"),
            "ownership": entity.get("ownership") or entity.get("disposition") or "UNKNOWN",
            "surface_semantics": "integrated-application-surface-not-code-ownership",
            "third_party_code_excluded": integrated_excluded,
        })
        if text is None:
            continue
        for regex, role in ((_URL, "endpoint"), (_CSP, "content-security-policy")):
            for match in regex.finditer(payload):
                excerpt = payload[match.start():match.end()]
                occurrence = {
                    "artifact": artifact, "entity_id": entity_id, "byte_start": match.start(),
                    "byte_end": match.end(), "excerpt_sha256": _sha(excerpt), "semantic_role": role,
                }
                occurrence["occurrence_id"] = "surface-occurrence:" + _sha(canonical_payload(occurrence))
                occurrence_rows.append(occurrence)
        for start, chunk in _utf8_chunks(text):
            chunk_occurrence = {
                "artifact": artifact, "entity_id": entity_id, "byte_start": start,
                "byte_end": start + len(chunk), "excerpt_sha256": _sha(chunk),
                "semantic_role": "surface-context",
            }
            chunk_occurrence["occurrence_id"] = "surface-occurrence:" + _sha(canonical_payload(chunk_occurrence))
            occurrence_rows.append(chunk_occurrence)
            unit = {
                "schema": "angerona/application-surface-work-unit/v1",
                **binding, "unit_kind": "application_surface_chunk", "entity_id": entity_id,
                "artifact": artifact, "byte_start": start, "byte_end": start + len(chunk),
                "excerpt_sha256": _sha(chunk), "content": chunk.decode("utf-8", "strict"),
                "occurrence_ids": [chunk_occurrence["occurrence_id"]],
                "ownership_claim": "NONE", "surface_semantics": "integrated-application-surface",
            }
            unit["unit_id"] = "application-surface:" + _sha(canonical_payload(unit))
            queue_rows.append(unit)
    occurrence_rows = canonical_order_rows(
        OCCURRENCE_SCHEMA, "occurrences", occurrence_rows,
        context="application-surface occurrence index",
    )
    occurrence_descriptor = _write_signed(output / "APPLICATION_SURFACE_OCCURRENCES.json", {
        "schema": OCCURRENCE_SCHEMA, **binding, "manifest_artifact": manifest_artifact,
        "component_definition_receipt": component_descriptor, "occurrences": occurrence_rows,
        "occurrence_count": len(occurrence_rows),
    })
    for unit in queue_rows:
        unit.pop("unit_id", None)
        unit["occurrences"] = canonical_order_rows(
            "angerona/application-surface-work-unit/v1", "occurrences", [
            row for row in occurrence_rows
            if row.get("artifact") == unit["artifact"]
            and int(row.get("byte_start", -1)) >= int(unit["byte_start"])
            and int(row.get("byte_end", -1)) <= int(unit["byte_end"])
        ], context=f"application-surface unit {unit.get('entity_id')}")
        unit["occurrence_ids"] = canonical_order_values(
            "angerona/application-surface-work-unit/v1", "occurrence_ids",
            [row["occurrence_id"] for row in unit["occurrences"]],
            context=f"application-surface unit {unit.get('entity_id')}",
        )
        if not unit["occurrence_ids"]:
            raise ValueError("application-surface unit lacks an exact occurrence receipt")
        unit["class_id"] = unit["entity_id"]
        unit["source_sha256"] = unit["artifact"]["sha256"]
        unit["input_manifest_sha256"] = occurrence_descriptor["sha256"]
        unit["occurrence_index"] = occurrence_descriptor
        unit["unit_id"] = "application-surface:" + _sha(canonical_payload(unit))
    third_party_exclusion = (
        (plan.get("partition_manifests") or {}).get("FULLY_EXCLUDED")
        or (plan.get("partition_manifests") or {}).get("EXCLUDED_THIRD_PARTY")
    )
    if not isinstance(third_party_exclusion, dict):
        raise ValueError("application surface lacks the signed third-party exclusion partition")
    surface_rows = canonical_order_rows(
        SURFACE_SCHEMA, "entities", surface_rows,
        context="application-surface manifest",
    )
    surface_descriptor = _write_signed(output / "APPLICATION_SURFACE_MANIFEST.json", {
        "schema": SURFACE_SCHEMA, **binding, "manifest_artifact": manifest_artifact,
        "component_definition_receipt": component_descriptor, "occurrence_index": occurrence_descriptor,
        "entities": surface_rows, "entity_count": len(surface_rows),
        "manifest_surface_facts": manifest_surface_facts,
        "code_ownership_claimed": False, "resource_reference_closure_complete": True,
        "signed_third_party_exclusion_manifest": third_party_exclusion,
        "third_party_semantics": "integrated-configuration-may-be-reviewed-but-excluded-code-remains-excluded",
    })
    queue_rows = canonical_order_rows(
        QUEUE_SCHEMA, "$rows", queue_rows, context="application-surface queue",
    )
    queue_jsonl = output / "APPLICATION_SURFACE_QUEUE.jsonl"
    queue_payload = b"".join(canonical_payload(row) + b"\n" for row in queue_rows)
    queue_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if queue_jsonl.exists() and queue_jsonl.read_bytes() != queue_payload:
        raise FileExistsError("refusing to replace immutable application-surface queue")
    if not queue_jsonl.exists():
        queue_jsonl.write_bytes(queue_payload)
    queue_artifact = _descriptor(queue_jsonl, queue_payload)
    queue_descriptor = _write_signed(output / "APPLICATION_SURFACE_QUEUE_MANIFEST.json", {
        "schema": QUEUE_SCHEMA, **binding, "surface_manifest": surface_descriptor,
        "routing_plan": routing_plan,
        "occurrence_index": occurrence_descriptor, "queue": queue_artifact,
        "parent_receipts": sorted(parent_lane_receipts, key=lambda row: (row["path"], row["sha256"])),
        "source_extracted_manifests": sorted(extracted_manifests, key=lambda row: (row["path"], row["sha256"])),
        "unit_count": len(queue_rows), "unit_ids": canonical_order_values(
            QUEUE_SCHEMA, "unit_ids", [row["unit_id"] for row in queue_rows],
            context="application-surface queue manifest",
        ),
        "ownership_claimed": False, "code_entity_unit_count": 0,
        "terminal_partition_complete": True,
    })
    parents = sorted(parent_lane_receipts, key=lambda row: (row["path"], row["sha256"]))
    lineage_body = {
        "schema": "angerona/application-surface-derived-queue/v1",
        "audit_epoch_id": str((plan.get("audit_epoch") or {}).get("epoch_id") or ""),
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "routing_plan": routing_plan,
        "ownership_policy": plan["ownership_policy"],
        "queue_path": queue_artifact["path"], "queue_sha256": queue_artifact["sha256"],
        "unit_count": len(queue_rows), "derivation_manifest": queue_descriptor,
        "parent_receipts": parents, "parent_set_sha256": _sha(canonical_payload(parents)),
        "source_extracted_manifests": sorted(extracted_manifests, key=lambda row: (row["path"], row["sha256"])),
        "occurrence_index": occurrence_descriptor,
        "derivation_semantics": "ownership-neutral-application-surface",
    }
    if not lineage_body["audit_epoch_id"]:
        raise ValueError("application-surface derived queue requires an audit epoch identity")
    lineage_descriptor = _write_signed(
        queue_jsonl.with_name(queue_jsonl.name + ".lineage.json"),
        with_document_identity(lineage_body),
    )
    return {
        "component_definition_receipt": component_descriptor,
        "surface_manifest": surface_descriptor, "occurrence_index": occurrence_descriptor,
        "queue": queue_artifact, "queue_manifest": queue_descriptor,
        "queue_lineage": lineage_descriptor,
        "entity_count": len(surface_rows), "unit_count": len(queue_rows),
    }
