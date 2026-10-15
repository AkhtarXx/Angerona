"""Signed adapters joining clean routing to deterministic Android audit lanes.

All functions are fail-closed and are intended to be invoked by the signed
clean-audit orchestrator.  Indexing is allowed before ownership; reconstruction
and model review consume only signed APP_OWNED entity manifests.
"""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any, Iterable
import xml.etree.ElementTree as ET
import zipfile

from .audit_lineage import (
    load_audit_epoch, open_verified_artifact, queue_matches_epoch,
    output_is_in_epoch, seal_checkpoint_set, verify_checkpoint_set,
)
from .clean_audit_routing import (
    EXECUTION_SCHEMA, EXTRACTED_MANIFEST_SCHEMA, classify_extracted_entities,
    verify_clean_apk_routing_plan,
)
from .cross_layer_graph import build_cross_layer_graph
from .dex_reconstruction_receipt import build_apk_dex_receipts
from .dex_relationship_index import build_dex_relationship_index
from .dynamic_security_planner import build_dynamic_security_plan
from .application_surface import (
    QUEUE_SCHEMA as APPLICATION_SURFACE_QUEUE_SCHEMA,
    build_application_surface,
)
from .evidence_signing import canonical_payload, sign_document, verify_document
from .jadx_bridge import find_jadx_cli
from .apktool_bridge import decode_apk, find_apktool
from .semantic_ai_controller import run_semantic_ai_queue
from .native_ownership_manifest import LANE_RECEIPT_SCHEMA
from .native_target_universe import ROOT_CONSERVATION_SCHEMA
from .signed_artifact_io import (
    extracted_manifest_bindings, load_signed_canonical,
    validate_extracted_entity_manifest, write_signed_canonical,
)
from .schema_validation import (
    canonical_order_rows, canonical_order_values,
    optional_int_field, optional_nullable_int_field,
    require_int_field, require_list_field,
)


QUEUE_MANIFEST_SCHEMA = "angerona/app-owned-semantic-queue-manifest/v1"
QUEUE_EPOCH_ATTACHMENT_SCHEMA = "angerona/semantic-queue-epoch-attachment/v1"
EXECUTION_SOURCE_SCHEMA = "angerona/clean-audit-execution-spec-source/v1"
MAX_DECODED_RESOURCE_FILES = 250_000
MAX_DECODED_RESOURCE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_DECODED_RESOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES = 8 * 1024 * 1024

_JS_RELATION = re.compile(
    rb"(?m)(?:\bimport\s+(?:[^;\r\n]*?\s+from\s+)?|\bexport\s+[^;\r\n]*?\s+from\s+|\brequire\s*\()"
    rb"[\"']([^\"'\r\n]+)[\"']"
)

LANE_SCHEMAS = {
    "deterministic_parse": "angerona/deterministic-artifact-parse-receipt/v1",
    "dex_index": "angerona/dex-ownership-index-receipt/v1",
    "hermes_index": "angerona/hermes-ownership-index-receipt/v1",
    "application_surface": "angerona/application-surface-completion-receipt/v1",
    "surface_semantic": "angerona/application-surface-semantic-completion-receipt/v1",
    "ownership_filter": "angerona/clean-ownership-filter-receipt/v1",
    "app_reconstruction": "angerona/app-owned-reconstruction-receipt/v1",
    "ai_review": "angerona/app-owned-ai-review-receipt/v1",
    "native_acceptance": "angerona/clean-native-acceptance-receipt/v1",
    "cross_layer_merge": "angerona/clean-cross-layer-merge-receipt/v1",
    "dynamic_security_plan": "angerona/dynamic-security-planning-completion-receipt/v1",
}


def _canonical(value: Any) -> bytes:
    return canonical_payload(value)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _descriptor(path: str | Path) -> dict[str, str]:
    resolved = Path(path).expanduser().resolve(strict=True)
    return {"path": str(resolved), "sha256": _sha(resolved.read_bytes())}


def _javascript_source_index(payload: bytes) -> dict[str, Any]:
    relations = []
    for match in _JS_RELATION.finditer(payload):
        start, end = match.span(1)
        excerpt = payload[start:end]
        relations.append({
            "byte_start": start, "byte_end": end, "excerpt_sha256": _sha(excerpt),
            "module_specifier": excerpt.decode("utf-8", "strict"),
            "evidence_semantics": "lexical-import-export-require-candidate-not-code-ownership",
        })
    return {
        "schema": "angerona/javascript-source-relationship-index/v1",
        "instruction_semantics": "index-only-no-ai-no-ownership-inference",
        "module_relations": relations, "module_relation_count": len(relations),
        "source_bytes_sha256": _sha(payload),
    }


def _stream_descriptor(path: str | Path) -> dict[str, str]:
    resolved = Path(path).expanduser().resolve(strict=True)
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(resolved), "sha256": digest.hexdigest()}


def _classify_decoded_resource(
    relative: str, payload: bytes,
) -> tuple[str, str | None, str | None, dict[str, Any]]:
    lower = relative.lower()
    suffix = Path(lower).suffix
    if len(payload) <= MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES:
        if suffix == ".xml":
            try:
                text = payload.decode("utf-8", errors="strict")
                root = ET.fromstring(text)
            except (UnicodeDecodeError, ET.ParseError):
                return "HOLD", None, "invalid-or-non-utf8-xml", {}
            local_tag = str(root.tag).rsplit("}", 1)[-1]
            media = "image/svg+xml" if local_tag == "svg" else "application/vnd.android.vector+xml" if local_tag in {
                "vector", "animated-vector", "selector", "shape",
            } else "application/xml"
            return "MODEL_VISIBLE_TEXT", media, None, {"xml_root": local_tag}
        if suffix in {".json", ".map"}:
            try:
                text = payload.decode("utf-8", errors="strict")
                parsed_json = json.loads(text)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return "HOLD", None, "invalid-or-non-utf8-json", {}
            if suffix == ".map" and not isinstance(parsed_json, dict):
                return "HOLD", None, "source-map-root-is-not-object", {}
            return "MODEL_VISIBLE_TEXT", "application/json", None, {
                "format": "source-map" if suffix == ".map" else "json",
            }
        if suffix in {
            ".txt", ".cfg", ".conf", ".ini", ".properties", ".yaml",
            ".yml", ".toml", ".csv", ".css", ".scss", ".less",
            ".html", ".htm", ".js", ".mjs", ".cjs", ".md",
        }:
            try:
                text = payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return "HOLD", None, "declared-text-is-not-utf8", {}
            if suffix in {".html", ".htm"}:
                try:
                    parser = HTMLParser(convert_charrefs=True)
                    parser.feed(text)
                    parser.close()
                except Exception as exc:  # HTMLParser reports malformed declarations as errors.
                    return "HOLD", None, "invalid-html5", {"error_class": type(exc).__name__}
                media = "text/html"
            elif suffix in {".js", ".mjs", ".cjs"}:
                media = "application/javascript"
            elif suffix in {".css", ".scss", ".less"}:
                media = "text/css"
            else:
                media = "text/plain"
            metadata = {"format": suffix.lstrip(".")}
            if suffix in {".js", ".mjs", ".cjs"}:
                metadata["javascript_source_index"] = _javascript_source_index(payload)
                metadata["ownership_gate_required_before_semantic_use"] = True
            return "MODEL_VISIBLE_TEXT", media, None, metadata
    elif suffix in {
        ".xml", ".json", ".txt", ".cfg", ".conf", ".ini", ".properties",
        ".yaml", ".yml", ".toml", ".csv", ".css", ".scss", ".less",
        ".html", ".htm", ".js", ".mjs", ".cjs", ".map", ".md",
    }:
        return "HOLD", None, "model-visible-text-size-bound-exceeded", {}

    signatures = [
        (
            suffix == ".kotlin_builtins"
            and payload.startswith(bytes.fromhex("00000003000000010000000000000007")),
            "application/vnd.kotlin.builtins-metadata", "NON_TEXT_METADATA",
        ),
        (payload.startswith(b"\x89PNG\r\n\x1a\n") and suffix == ".png", "image/png", "NON_TEXT_IMAGE_METADATA"),
        (payload.startswith(b"\xff\xd8\xff") and suffix in {".jpg", ".jpeg"}, "image/jpeg", "NON_TEXT_IMAGE_METADATA"),
        (len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WEBP" and suffix == ".webp", "image/webp", "NON_TEXT_IMAGE_METADATA"),
        (payload.startswith((b"GIF87a", b"GIF89a")) and suffix == ".gif", "image/gif", "NON_TEXT_IMAGE_METADATA"),
        (len(payload) >= 12 and payload[4:8] == b"ftyp" and suffix in {".mp4", ".m4a", ".3gp"}, "video/mp4", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith(b"OggS") and suffix in {".ogg", ".oga", ".opus"}, "audio/ogg", "NON_TEXT_MEDIA_METADATA"),
        (len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WAVE" and suffix == ".wav", "audio/wav", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith(b"ID3") and suffix == ".mp3", "audio/mpeg", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith((b"\x00\x01\x00\x00", b"OTTO", b"ttcf")) and suffix in {".ttf", ".otf", ".ttc"}, "font/collection", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith(b"wOFF") and suffix == ".woff", "font/woff", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith(b"wOF2") and suffix == ".woff2", "font/woff2", "NON_TEXT_MEDIA_METADATA"),
        (payload.startswith(b"\xfe\xed\xfe\xed") and suffix in {".jks", ".keystore"}, "application/x-java-keystore", "NON_TEXT_KEYSTORE_METADATA"),
        (len(payload) >= 4 and payload[:4] in {b"\x00\x00\x00\x01", b"\x00\x00\x00\x02"} and suffix == ".bks", "application/x-bouncycastle-keystore", "NON_TEXT_KEYSTORE_METADATA"),
        (len(payload) >= 4 and payload[0] == 0x30 and suffix in {".p12", ".pfx"}, "application/x-pkcs12", "NON_TEXT_KEYSTORE_METADATA"),
        (len(payload) >= 4 and payload[0] == 0x30 and suffix in {".cer", ".crt", ".der"}, "application/pkix-cert", "NON_TEXT_CERTIFICATE_METADATA"),
    ]
    for matched, media_type, route in signatures:
        if matched:
            metadata: dict[str, Any] = {}
            if media_type == "application/vnd.kotlin.builtins-metadata":
                metadata = {
                    "format": "kotlin-builtins-metadata",
                    "metadata_version_words": [
                        struct.unpack(">I", payload[offset:offset + 4])[0]
                        for offset in range(0, 16, 4)
                    ],
                    "contains_executable_code": False,
                    "ownership_inferred": False,
                }
            elif media_type == "image/png" and len(payload) >= 24:
                metadata = {
                    "width": struct.unpack(">I", payload[16:20])[0],
                    "height": struct.unpack(">I", payload[20:24])[0],
                }
            return route, media_type, None, metadata
    if len(payload) >= 4 and payload[:4] == b"\x03\x00\x08\x00":
        return "HOLD", "application/vnd.android.binary-xml", "android-binary-xml-requires-pinned-apktool-mapping", {}
    if len(payload) <= MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES and b"\x00" not in payload:
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = ""
        if text and sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text) >= 0.95:
            return "MODEL_VISIBLE_TEXT", "text/plain", None, {"format": "bounded-utf8-sniff"}
    return "HOLD", None, "unknown-binary-or-extension-magic-mismatch", {}


def _load_pinned_python_wrapper(
    descriptor_path: str | Path, roots: list[Path], expected_role: str,
) -> tuple[list[str], dict[str, Any], dict[str, str]]:
    supplied = Path(descriptor_path).expanduser().resolve(strict=True)
    if not _within(supplied, roots):
        raise ValueError("pinned wrapper descriptor escapes signed roots")
    document = json.loads(supplied.read_bytes())
    if (
        document.get("schema") != "angerona/pinned-python-tool-wrapper/v1"
        or not verify_document(document, require_signature=True)
        or document.get("role") != expected_role
    ):
        raise ValueError("pinned Python wrapper descriptor is unsigned or has the wrong role")
    python_path, _ = open_verified_artifact(document.get("python"), roots)
    script_path, _ = open_verified_artifact(document.get("script"), roots)
    probe_path, probe_payload = open_verified_artifact(document.get("probe_receipt"), roots)
    probe = json.loads(probe_payload)
    if (
        probe.get("schema") != "angerona/operator-tool-prerequisite/v1"
        or not verify_document(probe, require_signature=True)
        or probe.get("status") != "AVAILABLE"
        or probe.get("role") != expected_role
    ):
        raise ValueError("pinned wrapper has no signed AVAILABLE prerequisite")
    return [str(python_path), str(script_path)], document, {
        "path": str(probe_path), "sha256": _sha(probe_payload),
    }


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


def _write_signed(path: Path, body: dict[str, Any]) -> dict[str, str]:
    return write_signed_canonical(path, body)


def _roots(plan: dict[str, Any]) -> list[Path]:
    return [Path(root).resolve(strict=True) for root in plan["trusted_roots"]]


def _confined_output(plan: dict[str, Any], output: str | Path) -> Path:
    path = Path(output).expanduser().resolve()
    root = Path(plan["output_root"]).resolve(strict=True)
    if path != root and root not in path.parents:
        raise ValueError("adapter output escapes the signed plan output root")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _lineage(plan: dict[str, Any], lane: str) -> dict[str, Any]:
    if lane not in LANE_SCHEMAS:
        raise ValueError("unknown clean-audit lane")
    if os.environ.get("ANGERONA_PLAN_ID") != plan["plan_id"]:
        raise ValueError("adapter was not launched for this signed plan")
    if os.environ.get("ANGERONA_ROUTING_SET_ID") != plan["routing_set_id"]:
        raise ValueError("adapter routing-set environment mismatch")
    if os.environ.get("ANGERONA_LANE") != lane:
        raise ValueError("adapter lane environment mismatch")
    try:
        parents = json.loads(os.environ.get("ANGERONA_PARENT_RECEIPTS_JSON", ""))
    except json.JSONDecodeError as exc:
        raise ValueError("adapter parent-receipt environment is invalid") from exc
    if not isinstance(parents, dict):
        raise ValueError("adapter parent receipts must be an object")
    try:
        execution_spec = json.loads(os.environ.get("ANGERONA_EXECUTION_SPEC_DESCRIPTOR_JSON", ""))
        audit_epoch = json.loads(os.environ.get("ANGERONA_AUDIT_EPOCH_DESCRIPTOR_JSON", "null"))
    except json.JSONDecodeError as exc:
        raise ValueError("adapter execution/epoch environment is invalid") from exc
    if not isinstance(execution_spec, dict):
        raise ValueError("adapter execution specification binding is absent")
    spec_path, spec_payload = open_verified_artifact(execution_spec, _roots(plan))
    spec = json.loads(spec_payload)
    if (
        spec.get("schema") != EXECUTION_SCHEMA
        or not verify_document(spec, require_signature=True)
        or spec.get("source_plan_id") != plan["plan_id"]
        or spec.get("routing_set_id") != plan["routing_set_id"]
        or lane not in (spec.get("lanes") or {})
    ):
        raise ValueError(f"adapter execution specification lineage mismatch: {spec_path}")
    for descriptor in [
        *(spec.get("code_artifacts") or []), *(spec.get("argument_artifacts") or []),
        *[
            descriptor for row in (spec.get("lanes") or {}).values()
            for descriptor in (row.get("tool_artifacts") or {}).values()
        ],
    ]:
        open_verified_artifact(descriptor, _roots(plan))
    if audit_epoch:
        epoch_path, epoch_payload = open_verified_artifact(audit_epoch, _roots(plan))
        epoch = load_audit_epoch(epoch_path)
        if audit_epoch.get("epoch_id") != epoch["epoch_id"] or audit_epoch.get("sha256") != _sha(epoch_payload):
            raise ValueError("adapter epoch attachment is invalid")
    return {
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "lane": lane, "parent_receipts": parents,
        "ownership_policy": plan["ownership_policy"],
        "audit_epoch": audit_epoch, "execution_spec": execution_spec,
    }


def _completion(
    plan: dict[str, Any], lane: str, output: Path, body: dict[str, Any],
) -> dict[str, Any]:
    lineage = _lineage(plan, lane)
    root = Path(plan["output_root"]).resolve(strict=True)
    resolved_output = output.resolve()
    if resolved_output != root and root not in resolved_output.parents:
        raise ValueError("completion receipt escapes the signed audit output")
    receipt = {"schema": LANE_SCHEMAS[lane], **lineage, **body}
    descriptor = _write_signed(output, receipt)
    return {**receipt, "descriptor": descriptor}


def _partition_rows(plan: dict[str, Any], disposition: str) -> list[dict[str, Any]]:
    roots = _roots(plan)
    _, payload = open_verified_artifact(plan["partition_manifests"][disposition], roots)
    document = json.loads(payload)
    if not verify_document(document, require_signature=True):
        raise ValueError("routing partition signature is invalid")
    if document.get("routing_set_id") != plan["routing_set_id"] or document.get("disposition") != disposition:
        raise ValueError("routing partition lineage mismatch")
    return list(document.get("entries") or [])


def _route_rows(plan: dict[str, Any], route: str) -> list[dict[str, Any]]:
    return [
        row for disposition in ("APP_OWNED", "FILTER_PENDING")
        for row in _partition_rows(plan, disposition) if row.get("route") == route
    ]


def _write_extracted_manifest(
    plan: dict[str, Any], lane: str, output: Path, entities: list[dict[str, Any]],
    sources: list[dict[str, Any]], limitations: list[str],
) -> dict[str, str]:
    ids = [str(row.get("entity_id") or "") for row in entities]
    if not all(ids) or len(ids) != len(set(ids)):
        raise ValueError("extracted entity identities are empty or duplicated")
    body = {
        "schema": EXTRACTED_MANIFEST_SCHEMA, **extracted_manifest_bindings(plan),
        "producer_lane": lane, "entity_count": len(entities),
        "entities": sorted(entities, key=lambda row: row["entity_id"]),
        "source_artifacts": sources,
        "source_set_sha256": _sha(_canonical(sources)),
        "parent_bindings": sorted(
            [row for row in sources if isinstance(row, dict) and set(row) == {"path", "sha256"}],
            key=lambda row: (row["path"], row["sha256"]),
        ),
        "limitations": limitations,
    }
    return _write_signed(output, body)


def seal_clean_execution_spec(
    plan_path: str | Path, source_spec: str | Path, output_path: str | Path,
    audit_epoch: str | Path | None = None,
) -> dict[str, Any]:
    """Bind executable bytes, adapter source, argv, cwd, and lane schemas."""
    plan = verify_clean_apk_routing_plan(plan_path)
    source = json.loads(Path(source_spec).resolve(strict=True).read_bytes())
    if source.get("schema") != EXECUTION_SOURCE_SCHEMA:
        raise ValueError("unknown execution specification source schema")
    lanes: dict[str, Any] = {}
    for lane, row in (source.get("lanes") or {}).items():
        if lane not in LANE_SCHEMAS or not isinstance(row, dict):
            raise ValueError("execution specification contains an unknown lane")
        argv = row.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(value, str) and value for value in argv):
            raise ValueError("execution lane argv is invalid")
        executable = shutil.which(argv[0]) if not Path(argv[0]).is_absolute() else argv[0]
        if not executable:
            raise ValueError(f"execution lane executable is unavailable: {argv[0]}")
        executable_path = Path(executable).resolve(strict=True)
        completion_schema = str(row.get("completion_schema") or "")
        if completion_schema != LANE_SCHEMAS[lane]:
            raise ValueError("execution lane completion schema is not canonical")
        lanes[lane] = {
            **row, "argv": argv, "cwd": str(Path(row["cwd"]).resolve(strict=True)),
            "completion_schema": completion_schema,
            "executable": _descriptor(executable_path),
        }
        if lane == "app_reconstruction":
            jadx = find_jadx_cli()
            if jadx is None:
                raise ValueError("JADX must be available while sealing app reconstruction")
            lanes[lane]["tool_artifacts"] = {"jadx": _descriptor(jadx)}
        elif lane == "deterministic_parse":
            apktool = find_apktool()
            if apktool is None:
                raise ValueError("apktool must be available while sealing deterministic parsing")
            lanes[lane]["tool_artifacts"] = {"apktool": _descriptor(apktool)}
        probe_value = str((row.get("environment") or {}).get("ANGERONA_TOOL_PROBE_RECEIPT") or "")
        if probe_value:
            probe_path = Path(probe_value).expanduser().resolve(strict=True)
            probe = json.loads(probe_path.read_bytes())
            if (
                probe.get("schema") != "angerona/operator-tool-prerequisite/v1"
                or not verify_document(probe, require_signature=True)
                or probe.get("status") != "AVAILABLE"
            ):
                raise ValueError(f"lane {lane} has no signed AVAILABLE tool prerequisite")
            lanes[lane].setdefault("tool_artifacts", {})["operator_prerequisite"] = _descriptor(probe_path)
    source_files = [
        Path(__file__).resolve(),
        Path(__file__).with_name("clean_audit_routing.py").resolve(),
        Path(__file__).with_name("clean_audit_orchestrator.py").resolve(),
        Path(__file__).parents[1] / "scripts" / "run_clean_audit_adapter.py",
        Path(__file__).with_name("audit_lineage.py").resolve(),
        Path(__file__).with_name("apktool_bridge.py").resolve(),
        Path(__file__).with_name("cross_layer_graph.py").resolve(),
        Path(__file__).with_name("dex_reconstruction_receipt.py").resolve(),
        Path(__file__).with_name("dex_relationship_index.py").resolve(),
        Path(__file__).with_name("application_surface.py").resolve(),
        Path(__file__).with_name("evidence_signing.py").resolve(),
        Path(__file__).with_name("jadx_bridge.py").resolve(),
        Path(__file__).with_name("semantic_ai_controller.py").resolve(),
        Path(__file__).with_name("signed_artifact_io.py").resolve(),
        Path(__file__).with_name("schema_validation.py").resolve(),
        Path(__file__).parents[1] / "scripts" / "clean_android_tool_wrapper.py",
    ]
    argument_artifacts = []
    for row in lanes.values():
        for argument in row["argv"][1:]:
            candidate = Path(argument).expanduser()
            if not candidate.is_absolute():
                candidate = Path(row["cwd"]) / candidate
            if candidate.is_file():
                argument_artifacts.append(_descriptor(candidate))
    epoch_descriptor = None
    if audit_epoch is not None:
        epoch_path = Path(audit_epoch).resolve(strict=True)
        epoch = load_audit_epoch(epoch_path)
        epoch_descriptor = {**_descriptor(epoch_path), "epoch_id": epoch["epoch_id"]}
    body = {
        "schema": EXECUTION_SCHEMA, "source_plan_id": plan["plan_id"],
        "routing_set_id": plan["routing_set_id"], "lanes": lanes,
        "code_artifacts": [_descriptor(path) for path in source_files],
        "argument_artifacts": argument_artifacts, "audit_epoch": epoch_descriptor,
    }
    descriptor = _write_signed(Path(output_path).resolve(), body)
    return {**body, "descriptor": descriptor}


def deterministic_parse_adapter(
    plan_path: str | Path, output_dir: str | Path, completion_receipt: str | Path,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    _lineage(plan, "deterministic_parse")
    output = _confined_output(plan, output_dir)
    route = "deterministic-parser-then-ownership-filter-then-ai"
    rows = _route_rows(plan, route)
    entities: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    limitations: list[str] = []
    parser_terminal_counts = {
        "MODEL_VISIBLE_TEXT": 0, "NON_TEXT_ACCOUNTED": 0,
        "HOLD_PARSE_ERROR": 0, "DECODED_MAPPING_COMPLETE": 0,
    }
    if not rows:
        manifest = _write_extracted_manifest(
            plan, "deterministic_parse", output / "EXTRACTED_ENTITIES.json",
            [], [], [],
        )
        return _completion(plan, "deterministic_parse", Path(completion_receipt).resolve(), {
            "status": "COMPLETE", "completion_state": "EMPTY_COMPLETE",
            "lane_complete": True, "empty_membership": True,
            "tool_contacted": False, "extracted_entity_manifest": manifest,
            "input_entries": 0, "terminal_entries": 0,
            "terminal_disposition_counts": parser_terminal_counts,
            "entities": 0, "limitations": [],
        })
    apktool = find_apktool()
    if apktool is None:
        raise RuntimeError("apktool is unavailable for deterministic compiled-resource parsing")
    execution_descriptor = json.loads(os.environ["ANGERONA_EXECUTION_SPEC_DESCRIPTOR_JSON"])
    _, execution_payload = open_verified_artifact(execution_descriptor, _roots(plan))
    execution = json.loads(execution_payload)
    if execution["lanes"]["deterministic_parse"].get("tool_artifacts", {}).get("apktool") != _descriptor(apktool):
        raise ValueError("runtime apktool bytes differ from the signed execution specification")
    probe_descriptor = execution["lanes"]["deterministic_parse"].get("tool_artifacts", {}).get("operator_prerequisite")
    probe_verified = False
    if isinstance(probe_descriptor, dict):
        _probe_path, probe_payload = open_verified_artifact(probe_descriptor, _roots(plan))
        probe_document = json.loads(probe_payload)
        probe_verified = bool(
            probe_document.get("schema") == "angerona/operator-tool-prerequisite/v1"
            and verify_document(probe_document, require_signature=True)
            and probe_document.get("status") == "AVAILABLE"
        )
    decoded_root = output / "apktool-decoded"
    decoded = decode_apk(plan["apk"]["path"], skip_sources=True, keep_output=decoded_root)
    if decoded.status != "success":
        raise RuntimeError(f"deterministic apktool parse did not complete: {decoded.status}")
    decoded_root_resolved = decoded_root.resolve(strict=True)
    direct_path_members: dict[Path, list[int]] = {}
    non_directory_paths: set[Path] = set()
    resources_arsc_members = 0
    with zipfile.ZipFile(plan["apk"]["path"]) as member_inventory:
        for central_index, info in enumerate(member_inventory.infolist()):
            if info.is_dir():
                continue
            if info.filename == "resources.arsc":
                resources_arsc_members += 1
            candidate = (decoded_root_resolved / info.filename).resolve()
            if candidate != decoded_root_resolved and decoded_root_resolved not in candidate.parents:
                raise ValueError("HOLD: APK member decoded path escapes apktool output root")
            direct_path_members.setdefault(candidate, []).append(central_index)
            non_directory_paths.add(candidate)
    ambiguous_paths = {
        path: indexes for path, indexes in direct_path_members.items() if len(indexes) != 1
    }
    for candidate in non_directory_paths:
        parent = candidate.parent
        while parent != decoded_root_resolved:
            if parent in non_directory_paths:
                raise ValueError("HOLD: APK decoded paths contain a file/ancestor collision")
            if decoded_root_resolved not in parent.parents:
                raise ValueError("HOLD: APK decoded path ancestry escapes apktool output root")
            parent = parent.parent
    routed_resources_arsc_members = sum(
        str(row.get("name") or "") == "resources.arsc"
        for disposition in ("APP_OWNED", "EXCLUDED_THIRD_PARTY", "HOLD", "FILTER_PENDING")
        for row in _partition_rows(plan, disposition)
    )
    if resources_arsc_members != routed_resources_arsc_members:
        raise ValueError("HOLD: resources.arsc central-directory/routing membership mismatch")
    if resources_arsc_members > 1:
        raise ValueError("HOLD: duplicate resources.arsc membership is ambiguous")
    direct_decoded = {
        candidate for candidate in non_directory_paths
        if candidate.is_file() and candidate not in ambiguous_paths
    }
    arsc_outputs = []
    decoded_res = decoded_root / "res"
    if decoded_res.is_dir():
        for candidate in sorted(decoded_res.rglob("*")):
            if candidate.is_symlink():
                raise ValueError("apktool decoded resources contain a symlink")
            if candidate.is_file() and candidate.resolve() not in non_directory_paths:
                arsc_outputs.append(candidate.resolve())
    if len(arsc_outputs) > MAX_DECODED_RESOURCE_FILES:
        raise ValueError("HOLD: apktool decoded resource file-count bomb bound exceeded")
    decoded_resource_total_bytes = sum(path.stat().st_size for path in arsc_outputs)
    if decoded_resource_total_bytes > MAX_DECODED_RESOURCE_TOTAL_BYTES:
        raise ValueError("HOLD: apktool decoded resource total-byte bomb bound exceeded")
    raw_axml_entry_count = 0
    with zipfile.ZipFile(plan["apk"]["path"]) as archive:
        infos = archive.infolist()
        for row in rows:
            info = infos[int(row["central_directory_index"])]
            payload = archive.read(info)
            if _sha(payload) != row.get("content_sha256"):
                raise ValueError("deterministic parser input differs from routing plan")
            blob = output / "artifacts" / f"{_sha(payload)}.bin"
            _atomic(blob, payload)
            source_descriptor = _descriptor(blob)
            if str(row["name"]) == "resources.arsc":
                if not arsc_outputs:
                    raise ValueError("apktool produced no exact decoded entities for resources.arsc")
                mapping_rows = []
                for decoded_entity in arsc_outputs:
                    relative = decoded_entity.relative_to(decoded_root).as_posix()
                    decoded_bytes = decoded_entity.stat().st_size
                    decoded_descriptor = _stream_descriptor(decoded_entity)
                    if decoded_bytes > MAX_DECODED_RESOURCE_FILE_BYTES:
                        route, media_type, hold_reason, media_metadata = (
                            "HOLD", None, "decoded-resource-file-size-bound-exceeded", {},
                        )
                        decoded_payload = None
                    else:
                        decoded_payload = decoded_entity.read_bytes()
                        route, media_type, hold_reason, media_metadata = _classify_decoded_resource(
                            relative, decoded_payload,
                        )
                    entity_id = _sha(_canonical({
                        "source_entry_id": row["entry_id"], "decoded_relative_path": relative,
                        "decoded_sha256": decoded_descriptor["sha256"],
                    }))
                    mapping_rows.append({
                        "entity_id": entity_id, "decoded_relative_path": relative,
                        "artifact": decoded_descriptor, "decoded_bytes": decoded_bytes,
                        "route": route, "media_type": media_type,
                        "media_metadata": media_metadata, "hold_reason": hold_reason,
                    })
                    if route in {"MODEL_VISIBLE_TEXT", "HOLD"} and decoded_bytes <= MAX_DECODED_RESOURCE_FILE_BYTES:
                        entities.append({
                            "entity_id": entity_id, "entity_kind": "resource",
                            "qualified_name": f"resources.arsc::{relative}",
                            "artifact_sha256": decoded_descriptor["sha256"],
                            "entity_fingerprint_sha256": _sha(_canonical({
                                "resources_arsc_sha256": source_descriptor["sha256"],
                                "decoded_relative_path": relative,
                                "decoded_sha256": decoded_descriptor["sha256"],
                            })),
                            "artifact": decoded_descriptor, "byte_start": 0,
                            "byte_end": decoded_bytes,
                            "parse_status": (
                                "apktool-decoded-utf8" if route == "MODEL_VISIBLE_TEXT"
                                else "unknown-binary-hold"
                            ),
                            "forced_disposition": "HOLD" if route == "HOLD" else None,
                            "semantic_eligible": route == "MODEL_VISIBLE_TEXT",
                            "source_entry_id": row["entry_id"], "source_artifact": source_descriptor,
                        })
                    if route == "HOLD":
                        limitations.append(f"decoded-resource-hold:{relative}:{hold_reason}")
                mapping = _write_signed(output / "RESOURCE_ARSC_DECODED_ENTITY_MAPPING.json", {
                    "schema": "angerona/resources-arsc-decoded-entity-mapping/v1",
                    "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                    "source_entry_id": row["entry_id"], "resources_arsc": source_descriptor,
                    "apktool": _descriptor(apktool), "decoded_entity_count": len(mapping_rows),
                    "decoded_entities": mapping_rows,
                    "decoded_entity_stream_sha256": _sha(b"".join(_canonical(item) for item in mapping_rows)),
                    "mapping_semantics": "complete-apktool-decoded-output-accounting-not-sole-source-byte-provenance",
                    "model_visible_text_count": sum(row["route"] == "MODEL_VISIBLE_TEXT" for row in mapping_rows),
                    "non_text_accounted_count": sum(str(row["route"]).startswith("NON_TEXT_") for row in mapping_rows),
                    "hold_count": sum(row["route"] == "HOLD" for row in mapping_rows),
                    "decoded_total_bytes": decoded_resource_total_bytes,
                    "bounds": {
                        "max_files": MAX_DECODED_RESOURCE_FILES,
                        "max_total_bytes": MAX_DECODED_RESOURCE_TOTAL_BYTES,
                        "max_file_bytes": MAX_DECODED_RESOURCE_FILE_BYTES,
                        "max_model_visible_text_bytes": MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES,
                    },
                })
                sources.append({
                    "entry_id": row["entry_id"], "artifact": source_descriptor,
                    "decoded_entity_mapping": mapping,
                    "parser_terminal_disposition": "DECODED_MAPPING_COMPLETE",
                })
                parser_terminal_counts["DECODED_MAPPING_COMPLETE"] += 1
                continue
            decoded_candidate = decoded_root / str(row["name"])
            if str(row["name"]) == "AndroidManifest.xml":
                decoded_candidate = decoded_root / "AndroidManifest.xml"
            lower = str(row["name"]).lower()
            kind = "resource"
            parse_status = "binary-accounted"
            parser_identity = "verified-magic-extension-v1"
            parser_error = None
            parser_route = None
            parser_media_type = None
            parser_metadata: dict[str, Any] = {}
            parsed_payload = None
            parsed_descriptor = None
            axml_transform = None
            is_raw_axml = len(payload) >= 4 and payload[:4] == b"\x03\x00\x08\x00"
            if is_raw_axml:
                raw_axml_entry_count += 1
                parser_identity = "pinned-apktool-axml-transform-v1"
            selected_size = decoded_candidate.stat().st_size if decoded_candidate.is_file() else len(payload)
            if is_raw_axml and decoded_candidate.resolve() in ambiguous_paths:
                parser_error = {
                    "parser_identity": "pinned-apktool-axml-transform-v1",
                    "error_class": "AmbiguousDecodedCentralDirectoryPath",
                    "message": "multiple APK central-directory members map to one decoded path",
                }
            elif is_raw_axml and not decoded_candidate.is_file():
                parser_error = {
                    "parser_identity": "pinned-apktool-axml-transform-v1",
                    "error_class": "MissingDecodedAXMLOutput",
                    "message": "pinned apktool produced no exact decoded XML path",
                }
            elif is_raw_axml and not probe_verified:
                parser_error = {
                    "parser_identity": "pinned-apktool-axml-transform-v1",
                    "error_class": "MissingSignedToolProbeIdentity",
                    "message": "AXML transform requires the signed apktool prerequisite probe",
                }
            elif selected_size > MAX_DECODED_RESOURCE_FILE_BYTES:
                parser_error = {
                    "parser_identity": "bounded-resource-parser-v1",
                    "error_class": "ResourceSizeBoundExceeded",
                    "message": (
                        f"resource bytes {selected_size} exceed bound "
                        f"{MAX_DECODED_RESOURCE_FILE_BYTES}"
                    )[:512],
                }
            else:
                parsed_payload = decoded_candidate.read_bytes() if decoded_candidate.is_file() else payload
                parsed_blob = output / "parsed-artifacts" / f"{_sha(parsed_payload)}.bin"
                _atomic(parsed_blob, parsed_payload)
                parsed_descriptor = _descriptor(parsed_blob)
            suffix = Path(lower).suffix
            text_suffixes = {
                ".txt", ".cfg", ".conf", ".ini", ".properties", ".yaml",
                ".yml", ".toml", ".csv", ".css",
            }
            if parser_error is None and suffix in {".json", ".xml", ".html", ".htm"} | text_suffixes:
                if len(parsed_payload) > MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES:
                    parser_error = {
                        "parser_identity": "bounded-resource-text-v1",
                        "error_class": "ModelVisibleTextSizeBoundExceeded",
                        "message": (
                            f"text bytes {len(parsed_payload)} exceed bound "
                            f"{MAX_MODEL_VISIBLE_RESOURCE_TEXT_BYTES}"
                        )[:512],
                    }
                else:
                    try:
                        has_utf8_bom = parsed_payload.startswith(b"\xef\xbb\xbf")
                        decoded_text = parsed_payload.decode(
                            "utf-8-sig" if suffix == ".json" and has_utf8_bom else "utf-8",
                            errors="strict",
                        )
                        if suffix == ".json":
                            parser_identity = (
                                "python-json-utf8-sig-strict-v1"
                                if has_utf8_bom else "python-json-strict-v1"
                            )
                            json.loads(decoded_text)
                            kind, parse_status = "config", "json-validated"
                            parser_media_type = "application/json"
                        elif suffix == ".xml":
                            parser_identity = "python-elementtree-strict-v1"
                            ET.fromstring(decoded_text)
                            kind, parse_status = "config", "xml-validated"
                            parser_media_type = "application/xml"
                        elif suffix in {".html", ".htm"}:
                            parser_identity = "python-htmlparser-html5-bounded-v1"
                            html_parser = HTMLParser(convert_charrefs=True)
                            html_parser.feed(decoded_text)
                            html_parser.close()
                            kind, parse_status = "config", "utf8-validated"
                            parser_media_type = "text/html"
                        else:
                            parser_identity = "utf8-strict-v1"
                            kind, parse_status = "text", "utf8-validated"
                            parser_media_type = "text/plain"
                    except (UnicodeDecodeError, json.JSONDecodeError, ET.ParseError, ValueError) as exc:
                        parser_error = {
                            "parser_identity": parser_identity,
                            "error_class": type(exc).__name__,
                            "message": str(exc)[:512],
                        }
            elif parser_error is None:
                route, media_type, hold_reason, media_metadata = _classify_decoded_resource(
                    str(row["name"]), parsed_payload,
                )
                parser_route, parser_media_type, parser_metadata = route, media_type, media_metadata
                if route == "MODEL_VISIBLE_TEXT":
                    kind = "config" if media_type in {"application/json", "application/xml", "text/html"} else "text"
                    parse_status = (
                        "json-validated" if media_type == "application/json"
                        else "xml-validated" if media_type in {"application/xml", "image/svg+xml", "application/vnd.android.vector+xml"}
                        else "utf8-validated"
                    )
                    parser_identity = "verified-format-dispatch-v2"
                elif str(route).startswith("NON_TEXT_"):
                    parse_status = "non-text-accounted"
                else:
                    parser_error = {
                        "parser_identity": parser_identity,
                        "error_class": "UnsupportedOrMismatchedBinaryFormat",
                        "message": str(hold_reason or "unknown binary resource")[:512],
                    }
            if is_raw_axml:
                decoded_output_descriptor = (
                    _stream_descriptor(decoded_candidate)
                    if decoded_candidate.is_file() and decoded_candidate.resolve() not in ambiguous_paths
                    else None
                )
                axml_body = {
                    "schema": "angerona/android-axml-transform-receipt/v1",
                    "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                    "ownership_policy_id": plan["ownership_policy"]["policy_id"],
                    "audit_epoch": plan.get("audit_epoch"),
                    "central_directory_index": int(row["central_directory_index"]),
                    "central_directory_path": str(row["name"]), "entry_id": row["entry_id"],
                    "raw_artifact": source_descriptor, "raw_magic": payload[:4].hex(),
                    "decoded_artifact": decoded_output_descriptor,
                    "parsed_cas_artifact": parsed_descriptor,
                    "tool": _descriptor(apktool), "operator_prerequisite": probe_descriptor,
                    "status": "COMPLETE" if parser_error is None else "HOLD",
                    "hold_error": parser_error,
                    "mapping_semantics": "one-central-directory-raw-axml-to-one-exact-pinned-apktool-decoded-path",
                }
                axml_transform = _write_signed(
                    output / "axml-transforms" / f"{row['entry_id']}.json", axml_body,
                )
            if parser_error is not None:
                terminal_disposition = "HOLD_PARSE_ERROR"
                parse_status = "HOLD_PARSE_ERROR"
                descriptor = source_descriptor
                limitations.append(
                    f"direct-resource-hold:{row['entry_id']}:"
                    f"{parser_error['error_class']}:{parser_error['message']}"
                )
            elif parse_status == "non-text-accounted":
                terminal_disposition = "NON_TEXT_ACCOUNTED"
                descriptor = parsed_descriptor
            else:
                terminal_disposition = "MODEL_VISIBLE_TEXT"
                descriptor = parsed_descriptor
            parser_terminal_counts[terminal_disposition] += 1
            if parsed_payload is None:
                parsed_bytes = require_int_field(
                    row, "content_bytes", context="routed parser row", minimum=0,
                )
            else:
                parsed_bytes = len(parsed_payload)
            entity_id = _sha(_canonical({"apk": plan["apk"]["sha256"], "entry_id": row["entry_id"]}))
            entities.append({
                "entity_id": entity_id, "entity_kind": kind,
                "qualified_name": row["name"], "artifact_sha256": descriptor["sha256"],
                "entity_fingerprint_sha256": source_descriptor["sha256"], "artifact": descriptor,
                "byte_start": 0, "byte_end": parsed_bytes, "parse_status": parse_status,
                "parser_identity": parser_identity, "parser_error": parser_error,
                "parser_route": parser_route, "media_type": parser_media_type,
                "parser_metadata": parser_metadata,
                "axml_transform_receipt": axml_transform,
                "parser_terminal_disposition": terminal_disposition,
                "forced_disposition": "HOLD" if parser_error is not None else None,
                "semantic_eligible": terminal_disposition == "MODEL_VISIBLE_TEXT",
                "source_entry_id": row["entry_id"], "source_artifact": source_descriptor,
            })
            sources.append({
                "entry_id": row["entry_id"], "artifact": source_descriptor,
                "parsed_artifact": parsed_descriptor,
                "parser_identity": parser_identity, "parser_error": parser_error,
                "axml_transform_receipt": axml_transform,
                "parser_terminal_disposition": terminal_disposition,
            })
    source_entry_ids = [str(item.get("entry_id") or "") for item in sources]
    expected_entry_ids = [str(row["entry_id"]) for row in rows]
    if (
        len(source_entry_ids) != len(set(source_entry_ids))
        or set(source_entry_ids) != set(expected_entry_ids)
    ):
        raise ValueError("deterministic parser input-to-terminal-disposition conservation failed")
    axml_receipts = [
        item["axml_transform_receipt"] for item in sources
        if isinstance(item.get("axml_transform_receipt"), dict)
    ]
    axml_documents = []
    if len(axml_receipts) != raw_axml_entry_count:
        raise ValueError("raw AXML input-to-transform-receipt conservation failed")
    for descriptor in axml_receipts:
        _axml_path, axml_payload = open_verified_artifact(descriptor, _roots(plan))
        document = json.loads(axml_payload)
        if (
            document.get("schema") != "angerona/android-axml-transform-receipt/v1"
            or not verify_document(document, require_signature=True)
            or document.get("plan_id") != plan["plan_id"]
        ):
            raise ValueError("AXML transform set contains an invalid receipt")
        axml_documents.append(document)
    if len({int(row["central_directory_index"]) for row in axml_documents}) != len(axml_documents):
        raise ValueError("AXML transform receipts duplicate central-directory membership")
    axml_transform_set = _write_signed(output / "AXML_TRANSFORM_SET.json", {
        "schema": "angerona/android-axml-transform-set/v1",
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "ownership_policy_id": plan["ownership_policy"]["policy_id"],
        "audit_epoch": plan.get("audit_epoch"), "tool": _descriptor(apktool),
        "operator_prerequisite": probe_descriptor,
        "raw_axml_entry_count": raw_axml_entry_count, "receipt_count": len(axml_receipts),
        "complete_count": sum(row["status"] == "COMPLETE" for row in axml_documents),
        "hold_count": sum(row["status"] == "HOLD" for row in axml_documents),
        "receipts": sorted(axml_receipts, key=lambda row: (row["path"], row["sha256"])),
        "one_input_one_terminal_transform_receipt": True,
    })
    manifest = _write_extracted_manifest(
        plan, "deterministic_parse", output / "EXTRACTED_ENTITIES.json",
        entities, sources, limitations,
    )
    return _completion(plan, "deterministic_parse", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "extracted_entity_manifest": manifest,
        "input_entries": len(rows), "terminal_entries": len(source_entry_ids),
        "terminal_disposition_counts": parser_terminal_counts,
        "entities": len(entities), "limitations": limitations,
        "axml_transform_set": axml_transform_set,
    })


def dex_index_adapter(
    plan_path: str | Path, output_dir: str | Path, completion_receipt: str | Path,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    _lineage(plan, "dex_index")
    output = _confined_output(plan, output_dir)
    route = "dex-index-then-ownership-filter-before-app-only-decompile"
    route_rows = _route_rows(plan, route)
    expected = {str(row["content_sha256"]) for row in route_rows}
    if not route_rows:
        manifest = _write_extracted_manifest(
            plan, "dex_index", output / "EXTRACTED_ENTITIES.json", [], [], [],
        )
        return _completion(plan, "dex_index", Path(completion_receipt).resolve(), {
            "status": "COMPLETE", "completion_state": "EMPTY_COMPLETE",
            "lane_complete": True, "empty_membership": True,
            "tool_contacted": False, "extracted_entity_manifest": manifest,
            "dex_targets": 0, "entities": 0, "dex_index_manifest": None,
        })
    receipt_root = output / "dex-index"
    aggregate = build_apk_dex_receipts(plan["apk"]["path"], receipt_root)
    observed = {str(row["content_sha256"]) for row in aggregate.get("targets") or []}
    if observed != expected:
        raise ValueError("DEX index target set differs from the signed routing plan")
    entities: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    with zipfile.ZipFile(plan["apk"]["path"]) as archive:
        by_sha = {}
        for info in archive.infolist():
            if not info.is_dir() and info.filename.endswith(".dex"):
                payload = archive.read(info)
                by_sha[_sha(payload)] = payload
        for target in aggregate.get("targets") or []:
            dex_sha = str(target["content_sha256"])
            payload = by_sha[dex_sha]
            dex_blob = output / "artifacts" / f"{dex_sha}.dex"
            _atomic(dex_blob, payload)
            dex_descriptor = _descriptor(dex_blob)
            matching_routes = [row for row in route_rows if row["content_sha256"] == dex_sha]
            if len(matching_routes) != 1:
                raise ValueError("DEX relationship index lacks unique signed routing membership")
            relationship_index = build_dex_relationship_index(
                payload, output / "relationships" / f"{dex_sha}.json",
                apk_sha256=plan["apk"]["sha256"],
                member_name=str(matching_routes[0].get("normalized_path") or matching_routes[0].get("name") or matching_routes[0]["entry_id"]),
                plan_id=plan["plan_id"], routing_set_id=plan["routing_set_id"],
                ownership_policy=plan["ownership_policy"], audit_epoch=plan.get("audit_epoch"),
                artifact=dex_descriptor,
            )
            target_path = receipt_root / "dex" / dex_sha / "DEX_TARGET_RECEIPT.json"
            target_document = json.loads(target_path.read_bytes())
            classes: dict[str, list[dict[str, Any]]] = {}
            for summary in target_document.get("methods") or []:
                method_path = target_path.parent / summary["receipt"]
                method = json.loads(method_path.read_bytes())
                if not method.get("defined"):
                    continue
                descriptor = str(method["class_descriptor"])
                classes.setdefault(descriptor, []).append(method)
                code_start = optional_nullable_int_field(
                    method, "code_offset", default=0, context="DEX method", minimum=0,
                )
                instruction_units = optional_nullable_int_field(
                    method, "instruction_code_units", default=0,
                    context="DEX method", minimum=0,
                )
                code_end = code_start + 16 + instruction_units * 2 if code_start else 0
                fingerprint = str(method.get("instruction_bytes_sha256") or _sha(_canonical({
                    "qualified_name": method["qualified_name"], "access_flags": method.get("access_flags"),
                })))
                if len(fingerprint) != 64:
                    raise ValueError("DEX method fingerprint is invalid")
                entities.append({
                    "entity_id": method["method_id"], "entity_kind": "method",
                    "qualified_name": method["qualified_name"], "declaring_class": descriptor,
                    "artifact_sha256": dex_sha, "entity_fingerprint_sha256": fingerprint,
                    "artifact": dex_descriptor, "byte_start": code_start, "byte_end": code_end,
                    "index_receipt": _descriptor(method_path), "code_bearing": bool(code_start),
                })
            for descriptor, methods in classes.items():
                class_id = _sha(_canonical({"dex_sha256": dex_sha, "class_descriptor": descriptor}))
                class_fingerprint = _sha(_canonical({
                    "class_descriptor": descriptor,
                    "method_fingerprints": sorted(str(row.get("instruction_bytes_sha256") or "") for row in methods),
                }))
                entities.append({
                    "entity_id": class_id, "entity_kind": "class", "qualified_name": descriptor,
                    "artifact_sha256": dex_sha, "entity_fingerprint_sha256": class_fingerprint,
                    "artifact": dex_descriptor, "byte_start": 0, "byte_end": len(payload),
                    "defined_method_ids": [row["method_id"] for row in methods],
                })
            relationship_document = json.loads(Path(relationship_index["path"]).read_bytes())
            for definition in (
                relationship_document.get("class_definitions")
                or relationship_document.get("definitions")
                or relationship_document.get("classes")
                or []
            ):
                descriptor = str(definition["descriptor"])
                if descriptor in classes:
                    expected_id = _sha(_canonical({"dex_sha256": dex_sha, "class_descriptor": descriptor}))
                    if definition.get("entity_id") != expected_id:
                        raise ValueError("DEX relationship/class entity identity mismatch")
                    continue
                definition_start = int(definition["definition_byte_start"])
                definition_end = int(definition["definition_byte_end"])
                if not (0 <= definition_start < definition_end <= len(payload)):
                    raise ValueError("DEX class definition range is invalid")
                entities.append({
                    "entity_id": definition["entity_id"], "entity_kind": "class",
                    "qualified_name": descriptor, "artifact_sha256": dex_sha,
                    "entity_fingerprint_sha256": definition["definition_sha256"],
                    "artifact": dex_descriptor, "byte_start": definition_start,
                    "byte_end": definition_end, "defined_method_ids": [],
                    "zero_defined_methods": True,
                })
            sources.append({
                "target_sha256": dex_sha, "artifact": dex_descriptor,
                "target_receipt": _descriptor(target_path),
                "relationship_index": relationship_index,
            })
    manifest = _write_extracted_manifest(
        plan, "dex_index", output / "EXTRACTED_ENTITIES.json", entities, sources, [],
    )
    return _completion(plan, "dex_index", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "extracted_entity_manifest": manifest,
        "dex_targets": len(observed), "entities": len(entities),
        "dex_index_manifest": _descriptor(receipt_root / "DEX_TARGETS.json"),
    })


def hermes_index_adapter(
    plan_path: str | Path, output_dir: str | Path, completion_receipt: str | Path,
    indexer_descriptor: str | Path,
) -> dict[str, Any]:
    """Invoke a pinned index-only Hermes/JS extractor and verify all byte ranges."""
    plan = verify_clean_apk_routing_plan(plan_path)
    _lineage(plan, "hermes_index")
    output = _confined_output(plan, output_dir)
    rows = _route_rows(plan, "hermes-index-then-module-ownership-filter-before-app-only-decompile")
    if not rows:
        manifest = _write_extracted_manifest(
            plan, "hermes_index", output / "EXTRACTED_ENTITIES.json", [], [], [],
        )
        return _completion(plan, "hermes_index", Path(completion_receipt).resolve(), {
            "status": "COMPLETE", "completion_state": "EMPTY_COMPLETE",
            "lane_complete": True, "empty_membership": True,
            "tool_contacted": False, "extracted_entity_manifest": manifest,
            "input_entries": 0, "entities": 0, "indexer": None,
        })
    roots = _roots(plan)
    indexer_argv, descriptor_document, probe_descriptor = _load_pinned_python_wrapper(
        indexer_descriptor, roots, "hermes-indexer",
    )
    tool_environment = os.environ.copy()
    tool_environment["ANGERONA_TOOL_PROBE_RECEIPT"] = probe_descriptor["path"]
    entities: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    with zipfile.ZipFile(plan["apk"]["path"]) as archive:
        infos = archive.infolist()
        for row in rows:
            payload = archive.read(infos[int(row["central_directory_index"])])
            if _sha(payload) != row["content_sha256"]:
                raise ValueError("Hermes input differs from routing plan")
            source = output / "artifacts" / f"{_sha(payload)}.hbc"
            _atomic(source, payload)
            index_path = output / "indexes" / f"{row['entry_id']}.jsonl"
            index_path.parent.mkdir(parents=True, exist_ok=True)
            completed = subprocess.run(
                [*indexer_argv, "--index-only", "--input", str(source), "--output", str(index_path)],
                stdin=subprocess.DEVNULL, env=tool_environment, check=False,
            )
            if completed.returncode != 0 or not index_path.is_file():
                raise RuntimeError(f"Hermes indexer failed for {row['entry_id']}")
            seen: set[str] = set()
            for line in index_path.read_bytes().splitlines():
                module = json.loads(line)
                module_id = str(module.get("module_id") or "")
                start, end = int(module.get("byte_start", -1)), int(module.get("byte_end", -1))
                if not module_id or module_id in seen or start < 0 or end <= start or end > len(payload):
                    raise ValueError("Hermes index contains an invalid module range")
                seen.add(module_id)
                fragment = payload[start:end]
                fragment_path = output / "module-artifacts" / f"{_sha(fragment)}.bin"
                _atomic(fragment_path, fragment)
                fragment_descriptor = _descriptor(fragment_path)
                fingerprint = str(module.get("fingerprint_sha256") or fragment_descriptor["sha256"])
                if len(fingerprint) != 64:
                    raise ValueError("Hermes module fingerprint is invalid")
                entities.append({
                    "entity_id": _sha(_canonical({"entry_id": row["entry_id"], "module_id": module_id})),
                    "entity_kind": "js_module", "qualified_name": str(module.get("name") or module_id),
                    "artifact_sha256": fragment_descriptor["sha256"],
                    "entity_fingerprint_sha256": fingerprint,
                    "artifact": fragment_descriptor, "byte_start": 0, "byte_end": len(fragment),
                    "source_entry_id": row["entry_id"], "source_byte_start": start, "source_byte_end": end,
                    "module_id": module_id, "container_artifact": _descriptor(source),
                })
            ordered_ranges = sorted(
                (int(entity["source_byte_start"]), int(entity["source_byte_end"]))
                for entity in entities if entity.get("source_entry_id") == row["entry_id"]
            )
            cursor = 0
            metadata_ranges = []
            for start, end in ordered_ranges:
                if start < cursor:
                    raise ValueError("Hermes module ranges overlap")
                if start > cursor:
                    metadata_ranges.append({"byte_start": cursor, "byte_end": start, "disposition": "container-metadata"})
                cursor = end
            if cursor < len(payload):
                metadata_ranges.append({"byte_start": cursor, "byte_end": len(payload), "disposition": "container-metadata"})
            sources.append({
                "entry_id": row["entry_id"], "artifact": _descriptor(source),
                "index": _descriptor(index_path), "module_ranges": len(ordered_ranges),
                "container_metadata_ranges": metadata_ranges,
                "byte_accounting_complete": sum(end - start for start, end in ordered_ranges)
                + sum(item["byte_end"] - item["byte_start"] for item in metadata_ranges) == len(payload),
            })
    manifest = _write_extracted_manifest(
        plan, "hermes_index", output / "EXTRACTED_ENTITIES.json", entities, sources, [],
    )
    return _completion(plan, "hermes_index", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "extracted_entity_manifest": manifest,
        "input_entries": len(rows), "entities": len(entities), "indexer": descriptor_document,
    })


def application_surface_adapter(
    plan_path: str | Path, extracted_manifests: Iterable[str | Path],
    output_dir: str | Path, completion_receipt: str | Path,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "application_surface")
    output = _confined_output(plan, output_dir)
    if not lineage.get("audit_epoch"):
        raise ValueError("application surface requires an immutable audit epoch")
    output = output_is_in_epoch(output, load_audit_epoch(lineage["audit_epoch"]["path"]))
    roots = _roots(plan)
    descriptors = []
    for supplied in extracted_manifests:
        descriptor = _descriptor(supplied)
        open_verified_artifact(descriptor, roots)
        descriptors.append(descriptor)
    expected_manifests = []
    parent_lane_receipts = []
    parents = lineage.get("parent_receipts") or {}
    for lane in ("deterministic_parse", "dex_index", "hermes_index"):
        parent_descriptor = parents.get(lane)
        if not isinstance(parent_descriptor, dict):
            raise ValueError(f"application surface lacks exact {lane} parent")
        _parent_path, parent_payload = open_verified_artifact(parent_descriptor, roots)
        parent_lane_receipts.append(parent_descriptor)
        parent = json.loads(parent_payload)
        if (
            parent.get("schema") != LANE_SCHEMAS[lane]
            or not verify_document(parent, require_signature=True)
            or parent.get("plan_id") != plan["plan_id"]
            or parent.get("routing_set_id") != plan["routing_set_id"]
            or not isinstance(parent.get("extracted_entity_manifest"), dict)
        ):
            raise ValueError(f"application surface rejects incomplete {lane} parent")
        expected_manifests.append(parent["extracted_entity_manifest"])
    ordered_descriptors = canonical_order_rows(
        "angerona/canonical-artifact-set/v1", "artifacts", descriptors,
        context="application-surface extracted manifests",
    )
    ordered_expected = canonical_order_rows(
        "angerona/canonical-artifact-set/v1", "artifacts", expected_manifests,
        context="application-surface parent manifests",
    )
    if descriptors != ordered_descriptors or expected_manifests != ordered_expected:
        raise ValueError("application-surface manifest descriptors are not canonical")
    if descriptors != expected_manifests:
        raise ValueError("application-surface extracted manifests differ from exact checkpoint parents")
    result = build_application_surface(
        plan=plan, extracted_manifests=descriptors,
        parent_lane_receipts=parent_lane_receipts, routing_plan=_descriptor(plan_path),
        output_dir=output,
    )
    return _completion(plan, "application_surface", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "lane_complete": True,
        "extracted_entity_manifests": descriptors,
        "component_definition_receipt": result["component_definition_receipt"],
        "application_surface_manifest": result["surface_manifest"],
        "occurrence_index": result["occurrence_index"],
        "surface_queue": result["queue"], "surface_queue_manifest": result["queue_manifest"],
        "surface_queue_lineage": result["queue_lineage"],
        "surface_entities": result["entity_count"], "surface_units": result["unit_count"],
        "code_ownership_claimed": False,
    })


def ownership_filter_adapter(
    plan_path: str | Path, extracted_manifests: Iterable[str | Path],
    output_dir: str | Path, completion_receipt: str | Path,
    component_definition_receipt: str | Path,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "ownership_filter")
    output = _confined_output(plan, output_dir)
    roots = _roots(plan)
    surface_parent = (lineage.get("parent_receipts") or {}).get("application_surface")
    if not isinstance(surface_parent, dict):
        raise ValueError("ownership filter lacks its exact application-surface parent")
    _surface_path, surface_payload = open_verified_artifact(surface_parent, roots)
    surface_receipt = json.loads(surface_payload)
    if (
        surface_receipt.get("schema") != LANE_SCHEMAS["application_surface"]
        or not verify_document(surface_receipt, require_signature=True)
        or surface_receipt.get("plan_id") != plan["plan_id"]
        or surface_receipt.get("component_definition_receipt") != _descriptor(component_definition_receipt)
    ):
        raise ValueError("ownership filter component receipt is not its exact signed surface parent")
    entities: list[dict[str, Any]] = []
    sources = []
    seen: set[str] = set()
    for supplied in extracted_manifests:
        descriptor = _descriptor(supplied)
        _, document = load_signed_canonical(descriptor, roots, schema=EXTRACTED_MANIFEST_SCHEMA)
        validate_extracted_entity_manifest(document, plan)
        for entity in document.get("entities") or []:
            if entity["entity_id"] in seen:
                raise ValueError("duplicate entity across extracted manifests")
            seen.add(entity["entity_id"])
            entities.append(entity)
        sources.append(descriptor)
    expected_sources = []
    for lane in ("deterministic_parse", "dex_index", "hermes_index"):
        parent_descriptor = (lineage.get("parent_receipts") or {}).get(lane)
        if not isinstance(parent_descriptor, dict):
            raise ValueError(f"ownership filter lacks exact {lane} parent")
        _parent_path, parent_payload = open_verified_artifact(parent_descriptor, roots)
        parent = json.loads(parent_payload)
        if (
            parent.get("schema") != LANE_SCHEMAS[lane]
            or not verify_document(parent, require_signature=True)
            or not isinstance(parent.get("extracted_entity_manifest"), dict)
        ):
            raise ValueError(f"ownership filter rejects invalid {lane} parent")
        expected_sources.append(parent["extracted_entity_manifest"])
    ordered_sources = canonical_order_rows(
        "angerona/canonical-artifact-set/v1", "artifacts", sources,
        context="ownership-filter source manifests",
    )
    ordered_expected_sources = canonical_order_rows(
        "angerona/canonical-artifact-set/v1", "artifacts", expected_sources,
        context="ownership-filter parent manifests",
    )
    if sources != ordered_sources or expected_sources != ordered_expected_sources:
        raise ValueError("ownership-filter source manifest descriptors are not canonical")
    if sources != expected_sources:
        raise ValueError("ownership filter source manifests differ from exact checkpoint parents")
    aggregate = _write_extracted_manifest(
        plan, "ownership_filter", output / "ALL_EXTRACTED_ENTITIES.json", entities, sources, [],
    )
    classified = classify_extracted_entities(
        plan=plan, extracted_manifest=aggregate["path"], ownership_policy=plan["ownership_policy"]["path"],
        component_definition_receipt=component_definition_receipt,
        output_dir=output / "ownership", trusted_roots=plan["trusted_roots"],
    )
    manifests = classified["manifests"]
    counts = {}
    class_dispositions: dict[str, str] = {}
    method_rows: list[dict[str, Any]] = []
    for disposition, descriptor in manifests.items():
        document = json.loads(Path(descriptor["path"]).read_bytes())
        counts[disposition] = int(document["entity_count"])
        for entity in document["entities"]:
            if entity["entity_kind"] == "class":
                class_dispositions[str(entity["qualified_name"])] = disposition
            elif entity["entity_kind"] == "method":
                method_rows.append({"class": str(entity["declaring_class"]), "disposition": disposition})
    conflicts = [
        row for row in method_rows
        if class_dispositions.get(row["class"]) not in {None, row["disposition"]}
    ]
    if conflicts:
        raise ValueError("class/method ownership dispositions conflict")
    return _completion(plan, "ownership_filter", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "ownership_set_id": classified["ownership_set_id"],
        "entity_count": classified["entity_count"], "entity_manifests": manifests,
        "disposition_counts": counts, "fully_excluded_third_party": True,
        "unknown_hold_count": counts.get("HOLD", 0), "class_method_conflicts": 0,
    })


def split_occurrence_budget(text: str, maximum_annotated_bytes: int) -> list[tuple[int, int, bytes, int]]:
    """Losslessly split UTF-8 text while reserving exact annotation overhead."""
    if maximum_annotated_bytes < 12288:
        raise ValueError("occurrence context budget is too small")
    evidence_budget = maximum_annotated_bytes - 8192
    encoded = text.encode("utf-8")
    pieces: list[tuple[int, int, bytes, int]] = []
    cursor = 0
    while cursor < len(encoded):
        end = cursor
        estimated = 0
        while end < len(encoded):
            newline = encoded.find(b"\n", end)
            candidate_end = len(encoded) if newline < 0 else newline + 1
            line_bytes = candidate_end - end
            annotation = 196 + len(str(end)) + len(str(candidate_end))
            if estimated + line_bytes + annotation > evidence_budget:
                if end == cursor:
                    candidate_end = min(len(encoded), cursor + max(1, evidence_budget - annotation))
                    while candidate_end > cursor:
                        try:
                            encoded[cursor:candidate_end].decode("utf-8")
                            break
                        except UnicodeDecodeError:
                            candidate_end -= 1
                    if candidate_end == cursor:
                        raise ValueError("cannot split UTF-8 evidence within context budget")
                    end, estimated = candidate_end, candidate_end - cursor + annotation
                break
            estimated += line_bytes + annotation
            end = candidate_end
        if end <= cursor:
            raise ValueError("occurrence context splitter made no progress")
        pieces.append((cursor, end, encoded[cursor:end], estimated))
        cursor = end
    if b"".join(row[2] for row in pieces) != encoded:
        raise ValueError("occurrence context splitting was not lossless")
    return pieces


def app_reconstruction_adapter(
    plan_path: str | Path, app_owned_manifest: str | Path,
    output_dir: str | Path, completion_receipt: str | Path,
    *, context_budget_bytes: int = 65536,
    baksmali_descriptor: str | Path | None = None,
    hermes_decompiler_descriptor: str | Path | None = None,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    _lineage(plan, "app_reconstruction")
    output = _confined_output(plan, output_dir)
    document = json.loads(Path(app_owned_manifest).resolve(strict=True).read_bytes())
    if (
        not verify_document(document, require_signature=True)
        or document.get("disposition") != "APP_OWNED"
        or document.get("ownership_policy_id") != plan["ownership_policy"]["policy_id"]
        or document.get("plan_id") != plan["plan_id"]
        or document.get("routing_set_id") != plan["routing_set_id"]
    ):
        raise ValueError("reconstruction input is not the signed APP_OWNED entity set")
    classes = {str(row["qualified_name"]): row for row in document["entities"] if row["entity_kind"] == "class"}
    methods = [row for row in document["entities"] if row["entity_kind"] == "method"]
    js_modules = [row for row in document["entities"] if row["entity_kind"] == "js_module"]
    deterministic_entities = [
        row for row in document["entities"] if row["entity_kind"] in {"resource", "config", "text"}
    ]
    if any(str(row["declaring_class"]) not in classes for row in methods):
        raise ValueError("app-owned method lacks an app-owned declaring class")
    cli = None
    if classes:
        cli = find_jadx_cli()
        if cli is None:
            raise RuntimeError("JADX is unavailable for app-only reconstruction")
        execution_descriptor = json.loads(os.environ["ANGERONA_EXECUTION_SPEC_DESCRIPTOR_JSON"])
        _, execution_payload = open_verified_artifact(execution_descriptor, _roots(plan))
        execution = json.loads(execution_payload)
        expected_jadx = execution["lanes"]["app_reconstruction"].get("tool_artifacts", {}).get("jadx")
        if expected_jadx != _descriptor(cli):
            raise ValueError("runtime JADX bytes differ from the signed execution specification")
    baksmali_argv = None
    baksmali_document = None
    baksmali_probe = None
    if classes:
        if not baksmali_descriptor:
            raise ValueError("app-owned DEX reconstruction requires a pinned baksmali descriptor")
        baksmali_argv, baksmali_document, baksmali_probe = _load_pinned_python_wrapper(
            baksmali_descriptor, _roots(plan), "baksmali",
        )
    hermes_argv = None
    hermes_document = None
    hermes_probe = None
    if js_modules:
        if not hermes_decompiler_descriptor:
            raise ValueError("app-owned Hermes modules require a pinned module decompiler descriptor")
        hermes_argv, hermes_document, hermes_probe = _load_pinned_python_wrapper(
            hermes_decompiler_descriptor, _roots(plan), "hermes-decompiler",
        )
    class_units = []
    method_units = []
    source_descriptors = []
    smali_descriptors = []
    reconstruction_operations = []
    for descriptor, entity in sorted(classes.items()):
        java_name = descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
        class_root = output / "classes" / entity["entity_id"]
        class_root.mkdir(parents=True, exist_ok=True)
        source_path = class_root / "source.java"
        completed = subprocess.run([
            str(cli), "--single-class", java_name, "--single-class-output", str(source_path),
            plan["apk"]["path"],
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if completed.returncode != 0 or not source_path.is_file():
            raise RuntimeError(f"JADX app-only reconstruction failed: {descriptor}")
        smali_root = output / "smali" / entity["entity_id"]
        baksmali_environment = os.environ.copy()
        baksmali_environment["ANGERONA_TOOL_PROBE_RECEIPT"] = baksmali_probe["path"]
        completed_smali = subprocess.run([
            *baksmali_argv, "disassemble", entity["artifact"]["path"],
            "--classes", descriptor, "--output", str(smali_root),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=baksmali_environment, check=False)
        smali_files = sorted(smali_root.rglob("*.smali")) if smali_root.is_dir() else []
        if completed_smali.returncode != 0 or not smali_files:
            raise RuntimeError(f"baksmali app-only reconstruction failed: {descriptor}")
        class_smali_descriptors = [_descriptor(path) for path in smali_files]
        smali_descriptors.extend(class_smali_descriptors)
        reconstruction_operations.append({
            "entity_id": entity["entity_id"], "kind": "baksmali-single-class",
            "input_artifact": entity["artifact"], "output_artifacts": class_smali_descriptors,
            "tool_wrapper": baksmali_document, "tool_prerequisite": baksmali_probe,
        })
        source = source_path.read_text(encoding="utf-8", errors="strict")
        source_sha = _sha(source.encode())
        source_descriptors.append(_descriptor(source_path))
        reconstruction_operations.append({
            "entity_id": entity["entity_id"], "kind": "jadx-single-class",
            "input_artifact": entity["artifact"], "output_artifact": _descriptor(source_path),
            "tool": expected_jadx,
        })
        chunks = split_occurrence_budget(source, context_budget_bytes)
        for index, (start, end, chunk, estimate) in enumerate(chunks):
            chunk_path = class_root / f"chunk-{index:05d}.java"
            _atomic(chunk_path, chunk)
            input_items = [{"kind": "jadx-class-source-chunk", **_descriptor(chunk_path)}]
            input_body = {
                "class_id": entity["entity_id"], "source_sha256": source_sha,
                "chunk_index": index, "chunk_count": len(chunks), "byte_start": start,
                "byte_end": end, "inputs": input_items, "plan_id": plan["plan_id"],
                "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            }
            input_sha = _sha(_canonical(input_body))
            input_path = output / "input-manifests" / f"{input_sha}.json"
            _atomic(input_path, _canonical(input_body))
            class_units.append({
                "schema": "angerona/jadx-class-chunk-work-unit/v1",
                "unit_id": _sha(_canonical({"input": input_sha, "kind": "app-class"})),
                "unit_kind": "jadx_class_source_chunk", "state": "pending",
                "class_id": entity["entity_id"], "class_descriptors": [descriptor],
                "source_sha256": source_sha, "source_bytes": len(source.encode()),
                "byte_start": start, "byte_end": end, "chunk_index": index,
                "chunk_count": len(chunks), "inputs": input_items,
                "input_manifest_sha256": input_sha, "context_budget_bytes": context_budget_bytes,
                "input_manifest_path": str(input_path),
                "estimated_annotated_evidence_bytes": estimate, "evidence_requests": [],
                "unresolved_reasons": ["app-owned-semantic-reconstruction-pending"],
                "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            })
        for method in sorted((row for row in methods if row["declaring_class"] == descriptor), key=lambda row: row["entity_id"]):
            smali_signature = str(method["qualified_name"]).split("->", 1)[-1]
            matched_body = None
            for smali_file in smali_files:
                lines = smali_file.read_text(encoding="utf-8", errors="strict").splitlines(keepends=True)
                start_index = None
                for line_index, line in enumerate(lines):
                    if line.lstrip().startswith(".method ") and smali_signature in line:
                        start_index = line_index
                        break
                if start_index is None:
                    continue
                end_index = next(
                    (line_index + 1 for line_index in range(start_index, len(lines)) if lines[line_index].strip() == ".end method"),
                    None,
                )
                if end_index is None:
                    raise ValueError(f"unterminated app-owned smali method: {method['qualified_name']}")
                if matched_body is not None:
                    raise ValueError(f"ambiguous app-owned smali method: {method['qualified_name']}")
                matched_body = "".join(lines[start_index:end_index])
            if matched_body is None:
                raise ValueError(f"app-owned smali method is missing: {method['qualified_name']}")
            method_bytes = matched_body.encode("utf-8")
            method_pieces = split_occurrence_budget(matched_body, context_budget_bytes)
            piece_rows = []
            for fragment_index, (fragment_start, fragment_end, fragment, estimate) in enumerate(method_pieces):
                method_smali_path = output / "method-smali" / method["entity_id"] / f"fragment-{fragment_index:05d}.smali"
                _atomic(method_smali_path, fragment)
                piece_rows.append({
                    "fragment_index": fragment_index, "fragment_count": len(method_pieces),
                    "byte_start": fragment_start, "byte_end": fragment_end,
                    "artifact": _descriptor(method_smali_path),
                })
            if piece_rows[0]["byte_start"] != 0 or piece_rows[-1]["byte_end"] != len(method_bytes):
                raise ValueError("method fragment range conservation failed")
            if any(left["byte_end"] != right["byte_start"] for left, right in zip(piece_rows, piece_rows[1:])):
                raise ValueError("method fragment ranges are not contiguous")
            fragment_manifest = _write_signed(
                output / "method-smali" / method["entity_id"] / "FRAGMENT_MANIFEST.json",
                {
                    "schema": "angerona/method-fragment-source-manifest/v1",
                    "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                    "method_id": method["entity_id"], "method_source_sha256": _sha(method_bytes),
                    "method_source_bytes": len(method_bytes), "fragment_count": len(piece_rows),
                    "fragments": piece_rows,
                },
            )
            for piece in piece_rows:
                inputs = [
                    method["index_receipt"] | {"kind": "dex-method-receipt"},
                    {"kind": "app-owned-smali-method-fragment", **piece["artifact"]},
                    {"kind": "method-fragment-source-manifest", **fragment_manifest},
                ]
                method_input_body = {
                    "method_id": method["entity_id"], "inputs": inputs, "plan_id": plan["plan_id"],
                    "method_source_sha256": _sha(method_bytes), "method_source_bytes": len(method_bytes),
                    **{key: piece[key] for key in ("fragment_index", "fragment_count", "byte_start", "byte_end")},
                }
                input_sha = _sha(_canonical(method_input_body))
                method_input_path = output / "input-manifests" / f"{input_sha}.json"
                _atomic(method_input_path, _canonical(method_input_body))
                method_units.append({
                    "schema": (
                        "angerona/semantic-method-fragment-work-unit/v1"
                        if len(piece_rows) > 1 else "angerona/semantic-method-work-unit/v4"
                    ),
                    "unit_id": _sha(_canonical({"input": input_sha, "kind": "app-method-fragment"})),
                    "unit_kind": "dex_method_semantic_fragment" if len(piece_rows) > 1 else "dex_method_semantic_reconstruction",
                    "state": "pending", "method_id": method["entity_id"],
                    "qualified_name": method["qualified_name"], "class_descriptor": descriptor,
                    "inputs": inputs, "input_manifest_sha256": input_sha,
                    "input_manifest_path": str(method_input_path), "evidence_requests": [],
                    "method_source_sha256": _sha(method_bytes), "method_source_bytes": len(method_bytes),
                    **{key: piece[key] for key in ("fragment_index", "fragment_count", "byte_start", "byte_end")},
                    "estimated_annotated_evidence_bytes": estimate,
                    "unresolved_reasons": ["app-owned-method-fragment-semantic-review-pending"],
                    "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                    "ownership_policy_id": plan["ownership_policy"]["policy_id"],
                })
    for module in sorted(js_modules, key=lambda row: row["entity_id"]):
        module_root = output / "js-modules" / module["entity_id"]
        module_root.mkdir(parents=True, exist_ok=True)
        source_path = module_root / "module.js"
        hermes_environment = os.environ.copy()
        hermes_environment["ANGERONA_TOOL_PROBE_RECEIPT"] = hermes_probe["path"]
        completed_js = subprocess.run([
            *hermes_argv, "--decompile-module", "--input", module["container_artifact"]["path"],
            "--module-id", str(module["module_id"]), "--output", str(source_path),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=hermes_environment, check=False)
        if completed_js.returncode != 0 or not source_path.is_file():
            raise RuntimeError(f"Hermes app-only module reconstruction failed: {module['entity_id']}")
        source = source_path.read_text(encoding="utf-8", errors="strict")
        source_sha = _sha(source.encode())
        source_descriptors.append(_descriptor(source_path))
        reconstruction_operations.append({
            "entity_id": module["entity_id"], "kind": "hermes-single-module",
            "input_artifact": module["container_artifact"], "output_artifact": _descriptor(source_path),
            "tool_wrapper": hermes_document, "tool_prerequisite": hermes_probe,
        })
        chunks = split_occurrence_budget(source, context_budget_bytes)
        for index, (start, end, chunk, estimate) in enumerate(chunks):
            chunk_path = module_root / f"chunk-{index:05d}.js"
            _atomic(chunk_path, chunk)
            input_items = [{"kind": "js-app-owned-module-source", **_descriptor(chunk_path)}]
            input_body = {
                "class_id": module["entity_id"], "module_id": module["module_id"],
                "source_sha256": source_sha, "chunk_index": index, "chunk_count": len(chunks),
                "byte_start": start, "byte_end": end, "inputs": input_items,
                "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            }
            input_sha = _sha(_canonical(input_body))
            input_path = output / "input-manifests" / f"{input_sha}.json"
            _atomic(input_path, _canonical(input_body))
            class_units.append({
                "schema": "angerona/jadx-class-chunk-work-unit/v1",
                "unit_id": _sha(_canonical({"input": input_sha, "kind": "app-js-module"})),
                "unit_kind": "js_module_source_chunk", "state": "pending",
                "class_id": module["entity_id"], "class_descriptors": [str(module["qualified_name"])],
                "source_sha256": source_sha, "source_bytes": len(source.encode()),
                "byte_start": start, "byte_end": end, "chunk_index": index,
                "chunk_count": len(chunks), "inputs": input_items,
                "input_manifest_sha256": input_sha, "input_manifest_path": str(input_path),
                "context_budget_bytes": context_budget_bytes,
                "estimated_annotated_evidence_bytes": estimate, "evidence_requests": [],
                "unresolved_reasons": ["app-owned-js-semantic-reconstruction-pending"],
                "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            })
    for entity in sorted(deterministic_entities, key=lambda row: row["entity_id"]):
        artifact_path, artifact_payload = open_verified_artifact(entity["artifact"], _roots(plan))
        try:
            source = artifact_payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"app-owned deterministic artifact is not model-visible UTF-8: {artifact_path}") from exc
        source_sha = _sha(artifact_payload)
        source_descriptors.append(_descriptor(artifact_path))
        chunks = split_occurrence_budget(source, context_budget_bytes)
        for index, (start, end, chunk, estimate) in enumerate(chunks):
            entity_root = output / "deterministic-entities" / entity["entity_id"]
            chunk_path = entity_root / f"chunk-{index:05d}.txt"
            _atomic(chunk_path, chunk)
            input_items = [{"kind": "app-owned-deterministic-artifact", **_descriptor(chunk_path)}]
            input_body = {
                "class_id": entity["entity_id"], "source_sha256": source_sha,
                "chunk_index": index, "chunk_count": len(chunks), "byte_start": start,
                "byte_end": end, "inputs": input_items, "plan_id": plan["plan_id"],
                "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            }
            input_sha = _sha(_canonical(input_body))
            input_path = output / "input-manifests" / f"{input_sha}.json"
            _atomic(input_path, _canonical(input_body))
            class_units.append({
                "schema": "angerona/jadx-class-chunk-work-unit/v1",
                "unit_id": _sha(_canonical({"input": input_sha, "kind": "app-deterministic"})),
                "unit_kind": "resource_semantic_chunk", "state": "pending",
                "class_id": entity["entity_id"], "class_descriptors": [str(entity["qualified_name"])],
                "source_sha256": source_sha, "source_bytes": len(artifact_payload),
                "byte_start": start, "byte_end": end, "chunk_index": index,
                "chunk_count": len(chunks), "inputs": input_items,
                "input_manifest_sha256": input_sha, "input_manifest_path": str(input_path),
                "context_budget_bytes": context_budget_bytes,
                "estimated_annotated_evidence_bytes": estimate, "evidence_requests": [],
                "unresolved_reasons": ["app-owned-resource-semantic-review-pending"],
                "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
                "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            })
    queue_descriptors = {}
    for name, rows in (("class", class_units), ("method", method_units)):
        queue = output / f"APP_OWNED_{name.upper()}_QUEUE.jsonl"
        queue_payload = b"".join(_canonical(row) for row in sorted(rows, key=lambda row: row["unit_id"]))
        _atomic(queue, queue_payload)
        queue_descriptor = _descriptor(queue)
        manifest = _write_signed(output / f"APP_OWNED_{name.upper()}_QUEUE_MANIFEST.json", {
            "schema": QUEUE_MANIFEST_SCHEMA, "plan_id": plan["plan_id"],
            "routing_set_id": plan["routing_set_id"],
            "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            "ownership_manifest": _descriptor(app_owned_manifest), "queue_kind": name,
            "queue": queue_descriptor, "unit_count": len(rows),
            "unit_id_stream_sha256": _sha(b"".join((row["unit_id"] + "\n").encode() for row in sorted(rows, key=lambda row: row["unit_id"]))),
        })
        queue_descriptors[name] = {"queue": queue_descriptor, "manifest": manifest}
    return _completion(plan, "app_reconstruction", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "app_owned_classes": len(classes),
        "app_owned_methods": len(methods), "source_artifacts": source_descriptors,
        "app_owned_js_modules": len(js_modules), "smali_artifacts": smali_descriptors,
        "app_owned_deterministic_entities": len(deterministic_entities),
        "reconstruction_operations": reconstruction_operations,
        "semantic_queues": queue_descriptors, "context_budget_bytes": context_budget_bytes,
        "third_party_reconstructed": 0, "hold_reconstructed": 0,
        "completion_state": (
            "EMPTY_COMPLETE"
            if not classes and not methods and not js_modules and not deterministic_entities
            else "COMPLETE"
        ),
        "empty_membership": not classes and not methods and not js_modules and not deterministic_entities,
        "tool_contacted": bool(classes or js_modules),
    })


def _verify_app_queue(plan: dict[str, Any], queue: str | Path, manifest: str | Path) -> dict[str, Any]:
    document = json.loads(Path(manifest).resolve(strict=True).read_bytes())
    if (
        document.get("schema") != QUEUE_MANIFEST_SCHEMA
        or not verify_document(document, require_signature=True)
        or document.get("plan_id") != plan["plan_id"]
        or document.get("routing_set_id") != plan["routing_set_id"]
        or document.get("ownership_policy_id") != plan["ownership_policy"]["policy_id"]
        or document.get("queue") != _descriptor(queue)
    ):
        raise ValueError("semantic queue is not the exact signed APP_OWNED queue")
    rows = [
        json.loads(raw_line) for raw_line in Path(queue).resolve(strict=True).read_bytes().splitlines()
        if raw_line.strip()
    ]
    ordered = canonical_order_rows(
        "angerona/canonical-unit-jsonl/v1", "$rows", rows,
        context="signed APP_OWNED queue",
    )
    if rows != ordered:
        raise ValueError("signed APP_OWNED queue rows are not in canonical unit_id order")
    unit_stream = b"".join((row["unit_id"] + "\n").encode() for row in rows)
    if (
        require_int_field(document, "unit_count", context="APP_OWNED queue manifest", minimum=0)
        != len(rows)
        or document.get("unit_id_stream_sha256") != _sha(unit_stream)
    ):
        raise ValueError("signed APP_OWNED queue identity stream mismatch")
    return document


def ai_review_adapter(
    plan_path: str | Path, queues: Iterable[tuple[str | Path, str | Path, str | Path]],
    output_dir: str | Path, completion_receipt: str | Path,
    *, endpoint: str, model: str, workers: int = 3,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "ai_review")
    if not lineage.get("audit_epoch"):
        raise ValueError("AI review requires the final epoch-bound routing plan")
    output = _confined_output(plan, output_dir)
    epoch_descriptor = lineage["audit_epoch"]
    epoch_path = epoch_descriptor["path"]
    epoch = load_audit_epoch(epoch_path)
    set_descriptors = []
    method_fragment_groups: dict[str, list[dict[str, Any]]] = {}
    queue_attachments = []
    for index, (queue, manifest, checkpoint_root) in enumerate(queues):
        queue_document = _verify_app_queue(plan, queue, manifest)
        for raw_line in Path(queue).resolve(strict=True).read_bytes().splitlines():
            unit = json.loads(raw_line)
            if unit.get("unit_kind") == "dex_method_semantic_fragment":
                method_fragment_groups.setdefault(str(unit["method_id"]), []).append(unit)
        queue_sha = queue_matches_epoch(queue, epoch)
        if queue_sha != queue_document["queue"]["sha256"]:
            raise ValueError("epoch queue hash differs from signed APP_OWNED queue")
        attachment = _write_signed(output / f"QUEUE_EPOCH_ATTACHMENT_{index}.json", {
            "schema": QUEUE_EPOCH_ATTACHMENT_SCHEMA, "plan_id": plan["plan_id"],
            "routing_set_id": plan["routing_set_id"],
            "ownership_policy_id": plan["ownership_policy"]["policy_id"],
            "audit_epoch": epoch_descriptor, "queue_manifest": _descriptor(manifest),
            "queue": _descriptor(queue),
        })
        queue_attachments.append(attachment)
        result = run_semantic_ai_queue(
            queue, checkpoint_root, endpoint=endpoint, model=model, workers=workers,
            max_attempts=3, timeout=1800, max_tokens=5000, max_token_ceiling=32000,
            audit_epoch=epoch_path,
        )
        if not result.get("semantic_complete"):
            raise ValueError("AI queue has retryable or unresolved checkpoints")
        set_path = output / f"CHECKPOINT_SET_{index}.json"
        seal_checkpoint_set(queue, checkpoint_root, epoch_path, set_path)
        verify_checkpoint_set(set_path, queue, epoch_path)
        set_descriptors.append(_descriptor(set_path))
    fragment_consolidation = None
    if method_fragment_groups:
        consolidated = []
        all_set_sha = {row["sha256"] for row in set_descriptors}
        for method_id, fragments in sorted(method_fragment_groups.items()):
            ordered = sorted(fragments, key=lambda row: int(row["fragment_index"]))
            expected_indexes = list(range(int(ordered[0]["fragment_count"])))
            observed_indexes = [int(row["fragment_index"]) for row in ordered]
            if observed_indexes != expected_indexes or any(
                int(left["byte_end"]) != int(right["byte_start"])
                for left, right in zip(ordered, ordered[1:])
            ):
                raise ValueError(f"method fragment terminal set is incomplete: {method_id}")
            if int(ordered[0]["byte_start"]) != 0 or int(ordered[-1]["byte_end"]) != int(ordered[0]["method_source_bytes"]):
                raise ValueError(f"method fragment terminal ranges do not conserve source: {method_id}")
            if len({row["method_source_sha256"] for row in ordered}) != 1:
                raise ValueError(f"method fragment source identity is mixed: {method_id}")
            consolidated.append({
                "method_id": method_id, "method_source_sha256": ordered[0]["method_source_sha256"],
                "method_source_bytes": ordered[0]["method_source_bytes"],
                "fragment_count": len(ordered), "unit_ids": canonical_order_values(
                    "angerona/method-fragment-consolidation-set/v1", "unit_ids",
                    [row["unit_id"] for row in ordered],
                    context=f"method fragment set {method_id}",
                ),
                "state": "terminal-fragment-set-complete",
            })
        fragment_consolidation = _write_signed(output / "METHOD_FRAGMENT_CONSOLIDATION_SET.json", {
            "schema": "angerona/method-fragment-consolidation-set/v1",
            "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
            "audit_epoch": epoch_descriptor, "checkpoint_set_sha256": sorted(all_set_sha),
            "method_count": len(consolidated), "methods": consolidated,
            "semantic_claim": "all-fragments-terminal-no-whole-method-synthesis-claimed",
            "coverage_only": True, "semantic_synthesis": False,
            "coverage_only_semantic_synthesis": False,
        })
    return _completion(plan, "ai_review", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "audit_epoch": epoch_descriptor,
        "queue_epoch_attachments": queue_attachments,
        "terminal_checkpoint_sets": set_descriptors,
        "method_fragment_consolidation_set": fragment_consolidation,
        "app_owned_only": True, "third_party_ai_units": 0, "hold_ai_units": 0,
    })


def surface_semantic_adapter(
    plan_path: str | Path, queue: str | Path, queue_manifest: str | Path,
    checkpoint_root: str | Path, output_dir: str | Path, completion_receipt: str | Path,
    *, endpoint: str, model: str, workers: int = 3,
) -> dict[str, Any]:
    """Run the ownership-neutral application surface only after epoch pinning."""
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "surface_semantic")
    if not lineage.get("audit_epoch"):
        raise ValueError("surface semantic review requires an epoch-bound clean plan")
    output = _confined_output(plan, output_dir)
    roots = _roots(plan)
    manifest_descriptor = _descriptor(queue_manifest)
    surface_parent = (lineage.get("parent_receipts") or {}).get("application_surface")
    if not isinstance(surface_parent, dict):
        raise ValueError("surface semantic lane lacks its exact application-surface parent")
    _surface_path, surface_payload = open_verified_artifact(surface_parent, roots)
    surface_receipt = json.loads(surface_payload)
    if (
        surface_receipt.get("schema") != LANE_SCHEMAS["application_surface"]
        or not verify_document(surface_receipt, require_signature=True)
        or surface_receipt.get("plan_id") != plan["plan_id"]
        or surface_receipt.get("surface_queue_manifest") != manifest_descriptor
        or surface_receipt.get("surface_queue_lineage") != _descriptor(
            Path(queue).resolve(strict=True).with_name(Path(queue).name + ".lineage.json")
        )
    ):
        raise ValueError("surface semantic queue is not the exact signed parent queue")
    _path, payload = open_verified_artifact(manifest_descriptor, roots)
    try:
        manifest_document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("application-surface queue manifest is not JSON") from exc
    if (
        manifest_document.get("schema") != APPLICATION_SURFACE_QUEUE_SCHEMA
        or not verify_document(manifest_document, require_signature=True)
        or manifest_document.get("plan_id") != plan["plan_id"]
        or manifest_document.get("routing_set_id") != plan["routing_set_id"]
        or manifest_document.get("ownership_policy") != plan["ownership_policy"]
        or manifest_document.get("audit_epoch") != plan.get("audit_epoch")
        or manifest_document.get("queue") != _descriptor(queue)
        or manifest_document.get("ownership_claimed") is not False
    ):
        raise ValueError("surface semantic queue lineage or ownership-neutral contract is invalid")
    epoch_descriptor = lineage["audit_epoch"]
    epoch_path = epoch_descriptor["path"]
    epoch = load_audit_epoch(epoch_path)
    if queue_matches_epoch(queue, epoch) != manifest_document["queue"]["sha256"]:
        raise ValueError("application-surface queue is not sealed in the audit epoch")
    result = run_semantic_ai_queue(
        queue, checkpoint_root, endpoint=endpoint, model=model, workers=workers,
        max_attempts=3, timeout=1800, max_tokens=5000, max_token_ceiling=32000,
        audit_epoch=epoch_path,
    )
    if not result.get("semantic_complete"):
        raise ValueError("application-surface semantic queue has nonterminal checkpoints")
    set_path = output / "APPLICATION_SURFACE_CHECKPOINT_SET.json"
    seal_checkpoint_set(queue, checkpoint_root, epoch_path, set_path)
    verify_checkpoint_set(set_path, queue, epoch_path)
    return _completion(plan, "surface_semantic", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "lane_complete": True, "audit_epoch": epoch_descriptor,
        "surface_queue_manifest": manifest_descriptor,
        "terminal_checkpoint_set": _descriptor(set_path),
        "occurrence_index": manifest_document["occurrence_index"],
        "code_ownership_claimed": False, "hold_tolerated_for_parallel_surface_only": True,
    })


_NATIVE_ROLE_LANES = {
    "reconstruction": {"native-ghidra-materialization"},
    "ida": {"native-ida-static"},
    "semantic_queue": {"native-semantic-queue"},
    "semantic_ai": {"native-semantic-ai"},
    "evidence_resolution": {"native-evidence-resolution"},
    "evidence_ai": {"native-semantic-ai", "native-ai-evidence"},
    "consolidation_queue": {"native-consolidation-queue"},
    "consolidation_ai": {"native-semantic-ai"},
}


def native_acceptance_adapter(
    plan_path: str | Path, lane_receipts: dict[str, str | Path],
    root_conservation_receipt: str | Path, completion_receipt: str | Path,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "native_acceptance")
    native = plan.get("external_native_routing")
    epoch = lineage.get("audit_epoch")
    if not native or not epoch:
        raise ValueError("native acceptance requires exact signed routing and audit epoch")
    if set(lane_receipts) != set(_NATIVE_ROLE_LANES):
        raise ValueError("native acceptance requires every authoritative native lane role exactly once")
    expected_app_values = canonical_order_values(
        "angerona/canonical-target-set/v1", "expected",
        native["expected_app_owned_target_sha256"], context="native routing",
    )
    expected_excluded_values = canonical_order_values(
        "angerona/canonical-target-set/v1", "excluded",
        native["excluded_target_sha256"], context="native routing",
    )
    hold_values = canonical_order_values(
        "angerona/canonical-target-set/v1", "hold",
        native.get("hold_target_sha256") or [], context="native routing",
    )
    if (
        native["expected_app_owned_target_sha256"] != expected_app_values
        or native["excluded_target_sha256"] != expected_excluded_values
        or (native.get("hold_target_sha256") or []) != hold_values
    ):
        raise ValueError("native routing target arrays are not canonical")
    expected_app = set(expected_app_values)
    expected_excluded = set(expected_excluded_values)
    if hold_values:
        raise ValueError("native acceptance is blocked by HOLD targets")
    accepted_receipts = {}
    for role, supplied in sorted(lane_receipts.items()):
        path, payload = open_verified_artifact(_descriptor(supplied), _roots(plan))
        receipt = json.loads(payload)
        if (
            receipt.get("schema") != LANE_RECEIPT_SCHEMA
            or not verify_document(receipt, require_signature=True)
            or receipt.get("lane") not in _NATIVE_ROLE_LANES[role]
            or receipt.get("lane_epoch_id") != epoch["epoch_id"]
            or receipt.get("routing") != native["routing_binding"]
            or receipt.get("lane_complete") is not True
            or receipt.get("semantic_complete") is not True
            or receipt.get("expected_app_owned_target_sha256") != expected_app_values
            or receipt.get("processed_app_owned_target_sha256") != expected_app_values
            or receipt.get("excluded_target_sha256") != expected_excluded_values
            or receipt.get("hold_target_sha256")
        ):
            raise ValueError(f"native {role} receipt is incomplete or has mixed lineage: {path}")
        if expected_excluded.intersection(receipt.get("processed_app_owned_target_sha256") or []):
            raise ValueError(f"native {role} receipt leaks excluded targets")
        accepted_receipts[role] = {"path": str(path), "sha256": _sha(payload)}
    root_path, root_payload = open_verified_artifact(_descriptor(root_conservation_receipt), _roots(plan))
    root = json.loads(root_payload)
    root_rows = require_list_field(root, "rows", context="native root conservation")
    if root_rows != canonical_order_rows(
        "angerona/canonical-target-set/v1", "rows", root_rows,
        context="native root conservation",
    ):
        raise ValueError("native root conservation rows are not canonical")
    root_targets = [str(row.get("target_sha256") or "") for row in root_rows]
    if (
        root.get("schema") != ROOT_CONSERVATION_SCHEMA
        or not verify_document(root, require_signature=True)
        or root.get("audit_epoch_id") != epoch["epoch_id"]
        or root.get("universe_file_sha256") != native["native_universe"]["sha256"]
        or root.get("ownership_manifest_file_sha256") != native["ownership_manifest"]["sha256"]
        or root.get("universe_conserved") is not True
        or root.get("controller_complete") is not True
        or root_targets != sorted(expected_app | expected_excluded)
        or any(require_int_field(
            row, "event_count", context="native root conservation row", minimum=0,
        ) != 1 for row in root_rows)
    ):
        raise ValueError(f"native root conservation is incomplete or has mixed lineage: {root_path}")
    for row in root_rows:
        target = str(row["target_sha256"])
        expected_state = "target-semantic-complete" if target in expected_app else "ownership-excluded-third-party"
        if row.get("state") != expected_state:
            raise ValueError("native root terminal disposition does not match signed routing")
    return _completion(plan, "native_acceptance", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "lane_complete": True, "semantic_complete": True,
        "native_routing": native, "native_lane_receipts": accepted_receipts,
        "root_conservation_receipt": {"path": str(root_path), "sha256": _sha(root_payload)},
        "expected_app_owned_target_count": len(expected_app),
        "excluded_target_count": len(expected_excluded), "hold_target_count": 0,
        "excluded_leakage_count": 0, "root_conserved": True,
    })


def _verified_clean_lane_receipt(
    plan: dict[str, Any], receipt: str | Path, lane: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    descriptor = _descriptor(receipt)
    _path, payload = open_verified_artifact(descriptor, _roots(plan))
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{lane} completion receipt is not JSON") from exc
    if (
        document.get("schema") != LANE_SCHEMAS[lane]
        or not verify_document(document, require_signature=True)
        or document.get("plan_id") != plan["plan_id"]
        or document.get("routing_set_id") != plan["routing_set_id"]
        or document.get("ownership_policy_id") != plan["ownership_policy"]["policy_id"]
        or document.get("audit_epoch") != plan.get("audit_epoch")
        or document.get("status") != "COMPLETE"
        or document.get("lane_complete") is not True
    ):
        raise ValueError(f"{lane} completion receipt is nonterminal or has mixed lineage")
    return descriptor, document


def cross_layer_merge_adapter(
    plan_path: str | Path, ownership_receipt: str | Path,
    smali_root: str | Path, dex_receipt_root: str | Path, audit_root: str | Path,
    output_dir: str | Path, completion_receipt: str | Path,
    *, application_surface_receipt: str | Path,
    surface_semantic_receipt: str | Path,
    native_acceptance_receipt: str | Path | None = None,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "cross_layer_merge")
    surface_descriptor, surface = _verified_clean_lane_receipt(
        plan, application_surface_receipt, "application_surface",
    )
    surface_ai_descriptor, surface_ai = _verified_clean_lane_receipt(
        plan, surface_semantic_receipt, "surface_semantic",
    )
    parents = lineage.get("parent_receipts") or {}
    if (
        parents.get("application_surface") != surface_descriptor
        or parents.get("surface_semantic") != surface_ai_descriptor
        or surface_ai.get("surface_queue_manifest") != surface.get("surface_queue_manifest")
        or surface_ai.get("occurrence_index") != surface.get("occurrence_index")
        or surface.get("code_ownership_claimed") is not False
        or surface_ai.get("code_ownership_claimed") is not False
    ):
        raise ValueError("cross-layer application-surface parents disagree or claim code ownership")
    ownership = json.loads(Path(ownership_receipt).resolve(strict=True).read_bytes())
    if (
        not verify_document(ownership, require_signature=True)
        or ownership.get("schema") != LANE_SCHEMAS["ownership_filter"]
        or ownership.get("plan_id") != plan["plan_id"]
        or require_int_field(
            ownership, "unknown_hold_count", context="ownership receipt", minimum=0,
        ) != 0
        or not ownership.get("fully_excluded_third_party")
    ):
        raise ValueError("cross-layer merge is blocked by ownership HOLD or lineage failure")
    coverage = json.loads(Path(plan["coverage_accounting"]["path"]).read_bytes())
    disposition_counts = coverage.get("disposition_counts")
    if not isinstance(disposition_counts, dict):
        raise ValueError("coverage accounting disposition_counts must be an object")
    if require_int_field(
        disposition_counts, "HOLD", context="coverage disposition_counts", minimum=0,
    ) != 0:
        raise ValueError("cross-layer merge is blocked by APK HOLD entries")
    native_acceptance = None
    if plan.get("external_native_routing"):
        if not native_acceptance_receipt:
            raise ValueError("cross-layer merge requires the terminal native acceptance receipt")
        supplied_native_descriptor = _descriptor(native_acceptance_receipt)
        expected_native_descriptor = (lineage.get("parent_receipts") or {}).get("native_acceptance")
        if supplied_native_descriptor != expected_native_descriptor:
            raise ValueError("cross-layer native acceptance is not its exact checkpoint parent")
        native_path, native_payload = open_verified_artifact(supplied_native_descriptor, _roots(plan))
        native_acceptance = json.loads(native_payload)
        if (
            native_acceptance.get("schema") != LANE_SCHEMAS["native_acceptance"]
            or not verify_document(native_acceptance, require_signature=True)
            or native_acceptance.get("plan_id") != plan["plan_id"]
            or native_acceptance.get("routing_set_id") != plan["routing_set_id"]
            or native_acceptance.get("audit_epoch") != plan.get("audit_epoch")
            or native_acceptance.get("lane_complete") is not True
            or native_acceptance.get("root_conserved") is not True
            or require_int_field(
                native_acceptance, "hold_target_count",
                context="native acceptance", minimum=0,
            ) != 0
            or require_int_field(
                native_acceptance, "excluded_leakage_count",
                context="native acceptance", minimum=0,
            ) != 0
        ):
            raise ValueError(f"cross-layer merge rejects incomplete native acceptance: {native_path}")
    output = _confined_output(plan, output_dir)
    roots = _roots(plan)
    def inventory(root: Path) -> dict[str, Any]:
        rows = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"cross-layer input contains a symlink: {path}")
            if path.is_file():
                payload = path.read_bytes()
                rows.append({
                    "path": path.relative_to(root).as_posix(), "bytes": len(payload),
                    "sha256": _sha(payload),
                })
        return {
            "root": str(root), "file_count": len(rows),
            "file_stream_sha256": _sha(b"".join(_canonical(row) for row in rows)),
            "files": rows,
        }

    inputs = []
    for value in (smali_root, dex_receipt_root, audit_root):
        path = Path(value).resolve(strict=True)
        if not _within(path, roots):
            raise ValueError("cross-layer input escapes signed roots")
        inputs.append(path)
    input_inventories = [inventory(path) for path in inputs]
    graph = build_cross_layer_graph(inputs[0], inputs[1], inputs[2], output / "graph")
    if [inventory(path) for path in inputs] != input_inventories:
        raise ValueError("cross-layer inputs changed while the graph was built")
    if not graph.get("graph_complete"):
        raise ValueError("cross-layer graph retains unresolved work units")
    graph_descriptor = _descriptor(output / "graph" / "CROSS_LAYER_GRAPH.json")
    return _completion(plan, "cross_layer_merge", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "cross_layer_graph": graph_descriptor,
        "graph_manifest_sha256": graph["manifest_sha256"],
        "ownership_receipt": _descriptor(ownership_receipt), "hold_count": 0,
        "application_surface_receipt": surface_descriptor,
        "surface_semantic_receipt": surface_ai_descriptor,
        "native_acceptance_receipt": _descriptor(native_acceptance_receipt) if native_acceptance_receipt else None,
        "input_inventories": input_inventories,
    })


def dynamic_security_plan_adapter(
    plan_path: str | Path, cross_layer_receipt: str | Path,
    output_dir: str | Path, completion_receipt: str | Path,
    *, occurrence_indexes: Iterable[str | Path] = (),
) -> dict[str, Any]:
    """Build the hypothesis-only discovery queue from the exact sealed merge graph."""
    plan = verify_clean_apk_routing_plan(plan_path)
    lineage = _lineage(plan, "dynamic_security_plan")
    supplied_parent = _descriptor(cross_layer_receipt)
    expected_parent = (lineage.get("parent_receipts") or {}).get("cross_layer_merge")
    if supplied_parent != expected_parent:
        raise ValueError("dynamic security planner is not bound to its exact cross-layer parent")
    output = _confined_output(plan, output_dir)
    result = build_dynamic_security_plan(
        plan_path=plan_path,
        audit_epoch=plan["audit_epoch"]["path"],
        cross_layer_receipt=cross_layer_receipt,
        output_dir=output,
        occurrence_indexes=occurrence_indexes,
    )
    return _completion(plan, "dynamic_security_plan", Path(completion_receipt).resolve(), {
        "status": "COMPLETE", "lane_complete": True,
        "cross_layer_receipt": supplied_parent,
        "dynamic_security_plan": result["manifest"],
        "dynamic_security_queue": result["queue"],
        "dynamic_security_lineage": result["lineage"],
        "dynamic_evidence_anchors": result["anchor_index"],
        "unit_count": result["units"], "node_count": result["nodes"],
        "edge_count": result["edges"], "fact_count": result["facts"],
        "anchor_count": result["anchors"],
        "confirmation_semantics": "hypotheses-only-independent-proof-required",
    })
