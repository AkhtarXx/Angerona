"""Fail-closed native ownership classification and exact Ghidra scheduling."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
from typing import Any

from .evidence_signing import sign_document, verify_document
from .native_pre_re_classifier import (
    CONFIRMED_APP_OWNED,
    CONFIRMED_THIRD_PARTY,
    HOLD_UNKNOWN as PRE_RE_HOLD,
    MODIFIED_VENDOR_REVIEW,
    load_pre_re_classification,
)
from .native_target_universe import load_native_target_universe
from .schema_validation import require_int_field, require_list_field


OWNERSHIP_SCHEMA = "angerona/native-ownership-routing/v3"
RANGE_QUEUE_SCHEMA = "angerona/native-analysis-range-queue/v2"
APP_PROVENANCE_SCHEMA = "angerona/native-app-build-provenance/v1"
REFERENCE_SCHEMA = "angerona/native-third-party-reference/v1"
OVERRIDE_SCHEMA = "angerona/native-ownership-overrides/v1"
ANALYZE_APP = "ANALYZE_APP_OWNED"
ANALYZE_MODIFIED = "ANALYZE_OPERATOR_APPROVED_MODIFIED_APP"
EXCLUDE_THIRD_PARTY = "FULLY_EXCLUDED_THIRD_PARTY"
HOLD = "HOLD_UNKNOWN"
_POLICY = {
    "schema": "angerona/native-ownership-policy/v2",
    "analyze_dispositions": [ANALYZE_APP, ANALYZE_MODIFIED],
    "excluded_dispositions": [EXCLUDE_THIRD_PARTY],
    "hold_dispositions": [HOLD],
    "app_owned_requires": "signed PRE-RE exact authenticated app-build bytes",
    "modified_app_requires": "signed explicit human override for exact target SHA",
    "third_party_requires": [
        "signed PRE-RE exact authenticated upstream bytes",
        "or signed PRE-RE authenticated package multi-signal match with no negative evidence",
    ],
    "pre_re_classifier_required_before_workspace_or_engine": True,
    "fingerprint_only_exclusion_forbidden": True,
    "metadata_ai_advisory_never_authorizes_launch_or_exclusion": True,
    "conflict_action": HOLD,
    "unknown_action": HOLD,
    "path_or_library_name_never_proves_app_ownership": True,
    "third_party_decompilation_forbidden": True,
    "mixed_vendor_requires_signed_selective_ranges": True,
    "matched_vendor_ranges_never_enter_re_or_ai": True,
}

from .native_range_authority import (
    derive_partition,
    launch_authority_token,
    validate_launch_authority,
    validate_partition,
)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Any, *, immutable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable and os.path.lexists(path):
        raise ValueError(f"immutable ownership output already exists: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if immutable:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _signed_source(path: Path | None, schema: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None:
        return {}, {"present": False, "schema": schema}
    supplied = path.expanduser().absolute()
    metadata = supplied.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"ownership source must be a non-symlink regular file: {supplied}")
    document = json.loads(supplied.read_text(encoding="utf-8"))
    if document.get("schema") != schema or not verify_document(document, require_signature=True):
        raise ValueError(f"ownership source signature/schema verification failed: {supplied}")
    return document, {
        "present": True,
        "schema": schema,
        "path": str(supplied.resolve(strict=True)),
        "sha256": _sha256_path(supplied),
        "payload_sha256": document.get("payload_sha256"),
        "signature_key_id": document.get("signature_key_id"),
    }


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    return data[offset:data.find(b"\0", offset) if b"\0" in data[offset:] else len(data)].decode(
        "utf-8", errors="replace",
    )


def _elf_metadata(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or len(data) < 52:
        raise ValueError(f"ownership target is not ELF: {path}")
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
    if elf_class not in {1, 2} or not endian:
        raise ValueError("unsupported ELF identity")
    if elf_class == 2:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        shfmt = endian + "IIQQQQIIQQ"
    else:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        shoff = struct.unpack_from(endian + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 46)
        shfmt = endian + "IIIIIIIIII"
    expected_size = struct.calcsize(shfmt)
    if shentsize < expected_size or shnum > 65535 or shoff + shentsize * shnum > len(data):
        raise ValueError("ELF section table is invalid")
    sections = []
    for index in range(shnum):
        fields = struct.unpack_from(shfmt, data, shoff + index * shentsize)
        sections.append({
            "name_offset": int(fields[0]), "type": int(fields[1]),
            "offset": int(fields[4]), "size": int(fields[5]),
            "link": int(fields[6]), "entry_size": int(fields[9]),
        })
    if shstrndx >= len(sections):
        raise ValueError("ELF section-name table is invalid")
    shstr = sections[shstrndx]
    shstr_data = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for section in sections:
        section["name"] = _cstring(shstr_data, section["name_offset"])
        if section["offset"] + section["size"] > len(data):
            raise ValueError("ELF section extends beyond target")
    build_ids: list[str] = []
    dynamic_symbols: list[str] = []
    soname = ""
    comments: list[str] = []
    for section in sections:
        payload = data[section["offset"]:section["offset"] + section["size"]]
        if section["type"] == 7:
            cursor = 0
            while cursor + 12 <= len(payload):
                namesz, descsz, note_type = struct.unpack_from(endian + "III", payload, cursor)
                cursor += 12
                name = payload[cursor:cursor + namesz].rstrip(b"\0")
                cursor += (namesz + 3) & ~3
                desc = payload[cursor:cursor + descsz]
                cursor += (descsz + 3) & ~3
                if name == b"GNU" and note_type == 3 and desc:
                    build_ids.append(desc.hex())
        if section["name"] == ".comment":
            comments.extend(
                value.decode("utf-8", errors="replace")
                for value in payload.split(b"\0") if value
            )
        if section["type"] == 11 and section["link"] < len(sections):
            strings = sections[section["link"]]
            string_data = data[strings["offset"]:strings["offset"] + strings["size"]]
            entry_size = section["entry_size"] or (24 if elf_class == 2 else 16)
            for cursor in range(0, len(payload) - entry_size + 1, entry_size):
                name_offset = struct.unpack_from(endian + "I", payload, cursor)[0]
                name = _cstring(string_data, name_offset)
                if name:
                    dynamic_symbols.append(name)
        if section["type"] == 6 and section["link"] < len(sections):
            strings = sections[section["link"]]
            string_data = data[strings["offset"]:strings["offset"] + strings["size"]]
            entry_size = 16 if elf_class == 2 else 8
            tag_fmt = endian + ("qQ" if elf_class == 2 else "iI")
            for cursor in range(0, len(payload) - entry_size + 1, entry_size):
                tag, value = struct.unpack_from(tag_fmt, payload, cursor)
                if tag == 0:
                    break
                if tag == 14:
                    soname = _cstring(string_data, int(value))
    symbols = sorted(set(dynamic_symbols))
    metadata = {
        "elf_class": 64 if elf_class == 2 else 32,
        "endianness": "little" if endian == "<" else "big",
        "machine": machine,
        "build_ids": sorted(set(build_ids)),
        "soname": soname,
        "dynamic_symbol_count": len(symbols),
        "dynamic_symbol_fingerprint_sha256": hashlib.sha256(_canonical(symbols)).hexdigest(),
        "dynamic_symbol_sample": symbols[:64],
        "comment_fingerprint_sha256": hashlib.sha256(_canonical(sorted(set(comments)))).hexdigest(),
        "comments": sorted(set(comments))[:16],
    }
    metadata["metadata_fingerprint_sha256"] = hashlib.sha256(_canonical(metadata)).hexdigest()
    return metadata


def _rows_by_sha(document: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in require_list_field(document, "rows", context="native ownership source"):
        if not isinstance(row, dict):
            raise ValueError(f"{label} row is invalid")
        target_sha = str(row.get("target_sha256") or "").lower()
        if len(target_sha) != 64 or target_sha in result:
            raise ValueError(f"{label} target SHA is invalid or duplicate")
        result[target_sha] = row
    return result


def _tree_evidence(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        return {"present": False, "state": "none"}
    rows = []
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            rows.append({
                "path": item.relative_to(path).as_posix(),
                "bytes": item.stat().st_size,
                "sha256": _sha256_path(item),
            })
    return {
        "present": True,
        "state": "superseded-read-only",
        "path": str(path.resolve()),
        "file_count": len(rows),
        "tree_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
    }


def _range_scope(
    *, target_sha: str, disposition: str, classifier_row: dict[str, Any],
) -> dict[str, Any]:
    if disposition == ANALYZE_APP:
        routing = classifier_row.get("range_routing") or {}
        executable = routing.get("executable_ranges") or []
        partition = derive_partition(executable, executable, [])
        body = {
            "target_sha256": target_sha,
            "analysis_scope": "whole_target",
            "allowed_executable_ranges": partition["allowed_ranges"],
            "excluded_library_ranges": [],
            "ambiguous_executable_ranges": [],
            "executable_partition": partition,
            "partition_sha256": partition["partition_sha256"],
            "partition_counts": partition["partition_counts"],
            "classifier_range_routing_sha256": None,
            "address_domain": "ELF_VIRTUAL_ADDRESS",
        }
    elif disposition == ANALYZE_MODIFIED:
        routing = classifier_row.get("range_routing")
        if classifier_row.get("decision") != MODIFIED_VENDOR_REVIEW or not isinstance(routing, dict):
            raise ValueError("modified mixed target lacks PRE-RE range routing")
        partition = validate_partition(routing.get("executable_partition") or {})
        allowed = partition["allowed_ranges"]
        excluded = partition["excluded_ranges"]
        ambiguous = partition["ambiguous_ranges"]
        if not allowed or not excluded or ambiguous:
            raise ValueError("modified mixed target lacks conserved allowed/excluded ranges")
        body = {
            "target_sha256": target_sha,
            "analysis_scope": "selective_ranges",
            "allowed_executable_ranges": allowed,
            "excluded_library_ranges": excluded,
            "ambiguous_executable_ranges": ambiguous,
            "executable_partition": partition,
            "partition_sha256": partition["partition_sha256"],
            "partition_counts": partition["partition_counts"],
            "classifier_range_routing_sha256": hashlib.sha256(_canonical(routing)).hexdigest(),
            "address_domain": "ELF_VIRTUAL_ADDRESS",
        }
    else:
        raise ValueError("range scope requested for a non-analysis disposition")
    scoped = {**body, "range_authority_sha256": hashlib.sha256(_canonical(body)).hexdigest()}
    return {**scoped, "native_launch_authority_token": launch_authority_token(scoped)}


def build_native_ownership_manifest(
    *, universe_path: Path, output_path: Path,
    pre_re_classification_path: Path,
    app_provenance_path: Path | None = None,
    third_party_reference_path: Path | None = None,
    override_path: Path | None = None,
    reconstruction_root: Path | None = None,
) -> dict[str, Any]:
    if reconstruction_root is None:
        raise ValueError("--reconstruction-root is required to bind superseded checkpoints")
    reconstruction_root = reconstruction_root.expanduser().absolute()
    reconstruction_metadata = reconstruction_root.lstat()
    if stat.S_ISLNK(reconstruction_metadata.st_mode) or not stat.S_ISDIR(reconstruction_metadata.st_mode):
        raise ValueError("superseded reconstruction root must be a non-symlink directory")
    universe, records = load_native_target_universe(universe_path)
    classification, classification_rows = load_pre_re_classification(
        pre_re_classification_path, universe_path=universe_path,
    )
    classification_supplied = pre_re_classification_path.expanduser().absolute()
    classification_source = {
        "present": True,
        "schema": classification.get("schema"),
        "path": str(classification_supplied.resolve(strict=True)),
        "sha256": _sha256_path(classification_supplied),
        "payload_sha256": classification.get("payload_sha256"),
        "signature_key_id": classification.get("signature_key_id"),
        "classifier_identity_sha256": classification.get("classifier_identity_sha256"),
        "catalog_identity_sha256": classification.get("catalog_identity_sha256"),
    }
    classification_by_sha = {
        str(row["target_sha256"]): row for row in classification_rows
    }
    if app_provenance_path is not None or third_party_reference_path is not None:
        raise ValueError(
            "legacy direct app/reference ownership inputs are forbidden; ingest them into PRE-RE catalogs"
        )
    app_doc, app_source = _signed_source(app_provenance_path, APP_PROVENANCE_SCHEMA)
    reference_doc, reference_source = _signed_source(third_party_reference_path, REFERENCE_SCHEMA)
    override_doc, override_source = _signed_source(override_path, OVERRIDE_SCHEMA)
    app_rows = _rows_by_sha(app_doc, "app provenance") if app_doc else {}
    reference_rows = _rows_by_sha(reference_doc, "third-party reference") if reference_doc else {}
    override_rows = _rows_by_sha(override_doc, "ownership override") if override_doc else {}
    record_by_sha = {row["target_sha256"]: row for row in records}
    output_rows = []
    queue = []
    policy_sha = hashlib.sha256(_canonical(_POLICY)).hexdigest()
    for universe_row in require_list_field(
        universe, "targets", context="native target universe",
    ):
        target_sha = str(universe_row["target_sha256"])
        record = record_by_sha[target_sha]
        target_path = record.get("target")
        metadata_error = None
        if target_path is None:
            metadata = {"error": "missing extracted target"}
            metadata_error = metadata["error"]
        else:
            try:
                metadata = _elf_metadata(target_path)
            except Exception as exc:
                metadata_error = f"{type(exc).__name__}: {exc}"
                metadata = {"error": metadata_error}
        classifier_row = classification_by_sha[target_sha]
        classifier_decision = classifier_row.get("decision")
        override = override_rows.get(target_sha)
        disposition = HOLD
        confidence = "none"
        basis = "PRE-RE classifier did not grant launch or exclusion authority"
        if override is not None:
            requested = str(override.get("disposition") or "")
            if requested not in {ANALYZE_MODIFIED, HOLD}:
                raise ValueError(f"unsupported ownership override disposition: {target_sha}")
            if (
                not override.get("override_id")
                or not override.get("reason")
                or not override.get("approved_by")
                or not override.get("approved_at_utc")
            ):
                raise ValueError(f"ownership override lacks human approval lineage: {target_sha}")
            disposition, confidence = requested, "operator-approved"
            basis = "signed exact-target human override"
            if disposition == ANALYZE_MODIFIED:
                try:
                    partition = validate_partition(
                        (classifier_row.get("range_routing") or {}).get("executable_partition") or {},
                    )
                    if partition["ambiguous_ranges"]:
                        raise ValueError("ambiguous executable bytes")
                except ValueError:
                    disposition, confidence = HOLD, "operator-review-range-incomplete"
                    basis = "signed override cannot bypass incomplete executable partition"
        elif classifier_decision == CONFIRMED_APP_OWNED:
            disposition, confidence = ANALYZE_APP, str(classifier_row.get("evidence_tier"))
            basis = "signed PRE-RE classifier confirmed authenticated app-build bytes"
        elif classifier_decision == CONFIRMED_THIRD_PARTY:
            disposition, confidence = EXCLUDE_THIRD_PARTY, str(classifier_row.get("evidence_tier"))
            basis = "signed PRE-RE classifier confirmed authenticated third-party evidence"
        elif classifier_decision == MODIFIED_VENDOR_REVIEW:
            disposition, confidence = HOLD, "operator-review-required"
            basis = "PRE-RE classifier detected vendor lineage or modification risk"
        elif classifier_decision != PRE_RE_HOLD:
            raise ValueError(f"unsupported PRE-RE classifier decision: {target_sha}")
        elif metadata_error is not None:
            disposition, confidence = HOLD, "metadata-unavailable"
            basis = "ELF metadata unavailable and no exact signed ownership proof"
        prior_root = reconstruction_root / "targets" / target_sha
        row = {
            "target_sha256": target_sha,
            "apk_path": universe_row.get("apk_path"),
            "apk_aliases": universe_row.get("aliases") or [],
            "disposition": disposition,
            "confidence": confidence,
            "basis": basis,
            "policy_sha256": policy_sha,
            "metadata_evidence": metadata,
            "classifier_decision_evidence": classifier_row,
            "app_provenance_evidence": (
                classifier_row.get("matched_reference")
                if classifier_decision == CONFIRMED_APP_OWNED else None
            ),
            "third_party_reference_evidence": (
                classifier_row.get("matched_reference")
                if classifier_decision == CONFIRMED_THIRD_PARTY else None
            ),
            "human_override_lineage": [override] if override is not None else [],
            "prior_checkpoint_evidence": _tree_evidence(prior_root),
        }
        output_rows.append(row)
        if disposition in {ANALYZE_APP, ANALYZE_MODIFIED}:
            range_scope = _range_scope(
                target_sha=target_sha, disposition=disposition, classifier_row=classifier_row,
            )
            queue.append({
                "target_sha256": target_sha,
                "disposition": disposition,
                "target_path": str(target_path) if target_path is not None else None,
                "analysis_path": str(record.get("analysis")) if record.get("analysis") is not None else None,
                "ownership_row_sha256": hashlib.sha256(_canonical(row)).hexdigest(),
                **range_scope,
            })
    output_rows.sort(key=lambda row: row["target_sha256"])
    queue.sort(key=lambda row: row["target_sha256"])
    partition_rows = [{
        "target_sha256": row["target_sha256"],
        "partition_sha256": row["partition_sha256"],
        "partition_counts": row["partition_counts"],
        "native_launch_authority_token": row["native_launch_authority_token"],
    } for row in queue]
    range_queue = sign_document({
        "schema": RANGE_QUEUE_SCHEMA,
        "policy_sha256": policy_sha,
        "target_universe_sha256": universe.get("target_universe_sha256"),
        "rows_sha256": hashlib.sha256(_canonical(queue)).hexdigest(),
        "row_count": len(queue),
        "partition_set_sha256": hashlib.sha256(_canonical(partition_rows)).hexdigest(),
        "partition_rows": partition_rows,
        "rows": queue,
    })
    if range_queue.get("trust") != "operator_signed":
        raise ValueError("native range queue requires an operator signing key")
    manifest = sign_document({
        "schema": OWNERSHIP_SCHEMA,
        "policy": _POLICY,
        "policy_sha256": policy_sha,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha256_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        "sources": {
            "pre_re_classification": classification_source,
            "app_provenance": app_source,
            "third_party_reference": reference_source,
            "human_overrides": override_source,
        },
        "target_count": len(output_rows),
        "rows_sha256": hashlib.sha256(_canonical(output_rows)).hexdigest(),
        "rows": output_rows,
        "app_owned_queue_count": len(queue),
        "app_owned_queue_sha256": hashlib.sha256(_canonical(queue)).hexdigest(),
        "app_owned_queue": queue,
        "analysis_range_queue": range_queue,
        "analysis_range_queue_sha256": hashlib.sha256(_canonical(range_queue)).hexdigest(),
        "partition_set_sha256": hashlib.sha256(_canonical(partition_rows)).hexdigest(),
        "partition_rows": partition_rows,
        "disposition_counts": dict(sorted(
            {name: sum(row["disposition"] == name for row in output_rows)
             for name in {ANALYZE_APP, ANALYZE_MODIFIED, EXCLUDE_THIRD_PARTY, HOLD}}.items()
        )),
    })
    if manifest.get("trust") != "operator_signed":
        raise ValueError("native ownership manifest requires an operator signing key")
    _atomic_json(output_path.expanduser().absolute(), manifest, immutable=True)
    return manifest


def load_native_ownership_manifest(
    path: Path, *, universe_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    supplied = path.expanduser().absolute()
    metadata = supplied.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("native ownership manifest must be a non-symlink regular file")
    universe, records = load_native_target_universe(universe_path)
    document = json.loads(supplied.read_text(encoding="utf-8"))
    if document.get("schema") != OWNERSHIP_SCHEMA or not verify_document(document, require_signature=True):
        raise ValueError("native ownership manifest signature/schema verification failed")
    policy_sha = hashlib.sha256(_canonical(_POLICY)).hexdigest()
    if document.get("policy") != _POLICY or document.get("policy_sha256") != policy_sha:
        raise ValueError("native ownership policy mismatch")
    if (
        document.get("universe_file_sha256") != _sha256_path(universe_path.resolve())
        or document.get("universe_payload_sha256") != universe.get("payload_sha256")
        or document.get("target_universe_sha256") != universe.get("target_universe_sha256")
    ):
        raise ValueError("native ownership universe binding mismatch")
    classification_source = (document.get("sources") or {}).get("pre_re_classification") or {}
    if not classification_source.get("present") or not classification_source.get("path"):
        raise ValueError("native ownership routing lacks mandatory PRE-RE classification")
    classification_path = Path(str(classification_source["path"])).expanduser().absolute()
    classification, classification_rows = load_pre_re_classification(
        classification_path, universe_path=universe_path,
    )
    if (
        _sha256_path(classification_path) != classification_source.get("sha256")
        or classification.get("payload_sha256") != classification_source.get("payload_sha256")
        or classification.get("classifier_identity_sha256")
        != classification_source.get("classifier_identity_sha256")
        or classification.get("catalog_identity_sha256")
        != classification_source.get("catalog_identity_sha256")
    ):
        raise ValueError("native ownership PRE-RE classification binding mismatch")
    classification_by_sha = {
        str(row["target_sha256"]): row for row in classification_rows
    }
    rows = require_list_field(document, "rows", context="native ownership routing")
    expected_targets = sorted(str(row["target_sha256"]) for row in require_list_field(
        universe, "targets", context="native target universe",
    ))
    actual_targets = [str(row.get("target_sha256") or "") for row in rows if isinstance(row, dict)]
    if actual_targets != expected_targets or document.get("target_count") != len(expected_targets):
        raise ValueError("native ownership target conservation mismatch")
    if document.get("rows_sha256") != hashlib.sha256(_canonical(rows)).hexdigest():
        raise ValueError("native ownership rows hash mismatch")
    record_by_sha = {row["target_sha256"]: row for row in records}
    expected_queue = []
    policy_events = []
    for row in rows:
        if row.get("policy_sha256") != policy_sha:
            raise ValueError("native ownership row policy mismatch")
        disposition = row.get("disposition")
        classifier_row = classification_by_sha.get(str(row.get("target_sha256") or ""))
        if classifier_row is None or row.get("classifier_decision_evidence") != classifier_row:
            raise ValueError("native ownership row PRE-RE decision binding mismatch")
        if disposition in {ANALYZE_APP, ANALYZE_MODIFIED}:
            if disposition == ANALYZE_APP:
                if (
                    classifier_row.get("decision") != CONFIRMED_APP_OWNED
                    or classifier_row.get("evidence_tier") != "exact-authenticated-app-build-bytes"
                ):
                    raise ValueError("app-owned disposition lacks exact PRE-RE build provenance")
            else:
                lineage = row.get("human_override_lineage") or []
                if (
                    not document.get("sources", {}).get("human_overrides", {}).get("present")
                    or len(lineage) != 1
                    or lineage[0].get("target_sha256") != row["target_sha256"]
                    or lineage[0].get("disposition") != ANALYZE_MODIFIED
                ):
                    raise ValueError("modified-app disposition lacks exact signed override lineage")
            record = record_by_sha[row["target_sha256"]]
            expected_queue.append({
                "target_sha256": row["target_sha256"],
                "disposition": disposition,
                "target_path": str(record.get("target")) if record.get("target") is not None else None,
                "analysis_path": str(record.get("analysis")) if record.get("analysis") is not None else None,
                "ownership_row_sha256": hashlib.sha256(_canonical(row)).hexdigest(),
                **_range_scope(
                    target_sha=row["target_sha256"], disposition=disposition,
                    classifier_row=classifier_row,
                ),
            })
        else:
            if disposition not in {EXCLUDE_THIRD_PARTY, HOLD}:
                raise ValueError("native ownership disposition is invalid")
            if disposition == EXCLUDE_THIRD_PARTY:
                if (
                    classifier_row.get("decision") != CONFIRMED_THIRD_PARTY
                    or classifier_row.get("evidence_tier") != "exact-authenticated-upstream-bytes"
                ):
                    raise ValueError("third-party exclusion lacks admissible PRE-RE evidence")
            policy_events.append({
                "schema": "angerona/target-event/v2",
                "target_sha256": row["target_sha256"],
                "state": (
                    "ownership-excluded-third-party"
                    if disposition == EXCLUDE_THIRD_PARTY else "ownership-hold"
                ),
                "ownership_disposition": disposition,
                "ownership_row_sha256": hashlib.sha256(_canonical(row)).hexdigest(),
            })
    if (
        document.get("app_owned_queue") != expected_queue
        or document.get("app_owned_queue_count") != len(expected_queue)
        or document.get("app_owned_queue_sha256") != hashlib.sha256(_canonical(expected_queue)).hexdigest()
    ):
        raise ValueError("native app-owned queue mismatch")
    range_queue = document.get("analysis_range_queue")
    if (
        not isinstance(range_queue, dict)
        or range_queue.get("schema") != RANGE_QUEUE_SCHEMA
        or not verify_document(range_queue, require_signature=True)
        or range_queue.get("policy_sha256") != policy_sha
        or range_queue.get("target_universe_sha256") != universe.get("target_universe_sha256")
        or range_queue.get("rows") != expected_queue
        or range_queue.get("row_count") != len(expected_queue)
        or range_queue.get("rows_sha256") != hashlib.sha256(_canonical(expected_queue)).hexdigest()
        or range_queue.get("partition_rows") != [{
            "target_sha256": row["target_sha256"],
            "partition_sha256": row["partition_sha256"],
            "partition_counts": row["partition_counts"],
            "native_launch_authority_token": row["native_launch_authority_token"],
        } for row in expected_queue]
        or range_queue.get("partition_set_sha256") != document.get("partition_set_sha256")
        or document.get("analysis_range_queue_sha256")
        != hashlib.sha256(_canonical(range_queue)).hexdigest()
    ):
        raise ValueError("native signed analysis-range queue mismatch")
    expected_counts = dict(sorted(
        {name: sum(row["disposition"] == name for row in rows)
         for name in {ANALYZE_APP, ANALYZE_MODIFIED, EXCLUDE_THIRD_PARTY, HOLD}}.items()
    ))
    if document.get("disposition_counts") != expected_counts:
        raise ValueError("native ownership disposition counts mismatch")
    selected = []
    for queue_row in expected_queue:
        record = dict(record_by_sha[queue_row["target_sha256"]])
        record["ownership_disposition"] = queue_row["disposition"]
        record["ownership_row_sha256"] = queue_row["ownership_row_sha256"]
        record["analysis_scope"] = queue_row["analysis_scope"]
        record["allowed_executable_ranges"] = queue_row["allowed_executable_ranges"]
        record["excluded_library_ranges"] = queue_row["excluded_library_ranges"]
        record["ambiguous_executable_ranges"] = queue_row["ambiguous_executable_ranges"]
        record["executable_partition"] = queue_row["executable_partition"]
        record["partition_sha256"] = queue_row["partition_sha256"]
        record["partition_counts"] = queue_row["partition_counts"]
        record["range_authority_sha256"] = queue_row["range_authority_sha256"]
        record["native_launch_authority_token"] = queue_row["native_launch_authority_token"]
        validate_launch_authority(record)
        selected.append(record)
    return document, selected, policy_events


def verify_native_ownership_manifest(path: Path, *, universe_path: Path) -> dict[str, Any]:
    document, selected, policy_events = load_native_ownership_manifest(
        path, universe_path=universe_path,
    )
    return {
        "payload_sha256": document.get("payload_sha256"),
        "signature_key_id": document.get("signature_key_id"),
        "target_count": document.get("target_count"),
        "app_owned_queue_count": len(selected),
        "policy_terminal_count": len(policy_events),
        "disposition_counts": document.get("disposition_counts"),
    }


ROUTING_BINDING_SCHEMA = "angerona/native-ownership-routing-binding/v1"
ROUTED_OUTPUT_SCHEMA = "angerona/native-routed-output/v1"
LANE_RECEIPT_SCHEMA = "angerona/native-lane-completion-receipt/v1"


def native_routing_context(
    ownership_path: str | Path, universe_path: str | Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    ownership_file = Path(ownership_path).expanduser().absolute()
    universe_file = Path(universe_path).expanduser().absolute()
    document, selected, policy_events = load_native_ownership_manifest(
        ownership_file, universe_path=universe_file,
    )
    binding = {
        "schema": ROUTING_BINDING_SCHEMA,
        "ownership_manifest_path": str(ownership_file.resolve(strict=True)),
        "ownership_manifest_file_sha256": _sha256_path(ownership_file),
        "ownership_manifest_payload_sha256": document.get("payload_sha256"),
        "ownership_policy_sha256": document.get("policy_sha256"),
        "ownership_rows_sha256": document.get("rows_sha256"),
        "app_owned_queue_sha256": document.get("app_owned_queue_sha256"),
        "app_owned_queue_count": document.get("app_owned_queue_count"),
        "analysis_range_queue_sha256": document.get("analysis_range_queue_sha256"),
        "analysis_range_queue_payload_sha256": (
            document.get("analysis_range_queue") or {}
        ).get("payload_sha256"),
        "partition_set_sha256": document.get("partition_set_sha256"),
        "partition_rows": document.get("partition_rows"),
        "universe_file_sha256": document.get("universe_file_sha256"),
        "universe_payload_sha256": document.get("universe_payload_sha256"),
        "target_universe_sha256": document.get("target_universe_sha256"),
    }
    return document, selected, policy_events, binding


def native_routing_targets(
    selected: list[dict[str, Any]], policy_events: list[dict[str, Any]],
) -> tuple[set[str], set[str], set[str]]:
    app = {str(row["target_sha256"]) for row in selected}
    excluded = {
        str(row["target_sha256"]) for row in policy_events
        if row.get("state") == "ownership-excluded-third-party"
    }
    hold = {
        str(row["target_sha256"]) for row in policy_events
        if row.get("state") == "ownership-hold"
    }
    if app.intersection(excluded | hold) or excluded.intersection(hold):
        raise ValueError("native routing target dispositions overlap")
    return app, excluded, hold


def bind_native_output_directory(
    output_dir: str | Path, *, lane: str, lane_epoch_id: str,
    routing_binding: dict[str, Any],
) -> Path:
    if not lane or not lane_epoch_id:
        raise ValueError("native lane and lane_epoch_id are required")
    output = Path(output_dir).expanduser().absolute()
    if os.path.lexists(output):
        metadata = output.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("native routed output must be a non-symlink directory")
    else:
        output.mkdir(parents=True, exist_ok=False)
    marker_path = output / "NATIVE_ROUTED_OUTPUT.json"
    expected = {
        "schema": ROUTED_OUTPUT_SCHEMA,
        "lane": lane,
        "lane_epoch_id": lane_epoch_id,
        "routing": routing_binding,
    }
    if marker_path.is_file() and not marker_path.is_symlink():
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if not verify_document(marker, require_signature=True):
            raise ValueError("native routed output marker is not operator-signed")
        if any(marker.get(key) != value for key, value in expected.items()):
            raise ValueError("native routed output belongs to another routing/epoch")
        return output
    if any(output.iterdir()):
        raise ValueError("legacy/unbound native output is superseded-read-only; use a fresh directory")
    marker = sign_document(expected)
    if marker.get("trust") != "operator_signed":
        raise ValueError("native routed output marker requires operator signing")
    _atomic_json(marker_path, marker, immutable=True)
    return output


def publish_native_lane_receipt(
    output_path: str | Path, *, lane: str, lane_epoch_id: str,
    routing_binding: dict[str, Any], expected_app_targets: set[str],
    processed_targets: set[str], excluded_targets: set[str], hold_targets: set[str],
    semantic_complete: bool, input_bindings: list[dict[str, Any]],
    counts: dict[str, Any],
) -> dict[str, Any]:
    destination = Path(output_path).expanduser().absolute()
    previous_sha = ""
    previous_sequence = 0
    previous_archive = ""
    if os.path.lexists(destination):
        metadata = destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("native lane receipt latest must be a non-symlink regular file")
        previous_bytes = destination.read_bytes()
        previous = json.loads(previous_bytes)
        if not verify_document(previous, require_signature=True):
            raise ValueError("previous native lane receipt is invalid")
        if (
            previous.get("lane") != lane
            or previous.get("lane_epoch_id") != lane_epoch_id
            or previous.get("routing") != routing_binding
        ):
            raise ValueError("native lane receipt chain identity mismatch")
        cursor = previous
        cursor_sequence = require_int_field(
            cursor, "sequence", context="native lane receipt", minimum=1, maximum=100000,
        )
        while cursor_sequence > 1:
            relative = str(cursor.get("previous_receipt_archive") or "")
            expected_previous_sha = str(cursor.get("previous_receipt_sha256") or "")
            archived = (destination.parent / relative).absolute()
            try:
                archived.resolve(strict=True).relative_to(destination.parent.resolve())
            except (OSError, ValueError) as exc:
                raise ValueError("native lane receipt archive escapes history root") from exc
            archived_metadata = archived.lstat()
            if stat.S_ISLNK(archived_metadata.st_mode) or not stat.S_ISREG(archived_metadata.st_mode):
                raise ValueError("native lane receipt archive is not a regular file")
            archived_bytes = archived.read_bytes()
            if hashlib.sha256(archived_bytes).hexdigest() != expected_previous_sha:
                raise ValueError("native lane receipt backward hash mismatch")
            archived_document = json.loads(archived_bytes)
            if (
                not verify_document(archived_document, require_signature=True)
                or archived_document.get("lane") != lane
                or archived_document.get("lane_epoch_id") != lane_epoch_id
                or archived_document.get("routing") != routing_binding
                or require_int_field(
                    archived_document, "sequence",
                    context="archived native lane receipt", minimum=1, maximum=100000,
                ) != cursor_sequence - 1
            ):
                raise ValueError("native lane receipt backward chain mismatch")
            cursor = archived_document
            cursor_sequence -= 1
        if cursor.get("previous_receipt_sha256") or cursor.get("previous_receipt_archive"):
            raise ValueError("native lane receipt genesis is not empty")
        previous_sha = hashlib.sha256(previous_bytes).hexdigest()
        previous_sequence = require_int_field(
            previous, "sequence", context="previous native lane receipt",
            minimum=1, maximum=100000,
        )
        archive = destination.parent / "lane-receipt-history" / lane / f"{previous_sequence:08d}-{previous_sha}.json"
        if os.path.lexists(archive):
            archived_metadata = archive.lstat()
            if stat.S_ISLNK(archived_metadata.st_mode) or not stat.S_ISREG(archived_metadata.st_mode):
                raise ValueError("native lane receipt archive collision")
            if _sha256_path(archive) != previous_sha:
                raise ValueError("native lane receipt archive hash collision")
        else:
            archive.parent.mkdir(parents=True, exist_ok=True)
            temporary = archive.with_name(f".{archive.name}.{os.getpid()}.tmp")
            with temporary.open("xb") as handle:
                handle.write(previous_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, archive)
            temporary.unlink(missing_ok=True)
        previous_archive = archive.relative_to(destination.parent).as_posix()
    expected = sorted(expected_app_targets)
    processed = sorted(processed_targets)
    lane_complete = bool(
        semantic_complete and not hold_targets and processed == expected
    )
    receipt = sign_document({
        "schema": LANE_RECEIPT_SCHEMA,
        "lane": lane,
        "lane_epoch_id": lane_epoch_id,
        "sequence": previous_sequence + 1,
        "previous_receipt_sha256": previous_sha,
        "previous_receipt_archive": previous_archive,
        "routing": routing_binding,
        "expected_app_owned_target_sha256": expected,
        "expected_app_owned_target_count": len(expected),
        "processed_app_owned_target_sha256": processed,
        "processed_app_owned_target_count": len(processed),
        "excluded_target_sha256": sorted(excluded_targets),
        "hold_target_sha256": sorted(hold_targets),
        "input_bindings": input_bindings,
        "counts": counts,
        "semantic_complete": bool(semantic_complete),
        "lane_complete": lane_complete,
        "global_completion_claimed": False,
    })
    if receipt.get("trust") != "operator_signed":
        raise ValueError("native lane receipt requires operator signing")
    _atomic_json(destination, receipt)
    return receipt
