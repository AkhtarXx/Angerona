"""Permanent fail-closed native classification before reverse engineering.

This module is intentionally limited to ELF metadata.  It never imports or
starts IDA, Ghidra, a disassembler, or a decompiler.  Decisions are signed and
become launch authority only after native_ownership_manifest validates them.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable
import zipfile

from .evidence_signing import sign_document, verify_document
from .native_target_universe import load_native_target_universe
from .native_structural_signatures import extract_structural_signatures


FEATURE_SCHEMA = "angerona/native-pre-re-features/v4"
CATALOG_SCHEMA = "angerona/native-reference-catalog/v4"
PROVENANCE_SCHEMA = "angerona/native-package-provenance/v1"
ADVISORY_SCHEMA = "angerona/native-metadata-ai-advisory/v1"
CLASSIFICATION_SCHEMA = "angerona/native-pre-re-classification/v4"
CONFIRMED_THIRD_PARTY = "CONFIRMED_THIRD_PARTY_SKIP"
CONFIRMED_APP_OWNED = "CONFIRMED_APP_OWNED_ANALYZE"
MODIFIED_VENDOR_REVIEW = "MODIFIED_VENDOR_REVIEW"
HOLD_UNKNOWN = "HOLD_UNKNOWN"
DECISIONS = {
    CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED,
    MODIFIED_VENDOR_REVIEW, HOLD_UNKNOWN,
}

_POLICY = {
    "schema": "angerona/native-pre-re-classifier-policy/v4",
    "exact_authenticated_bytes_authorize": [
        CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED,
    ],
    "robust_similarity_authorizes": [],
    "whole_binary_skip_requires_exact_authenticated_artifact_bytes": True,
    "function_skip_requires_exact_raw_bytes_or_unique_significant_structure": True,
    "robust_similarity_min_score": 0.90,
    "robust_similarity_min_independent_signals": 4,
    "dynamic_symbol_minimum": 20,
    "dynamic_symbol_jaccard_minimum": 0.98,
    "function_symbol_minimum": 10,
    "function_symbol_jaccard_minimum": 0.95,
    "relocation_jaccard_minimum": 0.95,
    "needed_jaccard_minimum": 0.80,
    "negative_extra_jni_is_modified": True,
    "negative_app_namespace_is_not_third_party": True,
    "cross_abi_family_conservation_required": True,
    "filename_alone_never_classifies": True,
    "soname_alone_never_classifies": True,
    "ai_advisory_never_authorizes_skip_or_app_ownership": True,
    "package_license_notice_is_supporting_signal_only": True,
    "whole_binary_robust_skip_requires_complete_executable_range_conservation": False,
    "mixed_binary_matched_ranges_are_skip_candidates_only": True,
    "mixed_binary_unmatched_ranges_require_analysis_or_operator_review": True,
    "offline_cfg_bsim_bindiff_evidence_must_be_authenticated": True,
    "target_side_normal_re_projects_forbidden": True,
    "bounded_normalized_cfg_and_function_vectors": True,
    "unknown_action": HOLD_UNKNOWN,
}

_VENDOR_PATTERNS = {
    "META_REACT_NATIVE": re.compile(
        r"facebook|react[-_ /]?native|reactcommon|hermes|folly|\bglog\b|\byoga\b",
        re.I,
    ),
    "SWMANSION": re.compile(r"swmansion|rnscreens|reanimated|worklets", re.I),
    "VISION_CAMERA": re.compile(r"mrousavy|visioncamera", re.I),
    "MMKV": re.compile(r"reactnativemmkv|\bmmkv\b", re.I),
    "VERIDIUM": re.compile(r"veridium", re.I),
    "ANDROID_NDK_LLVM": re.compile(r"llvm-project|libcxxabi", re.I),
    "CRYPTOPP": re.compile(r"crypto\+\+|cryptopp", re.I),
    "FRESCO": re.compile(r"fresco|imagepipeline|imagetranscoder", re.I),
}


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: str | Path, label: str) -> Path:
    supplied = Path(path).expanduser().absolute()
    metadata = supplied.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    return supplied.resolve(strict=True)


def _atomic_json(path: Path, value: Any, *, immutable: bool = True) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable and os.path.lexists(path):
        raise ValueError(f"immutable classifier output already exists: {path}")
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


def _signed_document(path: Path, schema: str, label: str) -> tuple[Path, dict[str, Any]]:
    supplied = _regular(path, label)
    document = json.loads(supplied.read_text(encoding="utf-8"))
    if document.get("schema") != schema or not verify_document(document, require_signature=True):
        raise ValueError(f"{label} signature/schema verification failed")
    return supplied, document


def _tool_identity(name: str) -> dict[str, Any]:
    executable = shutil.which(name)
    if not executable:
        raise ValueError(f"required PRE-RE metadata tool is unavailable: {name}")
    path = _regular(Path(executable).resolve(), f"PRE-RE tool {name}")
    result = subprocess.run(
        [str(path), "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=10, check=False,
    )
    return {
        "name": name, "path": str(path), "sha256": _sha_path(path),
        "version_sha256": _sha_bytes(result.stdout.encode()),
        "version_excerpt": result.stdout.splitlines()[:3],
    }


def toolchain_identity() -> dict[str, Any]:
    rows = [_tool_identity(name) for name in ("readelf", "nm", "strings", "objdump")]
    return {
        "schema": "angerona/native-pre-re-toolchain/v1",
        "tools": rows,
        "identity_sha256": _sha_bytes(_canonical(rows)),
    }


def classifier_identity(toolchain: dict[str, Any]) -> str:
    source = _regular(Path(__file__), "PRE-RE classifier source")
    return _sha_bytes(_canonical({
        "policy": _POLICY,
        "source_sha256": _sha_path(source),
        "toolchain_identity_sha256": toolchain["identity_sha256"],
    }))


def _run(toolchain: dict[str, Any], name: str, args: list[str], path: Path) -> str:
    tool = next(row for row in toolchain["tools"] if row["name"] == name)
    result = subprocess.run(
        [tool["path"], *args, str(path)], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=30, check=False,
    )
    if result.returncode not in {0, 1}:
        raise ValueError(f"{name} metadata extraction failed: {result.returncode}")
    return result.stdout


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    a, b = set(left), set(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _bounded(values: Iterable[str], limit: int = 50_000) -> list[str]:
    result = sorted({str(value) for value in values if str(value)})
    if len(result) > limit:
        raise ValueError("PRE-RE metadata set exceeds deterministic bound")
    return result


def _symbol_records(value: str) -> list[dict[str, Any]]:
    records: dict[tuple[str, int, int, str, str, str, str], dict[str, Any]] = {}
    for line in value.splitlines():
        match = re.match(
            r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$",
            line,
        )
        if not match:
            continue
        address, size, symbol_type, binding, visibility, section, raw_name = match.groups()
        name = raw_name.split("@", 1)[0].strip()
        if not name or section == "UND":
            continue
        key = (name, int(address, 16), int(size), symbol_type, binding, visibility, section)
        records[key] = {
            "name": name, "address": int(address, 16), "size": int(size),
            "type": symbol_type, "binding": binding, "visibility": visibility,
            "section": section,
        }
    if len(records) > 50_000:
        raise ValueError("PRE-RE symbol record set exceeds deterministic bound")
    return [records[key] for key in sorted(records)]


def _covered_bytes(ranges: Iterable[dict[str, Any]], sections: Iterable[dict[str, Any]]) -> int:
    intervals = []
    executable = [(int(row["address"]), int(row["address"]) + int(row["size"])) for row in sections]
    for row in ranges:
        start, end = int(row["address"]), int(row["address"]) + int(row["size"])
        for section_start, section_end in executable:
            clipped_start, clipped_end = max(start, section_start), min(end, section_end)
            if clipped_end > clipped_start:
                intervals.append((clipped_start, clipped_end))
    total = 0
    end = -1
    for start, stop in sorted(intervals):
        if stop <= end:
            continue
        total += stop - max(start, end)
        end = stop
    return total


def _range_routing(
    target: dict[str, Any], reference: dict[str, Any], *, exact_bytes: bool = False,
) -> dict[str, Any]:
    target_functions = target.get("function_records") or []
    from .native_range_authority import derive_partition

    reference_rows = reference.get("function_records") or []
    reference_structural = {
        (str(row.get("normalized_cfg_sha256") or ""), str(row.get("function_vector_sha256") or ""))
        for row in reference.get("function_records") or []
        if row.get("normalized_cfg_sha256") and row.get("function_vector_sha256")
    }
    target_raw_counts = Counter(str(row.get("raw_function_sha256") or "") for row in target_functions)
    reference_raw_counts = Counter(str(row.get("raw_function_sha256") or "") for row in reference_rows)
    target_structural_counts = Counter(
        (str(row.get("normalized_cfg_sha256") or ""), str(row.get("function_vector_sha256") or ""))
        for row in target_functions
    )
    reference_structural_counts = Counter(
        (str(row.get("normalized_cfg_sha256") or ""), str(row.get("function_vector_sha256") or ""))
        for row in reference_rows
    )
    reference_by_raw = {str(row.get("raw_function_sha256") or ""): row for row in reference_rows}
    reference_by_structural = {
        (str(row.get("normalized_cfg_sha256") or ""), str(row.get("function_vector_sha256") or "")): row
        for row in reference_rows
    }

    def match_basis(row: dict[str, Any]) -> tuple[str | None, list[str]]:
        raw_sha = str(row.get("raw_function_sha256") or "")
        signature = (
            str(row.get("normalized_cfg_sha256") or ""),
            str(row.get("function_vector_sha256") or ""),
        )
        negative: list[str] = []
        if raw_sha and raw_sha in reference_by_raw:
            peer = reference_by_raw[raw_sha]
            if (
                target_raw_counts[raw_sha] == 1 and reference_raw_counts[raw_sha] == 1
                and int(peer.get("raw_function_bytes") or 0) == int(row.get("raw_function_bytes") or 0)
            ):
                return "exact-function-raw-bytes", negative
            negative.append("raw-function-digest-is-not-unique")
        peer = reference_by_structural.get(signature)
        if peer is not None:
            significant = (
                int(row.get("instruction_count") or 0) >= 16
                and int(row.get("basic_block_count") or 0) >= 3
                and int(row.get("size") or 0) >= 48
                and int(peer.get("instruction_count") or 0) == int(row.get("instruction_count") or 0)
                and int(peer.get("basic_block_count") or 0) == int(row.get("basic_block_count") or 0)
                and int(peer.get("callsite_count") or 0) == int(row.get("callsite_count") or 0)
                and target_structural_counts[signature] == 1
                and reference_structural_counts[signature] == 1
            )
            if significant:
                return "unique-significant-authenticated-structural", negative
            negative.append("structural-signature-small-common-or-colliding")
        return None, negative or ["no-exclusion-grade-function-evidence"]

    decisions = [(row, *match_basis(row)) for row in target_functions if int(row.get("size") or 0) > 0]
    raw_matched = [
        {
            **row, "route": "SKIP_MATCHED_LIBRARY_FUNCTION",
            "match_basis": basis,
            "collision_negative_evidence": negative,
        }
        for row, basis, negative in decisions if basis is not None
    ]
    raw_unmatched = [
        {**row, "route": "ANALYZE_UNMATCHED_OR_CUSTOM_FUNCTION", "negative_evidence": negative}
        for row, basis, negative in decisions if basis is None
    ]
    executable_sections = target.get("executable_sections") or []

    def clip_to_executable(
        rows: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        clipped: list[dict[str, Any]] = []
        outside = 0
        for row in rows:
            source_address = int(row.get("address") or 0)
            source_size = int(row.get("size") or 0)
            source_end = source_address + source_size
            fragments = []
            for section in executable_sections:
                section_start = int(section.get("address") or 0)
                section_end = section_start + int(section.get("size") or 0)
                start, end = max(source_address, section_start), min(source_end, section_end)
                if end > start:
                    fragments.append((start, end))
            if not fragments:
                outside += 1
                continue
            for index, (start, end) in enumerate(fragments):
                clipped.append({
                    **row,
                    "source_function_address": source_address,
                    "source_function_size": source_size,
                    "address": start,
                    "size": end - start,
                    "clipped_to_executable": (
                        start != source_address or end != source_end or len(fragments) != 1
                    ),
                    "executable_fragment_index": index,
                    "executable_fragment_count": len(fragments),
                })
        return clipped, outside

    matched, matched_outside = clip_to_executable(raw_matched)
    unmatched, unmatched_outside = clip_to_executable(raw_unmatched)
    executable_bytes = sum(int(row.get("size") or 0) for row in executable_sections)
    known_bytes = _covered_bytes(target_functions, executable_sections)
    matched_bytes = _covered_bytes(matched, executable_sections)
    unmatched_bytes = _covered_bytes(unmatched, executable_sections)
    unattributed_bytes = max(0, executable_bytes - known_bytes)
    if exact_bytes:
        # Exact whole-artifact identity is the only whole-skip authority. App-build
        # routing replaces this with an all-allowed partition at ownership time.
        partition = derive_partition(executable_sections, [], executable_sections)
    else:
        partition = derive_partition(executable_sections, unmatched, matched)
    complete = bool(exact_bytes)
    return {
        "schema": "angerona/native-function-range-routing/v2",
        "proof": "exact-authenticated-whole-elf-bytes" if exact_bytes else "lightweight-symbol-range-conservation",
        "whole_binary_skip_eligible": complete,
        "whole_binary_skip_requires_exact_bytes": True,
        "executable_bytes": executable_bytes,
        "known_function_bytes": known_bytes,
        "matched_function_bytes": matched_bytes,
        "unmatched_function_bytes": unmatched_bytes,
        "unattributed_executable_bytes": unattributed_bytes,
        "matched_function_records_outside_executable": matched_outside,
        "unmatched_function_records_outside_executable": unmatched_outside,
        "executable_ranges": executable_sections,
        "executable_partition": partition,
        "matched_library_function_ranges": matched,
        "unmatched_or_custom_function_ranges": unmatched,
        "offline_deep_similarity": {
            "accepted_if_authenticated": [
                "normalized-cfg-callgraph-basic-block-function-attributes",
                "ghidra-bsim-style-function-vectors",
            ],
            "present": False,
        },
    }


def extract_features(path: Path, toolchain: dict[str, Any]) -> dict[str, Any]:
    path = _regular(path, "PRE-RE ELF target")
    data = path.read_bytes()
    if not data.startswith(b"\x7fELF"):
        raise ValueError("PRE-RE target is not ELF")
    header = _run(toolchain, "readelf", ["-h", "--wide"], path)
    dynamic = _run(toolchain, "readelf", ["-d", "--wide"], path)
    notes = _run(toolchain, "readelf", ["-n"], path)
    symbols_text = _run(toolchain, "readelf", ["--dyn-syms", "--wide"], path)
    all_symbols_text = _run(toolchain, "readelf", ["--syms", "--wide"], path)
    relocations_text = _run(toolchain, "readelf", ["-r", "--wide"], path)
    sections_text = _run(toolchain, "readelf", ["-S", "--wide"], path)
    strings_text = _run(toolchain, "strings", ["-a", "-n", "8"], path)
    machine = (re.findall(r"^\s*Machine:\s*(.+)$", header, re.M) or [""])[0].strip()
    elf_class = (re.findall(r"^\s*Class:\s*(.+)$", header, re.M) or [""])[0].strip()
    needed = _bounded(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    soname = (re.findall(r"\(SONAME\).*?\[(.*?)\]", dynamic) or [""])[0]
    build_ids = _bounded(re.findall(r"Build ID:\s*([0-9a-fA-F]+)", notes))
    defined: list[str] = []
    functions: list[str] = []
    jni: list[str] = []
    dynamic_records = _symbol_records(symbols_text)
    function_records = [
        row for row in _symbol_records(all_symbols_text)
        if row["type"] == "FUNC" and row["size"] > 0
    ]
    objdump = next(row for row in toolchain["tools"] if row["name"] == "objdump")
    structural = extract_structural_signatures(path, function_records, Path(objdump["path"]))
    structural_by_address = {int(row["address"]): row for row in structural["rows"]}
    function_records = [
        {**row, **{
            key: value for key, value in structural_by_address.get(int(row["address"]), {}).items()
            if key not in {"name", "address", "size"}
        }}
        for row in function_records
    ]
    for row in dynamic_records:
        name, symbol_type = row["name"], row["type"]
        defined.append(name)
        if symbol_type == "FUNC":
            functions.append(name)
        if name == "JNI_OnLoad" or name.startswith("Java_") or "RegisterNatives" in name:
            jni.append(name)
    relocation_symbols: list[str] = []
    for line in relocations_text.splitlines():
        match = re.search(r"\b([_A-Za-z][A-Za-z0-9_.$@]*)\s*(?:\+\s*[-0-9a-fx]+)?$", line)
        if match and not match.group(1).startswith(("R_", ".")):
            relocation_symbols.append(match.group(1).split("@", 1)[0])
    section_shapes = []
    executable_sections = []
    for line in sections_text.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+\S+\s+(\S*)",
            line,
        )
        if match:
            name, section_type, address, size, flags = match.groups()
            section_shapes.append(f"{name}:{section_type}:{int(size, 16)}:{flags}")
            if "X" in flags and int(size, 16) > 0:
                executable_sections.append({
                    "name": name, "address": int(address, 16), "size": int(size, 16),
                })
    selected_strings = []
    license_notice_strings = []
    package_strings = []
    source_paths = []
    for value in strings_text.splitlines():
        if len(value) > 512:
            continue
        if re.search(r"(?:^|[; /(])(?:com|org|io|android|java)/[A-Za-z0-9_$/]{3,}", value):
            package_strings.append(value)
        if re.search(r"(?:^|[/\\])[A-Za-z0-9_.+@-]+\.(?:c|cc|cpp|cxx|h|hpp)(?::\d+)?$", value):
            source_paths.append(value)
        if any(pattern.search(value) for pattern in _VENDOR_PATTERNS.values()) or re.search(
            r"(?i)(clang version|android ndk|copyright|licensed under)", value,
        ):
            selected_strings.append(value)
        if re.search(r"(?i)(copyright|licensed under|apache license|bsd license|mit license|gpl|lgpl)", value):
            license_notice_strings.append(value)
    vendor_signals = {}
    searchable = _bounded([*defined, *jni, *package_strings, *source_paths, *selected_strings])
    for identity, pattern in _VENDOR_PATTERNS.items():
        matches = [value for value in searchable if pattern.search(value)]
        if matches:
            vendor_signals[identity] = matches[:32]
    features = {
        "schema": FEATURE_SCHEMA,
        "target_sha256": _sha_bytes(data), "bytes": len(data),
        "elf_class": elf_class, "machine": machine, "soname": soname,
        "build_ids": build_ids, "needed": needed,
        "defined_dynamic_symbols": _bounded(defined),
        "function_symbols": _bounded(functions),
        "function_records": function_records,
        "bounded_structural_signatures": structural,
        "relocation_symbols": _bounded(relocation_symbols),
        "section_shapes": _bounded(section_shapes),
        "executable_sections": executable_sections,
        "jni_exports": _bounded(jni),
        "package_strings": _bounded(package_strings, 10_000),
        "source_paths": _bounded(source_paths, 10_000),
        "build_metadata_strings": _bounded(selected_strings, 50_000),
        "license_notice_strings": _bounded(license_notice_strings, 10_000),
        "vendor_lineage_signals": vendor_signals,
        "toolchain_identity_sha256": toolchain["identity_sha256"],
    }
    for field in (
        "needed", "defined_dynamic_symbols", "function_symbols", "function_records",
        "relocation_symbols", "section_shapes", "executable_sections", "jni_exports",
        "package_strings", "source_paths", "license_notice_strings",
    ):
        features[f"{field}_sha256"] = _sha_bytes(_canonical(features[field]))
    features["feature_fingerprint_sha256"] = _sha_bytes(_canonical(features))
    return features


def _provenance_descriptor(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    supplied, document = _signed_document(path, PROVENANCE_SCHEMA, "native package provenance")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("native package provenance has no authenticated artifacts")
    return document, {
        "path": str(supplied), "sha256": _sha_path(supplied),
        "payload_sha256": document.get("payload_sha256"),
        "signature_key_id": document.get("signature_key_id"),
    }


def _archive_elfs(path: Path) -> Iterable[tuple[str, bytes]]:
    data = path.read_bytes()
    if data.startswith(b"\x7fELF"):
        yield path.name, data
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir() or info.flag_bits & 0x1 or info.file_size > 1024 * 1024 * 1024:
                    continue
                payload = archive.read(info)
                if payload.startswith(b"\x7fELF"):
                    yield info.filename, payload
        return
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.size > 1024 * 1024 * 1024:
                    continue
                handle = archive.extractfile(member)
                payload = handle.read() if handle is not None else b""
                if payload.startswith(b"\x7fELF"):
                    yield member.name, payload
        return
    if path.suffix.lower() == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != "angerona/native-reference-sbom/v1":
            return
        for row in document.get("native_artifacts") or []:
            digest = str(row.get("sha256") or "").lower()
            if len(digest) == 64:
                yield f"sbom:{digest}", b""


def build_reference_catalog(
    *, inputs: list[Path], provenance_path: Path, output_path: Path,
) -> dict[str, Any]:
    provenance, provenance_descriptor = _provenance_descriptor(provenance_path)
    source_kind = str(provenance.get("source_kind") or "")
    if source_kind not in {"third_party", "app_build"}:
        raise ValueError("native package provenance source_kind is invalid")
    for field in ("package_name", "version", "publisher", "package_format"):
        if not provenance.get(field):
            raise ValueError(f"native package provenance lacks {field}")
    if provenance["package_format"] not in {
        "maven-aar", "npm-native-package", "vendor-sdk-archive",
        "sbom-lockfile", "app-build-output",
    }:
        raise ValueError("native package provenance package_format is invalid")
    if source_kind == "app_build" and not provenance.get("source_revision"):
        raise ValueError("app-build provenance lacks its authoritative source revision")
    expected = {
        (str(row.get("sha256") or ""), int(row.get("bytes") or -1))
        for row in provenance["artifacts"] if isinstance(row, dict)
    }
    toolchain = toolchain_identity()
    records = []
    source_descriptors = []
    for raw in inputs:
        path = _regular(raw, "native catalog input")
        descriptor = {"path": str(path), "sha256": _sha_path(path), "bytes": path.stat().st_size}
        if (descriptor["sha256"], descriptor["bytes"]) not in expected:
            raise ValueError("native catalog input is not authenticated by provenance")
        source_descriptors.append(descriptor)
        for member_name, payload in _archive_elfs(path):
            if payload:
                with tempfile.NamedTemporaryFile(prefix="angerona-pre-re-", suffix=".so") as handle:
                    handle.write(payload); handle.flush()
                    features = extract_features(Path(handle.name), toolchain)
                artifact_sha = _sha_bytes(payload)
            else:
                artifact_sha = member_name.split(":", 1)[-1]
                features = None
            records.append({
                "source_kind": source_kind,
                "package_name": provenance["package_name"],
                "version": provenance["version"],
                "publisher": provenance["publisher"],
                "package_format": provenance["package_format"],
                "source_revision": provenance.get("source_revision"),
                "archive_sha256": descriptor["sha256"],
                "archive_member": member_name,
                "artifact_sha256": artifact_sha,
                "features": features,
            })
    records.sort(key=lambda row: (row["artifact_sha256"], row["archive_sha256"], row["archive_member"]))
    body = {
        "schema": CATALOG_SCHEMA,
        "feature_schema": FEATURE_SCHEMA,
        "feature_policy_sha256": _sha_bytes(_canonical(_POLICY)),
        "toolchain": toolchain,
        "provenance": provenance_descriptor,
        "provenance_document": provenance,
        "sources": source_descriptors,
        "record_count": len(records),
        "records_sha256": _sha_bytes(_canonical(records)),
        "records": records,
        "trust_roles": {
            "provenance_key_id": provenance.get("signature_key_id"),
            "catalog_key_id": None,
            "roles_separated": True,
        },
    }
    document = sign_document(body)
    if document.get("trust") != "operator_signed":
        raise ValueError("native reference catalog requires operator signing")
    if document.get("signature_key_id") == provenance.get("signature_key_id"):
        raise ValueError("catalog and package provenance must use separated signing roles")
    document["trust_roles"]["catalog_key_id"] = document.get("signature_key_id")
    # The role binding is inside the signature, so sign once more after filling it.
    document = sign_document({key: value for key, value in document.items() if key not in {
        "payload_sha256", "signature", "signature_key_id", "trust",
    }})
    _atomic_json(output_path, document)
    return document


def load_reference_catalog(path: Path) -> tuple[Path, dict[str, Any]]:
    supplied, document = _signed_document(path, CATALOG_SCHEMA, "native reference catalog")
    records = document.get("records")
    if not isinstance(records, list) or document.get("record_count") != len(records):
        raise ValueError("native reference catalog count mismatch")
    if document.get("records_sha256") != _sha_bytes(_canonical(records)):
        raise ValueError("native reference catalog record hash mismatch")
    provenance = document.get("provenance_document") or {}
    if not verify_document(provenance, require_signature=True) or provenance.get("schema") != PROVENANCE_SCHEMA:
        raise ValueError("native reference catalog provenance is invalid")
    roles = document.get("trust_roles") or {}
    if (
        roles.get("provenance_key_id") != provenance.get("signature_key_id")
        or roles.get("catalog_key_id") != document.get("signature_key_id")
        or roles.get("roles_separated") is not True
        or roles.get("provenance_key_id") == roles.get("catalog_key_id")
    ):
        raise ValueError("native reference catalog trust roles are not separated")
    if (
        document.get("feature_schema") != FEATURE_SCHEMA
        or document.get("feature_policy_sha256") != _sha_bytes(_canonical(_POLICY))
        or document.get("toolchain") != toolchain_identity()
    ):
        raise ValueError("native reference catalog feature/toolchain identity mismatch")
    provenance_path, reproduced_provenance = _provenance_descriptor(
        Path(str((document.get("provenance") or {}).get("path") or "")),
    )
    if reproduced_provenance != document.get("provenance") or provenance_path != provenance:
        raise ValueError("native reference catalog provenance source changed")
    sources = document.get("sources") or []
    if not isinstance(sources, list) or len(sources) != len({row.get("path") for row in sources}):
        raise ValueError("native reference catalog source list is duplicate or malformed")
    expected_sources = {
        (str(row.get("sha256") or ""), int(row.get("bytes") or -1))
        for row in provenance.get("artifacts") or [] if isinstance(row, dict)
    }
    actual_sources = set()
    reproduced_records = []
    toolchain = document["toolchain"]
    for descriptor in sources:
        source = _regular(descriptor.get("path"), "native catalog source")
        actual = {"path": str(source), "sha256": _sha_path(source), "bytes": source.stat().st_size}
        if actual != descriptor:
            raise ValueError("native reference catalog source path/hash/size changed")
        actual_sources.add((actual["sha256"], actual["bytes"]))
        for member_name, payload in _archive_elfs(source):
            if payload:
                with tempfile.NamedTemporaryFile(prefix="angerona-pre-re-", suffix=".so") as handle:
                    handle.write(payload); handle.flush()
                    features = extract_features(Path(handle.name), toolchain)
                artifact_sha = _sha_bytes(payload)
            else:
                artifact_sha, features = member_name.split(":", 1)[-1], None
            reproduced_records.append({
                "source_kind": provenance["source_kind"],
                "package_name": provenance["package_name"],
                "version": provenance["version"],
                "publisher": provenance["publisher"],
                "package_format": provenance["package_format"],
                "source_revision": provenance.get("source_revision"),
                "archive_sha256": actual["sha256"],
                "archive_member": member_name,
                "artifact_sha256": artifact_sha,
                "features": features,
            })
    if actual_sources != expected_sources:
        raise ValueError("native reference catalog omits or adds provenance artifacts")
    reproduced_records.sort(key=lambda row: (row["artifact_sha256"], row["archive_sha256"], row["archive_member"]))
    keys = [(row["artifact_sha256"], row["archive_sha256"], row["archive_member"]) for row in reproduced_records]
    if len(keys) != len(set(keys)) or len({row["artifact_sha256"] for row in reproduced_records}) != len(reproduced_records):
        raise ValueError("native reference catalog contains duplicate or ambiguous artifact membership")
    if reproduced_records != records:
        raise ValueError("native reference catalog record-to-source reproduction mismatch")
    return supplied, document


def _similarity(target: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    if not reference or target.get("soname") != reference.get("soname"):
        return {"score": 0.0, "signals": [], "negative_evidence": ["soname-mismatch"]}
    dyn = _jaccard(target["defined_dynamic_symbols"], reference["defined_dynamic_symbols"])
    funcs = _jaccard(target["function_symbols"], reference["function_symbols"])
    structural = _jaccard(
        [row.get("normalized_cfg_sha256") for row in target.get("function_records") or []
         if row.get("normalized_cfg_sha256")],
        [row.get("normalized_cfg_sha256") for row in reference.get("function_records") or []
         if row.get("normalized_cfg_sha256")],
    )
    relocs = _jaccard(target["relocation_symbols"], reference["relocation_symbols"])
    needed = _jaccard(target["needed"], reference["needed"])
    sections = _jaccard(target["section_shapes"], reference["section_shapes"])
    licenses = _jaccard(
        target.get("license_notice_strings") or [], reference.get("license_notice_strings") or [],
    )
    signals = [{"name": "soname", "value": 1.0, "weight": 0.05}]
    if len(target["defined_dynamic_symbols"]) >= _POLICY["dynamic_symbol_minimum"] and dyn >= _POLICY["dynamic_symbol_jaccard_minimum"]:
        signals.append({"name": "dynamic-symbols", "value": dyn, "weight": 0.25})
    if len(target["function_symbols"]) >= _POLICY["function_symbol_minimum"] and funcs >= _POLICY["function_symbol_jaccard_minimum"]:
        signals.append({"name": "function-symbols", "value": funcs, "weight": 0.15})
    if structural >= 0.95 and target.get("bounded_structural_signatures", {}).get("complete"):
        signals.append({"name": "normalized-cfg-function-vectors", "value": structural, "weight": 0.10})
    if target["relocation_symbols"] and relocs >= _POLICY["relocation_jaccard_minimum"]:
        signals.append({"name": "relocations", "value": relocs, "weight": 0.15})
    if needed >= _POLICY["needed_jaccard_minimum"]:
        signals.append({"name": "dependencies", "value": needed, "weight": 0.10})
    if sections >= 0.80:
        signals.append({"name": "section-shape", "value": sections, "weight": 0.05})
    target_vendor = set(target.get("vendor_lineage_signals") or {})
    reference_vendor = set(reference.get("vendor_lineage_signals") or {})
    if target_vendor & reference_vendor:
        signals.append({"name": "vendor-lineage", "value": 1.0, "weight": 0.10})
    if target.get("build_ids") and set(target["build_ids"]) & set(reference.get("build_ids") or []):
        signals.append({"name": "build-id", "value": 1.0, "weight": 0.05})
    negative = []
    extra_jni = sorted(set(target["jni_exports"]) - set(reference.get("jni_exports") or []))
    if extra_jni:
        negative.append("target-has-reference-absent-jni-exports")
    extra_functions = set(target["function_symbols"]) - set(reference.get("function_symbols") or [])
    if len(extra_functions) > max(5, int(len(target["function_symbols"]) * 0.02)):
        negative.append("target-has-material-extra-functions")
    score = sum(row["value"] * row["weight"] for row in signals)
    range_routing = _range_routing(target, reference)
    if not range_routing["whole_binary_skip_eligible"]:
        negative.append("executable-range-conservation-incomplete")
    return {
        "score": round(score, 6), "signals": signals,
        "negative_evidence": negative, "extra_jni_sample": extra_jni[:16],
        "jaccard": {"dynamic_symbols": dyn, "functions": funcs, "relocations": relocs,
                    "needed": needed, "sections": sections, "license_notices": licenses,
                    "normalized_cfg": structural},
        "supporting_signals": ([{"name": "package-license-notice", "value": licenses}]
                               if licenses >= 0.80 and target.get("license_notice_strings") else []),
        "range_routing": range_routing,
    }


def _load_advisory(path: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None:
        return {}, {"present": False, "schema": ADVISORY_SCHEMA}
    supplied, document = _signed_document(path, ADVISORY_SCHEMA, "native metadata AI advisory")
    return document, {
        "present": True, "schema": ADVISORY_SCHEMA, "path": str(supplied),
        "sha256": _sha_path(supplied), "payload_sha256": document.get("payload_sha256"),
    }


def _checkpoint(
    *, target: Path, target_sha: str, classifier_id: str, toolchain: dict[str, Any],
    catalog_identity: str, cache_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    cache_identity = _sha_bytes(_canonical({
        "classifier_identity_sha256": classifier_id,
        "catalog_identity_sha256": catalog_identity,
    }))
    cache = cache_root / target_sha / f"{cache_identity}.json"
    if cache.exists():
        supplied, document = _signed_document(cache, FEATURE_SCHEMA, "PRE-RE feature checkpoint")
        if (
            document.get("target_sha256") != target_sha
            or document.get("classifier_identity_sha256") != classifier_id
            or document.get("catalog_identity_sha256") != catalog_identity
            or document.get("cache_identity_sha256") != cache_identity
            or document.get("features", {}).get("target_sha256") != target_sha
        ):
            raise ValueError("PRE-RE feature checkpoint binding mismatch")
        return document["features"], {
            "path": str(supplied), "sha256": _sha_path(supplied),
            "payload_sha256": document.get("payload_sha256"),
        }
    features = extract_features(target, toolchain)
    if features["target_sha256"] != target_sha:
        raise ValueError("PRE-RE extracted target SHA mismatch")
    document = sign_document({
        "schema": FEATURE_SCHEMA, "target_sha256": target_sha,
        "classifier_identity_sha256": classifier_id,
        "catalog_identity_sha256": catalog_identity,
        "cache_identity_sha256": cache_identity,
        "toolchain": toolchain, "features": features,
    })
    if document.get("trust") != "operator_signed":
        raise ValueError("PRE-RE checkpoint requires operator signing")
    _atomic_json(cache, document)
    return features, {
        "path": str(cache.resolve()), "sha256": _sha_path(cache),
        "payload_sha256": document.get("payload_sha256"),
    }


def build_pre_re_classification(
    *, universe_path: Path, output_path: Path, cache_root: Path,
    catalog_paths: list[Path] | None = None, ai_advisory_path: Path | None = None,
    app_namespaces: list[str] | None = None,
) -> dict[str, Any]:
    universe, records = load_native_target_universe(universe_path)
    toolchain = toolchain_identity()
    identity = classifier_identity(toolchain)
    catalogs = [load_reference_catalog(path) for path in (catalog_paths or [])]
    catalog_descriptors = [{
        "path": str(path), "sha256": _sha_path(path),
        "payload_sha256": document.get("payload_sha256"),
        "records_sha256": document.get("records_sha256"),
    } for path, document in catalogs]
    catalog_identity = _sha_bytes(_canonical(catalog_descriptors))
    advisory, advisory_descriptor = _load_advisory(ai_advisory_path)
    advisory_rows = {
        str(row.get("target_sha256") or ""): row
        for row in advisory.get("rows") or [] if isinstance(row, dict)
    }
    exact_third: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exact_app: dict[str, list[dict[str, Any]]] = defaultdict(list)
    third_features = []
    for catalog_path, catalog in catalogs:
        source = (catalog.get("provenance_document") or {}).get("source_kind")
        for row in catalog["records"]:
            bound = {**row, "catalog_path": str(catalog_path),
                     "catalog_payload_sha256": catalog.get("payload_sha256")}
            if source == "third_party":
                exact_third[row["artifact_sha256"]].append(bound)
                if row.get("features"):
                    third_features.append(bound)
            elif source == "app_build":
                exact_app[row["artifact_sha256"]].append(bound)
    app_namespace_values = sorted({str(value) for value in (app_namespaces or []) if str(value)})
    app_tokens = [value.lower().replace(".", "/") for value in app_namespace_values]
    adjudication_identity = _sha_bytes(_canonical({
        "classifier_identity_sha256": identity,
        "catalog_identity_sha256": catalog_identity,
        "app_namespaces": app_namespace_values,
        "ai_advisory": advisory_descriptor,
    }))
    rows = []
    feature_by_sha = {}
    for record in records:
        target_sha = record["target_sha256"]
        target = record.get("target")
        if target is None:
            raise ValueError(f"PRE-RE classifier target is missing: {target_sha}")
        features, checkpoint = _checkpoint(
            target=target, target_sha=target_sha, classifier_id=identity,
            toolchain=toolchain, catalog_identity=catalog_identity, cache_root=cache_root,
        )
        feature_by_sha[target_sha] = features
        app_matches = exact_app.get(target_sha, [])
        third_matches = exact_third.get(target_sha, [])
        decision, tier, reason = HOLD_UNKNOWN, "none", "no authenticated provenance match"
        matched_reference = None
        range_routing = None
        comparisons = []
        negative = []
        if app_matches and third_matches:
            negative.append("conflicting-exact-app-and-third-party-provenance")
        elif len(app_matches) == 1:
            decision, tier, reason = (
                CONFIRMED_APP_OWNED, "exact-authenticated-app-build-bytes",
                "exact target SHA is present in signed app-build provenance",
            )
            matched_reference = app_matches[0]
            range_routing = _range_routing(
                features, app_matches[0].get("features") or features, exact_bytes=True,
            )
        elif len(third_matches) == 1:
            decision, tier, reason = (
                CONFIRMED_THIRD_PARTY, "exact-authenticated-upstream-bytes",
                "exact target SHA is present in signed third-party package provenance",
            )
            matched_reference = third_matches[0]
            range_routing = _range_routing(
                features, third_matches[0].get("features") or features, exact_bytes=True,
            )
        elif not app_matches and not third_matches:
            for candidate in third_features:
                comparison = _similarity(features, candidate["features"])
                if comparison["score"] >= 0.70:
                    comparisons.append({
                        "reference": {key: candidate.get(key) for key in (
                            "source_kind", "package_name", "version", "publisher", "artifact_sha256",
                            "catalog_path", "catalog_payload_sha256", "archive_member",
                        )},
                        **comparison,
                    })
            comparisons.sort(key=lambda row: (-row["score"], row["reference"]["artifact_sha256"]))
            best = comparisons[0] if comparisons else None
            target_text = "\n".join([
                *features.get("jni_exports", []), *features.get("package_strings", []),
                *features.get("source_paths", []),
            ]).lower().replace(".", "/")
            app_negative = any(token and token in target_text for token in app_tokens)
            if best and (
                best["score"] >= _POLICY["robust_similarity_min_score"]
                and len(best["signals"]) >= _POLICY["robust_similarity_min_independent_signals"]
                and not best["negative_evidence"] and not app_negative and bool(app_tokens)
            ):
                decision, tier, reason = (
                    MODIFIED_VENDOR_REVIEW, "authenticated-package-lineage-review-only",
                    "signed package reference identifies lineage but cannot authorize whole-binary exclusion",
                )
                matched_reference = best["reference"]
                range_routing = best["range_routing"]
            elif best or features.get("vendor_lineage_signals"):
                decision, tier, reason = (
                    MODIFIED_VENDOR_REVIEW, "vendor-lineage-or-modification-risk",
                    "vendor lineage exists but exact provenance or robust no-modification proof is incomplete",
                )
                if best:
                    negative.extend(best["negative_evidence"])
                    matched_reference = best["reference"]
                    range_routing = best["range_routing"]
        advisory_row = advisory_rows.get(target_sha)
        if advisory_row is not None:
            if advisory_row.get("feature_fingerprint_sha256") != features["feature_fingerprint_sha256"]:
                raise ValueError("native AI advisory feature binding mismatch")
            opinion = advisory_row.get("opinion")
            if decision == HOLD_UNKNOWN and opinion == MODIFIED_VENDOR_REVIEW:
                decision, tier, reason = (
                    MODIFIED_VENDOR_REVIEW, "metadata-ai-advisory-review-only",
                    "signed AI metadata advisory escalates to human review; it grants no launch or exclusion authority",
                )
        rows.append({
            "target_sha256": target_sha,
            "apk_path": record["universe_member"].get("apk_path"),
            "abis": record["universe_member"].get("abis") or [],
            "decision": decision, "evidence_tier": tier, "reason": reason,
            "matched_reference": matched_reference,
            "range_routing": range_routing,
            "similarity_candidates": comparisons[:5],
            "negative_evidence": sorted(set(negative)),
            "vendor_lineage_signals": features.get("vendor_lineage_signals") or {},
            "feature_fingerprint_sha256": features["feature_fingerprint_sha256"],
            "feature_checkpoint": checkpoint,
            "ai_advisory": advisory_row,
        })
    # Cross-ABI conservation is based on SONAME and signed universe membership,
    # never on a filename ownership guess.
    row_by_sha = {row["target_sha256"]: row for row in rows}
    families: dict[str, list[str]] = defaultdict(list)
    for target_sha, features in feature_by_sha.items():
        families[features.get("soname") or f"sha:{target_sha}"].append(target_sha)
    family_rows = []
    for soname, members in sorted(families.items()):
        members = sorted(members)
        decisions = {row_by_sha[digest]["decision"] for digest in members}
        confirmed_references = {
            (
                (row_by_sha[digest].get("matched_reference") or {}).get("source_kind"),
                (row_by_sha[digest].get("matched_reference") or {}).get("package_name"),
                (row_by_sha[digest].get("matched_reference") or {}).get("version"),
                (row_by_sha[digest].get("matched_reference") or {}).get("publisher"),
            )
            for digest in members
            if row_by_sha[digest]["decision"] in {CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED}
        }
        family_mismatch = (
            len(decisions) != 1
            or len(confirmed_references) != 1
            or next(iter(decisions), HOLD_UNKNOWN) not in {
                CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED,
            }
        )
        if len(members) > 1 and decisions.intersection({CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED}) and family_mismatch:
            for digest in members:
                row = row_by_sha[digest]
                if row["decision"] in {CONFIRMED_THIRD_PARTY, CONFIRMED_APP_OWNED}:
                    row["decision"] = MODIFIED_VENDOR_REVIEW
                    row["evidence_tier"] = "cross-abi-family-incomplete"
                    row["reason"] = "cross-ABI family lacks conserved authoritative decisions"
                    row["negative_evidence"] = sorted(set([
                        *row["negative_evidence"], "cross-abi-family-decision-mismatch",
                    ]))
        family_rows.append({
            "soname": soname, "target_sha256": members,
            "decisions": sorted({row_by_sha[digest]["decision"] for digest in members}),
        })
    rows.sort(key=lambda row: row["target_sha256"])
    counts = dict(sorted(Counter(row["decision"] for row in rows).items()))
    body = {
        "schema": CLASSIFICATION_SCHEMA,
        "classifier_policy": _POLICY,
        "classifier_policy_sha256": _sha_bytes(_canonical(_POLICY)),
        "classifier_identity_sha256": identity,
        "adjudication_identity_sha256": adjudication_identity,
        "catalog_identity_sha256": catalog_identity,
        "catalogs": catalog_descriptors,
        "ai_advisory": advisory_descriptor,
        "app_namespaces": app_namespace_values,
        "app_namespace_set_sha256": _sha_bytes(_canonical(app_namespace_values)),
        "toolchain": toolchain,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        "target_count": len(rows),
        "rows_sha256": _sha_bytes(_canonical(rows)),
        "rows": rows,
        "family_count": len(family_rows),
        "families_sha256": _sha_bytes(_canonical(family_rows)),
        "families": family_rows,
        "decision_counts": counts,
        "pre_re_only": True,
        "reverse_engine_contacted": False,
    }
    document = sign_document(body)
    if document.get("trust") != "operator_signed":
        raise ValueError("PRE-RE classification requires operator signing")
    _atomic_json(output_path, document)
    return document


def load_pre_re_classification(
    path: Path, *, universe_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    supplied, document = _signed_document(path, CLASSIFICATION_SCHEMA, "PRE-RE classification")
    universe, _records = load_native_target_universe(universe_path)
    if (
        document.get("classifier_policy") != _POLICY
        or document.get("classifier_policy_sha256") != _sha_bytes(_canonical(_POLICY))
        or document.get("universe_file_sha256") != _sha_path(universe_path.resolve())
        or document.get("universe_payload_sha256") != universe.get("payload_sha256")
        or document.get("target_universe_sha256") != universe.get("target_universe_sha256")
        or document.get("pre_re_only") is not True
        or document.get("reverse_engine_contacted") is not False
    ):
        raise ValueError("PRE-RE classification policy/universe binding mismatch")
    app_namespaces = document.get("app_namespaces") or []
    if (
        not isinstance(app_namespaces, list)
        or app_namespaces != sorted(set(app_namespaces))
        or document.get("app_namespace_set_sha256") != _sha_bytes(_canonical(app_namespaces))
        or document.get("adjudication_identity_sha256") != _sha_bytes(_canonical({
            "classifier_identity_sha256": document.get("classifier_identity_sha256"),
            "catalog_identity_sha256": document.get("catalog_identity_sha256"),
            "app_namespaces": app_namespaces,
            "ai_advisory": document.get("ai_advisory"),
        }))
    ):
        raise ValueError("PRE-RE adjudication input identity mismatch")
    toolchain = document.get("toolchain") or {}
    tools = toolchain.get("tools") or []
    if not isinstance(tools, list) or _sha_bytes(_canonical(tools)) != toolchain.get("identity_sha256"):
        raise ValueError("PRE-RE classifier toolchain identity is invalid")
    for tool in tools:
        tool_path = _regular(tool.get("path"), "PRE-RE classifier tool")
        if _sha_path(tool_path) != tool.get("sha256"):
            raise ValueError("PRE-RE classifier tool changed after classification")
    if document.get("classifier_identity_sha256") != classifier_identity(toolchain):
        raise ValueError("PRE-RE classifier source/tool identity changed")
    catalog_descriptors = document.get("catalogs") or []
    if document.get("catalog_identity_sha256") != _sha_bytes(_canonical(catalog_descriptors)):
        raise ValueError("PRE-RE catalog-set identity mismatch")
    exact_catalog_references: set[bytes] = set()
    robust_catalog_references: set[bytes] = set()
    exact_reference_rows: dict[bytes, dict[str, Any]] = {}
    robust_reference_rows: dict[bytes, dict[str, Any]] = {}
    for descriptor in catalog_descriptors:
        catalog_path, catalog = load_reference_catalog(Path(str(descriptor.get("path") or "")))
        if (
            _sha_path(catalog_path) != descriptor.get("sha256")
            or catalog.get("payload_sha256") != descriptor.get("payload_sha256")
            or catalog.get("records_sha256") != descriptor.get("records_sha256")
        ):
            raise ValueError("PRE-RE reference catalog binding mismatch")
        for record in catalog.get("records") or []:
            bound = {
                **record, "catalog_path": str(catalog_path),
                "catalog_payload_sha256": catalog.get("payload_sha256"),
            }
            exact_catalog_references.add(_canonical(bound))
            exact_reference_rows[_canonical(bound)] = bound
            robust_descriptor = {key: bound.get(key) for key in (
                "source_kind", "package_name", "version", "publisher", "artifact_sha256",
                "catalog_path", "catalog_payload_sha256", "archive_member",
            )}
            robust_catalog_references.add(_canonical(robust_descriptor))
            robust_reference_rows[_canonical(robust_descriptor)] = bound
    rows = document.get("rows")
    if not isinstance(rows, list) or document.get("target_count") != len(rows):
        raise ValueError("PRE-RE classification target count mismatch")
    if document.get("rows_sha256") != _sha_bytes(_canonical(rows)):
        raise ValueError("PRE-RE classification row hash mismatch")
    expected = sorted(str(row["target_sha256"]) for row in universe.get("targets") or [])
    actual = [str(row.get("target_sha256") or "") for row in rows if isinstance(row, dict)]
    if actual != expected or any(row.get("decision") not in DECISIONS for row in rows):
        raise ValueError("PRE-RE classification target conservation/decision mismatch")
    counts = dict(sorted(Counter(row["decision"] for row in rows).items()))
    if document.get("decision_counts") != counts:
        raise ValueError("PRE-RE classification decision count mismatch")
    for row in rows:
        checkpoint = row.get("feature_checkpoint") or {}
        checkpoint_path = _regular(checkpoint.get("path"), "PRE-RE feature checkpoint")
        if _sha_path(checkpoint_path) != checkpoint.get("sha256"):
            raise ValueError("PRE-RE feature checkpoint file hash mismatch")
        feature_document = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if (
            not verify_document(feature_document, require_signature=True)
            or feature_document.get("schema") != FEATURE_SCHEMA
            or feature_document.get("target_sha256") != row["target_sha256"]
            or feature_document.get("features", {}).get("feature_fingerprint_sha256")
            != row.get("feature_fingerprint_sha256")
        ):
            raise ValueError("PRE-RE feature checkpoint binding is invalid")
        features = feature_document["features"]
        tier = row.get("evidence_tier")
        reference = row.get("matched_reference")
        bound_reference = None
        exact_bytes = tier in {
            "exact-authenticated-upstream-bytes", "exact-authenticated-app-build-bytes",
        } or bool(
            isinstance(reference, dict)
            and reference.get("artifact_sha256") == row.get("target_sha256")
            and reference.get("source_kind") in {"third_party", "app_build"}
        )
        if reference:
            bound_reference = (
                exact_reference_rows.get(_canonical(reference))
                or robust_reference_rows.get(_canonical(reference))
            )
            if bound_reference is None:
                raise ValueError("PRE-RE range routing references an unbound catalog record")
            expected_routing = _range_routing(
                features, bound_reference.get("features") or features, exact_bytes=exact_bytes,
            )
            if row.get("range_routing") != expected_routing:
                raise ValueError("PRE-RE function-range routing does not reproduce")
        elif row.get("range_routing") is not None:
            raise ValueError("PRE-RE function-range routing lacks a catalog reference")
        if row["decision"] == CONFIRMED_THIRD_PARTY and tier != "exact-authenticated-upstream-bytes":
            raise ValueError("third-party skip lacks admissible PRE-RE evidence tier")
        if row["decision"] == CONFIRMED_THIRD_PARTY:
            reference = row.get("matched_reference") or {}
            if tier == "exact-authenticated-upstream-bytes" and (
                reference.get("artifact_sha256") != row["target_sha256"]
                or reference.get("source_kind") != "third_party"
                or _canonical(reference) not in exact_catalog_references
            ):
                raise ValueError("exact third-party decision lacks byte-identical catalog evidence")
        if tier in {"vendor-lineage-or-modification-risk", "authenticated-package-lineage-review-only"} and reference:
            candidates = row.get("similarity_candidates") or []
            expected_candidate = {
                "reference": reference,
                **_similarity(features, (bound_reference or {}).get("features") or {}),
            }
            if not candidates or candidates[0] != expected_candidate:
                raise ValueError("mixed/vendor range evidence does not reproduce")
        if row["decision"] == CONFIRMED_APP_OWNED and tier != "exact-authenticated-app-build-bytes":
            raise ValueError("app-owned analysis lacks exact build provenance")
        if row["decision"] == CONFIRMED_APP_OWNED:
            reference = row.get("matched_reference") or {}
            if (
                reference.get("artifact_sha256") != row["target_sha256"]
                or reference.get("source_kind") != "app_build"
                or not reference.get("source_revision")
                or _canonical(reference) not in exact_catalog_references
            ):
                raise ValueError("app-owned decision lacks byte-identical build catalog evidence")
    return document, rows


def verify_pre_re_classification(path: Path, *, universe_path: Path) -> dict[str, Any]:
    document, rows = load_pre_re_classification(path, universe_path=universe_path)
    return {
        "payload_sha256": document.get("payload_sha256"),
        "signature_key_id": document.get("signature_key_id"),
        "classifier_identity_sha256": document.get("classifier_identity_sha256"),
        "adjudication_identity_sha256": document.get("adjudication_identity_sha256"),
        "catalog_identity_sha256": document.get("catalog_identity_sha256"),
        "target_count": len(rows), "decision_counts": document.get("decision_counts"),
    }
