#!/usr/bin/env python3
"""Build the fixture, run real engines sequentially, and score their evidence.

There is deliberately no default wall-clock timeout.  Engine-level safety caps
can still be requested by other callers, but this quality benchmark lets each
selected engine finish naturally.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from src.analysis.library_signatures import library_classification_report
from src.analysis.library_signatures import quick_library_mark
from src.analysis.sink_hunter import SinkHunter
from src.analysis.xref_graph import XrefGraph
from src.config import load_config
from src.engines import make_engine
from src.models.analysis_graph import AnalysisGraph
from src.models.cpp_recovery import CppRecoveryAgent
from src.models.type_recovery import TypeRecoveryAgent


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"
SOURCE = HERE / "fixture.cpp"
ORACLE = HERE / "oracle.json"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)


def build_fixture() -> dict[str, Path]:
    BUILD.mkdir(parents=True, exist_ok=True)
    binary = BUILD / "complex_fixture"
    stripped = BUILD / "complex_fixture.stripped"
    _run([
        "g++", "-std=c++20", "-O2", "-g", "-fno-omit-frame-pointer",
        "-fno-builtin", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
        "-fPIE", "-pie", "-Wl,-z,relro,-z,now", str(SOURCE), "-o", str(binary),
    ])
    shutil.copy2(binary, stripped)
    _run(["strip", "--strip-all", str(stripped)])
    return {"full": binary, "stripped": stripped}


def inspect_security(binary: Path) -> dict[str, Any]:
    output = _run(["readelf", "-W", "-h", "-l", "-d", "-s", str(binary)]).stdout
    stack_line = next((line for line in output.splitlines() if "GNU_STACK" in line), "")
    return {
        "pie": "Type:" in output and "DYN" in output.split("Type:", 1)[1].splitlines()[0],
        "nx": bool(stack_line) and "RWE" not in stack_line and " E " not in f" {stack_line} ",
        "relro": "full" if "GNU_RELRO" in output and ("BIND_NOW" in output or "FLAGS" in output and " NOW" in output) else "partial",
        "stack_canary": "__stack_chk_fail" in output,
    }


def _corpus(items: list[dict], fields: tuple[str, ...]) -> str:
    values: list[str] = []
    for item in items:
        for field in fields:
            value = item.get(field)
            if value is not None:
                values.append(str(value))
    return "\n".join(values).lower()


def _token_results(tokens: list[str], corpus: str) -> dict[str, bool]:
    normalized = corpus.lower()
    return {token: token.lower() in normalized for token in tokens}


def evaluate_export(data: dict, oracle: dict, *, stripped: bool) -> dict[str, Any]:
    functions = list(data.get("functions") or [])
    strings = list(data.get("strings") or [])
    imports = list(data.get("imports") or [])
    classifications = library_classification_report(functions)
    role_by_entry = {
        (row.get("entry"), row.get("name")): str(row["role"])
        for row in classifications
    }
    user_functions = [
        fn for fn in functions
        if role_by_entry.get(
            (fn.get("entry"), str(fn.get("name") or fn.get("entry") or "unknown")),
            "user_primary",
        ) != "library"
    ]
    user_fragments = [
        fn for fn in functions
        if role_by_entry.get(
            (fn.get("entry"), str(fn.get("name") or fn.get("entry") or "unknown")),
            "user_primary",
        ) == "user_fragment"
    ]
    logical_user_functions = [
        fn for fn in functions
        if role_by_entry.get(
            (fn.get("entry"), str(fn.get("name") or fn.get("entry") or "unknown")),
            "user_primary",
        ) == "user_primary"
    ]
    decompiled_user = [
        fn for fn in user_functions
        if str(fn.get("decompiled") or "").strip()
        and "decompile failed" not in str(fn.get("decompiled") or "").lower()
    ]
    decompiled_logical_user = [
        fn for fn in logical_user_functions
        if str(fn.get("decompiled") or "").strip()
        and "decompile failed" not in str(fn.get("decompiled") or "").lower()
    ]
    auto_prefixes = ("fun_", "sub_", "nullsub_", "loc_", "case")
    auto_named_logical_user = [
        fn for fn in logical_user_functions
        if str(fn.get("name") or "").lower().startswith(auto_prefixes)
    ]

    string_hits = _token_results(
        oracle["expected_strings"],
        _corpus(strings, ("value", "string", "name")),
    )
    import_hits = _token_results(
        oracle["expected_import_tokens"],
        _corpus(imports, ("name", "symbol", "library")),
    )
    function_hits = _token_results(
        oracle["expected_function_tokens"],
        _corpus(functions, ("name", "signature", "namespace", "decompiled")),
    )
    sink_corpus = "\n".join((
        _corpus(functions, ("name", "signature", "decompiled", "callees")),
        _corpus(imports, ("name", "symbol")),
    ))
    sink_hits = _token_results(oracle["expected_sink_tokens"], sink_corpus)

    minimums = oracle["minimums"]
    required: dict[str, bool] = {
        "minimum_functions": len(functions) >= minimums["functions"],
        "minimum_strings": len(strings) >= minimums["strings"],
        "minimum_imports": len(imports) >= minimums["imports"],
        "minimum_decompiled_user_functions": (
            len(decompiled_logical_user) >= minimums["decompiled_functions"]
        ),
        "all_expected_strings": all(string_hits.values()),
        "all_expected_imports": all(import_hits.values()),
    }
    if "strcpy" in sink_hits:
        required["unsafe_import_sink_found"] = sink_hits["strcpy"]
    # Stripping intentionally removes user symbols.  Penalizing an engine for
    # not guessing their original source names would reward fabrication.
    if not stripped:
        required["all_expected_function_names"] = all(function_hits.values())
        required["all_expected_sinks"] = all(sink_hits.values())

    metadata = data.get("metadata") or {}
    emitted = metadata.get("emitted_function_count")
    metadata_consistent = emitted is None or int(emitted) == len(functions)
    reason_counts = Counter(row["reason"] for row in classifications)
    return {
        "passed": all(required.values()),
        "score": round(sum(required.values()) / max(1, len(required)), 4),
        "required": required,
        "counts": {
            "functions_emitted": len(functions),
            "functions_user_or_unknown": len(user_functions),
            "functions_user_logical": len(logical_user_functions),
            "functions_user_fragments": len(user_fragments),
            "functions_primary_named": (
                len(logical_user_functions) - len(auto_named_logical_user)
            ),
            "functions_auto_named_or_fragments": (
                len(auto_named_logical_user) + len(user_fragments)
            ),
            "functions_library_or_thunk": len(functions) - len(user_functions),
            "decompiled_user_functions": len(decompiled_user),
            "decompiled_logical_user_functions": len(decompiled_logical_user),
            "strings": len(strings),
            "imports": len(imports),
        },
        "coverage": {
            "user_decompile_ratio": round(len(decompiled_user) / max(1, len(user_functions)), 4),
            "logical_user_decompile_ratio": round(
                len(decompiled_logical_user) / max(1, len(logical_user_functions)),
                4,
            ),
            "metadata_emitted_count_consistent": metadata_consistent,
        },
        "expected": {
            "strings": string_hits,
            "imports": import_hits,
            "functions": function_hits,
            "sinks": sink_hits,
        },
        "library_classification_reasons": dict(sorted(reason_counts.items())),
    }


def evaluate_pipeline(data: dict, oracle: dict, *, stripped: bool) -> dict[str, Any]:
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    try:
        image_base = int(str((data.get("metadata") or {}).get("image_base") or "0"), 16)
    except (TypeError, ValueError):
        image_base = 0
    program_roles = {}
    for node in graph.nodes:
        role = str(node.properties.get("semantic_role") or "")
        if role not in {"process_entry", "program_main"} or not node.address:
            continue
        try:
            offset = int(str(node.address), 16) - image_base
        except (KeyError, TypeError, ValueError):
            continue
        program_roles[role] = {
            "node_id": node.id,
            "name": node.name,
            "address": node.address,
            "image_offset": offset,
            "evidence": node.properties.get("semantic_role_evidence") or {},
        }
    marks = quick_library_mark(list(data.get("functions") or []))
    xref = XrefGraph(graph, library_marks=marks)
    sink_report = SinkHunter(xref).run(max_depth=16)
    signatures = TypeRecoveryAgent(graph).recover_signatures()
    structures = TypeRecoveryAgent(graph).recover_structures(max_structs=200)
    cpp_agent = CppRecoveryAgent(graph)
    classes = cpp_agent.build_hierarchy()
    recovered_class_rows = []
    for recovered in classes.values():
        row = recovered.as_dict()
        offsets = []
        for address in row.get("vtables") or []:
            try:
                offsets.append(int(str(address), 16) - image_base)
            except (TypeError, ValueError):
                continue
        row["vtable_image_offsets"] = sorted(set(offsets))
        recovered_class_rows.append(row)
    recovered_class_rows.sort(key=lambda row: str(row["class_name"]))
    user_class_rows = [
        row for row in recovered_class_rows
        if row["role"] == "user_candidate"
    ]
    runtime_class_rows = [
        row for row in recovered_class_rows
        if row["role"] == "runtime_support"
    ]
    library_class_rows = [
        row for row in recovered_class_rows
        if row["role"] == "library_support"
    ]
    user_vtable_offsets = {
        int(offset)
        for row in user_class_rows
        for offset in (row.get("vtable_image_offsets") or [])
    }
    user_class_names = {
        str(row["class_name"]) for row in user_class_rows
    }
    user_inheritance_edges = {
        (str(parent), str(row["class_name"]))
        for row in user_class_rows
        for parent in (row.get("parents") or [])
        if str(parent) in user_class_names
    }
    user_vtable_layouts = set()
    for table in cpp_agent.vtables:
        if (
            str(table.class_name or "") not in user_class_names
            or table.address_point is None
            or table.offset_to_top is None
            or table.table_kind not in {"primary", "secondary"}
            or not table.method_slots_validated
            or not table.method_entries
        ):
            continue
        try:
            table_address = int(str(table.address), 16)
            address_point = int(str(table.address_point), 16)
            first_method_target = (
                int(str(table.first_method_target), 16)
                if table.first_method_target is not None else 0
            )
            method_target_offsets = tuple(
                int(str(entry["target_addr"]), 16) - image_base
                for entry in table.method_entries
            )
        except (KeyError, TypeError, ValueError):
            continue
        user_vtable_layouts.add((
            str(table.class_name),
            table_address - image_base,
            address_point - image_base,
            int(table.offset_to_top),
            str(table.table_kind),
            (
                first_method_target - image_base
                if first_method_target > 0 else None
            ),
            len(method_target_offsets),
            method_target_offsets,
            str(table.method_boundary_reason or ""),
        ))
    user_base_layouts = {
        (
            str(row["class_name"]),
            str(base.get("base_class") or ""),
            int(base.get("offset")),
            str(base.get("offset_kind") or ""),
            (
                int(base["object_offset"])
                if base.get("object_offset") is not None else None
            ),
            (
                int(base["vbase_offset_slot_offset"])
                if base.get("vbase_offset_slot_offset") is not None else None
            ),
            int(base.get("flags")),
            bool(base.get("is_virtual")),
            bool(base.get("is_public")),
        )
        for row in user_class_rows
        for base in (
            (row.get("rtti_type_info") or {}).get("bases") or []
        )
        if isinstance(base, dict)
        and str(base.get("base_class") or "") in user_class_names
        and base.get("offset") is not None
        and base.get("flags") is not None
    }
    typeinfo_class_by_address = {}
    for row in user_class_rows:
        typeinfo_address = (
            (row.get("rtti_type_info") or {}).get("typeinfo_address")
        )
        if typeinfo_address is None:
            continue
        try:
            typeinfo_class_by_address[int(str(typeinfo_address), 16)] = str(
                row["class_name"]
            )
        except (TypeError, ValueError):
            continue
    user_vtable_prefix_layouts = set()
    for table in cpp_agent.vtables:
        if (
            str(table.class_name or "") not in user_class_names
            or table.address_point is None
            or table.offset_to_top is None
            or not table.prefix_entries_validated
            or not table.prefix_entries
            or table.prefix_boundary_reason is None
        ):
            continue
        try:
            prefix_entries = tuple(
                (
                    int(entry["relative_to_address_point"]),
                    int(str(entry["pointer_address"]), 16) - image_base,
                    int(entry["value"]),
                    str(entry["entry_kind"]),
                    (
                        typeinfo_class_by_address.get(
                            int(str(entry["base_typeinfo_address"]), 16)
                        )
                        if entry.get("base_typeinfo_address") is not None
                        else None
                    ),
                )
                for entry in table.prefix_entries
            )
        except (KeyError, TypeError, ValueError):
            continue
        user_vtable_prefix_layouts.add((
            str(table.class_name),
            str(table.table_kind),
            int(table.offset_to_top),
            str(table.prefix_boundary_reason),
            prefix_entries,
        ))
    user_vtts = set()
    for row in user_class_rows:
        vtt = (row.get("rtti_type_info") or {}).get("vtt")
        if not isinstance(vtt, dict):
            continue
        try:
            vtt_entries = tuple(
                (
                    int(str(entry["pointer_address"]), 16) - image_base,
                    int(str(entry["address_point_address"]), 16) - image_base,
                    int(str(entry["vtable_address"]), 16) - image_base,
                    int(entry["offset_to_top"]),
                    str(entry["table_kind"]),
                    (
                        typeinfo_class_by_address.get(
                            int(str(entry["typeinfo_address"]), 16)
                        )
                        if entry.get("typeinfo_address") is not None
                        else None
                    ),
                    (
                        str(entry["table_role"])
                        if entry.get("table_role") is not None
                        else None
                    ),
                    (
                        int(entry["leading_null_slot_count"])
                        if entry.get("leading_null_slot_count") is not None
                        else None
                    ),
                )
                for entry in vtt["entries"]
            )
            user_vtts.add((
                str(row["class_name"]),
                int(str(vtt["vtt_address"]), 16) - image_base,
                str(vtt["evidence"]),
                float(vtt["confidence"]),
                vtt_entries,
            ))
        except (KeyError, TypeError, ValueError):
            continue
    user_this_adjustments = set()
    for table in cpp_agent.vtables:
        if (
            str(table.class_name or "") not in user_class_names
            or table.table_kind != "secondary"
            or table.offset_to_top is None
        ):
            continue
        for entry in table.method_entries:
            adjustment = entry.get("this_adjustment")
            if not isinstance(adjustment, dict):
                continue
            try:
                candidate_offsets = tuple(
                    (
                        int(candidate["slot"]),
                        int(candidate["value"]),
                    )
                    for candidate in (
                        adjustment.get("candidate_vcall_offsets") or []
                    )
                )
                user_this_adjustments.add((
                    str(table.class_name),
                    str(table.table_kind),
                    int(table.offset_to_top),
                    int(entry["slot_index"]),
                    int(str(entry["target_addr"]), 16) - image_base,
                    str(adjustment["kind"]),
                    bool(adjustment["resolved"]),
                    (
                        int(adjustment["fixed_delta"])
                        if adjustment.get("fixed_delta") is not None
                        else None
                    ),
                    (
                        int(adjustment["vcall_offset_slot"])
                        if adjustment.get("vcall_offset_slot") is not None
                        else None
                    ),
                    (
                        int(adjustment["vcall_offset_value"])
                        if adjustment.get("vcall_offset_value") is not None
                        else None
                    ),
                    candidate_offsets,
                    str(adjustment["evidence"]),
                    float(adjustment["confidence"]),
                ))
            except (KeyError, TypeError, ValueError):
                continue

    string_nodes = {
        node.id: node
        for node in graph.nodes
        if node.kind == "string"
    }
    user_referenced_strings: dict[str, dict[str, Any]] = {}
    code_string_reference_count = 0
    for edge in graph.edges:
        if not edge.properties.get("string_reference"):
            continue
        code_string_reference_count += 1
        source = graph.get_node(edge.src)
        target = string_nodes.get(edge.dst)
        if source is None or source.kind != "function" or target is None:
            continue
        source_key = str(source.name or source.address or "unknown")
        if marks.get(source_key, False):
            continue
        record = user_referenced_strings.setdefault(
            target.id,
            {
                "node_id": target.id,
                "value": target.name or "",
                "address": target.address,
                "memory_block": target.properties.get("memory_block"),
                "sources": [],
            },
        )
        source_record = {
            "node_id": source.id,
            "name": source.name,
            "address": source.address,
            "xref_address": edge.address,
        }
        if source_record not in record["sources"]:
            record["sources"].append(source_record)
    referenced_string_rows = sorted(
        user_referenced_strings.values(),
        key=lambda row: (str(row["value"]), str(row["address"])),
    )
    referenced_string_corpus = "\n".join(
        str(row["value"]) for row in referenced_string_rows
    )

    sink_rows = [
        row
        for rows in sink_report.get("categories", {}).values()
        for row in rows
    ]
    reachable_names = "\n".join(
        str(row.get("name") or "").lower()
        for row in sink_rows
        if row.get("reachable")
    )
    unsafe_reachable_rows = [
        row for row in sink_rows
        if row.get("reachable")
        and str(row.get("name") or "").lstrip(".").split("@", 1)[0].lower() == "strcpy"
    ]
    unsafe_boundary_paths = [
        row for row in unsafe_reachable_rows
        if int(row.get("source_distance") or 0) >= 1
        and bool((row.get("evidence") or {}).get("reachability_target_is_boundary"))
    ]
    ranked_source_provenance = {
        "metadata_entry_point", "entry_export", "callable_export",
        "caller_supplied",
    }
    unsafe_ranked_paths = [
        row for row in unsafe_boundary_paths
        if str(
            (row.get("evidence") or {}).get("reachability_source_provenance")
            or ""
        ) in ranked_source_provenance
    ]
    source_evidence = list(sink_report.get("source_evidence") or [])
    fallback_sources = [
        row for row in source_evidence
        if row.get("provenance") == "fallback_call_root"
    ]
    ranked_sources = [
        row for row in source_evidence
        if row.get("provenance") in ranked_source_provenance
    ]
    reachable_rows = [row for row in sink_rows if row.get("reachable")]
    semantic_paths_valid = all(
        row.get("semantic_source_distance") is not None
        and row.get("source_distance") is not None
        and 0 <= int(row["semantic_source_distance"]) <= int(row["source_distance"])
        and bool(row.get("semantic_shortest_path"))
        for row in reachable_rows
    )
    ranked_reachable_names = "\n".join(
        str(row.get("name") or "").lower()
        for row in sink_rows
        if row.get("reachable")
        and str(
            (row.get("evidence") or {}).get("reachability_source_provenance")
            or ""
        ) in ranked_source_provenance
    )
    expected_reachable_sinks = oracle.get("expected_reachable_sink_tokens", [])
    reachable_sink_hits = _token_results(
        expected_reachable_sinks, ranked_reachable_names
    )
    class_names = "\n".join(
        str(row["class_name"]) for row in user_class_rows
    ).lower()
    class_hits = _token_results(oracle.get("expected_cpp_class_tokens", []), class_names)
    minimums = oracle["minimums"]
    all_sink_names = "\n".join(str(row.get("name") or "").lower() for row in sink_rows)
    required = {
        "unsafe_sink_found": "strcpy" in all_sink_names,
        "minimum_recovered_signatures": len(signatures) >= minimums["recovered_signatures"],
        "signature_count_not_inflated": len(signatures) <= len(data.get("functions") or []),
        "minimum_recovered_structures": (
            len(structures) >= minimums.get("recovered_structures", 0)
        ),
        "minimum_cpp_classes": (
            len(user_class_rows) >= minimums["cpp_classes"]
        ),
        "expected_cpp_classes": all(class_hits.values()),
    }
    expected_class_names = {
        str(name)
        for name in (oracle.get("expected_cpp_classes") or [])
        if str(name)
    }
    if expected_class_names:
        required["expected_cpp_class_set_recovered"] = (
            user_class_names == expected_class_names
        )
    if "cpp_vtables" in minimums:
        required["minimum_user_cpp_vtables"] = (
            len(user_vtable_offsets) >= int(minimums["cpp_vtables"])
        )
    expected_inheritance = {
        (str(record["parent"]), str(record["child"]))
        for record in (oracle.get("expected_cpp_inheritance") or [])
        if isinstance(record, dict)
        and record.get("parent")
        and record.get("child")
    }
    if expected_inheritance:
        required["expected_cpp_inheritance_recovered"] = (
            expected_inheritance == user_inheritance_edges
        )
    expected_base_layouts = {
        (
            str(record["class"]),
            str(record["base"]),
            int(record["offset"]),
            str(record["offset_kind"]),
            (
                int(record["object_offset"])
                if record.get("object_offset") is not None else None
            ),
            (
                int(record["vbase_offset_slot_offset"])
                if record.get("vbase_offset_slot_offset") is not None else None
            ),
            int(record["flags"]),
            bool(record["is_virtual"]),
            bool(record["is_public"]),
        )
        for record in (oracle.get("expected_cpp_base_layouts") or [])
        if isinstance(record, dict)
        and record.get("class")
        and record.get("base")
        and record.get("offset") is not None
        and record.get("offset_kind") in {
            "object_offset", "vbase_offset_slot"
        }
        and record.get("flags") is not None
    }
    if expected_base_layouts:
        required["expected_cpp_base_layouts_recovered"] = (
            expected_base_layouts == user_base_layouts
        )
    expected_vtable_layouts = {
        (
            str(record["class"]),
            str(record["table_kind"]),
            int(record["offset_to_top"]),
            int(record["method_count"]),
        )
        for record in (oracle.get("expected_cpp_vtable_layouts") or [])
        if isinstance(record, dict)
        and record.get("class")
        and record.get("table_kind") in {"primary", "secondary"}
        and record.get("offset_to_top") is not None
        and record.get("method_count") is not None
    }
    recovered_vtable_layout_identities = {
        (class_name, table_kind, offset_to_top, method_count)
        for (
            class_name,
            _table_offset,
            _address_point_offset,
            offset_to_top,
            table_kind,
            _first_method_offset,
            method_count,
            _method_target_offsets,
            _boundary_reason,
        ) in user_vtable_layouts
    }
    if expected_vtable_layouts:
        required["expected_cpp_vtable_layouts_recovered"] = (
            expected_vtable_layouts == recovered_vtable_layout_identities
        )
    expected_prefix_layouts = {
        (
            str(record["class"]),
            str(record["table_kind"]),
            int(record["offset_to_top"]),
            str(record["prefix_boundary_reason"]),
            tuple(
                (
                    int(entry["relative_to_address_point"]),
                    int(entry["value"]),
                    str(entry["entry_kind"]),
                    (
                        str(entry["base"])
                        if entry.get("base") is not None else None
                    ),
                )
                for entry in record["entries"]
            ),
        )
        for record in (
            oracle.get("expected_cpp_vtable_prefix_layouts") or []
        )
        if isinstance(record, dict)
        and record.get("class")
        and record.get("table_kind") in {"primary", "secondary"}
        and isinstance(record.get("entries"), list)
        and record["entries"]
    }
    recovered_prefix_identities = {
        (
            class_name,
            table_kind,
            offset_to_top,
            boundary_reason,
            tuple(
                (relative, value, entry_kind, base_class)
                for (
                    relative,
                    _pointer_offset,
                    value,
                    entry_kind,
                    base_class,
                ) in entries
            ),
        )
        for (
            class_name,
            table_kind,
            offset_to_top,
            boundary_reason,
            entries,
        ) in user_vtable_prefix_layouts
    }
    if expected_prefix_layouts:
        required["expected_cpp_vtable_prefix_layouts_recovered"] = (
            expected_prefix_layouts == recovered_prefix_identities
        )
    expected_vtts = {
        (
            str(record["class"]),
            tuple(
                (
                    str(entry["table_kind"]),
                    int(entry["offset_to_top"]),
                    (
                        str(entry["typeinfo_class"])
                        if entry.get("typeinfo_class") is not None
                        else None
                    ),
                    (
                        str(entry["table_role"])
                        if entry.get("table_role") is not None
                        else None
                    ),
                    (
                        int(entry["leading_null_slot_count"])
                        if entry.get("leading_null_slot_count") is not None
                        else None
                    ),
                )
                for entry in record["entries"]
            ),
        )
        for record in (oracle.get("expected_cpp_vtts") or [])
        if isinstance(record, dict)
        and record.get("class")
        and isinstance(record.get("entries"), list)
        and len(record["entries"]) >= 2
    }
    recovered_vtt_identities = {
        (
            class_name,
            tuple(
                (
                    table_kind,
                    offset_to_top,
                    typeinfo_class,
                    table_role,
                    leading_null_slot_count,
                )
                for (
                    _pointer_offset,
                    _address_point_offset,
                    _vtable_offset,
                    offset_to_top,
                    table_kind,
                    typeinfo_class,
                    table_role,
                    leading_null_slot_count,
                ) in entries
            ),
        )
        for (
            class_name,
            _vtt_offset,
            _evidence,
            _confidence,
            entries,
        ) in user_vtts
    }
    if expected_vtts:
        required["expected_cpp_vtts_recovered"] = (
            expected_vtts == recovered_vtt_identities
        )
    if "cpp_vtable_prefix_entries" in minimums:
        required["minimum_cpp_vtable_prefix_entries"] = (
            sum(
                len(layout[4]) for layout in user_vtable_prefix_layouts
            )
            >= int(minimums["cpp_vtable_prefix_entries"])
        )
    if "cpp_vtts" in minimums:
        required["minimum_cpp_vtts"] = (
            len(user_vtts) >= int(minimums["cpp_vtts"])
        )
    expected_adjustments = {
        (
            str(record["class"]),
            str(record["table_kind"]),
            int(record["offset_to_top"]),
            int(record["slot_index"]),
        ): record
        for record in (
            oracle.get("expected_cpp_this_adjustments") or []
        )
        if isinstance(record, dict)
        and record.get("class")
        and record.get("table_kind") == "secondary"
        and record.get("offset_to_top") is not None
        and record.get("slot_index") is not None
    }
    recovered_adjustments = {
        (
            class_name,
            table_kind,
            offset_to_top,
            slot_index,
        ): (
            kind,
            resolved,
            fixed_delta,
            vcall_slot,
            vcall_value,
            candidate_offsets,
            evidence,
            confidence,
        )
        for (
            class_name,
            table_kind,
            offset_to_top,
            slot_index,
            _target_offset,
            kind,
            resolved,
            fixed_delta,
            vcall_slot,
            vcall_value,
            candidate_offsets,
            evidence,
            confidence,
        ) in user_this_adjustments
    }
    if expected_adjustments:
        adjustment_keys_exact = (
            expected_adjustments.keys() == recovered_adjustments.keys()
        )
        adjustment_semantics_valid = adjustment_keys_exact
        if adjustment_semantics_valid:
            for key, expected in expected_adjustments.items():
                (
                    kind,
                    resolved,
                    fixed_delta,
                    vcall_slot,
                    vcall_value,
                    candidate_offsets,
                    evidence,
                    confidence,
                ) = recovered_adjustments[key]
                expected_kind = str(expected["kind"])
                if (
                    kind != expected_kind
                    or not evidence
                    or confidence < 0.85
                ):
                    adjustment_semantics_valid = False
                    break
                if expected_kind == "fixed":
                    if (
                        not resolved
                        or fixed_delta != int(expected["fixed_delta"])
                        or vcall_slot is not None
                        or vcall_value is not None
                    ):
                        adjustment_semantics_valid = False
                        break
                    continue
                expected_slot = int(expected["vcall_offset_slot"])
                expected_value = int(expected["vcall_offset_value"])
                expected_fixed = int(expected["fixed_delta"])
                if resolved:
                    valid_virtual = (
                        fixed_delta == expected_fixed
                        and vcall_slot == expected_slot
                        and vcall_value == expected_value
                    )
                else:
                    valid_virtual = (
                        fixed_delta is None
                        and vcall_slot is None
                        and vcall_value is None
                        and (expected_slot, expected_value)
                        in candidate_offsets
                    )
                if not valid_virtual:
                    adjustment_semantics_valid = False
                    break
        required["expected_cpp_this_adjustments_recovered"] = (
            adjustment_semantics_valid
        )
    if "cpp_this_adjustments" in minimums:
        required["minimum_cpp_this_adjustments"] = (
            len(user_this_adjustments)
            >= int(minimums["cpp_this_adjustments"])
        )
    reachability_gate = (
        "unsafe_sink_reachable_from_inferred_entry"
        if stripped
        else "unsafe_exported_sink_reachable"
    )
    required[reachability_gate] = "strcpy" in reachable_names
    required["unsafe_sink_reaches_callable_boundary"] = bool(unsafe_boundary_paths)
    required["unsafe_sink_reaches_ranked_source_boundary"] = (
        bool(unsafe_ranked_paths)
        if ranked_sources else bool(unsafe_boundary_paths)
    )
    required["ranked_sources_do_not_mix_fallback_roots"] = not (
        ranked_sources and fallback_sources
    )
    required["reachable_sink_semantic_paths_valid"] = (
        bool(reachable_rows) and semantic_paths_valid
    )
    expected_program_roles = set(oracle.get("expected_program_roles") or [])
    if expected_program_roles:
        required["expected_program_roles_recovered"] = (
            expected_program_roles <= program_roles.keys()
            and all(
                (program_roles[role].get("evidence") or {}).get("confidence") == 1.0
                for role in expected_program_roles
            )
        )
    expected_referenced_strings = list(
        oracle.get("expected_user_referenced_strings") or []
    )
    referenced_string_hits = _token_results(
        expected_referenced_strings,
        referenced_string_corpus,
    )
    if expected_referenced_strings:
        required["all_expected_strings_referenced_by_user_code"] = all(
            referenced_string_hits.values()
        )
    if expected_reachable_sinks:
        required["all_expected_sinks_reachable_from_ranked_entry"] = all(
            reachable_sink_hits.values()
        )
        if "__fprintf_chk" in expected_reachable_sinks:
            required["exception_handler_sink_reachable_from_ranked_entry"] = (
                reachable_sink_hits["__fprintf_chk"]
            )
    return {
        "passed": all(required.values()),
        "score": round(sum(required.values()) / max(1, len(required)), 4),
        "required": required,
        "counts": {
            "graph_nodes": xref.node_count,
            "graph_edges": xref.edge_count,
            "logical_sinks": sink_report.get("total_sinks", 0),
            "reachable_sinks": sink_report.get("reachable_sinks", 0),
            "ranked_sources": len(ranked_sources),
            "fallback_sources": len(fallback_sources),
            "recovered_signatures": len(signatures),
            "recovered_structures": len(structures),
            "cpp_classes": len(user_class_rows),
            "cpp_classes_raw": len(classes),
            "cpp_runtime_support_classes": len(runtime_class_rows),
            "cpp_library_support_classes": len(library_class_rows),
            "cpp_vtables": len(user_vtable_offsets),
            "cpp_vtables_raw": len(cpp_agent.vtables),
            "cpp_user_inheritance_edges": len(user_inheritance_edges),
            "cpp_user_base_layouts": len(user_base_layouts),
            "cpp_user_vtable_layouts": len(user_vtable_layouts),
            "cpp_user_vtable_method_slots": sum(
                layout[6] for layout in user_vtable_layouts
            ),
            "cpp_user_vtable_prefix_layouts": len(
                user_vtable_prefix_layouts
            ),
            "cpp_user_vtable_prefix_entries": sum(
                len(layout[4]) for layout in user_vtable_prefix_layouts
            ),
            "cpp_user_vtts": len(user_vtts),
            "cpp_user_this_adjustments": len(user_this_adjustments),
            "cpp_user_this_adjustments_resolved": sum(
                1 for adjustment in user_this_adjustments
                if adjustment[6]
            ),
            "cpp_user_this_adjustments_unresolved": sum(
                1 for adjustment in user_this_adjustments
                if not adjustment[6]
            ),
            "raw_strings": len(string_nodes),
            "code_string_references": code_string_reference_count,
            "user_referenced_strings": len(referenced_string_rows),
        },
        "cpp_class_hits": class_hits,
        "cpp_user_inheritance_edges": [
            {"parent": parent, "child": child}
            for parent, child in sorted(user_inheritance_edges)
        ],
        "cpp_user_base_layouts": [
            {
                "class": class_name,
                "base": base_name,
                "offset": offset,
                "offset_kind": offset_kind,
                "object_offset": object_offset,
                "vbase_offset_slot_offset": vbase_offset_slot_offset,
                "flags": flags,
                "is_virtual": is_virtual,
                "is_public": is_public,
            }
            for (
                class_name,
                base_name,
                offset,
                offset_kind,
                object_offset,
                vbase_offset_slot_offset,
                flags,
                is_virtual,
                is_public,
            ) in sorted(user_base_layouts)
        ],
        "cpp_user_vtable_layouts": [
            {
                "class": class_name,
                "vtable_image_offset": table_offset,
                "address_point_image_offset": address_point_offset,
                "offset_to_top": offset_to_top,
                "table_kind": table_kind,
                "first_method_target_image_offset": first_method_offset,
                "method_count": method_count,
                "method_target_image_offsets": list(
                    method_target_offsets
                ),
                "slot_boundary_reason": boundary_reason,
            }
            for (
                class_name,
                table_offset,
                address_point_offset,
                offset_to_top,
                table_kind,
                first_method_offset,
                method_count,
                method_target_offsets,
                boundary_reason,
            ) in sorted(user_vtable_layouts)
        ],
        "cpp_user_vtable_prefix_layouts": [
            {
                "class": class_name,
                "table_kind": table_kind,
                "offset_to_top": offset_to_top,
                "prefix_boundary_reason": boundary_reason,
                "entries": [
                    {
                        "relative_to_address_point": relative,
                        "pointer_image_offset": pointer_offset,
                        "value": value,
                        "entry_kind": entry_kind,
                        "base": base_class,
                    }
                    for (
                        relative,
                        pointer_offset,
                        value,
                        entry_kind,
                        base_class,
                    ) in entries
                ],
            }
            for (
                class_name,
                table_kind,
                offset_to_top,
                boundary_reason,
                entries,
            ) in sorted(user_vtable_prefix_layouts)
        ],
        "cpp_user_vtts": [
            {
                "class": class_name,
                "vtt_image_offset": vtt_offset,
                "evidence": evidence,
                "confidence": confidence,
                "entries": [
                    {
                        "pointer_image_offset": pointer_offset,
                        "address_point_image_offset": address_point_offset,
                        "vtable_image_offset": vtable_offset,
                        "offset_to_top": offset_to_top,
                        "table_kind": table_kind,
                        "typeinfo_class": typeinfo_class,
                        "table_role": table_role,
                        "leading_null_slot_count": (
                            leading_null_slot_count
                        ),
                    }
                    for (
                        pointer_offset,
                        address_point_offset,
                        vtable_offset,
                        offset_to_top,
                        table_kind,
                        typeinfo_class,
                        table_role,
                        leading_null_slot_count,
                    ) in entries
                ],
            }
            for (
                class_name,
                vtt_offset,
                evidence,
                confidence,
                entries,
            ) in sorted(user_vtts)
        ],
        "cpp_user_this_adjustments": [
            {
                "class": class_name,
                "table_kind": table_kind,
                "offset_to_top": offset_to_top,
                "slot_index": slot_index,
                "target_image_offset": target_offset,
                "kind": kind,
                "resolved": resolved,
                "fixed_delta": fixed_delta,
                "vcall_offset_slot": vcall_slot,
                "vcall_offset_value": vcall_value,
                "candidate_vcall_offsets": [
                    {"slot": slot, "value": value}
                    for slot, value in candidate_offsets
                ],
                "evidence": evidence,
                "confidence": confidence,
            }
            for (
                class_name,
                table_kind,
                offset_to_top,
                slot_index,
                target_offset,
                kind,
                resolved,
                fixed_delta,
                vcall_slot,
                vcall_value,
                candidate_offsets,
                evidence,
                confidence,
            ) in sorted(user_this_adjustments)
        ],
        "recovered_cpp_classes": recovered_class_rows,
        "program_roles": program_roles,
        "user_referenced_string_hits": referenced_string_hits,
        "user_referenced_strings": referenced_string_rows,
        "reachable_sink_hits": reachable_sink_hits,
        "sink_report": sink_report,
    }


def compare_engines(results: dict[str, dict]) -> dict[str, Any]:
    if not {"ghidra", "ida"} <= results.keys():
        return {}
    if any(
        "evaluation" not in results[name] or "pipeline" not in results[name]
        for name in ("ghidra", "ida")
    ):
        return {
            "passed": False,
            "required": {"both_engines_completed": False},
            "error": "cross-engine comparison requires two completed engine results",
        }
    g = results["ghidra"]["evaluation"]["counts"]
    i = results["ida"]["evaluation"]["counts"]
    user_delta = abs(g["functions_user_or_unknown"] - i["functions_user_or_unknown"])
    user_relative_delta = user_delta / max(
        1, g["functions_user_or_unknown"], i["functions_user_or_unknown"]
    )
    logical_user_delta = abs(
        g["functions_user_logical"] - i["functions_user_logical"]
    )
    logical_user_relative_delta = logical_user_delta / max(
        1, g["functions_user_logical"], i["functions_user_logical"]
    )

    def reachable_sink_keys(result: dict) -> set[tuple[str, str]]:
        report = result["pipeline"]["sink_report"]
        return {
            (
                category,
                str(row.get("name") or "").lstrip(".").split("@", 1)[0].lower(),
            )
            for category, rows in report.get("categories", {}).items()
            for row in rows
            if row.get("reachable")
        }

    ghidra_sinks = reachable_sink_keys(results["ghidra"])
    ida_sinks = reachable_sink_keys(results["ida"])

    def source_provenance_classes(result: dict) -> set[str]:
        report = result["pipeline"]["sink_report"]
        canonical = {
            "metadata_entry_point": "entry",
            "entry_export": "entry",
            "callable_export": "callable_export",
            "fallback_call_root": "fallback",
            "caller_supplied": "caller_supplied",
        }
        return {
            canonical.get(str(row.get("provenance") or ""), "unknown")
            for row in report.get("source_evidence", [])
        }

    def sink_distance(
        result: dict,
        category: str,
        sink_name: str,
        *,
        field: str = "source_distance",
    ) -> int | None:
        rows = result["pipeline"]["sink_report"].get("categories", {}).get(
            category, []
        )
        distances = [
            int(row[field])
            for row in rows
            if row.get("reachable")
            and row.get(field) is not None
            and str(row.get("name") or "").lstrip(".").split("@", 1)[0].lower()
            == sink_name
        ]
        return min(distances) if distances else None

    ghidra_source_classes = source_provenance_classes(results["ghidra"])
    ida_source_classes = source_provenance_classes(results["ida"])
    ghidra_program_roles = {
        role: int(record["image_offset"])
        for role, record in (
            results["ghidra"]["pipeline"].get("program_roles") or {}
        ).items()
    }
    ida_program_roles = {
        role: int(record["image_offset"])
        for role, record in (
            results["ida"]["pipeline"].get("program_roles") or {}
        ).items()
    }
    ghidra_user_strings = {
        str(record.get("value") or "")
        for record in (
            results["ghidra"]["pipeline"].get("user_referenced_strings") or []
        )
    }
    ida_user_strings = {
        str(record.get("value") or "")
        for record in (
            results["ida"]["pipeline"].get("user_referenced_strings") or []
        )
    }
    ghidra_user_classes = {
        str(record.get("class_name") or "")
        for record in (
            results["ghidra"]["pipeline"].get("recovered_cpp_classes") or []
        )
        if record.get("role") == "user_candidate"
    }
    ida_user_classes = {
        str(record.get("class_name") or "")
        for record in (
            results["ida"]["pipeline"].get("recovered_cpp_classes") or []
        )
        if record.get("role") == "user_candidate"
    }
    ghidra_user_vtables = {
        str(record.get("class_name") or ""): tuple(
            int(offset)
            for offset in (record.get("vtable_image_offsets") or [])
        )
        for record in (
            results["ghidra"]["pipeline"].get("recovered_cpp_classes") or []
        )
        if record.get("role") == "user_candidate"
    }
    ida_user_vtables = {
        str(record.get("class_name") or ""): tuple(
            int(offset)
            for offset in (record.get("vtable_image_offsets") or [])
        )
        for record in (
            results["ida"]["pipeline"].get("recovered_cpp_classes") or []
        )
        if record.get("role") == "user_candidate"
    }
    ghidra_inheritance = {
        (str(record.get("parent") or ""), str(record.get("child") or ""))
        for record in (
            results["ghidra"]["pipeline"].get(
                "cpp_user_inheritance_edges"
            ) or []
        )
    }
    ida_inheritance = {
        (str(record.get("parent") or ""), str(record.get("child") or ""))
        for record in (
            results["ida"]["pipeline"].get(
                "cpp_user_inheritance_edges"
            ) or []
        )
    }
    def base_layouts(result: dict) -> set[
        tuple[
            str, str, int, str, int | None, int | None, int, bool, bool
        ]
    ]:
        return {
            (
                str(record.get("class") or ""),
                str(record.get("base") or ""),
                int(record.get("offset")),
                str(record.get("offset_kind") or ""),
                (
                    int(record["object_offset"])
                    if record.get("object_offset") is not None else None
                ),
                (
                    int(record["vbase_offset_slot_offset"])
                    if record.get("vbase_offset_slot_offset") is not None
                    else None
                ),
                int(record.get("flags")),
                bool(record.get("is_virtual")),
                bool(record.get("is_public")),
            )
            for record in (
                result["pipeline"].get("cpp_user_base_layouts") or []
            )
            if record.get("offset") is not None
            and record.get("flags") is not None
        }

    ghidra_base_layouts = base_layouts(results["ghidra"])
    ida_base_layouts = base_layouts(results["ida"])
    def vtable_layouts(result: dict) -> set[
        tuple[
            str,
            int,
            int,
            int,
            str,
            int | None,
            int,
            tuple[int, ...],
            str,
        ]
    ]:
        return {
            (
                str(record.get("class") or ""),
                int(record.get("vtable_image_offset")),
                int(record.get("address_point_image_offset")),
                int(record.get("offset_to_top")),
                str(record.get("table_kind") or ""),
                (
                    int(record["first_method_target_image_offset"])
                    if record.get("first_method_target_image_offset")
                    is not None else None
                ),
                int(record.get("method_count")),
                tuple(
                    int(offset)
                    for offset in (
                        record.get("method_target_image_offsets") or []
                    )
                ),
                str(record.get("slot_boundary_reason") or ""),
            )
            for record in (
                result["pipeline"].get("cpp_user_vtable_layouts") or []
            )
            if record.get("vtable_image_offset") is not None
            and record.get("address_point_image_offset") is not None
            and record.get("offset_to_top") is not None
            and record.get("method_count") is not None
        }

    ghidra_vtable_layouts = vtable_layouts(results["ghidra"])
    ida_vtable_layouts = vtable_layouts(results["ida"])

    def vtable_prefix_layouts(result: dict) -> set[tuple]:
        return {
            (
                str(record.get("class") or ""),
                str(record.get("table_kind") or ""),
                int(record.get("offset_to_top")),
                str(record.get("prefix_boundary_reason") or ""),
                tuple(
                    (
                        int(entry.get("relative_to_address_point")),
                        int(entry.get("pointer_image_offset")),
                        int(entry.get("value")),
                        str(entry.get("entry_kind") or ""),
                        (
                            str(entry.get("base"))
                            if entry.get("base") is not None else None
                        ),
                    )
                    for entry in (record.get("entries") or [])
                ),
            )
            for record in (
                result["pipeline"].get(
                    "cpp_user_vtable_prefix_layouts"
                ) or []
            )
            if record.get("offset_to_top") is not None
            and record.get("entries")
        }

    def vtts(result: dict) -> set[tuple]:
        return {
            (
                str(record.get("class") or ""),
                int(record.get("vtt_image_offset")),
                str(record.get("evidence") or ""),
                float(record.get("confidence")),
                tuple(
                    (
                        int(entry.get("pointer_image_offset")),
                        int(entry.get("address_point_image_offset")),
                        int(entry.get("vtable_image_offset")),
                        int(entry.get("offset_to_top")),
                        str(entry.get("table_kind") or ""),
                        (
                            str(entry.get("typeinfo_class"))
                            if entry.get("typeinfo_class") is not None
                            else None
                        ),
                        (
                            str(entry.get("table_role"))
                            if entry.get("table_role") is not None
                            else None
                        ),
                        (
                            int(entry.get("leading_null_slot_count"))
                            if entry.get("leading_null_slot_count")
                            is not None
                            else None
                        ),
                    )
                    for entry in (record.get("entries") or [])
                ),
            )
            for record in (
                result["pipeline"].get("cpp_user_vtts") or []
            )
            if record.get("vtt_image_offset") is not None
            and record.get("entries")
        }

    def this_adjustments(result: dict) -> set[tuple]:
        return {
            (
                str(record.get("class") or ""),
                str(record.get("table_kind") or ""),
                int(record.get("offset_to_top")),
                int(record.get("slot_index")),
                int(record.get("target_image_offset")),
                str(record.get("kind") or ""),
                bool(record.get("resolved")),
                (
                    int(record["fixed_delta"])
                    if record.get("fixed_delta") is not None else None
                ),
                (
                    int(record["vcall_offset_slot"])
                    if record.get("vcall_offset_slot") is not None
                    else None
                ),
                (
                    int(record["vcall_offset_value"])
                    if record.get("vcall_offset_value") is not None
                    else None
                ),
                tuple(
                    (
                        int(candidate.get("slot")),
                        int(candidate.get("value")),
                    )
                    for candidate in (
                        record.get("candidate_vcall_offsets") or []
                    )
                ),
                str(record.get("evidence") or ""),
                float(record.get("confidence")),
            )
            for record in (
                result["pipeline"].get(
                    "cpp_user_this_adjustments"
                ) or []
            )
            if record.get("offset_to_top") is not None
            and record.get("slot_index") is not None
            and record.get("target_image_offset") is not None
        }

    ghidra_prefix_layouts = vtable_prefix_layouts(results["ghidra"])
    ida_prefix_layouts = vtable_prefix_layouts(results["ida"])
    ghidra_vtts = vtts(results["ghidra"])
    ida_vtts = vtts(results["ida"])
    ghidra_this_adjustments = this_adjustments(results["ghidra"])
    ida_this_adjustments = this_adjustments(results["ida"])
    ghidra_unsafe_distance = sink_distance(results["ghidra"], "memory_copy", "strcpy")
    ida_unsafe_distance = sink_distance(results["ida"], "memory_copy", "strcpy")
    unsafe_distance_delta = (
        abs(ghidra_unsafe_distance - ida_unsafe_distance)
        if ghidra_unsafe_distance is not None and ida_unsafe_distance is not None
        else None
    )
    ghidra_exception_distance = sink_distance(
        results["ghidra"], "format_string", "__fprintf_chk"
    )
    ida_exception_distance = sink_distance(
        results["ida"], "format_string", "__fprintf_chk"
    )
    exception_distance_delta = (
        abs(ghidra_exception_distance - ida_exception_distance)
        if ghidra_exception_distance is not None and ida_exception_distance is not None
        else None
    )
    ghidra_unsafe_semantic_distance = sink_distance(
        results["ghidra"], "memory_copy", "strcpy",
        field="semantic_source_distance",
    )
    ida_unsafe_semantic_distance = sink_distance(
        results["ida"], "memory_copy", "strcpy",
        field="semantic_source_distance",
    )
    ghidra_exception_semantic_distance = sink_distance(
        results["ghidra"], "format_string", "__fprintf_chk",
        field="semantic_source_distance",
    )
    ida_exception_semantic_distance = sink_distance(
        results["ida"], "format_string", "__fprintf_chk",
        field="semantic_source_distance",
    )
    required = {
        "both_engines_completed": True,
        "both_exports_passed": all(
            results[name]["evaluation"]["passed"] for name in ("ghidra", "ida")
        ),
        "both_pipelines_passed": all(
            results[name]["pipeline"]["passed"] for name in ("ghidra", "ida")
        ),
        "reachable_sink_set_parity": ghidra_sinks == ida_sinks,
        "source_provenance_class_parity": (
            ghidra_source_classes == ida_source_classes
        ),
        "unsafe_sink_path_distance_within_one_hop": (
            unsafe_distance_delta is not None and unsafe_distance_delta <= 1
        ),
        "unsafe_sink_semantic_distance_parity": (
            ghidra_unsafe_semantic_distance is not None
            and ghidra_unsafe_semantic_distance == ida_unsafe_semantic_distance
        ),
        "logical_user_function_count_within_15_percent": (
            logical_user_relative_delta <= 0.15
        ),
        "logical_user_function_count_parity": logical_user_delta == 0,
        "both_unsafe_paths_reach_callable_boundary": all(
            results[name]["pipeline"]["required"].get(
                "unsafe_sink_reaches_callable_boundary", False
            )
            for name in ("ghidra", "ida")
        ),
    }
    exception_sink_key = ("format_string", "__fprintf_chk")
    if exception_sink_key in ghidra_sinks or exception_sink_key in ida_sinks:
        required["exception_sink_path_distance_within_one_hop"] = (
            exception_distance_delta is not None and exception_distance_delta <= 1
        )
        required["exception_sink_semantic_distance_parity"] = (
            ghidra_exception_semantic_distance is not None
            and ghidra_exception_semantic_distance
            == ida_exception_semantic_distance
        )
    if ghidra_program_roles or ida_program_roles:
        required["program_boundary_role_parity"] = (
            ghidra_program_roles == ida_program_roles
            and {"process_entry", "program_main"} <= ghidra_program_roles.keys()
        )
    if ghidra_user_strings or ida_user_strings:
        required["user_referenced_string_set_parity"] = (
            bool(ghidra_user_strings)
            and ghidra_user_strings == ida_user_strings
        )
    if ghidra_user_classes or ida_user_classes:
        required["user_cpp_class_set_parity"] = (
            bool(ghidra_user_classes)
            and ghidra_user_classes == ida_user_classes
        )
    if any(ghidra_user_vtables.values()) or any(ida_user_vtables.values()):
        required["user_cpp_vtable_offset_parity"] = (
            bool(ghidra_user_vtables)
            and ghidra_user_vtables == ida_user_vtables
        )
    if ghidra_inheritance or ida_inheritance:
        required["user_cpp_inheritance_parity"] = (
            bool(ghidra_inheritance)
            and ghidra_inheritance == ida_inheritance
        )
    if ghidra_base_layouts or ida_base_layouts:
        required["user_cpp_base_layout_parity"] = (
            bool(ghidra_base_layouts)
            and ghidra_base_layouts == ida_base_layouts
        )
    if ghidra_vtable_layouts or ida_vtable_layouts:
        required["user_cpp_vtable_layout_parity"] = (
            bool(ghidra_vtable_layouts)
            and ghidra_vtable_layouts == ida_vtable_layouts
        )
    if ghidra_prefix_layouts or ida_prefix_layouts:
        required["user_cpp_vtable_prefix_layout_parity"] = (
            bool(ghidra_prefix_layouts)
            and ghidra_prefix_layouts == ida_prefix_layouts
        )
    if ghidra_vtts or ida_vtts:
        required["user_cpp_vtt_parity"] = (
            bool(ghidra_vtts) and ghidra_vtts == ida_vtts
        )
    if ghidra_this_adjustments or ida_this_adjustments:
        required["user_cpp_this_adjustment_parity"] = (
            bool(ghidra_this_adjustments)
            and ghidra_this_adjustments == ida_this_adjustments
        )
    comparison = {
        "passed": all(required.values()),
        "required": required,
        "function_count_delta": abs(g["functions_emitted"] - i["functions_emitted"]),
        "user_function_count_delta": user_delta,
        "user_function_count_relative_delta": round(user_relative_delta, 4),
        "logical_user_function_count_delta": logical_user_delta,
        "logical_user_function_count_relative_delta": round(
            logical_user_relative_delta, 4
        ),
        "primary_named_function_count_delta": abs(g["functions_primary_named"] - i["functions_primary_named"]),
        "decompiled_user_count_delta": abs(g["decompiled_user_functions"] - i["decompiled_user_functions"]),
        "decompiled_logical_user_count_delta": abs(
            g["decompiled_logical_user_functions"]
            - i["decompiled_logical_user_functions"]
        ),
        "logical_sink_count_delta": abs(
            results["ghidra"]["pipeline"]["counts"]["logical_sinks"]
            - results["ida"]["pipeline"]["counts"]["logical_sinks"]
        ),
        "ghidra_source_provenance_classes": sorted(ghidra_source_classes),
        "ida_source_provenance_classes": sorted(ida_source_classes),
        "ghidra_unsafe_sink_distance": ghidra_unsafe_distance,
        "ida_unsafe_sink_distance": ida_unsafe_distance,
        "unsafe_sink_path_distance_delta": unsafe_distance_delta,
        "ghidra_exception_sink_distance": ghidra_exception_distance,
        "ida_exception_sink_distance": ida_exception_distance,
        "exception_sink_path_distance_delta": exception_distance_delta,
        "ghidra_unsafe_sink_semantic_distance": ghidra_unsafe_semantic_distance,
        "ida_unsafe_sink_semantic_distance": ida_unsafe_semantic_distance,
        "ghidra_exception_sink_semantic_distance": (
            ghidra_exception_semantic_distance
        ),
        "ida_exception_sink_semantic_distance": ida_exception_semantic_distance,
        "ghidra_program_role_offsets": ghidra_program_roles,
        "ida_program_role_offsets": ida_program_roles,
        "ghidra_user_referenced_strings": sorted(ghidra_user_strings),
        "ida_user_referenced_strings": sorted(ida_user_strings),
        "ghidra_user_cpp_classes": sorted(ghidra_user_classes),
        "ida_user_cpp_classes": sorted(ida_user_classes),
        "ghidra_user_cpp_vtable_offsets": ghidra_user_vtables,
        "ida_user_cpp_vtable_offsets": ida_user_vtables,
        "ghidra_user_cpp_inheritance": [
            {"parent": parent, "child": child}
            for parent, child in sorted(ghidra_inheritance)
        ],
        "ida_user_cpp_inheritance": [
            {"parent": parent, "child": child}
            for parent, child in sorted(ida_inheritance)
        ],
        "ghidra_user_cpp_base_layouts": [
            {
                "class": class_name,
                "base": base_name,
                "offset": offset,
                "offset_kind": offset_kind,
                "object_offset": object_offset,
                "vbase_offset_slot_offset": vbase_offset_slot_offset,
                "flags": flags,
                "is_virtual": is_virtual,
                "is_public": is_public,
            }
            for (
                class_name,
                base_name,
                offset,
                offset_kind,
                object_offset,
                vbase_offset_slot_offset,
                flags,
                is_virtual,
                is_public,
            ) in sorted(ghidra_base_layouts)
        ],
        "ida_user_cpp_base_layouts": [
            {
                "class": class_name,
                "base": base_name,
                "offset": offset,
                "offset_kind": offset_kind,
                "object_offset": object_offset,
                "vbase_offset_slot_offset": vbase_offset_slot_offset,
                "flags": flags,
                "is_virtual": is_virtual,
                "is_public": is_public,
            }
            for (
                class_name,
                base_name,
                offset,
                offset_kind,
                object_offset,
                vbase_offset_slot_offset,
                flags,
                is_virtual,
                is_public,
            ) in sorted(ida_base_layouts)
        ],
        "ghidra_user_cpp_vtable_layouts": [
            {
                "class": class_name,
                "vtable_image_offset": table_offset,
                "address_point_image_offset": address_point_offset,
                "offset_to_top": offset_to_top,
                "table_kind": table_kind,
                "first_method_target_image_offset": first_method_offset,
                "method_count": method_count,
                "method_target_image_offsets": list(
                    method_target_offsets
                ),
                "slot_boundary_reason": boundary_reason,
            }
            for (
                class_name,
                table_offset,
                address_point_offset,
                offset_to_top,
                table_kind,
                first_method_offset,
                method_count,
                method_target_offsets,
                boundary_reason,
            ) in sorted(ghidra_vtable_layouts)
        ],
        "ida_user_cpp_vtable_layouts": [
            {
                "class": class_name,
                "vtable_image_offset": table_offset,
                "address_point_image_offset": address_point_offset,
                "offset_to_top": offset_to_top,
                "table_kind": table_kind,
                "first_method_target_image_offset": first_method_offset,
                "method_count": method_count,
                "method_target_image_offsets": list(
                    method_target_offsets
                ),
                "slot_boundary_reason": boundary_reason,
            }
            for (
                class_name,
                table_offset,
                address_point_offset,
                offset_to_top,
                table_kind,
                first_method_offset,
                method_count,
                method_target_offsets,
                boundary_reason,
            ) in sorted(ida_vtable_layouts)
        ],
        "ghidra_user_cpp_vtable_prefix_layouts": (
            results["ghidra"]["pipeline"].get(
                "cpp_user_vtable_prefix_layouts"
            ) or []
        ),
        "ida_user_cpp_vtable_prefix_layouts": (
            results["ida"]["pipeline"].get(
                "cpp_user_vtable_prefix_layouts"
            ) or []
        ),
        "ghidra_user_cpp_vtts": (
            results["ghidra"]["pipeline"].get("cpp_user_vtts") or []
        ),
        "ida_user_cpp_vtts": (
            results["ida"]["pipeline"].get("cpp_user_vtts") or []
        ),
        "ghidra_user_cpp_this_adjustments": (
            results["ghidra"]["pipeline"].get(
                "cpp_user_this_adjustments"
            ) or []
        ),
        "ida_user_cpp_this_adjustments": (
            results["ida"]["pipeline"].get(
                "cpp_user_this_adjustments"
            ) or []
        ),
        "ghidra_reachable_sinks": sorted(f"{cat}:{name}" for cat, name in ghidra_sinks),
        "ida_reachable_sinks": sorted(f"{cat}:{name}" for cat, name in ida_sinks),
        "note": (
            "Raw totals retain engine-specific user fragments; logical user "
            "counts compare primary functions without discarding fragment evidence."
        ),
    }
    return comparison


def run_engine(engine_name: str, binary: Path, oracle: dict, *, stripped: bool, force: bool) -> dict[str, Any]:
    config = load_config(engine_name)
    engine = make_engine(config)
    ready, message = config.ready()
    if not ready:
        raise RuntimeError(f"{engine_name} unavailable: {message}")
    started = time.monotonic()
    data = engine.analyze(
        binary,
        decompile=True,
        max_functions=0,
        force=force,
        timeout=0,
    )
    elapsed = round(time.monotonic() - started, 3)
    result_path = BUILD / f"{binary.name}.{engine_name}.json"
    result_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {
        "seconds": elapsed,
        "cache": data.get("_cache"),
        "export": str(result_path),
        "evaluation": evaluate_export(data, oracle, stripped=stripped),
        "pipeline": evaluate_pipeline(data, oracle, stripped=stripped),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engines", default="ghidra,ida")
    parser.add_argument("--variants", default="full,stripped")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--cached", action="store_true", help="Reuse engine caches instead of forcing fresh runs.")
    parser.add_argument("--report", default=str(BUILD / "benchmark_report.json"))
    args = parser.parse_args(argv)

    binaries = (
        {
            "full": BUILD / "complex_fixture",
            "stripped": BUILD / "complex_fixture.stripped",
        }
        if args.skip_build else build_fixture()
    )
    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    engines = [item.strip() for item in args.engines.split(",") if item.strip()]
    variants = [item.strip() for item in args.variants.split(",") if item.strip()]
    report: dict[str, Any] = {
        "fixture_version": oracle["fixture_version"],
        "timeout_policy": "none",
        "variants": {},
    }
    failed = False
    for variant in variants:
        binary = binaries[variant]
        variant_report: dict[str, Any] = {
            "binary": str(binary),
            "security": inspect_security(binary),
            "engines": {},
        }
        variant_report["security_checks"] = {
            key: variant_report["security"].get(key) == expected
            for key, expected in oracle.get("security_expectations", {}).items()
        }
        failed = failed or not all(variant_report["security_checks"].values())
        for engine_name in engines:
            try:
                result = run_engine(
                    engine_name,
                    binary,
                    oracle,
                    stripped=(variant == "stripped"),
                    force=not args.cached,
                )
                variant_report["engines"][engine_name] = result
                failed = failed or not (
                    result["evaluation"]["passed"] and result["pipeline"]["passed"]
                )
                print(
                    f"[{variant}/{engine_name}] "
                    f"export={result['evaluation']['score']:.2%} "
                    f"pipeline={result['pipeline']['score']:.2%} "
                    f"seconds={result['seconds']}"
                )
            except Exception as exc:  # one engine failure must not erase the other evidence
                variant_report["engines"][engine_name] = {"error": str(exc)}
                failed = True
                print(f"[{variant}/{engine_name}] ERROR: {exc}")
        variant_report["comparison"] = compare_engines(variant_report["engines"])
        if variant_report["comparison"]:
            failed = failed or not variant_report["comparison"].get("passed", False)
        report["variants"][variant] = variant_report

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"report={report_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
