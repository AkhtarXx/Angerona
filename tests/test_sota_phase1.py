"""Tests for Phase 1 state-of-the-art modules.

These tests validate the engine-agnostic analysis graph, reversible checkpoint
DB, library signature matcher, xref reasoning graph, and sink hunter built from
the IDA Pro Book study.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.models.analysis_graph import AnalysisGraph
from src.models.checkpoint_db import CheckpointDB
from src.analysis.library_signatures import SignatureDB, match_functions_against_db
from src.analysis.xref_graph import XrefGraph
from src.analysis.sink_hunter import SinkHunter


def _sample_engine_json() -> dict:
    """Return a minimal analysis export in the canonical REDump shape."""
    return {
        "metadata": {
            "name": "test_sample",
            "executable_format": "ELF",
            "language_id": "x86:LE:64:default",
            "processor": "x86",
            "sha256": "abc123",
            "image_base": "0x400000",
            "entry_point": "0x401000",
        },
        "memory": [
            {"name": ".text", "start": "0x401000", "end": "0x402000", "size": 4096,
             "r": True, "w": False, "x": True, "initialized": True}
        ],
        "functions": [
            {"name": "main", "entry": "0x401000", "size": 64,
             "signature": "int main(int argc, char **argv)",
             "callees": ["process_input"], "callers": []},
            {"name": "process_input", "entry": "0x401100", "size": 96,
             "signature": "void process_input(char *buf)",
             "callees": ["strcpy"], "callers": ["main"]},
            {"name": "strcpy", "entry": "0x401200", "size": 32,
             "signature": "char *strcpy(char *dest, const char *src)",
             "callees": [], "callers": ["process_input"],
             "is_external": True},
        ],
        "strings": [
            {"address": "0x403000", "value": "hello", "length": 5},
        ],
        "imports": [
            {"name": "strcpy", "library": "libc.so.6", "type": "Function"},
        ],
        "exports": [
            {"address": "0x401000", "name": "main"},
        ],
        "symbols": [
            {"name": "main", "address": "0x401000", "type": "Function", "primary": True},
            {"name": "some_global", "address": "0x404000", "type": "Data", "primary": True},
        ],
    }


def test_analysis_graph_builds_from_json():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    assert graph.metadata["program_id"].startswith("program:")
    fn_ids = [n.id for n in graph.nodes if n.kind == "function"]
    assert any("main" in n.name for n in graph.nodes if n.kind == "function")

    # Check contains edges from program to functions/segments/symbols.
    prog_id = graph.metadata["program_id"]
    contains = [e for e in graph.edges if e.kind == "contains" and e.src == prog_id]
    assert len(contains) >= 3

    # Check call edges preserved.
    calls = [e for e in graph.edges if e.kind == "calls"]
    assert len(calls) >= 2


def test_analysis_graph_links_string_xrefs_without_discarding_provenance():
    data = _sample_engine_json()
    data["strings"][0].update({
        "byte_length": 6,
        "memory_block": ".rodata",
        "xrefs_to": [{
            "from": "0x401010",
            "type": "DATA",
            "engine_reference_type": "DATA",
            "from_function": "main",
            "from_memory_block": ".text",
        }],
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    string_node = next(
        node for node in graph.nodes
        if node.kind == "string" and node.name == "hello"
    )
    assert string_node.properties["length"] == 5
    assert string_node.properties["byte_length"] == 6
    assert string_node.properties["memory_block"] == ".rodata"
    assert string_node.properties["xref_count"] == 1
    assert string_node.properties["referenced_by_function_count"] == 1
    assert string_node.properties["string_role"] == "code_referenced"
    assert any(
        edge.src == "function:0x401000"
        and edge.dst == string_node.id
        and edge.kind == "references"
        and edge.address == "0x401010"
        and edge.properties["string_reference"] is True
        and edge.properties["from_memory_block"] == ".text"
        for edge in graph.edges
    )
    assert any(
        edge.src == graph.metadata["program_id"]
        and edge.dst == string_node.id
        and edge.kind == "contains"
        for edge in graph.edges
    )


def test_analysis_graph_does_not_invent_owner_for_unresolved_string_xref():
    data = _sample_engine_json()
    data["strings"][0]["xrefs_to"] = [{
        "from": "0x500000",
        "type": "DATA",
        "from_function": "",
    }]
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    string_node = next(node for node in graph.nodes if node.kind == "string")
    assert string_node.properties["xref_count"] == 0
    assert string_node.properties["referenced_by_function_count"] == 0
    assert string_node.properties["string_role"] == "unreferenced"
    assert not any(
        edge.dst == string_node.id
        and edge.properties.get("string_reference")
        for edge in graph.edges
    )
    assert not any(
        node.kind == "function" and node.properties.get("synthetic")
        for node in graph.nodes
    )


def test_analysis_graph_preserves_same_address_symbol_aliases():
    data = _sample_engine_json()
    data["symbols"].extend([
        {
            "name": "_ZTVN7fixture12XorProcessorE",
            "address": "0x406000",
            "type": "Label",
            "primary": False,
        },
        {
            "name": "vtable",
            "address": "0x406000",
            "type": "Label",
            "primary": True,
        },
    ])
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    aliases = [
        node for node in graph.nodes
        if node.kind == "symbol" and node.address == "0x406000"
    ]
    assert {node.name for node in aliases} == {
        "_ZTVN7fixture12XorProcessorE",
        "vtable",
    }
    assert len({node.id for node in aliases}) == 2
    assert any(
        edge.kind == "aliases"
        and edge.properties.get("same_address") is True
        and {edge.src, edge.dst} == {node.id for node in aliases}
        for edge in graph.edges
    )


def test_analysis_graph_accepts_legacy_and_structured_xrefs():
    data = _sample_engine_json()
    data["functions"][1]["xrefs_to"] = ["0x401020"]
    data["functions"][2]["xrefs_to"] = [{
        "from": "0x401120",
        "type": "UNCONDITIONAL_CALL",
        "from_function": "process_input",
    }]
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    assert any(
        edge.kind == "calls"
        and edge.src.endswith("0x401100")
        and edge.dst.endswith("0x401200")
        for edge in graph.edges
    )


def test_analysis_graph_resolves_disjoint_function_body_ranges():
    for range_evidence in (
        {
            "body_ranges": [
                {"start": "0x1480", "end": "0x1498", "size": 25, "end_inclusive": True},
                {"start": "0x1499", "end": "0x14a4", "size": 12, "end_inclusive": True},
            ],
        },
        {
            "decompiled": (
                "/* DWARF func body range[0]: "
                "{@address 0x1480 00001480} (37 bytes) */"
            ),
        },
    ):
        data = _sample_engine_json()
        data["functions"] = [
            {
                "name": "main",
                "entry": "0x1480",
                "size": 25,
                "callers": [],
                "callees": [],
                **range_evidence,
            },
            {
                "name": "main.cold",
                "entry": "0x1411",
                "size": 75,
                "callers": [],
                "callees": [],
                "xrefs_to": [{
                    "from": "0x14a0",
                    "type": "UNCONDITIONAL_JUMP",
                    "from_function": "",
                }],
            },
        ]
        data["exports"] = []

        graph = AnalysisGraph()
        graph.from_engine_json(data)

        edge = next(
            edge for edge in graph.edges
            if edge.src == "function:0x1480"
            and edge.dst == "function:0x1411"
            and edge.kind == "calls"
        )
        assert edge.properties["tail_call"] is True
        assert graph.get_node("function:0x14a0") is None


def test_analysis_graph_uses_xref_address_when_stripped_names_collide():
    data = _sample_engine_json()
    data["exports"] = []
    data["functions"] = [
        {
            "name": "strcpy",
            "entry": "0x401100",
            "size": 9,
            "is_external": False,
            "memory_block": ".text",
            "callees": ["strcpy"],
            "callers": [],
        },
        {
            "name": "strcpy",
            "entry": "0x401200",
            "size": 16,
            "callees": [],
            "callers": ["strcpy"],
            "is_external": True,
            "xrefs_to": [{
                "from": "0x401104",
                "type": "UNCONDITIONAL_CALL",
                "from_function": "strcpy",
            }],
        },
    ]

    graph = AnalysisGraph()
    graph.from_engine_json(data)

    assert any(
        edge.kind == "calls"
        and edge.src == "function:0x401100"
        and edge.dst == "function:0x401200"
        for edge in graph.edges
    )
    report = SinkHunter(XrefGraph(graph)).run(max_depth=4)
    assert report["reachable_sinks"] == 1
    sink = report["categories"]["memory_copy"][0]
    assert sink["source_distance"] == 1
    assert sink["shortest_path"] == [
        "function:0x401100",
        "function:0x401200",
    ]
    assert sink["evidence"]["reachability_target_is_boundary"] is True


def test_analysis_graph_recovers_orphan_tail_call_for_stripped_ida():
    data = _sample_engine_json()
    data["exports"] = []
    data["functions"] = [{
        "name": ".strcpy",
        "entry": "0x401200",
        "size": 16,
        "callees": ["strcpy"],
        "callers": [],
        "is_external": True,
        "xrefs_to": [{
            "from": "0x401184",
            "type": "UNCONDITIONAL_JUMP",
            "from_function": "",
        }],
    }]

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    inferred = graph.get_node("function:0x401184")

    assert inferred is not None
    assert inferred.properties["inferred_from"] == "orphan_code_xref"
    assert any(
        edge.kind == "calls"
        and edge.src == inferred.id
        and edge.dst == "function:0x401200"
        and edge.properties["tail_call"] is True
        for edge in graph.edges
    )

    report = SinkHunter(XrefGraph(graph)).run(max_depth=4)
    assert report["reachable_sinks"] == 0
    assert inferred.id not in report["source_nodes"]

    # The orphan evidence remains usable when an analyst or an upstream
    # loader explicitly establishes it as a boundary.
    report = SinkHunter(
        XrefGraph(graph), source_node_ids=[inferred.id]
    ).run(max_depth=4)
    assert report["reachable_sinks"] == 1
    sink = report["categories"]["memory_copy"][0]
    assert sink["source_distance"] == 1
    assert sink["evidence"]["reachability_source_inferred"] is True
    assert sink["evidence"]["reachability_source_provenance"] == "caller_supplied"
    assert sink["evidence"]["reachability_target_is_boundary"] is True


def test_analysis_graph_adds_native_exception_handler_edge():
    data = {
        "metadata": {
            "name": "native_eh",
            "entry_point": "0x1480",
            "image_base": "0x0",
        },
        "functions": [
            {
                "name": "main",
                "entry": "0x1480",
                "size": 37,
                "body_ranges": [{
                    "start": "0x1480",
                    "end": "0x14a4",
                    "size": 37,
                    "end_inclusive": True,
                }],
                "callees": [],
                "callers": [],
            },
            {
                "name": "exception_handler_1411",
                "entry": "0x1411",
                "size": 98,
                "body_ranges": [{
                    "start": "0x1411",
                    "end": "0x1472",
                    "size": 98,
                    "end_inclusive": True,
                }],
                "callees": ["__cxa_begin_catch", "_Unwind_Resume", "__fprintf_chk"],
                "callers": [],
                "is_exception_handler": True,
            },
            {
                "name": "__fprintf_chk",
                "entry": "0x2100",
                "size": 16,
                "is_external": True,
                "callees": [],
                "callers": [],
            },
        ],
        "imports": [{"name": "__fprintf_chk"}],
        "exception_regions": [{
            "kind": "cpp",
            "source": "ida_tryblks",
            "confidence": 1.0,
            "owner": {"name": "main", "entry": "0x1480"},
            "protected_ranges": [{
                "start": "0x148d",
                "end": "0x1491",
                "size": 5,
                "end_inclusive": True,
            }],
            "handlers": [{
                "entry": "0x1499",
                "control_targets": [{
                    "from": "0x14a0",
                    "address": "0x1411",
                    "type": "UNCONDITIONAL_JUMP",
                }],
            }],
        }],
    }

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    edge = next(
        edge for edge in graph.edges
        if edge.src == "function:0x1480"
        and edge.dst == "function:0x1411"
        and edge.kind == "calls"
    )
    assert edge.properties["inferred_exception_handler"] is True
    assert edge.properties["exception_evidence"] == "ida_tryblks"
    assert edge.properties["landing_pad"] == "0x1499"
    assert graph.metadata["exception_region_count"] == 1

    report = SinkHunter(XrefGraph(graph)).run(max_depth=6)
    assert report["reachable_sinks"] == 1
    sink = report["categories"]["format_string"][0]
    assert sink["source_distance"] == 2


def test_analysis_graph_recovers_ghidra_cold_exception_handler_owner():
    data = {
        "metadata": {
            "name": "ghidra_eh",
            "entry_point": "0x1480",
            "image_base": "0x0",
        },
        "functions": [
            {
                "name": "main",
                "entry": "0x1480",
                "size": 25,
                "body_ranges": [{
                    "start": "0x1480",
                    "end": "0x1498",
                    "size": 25,
                    "end_inclusive": True,
                }],
                "callees": [],
                "callers": [],
            },
            {
                "name": "FUN_00101411",
                "entry": "0x1411",
                "size": 98,
                "body_ranges": [{
                    "start": "0x1411",
                    "end": "0x1472",
                    "size": 98,
                    "end_inclusive": True,
                }],
                "callees": [
                    "__cxa_begin_catch",
                    "__cxa_end_catch",
                    "_Unwind_Resume",
                    "__fprintf_chk",
                ],
                "callers": [],
                "xrefs_to": [{
                    "from": "0x14a0",
                    "type": "UNCONDITIONAL_JUMP",
                    "from_function": "",
                }],
            },
            {
                "name": "__fprintf_chk",
                "entry": "0x2100",
                "size": 16,
                "is_external": True,
                "callees": [],
                "callers": [],
            },
        ],
        "imports": [{"name": "__fprintf_chk"}],
    }

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    edge = next(
        edge for edge in graph.edges
        if edge.src == "function:0x1480"
        and edge.dst == "function:0x1411"
        and edge.kind == "calls"
        and edge.properties.get("inferred_exception_handler")
    )
    assert edge.properties["exception_evidence"] == (
        "landing_pad_tail_jump_and_eh_runtime_calls"
    )
    assert edge.properties["confidence"] == 0.95

    report = SinkHunter(XrefGraph(graph)).run(max_depth=6)
    assert report["reachable_sinks"] == 1
    sink = report["categories"]["format_string"][0]
    assert sink["source_distance"] == 2


def test_analysis_graph_recovers_libc_start_main_callback_edge():
    data = {
        "metadata": {
            "name": "stripped_elf",
            "entry_point": "0x401000",
            "image_base": "0x400000",
        },
        "functions": [
            {
                "name": "start",
                "entry": "0x401000",
                "size": 32,
                "callers": [],
                "callees": ["__libc_start_main"],
            },
            {
                "name": "main",
                "entry": "0x401100",
                "size": 32,
                "callers": [],
                "callees": [],
                "xrefs_to": [{
                    "from": "0x401010",
                    "type": "OFFSET",
                    "from_function": "start",
                }],
            },
        ],
    }
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    callback_edges = [
        edge for edge in graph.edges
        if edge.src == "function:0x401000"
        and edge.dst == "function:0x401100"
        and edge.kind == "calls"
    ]
    assert len(callback_edges) == 1
    assert callback_edges[0].properties["inferred_callback"] == (
        "libc_start_main_argument"
    )
    assert callback_edges[0].properties["raw_type"] == "offset"
    assert graph.get_node("function:0x401000").properties["semantic_role"] == (
        "process_entry"
    )
    assert graph.get_node("function:0x401100").properties["semantic_role"] == (
        "program_main"
    )
    assert graph.metadata["program_roles"]["program_main"]["node_id"] == (
        "function:0x401100"
    )
    assert graph.metadata["program_roles"]["program_main"]["evidence"][
        "confidence"
    ] == 1.0


def test_analysis_graph_does_not_guess_main_from_ambiguous_startup_callbacks():
    data = {
        "metadata": {
            "name": "ambiguous_startup",
            "entry_point": "0x401000",
            "image_base": "0x400000",
        },
        "functions": [
            {
                "name": "start",
                "entry": "0x401000",
                "size": 32,
                "callers": [],
                "callees": ["__libc_start_main"],
            },
            {
                "name": "FUN_401100",
                "entry": "0x401100",
                "size": 32,
                "callers": [],
                "callees": [],
                "xrefs_to": [{
                    "from": "0x401010",
                    "type": "OFFSET",
                    "from_function": "start",
                }],
            },
            {
                "name": "FUN_401200",
                "entry": "0x401200",
                "size": 32,
                "callers": [],
                "callees": [],
                "xrefs_to": [{
                    "from": "0x401018",
                    "type": "OFFSET",
                    "from_function": "start",
                }],
            },
        ],
    }
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    callback_edges = [
        edge for edge in graph.edges
        if edge.src == "function:0x401000"
        and edge.kind == "calls"
        and edge.properties.get("inferred_callback")
    ]
    assert {edge.dst for edge in callback_edges} == {
        "function:0x401100",
        "function:0x401200",
    }
    assert "program_roles" not in graph.metadata
    assert all(
        "semantic_role" not in graph.get_node(node_id).properties
        for node_id in ("function:0x401000", "function:0x401100", "function:0x401200")
    )


def test_sink_hunter_prefers_entry_over_disconnected_call_root():
    data = {
        "metadata": {
            "name": "ranked_sources",
            "entry_point": "0x401000",
            "image_base": "0x400000",
        },
        "functions": [
            {
                "name": "start",
                "entry": "0x401000",
                "size": 32,
                "memory_block": ".text",
                "callers": [],
                "callees": ["main"],
            },
            {
                "name": "main",
                "entry": "0x401100",
                "size": 32,
                "memory_block": ".text",
                "callers": ["start"],
                "callees": [],
            },
            {
                "name": "orphan_worker",
                "entry": "0x401200",
                "size": 32,
                "memory_block": ".text",
                "callers": [],
                "callees": [".strcpy"],
            },
            {
                "name": ".strcpy",
                "entry": "0x401300",
                "size": 16,
                "memory_block": ".plt",
                "is_external": True,
                "callers": ["orphan_worker"],
                "callees": [],
            },
        ],
        "imports": [{"name": "strcpy"}],
    }
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    report = SinkHunter(XrefGraph(graph)).run(max_depth=8)

    assert report["source_nodes"] == ["function:0x401000"]
    assert report["source_evidence"] == [{
        "node_id": "function:0x401000",
        "provenance": "metadata_entry_point",
    }]
    assert report["reachable_sinks"] == 0


def test_analysis_graph_persistence_json(tmp_path):
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    path = tmp_path / "graph.json"
    graph.save_json(path)
    loaded = AnalysisGraph.load_json(path)
    assert loaded.node_count == graph.node_count
    assert loaded.edge_count == graph.edge_count


def test_checkpoint_db_create_list_revert(tmp_path):
    db = CheckpointDB(tmp_path / "ckpt.db")
    root = db.create_checkpoint("loader", "initial load")
    assert root.id == 1

    child = db.create_checkpoint("namer", "rename dangerous functions", parent_id=root.id)
    db.record_mutation(child.id, "names", "func:0x401000", "name", "sub_401000", "main")

    assert len(db.list_checkpoints()) == 2
    muts = db.mutations_for(child.id)
    assert len(muts) == 1
    assert muts[0].old() == "sub_401000"
    assert muts[0].new() == "main"

    # Revert child returns mutations in reverse order so caller can apply old values.
    rollback = db.rollback(child.id)
    # rollback order is reverse; a single mutation returns to its old value.
    assert rollback[0].old() == "sub_401000"


def test_signature_db_match():
    db = SignatureDB()
    # Build a signature from a synthesized library function with disassembly list.
    library_json = {
        "functions": [
            {"name": "strcpy", "entry": "0x1000",
             "disassembly": ["mov rax, rdi", "mov rcx, rsi", "mov dl, byte ptr [rcx]",
                             "mov byte ptr [rax], dl", "test dl, dl",
                             "jz done", "inc rax", "inc rcx", "jmp short loop"],
             "decompiled": "char *strcpy(char *dest, const char *src) { ... }"},
        ]
    }
    db.build_from_export("libc", library_json)
    assert len(db.signatures) == 1

    # Query should match a similar implementation.
    disasm = ["mov rax, rdi", "mov rcx, rsi", "mov dl, byte ptr [rcx]",
              "mov byte ptr [rax], dl", "test dl, dl",
              "jz done", "inc rax", "inc rcx", "jmp short loop"]
    match = db.match("FAKE_strcpy", disasm)
    assert match is not None
    assert match["matched"]


def test_xref_graph_queries():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    xref = XrefGraph(graph)

    main_id = xref.function_by_name("main")
    assert main_id is not None
    callees = xref.callees(main_id)
    assert any("process_input" in xref.node_name(c) for c in callees)

    all_callers = xref.all_callers(xref.function_by_name("strcpy"))
    assert main_id in all_callers or xref.function_by_name("process_input") in all_callers



def test_sink_hunter_finds_strcpy_and_path():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    xref = XrefGraph(graph)
    hunter = SinkHunter(xref, source_node_ids=[xref.function_by_name("main")])

    report = hunter.run(max_depth=8)
    assert report["total_sinks"] >= 1
    assert report["reachable_sinks"] >= 1

    sink_names = []
    for cat in report["categories"].values():
        for s in cat:
            sink_names.append(s["name"])
    assert any("strcpy" in n for n in sink_names)

    high = report["high_risk_reachable"]
    assert any("strcpy" in h["name"] for h in high)


def test_sink_hunter_reports_fragment_thunk_normalized_semantic_path():
    data = {
        "metadata": {
            "name": "semantic_path",
            "entry_point": "0x401000",
            "image_base": "0x400000",
        },
        "functions": [
            {
                "name": "main",
                "entry": "0x401000",
                "size": 16,
                "callers": [],
                "callees": ["FUN_00401020"],
            },
            {
                "name": "FUN_00401020",
                "entry": "0x401020",
                "size": 12,
                "callers": [],
                "callees": ["worker"],
                "xrefs_to": [{
                    "from": "0x401008",
                    "type": "UNCONDITIONAL_JUMP",
                    "from_function": "main",
                }],
            },
            {
                "name": "worker",
                "entry": "0x401040",
                "size": 32,
                "callers": ["FUN_00401020"],
                "callees": ["copy_bridge"],
            },
            {
                "name": "copy_bridge",
                "entry": "0x401080",
                "size": 8,
                "is_thunk": True,
                "callers": ["worker"],
                "callees": [".strcpy"],
            },
            {
                "name": ".strcpy",
                "entry": "0x401100",
                "size": 8,
                "is_external": True,
                "is_thunk": True,
                "callers": ["copy_bridge"],
                "callees": [],
            },
        ],
        "imports": [{"name": "strcpy"}],
    }
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    report = SinkHunter(XrefGraph(graph)).run(max_depth=8)
    sink = report["categories"]["memory_copy"][0]

    assert sink["source_distance"] == 4
    assert sink["semantic_source_distance"] == 2
    assert sink["semantic_shortest_path"] == [
        "function:0x401000",
        "function:0x401040",
        "function:0x401100",
    ]
    assert sink["source_distance"] >= sink["semantic_source_distance"] >= 1
    assert {
        row["reason"]
        for row in sink["evidence"]["semantic_collapsed_nodes"]
    } == {"jump_target_fragment", "engine_thunk"}


def test_sink_hunter_resolves_export_sources_and_deduplicates_aliases():
    data = _sample_engine_json()
    data["functions"].append({
        "name": "strcpy",
        "entry": "0x501200",
        "size": 8,
        "is_external": True,
        "callers": [],
        "callees": [],
    })
    data["symbols"].append({
        "name": "strcpy_ptr",
        "address": "0x601200",
        "type": "Data",
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    hunter = SinkHunter(XrefGraph(graph))

    report = hunter.run(max_depth=8)
    strcpy_matches = [
        sink
        for sinks in report["categories"].values()
        for sink in sinks
        if sink["name"].lstrip(".").startswith("strcpy")
    ]
    assert len(strcpy_matches) == 1
    assert strcpy_matches[0]["reachable"] is True
    assert len(strcpy_matches[0]["evidence"]["alias_node_ids"]) >= 3


def test_sink_hunter_avoids_embedded_runtime_and_category_false_positives():
    data = _sample_engine_json()
    data["functions"].extend([
        {
            "name": "__cxa_free_exception",
            "entry": "0x401300",
            "size": 8,
            "is_external": True,
            "callers": [],
            "callees": [],
        },
        {
            "name": "__fprintf_chk",
            "entry": "0x401400",
            "size": 8,
            "is_external": True,
            "callers": [],
            "callees": [],
        },
    ])
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    report = SinkHunter(XrefGraph(graph)).run()
    categories = {
        category: {row["name"] for row in rows}
        for category, rows in report["categories"].items()
    }

    assert "__cxa_free_exception" not in {
        name for names in categories.values() for name in names
    }
    assert "__fprintf_chk" in categories["format_string"]
    assert "__fprintf_chk" not in categories.get("memory_copy", set())


def test_library_noise_suppression():
    data = _sample_engine_json()
    # Direct lexical noise suppression using the internal helper.
    from src.analysis.library_signatures import quick_library_mark
    marks = quick_library_mark(data["functions"])
    # strcpy is clearly a library name in this synthetic data; main/process_input are not.
    assert marks["strcpy"] is True
    assert marks["main"] is False
    assert marks["process_input"] is False
