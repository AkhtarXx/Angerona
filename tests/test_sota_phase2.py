"""Tests for Phase 2 state-of-the-art modules.

Phase 2 covers multi-source triage, type/structure recovery,
C++/RTTI/vtable recovery, and differential analysis.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.models.analysis_graph import AnalysisGraph
from src.models.triage_profile import MultiSourceTriager, format_triage
from src.models.type_recovery import TypeRecoveryAgent
from src.models.cpp_recovery import CppRecoveryAgent
from src.analysis.differential import GraphDiffer


SAMPLES_DIR = Path(__file__).parent.parent / "samples"
LBUZ = SAMPLES_DIR / "lbuz_program.elf"


def _sample_engine_json() -> dict:
    return {
        "metadata": {
            "name": "test_sample",
            "executable_format": "ELF",
            "language_id": "x86:LE:64:default",
            "processor": "x86",
            "sha256": "abc123",
            "image_base": "0x400000",
            "entry_point": "0x401000",
            "pointer_size": 8,
        },
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
            {"name": "_ZN3FooC2Ev", "entry": "0x401300", "size": 48,
             "callees": [], "callers": ["main"]},
            {"name": "_ZTV3Foo", "entry": "0x403000", "size": 16,
             "callees": [], "callers": []},
        ],
        "strings": [
            {"address": "0x404000", "value": "hello", "length": 5},
        ],
        "imports": [{"name": "strcpy", "library": "libc.so.6"}],
        "exports": [{"address": "0x401000", "name": "main"}],
        "symbols": [
            {"name": "some_global", "address": "0x405000", "type": "Data"},
        ],
    }


def test_triage_on_real_elf():
    if not LBUZ.exists():
        pytest.skip("lbuz sample not present")
    triager = MultiSourceTriager()
    profile = triager.triage(LBUZ)
    assert profile.format == "ELF"
    assert profile.bitness == 64
    assert profile.endian in ("little", "big")
    assert profile.stripped is True or profile.stripped is False
    text = format_triage(profile)
    assert isinstance(text, str)
    assert "ELF" in text


def test_triage_on_missing_path():
    triager = MultiSourceTriager()
    profile = triager.triage("/nonexistent/file")
    assert profile.confidence.get("existence") == 0.0
    assert any("path not found" in i for i in profile.indicators)


def test_type_recovery_scaled_index_detection():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    agent = TypeRecoveryAgent(graph)
    accesses = agent.find_scaled_index_access()
    # The synthetic graph does not carry rich disassembly text, so we may get
    # zero or a small number of matches. The method must return a list without
    # throwing.
    assert isinstance(accesses, list)


def test_type_recovery_respects_pointer_arithmetic_and_ignores_tls_canary():
    data = _sample_engine_json()
    data["functions"][0]["decompiled"] = """
        void f(long *param_1) {
            param_1[1] = 1;
            *(undefined4 *)(param_1 + 2) = 2;
            sink(*(long *)(in_FS_OFFSET + 0x28));
        }
    """
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    structures = TypeRecoveryAgent(graph).recover_structures()
    candidate = next(s for s in structures if s.name.endswith("_param_1"))
    fields = {field["offset"]: field for field in candidate.fields}

    assert fields[8]["size"] == 8
    assert fields[16]["size"] == 4
    assert all("FS_OFFSET" not in structure.name for structure in structures)


def test_type_recovery_handles_ida_stack_local_syntax():
    data = _sample_engine_json()
    data["functions"][0]["decompiled"] = (
        "value = [rbp-20h]; other = [rbp-0x18]; argument = [rbp+8];"
    )
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    locals_ = TypeRecoveryAgent(graph).extract_stack_locals(
        graph.get_node("function:0x401000")
    )
    offsets = {local["offset"] for local in locals_}
    assert offsets == {-0x20, -0x18}


def test_type_recovery_signatures():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    agent = TypeRecoveryAgent(graph)
    sigs = agent.recover_signatures()

    assert isinstance(sigs, dict)
    assert "function:0x401000" in sigs
    assert sigs["function:0x401000"].name == "main"
    # Calling convention should be inferred for x86-64 ELF as fastcall/register-based
    assert sigs["function:0x401000"].calling_convention in (
        "fastcall", "cdecl", "stdcall", "thiscall", "unknown",
    )


def test_type_recovery_does_not_count_synthetic_callsites_as_signatures():
    data = _sample_engine_json()
    baseline_graph = AnalysisGraph()
    baseline_graph.from_engine_json(data)
    baseline_count = len(TypeRecoveryAgent(baseline_graph).recover_signatures())
    data["functions"].append({
        "name": "inferred_callsite_0x499999",
        "entry": "0x499999",
        "size": 1,
        "synthetic": True,
        "inferred_from": "orphan_code_xref",
        "callers": [],
        "callees": [],
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    signatures = TypeRecoveryAgent(graph).recover_signatures()

    assert "function:0x499999" not in signatures
    assert len(signatures) == baseline_count


def test_cpp_recovery_finds_vtable():
    data = _sample_engine_json()
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    agent = CppRecoveryAgent(graph)
    vtables = agent.find_vtables()

    # _ZTV3Foo was explicitly added as a synthetic function node; the agent
    # treats all function nodes with vtable-like names as vtable candidates.
    table = next((v for v in vtables if "Foo" in (v.class_name or "")), None)
    assert table is not None


def test_cpp_recovery_demangle():
    agent = CppRecoveryAgent(AnalysisGraph())
    assert "Foo" in agent.demangle_name("_ZN3FooC2Ev")
    assert agent.demangle_name("_ZTSN7fixture12XorProcessorE") == (
        "typeinfo name for fixture::XorProcessor"
    )
    assert agent.demangle_name("main") == "main"


def test_cpp_recovery_uses_stripped_itanium_rtti_type_strings():
    data = _sample_engine_json()
    data["strings"].append({
        "address": "0x404100",
        "value": "N7fixture12XorProcessorE",
        "length": 24,
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    classes = CppRecoveryAgent(graph).build_hierarchy()
    recovered = classes["fixture::XorProcessor"]
    assert recovered.vtables == []
    assert recovered.rtti_type_info["kind"] == "itanium_type_name_string"
    assert recovered.role == "user_candidate"
    assert recovered.as_dict()["role_reason"] == "no_runtime_support_evidence"


def test_cpp_recovery_marks_abi_types_as_retained_runtime_support():
    data = _sample_engine_json()
    data["strings"].append({
        "address": "0x404180",
        "value": "N10__cxxabiv117__class_type_infoE",
        "length": 31,
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    classes = CppRecoveryAgent(graph).build_hierarchy()
    recovered = classes["__cxxabiv1::__class_type_info"]
    assert recovered.role == "runtime_support"
    assert recovered.role_reason == "compiler_abi_namespace"
    assert recovered.rtti_type_info["kind"] == "itanium_type_name_string"
    assert recovered.as_dict()["class_name"] == (
        "__cxxabiv1::__class_type_info"
    )


def test_cpp_recovery_uses_structural_stripped_rtti_vtable_evidence():
    data = _sample_engine_json()
    data["strings"].append({
        "address": "0x404100",
        "value": "N7fixture12XorProcessorE",
        "length": 24,
        "rtti_vtable_candidates": [{
            "typeinfo_address": "0x405000",
            "name_pointer_address": "0x405008",
            "vtable_address": "0x403100",
            "rtti_pointer_address": "0x403108",
            "offset_to_top": 0,
            "memory_block": ".data.rel.ro",
            "evidence": (
                "itanium_name_pointer_and_zero_offset_vtable_header"
            ),
            "confidence": 0.95,
        }],
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    recovered = CppRecoveryAgent(graph).build_hierarchy()[
        "fixture::XorProcessor"
    ]
    assert recovered.vtables == ["0x403100"]
    assert recovered.confidence == 0.95
    assert recovered.rtti_type_info["kind"] == "itanium_type_name_string"


def test_cpp_recovery_rejects_weak_or_base_pointer_rtti_candidate():
    data = _sample_engine_json()
    data["strings"].append({
        "address": "0x404100",
        "value": "N7fixture12XorProcessorE",
        "length": 24,
        "rtti_vtable_candidates": [
            {
                "vtable_address": "0x403100",
                "offset_to_top": 1,
                "evidence": (
                    "itanium_name_pointer_and_zero_offset_vtable_header"
                ),
                "confidence": 0.95,
            },
            {
                "vtable_address": "0x403200",
                "offset_to_top": 0,
                "evidence": "generic_vtable_label",
                "confidence": 1.0,
            },
        ],
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    recovered = CppRecoveryAgent(graph).build_hierarchy()[
        "fixture::XorProcessor"
    ]
    assert recovered.vtables == []


def test_cpp_recovery_parses_zero_padded_ghidra_addresses_as_hex():
    assert CppRecoveryAgent._addr_int("00103200") == 0x103200
    assert CppRecoveryAgent._addr_int("00105c28") == 0x105C28
    assert CppRecoveryAgent._addr_int("103200") == 103200


def _secondary_vtable_engine_json() -> dict:
    data = _sample_engine_json()
    data["strings"].append({
        "address": "0x404180",
        "value": "N7fixture16AuditedProcessorE",
        "length": 28,
        "rtti_vtable_candidates": [{
            "typeinfo_address": "0x405000",
            "name_pointer_address": "0x405008",
            "vtable_address": "0x403028",
            "rtti_pointer_address": "0x403030",
            "address_point_address": "0x403038",
            "first_method_pointer_address": "0x403038",
            "first_method_target_address": "0x401380",
            "offset_to_top": -8,
            "table_kind": "secondary",
            "slot_count": 3,
            "method_slots": [
                {
                    "slot_index": 0,
                    "method_offset": 0,
                    "pointer_address": "0x403038",
                    "target_address": "0x401380",
                },
                {
                    "slot_index": 1,
                    "method_offset": 8,
                    "pointer_address": "0x403040",
                    "target_address": "0x401390",
                },
                {
                    "slot_index": 2,
                    "method_offset": 16,
                    "pointer_address": "0x403048",
                    "target_address": "0x4013a0",
                },
            ],
            "slot_boundary_reason": (
                "code_reference_to_next_data_object"
            ),
            "memory_block": ".data.rel.ro",
            "discovery": "aligned_pointer_scan",
            "evidence": (
                "itanium_name_pointer_negative_offset_and_"
                "callable_vtable_header"
            ),
            "confidence": 0.98,
        }],
    })
    return data


def test_cpp_recovery_recovers_validated_secondary_vtable_header():
    graph = AnalysisGraph()
    graph.from_engine_json(_secondary_vtable_engine_json())

    agent = CppRecoveryAgent(graph)
    vtables = [
        table for table in agent.find_vtables()
        if table.class_name == "fixture::AuditedProcessor"
    ]
    assert len(vtables) == 1
    assert vtables[0].address == "0x403028"
    assert vtables[0].address_point == "0x403038"
    assert vtables[0].offset_to_top == -8
    assert vtables[0].table_kind == "secondary"
    assert vtables[0].first_method_target == "0x401380"
    assert vtables[0].method_slots_validated is True
    assert vtables[0].method_boundary_reason == (
        "code_reference_to_next_data_object"
    )
    assert [
        entry["target_addr"] for entry in vtables[0].method_entries
    ] == ["0x401380", "0x401390", "0x4013a0"]
    assert [
        entry["this_adjustment"] for entry in vtables[0].method_entries
    ] == [
        {
            "kind": "fixed",
            "resolved": True,
            "fixed_delta": -8,
            "vcall_offset_slot": None,
            "vcall_offset_value": None,
            "candidate_vcall_offsets": [],
            "evidence": "secondary_vtable_offset_to_top",
            "confidence": 0.98,
        }
    ] * 3

    classes = agent.build_hierarchy()
    assert classes["fixture::AuditedProcessor"].vtables == ["0x403028"]


@pytest.mark.parametrize(
    "corruption",
    [
        "wrong_evidence",
        "positive_offset",
        "misaligned_offset",
        "wrong_rtti_slot",
        "wrong_address_point",
        "wrong_method_slot",
        "non_callable_target",
        "weak_confidence",
        "slot_count_mismatch",
        "non_contiguous_slot",
        "wrong_slot_pointer",
        "zero_slot_target",
        "unknown_boundary",
    ],
)
def test_cpp_recovery_rejects_malformed_secondary_vtable_header(
    corruption: str,
):
    data = _secondary_vtable_engine_json()
    candidate = data["strings"][-1]["rtti_vtable_candidates"][0]
    if corruption == "wrong_evidence":
        candidate["evidence"] = "same_rtti_pointer_only"
    elif corruption == "positive_offset":
        candidate["offset_to_top"] = 8
    elif corruption == "misaligned_offset":
        candidate["offset_to_top"] = -4
    elif corruption == "wrong_rtti_slot":
        candidate["rtti_pointer_address"] = "0x403038"
    elif corruption == "wrong_address_point":
        candidate["address_point_address"] = "0x403040"
    elif corruption == "wrong_method_slot":
        candidate["first_method_pointer_address"] = "0x403040"
    elif corruption == "non_callable_target":
        candidate["first_method_target_address"] = "0x0"
    elif corruption == "weak_confidence":
        candidate["confidence"] = 0.9
    elif corruption == "slot_count_mismatch":
        candidate["slot_count"] = 4
    elif corruption == "non_contiguous_slot":
        candidate["method_slots"][1]["slot_index"] = 2
    elif corruption == "wrong_slot_pointer":
        candidate["method_slots"][1]["pointer_address"] = "0x403048"
    elif corruption == "zero_slot_target":
        candidate["method_slots"][1]["target_address"] = "0x0"
    elif corruption == "unknown_boundary":
        candidate["slot_boundary_reason"] = "callable_guess_limit"

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    vtables = [
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::AuditedProcessor"
    ]
    assert vtables == []


def _virtual_prefix_vtt_engine_json() -> dict:
    data = _sample_engine_json()
    vtt = {
        "vtt_address": "0x405f00",
        "entry_count": 2,
        "entries": [
            {
                "entry_index": 0,
                "pointer_address": "0x405f00",
                "address_point_address": "0x406010",
                "vtable_address": "0x406000",
                "offset_to_top": 0,
                "table_kind": "primary",
            },
            {
                "entry_index": 1,
                "pointer_address": "0x405f08",
                "address_point_address": "0x406060",
                "vtable_address": "0x406050",
                "offset_to_top": -16,
                "table_kind": "secondary",
            },
        ],
        "evidence": (
            "contiguous_data_pointers_cover_distinct_"
            "same_rtti_vtable_address_points"
        ),
        "confidence": 0.99,
    }
    data["strings"].append({
        "address": "0x404180",
        "value": "N7fixture23VirtualAuditedProcessorE",
        "length": 35,
        "rtti_vtable_candidates": [
            {
                "typeinfo_address": "0x407000",
                "name_pointer_address": "0x407008",
                "vtable_address": "0x406000",
                "rtti_pointer_address": "0x406008",
                "address_point_address": "0x406010",
                "first_method_pointer_address": "0x406010",
                "first_method_target_address": "0x401300",
                "offset_to_top": 0,
                "table_kind": "primary",
                "slot_count": 1,
                "method_slots": [{
                    "slot_index": 0,
                    "method_offset": 0,
                    "pointer_address": "0x406010",
                    "target_address": "0x401300",
                }],
                "slot_boundary_reason": "non_callable_pointer",
                "prefix_entry_count": 1,
                "prefix_entries": [{
                    "entry_index": 0,
                    "relative_to_address_point": -24,
                    "pointer_address": "0x405ff8",
                    "value": 16,
                    "entry_kind": "vbase_offset",
                    "base_typeinfo_address": "0x407100",
                }],
                "prefix_boundary_reason": "vmi_virtual_base_slots",
                "vtt_candidate": vtt,
                "memory_block": ".data.rel.ro",
                "discovery": "aligned_pointer_scan",
                "evidence": (
                    "itanium_name_pointer_and_zero_offset_vtable_header"
                ),
                "confidence": 0.97,
            },
            {
                "typeinfo_address": "0x407000",
                "name_pointer_address": "0x407008",
                "vtable_address": "0x406050",
                "rtti_pointer_address": "0x406058",
                "address_point_address": "0x406060",
                "first_method_pointer_address": "0x406060",
                "first_method_target_address": "0x401300",
                "offset_to_top": -16,
                "table_kind": "secondary",
                "slot_count": 1,
                "method_slots": [{
                    "slot_index": 0,
                    "method_offset": 0,
                    "pointer_address": "0x406060",
                    "target_address": "0x401300",
                }],
                "slot_boundary_reason": "non_callable_pointer",
                "prefix_entry_count": 2,
                "prefix_entries": [
                    {
                        "entry_index": 0,
                        "relative_to_address_point": -32,
                        "pointer_address": "0x406040",
                        "value": -16,
                        "entry_kind": "vcall_or_vbase_offset",
                        "base_typeinfo_address": None,
                    },
                    {
                        "entry_index": 1,
                        "relative_to_address_point": -24,
                        "pointer_address": "0x406048",
                        "value": -16,
                        "entry_kind": "vcall_or_vbase_offset",
                        "base_typeinfo_address": None,
                    },
                ],
                "prefix_boundary_reason": (
                    "preceding_callable_vtable_slot"
                ),
                "vtt_candidate": vtt,
                "memory_block": ".data.rel.ro",
                "discovery": "aligned_pointer_scan",
                "evidence": (
                    "itanium_name_pointer_negative_offset_and_"
                    "callable_vtable_header"
                ),
                "confidence": 0.98,
            },
        ],
    })
    return data


def test_cpp_recovery_validates_virtual_prefix_entries_and_vtt():
    graph = AnalysisGraph()
    graph.from_engine_json(_virtual_prefix_vtt_engine_json())
    agent = CppRecoveryAgent(graph)

    vtables = sorted(
        (
            table for table in agent.find_vtables()
            if table.class_name == "fixture::VirtualAuditedProcessor"
        ),
        key=lambda table: table.address,
    )
    assert len(vtables) == 2
    assert [
        (
            table.table_kind,
            table.prefix_boundary_reason,
            [
                (
                    entry["relative_to_address_point"],
                    entry["value"],
                    entry["entry_kind"],
                )
                for entry in table.prefix_entries
            ],
        )
        for table in vtables
    ] == [
        (
            "primary",
            "vmi_virtual_base_slots",
            [(-24, 16, "vbase_offset")],
        ),
        (
            "secondary",
            "preceding_callable_vtable_slot",
            [
                (-32, -16, "vcall_or_vbase_offset"),
                (-24, -16, "vcall_or_vbase_offset"),
            ],
        ),
    ]
    assert all(table.prefix_entries_validated for table in vtables)
    assert all(table.vtt_info is not None for table in vtables)
    assert vtables[0].vtt_info["vtt_address"] == "0x405f00"
    secondary_adjustments = [
        entry["this_adjustment"]
        for entry in vtables[1].method_entries
    ]
    assert len(secondary_adjustments) == 1
    assert secondary_adjustments[0]["kind"] == "virtual_vcall"
    assert secondary_adjustments[0]["resolved"] is False
    assert secondary_adjustments[0]["candidate_vcall_offsets"] == [
        {"slot": -32, "value": -16},
        {"slot": -24, "value": -16},
    ]

    classes = agent.build_hierarchy()
    vtt = classes[
        "fixture::VirtualAuditedProcessor"
    ].rtti_type_info["vtt"]
    assert vtt["entry_count"] == 2
    assert [
        (entry["table_kind"], entry["offset_to_top"])
        for entry in vtt["entries"]
    ] == [("primary", 0), ("secondary", -16)]


@pytest.mark.parametrize(
    "corruption",
    [
        "prefix_count",
        "prefix_pointer",
        "prefix_kind",
        "prefix_boundary",
        "vtt_pointer_gap",
        "vtt_duplicate_target",
        "vtt_wrong_header",
        "vtt_weak_confidence",
    ],
)
def test_cpp_recovery_rejects_malformed_virtual_prefix_or_vtt(
    corruption: str,
):
    data = _virtual_prefix_vtt_engine_json()
    candidate = data["strings"][-1]["rtti_vtable_candidates"][0]
    if corruption == "prefix_count":
        candidate["prefix_entry_count"] = 2
    elif corruption == "prefix_pointer":
        candidate["prefix_entries"][0]["pointer_address"] = "0x405ff0"
    elif corruption == "prefix_kind":
        candidate["prefix_entries"][0][
            "entry_kind"
        ] = "vcall_or_vbase_offset"
    elif corruption == "prefix_boundary":
        candidate["prefix_boundary_reason"] = "backward_scan_limit"
    elif corruption == "vtt_pointer_gap":
        candidate["vtt_candidate"]["entries"][1][
            "pointer_address"
        ] = "0x405f10"
    elif corruption == "vtt_duplicate_target":
        candidate["vtt_candidate"]["entries"][1].update({
            "address_point_address": "0x406010",
            "vtable_address": "0x406000",
            "offset_to_top": 0,
            "table_kind": "primary",
        })
    elif corruption == "vtt_wrong_header":
        candidate["vtt_candidate"]["entries"][0][
            "vtable_address"
        ] = "0x406008"
    elif corruption == "vtt_weak_confidence":
        candidate["vtt_candidate"]["confidence"] = 0.98

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    vtables = [
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::VirtualAuditedProcessor"
        and table.table_kind == "primary"
    ]
    assert vtables == []


def _construction_vtt_engine_json() -> dict:
    data = _virtual_prefix_vtt_engine_json()
    root = data["strings"][-1]
    root["rtti_typeinfo_candidates"] = [{
        "typeinfo_address": "0x407000",
        "typeinfo_kind": "vmi_class_type_info",
        "base_count": 1,
        "bases": [{
            "base_typeinfo_address": "0x407100",
            "offset": 16,
            "offset_kind": "object_offset",
            "object_offset": 16,
            "flags": 2,
            "is_virtual": False,
        }],
        "evidence": "itanium_type_name_vptr_kind_and_base_array",
        "confidence": 1.0,
    }]
    data["strings"].extend([
        {
            "address": "0x4041c0",
            "value": "N7fixture17VirtualAuditLayerE",
            "length": 29,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x407100",
                "typeinfo_kind": "vmi_class_type_info",
                "base_count": 1,
                "bases": [{
                    "base_typeinfo_address": "0x407200",
                    "flags": 3,
                    "is_virtual": True,
                }],
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_array"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "address": "0x404200",
            "value": "N7fixture9AuditableE",
            "length": 20,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x407200",
                "typeinfo_kind": "class_type_info",
                "base_count": 0,
                "bases": [],
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
    ])
    vtt = {
        "vtt_address": "0x405e00",
        "entry_count": 3,
        "entries": [
            {
                "entry_index": 0,
                "pointer_address": "0x405e00",
                "address_point_address": "0x406010",
                "vtable_address": "0x406000",
                "typeinfo_address": "0x407000",
                "offset_to_top": 0,
                "table_kind": "primary",
                "table_role": "complete_object",
                "leading_null_slot_count": 0,
            },
            {
                "entry_index": 1,
                "pointer_address": "0x405e08",
                "address_point_address": "0x405f80",
                "vtable_address": "0x405f70",
                "typeinfo_address": "0x407100",
                "offset_to_top": 0,
                "table_kind": "primary",
                "table_role": "construction",
                "leading_null_slot_count": 2,
            },
            {
                "entry_index": 2,
                "pointer_address": "0x405e10",
                "address_point_address": "0x406060",
                "vtable_address": "0x406050",
                "typeinfo_address": "0x407000",
                "offset_to_top": -16,
                "table_kind": "secondary",
                "table_role": "complete_object",
                "leading_null_slot_count": 0,
            },
        ],
        "evidence": (
            "contiguous_data_pointers_start_at_complete_object_"
            "and_cover_valid_base_construction_address_points"
        ),
        "confidence": 0.99,
    }
    for candidate in root["rtti_vtable_candidates"]:
        candidate["vtt_candidate"] = vtt
    return data


def test_cpp_recovery_validates_construction_vtt_from_base_rtti_closure():
    data = _construction_vtt_engine_json()
    data["symbols"] = [
        {
            "address": "0x405e00",
            "type": "data",
            "name": "_ZTTN7fixture23VirtualAuditedProcessorE",
        },
        {
            "address": "0x405f70",
            "type": "data",
            "name": "_ZTVN7fixture17VirtualAuditLayerE",
        },
    ]
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    all_tables = CppRecoveryAgent(graph).find_vtables()
    tables = [
        table for table in all_tables
        if table.class_name == "fixture::VirtualAuditedProcessor"
    ]
    assert len(tables) == 2
    assert all(table.address != "0x405e00" for table in all_tables)
    assert all(table.address != "0x405f70" for table in all_tables)
    assert all(table.vtt_info is not None for table in tables)
    assert [
        (
            entry["table_role"],
            entry["typeinfo_address"],
            entry["leading_null_slot_count"],
        )
        for entry in tables[0].vtt_info["entries"]
    ] == [
        ("complete_object", "0x407000", 0),
        ("construction", "0x407100", 2),
        ("complete_object", "0x407000", 0),
    ]
    secondary = next(
        table for table in tables if table.table_kind == "secondary"
    )
    assert secondary.method_entries[0]["this_adjustment"] == {
        "kind": "fixed",
        "resolved": True,
        "fixed_delta": -16,
        "vcall_offset_slot": None,
        "vcall_offset_value": None,
        "candidate_vcall_offsets": [],
        "evidence": "rtti_nonvirtual_base_object_offset",
        "confidence": 1.0,
    }


@pytest.mark.parametrize(
    "corruption",
    [
        "foreign_typeinfo",
        "wrong_role",
        "too_many_null_slots",
        "partial_role_metadata",
        "base_has_no_virtual_base",
        "weak_root_rtti",
        "wrong_root_role",
    ],
)
def test_cpp_recovery_rejects_unproven_construction_vtt(
    corruption: str,
):
    data = _construction_vtt_engine_json()
    root = data["strings"][-3]
    vtt = root["rtti_vtable_candidates"][0]["vtt_candidate"]
    if corruption == "foreign_typeinfo":
        vtt["entries"][1]["typeinfo_address"] = "0x409000"
    elif corruption == "wrong_role":
        vtt["entries"][1]["table_role"] = "complete_object"
    elif corruption == "too_many_null_slots":
        vtt["entries"][1]["leading_null_slot_count"] = 3
    elif corruption == "partial_role_metadata":
        vtt["entries"][1].pop("table_role")
    elif corruption == "base_has_no_virtual_base":
        base = data["strings"][-2][
            "rtti_typeinfo_candidates"
        ][0]["bases"][0]
        base.update({"flags": 2, "is_virtual": False})
    elif corruption == "weak_root_rtti":
        root["rtti_typeinfo_candidates"][0]["confidence"] = 0.99
    elif corruption == "wrong_root_role":
        vtt["entries"][0]["table_role"] = "construction"

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    tables = [
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::VirtualAuditedProcessor"
    ]
    assert tables == []


@pytest.mark.parametrize(
    ("evidence", "source_name", "confidence"),
    [
        (
            "itanium_mangled_thunk_symbol",
            "_ZTv0_n24_N7fixture23VirtualAuditedProcessorD0Ev",
            1.0,
        ),
        (
            "x86_sysv_this_adjustment_instruction_pattern",
            None,
            0.99,
        ),
    ],
)
def test_cpp_recovery_resolves_exact_virtual_this_adjustment(
    evidence: str,
    source_name: str | None,
    confidence: float,
):
    data = _virtual_prefix_vtt_engine_json()
    candidate = data["strings"][-1]["rtti_vtable_candidates"][1]
    candidate["method_slots"][0]["this_adjustment_candidates"] = [{
        "kind": "virtual_vcall",
        "fixed_delta": 0,
        "vcall_offset_slot": -24,
        "evidence": evidence,
        "source_name": source_name,
        "confidence": confidence,
    }]
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    secondary = next(
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::VirtualAuditedProcessor"
        and table.table_kind == "secondary"
    )
    adjustment = secondary.method_entries[0]["this_adjustment"]
    assert adjustment == {
        "kind": "virtual_vcall",
        "resolved": True,
        "fixed_delta": 0,
        "vcall_offset_slot": -24,
        "vcall_offset_value": -16,
        "candidate_vcall_offsets": [{"slot": -24, "value": -16}],
        "evidence": evidence,
        "confidence": confidence,
    }


def test_cpp_recovery_allows_fixed_thunk_on_prefixed_secondary_table():
    data = _virtual_prefix_vtt_engine_json()
    candidate = data["strings"][-1]["rtti_vtable_candidates"][1]
    candidate["method_slots"][0]["this_adjustment_candidates"] = [{
        "kind": "fixed",
        "fixed_delta": -16,
        "vcall_offset_slot": None,
        "evidence": "itanium_mangled_thunk_symbol",
        "source_name": (
            "_ZThn16_N7fixture23VirtualAuditedProcessorD0Ev"
        ),
        "confidence": 1.0,
    }]
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    secondary = next(
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::VirtualAuditedProcessor"
        and table.table_kind == "secondary"
    )
    assert secondary.method_entries[0]["this_adjustment"] == {
        "kind": "fixed",
        "resolved": True,
        "fixed_delta": -16,
        "vcall_offset_slot": None,
        "vcall_offset_value": None,
        "candidate_vcall_offsets": [],
        "evidence": "itanium_mangled_thunk_symbol",
        "confidence": 1.0,
    }


@pytest.mark.parametrize(
    "corruption",
    [
        "not_a_list",
        "wrong_kind",
        "slot_outside_prefix",
        "misaligned_slot",
        "mangled_name_mismatch",
        "weak_confidence",
        "instruction_with_source_name",
        "adjustment_on_primary",
    ],
)
def test_cpp_recovery_rejects_malformed_this_adjustment_evidence(
    corruption: str,
):
    data = _virtual_prefix_vtt_engine_json()
    table_index = 0 if corruption == "adjustment_on_primary" else 1
    candidate = data["strings"][-1]["rtti_vtable_candidates"][table_index]
    raw_slot = candidate["method_slots"][0]
    raw_slot["this_adjustment_candidates"] = [{
        "kind": "virtual_vcall",
        "fixed_delta": 0,
        "vcall_offset_slot": -24,
        "evidence": "itanium_mangled_thunk_symbol",
        "source_name": (
            "_ZTv0_n24_N7fixture23VirtualAuditedProcessorD0Ev"
        ),
        "confidence": 1.0,
    }]
    if corruption == "not_a_list":
        raw_slot["this_adjustment_candidates"] = {}
    elif corruption == "wrong_kind":
        raw_slot["this_adjustment_candidates"][0]["kind"] = "covariant"
    elif corruption == "slot_outside_prefix":
        raw_slot["this_adjustment_candidates"][0][
            "vcall_offset_slot"
        ] = -40
        raw_slot["this_adjustment_candidates"][0][
            "source_name"
        ] = "_ZTv0_n40_N7fixture23VirtualAuditedProcessorD0Ev"
    elif corruption == "misaligned_slot":
        raw_slot["this_adjustment_candidates"][0][
            "vcall_offset_slot"
        ] = -28
        raw_slot["this_adjustment_candidates"][0][
            "source_name"
        ] = "_ZTv0_n28_N7fixture23VirtualAuditedProcessorD0Ev"
    elif corruption == "mangled_name_mismatch":
        raw_slot["this_adjustment_candidates"][0][
            "source_name"
        ] = "_ZTv0_n32_N7fixture23VirtualAuditedProcessorD0Ev"
    elif corruption == "weak_confidence":
        raw_slot["this_adjustment_candidates"][0]["confidence"] = 0.98
    elif corruption == "instruction_with_source_name":
        raw_slot["this_adjustment_candidates"][0].update({
            "evidence": "x86_sysv_this_adjustment_instruction_pattern",
            "source_name": "fabricated",
            "confidence": 0.99,
        })

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    tables = [
        table for table in CppRecoveryAgent(graph).find_vtables()
        if table.class_name == "fixture::VirtualAuditedProcessor"
        and table.table_kind == candidate["table_kind"]
    ]
    assert tables == []


def test_cpp_recovery_builds_single_inheritance_from_validated_rtti():
    data = _sample_engine_json()
    data["strings"].extend([
        {
            "address": "0x404100",
            "value": "N7fixture9ProcessorE",
            "length": 20,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405000",
                "typeinfo_kind": "class_type_info",
                "base_typeinfo_address": "",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "address": "0x404140",
            "value": "N7fixture12XorProcessorE",
            "length": 24,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405020",
                "typeinfo_kind": "si_class_type_info",
                "base_typeinfo_address": "0x405000",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
    ])
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    classes = CppRecoveryAgent(graph).build_hierarchy()
    assert classes["fixture::XorProcessor"].parents == [
        "fixture::Processor"
    ]
    assert classes["fixture::Processor"].children == [
        "fixture::XorProcessor"
    ]
    assert classes["fixture::XorProcessor"].rtti_type_info["base_class"] == (
        "fixture::Processor"
    )
    assert classes["fixture::XorProcessor"].rtti_type_info[
        "hierarchy_confidence"
    ] == 1.0


def test_cpp_recovery_rejects_unvalidated_rtti_inheritance():
    data = _sample_engine_json()
    data["strings"].extend([
        {
            "address": "0x404100",
            "value": "N7fixture9ProcessorE",
            "length": 20,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405000",
                "typeinfo_kind": "class_type_info",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "address": "0x404140",
            "value": "N7fixture12XorProcessorE",
            "length": 24,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405020",
                "typeinfo_kind": "si_class_type_info",
                "base_typeinfo_address": "0x405000",
                "evidence": "address_proximity_only",
                "confidence": 1.0,
            }],
        },
    ])
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    classes = CppRecoveryAgent(graph).build_hierarchy()
    assert classes["fixture::XorProcessor"].parents == []
    assert classes["fixture::Processor"].children == []


def _vmi_engine_json() -> dict:
    data = _sample_engine_json()
    data["strings"].extend([
        {
            "address": "0x404100",
            "value": "N7fixture9ProcessorE",
            "length": 20,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405000",
                "typeinfo_kind": "class_type_info",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "address": "0x404120",
            "value": "N7fixture9AuditableE",
            "length": 20,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405010",
                "typeinfo_kind": "class_type_info",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "address": "0x404140",
            "value": "N7fixture16AuditedProcessorE",
            "length": 28,
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x405020",
                "typeinfo_kind": "vmi_class_type_info",
                "vmi_flags": 0,
                "base_count": 2,
                "bases": [
                    {
                        "base_pointer_address": "0x405038",
                        "base_typeinfo_address": "0x405000",
                        "offset_flags_address": "0x405040",
                        "offset": 0,
                        "offset_kind": "object_offset",
                        "object_offset": 0,
                        "vbase_offset_slot_offset": None,
                        "flags": 2,
                        "is_virtual": False,
                        "is_public": True,
                    },
                    {
                        "base_pointer_address": "0x405048",
                        "base_typeinfo_address": "0x405010",
                        "offset_flags_address": "0x405050",
                        "offset": 8,
                        "offset_kind": "object_offset",
                        "object_offset": 8,
                        "vbase_offset_slot_offset": None,
                        "flags": 2,
                        "is_virtual": False,
                        "is_public": True,
                    },
                ],
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_array"
                ),
                "confidence": 1.0,
            }],
        },
    ])
    return data


def test_cpp_recovery_builds_multiple_inheritance_from_validated_vmi_rtti():
    graph = AnalysisGraph()
    graph.from_engine_json(_vmi_engine_json())

    classes = CppRecoveryAgent(graph).build_hierarchy()
    audited = classes["fixture::AuditedProcessor"]
    assert audited.parents == [
        "fixture::Processor",
        "fixture::Auditable",
    ]
    assert classes["fixture::Processor"].children == [
        "fixture::AuditedProcessor"
    ]
    assert classes["fixture::Auditable"].children == [
        "fixture::AuditedProcessor"
    ]
    assert classes["fixture::Processor"].rtti_type_info[
        "typeinfo_address"
    ] == "0x405000"
    assert classes["fixture::Auditable"].rtti_type_info[
        "typeinfo_address"
    ] == "0x405010"
    assert audited.rtti_type_info["typeinfo_kind"] == "vmi_class_type_info"
    assert audited.rtti_type_info["base_classes"] == [
        "fixture::Processor",
        "fixture::Auditable",
    ]
    assert [
        (base["offset"], base["flags"])
        for base in audited.rtti_type_info["bases"]
    ] == [(0, 2), (8, 2)]


def test_cpp_recovery_distinguishes_virtual_base_slot_from_object_offset():
    data = _vmi_engine_json()
    virtual_base = data["strings"][-1]["rtti_typeinfo_candidates"][0][
        "bases"
    ][1]
    virtual_base.update({
        "offset": -24,
        "offset_kind": "vbase_offset_slot",
        "object_offset": None,
        "vbase_offset_slot_offset": -24,
        "flags": 3,
        "is_virtual": True,
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    classes = CppRecoveryAgent(graph).build_hierarchy()
    audited = classes["fixture::AuditedProcessor"]
    recovered_virtual_base = audited.rtti_type_info["bases"][1]
    assert recovered_virtual_base["base_class"] == "fixture::Auditable"
    assert recovered_virtual_base["offset"] == -24
    assert recovered_virtual_base["offset_kind"] == "vbase_offset_slot"
    assert recovered_virtual_base["object_offset"] is None
    assert recovered_virtual_base["vbase_offset_slot_offset"] == -24
    assert recovered_virtual_base["is_virtual"] is True


@pytest.mark.parametrize(
    "corruption",
    [
        "wrong_kind",
        "non_null_object_offset",
        "missing_slot",
        "mismatched_slot",
        "partial_semantics",
    ],
)
def test_cpp_recovery_rejects_ambiguous_virtual_base_offsets(
    corruption: str,
):
    data = _vmi_engine_json()
    virtual_base = data["strings"][-1]["rtti_typeinfo_candidates"][0][
        "bases"
    ][1]
    virtual_base.update({
        "offset": -24,
        "offset_kind": "vbase_offset_slot",
        "object_offset": None,
        "vbase_offset_slot_offset": -24,
        "flags": 3,
        "is_virtual": True,
    })
    if corruption == "wrong_kind":
        virtual_base["offset_kind"] = "object_offset"
    elif corruption == "non_null_object_offset":
        virtual_base["object_offset"] = -24
    elif corruption == "missing_slot":
        virtual_base["vbase_offset_slot_offset"] = None
    elif corruption == "mismatched_slot":
        virtual_base["vbase_offset_slot_offset"] = -16
    elif corruption == "partial_semantics":
        del virtual_base["object_offset"]

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    classes = CppRecoveryAgent(graph).build_hierarchy()
    assert classes["fixture::AuditedProcessor"].parents == []
    assert classes["fixture::Processor"].children == []
    assert classes["fixture::Auditable"].children == []


@pytest.mark.parametrize(
    "corruption",
    [
        "weak_confidence",
        "wrong_evidence",
        "count_mismatch",
        "invalid_base_address",
        "inconsistent_flags",
    ],
)
def test_cpp_recovery_rejects_malformed_vmi_rtti(corruption: str):
    data = _vmi_engine_json()
    candidate = data["strings"][-1]["rtti_typeinfo_candidates"][0]
    if corruption == "weak_confidence":
        candidate["confidence"] = 0.99
    elif corruption == "wrong_evidence":
        candidate["evidence"] = "address_proximity_only"
    elif corruption == "count_mismatch":
        candidate["base_count"] = 3
    elif corruption == "invalid_base_address":
        candidate["bases"][1]["base_typeinfo_address"] = "0x0"
    elif corruption == "inconsistent_flags":
        candidate["bases"][1]["is_public"] = False

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    classes = CppRecoveryAgent(graph).build_hierarchy()
    assert classes["fixture::AuditedProcessor"].parents == []
    assert classes["fixture::Processor"].children == []
    assert classes["fixture::Auditable"].children == []


def test_cpp_recovery_rejects_ambiguous_typeinfo_address_mapping():
    data = _vmi_engine_json()
    data["strings"].append({
        "address": "0x404180",
        "value": "N7fixture9OtherBaseE",
        "length": 20,
        "rtti_typeinfo_candidates": [{
            "typeinfo_address": "0x405000",
            "typeinfo_kind": "class_type_info",
            "evidence": "itanium_type_name_vptr_kind_and_base_pointer",
            "confidence": 1.0,
        }],
    })
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    classes = CppRecoveryAgent(graph).build_hierarchy()
    audited = classes["fixture::AuditedProcessor"]
    assert "fixture::Processor" not in audited.parents
    assert audited.parents == ["fixture::Auditable"]
    assert classes["fixture::Processor"].children == []


def test_cpp_recovery_deduplicates_engine_aliases_for_same_vtable():
    data = _sample_engine_json()
    data["symbols"].extend([
        {
            "name": "_ZTV3Foo",
            "address": "0x403000",
            "type": "Label",
            "primary": False,
        },
        {
            "name": "vtable for Foo",
            "address": "0x403000",
            "type": "Label",
            "primary": True,
        },
    ])
    graph = AnalysisGraph()
    graph.from_engine_json(data)

    agent = CppRecoveryAgent(graph)
    foo_tables = [
        table for table in agent.find_vtables()
        if table.class_name == "Foo"
    ]
    assert len(foo_tables) == 1
    assert foo_tables[0].address == "0x403000"
    assert len(agent.vtables) == len(agent.find_vtables())


def test_differential_identical_graphs():
    data = _sample_engine_json()
    graph_a = AnalysisGraph()
    graph_a.from_engine_json(data)
    graph_b = AnalysisGraph()
    graph_b.from_engine_json(data)
    differ = GraphDiffer(graph_a, graph_b)
    diff = differ.diff_functions()
    statuses = {d.status for d in diff}
    assert "identical" in statuses
    assert "unique_a" not in statuses
    assert "unique_b" not in statuses


def test_differential_renamed_function():
    data_a = _sample_engine_json()
    data_b = _sample_engine_json()
    data_b["functions"][0]["name"] = "renamed_main"
    graph_a = AnalysisGraph()
    graph_a.from_engine_json(data_a)
    graph_b = AnalysisGraph()
    graph_b.from_engine_json(data_b)

    differ = GraphDiffer(graph_a, graph_b)
    diff = differ.diff_functions()
    modified = [d for d in diff if d.status in ("modified", "similar", "identical")]
    assert len(modified) >= 1
    names = {d.name for d in modified}
    assert any("main" in n or "renamed_main" in n for n in names)


def test_differential_call_graph_stats():
    data = _sample_engine_json()
    graph_a = AnalysisGraph()
    graph_a.from_engine_json(data)
    graph_b = AnalysisGraph()
    graph_b.from_engine_json(data)
    stats = GraphDiffer(graph_a, graph_b).diff_call_graph()
    assert stats["call_graph_similarity"] == 1.0
    assert len(stats["common_nodes"]) >= 3


def test_cli_sota_analyze_phase2_outputs():
    if not LBUZ.exists():
        pytest.skip("lbuz sample not present")
    cmd = [sys.executable, "-m", "src.cli", "sota-analyze", str(LBUZ),
           "--engine", "ghidra", "--force"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr

    stdout = result.stdout.strip()
    assert "signatures" in stdout
    assert "structures" in stdout
    assert "cpp classes" in stdout

    # Locate workspace from output: "workspace     : <path>"
    workspace = None
    for line in stdout.splitlines():
        if line.strip().startswith("workspace"):
            workspace = Path(line.split(":", 1)[1].strip())
            break
    assert workspace and workspace.exists()
    assert (workspace / "raw" / "triage_profile.json").exists()
    assert (workspace / "raw" / "type_signatures.json").exists()
    assert (workspace / "raw" / "recovered_structures.json").exists()
    assert (workspace / "raw" / "cpp_classes.json").exists()
