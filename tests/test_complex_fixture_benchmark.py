from benchmarks.complex_fixture.run_benchmark import (
    compare_engines,
    evaluate_export,
    evaluate_pipeline,
)
from src.analysis.library_signatures import (
    classify_library_function,
    classify_user_fragment,
)


ORACLE = {
    "expected_strings": ["banner"],
    "expected_function_tokens": ["main", "user_parse"],
    "expected_import_tokens": ["strcpy"],
    "expected_sink_tokens": ["strcpy", "user_parse"],
    "minimums": {
        "functions": 2,
        "strings": 1,
        "imports": 1,
        "decompiled_functions": 2,
        "recovered_signatures": 2,
        "cpp_classes": 0,
    },
    "expected_cpp_class_tokens": [],
}


def _export():
    return {
        "metadata": {"emitted_function_count": 3},
        "functions": [
            {"name": "main", "entry": "0x1000", "decompiled": "int main() { return user_parse(); }"},
            {"name": "_Z10user_parsev", "entry": "0x1100", "decompiled": "int user_parse() { return 1; }"},
            {"name": ".strcpy", "entry": "0x1200", "is_external": True, "decompiled": "jmp strcpy"},
        ],
        "strings": [{"value": "banner"}],
        "imports": [{"name": "strcpy@@GLIBC_2.2.5"}],
    }


def _vmi_export():
    data = _export()
    data["strings"].extend([
        {
            "value": "N7fixture9ProcessorE",
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x5000",
                "typeinfo_kind": "class_type_info",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "value": "N7fixture9AuditableE",
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x5010",
                "typeinfo_kind": "class_type_info",
                "evidence": (
                    "itanium_type_name_vptr_kind_and_base_pointer"
                ),
                "confidence": 1.0,
            }],
        },
        {
            "value": "N7fixture16AuditedProcessorE",
            "rtti_typeinfo_candidates": [{
                "typeinfo_address": "0x5020",
                "typeinfo_kind": "vmi_class_type_info",
                "vmi_flags": 0,
                "base_count": 2,
                "bases": [
                    {
                        "base_pointer_address": "0x5038",
                        "base_typeinfo_address": "0x5000",
                        "offset_flags_address": "0x5040",
                        "offset": 0,
                        "offset_kind": "object_offset",
                        "object_offset": 0,
                        "vbase_offset_slot_offset": None,
                        "flags": 2,
                        "is_virtual": False,
                        "is_public": True,
                    },
                    {
                        "base_pointer_address": "0x5048",
                        "base_typeinfo_address": "0x5010",
                        "offset_flags_address": "0x5050",
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


def test_evaluator_keeps_user_mangled_cpp_and_suppresses_external_boundary():
    result = evaluate_export(_export(), ORACLE, stripped=False)
    assert result["passed"] is True
    assert result["counts"]["functions_user_or_unknown"] == 2
    assert result["counts"]["functions_user_logical"] == 2
    assert result["counts"]["functions_user_fragments"] == 0
    assert result["counts"]["functions_library_or_thunk"] == 1


def test_evaluator_separates_runtime_noise_from_user_fragments():
    data = _export()
    data["metadata"]["emitted_function_count"] = 9
    data["functions"].extend([
        {
            "name": "_DT_INIT",
            "entry": "0x1300",
            "memory_block": ".init",
        },
        {
            "name": "caseD_0",
            "entry": "0x1400",
            "namespace": "switchD_1700",
        },
        {
            "name": "FUN_1500",
            "entry": "0x1500",
            "callers": [],
            "xrefs_to": [{
                "type": "CONDITIONAL_JUMP",
                "from_function": "FUN_1700",
            }],
        },
        {
            "name": "FUN_1600",
            "entry": "0x1600",
            "callers": [],
            "xrefs_to": [],
        },
        {
            "name": "user_split",
            "entry": "0x1700",
            "callers": [],
            "body_ranges": [{"start": "0x1700", "end": "0x1710"}],
            "xrefs_to": [{
                "from": "0x1900",
                "type": "UNCONDITIONAL_JUMP",
                "from_function": "user_split",
            }],
        },
        {
            "name": "user_loop",
            "entry": "0x1800",
            "callers": [],
            "body_ranges": [{"start": "0x1800", "end": "0x1810"}],
            "xrefs_to": [{
                "from": "0x1808",
                "type": "CONDITIONAL_JUMP",
                "from_function": "user_loop",
            }],
        },
    ])

    result = evaluate_export(data, ORACLE, stripped=False)
    assert result["counts"]["functions_user_or_unknown"] == 7
    assert result["counts"]["functions_user_fragments"] == 3
    assert result["counts"]["functions_user_logical"] == 4
    assert result["counts"]["functions_library_or_thunk"] == 2


def test_stripped_tm_clone_scaffold_is_runtime_not_user_code():
    is_library, reason = classify_library_function({
        "name": "FUN_00101510",
        "memory_block": ".text",
        "callers": ["_INIT_0"],
        "callees": ["_ITM_registerTMCloneTable"],
    })
    assert is_library is True
    assert reason == "runtime_scaffolding_behavior"

    # IDA may miss the final weak indirect jump, but the named GOT dependency
    # still proves this is compiler TM-clone scaffolding.
    is_library, reason = classify_library_function({
        "name": "sub_1510",
        "size": 57,
        "callers": ["sub_1590"],
        "callees": [],
        "referenced_symbols": [
            "unk_5038",
            "_ITM_registerTMCloneTable_ptr",
        ],
    })
    assert is_library is True
    assert reason == "runtime_scaffolding_behavior"

    # Native finalization glue is recognized from the actual .fini_array
    # provenance plus __cxa_finalize, not merely because it has no callers.
    is_library, reason = classify_library_function({
        "name": "sub_1550",
        "size": 57,
        "callers": [],
        "callees": ["__cxa_finalize", "sub_14E0"],
        "xrefs_to": [{
            "from": "0x4c38",
            "type": "OFFSET",
            "from_memory_block": ".fini_array",
        }],
    })
    assert is_library is True
    assert reason == "runtime_scaffolding_behavior"

    # User-owned destructors remain user code even when registered in the
    # finalizer array.
    is_library, reason = classify_library_function({
        "name": "sub_9000",
        "size": 80,
        "callers": [],
        "callees": ["user_flush_telemetry"],
        "xrefs_to": [{
            "from": "0xa000",
            "type": "OFFSET",
            "from_memory_block": ".fini_array",
        }],
    })
    assert is_library is False
    assert reason == "user_or_unknown"

    # A user constructor is not noise merely because Ghidra names its caller
    # like an init routine.
    is_library, reason = classify_library_function({
        "name": "FUN_00102000",
        "memory_block": ".text",
        "callers": ["_INIT_0"],
        "callees": ["user_register_plugin"],
    })
    assert is_library is False
    assert reason == "user_or_unknown"

    is_library, reason = classify_library_function({
        "name": "_FINI_0",
        "memory_block": ".text",
        "callers": [],
        "callees": ["FUN_deregister_tm_clones"],
    })
    assert is_library is True
    assert reason == "known_runtime_symbol"


def test_shared_epilogue_requires_jump_evidence_not_a_normal_call():
    candidate = {
        "name": "FUN_001017bd",
        "size": 2,
        "callers": ["dispatch_command"],
        "callees": [],
        "xrefs_to": [{
            "from": "001012a5",
            "type": "UNCONDITIONAL_JUMP",
            "engine_reference_type": "UNCONDITIONAL_CALL",
            "from_function": "dispatch_command",
        }],
    }
    is_fragment, reason = classify_user_fragment(candidate)
    assert is_fragment is True
    assert reason == "shared_epilogue_fragment"

    candidate["xrefs_to"][0]["type"] = "UNCONDITIONAL_CALL"
    is_fragment, reason = classify_user_fragment(candidate)
    assert is_fragment is False
    assert reason == "user_primary"


def test_stripped_mode_does_not_require_original_source_names():
    data = _export()
    data["functions"][0]["name"] = "sub_1000"
    data["functions"][1]["name"] = "sub_1100"
    data["functions"][0]["decompiled"] = "int f() { return 0; }"
    data["functions"][1]["decompiled"] = "int g() { return 1; }"
    result = evaluate_export(data, ORACLE, stripped=True)
    assert result["passed"] is True
    assert "all_expected_function_names" not in result["required"]


def test_stripped_pipeline_requires_sink_reachability_from_inferred_entry():
    disconnected = _export()
    result = evaluate_pipeline(disconnected, ORACLE, stripped=True)
    assert result["required"]["unsafe_sink_reachable_from_inferred_entry"] is False
    assert result["required"]["unsafe_sink_reaches_callable_boundary"] is False

    connected = _export()
    connected["functions"][0].update({
        "size": 16,
        "callers": [],
        "callees": [".strcpy"],
    })
    connected["functions"][2].update({
        "size": 16,
        "callers": ["main"],
        "callees": [],
    })
    result = evaluate_pipeline(connected, ORACLE, stripped=True)
    assert result["required"]["unsafe_sink_reachable_from_inferred_entry"] is True
    assert result["required"]["unsafe_sink_reaches_callable_boundary"] is True


def test_pipeline_requires_expected_exception_sink_from_ranked_entry():
    oracle = {
        **ORACLE,
        "expected_reachable_sink_tokens": ["strcpy", "__fprintf_chk"],
    }
    connected = _export()
    connected["metadata"].update({
        "entry_point": "0x1000",
        "emitted_function_count": 5,
    })
    connected["functions"][0].update({
        "size": 16,
        "callers": [],
        "callees": [".strcpy", "exception_handler"],
    })
    connected["functions"][2].update({
        "size": 16,
        "callers": ["main"],
        "callees": [],
    })
    connected["functions"].extend([
        {
            "name": "exception_handler",
            "entry": "0x1300",
            "size": 32,
            "callers": ["main"],
            "callees": ["__cxa_begin_catch", "_Unwind_Resume", "__fprintf_chk"],
        },
        {
            "name": "__fprintf_chk",
            "entry": "0x1400",
            "size": 16,
            "is_external": True,
            "callers": ["exception_handler"],
            "callees": [],
        },
    ])
    connected["imports"].append({"name": "__fprintf_chk"})

    result = evaluate_pipeline(connected, oracle, stripped=True)
    assert result["required"][
        "all_expected_sinks_reachable_from_ranked_entry"
    ] is True
    assert result["required"][
        "exception_handler_sink_reachable_from_ranked_entry"
    ] is True

    connected["functions"][0]["callees"] = [".strcpy"]
    connected["functions"][3]["callers"] = []
    result = evaluate_pipeline(connected, oracle, stripped=True)
    assert result["required"][
        "exception_handler_sink_reachable_from_ranked_entry"
    ] is False


def test_pipeline_recovers_program_boundary_roles_without_renaming():
    oracle = {
        **ORACLE,
        "expected_program_roles": ["process_entry", "program_main"],
    }
    data = _export()
    data["metadata"].update({
        "image_base": "0x0",
        "entry_point": "0x900",
        "emitted_function_count": 4,
    })
    data["functions"][0].update({
        "size": 32,
        "callers": [],
        "callees": [],
        "xrefs_to": [{
            "from": "0x908",
            "type": "OFFSET",
            "from_function": "start",
        }],
    })
    data["functions"].append({
        "name": "start",
        "entry": "0x900",
        "size": 32,
        "callers": [],
        "callees": ["__libc_start_main"],
    })

    result = evaluate_pipeline(data, oracle, stripped=True)
    assert result["required"]["expected_program_roles_recovered"] is True
    assert result["program_roles"]["process_entry"]["image_offset"] == 0x900
    assert result["program_roles"]["program_main"]["image_offset"] == 0x1000
    assert result["program_roles"]["program_main"]["name"] == "main"
    assert result["program_roles"]["program_main"]["evidence"]["kind"] == (
        "libc_start_main_argument"
    )


def test_pipeline_requires_expected_strings_to_have_user_code_xrefs():
    oracle = {
        **ORACLE,
        "expected_user_referenced_strings": ["banner"],
    }
    data = _export()
    data["functions"][0]["size"] = 16
    data["functions"][2]["size"] = 16
    data["strings"][0].update({
        "address": "0x2000",
        "memory_block": ".rodata",
        "xrefs_to": [{
            "from": "0x1208",
            "type": "DATA",
            "from_function": ".strcpy",
            "from_memory_block": ".plt",
        }],
    })

    result = evaluate_pipeline(data, oracle, stripped=False)
    assert result["required"][
        "all_expected_strings_referenced_by_user_code"
    ] is False
    assert result["user_referenced_strings"] == []

    data["strings"][0]["xrefs_to"] = [{
        "from": "0x1008",
        "type": "DATA",
        "from_function": "main",
        "from_memory_block": ".text",
    }]
    result = evaluate_pipeline(data, oracle, stripped=False)
    assert result["required"][
        "all_expected_strings_referenced_by_user_code"
    ] is True
    assert result["user_referenced_strings"][0]["value"] == "banner"
    assert result["user_referenced_strings"][0]["sources"][0]["name"] == "main"


def test_pipeline_does_not_count_abi_runtime_types_as_user_classes():
    data = _export()
    data["strings"].append({
        "address": "0x2100",
        "value": "N10__cxxabiv117__class_type_infoE",
        "length": 31,
    })
    oracle = {
        **ORACLE,
        "minimums": {
            **ORACLE["minimums"],
            "cpp_classes": 1,
        },
    }

    result = evaluate_pipeline(data, oracle, stripped=False)
    assert result["required"]["minimum_cpp_classes"] is False
    assert result["counts"]["cpp_classes"] == 0
    assert result["counts"]["cpp_classes_raw"] == 1
    assert result["counts"]["cpp_runtime_support_classes"] == 1
    assert result["recovered_cpp_classes"][0]["role"] == "runtime_support"


def test_pipeline_requires_evidence_backed_user_vtable_minimum():
    data = _export()
    data["metadata"]["image_base"] = "0x0"
    data["symbols"] = [
        {
            "name": "_ZTVN7fixture12XorProcessorE",
            "address": "0x2200",
            "type": "Label",
            "primary": False,
        },
        {
            "name": "vtable",
            "address": "0x2200",
            "type": "Label",
            "primary": True,
        },
    ]
    oracle = {
        **ORACLE,
        "minimums": {
            **ORACLE["minimums"],
            "cpp_classes": 1,
            "cpp_vtables": 1,
        },
    }

    result = evaluate_pipeline(data, oracle, stripped=False)
    assert result["required"]["minimum_cpp_classes"] is True
    assert result["required"]["minimum_user_cpp_vtables"] is True
    assert result["counts"]["cpp_vtables"] == 1
    recovered = result["recovered_cpp_classes"][0]
    assert recovered["class_name"] == "fixture::XorProcessor"
    assert recovered["vtable_image_offsets"] == [0x2200]

    data["symbols"] = [data["symbols"][1]]
    result = evaluate_pipeline(data, oracle, stripped=False)
    assert result["required"]["minimum_user_cpp_vtables"] is False
    assert result["counts"]["cpp_vtables"] == 0


def test_pipeline_enforces_exact_vmi_class_edge_and_layout_oracles():
    oracle = {
        **ORACLE,
        "minimums": {
            **ORACLE["minimums"],
            "cpp_classes": 3,
        },
        "expected_cpp_classes": [
            "fixture::Processor",
            "fixture::Auditable",
            "fixture::AuditedProcessor",
        ],
        "expected_cpp_inheritance": [
            {
                "parent": "fixture::Processor",
                "child": "fixture::AuditedProcessor",
            },
            {
                "parent": "fixture::Auditable",
                "child": "fixture::AuditedProcessor",
            },
        ],
        "expected_cpp_base_layouts": [
            {
                "class": "fixture::AuditedProcessor",
                "base": "fixture::Processor",
                "offset": 0,
                "offset_kind": "object_offset",
                "object_offset": 0,
                "vbase_offset_slot_offset": None,
                "flags": 2,
                "is_virtual": False,
                "is_public": True,
            },
            {
                "class": "fixture::AuditedProcessor",
                "base": "fixture::Auditable",
                "offset": 8,
                "offset_kind": "object_offset",
                "object_offset": 8,
                "vbase_offset_slot_offset": None,
                "flags": 2,
                "is_virtual": False,
                "is_public": True,
            },
        ],
    }
    result = evaluate_pipeline(_vmi_export(), oracle, stripped=False)
    assert result["required"]["expected_cpp_class_set_recovered"] is True
    assert result["required"]["expected_cpp_inheritance_recovered"] is True
    assert result["required"]["expected_cpp_base_layouts_recovered"] is True

    subset_oracle = {
        **oracle,
        "expected_cpp_classes": oracle["expected_cpp_classes"][:-1],
        "expected_cpp_inheritance": oracle["expected_cpp_inheritance"][:-1],
        "expected_cpp_base_layouts": oracle["expected_cpp_base_layouts"][:-1],
    }
    subset_result = evaluate_pipeline(
        _vmi_export(), subset_oracle, stripped=False
    )
    assert subset_result["required"][
        "expected_cpp_class_set_recovered"
    ] is False
    assert subset_result["required"][
        "expected_cpp_inheritance_recovered"
    ] is False
    assert subset_result["required"][
        "expected_cpp_base_layouts_recovered"
    ] is False


def test_cross_engine_comparison_is_an_enforced_quality_gate():
    data = _export()
    data["functions"][0].update({
        "size": 16,
        "callers": [],
        "callees": [".strcpy"],
    })
    data["functions"][2].update({
        "size": 16,
        "callers": ["main"],
        "callees": [],
    })
    data["strings"][0].update({
        "address": "0x2000",
        "memory_block": ".rodata",
        "xrefs_to": [{
            "from": "0x1008",
            "type": "DATA",
            "from_function": "main",
            "from_memory_block": ".text",
        }],
    })

    def result() -> dict:
        return {
            "evaluation": evaluate_export(data, ORACLE, stripped=False),
            "pipeline": evaluate_pipeline(data, ORACLE, stripped=False),
        }

    results = {"ghidra": result(), "ida": result()}
    for engine_result in results.values():
        engine_result["pipeline"]["program_roles"] = {
            "process_entry": {"image_offset": 0x900},
            "program_main": {"image_offset": 0x1000},
        }
        engine_result["pipeline"]["recovered_cpp_classes"] = [
            {
                "class_name": "fixture::Processor",
                "role": "user_candidate",
                "vtable_image_offsets": [0x3000],
            },
            {
                "class_name": "__cxxabiv1::__class_type_info",
                "role": "runtime_support",
            },
        ]
        engine_result["pipeline"]["cpp_user_inheritance_edges"] = [{
            "parent": "fixture::Processor",
            "child": "fixture::XorProcessor",
        }]
        engine_result["pipeline"]["cpp_user_base_layouts"] = [{
            "class": "fixture::AuditedProcessor",
            "base": "fixture::Auditable",
            "offset": 8,
            "offset_kind": "object_offset",
            "object_offset": 8,
            "vbase_offset_slot_offset": None,
            "flags": 2,
            "is_virtual": False,
            "is_public": True,
        }]
        engine_result["pipeline"]["cpp_user_vtable_layouts"] = [{
            "class": "fixture::AuditedProcessor",
            "vtable_image_offset": 0x3000,
            "address_point_image_offset": 0x3010,
            "offset_to_top": -8,
            "table_kind": "secondary",
            "first_method_target_image_offset": 0x1100,
            "method_count": 3,
            "method_target_image_offsets": [0x1100, 0x1110, 0x1120],
            "slot_boundary_reason": (
                "code_reference_to_next_data_object"
            ),
        }]
        engine_result["pipeline"][
            "cpp_user_vtable_prefix_layouts"
        ] = [{
            "class": "fixture::VirtualAuditedProcessor",
            "table_kind": "primary",
            "offset_to_top": 0,
            "prefix_boundary_reason": "vmi_virtual_base_slots",
            "entries": [{
                "relative_to_address_point": -24,
                "pointer_image_offset": 0x2FF8,
                "value": 16,
                "entry_kind": "vbase_offset",
                "base": "fixture::Auditable",
            }],
        }]
        engine_result["pipeline"]["cpp_user_vtts"] = [{
            "class": "fixture::VirtualAuditedProcessor",
            "vtt_image_offset": 0x2F00,
            "evidence": (
                "contiguous_data_pointers_cover_distinct_"
                "same_rtti_vtable_address_points"
            ),
            "confidence": 0.99,
            "entries": [
                {
                    "pointer_image_offset": 0x2F00,
                    "address_point_image_offset": 0x3010,
                    "vtable_image_offset": 0x3000,
                    "offset_to_top": 0,
                    "table_kind": "primary",
                },
                {
                    "pointer_image_offset": 0x2F08,
                    "address_point_image_offset": 0x3060,
                    "vtable_image_offset": 0x3050,
                    "offset_to_top": -16,
                    "table_kind": "secondary",
                },
            ],
        }]
        engine_result["pipeline"]["cpp_user_this_adjustments"] = [{
            "class": "fixture::VirtualAuditedProcessor",
            "table_kind": "secondary",
            "offset_to_top": -16,
            "slot_index": 1,
            "target_image_offset": 0x3300,
            "kind": "virtual_vcall",
            "resolved": True,
            "fixed_delta": 0,
            "vcall_offset_slot": -24,
            "vcall_offset_value": -16,
            "candidate_vcall_offsets": [{
                "slot": -24,
                "value": -16,
            }],
            "evidence": (
                "x86_sysv_this_adjustment_instruction_pattern"
            ),
            "confidence": 0.99,
        }]
    comparison = compare_engines(results)
    assert comparison["passed"] is True
    assert comparison["required"]["reachable_sink_set_parity"] is True
    assert comparison["required"]["source_provenance_class_parity"] is True
    assert comparison["required"][
        "unsafe_sink_path_distance_within_one_hop"
    ] is True
    assert comparison["required"][
        "unsafe_sink_semantic_distance_parity"
    ] is True
    assert comparison["required"][
        "logical_user_function_count_within_15_percent"
    ] is True
    assert comparison["required"]["logical_user_function_count_parity"] is True
    assert comparison["required"]["program_boundary_role_parity"] is True
    assert comparison["required"]["user_referenced_string_set_parity"] is True
    assert comparison["required"]["user_cpp_class_set_parity"] is True
    assert comparison["required"]["user_cpp_vtable_offset_parity"] is True
    assert comparison["required"]["user_cpp_inheritance_parity"] is True
    assert comparison["required"]["user_cpp_base_layout_parity"] is True
    assert comparison["required"]["user_cpp_vtable_layout_parity"] is True
    assert comparison["required"][
        "user_cpp_vtable_prefix_layout_parity"
    ] is True
    assert comparison["required"]["user_cpp_vtt_parity"] is True
    assert comparison["required"][
        "user_cpp_this_adjustment_parity"
    ] is True

    results["ida"]["evaluation"]["counts"]["functions_user_logical"] = 1
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"][
        "logical_user_function_count_within_15_percent"
    ] is False
    assert comparison["required"]["logical_user_function_count_parity"] is False
    results["ida"]["evaluation"]["counts"]["functions_user_logical"] = 2

    results["ida"]["pipeline"]["program_roles"]["program_main"]["image_offset"] = 0x1004
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["program_boundary_role_parity"] is False
    results["ida"]["pipeline"]["program_roles"]["program_main"]["image_offset"] = 0x1000

    results["ida"]["pipeline"]["user_referenced_strings"][0]["value"] = "different"
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_referenced_string_set_parity"] is False
    results["ida"]["pipeline"]["user_referenced_strings"][0]["value"] = "banner"

    results["ida"]["pipeline"]["recovered_cpp_classes"][0][
        "class_name"
    ] = "fixture::Different"
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_class_set_parity"] is False
    results["ida"]["pipeline"]["recovered_cpp_classes"][0][
        "class_name"
    ] = "fixture::Processor"

    results["ida"]["pipeline"]["recovered_cpp_classes"][0][
        "vtable_image_offsets"
    ] = [0x3008]
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_vtable_offset_parity"] is False
    results["ida"]["pipeline"]["recovered_cpp_classes"][0][
        "vtable_image_offsets"
    ] = [0x3000]

    results["ida"]["pipeline"]["cpp_user_inheritance_edges"][0][
        "parent"
    ] = "fixture::Different"
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_inheritance_parity"] is False
    results["ida"]["pipeline"]["cpp_user_inheritance_edges"][0][
        "parent"
    ] = "fixture::Processor"

    results["ida"]["pipeline"]["cpp_user_base_layouts"][0]["offset"] = 16
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_base_layout_parity"] is False
    results["ida"]["pipeline"]["cpp_user_base_layouts"][0]["offset"] = 8

    results["ida"]["pipeline"]["cpp_user_base_layouts"][0][
        "offset_kind"
    ] = "vbase_offset_slot"
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_base_layout_parity"] is False
    results["ida"]["pipeline"]["cpp_user_base_layouts"][0][
        "offset_kind"
    ] = "object_offset"

    results["ida"]["pipeline"]["cpp_user_base_layouts"][0][
        "object_offset"
    ] = 16
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_base_layout_parity"] is False
    results["ida"]["pipeline"]["cpp_user_base_layouts"][0][
        "object_offset"
    ] = 8

    results["ida"]["pipeline"]["cpp_user_vtable_prefix_layouts"][0][
        "entries"
    ][0]["value"] = 24
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"][
        "user_cpp_vtable_prefix_layout_parity"
    ] is False
    results["ida"]["pipeline"]["cpp_user_vtable_prefix_layouts"][0][
        "entries"
    ][0]["value"] = 16

    results["ida"]["pipeline"]["cpp_user_vtts"][0]["entries"][1][
        "address_point_image_offset"
    ] = 0x3068
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_vtt_parity"] is False
    results["ida"]["pipeline"]["cpp_user_vtts"][0]["entries"][1][
        "address_point_image_offset"
    ] = 0x3060

    results["ida"]["pipeline"]["cpp_user_this_adjustments"][0][
        "vcall_offset_slot"
    ] = -32
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"][
        "user_cpp_this_adjustment_parity"
    ] is False
    results["ida"]["pipeline"]["cpp_user_this_adjustments"][0][
        "vcall_offset_slot"
    ] = -24

    results["ida"]["pipeline"]["cpp_user_vtable_layouts"][0][
        "address_point_image_offset"
    ] = 0x3018
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_vtable_layout_parity"] is False
    results["ida"]["pipeline"]["cpp_user_vtable_layouts"][0][
        "address_point_image_offset"
    ] = 0x3010

    results["ida"]["pipeline"]["cpp_user_vtable_layouts"][0][
        "method_target_image_offsets"
    ][1] = 0xDEAD
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["user_cpp_vtable_layout_parity"] is False
    results["ida"]["pipeline"]["cpp_user_vtable_layouts"][0][
        "method_target_image_offsets"
    ][1] = 0x1110

    results["ida"]["pipeline"]["sink_report"]["categories"] = {}
    comparison = compare_engines(results)
    assert comparison["passed"] is False
    assert comparison["required"]["reachable_sink_set_parity"] is False


def test_cross_engine_comparison_fails_cleanly_on_engine_error():
    comparison = compare_engines({
        "ghidra": {"error": "failed"},
        "ida": {"evaluation": {}, "pipeline": {}},
    })
    assert comparison["passed"] is False
    assert comparison["required"]["both_engines_completed"] is False
