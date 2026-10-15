from __future__ import annotations

from src.analysis.native_pre_re_classifier import _range_routing


def _function(address: int, size: int, digest: str) -> dict:
    return {
        "address": address,
        "size": size,
        "raw_function_sha256": digest,
        "raw_function_bytes": size,
        "normalized_cfg_sha256": "",
        "function_vector_sha256": "",
        "instruction_count": 1,
        "basic_block_count": 1,
        "callsite_count": 0,
    }


def test_range_routing_clips_matches_to_exact_executable_intersection():
    target = {
        "executable_sections": [{"address": 100, "size": 100}],
        "function_records": [
            _function(90, 30, "a" * 64),
            _function(300, 20, "b" * 64),
        ],
    }
    reference = {
        "function_records": [
            _function(90, 30, "a" * 64),
            _function(300, 20, "b" * 64),
        ],
    }

    routing = _range_routing(target, reference)

    assert routing["matched_function_records_outside_executable"] == 1
    assert routing["unmatched_function_records_outside_executable"] == 0
    assert routing["matched_library_function_ranges"] == [{
        **_function(90, 30, "a" * 64),
        "route": "SKIP_MATCHED_LIBRARY_FUNCTION",
        "match_basis": "exact-function-raw-bytes",
        "collision_negative_evidence": [],
        "source_function_address": 90,
        "source_function_size": 30,
        "address": 100,
        "size": 20,
        "clipped_to_executable": True,
        "executable_fragment_index": 0,
        "executable_fragment_count": 1,
    }]
    partition = routing["executable_partition"]
    assert partition["partition_counts"] == {
        "allowed_bytes": 0,
        "excluded_bytes": 20,
        "ambiguous_bytes": 80,
        "allowed_range_count": 0,
        "excluded_range_count": 1,
        "ambiguous_range_count": 1,
        "executable_bytes": 100,
    }
