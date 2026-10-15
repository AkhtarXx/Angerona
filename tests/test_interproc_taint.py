"""Coverage for inter-procedural taint tracking over the canonical SSA IR."""

import pytest

from src.analysis.canonical_ir import SSAConverter, TaintEngine
from src.analysis.interproc_taint import (
    CallGraphIndex,
    InterprocTaintEngine,
    InterprocTaintError,
    find_interproc_paths,
)
from src.models.analysis_graph import AnalysisGraph, Edge, Node


def _single_function_ir():
    return {
        "function:test": SSAConverter().convert(
            "function:test",
            {
                "entry": [
                    {"id": "copy", "opcode": "COPY", "inputs": ["arg"], "output": "x"},
                    {"id": "sink", "opcode": "CALLIND", "inputs": ["x"]},
                ],
            },
            {"entry": []},
            entry_block="entry",
        )
    }


def test_single_function_matches_intraprocedural_engine() -> None:
    irs = _single_function_ir()
    intra = TaintEngine().analyze(irs["function:test"], sources={"arg@0"})
    findings = InterprocTaintEngine().analyze(
        {"function:test": []},
        irs,
        sources={"function:test": {"arg@0"}},
    )
    assert [finding.sink_operation for finding in findings] == [
        finding.sink_operation for finding in intra
    ]
    assert findings[0].sink_function_id == "function:test"
    assert findings[0].path == ()
    assert all(op.startswith("function:test:") for op in findings[0].slice_operations)


def test_source_in_caller_flows_through_sysv_arg_registers() -> None:
    caller = SSAConverter().convert(
        "function:caller",
        {
            "entry": [
                {"id": "load", "opcode": "COPY", "inputs": ["taint_src"], "output": "rdi"},
                {"id": "load2", "opcode": "COPY", "inputs": ["other"], "output": "rsi"},
                {"id": "call", "opcode": "CALL", "inputs": ["rdi", "rsi"], "output": "rax"},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    callee = SSAConverter().convert(
        "function:callee",
        {
            "entry": [
                {"id": "use", "opcode": "STORE", "inputs": ["rdi"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    findings = InterprocTaintEngine().analyze(
        {"function:caller": ["function:callee"]},
        {
            "function:caller": caller,
            "function:callee": callee,
        },
        sources={"function:caller": {"taint_src@0"}},
        sink_opcodes={"STORE"},
    )
    assert any(
        finding.sink_function_id == "function:callee"
        and finding.sink_operation == "use"
        and finding.path == (("function:caller", "function:callee"),)
        for finding in findings
    )


def test_tainted_return_in_callee_flows_back_to_caller() -> None:
    caller = SSAConverter().convert(
        "function:caller",
        {
            "entry": [
                {"id": "call", "opcode": "CALL", "inputs": ["rdi"], "output": "rax"},
                {"id": "sink", "opcode": "STORE", "inputs": ["rax"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    callee = SSAConverter().convert(
        "function:callee",
        {
            "entry": [
                {"id": "produce", "opcode": "COPY", "inputs": ["secret"], "output": "rax"},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    findings = InterprocTaintEngine().analyze(
        {"function:caller": ["function:callee"]},
        {
            "function:caller": caller,
            "function:callee": callee,
        },
        sources={"function:callee": {"secret@0"}},
        sink_opcodes={"STORE"},
    )
    caller_sinks = [
        finding for finding in findings if finding.sink_function_id == "function:caller"
    ]
    assert caller_sinks
    assert caller_sinks[0].sink_operation == "sink"


def test_callsite_address_disambiguates_out_of_order_callees() -> None:
    # Source order is "call b; call a" while sorted callee ids are [a, b], so
    # positional pairing would bind call_b's tainted rdi into a and drop the
    # real flow into b.  Address annotations must instead bind each call to its
    # own callee.
    caller = SSAConverter().convert(
        "function:caller",
        {
            "entry": [
                {"id": "copy_b", "opcode": "COPY", "inputs": ["taint_b"], "output": "rdi"},
                {"id": "call_b", "opcode": "CALL", "inputs": ["rdi"], "address": "0x1001"},
                {"id": "call_a", "opcode": "CALL", "inputs": ["rsi"], "address": "0x1002"},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    fn_b = SSAConverter().convert(
        "function:b",
        {"entry": [{"id": "sink_b", "opcode": "STORE", "inputs": ["rdi"]}]},
        {"entry": []},
        entry_block="entry",
    )
    fn_a = SSAConverter().convert(
        "function:a",
        {"entry": [{"id": "sink_a", "opcode": "STORE", "inputs": ["rsi"]}]},
        {"entry": []},
        entry_block="entry",
    )
    graph = AnalysisGraph()
    for fid, addr in (
        ("function:caller", "0x1000"),
        ("function:a", "0x2000"),
        ("function:b", "0x3000"),
    ):
        graph.add_node(Node(id=fid, kind="function", address=addr))
    graph.add_edge(Edge(src="function:caller", dst="function:b", kind="calls", address="0x1001"))
    graph.add_edge(Edge(src="function:caller", dst="function:a", kind="calls", address="0x1002"))

    findings = InterprocTaintEngine().analyze(
        graph,
        {"function:caller": caller, "function:a": fn_a, "function:b": fn_b},
        sources={"function:caller": {"taint_b@0"}},
        sink_opcodes={"STORE"},
    )
    sink_ids = {(finding.sink_function_id, finding.sink_operation) for finding in findings}
    assert ("function:b", "sink_b") in sink_ids
    assert ("function:a", "sink_a") not in sink_ids


def test_multi_hop_path_is_recorded_in_finding() -> None:
    fn_a = SSAConverter().convert(
        "function:a",
        {
            "entry": [
                {"id": "seed", "opcode": "COPY", "inputs": ["taint"], "output": "rdi"},
                {"id": "call_b", "opcode": "CALL", "inputs": ["rdi"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    fn_b = SSAConverter().convert(
        "function:b",
        {
            "entry": [
                {"id": "forward", "opcode": "COPY", "inputs": ["rdi"], "output": "rdi"},
                {"id": "call_c", "opcode": "CALL", "inputs": ["rdi"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    fn_c = SSAConverter().convert(
        "function:c",
        {
            "entry": [
                {"id": "sink", "opcode": "CALLIND", "inputs": ["rdi"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    findings = InterprocTaintEngine().analyze(
        {
            "function:a": ["function:b"],
            "function:b": ["function:c"],
        },
        {
            "function:a": fn_a,
            "function:b": fn_b,
            "function:c": fn_c,
        },
        sources={"function:a": {"taint@0"}},
        sink_opcodes={"CALLIND"},
    )
    sink_c = [finding for finding in findings if finding.sink_function_id == "function:c"]
    assert sink_c
    assert sink_c[0].path == (
        ("function:a", "function:b"),
        ("function:b", "function:c"),
    )
    chain = find_interproc_paths(sink_c[0], CallGraphIndex({
        "function:a": ["function:b"],
        "function:b": ["function:c"],
    }))
    assert [hop.callee_function_id for hop in chain] == ["function:b", "function:c"]


def test_cycle_in_call_graph_terminates_within_cap() -> None:
    fn_ping = SSAConverter().convert(
        "function:ping",
        {"entry": [{"id": "call_pong", "opcode": "CALL", "inputs": ["rdi"], "output": "rax"}]},
        {"entry": []},
        entry_block="entry",
    )
    fn_pong = SSAConverter().convert(
        "function:pong",
        {"entry": [{"id": "call_ping", "opcode": "CALL", "inputs": ["rdi"], "output": "rax"}]},
        {"entry": []},
        entry_block="entry",
    )
    findings = InterprocTaintEngine().analyze(
        {
            "function:ping": ["function:pong"],
            "function:pong": ["function:ping"],
        },
        {
            "function:ping": fn_ping,
            "function:pong": fn_pong,
        },
        sources={"function:ping": {"rdi@0"}},
    )
    assert isinstance(findings, list)


def test_sanitizer_blocks_cross_function_propagation() -> None:
    caller = SSAConverter().convert(
        "function:caller",
        {
            "entry": [
                {"id": "seed", "opcode": "COPY", "inputs": ["taint"], "output": "rdi"},
                {"id": "call", "opcode": "CALL", "inputs": ["rdi"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    callee = SSAConverter().convert(
        "function:callee",
        {
            "entry": [
                {"id": "validate", "opcode": "VALIDATE", "inputs": ["rdi"], "output": "safe"},
                {"id": "sink", "opcode": "STORE", "inputs": ["safe"]},
            ],
        },
        {"entry": []},
        entry_block="entry",
    )
    findings = InterprocTaintEngine().analyze(
        {"function:caller": ["function:callee"]},
        {
            "function:caller": caller,
            "function:callee": callee,
        },
        sources={"function:caller": {"taint@0"}},
        sink_opcodes={"STORE"},
        sanitizer_opcodes={"VALIDATE"},
    )
    assert findings == []


def test_empty_input_returns_empty_list() -> None:
    engine = InterprocTaintEngine()
    assert engine.analyze(None, {}, sources={}) == []
    assert engine.analyze({}, {}, sources={}) == []
    assert engine.analyze({}, None, sources={}) == []
    assert engine.analyze({"function:a": ["function:b"]}, {"function:a": "not-an-ir"}, sources={}) == []


def test_non_convergence_raises_interproc_taint_error(monkeypatch: pytest.MonkeyPatch) -> None:
    irs = _single_function_ir()

    def _explode(self, ir, tainted, sanitizers):  # noqa: ANN001, ANN202
        tainted.add(f"forced@{len(tainted)}")
        return None

    monkeypatch.setattr(
        InterprocTaintEngine, "_propagate_intraprocedural", _explode
    )
    with pytest.raises(InterprocTaintError):
        InterprocTaintEngine().analyze(
            {"function:test": []},
            irs,
            sources={"function:test": {"arg@0"}},
        )


def test_call_graph_index_wraps_analysis_graph_edges() -> None:
    graph = AnalysisGraph()
    graph.add_node(Node(id="function:a", kind="function", address="0x1"))
    graph.add_node(Node(id="function:b", kind="function", address="0x2"))
    graph.add_node(Node(id="function:c", kind="function", address="0x3"))
    graph.add_edge(Edge(src="function:a", dst="function:b", kind="calls"))
    graph.add_edge(Edge(src="function:b", dst="function:c", kind="calls"))
    index = CallGraphIndex(graph)
    assert index.callees("function:a") == ("function:b",)
    assert index.callers("function:b") == ("function:a",)
    assert index.topological() == ["function:a", "function:b", "function:c"]
    cycle = CallGraphIndex({"function:a": ["function:b"], "function:b": ["function:a"]})
    ordered = cycle.topological()
    assert set(ordered) == {"function:a", "function:b"}
