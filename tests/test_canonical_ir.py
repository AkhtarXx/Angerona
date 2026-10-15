from src.analysis.canonical_ir import DefUseIndex, ProgramSlicer, SSAConverter, TaintEngine


def _diamond_ir():
    return SSAConverter().convert(
        "function:test",
        {
            "entry": [{"id": "source", "opcode": "COPY", "inputs": ["arg"], "output": "x"}],
            "left": [{"id": "left_add", "opcode": "INT_ADD", "inputs": ["x", "one"], "output": "x"}],
            "right": [{"id": "right_sub", "opcode": "INT_SUB", "inputs": ["x", "one"], "output": "x"}],
            "join": [
                {"id": "copy_y", "opcode": "COPY", "inputs": ["x"], "output": "y"},
                {"id": "sink", "opcode": "CALLIND", "inputs": ["y"]},
            ],
        },
        {"entry": ["left", "right"], "left": ["join"], "right": ["join"], "join": []},
        entry_block="entry",
    )


def test_ssa_inserts_phi_and_builds_unique_def_use() -> None:
    ir = _diamond_ir()
    phi = ir.operations["join:phi:x"]
    assert phi.opcode == "PHI"
    assert set(phi.inputs) == {"x@2", "x@3"}
    assert ir.operations["copy_y"].inputs == ("x@phi:join",)
    index = DefUseIndex.build(ir)
    assert index.definitions["x@phi:join"] == "join:phi:x"


def test_backward_slice_crosses_phi_and_both_branches() -> None:
    selected = ProgramSlicer(_diamond_ir()).backward(["sink"])
    assert {"source", "left_add", "right_sub", "join:phi:x", "copy_y", "sink"} <= selected


def test_taint_flows_from_external_argument_to_indirect_call() -> None:
    ir = _diamond_ir()
    findings = TaintEngine().analyze(ir, sources={"arg@0"})
    assert [finding.sink_operation for finding in findings] == ["sink"]
    assert "source" in findings[0].slice_operations


def test_sanitizer_stops_explicit_taint() -> None:
    ir = SSAConverter().convert(
        "function:sanitize",
        {"entry": [
            {"id": "clean", "opcode": "VALIDATE", "inputs": ["arg"], "output": "safe"},
            {"id": "sink", "opcode": "STORE", "inputs": ["safe"]},
        ]},
        {"entry": []},
        entry_block="entry",
    )
    assert TaintEngine().analyze(ir, sources={"arg@0"}, sanitizer_opcodes={"VALIDATE"}) == []
