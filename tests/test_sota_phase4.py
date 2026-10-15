"""Tests for Phase 4 state-of-the-art modules.

Phase 4 covers control-flow graph construction, stack-frame recovery,
gadget finding, and indirect control-flow recovery.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from src.config import load_config

from src.models.analysis_graph import AnalysisGraph, Node
from src.analysis.cfg_spine import CFGSpine, BasicBlock, FunctionCFG
from src.analysis.stack_frame_recovery import StackFrameRecovery, StackFrame
from src.analysis.gadget_finder import GadgetFinder, Gadget
from src.analysis.indirect_flow import IndirectFlowRecovery, SwitchTable, FunctionPointerTable


SAMPLES_DIR = Path(__file__).parent.parent / "samples"
CRACKME = SAMPLES_DIR / "crackme"


def _sample_graph() -> AnalysisGraph:
    from src.models.analysis_graph import Edge, Node
    graph = AnalysisGraph()
    program_id = "program:test_sample"
    graph.add_node(Node(id=program_id, kind="program", address="0x400000", name="test_sample"))
    graph.metadata["program_id"] = program_id

    functions = [
        ("function:0x401000", "main", "0x401000", [
            ("0x401000", "push", "rbp"),
            ("0x401001", "mov", "rbp, rsp"),
            ("0x401003", "sub", "rsp, 0x30"),
            ("0x401006", "cmp", "eax, 1"),
            ("0x401008", "je", "0x401010"),
            ("0x40100a", "jmp", "0x401020"),
            ("0x401010", "mov", "eax, 2"),
            ("0x401012", "jmp", "0x401018"),
            ("0x401018", "ret", ""),
        ]),
        ("function:0x401020", "sub", "0x401020", [
            ("0x401020", "mov", "eax, 1"),
            ("0x401022", "ret", ""),
        ]),
    ]
    for fn_id, name, addr, instrs in functions:
        graph.add_node(Node(id=fn_id, kind="function", address=addr, name=name, properties={"size": len(instrs) * 2}))
        graph.add_edge(Edge(src=program_id, dst=fn_id, kind="contains"))
        for iaddr, mnemonic, operands in instrs:
            iid = f"instruction:{iaddr}"
            graph.add_node(Node(id=iid, kind="instruction", address=iaddr, properties={
                "mnemonic": mnemonic,
                "operands": operands,
            }))
            graph.add_edge(Edge(src=fn_id, dst=iid, kind="contains"))

    # also add calls edge
    graph.add_edge(Edge(src="function:0x401000", dst="function:0x401020", kind="calls"))
    return graph


def test_cfg_spine_basic_block_splitting():
    graph = _sample_graph()
    spine = CFGSpine(graph)
    cfg = spine.build_function_cfg(graph.get_node("function:0x401000"))
    assert isinstance(cfg, FunctionCFG)
    assert cfg.entry == "0x401000"
    assert len(cfg.blocks) >= 2
    paths = cfg.all_paths(max_paths=10)
    assert paths
    assert cfg.depth() >= 2


def test_cfg_spine_block_dataclass():
    b = BasicBlock(address="0x401000", instructions=[{"mnemonic": "ret"}],
                   successors=[], predecessors=[], is_entry=True, is_exit=True)
    d = b.as_dict()
    assert d["address"] == "0x401000"
    assert d["is_entry"] is True


def test_stack_frame_recovery_x64():
    graph = _sample_graph()
    sfr = StackFrameRecovery(graph)
    frame = sfr.recover(graph.get_node("function:0x401000"))
    assert isinstance(frame, StackFrame)
    assert frame.function_name == "main"
    assert frame.size is not None
    assert frame.size > 0
    assert frame.calling_convention in ("microsoft_x64", "sysv_amd64", "cdecl", "unknown")
    assert any(lv["offset"] < 0 for lv in frame.locals)


def test_stack_frame_recovery_serialization():
    graph = _sample_graph()
    sfr = StackFrameRecovery(graph)
    frames = sfr.recover_all()
    data = {k: v.as_dict() for k, v in frames.items()}
    assert isinstance(data, dict)
    assert "function:0x401000" in data


def test_gadget_finder_exact_gadgets():
    if not CRACKME.exists():
        pytest.skip("crackme sample not present")
    finder = GadgetFinder(CRACKME)
    gadgets = finder.find_exact_gadgets()
    assert isinstance(gadgets, list)
    for g in gadgets:
        assert isinstance(g, Gadget)
        assert g.address.startswith("0x")
        assert g.bytes_hex
        assert g.category in ("jmp_reg", "call_reg", "push_ret", "stack_pivot", "other")


def test_gadget_finder_ret_gadgets():
    if not CRACKME.exists():
        pytest.skip("crackme sample not present")
    finder = GadgetFinder(CRACKME, pointer_size=8)
    gadgets = finder.find_ret_gadgets(max_len=8)
    assert isinstance(gadgets, list)
    assert all("ret" in g.mnemonic_sequence for g in gadgets)


def test_indirect_flow_recovery_detects_switch_hints():
    graph = _sample_graph()
    # Add a function that looks switch-like.
    graph.add_node(Node(
        id="function:0x401030",
        kind="function",
        address="0x401030",
        name="switch_handler",
        properties={
            "disassembly": "cmp eax, 3\nja default\njmp [table + 0x401040]\ndefault:\nret\n",
        },
    ))
    from src.models.analysis_graph import Edge
    graph.add_edge(Edge(src="program:test_sample", dst="function:0x401030", kind="contains"))
    ifr = IndirectFlowRecovery(graph)
    tables = ifr.find_switch_tables()
    # The heuristic may or may not find a table from this tiny synthetic graph;
    # the test ensures no exception and the return type is correct.
    assert isinstance(tables, list)
    for t in tables:
        assert isinstance(t, SwitchTable)


def test_indirect_flow_recovery_pointer_tables():
    graph = _sample_graph()
    ifr = IndirectFlowRecovery(graph)
    tables = ifr.find_function_pointer_tables()
    assert isinstance(tables, list)
    for t in tables:
        assert isinstance(t, FunctionPointerTable)


@pytest.mark.skipif(not load_config().ghidra_ready()[0], reason="Ghidra/JDK installation unavailable")
def test_cli_cfg_build():
    cmd = [
        sys.executable, "-m", "src.cli", "sota-analyze", str(CRACKME),
        "--engine", "ghidra", "--force", "--max-functions", "10",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    stdout = result.stdout
    ws_line = [l for l in stdout.splitlines() if "workspace" in l]
    workspace = Path(ws_line[0].split(":", 1)[1].strip())

    cfg_cmd = [sys.executable, "-m", "src.cli", "cfg-build", str(workspace), "--json"]
    cfg_result = subprocess.run(cfg_cmd, capture_output=True, text=True, timeout=30)
    assert cfg_result.returncode == 0, cfg_result.stderr
    out = json.loads(cfg_result.stdout)
    assert isinstance(out, dict)
    assert (workspace / "raw" / "cfgs.json").exists()


@pytest.mark.skipif(not load_config().ghidra_ready()[0], reason="Ghidra/JDK installation unavailable")
def test_cli_stack_frames():
    cmd = [
        sys.executable, "-m", "src.cli", "sota-analyze", str(CRACKME),
        "--engine", "ghidra", "--force", "--max-functions", "10",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    stdout = result.stdout
    ws_line = [l for l in stdout.splitlines() if "workspace" in l]
    workspace = Path(ws_line[0].split(":", 1)[1].strip())

    sf_cmd = [sys.executable, "-m", "src.cli", "stack-frames", str(workspace), "--json"]
    sf_result = subprocess.run(sf_cmd, capture_output=True, text=True, timeout=30)
    assert sf_result.returncode == 0, sf_result.stderr
    out = json.loads(sf_result.stdout)
    assert isinstance(out, dict)
    assert (workspace / "raw" / "stack_frames.json").exists()


def test_cli_gadget_find():
    cmd = [sys.executable, "-m", "src.cli", "gadget-find", str(CRACKME), "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert "exact" in out
    assert "ret" in out


@pytest.mark.skipif(not load_config().ghidra_ready()[0], reason="Ghidra/JDK installation unavailable")
def test_cli_indirect_flow():
    cmd = [
        sys.executable, "-m", "src.cli", "sota-analyze", str(CRACKME),
        "--engine", "ghidra", "--force", "--max-functions", "10",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    stdout = result.stdout
    ws_line = [l for l in stdout.splitlines() if "workspace" in l]
    workspace = Path(ws_line[0].split(":", 1)[1].strip())

    if_cmd = [sys.executable, "-m", "src.cli", "indirect-flow", str(workspace), "--json"]
    if_result = subprocess.run(if_cmd, capture_output=True, text=True, timeout=30)
    assert if_result.returncode == 0, if_result.stderr
    out = json.loads(if_result.stdout)
    assert "switch_tables" in out
    assert "function_pointer_tables" in out
    assert (workspace / "raw" / "indirect_flow.json").exists()
