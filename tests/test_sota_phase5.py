"""Phase 5 behavior tests: compiler personality + custom ISA framework."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from src.analysis.compiler_personality import (
    CompilerPersonalityDetector,
    _shannon_entropy,
)
from src.models.analysis_graph import AnalysisGraph
from src.processors._register_defaults import register_defaults
from src.processors.analyzer import CustomIsaAnalyzer
from src.processors.base import Instruction, ProcessorModule
from src.processors.evm import EvmProcessor
from src.processors.loader import VmBytecodeLoader
from src.processors.registry import ProcessorRegistry
from src.processors.solana_bpf import SolanaBpfProcessor


# ------------------------------------------------------------------ helpers

CLI = [sys.executable, "-m", "src"]


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*CLI, *args],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )


# ------------------------------------------------------------------ compiler personality unit tests

def test_shannon_entropy_uniform() -> None:
    data = bytes(range(256))
    entropy = _shannon_entropy(data)
    assert entropy == pytest.approx(8.0, abs=0.01)


def test_shannon_entropy_zero() -> None:
    assert _shannon_entropy(b"\x00" * 256) == pytest.approx(0.0, abs=0.01)


def test_detects_msvc_hints() -> None:
    strings = ["msvcrt.dll", "Visual C++", "KERNEL32"]
    detector = CompilerPersonalityDetector(strings=strings, sample_bytes=b"A" * 4096)
    result = detector.detect()
    assert result["compiler"]["name"] == "msvc"
    assert result["compiler"]["confidence"] > 0.0


def test_detects_packer_upx() -> None:
    strings = ["UPX!", "UPX0", "upx -d"]
    detector = CompilerPersonalityDetector(strings=strings, sample_bytes=b"A" * 4096)
    result = detector.detect()
    assert result["packer"]["name"] == "upx"


def test_suggests_bochs_for_high_entropy() -> None:
    # Random-ish high entropy content.
    sample = bytes((i * 77 + 13) % 256 for i in range(8192))
    detector = CompilerPersonalityDetector(sample_bytes=sample, strings=[])
    result = detector.detect()
    assert result["obfuscation"]["high_entropy"] is True
    assert result["suggested_backend"] == "bochs_idb"


# ------------------------------------------------------------------ processor unit tests

def test_register_defaults() -> None:
    ProcessorRegistry.clear()
    register_defaults()
    assert ProcessorRegistry.has("solana-bpf")
    assert ProcessorRegistry.has("evm")
    assert "solana-bpf" in ProcessorRegistry.list()


def test_solana_decode_add64() -> None:
    # add64 r1, 2  -> opcode 0x07 (ALU64 add64), dst=1, src=0, offset=0, imm=2
    insn_bytes = bytes([0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
    proc = SolanaBpfProcessor()
    insn = proc.decode(insn_bytes, 0x100)
    assert insn is not None
    assert insn.mnemonic == "add64"
    assert insn.operands == "r1, 0x2"
    assert insn.size == 8


def test_solana_decode_call() -> None:
    # call helper #33 -> opcode 0x85 (JMP call), imm=33
    insn_bytes = bytes([0x85, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00])
    proc = SolanaBpfProcessor()
    insn = proc.decode(insn_bytes, 0)
    assert insn is not None
    assert insn.mnemonic == "call"
    assert insn.operands == "0x21"
    assert "call" in {e["kind"] for e in insn.effects}
    call_effect = next(e for e in insn.effects if e["kind"] == "call")
    assert call_effect["target_kind"] == "helper"
    assert call_effect["symbolic_target"] == "helper_33"


def test_evm_decode_push1() -> None:
    proc = EvmProcessor()
    insn = proc.decode(bytes([0x60, 0x42]), 0x200)
    assert insn is not None
    assert insn.mnemonic == "PUSH1"
    assert insn.operands == "0x42"
    assert insn.size == 2


def test_evm_decode_jump() -> None:
    proc = EvmProcessor()
    insn = proc.decode(bytes([0x56]), 0x300)
    assert insn is not None
    assert insn.mnemonic == "JUMP"
    assert {"kind": "jump", "target": None} in insn.effects


# ------------------------------------------------------------------ loader integration tests

def test_loader_creates_program_and_instructions() -> None:
    register_defaults()
    proc = SolanaBpfProcessor()
    loader = VmBytecodeLoader(proc, base_addr=0x1000)
    # add64 r1,2 ; exit
    bytecode = bytes([
        0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    graph = loader.load(bytecode, program_name="test_program")
    assert graph.node_count > 0
    program = graph.get_node("program:test_program")
    assert program is not None
    main_fn = graph.get_node("func:main")
    assert main_fn is not None
    instructions = [n for n in graph.nodes if n.kind == "instruction"]
    assert len(instructions) == 2


# ------------------------------------------------------------------ analyzer integration tests

def test_analyze_custom_sbf() -> None:
    register_defaults()
    # Tiny SBF program: add64 r1, 2; call 0x5; exit
    bytecode = bytes([
        0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x85, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    analyzer = CustomIsaAnalyzer("solana-bpf")
    result = analyzer.analyze(bytecode, base_addr=0x1000)
    assert result["processor"] == "solana-bpf"
    graph = result["graph"]
    assert graph.node_count >= 4
    instructions = [n for n in graph.nodes if n.kind == "instruction"]
    assert len(instructions) == 3
    # Verify call edge is materialized for helper call.
    assert any(e.kind == "calls" for e in graph.edges)
    assert graph.get_node("import:helper_5") is not None
    assert graph.get_node("func:0x5") is None


def test_sbf_helper_calls_are_imports_not_function_stubs() -> None:
    register_defaults()
    # Three helper calls; old loader created three fake func:0xN nodes, inflating
    # callgraph function counts and confusing downstream agents.
    bytecode = b"".join([
        bytes([0x85, 0x00, 0x00, 0x00, imm, 0x00, 0x00, 0x00])
        for imm in (1, 2, 5)
    ]) + bytes([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    graph = VmBytecodeLoader(SolanaBpfProcessor(), base_addr=0x1000).load(bytecode)
    for imm in (1, 2, 5):
        assert graph.get_node(f"import:helper_{imm}") is not None
        assert graph.get_node(f"func:0x{imm:x}") is None


def test_sbf_branch_target_resolved() -> None:
    """Conditional branch in SBF must create edges to the target and fall-through."""
    register_defaults()
    proc = SolanaBpfProcessor()
    # bytecode: add64 r1, 1 (0x1000)
    #           jeq r1, 0x2, +1  -> if equal jump over exit to lddw at 0x1018
    #           exit              -> 0x1010
    #           lddw r2, 0x0      -> 0x1018
    add = bytes([0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    # jeq r1, 0x2, +1: opcode 0x15 (JMP JEQ), regs r1/r0? no src reg byte -> dst=r1, src=0 imm=2 offset=1
    jeq = bytes([0x15, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00])
    exit_ = bytes([0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    lddw = bytes([0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    bytecode = add + jeq + exit_ + lddw
    analyzer = CustomIsaAnalyzer("solana-bpf")
    result = analyzer.analyze(bytecode, base_addr=0x1000)
    graph = result["graph"]
    jump_edges = [e for e in graph.edges if e.kind in ("jump", "conditional_jump")]
    fallthrough_edges = [e for e in graph.edges if e.kind == "fall_through"]
    assert any(e.dst == "inst:0x1018" for e in jump_edges), "branch target edge missing"
    assert any(e.dst == "inst:0x1010" for e in fallthrough_edges), "fall-through edge missing"


def test_analyze_custom_evm() -> None:
    register_defaults()
    bytecode = bytes([
        0x60, 0x05,  # PUSH1 0x05 (jump destination)
        0x56,        # JUMP
        0x00,        # STOP
        0x00,        # STOP
        0x00,        # STOP target at address 0x05
    ])
    analyzer = CustomIsaAnalyzer("evm")
    result = analyzer.analyze(bytecode, base_addr=0x0)
    assert result["processor"] == "evm"
    assert result["graph"].node_count >= 5
    graph = result["graph"]
    jump_edges = [e for e in graph.edges if e.kind == "jump"]
    assert any(e.dst == "inst:0x5" for e in jump_edges), "EVM jump target edge missing"


# ------------------------------------------------------------------ CLI behavior tests

def test_cli_compiler_detect() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 4096)
        tmp_path = tmp.name
    try:
        cp = _run_cli("compiler-detect", "--json", tmp_path)
        assert cp.returncode == 0, cp.stderr
        data = json.loads(cp.stdout)
        assert "compiler" in data
        assert "obfuscation" in data
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_custom_isa_list() -> None:
    cp = _run_cli("custom-isa-list", "--json")
    assert cp.returncode == 0, cp.stderr
    data = json.loads(cp.stdout)
    assert "solana-bpf" in data["processors"]
    assert "evm" in data["processors"]


def test_cli_analyze_custom_sbf() -> None:
    bytecode = bytes([
        0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(bytecode)
        tmp_path = tmp.name
    try:
        cp = _run_cli("analyze-custom", "--json", "--isa", "solana-bpf", tmp_path)
        assert cp.returncode == 0, cp.stderr
        data = json.loads(cp.stdout)
        assert data["isa"] == "solana-bpf"
        assert data["nodes"] > 0
        assert "graph" in data
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_analyze_custom_evm() -> None:
    bytecode = bytes([0x60, 0x01, 0x60, 0x02, 0x01, 0x00])
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(bytecode)
        tmp_path = tmp.name
    try:
        cp = _run_cli("analyze-custom", "--json", "--isa", "evm", tmp_path)
        assert cp.returncode == 0, cp.stderr
        data = json.loads(cp.stdout)
        assert data["isa"] == "evm"
        assert data["nodes"] > 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)
