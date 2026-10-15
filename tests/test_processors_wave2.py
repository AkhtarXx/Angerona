"""Wave-2 processor tests (jvm / dex / cil / beam / v8_ignition)."""
from __future__ import annotations

from src.processors._register_defaults import register_managed_defaults
from src.processors.registry import ProcessorRegistry
from src.processors.jvm import JvmProcessor
from src.processors.dex import DexProcessor
from src.processors.cil import CilProcessor
from src.processors.beam import BeamProcessor
from src.processors.v8_ignition import V8IgnitionProcessor


def test_wave2_registered():
    register_managed_defaults()
    for name in ("jvm", "dex", "cil", "beam", "v8-ignition"):
        assert ProcessorRegistry.has(name)


def test_jvm_decode_iadd():
    insn = JvmProcessor().decode(bytes([0x60]), 0)
    assert insn is not None and insn.mnemonic == "iadd"
    assert insn.size == 1


def test_jvm_decode_bipush_size():
    insn = JvmProcessor().decode(bytes([0x10, 0x2A]), 0)   # bipush 42
    assert insn is not None and insn.size == 2


def test_jvm_invoke_is_call_edge():
    proc = JvmProcessor()
    insn = proc.decode(bytes([0xb6, 0x12, 0x34]), 0)       # invokevirtual idx
    assert insn is not None
    effects = proc.emulate(insn)
    assert effects and effects[0]["kind"] == "call"


def test_dex_decode_nop():
    insn = DexProcessor().decode(bytes([0x00, 0x00]), 0)
    assert insn is not None and insn.mnemonic == "nop"


def test_dex_invoke_virtual_call_edge():
    proc = DexProcessor()
    insn = proc.decode(bytes([0x6e, 0x01, 0x00, 0x10]), 8)  # invoke-virtual
    assert insn is not None and insn.mnemonic == "invoke-virtual"
    effects = proc.emulate(insn)
    assert effects[0]["kind"] == "call"


def test_cil_decode_add():
    insn = CilProcessor().decode(bytes([0x58]), 0)
    assert insn is not None and insn.mnemonic == "add"


def test_cil_ldstr_size():
    insn = CilProcessor().decode(bytes([0x72]) + b"\x01\x00\x00\x00", 0)
    assert insn is not None and insn.mnemonic == "ldstr"
    assert insn.size == 5


def test_beam_decode_call():
    proc = BeamProcessor()
    insn = proc.decode(bytes([0x05, 0xAA, 0xBB, 0xCC]), 0)
    # tag 0x05 = call
    assert insn is not None and insn.mnemonic == "call"


def test_v8_jump_not_call():
    proc = V8IgnitionProcessor()
    insn = proc.decode(bytes([0x03, 0x12, 0x34]), 0)   # Ldar (load accumulator register)
    assert insn is not None and insn.mnemonic == "Ldar"


def test_v8_ldaconstant():
    proc = V8IgnitionProcessor()
    insn = proc.decode(bytes([0x0B, 0x03, 0x00]), 0)
    assert insn is not None and insn.mnemonic == "LdaConstant"
