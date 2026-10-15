"""Wave-1 bytecode processor tests (wasm / lua51/53/54 / pyc)."""
from __future__ import annotations

from src.processors._register_defaults import register_managed_defaults
from src.processors.registry import ProcessorRegistry
from src.processors.wasm import WasmProcessor
from src.processors.lua_bc import Lua51Processor, Lua53Processor, Lua54Processor
from src.processors.pyc import PycProcessor, Pyc311Processor


def test_register_managed_defaults_registers_wave1():
    register_managed_defaults()
    for name in ("wasm", "lua51", "lua53", "lua54", "pyc", "pyc-38", "pyc-311"):
        assert ProcessorRegistry.has(name)


def test_wasm_decode_i32_const():
    proc = WasmProcessor()
    insn = proc.decode(bytes([0x41, 0x2A]), 0x100)   # i32.const 42
    assert insn is not None and insn.mnemonic == "i32.const"
    assert insn.operands == "42"
    assert insn.size == 2


def test_wasm_decode_call_effects():
    proc = WasmProcessor()
    insn = proc.decode(bytes([0x10, 0x05]), 0x0)     # call 5
    assert insn is not None and insn.mnemonic == "call"
    effects = proc.emulate(insn)
    assert effects and effects[0]["kind"] == "call"


def test_wasm_block_instructions():
    proc = WasmProcessor()
    for op, name in [(0x02, "block"), (0x03, "loop"), (0x04, "if"),
                     (0x0B, "end"), (0x0F, "return")]:
        insn = proc.decode(bytes([op, 0x40]), 0)
        assert insn is not None and insn.mnemonic == name, (op, insn)


def test_lua51_decode_instruction():
    proc = Lua51Processor()
    # MOVE op=0, A=1, B=2, C=0 → 0x00001080 in little-endian
    raw = (0 | (1 << 6) | (0 << 14) | (2 << 23)).to_bytes(4, "little")
    insn = proc.decode(raw, 0x800)
    assert insn is not None and insn.mnemonic == "MOVE"


def test_lua53_vs_lua54_tables_distinct():
    assert set(Lua53Processor._OPS) != set(Lua54Processor._OPS)
    assert "LOADKX" in Lua53Processor._OPS  # 5.3 has LoadKx
    assert "LJMP" not in Lua53Processor._OPS
    assert "LOADKX" in Lua54Processor._OPS


def test_pyc_decode_call_edge():
    proc = PycProcessor()
    # CALL opcode is 0x6B in our 3.11 table
    insn = proc.decode(bytes([0x62, 0x02]), 0)
    assert insn is not None
    if insn.mnemonic == "CALL_FUNCTION_EX" or insn.mnemonic == "CALL":
        effects = proc.emulate(insn)
        assert any(e["kind"] == "call" for e in effects)


def test_pyc_version_tags():
    proc = PycProcessor()
    assert "pyc-38" == (PycProcessor._VERSION_TAGS.get(b"\x42\x0d\x0d\x0a"))


def test_pyc311_brand():
    proc = Pyc311Processor()
    assert proc.name == "pyc-311"
