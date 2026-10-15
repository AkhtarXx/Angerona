"""WebAssembly (WASM) processor module.

Decode WASM bytecode instructions into the Angerona IR. WASM is a structured
stack-based format (block/loop/if/end nesting), so a single `main` blob isn't
sufficient — we emit per-function bodies through the loader's ``body_regions``
hint when available, and per-section decode falls back to a synthetic entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.processors.base import Instruction, ProcessorModule


# WASM opcodes (subset — core MVP + extensions).
_OP = {
    0x00: "unreachable", 0x01: "nop",
    0x02: "block", 0x03: "loop", 0x04: "if", 0x05: "else", 0x0B: "end",
    0x0C: "br", 0x0D: "br_if", 0x0E: "br_table", 0x0F: "return",
    0x10: "call", 0x11: "call_indirect",
    0x1A: "drop", 0x1B: "select",
    0x20: "local.get", 0x21: "local.set", 0x22: "local.tee",
    0x23: "global.get", 0x24: "global.set",
    0x28: "i32.load", 0x29: "i64.load", 0x2A: "f32.load", 0x2B: "f64.load",
    0x2C: "i32.load8_s", 0x2D: "i32.load8_u", 0x2E: "i32.load16_s", 0x2F: "i32.load16_u",
    0x36: "i32.store", 0x37: "i64.store", 0x38: "f32.store", 0x39: "f64.store",
    0x3A: "i32.store8", 0x3B: "i32.store16",
    0x3F: "memory.size", 0x40: "memory.grow",
    0x41: "i32.const", 0x42: "i64.const", 0x43: "f32.const", 0x44: "f64.const",
    0x45: "i32.eqz", 0x46: "i32.eq", 0x47: "i32.ne", 0x48: "i32.lt_s", 0x49: "i32.lt_u",
    0x4A: "i32.gt_s", 0x4B: "i32.gt_u", 0x4C: "i32.le_s", 0x4D: "i32.le_u",
    0x4E: "i32.ge_s", 0x4F: "i32.ge_u",
    0x67: "i64.add", 0x7C: "i32.add", 0x7D: "i32.sub", 0x7E: "i32.mul",
    0x7F: "i32.div_s", 0x80: "i32.div_u", 0x81: "i32.rem_s", 0x82: "i32.rem_u",
    0x83: "i32.and", 0x84: "i32.or", 0x85: "i32.xor", 0x86: "i32.shl",
    0x87: "i32.shr_s", 0x88: "i32.shr_u", 0x89: "i32.rotl", 0x8A: "i32.rotr",
}

_LEB_OP = {0x10, 0x11, 0x0C, 0x0D, 0x20, 0x21, 0x22, 0x23, 0x24}
_SIGNED_LEB_OP = {0x41, 0x42}


def _uleb(data: bytes, off: int) -> tuple[int, int]:
    result = 0; shift = 0; n = 0
    while True:
        if off + n >= len(data):
            raise ValueError("truncated LEB128")
        b = data[off + n]
        result |= (b & 0x7F) << shift
        n += 1
        if not b & 0x80:
            break
        shift += 7
    return result, n


def _sleb(data: bytes, off: int, bits: int = 64) -> tuple[int, int]:
    result = 0; shift = 0; n = 0
    while True:
        if off + n >= len(data):
            raise ValueError("truncated SLEB128")
        b = data[off + n]
        result |= (b & 0x7F) << shift
        n += 1
        shift += 7
        if not b & 0x80:
            if shift < bits and (b & 0x40):
                result |= -(1 << shift)
            break
    return result, n


class WasmProcessor(ProcessorModule):
    name = "wasm"
    arch = "wasm"
    bits = 32
    pointer_size = 4
    max_instr_size = 10

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if not data:
            return None
        op = data[0]
        name = _OP.get(op)
        if name is None:
            return None
        size = 1
        operands = ""
        if op in _LEB_OP:
            try:
                v, n = _uleb(data, 1)
                operands = str(v)
                size = 1 + n
            except ValueError:
                return None
        elif op in _SIGNED_LEB_OP:
            try:
                v, n = _sleb(data, 1)
                operands = str(v)
                size = 1 + n
            except ValueError:
                return None
        elif op == 0x43:  # f32.const
            if len(data) < 5: return None
            import struct as _s
            operands = f"{_s.unpack('<f', data[1:5])[0]:.4f}"
            size = 5
        elif op == 0x44:  # f64.const
            if len(data) < 9: return None
            import struct as _s
            operands = f"{_s.unpack('<d', data[1:9])[0]:.4f}"
            size = 9
        elif op in (0x02, 0x03, 0x04):  # block/loop/if → blocktype
            if len(data) < 2: return None
            operands = f"blocktype=0x{data[1]:02x}"
            size = 2
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=size, bytes=data[:size])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic in ("call", "call_indirect"):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic in ("br", "br_if", "br_table", "return"):
            return [{"kind": "jump", "target": insn.operands or None}]
        if insn.mnemonic in ("block", "loop", "if", "else", "end"):
            return []
        return []
