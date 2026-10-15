""".NET CIL bytecode processor."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# .NET CIL opcodes (subset of single-byte + two-byte 0xFE prefix).
_CIL_OPS = {
    0x00: "nop", 0x01: "break", 0x02: "ldarg.0", 0x03: "ldarg.1", 0x04: "ldarg.2",
    0x05: "ldarg.3", 0x06: "ldloc.0", 0x07: "ldloc.1", 0x08: "ldloc.2", 0x09: "ldloc.3",
    0x0A: "stloc.0", 0x0B: "stloc.1", 0x0C: "stloc.2", 0x0D: "stloc.3",
    0x0E: "ldarg.s", 0x0F: "ldarga.s", 0x10: "starg.s", 0x11: "ldloc.s", 0x12: "ldloca.s",
    0x13: "stloc.s", 0x14: "ldnull", 0x15: "ldc.i4.m1", 0x16: "ldc.i4.0",
    0x17: "ldc.i4.1", 0x18: "ldc.i4.2", 0x19: "ldc.i4.3", 0x1A: "ldc.i4.4",
    0x1B: "ldc.i4.5", 0x1C: "ldc.i4.6", 0x1D: "ldc.i4.7", 0x1E: "ldc.i4.8",
    0x1F: "ldc.i4.s", 0x20: "ldc.i4", 0x21: "ldc.i8", 0x22: "ldc.r4", 0x23: "ldc.r8",
    0x25: "dup", 0x26: "pop", 0x27: "jmp", 0x28: "call", 0x29: "calli",
    0x2A: "ret", 0x2B: "br.s", 0x2C: "brfalse.s", 0x2D: "brtrue.s",
    0x2E: "beq.s", 0x2F: "bge.s", 0x30: "bgt.s", 0x31: "ble.s", 0x32: "blt.s",
    0x33: "bne.un.s", 0x34: "bge.un.s", 0x35: "bgt.un.s", 0x36: "ble.un.s",
    0x37: "blt.un.s", 0x38: "br", 0x39: "brfalse", 0x3A: "brtrue",
    0x3B: "beq", 0x3C: "bge", 0x3D: "bgt", 0x3E: "ble", 0x3F: "blt",
    0x40: "bne.un", 0x41: "bge.un", 0x42: "bgt.un", 0x43: "ble.un", 0x44: "blt.un",
    0x45: "switch", 0x58: "add", 0x59: "sub", 0x5A: "mul", 0x5B: "div", 0x5C: "div.un",
    0x5D: "rem", 0x5E: "rem.un", 0x5F: "and", 0x60: "or", 0x61: "xor", 0x62: "shl",
    0x63: "shr", 0x64: "shr.un", 0x65: "neg", 0x66: "not", 0x67: "conv.i1",
    0x68: "conv.i2", 0x69: "conv.i4", 0x6A: "conv.i8", 0x6B: "conv.r4",
    0x6C: "conv.r8", 0x6D: "conv.u4", 0x6E: "conv.u8",
    0x6F: "callvirt", 0x70: "cpobj", 0x71: "ldobj", 0x72: "ldstr",
    0x73: "newobj", 0x74: "castclass", 0x75: "isinst", 0x76: "conv.r.un",
    0x79: "unbox", 0x7A: "throw", 0x7B: "ldfld", 0x7C: "ldflda", 0x7D: "stfld",
    0x7E: "ldsfld", 0x7F: "ldsflda", 0x80: "stsfld", 0x81: "stobj",
    0x82: "conv.ovf.i1.un", 0x83: "conv.ovf.i2.un", 0x84: "conv.ovf.i4.un",
    0x85: "conv.ovf.i8.un", 0x86: "conv.ovf.u1.un", 0x87: "conv.ovf.u2.un",
    0x88: "conv.ovf.u4.un", 0x89: "conv.ovf.u8.un", 0x8A: "conv.ovf.i.un",
    0x8B: "conv.ovf.u.un", 0x8C: "box", 0x8D: "newarr", 0x8E: "ldlen",
    0x8F: "ldelema", 0x90: "ldelem.i1", 0x91: "ldelem.u1", 0x92: "ldelem.i2",
    0x93: "ldelem.u2", 0x94: "ldelem.i4", 0x95: "ldelem.u4", 0x96: "ldelem.i8",
    0x97: "ldelem.i", 0x98: "ldelem.r4", 0x99: "ldelem.r8", 0x9A: "ldelem.ref",
    0x9B: "stelem.i", 0x9C: "stelem.i1", 0x9D: "stelem.u1", 0x9E: "stelem.i2",
    0x9F: "stelem.u2", 0xA0: "stelem.i4", 0xA1: "stelem.u4", 0xA2: "stelem.i8",
    0xA3: "stelem.r4", 0xA4: "stelem.r8", 0xA5: "stelem.ref",
    0xA6: "ldelem", 0xA7: "stelem", 0xA8: "unbox.any",
    0xD0: "ldtoken", 0xD1: "conv.u2", 0xD2: "conv.u1", 0xD3: "conv.i",
    0xD4: "conv.ovf.i", 0xD5: "conv.ovf.u", 0xD6: "add.ovf", 0xD7: "add.ovf.un",
    0xD8: "mul.ovf", 0xD9: "mul.ovf.un", 0xDA: "sub.ovf", 0xDB: "sub.ovf.un",
    0xDC: "endfinally", 0xDD: "leave", 0xDE: "leave.s", 0xDF: "stind.i",
    0xE0: "conv.u", 0xF8: "prefix7", 0xF9: "prefix6", 0xFA: "prefix5",
    0xFB: "prefix4", 0xFC: "prefix3", 0xFD: "prefix2", 0xFE: "prefix1",
    0xFF: "prefixref",
}

_ONE_OPERAND = {"ldarg.s", "ldarga.s", "starg.s", "ldloc.s", "ldloca.s",
                 "stloc.s", "ldc.i4.s", "br.s", "brfalse.s", "brtrue.s",
                 "beq.s", "bge.s", "bgt.s", "ble.s", "blt.s",
                 "bne.un.s", "bge.un.s", "bgt.un.s", "ble.un.s", "blt.un.s",}
_FOUR_OPERAND = {"ldc.i4", "ldstr", "ldtoken", "call", "jmp", "br", "brfalse",
                  "brtrue", "beq", "bge", "bgt", "ble", "blt", "bne.un",
                  "bge.un", "bgt.un", "ble.un", "blt.un", "callvirt", "newobj",
                  "castclass", "isinst", "ldfld", "ldflda", "stfld", "ldsfld",
                  "ldsflda", "stsfld", "cpobj", "ldobj", "newarr",
                  "ldelema", "ldelem", "stelem", "box", "unbox", "unbox.any"}
_EIGHT_OPERAND = {"ldc.i8", "ldc.r8"}
_FIVE_OPERAND = {"ldc.r4", "switch"}


class CilProcessor(ProcessorModule):
    name = "cil"
    arch = "dotnet-cil"
    bits = 64
    pointer_size = 8
    max_instr_size = 12

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if not data:
            return None
        op = data[0]
        if op == 0xFE:
            if len(data) < 2:
                return None
            # reserved for two-byte opcodes in real CIL; treat as unknown here
            return None
        name = _CIL_OPS.get(op)
        if name is None:
            return None
        size = 1
        if name in _ONE_OPERAND:
            size = 2
        elif name in _FOUR_OPERAND:
            size = 5
        elif name in _EIGHT_OPERAND:
            size = 9
        elif name in _FIVE_OPERAND:
            size = 5
        if len(data) < size:
            return None
        operands = ""
        if size > 1:
            operands = data[1:size].hex()
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=size, bytes=data[:size])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic in ("call", "calli", "callvirt", "newobj", "jmp"):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic.startswith(("br", "beq", "bge", "bgt", "ble", "blt",
                                      "bne", "bge.un", "bgt.un", "ble.un", "blt.un",
                                      "switch", "leave", "throw", "ret", "endfinally")):
            return [{"kind": "jump"}]
        return []
