"""Dalvik DEX processor."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# Dalvik opcodes (subset covering invoke / control flow / loads/stores, ~80).
# Encoding helpers: 35c / 3rc / 45cc / 4rcc / 22c etc.
_DEX_OPS = {
    0x00: ("nop", "10x"), 0x01: ("move", "12x"), 0x02: ("move/from16", "22x"),
    0x03: ("move/16", "32x"), 0x04: ("move-wide", "12x"),
    0x07: ("move-object", "12x"), 0x0a: ("move-result", "11x"),
    0x0d: ("move-exception", "11x"), 0x0e: ("return-void", "10x"),
    0x0f: ("return", "11x"), 0x10: ("return-wide", "11x"),
    0x11: ("return-object", "11x"),
    0x12: ("const/4", "11n"), 0x13: ("const/16", "21s"),
    0x14: ("const", "31i"), 0x15: ("const/high16", "21h"),
    0x16: ("const-wide/16", "21s"), 0x17: ("const-wide/32", "31i"),
    0x18: ("const-wide", "51l"), 0x19: ("const-wide/high16", "21h"),
    0x1a: ("const-string", "21c"), 0x1b: ("const-string/jumbo", "31c"),
    0x1c: ("const-class", "21c"), 0x1d: ("monitor-enter", "11x"),
    0x1e: ("monitor-exit", "11x"), 0x1f: ("check-cast", "21c"),
    0x20: ("instance-of", "22c"), 0x21: ("array-length", "12x"),
    0x22: ("new-instance", "21c"), 0x23: ("new-array", "22c"),
    0x24: ("filled-new-array", "35c"), 0x25: ("filled-new-array-range", "3rc"),
    0x26: ("fill-array-data", "31t"), 0x27: ("throw", "11x"),
    0x28: ("goto", "10t"), 0x29: ("goto/16", "20t"), 0x2a: ("goto/32", "30t"),
    0x2b: ("packed-switch", "31t"), 0x2c: ("sparse-switch", "31t"),
    0x2d: ("cmpkind", "23x"), 0x32: ("if-eq", "22t"), 0x33: ("if-ne", "22t"),
    0x34: ("if-lt", "22t"), 0x35: ("if-ge", "22t"), 0x36: ("if-gt", "22t"),
    0x37: ("if-le", "22t"), 0x38: ("if-eqz", "21t"), 0x39: ("if-nez", "21t"),
    0x3a: ("if-ltz", "21t"), 0x3b: ("if-gez", "21t"), 0x3c: ("if-gtz", "21t"),
    0x3d: ("if-lez", "21t"),
    0x44: ("aget", "23x"), 0x45: ("aget-wide", "23x"), 0x46: ("aget-object", "23x"),
    0x47: ("aget-boolean", "23x"), 0x48: ("aget-byte", "23x"),
    0x49: ("aget-char", "23x"), 0x4a: ("aget-short", "23x"),
    0x4b: ("aput", "23x"), 0x52: ("iget", "22c"), 0x53: ("iget-wide", "22c"),
    0x54: ("iget-object", "22c"), 0x55: ("iget-boolean", "22c"),
    0x56: ("iget-byte", "22c"), 0x57: ("iget-char", "22c"),
    0x58: ("iget-short", "22c"), 0x59: ("iput", "22c"),
    0x5a: ("iput-wide", "22c"), 0x5b: ("iput-object", "22c"),
    0x5c: ("iput-boolean", "22c"), 0x5d: ("iput-byte", "22c"),
    0x5e: ("iput-char", "22c"), 0x5f: ("iput-short", "22c"),
    0x60: ("sget", "21c"), 0x61: ("sget-wide", "21c"), 0x62: ("sget-object", "21c"),
    0x63: ("sget-boolean", "21c"), 0x64: ("sget-byte", "21c"),
    0x65: ("sget-char", "21c"), 0x66: ("sget-short", "21c"),
    0x67: ("sput", "21c"), 0x68: ("sput-wide", "21c"), 0x69: ("sput-object", "21c"),
    0x6a: ("sput-boolean", "21c"), 0x6b: ("sput-byte", "21c"),
    0x6c: ("sput-char", "21c"), 0x6d: ("sput-short", "21c"),
    0x6e: ("invoke-virtual", "35c"), 0x6f: ("invoke-super", "35c"),
    0x70: ("invoke-direct", "35c"), 0x71: ("invoke-static", "35c"),
    0x72: ("invoke-interface", "35c"), 0x74: ("invoke-virtual/range", "3rc"),
    0x75: ("invoke-super/range", "3rc"), 0x76: ("invoke-direct/range", "3rc"),
    0x77: ("invoke-static/range", "3rc"), 0x78: ("invoke-interface/range", "3rc"),
    0x7b: ("neg-int", "12x"), 0x7c: ("not-int", "12x"), 0x7d: ("neg-long", "12x"),
    0x7e: ("not-long", "12x"), 0x7f: ("neg-float", "12x"), 0x80: ("neg-double", "12x"),
    0x81: ("int-to-long", "12x"), 0x82: ("int-to-float", "12x"),
    0x83: ("int-to-double", "12x"), 0x84: ("long-to-int", "12x"),
    0x85: ("long-to-float", "12x"), 0x86: ("long-to-double", "12x"),
    0x87: ("float-to-int", "12x"), 0x88: ("float-to-long", "12x"),
    0x89: ("float-to-double", "12x"), 0x8a: ("double-to-int", "12x"),
    0x8b: ("double-to-long", "12x"), 0x8c: ("double-to-float", "12x"),
    0x8d: ("int-to-byte", "12x"), 0x8e: ("int-to-char", "12x"),
    0x8f: ("int-to-short", "12x"),
    0x90: ("add-int", "23x"), 0x91: ("sub-int", "23x"), 0x92: ("mul-int", "23x"),
    0x93: ("div-int", "23x"), 0x94: ("rem-int", "23x"),
    0x95: ("and-int", "23x"), 0x96: ("or-int", "23x"), 0x97: ("xor-int", "23x"),
    0x98: ("shl-int", "23x"), 0x99: ("shr-int", "23x"), 0x9a: ("ushr-int", "23x"),
    0xb0: ("add-int/2addr", "12x"), 0xb1: ("sub-int/2addr", "12x"),
    0xb2: ("mul-int/2addr", "12x"), 0xb3: ("div-int/2addr", "12x"),
    0xb4: ("rem-int/2addr", "12x"), 0xb5: ("and-int/2addr", "12x"),
    0xb6: ("or-int/2addr", "12x"), 0xb7: ("xor-int/2addr", "12x"),
    0xb8: ("shl-int/2addr", "12x"), 0xb9: ("shr-int/2addr", "12x"),
    0xba: ("ushr-int/2addr", "12x"),
    0xd0: ("add-int/lit16", "22s"), 0xd1: ("rsub-int", "22s"),
    0xd2: ("mul-int/lit16", "22s"), 0xd3: ("div-int/lit16", "22s"),
    0xd4: ("rem-int/lit16", "22s"), 0xd5: ("and-int/lit16", "22s"),
    0xd6: ("or-int/lit16", "22s"), 0xd7: ("xor-int/lit16", "22s"),
    0xd8: ("add-int/lit8", "22b"), 0xd9: ("rsub-int/lit8", "22b"),
    0xda: ("mul-int/lit8", "22b"), 0xdb: ("div-int/lit8", "22b"),
    0xdc: ("rem-int/lit8", "22b"), 0xdd: ("and-int/lit8", "22b"),
    0xde: ("or-int/lit8", "22b"), 0xdf: ("xor-int/lit8", "22b"),
    0xe0: ("shl-int/lit8", "22b"), 0xe1: ("shr-int/lit8", "22b"),
    0xe2: ("ushr-int/lit8", "22b"),
    0xf1: ("invoke-polymorphic", "45cc"), 0xf2: ("invoke-polymorphic/range", "4rcc"),
    0xf3: ("invoke-custom", "35c"), 0xf4: ("invoke-custom/range", "3rc"),
}

_FORMAT_SIZE_16 = {"10x", "12x", "11x", "11n", "10t"}
_FORMAT_SIZE_32 = {"20t", "21s", "21h", "21c", "21t", "22x", "22t", "22b",
                   "22c", "22s", "23x", "31t", "31c", "31i", "32x", "35c"}


class DexProcessor(ProcessorModule):
    name = "dex"
    arch = "dalvik"
    bits = 32
    pointer_size = 4
    max_instr_size = 10

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 2:
            return None
        op = data[0]
        entry = _DEX_OPS.get(op)
        if entry is None:
            return None
        name, fmt = entry
        size = 2 if fmt in _FORMAT_SIZE_16 else (4 if fmt in _FORMAT_SIZE_32 else 6)
        if fmt in ("45cc", "4rcc"):
            size = 8
        elif fmt in ("3rc",):
            size = 6
        elif fmt in ("51l",):
            size = 10
        if len(data) < size:
            return None
        hi = data[1]
        reg = hi & 0x0F
        arg2 = (hi >> 4) & 0x0F
        operands = f"v{reg}"
        if size >= 4:
            operands += " " + data[2:4].hex()
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=size, bytes=data[:size])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic.startswith("invoke"):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic.startswith(("goto", "if", "return", "throw",
                                     "switch", "packed-switch", "sparse-switch")):
            return [{"kind": "jump"}]
        return []
