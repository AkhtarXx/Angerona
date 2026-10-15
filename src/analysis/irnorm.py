"""Cross-architecture IR normalization (p-code-style) for arch-agnostic RE.

Research basis (angerona research notes, 2026-07-15):
  Part 6 (custom arch) + Part 8 (decompiler IR): the decisive axis for analyzing
  OBSCURE/non-standard archs is RETARGETABILITY — lifting every arch to ONE common
  intermediate representation. Ghidra's p-code is exactly that; this module provides a
  LIGHTWEIGHT, dependency-free p-code-style normalizer for the common cases angerona
  already exports (x86/ARM/MIPS via IDA/Ghidra disassembly), so downstream analysis
  (similarity, struct recovery, taint seeding) can treat instructions by SEMANTICS
  (LOAD/STORE/ADD/BRANCH/CALL) instead of by mnemonic. For full p-code we defer to
  Ghidra's exported IR; this normalizer covers the 90% case without a Ghidra dependency.

Normalized op classes:
  MOV/LOAD/STORE/ADD/SUB/MUL/DIV/AND/OR/XOR/CMP/BRANCH/CALL/RET/OTHER

Graceful: unknown mnemonics -> OTHER (never raises).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# mnemonic -> normalized op (covers x86/ARM/MIPS/PPC common forms)
_OP_MAP = {
    # moves / loads / stores
    "mov": "MOV", "move": "MOV", "ldr": "LOAD", "ldrb": "LOAD", "ldr.w": "LOAD",
    "lw": "LOAD", "lwz": "LOAD", "ld": "LOAD", "ldp": "LOAD",
    "str": "STORE", "strb": "STORE", "st": "STORE", "sw": "STORE", "stp": "STORE",
    "strb.w": "STORE", "swi": "STORE",
    # arithmetic
    "add": "ADD", "adds": "ADD", "add.w": "ADD", "addd": "ADD", "sub": "SUB",
    "subs": "SUB", "sub.w": "SUB", "mul": "MUL", "muls": "MUL", "mull": "MUL",
    "div": "DIV", "udiv": "DIV", "sdiv": "DIV", "rem": "DIV",
    # logic
    "and": "AND", "ands": "AND", "or": "OR", "orr": "OR", "eor": "XOR",
    "xor": "XOR", "not": "XOR", "mvn": "XOR",
    # compare
    "cmp": "CMP", "cmps": "CMP", "cmn": "CMP", "tst": "CMP", "test": "CMP",
    # control
    "jmp": "BRANCH", "jne": "BRANCH", "je": "BRANCH", "jz": "BRANCH", "jnz": "BRANCH",
    "jg": "BRANCH", "jl": "BRANCH", "jge": "BRANCH", "jle": "BRANCH", "ja": "BRANCH",
    "jb": "BRANCH", "jae": "BRANCH", "jbe": "BRANCH", "jmp.w": "BRANCH",
    "b": "BRANCH", "beq": "BRANCH", "bne": "BRANCH", "bgt": "BRANCH", "blt": "BRANCH",
    "bge": "BRANCH", "ble": "BRANCH", "bhi": "BRANCH", "blo": "BRANCH", "bal": "BRANCH",
    "call": "CALL", "bl": "CALL", "blr": "CALL", "jal": "CALL", "jalr": "CALL",
    "jr": "CALL", "ret": "RET", "ret.w": "RET", "bx": "RET", "bx lr": "RET",
    "pop": "RET", "leave": "RET",
}


@dataclass
class NormInstr:
    addr: str
    op: str              # normalized op class
    mnemonic: str
    operands: str = ""

    def as_dict(self) -> dict:
        return {"addr": self.addr, "op": self.op, "mnemonic": self.mnemonic,
                "operands": self.operands}


def normalize_line(line: str) -> NormInstr | None:
    """Normalize one disassembly line into a p-code-style op."""
    m = re.match(r"^\s*([0-9a-fA-Fx]+):?\s+([a-z][a-z0-9.]*)?\s*(.*)$", line.strip(), re.I)
    if not m:
        return None
    addr, mnem, ops = m.group(1), (m.group(2) or "").lower(), (m.group(3) or "").strip()
    if not mnem:
        return None
    op = _OP_MAP.get(mnem, "OTHER")
    return NormInstr(addr=addr, op=op, mnemonic=mnem, operands=ops)


def normalize_function(asm_text: str) -> list[NormInstr]:
    """Normalize a whole function's disassembly into p-code-style ops."""
    out: list[NormInstr] = []
    for line in (asm_text or "").splitlines():
        ni = normalize_line(line)
        if ni:
            out.append(ni)
    return out


def semantic_signature(asm_text: str) -> str:
    """A compact semantic signature (op-class n-gram) for arch-agnostic similarity.

    Two functions doing the same THING on different archs get similar signatures
    (LOAD/STORE/ADD/CMP/BRANCH/CALL...) — this is what makes cross-arch matching
    possible even without full p-code.
    """
    ops = [ni.op for ni in normalize_function(asm_text)]
    # 2-gram signature
    grams = ops + [f"{a}>{b}" for a, b in zip(ops, ops[1:])]
    from collections import Counter
    c = Counter(grams)
    return " ".join(f"{k}:{v}" for k, v in c.most_common(40))
