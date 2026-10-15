"""Lua 5.x bytecode processor (lua51 / lua53 / lua54)."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# Lua 5.1 opcodes (36 total — subset table).
_LUA51_OPS = [
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP",
    "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG",
]

_LUA53_OPS = [
    "MOVE", "LOADK", "LOADKX", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETTABUP",
    "GETTABLE", "SETTABUP", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD",
    "SUB", "MUL", "MOD", "POW", "DIV", "IDIV", "BAND", "BOR", "BXOR", "SHL",
    "SHR", "UNM", "BNOT", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "EQK", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "RETURN0",
    "RETURN1", "FORLOOP", "FORPREP", "TFORCALL", "TFORLOOP", "SETLIST",
    "CLOSURE", "VARARG", "EXTRAARG",
]

_LUA54_OPS = [  # v51 additions: LJMP/LTFK/TBC/MMBIN/MMBINI/MMBINK, VARARGPREP
    "MOVE", "LOADI", "LOADF", "LOADK", "LOADKX", "LOADFALSE", "LFALSESKIP",
    "LOADTRUE", "LOADNIL", "GETUPVAL", "SETUPVAL", "GETTABUP", "GETTABLE",
    "GETI", "GETFIELD", "SETTABUP", "SETTABLE", "SETI", "SETFIELD", "NEWTABLE",
    "SELF", "ADDI", "ADDK", "SUBK", "MULK", "MODK", "POWK", "DIVK", "IDIVK",
    "BANDK", "BORK", "BXORK", "SHRI", "SHLI", "ADD", "SUB", "MUL", "MOD",
    "POW", "DIV", "IDIV", "BAND", "BOR", "BXOR", "SHL", "SHR", "UNM", "BNOT",
    "NOT", "LEN", "CONCAT", "CLOSE", "TBC", "JMP", "EQ", "LT", "LE", "EQK",
    "EQI", "LTI", "LEI", "GTI", "GEI", "TEST", "TESTSET", "CALL", "TAILCALL",
    "RETURN", "RETURN0", "RETURN1", "FORLOOP", "FORPREP", "TFORPREP",
    "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARGPREP", "VARARG",
    "EXTRAARG",
]


def _detect_lua_version(data: bytes) -> str | None:
    """Best-effort Lua bytecode version from header."""
    if len(data) < 8 or data[0] != 0x1B or data[1:4] != b"Lua":
        return None
    # Byte 4 = official Lua release version byte (5.1=0x51, 5.3=0x53, 5.4=0x54)
    v = data[4]
    if v == 0x51: return "lua51"
    if v == 0x52: return "lua52"
    if v == 0x53: return "lua53"
    if v == 0x54: return "lua54"
    return None


class _LuaBase(ProcessorModule):
    _OPS = []
    arch = "lua"
    bits = 32
    pointer_size = 4
    max_instr_size = 8

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 4:
            return None
        raw = int.from_bytes(data[:4], "little")
        opcode = raw & 0x3F
        a = (raw >> 6) & 0xFF
        b = (raw >> 23) & 0x1FF
        c = (raw >> 14) & 0x1FF
        bx = raw >> 16
        if opcode >= len(self._OPS):
            return None
        name = self._OPS[opcode]
        operands = f"A={a}"
        if name in ("JMP", "FORLOOP", "FORPREP", "CLOSURE"):
            sbx = ((bx ^ 0x7FFF) - 0x7FFF) if opcode != 39 else bx
            operands = f"A={a} sBx={sbx}"
        elif name in ("LOADK", "SETLIST"):
            operands = f"A={a} Bx={bx}"
        else:
            operands = f"A={a} B={b} C={c}"
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=4, bytes=data[:4])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic in ("CALL", "TAILCALL"):
            return [{"kind": "call"}]
        if insn.mnemonic in ("JMP", "FORLOOP", "FORPREP", "RETURN",
                             "CLOSURE", "TFORLOOP", "TEST", "TESTSET"):
            return [{"kind": "jump"}]
        return []


class Lua51Processor(_LuaBase):
    name = "lua51"
    _OPS = _LUA51_OPS


class Lua53Processor(_LuaBase):
    name = "lua53"
    _OPS = _LUA53_OPS


class Lua54Processor(_LuaBase):
    name = "lua54"
    _OPS = _LUA54_OPS
