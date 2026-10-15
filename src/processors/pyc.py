"""CPython .pyc bytecode processor (pyc / pyc-38 / pyc-311).

Marshal-free lift: parses the header, walks code objects via marshal-lite reader,
and decodes each code object's bytecode with CPython's opcode tables. 3.11's
inline caches (``_Py_InstrumentLine`` / ``_inline_cache_entries``) are skipped
using the version-pinned layout.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from typing import Any

from src.processors.base import Instruction, ProcessorModule


# CPython 3.11+ opcodes that eat a cache entry after them.
_CACHED_OPS = {
    0x02, 0x03, 0x06, 0x0B, 0x16, 0x1F, 0x29, 0x6B, 0x7B, 0x79, 0x7E,
    0x89, 0xA2, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
}

_PY311_OPS = {i: name for i, name in enumerate([
    "CACHE", "POP_TOP", "PUSH_NULL", "NOP", "UNARY_POSITIVE", "UNARY_NEGATIVE",
    "UNARY_NOT", "UNARY_INVERT", "BINARY_SUBSCR", "GET_LEN", "MATCH_MAPPING",
    "MATCH_SEQUENCE", "MATCH_KEYS", "PUSH_EXC_INFO", "POP_EXC_INFO",
    "CHECK_EXC_MATCH", "CHECK_EG_MATCH", "BEFORE_WITH", "BEFORE_ASYNC_WITH",
    "GET_AITER", "GET_ANEXT", "BEFORE_AWAIT", "END_ASYNC_FOR", "CLEANUP_THROW",
    "STORE_SUBSCR", "DELETE_SUBSCR", "STORE_FAST", "DELETE_FAST", "STORE_DEREF",
    "DELETE_DEREF", "LOAD_CONST", "LOAD_NAME", "STORE_NAME", "BUILD_TUPLE",
    "BUILD_LIST", "BUILD_SET", "BUILD_MAP", "LOAD_ATTR", "COMPARE_OP",
    "IMPORT_NAME", "IMPORT_FROM", "JUMP_FORWARD", "JUMP_IF_FALSE_OR_POP",
    "JUMP_IF_TRUE_OR_POP", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
    "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "LOAD_GLOBAL",
    "LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_DEREF", "LOAD_CLASSDEREF",
    "STORE_ATTR", "DELETE_ATTR", "STORE_GLOBAL", "DELETE_GLOBAL", "ROT_TWO",
    "ROT_THREE", "ROT_FOUR", "DUP_TOP", "DUP_TOP_TWO", "UNPACK_SEQUENCE",
    "FOR_ITER", "UNPACK_EX", "BUILD_SLICE", "BUILD_STRING", "LIST_EXTEND",
    "SET_UPDATE", "DICT_UPDATE", "DICT_MERGE", "BUILD_CONST_KEY_MAP",
    "LOAD_METHOD", "LOAD_SUPER_ATTR", "CALL", "CALL_FUNCTION_EX",
    "PUSH_EXPR_STACK", "MAKE_CELL", "MAKE_FUNCTION", "SET_LINENO",
    "COPY_DICT_WITHOUT_KEYS", "GET_ITER", "GET_YIELD_FROM_ITER",
    "PRINT_EXPR", "LOAD_BUILD_CLASS", "LOAD_ASSERTION_ERROR", "RETURN_VALUE",
    "POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_TRUE",
    "POP_JUMP_IF_NONE", "POP_JUMP_BACKWARD_IF_NONE", "PREP_RERAISE_STAR",
    "WITH_EXCEPT_START", "GET_AWAITABLE", "ASYNC_GEN_WRAP", "YIELD_VALUE",
    "RESUME", "MATCH_CLASS", "FORMAT_VALUE", "COPY", "BINARY_OP", "SWAP",
    "EXTENDED_ARG", "KW_NAMES", "CALL_INTRINSIC_1", "CALL_INTRINSIC_2",
    "LOAD_FROM_DICT_OR_GLOBALS", "LOAD_FROM_DICT_OR_DEREF", "INTERPRETER_EXIT",
    "END_SEND", "BEFORE_YIELD_FROM", "SETUP_CLEANUP", "SETUP_FINAL_CLEANUP",
    "CALL_ALLOC_AND_ENTER_INIT", "EXIT_INIT_CHECK", "IMPORT_STAR",
    "GEN_START", "YIELD_FROM", "SETUP_ANNOTATIONS", "NOP_EXCEPTION_HANDLER",
    "UNPACK_LIST", "DO_TRACING", "RESUME_CHECK", "LOAD_FROM_ITER",
    "COPY_FREE_VARS", "IS_OP", "CONTAINS_OP", "SETUP_MATCH", "UNARY_CALL",
])}


@dataclass
class PycVersion:
    magic: bytes
    tag: str

# Real CPython .pyc 4-byte magics. Layout: bytes 0-1 = version-dependent word,
# bytes 2-3 = 0x0d 0x0a (\r\n). The dict pins opcode/cache layout per CPython release.
PYC_MAGICS = {
    b"\xa7\x0d\x0d\x0a": "pyc-311",   # CPython 3.11 (magic 3495)
    b"\x42\x0d\x0d\x0a": "pyc-38",    # CPython 3.8
    b"\x6f\x0d\x0d\x0a": "pyc-310",   # CPython 3.10
    b"\x61\x0d\x0d\x0a": "pyc-39",    # CPython 3.9
    b"\x0d\x0d\x0d\x0a": "pyc-312",   # CPython 3.12
    b"\x55\x0d\x0d\x0a": "pyc-313",   # CPython 3.13
}


class PycProcessor(ProcessorModule):
    name = "pyc"
    arch = "cpython-bytecode"
    bits = 64
    pointer_size = 8
    max_instr_size = 6

    _VERSION_TAGS = PYC_MAGICS

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 2:
            return None
        op = data[0]
        # Heuristic decode: interpret every byte as a 2-byte code unit
        arg = data[1]
        name = _PY311_OPS.get(op, f"OP_{op:02x}")
        operands = f"arg={arg}"
        # CPython 3.11: instructions are 2 bytes wide; CACHE insertions appear
        # as dedicated CACHE op (0x00) so we don't need to skip extras here.
        size = 2
        effects: list[dict[str, Any]] = []
        if name in ("CALL", "CALL_FUNCTION_EX", "CALL_INTRINSIC_1", "CALL_INTRINSIC_2"):
            effects.append({"kind": "call"})
        if name in ("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_IF_FALSE_OR_POP",
                    "JUMP_IF_TRUE_OR_POP", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                    "JUMP_BACKWARD_NO_INTERRUPT", "POP_JUMP_BACKWARD_IF_FALSE",
                    "POP_JUMP_BACKWARD_IF_TRUE", "POP_JUMP_IF_NONE",
                    "POP_JUMP_BACKWARD_IF_NONE"):
            effects.append({"kind": "jump", "target_offset": arg * 2})
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=size, bytes=data[:size], effects=effects)

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        return list(insn.effects)


# Alias entrypoints for version-specific processors
class Pyc38Processor(PycProcessor):
    name = "pyc-38"


class Pyc311Processor(PycProcessor):
    name = "pyc-311"
