"""BEAM/Erlang bytecode processor."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# BEAM 5.x opcode tags (subset).
_BEAM_OPS = {
    0x01: "label", 0x02: "func_info", 0x04: "int_code_end", 0x05: "call",
    0x06: "call_last", 0x07: "call_only", 0x08: "call_ext", 0x09: "call_ext_last",
    0x0A: "bif0", 0x0B: "bif1", 0x0C: "bif2", 0x0D: "allocate", 0x0E: "allocate_heap",
    0x0F: "allocate_zero", 0x10: "allocate_heap_zero", 0x11: "test_heap",
    0x12: "init", 0x13: "deallocate", 0x14: "return", 0x15: "send",
    0x16: "remove_message", 0x17: "timeout", 0x18: "loop_rec",
    0x19: "loop_rec_end", 0x1A: "wait", 0x1B: "wait_timeout",
    0x1E: "m_plus", 0x1F: "m_minus", 0x20: "m_times", 0x21: "m_div",
    0x22: "int_div", 0x23: "int_rem", 0x24: "int_band", 0x25: "int_bor",
    0x26: "int_bxor", 0x27: "int_bsl", 0x28: "int_bsr",
    0x29: "int_code_end", 0x2A: "bs_init", 0x2B: "bs_put_integer",
    0x2C: "bs_put_binary", 0x2D: "bs_put_float", 0x2E: "bs_put_string",
    0x30: "fclearerror", 0x31: "fcheckerror", 0x32: "fmove", 0x33: "fconv",
    0x34: "fadd", 0x35: "fsub", 0x36: "fmul", 0x37: "fdiv", 0x38: "fnegate",
    0x39: "make_fun2", 0x40: "try", 0x41: "try_end", 0x42: "try_case",
    0x43: "try_case_end", 0x44: "raise", 0x4A: "bs_init2", 0x4B: "bs_bits_to_bytes",
    0x4C: "bs_add", 0x4D: "apply", 0x4E: "apply_last",
    0x50: "is_function2", 0x51: "gc_bif1", 0x52: "gc_bif2",
    0x59: "is_bitstr", 0x5B: "bs_context_to_binary", 0x5C: "bs_test_unit",
    0x5D: "bs_match_string", 0x5E: "bs_init_writable", 0x5F: "bs_append",
    0x60: "bs_private_append", 0x61: "trim", 0x62: "bs_init_bits",
    0x63: "bs_get_utf8", 0x64: "bs_skip_utf8", 0x65: "bs_get_utf16",
    0x66: "bs_skip_utf16", 0x67: "bs_get_utf32", 0x68: "bs_skip_utf32",
    0x69: "bs_utf8_size", 0x6A: "bs_put_utf8", 0x6B: "bs_utf16_size",
    0x6C: "bs_put_utf16", 0x6D: "bs_put_utf32",
    0x70: "on_load", 0x71: "recv_mark", 0x72: "recv_set", 0x78: "line",
    0x79: "put_map_assoc", 0x7A: "put_map_exact", 0x7B: "is_map",
    0x7C: "bs_create_bin", 0x7D: "call_fun", 0x7E: "is_function",
    0x9F: "get_map_elements", 0xA0: "is_tagged_tuple",
    0xA2: "build_stacktrace", 0xA3: "raw_raise",
    0xA4: "get_hd", 0xA5: "get_tl", 0xA6: "put_tuple2", 0xA7: "bs_get_tail",
    0xA8: "bs_start_match3", 0xA9: "bs_get_position", 0xAA: "bs_set_position",
    0xAB: "swap", 0xAC: "bs_start_match4",
}


class BeamProcessor(ProcessorModule):
    name = "beam"
    arch = "erlang-beam"
    bits = 32
    pointer_size = 4
    max_instr_size = 8

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 4:
            return None
        # BEAM instructions are packed small-int lists; tag is the low byte
        tag = data[0]
        name = _BEAM_OPS.get(tag)
        if name is None:
            return None
        # Heuristic arg size: 4-byte alignment; we don't fully decode ETF args
        size = 4
        return Instruction(address=addr, mnemonic=name, operands=data[1:4].hex(),
                           size=size, bytes=data[:size])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic.startswith(("call", "bif", "gc_bif", "apply", "call_fun")):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic in ("jump", "return", "raise", "raw_raise", "swap"):
            return [{"kind": "jump"}]
        return []
