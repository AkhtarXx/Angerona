"""JVM class bytecode processor."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# JVM opcode table (subset — most-used ~80 opcodes for structural analysis).
_JVM_OPS = {
    0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
    0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
    0x08: "iconst_5", 0x10: "bipush", 0x11: "sipush",
    0x12: "ldc", 0x13: "ldc_w", 0x14: "ldc2_w", 0x15: "iload", 0x16: "lload",
    0x17: "fload", 0x18: "dload", 0x19: "aload",
    0x1a: "iload_0", 0x1b: "iload_1", 0x1c: "iload_2", 0x1d: "iload_3",
    0x2a: "aload_0", 0x2b: "aload_1", 0x2c: "aload_2", 0x2d: "aload_3",
    0x36: "istore", 0x3b: "istore_0", 0x3c: "istore_1", 0x3d: "istore_2", 0x3e: "istore_3",
    0x4b: "astore_0", 0x4c: "astore_1", 0x4d: "astore_2", 0x4e: "astore_3",
    0x53: "aastore", 0x57: "pop", 0x59: "dup", 0x5a: "dup_x1", 0x5b: "dup_x2",
    0x60: "iadd", 0x61: "ladd", 0x62: "fadd", 0x63: "dadd",
    0x64: "isub", 0x68: "imul", 0x6c: "idiv", 0x70: "irem",
    0x74: "ineg", 0x78: "ishl", 0x7a: "ishr", 0x7c: "iushr",
    0x7e: "iand", 0x80: "ior", 0x82: "ixor",
    0x84: "iinc", 0x85: "i2l", 0x86: "i2f", 0x87: "i2d", 0x88: "l2i",
    0x89: "l2f", 0x8a: "l2d", 0x8b: "f2i", 0x8c: "f2l", 0x8d: "f2d",
    0x8e: "d2i", 0x8f: "d2l", 0x90: "d2f", 0x91: "i2b", 0x92: "i2c", 0x93: "i2s",
    0x94: "lcmp", 0x95: "fcmpl", 0x96: "fcmpg", 0x97: "dcmpl", 0x98: "dcmpg",
    0x99: "ifeq", 0x9a: "ifne", 0x9b: "iflt", 0x9c: "ifge", 0x9d: "ifgt", 0x9e: "ifle",
    0x9f: "if_icmpeq", 0xa0: "if_icmpne", 0xa1: "if_icmplt", 0xa2: "if_icmpge",
    0xa3: "if_icmpgt", 0xa4: "if_icmple", 0xa5: "if_acmpeq", 0xa6: "if_acmpne",
    0xa7: "goto", 0xa8: "jsr", 0xa9: "ret",
    0xaa: "tableswitch", 0xab: "lookupswitch",
    0xac: "ireturn", 0xad: "lreturn", 0xae: "freturn", 0xaf: "dreturn",
    0xb0: "areturn", 0xb1: "return",
    0xb2: "getstatic", 0xb3: "putstatic", 0xb4: "getfield", 0xb5: "putfield",
    0xb6: "invokevirtual", 0xb7: "invokespecial", 0xb8: "invokestatic",
    0xb9: "invokeinterface", 0xba: "invokedynamic", 0xbb: "new",
    0xbc: "newarray", 0xbd: "anewarray", 0xbe: "arraylength", 0xbf: "athrow",
    0xc0: "checkcast", 0xc1: "instanceof", 0xc2: "monitorenter", 0xc3: "monitorexit",
    0xc5: "multianewarray", 0xc6: "ifnull", 0xc7: "ifnonnull",
    0xc8: "goto_w", 0xc9: "jsr_w",
}

_OPCODE_SIZES = {op: 2 for op in (0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36)}
_OPCODE_SIZES.update({op: 3 for op in (0x99, 0x9a, 0x9b, 0x9c,
                                          0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3,
                                          0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
                                          0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                                          0xb8, 0xb9, 0xbA, 0xbc, 0xbd, 0xc0, 0xc1)})
_OPCODE_SIZES[0xc5] = 4
_OPCODE_SIZES[0xc6] = 3
_OPCODE_SIZES[0xc7] = 3
_OPCODE_SIZES[0xc8] = 5
_OPCODE_SIZES[0xc9] = 5
# variable-length:
_VARIABLE_LEN = {0xaa, 0xab}


class JvmProcessor(ProcessorModule):
    name = "jvm"
    arch = "jvm-class"
    bits = 32
    pointer_size = 4
    max_instr_size = 16

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if not data:
            return None
        op = data[0]
        name = _JVM_OPS.get(op)
        if name is None:
            return None
        if op in _VARIABLE_LEN:
            return self._decode_switch(data, addr, op, name)
        size = _OPCODE_SIZES.get(op, 1)
        if len(data) < size:
            return None
        operands = _fmt_operands(name, data[1:size])
        return Instruction(address=addr, mnemonic=name, operands=operands,
                           size=size, bytes=data[:size])

    def _decode_switch(self, data: bytes, addr: int, op: int, name: str) -> Instruction | None:
        # 4-byte alignment: padding after opcode (1 byte), then default/jump targets
        if len(data) < 4:
            return None
        # speculative size; tableswitch is parsed as instruction shape only here
        return Instruction(address=addr, mnemonic=name,
                           operands="(variable)", size=4,
                           bytes=data[:4])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic.startswith("invoke"):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic.startswith(("goto", "if", "jsr", "tableswitch", "lookupswitch")):
            return [{"kind": "jump"}]
        return []


def _fmt_operands(name: str, operand_bytes: bytes) -> str:
    return f"{operand_bytes.hex()}"
