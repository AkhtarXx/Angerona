"""Solana BPF (SBF) processor module.

Decodes a reasonable subset of Solana BPFv2 instructions into the Angerona IR.
The goal is not bit-perfect execution realism but enough structural accuracy to
run the generic CFG, stack-frame, and xref passes on Solana programs.

Instruction format (little-endian unless noted):
  +--------+--------+--------+----------------+
  |  raw_opcode (8)   |  regs  | offset / imm16 |  imm32 / etc
  +--------+--------+--------+----------------+
  Minimum 8 bytes (64-bit ALU/branch/load/store classes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.processors.base import Instruction, ProcessorModule


def _u16_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little", signed=False)


def _s16_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little", signed=True)


def _u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little", signed=False)


def _s32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little", signed=True)


def _u64_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little", signed=False)


@dataclass
class _DecodedOperand:
    dst: str = "r0"
    src: str | None = None
    imm: int | None = None
    offset: int = 0


class SolanaBpfProcessor(ProcessorModule):
    """Solana BPF decoder and semantic analyzer."""

    name = "solana-bpf"
    arch = "sbf"
    bits = 64
    pointer_size = 8
    max_instr_size = 16

    # Opcode class bits.
    _CLS_LD = 0x00
    _CLS_LDX = 0x01
    _CLS_ST = 0x02
    _CLS_STX = 0x03
    _CLS_ALU = 0x04
    _CLS_JMP = 0x05
    _CLS_JMP32 = 0x06
    _CLS_ALU64 = 0x07

    _OP_ADD = 0x00
    _OP_SUB = 0x10
    _OP_MUL = 0x20
    _OP_DIV = 0x30
    _OP_OR = 0x40
    _OP_AND = 0x50
    _OP_LSH = 0x60
    _OP_RSH = 0x70
    _OP_NEG = 0x80
    _OP_MOD = 0x90
    _OP_XOR = 0xA0
    _OP_MOV = 0xB0
    _OP_ARSH = 0xC0
    _OP_END = 0xD0

    _OP_JA = 0x00
    _OP_JEQ = 0x10
    _OP_JGT = 0x20
    _OP_JGE = 0x30
    _OP_JSET = 0x40
    _OP_JNE = 0x50
    _OP_JSGT = 0x60
    _OP_JSGE = 0x70
    _OP_CALL = 0x80
    _OP_EXIT = 0x90
    _OP_JLT = 0xA0
    _OP_JLE = 0xB0
    _OP_JSLT = 0xC0
    _OP_JSLE = 0xD0

    _SIZE_W = 0x00
    _SIZE_H = 0x08
    _SIZE_B = 0x10
    _SIZE_DW = 0x18

    _ALU_MNEM: dict[int, str] = {
        _OP_ADD: "add64",
        _OP_SUB: "sub64",
        _OP_MUL: "mul64",
        _OP_DIV: "div64",
        _OP_OR: "or64",
        _OP_AND: "and64",
        _OP_LSH: "lsh64",
        _OP_RSH: "rsh64",
        _OP_NEG: "neg64",
        _OP_MOD: "mod64",
        _OP_XOR: "xor64",
        _OP_MOV: "mov64",
        _OP_ARSH: "arsh64",
    }

    _JMP_MNEM: dict[int, str] = {
        _OP_JA: "ja",
        _OP_JEQ: "jeq",
        _OP_JGT: "jgt",
        _OP_JGE: "jge",
        _OP_JSET: "jset",
        _OP_JNE: "jne",
        _OP_JSGT: "jsgt",
        _OP_JSGE: "jsge",
        _OP_JLT: "jlt",
        _OP_JLE: "jle",
        _OP_JSLT: "jslt",
        _OP_JSLE: "jsle",
        _OP_CALL: "call",
        _OP_EXIT: "exit",
    }

    _SIZE_SUFFIX: dict[int, str] = {
        _SIZE_W: "w",
        _SIZE_H: "h",
        _SIZE_B: "b",
        _SIZE_DW: "dw",
    }

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 8:
            return None

        raw_opcode = data[0]
        dst_reg = data[1] & 0x0F
        src_reg = (data[1] & 0xF0) >> 4
        offset = _s16_le(data, 2)
        imm32 = _s32_le(data, 4)
        # Store the original signed offset for branch targets separately.
        branch_offset = offset
        imm: int | None = imm32
        size = 8

        cls = raw_opcode & 0x07
        op = raw_opcode & 0xF0

        opnds = _DecodedOperand(dst=f"r{dst_reg}")
        mnemonic = "unknown"

        if cls in (self._CLS_ALU, self._CLS_ALU64, self._CLS_JMP, self._CLS_JMP32):
            if cls == self._CLS_ALU64:
                mnemonic = self._ALU_MNEM.get(op, f"alu64_0x{op:x}")
            elif cls == self._CLS_ALU:
                mnemonic = self._ALU_MNEM.get(op, f"alu_0x{op:x}")
                if mnemonic.endswith("64"):
                    mnemonic = mnemonic[:-2]
            else:
                mnemonic = self._JMP_MNEM.get(op, f"jmp_0x{op:x}")

            if op == self._OP_END:
                if imm32 == 0:
                    mnemonic = "le16" if cls == self._CLS_ALU else "le32"
                else:
                    mnemonic = "be16" if cls == self._CLS_ALU else "be32"
                if cls == self._CLS_ALU64:
                    mnemonic = mnemonic.replace("16", "64") if "16" in mnemonic else mnemonic.replace("32", "64")

            src_is_reg = (raw_opcode & 0x08) != 0
            if op == self._OP_NEG or op == self._OP_EXIT:
                opnds.imm = None
                opnds.src = None
            elif src_is_reg:
                opnds.src = f"r{src_reg}"
                opnds.imm = None
            else:
                opnds.imm = imm
                opnds.src = None

            if op == self._OP_EXIT:
                mnemonic = "exit"
            elif op == self._OP_CALL:
                mnemonic = "call"
                opnds.imm = imm32 if imm32 >= 0 else imm32 + (1 << 32)

        elif cls in (self._CLS_LD, self._CLS_LDX, self._CLS_ST, self._CLS_STX):
            # Size is bits 3-4 of the opcode byte: 0=W,1=H,2=B,3=DW.
            size_bits = (raw_opcode >> 3) & 0x03
            size_code = size_bits * 8
            suffix = self._SIZE_SUFFIX.get(size_code, "x")
            mode = (raw_opcode >> 5) & 0x07
            if cls == self._CLS_LD:
                mnemonic = f"ld{suffix}"
                if mode == 0:  # immediate
                    if suffix == "dw":
                        if len(data) < 16:
                            return None
                        imm = _u64_le(data, 8)
                        size = 16
                        opnds.imm = imm
                    else:
                        opnds.imm = imm32
                else:
                    opnds.src = f"r{src_reg}"
                    opnds.offset = offset
            elif cls == self._CLS_LDX:
                mnemonic = f"ldx{suffix}"
                opnds.src = f"r{src_reg}"
                opnds.offset = offset
            elif cls == self._CLS_ST:
                mnemonic = f"st{suffix}"
                opnds.imm = imm32
                opnds.offset = offset
            elif cls == self._CLS_STX:
                mnemonic = f"stx{suffix}"
                opnds.src = f"r{src_reg}"
                opnds.offset = offset
        else:
            return None

        instr = Instruction(
            address=addr,
            mnemonic=mnemonic,
            operands=self._render_operands(mnemonic, opnds),
            size=size,
            bytes=data[:size],
        )
        if cls in (self._CLS_JMP, self._CLS_JMP32):
            instr.properties["branch_offset"] = branch_offset
        if mnemonic == "call":
            instr.properties["immediate"] = opnds.imm
        instr.effects = self.emulate(instr)
        return instr

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        effects: list[dict[str, Any]] = []
        m = insn.mnemonic

        if m == "exit":
            effects.append({"kind": "return"})
            return effects

        if m == "call":
            # SBF CALL imm invokes a runtime helper/syscall, not a normal
            # program function.  Keep the helper index for graphing, but mark it
            # explicitly so downstream loaders do not invent func:0xNN stubs.
            target = self._parse_call_target(insn)
            effects.append({
                "kind": "call",
                "target": target,
                "target_kind": "helper",
                "symbolic_target": insn.properties.get("symbolic_target"),
            })
            return effects

        if m == "ja" or m.startswith("jmp"):
            target = self._parse_jump_target(insn)
            effects.append({"kind": "jump", "target": target})
            return effects

        if m.startswith("j"):
            target = self._parse_jump_target(insn)
            effects.append({"kind": "conditional_jump", "target": target})
            effects.append({"kind": "fall_through"})
            return effects

        if m.startswith("st") or m.startswith("ld"):
            effects.append({"kind": "memory_access"})

        effects.append({"kind": "fall_through"})
        return effects

    def _render_operands(self, mnemonic: str, opnds: _DecodedOperand) -> str:
        if mnemonic in ("exit",):
            return ""
        # CALL in SBF uses only an immediate helper index.
        if mnemonic == "call":
            return f"0x{opnds.imm:x}" if opnds.imm is not None else ""
        if mnemonic.startswith(("ld", "st")):
            if opnds.src is not None:
                sign = "" if opnds.offset < 0 else "+"
                return f"{opnds.dst}, [{opnds.src}{sign}0x{abs(opnds.offset):x}]"
            # stb [r1+0x10], 0x1  -- keep source-less store shape
            return f"{opnds.dst}, 0x{opnds.imm or 0:x}"
        # ALU / JMP: always include dst register.
        parts: list[str] = [opnds.dst]
        if opnds.src is not None:
            parts.append(opnds.src)
        elif opnds.imm is not None:
            parts.append(f"0x{opnds.imm:x}")
        return ", ".join(parts)

    def _parse_call_target(self, insn: Instruction) -> int | None:
        """Call target encoded as a helper index immediate.

        For graph resolution we keep it as an integer (keyed by helper index).
        A separate display label can use the properties.
        """
        imm = insn.properties.get("immediate")
        if imm is None and insn.operands.startswith("0x"):
            try:
                imm = int(insn.operands, 16)
            except Exception:
                pass
        if imm is None:
            return None
        insn.properties["symbolic_target"] = f"helper_{int(imm)}"
        insn.properties["call_target_kind"] = "helper"
        return int(imm)

    def _parse_jump_target(self, insn: Instruction) -> int | None:
        """Branch target from the signed instruction offset property.

        SBF branch offsets are expressed in 64-bit instruction units, so we
        multiply by 8.
        """
        offset = insn.properties.get("branch_offset")
        if offset is None:
            return None
        step = insn.size or 8
        return (insn.address + step + (int(offset) * 8)) & 0xFFFFFFFFFFFFFFFF
