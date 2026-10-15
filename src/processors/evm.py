"""Ethereum Virtual Machine (EVM) processor module.

Decodes EVM opcodes into the Angerona IR.  Stack-machine semantics are reduced
to reads/writes (stack), calls (CALL family), jumps, and fall-through.  This
is sufficient to run CFG construction and xref heuristics.

Jump targets are resolved by peeking at the preceding PUSH immediate, a
standard EVM stack-machine recovery pattern.
"""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


class EvmProcessor(ProcessorModule):
    """EVM bytecode processor."""

    name = "evm"
    arch = "evm"
    bits = 256
    pointer_size = 32
    max_instr_size = 33

    # (opcode, size_without_immediate, has_offset_imm, mnemonic)
    _OPCODES: dict[int, tuple[int, int, str]] = {
        0x00: (1, 0, "STOP"),
        0x01: (1, 0, "ADD"),
        0x02: (1, 0, "MUL"),
        0x03: (1, 0, "SUB"),
        0x04: (1, 0, "DIV"),
        0x10: (1, 0, "LT"),
        0x11: (1, 0, "GT"),
        0x14: (1, 0, "EQ"),
        0x16: (1, 0, "AND"),
        0x17: (1, 0, "OR"),
        0x18: (1, 0, "XOR"),
        0x19: (1, 0, "NOT"),
        0x54: (1, 0, "SLOAD"),
        0x55: (1, 0, "SSTORE"),
        0x56: (1, 0, "JUMP"),
        0x57: (1, 0, "JUMPI"),
        0x60: (1, 1, "PUSH1"),
        0x61: (1, 2, "PUSH2"),
        0x62: (1, 3, "PUSH3"),
        0x63: (1, 4, "PUSH4"),
        0x64: (1, 5, "PUSH5"),
        0x65: (1, 6, "PUSH6"),
        0x66: (1, 7, "PUSH7"),
        0x67: (1, 8, "PUSH8"),
        0x68: (1, 9, "PUSH9"),
        0x69: (1, 10, "PUSH10"),
        0x6A: (1, 11, "PUSH11"),
        0x6B: (1, 12, "PUSH12"),
        0x6C: (1, 13, "PUSH13"),
        0x6D: (1, 14, "PUSH14"),
        0x6E: (1, 15, "PUSH15"),
        0x6F: (1, 16, "PUSH16"),
        0x70: (1, 17, "PUSH17"),
        0x71: (1, 18, "PUSH18"),
        0x72: (1, 19, "PUSH19"),
        0x73: (1, 20, "PUSH20"),
        0x74: (1, 21, "PUSH21"),
        0x75: (1, 22, "PUSH22"),
        0x76: (1, 23, "PUSH23"),
        0x77: (1, 24, "PUSH24"),
        0x78: (1, 25, "PUSH25"),
        0x79: (1, 26, "PUSH26"),
        0x7A: (1, 27, "PUSH27"),
        0x7B: (1, 28, "PUSH28"),
        0x7C: (1, 29, "PUSH29"),
        0x7D: (1, 30, "PUSH30"),
        0x7E: (1, 31, "PUSH31"),
        0x7F: (1, 32, "PUSH32"),
        0x80: (1, 0, "DUP1"),
        0x81: (1, 0, "DUP2"),
        0x90: (1, 0, "SWAP1"),
        0x91: (1, 0, "SWAP2"),
        0xA0: (1, 0, "LOG0"),
        0xF0: (1, 0, "CREATE"),
        0xF1: (1, 0, "CALL"),
        0xF3: (1, 0, "RETURN"),
        0xFD: (1, 0, "REVERT"),
        0xFE: (1, 0, "INVALID"),
        0xFF: (1, 0, "SELFDESTRUCT"),
    }

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if not data:
            return None
        opcode = data[0]
        info = self._OPCODES.get(opcode)
        if info is None:
            instr = Instruction(
                address=addr,
                mnemonic="UNKNOWN",
                operands=f"0x{opcode:02x}",
                size=1,
                bytes=data[:1],
            )
            instr.effects = self.emulate(instr)
            return instr
        base_size, imm_size, mnemonic = info
        total_size = base_size + imm_size
        if len(data) < total_size:
            return None
        operands = ""
        imm: int | None = None
        if imm_size:
            operands = "0x" + data[base_size:total_size].hex()
            imm = int(data[base_size:total_size].hex(), 16)
        instr = Instruction(
            address=addr,
            mnemonic=mnemonic,
            operands=operands,
            size=total_size,
            bytes=data[:total_size],
        )
        if imm is not None:
            instr.properties["immediate"] = imm
        instr.effects = self.emulate(instr)
        return instr

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        effects: list[dict[str, Any]] = []
        m = insn.mnemonic

        if m in ("STOP", "RETURN", "REVERT", "SELFDESTRUCT", "INVALID"):
            effects.append({"kind": "return"})
            return effects

        target = insn.properties.get("jump_target")
        if m == "JUMP":
            effects.append({"kind": "jump", "target": target})
            return effects

        if m == "JUMPI":
            effects.append({"kind": "conditional_jump", "target": target})
            effects.append({"kind": "fall_through"})
            return effects

        if m in ("CALL", "CREATE"):
            effects.append({"kind": "call", "target": None})
            effects.append({"kind": "fall_through"})
            return effects

        if m in ("SLOAD", "SSTORE"):
            effects.append({"kind": "memory_access"})

        if m.startswith("PUSH") or m in ("DUP", "SWAP"):
            effects.append({"kind": "stack_access"})

        effects.append({"kind": "fall_through"})
        return effects

    def disassemble(
        self,
        data: bytes,
        base_addr: int = 0,
        max_instructions: int = 0,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> list[Instruction]:
        """Decode a byte sequence into sequential instructions.

        Overridden to resolve JUMP/JUMPI targets from the preceding PUSH.
        """
        instructions = super().disassemble(data, base_addr, max_instructions, metadata=metadata)
        # Resolve jump targets by looking back one instruction.
        for idx, insn in enumerate(instructions):
            if insn.mnemonic in ("JUMP", "JUMPI") and idx > 0:
                prev = instructions[idx - 1]
                if prev.mnemonic.startswith("PUSH"):
                    imm = prev.properties.get("immediate")
                    if isinstance(imm, int):
                        insn.properties["jump_target"] = imm
                        insn.effects = self.emulate(insn)
        return instructions
