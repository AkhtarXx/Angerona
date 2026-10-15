"""Abstract base for custom ISA processors.

Mirrors Ida's processor_t three-stage pipeline (u_ana, u_emu, u_out) but maps
onto our engine-agnostic AnalysisGraph IR:

* decode  -> Instruction (mnemonic, operands, size, effects)
* emulate -> list of effect dicts (reads, writes, calls, jumps)
* render  -> human disassembly text
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Instruction:
    """Decoded instruction representation."""

    address: int
    mnemonic: str
    operands: str = ""
    size: int = 0
    bytes: bytes = field(default_factory=bytes)
    effects: list[dict[str, Any]] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "size": self.size,
            "bytes": self.bytes.hex() if self.bytes else "",
            "effects": list(self.effects),
            "properties": dict(self.properties),
        }


class ProcessorModule(ABC):
    """Base class for custom ISA processors."""

    name: str = ""
    arch: str = ""
    bits: int = 64
    pointer_size: int = 8
    max_instr_size: int = 16
    maturity: str = "experimental"
    coverage_notes: str = "Opcode decoding is partial; unknown bytes are preserved as db records."

    @abstractmethod
    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        """Decode a single instruction from ``data`` at ``addr``.

        Returns an :class:`Instruction` or ``None`` if the bytes are invalid.
        """
        ...

    @abstractmethod
    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        """Return semantic effects for ``insn``.

        Each effect is a dict with ``kind`` in ``read``, ``write``, ``call``,
        ``jump``, ``fall_through``, ``stack_delta``.  Optional keys include
        ``address``, ``target``, ``register``.
        """
        ...

    def render(self, insn: Instruction) -> str:
        """Render instruction as human text."""
        if insn.operands:
            return f"{insn.mnemonic} {insn.operands}"
        return insn.mnemonic

    def disassemble(
        self,
        data: bytes,
        base_addr: int = 0,
        max_instructions: int = 0,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> list[Instruction]:
        """Decode a byte sequence into sequential instructions."""
        instructions: list[Instruction] = []
        offset = 0
        count = 0
        while offset < len(data):
            if max_instructions and count >= max_instructions:
                break
            insn = self.decode(data[offset:], base_addr + offset, metadata=metadata)
            if insn is None:
                # Unknown byte: emit a pseudo-instruction so the graph still
                # records the gap.
                insn = Instruction(
                    address=base_addr + offset,
                    mnemonic="db",
                    operands=f"0x{data[offset]:02x}",
                    size=1,
                    bytes=data[offset:offset + 1],
                )
            instructions.append(insn)
            offset += insn.size
            count += 1
        return instructions
