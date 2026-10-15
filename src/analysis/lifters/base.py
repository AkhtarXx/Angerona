"""Shared lifter contracts."""

from __future__ import annotations

from dataclasses import dataclass, field


class LifUnavailable(RuntimeError):
    """Raised when a lifter cannot be built for an ISA/byte stream."""


@dataclass(frozen=True)
class LiftRequest:
    isa: str                       # "x86-64", "arm-le-32", "mips-be-32", "sparc-32"
    bytes_code: bytes
    base_address: int = 0
    endianness: str = ""           # "" = infer from isa
    max_instructions: int = 5000


@dataclass
class LiftOutcome:
    """One lifter's view over a LiftRequest.IR form is context-dependent.

    ``ir`` mirrors a canonical p-code op record so downstream consumers
    (resolve-ir, bequiv, analysis passes) see the same shape regardless of
    which lifter produced it. Every row carries a confidence tier + the
    lifter name (provenance).
    """

    request: LiftRequest
    ir: list[dict] = field(default_factory=list)
    confidence: float = 0.0        # 0..1
    provenance: str = ""           # "pypcode" | "pyvex" | "irnorm"
    unresolved: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "isa": self.request.isa,
            "base_address": self.request.base_address,
            "bytes": len(self.request.bytes_code),
            "ir_ops": len(self.ir),
            "confidence": self.confidence,
            "provenance": self.provenance,
            "unresolved": self.unresolved,
        }
