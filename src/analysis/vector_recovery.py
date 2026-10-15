"""MCU entry / vector-table recovery check (Part 4, recommendation 4).

Research basis (angerona research notes, 2026-07-15, Part 4):
  Bare-metal firmware entry-point recovery (reset vector) is a real gap. Classic approach:
  parse the interrupt vector table -- ARM Reset_Handler at offset 4, MIPS exception base
  (0x80000000 / 0xBFC00000), RISC-V mtvec -- then CONFIRM the recovered handler resolves
  to sane code (a natural fit for the CFG/structural verification pillar: does the entry's
  CFG match a sane handler shape?). This module extracts the candidate entry and flags
  whether it points at code-like (non-zero, in-bounds, aligned) content.

What it does (production, deterministic, no engine required):
  - Given an architecture + raw image bytes, locates the reset/exception vector.
  - Validates the handler target: in-bounds, aligned, points to non-uniform (code-like)
    bytes (entropy/repetition check), not into a clearly-data region (all-zero / all-0xFF).
  - Returns a verdict the verify_cfg pillar can consume.

Graceful: unknown arch -> "unsupported" (never a false pass); tiny/empty image -> low confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class VectorRecovery:
    arch: str
    vector_addr: Optional[int]
    handler_addr: Optional[int]
    sane: bool
    confidence: str  # high | medium | low | unsupported
    detail: str = ""

    def as_dict(self) -> dict:
        return {"arch": self.arch, "vector_addr": self.vector_addr,
                "handler_addr": self.handler_addr, "sane": self.sane,
                "confidence": self.confidence, "detail": self.detail}


def _looks_like_code(block: bytes) -> bool:
    """Heuristic: code-like bytes are not a single repeated uniform byte
    (all-zero / all-0xFF / all-same padding is data, not code)."""
    if not block or len(block) < 4:
        return False
    if len(set(block[:64])) < 2:
        return False  # uniform single byte -> likely padding/data
    return True


def _u32(data: bytes, off: int) -> Optional[int]:
    if off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def recover_vector(arch: str, image: str | Path) -> VectorRecovery:
    data = Path(image).read_bytes()
    arch = (arch or "").lower()

    if arch in ("arm", "armv7", "armv7m", "cortex-m", "thumb"):
        # ARM vector table: offset 0 = initial SP, offset 4 = Reset_Handler (LSB set = Thumb)
        if len(data) < 8:
            return VectorRecovery("arm", 4, None, False, "low", "image too small for vector table")
        sp = _u32(data, 0)
        reset = _u32(data, 4)
        if reset is None:
            return VectorRecovery("arm", 4, None, False, "low", "no reset vector")
        handler = reset & ~1
        sane = (handler < len(data)) and (handler % 2 == 0) and _looks_like_code(
            data[handler:handler + 64])
        conf = "high" if sane else "medium"
        return VectorRecovery("arm", 4, handler, sane, conf,
                              f"SP=0x{sp:08x} reset=0x{reset:08x} handler=0x{handler:08x}")

    if arch in ("mips", "mips32"):
        # MIPS: exception base usually 0x80000000 (kseg0) or 0xBFC00000 (boot); first
        # word at the base is the reset jump. We scan the common boot base if present.
        for base in (0xBFC00000, 0x80000000):
            off = base & 0x0FFFFFFF  # map into a small image if it starts at base
            if off + 4 <= len(data):
                w = _u32(data, off)
                if w is not None and w != 0 and w != 0xFFFFFFFF:
                    handler = off  # the word at the exception base IS the reset instruction
                    sane = _looks_like_code(data[off:off + 64])
                    return VectorRecovery("mips", off, handler, sane,
                                          "high" if sane else "medium",
                                          f"exception-base 0x{base:08x} word=0x{w:08x}")
        return VectorRecovery("mips", None, None, False, "low", "no MIPS exception base found")

    if arch in ("riscv", "risc-v", "rv32", "rv64"):
        # RISC-V: mtvec is a CSR; in a bare-metal image the reset vector is typically at
        # the start (0x0 or 0x80000000). We check offset 0 for a plausible jump/branch.
        if len(data) < 8:
            return VectorRecovery("riscv", 0, None, False, "low", "image too small")
        w = _u32(data, 0)
        sane = w is not None and w != 0 and w != 0xFFFFFFFF and _looks_like_code(data[:64])
        return VectorRecovery("riscv", 0, 0 if sane else None, sane,
                              "high" if sane else "medium",
                              f"reset word=0x{w:08x}" if w is not None else "no reset word")

    return VectorRecovery(arch, None, None, False, "unsupported",
                          f"arch {arch!r} not supported for vector recovery")


def confidence_tier(v: VectorRecovery) -> str:
    """Map a vector recovery to the evalability tier language used elsewhere."""
    if v.confidence == "unsupported":
        return "unsupported"
    if v.sane:
        return "high"
    return "low"
