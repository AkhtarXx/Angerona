"""P-code lifter via pypcode (SLEIGH semantics — the unified bridge).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §universal-lifting
+ MASTER_PLAN Phase 3): Ghidra ships ~180 SLEIGH language variants; pypcode exposes
the full set through a Python API (no JVM, no project). This is the primary lifter
for everything Ghidra-class (including obscure firmware ISAs).
"""

from __future__ import annotations

from .base import LiftOutcome, LiftRequest, LifUnavailable


def lift(req: LiftRequest) -> LiftOutcome:
    try:
        import pypcode  # type: ignore
    except ImportError as exc:
        raise LifUnavailable(f"pypcode not installed: {exc}") from exc

    # Map Angerona ISA strings onto pypcode language selectors
    lang_map = {
        "x86-64": ("x86:LE:64:default", 8, "little"),
        "x86-32": ("x86:LE:32:default", 4, "little"),
        "x86-16": ("x86:LE:16:Real Mode", 2, "little"),
        "arm-le-32": ("ARM:LE:32:v7A", 4, "little"),
        "arm-be-32": ("ARM:BE:32:v7A", 4, "big"),
        "aarch64": ("AARCH64:LE:64:v8A", 8, "little"),
        "mips-le-32": ("MIPS:LE:32:default", 4, "little"),
        "mips-be-32": ("MIPS:BE:32:default", 4, "big"),
        "mips-le-64": ("MIPS:LE:64:64-32", 8, "little"),
        "ppc-be-32": ("PowerPC:BE:32:default", 4, "big"),
        "ppc-le-64": ("PowerPC:LE:64:default", 8, "little"),
        "sparc-be-32": ("sparc:BE:32:default", 4, "big"),
        "sparc-be-64": ("sparc:BE:64:default", 8, "big"),
        "riscv-le-32": ("RISCV:LE:32:RV32IMA", 4, "little"),
        "riscv-le-64": ("RISCV:LE:64:RV64IMA", 8, "little"),
        "tricore": ("tricore:LE:32:default", 4, "little"),
        "xtensa-le-32": ("xtensa:LE:32:default", 4, "little"),
        "avr8": ("avr8:LE:16:atmega256", 2, "little"),
        "6502": ("6502:LE:16:default", 2, "little"),
        "sh4": ("SuperH4:BE:32:default", 4, "big"),
    }
    lang_id, ptr_size, endian = lang_map.get(req.isa.lower(), (None, None, None))
    if lang_id is None:
        raise LifUnavailable(f"no pypcode language for isa={req.isa!r}")

    try:
        ctx = pypcode.Context(lang_id)
        tx = ctx.translate(req.bytes_code, req.base_address, max_instructions=req.max_instructions)
    except Exception as exc:  # noqa: BLE001
        raise LifUnavailable(f"pypcode translation failed: {exc}") from exc

    ops = []
    for op in getattr(tx, "ops", []):
        ops.append({
            "opcode": op.opcode.name if hasattr(op.opcode, "name") else str(op.opcode),
            "inputs": list(op.inputs) if hasattr(op, "inputs") else [],
            "output": op.output if hasattr(op, "output") else None,
        })
    return LiftOutcome(
        request=req,
        ir=ops,
        confidence=0.92,           # SLEIGH specs are battle-tested
        provenance="pypcode",
    )
