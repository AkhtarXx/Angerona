"""irnorm-based fallback lifter — the 90%-coverage shim."""

from __future__ import annotations

from .base import LiftOutcome, LiftRequest, LifUnavailable


def lift(req: LiftRequest) -> LiftOutcome:
    """Pseudo-lift: produce a coarse line-per-structural-pattern summary using
    capstone linear-sweep + irnorm-style mnemonic normalisation. Lower confidence,
    used only when no SLEIGH language or pyvex guest exists.
    """
    try:
        import capstone
    except ImportError:
        raise LifUnavailable("capstone not installed for fallback lifter")

    arch_map = {
        "x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86-32": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "aarch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "arm-le-32": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN),
        "arm-be-32": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN),
        "mips-le-32": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN),
        "mips-be-32": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN),
        "riscv-le-64": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_LITTLE_ENDIAN),
        "riscv-le-32": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_LITTLE_ENDIAN),
    }
    cfg = arch_map.get(req.isa.lower())
    if cfg is None:
        raise LifUnavailable(f"fallback has no capstone profile for isa={req.isa!r}")
    md = capstone.Cs(*cfg)
    ops: list[dict] = []
    try:
        count = 0
        for insn in md.disasm(req.bytes_code, req.base_address, count=req.max_instructions):
            ops.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })
            count += 1
            if count >= req.max_instructions:
                break
    except Exception as exc:  # noqa: BLE001
        raise LifUnavailable(f"capstone sweep failed: {exc}") from exc
    return LiftOutcome(
        request=req,
        ir=ops,
        confidence=0.55,           # best-effort; NOT decompiler-grade
        provenance="irnorm-capstone",
        unresolved=["linear sweep without CFG; no decompiler semantics"],
    )
