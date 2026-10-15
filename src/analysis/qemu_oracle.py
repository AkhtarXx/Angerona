"""Legacy compatibility implementation of the Unicorn execution oracle.

New code must import :mod:`src.analysis.unicorn_oracle`.  Despite this legacy
filename, every execution path in this module uses the Python Unicorn engine;
it does not invoke QEMU.  The name is retained only for downstream imports.

Research basis (angerona research notes, 2026-07-15, Part 6):
  The re-executability / behavioral-equivalence gate (MCGD 2604.23940: compile-only =
  0% behavioral correctness despite 91-99% compile rates) is AI-RE's strongest anchor --
  but it REQUIRES an execution oracle, which obscure archs usually LACK. Where a
  Unicorn backend exists, wire it as the
  execution oracle so the re-executability gate comes back online even for obscure archs.

What this module does (production, uses the installed `unicorn` package):
  - Detects which Unicorn arch maps to a given ISA name (ARM/ARM64/MIPS/X86/PPC/SPARC/
    M68K/RISCV/S390X/TRICORE).
  - Runs a small *harness function* in Unicorn: map the code + a stack, set the PC,
    emulate N instructions, and return the final register state / exit condition. This is
    the re-execution oracle that feeds behavioral equivalence (bequiv.py) for obscure
    archs where native detonation is impossible.
  - Degrades gracefully: arch not in Unicorn -> "unsupported" (never a false pass); no
    unicorn installed -> "unavailable". The static-only fallback (claims/CFG) remains.

Graceful: unsupported arch / missing unicorn -> explicit status, no fabricated result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    import unicorn
    from unicorn import Uc, UcError
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP
    from unicorn.arm64_const import UC_ARM64_REG_PC
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_EIP
    from unicorn.mips_const import UC_MIPS_REG_PC
    from unicorn.ppc_const import UC_PPC_REG_PC
    from unicorn.sparc_const import UC_SPARC_REG_PC
    from unicorn.m68k_const import UC_M68K_REG_PC
    from unicorn.riscv_const import UC_RISCV_REG_PC
    from unicorn.s390x_const import UC_S390X_REG_PC
    from unicorn.tricore_const import UC_TRICORE_REG_PC
    _HAVE_UNICORN = True
except Exception:  # noqa: BLE001
    _HAVE_UNICORN = False


# Architectures the oracle knows how to map. Keep this independent from the
# optional Unicorn installation: "known backend mapping" and "runtime available"
# are separate capabilities.
_SUPPORTED_ARCHES = frozenset({
    "arm", "armthumb", "arm64", "aarch64", "mips", "x86", "x86_64",
    "ppc", "sparc", "m68k", "riscv", "riscv64", "s390x", "tricore",
})


# ISA name -> (unicorn arch const, unicorn mode const, pc register const, sp register const|None)
if _HAVE_UNICORN:
    _ARCH_MAP = {
    "arm": ("UC_ARCH_ARM", "UC_MODE_ARM", UC_ARM_REG_PC, UC_ARM_REG_SP),
    "armthumb": ("UC_ARCH_ARM", "UC_MODE_THUMB", UC_ARM_REG_PC, UC_ARM_REG_SP),
    "arm64": ("UC_ARCH_ARM64", "UC_MODE_ARM", UC_ARM64_REG_PC, None),
    "aarch64": ("UC_ARCH_ARM64", "UC_MODE_ARM", UC_ARM64_REG_PC, None),
    "mips": ("UC_ARCH_MIPS", "UC_MODE_MIPS32", UC_MIPS_REG_PC, None),
    "x86": ("UC_ARCH_X86", "UC_MODE_32", UC_X86_REG_EIP, UC_X86_REG_RSP),
    "x86_64": ("UC_ARCH_X86", "UC_MODE_64", UC_X86_REG_RIP, UC_X86_REG_RSP),
    "ppc": ("UC_ARCH_PPC", "UC_MODE_32", UC_PPC_REG_PC, None),
    "sparc": ("UC_ARCH_SPARC", "UC_MODE_32", UC_SPARC_REG_PC, None),
    "m68k": ("UC_ARCH_M68K", "UC_MODE_BIG_ENDIAN", UC_M68K_REG_PC, None),
    "riscv": ("UC_ARCH_RISCV", "UC_MODE_RISCV32", UC_RISCV_REG_PC, None),
    "riscv64": ("UC_ARCH_RISCV", "UC_MODE_RISCV64", UC_RISCV_REG_PC, None),
    "s390x": ("UC_ARCH_S390X", "UC_MODE_BIG_ENDIAN", UC_S390X_REG_PC, None),
        "tricore": ("UC_ARCH_TRICORE", "UC_MODE_BIG_ENDIAN", UC_TRICORE_REG_PC, None),
    }
else:
    _ARCH_MAP = {}


@dataclass
class EmuResult:
    status: str            # success | error | unsupported | unavailable
    arch: Optional[str] = None
    instructions_run: int = 0
    last_pc: Optional[int] = None
    exit_reason: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"status": self.status, "arch": self.arch,
                "instructions_run": self.instructions_run, "last_pc": self.last_pc,
                "exit_reason": self.exit_reason, "detail": self.detail}


def arch_supported(isa: str) -> bool:
    """Return whether Angerona has a mapping for ``isa``.

    This intentionally does not report whether Unicorn is installed; callers
    get that operational state from :func:`emulate_function` as ``unavailable``.
    """
    return isa.lower() in _SUPPORTED_ARCHES


def emulate_function(code: bytes, isa: str, base_addr: int = 0x1000,
                     stack_size: int = 0x10000, max_instructions: int = 2000,
                     registers: Optional[dict] = None) -> EmuResult:
    """Emulate ``code`` in Unicorn for an obscure-arch re-execution oracle.

    Returns an EmuResult with the run status and final PC/exit reason. This is the
    execution oracle that re-enables behavioral equivalence (bequiv.py) on archs where
    native detonation is impossible. ``registers`` maps reg-name -> value to pre-set.
    """
    isa = isa.lower()
    if isa not in _SUPPORTED_ARCHES:
        return EmuResult(status="unsupported", arch=isa,
                         detail=f"no Unicorn backend mapping for {isa}")
    if not _HAVE_UNICORN:
        return EmuResult(status="unavailable", arch=isa,
                         detail="unicorn not installed")
    if isa not in _ARCH_MAP:
        return EmuResult(status="unsupported", arch=isa,
                         detail=f"no Unicorn backend for {isa}")
    arch_c, mode_c, pc_const, sp_const = _ARCH_MAP[isa]
    arch_v = getattr(unicorn, arch_c)
    mode_v = getattr(unicorn, mode_c)
    try:
        mu = Uc(arch_v, mode_v)
    except UcError as e:
        return EmuResult(status="unsupported", arch=isa, detail=str(e))

    stack_top = base_addr + 0x200000
    # map code + stack (sizes page-aligned to 0x1000)
    code_size = ((len(code) + 0x1000 - 1) // 0x1000) * 0x1000
    mu.mem_map(base_addr, max(0x1000, code_size))
    mu.mem_write(base_addr, code)
    mu.mem_map(stack_top, stack_size)
    try:
        mu.reg_write(pc_const, base_addr)
        if sp_const is not None:
            mu.reg_write(sp_const, stack_top + stack_size - 0x100)
    except UcError:
        pass
    if registers:
        for rname, val in registers.items():
            try:
                mu.reg_write(getattr(unicorn, rname), val)
            except Exception:
                pass
    res = EmuResult(status="success", arch=isa)
    try:
        # until = just past the code region; count = max instructions as a safety cap
        mu.emu_start(base_addr, base_addr + len(code), count=max_instructions)
        res.last_pc = mu.reg_read(pc_const)
        # Unicorn exposes no portable instruction counter here.  The PC and
        # explicit exit reason are evidence; do not invent a count.
        res.exit_reason = "reached end of code region"
    except UcError as e:
        res.status = "error"
        try:
            res.last_pc = mu.reg_read(pc_const)
        except UcError:
            pass
        res.exit_reason = f"emulation stopped: {e}"
        res.detail = str(e)
    return res
