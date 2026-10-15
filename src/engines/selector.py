"""Smart engine selector — IDA Pro DEFAULT, Ghidra/SLEIGH fallback for non-standard arch.

Research basis (angerona research notes, 2026-07-15):
  Part 6 (custom/obscure architectures): the decisive axis is RETARGETABILITY. Ghidra/
  SLEIGH gives a decompiler + CFG + p-code IR from one .slaspec, whereas IDA 9.1 does
  NOT register custom Python processors headlessly (we proved this live with the
  Solana/eBPF plugin — set_processor_type raised RuntimeError 1391). So for non-standard
  archs (eBPF/Solana, GameBoy, AVR, Tricore, Xtensa, custom RISC-V) IDA cannot load the
  binary at all, but Ghidra can.

Design decision (jani, 2026-07-15): IDA Pro is the DEFAULT engine (paid, professional,
more capable on x86/ARM). This router keeps IDA default and AUTO-FALLS-BACK to Ghidra
ONLY when the binary's architecture is one IDA cannot handle headlessly. The user is
never silently switched away from IDA for a binary IDA supports.

The selector is a pure function over a binary's ELF/PE/Mach-O header (no engine launch
needed for the cheap path), so it is cheap and degrades gracefully: if detection fails,
fall back to the configured default engine.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional


# Architectures Ghidra/SLEIGH handles but IDA 9.1 does NOT load headlessly.
# (IDA needs a registered processor module; 9.1 won't auto-discover custom .py
# processors — proven live with the eBPF/Solana plugin.)
_GHIDRA_ONLY_ARCHS = {
    # AVR (Atmel) — 0x1057
    "avr": 0x1057,
    # Tricore — 0x0522
    "tricore": 0x0522,
    # Xtensa — 0x5E
    "xtensa": 0x005E,
    # Renesas (V850 etc.) — 0x9081 / 0xAE57
    "v850": 0x9081,
}


def _elf_machine(binary: Path) -> Optional[int]:
    """Return the ELF e_machine field, or None if not an ELF."""
    try:
        with open(binary, "rb") as fh:
            magic = fh.read(4)
            if magic[:4] != b"\x7fELF":
                return None
            # EI_DATA (offset 5) selects the header byte order: 1 = LSB, 2 = MSB.
            fh.seek(5)
            ei_data = fh.read(1)
            endian = ">" if ei_data == b"\x02" else "<"
            # e_machine is a half at offset 18 (ELF32 and ELF64 both).
            fh.seek(18)
            data = fh.read(2)
            if len(data) < 2:
                return None
            return struct.unpack(endian + "H", data)[0]
    except Exception:
        return None


def _ghidra_only_for_machine(machine: int) -> Optional[str]:
    """Map an ELF e_machine to a Ghidra-only arch name, or None if IDA can handle it."""
    # x86, ARM, MIPS, PowerPC, SPARC, 68k, IA-64, RISC-V — IDA handles these fine.
    ida_ok = {
        0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "ARM64",
        0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x02: "SPARC",
        0x04: "68k", 0x32: "IA-64", 0xF3: "RISC-V",
    }
    if machine in ida_ok:
        return None
    # Architectures that still require Ghidra/SLEIGH.
    for name, m in _GHIDRA_ONLY_ARCHS.items():
        if m == machine and machine != 0x0000:
            return name
    # Unknown e_machine (non-zero, not in ida_ok, not explicitly mapped) — treat as
    # Ghidra-only to be safe (IDA likely can't load it). Zero-machine = unknown format.
    if machine not in (0x0000,):
        return f"unknown_arch_0x{machine:04X}"
    return None


def _ida_solana_runtime_available() -> bool:
    """Return whether IDA's custom SBF loader and processor are runnable."""

    try:
        from ..config import load_config
        from ..solana.adapters import collect_solana_adapter_status

        statuses = collect_solana_adapter_status(load_config("ida"))
        return any(
            status.name == "ida-solana-processor" and status.available
            for status in statuses
        )
    except Exception:
        return False


def select_engine(
    binary: str | Path,
    default: str = "ida",
    *,
    ida_solana_available: bool | None = None,
) -> tuple[str, str]:
    """Return (engine, reason).

    engine is "ida" or "ghidra". IDA is preferred; Ghidra is selected only when the
    binary's architecture is one IDA cannot load headlessly. ``reason`` explains the
    choice for logging/transparency.
    """
    binary = Path(binary)
    machine = _elf_machine(binary)
    if machine is None:
        # Not an ELF (PE/Mach-O) — default engine handles those on its own; don't
        # override the user's default.
        return default, f"non-ELF binary -> use default engine ({default})"
    if machine in {0x00F7, 0x0107} and default == "ida":
        available = (
            _ida_solana_runtime_available()
            if ida_solana_available is None
            else ida_solana_available
        )
        if available:
            return "ida", (
                f"ELF arch 0x{machine:04X} is supported by the installed "
                "Solana SBF loader; keeping IDA as primary and using Ghidra "
                "as decompilation evidence"
            )
        return "ghidra", (
            f"ELF arch 0x{machine:04X} requires the Solana SBF loader, "
            "which is unavailable; routing to Ghidra/eBPF"
        )
    ghidra_arch = _ghidra_only_for_machine(machine)
    if ghidra_arch and default == "ida":
        return "ghidra", (
            f"architecture 0x{machine:04X} ({ghidra_arch}) is not loadable by IDA 9.1 "
            f"headlessly; routing to Ghidra/SLEIGH (IDA remains default for x86/ARM)")
    return default, f"ELF arch 0x{machine:04X} supported by {default}"
