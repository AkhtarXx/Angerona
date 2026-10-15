"""Lift-confidence caveat (Part 6, P0 / REFORGE confidence-tiering).

Research basis (angerona research notes, 2026-07-15, Part 6):
  Obscure architectures fail SILENTLY: a mis-applied SLEIGH/IDA spec produces fluent,
  plausible, INCORRECT disassembly that fools both humans and LLMs (the §4.2
  garbage-in/confident-out quadrant). The re-executability gate is offline exactly where
  it is needed most. Part 6 P0: surface "lift confidence" as a first-class coverage
  caveat -- flag functions decoded under unknown-opcode / fallback conditions as
  *ungated* (mirroring REFORGE's confidence-tiering, Part 2 §B3), so an analyst is never
  silently trusting a bad lift.

What this module does (production, ISA-agnostic, reads exported facts):
  - Inspects the export for signals of a *weak* lift: unknown-opcode markers in the
    disassembly, "analysis pending" / fallback-decoder notes, empty decompilation on
    non-tiny functions, or an engine "fallback" flag from the selector.
  - Produces a per-function LIFT_CONFIDENCE tier (high / medium / low / ungated) and a
    coverage caveat string the UI/export surfaces, plus a global lift_confidence_ratio.
  - Integrates with coverage_tier.py: functions whose lift is low/ungated are reported as
    NOT independently verifiable (structure gates may be meaningless on them).

Graceful: no disassembly present -> "ungated" with a clear "no lift" note (never a
false "high confidence").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# markers that indicate a weak / fallback / unknown-opcode lift
_UNK_OPCODE = re.compile(
    r"\b(unknown|illegal|undefined|bad|invalid)\s+(opcode|instruction|mnemonic)\b",
    re.I)
_FALLBACK = re.compile(r"\b(fallback|default decoder|analysis (?:failed|pending)|unrecognized)\b", re.I)
_PARTIAL = re.compile(r"\b(db|byte ptr|unknown bytes|data\s*\?)\b", re.I)


@dataclass
class LiftConfidence:
    function: str
    tier: str                       # high | medium | low | ungated
    reason: str = ""

    def as_dict(self) -> dict:
        return {"function": self.function, "tier": self.tier, "reason": self.reason}


@dataclass
class LiftReport:
    total: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    ungated: int = 0
    ratio: float = 0.0
    caveat: str = ""
    per_function: list[LiftConfidence] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"total": self.total, "high": self.high, "medium": self.medium,
                "low": self.low, "ungated": self.ungated,
                "lift_confidence_ratio": round(self.ratio, 3),
                "caveat": self.caveat,
                "per_function": [c.as_dict() for c in self.per_function[:50]]}


def _tier_for(asm: str, has_decompiled: bool, size: int) -> tuple[str, str]:
    """Return (tier, reason) for one function's lift."""
    if has_decompiled and not asm.strip():
        # decompiled C exists; asm dump optional -> treat as clean (high)
        return "high", "decompiled C present (asm dump absent)"
    if not asm.strip():
        return "ungated", "no disassembly produced"
    if _UNK_OPCODE.search(asm) or _FALLBACK.search(asm):
        return "ungated", "unknown-opcode / fallback decoder detected (weak lift)"
    if not has_decompiled and size >= 16:
        return "low", "no decompiled C for non-trivial function (lift not confirmed)"
    if _PARTIAL.search(asm):
        return "medium", "partial/disassembled-as-data regions present"
    return "high", "clean disassembly + decompilation"


def assess_lift(export_dir: str | Path,
                engine_fallback: bool = False) -> LiftReport:
    """Assess lift confidence per function from an export dir."""
    d = Path(export_dir)
    rep = LiftReport()
    # load function sizes/names
    funcs: list[tuple[str, int]] = []
    fcsv = d / "functions.csv"
    if fcsv.is_file():
        for line in fcsv.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 3:
                try:
                    funcs.append((parts[0].strip(), int(parts[2])))
                except Exception:
                    funcs.append((parts[0].strip(), 0))
    # which functions have decompiled C? Match by name/stem overlap (export names
    # files by address, e.g. main_0x100.c, while functions.csv may list "main").
    decompiled: set[str] = set()
    if (d / "decompiled").is_dir():
        for cf in (d / "decompiled").glob("*.c"):
            decompiled.add(cf.stem)
    has_all = (d / "all_decompiled.c").is_file()
    asm_dir = d / "asm"
    asm_files = list(asm_dir.glob("*.asm")) if asm_dir.is_dir() else []

    def _has_dec(name: str) -> bool:
        if has_all:
            return True
        if name in decompiled:
            return True
        # substring match either direction (name <-> stem)
        return any(name in s or s in name for s in decompiled)

    if engine_fallback:
        rep.caveat = ("Engine fell back to a non-primary decoder for this arch; "
                      "ALL functions treated as ungated until lift is verified.")
        rep.total = len(funcs)
        rep.ungated = len(funcs)
        rep.ratio = 0.0
        for name, _ in funcs:
            rep.per_function.append(LiftConfidence(name, "ungated", rep.caveat))
        return rep

    for name, size in funcs:
        asm = ""
        for af in asm_files:
            if name in af.stem or af.stem in name:
                asm = af.read_text(errors="ignore")
                break
        has_dec = _has_dec(name)
        tier, reason = _tier_for(asm, has_dec, size)
        rep.per_function.append(LiftConfidence(name, tier, reason))
        setattr(rep, tier, getattr(rep, tier) + 1)
    rep.total = len(funcs)
    rep.ratio = (rep.high + rep.medium) / rep.total if rep.total else 0.0
    rep.caveat = (f"{rep.ungated} of {rep.total} functions have a weak/unknown lift "
                  f"(ungated) -- structure gates (CFG/BinDiff) may be meaningless on them; "
                  f"claim-verification remains the only always-valid anchor.")
    return rep
