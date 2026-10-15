"""Coverage stratified by evaluability tier (B3, research Part 2 / REFORGE 2607.07738).

Research basis (angerona research notes, 2026-07-15, Part 2 B3 + A2):
  REFORGE shows capability is over-claimed because benchmarks "report accuracy without
  disclosing how many functions were reliably evaluable" — high-confidence yield falls
  from 87.2% to 65.9% across optimization levels, and unpaired comparisons overstate
  decay via survivorship bias. Angerona reports a flat "N functions analyzed" coverage
  number; per B3 that number is only as trustworthy as the *evaluability* of those
  functions (on -O2+ / stripped targets, some functions' ground truth is not reliably
  recoverable).

This module stratifies a binary's functions into evaluability tiers so coverage is
reported honestly:
  - TIER3 (high): named + has recovered type/signature + decompiled C present
  - TIER2 (medium): decompiled C present (behavior recoverable) but stripped/auto name
  - TIER1 (low): only disassembly/export, no decompiled C (structural only)
  - TIER0 (unreliable): tiny/thunk/compiler-stub, weak/unknown-opcode lift, or
    unrecovered — excluded from capability claims
The report surfaces:
  - evalable_ratio       (TIER1+TIER2+TIER3) / total        — coverage envelope
  - high_confidence_ratio  TIER3 / total                    — REFORGE-style honest yield

Optionally accepts a lift-confidence report (``src.analysis.lift_confidence``) so
functions whose disassembly was produced by a weak/fallback decoder are demoted to
tier0 (structure gates may be meaningless on them) instead of poisoning tier1+.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.analysis.lift_confidence import LiftReport


_AUTO = re.compile(r"^(FUN_|LAB_|SUB_|thunk_|loc_)", re.I)
_STUB = re.compile(r"^(_|sub_|nullsub|j_|compiler_|gcc_|__)", re.I)


@dataclass
class CoverageTier:
    tier: int                       # 0..3 (3 = highest evaluability)
    name: str
    count: int = 0
    example: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"tier": self.tier, "name": self.name,
                "count": self.count, "example": self.example[:10]}


@dataclass
class FunctionTier:
    """Per-function evaluability assignment, kept for reporting/audit."""

    name: str
    entry: str
    tier: int
    reason: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "entry": self.entry, "tier": self.tier,
                "reason": self.reason}


@dataclass
class CoverageReport:
    total: int = 0
    tiers: list[CoverageTier] = field(default_factory=list)
    evalable_ratio: float = 0.0         # (tier1+tier2+tier3) / total
    high_confidence_ratio: float = 0.0  # tier3 / total (REFORGE honest yield)
    flat_coverage: int = 0
    per_function: list[FunctionTier] = field(default_factory=list)
    note: str = ""

    def tier_count(self, tier: int) -> int:
        for t in self.tiers:
            if t.tier == tier:
                return t.count
        return 0

    def as_dict(self, *, include_functions: bool = False) -> dict:
        out = {
            "total": self.total,
            "flat_coverage": self.flat_coverage,
            "evalable_ratio": round(self.evalable_ratio, 3),
            "high_confidence_ratio": round(self.high_confidence_ratio, 3),
            "tier3_high": self.tier_count(3),
            "tier2_medium": self.tier_count(2),
            "tier1_low": self.tier_count(1),
            "tier0_unreliable": self.tier_count(0),
            "tiers": [t.as_dict() for t in self.tiers],
            "note": ("flat coverage should be read with evalable_ratio; tier3/total is "
                     "the REFORGE-style high-confidence yield; functions in tier0 are "
                     "excluded from capability claims (ground truth unreliable)."),
        }
        if self.note:
            out["lift_note"] = self.note
        if include_functions:
            out["per_function"] = [f.as_dict() for f in self.per_function]
        return out

    def summary_line(self) -> str:
        """One-line honest coverage summary for reports / the supervisor."""
        return (
            f"coverage: {self.total} functions "
            f"(high-confidence {self.tier_count(3)} "
            f"= {self.high_confidence_ratio:.0%}, "
            f"evaluable {self.tier_count(1) + self.tier_count(2) + self.tier_count(3)} "
            f"= {self.evalable_ratio:.0%}, "
            f"unreliable/excluded {self.tier_count(0)})"
        )


def _tier_for(func: dict, has_decompiled: bool) -> tuple[int, str]:
    name = (func.get("name") or "").strip()
    size = func.get("size", 0) or 0
    sig = (func.get("signature") or "").strip()
    # tier0: stubs / tiny / compiler artifacts
    if size < 8 or _STUB.match(name) or "import" in name.lower():
        return 0, "tiny/stub/import-thunk"
    # tier3: real name + signature + decompiled
    if has_decompiled and not _AUTO.match(name) and sig:
        return 3, "named + signature + decompiled"
    # tier2: decompiled but stripped/auto name
    if has_decompiled:
        return 2, "decompiled, auto name"
    # tier1: only structural (export/disasm), no decompiled C
    return 1, "no decompiled C (structural only)"


def stratify_coverage(
    export_dir: str | Path,
    lift_report: "LiftReport | None" = None,
) -> CoverageReport:
    """Stratify a binary's functions by evaluability tier from the export facts.

    When ``lift_report`` (from :func:`src.analysis.lift_confidence.assess_lift`) is
    supplied, functions whose lift tier is ``low`` or ``ungated`` are demoted to
    tier0 with the lift reason recorded — a weak/unknown-opcode lift means ground
    truth for that function is not reliably recoverable, so structural gates on it
    are excluded from capability claims (REFORGE honesty rule).
    """
    d = Path(export_dir)
    # load functions
    funcs: list[dict] = []
    fcsv = d / "functions.csv"
    if fcsv.is_file():
        for line in fcsv.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 3:
                funcs.append({"name": parts[0].strip(),
                              "entry": parts[1].strip(),
                              "size": _to_int(parts[2]),
                              "signature": parts[3].strip() if len(parts) > 3 else ""})
    # which functions have decompiled C? Files are named <name>_<entry>.c (e.g.
    # main_0x100.c), while functions.csv may list entry as "0x100" or "0x00000100" and
    # the name as "main" or "FUN_00000100" — so match against both raw fields and the
    # file-stem prefixes
    #   <name>_<entry>,  <name>_<norm(entry)>,  <norm(entry)>,  FUN_<norm(entry)>.
    decompiled: set[str] = set()
    cdir = d / "decompiled"
    if cdir.is_dir():
        for cf in cdir.glob("*.c"):
            decompiled.add(cf.stem)
    has_all = (d / "all_decompiled.c").is_file()

    def _norm_entry(entry: str) -> str:
        e = str(entry).strip().lower()
        return e if e.startswith("0x") else ("0x" + e)

    def _has_decompiled(name: str, entry: str) -> bool:
        if has_all:
            return True
        e = _norm_entry(entry)          # "0x00000100" (or "0x100" if given that way)
        e_short = "0x" + e[2:].lstrip("0") or "0x0"   # "0x100"
        candidates = (
            f"{name}_{e}",
            f"{name}_{e_short}",
            e,
            e_short,
            f"FUN_{e[2:].zfill(8)}",
            f"FUN_{e_short[2:]}",
            name,
        )
        for cand in candidates:
            if cand in decompiled:
                return True
        # relaxed prefix match: stem startswith "<name>_"
        prefix = f"{name}_"
        return any(stem.startswith(prefix) for stem in decompiled)

    # lift-confidence lookup (function name -> (tier, reason))
    lift_tiers: dict[str, tuple[str, str]] = {}
    if lift_report is not None:
        for conf in lift_report.per_function:
            lift_tiers[conf.function] = (conf.tier, conf.reason)

    tiers = [CoverageTier(3, "high-evaluability"), CoverageTier(2, "medium-evaluability"),
             CoverageTier(1, "low-evaluability-structural-only"),
             CoverageTier(0, "unreliable-stub/tiny/weak-lift")]
    per_function: list[FunctionTier] = []
    lift_note = ""
    demoted = 0
    for f in funcs:
        has_dec = _has_decompiled(f["name"], f["entry"])
        t, reason = _tier_for(f, has_dec)
        # REFORGE honesty: a weak/unknown-opcode lift demotes the function to tier0
        # regardless of name/signature/decompile signals — ground truth unreliable.
        lift = lift_tiers.get(f["name"])
        if lift is not None and lift[0] in ("low", "ungated"):
            if t > 0:
                demoted += 1
            t = 0
            reason = f"weak lift ({lift[0]}): {lift[1]}"
        tiers[3 - t].count += 1
        if len(tiers[3 - t].example) < 10:
            tiers[3 - t].example.append(f["name"])
        per_function.append(FunctionTier(f["name"], f["entry"], t, reason))
    if demoted and lift_report is not None:
        lift_note = (f"{demoted} function(s) demoted to tier0 by lift-confidence "
                     "(low/ungated); structure gates excluded for them.")
    total = len(funcs)
    evalable = sum(t.count for t in tiers[:3])  # tiers 1,2,3
    high = tiers[0].count  # tier3
    rep = CoverageReport(
        total=total, tiers=tiers, flat_coverage=total,
        evalable_ratio=(evalable / total) if total else 0.0,
        high_confidence_ratio=(high / total) if total else 0.0,
        per_function=per_function,
        note=lift_note,
    )
    return rep


def _to_int(s: str) -> int:
    try:
        return int(s)
    except Exception:
        return 0
