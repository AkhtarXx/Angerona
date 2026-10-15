"""Behavior tests for REFORGE-style honest coverage tiering (roadmap Phase A1).

Proves:
  1. coverage tiering exposes high_confidence_ratio (REFORGE honest yield) and per-function tiers.
  2. weak/unknown-opcode lifts demote functions to tier0 (they no longer inflate tiers).
  3. backward-compat: stratify_coverage without a lift report behaves exactly as before.
  4. re_analysis wires lift-confidence into the coverage pass and emits a summary line.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.coverage_tier import stratify_coverage
from src.analysis.lift_confidence import LiftConfidence, LiftReport


def _export(tmp: Path, funcs: list[tuple[str, str, int, str]], decompiled: list[str]) -> Path:
    """funcs: (name, entry, size, signature). decompiled: file stems present in decompiled/."""
    lines = ["name,entry,size,signature"] + [",".join(map(str, f)) for f in funcs]
    (tmp / "functions.csv").write_text("\n".join(lines) + "\n")
    (tmp / "decompiled").mkdir(exist_ok=True)
    for stem in decompiled:
        (tmp / "decompiled" / f"{stem}.c").write_text("int f(){return 0;}")
    return tmp


def _lift(tiers: dict[str, str]) -> LiftReport:
    rep = LiftReport()
    rep.per_function = [LiftConfidence(name, tier, f"reason:{tier}")
                        for name, tier in tiers.items()]
    return rep


# --------------------------------------------------------------- high-confidence ratio

def test_high_confidence_ratio_exposed():
    d = _export(Path(tempfile.mkdtemp()),
                funcs=[("main", "0x100", 40, "int main()"),
                       ("helper", "0x300", 80, "int helper(int)"),
                       ("FUN_500", "0x500", 30, "")],        # auto name, decompiled -> tier2
                decompiled=["main_0x100", "helper_0x300", "FUN_500_0x500"])
    rep = stratify_coverage(d)
    assert rep.total == 3
    assert rep.tier_count(3) == 2          # main + helper
    assert rep.tier_count(2) == 1          # FUN_500
    assert rep.high_confidence_ratio == rep.tier_count(3) / rep.total
    assert abs(rep.high_confidence_ratio - (2 / 3)) < 1e-6
    # summary line is honest, no flat-only number
    line = rep.summary_line()
    assert "high-confidence" in line and "67%" in line


def test_no_functions_zero_division_safe():
    d = Path(tempfile.mkdtemp())
    (d / "functions.csv").write_text("name,entry,size,signature\n")
    rep = stratify_coverage(d)
    assert rep.total == 0
    assert rep.evalable_ratio == 0.0
    assert rep.high_confidence_ratio == 0.0


# --------------------------------------------------------------- lift-driven demotion

def test_weak_lift_demotes_to_tier0():
    d = _export(Path(tempfile.mkdtemp()),
                funcs=[("main", "0x100", 40, "int main()"),
                       ("handler_X", "0x200", 60, "void handler_X(int)")],
                decompiled=["main_0x100", "handler_X_0x200"])
    lift = _lift({"main": "high", "handler_X": "ungated"})
    rep = stratify_coverage(d, lift_report=lift)
    # handler_X had every high-tier signal but a weak lift: demoted to tier0
    assert rep.tier_count(3) == 1          # only main remains
    assert rep.tier_count(0) == 1
    assert rep.note and "demoted" in rep.note
    pf = {f.name: f for f in rep.per_function}
    assert pf["handler_X"].tier == 0
    assert "ungated" in pf["handler_X"].reason


def test_low_lift_also_demotes():
    d = _export(Path(tempfile.mkdtemp()),
                funcs=[("vm_handler", "0x300", 90, "")],
                decompiled=[])
    lift = _lift({"vm_handler": "low"})
    rep = stratify_coverage(d, lift_report=lift)
    # was tier1 (no decompiled), weak lift drags it to tier0
    assert rep.tier_count(0) == 1
    assert rep.tier_count(1) == 0


def test_high_lift_keeps_tier():
    d = _export(Path(tempfile.mkdtemp()),
                funcs=[("main", "0x100", 40, "int main()")],
                decompiled=["main_0x100"])
    lift = _lift({"main": "high"})
    rep = stratify_coverage(d, lift_report=lift)
    assert rep.tier_count(3) == 1
    assert not rep.note


# --------------------------------------------------------------- backward compat

def test_backward_compatible_without_lift():
    """No lift report -> identical behavior to the pre-upgrade module."""
    funcs = [("main", "0x100", 40, "int main()"),
             ("FUN_200", "0x200", 5, "")]  # tiny -> tier0
    d = _export(Path(tempfile.mkdtemp()), funcs=funcs, decompiled=["main_0x100"])
    rep = stratify_coverage(d)
    assert rep.total == 4 - 2  # 2 funcs
    assert rep.tier_count(0) == 1   # FUN_200 tiny
    assert rep.tier_count(3) == 1   # main
    assert rep.evalable_ratio == 0.5


# --------------------------------------------------------------- re_analysis wiring

def test_re_analysis_coverage_includes_lift_demotions_and_summary():
    from src.analysis.re_analysis import run_re_analysis

    d = _export(Path(tempfile.mkdtemp()),
                funcs=[("main", "0x100", 40, "int main()"),
                       ("mystery", "0x200", 60, "")],
                decompiled=["main_0x100"])
    # fake asm dir that marks mystery as a weak lift (unknown opcode)
    (d / "asm").mkdir()
    (d / "asm" / "mystery_0x200.asm").write_text(
        "mov eax, [rbx]\nunknown opcode 0xFF\nret\n")

    out = run_re_analysis(d)
    cov = out["passes"]["coverage_tier"]
    assert cov["total"] == 2
    assert "high_confidence_ratio" in cov
    assert "summary" in cov
    assert "high-confidence" in cov["summary"]
    # mystery has a weak lift -> demoted; main is tier3
    assert cov["tier3_high"] == 1
    assert cov["tier0_unreliable"] == 1
    assert abs(cov["high_confidence_ratio"] - 0.5) < 1e-6
