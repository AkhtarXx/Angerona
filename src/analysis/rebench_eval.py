"""Uncertainty-aware evaluation harness (Part 3, recommendation 6 / Reforge 2607.07738).

Research basis (angerona research notes, 2026-07-15, Part 3):
  Reforge (2607.07738) shows capability is over-claimed because benchmarks "report
  accuracy without disclosing how many functions were reliably evaluable" -- high-confidence
  yield falls from 87.2% to 65.9% across optimization levels, and unpaired comparisons
  overstate decay via SURVIVORSHIP BIAS. To report angerona's function-naming / type
  inference honestly we must (a) stratify by an evaluability/confidence funnel and (b) only
  compare PAIRED functions (same ground-truth function present in both samples), never drop
  un-alignable functions and silently inflate the rate.

What this module does (production, no external benchmark needed):
  - Takes a set of (predicted_name, ground_truth_name, confidence_tier) triples.
  - Computes accuracy ONLY over functions whose ground truth is reliably evaluable
    (tier >= threshold) -- the "high-confidence yield", not the flat number.
  - Reports paired vs unpaired counts so survivorship bias is explicit (we never hide how
    many functions were excluded).
  - Emits a REFORGE-style funnel: total -> evaluable -> paired -> correct.

Graceful: empty input -> zeroed report (no false 100%).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EvalRow:
    predicted: str
    ground_truth: Optional[str]   # None => no reliable ground truth (unaligned)
    confidence_tier: int = 3       # 0..3 (3 = highest evaluability)


@dataclass
class EvalReport:
    total: int = 0
    evaluable: int = 0            # ground_truth present AND tier >= min_tier
    paired: int = 0               # also has a prediction to compare
    correct: int = 0
    accuracy: float = 0.0
    flat_accuracy: float = 0.0    # naive (ignores evaluability) -- for contrast
    note: str = ""

    def as_dict(self) -> dict:
        return {"total": self.total, "evaluable": self.evaluable, "paired": self.paired,
                "correct": self.correct, "accuracy": round(self.accuracy, 4),
                "flat_accuracy": round(self.flat_accuracy, 4), "note": self.note}


def evaluate(rows: list[EvalRow], min_tier: int = 2) -> EvalReport:
    """Compute an uncertainty-aware accuracy report (Reforge-style funnel).

    ``min_tier`` is the evaluability floor for a function to count toward the honest
    accuracy. Functions below it (or with no ground truth) are reported as EXCLUDED, not
    silently dropped -- survivorship bias is made explicit.
    """
    rep = EvalReport(total=len(rows))
    flat_correct = 0
    flat_total = 0
    for r in rows:
        has_gt = r.ground_truth is not None
        if has_gt and r.predicted:  # only rows with a prediction AND gt are flat-compared
            flat_total += 1
            if r.predicted == r.ground_truth:
                flat_correct += 1
        if has_gt and r.confidence_tier >= min_tier:
            rep.evaluable += 1
            if r.predicted:
                rep.paired += 1
                if r.predicted == r.ground_truth:
                    rep.correct += 1
    rep.flat_accuracy = (flat_correct / flat_total) if flat_total else 0.0
    rep.accuracy = (rep.correct / rep.paired) if rep.paired else 0.0
    excluded = rep.total - rep.evaluable
    rep.note = (f"{excluded} of {rep.total} functions excluded from honest accuracy "
                f"(unaligned ground truth or tier<{min_tier}); flat_accuracy "
                f"{rep.flat_accuracy:.2f} vs evaluable_accuracy {rep.accuracy:.2f} "
                f"-- gap shows survivorship bias when present.")
    return rep
