"""Composite verification metric — replaces the single BinDiff similarity threshold.

Research basis (angerona research notes, 2026-07-15):
  Part 3 / Part 12: a SINGLE similarity threshold (bindiff_threshold=0.7) is a GAMEABLE
  proxy. An attacker (or a confident hallucination) can hit one signal while failing
  others. The 2026 consensus is a COMPOSITE metric: combine the independent pillars
  (claims, capabilities, type-fidelity, provenance, structural similarity) into one
  score with explicit weights, and gate on the composite — not on any single axis.

This module is the orchestrator the loop calls instead of trusting one number. Each
pillar returns verified=True/False (graceful). We combine them: a hard-fail on any
NON-GRACEFUL pillar forces NEEDS_WORK; the composite score is the weighted mean of
per-pillar confidence, surfaced for transparency and tuning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

# Pillar weights — structural similarity is the strongest objective signal, provenance
# is a hard safety gate, content pillars are corroboration. Tunable via set_weights().
_DEFAULT_WEIGHTS = {
    "claims": 0.20,
    "capabilities": 0.20,
    "type_fidelity": 0.15,
    "provenance": 0.25,   # safety gate — weighted highest among content pillars
    "structural": 0.20,   # bindiff similarity
}


@dataclass
class PillarResult:
    name: str
    verified: bool
    confidence: float          # 0.0 (fail) .. 1.0 (pass); graceful-skip = 1.0 w/ no evidence
    evidence: str = ""         # "skipped" | "checked" | "collapsed" etc.
    hard_fail: bool = False    # True => forces NEEDS_WORK regardless of composite


@dataclass
class CompositeReport:
    score: float
    verified: bool
    pillars: list[PillarResult] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "verified": self.verified,
            "pillars": [
                {"name": p.name, "verified": p.verified, "confidence": round(p.confidence, 3),
                 "evidence": p.evidence, "hard_fail": p.hard_fail} for p in self.pillars
            ],
            "detail": self.detail,
        }


class CompositeVerifier:
    """Combine verification pillars into one decision + transparent score."""

    def __init__(self, weights: Optional[dict] = None):
        self.weights = dict(_DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

    def _pillar(self, name: str, verified: bool, evidence: str,
                hard_fail: bool = False, confidence: Optional[float] = None) -> PillarResult:
        if confidence is None:
            confidence = 1.0 if verified else 0.0
        return PillarResult(name=name, verified=verified, confidence=confidence,
                            evidence=evidence, hard_fail=hard_fail)

    def evaluate(self, pillars: list[PillarResult],
                 structural_similarity: Optional[float] = None) -> CompositeReport:
        """Evaluate. ``structural_similarity`` (0-1) feeds the 'structural' pillar when
        supplied; otherwise that pillar is treated as no-evidence (graceful)."""
        results = list(pillars)
        if structural_similarity is not None:
            results.append(self._pillar(
                "structural", structural_similarity >= 0.7,
                f"similarity={structural_similarity:.3f}",
                confidence=structural_similarity))
        else:
            results.append(self._pillar("structural", True, "no evidence (skipped)"))

        # Hard-fail gates (provenance collapse, injection-driven) force NEEDS_WORK.
        hard_fails = [p for p in results if p.hard_fail]
        if hard_fails:
            return CompositeReport(
                score=0.0, verified=False, pillars=results,
                detail="; ".join(f"HARD_FAIL[{p.name}]: {p.evidence}" for p in hard_fails))

        # Weighted composite of confidence across weighted pillars.
        total_w = 0.0
        acc = 0.0
        for p in results:
            w = self.weights.get(p.name, 0.0)
            if w == 0.0:
                continue
            total_w += w
            acc += w * p.confidence
        score = (acc / total_w) if total_w else 1.0
        # Any non-graceful pillar failing => the composite is not "verified" even if the
        # mean is high (we don't let one strong signal mask a contradiction).
        any_failed = any(not p.verified for p in results if p.evidence != "no evidence (skipped)")
        verified = (not any_failed) and score >= 0.7
        return CompositeReport(
            score=score, verified=verified, pillars=results,
            detail=("composite pass" if verified else "composite fail"))
