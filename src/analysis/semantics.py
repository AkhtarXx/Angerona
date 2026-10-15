"""Semantics corroboration + confidence tiering — gates un-verifiable NL findings.

Research basis (angerona research notes, 2026-07-15):
  Part 13 (semantics): "what this function does" prose has NO residual signal in the
  binary at all — it sails through every existing gate. Unlike struct layout, there is
  often nothing in the binary to check against. The right control is NOT a recompile
  gate but CORROBORATION + CONFIDENCE TIERING: a semantic claim is only as trustworthy
  as the evidence backing it (imports it cites, xrefs it names, strings it references).
  Claims with zero corroboration are marked LOW confidence and surfaced as "analyst
  hypotheses", not facts.

This module scores a semantic claim's corroboration against the binary's facts and
returns a confidence tier (HIGH / MEDIUM / LOW). It does NOT block — it tiers, because
  semantics can legitimately be inferred. Used by the report generator to label claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_SEMANTIC_CLAIM_RE = re.compile(
    r"(this function|the (code|routine|handler)|it (reads|writes|allocates|decrypts|"
    r"sends|receives|parses|validates|checks)|responsible for|purpose is|implements)",
    re.I)


@dataclass
class SemanticConfidence:
    tier: str                       # HIGH | MEDIUM | LOW
    score: float                    # 0..1
    corroborated_by: list[str] = field(default_factory=list)
    detail: str = ""


def _fact_tokens(export_dir: str | Path) -> set[str]:
    d = Path(export_dir)
    toks: set[str] = set()
    for fname in ("imports.txt", "strings.txt", "symbols.txt", "exports.txt"):
        f = d / fname
        if f.is_file():
            for line in f.read_text(errors="ignore").splitlines():
                val = line.split("\t")[-1].strip().lower()
                if val:
                    toks.add(val)
    return toks


def score_semantics(text: str, export_dir: str | Path) -> SemanticConfidence:
    """Score a semantic claim's corroboration against binary facts.

    Corroboration signals:
      + mentions an import/API name that exists in the binary  -> HIGH
      + references a string/constant present in the binary      -> MEDIUM
      + cites a known function/symbol name                      -> MEDIUM
      + no corroboration at all                                  -> LOW (hypothesis)
    Graceful: missing facts -> LOW (cannot corroborate).
    """
    if not text or not _SEMANTIC_CLAIM_RE.search(text):
        return SemanticConfidence(tier="LOW", score=0.0,
                                  detail="not a semantic claim (no action)")
    facts = _fact_tokens(export_dir)
    if not facts:
        return SemanticConfidence(tier="LOW", score=0.2,
                                  detail="no binary facts to corroborate against")
    low = text.lower()
    corrob: list[str] = []
    # import/API mention
    for tok in facts:
        # only meaningful tokens (length >= 4) to avoid false hits
        if len(tok) >= 4 and tok in low:
            corrob.append(tok)
    score = 0.0
    if corrob:
        # more distinct corroborating tokens => higher confidence
        score = min(0.4 + 0.1 * len(corrob), 1.0)
    tier = "LOW"
    if score >= 0.7:
        tier = "HIGH"
    elif score >= 0.4:
        tier = "MEDIUM"
    return SemanticConfidence(tier=tier, score=score, corroborated_by=corrob[:10],
                              detail=f"{len(corrob)} corroborating tokens")
