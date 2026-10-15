"""Corpus-coverage caveat for identity findings (B4, research Part 2 / Anchor 2607.09452).

Research basis (angerona research notes, 2026-07-15, Part 2 B4):
  Anchor-Based Retrieval (2607.09452) hits 95.2% assembly-instruction coverage on a
  high-fidelity DB but only 35.5% on a generic GitHub DB — a ~60-point swing PURELY from
  corpus quality. Angerona's match_against_corpus / corpus_dir identity check inherits this
  cliff: its value is a function of corpus coverage, and a retrieval MISS looks identical
  to a genuine "no known match / novel code." B4 says we must surface corpus coverage as a
  caveat so an identity finding is never over-read.

This module wraps corpus-match output with an explicit, honest caveat string the report
and MCP tool should surface: it reports the corpus SIZE (how many reference binaries were
compared) and states plainly that absence of a match does not imply novel code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CorpusCaveat:
    corpus_path: str
    corpus_size: int                # number of reference .BinExport files compared
    matched: bool
    caveat: str = ""
    confidence_note: str = ""

    def as_dict(self) -> dict:
        return {
            "corpus_path": self.corpus_path, "corpus_size": self.corpus_size,
            "matched": self.matched, "caveat": self.caveat,
            "confidence_note": self.confidence_note,
        }


def _count_refs(corpus_dir: str | Path) -> int:
    d = Path(corpus_dir)
    return len(list(d.glob("**/*.BinExport")))


def attach_corpus_caveat(corpus_dir: str | Path, matched: bool,
                         best_similarity: float | None = None) -> CorpusCaveat:
    """Build an honest caveat for a corpus-identity finding.

    ``matched`` = did we find a reference binary above threshold.
    Always reports corpus_size so the reader knows the EVIDENCE BASE. The caveat makes
    explicit that a non-match is a coverage statement, not a novelty claim (B4).
    """
    size = _count_refs(corpus_dir)
    if matched:
        caveat = (f"Matched against a corpus of {size} reference binaries; a hit means "
                  f"structural similarity to known code, NOT proof of origin. Lower corpus "
                  f"coverage weakens this signal (Anchor 2607.09452: retrieval quality swings "
                  f"~60 points with corpus fidelity).")
        note = f"corpus_size={size}; treat as 'similar to known', not 'identical to X'"
    else:
        caveat = (f"No match in corpus of {size} reference binaries. Per B4 (Anchor "
                  f"2607.09452), ABSENCE OF MATCH DOES NOT IMPLY NOVEL CODE — it may be a "
                  f"retrieval miss (corpus too small/low-fidelity). Do not report 'novel/"
                  f"unknown' without corroborating evidence.")
        note = f"corpus_size={size}; miss != novel; corroborate before claiming unknown"
    return CorpusCaveat(corpus_path=str(corpus_dir), corpus_size=size,
                        matched=matched, caveat=caveat, confidence_note=note)
