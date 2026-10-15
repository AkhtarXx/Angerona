"""Source-DB anchor retrieval (Pattern D-i, research Part 3 / Gagnon 2607.09452).

Research basis (angerona research notes, 2026-07-15, Part 3 + Part 4):
  Gagnon et al. (2607.09452) — Anchor-Based Retrieval + LLM Reasoning: recover source
  from binary functions via Ghidra-extracted ANCHORS (strings, constants, externals,
  symbols) -> inverted-index DB -> LLM rerank. 95.2% instruction coverage on a
  high-fidelity DB, dropping to 35.5% on a noisy GitHub DB — DATABASE QUALITY DOMINATES.
  This is Pattern D(i); angerona has D(ii) (corpus identity) but NOT D(i).

What this module does (production, deterministic core):
  - Extracts anchors from a target's exported facts (strings/constants/imports/symbols)
    and from a source-DB of known source files.
  - Builds an inverted index (anchor token -> source files) and ranks candidate source
    files by anchor overlap with the target (Jaccard + weighted by rarity of the anchor).
  - Returns ranked (source_file, score, matched_anchors) so the supervisor can seed
    worker analysis with ground-truth source where a DB exists.
  - Optional ``rerank_fn`` hook lets a caller plug an LLM rerank on top (kept separate
    so the deterministic core is always available and testable without network/LLM).

Graceful: empty target anchors or empty DB -> empty ranking (no false positives).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# anchors we trust: string literals, hex constants, imported/exported symbols, magic bytes
_STR_LIT = re.compile(r"\"([^\"]{4,80})\"")
_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_DEC = re.compile(r"\b(1[0-9]{3}|20[0-9]{2}|0x[0-9a-fA-F]{4,})\b")
_SYM = re.compile(r"\b([a-z][a-z0-9_]{3,})\b", re.I)


@dataclass
class AnchorHit:
    source_file: str
    score: float
    matched_anchors: list[str]

    def as_dict(self) -> dict:
        return {"source_file": self.source_file, "score": round(self.score, 4),
                "matched_anchors": self.matched_anchors[:30]}


def extract_anchors(text: str) -> set[str]:
    """Extract a set of anchor tokens from free text (report, source, strings dump)."""
    anchors: set[str] = set()
    for m in _STR_LIT.finditer(text):
        anchors.add("str:" + m.group(1).lower())
    for m in _HEX.finditer(text):
        anchors.add("hex:" + m.group(0).lower())
    for m in _DEC.finditer(text):
        anchors.add("num:" + m.group(0))
    # symbol-like tokens (skip C keywords / common words)
    skip = {"void", "int", "char", "return", "if", "else", "for", "while", "static",
            "const", "struct", "the", "and", "or", "this", "that", "with", "from"}
    for m in _SYM.finditer(text):
        tok = m.group(1).lower()
        if tok not in skip and len(tok) >= 4:
            anchors.add("sym:" + tok)
    return anchors


def _rare_weight(anchor: str, doc_freq: dict[str, int], n_docs: int) -> float:
    """IDF-style rarity weight: rarer anchor -> stronger signal (mirrors DB-quality effect)."""
    df = doc_freq.get(anchor, 0)
    if df == 0:
        df = 1
    import math
    return math.log((n_docs + 1) / df) + 1.0


def rank_sources(target_anchors: set[str], source_db_dir: str | Path,
                 top_k: int = 10,
                 rerank_fn: Optional[Callable[[list[AnchorHit], str], list[AnchorHit]]] = None,
                 target_text: str = "") -> list[AnchorHit]:
    """Rank source files in ``source_db_dir`` by anchor overlap with ``target_anchors``.

    ``target_text`` is the raw target text (for the optional rerank hook).
    Returns ranked AnchorHit list (empty if no overlap / empty inputs).
    """
    d = Path(source_db_dir)
    source_files: list[Path] = []
    for ext in ("*.c", "*.cpp", "*.h", "*.py", "*.go", "*.rs"):
        source_files.extend(d.rglob(ext))
    if not source_files or not target_anchors:
        return []

    doc_anchors: dict[Path, set[str]] = {}
    doc_freq: dict[str, int] = {}
    for sf in source_files:
        try:
            a = extract_anchors(sf.read_text(errors="ignore"))
        except Exception:
            a = set()
        doc_anchors[sf] = a
        for anc in a:
            doc_freq[anc] = doc_freq.get(anc, 0) + 1

    n_docs = len(source_files)
    hits: list[AnchorHit] = []
    for sf, a in doc_anchors.items():
        shared = a & target_anchors
        if not shared:
            continue
        # weighted Jaccard: sum IDF-weighted shared / sum IDF-weighted union
        num = sum(_rare_weight(x, doc_freq, n_docs) for x in shared)
        den = sum(_rare_weight(x, doc_freq, n_docs) for x in (a | target_anchors))
        score = num / den if den else 0.0
        hits.append(AnchorHit(source_file=str(sf), score=score,
                               matched_anchors=sorted(shared)))
    hits.sort(key=lambda h: h.score, reverse=True)
    hits = hits[:top_k]
    if rerank_fn is not None:
        try:
            hits = rerank_fn(hits, target_text)
        except Exception:
            pass  # rerank is best-effort; keep deterministic ranking
    return hits


def rank_from_export(export_dir: str | Path, source_db_dir: str | Path,
                     top_k: int = 10) -> list[AnchorHit]:
    """Convenience: build target anchors from an angerona export dir then rank sources."""
    d = Path(export_dir)
    chunks: list[str] = []
    for name in ("strings.txt", "imports.txt", "exports.txt", "symbols.txt"):
        p = d / name
        if p.is_file():
            chunks.append(p.read_text(errors="ignore"))
    target_anchors = extract_anchors("\n".join(chunks))
    return rank_sources(target_anchors, source_db_dir, top_k=top_k)
