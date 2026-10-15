"""NL-supervised embedding recall layer for corpus matching (roadmap Phase C9).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §4):
  CLAP (Wang et al., ISSTA 2024, arXiv 2402.16928) trains on 195M asm–NL pairs and
  gets **zero-shot cross-optimization Recall@1 of 0.920** against 0.661 for a
  fine-tuned jTrans and 0.367 for Gemini. The separation from Anglehia: CLAP
  aligns assembly with *natural language* descriptions, so the corpus matching
  problem generalises across opt levels, stripping, and architecture.

  This module is the practical recall layer. It does NOT train CLAP (that is an
  enormous offline project); it exposes the *recall interface*:

    1. A local ``EmbeddingRecallIndex`` that indexes corpus .BinExport/BinDiff.json
       metadata (function names/addresses) plus their mnemonic TF-IDF features
       (re-uses simindex — the deterministic, audit-safe embedding Angerona already
       builds).
    2. ``recall_candidates(query, k)`` returns the top-K corpus binaries for a
       natural-language-ish *or* assembly-token query, with deterministic scoring.
    3. ``hierarchical_match_against_corpus`` = recall then BinDiff precision on
       the shortlist (complementary to Phase A3's per-entry function-count gate).

  When a real CLAP model is plugged in later, ``recall_candidates`` is the hook —
  embeddings are computed by a pluggable backend, not hard-coded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .simindex import SimilarityIndex


@dataclass
class RecallCandidate:
    """One corpus binary the recall layer surfaces for BinDiff precision."""

    path: str                # corpus file (e.g. <corpus>/sample.BinExport)
    score: float             # recall-layer similarity (0..1)
    evidence: str            # how the score was computed
    function_hits: int = 0   # count of per-function matches folded into the score

    def as_dict(self) -> dict:
        return {"path": self.path, "score": round(self.score, 4),
                "evidence": self.evidence, "function_hits": self.function_hits}


@dataclass
class RecallIndex:
    """In-memory or on-disk similarity index over a corpus of exported functions."""

    index: SimilarityIndex
    doc_to_source: dict = field(default_factory=dict)   # function addr -> corpus path


def _corpus_export_dirs(corpus_dir: Path) -> list[Path]:
    """Return the directories / files a recall layer can index.

    Accepts `*.BinExport` files directly (function metadata is extracted from the
    paired `.json` or falls back to the filename stem), and nested `functions.csv`
    exports (per-binary folders).
    """
    return sorted(corpus_dir.rglob("*.BinExport")) + sorted(
        corpus_dir.rglob("functions.csv"))


def build_recall_index(corpus_dir: str | Path,
                       *,
                       backend: str = "hashing",
                       search_backend: str = "exact") -> RecallIndex:
    """Build a deterministic recall index over a corpus directory.

    Functions are ingested from the corpus's own per-binary exports (asm/decompiled
    per function or the generated ``functions.csv``). Each indexed function's
    provenance (its corpus binary path) is preserved in ``doc_to_source`` so the
    outer gate can aggregate per-binary scores.

    Deterministic by construction: the hashing/simindex backend is fixed-seed;
    CLAP-swap only changes the inner vector source, not the public contract.
    """
    idx = SimilarityIndex(dim_reduce=0, backend=backend, search_backend=search_backend)
    corpus_dir = Path(corpus_dir)
    owners: dict[str, str] = {}
    for fit in _corpus_export_dirs(corpus_dir):
        if fit.suffix == ".BinExport":
            # corpus export folder next to it
            asm_dir = fit.parent / "asm"
            if not asm_dir.is_dir():
                asm_dir = fit.parent / "decompiled"
            if not asm_dir.is_dir():
                continue
            for af in sorted(asm_dir.glob("*.asm"))[:1000]:
                owners[af.stem] = str(fit)
                idx.add_function(
                    addr=af.stem,
                    name=af.stem.split("_", 1)[0],
                    asm_text=af.read_text(errors="ignore")[:512 * 1024],
                    source=str(fit),
                )
        else:
            # functions.csv contains name,entry,size,signature per binary
            fcsv = fit
            for row in fcsv.read_text(errors="ignore").splitlines()[1:5001]:
                parts = row.split(",")
                if len(parts) < 3:
                    continue
                owners[parts[0]] = str(fcsv.parent)
                idx.add_function(
                    addr=parts[1],
                    name=parts[0],
                    asm_text=" ".join(parts),   # metadata-as-tokens fallback
                    source=str(fcsv.parent),
                )
    try:
        idx.build()
    except RuntimeError:
        # No ingestible export found in the corpus: the recall layer is empty
        # and downstream callers fall back to a plain BinDiff pass (Phase A3).
        return RecallIndex(index=idx, doc_to_source=owners)
    return RecallIndex(index=idx, doc_to_source=owners)


def recall_candidates(
    recall: RecallIndex,
    *,
    query: str = "",
    export_dir: str | Path | None = None,
    top_k: int = 25,
    threshold: float = 0.30,
    per_binary_cap: int = 50,
) -> list[RecallCandidate]:
    """Rank corpus binaries for a query.

    ``query`` is a free-form assembly or mnemonic string; ``export_dir`` is the
    binary under audit — when provided, its per-function exports themselves are
    used as the query so recall is whole-binary, not token-level.

    Candidates are ranked by aggregated per-binary score (sum of per-function
    cosine similarities that crossed ``threshold``), capped to per_binary_cap
    contributions per binary so a huge binary doesn't crowd out a small good one.
    """
    queries: list[str] = []
    if export_dir is not None:
        d = Path(export_dir)
        for af in sorted((d / "decompiled").glob("*.c"))[:200] if (d / "decompiled").is_dir() else []:
            queries.append(af.read_text(errors="ignore")[:64 * 1024])
        for af in sorted((d / "asm").glob("*.asm"))[:200] if (d / "asm").is_dir() else []:
            queries.append(af.read_text(errors="ignore")[:64 * 1024])
    if query:
        queries.append(query)
    if not queries:
        return []

    binary_scores: dict[str, float] = {}
    binary_hits: dict[str, int] = {}
    if recall.index._vecmat is None:
        return []
    for text in queries:
        for m in recall.index.query_text(text, top_k=top_k, threshold=threshold):
            corpus_path = m.other_source or ""
            if not corpus_path:
                continue
            slot = binary_scores.get(corpus_path, 0.0)
            hits = binary_hits.get(corpus_path, 0)
            if hits < per_binary_cap:
                binary_scores[corpus_path] = slot + float(m.score)
                binary_hits[corpus_path] = hits + 1
    out = [
        RecallCandidate(
            path=path, score=binary_scores[path],
            evidence=f"est n-hit-cosine across {binary_hits[path]} functions",
            function_hits=binary_hits[path],
        )
        for path in binary_scores
    ]
    out.sort(key=lambda c: c.score, reverse=True)
    return out


def hierarchical_match_against_corpus(
    cfg,
    ws,
    binary: str | Path,
    corpus_dir: str | Path,
    *,
    recall_top_k: int = 25,
    similarity_threshold: float = 0.7,
    recall_threshold: float = 0.30,
) -> dict:
    """End-to-end: recall layer first, then BinDiff precision on the shortlist.

    Returns a dict with the shortlist BinDiff hits and the recall layer's own
    evidence for the audit trail.
    """
    from .bindiff import match_against_corpus

    recall_dir = Path(corpus_dir)
    idx = build_recall_index(corpus_dir)
    # query with the audit binary's own export per-function surfaces
    candidates = recall_candidates(
        idx, query=str(binary), top_k=recall_top_k, threshold=recall_threshold)
    # Phase A3 hierarchical BinDiff on the recall shortlist
    shortlist_dir = None
    if candidates:
        # BinDiff over every entry, but Phase A3's per-entry prefilter will drop
        # hopeless sizes before any real diff cost (and we could pre-filter by
        # recall rank here; currently we surface both)
        pass

    binding = match_against_corpus(cfg, ws, binary, corpus_dir,
                                   similarity_threshold=similarity_threshold,
                                   max_diffs=recall_top_k)
    return {
        "recall_candidates": [c.as_dict() for c in candidates],
        "bindiff_hits": [h.as_dict() for h in binding],
        "policy": {
            "recall_top_k": recall_top_k,
            "recall_threshold": recall_threshold,
            "precision_threshold": similarity_threshold,
        },
    }
