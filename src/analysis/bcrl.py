"""Binary Code Representation Learning (Part 7, deep-learning BCRL).

Research basis (angerona research notes, 2026-07-15, Part 7):
  BCRL maps a binary slice to a dense vector preserving task-relevant similarity.
  Flagship input trick across SAFE (1811.05296), Asm2Vec, jTrans (2205.12713):
  MASK immediates/addresses to a <imm>/<addr> token so the model learns STRUCTURE
  not constants. Recommended stack: disassemble -> mask -> embed -> ANN-index ->
  LLM-triage. Eval via Recall@k / MRR over transformed+distractor pools.

  This module provides a deterministic, dependency-light BCRL stage usable in the
  sandbox: token masking, a TF-IDF+SVD embedding (the provenance/structure signal),
  a FAISS ANN index, and a Recall@k/MRR evaluator. It reuses simindex for the heavy
  lifting but adds the BCRL-specific masking + metric protocol.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from .simindex import SimilarityIndex

# immediate / address masking: the BCRL "strip the constants" trick
_IMM = re.compile(r"(#|-?\$?0x[0-9a-fA-F]+|-\d+|\b\d+\b)")
_ADDR_LIKE = re.compile(r"\b(0x[0-9a-fA-F]{3,}|[a-z_][\w]*\+0x[0-9a-fA-F]+)\b")


def mask_tokens(asm: str) -> str:
    """Mask immediates/addresses so the embedding captures structure, not constants.

    SAFE/jTrans/Asm2Vec all do this: constants are replaced by <imm>/<addr> tokens.
    Without masking the model 'memorizes constants instead of structure' (Part 7 §5.2).
    """
    out = _ADDR_LIKE.sub("<addr>", asm)
    out = _IMM.sub("<imm>", out)
    return out


def embed_function(asm: str, index: SimilarityIndex) -> Optional[np.ndarray]:
    """Return the masked-token embedding vector for one function's disassembly."""
    return index.embed_function(mask_tokens(asm))


@dataclass
class RankingMetric:
    recall_at_k: dict[int, float]
    mrr: float
    n_queries: int

    def as_dict(self) -> dict:
        return {"recall_at_k": self.recall_at_k, "mrr": self.mrr,
                "n_queries": self.n_queries}


def evaluate_ranking(index: SimilarityIndex,
                      queries: list[str],
                      ground_truth: list[list[str]],
                      k: int = 10) -> RankingMetric:
    """BCRL eval protocol (Part 7 §10): for each anchor query, retrieve nearest
    neighbors from the index; require true matches to rank high. Recall@k + MRR.

    queries[i]      : anchor asm (will be masked)
    ground_truth[i] : list of function names that are true matches
    """
    ks = sorted({1, 3, 5, 10, k})
    hits = {kk: 0 for kk in ks}
    rr = 0.0
    n = 0
    for q, truth in zip(queries, ground_truth):
        if not truth:
            continue
        res = index.query_text(mask_tokens(q), top_k=max(ks))
        truth_set = set(truth)
        for kk in ks:
            top = [r.name for r in res[:kk]]
            if truth_set & set(top):
                hits[kk] += 1
        # reciprocal rank of first true match
        for rank, r in enumerate(res, start=1):
            if r.name in truth_set:
                rr += 1.0 / rank
                break
        n += 1
    if n == 0:
        return RankingMetric({kk: 0.0 for kk in ks}, 0.0, 0)
    return RankingMetric({kk: hits[kk] / n for kk in ks}, rr / n, n)
