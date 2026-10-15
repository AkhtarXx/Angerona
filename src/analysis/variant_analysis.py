"""Variant analysis (Part 9, AI-driven vuln discovery — Big Sleep methodology).

Research basis (angerona research notes, 2026-07-15, Part 9):
  The single highest-yield LLM vuln technique (Google Big Sleep / Project Zero)
  is VARIANT ANALYSIS: seed with a *known patched bug* and hunt for SIBLINGS -- the
  same vulnerable pattern un-patched elsewhere. Big Sleep's SQLite stack-buffer
  underflow was found this way: "rather than open-ended 'find any bug', seed the
  agent with a recently patched vulnerability and ask 'find another one like
  this'." Angerona already has BinDiff/simindex plumbing; this module makes
  variant analysis a FIRST-CLASS stage: given a seed (function asm + optional CVE
  id), retrieve the nearest functions across the indexed corpus and rank them as
  candidate variants for LLM triage.

  Critical: this only surfaces CANDIDATES. Confirmation requires a non-LLM oracle
  (PoV / recompile-verify / CFG anchor) -- exactly the gate Angerona enforces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .simindex import SimilarityIndex


@dataclass
class VariantCandidate:
    addr: str
    name: str
    score: float
    source: str = "corpus"

    def as_dict(self) -> dict:
        return {"addr": self.addr, "name": self.name,
                "score": round(float(self.score), 4), "source": self.source}


@dataclass
class VariantReport:
    seed_name: Optional[str]
    cve: Optional[str]
    candidates: list[VariantCandidate]

    def as_dict(self) -> dict:
        return {"seed_name": self.seed_name, "cve": self.cve,
                "n_candidates": len(self.candidates),
                "candidates": [c.as_dict() for c in self.candidates]}


def find_variants(seed_asm: str,
                  index: SimilarityIndex,
                  cve: Optional[str] = None,
                  seed_name: Optional[str] = None,
                  top_k: int = 20,
                  threshold: float = 0.80) -> VariantReport:
    """Given a seed (patched bug) asm, retrieve corpus functions most similar.

    Returns candidates ABOVE threshold, EXCLUDING the seed itself. These are the
    un-patched-sibling hypotheses for the worker agents to triage. High similarity
    + semantic proximity to a known-bad pattern = highest-yield triage target.
    """
    matches = index.query_text(seed_asm, top_k=top_k, threshold=threshold)
    cands: list[VariantCandidate] = []
    for m in matches:
        if seed_name and m.name == seed_name:
            continue
        cands.append(VariantCandidate(addr=m.addr, name=m.name,
                                       score=m.score, source="corpus"))
    cands.sort(key=lambda c: c.score, reverse=True)
    return VariantReport(seed_name=seed_name, cve=cve, candidates=cands)


def find_variants_across(seeds: list[tuple[str, str]],
                         index: SimilarityIndex,
                         top_k: int = 20,
                         threshold: float = 0.80) -> list[VariantReport]:
    """Run variant analysis for several seed (name, asm) pairs (e.g. a CVE feed)."""
    out: list[VariantReport] = []
    for name, asm in seeds:
        out.append(find_variants(asm, index, seed_name=name,
                                 top_k=top_k, threshold=threshold))
    return out


# ------------------------------------------------------------- Big Sleep seed mode


@dataclass
class CommitSeed:
    """A Big Sleep-style commit patch: fixed upstream, sibling bugs still in HEAD.

    The patch's *removed* lines describe the pre-fix vulnerable shape; added lines
    are the fix. Sibling functions whose behaviour matches the removed-line shape
    (analogous pointer arithmetic, bounds logic, refcount handling) are triaged as
    candidate variants.
    """

    commit_message: str
    cve: str = ""
    removed_code: str = ""         # pre-fix vulnerable lines (minus markers)
    added_code: str = ""           # post-fix lines (plus markers)
    hunt_keywords: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"commit_message": self.commit_message, "cve": self.cve,
                "removed_code": self.removed_code, "added_code": self.added_code,
                "hunt_keywords": self.hunt_keywords}


def parse_commit_seed(commit_message: str, diff_text: str,
                      cve: str = "") -> CommitSeed:
    """Extract Big Sleep seed signals from a commit message + unified diff.

    Removed lines (``-``) reveal the vulnerable shape; added lines (``+``) describe
    the fix. Hunt keywords = security-relevant API/pattern tokens that appear in
    the removed lines (strcpy/memcpy/printf/format bounds/loop bounds/refcount/
    negative-index) — a sibling function containing the same pattern family is a
    candidate regardless of surrounding architecture.
    """
    removed: list[str] = []
    added: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            removed.append(line[1:].strip())
        elif line.startswith("+"):
            added.append(line[1:].strip())
    src = "\n".join(removed)
    patterns = {
        "strcpy": r"\bstrcpy\s*\(", "memcpy": r"\bmemcpy\s*\(",
        "sprintf": r"\bsprintf\s*\(", "format_string": r"%s\b",
        "negative_index": r"\[\s*-\s*\d+",
        "bounds_loop": r"\bfor\b.*<\s*\w+\s*;",
        "refcount": r"(refcount|usecount|count_)[+-]",
        "deref_pointer": r"\*\s*\w+\s*=",
        "index_write": r"\w+\s*\[\s*[^\]]+\]\s*=",
    }
    kws = [name for name, pat in patterns.items()
           if __import__("re").search(pat, src, __import__("re").I)]
    # always fall back to the removed-line "shape fingerprint"
    shape = " ".join(w for w in src.split() if w.isalpha() and
                     len(w) > 3)[:200]
    return CommitSeed(
        commit_message=commit_message.strip(),
        cve=cve.strip(),
        removed_code=src.strip(),
        added_code="\n".join(added).strip(),
        hunt_keywords=kws + ([shape] if shape else []),
    )


def hunt_siblings_from_commit(
    seed: CommitSeed,
    index: SimilarityIndex,
    *,
    top_k: int = 20,
    threshold: float = 0.75,
) -> dict:
    """Run the Big Sleep seed→siblings loop over a similarity index.

    For every hunt keyword the seed carries, one targeted variant query is issued;
    candidates per keyword are merged, de-duplicated by address, and ranked by
    cumulative score across all matched keywords (a sibling firing on >1 pattern
    family is strictly stronger evidence than one matching a single pattern).
    """
    merged: dict[str, dict] = {}
    for kw in seed.hunt_keywords:
        for m in index.query_text(kw, top_k=top_k, threshold=threshold):
            slot = merged.setdefault(m.addr, {
                "addr": m.addr, "name": m.name,
                "score": 0.0, "matched_keywords": [],
            })
            slot["score"] = max(slot["score"], float(m.score))
            if kw not in slot["matched_keywords"]:
                slot["matched_keywords"].append(kw)
    ranked = sorted(merged.values(),
                    key=lambda s: (-len(s["matched_keywords"]), -s["score"]))
    return {
        "seed": seed.as_dict(),
        "n_keywords": len(seed.hunt_keywords),
        "n_unique_candidates": len(ranked),
        "candidates": ranked[:top_k],
        "note": ("candidates are triage hypotheses; only dynamic PoV / structural "
                 "verification promotes them, never a similarity score alone."),
    }
