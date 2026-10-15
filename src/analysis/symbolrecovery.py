"""Symbol / type recovery for stripped binaries (Retypd/Nova/Debin lineage).

Research basis (angerona research notes, 2026-07-15):
  Part 11 (symbols/types): a stripped binary has no symbol/type info, but its
  FUNCTIONS can be matched against a KNOLEDGE CORPUS of named binaries (the same
  library compiled with symbols, or a known version). When a query function is
  sufficiently similar (cosine >= threshold) to a named function in the corpus, we
  recover that name/type. This is exactly how Retypd / BinSub / Lumina-style recovery
  works: similarity -> candidate name -> (optionally) cross-engine consensus.

This module uses the ML similarity index (simindex.py) as the matcher and adds:
  * name recovery: best similar named function -> proposed symbol
  * type recovery: when the corpus function carries a recovered struct/type, propose it
  * cross-engine consensus: IDA name vs Ghidra name; if both agree -> HIGH confidence,
    if they disagree -> present both, mark MEDIUM (no silent pick — ties to provenance)
  * confidence tiering by similarity score

Graceful: no corpus -> empty recovery (no error). Low similarity -> no proposal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RecoveredSymbol:
    addr: str
    proposed_name: str
    similarity: float
    source_corpus: str = ""
    confidence: str = "LOW"   # HIGH | MEDIUM | LOW
    proposed_type: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "addr": self.addr, "proposed_name": self.proposed_name,
            "similarity": round(self.similarity, 4), "source_corpus": self.source_corpus,
            "confidence": self.confidence, "proposed_type": self.proposed_type,
            "note": self.note,
        }


@dataclass
class RecoveryReport:
    symbols: list[RecoveredSymbol] = field(default_factory=list)
    corpus_count: int = 0
    ambiguous: int = 0
    rejected_generated_names: int = 0
    rejected_unsafe_names: int = 0
    rejected_low_information: int = 0
    candidate_set_truncated: int = 0

    def as_dict(self) -> dict:
        return {"corpus_count": self.corpus_count,
                "ambiguous": self.ambiguous,
                "rejected_generated_names": self.rejected_generated_names,
                "rejected_unsafe_names": self.rejected_unsafe_names,
                "rejected_low_information": self.rejected_low_information,
                "candidate_set_truncated": self.candidate_set_truncated,
                "recovered": [s.as_dict() for s in self.symbols]}


def _conf(sim: float, threshold: float) -> str:
    if sim >= 0.92:
        return "HIGH"
    if sim >= threshold:
        return "MEDIUM"
    return "LOW"


_GENERATED_NAME = re.compile(
    r"^(?:FUN_|LAB_|SUB_|sub_|loc_|thunk_|function_|fn_|corpus_fn_|f\d+$|0x[0-9a-f]+$)", re.I
)
_SAFE_SYMBOL_NAME = re.compile(r"^[A-Za-z_~][A-Za-z0-9_.$@:~?]{0,127}$")
_INSTRUCTION_LIKE = re.compile(
    r"(?:ignore_?(?:all_?)?(?:previous_?)?instructions?|system_?prompt|"
    r"jailbreak|declare_?(?:critical|vulnerable|rce)|assistant_?message|prompt_?injection)",
    re.I,
)


def _meaningful_name(name: str) -> bool:
    value = (name or "").strip()
    return (
        bool(value)
        and not _GENERATED_NAME.match(value)
        and bool(_SAFE_SYMBOL_NAME.fullmatch(value))
        and not _INSTRUCTION_LIKE.search(value)
    )


def recover_symbols(query_code_dir: str | Path, corpus_code_dirs: list[str | Path],
                    *, top_k: int = 3, threshold: float = 0.80,
                    index=None) -> RecoveryReport:
    """Recover symbol names for the stripped binary in ``query_code_dir``.

    ``corpus_code_dirs`` are exported code/ dirs of NAMED/binaries (libraries with
    symbols, or known versions). For each query function we find the most similar
    named corpus function(s); if similarity >= threshold we propose the name.
    """
    from .simindex import AUDIT_SIMILARITY_POLICY, SimilarityIndex

    report = RecoveryReport()
    # Build one combined index from all corpus dirs.
    idx = index or SimilarityIndex(dim_reduce=128)
    if index is None:
        for c in corpus_code_dirs:
            n = idx.add_corpus(c)
            report.corpus_count += n
    else:
        report.corpus_count = len(getattr(idx, "_docs", []))
    report.rejected_unsafe_names = int(getattr(idx, "_unsafe_label_count", 0))
    if report.corpus_count == 0:
        return report
    if getattr(idx, "_vecmat", None) is None:
        idx.build()

    # Query: returns matches of query funcs -> corpus funcs.
    matches, tie_truncated, low_information = idx.query_ties(
        query_code_dir,
        threshold=threshold,
        margin=float(AUDIT_SIMILARITY_POLICY["tie_margin"]),
        max_distinct=int(AUDIT_SIMILARITY_POLICY["max_distinct_ties"]),
    )
    report.rejected_low_information += len(low_information)
    # Group by query addr. Conflicting near-tied labels are uncertainty, not a
    # license to silently pick whichever corpus happened to be ingested first.
    grouped: dict[tuple[str, str], list] = {}
    for m in matches:
        key = (m.addr, m.name)
        grouped.setdefault(key, []).append(m)
    for (addr, qname), candidates in grouped.items():
        if (addr, qname) in tie_truncated:
            report.candidate_set_truncated += 1
            report.ambiguous += 1
            continue
        candidates.sort(key=lambda item: (-item.score, item.other_name, item.other_addr))
        accepted = []
        for item in candidates:
            if _GENERATED_NAME.match((item.other_name or "").strip()):
                report.rejected_generated_names += 1
                continue
            if not _meaningful_name(item.other_name):
                report.rejected_unsafe_names += 1
                continue
            if (
                item.query_token_count < int(AUDIT_SIMILARITY_POLICY["minimum_tokens"])
                or item.query_unique_tokens < int(AUDIT_SIMILARITY_POLICY["minimum_unique_tokens"])
                or item.other_token_count < int(AUDIT_SIMILARITY_POLICY["minimum_tokens"])
                or item.other_unique_tokens < int(AUDIT_SIMILARITY_POLICY["minimum_unique_tokens"])
            ):
                report.rejected_low_information += 1
                continue
            accepted.append(item)
        candidates = accepted
        if not candidates:
            continue
        best = candidates[0]
        conflicting = next(
            (
                item for item in candidates[1:]
                if item.other_name != best.other_name and best.score - item.score <= 0.02
            ),
            None,
        )
        if conflicting is not None:
            report.ambiguous += 1
            continue
        sim, cname, caddr, ctype = best.score, best.other_name, best.other_addr, ""
        conf = _conf(sim, threshold)
        # Similarity corpora are explicit external inputs, not authenticated
        # independent witnesses. Similarity alone can therefore never justify HIGH.
        if conf == "HIGH":
            conf = "MEDIUM"
        if conf == "LOW":
            continue
        report.symbols.append(RecoveredSymbol(
            addr=addr, proposed_name=cname, similarity=sim,
            source_corpus=str(best.other_source), confidence=conf,
            proposed_type=ctype,
            note=f"candidate label from corpus function {cname} @ {caddr}; untrusted until corroborated"))
    return report


def cross_engine_consensus(ida_symbols: dict[str, str], ghidra_symbols: dict[str, str]) -> dict:
    """Merge IDA and Ghidra recovered names per address.

    Returns {addr: {"name": str, "confidence": str, "note": str}}.
    If both engines name the same addr the SAME -> HIGH; different -> MEDIUM with both
    candidates (no silent pick — ties to the provenance principle). Missing on one side
    -> use the other, MEDIUM.
    """
    out: dict[str, dict] = {}
    addrs = set(ida_symbols) | set(ghidra_symbols)
    for a in addrs:
        iname = ida_symbols.get(a)
        gname = ghidra_symbols.get(a)
        if iname and gname:
            if iname == gname:
                out[a] = {"name": iname, "confidence": "HIGH", "note": "IDA+Ghidra agree"}
            else:
                out[a] = {"name": iname, "confidence": "MEDIUM",
                          "note": f"disagree: IDA={iname}, Ghidra={gname} (presenting IDA)"}
        elif iname:
            out[a] = {"name": iname, "confidence": "MEDIUM", "note": "IDA only"}
        elif gname:
            out[a] = {"name": gname, "confidence": "MEDIUM", "note": "Ghidra only"}
    return out
