"""Raw-blob forensics (roadmap Phase 4): BlobFacts for headerless binaries.

Research basis (research/agnostic/raw-binary-forensics_vetted.md + MASTER_PLAN):
  Nucleus (USENIX 2017) shows structure beats ML for function detection on blobs;
  Andreassen & Morrison confirm endianness+width can be inferred at ~86-99% on
  open-set. Base-address inference ports basefind2's difference method +
  rbasefind's exhaustive string/pointer voting, verified by % of harvested pointers
  landing within the image. All inferences carry a confidence number, not a label.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class BlobFacts:
    """Everything we know about a headerless blob. ``unresolved`` is required."""

    isa_hint: str                   # "arm-le-32", "mips-be-32", "x86-16", "unknown"
    endianness: str                 # "little" | "big" | "unknown"
    word_size: int                  # 16 | 32 | 64 | 0=unknown
    base_candidates: tuple[int, ...]  # ordered by confidence (margin>=3 means trusted)
    base_margin: float              # top / runner-up ratio (<3 = suspect)
    entry_hint: int | None          # reset vector / vector table entrypoint
    confidence: float               # 0..1 aggregate
    evidence: tuple = ()
    unresolved: tuple = ()

    def as_dict(self) -> dict:
        return {
            "isa_hint": self.isa_hint,
            "endianness": self.endianness,
            "word_size": self.word_size,
            "base_candidates": [hex(b) for b in self.base_candidates],
            "base_margin": round(self.base_margin, 3),
            "entry_hint": hex(self.entry_hint) if self.entry_hint is not None else None,
            "confidence": round(self.confidence, 3),
            "evidence": list(self.evidence),
            "unresolved": list(self.unresolved),
        }


# ------------------------------------------------------ format shortcuts

def _looks_ihex(data: bytes) -> bool:
    """Intel HEX: multiple lines starting with ':' Type 00/02/03/04/05 record."""
    if len(data) < 11 or not data.startswith(b":"):
        return False
    lines = data.splitlines()
    if len(lines) < 2:
        return False
    return all(line.startswith(b":") and len(line) >= 11 and all(
        c in b"0123456789abcdefABCDEF:" for c in line) for line in lines[:10])


def _looks_srec(data: bytes) -> bool:
    if len(data) < 4 or data[:1] not in (b"S",):
        return False
    lines = data.splitlines()
    if len(lines) < 2:
        return False
    # S-records start with S followed by digit 0-9
    return all(re.match(rb"^S[0-9][0-9A-Fa-f]{4,}", line) for line in lines[:5])


# ------------------------------------------------------ ISA/endianness heuristics

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _endianness_and_width(data: bytes) -> tuple[str, int, float]:
    """Crude Andreassen-Morrison-style bigram vote.

    Looks at 32-bit value distribution. High fraction of sensible LE pointers
    suggests LE; high fraction of BE pointers suggests BE. Returns ("little"|"big"
    |"unknown", word_size, confidence).
    """
    if len(data) < 256:
        return "unknown", 0, 0.0
    # Sample 256 possible 4-byte windows
    n_windows = min(len(data) // 4 - 1, 256)
    le_hits = 0
    be_hits = 0
    total = 0
    for i in range(0, n_windows * 4, 4):
        window = data[i:i + 4]
        le = int.from_bytes(window, "little")
        be = int.from_bytes(window, "big")
        # A "sensible pointer" is a 32-bit value in a plausible address range
        le_sens = 0x00000800 <= le <= 0xFFFFFFFF and (le & 3) == 0
        be_sens = 0x00000800 <= be <= 0xFFFFFFFF and (be & 3) == 0
        if le_sens and not be_sens: le_hits += 1
        if be_sens and not le_sens: be_hits += 1
        if le_sens or be_sens: total += 1
    if total < 8:
        return "unknown", 4, 0.0
    conf = (max(le_hits, be_hits) - min(le_hits, be_hits)) / max(total, 1)
    if le_hits > be_hits:
        return "little", 4, conf
    if be_hits > le_hits:
        return "big", 4, conf
    return "unknown", 4, 0.0


def _isa_hint(data: bytes, endianness: str) -> tuple[str, float]:
    """Coarse ISA hint from opcode/mnemonic density heuristics.

    Real production uses cpu_rec + ISADetect; this is the deterministic stand-in
    that returns a *hint* with confidence — never a definitive label.
    """
    if not data:
        return "unknown", 0.0
    # ARM LE thumb branches (0x47 0x70 0x00 0xBX = bx lr; arm push/pop patterns)
    if endianness == "little":
        thumb_count = sum(1 for i in range(len(data) - 1) if data[i] == 0x70 and data[i+1] == 0x47)
        if thumb_count >= 4:
            return "arm-le-thumb", 0.55
        # x86 common prologue: 55 48 89 E5 / 53 51 56 57
        x86 = sum(1 for i in range(len(data) - 1) if data[i] == 0x55 and data[i+1] in (0x48, 0x53))
        if x86 >= 2:
            return "x86-64", 0.4
    # MIPS big-endian: 27 bd ff e0 (addiu sp) / af bf 00 (sw ra)
    if endianness == "big":
        mips = data.count(b"\x27\xbd") + data.count(b"\xaf\xbf")
        if mips >= 4:
            return "mips-be-32", 0.55
    return "unknown", 0.0


# ------------------------------------------------------ vector anchors

def _find_cortex_m_vector_table(data: bytes) -> tuple[int | None, float]:
    """Cortex-M reset vector table: initial SP (top-of-stack) + reset handler pointer with Thumb bit set.
    Returns (base_address, confidence)."""
    if len(data) < 16:
        return None, 0.0
    for base in range(0, min(len(data) - 16, 4096), 4):
        sp = int.from_bytes(data[base:base + 4], "little")
        reset = int.from_bytes(data[base + 4:base + 8], "little") & ~1
        # sane SRAM stack top for typical Cortex-M
        if not (0x20000000 <= sp <= 0x20400000 or 0x10000000 <= sp <= 0x10800000):
            continue
        # reset handler points somewhere within the image
        if not (0x00000000 <= reset - 0x08000000 < len(data)):
            continue
        confidence = 0.82
        return base, confidence
    return None, 0.0


def _find_x86_reset_vector(data: bytes) -> tuple[int | None, float]:
    """x86 reset vector at 4 GiB - 16 (SDM §9.1.4): jump to BIOS entry point.
    We look for a relative jump (E9) or absolute far jump (EA) near the end."""
    if len(data) < 16:
        return None, 0.0
    tail = data[-16:]
    # Look for E9 <rel32> at offset 0 of the last 16 bytes
    if tail[0] == 0xE9:
        return 0xFFFFFFF0, 0.65
    if tail[0] == 0xEA:
        return 0xFFFFFFF0, 0.55
    return None, 0.0


# ------------------------------------------------------ base-address inference

def _infer_base_candidates(data: bytes, candidates: list[int]) -> list[tuple[int, float]]:
    """Basefind-style voting: count pointers that would land in-image given a base.

    Returns [(base, code), ...] ordered by in-image rate.
    """
    if not data:
        return []
    size = len(data)
    results = []
    for base in candidates:
        hits = 0
        total = 0
        for i in range(0, size - 4, 4):
            v32 = int.from_bytes(data[i:i + 4], "little")
            total += 1
            if base <= v32 < base + size:
                hits += 1
        if hits:
            rate = hits / max(total, 1)
            results.append((base, rate))
    return sorted(results, key=lambda p: p[1], reverse=True)


def fingerprint(data: bytes) -> BlobFacts:
    """Public entry: produce BlobFacts for a headerless blob.

    Invariant: every fact is either established (in evidence) or recorded in
    ``unresolved``. Base candidates are only trusted when margin >= 3.
    """
    if not data:
        return BlobFacts(isa_hint="unknown", endianness="unknown", word_size=0,
                          base_candidates=(), base_margin=0.0, entry_hint=None,
                          confidence=0.0, unresolved=("zero-byte blob",))

    evidence: list[dict] = []
    unresolved: list[str] = []

    # 1. format shortcuts
    if _looks_ihex(data):
        return BlobFacts(isa_hint="unknown", endianness="little", word_size=4,
                          base_candidates=(), base_margin=0.0, entry_hint=0,
                          confidence=0.9, evidence=({"signal": "ihex-record"},),
                          unresolved=())
    if _looks_srec(data):
        return BlobFacts(isa_hint="unknown", endianness="little", word_size=4,
                          base_candidates=(), base_margin=0.0, entry_hint=0,
                          confidence=0.9, evidence=({"signal": "srec-record"},),
                          unresolved=())

    # 2. endianness + word size
    endianness, word_size, ew_conf = _endianness_and_width(data)
    if endianness == "unknown":
        unresolved.append("endianness unclear (no clear LE/BE vote)")
    evidence.append({"signal": "endianness_vote",
                      "endianness": endianness, "word_size": word_size,
                      "confidence": round(ew_conf, 3)})

    # 3. ISA hint
    isa_hint, isa_conf = _isa_hint(data, endianness)
    if isa_hint == "unknown":
        unresolved.append("isa unclear (no characteristic opcode pattern)")
    evidence.append({"signal": "isa_hint", "isa": isa_hint,
                      "confidence": round(isa_conf, 3)})

    # 4. vector tables (Cortex-M, x86 reset)
    cm_base, cm_conf = _find_cortex_m_vector_table(data)
    if cm_base is not None:
        isa_hint = "arm-le-thumb"
        evidence.append({"signal": "cortex-m-vector", "base": hex(cm_base),
                          "confidence": round(cm_conf, 3)})
    x86_base, x86_conf = _find_x86_reset_vector(data)
    if x86_base is not None:
        evidence.append({"signal": "x86-reset-vector", "base": hex(x86_base),
                          "confidence": round(x86_conf, 3)})

    # 5. base-address inference over common candidates
    size = len(data)
    size_align = (size + 0xFFF) & ~0xFFF
    candidates = [
        0x0, 0x1000, 0x8000, 0xC000, 0x80000000, 0x400000,
        0x10000000, 0x20000000, 0x08000000, 0x0C000000,
        max(0, 0x100000000 - size_align),  # high x86 reset mapping
    ]
    if size <= 64 * 1024:
        candidates.append(0x100)   # DOS COM
    scores = _infer_base_candidates(data, candidates)

    base_candidates: tuple[int, ...] = ()
    base_margin = 0.0
    if scores:
        best, second = scores[0], scores[1] if len(scores) > 1 else (0, 0.0)
        base_margin = best[1] / second[1] if second[1] > 0 else float("inf")
        if base_margin >= 3.0:
            base_candidates = (best[0],)
            evidence.append({"signal": "base_inferred", "base": hex(best[0]),
                              "rate": round(best[1], 3), "margin": round(base_margin, 2)})
        else:
            unresolved.append(f"weak base inference (margin={base_margin:.2f} < 3.0, "
                              f"top={hex(best[0])} rate={best[1]:.2f})")
            base_candidates = tuple(b for b, _ in scores[:3])
    else:
        unresolved.append("no base candidates with in-image pointer rate > 0")

    entry_hint = cm_base if cm_base is not None else x86_base
    # Aggregate over the FACTS WE ACTUALLY HAVE (not a fixed 4-slot mask).
    # base_margin is included as its own term when present so a verified strong
    # margin also lifts overall confidence.
    confidences: list[float] = [ew_conf, isa_conf]
    if cm_base is not None:
        confidences.append(cm_conf)
    if x86_base is not None:
        confidences.append(x86_conf)
    if base_margin >= 3.0:
        confidences.append(min(1.0, base_margin / 10.0))
    confidence = (sum(confidences) / len(confidences)) if confidences else 0.0
    confidence = min(1.0, confidence)

    return BlobFacts(
        isa_hint=isa_hint,
        endianness=endianness,
        word_size=word_size,
        base_candidates=base_candidates,
        base_margin=max(0.0, base_margin),
        entry_hint=entry_hint,
        confidence=min(1.0, confidence),
        evidence=tuple(evidence),
        unresolved=tuple(unresolved),
    )
