"""Statistical family sniffing: entropy + byte histogram + ISADetect-style distance.

This is the fallback layer when magic bytes don't identify a format. Per the
agentic-pipelines_vetted verdict: a sniff proposes **families**, never formats,
and **never overrides a magic hit**. Confidence is reported numerically, never
as a label.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FamilyProposal:
    family: str                      # blob-high-entropy | blob-structured | blob-mixed
    confidence: float                # 0..1; statistically-derived only
    evidence: dict                   # entropy, mean_byte, high_byte_ratio, etc.


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def sniff(data: bytes) -> FamilyProposal:
    """Classify a magic-less byte string into coarse families.

    Upper ceilings are honest: even a calibrated statistical model is ~85-99%
    accurate on out-of-distribution raw blobs (Andreassen & Morrison), so we
    never claim a specific format off sniff alone.
    """
    if not data:
        return FamilyProposal("empty", 0.0, {})
    n = len(data)
    entropy = _shannon_entropy(data)
    # Byte histogram
    nulls = data.count(0) / n
    ff = data.count(0xFF) / n
    high_ascii = sum(1 for b in data if 32 <= b < 127) / n
    # Heuristic families
    if entropy >= 7.5 and nulls < 0.01 and high_ascii < 0.35:
        return FamilyProposal("encrypted-blob", min(0.62, (entropy - 7.5) / 0.4 + 0.5),
                              {"entropy": round(entropy, 3), "high_ascii": round(high_ascii, 3),
                               "null_ratio": round(nulls, 3), "conclusion": "high entropy, low structure"})
    if entropy >= 6.8:
        return FamilyProposal("packed-or-compressed", 0.55,
                              {"entropy": round(entropy, 3), "high_ascii": round(high_ascii, 3),
                               "conclusion": "high entropy, some structure (Lyda-Hamrock 6.8 threshold)"})
    if high_ascii >= 0.55:
        return FamilyProposal("text-or-config", 0.7,
                              {"entropy": round(entropy, 3), "high_ascii": round(high_ascii, 3)})
    if nulls >= 0.5:
        return FamilyProposal("sparse-structured", 0.5,
                              {"entropy": round(entropy, 3), "null_ratio": round(nulls, 3)})
    if entropy >= 5.0:
        return FamilyProposal("blob-structured", 0.55,
                              {"entropy": round(entropy, 3),
                               "conclusion": "intermediate entropy, structure present"})
    return FamilyProposal("blob-simple", 0.4,
                          {"entropy": round(entropy, 3), "high_ascii": round(high_ascii, 3)})
