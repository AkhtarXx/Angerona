"""Provenance tracking for RE findings — the RARE-defense pillar.

Research basis (angerona research notes, 2026-07-15):
  RARE — "Representation-Confusion Attacks on LLM-Assisted RE" (arXiv:2607.12507)
  proves that feeding the SAME poisoned recovery to an LLM through N *different-looking*
  tools makes it "confirm" 23-32 of 40 false claims, because the "independent"
  confirmations all trace back to ONE origin. Angerona's independent-reviewer design
  assumes worker outputs are independent evidence — this module closes that gap.

A finding/claim is tagged with its provenance chain:
    provenance = {tool, function, byte_range, engine}
and we detect "provenance collapse" when multiple confirmations trace to one source.

This is a SAFETY pillar (analyzing attacker-controlled binaries). It degrades
gracefully: with no provenance data it returns "no evidence" (verified=True), never a
hard block — mirroring the other verify-pillar contracts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Instruction-like phrases that, if found inside a binary's extracted strings, may be
# an attempt to hijack the RE agent (Crawford et al., arXiv:2605.30667). Used by the
# injection scanner (scan_injection.py) and as a soft signal here.
_INJECTION_HINTS = re.compile(
    r"(ignore (all |previous )?(instructions|prompts)|"
    r"you are (now )?(a |an )?\w+|"
    r"system[: ]|disregard|reveal|exfiltrat|base64:\s*[A-Za-z0-9+/]{20,}|"
    r"execute|run the following|as an ai)",
    re.I,
)


@dataclass
class ProvenanceTag:
    """Where a claim's supporting evidence came from."""
    tool: str = "unknown"           # e.g. "ghidra_decompile", "ida_dump", "bindiff"
    function: str = "unknown"        # function name/addr the evidence ties to
    byte_range: Optional[str] = None  # "0x401000-0x4010ff" if known
    engine: str = "unknown"          # "ida" | "ghidra"

    def key(self) -> tuple:
        """Identity used for collapse detection: same key = same origin."""
        return (self.tool, self.function, self.byte_range or "", self.engine)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "function": self.function,
            "byte_range": self.byte_range,
            "engine": self.engine,
        }


@dataclass
class ProvenanceReport:
    verified: bool
    pillar: str = "provenance"
    checked: int = 0
    collapses: list[str] = field(default_factory=list)
    detail: str = ""


def parse_provenance(claim_meta: dict | None) -> ProvenanceTag:
    """Build a ProvenanceTag from an agent-supplied claim metadata dict.

    Agents are encouraged to attach ``_provenance`` to claims they emit, e.g.:
        {"text": "...", "_provenance": {"tool": "ida_dump", "function": "sub_401000",
                                         "byte_range": "0x401000-0x401050", "engine": "ida"}}
    Missing fields default to "unknown" (which still participates in collapse detection
    as a distinct bucket, so we never silently merge two genuinely-unknown sources).
    """
    m = claim_meta or {}
    p = m.get("provenance") or m.get("_provenance") or {}
    if not isinstance(p, dict):
        p = {}
    return ProvenanceTag(
        tool=str(p.get("tool", "unknown")),
        function=str(p.get("function", "unknown")),
        byte_range=(str(p["byte_range"]) if p.get("byte_range") else None),
        engine=str(p.get("engine", "unknown")),
    )


def verify_provenance(claims: list[dict]) -> ProvenanceReport:
    """Check a set of claims for provenance collapse.

    ``claims`` is a list of dicts, each optionally carrying a ``_provenance`` block.
    If N>=2 confirmations share the SAME origin key, that is a collapse: the
    "independent" review was actually one source counted N times (RARE attack).

    Graceful: zero or one claim -> no evidence (verified=True). No provenance data at
    all -> no evidence (verified=True), never a hard block.
    """
    if not claims:
        return ProvenanceReport(verified=True, checked=0,
                                detail="no claims supplied -> no evidence (inconclusive)")
    tags = [parse_provenance(c) for c in claims]
    # count origins
    from collections import Counter
    counts = Counter(t.key() for t in tags)
    collapses = []
    for key, n in counts.items():
        if n >= 2:
            tool, func, brange, eng = key
            collapses.append(
                f"provenance collapse: {n} confirmations trace to one origin "
                f"(tool={tool}, function={func}, byte_range={brange or 'n/a'}, engine={eng})"
            )
    verified = not collapses
    return ProvenanceReport(
        verified=verified,
        checked=len(tags),
        collapses=collapses,
        detail=("provenance independent across sources"
                if verified else "; ".join(collapses[:10])),
    )


def scan_provenance_notes(text: str) -> list[str]:
    """Lightweight scan of free-text for injection-style phrasing (soft signal).

    This is the cheap, string-only check used when no structured provenance is
    available. It does NOT block — it flags strings that an agent should treat as
    DATA, not instructions. The heavier scanner lives in scan_injection.py.
    """
    if not text:
        return []
    return [m.group(0) for m in _INJECTION_HINTS.finditer(text)][:10]


def load_provenance_manifest(export_dir: str | Path) -> dict:
    """Read any provenance manifest the export step wrote alongside facts.

    Returns {} if absent (graceful).
    """
    p = Path(export_dir) / "PROVENANCE_MANIFEST.json"
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}
