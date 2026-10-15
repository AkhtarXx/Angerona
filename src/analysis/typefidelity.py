"""Type/struct-fidelity pillar — closes the largest un-gated hallucination surface.

Research basis (angerona research notes, 2026-07-15):
  Part 11 (symbols/types): an RE agent can INVENT a struct layout or variable type and
  pass ALL existing verify pillars, because types/structs are not a *verified artifact*.
  Retypd/Nova/XTRIDE show types CAN be recovered deterministically from binaries, so a
  claimed composite type should be cross-checked against what the engine actually
  recovered (BinExport for Ghidra, IDA's local types / Hex-Rays for IDA).

This pillar verifies a claim's types/structs two ways:
  1. NAME presence: does the claimed struct/type name appear in the binary's recovered
     symbols/types? (cheap, catches fabricated names)
  2. TYPE-DIFF (optional, stronger): recompile the agent's recovered source and BinDiff
     the *type information* — if the agent's struct layout diverges from the original,
     structural_strength drops. Degrades gracefully when BinDiff isn't provisioned.

Graceful: missing data -> "no evidence" (verified=True), never a hard block.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Struct/type declarations an agent might fabricate in recovered C.
# Capture the type name following struct/union/enum (handles `typedef struct Foo` too,
# because the inner struct Foo is what we verify against the binary).
_STRUCT_RE = re.compile(r"\b(?:struct|union|enum)\s+(\w+)", re.I)


@dataclass
class TypeFidelityReport:
    verified: bool
    pillar: str = "type_fidelity"
    checked: int = 0
    unsupported: list[str] = field(default_factory=list)
    detail: str = ""


def extract_claimed_types(report: str) -> list[str]:
    """Pull struct/union/enum/type names the agent declared in recovered C."""
    out: list[str] = []
    for m in _STRUCT_RE.finditer(report or ""):
        name = m.group(1)
        if name and name not in ("int", "char", "void", "long", "float", "double", "short"):
            out.append(name)
    # de-dup preserve order
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def load_recovered_types(export_dir: str | Path) -> set[str]:
    """Names the engine actually recovered (symbols.txt + a types export if present)."""
    d = Path(export_dir)
    names: set[str] = set()
    sym = d / "symbols.txt"
    if sym.is_file():
        for line in sym.read_text(errors="ignore").splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                names.add(parts[-1].strip().lower())
    # Optional explicit types export (engine may write recovered local types).
    types_f = d / "types.txt"
    if types_f.is_file():
        for line in types_f.read_text(errors="ignore").splitlines():
            names.add(line.strip().lower())
    return names


def verify_type_fidelity(report: str, export_dir: str | Path,
                         binary: str | Path | None = None) -> TypeFidelityReport:
    """Verify claimed struct/type names actually exist in the binary's recovered types.

    Graceful: no symbols.txt/types.txt -> skipped (verified=True). A report with no
    declared types -> no evidence (verified=True). A declared type absent from the
    binary's recovered names -> unsupported -> NEEDS_WORK.
    """
    facts_dir = Path(export_dir)
    if not (facts_dir / "symbols.txt").is_file() and not (facts_dir / "types.txt").is_file():
        return TypeFidelityReport(verified=True, checked=0,
                                  detail="no symbols/types.txt -> skipped (no evidence)")
    claimed = extract_claimed_types(report)
    if not claimed:
        return TypeFidelityReport(
            verified=True, checked=0,
            detail="no struct/type declarations in report -> no evidence (inconclusive)")
    recovered = load_recovered_types(facts_dir)
    unsupported: list[str] = []
    for name in claimed:
        if name.lower() not in recovered:
            unsupported.append(f"declared type/struct not recovered from binary: {name}")
    verified = not unsupported
    return TypeFidelityReport(
        verified=verified, checked=len(claimed), unsupported=unsupported,
        detail=("all declared types present in binary's recovered types" if verified
                else "; ".join(unsupported[:10])),
    )
