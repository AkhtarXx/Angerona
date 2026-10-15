"""Signature DB loader: reads signatures.yaml, indexes by family and offset."""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass
from pathlib import Path


_PYC_PREFIX_RE = re.compile(rb"^..[\x0d\x0a]")


@dataclass(frozen=True)
class Signature:
    name: str
    family: str
    magic: bytes            # raw magic bytes; empty for heuristic-only entries
    offset: int
    variant: str
    confidence: float
    puid: str = ""
    polyrank: int = 50
    note: str = ""


_db: list[Signature] | None = None


def load_signatures(path: str | Path | None = None) -> list[Signature]:
    global _db
    if _db is not None:
        return _db
    p = Path(path) if path else Path(__file__).parent.parent / "signatures.yaml"
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    out: list[Signature] = []
    for row in (doc.get("signatures") or []):
        magic_str = str(row.get("magic") or "").strip()
        if magic_str.lower() in {"pyc-prefix", "heuristic", ""}:
            magic = b""
        else:
            try:
                magic = bytes.fromhex(magic_str)
            except ValueError as exc:
                raise ValueError(f"bad hex magic in signature {row!r}: {exc}")
        out.append(Signature(
            name=str(row["name"]),
            family=str(row["family"]),
            magic=magic,
            offset=int(row.get("offset") or 0),
            variant=str(row.get("variant") or ""),
            confidence=float(row.get("confidence") or 0.0),
            puid=str(row.get("puid") or ""),
            polyrank=int(row.get("polyrank") or 50),
            note=str(row.get("note") or ""),
        ))
    _db = out
    return out
