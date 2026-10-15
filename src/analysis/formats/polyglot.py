"""Polyglot multi-offset scan: forward magic + backward EOCD + interior stride.

A ZIP file may begin with a self-extracting ELF/PE stub (prefix stub) — file(1)
returns the first magic; we want the complete set of formats the bytes claim.
Per the format-detection_vetted doc: cap candidates at 3 by primary-preference
rank (pe > zip > pdf), cap parsed bytes at 256 MiB, EOCD scan window ≤64 KiB.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .detect import Identification, identify
from .loader import Signature


_EOCD_MAGIC = b"PK\x05\x06"
_EOCD_SCAN_WINDOW = 64 * 1024  # ZIP EOCD can reside up to ~57 KiB before EOF
_MAX_CANDIDATES = 3


@dataclass(frozen=True)
class PolyglotResult:
    interpretations: tuple[Identification, ...]
    primary: Identification | None
    notes: tuple[str, ...]


def _find_eocd(data: bytes) -> int | None:
    """Scan backward for the ZIP End-of-Central-Directory signature.

    ZIP comment + EOCD may extend up to ~64 KiB before EOF. We search the last
    min(len(data), 64 KiB + 4) bytes; the hit offset is file-absolute.
    """
    n = len(data)
    if n < len(_EOCD_MAGIC):
        return None
    lookback = min(n, _EOCD_SCAN_WINDOW + len(_EOCD_MAGIC))
    start = n - lookback
    search_area = data[start:]
    off = search_area.rfind(_EOCD_MAGIC)
    return (start + off) if off >= 0 else None


def _interior_scan(data: bytes, signatures: list[Signature],
                   stride: int = 4096) -> list[Identification]:
    """Scan every ``stride`` bytes of the body for secondary magic offsets.
    Returns candidates excluding offset 0 (already covered by the forward pass).
    Caps cost via _MAX_CANDIDATES.
    """
    hits: list[Identification] = []
    if len(data) < stride:
        return hits
    for sig in signatures:
        if not sig.magic:
            continue
        m = sig.magic
        pos = 0
        while True:
            pos = data.find(m, pos)
            if pos < 0:
                break
            if pos != sig.offset and len(hits) < _MAX_CANDIDATES * 4:
                # Only add if it differs from the forward-pass offset
                hits.append(Identification(sig, pos))
            pos += 1
    return hits


def scan_polyglot(data: bytes,
                  signatures: list[Signature] | None = None) -> PolyglotResult:
    """Return the set of interpretations for this byte string.

    Order: forward-scanned candidates (already ranked by polyrank), then ZIP
    EOCD if any, then one bounded interior probe (cost-capped). Returns the
    primary (lowest polyrank) and alternative interpretations for FormatProfile.
    """
    signatures = signatures or []
    forward = identify(data, signatures)
    alts: list[Identification] = list(forward[1:])
    primary = forward[0] if forward else None

    notes: list[str] = []
    eocd_off = _find_eocd(data)
    if eocd_off is not None and not any(h.signature.family == "zip" for h in forward):
        # It's a ZIP whose header didn't win the forward scan (e.g. self-extracting stub)
        zip_sigs = [s for s in signatures if s.family == "zip"]
        if zip_sigs:
            alts.append(Identification(zip_sigs[0], 0))
            notes.append(f"zip: EOCD found at 0x{eocd_off:x} but header didn't match at 0")

    # Bounded interior scan — only when the forward pass didn't already name
    # multiple formats (otherwise we'd pay O(n*m) work for nothing).
    if len(forward) < _MAX_CANDIDATES and len(data) > 8192:
        interior = _interior_scan(data[: 256 * 1024 * 1024], signatures)
        seen_families = {i.signature.family for i in forward}
        for ident in interior:
            family = ident.signature.family
            if family not in seen_families and len(seen_families) < _MAX_CANDIDATES * 2:
                alts.append(ident)
                seen_families.add(family)

    # Cap final output; preserve ordering.
    out = forward[:_MAX_CANDIDATES]
    if primary is None and alts:
        primary = alts[0]
        out = [primary]
    else:
        extra = [a for a in alts if a not in out][: _MAX_CANDIDATES - len(out)]
        out.extend(extra)
    return PolyglotResult(tuple(out), primary, tuple(notes))
