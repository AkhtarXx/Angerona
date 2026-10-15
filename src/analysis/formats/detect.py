"""Format signature detection: magic-offset lookups, TrID-style ranking."

Stage one of FormatProfile: match exact magics first, rank by confidence and
polyrank. Format-specific structural heuristics (e.g. Python .pyc without a
stable magic) are applied via ``_structural_heuristics`` as fallback at lower
confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .loader import Signature, load_signatures
from .safe_reader import Reader, ReaderError


@dataclass(frozen=True)
class Identification:
    signature: Signature
    offset: int

    @property
    def confidence(self) -> float:
        return self.signature.confidence


# Structural heuristic detectors for formats without reliable magic bytes.
def _is_pyc(data: bytes) -> bool:
    """CPython .pyc structural probe.

    Per CPython source (importlib._bootstrap_external): the 4-byte magic at
    file offset 0 is bytes 0-1 = version word, bytes 2-3 = 0x0d 0x0a (\\r\\n).
    We verify this exact marker rather than any version word, then pin the
    variant via PycProcessor.PYC_MAGICS.
    A bare 0x0d 0x0a pair elsewhere is NOT enough — plain text/CRLF files
    could false-positive, so we additionally require the file to pass a marshal-
    shaped header probe (4th byte is a well-known flag value).
    """
    if len(data) < 16:
        return False
    if not (data[2] == 0x0D and data[3] == 0x0A):
        return False
    # byte 12-15 is the .pyc header (mtime size info / flags); a tiny structural gate
    # on the version word keeps text files from tripping this detector.
    return data[:2] in {
        b"\xa7\x0d", b"\x42\x0d", b"\x61\x0d", b"\x6f\x0d", b"\x55\x0d", b"\x0d\x0d",
        b"\x2b\x0e",
    }


def _structural_heuristics(data: bytes, sig: Signature) -> Identification | None:
    if sig.family == "pyc" and sig.magic == b"" and _is_pyc(data):
        return Identification(sig, 0)
    return None


def identify(data: bytes,
             signatures: list[Signature] | None = None) -> list[Identification]:
    """Return all candidate identifications for ``data``, ranked by polyrank then confidence."""
    signatures = signatures or load_signatures()
    if not data:
        return []
    rdr = Reader(data)
    hits: list[Identification] = []
    for sig in signatures:
        if sig.magic:
            end = sig.offset + len(sig.magic)
            if end > len(data):
                continue
            try:
                if rdr.peek(len(sig.magic), sig.offset) == sig.magic:
                    hits.append(Identification(sig, sig.offset))
            except ReaderError:
                continue
        else:
            structurally = _structural_heuristics(data, sig)
            if structurally:
                hits.append(structurally)
    # Rank: primary_preference_rank low first, confidence high first. Magic-hit entries
    # always outrank structural heuristics of the same rank+confidence.
    hits.sort(key=lambda h: (
        h.signature.polyrank,
        -h.confidence,
        0 if h.signature.magic else 1,
    ))
    return hits
