"""Encrypted-blob detection in APK assets (Android SOTA priority 2).

Research basis (packer/payload-hiding studies: "DroidPack", DREBIN payload
classes, and the entropy-threshold conventions from `binwalk -E`): malware
hides second-stage payloads in ``assets/`` as high-entropy blocks, base64
blobs, or single-byte-XOR'd buffers. The deterministic heuristic used here —
size > 2 KiB AND entropy > 6.0 bits/byte, with base64/XOR shape votes — catches
that class without any ML model.

Heuristic-only: every candidate is tagged ``untrusted_child`` until a
decoding gate (unpacking.py) actually recovers a payload from it.
"""

from __future__ import annotations

from .finding import CONFIRMED, LIKELY, Finding
from .findings_compat import as_canonical_findings

import base64
import binascii
import math
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

SIZE_FLOOR = 2048               # >2 KiB, per the case-coverage heuristic
ENTROPY_FLOOR = 6.0             # bits/byte; text ~4.5, encrypted ~7.9
MAX_MEMBER_BYTES = 32 * 1024 * 1024   # zip-bomb guard: skip asset members >= 32 MiB
_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _is_base64_blob(data: bytes) -> bool:
    m = _B64_RUN.search(data)
    if not m:
        return False
    try:
        base64.b64decode(m.group(), validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _xor_key_candidate(data: bytes) -> int | None:
    """Detect single-byte-XOR: one byte value that would make >=70% of the
    block fall into the printable/NULL range when XORed."""
    if len(data) < 64:
        return None
    for key in range(1, 256):
        good = 0
        for b in data[:512]:
            v = b ^ key
            if v == 0 or 32 <= v < 127:
                good += 1
        if good / min(len(data), 512) >= 0.70:
            return key
    return None


@dataclass
class BlobCandidate:
    member: str
    size: int
    entropy: float
    signals: list[str]
    verdict: str           # encrypted-suspect | benign
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "member": self.member,
            "size": self.size,
            "entropy": round(self.entropy, 3),
            "signals": list(self.signals),
            "verdict": self.verdict,
            "trust": self.trust,
        }


@dataclass
class AssetScanResult:
    status: str            # success | empty | error | skipped
    candidates: list[Finding] = field(default_factory=list)
    members_scanned: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "candidates": self.candidates,
            "members_scanned": self.members_scanned,
            "note": self.note,
            "trust": self.trust,
            "policy": "threshold heuristic; candidates require decode-gate corroboration",
        }


def classify_blob(name: str, data: bytes) -> BlobCandidate:
    """Classify one asset buffer. Public verb for single-blob use."""
    entropy = shannon_entropy(data)
    signals: list[str] = []
    if len(data) > SIZE_FLOOR:
        signals.append("size>2KB")
    if entropy > ENTROPY_FLOOR:
        signals.append(f"entropy>{ENTROPY_FLOOR}")
    if _is_base64_blob(data):
        signals.append("base64-blob")
    key = _xor_key_candidate(data)
    if key is not None:
        signals.append(f"single-byte-xor:0x{key:02x}")
    suspect = (
        (len(data) > SIZE_FLOOR and entropy > ENTROPY_FLOOR)
        or "base64-blob" in signals
        or any(s.startswith("single-byte-xor") for s in signals)
    )
    return BlobCandidate(
        member=name, size=len(data), entropy=entropy, signals=signals,
        verdict="encrypted-suspect" if suspect else "benign",
    )


def scan_apk_assets(apk_path: str | Path) -> AssetScanResult:
    """Scan ``assets/`` (and ``res/raw/``) members of an APK for blobs."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return AssetScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return AssetScanResult(status="error", note=f"not a zip/apk: {exc}")
    candidates: list[BlobCandidate] = []
    scanned = 0
    with zf:
        for name in zf.namelist():
            if not (name.startswith("assets/") or name.startswith("res/raw/")):
                continue
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                continue
            try:
                data = zf.read(name)
            except (OSError, RuntimeError, KeyError):
                continue
            scanned += 1
            cand = classify_blob(name, data)
            if cand.verdict == "encrypted-suspect" or cand.signals:
                candidates.append(cand)
    return AssetScanResult(
        status="success" if scanned else "empty",
        candidates=as_canonical_findings("assets_blob_detector", candidates),
        members_scanned=scanned,
        note=f"{sum(1 for c in candidates if c.verdict == 'encrypted-suspect')} suspect blob(s) in {scanned} asset member(s)",
    )
