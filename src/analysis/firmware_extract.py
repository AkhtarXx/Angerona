"""Firmware extraction + format triage (Part 4, recommendation 1).

Research basis (angerona research notes, 2026-07-15, Part 4):
  binwalk (ReFirm Labs) is the deterministic FIRST step for firmware: entropy + signature
  scanning to locate/extract filesystems (SquashFS, CramFS, UBIFS, JFFS2), raw vendor
  boot headers, U-Boot images. Classic tooling is cheaper and more trustworthy than LLM
  for the mechanical extraction step; all extracted content is UNTRUSTED DATA (never
  executed, never obeyed) per angerona's security model. Ghidra is the right PRIMARY
  engine for firmware (broad embedded ISA coverage); IDA remains default for x86/ARM.

What this module does (production, deterministic):
  - Detects container format via magic/entropy heuristics (SquashFS, UBIFS, JFFS2,
    CramFS, U-Boot legacy/FIT, ELF, raw) WITHOUT shelling to binwalk where it is absent.
  - If binwalk is installed, runs it to extract into the workspace (untrusted) and records
    what was found; if absent, falls back to signature offsets so analysis can still proceed.
  - Emits an extraction manifest (offsets, sizes, detected format) for auditability.

Graceful: no binwalk -> signature-based triage still works; extraction simply skipped.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run
from typing import Optional


# (format, magic-prefix-as-hex-bytes, human note)
# NOTE: FDT/FIT magic corrected per the Flattened Device Tree spec (d0 0d fe ed;
# earlier tree had the wrong offset d0 0e fe ed). Verified by critic review
# (containers-archives_vetted.md §corrections).
_MAGICS = [
    ("squashfs", b"hsqs", "SquashFS filesystem"),
    ("squashfs", b"sqsh", "SquashFS (legacy byte order)"),
    ("ubifs", b"UBI#", "UBIFS / UBI volume"),
    ("jffs2", b"\x85\x19\x03\x20", "JFFS2"),
    ("cramfs", b"\x45\x3d\xcd\x28", "CramFS"),
    ("uimage", b"\x27\x05\x19\x56", "U-Boot legacy uImage"),
    ("fit", b"\xd0\x0d\xfe\xed", "U-Boot FIT device tree"),
    ("elf", b"\x7fELF", "ELF"),
    ("pkm", b"PK\x03\x04", "ZIP/PKZIP (possible OTA payload)"),
    ("gzip", b"\x1f\x8b", "gzip"),
    ("lzma", b"\x5d\x00\x00", "LZMA"),
    # L0/Master-plan extensions — additional container/firmware magics
    ("squashfs_streamed", b"shsq", "SquashFS (streamed / network endian)"),
    ("ubi_erase", b"UBI!", "UBI erase counter header"),
    ("ole2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound document"),
    ("wim", b"MSWIM\x00", "Windows Imaging (WIM)"),
    ("iso9660", b"CD001", "ISO9660 (located at 0x8000 sector offset)"),
    ("android_sparse", b"\x3a\xff\x26\xed", "Android sparse image (simg2img)"),
    ("lz4", b"\x04\x22\x4d\x18", "LZ4 frame"),
    ("rzip", b"RZIP", "LRZIP / rzip"),
    ("hfst", b"hfs", "Apple HFS/HFS+ (weak marker; magics overlap)"),
    ("pgp_armor", b"-----BEGIN", "ASCII-armored container"),
    ("lzop", b"\x89LZO", "LZO compressed"),
    ("bz2", b"BZh", "bzip2"),
]

_UIMAGE_HDR = 64  # U-Boot legacy header size


@dataclass
class ExtractionHit:
    fmt: str
    offset: int
    size: Optional[int]
    note: str

    def as_dict(self) -> dict:
        return {"fmt": self.fmt, "offset": self.offset,
                "size": self.size, "note": self.note}


@dataclass
class ExtractionManifest:
    image: str
    hits: list[ExtractionHit] = field(default_factory=list)
    extracted_dir: Optional[str] = None
    tool: str = "signature-scan"

    def as_dict(self) -> dict:
        return {"image": self.image, "tool": self.tool,
                "extracted_dir": self.extracted_dir,
                "hits": [h.as_dict() for h in self.hits]}


def scan_signatures(image: str | Path) -> list[ExtractionHit]:
    """Scan a firmware image for known container magic bytes; return hit offsets."""
    data = Path(image).read_bytes()
    hits: list[ExtractionHit] = []
    for fmt, magic, note in _MAGICS:
        off = 0
        while True:
            idx = data.find(magic, off)
            if idx < 0:
                break
            hits.append(ExtractionHit(fmt=fmt, offset=idx, size=None, note=note))
            off = idx + 1
    hits.sort(key=lambda h: h.offset)
    return hits


def run_binwalk(image: str | Path, out_dir: str | Path) -> ExtractionManifest:
    """Extract firmware with binwalk if available; else signature-scan fallback.

    All extracted artifacts are treated as UNTRUSTED DATA by the caller.
    """
    image = Path(image)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = ExtractionManifest(image=str(image))

    if observed_run(["which", "binwalk"], capture_output=True, text=True).returncode == 0:
        try:
            r = observed_run(["binwalk", "-e", "-C", str(out_dir), str(image)],
                               capture_output=True, text=True, timeout=300, check=False)
            manifest.tool = "binwalk"
            if r.returncode == 0:
                manifest.extracted_dir = str(out_dir)
        except Exception:
            manifest.tool = "binwalk(failed)->signature-scan"
    # always run signature scan so we have an index even without binwalk
    manifest.hits = scan_signatures(image)
    return manifest


def detect_format(image: str | Path) -> str:
    """Best-effort top-level format guess from the first magic hit."""
    hits = scan_signatures(image)
    if not hits:
        return "unknown/raw"
    # prefer ELF / uImage / fit at offset 0; else first signature
    for h in hits:
        if h.offset == 0:
            return h.fmt
    return hits[0].fmt
