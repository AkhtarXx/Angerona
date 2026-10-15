"""Behavior tests for firmware_extract signature detection (roadmap P0: hygiene).

Proves:
  1. FDT/FIT magic is now correct (d0 0d fe ed, NOT the historical d0 0e fe ed).
  2. Every magic in _MAGICS round-trips: signature detector finds it on known bytes.
  3. scan_signatures reports offsets correctly for embedded containers.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.firmware_extract import _MAGICS, scan_signatures


def test_fd_fit_magic_is_fdt_correct():
    magics = {fmt: magic for fmt, magic, _ in _MAGICS}
    assert magics["fit"] == b"\xd0\x0d\xfe\xed", (
        "FDT/FIT magic must be d0 0d fe ed per spec; "
        "regression guard against the historical d0 0e fe ed typo"
    )


def test_signature_scan_finds_fdt_on_real_bytes():
    with tempfile.TemporaryDirectory() as td:
        blob = Path(td) / "fw.bin"
        # embed the FDT magic at a non-zero offset w/ noise around it
        blob.write_bytes(b"\xff\x00" * 256 + b"\xd0\x0d\xfe\xed" + b"\x00" * 64)
        hits = scan_signatures(blob)
        fit_hits = [h for h in hits if h.fmt == "fit"]
        assert fit_hits, "FDT magic must be detected"
        assert fit_hits[0].offset == 512


def test_signature_scan_every_magic_detected():
    for fmt, magic, note in _MAGICS:
        with tempfile.TemporaryDirectory() as td:
            blob = Path(td) / "x.bin"
            blob.write_bytes(b"\x90" * 64 + magic + b"\x00" * 64)
            hits = scan_signatures(blob)
            found = [h for h in hits if h.fmt == fmt and h.offset == 64]
            assert found, f"{fmt} magic {magic.hex()} ({note}) not found at expected offset 64"


def test_extended_magics_present():
    names = {m[0] for m in _MAGICS}
    for required in ("squashfs", "jffs2", "cramfs", "uimage", "fit", "elf",
                     "ole2", "wim", "android_sparse", "lz4", "lzop", "bz2"):
        assert required in names, f"missing magic: {required}"
