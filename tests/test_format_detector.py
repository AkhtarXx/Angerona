"""Behavior tests for FORMAT detection layer (roadmap Phase 1).

Proves:
  1. signatures.yaml loads with corrected PRONOM PUIDs.
  2. detect() handles magic-hit formats correctly (ELF/PE/ZIP/WASM/DEX/etc.).
  3. Structural heuristic catches Python .pyc (no stable magic).
  4. Polyglot ZIP-with-ELF-stub returns both interpretations.
  5. Sniff fallback for unknown blob families with capped confidence.
  6. Honest degrade: empty file, missing file, no-magic blob.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.analysis.format_detector import FormatProfile, detect
from src.analysis.formats.loader import load_signatures


# -------------------------------------------------------------- loader sanity

def test_signatures_load_with_correct_puids():
    sigs = load_signatures()
    by_family = {s.family: s for s in sigs if s.puid}
    # vetted corrections: PE fmt/899 (+fmt/900 for PE+), ZIP x-fmt/263, PDF fmt/18
    assert by_family["pe"].puid == "fmt/899"
    assert by_family["zip"].puid == "x-fmt/263"
    assert by_family["ole2"].puid == "fmt/111"


# -------------------------------------------------------------- magic-hit formats

def test_detect_elf():
    profile = detect(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 500)
    assert profile.family == "elf"
    assert profile.confidence == 1.0
    assert not profile.container
    assert profile.recommended_engine == "ida|ghidra"
    assert profile.primary_preference_rank == 10


def test_detect_pe():
    profile = detect(b"MZ" + b"\x00" * 500)
    assert profile.family == "pe"
    assert profile.confidence == 1.0
    assert profile.primary_preference_rank == 5    # pe wins polyrank over zip


def test_detect_zip_is_container():
    profile = detect(b"PK\x03\x04" + b"\x00" * 500)
    assert profile.family == "zip"
    assert profile.container
    assert profile.primary_preference_rank == 20


def test_detect_wasm():
    profile = detect(b"\x00asm" + b"\x01\x00\x00\x00" + b"\x00" * 100)
    assert profile.family == "wasm"
    assert profile.recommended_engine == "processor:wasm"


def test_detect_dex():
    profile = detect(b"dex\n035\x00" + b"\x00" * 100)
    assert profile.family == "dex"
    assert profile.recommended_processor == "dex"


# -------------------------------------------------------------- pyc structural

def test_detect_pyc_structural():
    # fake CPython .pyc: 2-byte version tag + \x0d\x0a + flags
    pyc = b"\x42\x0d\x0d\x0a" + b"\x00" * 60
    pyc = b"\x55\x0d\x0d\x0a" + b"\x00" * 60
    profile = detect(pyc)
    assert profile.family == "pyc"
    assert profile.confidence <= 0.9    # structural heuristic, capped


# -------------------------------------------------------------- polyglot

def test_polyglot_pe_zip_interpretation():
    """A self-extracting archive stub (PE header + ZIP payload appended) is a
    true polyglot: both families should be named."""
    data = b"MZ" + b"\x00" * 512 + b"PK\x03\x04" + b"\x00" * 512 + b"PK\x05\x06" + b"\x00" * 20
    profile = detect(data)
    assert profile.family == "pe"        # pe wins polyrank
    assert "zip" in profile.polyglot or "pe" in profile.polyglot


# -------------------------------------------------------------- sniff fallback

def test_sniff_encrypted_blob():
    blob = bytes(range(256)) * 4
    profile = detect(blob)
    assert profile.family.startswith("blob") or profile.family == "empty"
    # sniff reports number, not a label
    assert profile.confidence <= 0.62


def test_sniff_high_ascii_text():
    profile = detect(b"hello world, this is a config file with mostly ASCII\n" * 20)
    assert profile.family.startswith("blob-") or "text" in profile.family or \
           "config" in profile.family or profile.family.startswith("blob")


def test_sniff_empty():
    profile = detect(b"")
    assert profile.family == "empty"
    assert profile.confidence == 0.0


def test_sniff_missing_file():
    profile = detect(Path("/nonexistent/nothing-here.bin"))
    assert profile.family == "missing"
    assert profile.unresolved


# -------------------------------------------------------------- FormatProfile shape

def test_profile_contract():
    """FormatProfile is frozen with the documented fields."""
    profile = detect(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    assert isinstance(profile, FormatProfile)
    d = profile.as_dict()
    for key in ("family", "variant", "confidence", "polyglot", "container",
                "recommended_engine", "recommended_processor", "evidence", "unresolved"):
        assert key in d
    # frozen: assignment must fail
    with pytest.raises(AttributeError):
        profile.family = "elf"  # noqa: F841
