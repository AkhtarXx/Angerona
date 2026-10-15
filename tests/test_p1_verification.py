"""Tests for the P1 verification-completeness pillars (research-backed)."""
from __future__ import annotations

from pathlib import Path

from src.analysis.typefidelity import verify_type_fidelity, extract_claimed_types
from src.analysis.composite import CompositeVerifier, PillarResult
from src.analysis.obfuscation import detect_obfuscation
from src.analysis.semantics import score_semantics


def test_type_fidelity_fabricated(tmp_path: Path):
    (tmp_path / "symbols.txt").write_text("0x1000\tFUN_401000\n")
    report = "typedef struct MySecret { int x; } MySecret;"
    rep = verify_type_fidelity(report, tmp_path)
    assert not rep.verified
    assert "MySecret" in rep.unsupported[0]


def test_type_fidelity_recovered_ok(tmp_path: Path):
    (tmp_path / "symbols.txt").write_text("0x1000\tRequestHeader\n")
    report = "struct RequestHeader { int len; };"
    rep = verify_type_fidelity(report, tmp_path)
    assert rep.verified


def test_type_fidelity_no_types_graceful(tmp_path: Path):
    rep = verify_type_fidelity("struct X { int a; };", tmp_path)
    assert rep.verified  # skipped


def test_extract_claimed_types():
    names = extract_claimed_types("typedef struct Foo { int x; } Foo; union Bar b;")
    assert "Foo" in names and "Bar" in names


def test_composite_hard_fail():
    v = CompositeVerifier()
    rep = v.evaluate([
        PillarResult("claims", True, 1.0, "checked"),
        PillarResult("provenance", False, 0.0, "collapsed", hard_fail=True),
    ])
    assert not rep.verified
    assert rep.score == 0.0


def test_composite_pass():
    v = CompositeVerifier()
    rep = v.evaluate([
        PillarResult("claims", True, 1.0, "checked"),
        PillarResult("capabilities", True, 1.0, "checked"),
        PillarResult("type_fidelity", True, 1.0, "checked"),
        PillarResult("provenance", True, 1.0, "checked"),
    ], structural_similarity=0.85)
    assert rep.verified
    assert rep.score >= 0.7


def test_composite_single_signal_masked():
    # One strong signal must not mask a failed content pillar.
    v = CompositeVerifier()
    rep = v.evaluate([
        PillarResult("claims", False, 0.0, "checked"),
        PillarResult("capabilities", True, 1.0, "checked"),
        PillarResult("type_fidelity", True, 1.0, "checked"),
        PillarResult("provenance", True, 1.0, "checked"),
    ], structural_similarity=0.95)
    assert not rep.verified


def test_obfuscation_protector(tmp_path: Path):
    (tmp_path / "imports.txt").write_text("kernel32\tVMProtectBegin\n")
    rep = detect_obfuscation(tmp_path)
    assert rep.suspected
    assert rep.tier in ("vm", "heavy", "light")


def test_obfuscation_clean(tmp_path: Path):
    (tmp_path / "imports.txt").write_text("libc\tprintf\n")
    rep = detect_obfuscation(tmp_path)
    assert not rep.suspected
    assert rep.tier == "clean"


def test_obfuscation_flattening(tmp_path: Path):
    rep = detect_obfuscation(tmp_path,
                             decompiled_text="while(1){ switch(state){ case 0x10: ... } }")
    assert rep.suspected


def test_semantics_low_no_facts(tmp_path: Path):
    rep = score_semantics("this function reads the config and decrypts it", tmp_path)
    assert rep.tier == "LOW"


def test_semantics_high_corroborated(tmp_path: Path):
    (tmp_path / "imports.txt").write_text("libc\tdecrypt\nlibc\tread\n")
    rep = score_semantics("this function reads the buffer and decrypts it", tmp_path)
    assert rep.tier in ("MEDIUM", "HIGH")
    assert rep.corroborated_by
