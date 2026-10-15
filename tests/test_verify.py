"""Tests for the objective report-verification pillars (claims + capabilities).

Pure unit tests — no Ghidra / Docker needed. They exercise the parsing, extraction and
graceful-degradation logic directly with fixtures / fakes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.analysis import verify as v


def _bind_manifest(tmp_path: Path) -> Path:
    binary = tmp_path / "x"
    binary.write_bytes(b"test-binary")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (tmp_path / "EXPORT_MANIFEST.json").write_text(
        json.dumps({"metadata": {"sha256": digest}})
    )
    return binary


# ----------------------------------------------------------- Pillar 1: claims

def test_extract_excludes_auto_names():
    # Stripped binaries: the agent legitimately cites Ghidra auto-names (FUN_/LAB_/SUB_/loc_).
    # These must NOT be treated as claim tokens (they're not in the binary's export facts).
    t = v.extract_cited_tokens("The function FUN_401000 calls SUB_402000 and LAB_403000.")
    assert t.strings == set()
    assert t.imports == set()


def test_verify_claims_zero_tokens_is_no_evidence():
    # A fluent report that cites zero literal tokens must surface as no-evidence
    # (inconclusive), not a silent pass -- it must not give false confidence.
    (tmp_path := Path("/tmp/_vczt")).mkdir(parents=True, exist_ok=True)
    (tmp_path / "strings.txt").write_text("0x1000\treal\n")
    rep = v.verify_claims("The sample beacons to its C2 and disables AMSI.", tmp_path)
    assert rep.verified  # graceful: 0 tokens -> no block
    assert rep.status == "inconclusive"
    assert "no evidence" in rep.detail  # but explicit, not silent


def test_verify_claims_sha256_mismatch_fails_closed(tmp_path):
    # Missing/mismatched content provenance is not admissible evidence.
    (tmp_path / "strings.txt").write_text("0x1000\treal\n")
    (tmp_path / "EXPORT_MANIFEST.json").write_text('{"binary": "/some/other/binary"}')
    rep = v.verify_claims("uses `real`", tmp_path, binary="/this/binary")
    assert not rep.verified
    assert rep.status == "unsupported"
    assert "provenance" in rep.detail


def test_verify_claims_vague_report_does_not_require_manifest(tmp_path):
    (tmp_path / "strings.txt").write_text("0x1000\treal\n")
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")

    rep = v.verify_claims("report text", tmp_path, binary=binary)

    assert rep.verified
    assert rep.checked == 0
    assert "no evidence" in rep.detail


def test_verify_claims_factual_report_requires_manifest(tmp_path):
    (tmp_path / "strings.txt").write_text("0x1000\treal\n")
    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")

    rep = v.verify_claims("uses `real`", tmp_path, binary=binary)

    assert not rep.verified
    assert "provenance" in rep.detail


def test_extract_cited_tokens_mixed():
    report = ("The binary drops `ransom_note.txt` and calls CreateFileW() to write. "
              "It prints 'Access granted!' and uses the RANSOM_KEY 'S3cr3t_K3y_2026'.")
    t = v.extract_cited_tokens(report)
    assert "ransom_note.txt" in t.strings
    assert "Access granted!" in t.strings
    assert "S3cr3t_K3y_2026" in t.strings
    assert "RANSOM_KEY" in t.strings          # bare UPPER token caught
    assert "CreateFileW" in t.imports


def test_verify_claims_flags_hallucinated_string(tmp_path):
    # The binary ONLY has these strings.
    (tmp_path / "strings.txt").write_text("0x1000\tS3cr3t_K3y_2026\n0x2000\tAccess granted!\n")
    report = "It uses 'S3cr3t_K3y_2026' and drops `ransom_note.txt`."
    rep = v.verify_claims(report, tmp_path)
    assert not rep.verified
    assert any("ransom_note.txt" in c for c in rep.unsupported)


def test_verify_claims_accepts_real_string(tmp_path):
    (tmp_path / "strings.txt").write_text("0x1000\tS3cr3t_K3y_2026\n")
    report = "The key is 'S3cr3t_K3y_2026'."
    rep = v.verify_claims(report, tmp_path)
    assert rep.verified
    assert rep.checked >= 1


def test_verify_claims_skips_when_no_strings_file(tmp_path):
    # Dir exists but no strings.txt -> no evidence, must NOT force NEEDS_WORK.
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tstrcmp\n")
    rep = v.verify_claims("the binary calls strcmp and drops `ghost.txt`", tmp_path)
    assert rep.verified
    assert "skipped" in rep.detail


def test_verify_claims_flags_hallucinated_import(tmp_path):
    (tmp_path / "strings.txt").write_text("0x1000\tdata\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tstrcmp\n")
    (tmp_path / "exports.txt").write_text("0x4000\tmain\n")
    (tmp_path / "symbols.txt").write_text("0x4000\tFUNC\tmain\n")
    report = "It calls CreateFileW() to write the file."
    rep = v.verify_claims(report, tmp_path)
    assert not rep.verified
    assert any("CreateFileW" in c for c in rep.unsupported)


def test_verify_claims_accepts_real_import(tmp_path):
    (tmp_path / "strings.txt").write_text("0x1000\tdata\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tstrcmp\n")
    report = "It calls strcmp() to compare."
    rep = v.verify_claims(report, tmp_path)
    assert rep.verified


# ----------------------------------------------------------- Pillar 1b: capabilities

def test_verify_capabilities_backed_by_imports(tmp_path):
    (tmp_path / "strings.txt").write_text("0x0\treal\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tInternetOpenA\n<EXTERNAL>\tURLDownloadToFileA\n")
    rep = v.verify_capabilities("The sample beacons to a C2 server and exfiltrates data", tmp_path)
    assert rep.verified  # capability asserted AND imports present


def test_verify_capabilities_unbacked_is_unsupported(tmp_path):
    (tmp_path / "strings.txt").write_text("0x0\treal\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tprintf\n<EXTERNAL>\tputs\n")
    rep = v.verify_capabilities("Performs AMSI bypass and persists via registry run keys", tmp_path)
    assert not rep.verified
    assert any("amsi" in d for d in rep.unsupported)
    assert any("persist" in d for d in rep.unsupported)


def test_verify_capabilities_no_claim_is_no_evidence(tmp_path):
    (tmp_path / "strings.txt").write_text("0x0\treal\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tprintf\n")
    rep = v.verify_capabilities("This is a benign hello-world binary", tmp_path)
    assert rep.verified  # no capability claimed -> skip, not block


def test_verify_claims_fabricated_specifics_are_unsupported(tmp_path):
    # A report can assert high-specificity technical facts in plain prose (no
    # backticks) -- e.g. a fabricated C2 IP + hex offset + "AES key". None of those
    # exist in the binary, so the gate must flag them (NEEDS_WORK), NOT silently pass.
    (tmp_path / "strings.txt").write_text("0x0\taccess granted\n0x0\tsecret\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tstrcmp\n<EXTERNAL>\tputs\n")
    rep = ("The binary contacts its C2 server at 185.199.108.9 and stores the AES "
           "static key at offset 0x402000.")
    r = v.verify_claims(rep, tmp_path, binary=_bind_manifest(tmp_path))
    assert not r.verified
    assert any("185.199.108.9" in d for d in r.unsupported)
    assert any("0x402000" in d for d in r.unsupported)


def test_verify_claims_vague_prose_stays_no_evidence(tmp_path):
    # Genuinely vague prose with no specific factual claim must still pass
    # (no-evidence), never a false NEEDS_WORK.
    (tmp_path / "strings.txt").write_text("0x0\taccess granted\n")
    (tmp_path / "imports.txt").write_text("<EXTERNAL>\tstrcmp\n")
    rep = "This is a small authentication helper that validates user input."
    r = v.verify_claims(rep, tmp_path, binary=_bind_manifest(tmp_path))
    assert r.verified
    assert "no evidence" in r.detail
