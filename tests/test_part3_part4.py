"""Behavioral tests for Part 3 (anchor_retrieval, evidence_ledger, rebench_eval) and
Part 4 (firmware_extract, vector_recovery) research recommendations."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.anchor_retrieval import extract_anchors, rank_sources
from src.analysis.evidence_ledger import build_ledger, parse_address_claims
from src.analysis.rebench_eval import evaluate, EvalRow
from src.analysis.firmware_extract import scan_signatures, detect_format, run_binwalk
from src.analysis.vector_recovery import recover_vector, confidence_tier


# ---------------------------------------------------------------- anchor retrieval
def test_extract_anchors():
    a = extract_anchors('calls AES_encrypt with key 0x1a2b and "secret-box"')
    assert "sym:aes_encrypt" in a
    assert "hex:0x1a2b" in a
    assert any(x.startswith("str:") for x in a)


def test_rank_sources_finds_overlap():
    db = Path(tempfile.mkdtemp())
    (db / "libcrypto.c").write_text(
        'void AES_encrypt(unsigned char* buf){ int k = 0x1a2b; printf("secret-box"); }\n')
    (db / "other.c").write_text('void unrelated(float x){ return; }\n')
    target = 'uses AES_encrypt and key 0x1a2b and string "secret-box"'
    hits = rank_sources(extract_anchors(target), db, top_k=5)
    assert hits, "expected at least one source hit"
    # libcrypto.c should rank first (most anchor overlap)
    assert "libcrypto.c" in hits[0].source_file
    assert hits[0].score > 0


def test_rank_sources_no_false_positive():
    db = Path(tempfile.mkdtemp())
    (db / "a.c").write_text("void foo(){ int x = 1234; }\n")
    target = "completely unrelated text about weather"
    hits = rank_sources(extract_anchors(target), db)
    assert hits == []  # no overlap => no false match


# ---------------------------------------------------------------- evidence ledger
def test_parse_address_claims():
    ac = parse_address_claims("func@0x1000 is AES_encrypt and 0x1000 = encrypt_block")
    assert "0x1000" in ac
    assert any("aes_encrypt" in c for c in ac["0x1000"])


def test_contradiction_detected():
    ledger = build_ledger([
        ("w1", "func@0x1000 is AES_encrypt"),
        ("w2", "func@0x1000 is des_encrypt"),
    ])
    assert len(ledger.contradictions) == 1
    c = ledger.contradictions[0]
    assert c.address == "0x1000"
    assert set(c.values) == {"aes_encrypt", "des_encrypt"}


def test_no_contradiction_when_agree():
    ledger = build_ledger([
        ("w1", "func@0x1000 is AES_encrypt"),
        ("w2", "func@0x1000 is AES_encrypt"),
    ])
    assert ledger.contradictions == []
    # independent support = 2 distinct workers
    assert ledger.independent_support("0x1000", "aes_encrypt") == 2


# ---------------------------------------------------------------- rebench eval
def test_eval_honest_vs_flat():
    rows = [
        EvalRow("AES_encrypt", "AES_encrypt", confidence_tier=3),   # evaluable correct
        EvalRow("foo", "bar", confidence_tier=3),                    # evaluable wrong
        EvalRow("baz", None, confidence_tier=3),                     # no ground truth (excluded)
        EvalRow("x", "y", confidence_tier=0),                        # low tier (excluded)
    ]
    rep = evaluate(rows, min_tier=2)
    assert rep.total == 4
    assert rep.evaluable == 2          # only tier>=2 with gt
    assert rep.paired == 2
    assert rep.correct == 1
    assert rep.accuracy == 0.5
    # flat counts the tier0 row too -> 3 compared, 1 correct => 1/3
    assert abs(rep.flat_accuracy - (1 / 3)) < 0.001
    assert "excluded" in rep.note


def test_eval_empty():
    rep = evaluate([])
    assert rep.total == 0 and rep.accuracy == 0.0


# ---------------------------------------------------------------- firmware extract
def test_scan_signatures_squashfs():
    img = Path(tempfile.mkdtemp()) / "fw.bin"
    data = b"\x00" * 100 + b"hsqs" + b"\x00" * 50 + b"\x1f\x8b" + b"\x00" * 10
    img.write_bytes(data)
    hits = scan_signatures(img)
    fmts = {h.fmt for h in hits}
    assert "squashfs" in fmts
    assert "gzip" in fmts


def test_detect_format_elf():
    img = Path(tempfile.mkdtemp()) / "fw.elf"
    img.write_bytes(b"\x7fELF" + b"\x00" * 64)
    assert detect_format(img) == "elf"


def test_run_binwalk_signature_fallback():
    img = Path(tempfile.mkdtemp()) / "fw.bin"
    img.write_bytes(b"\x00" * 10 + b"hsqs" + b"\x00" * 20)
    out = Path(tempfile.mkdtemp())
    man = run_binwalk(img, out)
    assert man.tool in ("signature-scan", "binwalk", "binwalk(failed)->signature-scan")
    assert any(h.fmt == "squashfs" for h in man.hits)


# ---------------------------------------------------------------- vector recovery
def test_arm_vector_recovery():
    # Self-contained tiny ARM image: SP then Reset_Handler (LSB=1 => Thumb),
    # handler at file offset 8 (within the image) pointing at code-like bytes.
    code = bytes([0xC0, 0x46]) * 40  # mov r12,r8-like Thumb-ish (non-uniform)
    img = Path(tempfile.mkdtemp()) / "arm.bin"
    img.write_bytes(b"\x00\x10\x01\x20"          # SP = 0x20011000
                    b"\x09\x00\x00\x00"          # Reset = 0x00000009 (Thumb, handler @ 0x00000008)
                    + code)
    vr = recover_vector("arm", img)
    assert vr.vector_addr == 4
    assert vr.handler_addr == 0x00000008
    # handler points into the code-like region (within image bounds)
    assert vr.sane is True


def test_arm_vector_into_zero_is_unsane():
    img = Path(tempfile.mkdtemp()) / "arm0.bin"
    img.write_bytes(b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00" * 64)
    vr = recover_vector("arm", img)
    assert vr.sane is False


def test_mips_vector_recovery():
    # exception base word that is non-zero / non-0xFFFFFFFF at offset 0
    img = Path(tempfile.mkdtemp()) / "mips.bin"
    img.write_bytes(b"\x3c\x1c\x80\x00" + b"\x00" * 60)  # lui gp,0x8000 (plausible code)
    vr = recover_vector("mips", img)
    assert vr.arch == "mips"
    assert vr.handler_addr is not None


def test_riscv_vector_recovery():
    img = Path(tempfile.mkdtemp()) / "rv.bin"
    img.write_bytes(b"\x97\x01\x01\x00" + b"\x00" * 60)   # auipc-ish non-uniform
    vr = recover_vector("riscv", img)
    assert vr.sane is True


def test_unsupported_arch():
    img = Path(tempfile.mkdtemp()) / "z80.bin"
    img.write_bytes(b"\x00" * 16)
    vr = recover_vector("z80", img)
    assert vr.confidence == "unsupported"
    assert confidence_tier(vr) == "unsupported"
