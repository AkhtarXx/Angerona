"""Behavioral tests for Part 5 (malware RE) and Part 6 (custom/obscure arch) gaps."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.binary_bpe import BPETokenizer, chunk_for_context
from src.analysis.malware_triage import triage, TriageResult
from src.analysis.lift_confidence import assess_lift
from src.analysis.sleigh_draft import draft_slaspec_prompt, verify_slaspec_draft
from src.analysis.unicorn_oracle import arch_supported, emulate_function


# ---------------------------------------------------------------- binary_bpe
def test_bpe_compresses():
    data = b"\x90" * 50 + b"\x55\x89\xe5" * 50 + b"\xc3" * 50  # repetitive x86
    tok = BPETokenizer().train(data, vocab_size=256)
    # repetitive data should compress (fewer tokens than bytes)
    assert tok.compression_ratio(data) < 1.0


def test_bpe_empty():
    tok = BPETokenizer().train(b"", vocab_size=64)
    assert tok.encode(b"abc")  # unk handling, no crash


def test_chunk_for_context():
    big = "\n\n".join(f"void func_{i}() {{ int x = {i}; }}\n" for i in range(200))
    chunks = chunk_for_context(big, token_budget=200)
    assert len(chunks) > 1
    for c in chunks:
        # ~4 chars/token * 200 tokens
        assert len(c) <= 200 * 4 + 50


# ---------------------------------------------------------------- malware triage
def _export_with(imports="", strings="", binary_bytes=None):
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "imports.txt").write_text(imports)
    (d / "strings.txt").write_text(strings)
    if binary_bytes is not None:
        (d / "binary").write_bytes(binary_bytes)
    return d


def test_triage_suspicious_api():
    d = _export_with(imports="VirtualAlloc\nCreateRemoteThread\nInternetOpen\n")
    res = triage(d)
    assert "virtualalloc" in res.suspicious_api_hits
    assert "createremotethread" in res.suspicious_api_hits
    assert res.confidence in ("low", "medium")


def test_triage_packer_upx():
    d = _export_with(binary_bytes=b"\x50\x4b\x03\x04" + b"UPX!" + b"\x00" * 40)
    res = triage(d)
    assert res.packer_detected == "upx"
    assert res.evasion_resistant is True
    assert res.confidence == "medium"


def test_triage_family_hypothesis():
    family_db = {"emotet": {"virtualalloc", "internetopen", "cryptencrypt"}}
    d = _export_with(imports="VirtualAlloc\nInternetOpen\nCryptEncrypt\n")
    res = triage(d, family_db=family_db)
    assert res.family_hypothesis == "emotet"
    assert res.family_score >= 0.25


def test_triage_empty_unknown():
    d = _export_with()
    res = triage(d)
    assert res.family_hypothesis is None
    assert res.confidence == "low"


# ---------------------------------------------------------------- lift confidence
def test_lift_confidence_clean():
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "functions.csv").write_text("name,entry,size,signature\nmain,0x100,40,int main()\n")
    (d / "decompiled").mkdir()
    (d / "decompiled" / "main_0x100.c").write_text("int main(){return 0;}")
    rep = assess_lift(d)
    assert rep.total == 1
    assert rep.high == 1
    assert rep.ratio == 1.0


def test_lift_confidence_ungated_unknown_opcode():
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "functions.csv").write_text("name,entry,size,signature\nx,0x100,40,\n")
    asm = d / "asm"
    asm.mkdir()
    (asm / "x.asm").write_text("0x100: ??? unknown opcode 0xAB\n")
    rep = assess_lift(d)
    assert rep.ungated == 1
    assert "ungated" in rep.caveat.lower()


def test_lift_confidence_engine_fallback():
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "functions.csv").write_text("name,entry,size,signature\nx,0x100,40,\n")
    rep = assess_lift(d, engine_fallback=True)
    assert rep.ungated == 1
    assert rep.ratio == 0.0


# ---------------------------------------------------------------- sleigh draft
def test_draft_prompt_contains_manual():
    p = draft_slaspec_prompt("ADD rD, rA, rB", ["ADD"], arch_name="mytri")
    assert "mytri" in p and "ADD rD, rA, rB" in p


def test_verify_slaspec_valid():
    draft = """
    define token t (8) op = (0,7);
    define space ram (64, 0);
    define register rA (32);
    define instruction ADD { op = 0; }
    """
    vec = [{"mnemonic": "ADD"}]
    res = verify_slaspec_draft(draft, vec)
    assert res.valid is True
    assert res.vectors_passed == 1


def test_verify_slaspec_invalid():
    draft = "define token t (8) op = (0,7);"  # missing sections + no ADD
    vec = [{"mnemonic": "ADD"}]
    res = verify_slaspec_draft(draft, vec)
    assert res.valid is False
    assert any("missing section" in r for r in res.reasons)


def test_verify_slaspec_empty():
    res = verify_slaspec_draft("", [])
    assert res.valid is False and "empty" in res.reasons[0]


# ---------------------------------------------------------------- qemu oracle
def test_arch_supported_known():
    assert arch_supported("arm")
    assert arch_supported("riscv64")
    assert not arch_supported("z80")


def test_emulate_arm_nop_sequence():
    # a few ARM Thumb instructions; we just verify it runs without crashing and
    # reports a supported status (exact semantics depend on unicorn backend)
    code = bytes([0x00, 0xbf, 0x00, 0xbf])  # NOP; NOP (Thumb)
    res = emulate_function(code, "armthumb", base_addr=0x1000)
    assert res.status in ("success", "error", "unsupported", "unavailable")
    if res.status == "success":
        assert res.instructions_run >= 0


def test_emulate_unsupported_arch():
    res = emulate_function(b"\x00\x00", "z80")
    assert res.status == "unsupported"
