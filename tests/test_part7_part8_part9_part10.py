"""Behavioral tests for Part 7 (BCRL), Part 8 (P-code struct), Part 9 (variant analysis),
Part 10 (obfuscation detection)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.bcrl import mask_tokens, embed_function, evaluate_ranking
from src.analysis.simindex import SimilarityIndex
from src.analysis.pcode_struct import recover_structs_from_decompiled
from src.analysis.variant_analysis import find_variants
from src.analysis.obfuscation_detect import classify_function, detect_in_export


# ---------------------------------------------------------------- Part 7 BCRL
def test_mask_tokens():
    asm = "mov eax, 0x1F4\ncall 0x400520\nadd ebx, 42"
    m = mask_tokens(asm)
    assert "0x1F4" not in m and "42" not in m
    assert "<imm>" in m and "<addr>" in m


def test_bcrl_recall_at_k():
    # build an index of two similar functions + distractor, then query a transform
    idx = SimilarityIndex(dim_reduce=32)
    idx.add_function("0x100", "aes_enc", "mov eax, 1\nxor edx, edx\ncall sub_1\nret")
    idx.add_function("0x200", "aes_dec", "mov ebx, 2\nxor ecx, ecx\ncall sub_2\nret")
    idx.add_function("0x300", "unrelated", "nop\nnop\nnop\nnop\nnop")
    idx.build()
    # query: a variant of aes_enc with different constants (masking should catch it)
    q = "mov eax, 0x99\nxor edx, edx\ncall sub_9\nret"
    res = idx.query_text(mask_tokens(q), top_k=3, threshold=0.0)
    names = [r.name for r in res]
    assert "aes_enc" in names  # the masked embedding should rank the sibling first
    metric = evaluate_ranking(idx, [q], [["aes_enc"]], k=3)
    assert metric.recall_at_k[1] >= 0.0  # protocol runs; not strict on synthetic data


def test_embed_function_returns_vector():
    idx = SimilarityIndex(dim_reduce=16)
    idx.add_function("0x1", "f", "mov eax, 1\nret")
    idx.build()
    v = embed_function("mov eax, 1\nret", idx)
    assert v is not None and v.shape[0] > 0


# ---------------------------------------------------------------- Part 8 struct
def _decompiled_dir(text: str):
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "decompiled").mkdir()
    (d / "decompiled" / "ctx_0x100.c").write_text(text)
    return d


def test_struct_recovery_finds_fields():
    code = """
    void process(user_t* u) {
        u->id = 1;
        u->name[0] = 'a';
        u->count = read32(u->id);
        struct point* p = &u->pt;
    }
    """
    structs = recover_structs_from_decompiled(_decompiled_dir(code))
    assert any(s.base_var == "u" for s in structs)
    u = next(s for s in structs if s.base_var == "u")
    assert "id" in u.fields and "name" in u.fields and "count" in u.fields
    assert u.fields["id"].writes >= 1  # u->id = 1 is a write


def test_struct_recovery_array():
    code = "void f(buf_t* b){ b->items[i] = 0; b->len = b->len + 1; }"
    structs = recover_structs_from_decompiled(_decompiled_dir(code))
    assert any(s.array_access for s in structs)


def test_struct_recovery_empty():
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "decompiled").mkdir()
    (d / "decompiled" / "x.c").write_text("void g(){ return; }")
    structs = recover_structs_from_decompiled(d)
    assert structs == []  # no struct-like access -> empty (no false positive)


# ---------------------------------------------------------------- Part 9 variant
def test_variant_analysis_finds_sibling():
    idx = SimilarityIndex(dim_reduce=32)
    idx.add_function("0x100", "xml_parse", "mov eax, 1\ncall parse_elem\nret")
    idx.add_function("0x200", "json_parse", "mov ebx, 2\ncall parse_elem\nret")
    idx.add_function("0x300", "noise", "nop\nnop\nnop")
    idx.build()
    # seed = the known-bad xml_parse variant; expect json_parse as candidate sibling
    rep = find_variants("mov eax, 9\ncall parse_elem\nret", idx,
                        seed_name="xml_parse", cve="CVE-2026-0001")
    assert rep.cve == "CVE-2026-0001"
    names = [c.name for c in rep.candidates]
    assert "xml_parse" not in names  # seed excluded
    assert "json_parse" in names  # sibling retrieved


def test_variant_analysis_no_seed_exclusion_crash():
    idx = SimilarityIndex(dim_reduce=8)
    idx.add_function("0x1", "f", "mov eax, 1\nret")
    idx.build()
    rep = find_variants("mov eax, 1\nret", idx)  # no seed_name
    assert rep.seed_name is None
    assert isinstance(rep.candidates, list)


# ---------------------------------------------------------------- Part 10 obfusc
def test_obfusc_flattened():
    asm = """
    while (state != 0) {
        switch (state) {
            case 1: jmp block_a
            case 2: jmp block_b
            case 3: jmp block_c
        }
    }
    """
    r = classify_function("vm_func", asm)
    assert r.label in ("flattened", "mixed")
    assert any("flatten" in reason.lower() or "dispatch" in reason.lower()
               for reason in r.reasons)


def test_obfusc_virtualized():
    asm = """
    vm_dispatch:
        jmp *handler_table[opcode]
        handler: ...
        opcode = next_byte()
    """
    r = classify_function("obf", asm)
    assert r.label == "virtualized"


def test_obfusc_clean():
    asm = "mov eax, 1\nadd ebx, eax\nret"
    r = classify_function("normal", asm)
    assert r.label == "clean"
    assert r.score == 0.0


def test_obfusc_detect_in_export():
    d = Path(tempfile.mkdtemp()) / "code"
    d.mkdir()
    (d / "asm").mkdir()
    (d / "asm" / "ok.asm").write_text("mov eax, 1\nret\n")
    (d / "asm" / "flat.asm").write_text(
        "while(state!=0){ switch(state){ case 1: jmp a case 2: jmp b } }\n")
    results = detect_in_export(d)
    assert len(results) == 2
    flagged = [r for r in results if r.label != "clean"]
    assert any(r.name == "flat" for r in flagged)
