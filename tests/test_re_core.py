"""Tests for the RE-core strength modules (RE-1..RE-5)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.simindex import SimilarityIndex, _function_tokens
from src.analysis.symbolrecovery import recover_symbols, cross_engine_consensus
from src.analysis.deobfuscate import deobfuscate_function, resolve_opaque_predicates
from src.analysis.structrecovery import recover_structs
from src.analysis.irnorm import normalize_function, normalize_line, semantic_signature


def _mk_corpus(base: Path, funcs: dict[str, str]):
    d = base / "code"
    d.mkdir(parents=True, exist_ok=True)
    (d / "functions.csv").write_text(
        "name,entry,size,sig\n" + "\n".join(f"{n},{a},10,x" for n, a in funcs.items()))
    dd = d / "decompiled"
    dd.mkdir()
    for n, body in funcs.items():
        (dd / f"{n}.c").write_text(body)
    return d


def test_simindex_detects_shared():
    a = _mk_corpus(Path(tempfile.mkdtemp()), {
        "f1": "mov eax, 1\nadd eax, ebx\ncall printf\nret\n",
        "f2": "mov ecx, 2\nxor edx, edx\ncall memcpy\nret\n",
    })
    b = _mk_corpus(Path(tempfile.mkdtemp()), {
        "f1": "mov eax, 1\nadd eax, ebx\ncall printf\nret\n",  # identical
        "f9": "int3\nud2\nnop\n",  # unique, no match
    })
    idx = SimilarityIndex(dim_reduce=64)
    idx.add_corpus(a)
    idx.build()
    m = idx.query(b, top_k=2, threshold=0.60)
    names = {x.name for x in m}
    assert "f1" in names
    assert "f9" not in names  # unique func correctly unmatched


def test_simindex_zero_vocab_no_false_match():
    a = _mk_corpus(Path(tempfile.mkdtemp()), {"f1": "mov eax, 1\ncall printf\nret\n"})
    b = _mk_corpus(Path(tempfile.mkdtemp()), {"fz": "push r12\npop r12\n syscall\n"})
    idx = SimilarityIndex(dim_reduce=32)
    idx.add_corpus(a)
    idx.build()
    m = idx.query(b, top_k=1, threshold=0.5)
    assert m == []  # no shared vocab -> no match


def test_symbolrecovery_recovers_name():
    corpus = _mk_corpus(Path(tempfile.mkdtemp()), {
        "memcpy_impl": "mov ecx, 2\nxor edx, edx\ncall memcpy\nret\n",
    })
    query = _mk_corpus(Path(tempfile.mkdtemp()), {
        "FUN_401000": "mov ecx, 2\nxor edx, edx\ncall memcpy\nret\n",  # looks like memcpy
    })
    rep = recover_symbols(query, [corpus], threshold=0.80)
    assert rep.corpus_count >= 1
    # f1 (memcpy_impl) should be proposed for FUN_401000
    assert any("memcpy" in s.proposed_name for s in rep.symbols)


def test_cross_engine_consensus():
    ida = {"0x100": "sub_sqrt", "0x200": "helper"}
    ghidra = {"0x100": "sub_sqrt", "0x300": "other"}
    out = cross_engine_consensus(ida, ghidra)
    assert out["0x100"]["confidence"] == "HIGH"   # agree
    assert out["0x200"]["confidence"] == "MEDIUM"  # IDA only
    assert "0x300" in out


def test_deobfuscate_flattened():
    asm = (
        "0x100: push ebp\n"
        "0x101: mov ebp, esp\n"
        "0x102: jmp 0x200\n"          # dispatcher
        "0x200: cmp eax, 1\n"
        "0x201: je 0x300\n"           # handler A
        "0x300: mov ebx, 2\n"
        "0x301: jmp 0x400\n"
        "0x400: ret\n"
    )
    res = deobfuscate_function(asm, entry="0x100")
    # static reachable order includes the handler + ret
    assert "0x300" in res.recovered_blocks
    assert res.method == "static_cfg_trace"


def test_structrecovery_parses():
    c = "struct Point { int x; int y; };\nvoid f(struct Point* p){ p->x = 1; }"
    rep = recover_structs(c)
    assert rep.parsed_ok
    assert any(s.name == "Point" and len(s.fields) == 2 for s in rep.structs)


def test_structrecovery_regex_fallback():
    c = "struct Foo { int a; char b; };"
    rep = recover_structs(c)
    assert any(s.name == "Foo" for s in rep.structs)


def test_irnorm_cross_arch():
    x86 = "0x10: mov eax, 1\n0x11: add eax, 2\n0x12: call 0x999\n0x13: ret\n"
    arm = "0x10: mov r0, #1\n0x14: add r0, r0, #2\n0x18: bl 0x999\n0x1c: bx lr\n"
    nx = normalize_function(x86)
    na = normalize_function(arm)
    ops_x = [i.op for i in nx]
    ops_a = [i.op for i in na]
    # both should be MOV, ADD, CALL, RET semantically
    assert ops_x == ["MOV", "ADD", "CALL", "RET"]
    assert ops_a == ["MOV", "ADD", "CALL", "RET"]
    # semantic signatures should share the core ops
    sx, sa = semantic_signature(x86), semantic_signature(arm)
    assert "MOV" in sx and "MOV" in sa
    assert "CALL" in sx and "CALL" in sa


def test_irnorm_unknown_is_other():
    ni = normalize_line("0x1: weirdop r1, r2")
    assert ni is not None
    assert ni.op == "OTHER"
