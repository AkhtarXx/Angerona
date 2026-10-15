"""Behavioral tests for A3 (forced re-exec), A4 (behavioral oracle), B3 (coverage tier),
B4 (corpus caveat)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.bequiv import compile_check, compile_problems, behavioral_check
from src.analysis.auto_reexec import forced_reexec, extract_c_blocks
from src.analysis.coverage_tier import stratify_coverage
from src.analysis.corpus_caveat import attach_corpus_caveat


GOOD_C = "int add(int a, int b){ return a + b; }\nint main(int c, char**v){ return add(2,3); }\n"
BAD_C = "int add(int a, int b){ return a - b; }\nint main(int c, char**v){ return add(2,3); }\n"


def _write_tmp(content: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "u.c"
    p.write_text(content)
    return p


def test_compile_check_good():
    p = _write_tmp(GOOD_C)
    ok, info = compile_check(p)
    assert ok, info


def test_compile_check_bad_syntax():
    p = _write_tmp("int main( { return ; }\n")
    ok, _ = compile_check(p)
    assert not ok


def test_compile_check_tolerates_missing_main():
    """A per-function reconstruction without main must still compile (auto-wrapped)."""
    p = _write_tmp("int add(int a, int b){ return a + b; }\n")  # no main
    ok, _ = compile_check(p)
    assert ok, "missing main should be auto-wrapped, not a failure"


def test_compile_check_tolerates_unresolved_externs():
    """Reconstructions referencing undefined runtime symbols (rust_panic/Solana calls)
    must still compile — structural diff only needs the function bodies present."""
    src = ("extern void rust_panic(void);\n"
           "int helper(int x){ if (x < 0) rust_panic(); return x + 1; }\n")
    p = _write_tmp(src)
    ok, _ = compile_check(p)
    assert ok, "unresolved externs must not fail the tolerant link"


def test_compile_check_surfaces_unknown_type():
    """A real C error (unknown type / missing typedef) must FAIL and surface the line."""
    src = ("extern void f(u32 *p);\n"  # u32 undefined -> real error
           "int main(void){ return 0; }\n")
    p = _write_tmp(src)
    ok, detail = compile_check(p)
    assert not ok
    problems = compile_problems(p)
    assert problems, "a real type error must produce parsed problems"
    assert any("u32" in pr["message"] for pr in problems)
    assert any("unknown type" in pr["message"] for pr in problems)


def test_compile_problems_bad_typedef_name():
    """Bare `longlong` (agent typo) is a real error, surfaced by name."""
    src = ("int main(void){ longlong x = 0; return (int)x; }\n")
    p = _write_tmp(src)
    problems = compile_problems(p)
    assert problems
    assert any("longlong" in pr["message"] for pr in problems)


def test_behavioral_equivalent():
    a = _write_tmp(GOOD_C)
    b = _write_tmp(GOOD_C)
    res = behavioral_check(a, b, test_inputs=[""])
    assert res.compiled and res.ran and res.equivalent


def test_behavioral_diverges():
    a = _write_tmp(GOOD_C)
    b = _write_tmp(BAD_C)
    res = behavioral_check(a, b, test_inputs=[""])
    assert res.compiled and res.ran
    assert not res.equivalent
    assert res.mismatches


def test_forced_reexec_flag_fails_compile():
    report = "Here is recovered code:\n```c\nint main( { return ; }\n```\n"
    findings = forced_reexec(report)
    assert len(findings) == 1
    assert not findings[0].compiled
    assert "failed to compile" in findings[0].detail


def test_forced_reexec_passes_good():
    report = f"Recovered:\n```c\n{GOOD_C}```\n"
    findings = forced_reexec(report)
    assert findings[0].compiled
    # no reference -> smoke run OK, equivalent flag reflects smoke (self==self True)
    assert findings[0].ran


def test_extract_c_blocks():
    report = "x\n```c\nint f(){}\n```\ny\n```cpp\nint g(){}\n```\n"
    blocks = extract_c_blocks(report)
    assert len(blocks) == 2


def test_coverage_tier_real():
    d = Path(tempfile.mkdtemp())
    (d / "functions.csv").write_text(
        "name,entry,size,signature\n"
        "main,0x100,40,int main()\n"
        "FUN_200,0x200,5,\n"          # tiny/stub -> tier0
        "helper,0x300,80,int helper(int)\n"
    )
    (d / "decompiled").mkdir()
    (d / "decompiled" / "main_0x100.c").write_text("int main(){return 0;}")
    (d / "decompiled" / "helper_0x300.c").write_text("int helper(int x){return x;}")
    rep = stratify_coverage(d)
    assert rep.total == 3
    # tier0 should catch the tiny FUN_200
    t0 = rep.tiers[3]
    assert t0.count == 1
    assert 0.0 < rep.evalable_ratio < 1.0


def test_coverage_tier_evalable_ratio():
    d = Path(tempfile.mkdtemp())
    (d / "functions.csv").write_text(
        "name,entry,size,signature\nreal,0x100,50,int real()\n"
    )
    (d / "decompiled").mkdir()
    (d / "decompiled" / "real_0x100.c").write_text("int real(){return 0;}")
    rep = stratify_coverage(d)
    assert rep.evalable_ratio == 1.0


def test_corpus_caveat_no_match():
    d = Path(tempfile.mkdtemp())
    (d / "ref1.BinExport").write_text("x")
    (d / "ref2.BinExport").write_text("y")
    cc = attach_corpus_caveat(d, matched=False)
    assert cc.corpus_size == 2
    assert not cc.matched
    assert "novel" in cc.caveat.lower()  # B4: miss != novel


def test_corpus_caveat_matched():
    d = Path(tempfile.mkdtemp())
    (d / "ref1.BinExport").write_text("x")
    cc = attach_corpus_caveat(d, matched=True)
    assert cc.matched
    assert cc.corpus_size == 1
    assert "not proof of origin" in cc.caveat.lower()
