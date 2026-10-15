"""Behavior tests for per-region equivalence localization (roadmap Phase B5)."""
from __future__ import annotations

from src.analysis.per_region_equiv import _hint, diff_regions, localize_for_verdict


ORIG_C = """
int parse(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i + 4 <= len) {
        uint32_t v = *(const uint32_t *)(data + i);
        if (v == 0xDEADBEEF) { return 1; }
        i += 4;
    }
    return 0;
}
"""

EQUIV_C = """
int parse(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i + 4 <= len) {
        uint32_t v = *(const uint32_t *)(data + i);
        if (v == 0xDEADBEEF) { return 1; }
        i += 4;
    }
    return 0;
}
"""

DIVERGENT_C = """
int parse(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 4 <= len; i++) {        // loop shape changed
        uint32_t v = *(const uint8_t *)(data + i); // wrong read width
        if (v == 0xDEADBEEF) { return 2; }         // different return
    }
    return 0;
}
"""

CALL_DRIFT_C = """
int parse(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i + 4 <= len) {
        uint32_t v = load_u32(data + i);           // extra call
        if (v == 0xDEADBEEF) { return 1; }
        i += 4;
    }
    audit(i);
    return 0;
}
"""


def test_identical_is_equivalent():
    rep = diff_regions(ORIG_C, EQUIV_C)
    assert rep.equivalent
    assert not rep.regions
    assert "identical" in rep.summary


def test_divergent_regions_are_localized():
    rep = diff_regions(ORIG_C, DIVERGENT_C)
    assert not rep.equivalent
    assert rep.regions
    for r in rep.regions:
        assert r.hint
        assert 0 <= r.original_span[0] <= r.original_span[1]
        assert 0 <= r.reconstruction_span[0] <= r.reconstruction_span[1]
    # while -> for keeps a single loop: the old string-length comparison wrongly
    # tagged equal loop counts as a "loop shape" mismatch.
    assert not any("loop shape" in r.hint for r in rep.regions)


def test_call_drift_hint():
    rep = diff_regions(ORIG_C, CALL_DRIFT_C)
    assert not rep.equivalent
    # call-count delta inside the loop + the trailing audit() call
    assert any("call-site drift" in r.hint for r in rep.regions)


def test_loop_shape_hint_counts_loops_not_string_length():
    # equal loop counts (for vs while) must not be tagged as a mismatch
    assert "loop shape" not in _hint(
        ["for (i = <num>; i < n; i++)"], ["while (i < n)"]
    )
    # a removed loop is a genuine loop-count delta
    assert (
        _hint(["for (i = <num>; i < n; i++)"], ["x = <num>;"])
        == "loop shape mismatch"
    )


def test_localize_for_verdict_repair_fragment():
    out = localize_for_verdict(ORIG_C, DIVERGENT_C)
    frag = out["repair_prompt_fragment"]
    assert "divergent" in out["summary"]
    assert frag and frag != "no localized divergence"
    # repair prompt names spans, not just "function wrong"
    assert "orig lines" in frag


def test_localize_for_verdict_identical():
    out = localize_for_verdict(ORIG_C, EQUIV_C)
    assert out["equivalent"]
    assert out["repair_prompt_fragment"] == "no localized divergence"


def test_normalization_strips_comments_and_numbers():
    a = "int f() {\n  return 42; /* comment */\n}\n"
    b = "int f(){\n  return 1000;\n}\nint g(){}"
    rep = diff_regions(a, b)
    # comments and immediate values fold away -> stable line diff, extra g() insert
    assert rep.regions
    insert = [r for r in rep.regions if r.kind == "insert"]
    assert insert
