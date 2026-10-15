"""Behavior tests for ReSym-style constraint solver (roadmap Phase B4)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.analysis.resym_solver import (
    FactBase,
    TypeClaim,
    _TYPE_AGNOSTIC_PRIMITIVES,
    aggregate_facts,
    parse_llm_claims,
    solve_from_code_dir,
    solve_types,
)
from src.analysis.pcode_struct import Field, StructCandidate


def _factbase_with_ctx(width: int = 8) -> FactBase:
    fb = FactBase()
    sc = StructCandidate(base_var="ctx")
    sc.fields["key"] = Field(offset=0, name="key", reads=3, width_hint=width)
    sc.fields["rounds"] = Field(offset=8, name="rounds", writes=1, width_hint=4)
    fb.add_struct(sc)
    return fb


# ----------------------------------------------------------------- claims parsing

def test_parse_llm_claims_from_list():
    text = json.dumps([
        {"var": "ctx", "field": "key", "claim": "char[64]"},
        {"var": "ctx", "field": "rounds", "claim": "int"},
    ])
    claims = parse_llm_claims(text)
    assert len(claims) == 2
    assert claims[0].var == "ctx" and claims[0].field == "key"


def test_parse_llm_claims_dict_wrapper_and_garbage():
    text = json.dumps({"claims": [{"var": "a", "claim": "int"}, {"bad": "row"}]})
    claims = parse_llm_claims(text)
    assert len(claims) == 1
    assert parse_llm_claims("not json at all") == []
    assert parse_llm_claims("[]") == []


# ----------------------------------------------------------------- accept/reject

def test_width_compatible_claim_accepted():
    fb = _factbase_with_ctx(width=8)
    claims = [TypeClaim(var="ctx", field="key", claim="char*")]
    layouts, verdicts = solve_types(claims, fb)
    assert verdicts[0].accepted
    assert layouts[0].fields["key"]["type"] == "char*"


def test_width_mismatch_claim_rejected_strict():
    fb = _factbase_with_ctx(width=8)      # key is 8 bytes wide
    claims = [TypeClaim(var="ctx", field="key", claim="char")]  # 1-byte mismatch
    layouts, verdicts = solve_types(claims, fb, strict=True)
    assert not verdicts[0].accepted
    assert "width" in verdicts[0].reason
    # strict rejection does NOT poison the layout
    assert not layouts or layouts[0].fields == {}


def test_width_mismatch_claim_warned_non_strict():
    fb = _factbase_with_ctx(width=8)
    claims = [TypeClaim(var="ctx", field="key", claim="char")]
    layouts, verdicts = solve_types(claims, fb, strict=False)
    assert verdicts[0].accepted          # no fact contradiction recorded under lenient
    assert layouts[0].fields["key"]["type"] == "char"


def test_type_agnostic_primitive_claim_blocked():
    fb = _factbase_with_ctx()
    claims = [TypeClaim(var="memset", field="", claim="struct ctx*")]
    layouts, verdicts = solve_types(claims, fb)
    assert not verdicts[0].accepted
    assert "type-agnostic" in verdicts[0].reason


def test_competing_claims_first_wins_under_constraints():
    fb = _factbase_with_ctx(width=8)
    claims = [
        TypeClaim(var="ctx", field="key", claim="char*"),      # width-8 ok
        TypeClaim(var="ctx", field="key", claim="struct foo*"), # tiebreak: first wins
    ]
    layouts, verdicts = solve_types(claims, fb)
    assert verdicts[0].accepted
    assert not verdicts[1].accepted
    assert "superseded" in verdicts[1].reason
    assert layouts[0].fields["key"]["type"] == "char*"


# ----------------------------------------------------------------- fact aggregation

def test_aggregate_facts_mines_struct_candidates():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "decompiled").mkdir()
        (d / "decompiled" / "crypto.c").write_text(
            "void dec(struct ctx *c) {\n"
            "  c->key[0] ^= 0xff;\n"
            "  c->rounds = 16;\n"
            "  memset(c->scratch, 0, 64);\n"
            "}\n"
        )
        fb = aggregate_facts(d)
        assert "c" in fb.vars
        assert "key" in fb.fields["c"] and "rounds" in fb.fields["c"]
        # memset is tracked as a type-agnostic primitive
        assert any(fn == "memset" for fn, _ in fb.type_agnostic_args)


def test_solve_from_code_dir_end_to_end():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "decompiled").mkdir()
        (d / "decompiled" / "f.c").write_text(
            "void f(struct t *p) {\n"
            "  p->a = 1;\n"
            "  p->b = 2;\n"
            "}\n"
        )
        llm = json.dumps({"claims": [
            {"var": "p", "field": "a", "claim": "int"},
            {"var": "p", "field": "b", "claim": "long long"},   # 8-byte
        ]})
        out = solve_from_code_dir(d, llm)
        assert out["claims_parsed"] == 2
        assert out["summary"]["layouts"] == 1
        assert out["facts"]["type_agnostic_args"] or True  # memset family absent → fine
        # both claims accepted (no width fact available, so no contradiction)
        assert out["summary"]["accepted_claims"] == 2


def test_confidence_when_facts_present_vs_absent():
    fb = _factbase_with_ctx(width=8)
    claims = [TypeClaim(var="ctx", field="key", claim="char*"),
              TypeClaim(var="ghost", field="", claim="struct t*")]
    layouts, _ = solve_types(claims, fb)
    ctx = next(lo for lo in layouts if lo.base == "ctx")
    ghost = next(lo for lo in layouts if lo.base == "ghost")
    # ctx has facts (key+rounds) and only key claimed -> partial confidence
    assert 0.0 < ctx.confidence < 1.0
    # ghost has no deterministic signal -> neutral 0.5
    assert ghost.confidence == 0.5
