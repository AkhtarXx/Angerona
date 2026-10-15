"""Behavior tests for runtime differential testing (roadmap Phase B6).

Real gcc compile + run. Proves:
  1. parse level rejects non-function bodies.
  2. compile level catches real C errors.
  3. behavior level confirms equivalent reconstructions across the input corpus.
  4. behavior level rejects divergent reconstructions and reports the first bad input.
  5. no-reference path is smoke-only and never claims behavioral equivalence.
  6. whole-dir verify gives a structured verdict.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from src.analysis.differential_runtime import (
    DifferentialVerdict,
    runtime_differential,
    verify_whole_reconstruction_dir,
)


GOOD_C = """
int add(int a, int b) { return a + b; }
int main(void) { return add(2, 3) == 5 ? 0 : 1; }
"""

EQUIV_C = """
int add(int a, int b) { return b + a; }
int main(void) { return add(2, 3) == 5 ? 0 : 1; }
"""

DIVERGENT_C = """
int add(int a, int b) { return a - b; }
int main(void) { return add(2, 3) == 5 ? 0 : 1; }
"""

BROKEN_C = """
int add(int a, int b) { return a + b
"""

NOT_A_FUNCTION = "struct ctx { int a; };\n"

require_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc unavailable")


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(content)
    return p


@require_gcc
def test_parse_level_rejects_non_function():
    with tempfile.TemporaryDirectory() as td:
        v = runtime_differential(_write(Path(td), "u.c", NOT_A_FUNCTION))
        assert not v.parse_ok
        assert not v.compile_ok
        assert "no function" in v.reason


@require_gcc
def test_compile_level_catches_error():
    with tempfile.TemporaryDirectory() as td:
        v = runtime_differential(_write(Path(td), "u.c", BROKEN_C))
        assert v.parse_ok
        assert not v.compile_ok
        assert v.reason == "compile failed"
        assert v.repair_hint           # repair agent gets actionable detail


@require_gcc
def test_behavior_confirms_equivalent_reconstruction():
    with tempfile.TemporaryDirectory() as td:
        a = _write(Path(td), "a.c", GOOD_C)
        b = _write(Path(td), "b.c", EQUIV_C)
        v = runtime_differential(a, reference_c=b, corpus_size=16)
        assert v.behavior_ok, v.reason
        assert v.reference.startswith("caller-supplied")
        assert v.inputs_tested > 0


@require_gcc
def test_behavior_rejects_divergent_reconstruction():
    with tempfile.TemporaryDirectory() as td:
        a = _write(Path(td), "a.c", GOOD_C)
        b = _write(Path(td), "b.c", DIVERGENT_C)
        v = runtime_differential(a, reference_c=b, corpus_size=16)
        assert not v.behavior_ok
        assert "divergence" in v.reason.lower()
        assert v.repair_hint


@require_gcc
def test_no_reference_is_smoke_only_never_equivalence():
    with tempfile.TemporaryDirectory() as td:
        a = _write(Path(td), "a.c", GOOD_C)
        v = runtime_differential(a, corpus_size=4)
        assert v.compile_ok
        # No oracle -> compile-level smoke only, NEVER behavioral equivalence.
        assert not v.behavior_ok
        assert "NOT confirmed" in v.reason
        assert "no reference" in v.reference


@require_gcc
def test_twin_dir_reference_self_consistency():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        _write(tdp, "a_0x100.c", GOOD_C)
        _write(tdp, "b_0x200.c", EQUIV_C)
        # recon without an explicit reference finds the twin `add`
        v = runtime_differential(tdp / "a_0x100.c", twin_dir=tdp, corpus_size=8)
        assert v.behavior_ok
        assert "twin" in v.reference


@require_gcc
def test_whole_dir_verdict():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        _write(tdp, "u1.c", GOOD_C)
        _write(tdp, "u2.c", EQUIV_C)
        rep = verify_whole_reconstruction_dir(tdp, corpus_size=4)
        assert rep["total"] == 2
        assert rep["compile_ok"] == 2
        # no reference per unit -> no behavioral confirmation claimed
        assert rep["verdict"] == "compile-only (behavioral oracle absent)"


@require_gcc
def test_whole_dir_compile_failures_marked():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        _write(tdp, "u1.c", GOOD_C)
        _write(tdp, "u2.c", BROKEN_C)
        rep = verify_whole_reconstruction_dir(tdp, corpus_size=4)
        assert rep["verdict"] == "compile-failures"
        assert rep["compile_ok"] == 1


@require_gcc
def test_whole_dir_empty_is_no_units():
    with tempfile.TemporaryDirectory() as td:
        rep = verify_whole_reconstruction_dir(Path(td), corpus_size=2)
        assert rep["verdict"] == "no-units"
        assert rep["total"] == 0
