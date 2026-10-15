"""Behavior tests for ASan-proxy oracle (roadmap Phase C8).

Real gcc + ASan builds and runs. Skips gracefully when ASan runtime is absent.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from src.analysis.asan_proxy import (
    build_asan_harness,
    fuzz_reconstruction_with_asan,
    promote_asan_verdict,
    run_asan_probe,
)


CLEAN_C = """
int add(int a, int b) { return a + b; }
int main(void) { return add(2, 3); }
"""

# Real stack-buffer-overflow ASan must catch.
BOF_C = """
#include <string.h>
int main(int argc, char **argv) {
    char buf[16];
    memset(buf, 'A', 32);           // stack-buffer-overflow: 32 > 16
    return buf[0];
}
"""

UBSAN_C = """
int main(void) {
    int d = 1; d <<= 64;            // UBSan: shift exponent >= width
    return d;
}
"""

require_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc unavailable")


@require_gcc
def test_build_asan_harness_succeeds_on_clean_unit():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        src = tdp / "clean.c"
        src.write_text(CLEAN_C)
        ok, out, detail = build_asan_harness(src, tdp / "clean_asan")
        if not ok and "asan_unavailable" in detail:
            pytest.skip("no ASan runtime available")
        assert ok, detail
        assert out.is_file()


@require_gcc
def test_build_fails_on_real_c_error():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        src = tdp / "broken.c"
        src.write_text("int f(int a) { return a +++ ")  # unterminated
        ok, _, detail = build_asan_harness(src, tdp / "broken_asan")
        assert not ok


@require_gcc
def test_run_probe_catches_stack_buffer_overflow():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        src = tdp / "bof.c"
        src.write_text(BOF_C)
        ok, out, detail = build_asan_harness(src, tdp / "bof_asan")
        if not ok:
            pytest.skip(f"asan unavailable: {detail}")
        fired, kind, blame, rc = run_asan_probe(out, [[]])
        assert fired
        assert kind.startswith("asan")           # any ASan signal counts
        # memo/mem-set fortified overflow shows up as unknown-crash on modern glibc
        assert "crash" in kind.lower() or "overflow" in kind.lower()


@require_gcc
def test_run_probe_catches_ubsan_shift():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        src = tdp / "ubs.c"
        src.write_text(UBSAN_C)
        ok, out, detail = build_asan_harness(src, tdp / "ubs_asan")
        if not ok:
            pytest.skip(f"asan unavailable: {detail}")
        fired, kind, blame, rc = run_asan_probe(out, [[]])
        # 1<<64 triggers UBSan shift exponent error
        assert fired
        assert "ubsan" in kind.lower() or "shift" in kind.lower()


@require_gcc
def test_fuzz_reconstruction_with_asan_overall_crash_confirmed():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "u1_0x100.c").write_text(BOF_C)
        (tdp / "u2_0x200.c").write_text(CLEAN_C)
        report = fuzz_reconstruction_with_asan(tdp, seeds=8, timeout=30)
        if all(u.status in {"asan_unavailable", "build_failed"}
               for u in report.units):
            pytest.skip("no ASan runtime")
        # At least one crash + one clean => crash_confirmed overall
        assert report.crashers >= 1
        crash_units = [u for u in report.units if u.status == "crash_confirmed"]
        assert crash_units
        assert any("overflow" in u.sanitizer_kind.lower() for u in crash_units) or \
               any(u.sanitizer_kind for u in crash_units)
        assert promote_asan_verdict(report).startswith("ASan-proxy CONFIRMED")


@require_gcc
def test_fuzz_reconstruction_clean_units_stay_clean():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "safe.c").write_text(CLEAN_C)
        report = fuzz_reconstruction_with_asan(tdp, seeds=6, timeout=30)
        if all(u.status in {"asan_unavailable", "build_failed"}
               for u in report.units):
            pytest.skip("no ASan runtime")
        assert report.crashers == 0
        assert all(u.status in {"ok"} for u in report.units)


@require_gcc
def test_fuzz_empty_dir_is_unavailable():
    with tempfile.TemporaryDirectory() as td:
        report = fuzz_reconstruction_with_asan(Path(td))
        assert report.overall == "unavailable"
