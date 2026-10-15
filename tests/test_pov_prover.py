"""PoV prover (angr) — real concolic confirmation behavior.

Two layers of tests:
* Unit tests for the sink-address parser + synthetic-region gate (always run).
* A guarded integration test that compiles a tiny vulnerable ELF and confirms angr
  reaches the sink. Skips when gcc or the repo venv's angr is unavailable.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from src.analysis.pov_oracle import (
    _angr_python,
    _parse_sink_address,
    confirm_with_angr,
)


# ---------------------------------------------------------------------------
# unit: sink-address parsing


def test_parse_sink_address_accepts_hex() -> None:
    assert _parse_sink_address("0x401156") == 0x401156
    assert _parse_sink_address("401156") == 0x401156


def test_parse_sink_address_engine_name_styles() -> None:
    assert _parse_sink_address("sub_401156") == 0x401156
    assert _parse_sink_address("FUN_00401156") == 0x401156


def test_parse_sink_address_rejects_non_addresses() -> None:
    assert _parse_sink_address("not_an_addr") is None
    assert _parse_sink_address("") is None
    assert _parse_sink_address("handle_request") is None


# ---------------------------------------------------------------------------
# unit: honest failure for non-address sinks


def test_non_address_sink_never_confirms() -> None:
    res = confirm_with_angr("/nonexistent", "handle_request", "overflow", timeout=5)
    assert res.confirmed is False
    assert res.detail


# ---------------------------------------------------------------------------
# integration: compile + confirm with real angr


_GCC = shutil.which("gcc")


def _compile_vulnerable(tmp_path: Path) -> tuple[Path, int]:
    src = tmp_path / "vuln.c"
    src.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "char g_buf[16];\n"
        "void process(void) {\n"
        "    char buf[16];\n"
        "    fgets(buf, 4096, stdin);\n"
        "    strcpy(g_buf, buf);\n"
        "}\n"
        "int main(void) { process(); return 0; }\n"
    )
    binary = tmp_path / "vuln"
    subprocess.run(
        [_GCC, "-O0", "-fno-stack-protector", "-no-pie", str(src), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    nm = subprocess.run(["nm", str(binary)], check=True, capture_output=True, text=True).stdout
    sink_addr = next(
        int(line.split()[0], 16)
        for line in nm.splitlines()
        if line.strip().endswith(" process")
    )
    return binary, sink_addr


@pytest.mark.skipif(_GCC is None, reason="gcc not installed")
def test_angr_confirms_real_vulnerable_sink(tmp_path: Path) -> None:
    if _angr_python() is None:
        pytest.skip("angr is not importable from any known interpreter")
    binary, sink_addr = _compile_vulnerable(tmp_path)
    res = confirm_with_angr(binary, hex(sink_addr), "stack_buffer_overflow", timeout=120)
    assert res.confirmed is True
    assert res.engine == "angr"
    assert "reached sink" in res.detail


@pytest.mark.skipif(_GCC is None, reason="gcc not installed")
def test_angr_rejects_synthetic_region_sink(tmp_path: Path) -> None:
    if _angr_python() is None:
        pytest.skip("angr is not importable from any known interpreter")
    binary, sink_addr = _compile_vulnerable(tmp_path)
    res = confirm_with_angr(binary, "0x500000", "overflow", timeout=30)
    assert res.confirmed is False
    assert "synthetic" in res.detail.lower() or "unreachable" in res.detail.lower() or "no structured result" in res.detail
