"""Tests for P2 (engine routing, PoV oracle, local model) and P3 (cost) pillars."""
from __future__ import annotations

import struct
import tempfile
from pathlib import Path

from src.engines.selector import select_engine, _elf_machine
from src.analysis.pov_oracle import confirm_vulnerability, PoVResult
from src.analysis.cost import estimate_tokens, compute_cost, estimate_code_dir
from src.config import local_model_config


def _write_elf(path: Path, machine: int):
    # Minimal ELF header: magic + class + data + pad + e_type(2) + e_machine(2)
    buf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    buf += struct.pack("<H", 0x0002)      # e_type = EXEC
    buf += struct.pack("<H", machine)     # e_machine
    buf += b"\x00" * 40
    path.write_bytes(bytes(buf))


def test_selector_btf_magic_is_not_treated_as_ebpf(tmp_path: Path):
    b = tmp_path / "prog.so"
    _write_elf(b, 0xEB9F)
    engine, reason = select_engine(b, default="ida")
    assert engine == "ghidra"
    assert "unknown_arch_0xEB9F" in reason
    assert "eBPF" not in reason
    assert "Solana" not in reason


def test_selector_solana_sbf_keeps_ida_when_loader_available(tmp_path: Path):
    b = tmp_path / "prog.so"
    _write_elf(b, 0x0107)  # Solana SBF
    engine, reason = select_engine(
        b,
        default="ida",
        ida_solana_available=True,
    )
    assert engine == "ida"
    assert "SBF loader" in reason


def test_selector_generic_ebpf_routes_ghidra_without_ida_loader(tmp_path: Path):
    b = tmp_path / "prog.so"
    _write_elf(b, 0x00F7)  # generic eBPF
    engine, reason = select_engine(
        b,
        default="ida",
        ida_solana_available=False,
    )
    assert engine == "ghidra"
    assert "unavailable" in reason


def test_selector_x86_keeps_ida(tmp_path: Path):
    b = tmp_path / "prog"
    _write_elf(b, 0x3E)  # x86-64
    engine, _ = select_engine(b, default="ida")
    assert engine == "ida"


def test_selector_arm_keeps_ida(tmp_path: Path):
    b = tmp_path / "prog"
    _write_elf(b, 0xB7)  # ARM64
    engine, _ = select_engine(b, default="ida")
    assert engine == "ida"


def test_selector_non_elf_default(tmp_path: Path):
    b = tmp_path / "prog.exe"
    b.write_bytes(b"MZ" + b"\x00" * 100)
    engine, _ = select_engine(b, default="ida")
    assert engine == "ida"


def test_pov_oracle_graceful_no_tools():
    # No angr/AFL++ in CI -> returns not confirmed, never raises.
    res = confirm_vulnerability("/nonexistent", "sub_0", "buffer_overflow")
    assert isinstance(res, PoVResult)
    assert res.engine in ("none", "angr", "aflpp")


def test_cost_estimate_basic():
    n = estimate_tokens("int main() { return 0; }")
    assert n >= 1


def test_cost_compute_with_cache():
    rep = compute_cost("haiku", input_tokens=1_000_000, output_tokens=100_000,
                        cached_fraction=0.8)
    assert rep.savings_pct > 0
    assert rep.est_usd_with_cache < rep.est_usd


def test_cost_code_dir(tmp_path: Path):
    (tmp_path / "a.c").write_text("int x; " * 1000)
    t = estimate_code_dir(tmp_path)
    assert t > 0


def test_local_model_off_by_default():
    import os
    os.environ.pop("ANGERONA_LOCAL_MODEL", None)
    assert local_model_config() is None


def test_local_model_on():
    import os
    os.environ["ANGERONA_LOCAL_MODEL"] = "1"
    cfg = local_model_config()
    assert cfg is not None
    assert "base_url" in cfg and "model" in cfg
    os.environ.pop("ANGERONA_LOCAL_MODEL", None)
