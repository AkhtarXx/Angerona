from __future__ import annotations

import struct
from pathlib import Path

from src.config import load_config
from src.solana.adapters import (
    collect_solana_adapter_status,
    ghidra_solana_language,
    is_solana_elf,
    preferred_solana_adapters,
)


def _write_elf(path: Path, machine: int) -> None:
    buf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    buf += struct.pack("<H", 0x0002)
    buf += struct.pack("<H", machine)
    buf += b"\x00" * 40
    path.write_bytes(bytes(buf))


def test_is_solana_elf_accepts_current_sbf_machine(tmp_path: Path):
    binary = tmp_path / "prog.so"
    _write_elf(binary, 0x0107)
    assert is_solana_elf(binary)


def test_is_solana_elf_accepts_generic_ebpf_machine(tmp_path: Path):
    binary = tmp_path / "prog.so"
    _write_elf(binary, 0x00F7)
    assert is_solana_elf(binary)


def test_is_solana_elf_rejects_btf_magic_as_machine(tmp_path: Path):
    binary = tmp_path / "prog.so"
    _write_elf(binary, 0xEB9F)
    assert not is_solana_elf(binary)


def test_is_solana_elf_rejects_x86_64(tmp_path: Path):
    binary = tmp_path / "prog"
    _write_elf(binary, 0x003E)
    assert not is_solana_elf(binary)


def test_detects_solana_adapter_paths_from_env(tmp_path: Path, monkeypatch):
    ghidra_ext = tmp_path / "ghidra_solana"
    ghidra_lang = ghidra_ext / "data" / "languages"
    ghidra_lang.mkdir(parents=True)
    (ghidra_lang / "eBPFSol.ldefs").write_text("<language_definitions/>")

    ida_procs = tmp_path / "ida" / "procs"
    (ida_procs / "solana").mkdir(parents=True)
    (ida_procs / "solana-init.py").write_text("# init")
    (ida_procs / "solana" / "processor.py").write_text("# processor")

    binja_plugin = tmp_path / "bn-ebpf-solana"
    binja_plugin.mkdir()
    (binja_plugin / "solanaview.py").write_text("# view")
    (binja_plugin / "types.c").write_text("typedef int x;")

    monkeypatch.setenv("ANGERONA_GHIDRA_SOLANA_EXTENSION", str(ghidra_ext))
    monkeypatch.setenv("ANGERONA_IDA_SOLANA_PROCESSOR", str(ida_procs))
    monkeypatch.setenv("ANGERONA_BINJA_SOLANA_PLUGIN", str(binja_plugin))

    cfg = load_config("ghidra")
    statuses = {s.name: s for s in collect_solana_adapter_status(cfg)}

    assert statuses["ghidra-solana-ebpf"].available
    assert statuses["ida-solana-processor"].installed
    ida_ready, _ = cfg.ida_ready()
    ida_loader = cfg.ida_install / "loaders" / "solana_sbf.py" if cfg.ida_install else None
    assert statuses["ida-solana-processor"].available is bool(
        ida_ready and cfg.idat and ida_loader and ida_loader.is_file()
    )
    assert statuses["binja-solana-ebpf"].available
    assert statuses["utility-radare2"].engine == "utility"
    assert statuses["utility-llvm-objdump"].engine == "utility"
    assert statuses["utility-anchor-cli"].engine == "utility"
    assert statuses["utility-solana-cli"].engine == "utility"


def test_prefers_solana_specific_ghidra_language(tmp_path: Path, monkeypatch):
    extension = tmp_path / "Solana-eBPF-for-Ghidra"
    language_dir = extension / "data" / "languages"
    language_dir.mkdir(parents=True)
    (language_dir / "eBPFSol.ldefs").write_text("<language_definitions/>")
    monkeypatch.setenv("ANGERONA_GHIDRA_SOLANA_EXTENSION", str(extension))

    assert ghidra_solana_language(load_config("ghidra")) == "eBPFSol:LE:64:default"


def test_preferred_adapters_prioritize_runtime_available_ida(tmp_path: Path, monkeypatch):
    ghidra_ext = tmp_path / "ghidra_solana"
    ghidra_ext.mkdir()
    (ghidra_ext / "eBPFSol.ldefs").write_text("<language_definitions/>")

    ida_procs = tmp_path / "ida" / "procs"
    (ida_procs / "solana").mkdir(parents=True)
    (ida_procs / "solana-init.py").write_text("# init")
    (ida_procs / "solana" / "processor.py").write_text("# processor")

    monkeypatch.setenv("ANGERONA_GHIDRA_SOLANA_EXTENSION", str(ghidra_ext))
    monkeypatch.setenv("ANGERONA_IDA_SOLANA_PROCESSOR", str(ida_procs))

    cfg = load_config("ida")
    ordered = preferred_solana_adapters(cfg, engine="ida")

    ida = next(s for s in ordered if s.name == "ida-solana-processor")
    assert ida.installed
    if ida.available:
        assert ordered[0].name == "ida-solana-processor"
    else:
        assert ordered[0].name == "ghidra-solana-ebpf"
        assert ordered[0].available


def test_detects_solana_utility_clis_from_path(tmp_path: Path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("r2", "llvm-objdump", "anchor", "solana"):
        tool = bin_dir / name
        tool.write_text("#!/bin/sh\nprintf '%s test-version\\n' \"$0\"\n")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    statuses = {s.name: s for s in collect_solana_adapter_status(load_config("ghidra"))}

    assert statuses["utility-radare2"].available
    assert statuses["utility-radare2"].path == str(bin_dir / "r2")
    assert statuses["utility-llvm-objdump"].available
    assert statuses["utility-anchor-cli"].available
    assert statuses["utility-solana-cli"].available
