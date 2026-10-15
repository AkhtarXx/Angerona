from __future__ import annotations

from pathlib import Path

import pytest

from src.config import load_config
from src.solana.adapters import (
    collect_solana_adapter_status,
    probe_solana_adapter_runtime,
)


SAMPLE = Path("samples/lbuz_program.elf")


def test_ida_timeout_output_normalizes_subprocess_bytes():
    from src.engines.ida import _timeout_text

    assert _timeout_text(b"partial\xff") == "partial\ufffd"
    assert _timeout_text("text") == "text"
    assert _timeout_text(None) == ""


@pytest.mark.skipif(not SAMPLE.is_file(), reason="real Solana sample not present")
def test_ghidra_solana_adapter_real_probe_passes():
    cfg = load_config("ghidra")
    ready, reason = cfg.ghidra_ready()
    if not ready:
        pytest.skip(reason)

    result = probe_solana_adapter_runtime(
        cfg,
        SAMPLE,
        engines=("ghidra",),
        max_functions=5,
        timeout=300,
    )[0]

    assert result.engine == "ghidra"
    assert result.installed
    assert result.available, result.reason
    assert "runtime probe passed" in result.reason


@pytest.mark.skipif(not SAMPLE.is_file(), reason="real Solana sample not present")
def test_ida_solana_adapter_real_probe_passes_when_loader_available():
    cfg = load_config("ida")
    ready, reason = cfg.ida_ready()
    if not ready:
        pytest.skip(reason)

    static = {
        status.name: status for status in collect_solana_adapter_status(cfg)
    }["ida-solana-processor"]
    if not static.installed:
        pytest.skip("IDA Solana processor files not installed")

    probed = probe_solana_adapter_runtime(
        cfg,
        SAMPLE,
        engines=("ida",),
        max_functions=5,
        timeout=120,
    )[0]

    assert probed.engine == "ida"
    assert probed.installed
    assert probed.available, probed.reason
    assert "runtime probe passed" in probed.reason


@pytest.mark.skipif(not SAMPLE.is_file(), reason="real Solana sample not present")
def test_ida_engine_uses_solana_loader_and_exports_syscall_imports():
    cfg = load_config("ida")
    ready, reason = cfg.ida_ready()
    if not ready:
        pytest.skip(reason)
    static = {
        status.name: status for status in collect_solana_adapter_status(cfg)
    }["ida-solana-processor"]
    if not static.available:
        pytest.skip(static.reason)

    from src.engines.ida import IdaEngine

    data = IdaEngine(cfg).analyze(
        SAMPLE,
        decompile=False,
        force=True,
        timeout=120,
    )

    assert data.get("_route") == "ida-idat-solana-loader"
    assert data.get("metadata", {}).get("processor") == "EBPF"
    assert data.get("metadata", {}).get("executable_format") == "Solana SBF/eBPF ELF"
    assert len(data.get("functions") or []) > 100
    imports = {entry.get("name") for entry in data.get("imports") or []}
    assert "sol_log_" in imports
    assert "sol_invoke_signed_rust" in imports
