from __future__ import annotations

import json
from pathlib import Path

from src.solana.utilities import collect_solana_utility_evidence


def _fake_tool(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def test_solana_utilities_capture_outputs_without_required_tools(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    binary = tmp_path / "program.so"
    binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

    manifest = collect_solana_utility_evidence(binary, tmp_path / "out", timeout=1)

    assert manifest["model"] == "solana_utility_evidence"
    assert manifest["utilities"]["llvm-objdump"]["available"] is False
    assert manifest["utilities"]["radare2"]["available"] is False
    assert (tmp_path / "out" / "manifest.json").is_file()


def test_solana_utilities_run_available_local_tools_to_files(tmp_path: Path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _fake_tool(bin_dir / "llvm-objdump", "echo llvm-disasm:$3\n")
    _fake_tool(bin_dir / "r2", "echo '{\"bin\":\"r2\"}'\n")
    _fake_tool(bin_dir / "anchor", "echo anchor 0.30.0\n")
    _fake_tool(bin_dir / "solana", "echo solana-cli 1.18.0\n")
    monkeypatch.setenv("PATH", str(bin_dir))
    binary = tmp_path / "program.so"
    binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

    manifest = collect_solana_utility_evidence(binary, tmp_path / "out", timeout=2)

    assert manifest["utilities"]["llvm-objdump"]["available"] is True
    assert manifest["utilities"]["radare2"]["available"] is True
    assert manifest["utilities"]["anchor-cli"]["stdout_tail"].startswith("anchor")
    assert manifest["utilities"]["solana-cli"]["stdout_tail"].startswith("solana-cli")
    llvm_stdout = Path(manifest["utilities"]["llvm-objdump"]["stdout_path"])
    assert llvm_stdout.is_file()
    saved = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert saved["policy"] == manifest["policy"]
