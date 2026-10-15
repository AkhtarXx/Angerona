from __future__ import annotations

from pathlib import Path

from src.analysis.export import export_analysis
from src.orchestration import batch_spine
from src.orchestration.batch_spine import BatchJobSpec, BatchSpine
from src.solana import fusion as fusion_module
from src.solana.fusion import (
    analyze_solana_with_engines,
    merge_solana_analyses,
)


class FakeEngine:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def analyze(self, binary, **kwargs):
        self.calls.append((binary, kwargs))
        if self.error:
            raise self.error
        return self.result

    @staticmethod
    def status():
        return {"ready": True, "message": "ok"}


def _ida_analysis():
    return {
        "metadata": {
            "engine": "ida",
            "processor": "EBPF",
            "bits": 32,
            "pointer_size": 4,
            "language_id": "EBPF:LE:32",
            "entry_point": "0xffffffffffffffff",
        },
        "functions": [
            {
                "entry": "0x100",
                "name": "sub_100",
                "size": 16,
                "decompiled": None,
                "callers": [],
                "callees": ["0x200"],
            }
        ],
        "strings": [{"address": "0x300", "value": "anchor"}],
        "imports": [{"name": "sol_log_", "library": "extern"}],
        "exports": [],
        "symbols": [{"address": "0x100", "name": "entrypoint", "type": "FUNC"}],
    }


def _ghidra_analysis():
    return {
        "metadata": {
            "engine": "ghidra",
            "processor": "eBPFSol",
            "bits": 64,
            "pointer_size": 8,
            "language_id": "eBPFSol:LE:64:default",
        },
        "functions": [
            {
                "entry": "ram:00000100",
                "name": "entrypoint",
                "size": 16,
                "decompiled": "void entrypoint(void) {}",
                "callers": ["ram:00000080"],
                "callees": [],
            },
            {
                "entry": "0x200",
                "name": "FUN_00000200",
                "size": 8,
                "decompiled": "void FUN_00000200(void) {}",
                "callers": ["0x100"],
                "callees": [],
            },
        ],
        "strings": [
            {"address": 0x300, "value": "anchor"},
            {"address": "0x310", "value": "second"},
        ],
        "imports": [
            {"name": "sol_log_", "library": ""},
            {"name": "sol_memcpy_", "library": ""},
        ],
        "exports": [{"address": "0x100", "name": "entrypoint"}],
        "symbols": [],
    }


def test_merge_prefers_ida_facts_and_fills_decompilation_from_ghidra():
    fused = merge_solana_analyses(
        {"ida": _ida_analysis(), "ghidra": _ghidra_analysis()},
        primary="ida",
    )

    assert fused["metadata"]["engine"] == "solana-fused"
    assert fused["metadata"]["primary_engine"] == "ida"
    assert fused["metadata"]["processor"] == "eBPFSol"
    assert fused["metadata"]["bits"] == 64
    assert fused["metadata"]["pointer_size"] == 8
    assert fused["metadata"]["language_id"] == "eBPFSol:LE:64:default"
    assert fused["metadata"]["source_metadata"]["ida"]["bits"] == 32
    assert fused["metadata"]["source_metadata"]["ghidra"]["bits"] == 64
    assert len(fused["functions"]) == 2
    entrypoint = fused["functions"][0]
    assert entrypoint["name"] == "entrypoint"
    assert entrypoint["decompiled"] == "void entrypoint(void) {}"
    assert entrypoint["_decompiled_source"] == "ghidra"
    assert entrypoint["_decompiler_kind"] == "ghidra_sleigh"
    assert entrypoint["callers"] == ["ram:00000080"]
    assert entrypoint["callees"] == ["0x200"]
    assert entrypoint["_sources"] == ["ida", "ghidra"]
    assert [item["name"] for item in fused["imports"]] == [
        "sol_log_",
        "sol_memcpy_",
    ]
    assert len(fused["strings"]) == 2
    assert "sbf_decompiler_policy" in fused["metadata"]["fusion"]


def test_analysis_is_sequential_and_isolates_secondary_failure():
    ida = FakeEngine(result=_ida_analysis())
    ghidra = FakeEngine(error=RuntimeError("decompiler failed"))

    result = analyze_solana_with_engines(
        "program.so",
        engines={"ida": ida, "ghidra": ghidra},
        primary="ida",
        max_functions=7,
    )

    assert result.primary == "ida"
    assert list(result.analyses) == ["ida"]
    assert result.errors == {"ghidra": "RuntimeError: decompiler failed"}
    assert ida.calls[0][1] == {
        "decompile": False,
        "max_functions": 7,
        "force": False,
    }
    assert ghidra.calls[0][1] == {
        "decompile": True,
        "max_functions": 7,
        "force": False,
    }
    assert result.fused["metadata"]["fusion"]["errors"] == result.errors


def test_analysis_uses_elf_header_as_architecture_truth(solana_elf):
    binary = solana_elf
    result = analyze_solana_with_engines(
        binary,
        engines={
            "ida": FakeEngine(result=_ida_analysis()),
            "ghidra": FakeEngine(result=_ghidra_analysis()),
        },
        primary="ida",
    )

    metadata = result.fused["metadata"]
    assert metadata["elf_class"] == "ELF64"
    assert metadata["elf_machine"] == 0x107
    assert metadata["bits"] == 64
    assert metadata["pointer_size"] == 8
    assert metadata["endianness"] == "little"
    assert metadata["entry_point"] == "0x1000"


def test_analysis_falls_back_when_primary_fails():
    ida = FakeEngine(error=RuntimeError("IDA unavailable"))
    ghidra = FakeEngine(result=_ghidra_analysis())

    result = analyze_solana_with_engines(
        "program.so",
        engines={"ida": ida, "ghidra": ghidra},
        primary="ida",
    )

    assert result.primary == "ghidra"
    assert result.fused["metadata"]["primary_engine"] == "ghidra"
    assert result.summary()["counts"]["decompiled_functions"] == 2


def test_fused_analysis_becomes_the_shared_downstream_export(tmp_path: Path, solana_elf):
    fused = merge_solana_analyses(
        {"ida": _ida_analysis(), "ghidra": _ghidra_analysis()},
        primary="ida",
    )
    binary = solana_elf

    manifest = export_analysis(
        FakeEngine(error=AssertionError("engine must not rerun")),
        str(binary),
        tmp_path,
        analysis_data=fused,
        producer="solana_fusion",
    )

    assert manifest["counts"]["functions"] == 2
    assert manifest["counts"]["decompiled_functions"] == 2
    assert manifest["metadata"]["engine"] == "solana-fused"
    assert (tmp_path / "analysis.json").is_file()
    assert "entrypoint" in (tmp_path / "all_decompiled.c").read_text()


def test_batch_analyze_uses_fusion_for_synthetic_solana_elf(tmp_path: Path, monkeypatch, solana_elf):
    ida_result = _ida_analysis()
    ida_result.update({"_cached": True, "_seconds": 1.25, "_cache": "/cache/ida.json"})
    ghidra_result = _ghidra_analysis()
    ghidra_result.update(
        {"_cached": True, "_seconds": 2.5, "_cache": "/cache/ghidra.json"}
    )
    ida = FakeEngine(result=ida_result)
    ghidra = FakeEngine(result=ghidra_result)
    monkeypatch.setattr(batch_spine, "make_engine", lambda _config: ida)
    monkeypatch.setattr(
        fusion_module,
        "build_solana_engine_map",
        lambda *_args, **_kwargs: {"ida": ida, "ghidra": ghidra},
    )
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", str(empty_path))
    binary = solana_elf

    result = BatchSpine(state_dir=tmp_path / "state").run(
        BatchJobSpec(
            binary=str(binary),
            engine="ida",
            output_dir=str(tmp_path / "runs"),
            stages=["analyze"],
            max_functions=5,
        )
    )

    assert result.return_code == 0
    workspace = Path(result.workspace)
    exported = (workspace / "code" / "analysis.json").read_text()
    assert '"engine": "solana-fused"' in exported
    assert (workspace / "raw" / "solana_ida_analysis.json").is_file()
    assert (workspace / "raw" / "solana_ghidra_analysis.json").is_file()
    assert (workspace / "raw" / "solana_fusion.json").is_file()
    assert (workspace / "raw" / "solana_utilities.json").is_file()
    assert result.artifacts["solana_fusion"].endswith("solana_fusion.json")
    assert result.artifacts["solana_utilities"].endswith("solana_utilities.json")
    assert result.artifacts["solana_ida_cache"] == "/cache/ida.json"
    assert result.artifacts["solana_ghidra_cache"] == "/cache/ghidra.json"
    utility_manifest = (workspace / "raw" / "solana_utilities.json").read_text()
    assert '"utility-radare2"' not in utility_manifest
    assert '"llvm-objdump"' in utility_manifest
    assert '"available": false' in utility_manifest
    stage_metadata = (workspace / "raw" / "engine_analysis_meta.json").read_text()
    assert '"cached": true' in stage_metadata
    assert '"seconds": 3.75' in stage_metadata
