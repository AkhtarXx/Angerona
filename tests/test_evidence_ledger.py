from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from src.analysis.export import export_analysis
from src.orchestration import batch_spine
from src.orchestration.batch_spine import BatchJobSpec, BatchSpine


class FakeEngine:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def status(self) -> dict:
        return {"ready": True, "message": "fake ready"}

    def analyze(self, binary, decompile=True, max_functions=0, force=False):
        self.calls.append({
            "binary": str(binary),
            "decompile": decompile,
            "max_functions": max_functions,
            "force": force,
        })
        return {
            "metadata": {
                "engine": "fake-engine",
                "sha256": "not-authoritative",
                "filename": Path(binary).name,
            },
            "functions": [
                {
                    "name": "main",
                    "entry": "0x401000",
                    "size": 32,
                    "signature": "int main(void)",
                    "decompiled": "int main(void) { return helper(); }",
                    "callers": [],
                    "callees": ["helper"],
                },
                {
                    "name": "helper",
                    "entry": "0x401020",
                    "size": 16,
                    "signature": "int helper(void)",
                    "decompiled": "",
                    "callers": ["main"],
                    "callees": [],
                },
            ],
            "strings": [{"address": "0x402000", "value": "hello"}],
            "imports": [{"library": "libc", "name": "puts"}],
            "exports": [{"address": "0x401000", "name": "main"}],
            "symbols": [{"address": "0x401000", "type": "FUNC", "name": "main"}],
        }


def test_export_writes_content_addressed_evidence_ledger(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF fake")
    dest = tmp_path / "code"

    manifest = export_analysis(FakeEngine(), str(binary), dest, producer="unit-test")

    ledger_path = dest / "EVIDENCE_LEDGER.json"
    assert ledger_path.is_file()
    ledger = json.loads(ledger_path.read_text())
    assert ledger["schema_version"] == 1
    assert ledger["model"] == "raw_truth_plus_reconstruction"
    assert ledger["producer"] == "unit-test"
    assert ledger["binary"]["path"] == str(binary)
    assert len(ledger["binary"]["sha256"]) == 64
    assert ledger["manifest"]["status"] == manifest["status"]
    assert ledger["artifact_count"] == len(ledger["artifacts"])
    assert ledger["file_count"] == len(ledger["artifacts"])

    by_path = {artifact["path"]: artifact for artifact in ledger["artifacts"]}
    assert "CALL_SUMMARY.json" in by_path
    assert by_path["analysis.json"]["role"] == "raw_engine_analysis"
    assert by_path["all_decompiled.c"]["role"] == "combined_decompiled_source"
    assert by_path["decompiled/main_0x401000.c"]["role"] == "function_decompiled_source"
    assert "EVIDENCE_LEDGER.json" not in by_path
    assert len(by_path["analysis.json"]["sha256"]) == 64

    targets = {target["name"]: target for target in ledger["reconstruction_targets"]}
    assert targets["main"]["state"] == "raw_decompiled"
    assert targets["main"]["decompiled_path"] == "decompiled/main_0x401000.c"
    assert targets["main"]["verification"] == "not_started"
    assert targets["helper"]["state"] == "needs_lift"
    assert targets["helper"]["decompiled_path"] is None

    rerun_manifest = export_analysis(FakeEngine(), str(binary), dest, producer="unit-test")
    assert "EVIDENCE_LEDGER.json" not in rerun_manifest["files"]


def test_export_writes_authoritative_call_summary(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF fake")
    dest = tmp_path / "code"
    export_analysis(FakeEngine(), str(binary), dest, producer="unit-test")
    summary = json.loads((dest / "CALL_SUMMARY.json").read_text())
    assert summary["model"] == "authoritative_engine_call_summary"
    assert summary["function_count"] == 2
    main = next(row for row in summary["functions"] if row["name"] == "main")
    assert main["callee_count"] == 1
    assert main["callees"] == ["helper"]


def test_batch_analyze_exports_code_tree_and_ledger(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    engine = FakeEngine()

    monkeypatch.setattr(
        batch_spine,
        "load_config",
        lambda engine=None: SimpleNamespace(engine=engine, sandbox=False),
    )
    monkeypatch.setattr(batch_spine, "make_engine", lambda _config: engine)

    spine = BatchSpine(state_dir=tmp_path / "state")
    result = spine.run(BatchJobSpec(
        binary=str(binary),
        engine="ghidra",
        output_dir=str(tmp_path / "runs"),
        stages=["analyze"],
        max_functions=25,
    ))

    assert result.return_code == 0
    assert len(engine.calls) == 1
    assert engine.calls[0]["max_functions"] == 25
    workspace = Path(result.workspace)
    assert (workspace / "code" / "analysis.json").is_file()
    assert (workspace / "code" / "decompiled" / "main_0x401000.c").is_file()
    assert (workspace / "code" / "EXPORT_MANIFEST.json").is_file()
    assert (workspace / "code" / "EVIDENCE_LEDGER.json").is_file()
    assert result.artifacts["code_export"] == str(workspace / "code")
    assert result.artifacts["evidence_ledger"] == str(workspace / "code" / "EVIDENCE_LEDGER.json")

    ledger = json.loads((workspace / "code" / "EVIDENCE_LEDGER.json").read_text())
    assert ledger["producer"] == "ghidra_batch_analyze"
    assert ledger["security_graph_seed"]["candidate_state"] == "not_started"
