"""Tests for Phase 3 state-of-the-art modules.

Phase 3 covers type library packaging, headless batch automation spine,
C++/RTTI/vtable recovery enrichment, and multi-fidelity execution backend selection.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.models.analysis_graph import AnalysisGraph
from src.models.type_library import (
    FunctionType,
    Parameter,
    StructField,
    StructType,
    TypeLibrary,
)
from src.execution.backend_selector import BackendSelector, ExecutionBackend, EmulatorProbeRequest
from src.execution.enrichment_loop import EnrichmentLoop, MemorySnapshot
from src.orchestration.batch_spine import BatchJobResult, BatchJobSpec, BatchSpine
from src.workspace import RunWorkspace


SAMPLES_DIR = Path(__file__).parent.parent / "samples"
LBUZ = SAMPLES_DIR / "lbuz_program.elf"
CRACKME = SAMPLES_DIR / "crackme"


def _sample_graph() -> AnalysisGraph:
    data = {
        "metadata": {
            "name": "test_sample",
            "executable_format": "ELF",
            "language_id": "x86:LE:64:default",
            "processor": "x86",
            "sha256": "abc",
            "image_base": "0x400000",
            "entry_point": "0x401000",
            "pointer_size": 8,
            "filename": "test_sample",
        },
        "functions": [
            {"name": "main", "entry": "0x401000", "callees": ["strcpy"], "callers": []},
            {"name": "strcpy", "entry": "0x401100", "callees": [], "callers": ["main"]},
        ],
        "strings": [],
        "imports": [],
        "exports": [{"address": "0x401000", "name": "main"}],
        "symbols": [],
    }
    graph = AnalysisGraph()
    graph.from_engine_json(data)
    return graph


def test_type_library_bootstrap_and_lookup():
    lib = TypeLibrary.bootstrap_stdlib("x64")
    ft = lib.lookup_function("strcpy")
    assert ft is not None
    assert ft.return_type == "char*"
    assert any(p.name == "dest" for p in ft.parameters)


def test_type_library_apply_to_graph():
    lib = TypeLibrary.bootstrap_stdlib("x64")
    graph = _sample_graph()
    applied = lib.apply_to_graph(graph)
    assert isinstance(applied, dict)
    strcpy_node = applied.get("function:0x401100")
    assert strcpy_node is not None
    node = graph.get_node("function:0x401100")
    assert node is not None
    assert "signature" in node.properties


def test_analysis_graph_resolves_xref_owner_from_indexed_body_range():
    graph = AnalysisGraph()
    graph.from_engine_json({
        "metadata": {"engine": "fake", "entry_point": "0x1000"},
        "functions": [
            {
                "name": "entrypoint",
                "entry": "0x1000",
                "size": 0x80,
                "body_ranges": [{"start": "0x1000", "size": 0x80}],
                "callees": [],
                "callers": [],
            },
            {
                "name": "target",
                "entry": "0x2000",
                "size": 0x20,
                "callees": [],
                "callers": [],
                "xrefs_to": [{"from": "0x1042", "type": "UNCONDITIONAL_CALL"}],
            },
        ],
        "strings": [],
        "imports": [],
        "exports": [],
        "symbols": [],
    })

    calls = [
        edge for edge in graph.edges
        if edge.kind == "calls" and edge.src == "function:0x1000"
    ]
    assert [edge.dst for edge in calls] == ["function:0x2000"]


def test_type_library_save_load():
    lib = TypeLibrary.bootstrap_stdlib("x64")
    lib.add_struct_type(StructType("MyStruct", 16, [StructField("field1", 0, 8, "uint64_t")]))
    path = Path("/tmp") / "test_type_library.json"
    lib.save_json(path)
    loaded = TypeLibrary()
    loaded.load_json(path)
    assert loaded.lookup_function("memcpy") is not None
    struct = loaded.lookup_struct("MyStruct")
    assert struct is not None
    assert struct.size == 16


def test_backend_selector_elf():
    selector = BackendSelector()
    backend = selector.select(CRACKME, triage_profile={"format": "elf", "has_interpreter": True})
    assert isinstance(backend, ExecutionBackend)
    assert backend.name in ("gdb", "qemu-user")


def test_backend_selector_pe():
    selector = BackendSelector()
    backend = selector.select("samples/malware.exe", triage_profile={"format": "pe"})
    assert backend.name == "bochs_pe"


def test_backend_selector_raw_shellcode():
    selector = BackendSelector()
    backend = selector.select("shellcode.bin", triage_profile={"format": "raw", "function_isolation": True})
    assert backend.name == "bochs_idb"


def test_backend_selector_disabled():
    selector = BackendSelector()
    backend = selector.select("unknown.baz", triage_profile={"format": "unknown", "execution_disabled": False})
    assert backend.name == "none"


def test_emulator_probe_request_validation():
    req = EmulatorProbeRequest("decode_buffer", args=[1, 2], capture_memory_ranges=[("out", 0x1000, 256)])
    assert req.function_name == "decode_buffer"


def test_enrichment_loop_no_selector():
    graph = _sample_graph()
    loop = EnrichmentLoop(selector_or_none=None)
    result = loop.enrich(graph, "function:0x401000")
    assert result.status == "no_backend"


def test_enrichment_loop_success_skeleton():
    graph = _sample_graph()

    class FakeSelector:
        def select(self, binary, triage_profile=None):
            return ExecutionBackend("gdb", "high", "linux", True, True, reason="fake")

        def run(self, probe):
            return MemorySnapshot("0x700000", "AAAA", 4, "fake", "2026-01-01T00:00:00")

    loop = EnrichmentLoop(FakeSelector())
    result = loop.enrich(graph, "main")
    assert result.status == "success"
    assert result.snapshot is not None
    assert result.snapshot.address == "0x700000"
    assert any(chg["op"] == "add_node" and chg["node"] == "segment:0x700000" for chg in result.changes)


def test_batch_spine_smoke(tmp_path):
    spec = BatchJobSpec(
        binary="samples/crackme",
        engine="ghidra",
        max_functions=10,
        force=True,
        output_dir=str(tmp_path),
        stages=["triage"],
    )
    spine = BatchSpine(state_dir=tmp_path / "state", log_level="DEBUG")
    result = spine.run(spec)
    assert result.return_code == 0
    assert any(s["stage"] == "triage" and s["status"] == "ok" for s in result.stage_logs)
    assert (Path(result.workspace) / "raw" / "batch_report.json").exists()


def test_batch_xref_reuses_signature_matches_and_ignores_self_db(tmp_path):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    spine = BatchSpine(state_dir=tmp_path / "state")
    spine._workspace = workspace
    spine._engine_analysis = {
        "metadata": {"engine": "fake", "entry_point": "0x1000"},
        "functions": [
            {"name": "entrypoint", "entry": "0x1000", "size": 16, "callees": ["helper"]},
            {"name": "helper", "entry": "0x1100", "size": 16, "callers": ["entrypoint"]},
        ],
        "imports": [],
        "exports": [{"address": "0x1000", "name": "entrypoint"}],
        "strings": [],
        "symbols": [],
    }
    spine._analysis_graph = AnalysisGraph()
    spine._analysis_graph.from_engine_json(spine._engine_analysis)

    class ExplodingSignatureDB:
        def match_many(self, _functions):
            raise AssertionError("xref stage should reuse cached signature matches")

    spine._signature_db = ExplodingSignatureDB()
    spine._signature_matches = {"helper": {"matched": True, "library": "lib", "name": "helper"}}
    spine._signature_match_source = "external_db"
    artifacts: dict[str, str] = {}
    spine._stage_xref(
        BatchJobSpec(
            binary=str(binary),
            engine="ghidra",
            signature_db=str(tmp_path / "db.json"),
            stages=["xref"],
        ),
        artifacts,
    )
    assert spine._xref_graph is not None
    assert spine._xref_graph.is_library("function:0x1100")

    spine._signature_matches = {"entrypoint": {"matched": True, "library": "target", "name": "entrypoint"}}
    spine._signature_match_source = "target_self"
    spine._stage_xref(
        BatchJobSpec(binary=str(binary), engine="ghidra", stages=["xref"]),
        {},
    )
    assert spine._xref_graph is not None
    assert not spine._xref_graph.is_library("function:0x1000")


def test_cli_backend_select():
    result = subprocess.run(
        [sys.executable, "-m", "src.cli", "backend-select", str(CRACKME)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["backend"] in ("gdb", "qemu-user")


def test_full_re_auto_prefers_ida_and_falls_back_to_ghidra(
    tmp_path,
    monkeypatch,
    capsys,
):
    import src.cli as cli

    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    calls = []

    monkeypatch.setattr(
        "src.engines.selector.select_engine",
        lambda binary, default="ida": ("ida", "IDA preferred for supported target"),
    )
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda engine: SimpleNamespace(state_dir=tmp_path / "state" / engine),
    )

    def fake_run(_self, spec):
        calls.append(spec.engine)
        workspace = tmp_path / f"run-{spec.engine}"
        (workspace / "raw").mkdir(parents=True, exist_ok=True)
        if spec.engine == "ida":
            return BatchJobResult(
                workspace=str(workspace),
                return_code=1,
                duration_seconds=0.1,
                stage_logs=[{
                    "stage": "analyze",
                    "status": "error",
                    "error": "unsupported input file",
                }],
                summary={"engine": "ida"},
                artifacts={},
            )
        return BatchJobResult(
            workspace=str(workspace),
            return_code=0,
            duration_seconds=0.2,
            stage_logs=[{"stage": "analyze", "status": "ok"}],
            summary={"engine": "ghidra"},
            artifacts={},
        )

    monkeypatch.setattr(BatchSpine, "run", fake_run)
    ns = SimpleNamespace(
        binary=str(target),
        engine=None,
        max_functions=0,
        force=False,
        sandbox=False,
        signature_db=None,
        type_library=None,
        output_dir=None,
        stages=None,
        log_level="INFO",
        json=True,
    )

    assert cli._cmd_sota_batch(ns) == 0
    out = json.loads(capsys.readouterr().out)
    assert calls == ["ida", "ghidra"]
    assert out["engine_selection"]["mode"] == "auto"
    assert out["engine_selection"]["preferred_engine"] == "ida"
    assert out["engine_selection"]["fallback_used"] is True
    assert out["engine_selection"]["final_engine"] == "ghidra"
    assert Path(out["artifacts"]["engine_selection"]).exists()


def test_full_re_explicit_engine_disables_fallback(
    tmp_path,
    monkeypatch,
    capsys,
):
    import src.cli as cli

    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    calls = []
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda engine: SimpleNamespace(state_dir=tmp_path / "state" / engine),
    )

    def fake_run(_self, spec):
        calls.append(spec.engine)
        workspace = tmp_path / f"run-{spec.engine}"
        (workspace / "raw").mkdir(parents=True, exist_ok=True)
        return BatchJobResult(
            workspace=str(workspace),
            return_code=1,
            duration_seconds=0.1,
            stage_logs=[{
                "stage": "analyze",
                "status": "error",
                "error": "loader error",
            }],
            summary={"engine": spec.engine},
            artifacts={},
        )

    monkeypatch.setattr(BatchSpine, "run", fake_run)
    ns = SimpleNamespace(
        binary=str(target),
        engine="ida",
        max_functions=0,
        force=False,
        sandbox=False,
        signature_db=None,
        type_library=None,
        output_dir=None,
        stages=None,
        log_level="INFO",
        json=True,
    )

    assert cli._cmd_sota_batch(ns) == 1
    out = json.loads(capsys.readouterr().out)
    assert calls == ["ida"]
    assert out["engine_selection"]["mode"] == "explicit"
    assert out["engine_selection"]["fallback_used"] is False


def test_full_re_parser_defaults_to_automatic_routing():
    from src.cli import _cmd_full_re, build_parser

    ns = build_parser().parse_args(["full-re", "sample.bin"])
    assert ns.engine is None
    assert ns.max_functions == 0
    assert ns.no_ai is False
    assert ns.func is _cmd_full_re


def test_full_re_parser_accepts_resume_workspace():
    from src.cli import build_parser

    ns = build_parser().parse_args(["full-re", "sample.bin", "--resume-workspace", "/tmp/old-run"])
    assert ns.resume_workspace == "/tmp/old-run"
    assert ns.func.__name__ == "_cmd_full_re"


def test_full_re_resume_workspace_uses_existing_workspace(monkeypatch, tmp_path):
    import src.cli as cli

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF")
    ws = tmp_path / "old_run"
    (ws / "code").mkdir(parents=True)
    (ws / "raw").mkdir(parents=True)
    (ws / "run.json").write_text(json.dumps({"binary": str(binary)}), encoding="utf-8")
    (ws / "code" / "all_decompiled.c").write_text("int main() {}", encoding="utf-8")
    (ws / "raw" / "analysis_graph.json").write_text("{\"nodes\":[]}", encoding="utf-8")
    (ws / "raw" / "security_slices.json").write_text("{}", encoding="utf-8")

    calls = {}

    def fake_run_sota_batch(_):
        calls["batch"] = True
        return SimpleNamespace(
            workspace=str(ws),
            return_code=0,
            duration_seconds=0.0,
            stage_logs=[],
            summary={},
            artifacts={},
        ), {"final_engine": "ida", "mode": "manual", "reason": "should-not-run"}

    class FakeOrchestrator:
        def __init__(self, cfg):
            pass

        def swarm_run(self, *_args, **kwargs):
            calls["swarm"] = str(kwargs["workspace"].root) if "workspace" in kwargs else ""
            return SimpleNamespace(converged=True)

    monkeypatch.setattr(cli, "_run_sota_batch", fake_run_sota_batch)
    monkeypatch.setattr("src.agents.orchestrator.Orchestrator", FakeOrchestrator)

    ns = cli.build_parser().parse_args([
        "full-re",
        str(binary),
        "--resume-workspace", str(ws),
        "--agent", "claude",
    ])
    assert cli._cmd_full_re(ns) == 0
    assert calls.get("batch") is None
    assert calls.get("swarm") == str(ws)


def test_full_re_no_ai_uses_batch_only(monkeypatch):
    import src.cli as cli

    calls = []

    class Result:
        workspace = "/tmp/ws"
        return_code = 0
        duration_seconds = 0.1
        stage_logs = []
        summary = {}
        artifacts = {}

    def fake_run(ns):
        calls.append("batch")
        return Result(), {"final_engine": "ghidra", "mode": "auto"}

    def fake_print(ns, result, routing):
        calls.append("print")
        return 7

    monkeypatch.setattr(cli, "_run_sota_batch", fake_run)
    monkeypatch.setattr(cli, "_print_sota_batch_result", fake_print)
    ns = cli.build_parser().parse_args(["full-re", "sample.bin", "--no-ai"])
    assert cli._cmd_full_re(ns) == 7
    assert calls == ["batch", "print"]


@pytest.mark.skipif(not LBUZ.exists(), reason="lbuz sample not present")
def test_cli_sota_batch_on_real_binary(tmp_path):
    cmd = [
        sys.executable, "-m", "src.cli", "sota-batch", str(LBUZ),
        "--engine", "ghidra", "--max-functions", "20", "--force",
        "--output-dir", str(tmp_path), "--json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stderr
    assert "workspace" in result.stdout
    stdout = result.stdout
    start = stdout.find("{")
    end = stdout.rfind("}")
    out = json.loads(stdout[start:end + 1]) if start != -1 and end > start else {}
    assert out.get("return_code") == 0
    artifacts = out.get("artifacts", {})
    assert artifacts.get("batch_report")
    assert artifacts.get("triage")
    assert artifacts.get("analysis_graph")
    assert artifacts.get("xref_graph")
    assert artifacts.get("sinks")
    assert Path(artifacts["batch_report"]).exists()


def test_cli_full_re_no_ai_on_tiny_real_binary(tmp_path):
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available to build tiny smoke binary")
    if shutil.which("analyzeHeadless") is None and not os.environ.get("GHIDRA_HOME"):
        pytest.skip("Ghidra headless runtime not available for real smoke")

    source = tmp_path / "tiny_vuln.c"
    binary = tmp_path / "tiny_vuln"
    source.write_text(
        "#include <string.h>\n"
        "int main(int argc, char **argv) {\n"
        "  char buf[8] = {0};\n"
        "  if (argc > 1) strcpy(buf, argv[1]);\n"
        "  return buf[0];\n"
        "}\n",
        encoding="utf-8",
    )
    compile_cmd = [
        "gcc", "-O0", "-g0", "-fno-stack-protector", "-no-pie",
        str(source), "-o", str(binary),
    ]
    compiled = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stderr

    cmd = [
        sys.executable, "-m", "src.cli", "full-re", str(binary),
        "--no-ai", "--engine", "ghidra", "--max-functions", "10", "--force",
        "--output-dir", str(tmp_path / "runs"), "--json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    start = result.stdout.find("{")
    end = result.stdout.rfind("}")
    out = json.loads(result.stdout[start:end + 1]) if start != -1 and end > start else {}
    assert out.get("return_code") == 0
    artifacts = out.get("artifacts", {})
    assert artifacts.get("code_export")
    assert artifacts.get("evidence_ledger")
    assert artifacts.get("security_slices")
    assert Path(artifacts["evidence_ledger"]).exists()
