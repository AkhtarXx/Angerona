"""Phase 8 behavior tests: structured decompiler pseudocode / function summaries."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from src.models.analysis_graph import AnalysisGraph, Edge, Node
from src.summary.function_summarizer import FunctionSummarizer
from src.summary.models import SummaryReport
from src.summary.pseudocode_generator import PseudocodeGenerator


CLI = [sys.executable, "-m", "src"]


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*CLI, *args],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )


def _sample_graph(binary_path: str = "fake.exe") -> AnalysisGraph:
    graph = AnalysisGraph()
    p = Node(id="program:sample", kind="program", address="0x400000", name="sample")
    f = Node(id="function:0x401000", kind="function", address="0x401000",
             name="main", properties={"binary": binary_path, "signature": "int main(int argc, char **argv)"})
    b1 = Node(id="block:0x401000", kind="block", address="0x401000")
    i1 = Node(id="instruction:0x401000", kind="instruction", address="0x401000",
              properties={"mnemonic": "cmp", "text": "cmp argc, 1"})
    i2 = Node(id="instruction:0x401010", kind="instruction", address="0x401010",
              properties={"mnemonic": "call", "text": "call puts"})
    s = Node(id="string:0x402000", kind="string", address="0x402000", name="hello world")
    imp = Node(id="import:puts", kind="import", name="puts")
    graph.add_node(p)
    graph.add_node(f)
    graph.add_node(b1)
    graph.add_node(i1)
    graph.add_node(i2)
    graph.add_node(s)
    graph.add_node(imp)
    graph.add_edge(Edge(src="program:sample", dst="function:0x401000", kind="contains"))
    graph.add_edge(Edge(src="function:0x401000", dst="block:0x401000", kind="contains"))
    graph.add_edge(Edge(src="block:0x401000", dst="instruction:0x401000", kind="contains"))
    graph.add_edge(Edge(src="block:0x401000", dst="instruction:0x401010", kind="contains"))
    graph.add_edge(Edge(src="instruction:0x401010", dst="import:puts", kind="calls"))
    graph.add_edge(Edge(src="instruction:0x401010", dst="string:0x402000", kind="data_read"))
    return graph


# ------------------------------------------------------------------ generator tests


def test_pseudocode_generator_empty_graph() -> None:
    gen = PseudocodeGenerator(AnalysisGraph())
    out = gen.generate("function:0x0")
    assert out.pseudocode
    assert any("not found" in line.text for line in out.pseudocode)


def test_pseudocode_generator_simple_function() -> None:
    graph = _sample_graph()
    gen = PseudocodeGenerator(graph)
    out = gen.generate("main")
    assert out.name == "main"
    assert out.signature == "int main(int argc, char **argv)"
    text_lines = [line.text for line in out.pseudocode]
    assert any("call puts" in line for line in text_lines)
    assert "puts" in out.calls
    assert "hello world" in out.strings


def test_pseudocode_generator_all_functions() -> None:
    graph = _sample_graph()
    gen = PseudocodeGenerator(graph)
    all_fns = gen.generate_all()
    assert "function:0x401000" in all_fns


# ------------------------------------------------------------------ summarizer tests


def test_function_summarizer_strings_and_calls() -> None:
    graph = _sample_graph()
    summarizer = FunctionSummarizer(graph)
    summary = summarizer.summarize("main")
    assert "puts" in summary.purpose or "hello world" in summary.purpose
    assert summary.io_summary
    assert summary.confidence in {"low", "medium", "high"}


def test_function_summarizer_risk_flags() -> None:
    graph = _sample_graph()
    summarizer = FunctionSummarizer(graph)
    summaries = summarizer.summarize_all()
    assert summaries
    for sm in summaries:
        assert sm.confidence


# ------------------------------------------------------------------ report tests


def test_summary_report_write_json() -> None:
    report = SummaryReport(workspace="/tmp/test")
    report.functions.append(PseudocodeGenerator(_sample_graph()).generate("main"))
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "report.json"
        report.write_json(path)
        data = json.loads(path.read_text())
    assert data["workspace"] == "/tmp/test"
    assert len(data["functions"]) == 1


# ------------------------------------------------------------------ CLI tests


def _make_workspace() -> Path:
    td = tempfile.mkdtemp()
    ws = Path(td) / "ws"
    ws.mkdir()
    raw = ws / "raw"
    raw.mkdir()
    graph = _sample_graph()
    (raw / "analysis_graph.json").write_text(json.dumps(graph.to_json(), indent=2))
    return ws


def test_cli_pseudocode_writes_file() -> None:
    ws = _make_workspace()
    try:
        cp = _run_cli("pseudocode", "--json", str(ws))
        assert cp.returncode == 0, cp.stderr
        out_path = ws / "raw" / "pseudocode.json"
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert len(data["functions"]) >= 1
        assert data["functions"][0]["pseudocode"]
    finally:
        import shutil
        shutil.rmtree(ws.parent, ignore_errors=True)


def test_cli_function_summary_json() -> None:
    ws = _make_workspace()
    try:
        cp = _run_cli("function-summary", "--json", str(ws))
        assert cp.returncode == 0, cp.stderr
        out_path = ws / "raw" / "function_summaries.json"
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert isinstance(data["summaries"], list)
        assert data["summaries"][0]["purpose"]
    finally:
        import shutil
        shutil.rmtree(ws.parent, ignore_errors=True)


def test_cli_function_summary_single_function() -> None:
    ws = _make_workspace()
    try:
        cp = _run_cli("function-summary", "--json", "--function", "main", str(ws))
        assert cp.returncode == 0, cp.stderr
        out_path = ws / "raw" / "function_summaries.json"
        data = json.loads(out_path.read_text())
        assert len(data["summaries"]) == 1
        assert data["summaries"][0]["name"] == "main"
    finally:
        import shutil
        shutil.rmtree(ws.parent, ignore_errors=True)
