"""Phase 6 behavior tests: execution-backed enrichment loop."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from src.execution.backend_selector import BackendSelector, EmulatorProbeRequest
from src.execution.enrichment_loop import EnrichmentLoop
from src.execution.models import MemorySnapshot
from src.execution.probe_runner import ProbeRunner
from src.execution.runners.base import AbstractRunner, RunnerResult
from src.execution.snapshot_applier import SnapshotApplier
from src.models.analysis_graph import AnalysisGraph, Edge, Node


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
             name="main", properties={"binary": binary_path})
    graph.add_node(p)
    graph.add_node(f)
    graph.add_edge(Edge(src="program:sample", dst="function:0x401000", kind="contains"))
    return graph


class FakeRunner(AbstractRunner):
    """Deterministic in-process runner for unit testing."""

    name = "fake"

    def __init__(self, payload: bytes | None = None) -> None:
        self.payload = payload or b"FAKE"

    def can_run(self) -> bool:
        return True

    def run(self, probe, binary_path: str | None = None) -> RunnerResult:
        ranges = list(getattr(probe, "capture_memory_ranges", []) or [] or [("default", 0x700000, len(self.payload))])
        name, addr, length = ranges[0]
        snapshot = MemorySnapshot.from_bytes(
            address=addr,
            payload=self.payload[:length],
            source=self.name,
            name=name,
        )
        return RunnerResult(status="success", snapshot=snapshot, note="fake runner")


# ------------------------------------------------------------------ unit tests

def test_memory_snapshot_from_bytes() -> None:
    snap = MemorySnapshot.from_bytes(0x1000, b"ABCD", source="test")
    assert snap.address == "0x1000"
    assert snap.length == 4
    assert snap.to_bytes() == b"ABCD"


def test_probe_runner_dispatch_success() -> None:
    runner = ProbeRunner()
    runner.register("fake", FakeRunner(b"\x90\x90"))
    probe = EmulatorProbeRequest(
        function_name="main",
        capture_memory_ranges=[("stack", 0x700000, 2)],
    )
    result = runner.run(probe, binary_path="ignored", backend_name="fake")
    assert result.status == "success"
    assert result.snapshot is not None
    assert result.snapshot.length == 2


def test_probe_runner_unknown_backend() -> None:
    runner = ProbeRunner()
    probe = EmulatorProbeRequest(function_name="main")
    result = runner.run(probe, binary_path="ignored", backend_name="doesnotexist")
    assert result.status == "no_backend"


def test_snapshot_applier_adds_segment() -> None:
    graph = _sample_graph()
    snap = MemorySnapshot.from_bytes(0x700000, b"zzzz", source="test")
    applier = SnapshotApplier(graph)
    changes = applier.apply(snap)
    assert any(chg["op"] == "add_node" and "segment" in chg["node"] for chg in changes)
    assert graph.get_node("segment:0x700000") is not None


def test_enrichment_loop_with_fake_runner() -> None:
    graph = _sample_graph()
    selector = BackendSelector()
    runner = ProbeRunner(selector)
    runner.register("unicorn", FakeRunner(b"\xde\xad"))
    loop = EnrichmentLoop(selector, runner)
    result = loop.enrich(
        graph, "main",
        probe_input={
            "capture_memory_ranges": [("secret", 0x800000, 2)],
            "backend": "unicorn",
        },
    )
    assert result.status == "success"
    assert result.snapshot is not None
    assert result.snapshot.source == "fake"
    assert any(chg["op"] == "add_node" and "segment" in chg["node"] for chg in result.changes)


def test_enrichment_loop_no_selector() -> None:
    graph = _sample_graph()
    loop = EnrichmentLoop(None)
    result = loop.enrich(graph, "main")
    assert result.status == "no_backend"


def test_enrichment_loop_legacy_selector_run() -> None:
    """Old-style selector.run() returning MemorySnapshot must still work."""
    graph = _sample_graph()

    class LegacySelector:
        def select(self, binary, triage_profile=None):
            from src.execution.backend_selector import ExecutionBackend
            return ExecutionBackend("gdb", "high", "linux", True, True, reason="fake")

        def run(self, probe):
            return MemorySnapshot("0x700000", "AAAA", 4, "fake", "2026-01-01T00:00:00")

    loop = EnrichmentLoop(LegacySelector())
    result = loop.enrich(graph, "main")
    assert result.status == "success"
    assert graph.get_node("segment:0x700000") is not None


def test_unicorn_runner_error_when_no_binary() -> None:
    """A missing binary path is rejected before attempting Unicorn execution."""
    from src.execution.runners.unicorn_runner import UnicornRunner
    runner = UnicornRunner()
    probe = EmulatorProbeRequest(function_name="main")
    result = runner.run(probe, binary_path="/no/such/binary")
    assert result.status == "error"


# ------------------------------------------------------------------ CLI tests

def test_cli_execution_status() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        cp = _run_cli("execution-status", "--json", tmp_path)
        assert cp.returncode == 0, cp.stderr
        data = json.loads(cp.stdout)
        assert "selected_backend" in data
        assert "available_runners" in data
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_probe_run_native_missing_symbol() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x00" * 64)
        tmp_path = tmp.name
    try:
        cp = _run_cli(
            "probe-run", "--json", "--backend", "native",
            "--capture-range", "stack:0x700000:16",
            tmp_path, "nonexistent_symbol",
        )
        assert cp.returncode == 1, cp.stderr
        data = json.loads(cp.stdout)
        assert data["status"] == "error"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_probe_run_native_symbol_found() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # NUL-terminated symbol name so byte-scan finds it without substring false positives.
        tmp.write(b"\x00main\x00symbol\x00")
        tmp_path = tmp.name
    try:
        cp = _run_cli(
            "probe-run", "--json", "--backend", "native",
            "--capture-range", "stack:0x700000:16",
            tmp_path, "main",
        )
        assert cp.returncode == 1, cp.stderr
        data = json.loads(cp.stdout)
        assert data["status"] == "error"
        assert data["snapshot"] is None
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_enrich_workspace_with_legacy_selector_graph() -> None:
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        ws.mkdir()
        raw = ws / "raw"
        raw.mkdir()
        binary_path = str(ws / "binary")
        bin_path = ws / "binary"
        bin_path.write_bytes(b"main\x00symbol\x00")
        graph = _sample_graph(binary_path)
        graph_path = raw / "analysis_graph.json"
        graph_path.write_text(json.dumps(graph.to_json(), indent=2))

        # Use native backend; capture range; symbol check can find 'main' in bytes.
        cp = _run_cli(
            "enrich-workspace", "--json", "--backend", "native",
            "--capture-range", "stack:0x700000:8",
            str(ws), "main",
        )
        assert cp.returncode == 1, cp.stderr
        data = json.loads(cp.stdout)
        assert data["status"] != "success"
        assert graph_path.read_text() == json.dumps(graph.to_json(), indent=2)
