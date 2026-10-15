"""Phase 7 behavior tests: symbolic / concolic execution probe layer."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from src.execution.backend_selector import EmulatorProbeRequest
from src.execution.enrichment_loop import EnrichmentLoop
from src.execution.models import MemorySnapshot
from src.execution.probe_runner import ProbeRunner
from src.execution.runners.base import AbstractRunner, RunnerResult
from src.execution.runners.symbolic_runner import FakeSymbolicRunner, SymbolicRunner
from src.execution.snapshot_applier import SnapshotApplier
from src.execution.symbolic.models import (
    MemoryWriteObservation,
    PathConstraint,
    SymbolicProbeRequest,
    SymbolicProbeResult,
)
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
    b1 = Node(id="block:0x401000", kind="block", address="0x401000")
    b2 = Node(id="block:0x401020", kind="block", address="0x401020")
    graph.add_node(p)
    graph.add_node(f)
    graph.add_node(b1)
    graph.add_node(b2)
    graph.add_edge(Edge(src="program:sample", dst="function:0x401000", kind="contains"))
    graph.add_edge(Edge(src="function:0x401000", dst="block:0x401000", kind="contains"))
    graph.add_edge(Edge(src="function:0x401000", dst="block:0x401020", kind="contains"))
    graph.add_edge(Edge(src="block:0x401000", dst="block:0x401020", kind="fall_through"))
    return graph


# ------------------------------------------------------------------ model tests


def test_symbolic_probe_request_validation() -> None:
    with pytest.raises(ValueError):
        SymbolicProbeRequest(function_name="main", max_paths=0)
    with pytest.raises(ValueError):
        SymbolicProbeRequest(function_name="main", symbolic_args=[-1])
    req = SymbolicProbeRequest(function_name="main", max_paths=4, max_steps=100)
    assert req.max_paths == 4
    assert req.as_dict()["max_paths"] == 4


def test_symbolic_result_serialization() -> None:
    result = SymbolicProbeResult(
        status="success",
        paths=[
            PathConstraint(
                path_id=0,
                predicate_text=["x > 0"],
                block_trace=[0x401000],
            ),
        ],
        memory_writes=[
            MemoryWriteObservation(concrete_address=0x404000, concrete_value=0x41),
        ],
    )
    data = result.as_dict()
    assert data["status"] == "success"
    assert data["paths"][0]["predicate_text"] == ["x > 0"]
    assert data["memory_writes"][0]["concrete_address"] == 0x404000


# ------------------------------------------------------------------ runner tests


def test_symbolic_runner_unavailable_without_angr() -> None:
    """When angr is absent, the runner reports unavailable.

    Because angr may actually be installed in CI, we monkeypatch the class
    guard to simulate its absence.
    """
    from src.execution.runners import symbolic_runner as sym_mod
    orig = SymbolicRunner._have_angr
    try:
        SymbolicRunner._have_angr = False
        runner = SymbolicRunner()
        assert runner.can_run() is False
        result = runner.run(SymbolicProbeRequest(function_name="main"), binary_path="/fake")
        assert result.status == "unavailable"
        assert "angr" in result.note.lower()
    finally:
        SymbolicRunner._have_angr = orig
        # reset lazy cache so subsequent tests reflect the real environment
        SymbolicRunner._have_angr = None


def test_fake_symbolic_runner_returns_constraints() -> None:
    runner = FakeSymbolicRunner()
    probe = EmulatorProbeRequest(function_name="main")
    result = runner.run(probe, binary_path="fake")
    assert result.status == "success"
    assert result.snapshot is not None
    assert result.snapshot.source == "symbolic"
    assert result.snapshot.properties.get("symbolic_result") is not None
    sym_result = result.snapshot.properties["symbolic_result"]
    assert len(sym_result["paths"]) >= 2
    assert sym_result["paths"][0]["block_trace"]


# ------------------------------------------------------------------ pipeline tests


def test_snapshot_applier_records_symbolic_constraints() -> None:
    graph = _sample_graph()
    runner = FakeSymbolicRunner()
    probe = EmulatorProbeRequest(function_name="main")
    runner_result = runner.run(probe, binary_path="fake")
    applier = SnapshotApplier(graph)
    changes = applier.apply(runner_result.snapshot, target_fn_id="function:0x401000")

    fn = graph.get_node("function:0x401000")
    assert fn is not None
    assert fn.properties.get("execution_source") == "symbolic"
    assert fn.properties.get("symbolic_result") is not None
    constraint_ids = [c["node"] for c in changes if c["op"] == "add_node" and "constraint" in c["node"]]
    assert constraint_ids
    for cid in constraint_ids:
        assert graph.get_node(cid) is not None
    proves = [c for c in changes if c["op"] == "add_edge" and c["kind"] == "proves_reachable"]
    assert proves


def test_enrichment_loop_symbolic_backend_chain() -> None:
    graph = _sample_graph(binary_path="fake")
    loop = EnrichmentLoop(selector_or_none=False, runner_or_none=ProbeRunner())
    runner = FakeSymbolicRunner()
    loop.runner.register("symbolic", runner)
    result = loop.enrich(graph, "function:0x401000", probe_input={"backend": "symbolic"})
    assert result.status == "success"
    fn = graph.get_node("function:0x401000")
    assert fn is not None
    assert fn.properties.get("symbolic_result") is not None
    assert result.detail.get("paths") is not None


# ------------------------------------------------------------------ CLI tests


def test_cli_symbolic_probe_reports_real_backend_status() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    try:
        cp = _run_cli("symbolic-probe", "--json", tmp_path, "main")
        assert cp.returncode in (0, 1), cp.stderr
        data = json.loads(cp.stdout)
        assert data["status"] in ("success", "unavailable")
        if data["status"] == "unavailable":
            assert "symbolic" in data["note"] or "angr" in data["note"].lower()
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ------------------------------------------------------------------ real angr tests (optional)

@pytest.mark.angr
def test_symbolic_runner_model_with_angr() -> None:
    """Instantiate angr project only if it is importable; no real binary needed."""
    runner = SymbolicRunner()
    if not runner.can_run():
        pytest.skip("angr not available")
    # We do not run a real probe here to keep CI fast and avoid binary fixtures.
    assert runner.name == "symbolic"


def test_symbolic_runner_executes_real_fixture_with_angr(tmp_path: Path) -> None:
    """Compile and symbolically execute a real function when angr is installed."""
    import shutil
    import subprocess

    runner = SymbolicRunner()
    if not runner.can_run() or shutil.which("gcc") is None:
        pytest.skip("angr and gcc are required")
    fixture = Path(__file__).parent / "fixtures" / "symbolic_add.c"
    binary = tmp_path / "symbolic-add"
    built = subprocess.run(
        ["gcc", "-O0", "-fno-pie", "-no-pie", str(fixture), "-o", str(binary)],
        capture_output=True, text=True, timeout=20,
    )
    assert built.returncode == 0, built.stderr
    probe = EmulatorProbeRequest(function_name="symbolic_add", args=[1, 2])

    result = runner.run(probe, str(binary))

    assert result.status == "success", result.note
    assert result.detail["detail"]["deadended_states"] >= 1
    assert result.detail["detail"]["symbolic_arguments"] == [0, 1]
    assert len(result.detail["paths"]) == 2
