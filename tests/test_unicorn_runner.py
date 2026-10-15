from pathlib import Path

from src.execution.backend_selector import EmulatorProbeRequest
from src.execution.models import DynamicEvent, MemoryImage, ModuleMapping
from src.execution.runners.base import RunnerResult
from src.execution.runners.unicorn_runner import UnicornRunner
from src.execution.snapshot_applier import SnapshotApplier
from src.models.analysis_graph import AnalysisGraph, Node


class _FakeHarness:
    def __init__(self) -> None:
        self.kwargs = None

    @staticmethod
    def available() -> bool:
        return True

    def run_path(self, path, **kwargs):
        self.kwargs = {"path": path, **kwargs}
        return RunnerResult(status="success", note="ok")


def test_runner_dispatches_loader_harness_with_concrete_request(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90\xc3")
    harness = _FakeHarness()
    runner = UnicornRunner(harness=harness)
    probe = EmulatorProbeRequest(
        function_name="target",
        entry_address=0x401000,
        isa="x86_64",
        args=["0x2a", 7],
        capture_memory_ranges=[("output", 0x500000, 16)],
        max_instructions=99,
        max_trace_events=20,
    )

    result = runner.run(probe, binary_path=str(binary))

    assert result.status == "success"
    assert harness.kwargs == {
        "path": str(binary),
        "entry_point": 0x401000,
        "architecture": "x86_64",
        "args": [42, 7],
        "capture_ranges": [("output", 0x500000, 16)],
        "max_instructions": 99,
        "max_events": 20,
    }


def test_runner_refuses_to_guess_unresolved_symbol(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\xc3")
    result = UnicornRunner(harness=_FakeHarness()).run(
        EmulatorProbeRequest(function_name="not_exported"),
        binary_path=str(binary),
    )
    assert result.status == "missing_symbol"


def test_memory_image_application_is_verified_and_idempotent() -> None:
    graph = AnalysisGraph()
    graph.add_node(Node(id="program:test", kind="program", address="0x400000"))
    graph.add_node(Node(id="function:main", kind="function", address="0x401000"))
    event = DynamicEvent.create(
        0,
        "basic_block",
        "test-provider",
        runtime_address=0x501000,
        static_address=0x401000,
        module_id="main",
    )
    image = MemoryImage.create(
        provider="test-provider",
        target_sha256="a" * 64,
        architecture="x86_64",
        pointer_size=8,
        load_base=0x500000,
        entry_point=0x501000,
        modules=[ModuleMapping(
            module_id="main",
            name="sample",
            runtime_base=0x500000,
            preferred_base=0x400000,
            size=0x2000,
            sha256="a" * 64,
        )],
        events=[event],
    )
    applier = SnapshotApplier(graph)

    first = applier.apply_image(image, target_fn_id="function:main")
    second = applier.apply_image(image, target_fn_id="function:main")

    assert any(change["op"] == "add_evidence" for change in first)
    assert second == []
    assert len(graph.metadata["dynamic_evidence"]) == 1
    event_node = graph.get_node(f"runtime_event:{image.capture_id}:0")
    assert event_node is not None
    assert event_node.properties["event_sha256"] == event.event_sha256
