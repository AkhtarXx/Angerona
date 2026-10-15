from pathlib import Path

import pytest

from src.execution.runners.native_runner import NativeAppcallRunner
from src.engines.ghidra import _project_name_for
from src.orchestration.batch_spine import BatchJobSpec
from src.services.contracts import EvidenceEnvelope, ServiceResponse, ServiceStatus
from src.workspace import RunWorkspace


class _Probe:
    function_name = "main"
    capture_memory_ranges = [("stack", 0x700000, 16)]


def test_native_runner_refuses_fake_binary_even_when_symbol_bytes_exist(tmp_path: Path) -> None:
    binary = tmp_path / "sample"
    binary.write_bytes(b"\x00main\x00")
    result = NativeAppcallRunner().run(_Probe(), str(binary))
    assert result.status == "error"
    assert result.snapshot is None


def test_native_runner_executes_integer_abi_function_in_sandbox(tmp_path: Path) -> None:
    import shutil
    import subprocess

    runner = NativeAppcallRunner()
    if not runner.can_run() or shutil.which("gcc") is None:
        pytest.skip("GDB, bubblewrap, and gcc are required")
    fixture = Path(__file__).parent / "fixtures" / "symbolic_add.c"
    binary = tmp_path / "native-add"
    built = subprocess.run(
        ["gcc", "-O0", "-g", "-fno-pie", "-no-pie", str(fixture), "-o", str(binary)],
        capture_output=True, text=True, timeout=20,
    )
    assert built.returncode == 0, built.stderr
    probe = type("Probe", (), {"function_name": "symbolic_add", "args": [2, 3]})()

    result = runner.run(probe, str(binary))

    assert result.status == "success", result.detail
    assert result.detail["return_value"] == 5
    assert result.detail["sandbox"] == "bubblewrap"
    assert result.detail["network"] is False


def test_workspace_names_are_unique_and_metadata_is_atomic(tmp_path: Path) -> None:
    first = RunWorkspace.create(tmp_path, "/bin/true")
    second = RunWorkspace.create(tmp_path, "/bin/true")
    assert first.root != second.root
    assert (first.root / "run.json").is_file()
    assert not list(first.root.glob(".run.json.*.tmp"))


def test_ghidra_foreign_owned_project_uses_current_user_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.engines.ghidra.getpass.getuser", lambda: "ubuntu")
    (tmp_path / "sample.gpr").write_text("")
    properties = tmp_path / "sample.rep" / "project.prp"
    properties.parent.mkdir()
    properties.write_text(
        '<FILE_INFO><BASIC_INFO><STATE NAME="OWNER" TYPE="string" '
        'VALUE="foreign-user" /></BASIC_INFO></FILE_INFO>'
    )

    assert _project_name_for(tmp_path, "sample") == "sample__owner_ubuntu"


def test_ghidra_current_user_project_is_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.engines.ghidra.getpass.getuser", lambda: "ubuntu")
    (tmp_path / "sample.gpr").write_text("")
    properties = tmp_path / "sample.rep" / "project.prp"
    properties.parent.mkdir()
    properties.write_text(
        '<FILE_INFO><BASIC_INFO><STATE NAME="OWNER" TYPE="string" '
        'VALUE="ubuntu" /></BASIC_INFO></FILE_INFO>'
    )

    assert _project_name_for(tmp_path, "sample") == "sample"


@pytest.mark.parametrize("engine", ["", "radare2", "IDA"])
def test_batch_rejects_unknown_engine(engine: str) -> None:
    with pytest.raises(ValueError):
        BatchJobSpec(binary="/bin/true", engine=engine, stages=["triage"])


def test_batch_rejects_unknown_stage() -> None:
    with pytest.raises(ValueError):
        BatchJobSpec(binary="/bin/true", engine="ghidra", stages=["magic"])


def test_evidence_envelope_binds_source_content(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(b"abc")
    evidence = EvidenceEnvelope.for_file(
        kind="static-analysis",
        producer="test",
        source=sample,
        payload={"functions": 1},
    )
    assert len(evidence.source_sha256) == 64
    assert not evidence.synthetic
    response = ServiceResponse(
        status=ServiceStatus.SUCCEEDED,
        evidence=(evidence,),
    )
    assert response.succeeded
    assert "source_sha256" in response.to_json()
