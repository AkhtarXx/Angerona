from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

import pytest

from src.agents.audit_state import AuditStateError, AuditStateStore, build_audit_identity
from src.agents.orchestrator import Orchestrator
from src.agents.supervisor import SwarmResult
from src.analysis.audit_readiness import (
    AuditReadinessError,
    MAX_JSON_BYTES,
    validate_audit_readiness,
)
from src.analysis.export import export_analysis
from src.workspace import RunWorkspace


class ReadyEngine:
    def analyze(self, binary, decompile=True, max_functions=0):
        return {
            "metadata": {"engine": "ready", "entry_point": "0x401000"},
            "functions": [{
                "name": "main", "entry": "0x401000", "size": 16,
                "signature": "int main(void)",
                "decompiled": (
                    "int main(void) { return 0; }" if decompile else ""
                ),
                "callers": [], "callees": [],
            }],
            "strings": [], "imports": [], "exports": [], "symbols": [],
        }


class PartialEngine(ReadyEngine):
    def analyze(self, binary, decompile=True, max_functions=0):
        result = super().analyze(binary, decompile, max_functions)
        result["functions"].append({
            "name": "assembly_only", "entry": "0x401100", "size": 8,
            "signature": "", "decompiled": "", "callers": [], "callees": [],
        })
        return result


class FailingEngine:
    def analyze(self, binary, decompile=True, max_functions=0):
        raise RuntimeError("engine crashed after leaving partial output")


class SwappingSourceEngine(ReadyEngine):
    def __init__(self, source: Path) -> None:
        self.source = source
        self.engine_input: Path | None = None

    def analyze(self, binary, decompile=True, max_functions=0):
        self.engine_input = Path(binary)
        assert self.engine_input.read_bytes() != b"replacement target B"
        self.source.write_bytes(b"replacement target B")
        return super().analyze(binary, decompile, max_functions)


class FakeConfig:
    engine = "ghidra"

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir

    def ready(self):
        return True, "ready"


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "target.bin"
    path.write_bytes(b"\x7fELF audit-readiness")
    return path


def test_transactional_export_writes_verified_readiness_record(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    result = validate_audit_readiness(code, binary=binary)
    assert result["status"] == "ready"
    assert result["agent_dispatch_allowed"] is True
    assert json.loads((code / "AUDIT_READINESS.json").read_text()) == result
    assert not list(tmp_path.glob(".code.export-*-*"))


def test_partial_decompilation_is_machine_visible_not_silently_full(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    manifest = export_analysis(PartialEngine(), str(binary), code)
    readiness = validate_audit_readiness(code, binary=binary)
    assert manifest["status"] == "partial"
    assert readiness["status"] == "ready_with_limitations"
    assert readiness["limitations"][0]["code"] == "decompilation_partial"
    assert readiness["coverage"]["decompiled_functions"] == 1
    assert readiness["coverage"]["functions"] == 2


def test_explicit_no_decompile_export_is_limited_but_transactionally_ready(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    manifest = export_analysis(ReadyEngine(), str(binary), code, decompile=False)
    readiness = validate_audit_readiness(code, binary=binary)
    assert manifest["status"] == "partial"
    assert readiness["status"] == "ready_with_limitations"
    assert readiness["limitations"][0]["code"] == "decompilation_unavailable"


def test_ledger_tamper_and_artifact_symlink_fail_closed(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    (code / "analysis.json").write_text("{}")
    with pytest.raises(AuditReadinessError, match="identity mismatch"):
        validate_audit_readiness(code, binary=binary)

    export_analysis(ReadyEngine(), str(binary), code)
    outside = tmp_path / "outside"
    outside.write_text("not evidence")
    (code / "analysis.json").unlink()
    (code / "analysis.json").symlink_to(outside)
    with pytest.raises(AuditReadinessError, match="safely open"):
        validate_audit_readiness(code, binary=binary)


def test_absolute_and_noncanonical_ledger_paths_never_escape_export(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    ledger_path = code / "EVIDENCE_LEDGER.json"
    for unsafe in ("/etc/passwd", "decompiled//main.c", "./analysis.json"):
        ledger = json.loads(ledger_path.read_text())
        ledger["artifacts"].append({
            "path": unsafe, "sha256": "0" * 64, "size_bytes": 0,
        })
        ledger["artifact_count"] = len(ledger["artifacts"])
        ledger_path.write_text(json.dumps(ledger))
        with pytest.raises(AuditReadinessError, match="unsafe export artifact path"):
            validate_audit_readiness(code, binary=binary)
        export_analysis(ReadyEngine(), str(binary), code)


def test_oversized_json_is_rejected_from_fstat_before_capture(tmp_path: Path) -> None:
    code = tmp_path / "code"
    code.mkdir()
    manifest = code / "EXPORT_MANIFEST.json"
    with manifest.open("wb") as handle:
        handle.truncate(MAX_JSON_BYTES + 1)
    with pytest.raises(AuditReadinessError, match=f"exceeds {MAX_JSON_BYTES} bytes"):
        validate_audit_readiness(code)


def test_failed_export_preserves_previous_committed_tree(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    before = (code / "AUDIT_READINESS.json").read_bytes()
    with pytest.raises(RuntimeError, match="engine crashed"):
        export_analysis(FailingEngine(), str(binary), code)
    assert (code / "AUDIT_READINESS.json").read_bytes() == before
    assert validate_audit_readiness(code, binary=binary)["status"] == "ready"
    assert not list(tmp_path.glob(".code.export-*-*"))


def test_failed_injection_scan_never_promotes_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.analysis.export as export_module

    binary = _binary(tmp_path)
    code = tmp_path / "code"
    monkeypatch.setattr(
        export_module,
        "scan_strings_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("scanner failed")),
    )
    with pytest.raises(AuditReadinessError, match="scan is absent or failed"):
        export_analysis(ReadyEngine(), str(binary), code)
    assert not code.exists()


def test_required_identity_artifact_cannot_be_silently_skipped(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(AuditStateError, match="required critical artifact is missing"):
        build_audit_identity(
            workspace_root=workspace,
            binary=binary,
            required_artifacts=("code/AUDIT_READINESS.json",),
        )


def test_resume_identity_rejects_same_content_symlink_substitution(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    workspace = tmp_path / "workspace"
    code = workspace / "code"
    code.mkdir(parents=True)
    readiness = code / "AUDIT_READINESS.json"
    readiness.write_text('{"status":"ready"}')
    identity = build_audit_identity(
        workspace_root=workspace,
        binary=binary,
        critical_artifacts=("code/AUDIT_READINESS.json",),
        required_artifacts=("code/AUDIT_READINESS.json",),
    )
    outside = tmp_path / "same-content.json"
    outside.write_bytes(readiness.read_bytes())
    readiness.unlink()
    readiness.symlink_to(outside)
    store = AuditStateStore(workspace)
    with pytest.raises(AuditStateError, match="safely open critical artifact"):
        store.validate_identity(identity)
    store.close()


def test_resume_rejects_oversized_artifact_from_fstat_before_hashing(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    workspace = tmp_path / "workspace"
    code = workspace / "code"
    code.mkdir(parents=True)
    readiness = code / "AUDIT_READINESS.json"
    readiness.write_text('{"status":"ready"}')
    identity = build_audit_identity(
        workspace_root=workspace,
        binary=binary,
        required_artifacts=("code/AUDIT_READINESS.json",),
    )
    with readiness.open("wb") as handle:
        handle.truncate(128 * 1024 * 1024)
    store = AuditStateStore(workspace)
    with pytest.raises(AuditStateError, match="size mismatch rejected before hashing"):
        store.validate_identity(identity)
    store.close()


def _rewrite_manifest_binding(code: Path, mutate) -> None:
    manifest_path = code / "EXPORT_MANIFEST.json"
    ledger_path = code / "EVIDENCE_LEDGER.json"
    manifest = json.loads(manifest_path.read_text())
    mutate(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    ledger = json.loads(ledger_path.read_text())
    ledger["manifest"] = {
        "status": manifest["status"],
        "counts": manifest["counts"],
        "effective_max_functions": manifest.get("effective_max_functions"),
    }
    for record in ledger["artifacts"]:
        if record["path"] == "EXPORT_MANIFEST.json":
            raw = manifest_path.read_bytes()
            record["sha256"] = hashlib.sha256(raw).hexdigest()
            record["size_bytes"] = len(raw)
    ledger_path.write_text(json.dumps(ledger, indent=2))


def test_manifest_status_must_exactly_match_decompilation_coverage(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    _rewrite_manifest_binding(code, lambda manifest: manifest.update(status="partial"))
    with pytest.raises(AuditReadinessError, match="status disagrees"):
        validate_audit_readiness(code, binary=binary)


def test_manifest_and_ledger_inventory_must_match_exactly(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)

    def omit_optional(manifest):
        manifest["files"].remove("strings.txt")

    _rewrite_manifest_binding(code, omit_optional)
    with pytest.raises(AuditReadinessError, match="inventories disagree"):
        validate_audit_readiness(code, binary=binary)


def test_ledger_boolean_counts_and_sizes_are_rejected(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    ledger_path = code / "EVIDENCE_LEDGER.json"
    ledger = json.loads(ledger_path.read_text())
    ledger["artifact_count"] = True
    ledger_path.write_text(json.dumps(ledger))
    with pytest.raises(AuditReadinessError, match="ledger artifact_count"):
        validate_audit_readiness(code, binary=binary)


def test_post_promotion_fsync_failure_rolls_back_previous_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.analysis.export as export_module

    binary = _binary(tmp_path)
    code = tmp_path / "code"
    export_analysis(ReadyEngine(), str(binary), code)
    before = (code / "AUDIT_READINESS.json").read_bytes()
    real_fsync = export_module.os.fsync
    parent_inode = tmp_path.stat().st_ino
    parent_fsyncs = 0

    def fail_commit_barrier(descriptor: int) -> None:
        nonlocal parent_fsyncs
        if os.fstat(descriptor).st_ino == parent_inode:
            parent_fsyncs += 1
            if parent_fsyncs == 3:
                raise OSError("injected parent durability failure")
        real_fsync(descriptor)

    monkeypatch.setattr(export_module.os, "fsync", fail_commit_barrier)
    with pytest.raises(OSError, match="injected parent durability failure"):
        export_analysis(PartialEngine(), str(binary), code)
    assert (code / "AUDIT_READINESS.json").read_bytes() == before
    assert validate_audit_readiness(code, binary=binary)["status"] == "ready"


def test_stale_transaction_staging_is_reclaimed_under_lock(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    orphan = tmp_path / ".code.export-dead-beef"
    orphan.mkdir()
    (orphan / "partial").write_text("crash")
    export_analysis(ReadyEngine(), str(binary), tmp_path / "code")
    assert not orphan.exists()


def test_non_anchor_engine_is_bound_to_preanalysis_target_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.agents.supervisor as supervisor_module

    binary = _binary(tmp_path)
    original = binary.read_bytes()
    original_sha = hashlib.sha256(original).hexdigest()
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    swapping_engine = SwappingSourceEngine(binary)
    orchestrator.engine = swapping_engine

    def completed(self):
        return SwarmResult(
            converged=True, supervisor_rounds=1, workers=[], workspace=self.ws,
            final_report="# Audit report\n\nSnapshot-bound analysis.",
        )

    monkeypatch.setattr(supervisor_module.SupervisorLoop, "run", completed)
    result = orchestrator.swarm_run(
        str(binary), workspace=workspace, pre_analyze=False,
        max_supervisor_rounds=1, max_worker_rounds=1, strict_verify=False,
    )
    assert result.converged is True
    assert binary.read_bytes() == b"replacement target B"
    assert swapping_engine.engine_input is not None
    assert swapping_engine.engine_input != binary
    assert swapping_engine.engine_input.read_bytes() == original
    assert workspace.meta["binary_snapshot_identity"] == {
        "size": len(original), "sha256": original_sha,
    }
    readiness = validate_audit_readiness(
        workspace.code_dir, binary=swapping_engine.engine_input,
    )
    assert readiness["target"]["sha256"] == original_sha


def test_non_anchor_export_failure_blocks_all_agent_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.agents.supervisor as supervisor_module

    binary = _binary(tmp_path)
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = FailingEngine()
    supervisor_calls = []

    def forbidden_run(self):
        supervisor_calls.append(self)
        raise AssertionError("supervisor must not run without a ready export")

    monkeypatch.setattr(supervisor_module.SupervisorLoop, "run", forbidden_run)
    result = orchestrator.swarm_run(
        str(binary), workspace=workspace, pre_analyze=False,
        max_supervisor_rounds=1, max_worker_rounds=1,
    )
    assert supervisor_calls == []
    assert result.terminal_status == "incomplete"
    assert result.incomplete_reason == "export_failed"
    assert result.workers == []
    assert result.final_report.startswith("# INCOMPLETE — AUDIT READINESS FAILED")
    store = AuditStateStore(workspace.root)
    snapshot = store.load_latest()
    assert snapshot is not None
    assert snapshot.payload["status"] == "incomplete"
    assert snapshot.payload["phase"] == "audit:readiness-failed"
    store.close()


def test_target_snapshot_failure_is_terminal_and_never_dispatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.agents.supervisor as supervisor_module
    import src.analysis.target_snapshot as target_snapshot_module

    binary = _binary(tmp_path)
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = ReadyEngine()
    supervisor_calls = []

    def fail_capture(*_args, **_kwargs):
        raise target_snapshot_module.TargetSnapshotError("injected capture failure")

    def forbidden_run(self):
        supervisor_calls.append(self)
        raise AssertionError("supervisor must not run without a target snapshot")

    monkeypatch.setattr(
        target_snapshot_module, "materialize_audit_target_snapshot", fail_capture,
    )
    monkeypatch.setattr(supervisor_module.SupervisorLoop, "run", forbidden_run)
    result = orchestrator.swarm_run(
        str(binary), workspace=workspace, pre_analyze=False,
        max_supervisor_rounds=1, max_worker_rounds=1,
    )
    assert supervisor_calls == []
    assert result.terminal_status == "incomplete"
    assert result.incomplete_reason == "target_snapshot_failed"
    assert workspace.meta["status"] == "incomplete"
    store = AuditStateStore(workspace.root)
    snapshot = store.load_latest()
    assert snapshot is not None
    assert snapshot.payload["status"] == "incomplete"
    assert snapshot.payload["incomplete_reason"] == "target_snapshot_failed"
    store.close()


def test_resume_refuses_changed_readiness_before_any_new_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.agents.supervisor as supervisor_module

    binary = _binary(tmp_path)
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = ReadyEngine()
    calls = 0

    def pause_once(self):
        nonlocal calls
        calls += 1
        return SwarmResult(
            converged=False, supervisor_rounds=0, workers=[], workspace=self.ws,
            final_report="", paused=True,
        )

    monkeypatch.setattr(supervisor_module.SupervisorLoop, "run", pause_once)
    first = orchestrator.swarm_run(
        str(binary), workspace=workspace, pre_analyze=False,
        max_supervisor_rounds=1, max_worker_rounds=1,
    )
    assert first.paused is True and calls == 1
    readiness_path = workspace.code_dir / "AUDIT_READINESS.json"
    readiness = json.loads(readiness_path.read_text())
    readiness["agent_dispatch_allowed"] = False
    readiness_path.write_text(json.dumps(readiness))

    reopened = RunWorkspace.open(workspace.root, binary=str(binary))
    resumed_store = AuditStateStore(workspace.root)
    with pytest.raises(AuditStateError, match="resume artifact changed"):
        orchestrator.swarm_run(
            str(binary), workspace=reopened, pre_analyze=False,
            max_supervisor_rounds=1, max_worker_rounds=1,
            audit_state_store=resumed_store,
        )
    assert calls == 1


def test_final_report_cannot_hide_machine_known_export_limitation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.agents.supervisor as supervisor_module

    binary = _binary(tmp_path)
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = PartialEngine()

    def completed(self):
        return SwarmResult(
            converged=True, supervisor_rounds=1, workers=[], workspace=self.ws,
            final_report="# Audit report\n\nNo caveat supplied by model.",
        )

    monkeypatch.setattr(supervisor_module.SupervisorLoop, "run", completed)
    result = orchestrator.swarm_run(
        str(binary), workspace=workspace, pre_analyze=False,
        max_supervisor_rounds=1, max_worker_rounds=1, strict_verify=False,
    )
    assert "## Deterministic export coverage limitations" in result.final_report
    assert "Decompiled functions: 1/2" in result.final_report
    assert (workspace.docs_dir / "consolidated_report.md").read_text() == result.final_report
