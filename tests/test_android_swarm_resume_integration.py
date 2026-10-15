"""R7+R8 end-to-end: run_android_ai_swarm resumes both halves of the pre-AI state.

F7/R7: the supervisor must receive its own committed swarm checkpoint via
``resume_payload`` (previously always ``None``, so every resume fresh-started and
replayed all already-failed outcomes).

F8/R8: the sealed pre-AI materialization must be reused instead of re-running
hours of IDA/objdump when ``ANDROID_PRE_AI_PROGRESS.json`` records
``materialization_complete=True`` with hash-verified sealed inventories.

This is the one test that exercises the wiring inside ``run_android_ai_swarm``
(not just the helpers), with a fake dispatch and a fake supervisor.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.agents.audit_state import AuditStateStore
from src.agents.supervisor import SwarmResult
from src.pipeline import android_ai_audit as aia
from src.pipeline.android_ai_audit import (
    _EVIDENCE_READER_NAME,
    _EVIDENCE_READER_SOURCE,
    _FINDING_ADJUDICATOR_NAME,
    _FINDING_ADJUDICATOR_SOURCE,
    _sha256,
    run_android_ai_swarm,
)
from src.pipeline.android_audit import AuditReport
from src.workspace import RunWorkspace


def _workspace(tmp_path: Path) -> RunWorkspace:
    runs = tmp_path / "runs"
    runs.mkdir()
    return RunWorkspace.create(runs, str(tmp_path / "target.apk"))


def _seal(ws: RunWorkspace) -> None:
    """Seal a completed pre-AI materialization (same shape as the adapter)."""
    code = ws.code_dir
    raw = ws.raw_dir
    files = {
        "source_inventory": code / "ANDROID_SOURCE_INVENTORY.json",
        "binary_inventory": code / "ANDROID_BINARY_INVENTORY.json",
        "finding_inventory": code / "ANDROID_FINDING_INVENTORY.json",
        "security_slices": raw / "security_slices.json",
        "overview": code / "ANDROID_TARGET_OVERVIEW.json",
    }
    # Real, loadable inventory documents so run_android_ai_swarm can parse them.
    files["source_inventory"].write_text(
        json.dumps({"files": [{"path": "a.java"}], "truncated": False}), encoding="utf-8"
    )
    files["binary_inventory"].write_text(json.dumps({"files": []}), encoding="utf-8")
    files["finding_inventory"].write_text(
        json.dumps({"schema_version": 1, "finding_count": 0, "findings": []}),
        encoding="utf-8",
    )
    files["security_slices"].write_text(json.dumps({"slices": []}), encoding="utf-8")
    files["overview"].write_text(
        json.dumps({"target": "com.resume.test", "source_file_count": 1}),
        encoding="utf-8",
    )
    (code / _EVIDENCE_READER_NAME).write_text(_EVIDENCE_READER_SOURCE, encoding="utf-8")
    (code / _FINDING_ADJUDICATOR_NAME).write_text(
        _FINDING_ADJUDICATOR_SOURCE, encoding="utf-8"
    )
    ws.meta["android_pre_ai_progress"] = {
        "materialization_complete": True,
        "final_materialization": True,
        "artifact_sha256": {
            key: _sha256(path) for key, path in files.items()
        },
    }
    ws._save_meta()


def _coverage() -> dict:
    return {
        "coverage_complete": True,
        "inventory_files": 1,
        "worker_slice_verified_files": 1,
        "missing_files": [],
        "inventory_truncated": False,
        "inventory_empty": False,
        "deterministic_findings_expected": 0,
        "deterministic_findings_verified": 0,
        "missing_finding_ids": [],
        "deterministic_finding_closure_complete": True,
    }


def test_run_android_ai_swarm_resumes_sealed_state_and_supervisor_payload(
    tmp_path, monkeypatch
):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"immutable-apk")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.metadata["coverage_gate"] = {
        "manifest_decoded": True,
        "static_code_covered": True,
        "origin_anchored": True,
        "runtime_required": False,
        "runtime_complete": True,
    }

    # F8 pre-state: sealed materialization.
    _seal(ws)

    # F7 pre-state: a committed swarm checkpoint from a prior supervisor round.
    seed_store = AuditStateStore(ws.root)
    seed_store.checkpoint({
        "kind": "swarm",
        "status": "incomplete",
        "phase": "supervise",
        "supervisor": {
            "round": 3,
            "next_round": 4,
            "last_plan_text": "prior plan",
            "coverage_complete": False,
            "seen_ids": ["slice-1"],
            "outcomes": [],
        },
    })
    seed_store.close()

    captured: dict = {}
    swarm = SwarmResult(
        converged=True,
        supervisor_rounds=1,
        workers=[],
        workspace=ws,
        final_report="## Summary\nresumed from checkpoint",
    )

    def fake_supervisor_run(self):
        # Capture what run_android_ai_swarm passed to the supervisor constructor.
        captured["resume_payload"] = dict(self.resume_payload)
        return swarm

    monkeypatch.setattr(aia.SupervisorLoop, "run", fake_supervisor_run)

    def fail_if_re_materialized(*_args, **_kwargs):
        raise AssertionError("materialize_android_ai_evidence re-ran despite sealed state")

    monkeypatch.setattr(
        aia, "materialize_android_ai_evidence", fail_if_re_materialized
    )
    monkeypatch.setattr(aia.ClaudeCodeAgent, "available", lambda _self: True)
    monkeypatch.setattr(aia.CodexAgent, "available", lambda _self: True)
    monkeypatch.setattr(
        aia, "_validate_finding_inventory",
        lambda *_args, **_kwargs: {"valid": True, "reason": ""},
    )
    monkeypatch.setattr(aia, "_collect_worker_ledgers", lambda *_args: ([], []))
    monkeypatch.setattr(aia, "_collect_finding_adjudications", lambda *_args: [])
    monkeypatch.setattr(aia, "_coverage_after_swarm", lambda *_args, **_kwargs: dict(_coverage()))

    outcome = run_android_ai_swarm(
        apk_path=apk, report=report, workspace=ws, rounds=1, parallel=1
    )

    # F8: sealed materialization was reused, never re-run.
    assert outcome.swarm.converged is True

    # F7: the supervisor received its own committed swarm checkpoint.
    assert "resume_payload" in captured
    assert captured["resume_payload"]["kind"] == "swarm"
    assert captured["resume_payload"]["supervisor"]["round"] == 3


def test_run_android_ai_swarm_fresh_starts_when_store_empty(tmp_path, monkeypatch):
    """Without a prior swarm checkpoint, the supervisor gets an empty payload."""
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"immutable-apk")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.metadata["coverage_gate"] = {
        "manifest_decoded": True,
        "static_code_covered": True,
        "origin_anchored": True,
        "runtime_required": False,
        "runtime_complete": True,
    }
    _seal(ws)

    captured: dict = {}
    swarm = SwarmResult(
        converged=True, supervisor_rounds=1, workers=[], workspace=ws,
        final_report="## Summary\nfresh",
    )
    monkeypatch.setattr(aia.SupervisorLoop, "run",
                        lambda self: (captured.update(resume_payload=dict(self.resume_payload)),
                                      swarm)[1])
    monkeypatch.setattr(
        aia, "materialize_android_ai_evidence",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("re-materialized!")),
    )
    monkeypatch.setattr(aia.ClaudeCodeAgent, "available", lambda _self: True)
    monkeypatch.setattr(aia.CodexAgent, "available", lambda _self: True)
    monkeypatch.setattr(
        aia, "_validate_finding_inventory",
        lambda *_args, **_kwargs: {"valid": True, "reason": ""},
    )
    monkeypatch.setattr(aia, "_collect_worker_ledgers", lambda *_args: ([], []))
    monkeypatch.setattr(aia, "_collect_finding_adjudications", lambda *_args: [])
    monkeypatch.setattr(aia, "_coverage_after_swarm", lambda *_args, **_kwargs: dict(_coverage()))

    run_android_ai_swarm(apk_path=apk, report=report, workspace=ws, rounds=1, parallel=1)

    assert captured["resume_payload"] == {}