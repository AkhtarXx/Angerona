"""R8: run_android_ai_swarm must skip re-materialization when inventories are sealed.

A resume previously re-ran ``materialize_android_ai_evidence`` unconditionally,
re-driving hours of IDA/objdump despite ``ANDROID_PRE_AI_PROGRESS.json`` already
recording ``materialization_complete=True`` with byte-verified sealed inventory
hashes. These tests pin ``_resume_materialized_overview``: it returns the saved
overview when every expensive sealed artifact still matches its live sha256,
recovers a completed raw checkpoint after a metadata-write crash, and repairs
cheap evidence scripts without re-running materialization.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.android_ai_audit import (
    _completed_materialization_progress,
    _resume_materialized_overview,
    _sha256,
    _EVIDENCE_READER_NAME,
    _EVIDENCE_READER_SOURCE,
    _FINDING_ADJUDICATOR_NAME,
    _FINDING_ADJUDICATOR_SOURCE,
)
from src.workspace import RunWorkspace


def _seal(ws: RunWorkspace) -> None:
    """Write the 5 sealed inventories + evidence scripts, then record their
    hashes in ws.meta as a completed pre-AI materialization."""
    code = ws.code_dir
    raw = ws.raw_dir
    files = {
        "source_inventory": code / "ANDROID_SOURCE_INVENTORY.json",
        "binary_inventory": code / "ANDROID_BINARY_INVENTORY.json",
        "finding_inventory": code / "ANDROID_FINDING_INVENTORY.json",
        "security_slices": raw / "security_slices.json",
        "overview": code / "ANDROID_TARGET_OVERVIEW.json",
    }
    for path in files.values():
        path.write_text(json.dumps({"sealed": path.name}), encoding="utf-8")
    files["security_slices"].write_text(json.dumps({"slices": []}), encoding="utf-8")
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


def test_resume_skips_materialization_when_sealed(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    overview = _resume_materialized_overview(ws)
    assert overview is not None
    assert overview.get("sealed") == "ANDROID_TARGET_OVERVIEW.json"


def test_resume_materializes_when_no_progress(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    assert _resume_materialized_overview(ws) is None


def test_resume_materializes_when_not_complete(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    ws.meta["android_pre_ai_progress"]["materialization_complete"] = False
    ws._save_meta()
    assert _resume_materialized_overview(ws) is None


def test_resume_materializes_when_sealed_hash_drifts(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    # Tamper with a sealed inventory after it was recorded.
    (ws.code_dir / "ANDROID_SOURCE_INVENTORY.json").write_text(
        '{"tampered": true}', encoding="utf-8"
    )
    assert _resume_materialized_overview(ws) is None


def test_resume_accepts_mutated_security_slice_execution_state(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    (ws.raw_dir / "security_slices.json").write_text(
        json.dumps({"slices": [{"id": "slice-1", "status": "completed"}]}),
        encoding="utf-8",
    )
    assert _resume_materialized_overview(ws) is not None


def test_resume_repairs_missing_evidence_script_without_materializing(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    (ws.code_dir / _EVIDENCE_READER_NAME).unlink()
    assert _resume_materialized_overview(ws) is not None
    assert (ws.code_dir / _EVIDENCE_READER_NAME).read_text(
        encoding="utf-8"
    ) == _EVIDENCE_READER_SOURCE


def test_resume_repairs_tampered_evidence_script_without_materializing(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    # A still-present but truncated reader must fail the gate, not merely pass
    # on existence: the coverage ledger sha256-verifies it byte-for-byte.
    (ws.code_dir / _EVIDENCE_READER_NAME).write_text(
        _EVIDENCE_READER_SOURCE[: len(_EVIDENCE_READER_SOURCE) // 2],
        encoding="utf-8",
    )
    assert _resume_materialized_overview(ws) is not None
    assert (ws.code_dir / _EVIDENCE_READER_NAME).read_text(
        encoding="utf-8"
    ) == _EVIDENCE_READER_SOURCE


def test_resume_recovers_completed_raw_checkpoint_when_meta_is_missing(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    progress = ws.meta.pop("android_pre_ai_progress")
    ws._save_meta()
    (ws.raw_dir / "ANDROID_PRE_AI_PROGRESS.json").write_text(
        json.dumps(progress), encoding="utf-8"
    )
    assert _resume_materialized_overview(ws) is not None


def test_resume_rejects_non_final_checkpoint(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    ws.meta["android_pre_ai_progress"]["final_materialization"] = False
    ws._save_meta()
    assert _resume_materialized_overview(ws) is None


def test_completed_checkpoint_survives_newer_incomplete_progress(tmp_path):
    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    _seal(ws)
    checkpoint = dict(ws.meta["android_pre_ai_progress"])
    checkpoint["updated_time_ns"] = 1
    ws.meta["android_pre_ai_checkpoint"] = checkpoint
    ws.meta["android_pre_ai_progress"] = {
        "materialization_complete": False,
        "updated_time_ns": 2,
        "completed": 10,
        "expected": 100,
    }
    ws._save_meta()
    assert _completed_materialization_progress(ws) == checkpoint
    assert _resume_materialized_overview(ws) is not None
