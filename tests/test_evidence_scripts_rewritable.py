"""R5: evidence reader/adjudicator scripts must be re-writable on resume.

`materialize_android_ai_evidence` writes ANGERONA_EVIDENCE_READ.py and
ANGERONA_FINDING_ADJUDICATE.py then chmod(0o555) (read+execute only). On a
re-resume the function runs again and `write_text` on the read-only file
raises PermissionError, crashing resume. The fix makes the second write
succeed (reset write bit / atomic replace) before re-sealing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.pipeline.android_audit import AuditReport
from src.pipeline.android_ai_audit import materialize_android_ai_evidence


def _minimal_report(apk: Path) -> AuditReport:
    return AuditReport(
        apk_path=str(apk),
        status="completed",
        metadata={
            "audit_input_snapshot": {
                "path": str(apk),
                "sha256": "a" * 64,
                "size": apk.stat().st_size,
            },
            "artifact_validation": {"sha256": "a" * 64},
        },
    )


def test_evidence_scripts_survive_resume(tmp_path, monkeypatch):
    """Two calls of materialize_android_ai_evidence (resume simulate) must not
    raise PermissionError on the chmod(0o555) evidence scripts."""
    from src.workspace import RunWorkspace

    ws = RunWorkspace.create(tmp_path / "run", "fake-binary")
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 16)
    report = _minimal_report(apk)

    # Stub the heavy/external work so this is a focused test of the
    # evidence-script write+chmod path on resume.
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory.materialize_binary_evidence",
        lambda *a, **k: {"files": [], "file_count": 0, "native_cache_hits": 0},
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._source_inventory",
        lambda code_dir, binary_inventory=None: {
            "files": [], "file_count": 0, "truncated": False,
            "artifact_inventory_count": 0,
            "binary_review_required": 0,
            "binary_analysis_incomplete": [],
        },
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._security_slices",
        lambda inventory, report: {"slices": []},
    )
    # APK identity gate uses _sha256(apk); give a real small apk so it resolves.
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._sha256", lambda p: "a" * 64
    )

    # First materialization writes + chmod 0o555 the scripts.
    materialize_android_ai_evidence(ws, report)
    reader = ws.code_dir / "ANGERONA_EVIDENCE_READ.py"
    adjud = ws.code_dir / "ANGERONA_FINDING_ADJUDICATE.py"
    assert reader.is_file()
    assert adjud.is_file()

    # Second materialization (resume) must NOT raise PermissionError.
    materialize_android_ai_evidence(ws, report)
    assert reader.is_file()
    assert adjud.is_file()
