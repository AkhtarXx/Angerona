"""R10 — deterministic-phase checkpoint file (F9b).

The deterministic phase used to persist its report only at the very end, so a
crash mid-phase discarded every completed expensive stage (multi-hour IDA
disassembly, apktool decode, dex_semantic reconciliation, JADX decompile,
replay-bundle packaging). ``run_android_audit`` now writes
``android-audit.checkpoint.json`` after each EXPENSIVE stage so a resume can
replay completed work instead of re-running it.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from src.pipeline.android_audit import (
    _DETERMINISTIC_CHECKPOINT_NAME,
    _write_deterministic_checkpoint,
    run_android_audit,
)


def _mk_apk(path: Path, with_libs: bool = False) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 128)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        if with_libs:
            zf.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 128)
    return path


def _checkpoint_json(artifacts: Path) -> dict:
    return json.loads((artifacts / _DETERMINISTIC_CHECKPOINT_NAME).read_text())


def test_write_deterministic_checkpoint_is_atomic_and_structured(tmp_path):
    artifacts = tmp_path / "artifacts"

    class _Report:
        steps_executed = ["artifact-snapshot", "apktool_bridge"]
        steps_skipped = ["janus_signature:not-applicable"]
        status = "partial"

    written = _write_deterministic_checkpoint(
        artifacts,
        apk_sha256="a" * 64,
        report=_Report(),
        stages={"apktool_manifest": {"complete": True, "output": "/tmp/apktool"}},
        elapsed_seconds=12.345,
    )
    assert written == artifacts / _DETERMINISTIC_CHECKPOINT_NAME
    assert written.is_file()
    # No stray .tmp file left behind after os.replace.
    assert not written.with_suffix(".json.tmp").exists()

    payload = json.loads(written.read_text())
    assert payload["schema_version"] == 1
    assert payload["apk_sha256"] == "a" * 64
    assert payload["steps_executed"] == ["artifact-snapshot", "apktool_bridge"]
    assert payload["steps_skipped"] == ["janus_signature:not-applicable"]
    assert payload["status"] == "partial"
    assert payload["elapsed_seconds"] == 12.345
    assert payload["stages"]["apktool_manifest"] == {
        "complete": True,
        "output": "/tmp/apktool",
    }


def test_write_deterministic_checkpoint_noop_without_persistent_artifacts(tmp_path):
    written = _write_deterministic_checkpoint(
        None, apk_sha256="a" * 64, report=object(), stages={}, elapsed_seconds=0.0
    )
    assert written is None


def test_run_writes_checkpoint_after_expensive_stages(tmp_path, monkeypatch):
    """A completed deterministic run leaves a checkpoint recording the expensive
    stages that finished. No ``--go``/AI is involved — pure deterministic phase."""
    from src.analysis.apksigner_bridge import ApkSignerResult
    from src.analysis.apktool_bridge import ApktoolResult

    monkeypatch.setattr(
        "src.analysis.apksigner_bridge.verify_apk_signature",
        lambda *a, **kw: ApkSignerResult(
            status="verified", apk_path="/x", package_name="com.checkpoint.test"
        ),
    )
    # Force the synthetic/binary manifest path so no external decoder is needed.
    monkeypatch.setattr(
        "src.analysis.apktool_bridge.decode_apk",
        lambda *args, **kwargs: ApktoolResult(
            status="failed", apk_path=str(args[0]), note="synthetic manifest"
        ),
    )

    apk = _mk_apk(tmp_path / "cp.apk")
    artifacts = tmp_path / "artifacts"
    report = run_android_audit(
        apk, artifact_output_dir=artifacts, try_runtime_extract=False
    )

    checkpoint_path = artifacts / _DETERMINISTIC_CHECKPOINT_NAME
    assert checkpoint_path.is_file(), "deterministic checkpoint was not written"

    payload = _checkpoint_json(artifacts)
    assert payload["schema_version"] == 1
    assert len(payload["apk_sha256"]) == 64
    # The last, always-run stage must be recorded.
    assert "finding_evidence" in payload["steps_executed"]
    assert payload["stages"]["finding_evidence"]["complete"] is True
    # Earlier expensive stages that finished must also be present.
    assert payload["stages"]["apktool_manifest"]["complete"] is True
    assert payload["stages"]["dex_semantic"]["complete"] is True
    assert payload["stages"]["jadx"]["complete"] is True
    # The report's steps list is mirrored into the checkpoint.
    assert payload["steps_executed"] == report.steps_executed