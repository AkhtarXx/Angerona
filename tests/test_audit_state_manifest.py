"""R6: the per-worker `android_artifacts/` bulk tree must NOT be content-addressed
into the model-visible manifest every round.

A full JADX+apktool decompilation tree is ~35k files / 2.5 GiB. Content-addressing
it into every checkpoint's manifest means 35k read+hash+write per round and
tripped the old 20k-file manifest quota. The tree is model-READABLE (workers
shell/read into it on demand per the prompt) but should not be part of the
content-addressed manifest blob set.

These tests pin:
  - android_artifacts/ files are EXCLUDED from the manifest `files`,
  - the directory itself remains in `directories` (still model-readable),
  - the quota raise (250k/256GiB) accommodates large trees that ARE captured.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.agents.audit_state import AuditStateStore
from src.workspace import RunWorkspace


def _worker_ws(tmp: Path) -> Path:
    ws = RunWorkspace.create(tmp / "run", "fake-binary")
    art = ws.code_dir / "android_artifacts"
    art.mkdir(parents=True, exist_ok=True)
    # 25k tiny files — exceeds the OLD 20k quota, well under the new 250k.
    for i in range(25_000):
        (art / f"f{i:06d}.txt").write_text("x")
    # A normal model-visible file that MUST be captured.
    (ws.code_dir / "EXPORT_MANIFEST.json").write_text(json.dumps({"ok": True}))
    (ws.docs_dir / "progress.md").write_text("# progress\n")
    return ws.root


def test_manifest_excludes_android_artifacts_files(tmp_path):
    """R6 fix: capture_workspace omits android_artifacts/ files from the manifest."""
    root = _worker_ws(tmp_path)
    store = AuditStateStore(root)
    manifest = store.capture_workspace()

    paths = {entry["path"] for entry in manifest["files"]}
    # android_artifacts files must NOT be content-addressed.
    assert not any(p.startswith("code/android_artifacts/") for p in paths), (
        "android_artifacts bulk files leaked into manifest"
    )
    # normal model-visible files are still captured.
    assert "code/EXPORT_MANIFEST.json" in paths
    assert "docs/progress.md" in paths


def test_manifest_keeps_android_artifacts_directory_readable(tmp_path):
    """The android_artifacts dir stays in `directories` so workers can still
    shell/read into it; only its files are not content-addressed."""
    root = _worker_ws(tmp_path)
    store = AuditStateStore(root)
    manifest = store.capture_workspace()
    dirs = set(manifest["directories"])
    assert "code/android_artifacts" in dirs


def test_manifest_quota_accommodates_large_captured_tree(tmp_path):
    """R6 raise: the new 250k-file quota does not abort a legitimately large
    model-visible tree (one that is NOT excluded)."""
    root = _worker_ws(tmp_path)
    # Add a second large captured tree that is NOT excluded (under docs/).
    big = root / "docs" / "big"
    big.mkdir(parents=True, exist_ok=True)
    for i in range(5_000):
        (big / f"g{i:05d}.txt").write_text("y")
    store = AuditStateStore(root)
    manifest = store.capture_workspace()  # must not raise
    assert manifest["file_count"] >= 5_000
