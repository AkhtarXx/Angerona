"""R1/R2: capture_tree (debug-only observability) must NOT be fatal to the audit.

`observed_progress_run` calls `capture_tree(workspace)` for a before/after
filesystem change-diff. capture_tree raises `ObservabilityError` when the
workspace exceeds the file limit. This is a DEBUG-ONLY observation feature;
its failure must degrade to a skipped tree-delta, NOT crash the disassembly
/ pre-AI materialization that wraps it.

These tests pin:
  - current buggy behavior (capture_tree raises above the limit), and
  - the fixed behavior (observed_progress_run survives it and still returns
    the subprocess result).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from src.observability import ObservabilityError, capture_tree
from src.subprocess_observability import observed_progress_run


def _make_workspace(root: Path, *, n_files: int) -> Path:
    """A minimal RunWorkspace-shaped dir (run.json + code/ + docs/ + raw/)."""
    for name in ("code", "docs", "raw"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "run.json").write_text(json.dumps({"binary": "/bin/true"}))
    bulk = root / "code" / "android_artifacts"
    bulk.mkdir(parents=True, exist_ok=True)
    for i in range(n_files):
        (bulk / f"f{i:06d}.txt").write_text("x")
    return root


def test_capture_tree_raises_above_file_limit(tmp_path):
    """Pin R1: capture_tree itself raises when the tree exceeds the limit."""
    ws = _make_workspace(tmp_path / "ws", n_files=5)
    with pytest.raises(ObservabilityError):
        capture_tree(ws, max_files=4)


def test_observed_progress_run_survives_capture_tree_limit(tmp_path, monkeypatch):
    """R1/R2 fix: when capture_tree hits its file limit, observed_progress_run
    must NOT crash — it returns the subprocess result and skips the tree-delta.

    capture_tree reads the file limit from os.environ (the PARENT process env),
    not the subprocess env, so we monkeypatch the env var directly.
    """
    ws = _make_workspace(tmp_path / "ws", n_files=20)
    progress = tmp_path / "progress.bin"
    progress.write_bytes(b"")
    # Force a tiny limit so capture_tree raises immediately (it reads os.environ).
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_TREE_MAX_FILES", "1")

    # /bin/true exits 0 immediately; the only thing that can fail this call is
    # the observation capture_tree raising through observed_progress_run.
    result = observed_progress_run(
        ["/bin/true"],
        progress_path=progress,
        idle_timeout=10.0,
        wall_timeout=10.0,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        observation_workspace=str(ws),
    )
    assert result.returncode == 0
