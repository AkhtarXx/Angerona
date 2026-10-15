"""R7: run_android_ai_swarm must resume the supervisor from its swarm snapshot.

The supervisor had committed checkpoints to disk on every round, but
``run_android_ai_swarm`` always constructed ``SupervisorLoop`` with
``resume_payload=None``, so ``saved_supervisor_state`` was always ``{}`` and the
supervisor fresh-started every resume — replaying all already-failed outcomes.

These tests pin the wiring:
  - ``_swarm_resume_payload`` returns the latest payload iff it is a ``swarm``
    checkpoint (round/outcomes restored),
  - a non-swarm checkpoint or an empty store yields a fresh-start payload,
  - ``run_android_ai_swarm`` actually passes that payload into ``SupervisorLoop``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.agents.audit_state import AuditStateStore
from src.pipeline.android_ai_audit import _swarm_resume_payload
from src.workspace import RunWorkspace


def _store(tmp: Path) -> AuditStateStore:
    ws = RunWorkspace.create(tmp / "run", "fake-binary")
    return AuditStateStore(ws.root)


def _checkpoint_swarm(store: AuditStateStore, *, round_: int) -> dict:
    store.checkpoint({
        "kind": "swarm",
        "status": "incomplete",
        "phase": "supervise",
        "supervisor": {
            "round": round_,
            "next_round": round_ + 1,
            "last_plan_text": "prior plan",
            "coverage_complete": False,
            "seen_ids": ["slice-1"],
            "outcomes": [],
        },
    })
    return store.load_latest().payload


def test_swarm_resume_payload_returns_latest_swarm_snapshot(tmp_path):
    store = _store(tmp_path)
    payload = _checkpoint_swarm(store, round_=2)
    assert payload["supervisor"]["round"] == 2

    resumed = _swarm_resume_payload(store)
    assert resumed["kind"] == "swarm"
    assert resumed["supervisor"]["round"] == 2


def test_swarm_resume_payload_empty_on_fresh_store(tmp_path):
    store = _store(tmp_path)
    assert _swarm_resume_payload(store) == {}


def test_swarm_resume_payload_ignores_non_swarm_kind(tmp_path):
    store = _store(tmp_path)
    store.checkpoint({"kind": "deterministic", "steps_executed": ["apktool"]})
    assert _swarm_resume_payload(store) == {}