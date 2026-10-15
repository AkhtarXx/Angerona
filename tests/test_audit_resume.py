"""Crash, pause, and exact-resume behavior for durable audit state."""

from __future__ import annotations

import json
import shutil
import types
from pathlib import Path

import pytest

from src.agents.audit_state import (
    AuditLeaseError,
    AuditStateError,
    AuditStateStore,
    ContextPolicyController,
    build_audit_identity,
)
from src.agents.loop import ConvergenceLoop
from src.agents.output_boundary import assess_agent_output
from src.agents.respawn_policy import POLICY_VERSION as RESPAWN_POLICY_VERSION, quality_failure
from src.agents.runtime import AgentResult
from src.agents.supervisor import SupervisorLoop, WorkerOutcome, WorkerSpec
from src.workspace import RunWorkspace


def _result(text: str) -> AgentResult:
    return AgentResult(
        ok=True,
        final_text=text,
        events=[],
        returncode=0,
        seconds=0.01,
    )


def test_snapshot_chain_is_immutable_and_corruption_fails_closed(tmp_path):
    store = AuditStateStore(tmp_path)
    first = store.checkpoint({"kind": "swarm", "status": "running", "value": 1})
    latest = store.checkpoint({"kind": "swarm", "status": "paused", "value": 2})
    assert first.path.is_file() and latest.path.is_file()
    assert store.load_latest().payload["value"] == 2

    # Crash residue is not a committed generation.
    (store.path / ".snapshot-orphan.tmp").write_text("partial")
    assert store.load_latest().generation == 2

    # Corrupting any committed parent invalidates the latest state. It must not
    # silently roll back to generation 1 or continue from generation 2.
    first.path.write_bytes(first.path.read_bytes() + b"\n")
    with pytest.raises(AuditStateError, match="checksum mismatch"):
        store.load_latest()
    store.close()


def test_durable_head_detects_deleted_latest_generation(tmp_path):
    store = AuditStateStore(tmp_path)
    store.checkpoint({"kind": "swarm", "value": 1})
    latest = store.checkpoint({"kind": "swarm", "value": 2})
    latest.path.unlink()
    with pytest.raises(AuditStateError, match="head references a missing snapshot"):
        store.load_latest()
    store.close()


def test_checkpoint_refuses_append_when_head_target_was_deleted(tmp_path):
    store = AuditStateStore(tmp_path)
    store.checkpoint({"kind": "swarm", "value": 1})
    latest = store.checkpoint({"kind": "swarm", "value": 2})
    latest.path.unlink()
    with pytest.raises(AuditStateError, match="head references a missing snapshot"):
        store.checkpoint({"kind": "swarm", "value": 3})
    store.close()


def test_new_snapshot_chain_refuses_missing_head(tmp_path):
    store = AuditStateStore(tmp_path)
    store.checkpoint({"kind": "swarm", "value": 1})
    (store.path / "audit-head.json").unlink()
    with pytest.raises(AuditStateError, match="head is missing"):
        store.load_latest()
    store.close()


def test_content_addressed_reports_are_deduplicated_and_verified(tmp_path):
    store = AuditStateStore(tmp_path)
    ref1 = store.put_blob(b"same large worker report")
    ref2 = store.put_blob(b"same large worker report")
    assert ref1 == ref2
    assert store.get_blob(ref1) == b"same large worker report"
    assert len(list(store.path.glob("blob-*.bin"))) == 1

    blob = store.path / ref1["name"]
    blob.write_bytes(b"substituted")
    with pytest.raises(AuditStateError, match="checksum mismatch"):
        store.get_blob(ref1)
    store.close()


def test_put_blob_repairs_deleted_cached_blob(tmp_path):
    store = AuditStateStore(tmp_path)
    ref = store.put_blob(b"critical durable state")
    (store.path / ref["name"]).unlink()

    repeated = store.put_blob(b"critical durable state")

    assert repeated == ref
    assert store.get_blob(repeated) == b"critical durable state"
    store.close()


def test_checkpoint_refuses_corrupt_nested_blob_reference(tmp_path):
    store = AuditStateStore(tmp_path)
    ref = store.put_blob(b"critical durable state")
    (store.path / ref["name"]).write_bytes(b"corrupt")

    with pytest.raises(AuditStateError, match="checksum mismatch"):
        store.checkpoint({"nested": {"report_ref": ref}})
    assert store.load_latest() is None
    store.close()


def _context_observation(
    *, limit: int, configured: int, model: str = "pinned-model"
) -> dict:
    output = 2_000
    total = limit + 1_000
    return {
        "source": "typed_provider_error",
        "agent_family": "claude",
        "model_name": model,
        "configured_context_window_tokens": configured,
        "context_limit_tokens": limit,
        "requested_total_tokens": total,
        "requested_input_tokens": total - output,
        "requested_output_tokens": output,
    }


def test_context_policy_promotes_and_restores_provider_limit(tmp_path):
    base = "a" * 64
    store = AuditStateStore(tmp_path)
    genesis = store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    assert genesis.version == 0 and genesis.windows["claude"] == 128_000

    promoted, changed = store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=256_000, configured=128_000),
    )
    assert changed is True
    assert promoted.version == 1 and promoted.windows["claude"] == 256_000
    store.close()

    reopened = AuditStateStore(tmp_path)
    restored = reopened.load_context_policy(required=True)
    assert restored is not None
    assert restored.initial_windows["claude"] == 128_000
    assert restored.windows["claude"] == 256_000
    assert restored.genesis_digest == genesis.genesis_digest
    reopened.close()


def test_context_policy_controller_updates_the_next_dispatch_window(tmp_path):
    base = "e" * 64
    store = AuditStateStore(tmp_path)
    genesis = store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    controller = ContextPolicyController(
        store, base_contract_sha256=base, snapshot=genesis
    )
    first_dispatch_window = controller.window("claude")
    promotions = controller.observe(
        "claude",
        [_context_observation(limit=256_000, configured=first_dispatch_window)],
    )
    second_dispatch_window = controller.window("claude")

    assert first_dispatch_window == 128_000
    assert [snapshot.version for snapshot in promotions] == [1]
    assert second_dispatch_window == 256_000
    assert store.load_context_policy(required=True).windows["claude"] == 256_000
    store.close()


def test_context_policy_rejects_stale_expansion_but_accepts_stale_tightening(tmp_path):
    base = "b" * 64
    store = AuditStateStore(tmp_path)
    store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=256_000, configured=128_000),
    )
    unchanged, changed = store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=300_000, configured=128_000),
    )
    assert changed is False and unchanged.windows["claude"] == 256_000

    tightened, changed = store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=64_000, configured=128_000),
    )
    assert changed is True and tightened.windows["claude"] == 64_000
    store.close()


def test_concurrent_context_observations_converge_to_safe_window(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    base = "1" * 64
    store = AuditStateStore(tmp_path)
    genesis = store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    controller = ContextPolicyController(
        store, base_contract_sha256=base, snapshot=genesis
    )
    observations = [
        _context_observation(limit=256_000, configured=128_000),
        _context_observation(limit=64_000, configured=128_000),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda value: controller.observe("claude", [value]), observations))

    assert controller.window("claude") == 64_000
    assert store.load_context_policy(required=True).windows["claude"] == 64_000
    store.close()


def test_context_policy_isolated_by_agent_and_model_profile(tmp_path):
    base = "3" * 64
    store = AuditStateStore(tmp_path)
    store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000, "codex": 256_000},
        profiles={
            "claude": {"model_name": "claude-model"},
            "codex": {"model_name": "codex-model"},
        },
    )
    observation = _context_observation(
        limit=64_000, configured=128_000, model="claude-model"
    )
    promoted, changed = store.promote_context_window(
        base_contract_sha256=base, agent="claude", observation=observation
    )
    assert changed
    assert promoted.windows == {"claude": 64_000, "codex": 256_000}
    with pytest.raises(AuditStateError, match="identity is not trusted"):
        store.promote_context_window(
            base_contract_sha256=base, agent="codex", observation=observation
        )
    store.close()


def test_context_policy_poisoning_and_chain_corruption_fail_closed(tmp_path):
    base = "c" * 64
    store = AuditStateStore(tmp_path)
    store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 256_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    with pytest.raises(AuditStateError, match="identity is not trusted"):
        store.promote_context_window(
            base_contract_sha256=base,
            agent="claude",
            observation=_context_observation(
                limit=128_000, configured=256_000, model="attacker-model"
            ),
        )
    assert store.load_context_policy(required=True).version == 0

    promoted, _ = store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=128_000, configured=256_000),
    )
    record = store.path / f"context-policy-{promoted.version:012d}-{promoted.digest}.json"
    record.write_bytes(record.read_bytes() + b"\n")
    with pytest.raises(AuditStateError, match="checksum mismatch"):
        store.load_context_policy(required=True)
    store.close()


def test_context_policy_missing_required_head_fails_closed(tmp_path):
    store = AuditStateStore(tmp_path)
    store.initialize_context_policy(
        base_contract_sha256="d" * 64,
        initial_windows={"codex": 128_000},
        profiles={"codex": {"model_name": "pinned-model"}},
    )
    (store.path / "context-policy-head.json").unlink()
    with pytest.raises(AuditStateError, match="head is missing"):
        store.load_context_policy(required=True)
    store.close()


def test_context_policy_rolls_forward_from_stale_head(tmp_path):
    base = "2" * 64
    store = AuditStateStore(tmp_path)
    genesis = store.initialize_context_policy(
        base_contract_sha256=base,
        initial_windows={"claude": 128_000},
        profiles={"claude": {"model_name": "pinned-model"}},
    )
    promoted, _ = store.promote_context_window(
        base_contract_sha256=base,
        agent="claude",
        observation=_context_observation(limit=256_000, configured=128_000),
    )
    # Simulate a crash/rollback after the immutable transition reached disk but
    # before its mutable head pointer became durable.
    store._write_context_policy_head(0, genesis.digest, base)

    rolled_forward = store.load_context_policy(required=True)
    assert rolled_forward.version == promoted.version == 1
    assert rolled_forward.digest == promoted.digest
    assert rolled_forward.windows["claude"] == 256_000
    store.close()


def test_pause_resume_control_and_exclusive_live_lease(tmp_path):
    owner = AuditStateStore(tmp_path)
    contender = AuditStateStore(tmp_path)
    owner.acquire_lease()
    assert contender.lease_active() is True
    with pytest.raises(AuditLeaseError, match="already active"):
        contender.acquire_lease()

    owner.request_pause("operator")
    assert contender.pause_requested() is True
    contender.request_resume("continue")
    assert owner.pause_requested() is False
    owner.release_lease()
    assert contender.lease_active() is False
    contender.acquire_lease()
    contender.close()
    owner.close()


def test_operator_instruction_mailbox_is_verified_scoped_and_ordered(tmp_path):
    store = AuditStateStore(tmp_path)
    first = store.request_operator_instruction(
        "Re-check the JADX gap before accepting coverage.",
        scope="future-dispatches",
    )
    store.request_operator_instruction(
        "Surface every unresolved tool failure in the final report.",
        scope="final-report",
    )
    records = store.operator_instructions()
    assert [item["scope"] for item in records] == [
        "future-dispatches", "final-report",
    ]
    assert records[0]["instruction"].startswith("Re-check the JADX")
    assert records[0]["created_ns"] < records[1]["created_ns"]

    first.write_bytes(first.read_bytes() + b"\n")
    with pytest.raises(AuditStateError, match="checksum mismatch"):
        store.operator_instructions()
    store.close()


def test_supervisor_adopts_operator_instruction_by_safe_point_scope(tmp_path):
    ws = RunWorkspace.create(tmp_path / "runs", "/bin/true")
    store = AuditStateStore(ws.root)
    store.request_operator_instruction(
        "Inspect the deferred loader path again.", scope="future-dispatches"
    )
    store.request_operator_instruction(
        "List the failed tool and exact limitation.", scope="final-report"
    )
    supervisor = SupervisorLoop(
        binary="/bin/true",
        objective="x",
        overview="overview",
        workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        strict_verify=False,
        state_store=store,
    )

    worker_block = supervisor._operator_instruction_block("worker")
    final_block = supervisor._operator_instruction_block("final-report")
    assert "deferred loader path" in worker_block
    assert "failed tool and exact limitation" not in worker_block
    assert "failed tool and exact limitation" in final_block
    assert "deferred loader path" not in final_block
    assert "cannot override target identity" in worker_block
    store.close()


def test_identity_allows_relocation_but_rejects_changed_target_or_artifact(tmp_path):
    ws = RunWorkspace.create(tmp_path / "runs", "/bin/true")
    (ws.code_dir / "analysis.json").write_text('{"stable": true}')
    identity = build_audit_identity(
        workspace_root=ws.root,
        binary="/bin/true",
        critical_artifacts=["code/analysis.json"],
    )
    store = AuditStateStore(ws.root)

    relocated = tmp_path / "relocated-target"
    shutil.copy2("/bin/true", relocated)
    assert store.validate_identity(identity, binary_override=relocated) == str(relocated.resolve())

    relocated.write_bytes(relocated.read_bytes() + b"changed")
    with pytest.raises(AuditStateError, match="does not match"):
        store.validate_identity(identity, binary_override=relocated)
    (ws.code_dir / "analysis.json").write_text('{"stable": false}')
    with pytest.raises(AuditStateError, match="artifact changed"):
        store.validate_identity(identity)
    store.close()


def test_workspace_open_preserves_artifacts_and_status(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    original = (ws.docs_dir / "progress.md").read_text()
    ws.pause(phase="test-boundary", note="hold")

    reopened = RunWorkspace.open(ws.root)
    assert (reopened.docs_dir / "progress.md").read_text().startswith(original)
    assert reopened.meta["status"] == "paused"
    reopened.resume(generation=7)
    assert reopened.meta["status"] == "running"
    assert reopened.meta["resume_generation"] == 7


def test_worker_resume_continues_at_next_committed_round(monkeypatch, tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    (ws.code_dir / "all_decompiled.c").write_text("committed binary view")
    analyst_tasks: list[str] = []
    review_count = 0
    pause_checks = 0

    def dispatch(_agent, task, system_prompt, _on_event):
        nonlocal review_count
        if "REVIEW_VERDICT" in system_prompt:
            review_count += 1
            verdict = "NEEDS_WORK" if review_count == 1 else "SATISFIED"
            if verdict == "NEEDS_WORK":
                return _result(
                    "## Gaps to address\n- deepen evidence\n"
                    "REVIEW_VERDICT: NEEDS_WORK"
                )
            return _result("## Verification\nevidence is complete\nREVIEW_VERDICT: SATISFIED")
        analyst_tasks.append(task)
        return _result(f"report-{len(analyst_tasks)}")

    def pause_after_first_round():
        nonlocal pause_checks
        pause_checks += 1
        return pause_checks >= 2

    first = ConvergenceLoop(
        binary="/bin/true",
        objective="exact objective",
        workspace=ws,
        dispatch=dispatch,
        max_rounds=2,
        strict_verify=False,
        pause_requested=pause_after_first_round,
    )
    monkeypatch.setattr(first, "_verify_understanding_step", lambda *_: (True, ""))
    paused = first.run()
    assert paused.paused is True and paused.rounds == 1
    assert len(analyst_tasks) == 1
    paused_state = AuditStateStore(ws.root)
    paused_snapshot = paused_state.load_latest()
    manifest_paths = {
        entry["path"] for entry in paused_snapshot.payload["workspace_manifest"]["files"]
    }
    assert "run.json" in manifest_paths
    committed_visible = {
        entry["path"]: paused_state.get_blob(entry["blob"])
        for entry in paused_snapshot.payload["workspace_manifest"]["files"]
        if entry["path"] in {"run.json", "docs/progress.md"}
    }
    paused_state.close()

    # Simulate a killed attempt changing model-visible files after the last
    # snapshot. Resume must restore/quarantine them and exclude uncommitted memory.
    (ws.code_dir / "all_decompiled.c").write_text("tampered crash residue")
    (ws.code_dir / "uncommitted-note.txt").write_text("must be quarantined")
    (ws.docs_dir / "lessons.md").write_text("- rogue uncommitted lesson\n")

    reopened = RunWorkspace.open(ws.root)
    reopened.resume()
    second = ConvergenceLoop(
        binary="/bin/true",
        objective="exact objective",
        workspace=reopened,
        dispatch=dispatch,
        max_rounds=2,
        strict_verify=False,
        pause_requested=lambda: False,
    )
    monkeypatch.setattr(second, "_verify_understanding_step", lambda *_: (True, ""))
    previous_dispatch = second.dispatch

    def exact_dispatch(*args, **kwargs):
        task = args[1]
        system_prompt = args[2]
        if "REVIEW_VERDICT" not in system_prompt and "REVISION round 2" in task:
            for relative, expected in committed_visible.items():
                assert (ws.root / relative).read_bytes() == expected
        return previous_dispatch(*args, **kwargs)

    second.dispatch = exact_dispatch
    resumed = second.run()
    assert resumed.converged is True and resumed.rounds == 2
    assert len(analyst_tasks) == 2
    assert "REVISION round 2" in analyst_tasks[1]
    assert "report-1" in analyst_tasks[1]
    assert "rogue uncommitted lesson" not in analyst_tasks[1]
    assert (ws.docs_dir / "lessons.md").read_text().splitlines()[0].startswith(
        "# Reflexion lesson log (Part 18 P1)"
    )
    assert (ws.code_dir / "all_decompiled.c").read_text() == "committed binary view"
    assert not (ws.code_dir / "uncommitted-note.txt").exists()
    assert list((ws.root.parent / ".angerona-recovery").rglob("uncommitted-note.txt"))


def test_worker_resume_rejects_configuration_drift(monkeypatch, tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    loop = ConvergenceLoop(
        binary="/bin/true",
        objective="fixed",
        workspace=ws,
        dispatch=lambda *_: _result("unused"),
        max_rounds=2,
        pause_requested=lambda: True,
    )
    loop.run()
    changed = ConvergenceLoop(
        binary="/bin/true",
        objective="changed",
        workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_: _result("unused"),
        max_rounds=2,
    )
    with pytest.raises(AuditStateError, match="configuration does not match"):
        changed.run()

    changed_search = ConvergenceLoop(
        binary="/bin/true",
        objective="fixed",
        workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_: _result("unused"),
        max_rounds=2,
        k_candidates=2,
    )
    with pytest.raises(AuditStateError, match="configuration does not match"):
        changed_search.run()


def test_worker_objective_is_pinned_when_peer_blackboard_changes(tmp_path):
    parent = RunWorkspace.create(tmp_path / "parent", "/bin/true")
    worker = RunWorkspace.create(parent.root / "workers", "w1")
    supervisor = SupervisorLoop(
        binary="/bin/true",
        objective="root",
        overview="overview",
        workspace=parent,
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        spawn_strategy="llm",
        topo_strategy="fixed",
    )
    supervisor._blackboard = parent.root / "blackboard.md"
    supervisor._blackboard.write_text("# blackboard\n\n## peer-old\nverified old context\n")
    spec = WorkerSpec(id="w1", title="slice", objective="inspect it")
    original = supervisor._worker_resume_objective(worker, spec)
    assert "verified old context" in original

    supervisor._blackboard.write_text("# blackboard\n\n## peer-new\nnew concurrent context\n")
    restored = supervisor._worker_resume_objective(worker, spec)
    assert restored == original
    assert "new concurrent context" not in restored


def test_supervisor_resume_runs_only_pending_worker_and_rebuilds_context(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    w1 = WorkerSpec(id="w1", title="first", objective="one")
    w2 = WorkerSpec(id="w2", title="second", objective="two")
    payload = {
        "kind": "swarm",
        "status": "paused",
        "supervisor": {
            "round": 1,
            "next_round": 1,
            "last_plan_text": "saved plan",
            "coverage_complete": True,
            "seen_ids": ["w1"],
            "retried_fingerprints": [],
            "active_plan": {
                "round": 1,
                "plan": {
                    "coverage_complete": True,
                    "workers": [
                        SupervisorLoop._spec_json(w1),
                        SupervisorLoop._spec_json(w2),
                    ],
                },
            },
            "worker_workspaces": {},
            # Inline report proves compatibility with the first checkpoint schema.
            "outcomes": [{
                "spec": SupervisorLoop._spec_json(w1),
                "converged": True,
                "rounds": 1,
                "report": "durable-first-report",
                "output_boundary": assess_agent_output(
                    "durable-first-report", role="worker_report"
                ).as_dict(),
                "workspace_root": "/saved/w1",
                "paused": False,
            }],
        },
    }
    snapshot = store.checkpoint(payload)
    (ws.root / "blackboard.md").write_text("stale duplicate durable-first-report\n")
    (ws.root / "global_lessons.md").write_text("stale lessons\n")
    worker_calls: list[str] = []

    def dispatch(_agent, _task, system_prompt, _on_event, **_kwargs):
        assert "consolidated" in system_prompt.lower() or "supervisor" in system_prompt.lower()
        return _result("final-report")

    supervisor = SupervisorLoop(
        binary="/bin/true",
        objective="x",
        overview="overview",
        workspace=ws,
        dispatch=dispatch,
        max_supervisor_rounds=1,
        max_worker_rounds=1,
        spawn_strategy="llm",
        topo_strategy="fixed",
        strict_verify=False,
        state_store=store,
        resume_payload=snapshot.payload,
    )

    def fake_worker(_self, spec, _k=None):
        worker_calls.append(spec.id)
        return WorkerOutcome(
            spec=spec,
            converged=True,
            rounds=1,
            report="durable-second-report",
            workspace_root="/saved/w2",
        )

    supervisor._run_one_worker = types.MethodType(fake_worker, supervisor)
    result = supervisor.run()
    assert worker_calls == ["w2"]
    assert [outcome.spec.id for outcome in result.workers] == ["w1", "w2"]
    blackboard = (ws.root / "blackboard.md").read_text()
    assert "stale duplicate" not in blackboard
    assert blackboard.count("durable-first-report") == 1
    assert blackboard.count("durable-second-report") == 1
    latest = store.load_latest()
    outcomes = latest.payload["supervisor"]["outcomes"]
    assert all("report_ref" in outcome and "report" not in outcome for outcome in outcomes)
    store.close()


def test_paused_adaptive_respawn_is_committed_and_resumed(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    initial = store.checkpoint({
        "kind": "swarm",
        "respawn_policy_version": RESPAWN_POLICY_VERSION,
        "status": "running",
        "supervisor": {},
    })

    def dispatch(_agent, task, system_prompt, _on_event, **_kwargs):
        if "WORK UNITS" in task or "plan" in system_prompt.lower():
            return _result(
                '```plan\n{"coverage_complete": false, "workers": '
                '[{"id":"w1","title":"first","functions":["f1"],'
                '"objective":"inspect"}]}\n```'
            )
        return _result("final")

    first_calls: list[str] = []
    first = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        spawn_strategy="llm", topo_strategy="fixed", strict_verify=False,
        state_store=store, resume_payload=initial.payload,
    )

    def first_worker(_self, spec, _k=None):
        first_calls.append(spec.id)
        return WorkerOutcome(
            spec=spec,
            converged=False,
            rounds=1,
            report="failed" if spec.id == "w1" else "paused retry",
            workspace_root=f"/saved/{spec.id}",
            paused=spec.id != "w1",
        )

    first._run_one_worker = types.MethodType(first_worker, first)
    paused = first.run()
    assert paused.paused is True
    assert any(worker_id.startswith("w1_r") for worker_id in first_calls)
    paused_snapshot = store.load_latest()
    assert paused_snapshot.payload["supervisor"]["active_plan"]["mode"] == "adaptive_respawn"

    # A newly generated machine slice must not mutate the already committed
    # respawn transaction during resume.
    (ws.raw_dir / "security_slices.json").write_text(json.dumps({
        "slices": [{
            "slice_id": "slice-new", "status": "candidate",
            "risk": {"severity": "HIGH", "category": "new"},
            "source": {"name": "src"}, "sink": {"name": "sink"},
            "reconstruction_targets": [],
        }],
    }))

    resumed_calls: list[str] = []
    second = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=RunWorkspace.open(ws.root),
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        spawn_strategy="llm", topo_strategy="fixed", strict_verify=False,
        state_store=store, resume_payload=paused_snapshot.payload,
    )

    def resumed_worker(_self, spec, _k=None):
        resumed_calls.append(spec.id)
        return WorkerOutcome(
            spec=spec, converged=True, rounds=1, report="retry complete",
            workspace_root=f"/saved/{spec.id}",
        )

    second._run_one_worker = types.MethodType(resumed_worker, second)
    second.run()
    assert resumed_calls and all(worker_id.startswith("w1_r") for worker_id in resumed_calls)
    assert not any(worker_id.startswith("sec_") for worker_id in resumed_calls)
    store.close()


def test_resume_reconciles_committed_failed_active_plan_into_adaptive_retry(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    failed = WorkerSpec(id="w1", title="failed", objective="inspect")
    snapshot = store.checkpoint({
        "kind": "swarm",
        "respawn_policy_version": RESPAWN_POLICY_VERSION,
        "status": "running",
        "supervisor": {
            "round": 1,
            "next_round": 1,
            "coverage_complete": False,
            "seen_ids": ["w1"],
            "retried_fingerprints": [],
            "active_plan": {
                "round": 1,
                "plan": {
                    "coverage_complete": False,
                    "workers": [SupervisorLoop._spec_json(failed)],
                },
            },
            "worker_workspaces": {},
            "outcomes": [{
                "spec": SupervisorLoop._spec_json(failed),
                "converged": False,
                "rounds": 1,
                "report": "committed failure",
                "workspace_root": "/saved/w1",
                "paused": False,
                "failure": quality_failure(stage="reviewer").as_dict(),
            }],
        },
    })
    worker_calls: list[str] = []
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("consolidated"),
        max_supervisor_rounds=1, max_worker_rounds=1,
        spawn_strategy="llm", topo_strategy="fixed", strict_verify=False,
        state_store=store, resume_payload=snapshot.payload,
    )

    def retry_worker(_self, spec, _k=None):
        worker_calls.append(spec.id)
        return WorkerOutcome(
            spec=spec, converged=True, rounds=1, report="retry complete",
            workspace_root=f"/saved/{spec.id}",
        )

    supervisor._run_one_worker = types.MethodType(retry_worker, supervisor)
    result = supervisor.run()
    assert worker_calls == ["w1_r1"]
    assert [outcome.spec.id for outcome in result.workers] == ["w1", "w1_r1"]
    store.close()


def test_resume_does_not_recursively_respawn_completed_retry_transaction(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    retry = WorkerSpec(id="w1_r1", title="retry", objective="inspect")
    snapshot = store.checkpoint({
        "kind": "swarm", "status": "running",
        "supervisor": {
            "round": 1, "next_round": 1, "coverage_complete": False,
            "seen_ids": [retry.id], "retried_fingerprints": ["already"],
            "active_plan": {
                "round": 1, "mode": "adaptive_respawn",
                "plan": {
                    "coverage_complete": False,
                    "workers": [SupervisorLoop._spec_json(retry)],
                },
            },
            "worker_workspaces": {},
            "outcomes": [{
                "spec": SupervisorLoop._spec_json(retry), "converged": False,
                "rounds": 1, "report": "retry failed",
                "workspace_root": "/saved/w1_r1", "paused": False,
            }],
        },
    })
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("consolidated"),
        max_supervisor_rounds=1, spawn_strategy="llm", topo_strategy="fixed",
        strict_verify=False, state_store=store, resume_payload=snapshot.payload,
    )

    def unexpected_worker(*_args, **_kwargs):
        raise AssertionError("completed adaptive transaction must not recursively retry")

    supervisor._run_one_worker = unexpected_worker
    result = supervisor.run()
    assert [outcome.spec.id for outcome in result.workers] == ["w1_r1"]
    store.close()


def test_partial_active_plan_reconciles_committed_and_pending_slice_statuses(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    (ws.raw_dir / "security_slices.json").write_text(json.dumps({
        "slices": [
            {"slice_id": "slice-1", "status": "candidate"},
            {"slice_id": "slice-2", "status": "candidate"},
        ],
    }))
    store = AuditStateStore(ws.root)
    s1 = WorkerSpec(id="s1", title="first", objective="one", slice_id="slice-1")
    s2 = WorkerSpec(id="s2", title="second", objective="two", slice_id="slice-2")
    snapshot = store.checkpoint({
        "kind": "swarm", "status": "running",
        "supervisor": {
            "round": 1, "next_round": 1, "coverage_complete": True,
            "seen_ids": ["s1"], "retried_fingerprints": [],
            "active_plan": {
                "round": 1,
                "plan": {
                    "coverage_complete": True,
                    "workers": [
                        SupervisorLoop._spec_json(s1),
                        SupervisorLoop._spec_json(s2),
                    ],
                },
            },
            "worker_workspaces": {},
            "outcomes": [{
                "spec": SupervisorLoop._spec_json(s1), "converged": True,
                "rounds": 1, "report": "CONFIRMED: first path",
                "output_boundary": assess_agent_output(
                    "CONFIRMED: first path", role="worker_report"
                ).as_dict(),
                "workspace_root": "/saved/s1", "paused": False,
            }],
        },
    })
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("consolidated"),
        max_supervisor_rounds=1, spawn_strategy="llm", topo_strategy="fixed",
        strict_verify=False, state_store=store, resume_payload=snapshot.payload,
    )

    def finish_pending(_self, spec, _k=None):
        assert spec.id == "s2"
        return WorkerOutcome(
            spec=spec, converged=True, rounds=1, report="CONFIRMED: second path",
            workspace_root="/saved/s2",
        )

    supervisor._run_one_worker = types.MethodType(finish_pending, supervisor)
    result = supervisor.run()
    assert [outcome.spec.id for outcome in result.workers] == ["s1", "s2"]
    slices = json.loads((ws.raw_dir / "security_slices.json").read_text())["slices"]
    assert {item["slice_id"]: item["status"] for item in slices} == {
        "slice-1": "confirmed", "slice-2": "confirmed",
    }
    validation = json.loads((ws.raw_dir / "validation_status.json").read_text())
    assert validation["summary"]["blocking_slice_ids"] == []
    assert (ws.root / "blackboard.md").read_text().count("## s1 ") == 1
    store.close()


def test_cli_exposes_status_pause_and_resume_commands():
    from src.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["audit-status", "/tmp/run"]).cmd == "audit-status"
    assert parser.parse_args(["audit-pause", "/tmp/run"]).cmd == "audit-pause"
    instruction = parser.parse_args([
        "audit-instruct", "/tmp/run", "retry the JADX evidence producer",
        "--scope", "future-dispatches",
    ])
    assert instruction.cmd == "audit-instruct"
    assert instruction.scope == "future-dispatches"
    resume = parser.parse_args(["audit-resume", "/tmp/run", "--binary", "/tmp/target"])
    assert resume.cmd == "audit-resume"
    assert resume.binary == "/tmp/target"


def test_web_status_preserves_explicit_paused_state():
    from src.web.server import _infer_status

    assert _infer_status({"status": "paused"}, {}, live=None) == "paused"
    assert _infer_status(
        {"status": "paused"}, {}, live={"finished": False}
    ) == "running"


def test_incomplete_checkpoint_is_terminal_for_supervisor_and_web(tmp_path):
    from src.web.server import _summarize_run

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    ws.meta["exact_resume_ready"] = True
    ws.meta["finished"] = "now"
    ws.meta["converged"] = False
    ws._save_meta()
    store = AuditStateStore(ws.root)
    snapshot = store.checkpoint({
        "kind": "swarm",
        "status": "incomplete",
        "final_report": "terminal-report",
        "converged": False,
        "incomplete_reason": "post_report_verification_artifact_unreadable",
        "supervisor": {"round": 2, "outcomes": []},
    })
    dispatched = []

    def dispatch(*args, **kwargs):
        dispatched.append((args, kwargs))
        raise AssertionError("terminal audit must not dispatch")

    loop = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=dispatch, strict_verify=False, state_store=store,
        resume_payload=snapshot.payload,
    )
    result = loop.run()
    assert result.terminal_status == "incomplete"
    assert result.final_report == "terminal-report"
    assert dispatched == []
    assert _summarize_run(ws.root)["resumable"] is False
    store.close()


def test_execution_contract_detects_runtime_drift(monkeypatch, tmp_path):
    from src.agents.run_contract import build_run_contract, validate_run_contract

    class MinimalConfig:
        engine = "ghidra"
        state_dir = tmp_path / "state"
        ghidra_install = None
        java_home = None
        sandbox = False

    monkeypatch.setenv("ANGERONA_CLAUDE_CMD", "/bin/true")
    binary = tmp_path / "target"
    binary.write_bytes(b"target")
    kwargs = {
        "config": MinimalConfig(),
        "binary": str(binary),
        "model": "pinned-model-id",
        "supervisor": "claude",
        "worker_analyst": "claude",
        "worker_reviewer": "claude",
        "idle_timeout": 300.0,
        "wall_timeout": 1800.0,
    }
    expected = build_run_contract(**kwargs)
    source_paths = {entry["path"] for entry in expected["source"]["files"]}
    assert "analysis/verify.py" in source_paths
    assert "engines/ghidra.py" in source_paths
    assert "secure_artifacts.py" in source_paths
    assert set(expected["agents"]) == {"claude"}
    validate_run_contract(expected, build_run_contract(**kwargs))

    changed = build_run_contract(**{**kwargs, "wall_timeout": 900.0})
    with pytest.raises(AuditStateError, match="execution contract changed"):
        validate_run_contract(expected, changed)

    for key in (
        "ANGERONA_CONTEXT_RECENT_CAPSULE_CHARS",
        "ANGERONA_TOOL_OUTPUT_PREVIEW_CHARS",
        "ANGERONA_AGENT_FS_SANDBOX",
        "ANGERONA_TRANSIENT_MAX_ATTEMPTS",
    ):
        value = "0" if key.endswith("FS_SANDBOX") else (
            "5" if key.endswith("MAX_ATTEMPTS") else "9000"
        )
        monkeypatch.setenv(key, value)
        with pytest.raises(AuditStateError, match="execution contract changed"):
            validate_run_contract(expected, build_run_contract(**kwargs))
        monkeypatch.delenv(key)

    for key, value in (("MCP_TIMEOUT", "123"), ("MCP_TOOL_TIMEOUT", "456")):
        monkeypatch.setenv(key, value)
        with pytest.raises(AuditStateError, match="execution contract changed"):
            validate_run_contract(expected, build_run_contract(**kwargs))
        monkeypatch.delenv(key)

    for key in (
        "ANGERONA_AGENT_MODEL", "ANGERONA_CLAUDE_MODEL",
        "ANGERONA_LOCAL_MODEL_NAME", "ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)
    unresolved = build_run_contract(**{**kwargs, "model": None})
    with pytest.raises(AuditStateError, match="unresolved provider-default"):
        validate_run_contract(unresolved, unresolved)


def test_execution_contract_pins_context_window_across_learned_profile(
    monkeypatch, tmp_path
):
    from src.agents.context_harness import ContextHarnessConfig
    from src.agents.run_contract import build_run_contract, validate_run_contract

    class MinimalConfig:
        engine = "ghidra"
        state_dir = tmp_path / "state"
        ghidra_install = None
        java_home = None
        sandbox = False

    monkeypatch.setenv("ANGERONA_CLAUDE_CMD", "/bin/true")
    monkeypatch.setenv("ANGERONA_CODEX_CMD", "/bin/true")
    monkeypatch.setenv("ANGERONA_CODEX_MODEL", "pinned-codex-model")
    monkeypatch.setenv("ANGERONA_CONTEXT_PROFILE_DIR", str(tmp_path / "profiles"))
    binary = tmp_path / "target"
    binary.write_bytes(b"target")
    kwargs = {
        "config": MinimalConfig(), "binary": str(binary), "model": "pinned-model",
        "supervisor": "claude", "worker_analyst": "claude",
        "worker_reviewer": "claude", "cheap_agent": "codex",
        "idle_timeout": 300.0, "wall_timeout": 1800.0,
    }
    initial = build_run_contract(**kwargs)
    windows = {
        agent: values["pinned_context_window_tokens"]
        for agent, values in initial["context"].items()
    }

    learned = ContextHarnessConfig.from_env(
        dict(__import__("os").environ), model_hint="pinned-model", agent_family="claude"
    )
    Path(learned.profile_path).parent.mkdir(parents=True, exist_ok=True)
    Path(learned.profile_path).write_text(json.dumps({"context_window_tokens": 131072}))
    resumed = build_run_contract(**kwargs, pinned_context_windows=windows)
    validate_run_contract(initial, resumed)


def test_supervisor_attempt_uses_fresh_isolated_workspace(tmp_path):
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    (ws.raw_dir / "supervisor_plan_1.md").write_text("uncommitted crash residue")
    seen_cwds: list[Path] = []

    def dispatch(_agent, _task, _prompt, _on_event, **kwargs):
        cwd = Path(kwargs["cwd_override"])
        seen_cwds.append(cwd)
        assert cwd.parent.name == "supervisor_calls"
        assert not (cwd / "raw" / "supervisor_plan_1.md").exists()
        return _result('```plan\n{"coverage_complete": true, "workers": []}\n```')

    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=1,
    )
    supervisor._round = 1
    supervisor._plan("")
    supervisor._plan("")
    assert len(seen_cwds) == 2 and seen_cwds[0] != seen_cwds[1]


def test_codex_supervisor_uses_read_only_no_mcp_route(monkeypatch):
    from src.agents import orchestrator as orchestrator_module

    seen: dict[str, object] = {}

    class FakeCodex:
        def available(self):
            return True

        def run(self, task, **kwargs):
            seen.update(kwargs)
            return _result("controlled")

    monkeypatch.setattr(orchestrator_module, "CodexAgent", FakeCodex)
    orchestrator = object.__new__(orchestrator_module.Orchestrator)
    orchestrator.config = object()
    result = orchestrator._run_codex(
        "plan", "/bin/true", "/tmp", "pinned", False, "system",
        120.0, 360.0, None, read_only_control=True,
    )
    assert result.ok is True
    assert seen["full_access"] is False
    assert seen["enable_mcp"] is False
    assert seen["target_binary"] is None


def test_execution_contract_hashes_ida_upstream_python(monkeypatch, tmp_path):
    from src.agents.run_contract import build_run_contract, validate_run_contract

    class MinimalIdaConfig:
        engine = "ida"
        state_dir = tmp_path / "state"
        ida_install = None
        idat = None
        libidalib = None
        java_home = None
        sandbox = False

    upstream_python = tmp_path / "ida-mcp-python"
    upstream_python.write_bytes(b"version-one")
    config = MinimalIdaConfig()
    config.ida_mcp_python = upstream_python
    binary = tmp_path / "target"
    binary.write_bytes(b"target")
    monkeypatch.setenv("ANGERONA_CLAUDE_CMD", "/bin/true")
    monkeypatch.setenv("ANGERONA_CODEX_CMD", "/bin/true")
    kwargs = {
        "config": config, "binary": str(binary), "model": "pinned",
        "supervisor": "claude", "worker_analyst": "claude",
        "worker_reviewer": "claude", "idle_timeout": 300.0,
        "wall_timeout": 1800.0,
    }
    expected = build_run_contract(**kwargs)
    windows = {
        agent: values["pinned_context_window_tokens"]
        for agent, values in expected["context"].items()
    }
    upstream_python.write_bytes(b"version-two-is-different")
    actual = build_run_contract(**kwargs, pinned_context_windows=windows)
    with pytest.raises(AuditStateError, match="execution contract changed"):
        validate_run_contract(expected, actual)
