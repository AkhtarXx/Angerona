from __future__ import annotations

import json
import types

import pytest

from src.agents.audit_state import AuditStateStore
from src.agents.orchestrator import normalize_terminal_audit_state
from src.agents.output_boundary import assess_agent_output
from src.agents.respawn_policy import POLICY_VERSION as RESPAWN_POLICY_VERSION
from src.agents.respawn_policy import WorkerFailure, quality_failure
from src.agents.runtime import AgentResult
from src.agents.supervisor import (
    ATTEMPT_LINEAGE_POLICY_VERSION,
    SupervisorLoop,
    WorkerOutcome,
    WorkerSpec,
    project_active_worker_outcomes,
    worker_scope_digest,
)
from src.workspace import RunWorkspace


def _outcome(
    spec: WorkerSpec,
    *,
    converged: bool,
    report: str = "verified",
    failure: dict | None = None,
) -> WorkerOutcome:
    return WorkerOutcome(
        spec=spec,
        converged=converged,
        rounds=1,
        report=report,
        workspace_root=f"/saved/{spec.id}",
        output_boundary=assess_agent_output(report, role="worker_report").as_dict(),
        failure=failure or {},
    )


def _replacement(
    parent: WorkerSpec,
    attempt_id: str,
    *,
    group: str,
    size: int,
    functions: list[str] | None = None,
    action: str | None = None,
) -> WorkerSpec:
    if functions is None:
        if size == 1:
            functions = list(parent.functions)
        else:
            half = len(parent.functions) // 2
            functions = (
                list(parent.functions[:half])
                if attempt_id.endswith("r1")
                else list(parent.functions[half:])
            )
    return WorkerSpec(
        id=attempt_id,
        title="replacement",
        focus=parent.focus,
        functions=functions,
        objective=parent.objective,
        depends_on=list(parent.depends_on),
        obf_focus=parent.obf_focus,
        slice_id=parent.slice_id,
        work_unit_id=parent.work_unit_id or parent.id,
        parent_attempt_id=parent.id,
        replacement_group_id=group,
        replacement_group_size=size,
        replacement_action=action or ("split" if size > 1 else "retry_same"),
        parent_scope_digest=worker_scope_digest(parent),
    )


def test_one_to_one_retry_supersedes_failed_parent() -> None:
    parent = WorkerSpec(
        id="w1", title="original", functions=["a", "b"], work_unit_id="w1"
    )
    child = _replacement(parent, "w1_r1", group="a" * 64, size=1)
    active = project_active_worker_outcomes([
        _outcome(parent, converged=False, failure=quality_failure(stage="reviewer").as_dict()),
        _outcome(child, converged=True),
    ])
    assert [item.spec.id for item in active] == ["w1_r1"]


def test_partial_split_is_atomic_and_keeps_parent_active() -> None:
    parent = WorkerSpec(
        id="w1", title="original", functions=["a", "b"], work_unit_id="w1"
    )
    first = _replacement(parent, "w1_r1", group="b" * 64, size=2)
    active = project_active_worker_outcomes([
        _outcome(parent, converged=False, failure=quality_failure(stage="reviewer").as_dict()),
        _outcome(first, converged=True),
    ])
    assert [item.spec.id for item in active] == ["w1"]


@pytest.mark.parametrize("second_converged", [False, True])
def test_complete_split_projects_every_child(second_converged: bool) -> None:
    parent = WorkerSpec(
        id="w1", title="original", functions=["a", "b"], work_unit_id="w1"
    )
    first = _replacement(parent, "w1_r1", group="c" * 64, size=2)
    second = _replacement(parent, "w1_r2", group="c" * 64, size=2)
    active = project_active_worker_outcomes([
        _outcome(parent, converged=False, failure=quality_failure(stage="reviewer").as_dict()),
        _outcome(first, converged=True),
        _outcome(
            second,
            converged=second_converged,
            failure=(None if second_converged else quality_failure(stage="reviewer").as_dict()),
        ),
    ])
    assert [item.spec.id for item in active] == ["w1_r1", "w1_r2"]
    assert all(item.converged for item in active) is second_converged


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate", "exact ordered scope partition"),
        ("dropped", "exact ordered scope partition"),
        ("slice", "immutable logical scope"),
        ("objective", "immutable logical scope"),
        ("digest", "parent-scope digest"),
        ("mixed_action", "one-to-one worker replacement"),
    ],
)
def test_split_scope_transaction_rejects_tampering(
    mutation: str, message: str
) -> None:
    parent = WorkerSpec(
        id="w1", title="parent", functions=["a", "b"], slice_id="slice1",
        focus="focus", objective="objective", depends_on=["root"],
        obf_focus=True, work_unit_id="unit",
    )
    first = _replacement(
        parent, "w1_r1", group="4" * 64, size=2, functions=["a"]
    )
    second = _replacement(
        parent, "w1_r2", group="4" * 64, size=2, functions=["b"]
    )
    if mutation == "duplicate":
        second.functions = ["a"]
    elif mutation == "dropped":
        second.functions = []
    elif mutation == "slice":
        second.slice_id = "other"
    elif mutation == "objective":
        second.objective = "changed"
    elif mutation == "digest":
        second.parent_scope_digest = "9" * 64
    elif mutation == "mixed_action":
        second.replacement_action = "retry_same"
    with pytest.raises(RuntimeError, match=message):
        project_active_worker_outcomes([
            _outcome(parent, converged=False),
            _outcome(first, converged=True),
            _outcome(second, converged=True),
        ])


def test_nested_replacement_preserves_exact_scope() -> None:
    parent = WorkerSpec(
        id="w1", title="parent", functions=["a", "b", "c", "d"],
        work_unit_id="unit",
    )
    first = _replacement(
        parent, "w1_r1", group="5" * 64, size=2, functions=["a", "b"]
    )
    second = _replacement(
        parent, "w1_r2", group="5" * 64, size=2, functions=["c", "d"]
    )
    grandchild = _replacement(
        first, "w1_r1_r1", group="6" * 64, size=1, action="retry_same"
    )
    history = [
        _outcome(parent, converged=False),
        _outcome(first, converged=False),
        _outcome(second, converged=True),
        _outcome(grandchild, converged=True),
    ]
    assert [item.spec.id for item in project_active_worker_outcomes(history)] == [
        "w1_r1_r1", "w1_r2"
    ]
    grandchild.objective = "scope drift"
    with pytest.raises(RuntimeError, match="immutable logical scope"):
        project_active_worker_outcomes(history)


def test_lineage_rejects_missing_parent_and_cycles() -> None:
    orphan = WorkerSpec(
        id="orphan", title="bad", work_unit_id="w1",
        parent_attempt_id="missing", replacement_group_id="d" * 64,
        replacement_group_size=1, replacement_action="retry_same",
        parent_scope_digest="0" * 64,
    )
    with pytest.raises(RuntimeError, match="missing parent"):
        project_active_worker_outcomes([_outcome(orphan, converged=True)])

    first = WorkerSpec(
        id="a", title="a", work_unit_id="unit", parent_attempt_id="b",
        replacement_group_id="e" * 64, replacement_group_size=1,
        replacement_action="retry_same", parent_scope_digest="0" * 64,
    )
    second = WorkerSpec(
        id="b", title="b", work_unit_id="unit", parent_attempt_id="a",
        replacement_group_id="f" * 64, replacement_group_size=1,
        replacement_action="retry_same", parent_scope_digest="0" * 64,
    )
    with pytest.raises(RuntimeError, match="cycle"):
        project_active_worker_outcomes([
            _outcome(first, converged=True), _outcome(second, converged=True)
        ])


def test_successful_retry_can_complete_real_supervisor_run(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(
            ok=True, final_text="## Summary\nverified replacement", returncode=0
        ),
        max_supervisor_rounds=2, max_worker_rounds=1,
        spawn_strategy="llm", topo_strategy="fixed", strict_verify=False,
        available_agents={"claude"},
    )
    plans = iter([
        {"coverage_complete": False, "workers": [
            {"id": "w1", "title": "slice", "functions": ["f"]}
        ]},
        {"coverage_complete": True, "workers": []},
    ])
    supervisor._plan = types.MethodType(lambda _self, _prior: next(plans), supervisor)

    def worker(_self, spec, _k=None):
        if spec.parent_attempt_id:
            return _outcome(spec, converged=True, report="CONFIRMED: replacement")
        return _outcome(
            spec, converged=False, report="failed original",
            failure=quality_failure(stage="reviewer").as_dict(),
        )

    supervisor._run_one_worker = types.MethodType(worker, supervisor)
    result = supervisor.run()
    assert result.converged is True
    assert result.incomplete_reason == ""
    assert [item.spec.id for item in project_active_worker_outcomes(result.workers)] == [
        "w1_r1"
    ]
    assert "UNVERIFIED WORKER FINDINGS" not in result.final_report
    assert "SUPERSEDED ATTEMPT HISTORY" in result.final_report
    validation = json.loads((ws.raw_dir / "validation_status.json").read_text())
    assert validation["summary"]["attempts_total"] == 2
    assert validation["summary"]["attempts_superseded"] == 1
    assert validation["summary"]["workers_total"] == 1
    assert ws.meta["status"] == "completed" and ws.meta["converged"] is True


def test_provider_reroute_preserves_logical_work_unit(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="ok"),
        worker_analyst="claude", cheap_agent="codex",
        available_agents={"claude", "codex"},
    )
    parent = WorkerSpec(
        id="w1", title="slice", agent="claude", work_unit_id="logical-slice"
    )
    failure = WorkerFailure(
        category="provider_auth", stage="analyst", action="reroute",
        retryable=True, infrastructure=True, source_agent="claude",
        reason_codes=("authentication_failed",),
    )
    child = supervisor._adaptive_respawn([
        _outcome(parent, converged=False, failure=failure.as_dict())
    ], set())[0]
    assert child.agent == "codex"
    assert child.work_unit_id == "logical-slice"
    assert child.parent_attempt_id == "w1"
    assert child.replacement_group_size == 1
    assert child.replacement_action == "reroute"
    assert child.parent_scope_digest == worker_scope_digest(parent)


def test_partial_split_checkpoint_resume_reconstructs_same_active_leaves(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    parent = WorkerSpec(
        id="w1", title="parent", functions=["a", "b"], work_unit_id="w1"
    )
    first = _replacement(parent, "w1_r1", group="1" * 64, size=2)
    second = _replacement(parent, "w1_r2", group="1" * 64, size=2)
    seed = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="ok"),
        state_store=store,
    )
    parent_outcome = _outcome(
        parent, converged=False, report="failed",
        failure=quality_failure(stage="reviewer").as_dict(),
    )
    first_outcome = _outcome(first, converged=True, report="CONFIRMED: first")
    snapshot = store.checkpoint({
        "kind": "swarm",
        "status": "running",
        "respawn_policy_version": RESPAWN_POLICY_VERSION,
        "attempt_lineage_policy_version": ATTEMPT_LINEAGE_POLICY_VERSION,
        "supervisor": {
            "round": 1,
            "next_round": 1,
            "coverage_complete": False,
            "seen_ids": ["w1", "w1_r1"],
            "retried_fingerprints": ["1" * 64],
            "active_plan": {
                "round": 1,
                "mode": "adaptive_respawn",
                "plan": {
                    "coverage_complete": False,
                    "workers": [seed._spec_json(first), seed._spec_json(second)],
                },
            },
            "worker_workspaces": {},
            "outcomes": [
                seed._outcome_json(parent_outcome),
                seed._outcome_json(first_outcome),
            ],
        },
    })
    assert [item.spec.id for item in project_active_worker_outcomes([
        parent_outcome, first_outcome
    ])] == ["w1"]

    resumed = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview",
        workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_args, **_kwargs: AgentResult(
            ok=True, final_text="## Summary\nresumed", returncode=0
        ),
        max_supervisor_rounds=1, spawn_strategy="llm", topo_strategy="fixed",
        strict_verify=False, state_store=store, resume_payload=snapshot.payload,
    )
    resumed._run_one_worker = types.MethodType(
        lambda _self, spec, _k=None: _outcome(
            spec, converged=True, report="CONFIRMED: second"
        ),
        resumed,
    )
    result = resumed.run()
    assert [item.spec.id for item in project_active_worker_outcomes(result.workers)] == [
        "w1_r1", "w1_r2"
    ]
    assert result.incomplete_reason == "supervisor_coverage_incomplete"
    restored = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview",
        workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        state_store=store, resume_payload=store.load_latest().payload,
    ).run()
    assert [item.spec.id for item in project_active_worker_outcomes(restored.workers)] == [
        "w1_r1", "w1_r2"
    ]
    store.close()


def test_terminal_state_never_completes_nonconverged_result() -> None:
    assert normalize_terminal_audit_state(False, "") == (
        False, "supervisor_work_units_unresolved", "incomplete"
    )
    assert normalize_terminal_audit_state(True, "") == (True, "", "completed")
    assert normalize_terminal_audit_state(True, "audit_call_budget_exhausted") == (
        False, "audit_call_budget_exhausted", "budget_exhausted"
    )


def test_workspace_terminal_persistence_enforces_convergence_invariant(tmp_path) -> None:
    failed = RunWorkspace.create(tmp_path / "failed", "/bin/true")
    failed.finish(converged=False, rounds=1)
    assert failed.meta["status"] == "incomplete"
    assert failed.meta["converged"] is False

    contradictory = RunWorkspace.create(tmp_path / "contradictory", "/bin/true")
    with pytest.raises(ValueError, match="converged workspace"):
        contradictory.finish(converged=True, rounds=1, status="incomplete")


def test_current_terminal_checkpoint_rejects_completed_nonconvergence(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    report = "# INCOMPLETE\n"
    boundary = assess_agent_output(report, role="supervisor_final_report").as_dict()
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        resume_payload={
            "attempt_lineage_policy_version": ATTEMPT_LINEAGE_POLICY_VERSION,
            "status": "completed", "converged": False,
            "final_report": report, "final_report_boundary": boundary,
            "supervisor": {"round": 1, "coverage_complete": False, "outcomes": []},
        },
    )
    with pytest.raises(RuntimeError, match="completed status contradicts convergence"):
        supervisor.run()


def test_unsupported_lineage_policy_and_legacy_authority_fail_closed(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    with pytest.raises(RuntimeError, match="attempt-lineage policy"):
        SupervisorLoop(
            binary="/bin/true", objective="x", overview="overview", workspace=ws,
            dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="ok"),
            resume_payload={
                "attempt_lineage_policy_version": 999,
                "supervisor": {"round": 1},
            },
        )

    # A pre-policy checkpoint cannot invent a parent relationship and make its
    # failed historical outcome disappear. Both records restore as independent roots.
    parent = WorkerSpec(id="w1", title="parent")
    child = _replacement(parent, "w1_r1", group="2" * 64, size=1)
    legacy = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="ok"),
        resume_payload={"supervisor": {"round": 1}},
    )
    restored_parent = legacy._outcome_from_json({
        "spec": legacy._spec_json(parent), "converged": False, "rounds": 1,
        "report": "failed", "workspace_root": "", "paused": False,
        "failure": quality_failure(stage="reviewer").as_dict(),
    })
    restored_child = legacy._outcome_from_json({
        "spec": legacy._spec_json(child), "converged": True, "rounds": 1,
        "report": "verified", "workspace_root": "", "paused": False,
    })
    assert [item.spec.id for item in project_active_worker_outcomes([
        restored_parent, restored_child
    ])] == ["w1", "w1_r1"]


def test_restored_pending_lineage_is_validated_before_dispatch(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    orphan = WorkerSpec(
        id="w1_r1", title="orphan", work_unit_id="w1",
        parent_attempt_id="missing", replacement_group_id="3" * 64,
        replacement_group_size=1, replacement_action="retry_same",
        parent_scope_digest="0" * 64,
    )
    snapshot = store.checkpoint({
        "kind": "swarm", "status": "running",
        "respawn_policy_version": RESPAWN_POLICY_VERSION,
        "attempt_lineage_policy_version": ATTEMPT_LINEAGE_POLICY_VERSION,
        "supervisor": {
            "round": 1, "next_round": 1, "coverage_complete": False,
            "seen_ids": [], "retried_fingerprints": ["3" * 64],
            "active_plan": {
                "round": 1, "mode": "adaptive_respawn",
                "plan": {
                    "coverage_complete": False,
                    "workers": [SupervisorLoop._spec_json(orphan)],
                },
            },
            "worker_workspaces": {}, "outcomes": [],
        },
    })
    called = False

    def worker(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("malformed lineage must fail before dispatch")

    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="ok"),
        state_store=store, resume_payload=snapshot.payload,
        max_supervisor_rounds=1, spawn_strategy="llm", topo_strategy="fixed",
    )
    supervisor._run_one_worker = worker
    with pytest.raises(RuntimeError, match="missing parent"):
        supervisor.run()
    assert called is False
    store.close()


def test_partial_split_child_never_reaches_shared_blackboard(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    supervisor = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
    )
    supervisor._global_lessons = ws.root / "global_lessons.md"
    parent = WorkerSpec(
        id="w1", title="parent", functions=["a", "b"], work_unit_id="unit"
    )
    first = _replacement(parent, "w1_r1", group="7" * 64, size=2)
    second = _replacement(parent, "w1_r2", group="7" * 64, size=2)
    parent_outcome = _outcome(parent, converged=False, report="parent failed")
    first_outcome = _outcome(first, converged=True, report="CONFIRMED: first")
    blackboard = ws.root / "blackboard.md"
    supervisor._publish_blackboard([parent_outcome, first_outcome], blackboard)
    assert "w1_r1" not in blackboard.read_text()

    supervisor._publish_blackboard(
        [parent_outcome, first_outcome, _outcome(
            second, converged=True, report="CONFIRMED: second"
        )],
        blackboard,
    )
    published = blackboard.read_text()
    assert "## w1_r1" in published and "## w1_r2" in published
    assert "## w1 (" not in published


def test_malformed_split_checkpoint_rejected_before_dispatch(tmp_path) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    store = AuditStateStore(ws.root)
    seed = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        state_store=store,
    )
    parent = WorkerSpec(
        id="w1", title="parent", functions=["a", "b"], slice_id="slice1",
        work_unit_id="unit",
    )
    first = _replacement(
        parent, "w1_r1", group="8" * 64, size=2, functions=["a"]
    )
    second = _replacement(
        parent, "w1_r2", group="8" * 64, size=2, functions=["a"]
    )
    parent_outcome = _outcome(
        parent, converged=False, report="failed",
        failure=quality_failure(stage="reviewer").as_dict(),
    )
    snapshot = store.checkpoint({
        "kind": "swarm", "status": "running",
        "respawn_policy_version": RESPAWN_POLICY_VERSION,
        "attempt_lineage_policy_version": ATTEMPT_LINEAGE_POLICY_VERSION,
        "supervisor": {
            "round": 1, "next_round": 1, "coverage_complete": False,
            "seen_ids": ["w1"], "retried_fingerprints": ["8" * 64],
            "active_plan": {
                "round": 1, "mode": "adaptive_respawn",
                "plan": {
                    "coverage_complete": False,
                    "workers": [seed._spec_json(first), seed._spec_json(second)],
                },
            },
            "worker_workspaces": {},
            "outcomes": [seed._outcome_json(parent_outcome)],
        },
    })
    called = False

    def worker(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("scope-invalid replacement must not dispatch")

    resumed = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        state_store=store, resume_payload=snapshot.payload,
        max_supervisor_rounds=1, spawn_strategy="llm", topo_strategy="fixed",
    )
    resumed._run_one_worker = worker
    with pytest.raises(RuntimeError, match="exact ordered scope partition"):
        resumed.run()
    assert called is False
    store.close()


@pytest.mark.parametrize("malformed", [{"not": "a list"}, {}, "", 0])
def test_resume_rejects_unbounded_or_malformed_attempt_collections(
    tmp_path, malformed: object
) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    malformed_outcomes = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        resume_payload={"supervisor": {"round": 1, "outcomes": malformed}},
    )
    with pytest.raises(RuntimeError, match="outcomes are invalid or unbounded"):
        malformed_outcomes.run()

    workers = [
        SupervisorLoop._spec_json(WorkerSpec(id=f"w{i}", title="root"))
        for i in range(65)
    ]
    oversized_plan = SupervisorLoop(
        binary="/bin/true", objective="x", overview="overview", workspace=ws,
        dispatch=lambda *_args, **_kwargs: AgentResult(ok=True, final_text="unused"),
        resume_payload={
            "attempt_lineage_policy_version": ATTEMPT_LINEAGE_POLICY_VERSION,
            "supervisor": {
                "round": 1, "next_round": 1, "outcomes": [],
                "active_plan": {
                    "round": 1, "plan": {
                        "coverage_complete": False, "workers": workers,
                    },
                },
            },
        },
        max_supervisor_rounds=1,
    )
    with pytest.raises(RuntimeError, match="workers are invalid or unbounded"):
        oversized_plan.run()
