from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.agents.budget_harness import (
    AgentUsage,
    AuditBudgetController,
    AuditBudgetDenied,
    AuditBudgetError,
    AuditBudgetPolicy,
    extract_agent_usage,
    load_budget_status,
)
from src.agents.supervisor import SupervisorLoop
from src.agents.runtime import AgentResult
from src.agents.output_boundary import assess_agent_output
from src.agents.supervisor import WorkerOutcome, WorkerSpec
from src.agents.orchestrator import _audit_resource_guard, _register_audit_cleanup
from src.workspace import RunWorkspace


CONTRACT = "a" * 64


def _policy(**overrides) -> AuditBudgetPolicy:
    env = {
        "ANGERONA_TRANSIENT_MAX_ATTEMPTS": "1",
        "ANGERONA_CONTEXT_MAX_RECOVERIES": "0",
        "ANGERONA_AUDIT_DISPATCH_CALL_RESERVATION": "1",
    }
    return AuditBudgetPolicy.from_env(env, **overrides)


def test_policy_reserves_transient_and_context_recovery_launches_fail_closed():
    policy = AuditBudgetPolicy.from_env(
        {
            "ANGERONA_TRANSIENT_MAX_ATTEMPTS": "5",
            "ANGERONA_CONTEXT_MAX_RECOVERIES": "1",
        },
        max_calls=2,
        max_wall_seconds=0,
        critical_reserve_calls=0,
    )
    assert policy.max_calls == 2
    assert policy.dispatch_call_reservation == 6
    assert policy.max_wall_seconds == 0


def test_normal_work_cannot_consume_critical_reserve(tmp_path):
    policy = _policy(max_calls=10, critical_reserve_calls=3, max_wall_seconds=0)
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    normal = [
        controller.reserve(priority="normal", agent="claude", phase=f"worker-{idx}")
        for idx in range(7)
    ]
    with pytest.raises(AuditBudgetDenied, match="critical_reserve_protected"):
        controller.reserve(priority="normal", agent="codex", phase="extra-worker")

    critical = [
        controller.reserve(priority="critical", agent="codex", phase=f"verify-{idx}")
        for idx in range(3)
    ]
    with pytest.raises(AuditBudgetDenied, match="agent_call_budget_exhausted"):
        controller.reserve(priority="critical", agent="claude", phase="consolidate")
    assert len(normal) + len(critical) == 10
    controller.close()


def test_parallel_reservations_cannot_oversubscribe(tmp_path):
    policy = _policy(max_calls=8, critical_reserve_calls=0, max_wall_seconds=0)
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)

    def reserve(index: int):
        try:
            return controller.reserve(
                priority="normal", agent="claude", phase=f"parallel-{index}"
            )
        except AuditBudgetDenied:
            return None

    with ThreadPoolExecutor(max_workers=20) as pool:
        reservations = list(pool.map(reserve, range(40)))
    admitted = [item for item in reservations if item is not None]
    assert len(admitted) == 8
    status = controller.status()
    assert status["reserved"]["calls"] == 8
    assert status["remaining"]["calls"] == 0
    controller.close()


def test_commit_uses_measured_usage_and_unknown_usage_uses_reservation(tmp_path):
    policy = _policy(
        max_calls=5,
        critical_reserve_calls=0,
        max_wall_seconds=0,
        max_tokens=100_000,
        max_cost_usd=20,
    )
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    measured = controller.reserve(priority="normal", agent="claude", phase="analyst")
    status = controller.commit(
        measured,
        usage=AgentUsage(
            tokens=1234,
            cost_usd=0.25,
            token_measurement_available=True,
            cost_measurement_available=True,
            token_measurements=2,
            cost_measurements=2,
            attempts=2,
        ),
        elapsed_seconds=1.5,
        ok=True,
        returncode=0,
    )
    assert status["consumed"]["calls"] == 2
    assert status["consumed"]["tokens"] == 1234
    assert status["consumed"]["cost_usd"] == 0.25

    unknown = controller.reserve(priority="normal", agent="codex", phase="review")
    status = controller.commit(
        unknown,
        usage=AgentUsage(),
        elapsed_seconds=0.1,
        ok=False,
        returncode=1,
    )
    assert status["consumed"]["tokens"] == 1234 + policy.token_reservation_per_call
    assert status["consumed"]["cost_usd"] == 1.25
    controller.close()


def test_resume_conservatively_charges_abandoned_reservation_without_resetting_deadline(
    tmp_path,
):
    policy = _policy(max_calls=4, critical_reserve_calls=0, max_wall_seconds=60)
    first = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    reservation = first.reserve(priority="normal", agent="claude", phase="worker")
    original = first.status()
    first.close()

    resumed = AuditBudgetController(
        tmp_path, policy, contract_sha256=CONTRACT, resume=True
    )
    status = resumed.status()
    assert status["deadline_unix_ns"] == original["deadline_unix_ns"]
    assert status["consumed"]["calls"] == reservation.reserved_calls
    assert status["reserved"]["dispatches"] == 0
    resumed.close()


def test_hash_chain_corruption_fails_closed(tmp_path):
    policy = _policy(max_calls=4, critical_reserve_calls=0, max_wall_seconds=0)
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    controller.close()
    path = tmp_path / "raw" / "audit_budget" / "state.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["records"][0]["data"]["started_ns"] += 1
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(AuditBudgetError, match="hash chain"):
        load_budget_status(tmp_path)


def test_usage_extraction_handles_claude_codex_aliases_and_retries():
    usage = extract_agent_usage([
        {"type": "angerona_agent_retry", "phase": "attempt_started"},
        {"type": "angerona_agent_retry", "phase": "attempt_started"},
        {
            "type": "result",
            "usage": {"prompt_tokens": 10, "completion_tokens": 7},
            "total_cost_usd": 0.03,
        },
        {"type": "angerona_agent_retry", "phase": "attempt_started"},
        {"response": {"usage": {"total_token_count": 9}}},
    ])
    assert usage.tokens == 26
    assert usage.cost_usd == pytest.approx(0.03)
    assert usage.attempts == 3
    assert usage.token_measurement_available is True
    assert usage.cost_measurement_available is True


def test_partial_usage_measurement_charges_fallback_for_unknown_attempt(tmp_path):
    policy = _policy(
        max_calls=4, critical_reserve_calls=0, max_wall_seconds=0,
        max_tokens=100_000, max_cost_usd=10,
    )
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    reservation = controller.reserve(priority="normal", agent="claude", phase="worker")
    status = controller.commit(
        reservation,
        usage=AgentUsage(
            tokens=100,
            cost_usd=0.01,
            token_measurement_available=True,
            cost_measurement_available=True,
            token_measurements=1,
            cost_measurements=1,
            attempts=2,
        ),
        elapsed_seconds=0.1,
        ok=True,
        returncode=0,
    )
    assert status["consumed"]["tokens"] == 100 + policy.token_reservation_per_call
    assert status["consumed"]["cost_usd"] == 1.01
    controller.close()


def test_usage_parser_does_not_double_count_cached_or_reasoning_subsets():
    usage = extract_agent_usage([{
        "usage": {
            "input_tokens": 100,
            "cached_input_tokens": 80,
            "output_tokens": 20,
            "reasoning_tokens": 10,
        }
    }])
    assert usage.tokens == 120


def test_usage_counts_context_recovery_launches_when_retry_ledger_is_unavailable():
    usage = extract_agent_usage([
        {"usage": {"total_tokens": 10}},
        {"type": "angerona_context_recovery", "attempt": 1},
        {"usage": {"total_tokens": 20}},
        {"type": "angerona_context_recovery", "attempt": 2},
        {"usage": {"total_tokens": 30}},
        {"type": "angerona_context_recovery", "attempt": 3},
        {"usage": {"total_tokens": 40}},
    ])
    assert usage.attempts == 4
    assert usage.token_measurements == 4
    assert usage.tokens == 100


def test_usage_uses_larger_of_retry_attempts_and_context_recovery_inference():
    usage = extract_agent_usage([
        {"type": "angerona_agent_retry", "phase": "attempt_started"},
        {"type": "angerona_context_recovery", "attempt": 1},
        {"type": "angerona_agent_retry", "phase": "attempt_started"},
        {"type": "angerona_context_recovery", "attempt": 2},
    ])
    assert usage.attempts == 3


def test_token_reservation_headroom_drives_backpressure_status(tmp_path):
    policy = _policy(
        max_calls=10, critical_reserve_calls=0, max_wall_seconds=0,
        max_tokens=1_000,
    )
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    status = controller.status()
    assert status["normal_exhausted"] is True
    assert status["reason"] == "agent_token_budget_exhausted"
    with pytest.raises(AuditBudgetDenied, match="agent_token_budget_exhausted"):
        controller.reserve(priority="critical", agent="claude", phase="final")
    controller.close()


def test_valid_prefix_truncation_is_rejected_by_durable_head(tmp_path):
    policy = _policy(max_calls=4, critical_reserve_calls=0, max_wall_seconds=0)
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    reservation = controller.reserve(priority="normal", agent="claude", phase="worker")
    controller.commit(
        reservation, usage=AgentUsage(), elapsed_seconds=0.1, ok=True, returncode=0
    )
    controller.close()
    path = tmp_path / "raw" / "audit_budget" / "state.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["records"] = state["records"][:1]
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(AuditBudgetError, match="rolled back"):
        AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT, resume=True)


def test_live_monotonic_deadline_cannot_be_extended_by_backward_wall_clock(
    monkeypatch, tmp_path
):
    from src.agents import budget_harness

    policy = _policy(max_calls=4, critical_reserve_calls=0, max_wall_seconds=60)
    controller = AuditBudgetController(tmp_path, policy, contract_sha256=CONTRACT)
    before = controller.status()["remaining"]["wall_seconds"]
    real_time_ns = budget_harness.time.time_ns()
    monkeypatch.setattr(
        budget_harness.time, "time_ns", lambda: real_time_ns - 3_600_000_000_000
    )
    after = controller.status()["remaining"]["wall_seconds"]
    assert after <= before
    controller.close()


def test_resource_guard_releases_registered_resources_on_exception():
    released = []

    @_audit_resource_guard
    def explode():
        _register_audit_cleanup(lambda: released.append("store"))
        _register_audit_cleanup(lambda: released.append("lease"))
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        explode()
    assert released == ["lease", "store"]


def test_final_consolidation_budget_denial_forces_incomplete_terminal_state(tmp_path):
    workspace = RunWorkspace.create(tmp_path, "/bin/true")
    outcome = WorkerOutcome(
        spec=WorkerSpec(id="w1", title="verified", focus="", functions=[]),
        converged=True,
        rounds=1,
        report="verified evidence",
        workspace_root=str(workspace.root / "workers" / "w1"),
    )

    def dispatch(*_args, **_kwargs):
        return AgentResult(
            ok=False,
            final_text="budget denied",
            events=[{
                "type": "angerona_audit_budget",
                "phase": "denied",
                "reason": "agent_token_budget_exhausted",
            }],
            returncode=75,
        )

    status = {
        "normal_exhausted": True,
        "hard_exhausted": False,
        "reason": "agent_token_budget_exhausted",
        "overrun": {"calls": False, "tokens": False, "cost": False, "wall": False},
    }
    serialized_outcome = {
        "spec": {
            "id": outcome.spec.id,
            "title": outcome.spec.title,
            "focus": "",
            "functions": [],
            "objective": "",
            "depends_on": [],
            "agent": None,
            "obf_focus": False,
            "slice_id": "",
        },
        "converged": True,
        "rounds": 1,
        "report": outcome.report,
        "output_boundary": assess_agent_output(
            outcome.report,
            role="worker_report",
        ).as_dict(),
        "workspace_root": outcome.workspace_root,
        "paused": False,
    }
    loop = SupervisorLoop(
        binary="/bin/true",
        objective="audit",
        overview="target",
        workspace=workspace,
        dispatch=dispatch,
        max_supervisor_rounds=1,
        strict_verify=False,
        topo_strategy="fixed",
        resume_payload={
            "supervisor": {
                "outcomes": [serialized_outcome],
                "round": 1,
                "next_round": 2,
                "coverage_complete": True,
            }
        },
        budget_status=lambda: status,
    )
    result = loop.run()
    assert result.converged is False
    assert result.incomplete_reason == "agent_token_budget_exhausted"
    assert result.final_report.startswith("# INCOMPLETE")


def test_supervisor_fails_closed_when_budget_boundary_is_already_reached(tmp_path):
    workspace = RunWorkspace.create(tmp_path, "/bin/true")
    dispatch_calls = []

    def dispatch(*args, **kwargs):
        dispatch_calls.append((args, kwargs))
        raise AssertionError("no model dispatch is allowed past the budget boundary")

    loop = SupervisorLoop(
        binary="/bin/true",
        objective="audit",
        overview="target",
        workspace=workspace,
        dispatch=dispatch,
        strict_verify=False,
        topo_strategy="fixed",
        budget_status=lambda: {
            "normal_exhausted": True,
            "hard_exhausted": False,
            "reason": "critical_reserve_protected",
            "remaining": {"calls": 3},
        },
    )
    result = loop.run()
    assert result.converged is False
    assert result.incomplete_reason == "critical_reserve_protected"
    assert "INCOMPLETE" in result.final_report
    assert "BUDGET EXHAUSTED" in result.final_report
    assert dispatch_calls == []
