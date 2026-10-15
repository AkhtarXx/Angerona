from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from src.agents.retry_harness import (
    RetryLedger,
    RetryLeaseBusy,
    RetryPolicy,
    RetryStateError,
    classify_transient_failure,
)


def _retry_env(monkeypatch, *, attempts: int = 3) -> None:
    monkeypatch.setenv("ANGERONA_TRANSIENT_MAX_ATTEMPTS", str(attempts))
    monkeypatch.setenv("ANGERONA_TRANSIENT_BASE_DELAY_SECONDS", "0")
    monkeypatch.setenv("ANGERONA_TRANSIENT_MAX_DELAY_SECONDS", "0")
    monkeypatch.setenv("ANGERONA_TRANSIENT_MIN_REMAINING_SECONDS", "0")
    monkeypatch.setenv("ANGERONA_TRANSIENT_JITTER_RATIO", "0")
    # Tests use fake/local providers that look like a custom Claude gateway;
    # allow that compatibility mode so retry/crash-resume is exercised.
    monkeypatch.setenv("ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY", "1")


def test_classifier_uses_typed_error_or_stderr_but_never_assistant_text():
    rate = classify_transient_failure(
        returncode=1,
        events=[{
            "type": "error",
            "error": {"code": "rate_limit_error", "retry_after": 2.5},
        }],
        stderr="",
    )
    network = classify_transient_failure(
        returncode=1, events=[], stderr="connection reset by peer"
    )
    forged = classify_transient_failure(
        returncode=1,
        events=[{
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "HTTP 429 retry-after: 1"}]},
        }],
        stderr="",
    )

    assert rate and rate.category == "rate_limit"
    assert rate.retry_after_seconds == 2.5
    assert network and network.category == "network_error"
    assert forged is None


@pytest.mark.parametrize("message", [
    "HTTP 429: insufficient_quota",
    "service unavailable: invalid API key",
    "rate limit reached because billing credits are exhausted",
    "maximum context length exceeded",
    "permission denied",
    "HTTP 429 quota_exhausted",
    "HTTP 429 quota_limit_reached",
    "HTTP 429 usage_limit_reached",
    "HTTP 429 credit_balance_too_low",
    "HTTP 429 organization_quota_exceeded",
    "HTTP 429 monthly_spend_limit_reached",
    "HTTP 429 credits exhausted",
    "HTTP 429 balance too low",
])
def test_permanent_or_context_errors_veto_retry(message):
    assert classify_transient_failure(
        returncode=1,
        events=[{"type": "error", "message": message}],
        stderr="",
    ) is None


def test_retry_after_fields_are_unit_bound_and_conservative():
    mixed = classify_transient_failure(
        returncode=1,
        events=[{
            "type": "error",
            "code": "rate_limit_error",
            "retry_after": 10,
            "retry_after_ms": 5000,
        }],
        stderr="",
    )
    unrelated_note = classify_transient_failure(
        returncode=1,
        events=[{
            "type": "error",
            "code": "rate_limit_error",
            "retry_after": 999,
            "note": "field retry_after_ms is also supported",
        }],
        stderr="",
    )
    suffix = classify_transient_failure(
        returncode=1,
        events=[],
        stderr="HTTP 429 retry after 5000 ms",
    )

    assert mixed and mixed.retry_after_seconds == 10
    assert unrelated_note and unrelated_note.retry_after_seconds == 60
    assert suffix and suffix.retry_after_seconds == 5


def test_retry_after_aggregates_all_trusted_failure_channels():
    cross_channel = classify_transient_failure(
        returncode=1,
        events=[{"type": "error", "message": "HTTP 429 rate limit"}],
        stderr="HTTP 429 Retry-After: 60",
    )
    multiple_events = classify_transient_failure(
        returncode=1,
        events=[
            {"type": "error", "message": "HTTP 429", "retry_after": 1},
            {"type": "error", "message": "HTTP 429", "retry_after": 40},
        ],
        stderr="",
    )

    assert cross_channel and cross_channel.retry_after_seconds == 60
    assert multiple_events and multiple_events.retry_after_seconds == 40


def test_real_supervised_timeout_normalizes_signal_returncode(monkeypatch, tmp_path):
    from src.agents.runtime import _stream_process

    env = dict(os.environ)
    env["ANGERONA_AGENT_FS_SANDBOX"] = "0"
    rc, _out, err, _seconds = _stream_process(
        ["/bin/sh", "-c", "sleep 10"],
        input_text=None,
        cwd=str(tmp_path),
        env=env,
        idle_timeout=0.05,
        wall_timeout=5,
    )

    assert rc == 124
    assert "timed out" in err
    failure = classify_transient_failure(returncode=rc, events=[], stderr=err)
    assert failure and failure.category == "timeout"


def test_retry_policy_is_bounded_and_delay_is_deterministic():
    policy = RetryPolicy.from_env({
        "ANGERONA_TRANSIENT_MAX_ATTEMPTS": "999",
        "ANGERONA_TRANSIENT_BASE_DELAY_SECONDS": "2",
        "ANGERONA_TRANSIENT_MAX_DELAY_SECONDS": "10",
        "ANGERONA_TRANSIENT_JITTER_RATIO": "0.5",
        "ANGERONA_TRANSIENT_MIN_REMAINING_SECONDS": "999",
    })

    assert policy.max_attempts == 5
    assert policy.min_remaining_seconds == 60
    first = policy.delay_seconds(
        failed_attempt=2, dispatch_key="a" * 32, retry_after_seconds=None
    )
    second = policy.delay_seconds(
        failed_attempt=2, dispatch_key="a" * 32, retry_after_seconds=None
    )
    assert first == second
    assert 2 <= first <= 4


def test_retry_ledger_resumes_interrupted_session_and_hash_chain(tmp_path):
    key = "a" * 32
    ledger = RetryLedger(tmp_path, key)
    session = ledger.acquire_session()
    first_session_id = session.session_id
    assert session.start_attempt(launch_kind="initial") == 1
    ledger.close()

    resumed_ledger = RetryLedger(tmp_path, key)
    resumed = resumed_ledger.acquire_session()
    assert resumed.session_id == first_session_id
    assert resumed.resumed_after_crash
    assert resumed.attempts_used == 1
    resumed.record("success")
    resumed_ledger.close()

    next_ledger = RetryLedger(tmp_path, key)
    next_session = next_ledger.acquire_session()
    assert next_session.session_id != first_session_id
    assert not next_session.resumed_after_crash
    next_ledger.close()

    state_path = tmp_path / "raw" / "agent_retries" / key / "state.json"
    state = json.loads(state_path.read_text())
    state["records"][0]["kind"] = "tampered"
    state_path.write_text(json.dumps(state))
    corrupt = RetryLedger(tmp_path, key)
    with pytest.raises(RetryStateError, match="hash chain"):
        corrupt.acquire_session()
    corrupt.close()


def test_retry_ledger_lease_serializes_duplicate_dispatches(tmp_path):
    key = "b" * 32
    first = RetryLedger(tmp_path, key)
    first_session = first.acquire_session()
    acquired = threading.Event()
    suppressed: list[bool] = []

    def acquire_duplicate():
        duplicate = RetryLedger(tmp_path, key)
        session = duplicate.acquire_session()
        suppressed.append(session.duplicate_suppressed)
        acquired.set()
        duplicate.close()

    thread = threading.Thread(target=acquire_duplicate, daemon=True)
    thread.start()
    assert not acquired.wait(0.1)
    first_session.record("success")
    first.close()
    assert acquired.wait(2)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert suppressed == [True]


def test_retry_ledger_lease_timeout_fails_closed(tmp_path):
    key = "c" * 32
    owner = RetryLedger(tmp_path, key)
    owner.acquire_session()
    waiter = RetryLedger(tmp_path, key)
    with pytest.raises(RetryLeaseBusy, match="still active"):
        waiter.acquire_session(lock_timeout_seconds=0.05)
    waiter.close()
    owner.close()


def test_claude_retries_typed_rate_limit_and_preserves_task(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    calls: list[dict] = []

    def fake_stream(args, **kwargs):
        calls.append({"args": list(args), **kwargs})
        if len(calls) == 1:
            kwargs["on_line"](json.dumps({
                "type": "error",
                "error": {"code": "rate_limit_error", "retry_after": 0},
            }))
            return 1, "", "", 0.1
        kwargs["on_line"]('{"type":"result","result":"recovered report"}')
        return 0, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fake_stream)
    result = ClaudeCodeAgent(command="claude").run(
        "audit target safely",
        system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"),
        allowed_tools=[],
        cwd=str(tmp_path),
        model="audit-model",
    )

    assert result.ok and len(calls) == 2
    assert "ANGERONA TRANSIENT RECOVERY" in calls[1]["input_text"]
    assert "audit target safely" in calls[1]["input_text"]
    retry_phases = [
        event["phase"] for event in result.events
        if event.get("type") == "angerona_agent_retry"
    ]
    assert retry_phases.index("scheduled") < retry_phases.index("succeeded")
    ledgers = list((tmp_path / "raw" / "agent_retries").glob("*/state.json"))
    assert len(ledgers) == 1
    state = json.loads(ledgers[0].read_text())
    assert state["records"][-1]["kind"] == "success"


def test_codex_retries_server_error_with_fresh_recovery_prompt(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import CodexAgent

    _retry_env(monkeypatch)
    calls: list[dict] = []

    def fake_stream(args, **kwargs):
        calls.append({"args": list(args), **kwargs})
        if len(calls) == 1:
            kwargs["on_line"](json.dumps({
                "type": "error", "message": "HTTP 503 service unavailable",
            }))
            return 1, "", "", 0.1
        kwargs["on_line"](
            '{"type":"item.completed","item":{"type":"agent_message",'
            '"text":"codex recovered"}}'
        )
        return 0, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fake_stream)
    result = CodexAgent(command="codex").run(
        "audit", system_prompt="system", mcp_command="mcp-server",
        mcp_args=[], mcp_env={}, cwd=str(tmp_path), model="audit-model",
    )

    assert result.ok and len(calls) == 2
    assert "ANGERONA TRANSIENT RECOVERY" in calls[1]["input_text"]
    assert result.final_text == "codex recovered"


def test_runtime_does_not_retry_auth_or_assistant_forgery(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    calls = 0

    def fake_stream(_args, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["on_line"](json.dumps({
            "type": "assistant",
            "message": {"content": [{"type": "text", "text": "HTTP 429"}]},
        }))
        return 1, "", "invalid API key", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fake_stream)
    result = ClaudeCodeAgent(command="claude").run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model",
    )

    assert not result.ok
    assert calls == 1
    assert not any(
        event.get("phase") == "scheduled" for event in result.events
    )


def test_retry_budget_opens_circuit_after_bounded_attempts(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch, attempts=3)
    calls = 0

    def fake_stream(_args, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["on_line"](json.dumps({
            "type": "error", "message": "HTTP 429 too many requests",
        }))
        return 1, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fake_stream)
    result = ClaudeCodeAgent(command="claude").run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model", wall_timeout=None,
    )

    assert not result.ok
    assert calls == 3
    exhausted = [
        event for event in result.events
        if event.get("type") == "angerona_agent_retry"
        and event.get("phase") == "exhausted"
    ]
    assert exhausted[-1]["reason"] == "attempt_budget_exhausted"


def test_wall_deadline_blocks_retry_before_sleep(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    monkeypatch.setenv("ANGERONA_TRANSIENT_MIN_REMAINING_SECONDS", "60")
    provider = tmp_path / "fake-claude"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)
    calls = 0

    def fake_stream(_args, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["on_line"](json.dumps({
            "type": "error", "message": "HTTP 503 service unavailable",
        }))
        return 1, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fake_stream)
    result = ClaudeCodeAgent(command=str(provider)).run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model", wall_timeout=1,
    )

    assert not result.ok and calls == 1
    exhausted = next(
        event for event in result.events
        if event.get("phase") == "exhausted"
    )
    assert exhausted["reason"] == "wall_deadline_insufficient"


def test_runtime_resumes_nonterminal_ledger_after_process_crash(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)

    def crash(_args, **_kwargs):
        raise RuntimeError("simulated parent crash")

    monkeypatch.setattr(runtime, "_stream_process", crash)
    with pytest.raises(RuntimeError, match="simulated parent crash"):
        ClaudeCodeAgent(command="claude").run(
            "audit", system_prompt="system",
            mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
            cwd=str(tmp_path), model="audit-model",
        )

    seen: dict = {}

    def succeed(_args, **kwargs):
        seen.update(kwargs)
        kwargs["on_line"]('{"type":"result","result":"resumed"}')
        return 0, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", succeed)
    result = ClaudeCodeAgent(command="claude").run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model",
    )

    assert result.ok
    assert "ANGERONA TRANSIENT RECOVERY" in seen["input_text"]
    resumed = next(
        event for event in result.events if event.get("phase") == "resumed"
    )
    assert resumed["attempts_used"] == 1


@pytest.mark.parametrize("agent_family", ("claude", "codex"))
@pytest.mark.parametrize("changed_contract", ("target", "mcp", "isolation", "backend"))
def test_crash_resume_never_crosses_execution_contract(
    monkeypatch, tmp_path, agent_family, changed_contract
):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent, CodexAgent

    _retry_env(monkeypatch)
    monkeypatch.setenv("ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY", "1")
    monkeypatch.setenv(
        "ANGERONA_AGENT_CONTROL_STATE_DIR",
        str(tmp_path.parent / f"{tmp_path.name}-control"),
    )
    target = tmp_path / "target.bin"
    target.write_bytes(b"version-one")
    provider = tmp_path / f"fake-{agent_family}"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text('{"mcpServers":{}}')
    calls: list[dict] = []

    def stream(_args, **kwargs):
        calls.append(dict(kwargs))
        if len(calls) == 1:
            raise RuntimeError("simulated parent crash")
        if agent_family == "claude":
            kwargs["on_line"]('{"type":"result","result":"fresh contract"}')
        else:
            kwargs["on_line"](
                '{"type":"item.completed","item":{"type":"agent_message",'
                '"text":"fresh contract"}}'
            )
        return 0, "", "", 0.01

    monkeypatch.setattr(runtime, "_stream_process", stream)

    def launch(*, changed: bool):
        if agent_family == "claude":
            return ClaudeCodeAgent(command=str(provider)).run(
                "audit",
                system_prompt="system",
                mcp_config_path=str(mcp_config),
                allowed_tools=[],
                cwd=str(tmp_path),
                target_binary=str(target),
                model="audit-model",
                isolation_required=changed and changed_contract == "isolation",
            )
        return CodexAgent(command=str(provider)).run(
            "audit",
            system_prompt="system",
            mcp_command="mcp-server",
            mcp_args=["--changed"] if changed and changed_contract == "mcp" else [],
            mcp_env={"MODE": "changed"} if changed and changed_contract == "mcp" else {},
            cwd=str(tmp_path),
            target_binary=str(target),
            model="audit-model",
            enable_mcp=True,
            isolation_required=changed and changed_contract == "isolation",
        )

    with pytest.raises(RuntimeError, match="simulated parent crash"):
        launch(changed=False)
    if changed_contract == "target":
        target.write_bytes(b"version-two")
    elif changed_contract == "mcp" and agent_family == "claude":
        mcp_config.write_text('{"mcpServers":{"changed":{"command":"true"}}}')
    elif changed_contract == "backend":
        monkeypatch.setenv(
            "ANTHROPIC_BASE_URL" if agent_family == "claude" else "OPENAI_BASE_URL",
            "https://changed-provider.invalid/v1",
        )

    result = launch(changed=True)

    assert result.ok
    assert result.final_text == "fresh contract"
    assert len(calls) == 2
    assert "ANGERONA TRANSIENT RECOVERY" not in calls[1]["input_text"]
    assert "ANGERONA CONTEXT RECOVERY" not in calls[1]["input_text"]
    assert "audit" in calls[1]["input_text"]
    assert not any(
        event.get("phase") in {"resumed", "resumed_after_crash"}
        for event in result.events
    )


def test_runtime_releases_lease_while_exception_traceback_is_live(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    provider = tmp_path / "fake-claude"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)

    def crash(_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(runtime, "_stream_process", crash)
    try:
        ClaudeCodeAgent(command=str(provider)).run(
            "audit", system_prompt="system",
            mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
            cwd=str(tmp_path), model="audit-model", wall_timeout=1,
        )
    except RuntimeError:
        calls = 0

        def succeed(_args, **kwargs):
            nonlocal calls
            calls += 1
            kwargs["on_line"]('{"type":"result","result":"resumed"}')
            return 0, "", "", 0.01

        monkeypatch.setattr(runtime, "_stream_process", succeed)
        result = ClaudeCodeAgent(command=str(provider)).run(
            "audit", system_prompt="system",
            mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
            cwd=str(tmp_path), model="audit-model", wall_timeout=1,
        )
        assert result.ok and calls == 1
        assert any(event.get("phase") == "resumed" for event in result.events)
    else:
        pytest.fail("expected simulated runtime failure")


def test_crash_resume_preserves_original_wall_deadline(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    provider = tmp_path / "fake-claude"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)

    def crash(_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(runtime, "_stream_process", crash)
    # wall_timeout must comfortably exceed run() setup (env/config, execution
    # contract hashing, durable ledger open) so the crash is actually reached
    # before the in-process wall deadline pre-check expires the attempt.
    # Otherwise a cold/slow machine returns rc=124 without ever calling
    # _stream_process, and the RuntimeError is never raised (flaky).
    with pytest.raises(RuntimeError, match="boom"):
        ClaudeCodeAgent(command=str(provider)).run(
            "audit", system_prompt="system",
            mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
            cwd=str(tmp_path), model="audit-model", wall_timeout=1.0,
        )

    # Sleep past the original 1.0s wall deadline so the resumed dispatch sees it
    # as expired. Margin covers the setup latency already elapsed since the
    # deadline was captured at run() entry.
    time.sleep(1.2)
    calls = 0

    def should_not_launch(_args, **_kwargs):
        nonlocal calls
        calls += 1
        return 0, "", "", 0.01

    monkeypatch.setattr(runtime, "_stream_process", should_not_launch)
    result = ClaudeCodeAgent(command=str(provider)).run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model", wall_timeout=10,
    )

    assert not result.ok and result.returncode == 124 and calls == 0
    exhausted = next(event for event in result.events if event.get("phase") == "exhausted")
    assert exhausted["reason"] == "crash_resume_wall_timeout_exhausted"


def test_crash_resume_cannot_reset_total_attempt_budget(monkeypatch, tmp_path):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch, attempts=3)
    provider = tmp_path / "fake-claude"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)
    calls = 0

    def crash(_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("simulated process crash")

    monkeypatch.setattr(runtime, "_stream_process", crash)
    for _attempt in range(3):
        with pytest.raises(RuntimeError, match="simulated process crash"):
            ClaudeCodeAgent(command=str(provider)).run(
                "audit", system_prompt="system",
                mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
                cwd=str(tmp_path), model="audit-model",
            )
    result = ClaudeCodeAgent(command=str(provider)).run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model",
    )

    assert not result.ok and result.returncode == 75
    assert calls == 3
    exhausted = next(
        event for event in result.events if event.get("phase") == "exhausted"
    )
    assert exhausted["reason"] == "crash_resume_budget_exhausted"


def test_corrupt_ledger_disables_retry_but_allows_one_initial_attempt(
    monkeypatch, tmp_path
):
    from src.agents import runtime
    from src.agents.runtime import ClaudeCodeAgent

    _retry_env(monkeypatch)
    provider = tmp_path / "fake-claude"
    provider.write_text("#!/bin/sh\nexit 0\n")
    provider.chmod(0o755)

    def create_authoritative_ledger(_args, **_kwargs):
        raise RuntimeError("simulated process crash")

    monkeypatch.setattr(runtime, "_stream_process", create_authoritative_ledger)
    with pytest.raises(RuntimeError, match="simulated process crash"):
        ClaudeCodeAgent(command=str(provider)).run(
            "audit", system_prompt="system",
            mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
            cwd=str(tmp_path), model="audit-model",
        )
    authoritative_states = list(
        runtime._retry_control_root(tmp_path).glob("raw/agent_retries/*/state.json")
    )
    assert len(authoritative_states) == 1
    authoritative_states[0].write_text("{corrupt")
    calls = 0

    def fail(_args, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["on_line"](json.dumps({
            "type": "error", "message": "HTTP 429 too many requests",
        }))
        return 1, "", "", 0.1

    monkeypatch.setattr(runtime, "_stream_process", fail)
    result = ClaudeCodeAgent(command=str(provider)).run(
        "audit", system_prompt="system",
        mcp_config_path=str(tmp_path / "mcp.json"), allowed_tools=[],
        cwd=str(tmp_path), model="audit-model",
    )

    assert not result.ok and calls == 1
    disabled = next(
        event for event in result.events if event.get("phase") == "disabled"
    )
    assert disabled["reason"] == "durable_ledger_unavailable"
