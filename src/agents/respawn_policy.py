"""Deterministic, provider-neutral worker failure and respawn policy.

Only trusted runtime channels (typed events, process stderr, return codes, and
local exception types) may classify infrastructure failures.  Agent prose is
deliberately absent so a worker cannot prompt-inject the supervisor into
granting itself another attempt or selecting a different provider.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence

from .retry_harness import classify_transient_failure
from .runtime import AgentResult
from .scratch_quota import SCRATCH_QUOTA_EXIT
from .network_guard import NETWORK_POLICY_EXIT


POLICY_VERSION = 3

FAILURE_CATEGORIES = frozenset({
    "quality_gap",
    "verification_gap",
    "provider_transient_exhausted",
    "context_exhausted",
    "provider_auth",
    "provider_quota",
    "local_resource_exhausted",
    "network_policy_violation",
    "provider_permanent",
    "budget_exhausted",
    "tool_unavailable",
    "output_quarantined",
    "off_target_output",
    "duplicate_dispatch",
    "runtime_exception",
    "runtime_failure",
})
FAILURE_STAGES = frozenset({
    "analyst", "reviewer", "adversarial", "verification", "supervisor",
})
RESPAWN_ACTIONS = frozenset({"split", "retry_same", "reroute", "stop"})
_CATEGORY_ACTION = {
    "quality_gap": "split",
    "verification_gap": "split",
    "provider_transient_exhausted": "reroute",
    "context_exhausted": "reroute",
    "provider_auth": "reroute",
    "provider_quota": "reroute",
    "local_resource_exhausted": "stop",
    "network_policy_violation": "stop",
    "provider_permanent": "reroute",
    "budget_exhausted": "stop",
    "tool_unavailable": "stop",
    "output_quarantined": "stop",
    "off_target_output": "reroute",
    "duplicate_dispatch": "stop",
    "runtime_exception": "stop",
    "runtime_failure": "stop",
}
_NON_INFRASTRUCTURE = frozenset({
    "quality_gap", "verification_gap", "output_quarantined", "off_target_output",
    "network_policy_violation",
})
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

_AUTH_RE = re.compile(
    r"(?i)(?:auth(?:entication|orization)?|unauthorized|forbidden|"
    r"invalid[_ -]?api[_ -]?key|permission denied|not logged in|login required)"
)
_QUOTA_RE = re.compile(
    r"(?i)(?:billing|insufficient[_ -]?(?:credit|fund|quota)|"
    r"quota[_ -]?(?:exceeded|exhausted|limit[_ -]?(?:reached|exceeded))|"
    r"usage[_ -]?(?:exhausted|limit[_ -]?(?:reached|exceeded))|"
    r"spend[_ -]?limit|credits?[_ -]?(?:exhausted|insufficient)|"
    r"balance[_ -]?too[_ -]?low)"
)
_CONTEXT_RE = re.compile(
    r"(?i)(?:context[_ -]?(?:length|window)|maximum context length|"
    r"prompt is too long|context overflow)"
)
_PERMANENT_RE = re.compile(
    r"(?i)(?:invalid[_ -]?request|malformed|unsupported model|model not found|"
    r"request (?:body|size).{0,40}(?:too large|exceed)|payload too large)"
)
_TOOL_RE = re.compile(
    r"(?i)(?:(?:claude|codex) cli not found|command not found|no such file or directory|"
    r"mcp.{0,80}(?:tool|server).{0,80}(?:not found|unknown|disabled|incompatible)|"
    r"unknown tool|tool.{0,60}(?:not found|unavailable))"
)


@dataclass(frozen=True)
class WorkerFailure:
    """A bounded, checkpoint-safe control record; never contains model prose."""

    category: str
    stage: str
    action: str
    retryable: bool
    infrastructure: bool
    returncode: int = 0
    source_agent: str = ""
    reason_codes: tuple[str, ...] = ()
    policy_version: int = POLICY_VERSION

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["reason_codes"] = list(self.reason_codes)
        return value


def failure_from_dict(value: Mapping[str, object] | None) -> WorkerFailure | None:
    """Strictly restore a failure record, rejecting unknown policy/control data."""

    if not value:
        return None
    try:
        category = str(value["category"])
        stage = str(value["stage"])
        action = str(value["action"])
        policy_version = int(value["policy_version"])
        returncode = int(value.get("returncode") or 0)
        source_agent = str(value.get("source_agent") or "")
        raw_codes = value.get("reason_codes") or []
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("malformed worker failure record") from exc
    if policy_version != POLICY_VERSION:
        raise ValueError("unsupported worker failure policy version")
    if category not in FAILURE_CATEGORIES or stage not in FAILURE_STAGES:
        raise ValueError("unknown worker failure category or stage")
    if action not in RESPAWN_ACTIONS:
        raise ValueError("unknown worker failure action")
    if not isinstance(value.get("retryable"), bool) or not isinstance(
        value.get("infrastructure"), bool
    ):
        raise ValueError("worker failure booleans are not typed")
    if action != _CATEGORY_ACTION[category]:
        raise ValueError("worker failure action does not match its category")
    if bool(value["retryable"]) != (action != "stop"):
        raise ValueError("worker failure retryability does not match its action")
    if bool(value["infrastructure"]) != (category not in _NON_INFRASTRUCTURE):
        raise ValueError("worker failure infrastructure flag does not match its category")
    if not isinstance(raw_codes, (list, tuple)) or len(raw_codes) > 8:
        raise ValueError("worker failure reason codes are invalid")
    codes = tuple(str(item) for item in raw_codes)
    if any(_SAFE_CODE.fullmatch(item) is None for item in codes):
        raise ValueError("worker failure reason code is unsafe")
    if source_agent and _SAFE_AGENT.fullmatch(source_agent) is None:
        raise ValueError("worker failure source agent is unsafe")
    return WorkerFailure(
        category=category,
        stage=stage,
        action=action,
        retryable=bool(value["retryable"]),
        infrastructure=bool(value["infrastructure"]),
        returncode=returncode,
        source_agent=source_agent,
        reason_codes=codes,
        policy_version=policy_version,
    )


def quality_failure(*, stage: str, verification: bool = False) -> WorkerFailure:
    return WorkerFailure(
        category="verification_gap" if verification else "quality_gap",
        stage=stage,
        action="split",
        retryable=True,
        infrastructure=False,
        reason_codes=("binary_verification_failed",) if verification else ("needs_work",),
    )


def _trusted_text(events: Sequence[Mapping[str, object]], stderr: str) -> str:
    payloads: list[str] = []
    for event in events[-120:]:
        if not isinstance(event, Mapping):
            continue
        if event.get("type") in {
            "error", "angerona_agent_retry", "angerona_context_recovery",
            "angerona_audit_budget",
        }:
            try:
                payloads.append(json.dumps(event, ensure_ascii=True, sort_keys=True)[:4000])
            except (TypeError, ValueError):
                continue
    if isinstance(stderr, str) and stderr.strip():
        payloads.append(stderr[-20_000:])
    return "\n".join(payloads)


def _failure(
    category: str,
    stage: str,
    action: str,
    *,
    result: AgentResult,
    source_agent: str,
    reason_codes: tuple[str, ...],
) -> WorkerFailure:
    return WorkerFailure(
        category=category,
        stage=stage,
        action=action,
        retryable=action != "stop",
        infrastructure=category not in _NON_INFRASTRUCTURE,
        returncode=int(result.returncode),
        source_agent=source_agent,
        reason_codes=reason_codes,
    )


def classify_agent_failure(
    result: AgentResult,
    *,
    stage: str,
    source_agent: str,
) -> WorkerFailure:
    """Classify a terminal failed dispatch without consulting ``final_text``."""

    if stage not in FAILURE_STAGES:
        raise ValueError("unknown failure stage")
    events = [event for event in result.events[-120:] if isinstance(event, Mapping)]
    if result.returncode == NETWORK_POLICY_EXIT:
        return _failure(
            "network_policy_violation", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("candidate_network_policy_rejected",),
        )
    if result.returncode == SCRATCH_QUOTA_EXIT:
        return _failure(
            "local_resource_exhausted", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("candidate_scratch_quota_exhausted",),
        )
    if result.returncode == 71:
        return _failure(
            "output_quarantined", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("output_boundary_rejected",),
        )
    if result.returncode == 70:
        return _failure(
            "off_target_output", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=("off_target_rejected",),
        )

    retry_events = [
        event for event in events
        if event.get("type") == "angerona_agent_retry"
    ]
    if any(event.get("phase") == "duplicate_suppressed" for event in retry_events):
        return _failure(
            "duplicate_dispatch", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("duplicate_suppressed",),
        )
    budget_events = [
        event for event in events
        if event.get("type") == "angerona_audit_budget"
    ]
    if any(
        event.get("phase") == "denied"
        or (
            isinstance(event.get("status"), Mapping)
            and event["status"].get("normal_exhausted") is True
        )
        or (
            isinstance(event.get("status"), Mapping)
            and event["status"].get("hard_exhausted") is True
        )
        for event in budget_events
    ):
        return _failure(
            "budget_exhausted", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("audit_budget_exhausted",),
        )

    exhausted = [event for event in retry_events if event.get("phase") == "exhausted"]
    if exhausted:
        event = exhausted[-1]
        category = str(event.get("category") or "")
        reason = str(event.get("reason") or "retry_exhausted")
        if _SAFE_CODE.fullmatch(reason) is None:
            reason = "retry_exhausted"
        return _failure(
            "provider_transient_exhausted", stage, "reroute", result=result,
            source_agent=source_agent,
            reason_codes=tuple(code for code in (category, reason) if _SAFE_CODE.fullmatch(code)),
        )

    trusted_stderr = result.raw_stderr if isinstance(result.raw_stderr, str) else ""
    trusted = _trusted_text(events, trusted_stderr)
    if _CONTEXT_RE.search(trusted):
        return _failure(
            "context_exhausted", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=("context_recovery_exhausted",),
        )
    if _AUTH_RE.search(trusted):
        return _failure(
            "provider_auth", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=("authentication_failed",),
        )
    if _QUOTA_RE.search(trusted):
        return _failure(
            "provider_quota", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=("provider_quota_exhausted",),
        )
    if _PERMANENT_RE.search(trusted):
        return _failure(
            "provider_permanent", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=("nonretryable_request",),
        )
    if _TOOL_RE.search(trusted) or result.returncode in {126, 127}:
        return _failure(
            "tool_unavailable", stage, "stop", result=result,
            source_agent=source_agent, reason_codes=("required_tool_unavailable",),
        )
    transient = classify_transient_failure(
        returncode=result.returncode,
        events=events,
        stderr=trusted_stderr,
    )
    if transient is not None or result.returncode in {124, os.EX_TEMPFAIL}:
        reason = transient.category if transient is not None else "temporary_exit"
        return _failure(
            "provider_transient_exhausted", stage, "reroute", result=result,
            source_agent=source_agent, reason_codes=(reason,),
        )
    return _failure(
        "runtime_failure", stage, "stop", result=result,
        source_agent=source_agent, reason_codes=("unclassified_process_failure",),
    )


def classify_worker_exception(exc: BaseException, *, source_agent: str) -> WorkerFailure:
    """Convert local exceptions to symbolic policy data without persisting messages."""

    name = type(exc).__name__
    message = str(exc)[-4000:]
    if name == "AuditBudgetDenied":
        category, action, code = "budget_exhausted", "stop", "audit_budget_denied"
    elif isinstance(exc, (TimeoutError, ConnectionError)):
        category, action, code = (
            "provider_transient_exhausted", "reroute", "runtime_transport_exception"
        )
    elif _TOOL_RE.search(message):
        category, action, code = "tool_unavailable", "stop", "required_tool_unavailable"
    else:
        category, action, code = "runtime_exception", "stop", "unexpected_runtime_exception"
    return WorkerFailure(
        category=category,
        stage="supervisor",
        action=action,
        retryable=action != "stop",
        infrastructure=True,
        source_agent=source_agent,
        reason_codes=(code,),
    )
