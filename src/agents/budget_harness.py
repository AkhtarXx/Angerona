"""Crash-safe, provider-neutral budget control for a complete agent audit.

The controller reserves capacity before a model dispatch, commits measured usage
afterwards, and conservatively charges reservations whose owning process crashes.
All transitions are atomically replaced under a cross-process lock and hash-chained.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..observability import ledger_for_workspace
from ..secure_artifacts import SecureArtifactStore
from .context_harness import ContextHarnessConfig
from .retry_harness import RetryPolicy


DEFAULT_MAX_CALLS = 64
DEFAULT_MAX_WALL_SECONDS = 21_600.0
DEFAULT_CRITICAL_RESERVE_CALLS = 4
DEFAULT_TOKEN_RESERVATION = 32_768
DEFAULT_COST_RESERVATION_USD = 1.0
MAX_RECORDS = 16_384
MAX_STATE_BYTES = 8_000_000


class AuditBudgetError(RuntimeError):
    """The durable budget ledger is corrupt, incompatible, or unavailable."""


class AuditBudgetDenied(AuditBudgetError):
    """A dispatch cannot be admitted without violating the audit budget."""

    def __init__(self, reason: str, status: Mapping[str, object]):
        super().__init__(reason)
        self.reason = reason
        self.status = dict(status)


@dataclass(frozen=True)
class AuditBudgetPolicy:
    max_calls: int = DEFAULT_MAX_CALLS
    max_wall_seconds: float = DEFAULT_MAX_WALL_SECONDS
    max_tokens: int = 0
    max_cost_usd: float = 0.0
    critical_reserve_calls: int = DEFAULT_CRITICAL_RESERVE_CALLS
    token_reservation_per_call: int = DEFAULT_TOKEN_RESERVATION
    cost_reservation_per_call_usd: float = DEFAULT_COST_RESERVATION_USD
    dispatch_call_reservation: int = 4

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        *,
        max_calls: int | None = None,
        max_wall_seconds: float | None = None,
        max_tokens: int | None = None,
        max_cost_usd: float | None = None,
        critical_reserve_calls: int | None = None,
    ) -> "AuditBudgetPolicy":
        calls = _bounded_int(
            max_calls if max_calls is not None else env.get("ANGERONA_AUDIT_MAX_AGENT_CALLS"),
            DEFAULT_MAX_CALLS, 1, 10_000,
        )
        runtime_attempt_bound = (
            RetryPolicy.from_env(env).max_attempts
            + ContextHarnessConfig.from_env(env).max_recoveries
        )
        configured_dispatch_reservation = _bounded_int(
            env.get("ANGERONA_AUDIT_DISPATCH_CALL_RESERVATION"),
            runtime_attempt_bound, 1, 100,
        )
        dispatch_reservation = max(
            runtime_attempt_bound,
            configured_dispatch_reservation,
        )
        raw_reserve = _bounded_int(
            critical_reserve_calls if critical_reserve_calls is not None
            else env.get("ANGERONA_AUDIT_CRITICAL_RESERVE_CALLS"),
            DEFAULT_CRITICAL_RESERVE_CALLS, 0, calls - 1,
        )
        reserve = (
            0 if raw_reserve == 0
            else min(calls - 1, max(raw_reserve, dispatch_reservation))
        )
        return cls(
            max_calls=calls,
            max_wall_seconds=_bounded_float(
                max_wall_seconds if max_wall_seconds is not None
                else env.get("ANGERONA_AUDIT_MAX_WALL_SECONDS"),
                DEFAULT_MAX_WALL_SECONDS, 0.0, 604_800.0,
            ),
            max_tokens=_bounded_int(
                max_tokens if max_tokens is not None
                else env.get("ANGERONA_AUDIT_MAX_AGENT_TOKENS"),
                0, 0, 10_000_000_000,
            ),
            max_cost_usd=_bounded_float(
                max_cost_usd if max_cost_usd is not None
                else env.get("ANGERONA_AUDIT_MAX_COST_USD"),
                0.0, 0.0, 1_000_000.0,
            ),
            critical_reserve_calls=reserve,
            token_reservation_per_call=_bounded_int(
                env.get("ANGERONA_AUDIT_TOKEN_RESERVATION_PER_CALL"),
                DEFAULT_TOKEN_RESERVATION, 1, 10_000_000,
            ),
            cost_reservation_per_call_usd=_bounded_float(
                env.get("ANGERONA_AUDIT_COST_RESERVATION_PER_CALL_USD"),
                DEFAULT_COST_RESERVATION_USD, 0.01, 100_000.0,
            ),
            dispatch_call_reservation=dispatch_reservation,
        )

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.as_dict())).hexdigest()


@dataclass(frozen=True)
class AgentUsage:
    tokens: int = 0
    cost_usd: float = 0.0
    token_measurement_available: bool = False
    cost_measurement_available: bool = False
    token_measurements: int = 0
    cost_measurements: int = 0
    attempts: int = 1


@dataclass(frozen=True)
class BudgetReservation:
    reservation_id: str
    priority: str
    agent: str
    phase: str
    reserved_calls: int
    reserved_tokens: int
    reserved_cost_microusd: int


def _bounded_int(value: object, default: int, lower: int, upper: int) -> int:
    try:
        parsed = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    return max(lower, min(upper, parsed))


def _bounded_float(value: object, default: float, lower: float, upper: float) -> float:
    try:
        parsed = float(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        parsed = default
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        parsed = default
    return max(lower, min(upper, parsed))


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"), default=str,
    ).encode("utf-8")


def extract_agent_usage(events: Sequence[Mapping[str, object]]) -> AgentUsage:
    """Extract usage from Claude/Codex-style trusted runtime events.

    Unknown providers still consume call and wall budgets. Token/cost limits use a
    conservative fixed reservation whenever a provider omits those measurements.
    """

    tokens_by_attempt: dict[int, int] = {}
    costs_by_attempt: dict[int, float] = {}
    attempts = 0
    context_recoveries = 0
    input_aliases = {"input_tokens", "input_token_count", "prompt_tokens"}
    output_aliases = {"output_tokens", "output_token_count", "completion_tokens"}
    claude_cache_aliases = {"cache_creation_input_tokens", "cache_read_input_tokens"}
    cached_subset_aliases = {"cached_input_tokens", "cached_tokens"}
    reasoning_subset_aliases = {"reasoning_tokens"}
    total_aliases = {"total_tokens", "total_token_count"}

    for event in events:
        if event.get("type") == "angerona_agent_retry" and event.get("phase") == "attempt_started":
            attempts += 1
        if event.get("type") == "angerona_context_recovery":
            context_recoveries += 1
        attempt_bucket = max(1, attempts, 1 + context_recoveries)
        usage = event.get("usage")
        if not isinstance(usage, Mapping):
            response = event.get("response")
            usage = response.get("usage") if isinstance(response, Mapping) else None
        if isinstance(usage, Mapping):
            values: dict[str, int] = {}
            for key, raw in usage.items():
                normalized = str(key).strip().lower()
                if normalized not in (
                    input_aliases | output_aliases | claude_cache_aliases
                    | cached_subset_aliases | reasoning_subset_aliases | total_aliases
                ):
                    continue
                if isinstance(raw, bool):
                    continue
                try:
                    values[normalized] = max(0, int(raw))
                except (TypeError, ValueError):
                    continue
            total_values = [values[key] for key in total_aliases if key in values]
            if total_values:
                measured = max(total_values)
            else:
                primary_input = max(
                    (values[key] for key in input_aliases if key in values),
                    default=0,
                )
                cached_subset = max(
                    (values[key] for key in cached_subset_aliases if key in values),
                    default=0,
                )
                primary_output = max(
                    (values[key] for key in output_aliases if key in values),
                    default=0,
                )
                reasoning_subset = max(
                    (values[key] for key in reasoning_subset_aliases if key in values),
                    default=0,
                )
                measured = (
                    (primary_input or cached_subset)
                    + sum(values.get(key, 0) for key in claude_cache_aliases)
                    + (primary_output or reasoning_subset)
                )
            if values:
                # Provider streams may repeat cumulative usage within one attempt.
                # Keep the largest observation for that attempt instead of summing it.
                tokens_by_attempt[attempt_bucket] = max(
                    measured, tokens_by_attempt.get(attempt_bucket, 0)
                )
        for key in ("total_cost_usd", "cost_usd"):
            raw_cost = event.get(key)
            if raw_cost is None and isinstance(usage, Mapping):
                raw_cost = usage.get(key)
            if raw_cost is None:
                continue
            try:
                value = float(raw_cost)
            except (TypeError, ValueError):
                continue
            if value == value and value >= 0 and value != float("inf"):
                costs_by_attempt[attempt_bucket] = max(
                    value, costs_by_attempt.get(attempt_bucket, 0.0)
                )
                break
    measured_attempts = max(
        attempts,
        1 + context_recoveries,
        max(tokens_by_attempt, default=0),
        max(costs_by_attempt, default=0),
        1,
    )
    return AgentUsage(
        tokens=sum(tokens_by_attempt.values()),
        cost_usd=sum(costs_by_attempt.values()),
        token_measurement_available=bool(tokens_by_attempt),
        cost_measurement_available=bool(costs_by_attempt),
        token_measurements=len(tokens_by_attempt),
        cost_measurements=len(costs_by_attempt),
        attempts=measured_attempts,
    )


class AuditBudgetController:
    """Atomic admission control and durable accounting for one audit workspace."""

    def __init__(
        self,
        workspace_root: str | Path,
        policy: AuditBudgetPolicy,
        *,
        contract_sha256: str,
        resume: bool = False,
        minimum_sequence: int = 0,
        minimum_record_sha256: str = "",
    ) -> None:
        if not contract_sha256 or len(contract_sha256) != 64:
            raise ValueError("budget controller requires the immutable run-contract digest")
        self.policy = policy
        self.contract_sha256 = contract_sha256
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.observability = ledger_for_workspace(self.workspace_root)
        self._observed_sequence = 0
        self.store = SecureArtifactStore(workspace_root, "raw/audit_budget")
        self._thread_lock = threading.RLock()
        self._closed = False
        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                if resume:
                    raise AuditBudgetError(
                        "exact resume refused: durable audit budget ledger is missing"
                    )
                started_ns = time.time_ns()
                deadline_ns = (
                    started_ns + int(policy.max_wall_seconds * 1_000_000_000)
                    if policy.max_wall_seconds > 0 else None
                )
                state = {
                    "schema_version": 1,
                    "contract_sha256": contract_sha256,
                    "policy": policy.as_dict(),
                    "policy_sha256": policy.sha256,
                    "records": [],
                }
                self._append(
                    state, "genesis", started_ns=started_ns,
                    deadline_unix_ns=deadline_ns,
                )
                self._save(state)
            else:
                self._validate_identity(state)
                self._validate_minimum_anchor(
                    state,
                    sequence=minimum_sequence,
                    record_sha256=minimum_record_sha256,
                )
                if resume:
                    self._reconcile_abandoned(state)
            deadline = self._replay(state)["deadline_unix_ns"]
            self._live_deadline_monotonic = (
                None if deadline is None
                else time.monotonic() + max(
                    0.0, (int(deadline) - time.time_ns()) / 1_000_000_000
                )
            )

    def _load_optional(self) -> dict | None:
        try:
            raw = self.store.read_bytes("state.json")
        except FileNotFoundError:
            return None
        if len(raw) > MAX_STATE_BYTES:
            raise AuditBudgetError("audit budget ledger is oversized")
        try:
            state = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditBudgetError("audit budget ledger is not valid JSON") from exc
        if not isinstance(state, dict) or not isinstance(state.get("records"), list):
            raise AuditBudgetError("audit budget ledger schema mismatch")
        if len(state["records"]) > MAX_RECORDS:
            raise AuditBudgetError("audit budget ledger record limit exceeded")
        if not state["records"]:
            raise AuditBudgetError("audit budget ledger has no genesis record")
        previous = None
        for sequence, record in enumerate(state["records"], 1):
            if not isinstance(record, dict):
                raise AuditBudgetError("audit budget record is invalid")
            digest = record.get("sha256")
            body = {key: value for key, value in record.items() if key != "sha256"}
            if (
                record.get("sequence") != sequence
                or record.get("previous_sha256") != previous
                or digest != hashlib.sha256(_canonical_bytes(body)).hexdigest()
            ):
                raise AuditBudgetError("audit budget hash chain is corrupt")
            previous = digest
        genesis_records = [
            record for record in state["records"] if record.get("kind") == "genesis"
        ]
        if len(genesis_records) != 1 or state["records"][0].get("kind") != "genesis":
            raise AuditBudgetError(
                "audit budget ledger must start with exactly one genesis record"
            )
        head_names = sorted(
            name for name in self.store.list_names()
            if name.startswith("head-") and name.endswith(".json")
        )
        if head_names:
            try:
                highest_sequence = max(
                    int(name.removeprefix("head-").removesuffix(".json"))
                    for name in head_names
                )
                head = json.loads(
                    self.store.read_bytes(f"head-{highest_sequence:08d}.json")
                )
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuditBudgetError("audit budget durable head is invalid") from exc
            if (
                highest_sequence > len(state["records"])
                or not isinstance(head, dict)
                or head.get("sequence") != highest_sequence
                or head.get("record_sha256")
                != state["records"][highest_sequence - 1].get("sha256")
            ):
                raise AuditBudgetError("audit budget ledger was rolled back behind durable head")
        return state

    def _validate_identity(self, state: Mapping[str, object]) -> None:
        if (
            state.get("schema_version") != 1
            or state.get("contract_sha256") != self.contract_sha256
            or state.get("policy_sha256") != self.policy.sha256
            or state.get("policy") != self.policy.as_dict()
        ):
            raise AuditBudgetError(
                "exact resume refused: audit budget policy/contract does not match ledger"
            )

    @staticmethod
    def _validate_minimum_anchor(
        state: Mapping[str, object], *, sequence: int, record_sha256: str
    ) -> None:
        if not sequence and not record_sha256:
            return
        records = list(state.get("records") or [])
        if (
            sequence < 1
            or len(records) < sequence
            or len(record_sha256) != 64
            or records[sequence - 1].get("sha256") != record_sha256
        ):
            raise AuditBudgetError(
                "exact resume refused: audit budget ledger predates checkpoint anchor"
            )

    def _save(self, state: Mapping[str, object]) -> None:
        raw = json.dumps(
            state, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2
        ).encode("utf-8")
        if len(raw) > MAX_STATE_BYTES:
            raise AuditBudgetError("audit budget ledger would exceed size limit")
        self.store.replace_bytes_atomic("state.json", raw)
        records = list(state.get("records") or [])
        if records:
            last = records[-1]
            head = _canonical_bytes({
                "schema_version": 1,
                "sequence": int(last["sequence"]),
                "record_sha256": str(last["sha256"]),
                "contract_sha256": self.contract_sha256,
                "policy_sha256": self.policy.sha256,
            })
            self.store.write_bytes_atomic(
                f"head-{int(last['sequence']):08d}.json", head
            )
            sequence = int(last["sequence"])
            if sequence > self._observed_sequence:
                self.observability.emit(
                    component="budget_harness",
                    category="budget",
                    action=str(last.get("kind") or "state_changed"),
                    attributes={
                        "sequence": sequence,
                        "record_sha256": str(last["sha256"]),
                        **dict(last.get("data") or {}),
                    },
                )
                self._observed_sequence = sequence

    def _append(self, state: dict, kind: str, **data: object) -> None:
        records = state["records"]
        if len(records) >= MAX_RECORDS:
            raise AuditBudgetError("audit budget ledger record limit exceeded")
        body = {
            "sequence": len(records) + 1,
            "previous_sha256": records[-1]["sha256"] if records else None,
            "time_ns": time.time_ns(),
            "kind": kind,
            "data": data,
        }
        body["sha256"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        records.append(body)

    @staticmethod
    def _replay(state: Mapping[str, object]) -> dict[str, object]:
        records = list(state.get("records") or [])
        genesis = records[0]
        active: dict[str, dict] = {}
        calls = 0
        tokens = 0
        cost_microusd = 0
        agent_seconds = 0.0
        last_reason = ""
        for record in records:
            kind = record.get("kind")
            data = dict(record.get("data") or {})
            if kind == "reserved":
                active[str(data["reservation_id"])] = data
            elif kind in {"committed", "abandoned", "cancelled"}:
                reservation_id = str(data.get("reservation_id") or "")
                reservation = active.pop(reservation_id, {})
                if kind == "cancelled":
                    continue
                calls += int(data.get("charged_calls", reservation.get("reserved_calls", 1)) or 0)
                tokens += int(data.get("charged_tokens", reservation.get("reserved_tokens", 0)) or 0)
                cost_microusd += int(
                    data.get("charged_cost_microusd", reservation.get("reserved_cost_microusd", 0)) or 0
                )
                agent_seconds += float(data.get("elapsed_seconds") or 0.0)
            elif kind == "denied":
                last_reason = str(data.get("reason") or last_reason)
        reserved_calls = sum(int(item.get("reserved_calls") or 0) for item in active.values())
        reserved_tokens = sum(int(item.get("reserved_tokens") or 0) for item in active.values())
        reserved_cost = sum(int(item.get("reserved_cost_microusd") or 0) for item in active.values())
        gdata = dict(genesis.get("data") or {})
        return {
            "calls": calls,
            "tokens": tokens,
            "cost_microusd": cost_microusd,
            "agent_seconds": agent_seconds,
            "active": active,
            "reserved_calls": reserved_calls,
            "reserved_tokens": reserved_tokens,
            "reserved_cost_microusd": reserved_cost,
            "started_ns": int(gdata.get("started_ns") or 0),
            "deadline_unix_ns": gdata.get("deadline_unix_ns"),
            "last_denial_reason": last_reason,
        }

    def _reconcile_abandoned(self, state: dict) -> None:
        replay = self._replay(state)
        for reservation_id, reservation in dict(replay["active"]).items():
            self._append(
                state, "abandoned", reservation_id=reservation_id,
                charged_calls=int(reservation.get("reserved_calls") or 1),
                charged_tokens=int(reservation.get("reserved_tokens") or 0),
                charged_cost_microusd=int(reservation.get("reserved_cost_microusd") or 0),
                elapsed_seconds=0.0,
                reason="process_crash_or_unclean_shutdown",
            )
        if replay["active"]:
            self._save(state)

    def _status_from_state(self, state: Mapping[str, object]) -> dict[str, object]:
        replay = self._replay(state)
        now_ns = time.time_ns()
        deadline = replay["deadline_unix_ns"]
        wall_remaining = (
            None if deadline is None
            else max(0.0, (int(deadline) - now_ns) / 1_000_000_000)
        )
        live_remaining = (
            None if self._live_deadline_monotonic is None
            else max(0.0, self._live_deadline_monotonic - time.monotonic())
        )
        if wall_remaining is None:
            wall_remaining = live_remaining
        elif live_remaining is not None:
            wall_remaining = min(wall_remaining, live_remaining)
        admission_calls = int(replay["calls"]) + int(replay["reserved_calls"])
        admission_tokens = int(replay["tokens"]) + int(replay["reserved_tokens"])
        admission_cost = int(replay["cost_microusd"]) + int(replay["reserved_cost_microusd"])
        hard_reason = ""
        if wall_remaining == 0.0:
            hard_reason = "audit_wall_deadline_exhausted"
        elif admission_calls >= self.policy.max_calls:
            hard_reason = "agent_call_budget_exhausted"
        elif self.policy.max_tokens and admission_tokens >= self.policy.max_tokens:
            hard_reason = "agent_token_budget_exhausted"
        elif (
            self.policy.max_cost_usd
            and admission_cost >= round(self.policy.max_cost_usd * 1_000_000)
        ):
            hard_reason = "agent_cost_budget_exhausted"
        normal_reason = hard_reason
        if not normal_reason and (
            admission_calls + self.policy.dispatch_call_reservation
            > self.policy.max_calls - self.policy.critical_reserve_calls
        ):
            normal_reason = "critical_reserve_protected"
        if (
            not normal_reason and self.policy.max_tokens
            and admission_tokens
            + self.policy.token_reservation_per_call
            * self.policy.dispatch_call_reservation
            > self.policy.max_tokens
        ):
            normal_reason = "agent_token_budget_exhausted"
        if (
            not normal_reason and self.policy.max_cost_usd
            and admission_cost
            + round(
                self.policy.cost_reservation_per_call_usd
                * self.policy.dispatch_call_reservation * 1_000_000
            )
            > round(self.policy.max_cost_usd * 1_000_000)
        ):
            normal_reason = "agent_cost_budget_exhausted"
        normal_exhausted = bool(normal_reason)
        return {
            "policy_sha256": self.policy.sha256,
            "policy": self.policy.as_dict(),
            "consumed": {
                "calls": int(replay["calls"]),
                "tokens": int(replay["tokens"]),
                "cost_usd": int(replay["cost_microusd"]) / 1_000_000,
                "agent_seconds": round(float(replay["agent_seconds"]), 6),
            },
            "reserved": {
                "calls": int(replay["reserved_calls"]),
                "tokens": int(replay["reserved_tokens"]),
                "cost_usd": int(replay["reserved_cost_microusd"]) / 1_000_000,
                "dispatches": len(replay["active"]),
            },
            "remaining": {
                "calls": max(0, self.policy.max_calls - admission_calls),
                "tokens": (
                    None if not self.policy.max_tokens
                    else max(0, self.policy.max_tokens - admission_tokens)
                ),
                "cost_usd": (
                    None if not self.policy.max_cost_usd
                    else max(0.0, self.policy.max_cost_usd - admission_cost / 1_000_000)
                ),
                "wall_seconds": wall_remaining,
            },
            "deadline_unix_ns": deadline,
            "ledger_sequence": len(list(state.get("records") or [])),
            "ledger_record_sha256": str(
                (list(state.get("records") or [{}])[-1]).get("sha256") or ""
            ),
            "overrun": {
                "calls": admission_calls > self.policy.max_calls,
                "tokens": bool(
                    self.policy.max_tokens and admission_tokens > self.policy.max_tokens
                ),
                "cost": bool(
                    self.policy.max_cost_usd
                    and admission_cost > round(self.policy.max_cost_usd * 1_000_000)
                ),
                "wall": wall_remaining == 0.0,
            },
            "hard_exhausted": bool(hard_reason),
            "normal_exhausted": normal_exhausted,
            "reason": normal_reason,
            "last_denial_reason": replay["last_denial_reason"],
        }

    def status(self) -> dict[str, object]:
        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                raise AuditBudgetError("audit budget ledger disappeared")
            self._validate_identity(state)
            return self._status_from_state(state)

    def reserve(
        self,
        *,
        priority: str,
        agent: str,
        phase: str,
    ) -> BudgetReservation:
        if priority not in {"critical", "normal", "optional"}:
            raise ValueError("budget priority must be critical, normal, or optional")
        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                raise AuditBudgetError("audit budget ledger disappeared")
            self._validate_identity(state)
            status = self._status_from_state(state)
            reserved_calls = self.policy.dispatch_call_reservation
            reserved_tokens = (
                self.policy.token_reservation_per_call * reserved_calls
                if self.policy.max_tokens else 0
            )
            reserved_cost = (
                round(
                    self.policy.cost_reservation_per_call_usd
                    * reserved_calls * 1_000_000
                )
                if self.policy.max_cost_usd else 0
            )
            reason = str(status["reason"] or "")
            if priority == "critical" and reason == "critical_reserve_protected":
                reason = ""
            remaining = dict(status["remaining"])
            if not reason and int(remaining["calls"]) < reserved_calls:
                reason = "agent_call_budget_exhausted"
            if (
                not reason and self.policy.max_tokens
                and int(remaining["tokens"] or 0) < reserved_tokens
            ):
                reason = "agent_token_budget_exhausted"
            if (
                not reason and self.policy.max_cost_usd
                and float(remaining["cost_usd"] or 0.0) + 1e-12
                < reserved_cost / 1_000_000
            ):
                reason = "agent_cost_budget_exhausted"
            if reason:
                self._append(
                    state, "denied", reason=reason, priority=priority,
                    agent=agent, phase=phase,
                )
                self._save(state)
                denied_status = self._status_from_state(state)
                denied_status["reason"] = reason
                raise AuditBudgetDenied(reason, denied_status)
            reservation = BudgetReservation(
                reservation_id=uuid.uuid4().hex,
                priority=priority,
                agent=agent,
                phase=phase,
                reserved_calls=reserved_calls,
                reserved_tokens=reserved_tokens,
                reserved_cost_microusd=reserved_cost,
            )
            self._append(state, "reserved", **asdict(reservation))
            self._save(state)
            return reservation

    def commit(
        self,
        reservation: BudgetReservation,
        *,
        usage: AgentUsage,
        elapsed_seconds: float,
        ok: bool,
        returncode: int,
    ) -> dict[str, object]:
        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                raise AuditBudgetError("audit budget ledger disappeared")
            self._validate_identity(state)
            replay = self._replay(state)
            active = dict(replay["active"])
            if reservation.reservation_id not in active:
                raise AuditBudgetError("budget reservation is missing or already committed")
            unmeasured_token_attempts = max(
                0, usage.attempts - usage.token_measurements
            )
            unmeasured_cost_attempts = max(
                0, usage.attempts - usage.cost_measurements
            )
            charged_tokens = (
                usage.tokens
                + unmeasured_token_attempts * self.policy.token_reservation_per_call
                if self.policy.max_tokens else 0
            )
            charged_cost = (
                round(
                    (
                        usage.cost_usd
                        + unmeasured_cost_attempts
                        * self.policy.cost_reservation_per_call_usd
                    ) * 1_000_000
                )
                if self.policy.max_cost_usd else 0
            )
            self._append(
                state, "committed", reservation_id=reservation.reservation_id,
                charged_calls=max(1, usage.attempts),
                charged_tokens=max(0, charged_tokens),
                charged_cost_microusd=max(0, charged_cost),
                token_measurement_available=usage.token_measurement_available,
                cost_measurement_available=usage.cost_measurement_available,
                elapsed_seconds=max(0.0, float(elapsed_seconds)),
                ok=bool(ok), returncode=int(returncode),
            )
            self._save(state)
            return self._status_from_state(state)

    def abandon(
        self,
        reservation: BudgetReservation,
        *,
        elapsed_seconds: float,
        reason: str,
    ) -> dict[str, object]:
        """Conservatively charge an attempt whose runtime raised unexpectedly."""

        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                raise AuditBudgetError("audit budget ledger disappeared")
            self._validate_identity(state)
            active = dict(self._replay(state)["active"])
            if reservation.reservation_id not in active:
                raise AuditBudgetError("budget reservation is missing or already committed")
            self._append(
                state, "abandoned", reservation_id=reservation.reservation_id,
                charged_calls=reservation.reserved_calls,
                charged_tokens=reservation.reserved_tokens,
                charged_cost_microusd=reservation.reserved_cost_microusd,
                elapsed_seconds=max(0.0, float(elapsed_seconds)),
                reason=str(reason)[:500],
            )
            self._save(state)
            return self._status_from_state(state)

    def cancel(self, reservation: BudgetReservation, *, reason: str) -> dict[str, object]:
        """Release a reservation when the provider process was never launched."""

        with self._thread_lock, self.store.exclusive_lock():
            state = self._load_optional()
            if state is None:
                raise AuditBudgetError("audit budget ledger disappeared")
            self._validate_identity(state)
            active = dict(self._replay(state)["active"])
            if reservation.reservation_id not in active:
                raise AuditBudgetError("budget reservation is missing or already committed")
            self._append(
                state, "cancelled", reservation_id=reservation.reservation_id,
                reason=str(reason)[:500],
            )
            self._save(state)
            return self._status_from_state(state)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.store.close()

    def __enter__(self) -> "AuditBudgetController":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except (AttributeError, OSError):
            pass


def load_budget_status(workspace_root: str | Path) -> dict[str, object] | None:
    """Read and validate a budget ledger without requiring the run-contract inputs."""

    store = SecureArtifactStore(workspace_root, "raw/audit_budget")
    try:
        try:
            raw = store.read_bytes("state.json")
        except FileNotFoundError:
            return None
        if len(raw) > MAX_STATE_BYTES:
            raise AuditBudgetError("audit budget ledger is oversized")
        try:
            state = json.loads(raw)
            policy = AuditBudgetPolicy(**dict(state.get("policy") or {}))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AuditBudgetError("audit budget ledger is invalid") from exc
        controller = object.__new__(AuditBudgetController)
        controller.policy = policy
        controller.contract_sha256 = str(state.get("contract_sha256") or "")
        controller.store = store
        controller._thread_lock = threading.RLock()
        controller._closed = False
        validated = controller._load_optional()
        if validated is None:
            raise AuditBudgetError("audit budget ledger disappeared")
        state = validated
        controller._validate_identity(state)
        deadline = controller._replay(state)["deadline_unix_ns"]
        controller._live_deadline_monotonic = (
            None if deadline is None
            else time.monotonic() + max(
                0.0, (int(deadline) - time.time_ns()) / 1_000_000_000
            )
        )
        return controller._status_from_state(state)
    finally:
        store.close()
