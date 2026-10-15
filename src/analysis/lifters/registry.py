"""Lifter registry: arch-id + fingerprint → best lifter selection."""

from __future__ import annotations

from . import pcode_lifter, vex_lifter, fallback_lifter
from .base import LiftOutcome, LiftRequest, LifUnavailable

_LIFTERS: list = []


def register_lifters() -> None:
    """Register in preference order: pcode (widest), pyvex (fast), fallback."""
    global _LIFTERS
    _LIFTERS = [pcode_lifter, vex_lifter, fallback_lifter]


def get_lifter() -> list:
    """Return the registered lifter chain (registration is lazy)."""
    if not _LIFTERS:
        register_lifters()
    return _LIFTERS


def lift(req: LiftRequest) -> LiftOutcome:
    """Try each registered lifter in preference order; return first success.

    The outcome carries the lifter name + confidence; the caller (router)
    *also* tries the next lifter for dual-lifter agreement checks where
    confidence matters more than raw coverage.
    """
    errors: list[str] = []
    for lifter in get_lifter():
        try:
            return lifter.lift(req)
        except LifUnavailable as exc:
            errors.append(str(exc))
    raise LifUnavailable("no lifter could handle this bytes+isa; "
                          + "; ".join(errors))


def dual_lift(req: LiftRequest) -> tuple[LiftOutcome | None, LiftOutcome | None]:
    """Run every applicable lifter; return (best, alternate) for agreement checks."""
    outcomes: list[LiftOutcome] = []
    for lifter in get_lifter():
        try:
            outcomes.append(lifter.lift(req))
            if len(outcomes) >= 2:
                break
        except LifUnavailable:
            continue
    best = outcomes[0] if outcomes else None
    alt = outcomes[1] if len(outcomes) > 1 else None
    return best, alt
