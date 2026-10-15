"""Universal lifting front-ends: bytes -> CanonicalIR.

Three-lifter design from `MASTER_PLAN` Phase 3:
  * pcode_lifter   — primary, pypcode (SLEIGH semantics, ~180 variants)
  * vex_lifter     — fast path when angr/pyvex supports the guest (10 ISAs)
  * fallback_lifter — irnorm-based 90% coverage shim

All lifters produce a CanonicalIR-agnostic :class:`LiftOutcome` with a
confidence tier and honest provenance — never silently fabricate an IR.
"""

from .base import (LiftOutcome, LiftRequest, LifUnavailable)
from .registry import get_lifter, register_lifters

__all__ = ["LiftOutcome", "LiftRequest", "LifUnavailable",
           "get_lifter", "register_lifters"]
