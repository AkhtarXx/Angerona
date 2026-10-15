"""Android audit pipeline orchestration.

A professional never runs 25 modules independently and glues the outputs by
hand;  they follow a strict sequence that MATTERS:

  provenance → packer-id → (maybe) runtime-DEX-extract → TLS-stack →
  runtime exported-surface → MTLS-tier → rule scanners → fusion verdicts.

This package exposes ``run_android_audit()`` which encodes that order and
produces a single ``AuditReport`` with verdict tiers.  Every module's output
is tagged ``untrusted_child`` unless runtime-corroborated;  anything without
corroboration is reported as ``INCONCLUSIVE``, never ``SAFE``.
"""

from src.pipeline.android_audit import (  # noqa: F401
    AuditFinding,
    AuditReport,
    run_android_audit,
)
