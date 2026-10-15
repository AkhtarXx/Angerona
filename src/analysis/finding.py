"""Canonical Finding schema — verdict tiers every module must emit.

Architectural invariant (per 20-year veteran review): the verdict tier belongs
to the *module*, not to a later pipeline wrap.  Modules emit ``Finding``
objects with an explicit verdict, and orchestrators only enforce/aggregate.

Verdict tiers (final, don't extend casually):
  * CONFIRMED        — runtime / cryptographic proof
  * LIKELY           — strong multi-signal static evidence
  * INCONCLUSIVE     — weak signal, missing context, or no runtime gate
  * NOT_APPLICABLE   — wrong layer, unsupported platform, etc.
  * REFUSAL          — module honestly declines to claim (packer-resistant etc.)
"""

from __future__ import annotations

from dataclasses import dataclass, field

TRUST_TAG = "untrusted_child"

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_APPLICABLE = "NOT_APPLICABLE"
REFUSAL = "REFUSAL"

_VALID = {CONFIRMED, LIKELY, INCONCLUSIVE, NOT_APPLICABLE, REFUSAL}


@dataclass
class Finding:
    module: str
    kind: str
    severity: str            # critical | high | medium | low | info
    verdict: str             # one of CONFIRMED / LIKELY / INCONCLUSIVE / NOT_APPLICABLE / REFUSAL
    detail: str
    evidence: str = ""
    rule_layer: str = ""     # "java" | "native" | "manifest" | "binary" — for layer gating
    line_no: int = 0
    runtime_corroborated: bool = False
    metadata: dict = field(default_factory=dict)
    trust: str = TRUST_TAG

    def __post_init__(self) -> None:
        if self.verdict not in _VALID:
            raise ValueError(f"invalid verdict: {self.verdict!r}")

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "kind": self.kind,
            "severity": self.severity,
            "verdict": self.verdict,
            "detail": self.detail,
            "evidence": self.evidence,
            "rule_layer": self.rule_layer,
            "line_no": self.line_no,
            "runtime_corroborated": self.runtime_corroborated,
            "metadata": self.metadata,
            "trust": self.trust,
        }


def coerce_legacy_dict(module: str, d: dict, default_verdict: str = LIKELY) -> Finding:
    """Bridge: wrap an older dict-shaped finding in the canonical schema.

    Used during migration — modules that already emit dicts keep their API
    stable while gradually switching to :class:`Finding` return types.
    """
    v = d.get("verdict", default_verdict)
    # Legacy modules may use custom verdict vocabulary (e.g. ``encrypted-suspect``,
    # ``safe-default``) that is not in the canonical 5-tier set — degrade to the
    # default verdict and preserve the original in metadata for traceability.
    verdict = v if v in _VALID else default_verdict
    metadata = {k: val for k, val in d.items()
                if k not in {"kind", "rule", "severity", "verdict", "detail",
                             "message", "evidence", "rule_layer", "line_no",
                             "runtime_corroborated", "trust"}}
    if v not in _VALID:
        metadata.setdefault("legacy_verdict", v)
    return Finding(
        module=module,
        kind=d.get("kind", d.get("rule", "unknown")),
        severity=d.get("severity", "medium"),
        verdict=verdict,
        detail=d.get("detail", d.get("message", d.get("evidence", ""))),
        evidence=d.get("evidence", ""),
        rule_layer=d.get("rule_layer", ""),
        line_no=d.get("line_no", 0),
        runtime_corroborated=bool(d.get("runtime_corroborated", False)),
        metadata=metadata,
    )
