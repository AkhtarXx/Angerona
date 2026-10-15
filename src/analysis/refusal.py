"""Refusal policy: when to refuse gracefully instead of fabricate analysis.

Research basis (research/agnostic/packing-obfuscation_vetted.md §refusals):
  A professional never pretends to have analyzed what it couldn't. When packing
  strength exceeds a threshold and dump/recovery diagnostics are not producible,
  we emit a :class:`UnprotectableReport` with explicit signals and recommended
  analyst steps — never a fabricated CFG or fake finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UnprotectableReport:
    reason: str                     # "packed-vm-heavy" | "iat-unsalvageable" |
                                    # "decoy-twin-process" | "budget-exceeded" |
                                    # "unsupported-family" | "vm-region-over-threshold"
    strength: float
    signals: tuple = ()
    unresolved: tuple = ()
    recommended_analyst_steps: tuple = ()

    def as_dict(self) -> dict:
        return {
            "reason": self.reason,
            "strength": round(self.strength, 3),
            "signals": list(self.signals),
            "unresolved": list(self.unresolved),
            "recommended_analyst_steps": list(self.recommended_analyst_steps),
        }


_VM_REGION_DEFAULT_THRESHOLD = 0.40   # >40% virtualized exec-blob = refuse


def decide_refusal(packing_strength: float,
                    vm_region_ratio: float = 0.0,
                    iat_recoverable: bool = True,
                    decoy_suspected: bool = False,
                    budget_exceeded: bool = False,
                    packing_family: str = "") -> UnprotectableReport | None:
    """Return an UnprotectableReport when analysis is unsafe, else None.

    Conservative defaults; false negatives (skip-refusal) are preferred over
    fabricated analysis. Only concrete handler/trace evidence lifts the refusal.
    """
    # HIGH-confidence packing suspicion alone can block: real PE protectors refuse
    # naive static analysis. Only fire when we have a strong named signal.
    if packing_strength >= 0.80 and packing_family:
        return UnprotectableReport(
            reason="packed-vm-heavy", strength=packing_strength,
            signals=(f"packing_strength={packing_strength:.2f}",
                      f"family={packing_family}",),
            unresolved=("heavy protector detected; static analysis only verified "
                         f"as a {packing_family}-family signature, not behaviour",
                         "unicorn dynamic unblock or Scylla/UPX-vendor tool required",),
            recommended_analyst_steps=(
                "unpack via the vendor-specific detonator (upx -d / de4dot / frida-dexdump)",
                "re-feed the unpacked image through angerona analyze-any",
                "if virtualization-backed, escalate to vm_lift (Phase 9 flagship)",
            ),
        )
    if budget_exceeded:
        return UnprotectableReport(
            reason="budget-exceeded", strength=packing_strength,
            unresolved=("analysis-cost cap reached before verification",),
            recommended_analyst_steps=(
                "raise the wall-clock budget via ANGERONA_AUDIT_MAX_WALL_SECONDS",
                "run the analyst manually under gdb/x64dbg for this family",
            ),
        )
    if decoy_suspected:
        return UnprotectableReport(
            reason="decoy-twin-process", strength=packing_strength,
            unresolved=("twin-process decoy pattern matches; trace is untrustworthy",),
            recommended_analyst_steps=("isolate the security-critical child process "
                                        "before tracing",),
        )
    if not iat_recoverable:
        return UnprotectableReport(
            reason="iat-unsalvageable", strength=packing_strength,
            unresolved=("import address table could not be rebuilt",
                        "dynamic API resolution is unresolvable statically",),
            recommended_analyst_steps=(
                "dump memory at a chosen OEP under a debugger",
                "rebuild the IAT with Scylla/DumpPE and re-feed the image",
            ),
        )
    if vm_region_ratio > _VM_REGION_DEFAULT_THRESHOLD:
        return UnprotectableReport(
            reason="vm-region-over-threshold", strength=packing_strength,
            signals=(f"vm_region_ratio={vm_region_ratio:.2f}",),
            unresolved=("virtual-machine-region exceeds the 40% default threshold",
                         "handler-derived simplify requires the vm_lift flagship"),
            recommended_analyst_steps=(
                "run vm_lift on the handler trace for deeper reduce",
                "fall back to static-family reporting only",
            ),
        )
    return None
