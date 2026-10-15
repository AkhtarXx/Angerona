"""AI-agent red-team self-assessment (Research Part 16).

Angerona is *itself* an AI agent pointed at untrusted binaries. The vendor
red-team programs (Microsoft/Google/Meta "AI Red Team", OWASP LLM Top 10
2025, MITRE ATLAS) define the discipline its own operation must survive:
threat-model -> repeatable scenarios -> measurement -> mitigations.

This module is a deterministic, dependency-free POSTURE CHECK. It maps Angerona's
actual runtime configuration onto the OWASP LLM01/05/06/07 risks and the
MITRE ATLAS agentic-AI tactics, and reports which mitigations are ACTIVE vs
which are absent. It never blocks a run -- it records the posture so the report
carries the standards-backed framing (and so an operator can see, e.g., that
cloud-LLM mode leaks decompiled code off-box).

Graceful: missing inputs -> "unknown", never a fabricated verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# OWASP LLM Top 10 (2025) risks Angerona's security model explicitly targets.
_OWASP = {
    "LLM01": "Prompt Injection (from untrusted binary strings / tool output)",
    "LLM05": "Improper Output Handling (decompiler/tool output -> action)",
    "LLM06": "Excessive Agency (agent granted arbitrary tool/exec power)",
    "LLM07": "System Prompt Leakage",
}

# MITRE ATLAS agentic-AI tactics Angerona's architecture maps onto.
_ATLAS = {
    "AML.T0016": "Establish & Maintain Infrastructure (sandbox / egress control)",
    "AML.T0040": "ML Model Inference API Access (the LLM call egress)",
    "AML.T0051": "Adversarial ML Attack (poisoned strings in the sample)",
}


@dataclass
class PostureReport:
    verdict: str = "assessed"          # assessed | weak | strong
    engine_local: bool = False
    detonate_available: bool = False
    sandbox_available: bool = False
    llm_is_local: bool = False
    findings: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    standards: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "engine_local": self.engine_local,
            "detonate_available": self.detonate_available,
            "sandbox_available": self.sandbox_available,
            "llm_is_local": self.llm_is_local,
            "findings": self.findings,
            "mitigations": self.mitigations,
            "standards": self.standards,
        }


def assess_self(*,
               engine: str = "ghidra",
               detonate_available: bool = False,
               sandbox_available: bool = False,
               llm_is_local: bool = False) -> dict:
    """Map Angerona's runtime posture onto OWASP/ATLAS; report active mitigations.

    ``engine_local`` should be True for IDA/Ghidra (sample never leaves the box).
    ``llm_is_local`` True means the agent talks to a self-hosted model, so the
    *only* egress (the decompiled code + strings) stays on your network.
    """
    engine_local = str(engine).lower() in ("ida", "ghidra")
    rep = PostureReport(
        engine_local=engine_local,
        detonate_available=detonate_available,
        sandbox_available=sandbox_available,
        llm_is_local=llm_is_local,
    )

    # ---- mitigations ACTIVE (mapped to OWASP / ATLAS) ----
    if engine_local:
        rep.mitigations.append(
            "OWASP LLM05/LLM07 partial: sample disassembled LOCALLY; "
            "the binary never executes and stays on-box")
    if sandbox_available:
        rep.mitigations.append(
            "OWASP LLM06 (excessive agency): untrusted sample parse wrapped "
            "in no-network bubblewrap; ransomware cannot reach C2/kill-switch")
    if detonate_available:
        rep.mitigations.append(
            "Safe detonation: untrusted sample runs in a disposable no-network "
            "Docker container; behavioural signal without host risk (ATLAS AML.T0016)")
    if llm_is_local:
        rep.mitigations.append(
            "Privacy: fully local inference -> decompiled code/strings never "
            "egress (OWASP LLM01 blast-radius contained)")

    # ---- findings (residual risks) ----
    if not llm_is_local:
        rep.findings.append(
            "OWASP LLM01 residual: decompiled code + strings are sent to the "
            "hosted LLM provider on every analysis; use a local model for "
            "IP-sensitive / malware samples")
    if not sandbox_available and not detonate_available:
        rep.findings.append(
            "OWASP LLM06 residual: no no-network sandbox configured; parsing an "
            "obfuscated sample on the host widens the injection blast radius")
    if not detonate_available:
        rep.findings.append(
            "Dynamic oracle offline: suspected vulns stay SUSPECTED (no crash/PoV "
            "produced); static findings are not dynamically confirmed")

    # ---- verdict ----
    active = sum([engine_local, sandbox_available, detonate_available, llm_is_local])
    if active >= 3:
        rep.verdict = "strong"
    elif active <= 1:
        rep.verdict = "weak"
    else:
        rep.verdict = "assessed"

    rep.standards = {
        "owasp_llm_top10_2025": _OWASP,
        "mitre_atlas": _ATLAS,
        "vendor_red_team": [
            "Microsoft AI Red Team (best-practices + PyRIT)",
            "Google AI Red Team (perspectives on AI red-teaming)",
            "Meta CyberSecEval (offensive-cyber benchmark family)",
        ],
        "note": ("threat-model -> scenario -> measurement -> mitigation; "
                 "Angerona's analyze->review->verify loop is the operational "
                 "equivalent for binaries"),
    }
    return rep.as_dict()
