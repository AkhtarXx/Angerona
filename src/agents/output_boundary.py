"""Deterministic trust boundary for provider/model-authored text.

Model output is evidence, never orchestration authority.  This module gives every
promoted output a bounded, content-addressed policy verdict and provides a canonical
JSON envelope for the occasions where one model must inspect another model's prose.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping


POLICY_VERSION = 1
MAX_AGENT_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_FORWARDED_OUTPUT_BYTES = 2 * 1024 * 1024

_BIDI_OR_INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
)
_CONTROL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:ignore|disregard|override|bypass)\b"
            r"[^\n]{0,120}\b(?:instruction|prompt|context|reviewer|supervisor|policy|rules?)\b"
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:do\s+not|don['’]t|never)\s+"
            r"(?:follow|obey|heed|apply)\b[^\n]{0,120}"
            r"\b(?:instructions?|prompts?|rules?|context|policy|directives?)\b"
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:forget)\b[^\n]{0,100}"
            r"\b(?:earlier|prior|previous|above|initial)\b[^\n]{0,80}"
            r"\b(?:instructions?|prompts?|rules?|context|policy)\b"
        ),
    ),
    (
        "role_impersonation",
        re.compile(r"(?im)^\s*(?:system|developer|assistant)\s*:\s*\S"),
    ),
    (
        "downstream_agent_directive",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:the\s+)?"
            r"(?:(?:next|following)\s+)?"
            r"(?:reviewer|supervisor|worker|assistant|model)\s*[,:;\-]?\s+"
            r"(?:must|should|shall|will|needs?\s+to|is to|are to|"
            r"approve|accept|declare|return|emit|say|mark|suppress|conceal|hide)\b"
        ),
    ),
    (
        "role_takeover",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:you\s+are\s+now|act\s+as|"
            r"assume\s+(?:the\s+)?role\s+of|pretend\s+to\s+be)\s+(?:the\s+)?"
            r"(?:system|developer|assistant|reviewer|supervisor|worker)\b"
        ),
    ),
    (
        "workflow_result_manipulation",
        re.compile(
            r"(?im)^\s*(?:[-*>]\s*)?(?:(?:please|kindly)\s+)?"
            r"(?:ensure|declare|mark|report|claim|say|state|suppress|conceal|hide)\b"
            r"[^\n]{0,180}\b(?:review_verdict|audit\s+(?:is\s+)?complete|"
            r"no\s+findings|all\s+findings|satisfied|satisfaction)\b"
        ),
    ),
    (
        "agent_control_language",
        re.compile(
            r"(?im)^(?=[^\n]{0,240}\b(?:reviewer|supervisor|worker|assistant|"
            r"model|system)\b)(?=[^\n]{0,240}\b(?:approve|accept|declare|"
            r"return|emit|say|state|mark|suppress|conceal|hide|ignore|obey|"
            r"follow|satisf(?:y|ied|action))\b)[^\n]{1,240}$"
        ),
    ),
    (
        "control_result_directive",
        re.compile(
            r"(?im)^\s*(?:output|return|emit|write|set|mark)\b[^\n]{0,160}"
            r"\b(?:review_verdict|coverage_complete|satisfied|needs_work|plan json)\b"
        ),
    ),
    (
        "envelope_breakout",
        re.compile(r"(?i)</?untrusted_agent_output\b|⟦/?UNTRUSTED_AGENT_OUTPUT"),
    ),
)
_VERDICT_TOKEN = re.compile(
    r"(?im)^\s*REVIEW_VERDICT\s*:\s*(SATISFIED|NEEDS_WORK)\s*$"
)
_PLAN_CONTROL = re.compile(r"(?im)^\s*```plan\b")
_COVERAGE_CONTROL = re.compile(r"(?im)^\s*coverage_complete\s*:")


@dataclass(frozen=True)
class AgentOutputAssessment:
    role: str
    sha256: str
    size_bytes: int
    status: str
    reasons: tuple[str, ...]
    policy_version: int = POLICY_VERSION

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "role": self.role,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "reasons": list(self.reasons),
        }


def _encoded(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogatepass")


def assess_agent_output(
    text: str,
    *,
    role: str,
    allow_final_verdict: bool = False,
    allow_plan_control: bool = False,
) -> AgentOutputAssessment:
    """Classify model-authored text before it reaches a control or prompt sink."""

    if not isinstance(text, str):
        text = str(text)
    raw = _encoded(text)
    reasons: list[str] = []
    if len(raw) > MAX_AGENT_OUTPUT_BYTES:
        reasons.append("output_size_limit")
    if _BIDI_OR_INVISIBLE.search(text):
        reasons.append("invisible_or_bidi_control")
    if any(
        unicodedata.category(char) == "Cc" and char not in "\n\r\t"
        for char in text
    ):
        reasons.append("forbidden_control_character")

    scanned = text
    if allow_final_verdict:
        matches = list(_VERDICT_TOKEN.finditer(text))
        if len(matches) == 1:
            scanned = text[:matches[0].start()] + text[matches[0].end():]
            nonempty = [line.strip() for line in text.splitlines() if line.strip()]
            if not nonempty or matches[0].group(0).strip() != nonempty[-1]:
                reasons.append("nonterminal_verdict_control")
        else:
            reasons.append(
                "missing_verdict_control" if not matches else "duplicate_verdict_control"
            )
    # Normalize compatibility forms after removing the typed control record so
    # full-width and visually equivalent Unicode cannot bypass content policy.
    scanned = unicodedata.normalize("NFKC", scanned)
    if allow_plan_control:
        scanned = _PLAN_CONTROL.sub("", scanned)
        scanned = _COVERAGE_CONTROL.sub("", scanned)
    elif _PLAN_CONTROL.search(scanned):
        reasons.append("unauthorized_plan_control")
    elif role not in {"supervisor_consolidation", "supervisor_final_report"} and (
        _COVERAGE_CONTROL.search(scanned)
    ):
        reasons.append("unauthorized_coverage_control")
    if not allow_final_verdict and _VERDICT_TOKEN.search(scanned):
        reasons.append("unauthorized_verdict_control")

    for name, pattern in _CONTROL_PATTERNS:
        if pattern.search(scanned):
            reasons.append(name)
    reasons = sorted(set(reasons))
    return AgentOutputAssessment(
        role=role,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        status="quarantined" if reasons else "accepted",
        reasons=tuple(reasons),
    )


def boundary_record_matches(
    record: Mapping[str, Any] | None,
    assessment: AgentOutputAssessment,
) -> bool:
    """Require resume metadata to describe the exact bytes under this policy."""

    if not isinstance(record, Mapping):
        return False
    return (
        record.get("policy_version") == POLICY_VERSION
        and record.get("role") == assessment.role
        and record.get("sha256") == assessment.sha256
        and record.get("size_bytes") == assessment.size_bytes
        and record.get("status") == assessment.status
        and record.get("reasons") == list(assessment.reasons)
    )


def quarantine_placeholder(assessment: AgentOutputAssessment) -> str:
    reasons = ", ".join(assessment.reasons) or "policy rejection"
    return (
        "[QUARANTINED MODEL OUTPUT — not admissible evidence or instructions; "
        f"role={assessment.role}; sha256={assessment.sha256}; reasons={reasons}]"
    )


def render_untrusted_agent_output(
    text: str,
    *,
    role: str,
    source: str,
    assessment: AgentOutputAssessment | None = None,
) -> str:
    """Render accepted prose as length/hash-bound inert JSON data for another model."""

    current = assessment or assess_agent_output(text, role=role)
    if not current.accepted:
        return quarantine_placeholder(current)
    raw = _encoded(text)
    if len(raw) > MAX_FORWARDED_OUTPUT_BYTES:
        limited = AgentOutputAssessment(
            role=role,
            sha256=current.sha256,
            size_bytes=current.size_bytes,
            status="quarantined",
            reasons=("forwarded_output_size_limit",),
        )
        return quarantine_placeholder(limited)
    payload = {
        "authority": "none",
        "content": text,
        "content_sha256": current.sha256,
        "policy_version": POLICY_VERSION,
        "role": role,
        "source": source,
    }
    return (
        "<untrusted_agent_output>\n"
        + json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n</untrusted_agent_output>"
    )


def strict_reviewer_verdict(text: str) -> tuple[bool, str]:
    """Parse exactly one verdict token on the final non-empty line, else fail closed."""

    matches = list(_VERDICT_TOKEN.finditer(text or ""))
    if not matches:
        return False, "Reviewer emitted no explicit verdict; treating as unresolved."
    assessment = assess_agent_output(
        text,
        role="reviewer_output",
        allow_final_verdict=True,
    )
    if not assessment.accepted:
        return False, (
            "Reviewer output failed the agent-output boundary: "
            + ", ".join(assessment.reasons)
        )
    nonempty = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if len(matches) != 1 or not nonempty:
        return False, "Reviewer must emit exactly one verdict token."
    final = nonempty[-1]
    exact = re.fullmatch(
        r"REVIEW_VERDICT\s*:\s*(SATISFIED|NEEDS_WORK)",
        final,
        re.IGNORECASE,
    )
    if exact is None or matches[0].group(0).strip() != final:
        return False, "Reviewer verdict must be the final non-empty line."
    satisfied = exact.group(1).upper() == "SATISFIED"
    body = text[:matches[0].start()]
    gaps_match = re.search(
        r"##\s*Gaps to address\s*(.+?)(?:\Z)",
        body,
        re.IGNORECASE | re.DOTALL,
    )
    gaps = gaps_match.group(1).strip() if gaps_match else ""
    if satisfied and gaps:
        return False, "Reviewer supplied unresolved gaps with a SATISFIED verdict."
    if not satisfied and not gaps:
        gaps = "Reviewer requested more work without actionable gaps."
    return satisfied, gaps
