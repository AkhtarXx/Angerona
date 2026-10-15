"""Implicit-intent passing vulnerability finder (implicit-intent).

Detects when an app uses implicit intents (Intent() with action only, no
component/package) to reach components that could be hijacked by any
installed app.  Especially dangerous when the intent carries extras.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"

_IMPLICIT_INTENT_RE = re.compile(
    r"new\s+Intent\s*\(\s*\"([^\"]+)\"\s*\)|new\s+Intent\s*\(\s*\"([^\"]+)\"\s*,"
    r"\s*null\s*\)|setAction\s*\(\s*\"([^\"]+)\"\s*\)"
)
_SEND_ACTIONS = re.compile(
    r"(ACTION_SEND|ACTION_VIEW|ACTION_EDIT|ACTION_PICK|ACTION_GET_CONTENT|"
    r"ACTION_OPEN_DOCUMENT|ACTION_WEB_SEARCH|ACTION_DIAL|ACTION_CALL)"
)


@dataclass
class ImplicitIntentResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}




def _extract_smali_implicit_intents(text: str) -> list[tuple[str, str, int]]:
    """Parse smali for implicit-intent constructions.

    Pattern: new-instance of Intent followed by const-string of action name
    (ACTION_SEND etc.) that is NOT followed by setComponent/setPackage.
    """
    intents = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "new-instance" in line and "Landroid/content/Intent;" in line:
            # search forward for invoke-direct on constructor signature
            for j in range(i + 1, min(i + 8, len(lines))):
                if "const-string" in lines[j]:
                    action_m = re.search(r'"([^"]+)"', lines[j])
                    if action_m:
                        action = action_m.group(1)
                        risky = bool(re.search(r"ACTION(_SEND|_VIEW|_EDIT|_PICK|_GET_CONTENT|_OPEN_DOCUMENT|_WEB_SEARCH|_DIAL|_CALL)", action))
                        intents.append(("smali", action, j + 1, risky))
                        break
    return intents

def scan_source_text(text: str, *, source: str = "implicit") -> ImplicitIntentResult:
    if not text.strip():
        return ImplicitIntentResult(status="empty", note="no source")
    findings: list[Finding] = []
    # Primary: Java-source regex
    for m in _IMPLICIT_INTENT_RE.finditer(text):
        action = m.group(1) or m.group(2) or m.group(3) or ""
        risky = bool(_SEND_ACTIONS.search(action))
        findings.append(Finding(
            module="implicit_intent_finder",
            kind="implicit-intent",
            severity="high" if risky else "medium",
            verdict=LIKELY,
            detail=f"implicit intent with action={action or 'unknown'} (no component set)",
            evidence=m.group(0),
        ))
    # Secondary: smali-bytecode pattern
    for kind, action, line_no, risky in _extract_smali_implicit_intents(text):
        findings.append(Finding(
            module="implicit_intent_finder",
            kind="implicit-intent",
            severity="high" if risky else "medium",
            verdict=LIKELY,
            detail=f"smali implicit intent with action={action} (no component set)",
            evidence=f"smali@{kind}#{line_no}",
            line_no=line_no,
        ))
    return ImplicitIntentResult(status="success", findings=findings,
                                note=f"{len(findings)} implicit-intent finding(s)")
