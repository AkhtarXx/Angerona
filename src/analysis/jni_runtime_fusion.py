"""JNI static ↔ runtime evidence fusion.

``jni_boundary_taint`` produces *static* hypotheses about Java↔native
secret flow (loadLibrary, literal args into natives, ``NewStringUTF``
escapes).  Every finding is tagged ``untrusted_child`` because the data is
static — until a **runtime** observation (jnitrace) corroborates the
hypothesis, the finding is speculative.

This module wires the two streams:
  1. Static hypotheses in, keyed by (kind, evidence-substring).
  2. Runtime events from ``jnitrace_provider.parse_jnitrace_stream`` —
     each JSONL row tells us java-method ↔ native-call pairs actually seen.
  3. Fusion emits upgraded findings: hypotheses that match runtime evidence
     get ``corroborated=True`` + ``severity=high``; those that don't get a
     ``runtime_corroboration="not_observed_in_window"`` disclaimer instead of
     being silently trusted.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

TRUST_TAG = "untrusted_child"


@dataclass
class RuntimeEvent:
    kind: str                 # loadlibrary | call | return | string-escape
    java_class: str
    java_method: str
    native_fn: str = ""
    args_summary: str = ""


@dataclass
class FusedFinding:
    static_kind: str
    static_evidence: str
    static_line: int
    runtime_corroboration: str         # observed | not_observed_in_window | partial
    runtime_events_matched: list[str] = field(default_factory=list)
    severity_boosted: bool = False
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "static_kind": self.static_kind,
            "static_evidence": self.static_evidence[:200],
            "static_line": self.static_line,
            "runtime_corroboration": self.runtime_corroboration,
            "runtime_events_matched": self.runtime_events_matched,
            "severity_boosted": self.severity_boosted,
            "trust": self.trust,
        }


@dataclass
class JniFusionResult:
    status: str                     # ok | empty_input | no_runtime_events
    fused: list[FusedFinding]
    corroborated: int
    uncorroborated: int
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "fused": [f.as_dict() for f in self.fused],
            "corroborated": self.corroborated,
            "uncorroborated": self.uncorroborated,
            "note": self.note,
            "trust": self.trust,
        }


def parse_runtime_events(text: str | Iterable[str]) -> list[RuntimeEvent]:
    """Parse jnitrace JSONL rows into compact RuntimeEvent records.

    Expected row shapes (tolerant — extra fields ignored):
      {"kind":"call","java_class":"…","java_method":"…","native_fn":"…","args":…}
      {"kind":"loadlibrary","java_class":"System","java_method":"loadLibrary","args_summary":"native-lib"}
    """
    events: list[RuntimeEvent] = []
    if isinstance(text, str):
        lines = text.splitlines()
    else:
        lines = list(text)
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "").lower()
        if not kind:
            continue
        events.append(RuntimeEvent(
            kind=kind,
            java_class=str(row.get("java_class") or ""),
            java_method=str(row.get("java_method") or ""),
            native_fn=str(row.get("native_fn") or ""),
            args_summary=str(row.get("args_summary") or row.get("args") or ""),
        ))
    return events


def _evidence_tokens(evidence: str) -> list[str]:
    """Extract searchable tokens from static evidence text (>=3 chars)."""
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", evidence)
    return sorted(set(tokens))


def _matches(event: RuntimeEvent, static_kind: str, tokens: list[str]) -> bool:
    """Decide whether a runtime event matches a static hypothesis."""
    if not tokens:
        return False
    ev_text = " ".join([event.java_class, event.java_method, event.native_fn, event.args_summary])
    hits = sum(1 for t in tokens if t in ev_text)
    # Require at least one hits whose length is real evidence content
    # (>=4 chars), plus a kind mapping.  Short structural words (class
    # prefixes / "java" / "method") count zero towards corroboration.
    cont_tokens = [t for t in tokens if len(t) >= 4]
    content_hits = sum(1 for t in cont_tokens if t in ev_text)
    if content_hits < 1:
        return False
    if "loadlibrary" in static_kind.lower() or "load_library" in static_kind.lower():
        return event.kind == "loadlibrary"
    if "native_literal_arg" in static_kind.lower():
        return event.kind == "call" and event.native_fn != ""
    if "newstringutf" in static_kind.lower():
        return event.kind == "string-escape" or "NewStringUTF" in event.native_fn
    if "jni_field_read" in static_kind.lower():
        return event.kind == "call" and (
            "GetFieldID" in event.native_fn or "GetStaticFieldID" in event.native_fn
        )
    return event.kind == "call"


def fuse_static_with_runtime(
    static_findings: Iterable[dict | object],
    runtime_events: Iterable[RuntimeEvent],
) -> JniFusionResult:
    """Fuse static hypotheses with runtime events; upgrade matched findings."""
    events = list(runtime_events)
    if not events:
        return JniFusionResult(
            status="no_runtime_events", fused=[], corroborated=0, uncorroborated=0,
            note="no runtime events supplied — all static findings stay unverified",
        )

    fused: list[FusedFinding] = []
    corr = uncorr = 0
    for f in static_findings:
        kind = getattr(f, "kind", "") if not isinstance(f, dict) else f.get("kind", "")
        evidence = getattr(f, "evidence", "") if not isinstance(f, dict) else f.get("evidence", "")
        line = getattr(f, "line_no", 0) if not isinstance(f, dict) else f.get("line_no", 0)
        tokens = _evidence_tokens(evidence)
        matched_events = [e for e in events if _matches(e, kind, tokens)]
        if matched_events:
            corroboration = "observed"
            corr += 1
            boosted = True
        else:
            corroboration = "not_observed_in_window"
            uncorr += 1
            boosted = False
        fused.append(FusedFinding(
            static_kind=kind, static_evidence=evidence, static_line=line,
            runtime_corroboration=corroboration,
            runtime_events_matched=[
                f"{e.java_class}.{e.java_method} -> {e.native_fn or e.kind}"
                for e in matched_events[:4]
            ],
            severity_boosted=boosted,
        ))

    status = "ok"
    note = f"{corr} static findings corroborated by runtime, {uncorr} unverified"
    return JniFusionResult(
        status=status, fused=fused, corroborated=corr, uncorroborated=uncorr, note=note,
    )
