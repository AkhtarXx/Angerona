"""Logcat sensitive-data detector (Android SOTA priority 9).

Research basis (OWASP MASVS-STORAGE "no sensitive data in logs"; CWE-532
"Insertion of Sensitive Information into Log File"): on Android, ``Log.d``/
``Log.e`` output is readable by any app holding READ_LOGS on old versions and
by forensic tools everywhere — so logging tokens, session IDs, or PII is a
reportable leak. Release builds that fail to strip ``Log.v``/``Log.d`` keep
the full debug stream.

Matching the log *call* is static-detectable; whether a given argument is
actually sensitive is a claim tagged ``untrusted_child`` until a type/taint
gate confirms the argument's provenance.
"""

from __future__ import annotations

from .finding import CONFIRMED, LIKELY, Finding
from .findings_compat import as_canonical_findings

import re
from dataclasses import dataclass, field

TRUST_TAG = "untrusted_child"

_LOG_CALL = re.compile(r"\bLog\.(v|d|i|w|e|wtf)\s*\(")
_SENSITIVE_VOCAB = (
    "password", "passwd", "secret", "token", "session", "auth",
    "api_key", "apikey", "credential", "ssn", "credit", "card",
    "imei", "imsi", "msisdn", "location", "latitude", "longitude",
    "bearer", "cookie", "set-cookie",
)
_LEVEL_SEVERITY = {"v": "high", "d": "high", "i": "medium",
                   "w": "low", "e": "low", "wtf": "low"}


@dataclass
class LogFinding:
    level: str
    sensitive_vocab: list[str]
    severity: str
    evidence: str
    line_no: int
    source: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "kind": "log-sensitive",
            "level": self.level,
            "sensitive_vocab": list(self.sensitive_vocab),
            "severity": self.severity,
            "evidence": self.evidence,
            "line_no": self.line_no,
            "source": self.source,
            "trust": self.trust,
        }


@dataclass
class LogScanResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    total_log_calls: int = 0
    sensitive_calls: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": self.findings,
            "total_log_calls": self.total_log_calls,
            "sensitive_calls": self.sensitive_calls,
            "note": self.note,
            "trust": self.trust,
            "policy": "argument sensitivity is a claim; vocab + level are scoring signals",
        }


def scan_source_text(text: str, *, source: str = "java") -> LogScanResult:
    """Scan Java/Kotlin source for Log.* calls carrying sensitive vocabulary."""
    if not text:
        return LogScanResult(status="empty", note="empty text")
    findings: list[LogFinding] = []
    total = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        m = _LOG_CALL.search(line)
        if not m:
            continue
        total += 1
        level = m.group(1)
        low = line.lower()
        hits = sorted({w for w in _SENSITIVE_VOCAB if w in low})
        base = _LEVEL_SEVERITY.get(level, "info")
        # Sensitive vocabulary upgrades severity by one class.
        if hits and base in ("low", "medium"):
            sev = "medium" if base == "low" else "high"
        else:
            sev = base if hits else "info"
        if hits or level in ("v", "d"):
            findings.append(LogFinding(
                level=level, sensitive_vocab=hits, severity=sev,
                evidence=line.strip(), line_no=line_no, source=source,
            ))
    # Smali alias: Landroid/util/Log;->d( — the sensitive literal usually sits
    # on a nearby const-string, so scan a small window around the invoke.
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        sm = re.search(r"Landroid/util/Log;->(v|d|i|w|e|wtf)\(", line)
        if sm:
            total += 1
            window = "\n".join(lines[max(0, line_no - 7):line_no]).lower()
            hits = sorted({w for w in _SENSITIVE_VOCAB if w in window})
            findings.append(LogFinding(
                level=sm.group(1), sensitive_vocab=hits,
                severity="high" if hits else _LEVEL_SEVERITY.get(sm.group(1), "info"),
                evidence=line.strip(), line_no=line_no, source=source,
            ))
    sensitive = sum(1 for f in findings if f.sensitive_vocab)
    return LogScanResult(
        status="success",
        findings=as_canonical_findings("logcat_sensitive", findings),
        total_log_calls=total,
        sensitive_calls=sensitive,
        note=f"{total} Log call(s), {sensitive} carrying sensitive vocabulary",
    )
