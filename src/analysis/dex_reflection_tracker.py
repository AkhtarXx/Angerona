"""DEX reflection / dynamic-loader / ProcessBuilder tracker (Android SOTA 8).

Research basis (CWE-470 "Use of Externally-Controlled Input to Select Classes";
the drozer/QARK reflective-loading rules; DREBIN's ``DexClassLoader`` feature
family): runtime class loading defeats every static whitelist, so the pipeline
needs a dedicated pass that inventories ``Class.forName`` /
``DexClassLoader`` / ``PathClassLoader`` / ``ProcessBuilder`` sites and marks
which ones take a *variable* argument (dynamic) versus a string literal.

A literal argument is a deterministic fact; a variable argument is a static
claim tagged ``untrusted_child`` until a data-flow gate resolves the source.
"""

from __future__ import annotations

from .finding import CONFIRMED, LIKELY, Finding
from .findings_compat import as_canonical_findings

import re
from dataclasses import dataclass, field

TRUST_TAG = "untrusted_child"

_API_KINDS: tuple[tuple[str, str, str], ...] = (
    ("class.forname", "reflection-class-load", "medium"),
    ("class;->forname", "reflection-class-load", "medium"),   # smali fragment
    ("dexclassloader", "dynamic-dex-load", "high"),
    ("pathclassloader", "dynamic-class-load", "high"),
    ("inmemorydexclassloader", "memory-dex-load", "high"),
    ("loadclass(", "reflection-loadclass", "medium"),
    ("getdeclaredmethod", "reflection-method-lookup", "low"),
    ("method.invoke", "reflection-invoke", "medium"),
    (".invoke(", "reflection-invoke", "medium"),
    ("processbuilder", "process-builder", "high"),
    ("runtime.getruntime().exec", "runtime-exec", "high"),
    ("runtime;->exec", "runtime-exec", "high"),               # smali fragment
    ("system.loadlibrary", "native-load", "low"),
    ("system.load(", "native-load-path", "medium"),
)

# const-string vX, "..." immediately feeding the loader = literal arg.
_LITERAL_RE = re.compile(r'const-string\s+(v\d+),\s*"([^"]+)"')
_CALL_RE = re.compile(r"invoke-\w+\s+\{([^}]*)\}")


@dataclass
class ReflectionSite:
    api: str
    kind: str
    severity: str
    argument_kind: str      # literal | variable | unknown
    literal: str | None
    line_no: int
    source: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "api": self.api,
            "kind": self.kind,
            "severity": self.severity,
            "argument_kind": self.argument_kind,
            "literal": self.literal,
            "line_no": self.line_no,
            "source": self.source,
            "trust": self.trust,
        }


@dataclass
class ReflectionScanResult:
    status: str
    sites: list[Finding] = field(default_factory=list)
    dynamic_loads: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "sites": self.sites,
            "dynamic_loads": self.dynamic_loads,
            "note": self.note,
            "trust": self.trust,
            "policy": "literal args are facts; variable args are untrusted claims",
        }


def scan_smali_text(text: str, *, source: str = "smali") -> ReflectionScanResult:
    """Track reflection/loader sites in smali text with literal resolution."""
    if not text:
        return ReflectionScanResult(status="empty", note="empty text")
    lines = text.splitlines()
    literals: dict[str, str] = {}
    for i, line in enumerate(lines, 1):
        m = _LITERAL_RE.search(line)
        if m:
            literals[m.group(1)] = (m.group(2), i)
    sites: list[ReflectionSite] = []
    for i, line in enumerate(lines, 1):
        low = line.lower()
        for api, kind, severity in _API_KINDS:
            if api not in low:
                continue
            arg_kind, literal = "unknown", None
            call = _CALL_RE.search(line)
            if call:
                for reg in (r.strip() for r in call.group(1).split(",")):
                    if reg in literals:
                        arg_kind = "literal"
                        literal = literals[reg][0]
                        break
                if arg_kind == "unknown":
                    arg_kind = "variable"
            sites.append(ReflectionSite(
                api=api, kind=kind, severity=severity,
                argument_kind=arg_kind, literal=literal,
                line_no=i, source=source,
            ))
            break
    dynamic = sum(1 for s in sites
                  if s.kind in {"dynamic-dex-load", "dynamic-class-load", "memory-dex-load"})
    return ReflectionScanResult(
        status="success",
        sites=as_canonical_findings("dex_reflection_tracker", sites),
        dynamic_loads=dynamic,
        note=f"{len(sites)} reflection/loader site(s), {dynamic} dynamic load(s)",
    )


def scan_source_text(text: str, *, source: str = "java") -> ReflectionScanResult:
    """Equivalent pass over decompiled Java source text."""
    if not text:
        return ReflectionScanResult(status="empty", note="empty text")
    sites: list[ReflectionSite] = []
    for i, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for api, kind, severity in _API_KINDS:
            if api in low:
                m = re.search(r'\(\s*"([^"]+)"', line)
                sites.append(ReflectionSite(
                    api=api, kind=kind, severity=severity,
                    argument_kind="literal" if m else "variable",
                    literal=m.group(1) if m else None,
                    line_no=i, source=source,
                ))
                break
    dynamic = sum(1 for s in sites
                  if s.kind in {"dynamic-dex-load", "dynamic-class-load", "memory-dex-load"})
    return ReflectionScanResult(
        status="success",
        sites=as_canonical_findings("dex_reflection_tracker", sites),
        dynamic_loads=dynamic,
        note=f"{len(sites)} reflection/loader site(s), {dynamic} dynamic load(s)",
    )
