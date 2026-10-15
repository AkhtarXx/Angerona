"""JNI boundary taint — follow secrets across the Java <-> native edge.

Sensitive logic that lives partly in Java and partly in C++ is easy to miss
from either side alone:

  * Java passes a lookup key into ``nativeAuth(ctx, "pin_2026")`` — the
    literal escapes to native code and disappears from smali/string scans.
  * Native code pulls the other half from Java with
    ``GetObjectClass -> GetFieldID("token", "..."`` — a Java-field read has
    jumped the boundary; that field name is sensitive vocabulary.
  * Strings that originate in C/C++ are pushed out through
    ``NewStringUTF("sk_live_...")`` — a native-authored secret surfaces in
    Java side; the literal appears in *native* memory, not in the .so's
    static strings.

This module is two small scanners in one:

  1. ``scan_source_text`` — over smali / JADX Java / Kotlin text, finds
     ``System.loadLibrary`` / ``System.load`` sites and literal arguments into
     ``native``-named methods -> Java-to-native secret lifts.
  2. ``scan_native_strings`` — over .so bytes, finds JNI string-table
     markers (``GetFieldID`` etc.) paired with sensitive vocabulary
     (``token``/``pin``/``key``/``session``...) and ``NewStringUTF("...")``
     literals -> native-to-Java secret escapers.

Every finding carries severity and the boundary direction.  Results are
static evidence and stay untrusted_child until a dynamic (jnitrace) gate
corroborates the call sequence.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field

TRUST_TAG = "untrusted_child"

_SENSITIVE = (
    "token", "secret", "key", "pin", "password", "passwd", "session",
    "auth", "credential", "api_key", "apikey", "salt", "iv", "nonce",
    "pepper", "hmac", "private",
)

_LOADLIB_RE = re.compile(r"System\.loadLibrary\s*\(\s*\"([^\"]+)\"")
_LOADLIB_ABS_RE = re.compile(r"System\.load\s*\(\s*\"([^\"]+)\"")
# Matches both Java's `native <ret-type> <name>(` and smali's
# `native <name>(` (smali puts the name directly before `(`).
_NATIVE_DECL_RE = re.compile(r"\bnative\s+(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\(")
_NATIVE_CALL_RE = re.compile(r"\b(\w*[Nn]ative\w*)\s*\(\s*([^)]*)\)")
_LITERAL_ARG_RE = re.compile(r'"([^"]{4,})"')

_JNI_MARKERS = (
    b"GetFieldID", b"GetStaticFieldID", b"GetObjectField",
    b"GetStaticObjectField", b"GetStringUTFChars", b"NewStringUTF",
)
_JNI_MARKERS_SM = tuple(m.decode() for m in _JNI_MARKERS)


@dataclass(frozen=True)
class BoundaryFinding:
    direction: str      # java_to_native | native_to_java
    kind: str           # load_library | native_literal_arg | jni_field_read | newstringutf_escape
    sensitive_vocab: list[str]
    severity: str       # critical | high | medium | low
    evidence: str
    line_no: int        # 0 when source is raw bytes
    source: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "direction": self.direction,
            "kind": self.kind,
            "sensitive_vocab": list(self.sensitive_vocab),
            "severity": self.severity,
            "evidence": self.evidence,
            "line_no": self.line_no,
            "source": self.source,
            "trust": self.trust,
        }


@dataclass(frozen=True)
class JniBoundaryResult:
    status: str                    # findings | clean | empty_source
    findings: list[dict]
    libraries_loaded: list[str]
    native_methods_seen: int
    jni_edge_hits: int
    note: str
    trust: str = TRUST_TAG


def _vocab_in(text: str) -> list[str]:
    low = text.lower()
    return sorted({w for w in _SENSITIVE if w in low})


def _severity(kind: str, vocab: list[str]) -> str:
    strong = {"password", "passwd", "secret", "private", "api_key", "apikey", "pepper", "salt"}
    medium = {"token", "key", "session", "auth", "credential", "hmac", "iv", "nonce"}
    weak = {"pin"}
    vset = set(vocab)
    if vset & strong:
        base = "critical"
    elif vset & medium:
        base = "high"
    elif vset & weak:
        base = "medium"
    else:
        base = "low"
    if kind == "newstringutf_escape" and base == "low":
        return "medium"
    return base


def scan_source_text(text: str, source_name: str = "input") -> JniBoundaryResult:
    if not text.strip():
        return JniBoundaryResult(
            status="empty_source", findings=[], libraries_loaded=[],
            native_methods_seen=0, jni_edge_hits=0, note="no source text",
        )

    findings: list[BoundaryFinding] = []
    libraries: list[str] = []
    native_methods = 0
    jni_hits = 0
    declared_natives: set[str] = set()

    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        for m in _LOADLIB_RE.finditer(line):
            libraries.append(m.group(1))
            jni_hits += 1
        for m in _LOADLIB_ABS_RE.finditer(line):
            libraries.append(m.group(1))
            jni_hits += 1
        for m in _NATIVE_DECL_RE.finditer(line):
            native_methods += 1
            declared_natives.add(m.group(1))

    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        for m in _NATIVE_CALL_RE.finditer(line):
            args = m.group(2)
            lits = _LITERAL_ARG_RE.findall(args)
            if not lits:
                continue
            vocab = _vocab_in(args)
            sev = _severity("native_literal_arg", vocab)
            findings.append(
                BoundaryFinding(
                    direction="java_to_native",
                    kind="native_literal_arg",
                    sensitive_vocab=vocab,
                    severity=sev,
                    evidence=line[:160],
                    line_no=i,
                    source=source_name,
                )
            )
            jni_hits += 1
        # also catch calls to methods *declared native* elsewhere in the file
        for name in declared_natives:
            for m in re.finditer(rf"\b{re.escape(name)}\s*\(\s*([^)]*)\)", line):
                args = m.group(1)
                lits = _LITERAL_ARG_RE.findall(args)
                if not lits:
                    continue
                vocab = _vocab_in(args)
                sev = _severity("native_literal_arg", vocab)
                findings.append(
                    BoundaryFinding(
                        direction="java_to_native",
                        kind="native_literal_arg",
                        sensitive_vocab=vocab,
                        severity=sev,
                        evidence=line[:160],
                        line_no=i,
                        source=source_name,
                    )
                )
                jni_hits += 1

    libraries = sorted(set(libraries))
    status = "findings" if findings else "clean"
    note = (
        f"{len(findings)} JNI-boundary finding(s); "
        f"{len(libraries)} native librar(ies) loaded; "
        f"{native_methods} native method declaration(s)."
    )
    return JniBoundaryResult(
        status=status,
        findings=[f.as_dict() for f in findings],
        libraries_loaded=libraries,
        native_methods_seen=native_methods,
        jni_edge_hits=jni_hits,
        note=note,
    )


_STANDALONE_UTF_RE = re.compile(
    rb'NewStringUTF[^\x00]{0,32}?["\']([ -~]{4,128})["\']'
)


def _vocab_in_bytes(blob: bytes) -> list[str]:
    low = blob.lower()
    return sorted({w for w in _SENSITIVE if w.encode() in low})


def scan_native_strings(data: bytes, source_name: str = "lib.so") -> JniBoundaryResult:
    if not data:
        return JniBoundaryResult(
            status="empty_source", findings=[], libraries_loaded=[],
            native_methods_seen=0, jni_edge_hits=0, note="no bytes",
        )

    findings: list[BoundaryFinding] = []
    jni_hits = 0

    # 1) JNI marker strings carrying sensitive vocabulary nearby
    for marker in _JNI_MARKERS:
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx < 0:
                break
            window = data[max(0, idx - 64) : idx + len(marker) + 128]
            vocab = _vocab_in_bytes(window)
            kind = "jni_field_read"
            sev = _severity(kind, vocab)
            if vocab:
                findings.append(
                    BoundaryFinding(
                        direction="native_to_java",
                        kind=kind,
                        sensitive_vocab=vocab,
                        severity=sev,
                        evidence=f"{marker.decode()} near {vocab[:3]}",
                        line_no=0,
                        source=source_name,
                    )
                )
            jni_hits += 1
            start = idx + len(marker)

    # 2) NewStringUTF("<literal>") escapes with sensitive vocabulary
    for m in _STANDALONE_UTF_RE.finditer(data):
        lit = m.group(1)
        vocab = _vocab_in_bytes(lit)
        if not vocab:
            continue
        findings.append(
            BoundaryFinding(
                direction="native_to_java",
                kind="newstringutf_escape",
                sensitive_vocab=vocab,
                severity=_severity("newstringutf_escape", vocab),
                evidence=f"NewStringUTF(\"{lit.decode('ascii', 'replace')[:48]}\"...)",
                line_no=0,
                source=source_name,
            )
        )
        jni_hits += 1

    status = "findings" if findings else "clean"
    note = f"{len(findings)} JNI-boundary finding(s) over {len(data)} byte(s)."
    return JniBoundaryResult(
        status=status,
        findings=[f.as_dict() for f in findings],
        libraries_loaded=[],
        native_methods_seen=0,
        jni_edge_hits=jni_hits,
        note=note,
    )


def scan_apk(apk_path: str) -> dict[str, JniBoundaryResult]:
    results: dict[str, JniBoundaryResult] = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                results[name] = scan_native_strings(zf.read(name), source_name=name)
            elif name.endswith((".java", ".kt", ".smali")):
                try:
                    text = zf.read(name).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    continue
                results[name] = scan_source_text(text, source_name=name)
    return results
