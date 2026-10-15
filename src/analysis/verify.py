"""Objective, binary-backed verification of an RE agent's *report* — beyond BinDiff.

This module is the content-level "reality anchor" that complements BinDiff's structural
check: it verifies that what the agent *claims* in its markdown report actually exists in
the binary (strings/imports/symbols), and that a reconstructed function's *control flow*
matches the original.

Every check degrades gracefully: missing data returns an explicit ``inconclusive``
status while retaining ``verified=True`` for backwards-compatible gate behavior.
Only a non-empty, contradicting finding forces NEEDS_WORK.

Pillars
-------
1. ``verify_claims``  — agent-cited strings/imports/symbols must exist in the binary's
   exported facts (strings.txt / imports.txt / exports.txt / symbols.txt).
2. ``verify_capabilities`` — capabilities an agent ASSERTS in prose (C2, AMSI bypass,
   persistence, exfiltration, DNS, injection, ...) must be backed by matching imports
   / API calls in the binary. Stops fluent prose that describes behaviour with no
   corresponding code.

Structural *depth* (per-function control-flow) is covered by the recompile-verify
gate (``verify_reconstruction`` / ``verify_understanding``), which compares the
agent's reconstructed function to the original via BinDiff's per-function similarity
and ``structural_strength`` -- real, populated data. A separate block/edge "CFG depth"
gate was prototyped and removed: the per-function basic-block / edge counts are not
exposed by either the ``.BinDiff`` SQLite table (always 0) or the ``.BinExport``
protobuf, so it could never produce a real signal.

A third pillar (dynamic-evidence feedback) was designed and CUT after peer review: the
detonation container runs with ``--network none``, so observed network is structurally
impossible and any "contradiction" check would only produce false positives. Documented
as a known limit, not implemented.
"""

from __future__ import annotations

import json
import re
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Ghidra auto-generated symbol names (stripped binaries) -- never "real" claims.
_AUTO_NAME = re.compile(r"^(FUN_|LAB_|SUB_|loc_|thunk_)", re.I)

# --------------------------------------------------------------------------- extraction

_BACKTICK = re.compile(r"`([^`]+)`")                 # `token`
_QUOTE = re.compile(r"'([^']{2,80})'")              # 'token'
_DQUOTE = re.compile(r'"([^"]{2,80})"')             # "token"
_BARE = re.compile(r"\b([A-Z][A-Z0-9_]{5,60})\b")   # RANSOM_KEY, CREATEFILE_W
_IMPORT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,60})\(")  # Foo(  call site
_REPORT_STATUS_TOKENS = {
    "CONFIRMED",
    "REJECTED",
    "NEEDS_MORE_EVIDENCE",
    "NEEDS_WORK",
    "UNSUPPORTED",
}

# Capability -> required supporting import/API tokens. If the report asserts a capability
# (even in prose) but the binary exposes none of the expected APIs, that claim is
# unsupported -- this catches agents that describe behaviour (C2, AMSI bypass) without
# the imports that would make it real. Graceful: unknown capability -> no check.
_CAPABILITY_REQUIREMENTS: dict[str, set[str]] = {
    "c2": {"internetopen", "internetopenurl", "urlopen", "getaddrinfo", "socket",
           "connect", "wsastartup", "curl", "http", "winhttp"},
    "beacon": {"internetopen", "internetopenurl", "urlopen", "getaddrinfo", "socket",
               "sleep", "createthread"},
    "amsi": {"amsiscanbuffer", "amsiscanstring", "amsi", "virtualprotect",
             "virtualalloc", "ntprotectvirtualmemory"},
    "persist": {"regsetvalueex", "regcreatekeyex", "createservice", "regopenkeyex",
                "schtasks", "wmic", "movefileex"},
    "exfiltrat": {"internetopen", "urlopen", "getaddrinfo", "socket", "send",
                  "writefile", "internetwritefile"},
    "dns": {"getaddrinfo", "gethostbyname", "dnsquery", "resolv", "socket"},
    "inject": {"virtualalloc", "virtualprotect", "writeprocessmemory",
               "createremotethread", "ntallocvirtualmemory", "loadlibrary"},
    "encrypt": {"cryptencrypt", "aes", "rsa", "cryptgenkey", "evp", "openssl"},
    "screenshot": {"bitblt", "getdc", "createdc", "gdi32", "capturedc"},
}


def verify_capabilities(report: str, export_dir: str | Path) -> VerificationReport:
    """Check that asserted capabilities are backed by the binary's imports/xrefs.

    Capability keywords detected in the report (prose or literal) must be supported by
    at least one expected API import in the exported facts. A capability with zero
    supporting imports is reported as unsupported -> the loop forces NEEDS_WORK. This is
    the check that stops an agent describing C2 / AMSI-bypass / persistence in fluent
    prose with no corresponding imports. Graceful: if no facts or no capabilities claimed,
    returns "no evidence" (skip), never a hard block.
    """
    facts_dir = Path(export_dir)
    if not any((facts_dir / name).is_file()
               for name in ("imports.txt", "exports.txt", "symbols.txt")):
        return VerificationReport(verified=True, pillar="capabilities",
                                  checked=0, detail="no symbol facts -> skipped (no evidence)")
    facts = load_binary_facts(facts_dir)
    known = {x.lower() for x in (facts["imports"] | facts["exports"] | facts["symbols"])}
    text = (report or "").lower()
    unsupported: list[str] = []
    checked = 0
    for cap, required in _CAPABILITY_REQUIREMENTS.items():
        if cap not in text:
            continue
        checked += 1
        # A required API is "supported" if any known import *contains* it (case-insensitive
        # substring) -- e.g. required "internetopen" matches "InternetOpenA".
        supported = any(any(req in imp for imp in known) for req in required)
        if not supported:
            unsupported.append(f"capability '{cap}' asserted but no supporting import "
                               f"({', '.join(sorted(required)[:4])}...)")
    verified = not unsupported
    return VerificationReport(
        verified=verified, pillar="capabilities", checked=checked,
        unsupported=unsupported,
        detail=("capabilities backed by binary imports" if verified
                else "; ".join(unsupported[:10])),
    )


@dataclass
class CitedTokens:
    strings: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)


def _is_auto_name(tok: str) -> bool:
    """Ghidra auto-names (FUN_401000, LAB_, SUB_, loc_) are not real agent claims."""
    return bool(_AUTO_NAME.match(tok))


def _is_report_status_token(tok: str) -> bool:
    return tok.strip().upper() in _REPORT_STATUS_TOKENS


def extract_cited_tokens(report: str) -> CitedTokens:
    """Pull candidate string/import literals out of the agent's markdown report.

    Auto-generated symbol names (FUN_/LAB_/SUB_/loc_) are excluded -- on stripped
    binaries the agent legitimately cites these and they are not in the binary's
    export facts, which would cause false NEEDS_WORK.
    """
    out = CitedTokens()
    for rx in (_BACKTICK, _QUOTE, _DQUOTE, _BARE):
        for m in rx.finditer(report or ""):
            tok = m.group(1).strip()
            if len(tok) >= 2 and not _is_auto_name(tok) and not _is_report_status_token(tok):
                out.strings.add(tok)
    for m in _IMPORT.finditer(report or ""):
        tok = m.group(1)
        if not _is_auto_name(tok):
            out.imports.add(tok)
    return out


# High-specificity factual claims an agent might fabricate. Detected even WITHOUT
# backticks, because a vaguely-worded but technically-specific claim (e.g. "the C2
# IP is 185.199.108.9" / "uses AES with a static key" / "the password is at 0x402000")
# is exactly the kind of detail a hallucinating report invents. If the report makes
# ANY such claim but NONE is corroborated by the binary's facts, verify_claims
# returns NEEDS_WORK instead of a silent pass.
#
# NOTE: generic capability keywords (c2, beacon, amsi, persist, ...) are intentionally
# NOT listed here -- those are handled by verify_capabilities (which checks the binary's
# imports). This list is only for concrete *details* (addresses, keys, encryption) that
# an agent can assert without a capability word and that must tie back to real binary data.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_HEXOFF = re.compile(r"\b0x[0-9A-Fa-f]{3,}\b")
_SPECIFIC_KEYWORDS = (
    "encryption", "encrypted", "decrypt", "aes", "rsa", "static key", "hard-coded",
    "hardcoded", "hard coded", "password", "passphrase", "secret key", "private key",
    "xor key", "kill switch", "ransom", "payload", "shellcode", "backdoor",
)


def specific_factual_claims(report: str) -> list[str]:
    """Return high-specificity technical claims found in the report (prose or literal).

    Used by ``verify_claims`` to catch fabricated detail: if the report asserts ANY
    specific fact (an IP, MAC, hex offset, or a concrete crypto/key/payload keyword)
    but none of those specifics are corroborated by the binary, the claim is
    unsupported. Generic capability verbs (c2, beacon, amsi, ...) are excluded on
    purpose -- verify_capabilities owns those via import analysis.
    """
    text = report or ""
    found: list[str] = []
    for rx in (_IPV4, _MAC, _HEXOFF):
        for m in rx.finditer(text):
            found.append(m.group(0))
    low = text.lower()
    for kw in _SPECIFIC_KEYWORDS:
        if kw in low:
            found.append(kw)
    return found


def objective_specific_claims(report: str) -> list[str]:
    """Objective high-specificity claims only: IPs, MACs, hex offsets.

    These are cheap to corroborate against the binary and safe to enforce even
    when the report ALSO cites literal tokens. The fuzzy keyword list
    (``_SPECIFIC_KEYWORDS``) is too broad for that path -- prose like "uses AES
    encryption" must not turn into a hard unsupported-claim verdict just because
    the binary's strings never spell "aes" literally.
    """
    text = report or ""
    found: list[str] = []
    for rx in (_IPV4, _MAC, _HEXOFF):
        for m in rx.finditer(text):
            found.append(m.group(0))
    return found

def _claim_corroborated(claim: str, facts: dict) -> bool:
    """A specific claim is corroborated if it (or a close substring) appears in the
    binary's strings/imports/exports/symbols, OR is a code reference whose
    ADDRESS is present in the binary's symbol/export address space (e.g. a
    report citing ``func @ 0x401000`` where 0x401000 is a real function
    entry). The latter keeps legitimate code references from being flagged as
    fabricated factual claims.
    """
    c = claim.strip().lower()
    if not c:
        return False
    strings_low = {s.lower() for s in facts["strings"] if s}
    known_low = {x.lower() for x in (facts["imports"] | facts["exports"] | facts["symbols"])}
    # A specific claim is corroborated only if it (or a close substring) appears in a
    # REAL binary string/name. We check `c in s` (the claim text is found inside a
    # binary string) -- NOT `s in c`, because a 1-char binary string (or empty) is a
    # substring of every claim, which would corroborate fabricated claims.
    if any(c in s for s in strings_low):
        return True
    # capability keyword / symbol name corroborated by a matching import/export/symbol name
    if any(c in k for k in known_low):
        return True
    # a hex address claim corroborated by a real symbol/export entry address
    if "0x" in c:
        addr = c.split("0x", 1)[1].split()[0].strip(".,):")
        if f"0x{addr.lower()}" in {a.lower() for a in facts.get("addresses", set())}:
            return True
    return False


# --------------------------------------------------------------------------- facts

def load_binary_facts(export_dir: str | Path) -> dict:
    """Load the ground-truth string/import/symbol sets already exported for a binary.

    Matches the exact formats written by ``src/analysis/export.py``:
      strings.txt  -> ``addr\tvalue``
      imports.txt  -> ``lib\tname``  (lib is ``<EXTERNAL>`` for ELF)
      exports.txt  -> ``addr\tname``
      symbols.txt  -> ``addr\ttype\tname``

    NOTE: symbol/export ADDRESSES are indexed too (not just names) so a
    report that cites a function by its real ``0x...`` address is corroborated
    instead of being flagged as an unsupported factual claim (see verify_claims).
    """
    d = Path(export_dir)

    def _lines(name: str) -> list[str]:
        p = d / name
        return p.read_text(errors="ignore").splitlines() if p.is_file() else []

    strings = {
        (ln.split("\t", 1)[1] if "\t" in ln else ln).strip()
        for ln in _lines("strings.txt") if ln.strip()
    }
    # Drop empty/whitespace-only strings: an empty string is a substring of EVERY
    # claim, which would make _claim_corroborated corroborate fabricated claims and
    # let the verify gate pass everything (the "gate that can never fail" trap).
    strings = {s for s in strings if s}

    def _tail(name: str) -> set[str]:
        return {ln.split("\t")[-1].strip() for ln in _lines(name) if ln.strip()}

    def _head(name: str) -> set[str]:
        # the ADDRESS column (first field) of exports/symbols
        return {ln.split("\t")[0].strip().lower() for ln in _lines(name)
                if ln.strip() and "\t" in ln}

    return {
        "strings": strings,
        "imports": _tail("imports.txt"),
        "exports": _tail("exports.txt"),
        "symbols": _tail("symbols.txt"),
        # addresses, normalised to lower-case hex (0xABC000)
        "addresses": _head("exports.txt") | _head("symbols.txt"),
    }


# --------------------------------------------------------------------------- reports

@dataclass
class VerificationReport:
    verified: bool
    pillar: str
    checked: int = 0
    unsupported: list[str] = field(default_factory=list)
    detail: str = ""
    status: str = ""

    def __post_init__(self) -> None:
        if not self.status:
            self.status = (
                "unsupported" if not self.verified
                else ("verified" if self.checked > 0 else "inconclusive")
            )
        if self.status not in {"verified", "unsupported", "inconclusive"}:
            raise ValueError(f"invalid verification status: {self.status}")


def _export_provenance_error(facts_dir: Path, binary: str | Path | None) -> str | None:
    """Return a provenance error for exported facts, or None when provenance is valid/skipped."""
    if binary is None:
        return None
    manifest = facts_dir / "EXPORT_MANIFEST.json"
    try:
        record = json.loads(manifest.read_text())
        expected = str((record.get("metadata") or {}).get("sha256") or "").lower()
        digest = hashlib.sha256()
        with Path(binary).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        actual = digest.hexdigest().lower()
        if not expected or expected != actual:
            return "facts directory failed SHA-256 provenance validation"
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return f"facts provenance validation error: {exc}"
    return None


def verify_claims(report: str, export_dir: str | Path, *,
                  min_string_len: int = 4,
                  binary: str | Path | None = None) -> VerificationReport:
    """Verify that the agent's cited strings/imports actually exist in the binary.

    Graceful: if no ``strings.txt`` is present, returns "skipped" (verified=True) — never a
    hard NEEDS_WORK. When ``binary`` is supplied, the exported facts are bound to that
    binary's sha256 via ``EXPORT_MANIFEST.json``; a mismatch is reported as no-evidence
    (the facts may belong to a different binary) rather than a false verdict. A report that
    cites zero tokens yields "no-evidence" (inconclusive) — never a silent pass, never a
    hard block.
    """
    facts_dir = Path(export_dir)
    if not (facts_dir / "strings.txt").is_file():
        return VerificationReport(verified=True, pillar="claims",
                                  checked=0, detail="no strings.txt -> skipped (no evidence)")

    cited = extract_cited_tokens(report)
    specifics: list[str] = specific_factual_claims(report)
    if (len(cited.strings) + len(cited.imports)) == 0 and not specifics:
        # A report with neither literal citations nor a high-specificity factual
        # claim (an IP, a hex offset, "uses AES with a static key") has nothing to
        # verify -> no evidence (inconclusive), never a silent pass.
        return VerificationReport(
            verified=True, pillar="claims", checked=0,
            detail="no verifiable claims cited in report -> no evidence (inconclusive)")

    if (len(cited.strings) + len(cited.imports)) == 0:
        facts = load_binary_facts(facts_dir)
        uncorroborated = [c for c in specifics if not _claim_corroborated(c, facts)]
        if uncorroborated:
            return VerificationReport(
                verified=False, pillar="claims", checked=len(uncorroborated),
                unsupported=[f"unsupported factual claim: {c!r}" for c in uncorroborated[:10]],
                detail="; ".join(f"unsupported factual claim: {c!r}" for c in uncorroborated[:10]))
        provenance_error = _export_provenance_error(facts_dir, binary)
        if provenance_error:
            return VerificationReport(
                verified=False, pillar="claims", checked=0,
                unsupported=["export provenance could not be validated"],
                detail=provenance_error)
        return VerificationReport(
            verified=True, pillar="claims", checked=0,
            detail="no verifiable claims cited in report -> no evidence (inconclusive)")

    facts = load_binary_facts(facts_dir)

    # Import/call claims: must be absent from imports/exports/symbols to be unsupported.
    known = {x.lower() for x in (facts["imports"] | facts["exports"] | facts["symbols"])}
    unsupported: list[str] = []
    for imp in cited.imports:
        if imp.lower() not in known:
            unsupported.append(f"import/call not in binary: {imp}")

    # String claims: a cited string literal absent from the binary's strings is
    # unsupported (case-insensitive, matching the import/symbol checks below).
    strings_low = {s.lower() for s in facts["strings"] if s}
    for s in cited.strings:
        if len(s) < min_string_len:
            continue
        if s.lower() not in strings_low:
            unsupported.append(f"string not in binary: {s!r}")

    # Objective high-specificity factual claims (IP, MAC, hex offset) must be
    # corroborated by the binary even when the report ALSO cites literal tokens --
    # otherwise a fabricated detail (e.g. "the C2 IP is 185.199.108.9") slips past the
    # literal-token check whenever at least one real string/import is cited. Only the
    # OBJECTIVE regex specifics are enforced here; the fuzzy keyword list is kept to
    # the zero-citation branch so prose like "uses AES encryption" is never a hard block.
    for c in objective_specific_claims(report):
        if not _claim_corroborated(c, facts):
            unsupported.append(f"unsupported factual claim: {c!r}")

    verified = not unsupported
    provenance_error = _export_provenance_error(facts_dir, binary) if verified else None
    if provenance_error:
        return VerificationReport(
            verified=False, pillar="claims", checked=len(cited.strings) + len(cited.imports),
            unsupported=["export provenance could not be validated"],
            detail=provenance_error)
    return VerificationReport(
        verified=verified, pillar="claims",
        checked=len(cited.strings) + len(cited.imports),
        unsupported=unsupported,
        detail=("all cited strings/imports present in binary" if verified
                else "; ".join(unsupported[:10])),
    )


# --------------------------------------------------------------------------- CFG
#
# NOTE: a dedicated block/edge "CFG depth" gate was prototyped and REMOVED. The
# per-function basic-block / edge counts needed to compare control-flow depth are
# not exposed by either the .BinDiff SQLite `function` table (columns present but
# always 0) or the .BinExport protobuf (schema inaccessible without a fragile
# hand-rolled reader). A gate that can never produce a real signal is worse than
# none, so structural depth is instead covered by the recompile-verify gate
# (verify_reconstruction / verify_understanding), which compares the agent's
# reconstructed function against the original via BinDiff's per-function similarity
# and structural_strength -- real, populated data.
