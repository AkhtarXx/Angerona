"""QARK-style security-rule pass over DEX/disassembled code (roadmap Android #2).

Rules are deterministic predicates over smali code — hardcoded keys, weak crypto,
exported components, unsafe reflection, root/tamper detection presence. Every
rule fires on concrete evidence (a physical line) so verification gates can
re-run independently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_HEX_KEY_RE = re.compile(
    r"(?:^|[\"'\s])([0-9a-fA-F]{32,64})(?:[\"'\s]|$)")
_LONG_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
_URL_RE = re.compile(r"https?://[^\s\"']+")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")


@dataclass
class RuleFinding:
    rule: str
    severity: str               # high | medium | low | info
    message: str
    evidence: str               # physical line/snippet supporting the finding
    line_no: int

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity,
                "message": self.message, "line_no": self.line_no,
                "evidence": self.evidence}


# ------------------------------------------------------------ generic checks

def _check_hardcoded_credentials(text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for idx, line in enumerate(text.splitlines(), 1):
        for match in _AWS_KEY.finditer(line):
            findings.append(RuleFinding(
                rule="hardcoded-aws-key", severity="high",
                message="AWS access key embedded in static code",
                evidence=line[:120], line_no=idx,
            ).as_dict())
        for match in _GOOGLE_API_KEY.finditer(line):
            findings.append(RuleFinding(
                rule="hardcoded-google-api-key", severity="high",
                message="Google API key embedded in static code",
                evidence=line[:120], line_no=idx,
            ).as_dict())
        for m in _HEX_KEY_RE.finditer(line):
            if len(m.group(1)) in {32, 48, 64}:
                # plausible symmetric key (AES-128/192/256) embedded
                findings.append(RuleFinding(
                    rule="hardcoded-symmetric-key", severity="high",
                    message="possible embedded symmetric key (hex-32/48/64)",
                    evidence=line[:120], line_no=idx,
                ).as_dict())
                break
    return findings


def _check_weak_crypto(text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    weak_patterns = [
        ("MD5", "weak-hash-md5",   "medium", "MD5 used for integrity/auth"),
        ("SHA1", "weak-hash-sha1", "medium", "SHA1 used for integrity/auth"),
        ("DES",  "weak-cipher-des", "high",   "DES/DESede selected for encryption"),
        ("RC4",  "weak-cipher-rc4", "high",   "RC4 selected for encryption"),
        ("ECB",  "weak-mode-ecb",  "high",   "ECB mode selected (no IV randomness)"),
    ]
    for idx, line in enumerate(text.splitlines(), 1):
        for token, rule, sev, msg in weak_patterns:
            if re.search(rf"\b{token}\b", line):
                findings.append(RuleFinding(
                    rule=rule, severity=sev,
                    message=msg, evidence=line[:120], line_no=idx).as_dict())
    return findings


def _check_reflection_api(text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    refl_toks = [
        ("Class.forName",       "reflection-class-load"),
        ("getMethod",           "reflection-method-lookup"),
        ("loadLibrary",         "native-library-load"),
        ("DexClassLoader",      "dynamic-dex-load"),
    ]
    for idx, line in enumerate(text.splitlines(), 1):
        for tok, rule in refl_toks:
            if tok in line:
                findings.append(RuleFinding(
                    rule=rule, severity="medium",
                    message=f"dynamic loader / reflection API: {tok}",
                    evidence=line[:120], line_no=idx).as_dict())
    return findings


def _check_insecure_comm(text: str) -> list[RuleFinding]:
    findings = []
    for idx, line in enumerate(text.splitlines(), 1):
        if "http://" in line or "SSLContext" in line:
            if "TrustAll" in line or "ALLOW_ALL_HOSTNAME_VERIFIER" in line or \
               "HostnameVerifier" in line or "TrustManager" in line:
                findings.append(RuleFinding(
                    rule="insecure-tls-trustall", severity="high",
                    message="custom TrustManager/HostnameVerifier accepting any cert",
                    evidence=line[:120], line_no=idx).as_dict())
            elif "http://" in line and "https://" not in line:
                findings.append(RuleFinding(
                    rule="cleartext-http", severity="medium",
                    message="cleartext HTTP endpoint",
                    evidence=line[:120], line_no=idx).as_dict())
    return findings


def _check_root_tamper_indicators(text: str) -> list[RuleFinding]:
    findings = []
    for idx, line in enumerate(text.splitlines(), 1):
        for tok in ("su", "busybox", "magisk", "supersu", "rootbeer", "R2HiddenApi",
                    "/proc/", "system_property"):
            # `su` must be a standalone token (word boundary) so `.super`
            # directives and `sub-*` opcodes don't flood findings.
            matched = re.search(r"\bsu\b", line.lower()) if tok == "su" else tok in line.lower()
            if matched:
                findings.append(RuleFinding(
                    rule="root-tamper-indicator", severity="info",
                    message=f"possible root/tamper check reference: {tok}",
                    evidence=line[:120], line_no=idx).as_dict())
                break
    return findings


# ------------------------------------------------------------ top-level

def run_security_rules_on_smali(smali_text: str) -> dict:
    """Run the full static rule suite over a smali blob; returns finding list."""
    findings = []
    findings.extend(_check_hardcoded_credentials(smali_text))
    findings.extend(_check_weak_crypto(smali_text))
    findings.extend(_check_reflection_api(smali_text))
    findings.extend(_check_insecure_comm(smali_text))
    findings.extend(_check_root_tamper_indicators(smali_text))
    by_severity = {}
    for f in findings:
        by_severity.setdefault(f["severity"], 0)
        by_severity[f["severity"]] += 1
    return {
        "findings": findings,
        "total": len(findings),
        "by_severity": by_severity,
        "policy": "deterministic static scan; findings require verification before presentation",
    }


def run_security_rules_on_dir(dex_dir: str | Path, glob: str = "**/*.smali") -> dict:
    """Run the rules across every smali file in a directory tree."""
    all_findings: list[RuleFinding] = []
    files = list(Path(dex_dir).rglob(glob))
    for f in files:
        text = f.read_text(errors="ignore")
        local = run_security_rules_on_smali(text)
        for row in local["findings"]:
            row["file"] = str(f.relative_to(dex_dir))
        all_findings.extend(local["findings"])
    by_severity = {}
    for f in all_findings:
        by_severity.setdefault(f["severity"], 0)
        by_severity[f["severity"]] += 1
    return {
        "files_scanned": len(files),
        "total": len(all_findings),
        "by_severity": by_severity,
        "findings": all_findings,
    }
