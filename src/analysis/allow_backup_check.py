"""android:allowBackup=true unencrypted-backup check (Android SOTA priority 10).

**Migration:** native ``Finding`` emission — module-owned verdict model subject
to pipeline orchestrator enforcement.

Research basis (OWASP MASVS-STORAGE backup controls; CWE-530 "Exposure of
Backup File"; Google's adb-backup abuse writeups): with ``allowBackup=true``
(default pre-API-31 semantics in many toolchains) and no
``fullBackupContent``/``dataExtractionRules`` restricting the set, any USB
host can pull the app's private SharedPreferences/databases via ``adb backup``
without root. The risk is only *unencrypted* when the app also stores secrets
in plaintext — this module flags the precondition and lets the storage pass
confirm the plaintext half.

Manifest attributes are deterministic when the manifest decodes; binary AXML
falls back to string-pool recovery, and any failure degrades to status=error
rather than crashing.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_ALLOW_BACKUP_RE = re.compile(r'android:allowBackup="(true|false)"')
_FULL_BACKUP_RE = re.compile(r'android:fullBackupContent="([^"]+)"')
_DATA_RULES_RE = re.compile(r'android:dataExtractionRules="([^"]+)"')
_DEBUGGABLE_RE = re.compile(r'android:debuggable="true"')


from .finding import INCONCLUSIVE, LIKELY, Finding


@dataclass
class BackupScanResult:
    status: str
    allow_backup: bool | None = None
    has_backup_rules: bool = False
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "allow_backup": self.allow_backup,
            "has_backup_rules": self.has_backup_rules,
            "findings": [f.as_dict() for f in self.findings],
            "note": self.note,
            "trust": self.trust,
            "policy": "manifest attributes are facts; plaintext-storage half needs storage pass",
        }


def scan_manifest_text(manifest_text: str, *, source: str = "AndroidManifest.xml") -> BackupScanResult:
    if not manifest_text:
        return BackupScanResult(status="empty", note="no manifest text")
    findings: list[Finding] = []
    m = _ALLOW_BACKUP_RE.search(manifest_text)
    allow_backup: bool | None = (m.group(1) == "true") if m else None
    has_rules = bool(_FULL_BACKUP_RE.search(manifest_text)
                     or _DATA_RULES_RE.search(manifest_text))
    if m is None:
        findings.append(Finding(
            module="allow_backup_check",
            kind="allow-backup-true", severity="medium", verdict=LIKELY,
            detail="allowBackup attribute absent (toolchain default is true on many targets)",
            rule_layer="manifest",
            evidence=source,
        ))
    elif allow_backup:
        # Static-only manifest evidence cannot reach CONFIRMED; the no-rules
        # (adb-backup-exploitable) case ranks above the rules-declared case,
        # which is mitigated and therefore only INCONCLUSIVE.
        findings.append(Finding(
            module="allow_backup_check",
            kind="allow-backup-true", severity="high",
            verdict=LIKELY if not has_rules else INCONCLUSIVE,
            detail='android:allowBackup="true"' + (" (rules declared)" if has_rules else " (no data-extraction rules)"),
            rule_layer="manifest",
            evidence=source,
        ))
    if (allow_backup or m is None) and not has_rules:
        findings.append(Finding(
            module="allow_backup_check",
            kind="no-backup-rules", severity="medium", verdict=LIKELY,
            detail="no fullBackupContent/dataExtractionRules restricting backup set",
            rule_layer="manifest",
            evidence=source,
        ))
    if _DEBUGGABLE_RE.search(manifest_text):
        findings.append(Finding(
            module="allow_backup_check",
            kind="debuggable-build", severity="high", verdict=LIKELY,
            detail='android:debuggable="true" compounds backup exposure',
            rule_layer="manifest",
            evidence=source,
        ))
    return BackupScanResult(
        status="success",
        allow_backup=allow_backup,
        has_backup_rules=has_rules,
        findings=findings,
        note=f"allowBackup={allow_backup} rules={has_rules} findings={len(findings)}",
    )


def scan_apk(apk_path: str | Path) -> BackupScanResult:
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return BackupScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return BackupScanResult(status="error", note=f"not a zip/apk: {exc}")
    with zf:
        if "AndroidManifest.xml" not in zf.namelist():
            return BackupScanResult(status="empty", note="no manifest member")
        try:
            raw = zf.read("AndroidManifest.xml")
        except (OSError, RuntimeError, KeyError):
            return BackupScanResult(status="error", note="manifest unreadable")
    text = raw.decode("utf-8", errors="ignore")
    if "android:" not in text:
        text = "\n".join(m.decode("ascii", errors="ignore")
                         for m in re.findall(rb"[ -~]{4,}", raw))
    return scan_manifest_text(text)
