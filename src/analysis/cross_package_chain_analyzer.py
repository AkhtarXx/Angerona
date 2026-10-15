"""Cross-APK collusion-chain analyzer.

Real-world Android malware increasingly splits into cooperating apps —
a benign-looking host APK with a permissions-limited companion app that
communicates via sharedUserId, exported content providers, custom permissions,
or IPC (broadcasts/services with implicit intents).  Single-APK audit tools
fully miss this.  2024-2026 campaigns (BadPack, AddSugar, Xloader) rely on
APK-pair/multi-APK collusion.

This module analyzes a *set* of installed/related APKs and identifies:
  * sharedUserId groups with dangerous permission elevation paths
  * custom signature-level permissions defined by one APK and enforced by another
  * exported components in one APK reachable from collusion-partner via IPC
  * same-signing-key collusion groups (samecert groups)

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import INCONCLUSIVE, LIKELY, Finding

TRUST_TAG = "untrusted_child"


@dataclass
class CollusionGroup:
    group_id: str
    packages: list[str]
    sharing_mechanism: str           # sharedUserId | same-cert | custom-permission | exported-bridge
    severity: str                    # critical | high | medium
    evidence: str
    findings: list[Finding] = field(default_factory=list)
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "packages": self.packages,
            "sharing_mechanism": self.sharing_mechanism,
            "severity": self.severity,
            "evidence": self.evidence,
            "findings": [f.as_dict() for f in self.findings],
            "trust": self.trust,
        }


@dataclass
class CrossPackageResult:
    status: str
    groups: list[CollusionGroup]
    singletons: list[str]
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "groups": [g.as_dict() for g in self.groups],
            "singletons": self.singletons,
            "note": self.note,
            "trust": self.trust,
        }


_SHARED_USER_RE = re.compile(r'android:sharedUserId="([^"]+)"')
_PACKAGE_RE = re.compile(r'package="([^"]+)"')
_PERMISSION_DEFINE_RE = re.compile(r'<permission\s+android:name="([^"]+)"')
_USES_PERMISSION_RE = re.compile(r'<uses-permission\s+android:name="([^"]+)"')
_PERMISSION_PROT = re.compile(r'android:protectionLevel="([^"]+)"')
_EXPORTED_COMPONENTS = re.compile(
    r'<(activity|service|provider|receiver)\b[^>]*?android:name="([^"]+)"[^>]*?android:exported="true"'
    r'|<(activity|service|provider|receiver)\b[^>]*?android:exported="true"[^>]*?android:name="([^"]+)"'
)


def _extract_manifest_text(apk: Path) -> str:
    try:
        with zipfile.ZipFile(apk) as zf:
            return zf.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
    except (zipfile.BadZipFile, OSError, KeyError):
        return ""


def _parse_package_and_attrs(manifest: str) -> dict:
    pkg_m = _PACKAGE_RE.search(manifest)
    shared_m = _SHARED_USER_RE.search(manifest)
    perms_defined = []
    for m in re.finditer(
        r'<permission\s+android:name="([^"]+)"[^>]*?android:protectionLevel="([^"]+)"',
        manifest,
    ):
        perms_defined.append({"name": m.group(1), "protection": m.group(2)})
    return {
        "package": pkg_m.group(1) if pkg_m else "",
        "shared_user_id": shared_m.group(1) if shared_m else "",
        "permissions_defined": perms_defined,
        "permissions_used": _USES_PERMISSION_RE.findall(manifest),
        "exported_components": [
            {
                "type": m.group(1) if m.group(1) else m.group(3),
                "name": m.group(2) if m.group(2) else m.group(4),
            }
            for m in _EXPORTED_COMPONENTS.finditer(manifest)
        ],
    }


def _apk_cert_fingerprint(apk: Path) -> str:
    """Cheap fingerprint of APK's v1 certificate blob (identity grouping)."""
    try:
        with zipfile.ZipFile(apk) as zf:
            for n in zf.namelist():
                if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")):
                    return hashlib.sha256(zf.read(n)).hexdigest()[:16]
    except (zipfile.BadZipFile, OSError):
        pass
    return ""


def analyze_cross_package(apk_paths: list[str | Path]) -> CrossPackageResult:
    """Analyze a set of APKs for collusion groups."""
    if not apk_paths:
        return CrossPackageResult(
            status="empty", groups=[], singletons=[], note="no APKs supplied",
        )

    infos: dict[str, dict] = {}
    certs: dict[str, str] = {}
    for p in apk_paths:
        p = Path(p)
        manifest = _extract_manifest_text(p)
        if not manifest:
            continue
        info = _parse_package_and_attrs(manifest)
        if not info["package"]:
            info["package"] = p.stem
        infos[str(p)] = info
        certs[str(p)] = _apk_cert_fingerprint(p)

    groups: list[CollusionGroup] = []
    singletons: list[str] = []
    seen_packages: set[str] = set()

    # 1) sharedUserId groups
    uid_to_pkgs: dict[str, list[str]] = {}
    for path, info in infos.items():
        suid = info.get("shared_user_id") or ""
        if suid:
            uid_to_pkgs.setdefault(suid, []).append(info["package"])

    for suid, pkgs in uid_to_pkgs.items():
        if len(pkgs) > 1:
            findings = [Finding(
                module="cross_package_chain_analyzer",
                kind="shared-userid-group",
                severity="high" if len(pkgs) >= 2 else "medium",
                verdict=LIKELY,
                detail=(
                    f"{len(pkgs)} APKs share userId '{suid}': "
                    f"collusion enables permission pooling via shared process"
                ),
                metadata={"sharedUserId": suid, "packages": pkgs},
            )]
            groups.append(CollusionGroup(
                group_id=f"uid:{suid}",
                packages=sorted(set(pkgs)),
                sharing_mechanism="sharedUserId",
                severity="high",
                evidence=f"android:sharedUserId={suid} in {len(pkgs)} manifests",
                findings=findings,
            ))
            seen_packages.update(pkgs)

    # 2) custom permission groups (signature-level custom permissions)
    perm_to_pkgs: dict[str, list[str]] = {}
    for path, info in infos.items():
        for perm in info.get("permissions_defined", []):
            name = perm.get("name", "")
            if not name:
                continue
            protos = perm.get("protection", "normal")
            if "signature" in protos or "privileged" in protos:
                perm_to_pkgs.setdefault(name, []).append(info["package"])

    for perm, pkgs in perm_to_pkgs.items():
        if len(pkgs) > 1:
            groups.append(CollusionGroup(
                group_id=f"perm:{perm}",
                packages=sorted(set(pkgs)),
                sharing_mechanism="custom-permission",
                severity="medium",
                evidence=f"custom signature-level permission : {perm} declared by {len(pkgs)} APKs",
            ))
            seen_packages.update(pkgs)

    # 3) same-cert collusion groups (v1-certificate identity)
    cert_groups: dict[str, list[str]] = {}
    for path, cert_fp in certs.items():
        if cert_fp:
            cert_groups.setdefault(cert_fp, []).append(infos[path]["package"])
    for fp, pkgs in cert_groups.items():
        if len(pkgs) > 1:
            groups.append(CollusionGroup(
                group_id=f"cert:{fp}",
                packages=sorted(set(pkgs)),
                sharing_mechanism="same-cert",
                severity="high",
                evidence=f"all {len(pkgs)} APKs signed with identical v1 certificate",
            ))
            seen_packages.update(pkgs)

    # 4) singletons — packages with no explicitly shared group
    for path, info in infos.items():
        pkg = info["package"]
        if pkg not in seen_packages:
            singletons.append(pkg)
            seen_packages.add(pkg)

    # 5) explicit exported surface in collusion groups gets escalation note
    for g in groups:
        # Warn when any group member has exported activities/providers that
        # become reachable by less-privileged collusion partners.
        for path, info in infos.items():
            if info["package"] in g.packages:
                for comp in info.get("exported_components", []):
                    if comp["type"] in ("provider", "activity"):
                        g.findings.append(Finding(
                            module="cross_package_chain_analyzer",
                            kind=f"cross-package-exposed-{comp['type']}",
                            severity="medium", verdict=LIKELY,
                            detail=(
                                f"{comp['name']} is exported"
                                f" in collusion group '{g.group_id}'; "
                                f"IPC caller may be another app with less privilege"
                            ),
                            metadata={"component": comp, "group": g.group_id},
                        ))

    status = "ok"
    note = f"{len(groups)} collusion groups across {len(infos)} APK(s)"
    return CrossPackageResult(
        status=status, groups=groups, singletons=sorted(singletons), note=note,
    )
