"""Non-exported BROWSABLE implicit-reachability detector.

Android 12 (API 31) changed the rules:  an activity with ``<category
android:name="android.intent.category.BROWSABLE" />`` + a data scheme WITHOUT
explicit ``android:exported="false"`` is **implicitly reachable** from other
apps and the browser, even when ``android:exported`` is unset.  Prior
Angraona flagged only explicitly-``exported="true"`` entries — an
attacker-reachable class of implicit routes escaped notice.

This module scans the decoded manifest for:
  * Activities with ``<intent-filter>`` containing ``BROWSABLE`` category
    PLUS ``<data android:scheme="…" />`` — implicit deep-link candidates
  * Whether ``android:autoVerify="true"`` is declared (App Links verification)
    — without it, the route cannot bypass the disambiguation dialog vs
    user's default-browser choice
  * Whether the activity explicitly sets ``android:exported=False``

Rate (static manifest scan — caps at LIKELY; CONFIRMED is reserved for
runtime / cryptographic proof per ``finding.py``, so never emitted here):
  * **LIKELY** — BROWSABLE + scheme + not explicitly ``exported="false"``
    (``autoVerify="true"`` downgrades severity to medium — the disambiguation
    dialog may still gate the route)
  * **NOT_APPLICABLE** — ``exported="false"`` explicitly set (route skipped)

Trust: ``untrusted_child``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"


@dataclass
class BrowsableResult:
    status: str                     # ok | error | empty
    implicit_routes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "implicit_routes": self.implicit_routes,
            "findings": [f.as_dict() for f in self.findings],
            "note": self.note,
            "trust": self.trust,
        }


def scan_manifest_text(manifest_text: str, *, source_name: str = "AndroidManifest.xml") -> BrowsableResult:
    """Scan a decoded manifest for implicit BROWSABLE routes.

    Parses with ElementTree instead of regex — attacker-supplied comments
    cannot split semantic blocks (attack: comment-injection ``</activity>``
    inside an ``<activity>`` block).
    """
    if not manifest_text.strip():
        return BrowsableResult(status="empty", note="empty manifest")

    findings: list[Finding] = []
    implicit_routes: list[str] = []

    import xml.etree.ElementTree as ET
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError:
        # Attacker malformed manifest or binary AXML not yet decoded — treat
        # the parse failure itself as attention-worthy, not silent info.
        # （ELITE-2 N-3: severity=info lets dashboards silently filter it.）
        findings.append(Finding(
            module="browsable_implicits",
            kind="manifest-obfuscation-suspected",
            severity="medium", verdict=LIKELY,
            detail="manifest did not parse as well-formed XML; attack surface visibility LOW — possible adversarial obfuscation",
            rule_layer="manifest", evidence=source_name,
        ))
        return BrowsableResult(
            status="ok", implicit_routes=[],
            findings=findings,
            note="manifest XML parse failed — treat BROWSABLE surface as UNKNOWN, not clean",
        )

    def _attr(el, name, default=None):
        return el.get(f"{ANDROID_NS}{name}") if el.get(f"{ANDROID_NS}{name}") is not None \
            else el.get(f"android:{name}")

    for app in root.iter("application"):
        # ELITE-1 R2 FRESH-2: include activity-alias — alias intent-filters
        # expose their target activity the same way.
        for act in list(app.iter("activity")) + list(app.iter("activity-alias")):
            name = (
                act.get(f"{ANDROID_NS}name")
                or act.get("android:name")
                or act.get(f"{ANDROID_NS}targetActivity")
                or act.get("android:targetActivity")
                or ""
            )
            exported_raw = act.get(f"{ANDROID_NS}exported") or act.get("android:exported")
            for intf in act.iter("intent-filter"):
                has_browsable = any(
                    (c.get(f"{ANDROID_NS}name") or c.get("android:name")) == "android.intent.category.BROWSABLE"
                    for c in intf.iter("category")
                )
                if not has_browsable:
                    continue
                schemes: list[str] = []
                hosts: list[str] = []
                for data in intf.iter("data"):
                    s = data.get(f"{ANDROID_NS}scheme") or data.get("android:scheme")
                    if s:
                        schemes.append(s)
                    h = data.get(f"{ANDROID_NS}host") or data.get("android:host")
                    if h:
                        hosts.append(h)
                if not schemes:
                    continue
                auto_verify_raw = intf.get(f"{ANDROID_NS}autoVerify") or intf.get("android:autoVerify")
                auto_verify = auto_verify_raw == "true"
                route_str = ",".join(f"{s}://{h or '*'}" for s, h in zip(schemes, hosts or [None] * len(schemes)))

                if exported_raw == "false":
                    continue  # explicitly not exported; ignore
                if auto_verify:
                    verdict = LIKELY
                    sev = "medium"
                else:
                    verdict = LIKELY
                    sev = "high"

                implicit_routes.append(f"{name} -> {route_str}")
                findings.append(Finding(
                    module="browsable_implicits",
                    kind="implicit-deep-link",
                    severity=sev,
                    verdict=verdict,
                    detail=(
                        f"{name} implicitly reachable via BROWSABLE+scheme: {route_str}"
                        + (" (autoVerify declared)" if auto_verify else " (no autoVerify)")
                    ),
                    evidence=ET.tostring(act, encoding="unicode")[:300],
                    rule_layer="manifest",
                    metadata={
                        "activity": name, "schemes": schemes, "hosts": hosts,
                        "auto_verify": auto_verify,
                        "exported": exported_raw,
                    },
                ))

    status = "ok"
    note = f"{len(findings)} implicit BROWSABLE route candidates"
    return BrowsableResult(
        status=status, implicit_routes=implicit_routes,
        findings=findings, note=note,
    )


def scan_apk(apk_path: str | Path, manifest_text: str = "") -> BrowsableResult:
    """Convenience wrapper — uses supplied manifest text if caller has it."""
    if manifest_text:
        return scan_manifest_text(manifest_text)
    return BrowsableResult(status="error", note="manifest text not provided")
