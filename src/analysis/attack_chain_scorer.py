"""Composite attack-chain scorer.

Individual findings are disjoint pixels;  the professional wants the *narrative**
— which findings chain into an exploitable kill-chain.

This module takes the full product of an ``android_audit.run_android_audit``
call, groups the findings by module+knowledge-domain, and emits *attack-chain
candidates* — composites whose combined severity exceeds each individual
member's.  Examples of chains detected:

  * exported-activity-without-host-allowlist + BROWSABLE implicit-reach +
    deep-link-into-webview + WebView bridge without nonce → account takeover
  * allowBackup=true without dataExtractionRules + exported provider without
    proper grant-uri → data exfiltration via ADB backup
  * cleartext HTTP + TrustAll + hardcoded auth tokens → MITM credential theft
  * root-indicators + DexClassLoader + writable /data/local/tmp payload →
    rooted-device tamper injection

A chain is only emitted when each required link is present in the input and
**all links share CONFIRMED or LIKELY verdict** — INCONCLUSIVE members break
the chain and the chain is downgraded.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .finding import CONFIRMED, LIKELY

TRUST_TAG = "untrusted_child"


@dataclass
class ChainLink:
    module: str
    kind: str
    severity: str
    verdict: str
    detail: str
    runtime_corroborated: bool = False

    def as_dict(self) -> dict:
        return {
            "module": self.module, "kind": self.kind,
            "severity": self.severity, "verdict": self.verdict,
            "detail": self.detail,
            "runtime_corroborated": self.runtime_corroborated,
        }


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    severity: str                        # critical | high | medium | low
    verdict: str                         # CONFIRMED | LIKELY | INCONCLUSIVE
    links: list[ChainLink]
    remediation_focus: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "verdict": self.verdict,
            "links": [l.as_dict() for l in self.links],
            "remediation_focus": self.remediation_focus,
            "trust": self.trust,
        }


@dataclass
class ChainScoreResult:
    status: str                     # ok | no_chains | error
    chains: list[AttackChain]
    links_consumed: int
    links_dropped: int
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "chains": [c.as_dict() for c in self.chains],
            "links_consumed": self.links_consumed,
            "links_dropped": self.links_dropped,
            "note": self.note,
            "trust": self.trust,
        }


# -- chain templates ---------------------------------------------------------

@dataclass(frozen=True)
class ChainTemplate:
    chain_id: str
    name: str
    description: str
    required_kinds: tuple[str, ...]      # each must map to a finding
    optional_kinds: tuple[str, ...] = ()
    remediation: str = ""


_TEMPLATES: tuple[ChainTemplate, ...] = (
    ChainTemplate(
        chain_id="webview_bridge_takeover",
        name="WebView bridge account-takeover",
        description="Deep-link into WebView plus exposed bridge method leaks session/secrets.",
        required_kinds=("implicit-deep-link", "js-bridge-registration", "scheme-registration"),
        optional_kinds=("unvalidated-uri-flow", "js-enabled"),
        remediation="Add host allowlist to deeplink + require nonce/BROWSABLE authenticity for JS bridge",
    ),
    ChainTemplate(
        chain_id="backup_exfiltration",
        name="Backup data exfiltration chain",
        description="allowBackup=true without proper data-extraction rules combined with exported provider leaks backups.",
        required_kinds=("allow-backup-true", "no-backup-rules", "exported-provider"),
        optional_kinds=("grant-uri-permissions",),
        remediation="Set allowBackup=false or declare dataExtractionRules; verify provider grant-uri scoping",
    ),
    ChainTemplate(
        chain_id="cleartext_credential_intercept",
        name="Cleartext credential interception",
        description="Cleartext HTTP/WebSocket + sensitive tokens visible to network attacker.",
        required_kinds=("cleartext-http", "hardcoded-aws-key"),
        optional_kinds=("websocket-cleartext", "cleartext-url", "trustall-tls"),
        remediation="Move endpoints to TLS; pin certs; strip hardcoded credentials",
    ),
    ChainTemplate(
        chain_id="root_payload_injection",
        name="Rooted payload injection chain",
        description="Root indicators + dynamic class loading from writable path = injectable DEX.",
        required_kinds=("root-indicator", "dynamic-class-load"),
        optional_kinds=("ptrace-detected",),
        remediation="Use strong class-loader allowlist; check for removable/tampered state",
    ),
    ChainTemplate(
        chain_id="provider_traversal_payload",
        name="Provider path-traversal chain",
        description="Exported provider + unsanitised uri.getPath() → arbitrary file read.",
        required_kinds=("exported-provider", "traversal-sink"),
        optional_kinds=("grant-uri-permissions",),
        remediation="Canonicalise file paths, scope via grant-uri-permissions, use FileProvider",
    ),

    # ------------------------------------------------------------------ wave-2 (production-grade coverage)
    ChainTemplate(
        chain_id="secret_harvest_multi",
        name="Multi-layer secret harvest",
        description="Hardcoded credentials + assets blob + native .so secret presence — multi-layer secret foot-print.",
        required_kinds=("hardcoded-symmetric-key", "labeled-secret"),
        optional_kinds=("nested-dex-payload", "hex-64-secret"),
        remediation="Strip all static secrets; move to KeyStore; audit native .so for embedded key material",
    ),
    ChainTemplate(
        chain_id="deeplink_xss_webview",
        name="Deeplink → WebView XSS chain",
        description="BROWSABLE deeplink into WebView with unsafe settings and remote content injection.",
        required_kinds=("implicit-deep-link", "webview-unsafe-settings"),
        optional_kinds=("cleartext-js-load", "unvalidated-uri-flow", "js-enabled"),
        remediation="Add host allowlist to deep link; disable setJavaScriptEnabled for external URIs",
    ),
    ChainTemplate(
        chain_id="intent_redirection_chain",
        name="Intent redirection pending-intent",
        description="Exported activity + implicit intent forwarded to another component = confused-deputy.",
        required_kinds=("exported-handler", "implicit-intent"),
        optional_kinds=("pending-intent-mutable",),
        remediation="Use explicit Intents; set FLAG_IMMUTABLE on PendingIntent",
    ),
    ChainTemplate(
        chain_id="logcat_credential_leak",
        name="Logcat credential + secrets broadcast",
        description="Sensitive log statement + external log access = credential exposure.",
        required_kinds=("log-sensitive",),
        optional_kinds=("hardcoded-aws-key", "labeled-secret"),
        remediation="Strip Log.* from production; use ProGuard/R8 log stripping",
    ),
    ChainTemplate(
        chain_id="rooting_tampered_payload",
        name="Rooted-device tampered payload",
        description="Root indicators + DEX loader + writable path → runtime code swap.",
        required_kinds=("root-indicator", "dynamic-class-load"),
        optional_kinds=("native-tamper-marker",),
        remediation="Implement Play Integrity + attestation binding; use explicit app sandbox",
    ),
    ChainTemplate(
        chain_id="trust_user_ca_cert",
        name="Trust-All + user-CA chain",
        description="Custom TrustManager + certificate pinning missing + cleartext fallback = MITM.",
        required_kinds=("trustall-tls", "cleartext-http"),
        optional_kinds=("allow-all-hostname", "custom-trustmanager"),
        remediation="Set NetworkSecurityConfig with proper pin-set; remove custom TrustManager",
    ),
    ChainTemplate(
        chain_id="mtls_bypass_native",
        name="MTLS client-cert extraction",
        description="Native TLS client-cert + key extraction = MTLS bypass.",
        required_kinds=("native-key-carving", "native-secrets"),
        optional_kinds=("hex-64-secret", "labeled-secret"),
        remediation="Move client cert to StrongBox/TEE; rotate via Android Keystore",
    ),
    ChainTemplate(
        chain_id="storage_shared_prefs_leak",
        name="SharedPreferences plaintext secrets",
        description="SharedPreferences plaintext write + backup-enabled = data exfiltration.",
        required_kinds=("cleartext-preference", "allow-backup-true"),
        optional_kinds=("no-backup-rules",),
        remediation="Use EncryptedSharedPreferences; disable backup for sensitive prefs",
    ),
    ChainTemplate(
        chain_id="insecure_deeplink_schema",
        name="Insecure normalised deeplink schema",
        description="Cleartext HTTP deeplink + lack of valid signature checking on normalised URLs.",
        required_kinds=("cleartext-http", "scheme-registration"),
        optional_kinds=("implicit-deep-link",),
        remediation="Migrate all deeplinks to HTTPS + autoVerify + host allowlist",
    ),
    ChainTemplate(
        chain_id="smali_obfuscation_evasion",
        name="Smali obfuscation evasion",
        description="Smali string-encryption wrapper + DexClassLoader = static blindspot.",
        required_kinds=("smali-encrypted-strings", "dynamic-class-load"),
        optional_kinds=("reflection-call",),
        remediation="Deploy runtime decryption observer; do not rely on DEX static strings only",
    ),
    ChainTemplate(
        chain_id="janus_signature_bypass",
        name="Janus CVE signature bypass chain",
        description="v1-only signature + embedded DEX at offset 0 = Janus bypass.",
        required_kinds=("janus",),
        optional_kinds=("nested-dex-payload",),
        remediation="Update targetSdk + minimum API level to reject v1-only APK installs",
    ),
    ChainTemplate(
        chain_id="reflection_pwn_context",
        name="Reflection + context theft",
        description="Class.forName/Method.invoke with attacker-controlled strings + exported context = reflection abuse.",
        required_kinds=("reflection-call", "exported-handler"),
        optional_kinds=("dynamic-class-load",),
        remediation="Use Class.forName with allowlist only; restrict exported components",
    ),
    ChainTemplate(
        chain_id="http_cache_credential_sniff",
        name="HTTP response cache credential sniff",
        description="OkHttp cache without credential scrub = token/PII reuse across users.",
        required_kinds=("cleartext-http", "http-cache-enabled"),
        optional_kinds=("hardcoded-aws-key",),
        remediation="Disable response caching for sensitive endpoints; strict Cache-Control",
    ),
    ChainTemplate(
        chain_id="keystore_hardware_bypass_chain",
        name="Keystore hardware attestation bypass",
        description="rooted device + fake attestation + hardware keystore claim = trust broken.",
        required_kinds=("root-indicator", "hardware-keystore-claim"),
        optional_kinds=("fake-signature",),
        remediation="Bind hardware attestation to Play Integrity; dynamic root detection at every critical call",
    ),
    ChainTemplate(
        chain_id="contentprovider_path_traversal_any",
        name="ContentProvider FileProvider traversal any",
        description="FileProvider with grant-uri permissions + catch-all authority = full app-filesystem read.",
        required_kinds=("exported-provider", "grant-uri-permissions", "file-provider-xml"),
        optional_kinds=("traversal-sink",),
        remediation="Use FileProvider with strict path restrictions; do not expose root",
    ),
)


def _finding_entities(finding) -> set[str]:
    """Return explicit source/sink identity tokens carried by a finding."""
    metadata = (
        finding.get("metadata", {})
        if isinstance(finding, dict)
        else getattr(finding, "metadata", {})
    )
    if not isinstance(metadata, dict):
        return set()
    entities: set[str] = set()
    for key in ("entity_id", "component", "class_path", "method", "path", "source"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            entities.add(f"{key}:{value.strip()}")
    return entities


def build_attack_chains(
    findings: Iterable,
    *,
    require_entity_binding: bool = False,
) -> ChainScoreResult:
    """Compose attack-chain candidates from a finding iterable.

    Every REQUIRED kind in a template must be covered by at least one
    CONFIRMED or LIKELY link — otherwise the chain does not emit.  （ older
    code only checked `len(links) >= len(required)`, which let a duplicate
    kind stand in for a missing one — a verdict-integrity hole. ）
    """
    fmap: dict[str, list] = {}
    for f in findings:
        kind = getattr(f, "kind", "") if not isinstance(f, dict) else f.get("kind", "")
        if not kind:
            continue
        fmap.setdefault(kind, []).append(f)

    chains: list[AttackChain] = []
    consumed = 0
    dropped = 0

    for tpl in _TEMPLATES:
        # all required kinds must be present
        if any(k not in fmap for k in tpl.required_kinds):
            for k in tpl.required_kinds:
                if k not in fmap:
                    dropped += 1
            continue
        bound_entity: str | None = None
        if require_entity_binding:
            entity_sets: list[set[str]] = []
            for required_kind in tpl.required_kinds:
                candidates: set[str] = set()
                for finding in fmap.get(required_kind, []):
                    verdict = (
                        finding.get("verdict") if isinstance(finding, dict)
                        else getattr(finding, "verdict", None)
                    )
                    if verdict in (CONFIRMED, LIKELY):
                        candidates.update(_finding_entities(finding))
                entity_sets.append(candidates)
            common_entities = set.intersection(*entity_sets) if entity_sets else set()
            if not common_entities:
                dropped += len(tpl.required_kinds)
                continue
            bound_entity = min(common_entities)
        links: list[ChainLink] = []
        chain_verdict = CONFIRMED
        any_inconclusive = False
        covered_kinds: set[str] = set()
        for kind in tpl.required_kinds + tpl.optional_kinds:
            # (a) optional kind evidence NEVER poisons the chain; it's just
            # weak corroboration.  (b) cap [:2] applied AFTER verdict-filtering
            # so a 3rd CONFIRMED instance can't be buried under 2 early
            # INCONCLUSIVE ones.
            per_kind = fmap.get(kind, [])
            filtered = []
            for f in per_kind:
                vv = getattr(f, "verdict", None) if not isinstance(f, dict) else f.get("verdict")
                if bound_entity and bound_entity not in _finding_entities(f):
                    continue
                if vv in (CONFIRMED, LIKELY):
                    filtered.append((f, vv))
                elif kind in tpl.required_kinds:
                    any_inconclusive = True
            for f, vv in filtered[:2]:
                consumed += 1
                if kind in tpl.required_kinds:
                    covered_kinds.add(kind)
                links.append(ChainLink(
                    module=getattr(f, "module", "") if not isinstance(f, dict) else f.get("module", ""),
                    kind=kind,
                    severity=getattr(f, "severity", "medium") if not isinstance(f, dict) else f.get("severity", "medium"),
                    verdict=vv,
                    detail=getattr(f, "detail", "") if not isinstance(f, dict) else f.get("detail", ""),
                    runtime_corroborated=bool(
                        getattr(f, "runtime_corroborated", False) if not isinstance(f, dict)
                        else f.get("runtime_corroborated", False)
                    ),
                ))
        # HARD RULE: every template.required_kind must be individually covered
        # by at least one CONFIRMED/LIKELY link — duplicates of one kind can
        # never satisfy another.
        if not all(k in covered_kinds for k in tpl.required_kinds):
            dropped += 1
            continue
        # verdict ceiling: a chain is only as strong as its weakest runtime gate.
        # Static-only evidence CANNOT be CONFIRMED — court-defensibility rule.
        # Only a REQUIRED-kind link backed by ``runtime_corroborated=True``
        # justifies top tier.  Optional-kind corroboration does NOT count
        # （ELITE-2 N-1: optional corroboration must never subsidize required.
        # ）
        runtime_proven = any(
            l.verdict == CONFIRMED and getattr(l, "runtime_corroborated", False) and l.kind in tpl.required_kinds
            for l in links
        )
        if not runtime_proven or any_inconclusive:
            chain_verdict = LIKELY
        severity = "critical" if tpl.chain_id in (
            "webview_bridge_takeover", "cleartext_credential_intercept") else "high"
        chains.append(AttackChain(
            chain_id=tpl.chain_id,
            name=tpl.name,
            description=tpl.description,
            severity=severity,
            verdict=chain_verdict,
            links=links,
            remediation_focus=tpl.remediation,
        ))

    status = "ok" if chains else "no_chains"
    return ChainScoreResult(
        status=status, chains=chains,
        links_consumed=consumed, links_dropped=dropped,
        note=f"{len(chains)} chains from {consumed} links ({dropped} dropped)",
    )
