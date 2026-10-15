"""Bulk-migration shim for legacy result dataclasses.

The top legacy modules already export a result dataclass with a ``findings``
list of small typed finding dataclasses (LogFinding, RootIndicator, TlsFinding,
DeepLinkFinding, ProviderFinding, etc.).  Instead of rewriting each module's
internal types (which is risky and churny), this shim **converts their
``.as_dict()`` shapes into canonical ``Finding`` instances at the module
boundary**.

Use::

    from .findings_compat import as_canonical_findings

    findings = as_canonical_findings(
        "module_name",
        my_finding_instances,
        verdict_map={"foo-kind": LIKELY, "bar-kind": CONFIRMED},
        default_verdict=LIKELY,
        layer_hint="manifest",
    )

The module's existing ``as_dict()`` payloads become Finding kwargs;
``verdict_map`` (optional) carries per-kind verdict choices so the module's
intent is preserved.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

from typing import Iterable

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"

# Canonical kind-mapping: per-module vocabulary → chain-template kinds.
# Modules emit module-specific kinds; chain templates expect canonical ones.
# （ELITE-1 found 15/20 templates dead due to name mismatches — this map is
#  the single point of truth that resolves them.）
KIND_CANONICAL_MAP: dict[str, str] = {
    # root-scanning vocabulary → chain template kinds
    "su_path": "root-indicator",
    "su_package": "root-indicator",
    "magisk": "root-indicator",
    "busybox": "root-indicator",
    "xposed": "root-indicator",
    "tracer_pid": "root-indicator",
    "root_indicator": "root-indicator",
    # TLS scanner vocabulary
    "trustall-tls": "trustall-tls",
    "trustall-certs": "trustall-tls",
    "insecure-tls-trustall": "trustall-tls",
    "trustmanager-override": "trustall-tls",
    "custom-trustmanager": "trustall-tls",
    "custom-sslsocketfactory": "trustall-tls",
    "allow-all-hostname": "trustall-tls",
    "hostname-verifier-install": "trustall-tls",
    # reflection / dynamic-load — keep specific names; only general name goes canonical
    "reflection": "reflection-call",
    "reflection-class-load": "reflection-class-load",
    "dynamic-class-load": "dynamic-class-load",
    "dynamic-dex-load": "dynamic-dex-load",
    "dexclassloader-detected": "dynamic-class-load",
    "custom-class-loader": "dynamic-class-load",
    "process-builder": "process-builder",
    "pathclassloader-hook": "dynamic-class-load",
    # secrets / assets
    "labeled-secret": "labeled-secret",
    "aws-access-key": "hardcoded-aws-key",
    "aws-access-key-secret": "hardcoded-aws-key",
    "google-api-key": "hardcoded-aws-key",
    "hex-64-secret": "hex-64-secret",
    "nested-dex-payload": "nested-dex-payload",
    "assets-encrypted-suspect": "nested-dex-payload",
    "nested-evil-dex": "nested-dex-payload",
    # webview bridge  — annotation is its own kind (different evidence nature)
    "js-bridge-registration": "js-bridge-registration",
    "js-bridge-annotation": "js-bridge-annotation",
    "js-enabled": "js-enabled",
    # deeplink / browsable
    "implicit-deep-link": "implicit-deep-link",
    "explicit-deep-link": "implicit-deep-link",
    "scheme-registration": "scheme-registration",
    # logcat sensitive
    "log-sensitive": "log-sensitive",
    # Janus
    "janus-suspicious": "janus",
    "janus-vulnerable": "janus",
    # content-provider
    "exported-provider": "exported-provider",
    "grant-uri-permissions": "grant-uri-permissions",
    "traversal-sink": "traversal-sink",
    "file-provider-xml": "file-provider-xml",
    # WebView unsafe settings
    "webview-unsafe-settings": "webview-unsafe-settings",
    "cleartext-js-load": "cleartext-js-load",
    "cleartext-js-load-url": "cleartext-js-load",
    "cleartext-js-load-http": "cleartext-js-load",
    # intent / implicit
    "implicit-intent": "implicit-intent",
    "intent-unsafe": "implicit-intent",
    "pending-intent-mutable": "pending-intent-mutable",
    # native key carving / anti-tamper
    "native-key-carving": "native-key-carving",
    "native-secrets": "native-secrets",
    "native-tamper-marker": "native-tamper-marker",
    "ptrace-detected": "ptrace-detected",
    "native-anti-tamper-marker": "native-tamper-marker",
    # hardware keystore
    "hardware-keystore-claim": "hardware-keystore-claim",
    # http cache
    "http-cache-enabled": "http-cache-enabled",
    # cleartext http
    "cleartext-http": "cleartext-http",
    "cleartext-url": "cleartext-http",
    "manifest-cleartext": "cleartext-http",
    "cleartext-preference": "cleartext-preference",
    # smali obfuscation
    "smali-encrypted-strings": "smali-encrypted-strings",
    "string-encryption-pattern": "smali-encrypted-strings",
    # unvalidated uri flow
    "unvalidated-uri-flow": "unvalidated-uri-flow",
    # allow-backup
    "allow-backup-true": "allow-backup-true",
    "no-backup-rules": "no-backup-rules",
    # generated/webbridge
    "scheme-carrying-activity": "scheme-registration",
    "export-hook-scheme": "scheme-registration",
}


def _canon_kind(kind: str) -> str:
    return KIND_CANONICAL_MAP.get(kind, kind)


def as_canonical_findings(
    module: str,
    items: Iterable,
    *,
    verdict_map: dict[str, str] | None = None,
    default_verdict: str = LIKELY,
    layer_hint: str = "",
    rule_layer_map: dict[str, str] | None = None,
) -> list[Finding]:
    """Convert result-items (dataclasses with ``as_dict()`` or dicts) into Finding.

    Handles legacy modules whose ``as_dict()`` already has a ``verdict`` field
    that uses custom per-module vocabulary (e.g. ``encrypted-suspect``,
    ``safe-default``).  Such values are NOT in the canonical 5-tier set so the
    ``verdict`` field is *not* treated as such; it goes into metadata and the
    Finding gets ``default_verdict`` instead.
    """
    out: list[Finding] = []
    vm = verdict_map or {}
    rlm = rule_layer_map or {}
    # canonical 5-tier set
    _valid = {"CONFIRMED", "LIKELY", "INCONCLUSIVE", "NOT_APPLICABLE", "REFUSAL"}
    for item in items:
        if isinstance(item, Finding):
            out.append(item)
            continue
        d = item.as_dict() if hasattr(item, "as_dict") else dict(item)
        # Per-module naming variance: some use "kind", others "marker", "rule",
        # "category", or even "verdict" (custom module-vocab like
        # ``encrypted-suspect`` / ``safe-default``).  Try several — and if the
        # module used its OWN verdict vocabulary, treat that as the kind so
        # downstream chain-templates match its semantic intent.
        _valid_tier = {"CONFIRMED", "LIKELY", "INCONCLUSIVE", "NOT_APPLICABLE", "REFUSAL"}
        v = d.get("verdict", "")
        raw_kind = (
            d.get("kind") or d.get("marker") or d.get("rule")
            or d.get("category") or (v if v and v not in _valid_tier else None)
            or "unknown"
        )
        kind = _canon_kind(raw_kind)
        verdict = vm.get(kind, v if v in _valid else default_verdict)
        rule_layer = rlm.get(kind, layer_hint or d.get("rule_layer", ""))
        metadata = {k: v for k, v in d.items()
                    if k not in {"kind", "rule", "severity", "verdict", "detail",
                                 "message", "evidence", "rule_layer", "line_no",
                                 "runtime_corroborated", "trust", "source", "marker",
                                 "category"}}
        # preserve the original verdict-vocab in metadata for traceability
        if v and v not in _valid:
            metadata.setdefault("legacy_verdict", v)
        out.append(Finding(
            module=module,
            kind=kind,
            severity=d.get("severity", "medium"),
            verdict=verdict,
            detail=d.get("detail", d.get("message", d.get("evidence", ""))),
            evidence=d.get("evidence", d.get("source", "")),
            rule_layer=rule_layer,
            line_no=int(d.get("line_no", d.get("offset", 0)) or 0),
            runtime_corroborated=bool(d.get("runtime_corroborated", False)),
            metadata=metadata,
        ))
    return out


__all__ = ["as_canonical_findings", "TRUST_TAG"]


def upgrade_result(module_name: str, result) -> object:
    """Promote ``result.findings`` items from legacy dicts to ``Finding``.

    If items are already ``Finding``, return result unchanged.  If dicts,
    rebuild result with the same fields except findings replaced by Finding.
    """
    base_findings = list(getattr(result, "findings", []))
    if not base_findings:
        return result
    if isinstance(base_findings[0], Finding):
        return result
    converted = []
    _valid_tier = {"CONFIRMED", "LIKELY", "INCONCLUSIVE", "NOT_APPLICABLE", "REFUSAL"}
    for f in base_findings:
        if isinstance(f, Finding):
            converted.append(f)
            continue
        if not isinstance(f, dict):
            converted.append(f)
            continue
        kind = f.get("kind") or f.get("rule") or f.get("marker") or "unknown"
        v = f.get("verdict", "")
        verdict = v if v in _valid_tier else None
        converted.append(Finding(
            module=module_name,
            kind=kind,
            severity=f.get("severity", "medium"),
            verdict=verdict or "LIKELY",
            detail=f.get("detail", f.get("message", f.get("evidence", ""))),
            evidence=f.get("evidence", ""),
            rule_layer=f.get("rule_layer", ""),
            line_no=int(f.get("line_no", f.get("offset", 0)) or 0),
            runtime_corroborated=bool(f.get("runtime_corroborated", False)),
            metadata={
                **{k: v for k, v in f.items()
                   if k not in {"kind", "rule", "severity", "verdict", "detail",
                                 "message", "evidence", "rule_layer", "line_no",
                                 "runtime_corroborated", "trust", "source",
                                 "marker", "category"}},
                **({"legacy_verdict": v} if v and v not in _valid_tier else {}),
            },
        ))
    field_names = [f for f in result.__dataclass_fields__]
    new_kwargs = {f: getattr(result, f) for f in field_names if f != "findings"}
    new_kwargs["findings"] = converted
    return type(result)(**new_kwargs)


__all__ = ["as_canonical_findings", "upgrade_result", "TRUST_TAG"]
