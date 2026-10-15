from __future__ import annotations

from src.analysis.attack_chain_scorer import build_attack_chains
from src.analysis.finding import CONFIRMED, INCONCLUSIVE, LIKELY, Finding


def _f(module, kind, severity="medium", verdict=LIKELY, detail=""):
    return Finding(module=module, kind=kind, severity=severity, verdict=verdict, detail=detail)


def test_webview_bridge_chain_composed():
    findings = [
        _f("browsable_implicits", "implicit-deep-link", "high", CONFIRMED),
        _f("webview_bridge_finder", "js-bridge-registration", "high", CONFIRMED),
        _f("deeplink_injection", "scheme-registration", "medium", LIKELY),
    ]
    r = build_attack_chains(findings)
    assert r.status == "ok"
    chain_ids = [c.chain_id for c in r.chains]
    assert "webview_bridge_takeover" in chain_ids


def test_backup_exfil_chain():
    findings = [
        _f("allow_backup_check", "allow-backup-true", "medium", CONFIRMED),
        _f("allow_backup_check", "no-backup-rules", "medium", LIKELY),
        _f("contentprovider_traversal", "exported-provider", "high", LIKELY),
    ]
    r = build_attack_chains(findings)
    assert "backup_exfiltration" in [c.chain_id for c in r.chains]


def test_inconclusive_link_breaks_chain():
    findings = [
        _f("browsable_implicits", "implicit-deep-link", "high", INCONCLUSIVE),
        _f("webview_bridge_finder", "js-bridge-registration", "high", CONFIRMED),
    ]
    r = build_attack_chains(findings)
    # implicit-deep-link is required and INCONCLUSIVE → no bridge chain
    assert "webview_bridge_takeover" not in [c.chain_id for c in r.chains]


def test_no_chains_when_isolated():
    findings = [
        _f("multidex_coverage", "dex-inventory", "info", CONFIRMED),
    ]
    r = build_attack_chains(findings)
    assert r.status == "no_chains"


def test_multiple_chains_composed():
    findings = [
        _f("browsable_implicits", "implicit-deep-link", "high", CONFIRMED),
        _f("webview_bridge_finder", "js-bridge-registration", "high", CONFIRMED),
        _f("deeplink_injection", "scheme-registration", "medium", LIKELY),
        _f("cleartext_tls_rule", "cleartext-http", "medium", CONFIRMED),
        _f("dex_security_rules", "hardcoded-aws-key", "high", CONFIRMED),
    ]
    r = build_attack_chains(findings)
    ids = {c.chain_id for c in r.chains}
    assert "webview_bridge_takeover" in ids
    assert "cleartext_credential_intercept" in ids


def test_chain_severity_critical_for_critical_tpls():
    findings = [
        _f("browsable_implicits", "implicit-deep-link", "high", CONFIRMED),
        _f("webview_bridge_finder", "js-bridge-registration", "high", CONFIRMED),
        _f("deeplink_injection", "scheme-registration", "medium", LIKELY),
    ]
    r = build_attack_chains(findings)
    webview_chain = next(c for c in r.chains if c.chain_id == "webview_bridge_takeover")
    assert webview_chain.severity == "critical"


def test_strict_chain_mode_requires_same_explicit_entity():
    entry = _f("browsable_implicits", "implicit-deep-link", "high", CONFIRMED)
    sink = _f("webview_bridge_finder", "js-bridge-registration", "high", CONFIRMED)
    scheme = _f("deeplink_injection", "scheme-registration", "medium", LIKELY)
    entry.metadata["component"] = "com.demo.Entry"
    sink.metadata["component"] = "com.demo.Other"
    scheme.metadata["component"] = "com.demo.Entry"
    unbound = build_attack_chains([entry, sink, scheme], require_entity_binding=True)
    assert "webview_bridge_takeover" not in [c.chain_id for c in unbound.chains]

    sink.metadata["component"] = "com.demo.Entry"
    bound = build_attack_chains([entry, sink, scheme], require_entity_binding=True)
    assert "webview_bridge_takeover" in [c.chain_id for c in bound.chains]
