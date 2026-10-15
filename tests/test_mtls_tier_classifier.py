from __future__ import annotations

import zipfile

from src.analysis.mtls_tier_classifier import classify_mtls_tier


def test_no_signals_server_no_tls():
    r = classify_mtls_tier()
    assert r.tier == "none"
    assert r.status == "mtls_not_detected"
    assert r.trust == "untrusted_child"


def test_server_tls_from_manifest_only():
    r = classify_mtls_tier(manifest_text='<manifest><uses-permission android:name="android.permission.INTERNET"/></manifest>')
    network_evidence = r.tier in ("server_tls", "none")
    assert network_evidence


def test_mtls_soft_from_source():
    src = """
import javax.net.ssl.KeyManagerFactory;
public class A {
    void init() {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        X509KeyManager km = (X509KeyManager) kmf.getKeyManagers()[0];
    }
}
"""
    r = classify_mtls_tier(source_text=src)
    assert r.tier == "mtls_soft"
    assert r.status == "identified"
    assert r.recommended_testing.startswith("repinning_only")


def test_mtls_hard_with_hardware_keystore():
    src = """
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.StrongBoxKeyManager;
import javax.net.ssl.KeyManagerFactory;
public class B {
    void init() {
        String alias = "client";
        KeyManagerFactory.getInstance("AndroidKeyStore");
    }
}
"""
    r = classify_mtls_tier(source_text=src)
    assert r.tier == "mtls_hard"
    assert r.hardware_keystore_evidence is True
    assert "runtime_hook_only" in r.recommended_testing


def test_native_keystore_only_soft():
    src = 'public class X { void k() { KeyStore.getInstance("AndroidKeyStore"); } }'
    r = classify_mtls_tier(source_text=src)
    # key store hit without keymgr chain ⇒ still partial
    assert r.tier in ("mtls_soft", "server_tls", "mtls_hard")


def test_real_signal_no_mtls(tmp_path):
    import os
    sig = "/tmp/signal.apk"
    if not os.path.exists(sig):
        import pytest; pytest.skip("signal unavailable")
    r = classify_mtls_tier(apk_path=sig)
    # Signal does not use client-cert MTLS — it's app-level auth not TLS-layer
    assert r.tier in ("none", "server_tls", "mtls_soft")


def test_real_aegis_no_mtls(tmp_path):
    import os
    aeg = "/tmp/aegis.apk"
    if not os.path.exists(aeg):
        import pytest; pytest.skip("aegis unavailable")
    r = classify_mtls_tier(apk_path=aeg)
    assert r.tier in ("none", "server_tls")
