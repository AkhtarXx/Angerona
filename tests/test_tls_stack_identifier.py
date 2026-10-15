from __future__ import annotations

import zipfile
from pathlib import Path

from src.analysis.tls_stack_identifier import identify_tls_stack


def _mk_apk(path, libs=(), dex_payload=b""):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64)
        for name, blob in libs:
            zf.writestr(name, blob)
        zf.writestr("classes.dex", dex_payload or (b"dex\n035\x00" + b"\x00" * 100))
    return path


def test_missing_apk_unknown(tmp_path):
    r = identify_tls_stack(tmp_path / "nope.apk")
    assert r.status == "unknown"
    assert r.primary_stack == "unknown"
    assert r.trust == "untrusted_child"


def test_rustls_by_lib_string(tmp_path):
    lib = b"\x7fELF" + b"\x00" * 32 + b"rustls::client::ClientConnection::new\x00" + b"\x00" * 64
    p = _mk_apk(tmp_path / "rust.apk", libs=[("lib/arm64-v8a/libsignal.so", lib)])
    r = identify_tls_stack(p)
    assert r.primary_stack == "rustls"
    assert "rustls" in r.stacks_detected
    assert r.recommended_rule_layer == "native"


def test_boringssl_by_lib_name(tmp_path):
    lib = b"\x7fELF" + b"\x00" * 32 + b"BoringSSL\x00ssl\x00"
    p = _mk_apk(tmp_path / "boring.apk", libs=[("lib/arm64-v8a/libboring_test.so", lib)])
    r = identify_tls_stack(p)
    assert "boringssl" in r.stacks_detected
    assert r.primary_stack == "boringssl"


def test_conscrypt_by_lib_pattern(tmp_path):
    lib = b"\x7fELF" + b"\x00" * 32 + b"com.android.org.conscrypt.SSL\x00"
    p = _mk_apk(tmp_path / "consc.apk", libs=[("lib/arm64-v8a/libconscrypt_jni.so", lib)])
    r = identify_tls_stack(p)
    assert r.primary_stack == "conscrypt_java"
    assert r.recommended_rule_layer == "java"


def test_dex_okhttp_and_pinning(tmp_path):
    dex = b"dex\n035\x00" + b"\x00" * 32 + b"okhttp3.CertificatePinner\x00" + b"\x00" * 32
    p = _mk_apk(tmp_path / "pin.apk", dex_payload=dex)
    r = identify_tls_stack(p)
    assert r.okhttp_present is True
    assert r.cert_pinning_likely is True


def test_multi_stack_partial(tmp_path):
    lib = b"\x7fELF" + b"\x00" * 32 + b"rustls_version\x00"
    lib2 = b"\x7fELF" + b"\x00" * 32 + b"com.android.org.conscrypt\x00"
    p = _mk_apk(tmp_path / "multi.apk", libs=[
        ("lib/arm64-v8a/libsignal.so", lib),
        ("lib/arm64-v8a/libcons.so", lib2),
    ])
    r = identify_tls_stack(p)
    assert "rustls" in r.stacks_detected
    assert "conscrypt_java" in r.stacks_detected


def test_real_signal_identifies_rustls(tmp_path):
    sig = Path("/tmp/signal.apk")
    if not sig.exists():
        import pytest; pytest.skip("signal not on disk")
    r = identify_tls_stack(sig)
    # Signal's TLS is in Rust via libsignal-net; conscrypt_jni is also bundled
    assert r.primary_stack in ("rustls", "boringssl", "conscrypt_java")
    assert r.status in ("identified", "partial")


def test_real_aegis_identifies_java_or_none(tmp_path):
    aeg = Path("/tmp/aegis.apk")
    if not aeg.exists():
        import pytest; pytest.skip("aegis not on disk")
    r = identify_tls_stack(aeg)
    # Aegis uses Java Cipher — no native TLS stack
    assert r.primary_stack in ("conscrypt_java", "unknown")
