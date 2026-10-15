from __future__ import annotations

import zipfile

from src.analysis.jni_boundary_taint import (
    scan_apk,
    scan_native_strings,
    scan_source_text,
)


def test_empty_source():
    res = scan_source_text("")
    assert res.status == "empty_source"


def test_loadlibrary_collected():
    src = """
public class Entry {
    static { System.loadLibrary("native-lib"); }
}
"""
    res = scan_source_text(src, "Entry.java")
    assert res.libraries_loaded == ["native-lib"]


def test_native_literal_arg_with_sensitive_vocab():
    src = """
class Auth {
    static native boolean validate(String s);
    boolean check() { return validate("master_token_2026"); }
}
"""
    res = scan_source_text(src, "Auth.java")
    found = [f for f in res.findings if f["kind"] == "native_literal_arg"]
    assert found, f"expected native_literal_arg, got {res.findings}"
    assert res.status == "findings"
    assert found[0]["direction"] == "java_to_native"
    assert "token" in found[0]["sensitive_vocab"]


def test_benign_native_call_low_severity():
    src = 'boolean ok() { return nativeCheck(x, y); }'
    res = scan_source_text(src, "x.java")
    assert res.status == "clean"


def test_smali_native_declaration_counted():
    # smali puts the method name directly before '(' (no Java return-type
    # token), so `native foo()V` must still be recognized as a declaration.
    src = """
.class public Lcom/x/Auth;
.super Ljava/lang/Object;

.method public static native foo()V
.end method
"""
    res = scan_source_text(src, "Auth.smali")
    assert res.native_methods_seen == 1


def test_native_strings_jni_marker_with_token():
    blob = b"\x7fELF" + b"\x00" * 64 + b"GetFieldID some_token field\x00"
    res = scan_native_strings(blob, "libx.so")
    kinds = {f["kind"] for f in res.findings}
    assert "jni_field_read" in kinds
    f = next(x for x in res.findings if x["kind"] == "jni_field_read")
    assert "token" in f["sensitive_vocab"]


def test_newstringutf_escape():
    blob = b'\x7fELF' + b"\x00" * 32 + b'NewStringUTF(env, "sk_live_secret_pwd_99")\x00'
    res = scan_native_strings(blob, "libsec.so")
    kinds = {f["kind"] for f in res.findings}
    assert "newstringutf_escape" in kinds
    f = next(x for x in res.findings if x["kind"] == "newstringutf_escape")
    assert f["direction"] == "native_to_java"
    assert f["severity"] in ("critical", "high")


def test_clean_native_blob():
    blob = b"\x7fELF" + b"\x00" * 512
    res = scan_native_strings(blob, "lib.so")
    assert res.status == "clean"


def test_apk_routes_java_and_so(tmp_path):
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("sources/Auth.java", 'class A { static native boolean v(String s); boolean x(){ return v("seed_secret_9"); } }')
        zf.writestr("lib/arm64-v8a/lib-j.so", b"\x7fELF" + b"\x00" * 64 + b"NewStringUTF(env, \"token_seed\")\x00")
    out = scan_apk(str(apk))
    assert "sources/Auth.java" in out
    assert "lib/arm64-v8a/lib-j.so" in out
    assert out["sources/Auth.java"].status == "findings"
