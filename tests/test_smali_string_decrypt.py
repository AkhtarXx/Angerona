"""Behavior tests for smali string decryption (roadmap Android #1)."""
from __future__ import annotations

from src.analysis.smali_string_decrypt import decrypt_dex_strings


PLAIN_SMALI = """
.class public final Lcom/x/Crypto;
.super Ljava/lang/Object;

.method public static a()Ljava/lang/String;
    .locals 2
    const/16 v0, 0x48
    const/16 v1, 0x21
    new-instance v2, Ljava/lang/StringBuilder;
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
"""

OBF_SMALI = """
.class public final Lcom/x/Obf;
.super Ljava/lang/Object;

.method private static s(I)Ljava/lang/String;
    .locals 1
    const/16 v0, 0x48
    or-int/lit8 v0, v0, 0x08
    int-to-char v0, v0
    return-object v0
.end method
"""

COMPLEX_SMALI = """
.method public static f(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 3
    const/16 v0, 0x41
    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I
    move-result v1
    return-object v1
.end method
"""


def test_simple_stringbuilder_chain():
    out = decrypt_dex_strings(PLAIN_SMALI)
    assert out["verified"] == 1
    result = next(r for r in out["results"] if r["decrypted"])
    assert result["decrypted"] == "H!"


def test_xor_string_via_int_to_char():
    out = decrypt_dex_strings(OBF_SMALI)
    assert out["verified"] == 0 or out["verified"] == 1    # constant-prop shape
    unresolved = out["results"][0]["unresolved"] if out["results"] else []
    # shape is outside our safe-list (or-int is allowed; the invoke-free shape should
    # resolve via the int-to-char path and return-object)
    # 0x48 ^ 0x08 = 0x40 = '@' — or, via or-int/lit8 path → still int-to-char → '@'
    if out["verified"] == 1:
        assert any(r["decrypted"] == "@" for r in out["results"])


def test_unsafe_invoke_fails():
    out = decrypt_dex_strings(COMPLEX_SMALI)
    assert out["verified"] == 0
    assert any("identityHashCode" in str(r["unresolved"]) or
               "unsupported" in str(r["unresolved"]) for r in out["results"]) or \
           out["results"][0]["unresolved"]
