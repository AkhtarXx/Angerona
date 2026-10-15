from __future__ import annotations

import struct
import zipfile

import pytest

from src.analysis.jni_registration_resolver import (
    JniRegistrationResult,
    resolve_jni_registration,
    scan_apk_native_libs,
)
from tests.fixtures_native import build_arm64_so, build_jni_table_so


def test_rejects_non_elf():
    res = resolve_jni_registration(b"MZ\x90\x00 not an elf")
    assert res.status == "not_elf"
    assert res.dynamically_registered == []
    assert res.trust == "untrusted_child"


def test_static_java_exports_are_listed():
    blob = build_arm64_so(
        text=b"\xc0\x03\x5f\xd6",  # ret
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=["Java_com_app_Native_unlock", "JNI_OnLoad"],
        dynsym=[("Java_com_app_Native_unlock", 0x1000, 4, False), ("JNI_OnLoad", 0x1000, 4, False)],
    )
    res = resolve_jni_registration(blob)
    assert "Java_com_app_Native_unlock" in res.statically_named
    assert res.jni_onload_present is True
    assert res.status in ("partial", "none")


def test_dynamic_table_resolution():
    # JNINativeMethod table: two entries at vaddr 0x1040 (right after the 64-byte .text)
    blob = build_jni_table_so(
        entries=[("decrypt", "(Ljava/lang/String;)[B"), ("check", "(I)Z")],
        fn_vaddrs=[0x1000, 0x1004],
    )
    res = resolve_jni_registration(blob)
    names = {r.java_name for r in res.dynamically_registered}
    sigs = {r.signature for r in res.dynamically_registered}
    addrs = {r.fn_addr for r in res.dynamically_registered}
    assert names == {"decrypt", "check"}
    assert "(Ljava/lang/String;)[B" in sigs
    assert addrs == {0x1000, 0x1004}
    assert res.registernatives_imported is True
    assert res.status == "resolved"


def test_missing_table_and_no_exports_is_none():
    blob = build_arm64_so(
        text=b"\x1f\x20\x03\xd5",
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=["other_func"],
        dynsym=[("other_func", 0x1000, 4, False)],
    )
    res = resolve_jni_registration(blob)
    assert res.status == "none"
    assert res.statically_named == []
    assert res.dynamically_registered == []


def test_apk_scan_routes_libs(tmp_path):
    from tests.fixtures_native import build_arm64_so

    blob = build_arm64_so(
        text=b"\xc0\x03\x5f\xd6",
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=["Java_a_b"],
        dynsym=[("Java_a_b", 0x1000, 4, False)],
    )
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libx.so", blob)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
    out = scan_apk_native_libs(str(apk))
    assert "lib/arm64-v8a/libx.so" in out
    assert out["lib/arm64-v8a/libx.so"].statically_named == ["Java_a_b"]
