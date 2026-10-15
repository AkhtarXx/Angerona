from __future__ import annotations

import struct
import zipfile

from src.analysis.crypto_const_fingerprints import (
    scan_apk_native_libs,
    scan_so_bytes,
)
from tests.fixtures_native import build_arm64_so


def _blank() -> bytes:
    return build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=b"", dynamic_entries=[], dynstr_names=[], dynsym=[])


def test_non_elf_unsupported():
    res = scan_so_bytes(b"PK\x03\x04 not elf")
    assert res.status == "unsupported"
    assert res.trust == "untrusted_child"


def test_aes_ttable_detected():
    # Ground truth from FIPS 197 / OpenSSL Te0 (NOT copied from the source
    # constant): Te0[0]=0xc66363a5, Te0[1]=0xf87c7c84, packed little-endian.
    te0_head = struct.pack("<II", 0xC66363A5, 0xF87C7C84)
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=te0_head + b"\x00" * 64,
                          dynamic_entries=[], dynstr_names=[], dynsym=[])
    res = scan_so_bytes(blob)
    assert "aes" in res.algorithms


def test_sha256_and_chacha():
    # Ground truth from FIPS 180-4 §4.2.2 (NOT copied from the source
    # constant): K[0]=0x428a2f98, K[1]=0x71374491, packed little-endian.
    ro = struct.pack("<II", 0x428A2F98, 0x71374491) + b"\x00" * 8 + b"expand 32-byte k"
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=ro, dynamic_entries=[], dynstr_names=[], dynsym=[])
    res = scan_so_bytes(blob)
    assert "sha256" in res.algorithms
    assert "chacha20" in res.algorithms


def test_custom_base64_alphabet_flagged():
    # a shuffled 64-char printable alphabet is NOT the standard one
    shuffled = bytes(sorted(set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), key=lambda b: (b * 7) % 64))
    assert len(shuffled) == 64
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=shuffled + b"\x00" * 4,
                          dynamic_entries=[], dynstr_names=[], dynsym=[])
    res = scan_so_bytes(blob)
    assert "base64_custom" in res.algorithms
    assert res.custom_base64_alphabets


def test_clean_elf_reports_none():
    res = scan_so_bytes(_blank())
    assert res.status == "none"
    assert res.sites == []


def test_apk_scan(tmp_path):
    # Ground truth (see test_aes_ttable_detected), NOT copied from the source constant.
    te0_head = struct.pack("<II", 0xC66363A5, 0xF87C7C84)
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=te0_head,
                          dynamic_entries=[], dynstr_names=[], dynsym=[])
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libc.so", blob)
        zf.writestr("AndroidManifest.xml", b"\x00" * 8)
    out = scan_apk_native_libs(str(apk))
    assert "lib/arm64-v8a/libc.so" in out
    assert out["lib/arm64-v8a/libc.so"].status == "found"
