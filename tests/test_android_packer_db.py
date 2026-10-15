from __future__ import annotations

import zipfile

from src.analysis.android_packer_db import (
    _ANDROID_PACKERS,
    detect_android_packer,
)


def _mk_apk(path, libs=(), assets=()):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64)
        for name, blob in libs:
            zf.writestr(name, blob)
        for name, blob in assets:
            zf.writestr(name, blob)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
    return path


def test_registry_includes_all_families():
    fams = {s.family for s in _ANDROID_PACKERS}
    assert {"bangcle", "secneo", "legu", "jiagu_360", "ijiami",
            "dexguard_native", "promon_shield", "appdome"} <= fams


def test_missing_apk_error(tmp_path):
    r = detect_android_packer(tmp_path / "nope.apk")
    assert r.status == "error"
    assert r.trust == "untrusted_child"


def test_clean_apk_no_match(tmp_path):
    p = _mk_apk(tmp_path / "clean.apk",
                libs=[("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 64)])
    r = detect_android_packer(p)
    assert r.status == "none"
    assert r.matches == []
    assert "libfoo.so" in r.apk_libs_seen[0]


def test_legu_detected_by_soname(tmp_path):
    fake_lib = b"\x7fELF" + b"\x00" * 64 + b"tencent_shell\x00"
    p = _mk_apk(tmp_path / "legu.apk",
                libs=[("lib/arm64-v8a/libtup.so", fake_lib)],
                assets=[("assets/libtup.so", fake_lib)])
    r = detect_android_packer(p)
    assert r.status in ("identified", "multiple_candidates")
    fams = [m.family for m in r.matches]
    assert "legu" in fams or "jiagu_360" in fams


def test_dexguard_native_detected_by_section(tmp_path):
    # Minimal ARM64 ELF with a DexGuard-like section name string in it
    fake_lib = b"\x7fELF" + b"\x00" * 64 + b"dexguard\x00.dgstrtab\x00"
    p = _mk_apk(tmp_path / "dg.apk",
                libs=[("lib/arm64-v8a/libdexhelper.so", fake_lib)],
                assets=[("assets/dexguard/info", b"\x00" * 8)])
    r = detect_android_packer(p)
    assert r.status in ("identified", "multiple_candidates")
    assert any(m.family == "dexguard_native" for m in r.matches)


def test_ijiami_by_asset_path(tmp_path):
    p = _mk_apk(tmp_path / "aji.apk",
                libs=[("lib/arm64-v8a/libx.so", b"\x7fELF" + b"\x00" * 64)],
                assets=[("assets/ijiami.dat", b"\x00" * 16)])
    r = detect_android_packer(p)
    assert r.status in ("identified", "multiple_candidates")
    fams = [m.family for m in r.matches]
    assert "ijiami" in fams


def test_real_signal_no_packer(tmp_path):
    sig = "/tmp/signal.apk"
    import os
    if not os.path.exists(sig):
        import pytest; pytest.skip("signal apk unavailable")
    r = detect_android_packer(sig)
    # Signal is unmodified builds — no commercial packer
    assert r.status in ("none", "multiple_candidates")
