"""Behavior tests for the multi-dex coverage inventory."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.multidex_coverage import TRUST_TAG, inventory_apk


def _valid_dex(size: int = 112) -> bytes:
    # dex magic + version + checksum/signature padding + declared file_size at 32
    blob = bytearray(size)
    blob[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, size)
    struct.pack_into("<I", blob, 36, 0x70)
    struct.pack_into("<I", blob, 40, 0x12345678)
    return bytes(blob)


def test_multidex_inventory_all_members(tmp_path):
    apk = write_apk(tmp_path / "app.apk", dex_count=3, files={
        "classes.dex": _valid_dex(112),
        "classes2.dex": _valid_dex(224),
        "classes3.dex": _valid_dex(336),
    })
    out = inventory_apk(apk)
    assert out.status == "success"
    assert out.dex_count == 3
    assert out.coverage_gap is True
    names = {d["name"] for d in out.dex_files}
    assert names == {"classes.dex", "classes2.dex", "classes3.dex"}
    assert all(d["status"] == "parsed" and d["magic_ok"] for d in out.dex_files)
    assert all(d["size_mismatch"] is False for d in out.dex_files)


def test_single_dex_no_gap(tmp_path):
    apk = write_apk(tmp_path / "app.apk", dex_count=1,
                    files={"classes.dex": _valid_dex(112)})
    out = inventory_apk(apk)
    assert out.dex_count == 1
    assert out.coverage_gap is False


def test_bad_magic_and_size_mismatch_noted(tmp_path):
    bad = bytearray(_valid_dex(112))
    bad[0:4] = b"ZZZZ"
    mismatch = bytearray(_valid_dex(112))
    struct.pack_into("<I", mismatch, 32, 999999)
    apk = write_apk(tmp_path / "app.apk", dex_count=3, files={
        "classes.dex": bytes(bad),
        "classes2.dex": bytes(mismatch),
        "classes3.dex": b"tiny",
    })
    out = inventory_apk(apk)
    assert out.status == "partial"
    by_name = {d["name"]: d for d in out.dex_files}
    assert by_name["classes.dex"]["status"] == "bad-magic"
    assert by_name["classes2.dex"]["size_mismatch"] is True
    assert by_name["classes3.dex"]["status"] == "truncated"


def test_malformed_apk_degrades(tmp_path):
    assert inventory_apk(tmp_path / "none.apk").status == "skipped"
    bad = tmp_path / "b.apk"
    bad.write_bytes(b"not a zip archive")
    assert inventory_apk(bad).status == "error"
    nodex = tmp_path / "nd.apk"
    import zipfile
    nodex.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(nodex, "w") as zf:
        zf.writestr("assets/x.bin", b"aa")
    assert inventory_apk(nodex).status == "empty"


def test_trust_envelope(tmp_path):
    apk = write_apk(tmp_path / "app.apk", dex_count=2,
                    files={"classes.dex": _valid_dex(112),
                           "classes2.dex": _valid_dex(112)})
    out = inventory_apk(apk)
    assert out.trust == TRUST_TAG == "untrusted_child"
    assert all(d["trust"] == "untrusted_child" for d in out.dex_files)
    assert "policy" in out.as_dict()
