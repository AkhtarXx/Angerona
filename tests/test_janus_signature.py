"""Behavior tests for the APK Janus (CVE-2017-13156) check."""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.analysis.janus_signature import TRUST_TAG, check_apk


def _write_janus_apk(path: Path, *, v1: bool = True) -> Path:
    """Conjoin a DEX header onto the front of a real ZIP archive.

    File shape: [DEX magic + filler][ZIP local entries ...][EOCD].
    The EOCD's central-directory offset is recomputed for the prepended
    bytes so the archive still parses as a ZIP.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("res/raw/x.txt", b"legit")
        if v1:
            zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n")
            zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake-rsa-block")
    zip_bytes = buf.getvalue()
    prefix = b"dex\n035\x00" + b"\x90" * 256
    body = prefix + zip_bytes
    # Fix the central-directory offset in the EOCD.
    eocd = body.rfind(b"PK\x05\x06")
    cd_off = int.from_bytes(body[eocd + 16:eocd + 20], "little") + len(prefix)
    body = body[:eocd + 16] + cd_off.to_bytes(4, "little") + body[eocd + 20:]
    path.write_bytes(body)
    return path


def _write_clean_signed_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake")
    return path


def test_janus_conjoined_apk_flagged(tmp_path):
    apk = _write_janus_apk(tmp_path / "janus.apk")
    out = check_apk(apk)
    assert out.status == "success"
    assert out.is_zip is True
    assert out.is_dex_at_offset0 is True
    assert out.first_entry_is_dex is True
    assert out.v1_signed is True and out.v2_signed is False
    assert out.suspicious is True
    assert out.signals


def test_clean_v1_apk_not_flagged(tmp_path):
    apk = _write_clean_signed_apk(tmp_path / "clean.apk")
    out = check_apk(apk)
    assert out.status == "success"
    assert out.is_zip is True
    assert out.is_dex_at_offset0 is False
    assert out.suspicious is False
    # v1-without-v2 is still noted as Janus-applicable surface
    assert any("v1" in s for s in out.signals)


def test_unsigned_plain_zip_not_suspicious(tmp_path):
    apk = tmp_path / "plain.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    out = check_apk(apk)
    assert out.suspicious is False
    assert out.v1_signed is False


def test_malformed_inputs_degrade(tmp_path):
    assert check_apk(tmp_path / "missing.apk").status == "skipped"
    tiny = tmp_path / "tiny.apk"
    tiny.write_bytes(b"PK")
    assert check_apk(tiny).status == "error"


def test_trust_envelope(tmp_path):
    apk = _write_janus_apk(tmp_path / "janus.apk")
    out = check_apk(apk)
    assert out.trust == TRUST_TAG == "untrusted_child"
    d = out.as_dict()
    assert "policy" in d
    assert d["suspicious"] is True
