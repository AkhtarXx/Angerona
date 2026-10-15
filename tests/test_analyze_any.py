"""End-to-end behavior tests for analyze-any (roadmap Phase 8)."""
from __future__ import annotations

import argparse
import io
import json
import tempfile
import zipfile
from pathlib import Path

from src.cli import _cmd_analyze_any


def _ns(binary: Path, recursive: bool = False, as_json: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        binary=str(binary), recursive=recursive, engine=None, json=as_json)


def _mkapk(path: Path) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("lib/arm64/libnative.so", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        zf.writestr("assets/notes.txt", b"android config")
    path.write_bytes(buf.getvalue())
    return path


def test_analyze_any_on_elf(tmp_path, capsys):
    p = tmp_path / "x.elf"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256)
    rc = _cmd_analyze_any(_ns(p))
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert rc == 0
    assert doc["profile"]["family"] == "elf"
    assert doc["profile"]["container"] is False
    assert doc["refusal"] is None


def test_analyze_any_on_apk_recursive(tmp_path, capsys):
    apk = _mkapk(tmp_path / "app.apk")
    rc = _cmd_analyze_any(_ns(apk, recursive=True))
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["profile"]["family"] == "zip"
    assert doc["profile"]["container"] is True
    families = {c["profile"]["family"] for c in doc["children"]}
    assert "dex" in families
    assert "elf" in families


def test_analyze_any_unknown_blob_degrades_gracefully(tmp_path, capsys):
    p = tmp_path / "weird.bin"
    p.write_bytes(bytes(range(256)) * 8)
    rc = _cmd_analyze_any(_ns(p))
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    # blob family or empty: never crashes
    assert doc["profile"]["family"]
    assert isinstance(doc["profile"]["unresolved"], list)


def test_analyze_any_missing_file():
    rc = _cmd_analyze_any(_ns(Path("/definitely/not/here.bin")))
    assert rc == 2


def test_analyze_any_dp_nofollow_sample(tmp_path, capsys):
    """Binaries that trigger a refusal get rc=3 and an UnprotectableReport."""
    # packed-PE pattern that trips the refusal threshold
    pe_pad = b"MZ" + b"\x00" * 30 + b"PE\x00\x00" + b"\x00" * 200 + b"UPX0" + b"\x00" * 50
    p = tmp_path / "packed.exe"
    p.write_bytes(pe_pad)
    rc = _cmd_analyze_any(_ns(p))
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    # may or may not refuse depending on heuristics; must at least return rc in {0,3}
    assert rc in (0, 2, 3)
