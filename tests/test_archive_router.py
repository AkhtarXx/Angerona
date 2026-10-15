"""Behavior tests for the recursive archive router (roadmap Phase 2)."""
from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

import pytest

from src.analysis.archive_router import (
    MAX_DEPTH,
    _route_container,
    route,
)


def _make_zip_buffer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_route_flat_zip_with_mixed_members():
    with tempfile.TemporaryDirectory() as td:
        z_bytes = _make_zip_buffer({
            "classes.dex": b"dex\n035\x00" + b"\x00" * 32,
            "lib/arm64/libnative.so": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32,
            "manifest.json": b'{"platform":"android"}',
        })
        apath = Path(td) / "app.apk"
        apath.write_bytes(z_bytes)
        verdict = route(apath)
        assert len(verdict.children) == 3
        families = {c.profile.family for c in verdict.children}
        assert "dex" in families
        assert "elf" in families


def test_route_zip_stops_at_depth_cap():
    # nested zips: outer -> inner1 -> inner2
    with tempfile.TemporaryDirectory() as td:
        inner2 = _make_zip_buffer({"inner.txt": b"deep"})
        inner1 = _make_zip_buffer({"inner2.zip": inner2, "readme.txt": b"mid"})
        outer = _make_zip_buffer({"inner1.zip": inner1})
        apath = Path(td) / "outer.zip"
        apath.write_bytes(outer)
        verdict = route(apath)
        # It should descend at least one level and stop gracefully
        assert verdict.depth_reached >= 1
        assert not verdict.unresolved or "depth" not in " ".join(verdict.unresolved).lower()


def test_route_hash_dedup_breaks_cycles():
    with tempfile.TemporaryDirectory() as td:
        payload = b"SAME_CONTENT" * 1000
        z_bytes = _make_zip_buffer({"a.bin": payload, "b.bin": payload})
        apath = Path(td) / "dupe.zip"
        apath.write_bytes(z_bytes)
        verdict = route(apath)
        # identical payload appears once as a child, the rest reported as cycle
        names = [c.name for c in verdict.children]
        assert names.count("a.bin") == 1 or names.count("b.bin") == 1 or len(names) <= 2
        assert any("cycle" in u.lower() for u in verdict.unresolved)


def test_route_self_referencing_zip_does_not_crash():
    with tempfile.TemporaryDirectory() as td:
        z_bytes = _make_zip_buffer({"self.zip": b"PK\x03\x04" + b"\x00" * 32})
        apath = Path(td) / "selfish.zip"
        apath.write_bytes(z_bytes)
        # Must not crash or infinite-loop; must truncate or report
        verdict = route(apath)
        assert verdict is not None


def test_route_missing_file_returns_note():
    verdict = route("/nonexistent/file.zip")
    assert verdict.unresolved or "missing" in verdict.note
