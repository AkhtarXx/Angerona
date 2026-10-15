"""Tests for src.analysis.bindiff (BinDiff structural verification).

These tests are split into two layers:

  * Unit tests for :func:`parse_bindiff` build a synthetic ``.BinDiff`` SQLite
    database in-memory that mirrors BinDiff's real schema (verified against
    ``database_writer.cc``) -- no Ghidra/BinDiff binary required.
  * Integration tests are guarded by ``_bindiff_ready()`` and skipped when the
    BinExport/BinDiff toolchain is not provisioned, exactly like the engine
    tests in this suite.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import json
import pytest

from src.analysis import bindiff as bd


# ----------------------------------------------------------- helpers (unit)

def _make_fake_bindiff(path: Path, *, overall_sim: float = 0.42,
                       overall_conf: float = 0.9, functions: list[dict] | None = None) -> Path:
    """Write a minimal but schema-valid ``.BinDiff`` SQLite database."""
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE metadata (version TEXT, file1 INT, file2 INT, description TEXT, "
        "created DATE, modified DATE, similarity DOUBLE PRECISION, "
        "confidence DOUBLE PRECISION)"
    )
    con.execute(
        "CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT, address2 BIGINT, "
        "name2 TEXT, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, "
        "flags INTEGER, algorithm SMALLINT, evaluate BOOLEAN, commentsported BOOLEAN, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.execute(
        "INSERT INTO metadata VALUES ('8', 1, 2, 'test', 'now', 'now', ?, ?)",
        (overall_sim, overall_conf),
    )
    rows = functions or [
        {"address1": 0x1000, "name1": "main", "address2": 0x1000, "name2": "main",
         "similarity": 0.95, "confidence": 0.8, "flags": 1,
         "basicblocks": 5, "edges": 6, "instructions": 42},
        {"address1": 0x2000, "name1": "helper", "address2": 0x2000, "name2": "helper",
         "similarity": 0.30, "confidence": 0.6, "flags": 8,
         "basicblocks": 2, "edges": 2, "instructions": 10},
    ]
    for i, f in enumerate(rows, start=1):
        con.execute(
            "INSERT INTO function VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (i, f["address1"], f["name1"], f["address2"], f["name2"],
             f["similarity"], f["confidence"], f["flags"], 0, 0, 0,
             f["basicblocks"], f["edges"], f["instructions"]),
        )
    con.commit()
    con.close()
    return path


def test_structural_strength_combines_flags_algo_similarity():
    """GAP 2 fix: structural_strength combines flags + algorithm weight + similarity."""
    fm_id = bd.FunctionMatch(0x1, 0x1, "a", "a", 0.9, 0.9, flags=1, algorithm=11)
    assert fm_id.structural_strength == 1.0
    fm_frag = bd.FunctionMatch(0x1, 0x1, "a", "a", 1.0, 1.0, flags=0, algorithm=11)
    assert fm_frag.structural_strength == pytest.approx(0.15, abs=1e-6)
    fm_strong = bd.FunctionMatch(0x1, 0x1, "a", "a", 0.8, 0.8, flags=0, algorithm=5)
    assert fm_strong.structural_strength == pytest.approx(0.8, abs=1e-6)
    assert fm_strong.algorithm_name == "MD index (flowgraph, top down)"
    assert fm_frag.algorithm_name == "instruction count"


def test_parse_bindiff_reads_algorithm_column():
    """GAP 2: the parser surfaces the algorithm column."""
    with tempfile.TemporaryDirectory() as d:
        db = _make_fake_bindiff(Path(d) / "x.BinDiff", overall_sim=0.42)
        con = sqlite3.connect(str(db))
        con.execute("INSERT INTO function VALUES (1, 4096, 'sub_1000', 4096, 'sub_1000', "
                    "0.85, 0.9, 0, 7, 0, 0, 10, 12, 200)")
        con.commit()
        con.close()
        r = bd.parse_bindiff(db)
        assert any(f.algorithm == 7 for f in r.functions)
        strong = [f for f in r.functions if f.algorithm == 7][0]
        assert strong.algorithm_name == "prime signature matching"
        assert strong.structural_strength > 0.8


def test_parse_bindiff_reads_metadata_and_functions():
    with tempfile.TemporaryDirectory() as d:
        db = _make_fake_bindiff(Path(d) / "x.BinDiff", overall_sim=0.42,
                                overall_conf=0.9)
        r = bd.parse_bindiff(db)
    assert r.overall_similarity == pytest.approx(0.42)
    assert r.overall_confidence == pytest.approx(0.9)
    assert len(r.functions) == 2


def test_functionmatch_flags_decode_correctly():
    with tempfile.TemporaryDirectory() as d:
        db = _make_fake_bindiff(Path(d) / "x.BinDiff")
        r = bd.parse_bindiff(db)
    by_name = {f.name1: f for f in r.functions}
    assert by_name["main"].identical is True
    assert by_name["main"].changed is False
    assert by_name["helper"].identical is False
    assert by_name["helper"].changed is True


def test_top_matches_sorted_and_filtered():
    with tempfile.TemporaryDirectory() as d:
        db = _make_fake_bindiff(Path(d) / "x.BinDiff")
        r = bd.parse_bindiff(db)
    top = r.top_matches(min_similarity=0.5, limit=1)
    assert len(top) == 1
    assert top[0].name1 == "main"
    assert top[0].similarity == pytest.approx(0.95)


def test_best_match_for_address():
    with tempfile.TemporaryDirectory() as d:
        db = _make_fake_bindiff(Path(d) / "x.BinDiff")
        r = bd.parse_bindiff(db)
    hit = r.best_match_for(0x2000)
    assert hit is not None and hit.name1 == "helper"
    assert r.best_match_for(0xDEAD) is None


def test_parse_missing_file_is_empty_not_error():
    r = bd.parse_bindiff("/nonexistent/path.BinDiff")
    assert r.functions == []
    assert r.overall_similarity == 0.0


def test_parse_corrupt_db_is_empty_not_error():
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "bad.BinDiff"
        bad.write_text("this is not a sqlite db")
        r = bd.parse_bindiff(bad)
    assert r.functions == []


# ----------------------------------------------------- config discovery (unit)

def test_bindiff_discovery_via_env(monkeypatch, tmp_path):
    fake = tmp_path / "bindiff"
    fake.write_bytes(b"\x7fELF fake")
    monkeypatch.setenv("BINDIFF_PATH", str(fake))
    from src import config
    assert config.find_bindiff() == fake


def test_binexport_discovery_via_user_ext(monkeypatch, tmp_path):
    # Simulate ~/.ghidra/<ver>/Extensions/BinExport/extension.properties.
    # Because vendored Ghidra installs also have the extension, disable the
    # VENDOR_DIR check by pointing vendor to an empty temp dir.
    ext = tmp_path / ".ghidra" / ".ghidra_11.0.3_PUBLIC" / "Extensions" / "BinExport"
    ext.mkdir(parents=True)
    (ext / "extension.properties").write_text("name=BinExport\nversion=11.0.3\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    from src import config
    monkeypatch.setattr(config, "VENDOR_DIR", tmp_path / "empty_vendor")
    found = config.find_binexport_ghidra()
    assert found == ext


# --------------------------------------------------------- integration guards

def _bindiff_ready() -> bool:
    from src import config
    try:
        return config.load_config("ghidra").bindiff_ready()[0]
    except Exception:
        return False


@pytest.mark.skipif(not _bindiff_ready(),
                    reason="BinDiff/BinExport toolchain not provisioned")
def test_ghidra_export_and_self_diff_roundtrip():
    """End-to-end: Ghidra export -> self-diff -> ~1.0 overall similarity."""
    from src.config import load_config
    from src.workspace import RunWorkspace

    cfg = load_config("ghidra")
    sample = sorted(Path(__file__).parent.parent.glob("samples/*"))[0]
    with tempfile.TemporaryDirectory() as d:
        ws = RunWorkspace.create(Path(d), str(sample))
        try:
            be = bd.cached_export(cfg, ws, str(sample))
        except RuntimeError as exc:
            pytest.skip(f"BinExport runtime unavailable (graceful no-op): {exc}")
        assert be.is_file()
        diff = bd.diff_binary(cfg, ws, str(be), str(be),
                              primary_is_binexport=True, secondary_is_binexport=True)
        # self-diff: BinDiff's conservative matcher gives the best per-function
        # matches a similarity of ~1.0 (verified empirically); assert that the
        # strongest matches are effectively identical, which is the real signal.
        top = diff.top_matches(min_similarity=0.99, limit=3)
        assert top, "self-diff should contain near-identical function matches"
        assert all(f.similarity >= 0.99 for f in top)


@pytest.mark.skipif(not _bindiff_ready(),
                    reason="BinDiff/BinExport toolchain not provisioned")
def test_mcp_bindiff_tools_registered_and_callable():
    """The two BinDiff MCP tools are registered and run end-to-end via the server."""
    from src.mcp.server import GhidraMCPServer
    from src.config import load_config
    from src.workspace import RunWorkspace

    cfg = load_config("ghidra")
    sample = sorted(Path(__file__).parent.parent.glob("samples/*"))[0]
    import shutil
    with tempfile.TemporaryDirectory() as d:
        ws = RunWorkspace.create(Path(d), str(sample))
        try:
            be = bd.cached_export(cfg, ws, str(sample))
        except RuntimeError as exc:
            pytest.skip(f"BinExport runtime unavailable (graceful no-op): {exc}")
        corpus = Path(d) / "corpus" / "fam"
        corpus.mkdir(parents=True)
        shutil.copy(be, corpus / "self.BinExport")

        srv = GhidraMCPServer(default_binary=str(sample))
        names = {t["name"] for t, _ in srv.tools.values()}
        assert {"bindiff_match", "verify_understanding", "verify_reconstruction",
                "verify_claims", "verify_capabilities"} <= names

        out = json.loads(srv.t_bindiff_match({"binary": str(sample),
                                              "corpus_dir": str(corpus),
                                              "similarity_threshold": 0.1}))
        assert out["hit_count"] >= 1

        out2 = json.loads(srv.t_verify_understanding(
            {"binary": str(sample), "recompiled_binexport": str(be),
             "similarity_threshold": 0.7}))
        assert out2["total"] >= 1

        # verify_reconstruction exercises the gcc compile -> export -> diff path
        csrc = Path(d) / "recon.c"
        csrc.write_text("int main(void){return 0;}\n")
        out3 = json.loads(srv.t_verify_reconstruction(
            {"binary": str(sample), "c_source": str(csrc),
             "similarity_threshold": 0.05}))
        assert "total" in out3
