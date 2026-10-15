"""Behavior tests for BinDiff multi-algorithm consensus (roadmap Phase A2).

Builds synthetic .BinDiff SQLite databases with the REAL schema (verified against
BinDiff's database_writer.cc) and proves:

  1. consensus_score aggregates per-family structural votes correctly.
  2. A strong single-family match passes when only ONE algorithm row exists
     (classic gate fallback — no second opinion available).
  3. A faithful recompile (cfg + callseq + signature agree) passes the consensus floor.
  4. A coincidental match (strong topology row but data/callseq families vote NO)
     FAILS consensus even though the classic strength gate alone would have passed.
  5. Name-only matches (no structural family) can never pass consensus.
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.analysis import bindiff as bd


def _write_db(path: Path, rows: list[dict]) -> Path:
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE metadata (version TEXT, file1 INT, file2 INT, description TEXT, "
        "created DATE, modified DATE, similarity DOUBLE PRECISION, "
        "confidence DOUBLE PRECISION)")
    con.execute(
        "CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT, address2 BIGINT, "
        "name2 TEXT, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, "
        "flags INTEGER, algorithm SMALLINT, evaluate BOOLEAN, commentsported BOOLEAN, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)")
    con.execute("INSERT INTO metadata VALUES ('8',1,2,'t','now','now',0.9,0.9)")
    for i, r in enumerate(rows, start=1):
        con.execute(
            "INSERT INTO function VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (i, r["address1"], r["name1"], r["address1"], r["name1"],
             r["similarity"], r["confidence"], r.get("flags", 0), r["algorithm"],
             0, 0, 10, 12, 100))
    con.commit()
    con.close()
    return path


def _judge_with_db(db: Path, name: str):
    """Run verify_understanding against a parsed DB, skipping the real bindiff CLI."""
    with patch.object(bd, "diff_binary") as m:
        m.return_value = bd.parse_bindiff(db)
        class _WS:  # minimal stand-in for RunWorkspace
            raw_dir = db.parent
        return bd.verify_understanding(
            cfg=None, ws=_WS(), binary="orig", recompiled_binexport="recon",
            function_name=name, similarity_threshold=0.55,
        )


# ---------------------------------------------------------------- unit: score

def test_consensus_score_counts_families():
    matches = [
        bd.FunctionMatch(1, 1, "f", "f", 0.9, 0.9, flags=0, algorithm=3),   # cfg
        bd.FunctionMatch(1, 1, "f", "f", 0.8, 0.8, flags=0, algorithm=15),  # callseq
        bd.FunctionMatch(1, 1, "f", "f", 0.2, 0.2, flags=0, algorithm=13),  # data, low sim
        bd.FunctionMatch(1, 1, "f", "f", 0.6, 0.6, flags=0, algorithm=7),   # signature
    ]
    score, fams = bd.consensus_score(matches, min_similarity=0.5)
    assert fams == {"cfg", "callseq", "signature"}     # data row below similarity floor
    assert score == pytest.approx(3 / 5, abs=1e-6)


def test_consensus_score_ignores_weak_algorithms():
    matches = [
        bd.FunctionMatch(1, 1, "f", "f", 1.0, 1.0, flags=0, algorithm=1),   # name hash
        bd.FunctionMatch(1, 1, "f", "f", 1.0, 1.0, flags=0, algorithm=11),  # insn count
    ]
    score, fams = bd.consensus_score(matches, min_similarity=0.5)
    assert fams == set() and score == 0.0


# -------------------------------------------------------- classic fallback (one row)

def test_single_algorithm_row_falls_back_to_classic_gate():
    with tempfile.TemporaryDirectory() as td:
        db = _write_db(Path(td) / "x.BinDiff", [
            dict(address1=0x1000, name1="decrypt", similarity=0.95,
                 confidence=0.9, algorithm=7),  # prime signature only
        ])
        r = _judge_with_db(db, "decrypt")
        # strong+high_sim, no second algorithm opinion -> classic gate, verified
        assert r.verified
        assert r.consensus_families == ["signature"]


# -------------------------------------------------------- faithful recompile passes

def test_multi_family_consensus_passes_faithful_recompile():
    with tempfile.TemporaryDirectory() as td:
        db = _write_db(Path(td) / "x.BinDiff", [
            dict(address1=0x1000, name1="parse_packet", similarity=0.92, confidence=0.9, algorithm=3),
            dict(address1=0x1000, name1="parse_packet", similarity=0.88, confidence=0.9, algorithm=5),
            dict(address1=0x1000, name1="parse_packet", similarity=0.81, confidence=0.9, algorithm=15),
            dict(address1=0x1000, name1="parse_packet", similarity=0.79, confidence=0.9, algorithm=7),
        ])
        r = _judge_with_db(db, "parse_packet")
        assert r.verified
        assert r.consensus >= 0.4           # >= 2/5 families
        assert set(r.consensus_families) == {"cfg", "callseq", "signature"}
        assert "consensus=3/5" in r.detail


# -------------------------------------------------------- coincidental match rejected

def test_consensus_blocks_coincidental_single_family_match():
    """Strong topology row but callseq/signature/data disagree -> reject."""
    with tempfile.TemporaryDirectory() as td:
        db = _write_db(Path(td) / "x.BinDiff", [
            # strong MD-index row (classic gate passes: 0.9 sim * 0.9 weight = 0.81 >= 0.55)
            dict(address1=0x1000, name1="pe_load", similarity=0.90, confidence=0.9, algorithm=3),
            # but the call order and data flow do not match at all
            dict(address1=0x1000, name1="pe_load", similarity=0.30, confidence=0.9, algorithm=15),
            dict(address1=0x1000, name1="pe_load", similarity=0.20, confidence=0.9, algorithm=13),
        ])
        r = _judge_with_db(db, "pe_load")
        assert not r.verified
        assert "consensus" in r.detail.lower()
        assert r.consensus < 0.4


def test_name_only_match_never_passes():
    """Name-hash matches contribute no structural family -> reject even at sim=1.0."""
    with tempfile.TemporaryDirectory() as td:
        db = _write_db(Path(td) / "x.BinDiff", [
            dict(address1=0x1000, name1="encrypt", similarity=1.0, confidence=0.9, algorithm=1),
            dict(address1=0x1000, name1="encrypt", similarity=0.99, confidence=0.9, algorithm=2),
        ])
        r = _judge_with_db(db, "encrypt")
        assert not r.verified


# -------------------------------------------------------- identical flag short-circuit

def test_identical_flag_short_circuits_consensus():
    with tempfile.TemporaryDirectory() as td:
        db = _write_db(Path(td) / "x.BinDiff", [
            dict(address1=0x1000, name1="crc32", similarity=1.0, confidence=0.9,
                 algorithm=1, flags=1),  # name-hash family but flagged identical
        ])
        r = _judge_with_db(db, "crc32")
        assert r.verified  # explicit identical flag is decisive
