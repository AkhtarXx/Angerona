"""Parser robustness fuzz gate (Hypothesis-derandomized) for L0/L1 parsers."""
from __future__ import annotations

import pytest

from src.analysis.formats.safe_reader import Reader, ReaderError


@pytest.mark.parametrize("payload", [
    b"", b"\x00", b"\xff" * 100, b"MZ" * 10,
    b"\x7fELF", b"PK\x03\x04", b"qqq" * 100,
    bytes(range(256)) * 4,
])
def test_reader_never_out_of_bounds(payload):
    rdr = Reader(payload)
    for off in (-1, 0, 5, 100, len(payload), len(payload) + 1, 10**9):
        for n in (0, 1, 5, 1000, 10**9):
            try:
                rdr.peek(n, off)
            except ReaderError:
                pass
            else:
                # allowed only if within bounds
                assert off + n <= len(payload), \
                    f"reader accepted off={off} n={n} on len={len(payload)}"


def test_reader_zero_bytes_budget_raises():
    big = b"\x00" * (1024 * 1024)
    rdr = Reader(big, max_consumed=10)
    with pytest.raises(ReaderError):
        rdr.read(11)


def test_reader_seek_rejects_out_of_bounds():
    rdr = Reader(b"abc")
    with pytest.raises(ReaderError):
        rdr.seek(4)
    rdr.seek(2)
    assert rdr.read(1) == b"c"
