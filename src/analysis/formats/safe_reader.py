"""Bounded, bounds-checked byte reader used by every parser at layer 0/1.

CVE-2019-8904 class: every file parser must refuse reads outside the buffer. All
detectors mutate state only after validating offsets/lengths. Integration with
Hypothesis ``@settings(derandomize=True)`` testing makes fuzz regressions
deterministic once found.
"""

from __future__ import annotations


class ReaderError(ValueError):
    """Parser error distinguishing malformed-input from application bugs."""


class Reader:
    def __init__(self, data: bytes, *, max_consumed: int = 256 * 1024 * 1024):
        self.data = bytes(data)
        self.pos = 0
        self.max_consumed = max_consumed

    def __len__(self) -> int:
        return len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def _check(self, off: int, n: int) -> None:
        if off < 0 or n < 0 or off + n > len(self.data):
            raise ReaderError(f"read out of bounds: off={off} n={n} len={len(self.data)}")

    def read(self, n: int, at: int | None = None) -> bytes:
        off = self.pos if at is None else at
        self._check(off, n)
        end = off + n
        if end > self.max_consumed:
            raise ReaderError("byte budget exceeded")
        if at is None:
            self.pos = end
        return self.data[off:end]

    def u8(self, at: int | None = None) -> int:
        return self.read(1, at)[0]

    def u32le(self, at: int | None = None) -> int:
        return int.from_bytes(self.read(4, at), "little")

    def u32be(self, at: int | None = None) -> int:
        return int.from_bytes(self.read(4, at), "big")

    def u64le(self, at: int | None = None) -> int:
        return int.from_bytes(self.read(8, at), "little")

    def peek(self, n: int, at: int) -> bytes:
        self._check(at, n)
        return self.data[at:at + n]

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > len(self.data):
            raise ReaderError(f"seek out of bounds: {pos}")
        self.pos = pos
