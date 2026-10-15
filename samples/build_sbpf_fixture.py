"""Build a deterministic minimal SBPF ELF for format/export contract tests.

This synthetic exit program is not a historical deployed Solana program.
"""
import argparse
import struct
from pathlib import Path


def build(path: Path, *, machine: int = 0x107, text: bytes | None = None) -> Path:
    text = text if text is not None else bytes.fromhex("b7000000000000009500000000000000")
    names = b"\0.text\0.shstrtab\0"
    strings_offset = 64 + len(text)
    sections_offset = (strings_offset + len(names) + 7) & ~7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3, machine, 1, 0x1000, 0, sections_offset, 0, 64, 0, 0, 64, 3, 2,
    )
    null = bytes(64)
    executable = struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x1000, 64, len(text), 0, 0, 8, 0)
    strings = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, strings_offset, len(names), 0, 0, 1, 0)
    payload = header + text + names
    path.write_bytes(payload + bytes(sections_offset - len(payload)) + null + executable + strings)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)
