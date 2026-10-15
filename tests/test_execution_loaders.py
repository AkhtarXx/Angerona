"""Safe executable mapping and address-normalization tests."""

from __future__ import annotations

import hashlib
import struct

import pytest

from src.execution.loaders import BinaryLoadError, load_binary_bytes


def _elf64(*, elf_type: int = 2) -> bytes:
    payload = b"\x90\xc3"
    header = bytearray(64)
    header[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        header,
        16,
        elf_type,
        62,
        1,
        0x401000,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0x1000,
        0x401000,
        0x401000,
        len(payload),
        0x100,
        0x1000,
    )
    return bytes(header) + program + b"\x00" * (0x1000 - 120) + payload


def _pe64() -> bytes:
    data = bytearray(0x402)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    section = optional + 0xF0
    data[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 2, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x400:0x402] = b"\x90\xc3"
    return bytes(data)


def test_load_elf_maps_pt_load_and_zero_fill() -> None:
    raw = _elf64()
    image = load_binary_bytes(raw)
    assert image.format == "elf"
    assert image.architecture == "x86_64"
    assert image.entry_point == 0x401000
    assert image.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert image.segments[0].permissions == "r-x"
    assert image.segments[0].materialized_bytes()[:2] == b"\x90\xc3"
    assert len(image.segments[0].materialized_bytes()) == 0x100


def test_load_position_independent_elf_rebases_runtime_and_static_addresses() -> None:
    image = load_binary_bytes(_elf64(elf_type=3), requested_base=0x700000)
    assert image.load_base == 0x700000
    assert image.entry_point == 0x700000
    assert image.static_address(image.entry_point) == 0x401000


def test_load_pe_maps_headers_and_executable_section() -> None:
    raw = _pe64()
    image = load_binary_bytes(raw)
    assert image.format == "pe"
    assert image.architecture == "x86_64"
    assert image.entry_point == 0x140001000
    text = next(segment for segment in image.segments if segment.name == ".text")
    assert text.runtime_address == 0x140001000
    assert text.permissions == "r-x"
    assert text.data == b"\x90\xc3"


def test_pe_refuses_unapplied_rebase() -> None:
    with pytest.raises(BinaryLoadError, match="relocation"):
        load_binary_bytes(_pe64(), requested_base=0x180000000)


def test_loader_rejects_truncated_segment_and_unknown_raw_input() -> None:
    truncated = _elf64()[:-1]
    with pytest.raises(BinaryLoadError, match="bounds"):
        load_binary_bytes(truncated)
    with pytest.raises(BinaryLoadError, match="raw architecture"):
        load_binary_bytes(b"\x90\xc3")


def test_raw_loader_requires_explicit_architecture() -> None:
    image = load_binary_bytes(
        b"\x90\xc3",
        requested_base=0x9000,
        raw_architecture="x86_64",
    )
    assert image.format == "raw"
    assert image.entry_point == 0x9000
    assert image.segments[0].data == b"\x90\xc3"
