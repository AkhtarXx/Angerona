from __future__ import annotations

from src.analysis.native_elf import DT_INIT, PT_LOAD, parse_elf
from tests.fixtures_native import build_arm64_so


def test_rejects_non_elf():
    assert parse_elf(b"MZ\x90\x00") is None
    assert parse_elf(b"") is None


def test_parses_sections_segments_dynamic_symbols():
    blob = build_arm64_so(
        text=b"\xc0\x03\x5f\xd6",
        rodata=b"",
        dynamic_entries=[(DT_INIT, 0x1000)],
        dynstr_names=["JNI_OnLoad", "other"],
        dynsym=[("JNI_OnLoad", 0x1000, 4, False), ("other", 0, 0, True)],
    )
    elf = parse_elf(blob)
    assert elf is not None
    assert elf.is64 and elf.machine == 183
    names = [s.name for s in elf.sections]
    assert ".text" in names and ".dynamic" in names
    assert elf.dynamic.get(DT_INIT) == [0x1000]
    syms = {s.name: s for s in elf.symbols}
    assert syms["JNI_OnLoad"].imported is False
    assert syms["other"].imported is True


def test_vaddr_translation_and_read_ptr():
    blob = build_arm64_so(
        text=b"ABCD",
        rodata=b"RSTU",
        dynamic_entries=[],
        dynstr_names=[],
        dynsym=[],
    )
    elf = parse_elf(blob)
    assert elf is not None
    # vaddr 0x1000 -> file offset where .text lives
    off = elf.vaddr_to_offset(0x1000)
    assert off is not None
    assert blob[off : off + 4] == b"ABCD"
    assert elf.read_at(blob, 0x1000, 4) == b"ABCD"
    assert elf.read_at(blob, 0xDEAD0000, 4) is None


def test_c_string_at_reads_rodata():
    blob = build_arm64_so(
        text=b"\x00" * 64,
        rodata=b"hello_key\x00world\x00",
        dynamic_entries=[],
        dynstr_names=[],
        dynsym=[],
    )
    elf = parse_elf(blob)
    assert elf is not None
    # rodata is mapped at the base of the rw PT_LOAD = 0x3000 in our fixture
    s = elf.c_string_at(blob, 0x3000)
    assert s == "hello_key"
    assert elf.c_string_at(blob, 0x0) is None


def test_exec_ranges_and_in_exec():
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=b"", dynamic_entries=[], dynstr_names=[], dynsym=[])
    elf = parse_elf(blob)
    assert elf is not None
    assert any(a == 0x1000 for a, _ in elf.exec_ranges())
    assert elf.in_exec(0x1000)
    assert not elf.in_exec(0x700000)


def test_truncated_elf_returns_none_or_partial():
    blob = build_arm64_so(text=b"\x00", rodata=b"", dynamic_entries=[], dynstr_names=[], dynsym=[])
    short = blob[:30]
    assert parse_elf(short) is None
