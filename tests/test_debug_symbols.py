from pathlib import Path

import pytest

from src.analysis.debug_symbols import (
    DebugMetadata,
    DebugMetadataMerger,
    DebugSymbol,
    DsymProvider,
    PdbTextAdapter,
    SignatureMetadataAdapter,
    elf_build_id,
)


def test_pdb_adapter_and_signature_merge_preserve_strong_name() -> None:
    target = "e" * 64
    pdb = PdbTextAdapter().ingest("00001000 RealFunction\n", target_sha256=target, image_base=0x140000000)
    signature = SignatureMetadataAdapter().ingest({"symbols": [{
        "name": "probable_function", "address": "0x140001000", "confidence": 0.99,
    }]}, target_sha256=target)
    merged = DebugMetadataMerger().merge([signature, pdb])
    assert merged.symbols[0].name == "RealFunction"
    assert merged.properties["conflicts"][0]["candidates"] == ["RealFunction", "probable_function"]


def test_pdb_adapter_parses_llvm_pdbutil_public_records() -> None:
    payload = """
      32 | S_PUB32 [size = 32] `mainCRTStartup`
           flags = function, addr = 0001:0032
       0 | S_PUB32 [size = 32] `angerona_pdb_add`
           flags = function, addr = 0001:0000
   368 | S_SECTION [size = 28] `.text`
         length = 57, alignment = 12, rva = 4096, section # = 1
    """
    metadata = PdbTextAdapter().ingest(payload, target_sha256="a" * 64, image_base=0x140000000)
    symbols = {symbol.name: symbol.address for symbol in metadata.symbols}
    assert symbols == {
        "mainCRTStartup": 0x140001032,
        "angerona_pdb_add": 0x140001000,
    }


def test_metadata_merge_refuses_cross_target_contamination() -> None:
    with pytest.raises(ValueError, match="different targets"):
        DebugMetadataMerger().merge([
            DebugMetadata("a" * 64, "dwarf"),
            DebugMetadata("b" * 64, "pdb"),
        ])


def test_dsym_payload_selection_is_unambiguous(tmp_path: Path) -> None:
    dwarf = tmp_path / "Sample.dSYM" / "Contents" / "Resources" / "DWARF"
    dwarf.mkdir(parents=True)
    payload = dwarf / "Sample"
    payload.write_bytes(b"mach-o")
    assert DsymProvider().locate(tmp_path / "Sample.dSYM") == payload


def test_debug_symbol_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        DebugSymbol("bad", 0, confidence=2.0)


def test_elf_build_id_parser_reads_gnu_note() -> None:
    import struct
    build_id = bytes.fromhex("1234567890abcdef")
    payload = bytearray(0x100)
    payload[:4] = b"\x7fELF"
    payload[4:6] = b"\x02\x01"
    struct.pack_into("<Q", payload, 32, 64)
    struct.pack_into("<HH", payload, 54, 56, 1)
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    struct.pack_into("<IIQQQQQQ", payload, 64, 4, 0, 0xC0, 0, 0, len(note), len(note), 4)
    payload[0xC0:0xC0 + len(note)] = note
    assert elf_build_id(bytes(payload)) == build_id.hex()
