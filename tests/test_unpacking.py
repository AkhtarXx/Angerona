import hashlib
import json
import struct

import pytest
from pathlib import Path

from src.analysis.unpacking import (
    CapeReportAdapter,
    DumpArtifact,
    MemoryDumpReconstructor,
    RecursiveArtifactAnalyzer,
    ResolvedImport,
)
from src.execution.models import MemoryImage, MemoryRegion
from src.execution.loaders import load_binary_bytes


def _image(*regions: MemoryRegion, target_sha256: str = "d" * 64, entry_point: int = 0x1000) -> MemoryImage:
    return MemoryImage.create(
        provider="test",
        target_sha256=target_sha256,
        architecture="x86_64",
        pointer_size=8,
        regions=list(regions),
        load_base=0x1000,
        entry_point=entry_point,
    )


def _pe64() -> bytes:
    data = bytearray(0x402)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 2, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x400:0x402] = b"\x90\xc3"
    return bytes(data)


def test_flat_dump_preserves_addresses_and_provenance(tmp_path: Path) -> None:
    image = _image(
        MemoryRegion.from_bytes(name="one", address=0x1000, payload=b"AB", permissions="r-x"),
        MemoryRegion.from_bytes(name="two", address=0x1004, payload=b"CD", permissions="rw-"),
    )
    artifact = MemoryDumpReconstructor().dump_flat(image, tmp_path / "dump.bin")
    assert (tmp_path / "dump.bin").read_bytes() == b"AB\x00\x00CD"
    assert artifact.parent_sha256 == "d" * 64
    assert artifact.sha256 == hashlib.sha256(b"AB\x00\x00CD").hexdigest()


def test_cape_adapter_validates_hash_and_containment(tmp_path: Path) -> None:
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"child")
    report = {
        "target": {"sha256": "a" * 64},
        "CAPE": [
            {"path": "payload.bin", "sha256": hashlib.sha256(b"child").hexdigest()},
            {"path": "../escape.bin"},
        ],
    }
    result = CapeReportAdapter().ingest(report, tmp_path)
    assert result.status == "success"
    assert [artifact.path for artifact in result.artifacts] == [str(payload)]
    assert "outside report directory" in result.notes[0]


def test_recursive_analysis_is_cycle_safe_and_tracks_lineage(tmp_path: Path) -> None:
    root = tmp_path / "root.bin"
    child = tmp_path / "child.bin"
    root.write_bytes(b"root")
    child.write_bytes(b"child")

    def analyzer(path: Path, _parent):
        target = child if path == root else root
        data = target.read_bytes()
        return [DumpArtifact(
            str(target), hashlib.sha256(data).hexdigest(), len(data), "", "test", "test"
        )]

    records = RecursiveArtifactAnalyzer(analyzer).run([root], max_depth=4)
    assert [row["depth"] for row in records] == [0, 1]
    assert records[1]["parent_sha256"] == records[0]["sha256"]


def test_pe_rebuild_synthesizes_named_import_directory(tmp_path: Path) -> None:
    original = _pe64()
    target_hash = hashlib.sha256(original).hexdigest()
    image = _image(
        MemoryRegion.from_bytes(
            name=".text", address=0x140001000, payload=b"\x90\xc3", permissions="r-x"
        ),
        target_sha256=target_hash,
        entry_point=0x140001000,
    )
    destination = tmp_path / "rebuilt.exe"
    artifact = MemoryDumpReconstructor().rebuild_pe(
        original,
        image,
        destination,
        imports=[ResolvedImport("KERNEL32.dll", "ExitProcess", 0x140003000, 0x7FFF1234)],
    )
    rebuilt = destination.read_bytes()
    loaded = load_binary_bytes(rebuilt)
    assert any(segment.name == ".angimp" for segment in loaded.segments)
    pe_offset = struct.unpack_from("<I", rebuilt, 0x3C)[0]
    optional = pe_offset + 24
    import_rva, import_size = struct.unpack_from("<II", rebuilt, optional + 112 + 8)
    assert import_rva == 0x2000
    assert import_size == 40
    metadata = json.loads(Path(artifact.metadata_path).read_text())
    assert metadata["import_reconstruction"]["synthesized"] is True


def test_pe_rebuild_rejects_memory_from_another_target(tmp_path: Path) -> None:
    original = _pe64()
    image = _image(
        MemoryRegion.from_bytes(name=".text", address=0x140001000, payload=b"\x90\xc3"),
        entry_point=0x140001000,
    )
    with pytest.raises(ValueError, match="target hash"):
        MemoryDumpReconstructor().rebuild_pe(original, image, tmp_path / "wrong.exe")
