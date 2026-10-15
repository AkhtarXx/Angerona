from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import zipfile
import zlib
from types import SimpleNamespace

import pytest

from src.analysis.android_binary_inventory import (
    _elf_nonexec_data_profile,
    _validated_precomputed_ida,
    _write_disassembly,
    _write_ida_evidence,
    analyze_native_static_evidence,
    detect_android_binary_format,
    materialize_binary_evidence,
    scan_apk_binary_members,
)
from src.execution.runtime_dex_extractor import _validate_dex


def _valid_dex(payload_size: int = 112) -> bytes:
    blob = bytearray(max(112, payload_size))
    blob[:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, len(blob))
    struct.pack_into("<I", blob, 36, 0x70)
    struct.pack_into("<I", blob, 40, 0x12345678)
    blob[12:32] = hashlib.sha1(blob[32:]).digest()
    struct.pack_into("<I", blob, 8, zlib.adler32(blob[12:]) & 0xFFFFFFFF)
    return bytes(blob)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(*chunks: tuple[bytes, bytes]) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"".join(
        _png_chunk(kind, payload) for kind, payload in chunks
    )


def test_magic_first_inventory_exports_disguised_code(tmp_path):
    apk = tmp_path / "target.apk"
    disguised_dex = _valid_dex()
    disguised_elf = b"\x7fELF" + b"\x00" * 128
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='com.test'/>")
        archive.writestr("assets/no_extension", disguised_dex)
        archive.writestr("assets/photo.dat", disguised_elf)

    result = scan_apk_binary_members(apk, export_dir=tmp_path / "exports")

    by_name = {item["member"]: item for item in result["members"]}
    assert by_name["assets/no_extension"]["format"] == "dex"
    assert by_name["assets/photo.dat"]["format"] == "elf"
    assert all(by_name[name]["exported_path"] for name in by_name if name.startswith("assets/"))
    assert len(result["exported_code_files"]) == 1


def test_low_entropy_opaque_asset_stays_unresolved(tmp_path):
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/vm.bytecode", b"\x01\x02\x03\x04" * 1024)

    result = scan_apk_binary_members(apk)

    item = result["members"][0]
    assert item["format"] == "opaque_binary"
    assert item["review_required"] is True
    assert result["unresolved_opaque_members"] == ["assets/vm.bytecode"]


def test_format_detector_uses_bytes_not_suffix():
    assert detect_android_binary_format("image.png", _valid_dex()) == "dex"
    assert detect_android_binary_format("payload.dex", b"SQLite format 3\x00") == "sqlite"


def test_conventional_profile_path_cannot_exempt_executable_bytes(tmp_path):
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/dexopt/baseline.prof", _valid_dex())

    result = scan_apk_binary_members(apk)

    item = result["members"][0]
    assert item["format"] == "dex"
    assert item["review_required"] is True
    assert item["review_reason"] == "embedded-dex"


def test_standard_png_is_fully_accounted_without_becoming_an_opaque_blocker(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr),
        (b"IDAT", zlib.compress(b"\x00\x00\x00\x00")),
        (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)

    result = scan_apk_binary_members(apk)

    item = result["members"][0]
    assert item["format"] == "png"
    assert item["payload_profile"]["structurally_complete"] is True
    assert item["payload_profile"]["bytes_accounted"] == len(image)
    assert item["review_required"] is False
    assert result["unresolved_opaque_members"] == []


def test_custom_high_entropy_png_chunk_is_unresolved_and_exported(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr),
        (b"vpAg", bytes(range(256)) * 4),
        (b"IDAT", zlib.compress(b"\x00\x00\x00\x00")),
        (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)

    result = scan_apk_binary_members(apk, export_dir=tmp_path / "exports")

    item = result["members"][0]
    assert item["payload_profile"]["suspicious"] is True
    assert "custom-png-chunk" in item["payload_profile"]["reasons"]
    assert item["review_required"] is True
    assert item["exported_path"]
    assert result["unresolved_opaque_members"] == ["assets/logo.png"]

    evidence = materialize_binary_evidence(tmp_path / "exports")
    assert evidence["files"][0]["analysis_complete"] is False
    assert "media-container" in evidence["files"][0]["limitation"]


def test_png_idat_rejects_hidden_bytes_after_valid_zlib_stream(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    valid_scanline = zlib.compress(b"\x00\x00\x00\x00\xff")
    hidden = bytes(range(256)) * 256
    image = _png(
        (b"IHDR", ihdr), (b"IDAT", valid_scanline + hidden), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert profile["suspicious"] is True
    assert "png-idat-hidden-or-unconsumed-payload" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_png_idat_rejects_invalid_scanline_filter(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr), (b"IDAT", zlib.compress(b"\x05\x00\x00\x00\xff")),
        (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert profile["suspicious"] is True
    assert "png-invalid-scanline-filter" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_png_rejects_payload_inside_iend_even_with_valid_crc(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr), (b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")),
        (b"IEND", bytes(range(256)) * 16),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert profile["suspicious"] is True
    assert "png-iend-size-order-or-cardinality" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_png_rejects_small_unknown_critical_chunk(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr), (b"ABCD", b"x"),
        (b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    assert "unknown-critical-png-chunk" in (
        result["members"][0]["payload_profile"]["reasons"]
    )
    assert result["members"][0]["review_required"] is True


def test_png_rejects_split_subthreshold_unknown_ancillary_chunks(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    chunks = [(b"vpAg", b"x" * 63) for _ in range(100)]
    image = _png(
        (b"IHDR", ihdr), *chunks,
        (b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert len(profile["custom_chunks"]) == 100
    assert "custom-png-chunk" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_png_rejects_split_known_text_metadata_payload(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    chunks = [(b"tEXt", b"Comment\0" + bytes(range(255)) * 16) for _ in range(20)]
    image = _png(
        (b"IHDR", ihdr), *chunks,
        (b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/logo.png", image)
    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert "png-ancillary-semantics-not-validated" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_structurally_valid_android_ninepatch_chunks_are_accounted(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 10, 10, 8, 6, 0, 0, 0)
    patch = bytearray(84)
    patch[:4] = bytes([0, 2, 2, 9])
    struct.pack_into("<II", patch, 4, 32, 40)
    struct.pack_into(">4i", patch, 12, 0, 0, 0, 0)
    struct.pack_into("<I", patch, 28, 48)
    struct.pack_into(">2i", patch, 32, 1, 9)
    struct.pack_into(">2i", patch, 40, 1, 9)
    struct.pack_into(">9I", patch, 48, *([1] * 9))
    outline = struct.pack("<4ifI", 0, 0, 0, 0, 0.0, 255)
    bounds = struct.pack("<4i", 1, 1, 1, 1)
    image = _png(
        (b"IHDR", ihdr), (b"npOl", outline), (b"npLb", bounds),
        (b"npTc", bytes(patch)), (b"IDAT", zlib.compress(b"\0" * 410)),
        (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("res/drawable/button.9.png", image)

    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert profile["structurally_complete"] is True
    assert profile["suspicious"] is False
    assert profile["custom_chunks"] == []
    assert result["members"][0]["review_required"] is False


def test_malformed_android_ninepatch_chunk_remains_unresolved(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 10, 10, 8, 6, 0, 0, 0)
    image = _png(
        (b"IHDR", ihdr), (b"npTc", b"malformed"),
        (b"IDAT", zlib.compress(b"\0" * 410)), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("res/drawable/button.9.png", image)

    result = scan_apk_binary_members(apk)
    profile = result["members"][0]["payload_profile"]
    assert profile["suspicious"] is True
    assert "invalid-android-ninepatch-chunk" in profile["reasons"]
    assert result["members"][0]["review_required"] is True


def test_real_aapt_mixed_endian_ninepatch_structure_is_accounted(tmp_path):
    apk = tmp_path / "target.apk"
    ihdr = struct.pack(">IIBBBBB", 16, 16, 8, 6, 0, 0, 0)
    patch = bytearray(116)
    patch[:4] = bytes([0, 4, 2, 15])
    struct.pack_into("<II", patch, 4, 32, 48)
    struct.pack_into(">4i", patch, 12, 0, 0, 0, 0)
    struct.pack_into("<I", patch, 28, 56)
    struct.pack_into(">4i", patch, 32, 4, 5, 11, 12)
    struct.pack_into(">2i", patch, 48, 7, 8)
    struct.pack_into(">15I", patch, 56, *([1] * 15))
    image = _png(
        (b"IHDR", ihdr), (b"npTc", bytes(patch)),
        (b"IDAT", zlib.compress(b"\0" * (16 * 16 * 4 + 16))), (b"IEND", b""),
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("res/drawable/compiled.9.png", image)
    result = scan_apk_binary_members(apk)
    assert result["members"][0]["payload_profile"]["suspicious"] is False
    assert result["members"][0]["review_required"] is False


def test_jpeg_payload_cannot_hide_by_adding_a_second_eoi_marker(tmp_path):
    apk = tmp_path / "target.apk"
    image = b"\xff\xd8\xff\xe0minimal\xff\xd9" + b"hidden-vm-bytecode" + b"\xff\xd9"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/photo.jpg", image)

    result = scan_apk_binary_members(apk)

    item = result["members"][0]
    assert item["format"] == "jpeg"
    assert item["payload_profile"]["suspicious"] is True
    assert "jpeg-trailing-payload" in item["payload_profile"]["reasons"]
    assert result["unresolved_opaque_members"] == ["assets/photo.jpg"]


def test_polyglot_and_unknown_bytecode_require_resolution(tmp_path):
    apk = tmp_path / "target.apk"
    png = b"\x89PNG\r\n\x1a\n" + b"image" * 20 + _valid_dex()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("res/drawable/logo.png", png)
        archive.writestr("payload.bc", b"\x01\x02\x03\x04" * 1024)
        archive.writestr("assets/config", b"endpoint=https://example.invalid\n")
    result = scan_apk_binary_members(apk)
    by_name = {item["member"]: item for item in result["members"]}
    assert by_name["res/drawable/logo.png"]["review_required"] is True
    assert by_name["res/drawable/logo.png"]["embedded_payloads"]
    assert by_name["payload.bc"]["review_required"] is True
    assert by_name["assets/config"]["review_required"] is True
    assert set(result["unresolved_opaque_members"]) >= {
        "res/drawable/logo.png", "payload.bc"
    }


def test_objdump_cannot_override_incomplete_ida(tmp_path, monkeypatch, native_elf_bytes, route_native):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "renamed.bin").write_bytes(native_elf_bytes)
    routing = route_native(root)
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence",
        lambda *args, **kwargs: {"status": "success", "complete": False},
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_disassembly",
        lambda *args, **kwargs: {"status": "success", "complete": True},
    )
    result = materialize_binary_evidence(root, **routing.materialize_kwargs)
    native = result["files"][0]
    assert native["native_backend"] == "llvm-objdump-assembly-only"
    assert native["analysis_complete"] is False
    assert result["incomplete_required"] == ["renamed.bin"]


def test_complete_ida_skips_redundant_objdump(tmp_path, monkeypatch, native_elf_bytes, route_native, precompute_native):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "native.so").write_bytes(native_elf_bytes)
    routing = route_native(root)
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence",
        lambda *args, **kwargs: {"status": "success", "complete": True},
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.producer_contract_sha256",
        lambda self, **_kwargs: "producer-contract-test",
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("complete IDA evidence must skip objdump")

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_disassembly", unexpected,
    )
    precomputed = precompute_native(root, routing, tmp_path / "static")
    result = materialize_binary_evidence(root, precomputed_native_records=precomputed, **routing.materialize_kwargs)
    native = result["files"][0]
    assert native["analysis_complete"] is True
    assert all(not path.endswith("disassembly.txt") for path in native["required_evidence"])


def test_ai_materializer_reuses_hash_attested_deterministic_ida(tmp_path, monkeypatch, native_elf_bytes, route_native):
    root = tmp_path / "artifacts"
    root.mkdir()
    target = root / "native.so"
    target.write_bytes(native_elf_bytes)
    routing = route_native(root)
    from src.analysis.native_ownership_manifest import native_routing_context
    from src.analysis.evidence_signing import sign_document
    _, _, _, binding = native_routing_context(routing.static_kwargs['ownership_manifest'], routing.static_kwargs['native_universe'])
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    deterministic = tmp_path / "deterministic" / "ida_analysis.txt"
    deterministic.parent.mkdir()
    deterministic.write_text("trusted deterministic IDA evidence\n")
    deterministic_hash = hashlib.sha256(deterministic.read_bytes()).hexdigest()
    native_data = deterministic.parent / "native_nonexec_data.json"
    native_data.write_text('{"status":"complete","complete":true}\n')
    native_data_hash = hashlib.sha256(native_data.read_bytes()).hexdigest()
    receipt = deterministic.parent / "native_static_receipt.json"
    receipt.write_text(json.dumps(sign_document({
        "schema_version": 2,
        "status": "complete",
        "target_sha256": digest,
        "target_bytes": target.stat().st_size,
        "ida_semantic_complete": True,
        "ida_producer_contract_sha256": "producer-contract-test",
        "native_data_complete": True,
        "native_routing": binding,
        "evidence_sha256": {
            str(deterministic): deterministic_hash,
            str(native_data): native_data_hash,
        },
    }), sort_keys=True))
    receipt_hash = hashlib.sha256(receipt.read_bytes()).hexdigest()
    precomputed = [{
        "path": str(target),
        "sha256": digest,
        "bytes": target.stat().st_size,
        "complete": True,
        "native_routing": binding,
        "ida": {
            "status": "success", "complete": True,
            "target_sha256": digest,
            "target_bytes": target.stat().st_size,
            "producer_contract_sha256": "producer-contract-test",
        },
        "native_data": {"status": "complete", "complete": True},
        "required_evidence": [str(deterministic), str(native_data), str(receipt)],
        "evidence_sha256": {
            str(deterministic): deterministic_hash,
            str(native_data): native_data_hash,
            str(receipt): receipt_hash,
        },
        "receipt": str(receipt),
    }]
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.producer_contract_sha256",
        lambda self, **_kwargs: "producer-contract-test",
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("hash-attested deterministic IDA must be reused")

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence", unexpected,
    )
    result = materialize_binary_evidence(
        root, precomputed_native_records=precomputed, **routing.materialize_kwargs,
    )

    native = result["files"][0]
    assert native["analysis_complete"] is True
    assert native["native_cache_hit"] is True
    copied = root / next(
        path for path in native["required_evidence"] if path.endswith("ida_analysis.txt")
    )
    assert copied.read_bytes() == deterministic.read_bytes()
    deterministic.write_text("tampered after receipt\n")
    assert _validated_precomputed_ida(
        precomputed[0], target_sha256=digest, target_bytes=target.stat().st_size
    ) is None


def test_deterministic_native_analysis_deduplicates_identical_hashes(tmp_path, monkeypatch, native_elf_bytes, route_native):
    target = tmp_path / "native.so"
    target.write_bytes(native_elf_bytes)
    routing = route_native(tmp_path)
    calls = []

    def fake_ida(_target, output, **_kwargs):
        calls.append(str(_target))
        output.write_text("IDA evidence\n")
        return {"status": "success", "complete": True}

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence", fake_ida,
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )
    result = analyze_native_static_evidence(
        [target, target], evidence_root=tmp_path / "evidence", **routing.static_kwargs,
    )

    assert len(calls) == 1
    assert result["complete"] is True
    assert len(result["records"]) == 1
    assert result["native_count"] == 1


def test_objdump_timeout_does_not_require_missing_artifact(tmp_path, monkeypatch, native_elf_bytes, route_native):
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "native.so").write_bytes(native_elf_bytes)
    routing = route_native(root)
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence",
        lambda *args, **kwargs: {"status": "failed", "complete": False},
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_disassembly",
        lambda *args, **kwargs: {
            "status": "TimeoutExpired", "complete": False,
            "bytes": 0, "published": False,
        },
    )
    result = materialize_binary_evidence(root, **routing.materialize_kwargs)
    native = result["files"][0]
    assert native["analysis_complete"] is False
    assert all(not path.endswith("disassembly.txt") for path in native["required_evidence"])


def test_objdump_streams_and_bounds_published_evidence(tmp_path, monkeypatch):
    target = tmp_path / "native.so"
    target.write_bytes(b"\x7fELF" + b"\x00" * 128)
    output = tmp_path / "disassembly.txt"

    def fake_run(_args, **kwargs):
        kwargs["stdout"].write(b"instruction\n")
        return SimpleNamespace(
            returncode=0,
            progress_bytes=len(b"instruction\n"),
            progress_items=1,
            progress_events=1,
            cpu_ticks=1,
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory.shutil.which",
        lambda _name: "/usr/bin/llvm-objdump",
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory.observed_progress_run", fake_run,
    )
    result = _write_disassembly(
        target, output, timeout=1, observation_workspace=None,
    )
    assert result["status"] == "success"
    assert result["published"] is True
    assert output.read_bytes() == b"instruction\n"
    assert not output.with_suffix(".txt.partial").exists()


def test_runtime_dex_validation_rejects_corruption(tmp_path):
    valid = tmp_path / "valid.dex"
    valid.write_bytes(_valid_dex())
    facts, reason = _validate_dex(valid)
    assert reason == ""
    assert facts["header_valid"] is True

    corrupt = tmp_path / "corrupt.dex"
    damaged = bytearray(_valid_dex())
    damaged[-1] ^= 0xFF
    corrupt.write_bytes(damaged)
    facts, reason = _validate_dex(corrupt)
    assert facts == {}
    assert reason in {"sha1-signature-mismatch", "adler32-checksum-mismatch"}


def test_ida_native_completion_rejects_any_unaccounted_executable_bytes(
    tmp_path, monkeypatch
):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        import pytest

        pytest.skip("C compiler unavailable")
    source = tmp_path / "native.c"
    target = tmp_path / "libnative.so"
    source.write_text("int exported(void) { return 7; }\n")
    subprocess.run(
        [compiler, "-shared", "-fPIC", str(source), "-o", str(target)],
        check=True,
    )
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.status", lambda self: {"ready": True}
    )
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.analyze",
        lambda self, *args, **kwargs: {
            "metadata": {
                "function_count": 1,
                "executable_coverage": {
                    "complete": False,
                    "executable_bytes": 100,
                    "accounted_bytes": 99,
                    "gap_bytes": 1,
                    "evidence_truncated": False,
                },
            },
            "functions": [{
                "name": "exported", "entry": "0x1000", "size": 4,
                "body_ranges": [{"start": "0x1000", "size": 4}],
                "decompiled": "int exported(void) { return 7; }",
                "is_external": False,
            }],
            "imports": [], "exports": [],
        },
    )
    result = _write_ida_evidence(target, tmp_path / "ida.txt", timeout=30)
    assert result["complete"] is False
    assert result["minimum_executable_ratio"] == 1.0


def test_native_nonexec_vm_section_blocks_static_completion(tmp_path, monkeypatch, route_native):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("C compiler unavailable")
    clean_source = tmp_path / "clean.c"
    clean_target = tmp_path / "libclean.so"
    clean_source.write_text("int exported(void) { return 7; }\n")
    vm_source = tmp_path / "vm.c"
    vm_target = tmp_path / "libvm.so"
    vm_source.write_text(
        '__attribute__((section(".angerona_vm"), used)) '
        "const unsigned char vm_payload[8192] = {1, 2, 3, 4};\n"
        "int dispatch(void) { return vm_payload[0]; }\n"
    )
    for source, target in ((clean_source, clean_target), (vm_source, vm_target)):
        subprocess.run(
            [compiler, "-shared", "-fPIC", str(source), "-o", str(target)],
            check=True,
        )

    clean_profile = _elf_nonexec_data_profile(clean_target.read_bytes())
    vm_profile = _elf_nonexec_data_profile(vm_target.read_bytes())
    assert clean_profile["complete"] is True
    assert vm_profile["complete"] is False
    assert ".angerona_vm" in vm_profile["suspicious_sections"]

    clean_apk = tmp_path / "clean.apk"
    vm_apk = tmp_path / "vm.apk"
    with zipfile.ZipFile(clean_apk, "w") as archive:
        archive.writestr("lib/x86_64/libclean.so", clean_target.read_bytes())
    with zipfile.ZipFile(vm_apk, "w") as archive:
        archive.writestr("lib/x86_64/libvm.so", vm_target.read_bytes())
    clean_inventory = scan_apk_binary_members(clean_apk)
    vm_inventory = scan_apk_binary_members(vm_apk)
    assert clean_inventory["native_members"] == ["lib/x86_64/libclean.so"]
    assert clean_inventory["native_structural_gate_complete"] is True
    assert vm_inventory["native_structural_gate_complete"] is False
    assert vm_inventory["unresolved_opaque_members"] == ["lib/x86_64/libvm.so"]

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence",
        lambda *args, **kwargs: {"status": "success", "complete": True},
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_disassembly",
        lambda *args, **kwargs: {"status": "success", "complete": True},
    )
    artifact_root = tmp_path / "materialized"
    artifact_root.mkdir()
    routed_target = artifact_root / "libvm.so"
    shutil.copy2(vm_target, routed_target)
    routing = route_native(artifact_root)
    result = analyze_native_static_evidence(
        [routed_target], evidence_root=tmp_path / "native-evidence", timeout=30, **routing.static_kwargs
    )
    assert result["native_count"] == 1
    assert result["complete"] is False
    assert result["records"][0]["ida"]["complete"] is True
    assert result["records"][0]["native_data"]["complete"] is False

    materialized = materialize_binary_evidence(artifact_root, **routing.materialize_kwargs)
    native = next(item for item in materialized["files"] if item["path"] == "libvm.so")
    assert native["analysis_complete"] is False
    assert native["native_data_profile"]["complete"] is False
    assert any(path.endswith("native_nonexec_data.json") for path in native["required_evidence"])
