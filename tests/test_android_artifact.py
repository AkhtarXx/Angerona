from __future__ import annotations

import zipfile

from src.analysis.android_artifact import validate_apk


def _elf_shared_object(machine: int, *, bits: int = 64) -> bytes:
    size = 64 if bits == 64 else 52
    header = bytearray(size)
    header[:4] = b"\x7fELF"
    header[4] = 2 if bits == 64 else 1
    header[5] = 1
    header[6] = 1
    header[16:18] = (3).to_bytes(2, "little")  # ET_DYN
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def test_native_only_apk_accepts_abi_matching_shared_object(tmp_path):
    apk = tmp_path / "native.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='com.example.native'/>")
        archive.writestr(
            "lib/arm64-v8a/libnative.so", _elf_shared_object(183)
        )

    result = validate_apk(apk)

    assert result.status == "valid"
    assert result.dex_entries == []
    assert result.native_entries == ["lib/arm64-v8a/libnative.so"]


def test_native_only_apk_rejects_abi_machine_mismatch(tmp_path):
    apk = tmp_path / "mismatch.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='com.example.native'/>")
        archive.writestr(
            "lib/arm64-v8a/libnative.so", _elf_shared_object(62)
        )

    result = validate_apk(apk)

    assert result.status == "invalid"
    assert "neither classes*.dex nor a valid ABI-matching" in result.note


def test_resource_only_apk_is_explicitly_invalid(tmp_path):
    apk = tmp_path / "resources.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='com.example.resources'/>")
        archive.writestr("res/raw/data.txt", b"data")

    result = validate_apk(apk)

    assert result.status == "invalid"
    assert result.dex_entries == []
    assert result.native_entries == []
    assert "neither classes*.dex nor a valid ABI-matching" in result.note
