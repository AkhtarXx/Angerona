from __future__ import annotations

import hashlib
import json
import struct
from types import SimpleNamespace

from src.analysis.dex_semantic import (
    inventory_dex_bytes,
    inventory_smali_tree,
    disassemble_dex,
    validate_dex_semantic_receipt,
)


def _matching_reassembly(root, inventory):
    semantic = inventory_smali_tree(root)["semantic_tree_sha256"]
    return {
        "status": "success", "inventory": inventory, "errors": [],
        "semantic_roundtrip_complete": True,
        "source_semantic_tree_sha256": semantic,
        "rebuilt_semantic_tree_sha256": semantic,
    }


def _one_class_one_method_dex() -> bytes:
    blob = bytearray(163)
    blob[:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, len(blob))
    struct.pack_into("<I", blob, 36, 0x70)
    struct.pack_into("<I", blob, 40, 0x12345678)
    struct.pack_into("<II", blob, 64, 1, 112)  # type_ids
    struct.pack_into("<II", blob, 88, 1, 116)  # method_ids
    struct.pack_into("<II", blob, 96, 1, 124)  # class_defs
    struct.pack_into("<I", blob, 112, 0)  # descriptor string index
    struct.pack_into("<HHI", blob, 116, 0, 0, 0)
    struct.pack_into("<8I", blob, 124, 0, 0, 0, 0, 0, 0, 156, 0)
    blob[156:163] = bytes([0, 0, 1, 0, 0, 1, 0])
    return bytes(blob)


def _one_class_one_code_method_dex() -> bytes:
    blob = bytearray(182)
    blob[:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, len(blob))
    struct.pack_into("<I", blob, 36, 0x70)
    struct.pack_into("<I", blob, 40, 0x12345678)
    struct.pack_into("<II", blob, 64, 1, 112)
    struct.pack_into("<II", blob, 88, 1, 116)
    struct.pack_into("<II", blob, 96, 1, 124)
    struct.pack_into("<I", blob, 112, 0)
    struct.pack_into("<HHI", blob, 116, 0, 0, 0)
    struct.pack_into("<8I", blob, 124, 0, 0, 0, 0, 0, 0, 156, 0)
    # one direct method, method_idx_diff=0, access=1, code_off=164
    blob[156:164] = bytes([0, 0, 1, 0, 0, 1, 0xA4, 0x01])
    struct.pack_into("<HHHHIIH", blob, 164, 1, 0, 0, 0, 0, 1, 0x000E)
    return bytes(blob)


def _one_class_four_code_unit_method_dex() -> bytes:
    blob = bytearray(_one_class_one_code_method_dex())
    blob.extend(b"\x00" * 6)
    struct.pack_into("<I", blob, 32, len(blob))
    struct.pack_into("<I", blob, 176, 4)
    struct.pack_into("<4H", blob, 180, 0x000E, 0x0000, 0x0000, 0x0000)
    return bytes(blob)


def test_dex_semantic_inventory_counts_declared_code_surface():
    result = inventory_dex_bytes(_one_class_one_method_dex())
    assert result.status == "parsed"
    assert result.class_defs == 1
    assert result.method_ids == 1
    assert result.defined_methods == 1
    assert result.code_methods == 0


def test_code_semantic_digest_rejects_same_size_opcode_substitution():
    original = bytearray(_one_class_one_code_method_dex())
    substituted = bytearray(original)
    struct.pack_into("<H", substituted, 180, 0x0027)  # throw v0, same one-unit size
    left = inventory_dex_bytes(bytes(original))
    right = inventory_dex_bytes(bytes(substituted))
    assert left.status == right.status == "parsed"
    assert left.code_shape_sha256 == right.code_shape_sha256
    assert left.code_semantic_sha256 != right.code_semantic_sha256


def test_smali_inventory_exposes_missing_method(tmp_path):
    smali = tmp_path / "Example.smali"
    smali.write_text(".class public LExample;\n.super Ljava/lang/Object;\n")
    observed = inventory_smali_tree(tmp_path)
    assert observed["classes"] == 1
    assert observed["methods"] == 0
    expected = inventory_dex_bytes(_one_class_one_method_dex())
    assert observed["methods"] != expected.defined_methods


def test_dex_semantic_inventory_rejects_table_out_of_bounds():
    blob = bytearray(_one_class_one_method_dex())
    struct.pack_into("<I", blob, 100, len(blob) - 1)
    result = inventory_dex_bytes(bytes(blob))
    assert result.status == "invalid"
    assert "class-defs-table-out-of-bounds" in result.errors


def test_dex_semantic_receipt_detects_smali_tree_mutation(tmp_path):
    output = tmp_path / "dex-output"
    output.mkdir()
    smali = output / "Example.smali"
    smali.write_text(
        ".class public LExample;\n.method public run()V\n.end method\n"
    )
    observed = inventory_smali_tree(output)
    input_sha = "a" * 64
    receipt_path = output / "ANGERONA_DEX_SEMANTIC_RECEIPT.json"
    receipt_path.write_text(json.dumps({
        "schema_version": 2,
        "status": "complete",
        "input_sha256": input_sha,
        "input_bytes": 123,
        "expected": {
            "class_defs": 1, "defined_methods": 1, "code_methods": 0,
            "code_units": 0, "code_shape_sha256": "shape",
            "code_semantic_sha256": "semantics",
        },
        "observed": observed,
        "apktool_status": "success",
        "bytecode_shape_complete": True,
        "reassembly": {
            "status": "success",
            "inventory": {
                "code_units": 0, "code_shape_sha256": "shape",
                "code_semantic_sha256": "semantics",
            },
            "semantic_roundtrip_complete": True,
            "source_semantic_tree_sha256": observed["semantic_tree_sha256"],
            "rebuilt_semantic_tree_sha256": observed["semantic_tree_sha256"],
        },
    }, sort_keys=True))
    receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    result = {
        "complete": True,
        "sha256": input_sha,
        "input_sha256": input_sha,
        "output": str(output),
        "smali_tree_sha256": observed["tree_sha256"],
        "receipt": str(receipt_path),
        "receipt_sha256": receipt_sha,
    }
    assert validate_dex_semantic_receipt(result) is True
    smali.write_text(smali.read_text() + "# tampered\n")
    assert validate_dex_semantic_receipt(result) is False


def test_dex_only_wrapper_manifest_absence_does_not_block_exact_smali(monkeypatch, tmp_path):
    source = tmp_path / "classes.dex"
    source.write_bytes(_one_class_one_method_dex())

    def fake_decode(_wrapper, *, keep_output, **_kwargs):
        output = keep_output / "smali"
        output.mkdir(parents=True)
        (output / "Example.smali").write_text(
            ".class public LExample;\n.method public run()V\n.end method\n"
        )
        return SimpleNamespace(
            status="partial",
            errors=["AndroidManifest.xml not produced by apktool"],
        )

    monkeypatch.setattr("src.analysis.apktool_bridge.decode_apk", fake_decode)
    expected = inventory_dex_bytes(source.read_bytes()).as_dict()
    monkeypatch.setattr(
        "src.analysis.dex_semantic._reassemble_smali_tree",
        lambda root, **_kwargs: _matching_reassembly(root, expected),
    )
    result = disassemble_dex(source, tmp_path / "output", timeout=30)
    assert result["complete"] is True
    assert result["dex_only_manifest_limitation"] is True


def test_code_bearing_dex_requires_nonempty_smali_method_body(monkeypatch, tmp_path):
    source = tmp_path / "classes.dex"
    source.write_bytes(_one_class_one_code_method_dex())

    def fake_decode(_wrapper, *, keep_output, **_kwargs):
        output = keep_output / "smali"
        output.mkdir(parents=True)
        (output / "Example.smali").write_text(
            ".class public LExample;\n.method public run()V\n.end method\n"
        )
        return SimpleNamespace(status="success", errors=[])

    monkeypatch.setattr("src.analysis.apktool_bridge.decode_apk", fake_decode)
    expected = inventory_dex_bytes(source.read_bytes()).as_dict()
    rebuilt = dict(expected)
    rebuilt["code_methods"] = 0
    rebuilt["code_units"] = 0
    rebuilt["code_shape_sha256"] = "different"
    monkeypatch.setattr(
        "src.analysis.dex_semantic._reassemble_smali_tree",
        lambda root, **_kwargs: _matching_reassembly(root, rebuilt),
    )
    result = disassemble_dex(source, tmp_path / "output", timeout=30)
    assert result["expected"]["code_methods"] == 1
    assert result["observed"]["code_methods"] == 0
    assert result["complete"] is False


def test_reassembly_shape_rejects_one_instruction_for_four_code_units(monkeypatch, tmp_path):
    source = tmp_path / "classes.dex"
    source.write_bytes(_one_class_four_code_unit_method_dex())

    def fake_decode(_wrapper, *, keep_output, **_kwargs):
        output = keep_output / "smali"
        output.mkdir(parents=True)
        (output / "Example.smali").write_text(
            ".class public LExample;\n.method public run()V\n"
            "    return-void\n.end method\n"
        )
        return SimpleNamespace(status="success", errors=[])

    original = inventory_dex_bytes(source.read_bytes()).as_dict()
    rebuilt = dict(original)
    rebuilt["code_units"] = 1
    rebuilt["code_shape_sha256"] = "different"
    monkeypatch.setattr("src.analysis.apktool_bridge.decode_apk", fake_decode)
    monkeypatch.setattr(
        "src.analysis.dex_semantic._reassemble_smali_tree",
        lambda root, **_kwargs: _matching_reassembly(root, rebuilt),
    )
    result = disassemble_dex(source, tmp_path / "output", timeout=30)
    assert result["expected"]["code_units"] == 4
    assert result["observed"]["instructions"] == 1
    assert result["bytecode_shape_complete"] is False
    assert result["complete"] is False
