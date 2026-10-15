from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from src.analysis.apk_content_manifest import (
    apk_content_manifest_sha256,
    build_apk_content_manifest,
)
from src.analysis.native_target_universe import build_native_target_universe


ELF_PAYLOAD = b"\x7fELF" + (b"\x00" * 124)


def _fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from nacl.signing import SigningKey

    key_path = tmp_path / "operator.seed"
    key_path.write_bytes(SigningKey.generate().encode())
    monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(key_path))

    apk_path = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("lib/arm64-v8a/libfixture.so", ELF_PAYLOAD)
        archive.writestr("assets/plain.txt", b"fixture")

    audit_root = tmp_path / "audit"
    targets_root = tmp_path / "targets"
    manifest = build_apk_content_manifest(apk_path, audit_root)
    target_path = targets_root / "lib/arm64-v8a/libfixture.so"
    target_path.parent.mkdir(parents=True)
    target_path.write_bytes(ELF_PAYLOAD)
    return apk_path, audit_root, targets_root, manifest


def _write_manifest(path: Path, manifest: dict) -> Path:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def test_canonical_v2_manifest_is_accepted_by_native_universe_consumer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    apk_path, audit_root, targets_root, manifest = _fixture(monkeypatch, tmp_path)

    assert manifest["manifest_sha256"] == apk_content_manifest_sha256(manifest)
    universe = build_native_target_universe(
        apk_manifest_path=audit_root / "APK_CONTENT_MANIFEST.json",
        apk_path=apk_path,
        targets_root=targets_root,
        audit_root=audit_root,
        output_path=audit_root / "NATIVE_TARGET_UNIVERSE.json",
    )

    assert universe["trust"] == "operator_signed"
    assert universe["native_entry_count"] == 1
    assert universe["target_count"] == 1


def test_native_universe_rejects_manifest_tamper_without_identity_update(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    apk_path, audit_root, targets_root, manifest = _fixture(monkeypatch, tmp_path)
    manifest["apk_bytes"] += 1
    tampered_path = _write_manifest(audit_root / "TAMPERED_MANIFEST.json", manifest)

    with pytest.raises(ValueError, match="payload hash mismatch"):
        build_native_target_universe(
            apk_manifest_path=tampered_path,
            apk_path=apk_path,
            targets_root=targets_root,
            audit_root=audit_root,
            output_path=audit_root / "REJECTED_UNIVERSE.json",
        )


def test_native_universe_rejects_rehashed_manifest_tamper_against_apk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    apk_path, audit_root, targets_root, manifest = _fixture(monkeypatch, tmp_path)
    manifest["apk_bytes"] += 1
    manifest["manifest_sha256"] = apk_content_manifest_sha256(manifest)
    tampered_path = _write_manifest(audit_root / "REHASHED_TAMPERED_MANIFEST.json", manifest)

    with pytest.raises(ValueError, match="size mismatch"):
        build_native_target_universe(
            apk_manifest_path=tampered_path,
            apk_path=apk_path,
            targets_root=targets_root,
            audit_root=audit_root,
            output_path=audit_root / "REJECTED_UNIVERSE.json",
        )
