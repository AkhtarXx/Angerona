from pathlib import Path
import hashlib
import json
import os
import zipfile
from types import SimpleNamespace
import pytest
from samples.build_sbpf_fixture import build


@pytest.fixture(scope="session", autouse=True)
def isolated_agent_control_state(tmp_path_factory):
    # Durable duplicate-dispatch state must survive production restarts, but
    # must not leak between independent test-suite invocations reusing /tmp.
    with pytest.MonkeyPatch.context() as patch:
        if not os.environ.get("ANGERONA_AGENT_CONTROL_STATE_DIR"):
            patch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path_factory.mktemp("agent-control")))
        yield


@pytest.fixture
def solana_elf(tmp_path: Path) -> Path:
    return build(tmp_path / "synthetic-sbpf.elf")


@pytest.fixture
def native_elf_bytes(tmp_path: Path) -> bytes:
    return build(tmp_path / "stub-x86.elf", machine=62, text=b"\x31\xc0\xc3").read_bytes()


@pytest.fixture
def route_native(tmp_path: Path, monkeypatch):
    """Issue real signed app-build routing for exact synthetic test inputs."""
    from nacl.signing import SigningKey
    from src.analysis.apk_content_manifest import build_apk_content_manifest
    from src.analysis.evidence_signing import sign_document
    from src.analysis.native_target_universe import build_native_target_universe
    from src.analysis.native_pre_re_classifier import (
        PROVENANCE_SCHEMA, build_reference_catalog, build_pre_re_classification,
    )
    from src.analysis.native_ownership_manifest import build_native_ownership_manifest

    def issue(root: Path):
        authority = tmp_path / "routing-authority"
        authority.mkdir()
        keys = []
        verify_paths = []
        for role in ("build", "operator"):
            key = authority / f"{role}.seed"
            signing = SigningKey.generate()
            key.write_bytes(signing.encode())
            keys.append(key)
            verify = key.with_suffix('.pub')
            verify.write_bytes(bytes(signing.verify_key))
            verify_paths.append(str(verify))
        monkeypatch.setenv("ANGERONA_VERIFY_KEY_PATHS", os.pathsep.join(verify_paths))
        targets = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.read_bytes().startswith(b"\x7fELF"):
                targets.append(path)
        apk = authority / "fixture.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            for index, target in enumerate(targets):
                archive.writestr(f"lib/x86_64/{index}.so", target.read_bytes())
        audit = authority / "audit"
        monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(keys[1]))
        build_apk_content_manifest(apk, audit)
        universe = audit / "NATIVE_TARGET_UNIVERSE.json"
        build_native_target_universe(apk_manifest_path=audit / "APK_CONTENT_MANIFEST.json",
                                    apk_path=apk, targets_root=root, audit_root=audit, output_path=universe)
        artifacts = [{'sha256': hashlib.sha256(t.read_bytes()).hexdigest(), 'bytes': t.stat().st_size}
                     for t in targets]
        monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(keys[0]))
        provenance = authority / "build-provenance.json"
        provenance.write_text(json.dumps(sign_document({
            'schema': PROVENANCE_SCHEMA, 'source_kind': 'app_build',
            'package_name': 'fixture', 'version': '1', 'publisher': 'test',
            'package_format': 'app-build-output', 'source_revision': 'synthetic-source-v1',
            'artifacts': artifacts,
        })))
        monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(keys[1]))
        catalog = authority / "catalog.json"
        unique = {}
        for target in targets:
            unique.setdefault(hashlib.sha256(target.read_bytes()).hexdigest(), target)
        build_reference_catalog(inputs=list(unique.values()), provenance_path=provenance, output_path=catalog)
        classification = authority / "classification.json"
        build_pre_re_classification(universe_path=universe, output_path=classification,
                                    cache_root=authority / "cache", catalog_paths=[catalog])
        reconstruction = authority / "reconstruction"
        reconstruction.mkdir()
        ownership = authority / "ownership.json"
        build_native_ownership_manifest(universe_path=universe, output_path=ownership,
                                        pre_re_classification_path=classification,
                                        reconstruction_root=reconstruction)
        common = {'ownership_manifest': ownership, 'native_universe': universe}
        return SimpleNamespace(static_kwargs={**common, 'lane_epoch_id': 'test-epoch'},
                               materialize_kwargs={**common, 'native_lane_epoch_id': 'test-epoch'})
    return issue


@pytest.fixture
def precompute_native(monkeypatch):
    """Exercise controller receipt creation around a test's stub engine."""
    from src.analysis import android_binary_inventory as inventory
    def produce(root, routing, evidence_root):
        writer = inventory._write_ida_evidence
        def pinned_writer(target, output, **kwargs):
            result = writer(target, output, **kwargs)
            if not output.exists():
                output.write_text('synthetic IDA evidence\n')
            return {**result, 'target_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                    'target_bytes': target.stat().st_size, 'producer_contract_sha256': 'producer-contract-test'}
        with monkeypatch.context() as patch:
            patch.setattr(inventory, '_write_ida_evidence', pinned_writer)
            paths = [p for p in root.rglob('*') if p.is_file() and p.read_bytes().startswith(b'\x7fELF')]
            return inventory.analyze_native_static_evidence(paths, evidence_root=evidence_root,
                                                           **routing.static_kwargs)['records']
    return produce
