"""Privacy boundaries of the source-review exporter; no real credentials."""
import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest


def exporter(monkeypatch, tmp_path):
    script = Path(__file__).resolve().parents[1] / 'scripts/prepare_review.py'
    spec = importlib.util.spec_from_file_location('prepare_review_under_test', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', tmp_path)
    return module


def write(root, name, content='safe content'):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.mark.parametrize('name', [
    '.env', 'src/.env.production', 'src/operator.key', 'src/credentials.json',
    'src/service-account-local.json', 'workspaces/run/report.json',
    'verification/run/log.md', 'review/notes.md', 'research/private.md',
    'tests/real_acceptance.py', 'src/__pycache__/cache.py',
    'frontend/node_modules/package/index.js', 'frontend/dist/index.html',
    'samples/private-target.elf', 'MEMORY.md',
])
def test_private_or_generated_files_are_excluded(monkeypatch, tmp_path, name):
    module = exporter(monkeypatch, tmp_path)
    assert not module.selected(write(tmp_path, name))


@pytest.mark.parametrize('prefix', ['sk-proj-', 'sk-proj-test'])
def test_detected_token_blocks_archive_without_printing_value(monkeypatch, tmp_path, capsys, prefix):
    module = exporter(monkeypatch, tmp_path)
    token = prefix + 'A' * 40
    write(tmp_path, 'README.md', token)
    output = tmp_path / 'dist/review.zip'
    monkeypatch.setattr(sys, 'argv', ['prepare_review', '--output', str(output)])
    assert module.main() == 1
    report = capsys.readouterr().out
    assert 'provider-token' in report and token not in report
    assert not output.exists()


def test_exact_fixture_exception_does_not_allow_changed_token(monkeypatch, tmp_path, capsys):
    module = exporter(monkeypatch, tmp_path)
    token = 'sk-proj-' + 'A' * 40
    path = write(tmp_path, 'tests/test_fixture.py', token)
    write(tmp_path, 'scripts/review_secret_allowlist.json', json.dumps([{
        'path': 'tests/test_fixture.py', 'rule': 'provider-token',
        'sha256': hashlib.sha256(token.encode()).hexdigest(), 'reason': 'Synthetic fixture',
    }]))
    monkeypatch.setattr(sys, 'argv', ['prepare_review', '--check'])
    assert module.main() == 0
    path.write_text('sk-proj-' + 'B' * 40)
    assert module.main() == 1
    assert token not in capsys.readouterr().out


def test_archive_uses_scanned_snapshot_and_verified_hashes(monkeypatch, tmp_path):
    module = exporter(monkeypatch, tmp_path)
    readme = write(tmp_path, 'README.md', 'safe source')
    write(tmp_path, 'workspaces/private.json', 'private data')
    original = module.findings

    def mutate_after_snapshot(path, payload=None):
        result = original(path, payload)
        readme.write_text('sk-proj-' + 'A' * 40)
        return result

    monkeypatch.setattr(module, 'findings', mutate_after_snapshot)
    output = tmp_path / 'review.zip'
    monkeypatch.setattr(sys, 'argv', ['prepare_review', '--output', str(output)])
    assert module.main() == 0
    with zipfile.ZipFile(output) as archive:
        assert archive.read('angerona/README.md') == b'safe source'
        assert not any('workspaces/' in name for name in archive.namelist())
        manifest = json.loads(archive.read('angerona/REVIEW_MANIFEST.json'))
        for relative, expected in manifest['files'].items():
            assert hashlib.sha256(archive.read('angerona/' + relative)).hexdigest() == expected


def test_symlink_is_not_exported(monkeypatch, tmp_path):
    module = exporter(monkeypatch, tmp_path)
    target = write(tmp_path, 'private.md', 'private data')
    link = tmp_path / 'README.md'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('symlink creation is unavailable on this host')
    assert not module.selected(link)
