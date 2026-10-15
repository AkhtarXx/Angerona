"""Exercise actual Git index/history boundaries with synthetic token strings."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


def setup_repo(tmp_path, monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('git_hygiene_under_test', scripts / 'check_git_hygiene.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.policy, 'ROOT', tmp_path)
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'scripts/review_secret_allowlist.json').write_text('[]')
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True, capture_output=True)
    return module


def git(root, *args):
    subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)


def commit(root):
    git(root, '-c', 'user.name=Synthetic test', '-c', 'user.email=test@example.invalid',
        'commit', '-qm', 'Synthetic fixture')


def test_staged_blob_is_checked_even_when_worktree_is_clean(tmp_path, monkeypatch, capsys):
    module = setup_repo(tmp_path, monkeypatch)
    token = 'sk-proj-' + 'A' * 40
    path = tmp_path / 'README.md'
    path.write_text(token)
    git(tmp_path, 'add', 'README.md')
    path.write_text('safe working copy')
    monkeypatch.setattr(sys, 'argv', ['check_git_hygiene', '--staged'])
    assert module.main() == 1
    output = capsys.readouterr().out
    assert 'provider-token' in output and token not in output


def test_history_detects_token_removed_from_current_tree(tmp_path, monkeypatch, capsys):
    module = setup_repo(tmp_path, monkeypatch)
    path = tmp_path / 'README.md'
    token = 'sk-proj-' + 'A' * 40
    path.write_text(token)
    git(tmp_path, 'add', 'README.md')
    commit(tmp_path)
    path.write_text('safe current source')
    git(tmp_path, 'add', 'README.md')
    commit(tmp_path)
    monkeypatch.setattr(sys, 'argv', ['check_git_hygiene', '--staged'])
    assert module.main() == 0
    capsys.readouterr()
    monkeypatch.setattr(sys, 'argv', ['check_git_hygiene', '--history'])
    assert module.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output)['commits'] == 2
    assert token not in output


def test_tracked_but_ignored_source_is_rejected(tmp_path, monkeypatch, capsys):
    module = setup_repo(tmp_path, monkeypatch)
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/local.json').write_text('{}')
    (tmp_path / '.gitignore').write_text('src/local.json\n')
    git(tmp_path, 'add', '-f', 'src/local.json')
    monkeypatch.setattr(sys, 'argv', ['check_git_hygiene', '--staged'])
    assert module.main() == 1
    assert 'tracked-but-ignored' in capsys.readouterr().out
