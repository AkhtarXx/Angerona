"""Audit staged source or all reachable/reflog Git history without printing values."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import prepare_review as policy


def git(*args: str, input_bytes: bytes | None = None) -> bytes:
    process = subprocess.run(['git', '-C', str(policy.ROOT), *args], input=input_bytes, capture_output=True)
    if process.returncode:
        raise RuntimeError('Git command failed: ' + ' '.join(args[:2]))
    return process.stdout


def blobs(object_ids: set[str]) -> dict[str, bytes]:
    """Read object contents in one process; never print its output."""
    if not object_ids:
        return {}
    raw = git('cat-file', '--batch', input_bytes=('\n'.join(sorted(object_ids)) + '\n').encode())
    result = {}
    offset = 0
    while offset < len(raw):
        end = raw.index(b'\n', offset)
        oid, kind, size_text = raw[offset:end].decode().split()
        if kind != 'blob':
            raise RuntimeError('Expected a Git blob')
        size = int(size_text)
        result[oid] = raw[end + 1:end + 1 + size]
        offset = end + size + 2
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', action='store_true', help='Scan all reachable and reflog commits')
    parser.add_argument('--staged', action='store_true', help='Scan index blobs, including unchanged tracked files (default)')
    args = parser.parse_args()
    entries = []
    commits = []
    if args.history:
        commits = git('rev-list', '--all', '--reflog').decode().splitlines()
        for commit in commits:
            for record in git('ls-tree', '-r', '-z', commit).split(b'\0'):
                if record:
                    metadata, path = record.split(b'\t', 1)
                    mode, kind, oid = metadata.decode().split()
                    entries.append((mode, oid, path.decode('utf-8'), commit))
    else:
        for record in git('ls-files', '--stage', '-z').split(b'\0'):
            if record:
                metadata, path = record.split(b'\t', 1)
                mode, oid, stage = metadata.decode().split()
                if stage != '0':
                    raise RuntimeError('Resolve merge conflicts before auditing')
                entries.append((mode, oid, path.decode('utf-8'), 'index'))
    # Exceptions are scoped to exact paths, rule names and matched bytes.
    exceptions = json.loads((policy.ROOT / 'scripts/review_secret_allowlist.json').read_text())
    allowed = {(item['path'], item['rule'], item['sha256']) for item in exceptions}
    problems = []
    checked = set()
    fixture_matches = 0
    ignored_check = subprocess.run(
        ['git', '-C', str(policy.ROOT), 'check-ignore', '--no-index', '-z', '--stdin'],
        input=b''.join(relative.encode() + b'\0' for _, _, relative, _ in entries), capture_output=True,
    )
    if ignored_check.returncode not in (0, 1):
        raise RuntimeError('Ignore-policy check failed')
    ignored_paths = set(ignored_check.stdout.decode().split('\0'))
    payloads = blobs({oid for mode, oid, relative, _ in entries
                      if mode in {'100644', '100755'} and policy.selected(policy.ROOT / relative)
                      and relative not in policy.BINARY_ASSETS and relative not in ignored_paths})
    for mode, oid, relative, revision in entries:
        if (oid, relative) in checked:
            continue
        checked.add((oid, relative))
        path = policy.ROOT / relative
        if mode not in {'100644', '100755'} or not policy.selected(path):
            problems.append({'path': relative, 'revision': revision, 'rule': 'outside-public-source-policy'})
            continue
        if relative in ignored_paths:
            problems.append({'path': relative, 'revision': revision, 'rule': 'tracked-but-ignored'})
            continue
        if relative in policy.BINARY_ASSETS:
            continue
        for match in policy.findings(path, payloads[oid]):
            if (relative, match['rule'], match.get('sha256')) in allowed:
                fixture_matches += 1
            else:
                problems.append({**match, 'revision': revision})
    report = {'scope': 'reachable/reflog history' if args.history else 'Git index',
              'commits': len(commits), 'unique_file_versions': len(checked),
              'reviewed_synthetic_matches': fixture_matches, 'findings': problems}
    print(json.dumps(report, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
