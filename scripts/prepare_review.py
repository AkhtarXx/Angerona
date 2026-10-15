"""Build a source-only review ZIP and scan its text without printing secret values.

Uses an explicit file policy rather than Git metadata or .gitignore. No files in
the working directory are deleted or modified. Only the requested ZIP is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    'README.md', 'CONTRIBUTING.md', 'REVIEW_GUIDE.md', 'SECURITY.md',
    'RESPONSIBLE_USE.md', 'LICENSE', 'pyproject.toml', '.gitignore', '.gitattributes', 'demo_flow.py',
}
BINARY_ASSETS = {
    'frontend/src/assets/logo.png', 'frontend/src/assets/logo-0.png',
    'frontend/src/assets/logo-1.png',
    *(f'frontend/public/fonts/geist-sans-{weight}.{suffix}'
      for weight in (400, 500) for suffix in ('woff', 'woff2')),
}
SOURCE_ROOTS = {'src', 'tests', 'scripts', 'docs', 'samples', 'benchmarks', '.github', '.githooks'}
EXCLUDED_PARTS = {
    '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv', '.git',
    '.codex', '.claude', '.cursor', '.idea', '.vscode', '.angerona',
    'dist', 'build', 'test-results', 'playwright-report', 'audit-output',
}
EXCLUDED_FILES = {
    'docs/codebase/GIT_HISTORY.md', 'docs/codebase/SYMBOL_REFERENCE.md',
    'src/scripts/watch_hermes_retry_gate.sh', 'samples/program_raw.json',
    'frontend/src/lib/recovered.ts',
}
TEXT_SUFFIXES = {
    '.py', '.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
    '.sh', '.c', '.cc', '.cpp', '.h', '.hpp', '.java', '.s', '.asm',
    '.ts', '.tsx', '.js', '.jsx', '.css', '.html', '.svg', '.xml', '.dockerfile',
}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'provider-token': re.compile(r'\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
    'aws-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'google-api-key': re.compile(r'\bAIza[A-Za-z0-9_-]{30,}\b'),
    'slack-token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'credential-url': re.compile(r'https?://[^\s/:@]+:[^\s/@]+@'),
    'credential-assignment': re.compile(
        r'''(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key)\s*["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']'''),
}
PLACEHOLDER = re.compile(r'(?i)(example|dummy|fake|test|placeholder|redacted|changeme|your[_ -]|\$\{|os\.environ|<|secret-name)')

def selected(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    name = rel.as_posix()
    if not path.resolve().is_relative_to(ROOT.resolve()):
        return False
    if path.is_symlink() or any(part in EXCLUDED_PARTS for part in rel.parts):
        return False
    if path.name.lower().startswith('.env') or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx', '.keystore', '.jks', '.token'}:
        return False
    if (path.suffix.lower() == '.env' or path.name.lower() in {
            'credentials.json', 'secrets.json', 'credentials.yaml', 'credentials.yml', 'secrets.yaml', 'secrets.yml',
            'auth.json', 'id_rsa', 'id_ed25519'}
            or path.name.lower().startswith(('credentials.', 'secrets.', 'service-account'))):
        return False
    if name in EXCLUDED_FILES or path.name.startswith('real_'):
        return False
    if name in BINARY_ASSETS:
        return True
    if len(rel.parts) == 1:
        return name in ROOT_FILES
    if rel.parts[0] == 'frontend':
        if rel.parts[1] not in {'src', 'e2e', 'public'} and len(rel.parts) > 2:
            return False
        if len(rel.parts) == 2 and path.name not in {
            'README.md', 'package.json', 'package-lock.json', 'index.html', '.gitignore',
            '.oxlintrc.json', 'playwright.config.ts', 'vite.config.ts',
            'tsconfig.json', 'tsconfig.app.json', 'tsconfig.node.json',
        }:
            return False
    elif rel.parts[0] not in SOURCE_ROOTS:
        return False
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {'.gitignore', 'pre-commit', 'Dockerfile'}

def findings(path: Path, payload: bytes | None = None) -> list[dict]:
    try:
        content = (path.read_bytes() if payload is None else payload).decode('utf-8-sig')
    except (UnicodeError, OSError):
        return [{'path': path.relative_to(ROOT).as_posix(), 'rule': 'unreadable-text', 'line': 0}]
    result = []
    for rule, pattern in PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(1) if rule == 'credential-assignment' else match.group()
            if rule == 'credential-assignment' and PLACEHOLDER.search(value):
                continue
            result.append({'path': path.relative_to(ROOT).as_posix(), 'rule': rule,
                           'line': content.count('\n', 0, match.start()) + 1,
                           'sha256': hashlib.sha256(match.group().encode()).hexdigest()})
    return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Scan review inputs without writing a ZIP')
    parser.add_argument('--audit-local', action='store_true', help='Also scan excluded local text; never print values')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/angerona-review.zip')
    args = parser.parse_args()
    files, local_files = [], []
    for directory, dirs, names in os.walk(ROOT, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_PARTS
                         and not d.endswith('-venv') and not (Path(directory) / d).is_symlink()
                         and (Path(directory) / d).resolve().is_relative_to(ROOT.resolve())
                         and (args.audit_local or Path(directory) != ROOT
                              or d in SOURCE_ROOTS or d == 'frontend'))
        for name in sorted(names):
            path = Path(directory) / name
            if selected(path):
                files.append(path)
            elif args.audit_local and not path.is_symlink() and path.stat().st_size < 8 * 1024 * 1024 and (
                path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith('.env')
            ):
                local_files.append(path)
    # Freeze bytes once: the archive must contain precisely what was scanned.
    payloads = {path: path.read_bytes() for path in files}
    allowlist_path = ROOT / 'scripts/review_secret_allowlist.json'
    exceptions = json.loads(allowlist_path.read_text()) if allowlist_path.exists() else []
    allowed = {(item['path'], item['rule'], item['sha256']) for item in exceptions}
    matches = [item for path, data in payloads.items()
               if path.relative_to(ROOT).as_posix() not in BINARY_ASSETS
               for item in findings(path, data)]
    detected = [item for item in matches if (item['path'], item['rule'], item.get('sha256')) not in allowed]
    local = [item for path in local_files for item in findings(path)]
    report = {'selected_files': len(files), 'findings': detected,
              'reviewed_fixture_matches': len(matches) - len(detected),
              'excluded_local_findings': local,
              'scope': 'Allowlisted source and seven named website assets; no history, runtime state, target binaries or dependencies.'}
    if detected:
        print(json.dumps(report, indent=2))
        return 1
    if not args.check:
        output = args.output.resolve()
        if output.exists():
            parser.error('Output already exists; choose a new path to preserve the previous archive.')
        if output.suffix.lower() != '.zip':
            parser.error('Output must end in .zip')
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest = {'format': 1, 'files': {path.relative_to(ROOT).as_posix(): hashlib.sha256(data).hexdigest() for path, data in payloads.items()}}
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                info = zipfile.ZipInfo('angerona/' + path.relative_to(ROOT).as_posix())
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100755 if path.suffix == '.sh' or path.name == 'pre-commit' else 0o100644) << 16
                archive.writestr(info, payloads[path])
            archive.writestr('angerona/REVIEW_MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
        report['archive'] = str(output)
        report['archive_sha256'] = hashlib.sha256(output.read_bytes()).hexdigest()
    print(json.dumps(report, indent=2))
    return 0

if __name__ == '__main__':
    sys.exit(main())
