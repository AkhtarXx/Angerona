# Git hygiene and sharing

Use Git to review and share the source. The local repository was initialized on
2026-10-15 because no repository metadata existed in this folder or its parents.
The personal-account repository was subsequently located and its reachable
history was prepared for privacy cleanup. Internal files and generated targets
are removed throughout that history; author/committer contact metadata uses a
generic project identity. See [history cleanup](HISTORY_CLEANUP.md) for scope.

```bash
git status --short --ignored
python scripts/check_git_hygiene.py --staged
python scripts/check_git_hygiene.py --history
bash scripts/install-git-hooks.sh
```

The default pre-commit guard scans the actual index. History mode scans all
reachable and reflog commits. Both reject files outside the public-source policy,
tracked files matched by ignore rules, symlinks/submodules and unresolved
credential patterns. Checks print locations and hashes, never credential values.

## Included

- Application source and normal pytest tests.
- Build configuration, source fixtures and benchmark source.
- Reviewer documentation and portable verification counts/skip reasons.
- Public website source and seven named logo/font assets, with the font license.
- `REVIEW_MANIFEST.json` containing per-file SHA-256 hashes.

## Excluded

- `.env` files, private-key/certificate containers and known credential filenames.
- Workspaces, databases, raw audit/verification output and model/provider logs.
- Git history, local assistant memory, internal research and review material.
- Host-specific `real_*.py` acceptance scripts and an internal operational watcher.
- Target binaries, decompiler databases, proprietary tools, generated builds,
  screenshots, dependency folders and virtual environments.
- Captured sample metadata with undocumented upstream provenance.

The source policy uses an explicit file selection, does not follow directory symlinks,
freezes file bytes before scanning, and archives that same snapshot. Known token
formats, private-key headers, credential URLs and literal credential assignments
block export. Exact hash-bound exceptions cover reviewed synthetic test
fixtures and a finding-label mapping; new values do not inherit those exceptions.
The exception list is visible in `scripts/review_secret_allowlist.json`.

## Git handling

`.gitignore` covers credentials, private state, verification/research material,
local plans and generated outputs. It does **not** hide files already tracked
and does not erase history. In a real Git checkout, inspect:

```bash
git status --short --ignored
git ls-files -- .env '*.pem' '*.key' 'workspaces/*' 'verification/*' 'review/*'
git check-ignore -v --no-index .env workspaces/example.json verification/example.log
```

If a sensitive file is already tracked, remove the specific file from the index
with `git rm --cached -- <path>` after reviewing the change. Keep the local copy
when it is still needed. If a real credential was previously exposed, revoke or
rotate it with its issuer; adding an ignore rule cannot make the old value safe.
Review history independently before publishing an existing repository.

The local commit uses a generic project identity to avoid recording a personal
email address. The remote repository history is included in the privacy rewrite. Other clones,
forks and GitHub cached objects require separate cleanup; never merge an old clone
back into the cleaned repository.
No credentials are added to examples; use environment variables or local config
outside the shareable source tree for real provider/signing values.

## Evidence policy

Raw local evidence is deliberately excluded because logs can reveal usernames,
absolute paths, target contents and private execution state. The portable record
in `docs/verification-results.json` preserves counts, skip reasons and hashes of
the local original evidence files. It is a summary, not a signed independent
attestation or a replacement for rerunning the supplied tests.

## Optional source export

`scripts/prepare_review.py` remains an optional source-only export utility. Git
is the primary review workflow. Creating an archive is not required to initialize,
commit or share the repository.
