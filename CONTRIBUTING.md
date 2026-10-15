# Contributing

Keep changes focused on binary analysis, evidence quality, portability and clear
failure semantics. Only use targets you are authorized to assess. Do not commit
credentials, proprietary tools, private target binaries or generated workspaces.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Install engine/runtime prerequisites for the features you work on. The
[verification guide](docs/VERIFICATION.md) records the qualification environment.
Windows extraction support does not imply parity with Linux sandbox features.
Create the virtual environment inside the checkout so required sandbox tests can
expose its interpreter without mounting an unrelated private home directory.

## Checks

```bash
gcc -O0 -g -fno-builtin -fno-stack-protector -no-pie samples/crackme.c -o samples/crackme
python -m pytest tests -q
python scripts/check_git_hygiene.py --staged
```

Start with focused tests, then run the relevant broader suite. Record missing
optional dependencies and skipped cases. For changes to the public website:

```bash
cd frontend
npm ci
npm run check
npm run test:e2e
```

Install the staged-source privacy guard with `bash scripts/install-git-hooks.sh`.
Internal catalog refresh is optional via `ANGERONA_REFRESH_CODEBASE_DOCS=1`; it
requires codebase-memory and ignored internal catalog inputs. The mechanical
catalog generator does not establish runtime verification.

## Change expectations

- Add meaningful regression coverage for changed failure or trust boundaries.
- Keep the README and affected architecture/interface docs aligned with the code.
- Preserve explicit unavailable, inconclusive and partial result states.
- Keep the local web default on loopback and provider isolation enabled.
- Explain what changed, how it was tested and any material remaining limitations.
- Use [the sharing workflow](docs/SHARING.md) to produce external review artifacts.

`.gitignore` only affects untracked files. If sensitive files were already tracked,
remove them from the index deliberately and review history before publication.
Never include actual credentials in test cases or bug reports.
