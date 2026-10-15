#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit scripts/update_codebase_docs.py scripts/install-git-hooks.sh

printf 'Installed repository hooks via core.hooksPath=.githooks\n'
printf 'Staged-source privacy checks run before each commit.\n'
printf 'Internal catalog refresh is opt-in via ANGERONA_REFRESH_CODEBASE_DOCS=1.\n'
