# Publication readiness

Publication record on 2026-10-15: a fresh Git source baseline is published at
[AkhtarXx/Angerona](https://github.com/AkhtarXx/Angerona). The predecessor's history, hosting caches, workflow logs,
saved secrets and local audit backups are not migrated. Validation below is
bounded by the stated environment and integration coverage.

Passing tests and secret-pattern scans do not establish that a repository is
safe to publish. Review the source, Git history, hosting surfaces and credential
lifecycle separately. Private audit evidence stays under ignored `verification/`.

| Check | Evidence and result |
| --- | --- |
| Backend behavior | Fresh clone from the public URL, source `1b645fc`: 1,851 passed, 38 skipped, no failures. |
| Public CLI real-target checks | 23/23 pass on source `1b645fc`: system ELF/source fixture analysis, Ghidra, full-re/resume, CFG/stack frames, sandboxed static analysis, MCP, HTTP and Docker. |
| Real targets and edge cases | See [verification results](VERIFICATION.md); live providers, Android device execution, deployed Solana and strict cross-engine parity remain unqualified. |
| Frontend | Previously qualified lint/build and 22 browser tests; fresh lockfile audit reports zero known vulnerabilities. |
| Python dependencies | Audited qualification environment reports zero known vulnerabilities after updating its installer from pip 24.0 to 26.2.1. Optional dependencies not installed there are outside this audit. |
| Current source privacy | 616 selected source/assets pass the source policy; 16 exact synthetic fixture matches reviewed. |
| Predecessor history privacy | Pre-hardening private baseline: 104 commits, 1,318 unique file versions pass the history checker; 42 exact synthetic matches reviewed. This history is not migrated into the fresh public repository. |
| Independent secret scan | Gitleaks 8.30.1 reports three candidates: two synthetic test values and one ordinary code expression. No live credential identified in these candidates. |
| Workflow isolation | CI uses read-only contents permission, fixed action revisions and checkout without persisted credentials. Deployment is limited to main pushes/manual runs; secrets are scoped to deployment steps. |
| Workflow validation | Actionlint 1.7.12 passes. This is static validation, not a hosted execution result. |
| Hosted execution | Python 3.11 compatibility, Python 3.12 full integrations, frontend and wheel/package jobs all pass in [the public CI run](https://github.com/AkhtarXx/Angerona/actions/runs/38766903639). |
| GitHub security settings | Secret scanning, push protection and private vulnerability reporting enabled; zero saved Actions secrets or variables in the new repository. Website deployment skips until its project variable is configured. |

## Open follow-ups

1. Revoke any credential previously disclosed outside the repository. Source
   scanning cannot revoke a token or prove its revocation.
2. Keep the predecessor private. An authenticated lookup still resolved a
   removed historical commit there after its rewrite, and its historical logs
   contain home directory paths. The fresh repository does not carry over those
   cache and workflow surfaces. Changing the predecessor's visibility requires
   a separate review.
3. Establish the original source, revision and license for the subprocess pattern
   described as adapted in `src/agents/runtime.py`. Preserve any required notices
   before claiming comprehensive third-party license clearance. The
   bundled fonts retain their separate OFL notice.

GitHub states that making a private repository public also exposes its Actions
history and logs. See [visibility consequences](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
and [sensitive-data removal boundaries](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

Use [the Git sharing guide](SHARING.md) for staged/history checks. Keep source
publishing separate from website deployment, and never publish private audit
backups or real-target workspaces.
