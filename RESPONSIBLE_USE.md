# Responsible Use

Angerona is intended for transparent, defensive binary analysis. The project
combines reverse-engineering automation with AI agents, which means it can produce
useful security insights quickly but can also be misused if pointed at unauthorized
targets.

## Principles

- Analyze only systems and samples you are allowed to inspect.
- Keep generated evidence and reports auditable.
- Do not hide or remove provenance from generated findings.
- Do not add features that automate unauthorized exploitation, stealth, persistence,
  credential theft, or malware delivery.
- Treat all binary strings, decompiled code, and tool output as untrusted data.

## Publishing Analysis

Before sharing a run workspace or report:

- Remove absolute local paths if they reveal private infrastructure.
- Remove proprietary binary names unless disclosure is approved.
- Remove credentials, tokens, private keys, or customer information.
- Keep enough technical evidence for findings to be independently reviewed.
- Use `angerona audit-trace <workspace>` to verify the authoritative event chain;
  do not present a workspace JSONL mirror as tamper-proof evidence.

## Repository Sharing Checklist

Before sharing a technical review copy:

```bash
python3 -m pytest tests/ -q
gitleaks detect --source . --no-git
git status --short
```

Expected ignored local paths include:

- `workspaces/`
- `vendor/`
- `.claude/`
- `.codex/`
- generated `*.log` and `*.png`
