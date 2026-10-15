# Security Policy

Angerona is a dual-use defensive security and reverse-engineering tool. Please
use it only on binaries you own, are authorized to assess, or are legally allowed
to research.

## Supported Use

- Malware triage in a controlled lab.
- Vulnerability research on authorized targets.
- Firmware or executable analysis for defensive review.
- Education and CTF-style exercises using permitted samples.

## Not Supported

- Unauthorized intrusion, persistence, credential theft, or evasion.
- Packaging exploit payloads or malware deployment workflows into this project.
- Uploading private customer, employer, or third-party binaries without permission.
- Exposing the web control plane directly to the public internet.

## Reporting Vulnerabilities

Do not open a public issue for an undisclosed vulnerability. Use GitHub's
**Security > Report a vulnerability** flow for this repository to open a private
advisory with the maintainers. Include:

- A concise impact summary.
- Affected commit/version.
- Steps to reproduce.
- Whether secrets, local files, or remote code execution are involved.

Do not include real credentials, proprietary samples, or unrelated personal data
in reports.

Angerona is currently a research beta. Security fixes target the latest commit on
`main`; older snapshots do not receive separate support releases.

## Operational Safety

- Keep the web UI bound to `127.0.0.1` unless you have your own authentication and
  network controls in front of it.
- Prefer SSH port forwarding for remote access.
- Use disposable VMs for real malware.
- Enable parser sandboxing for untrusted samples when available.
- Keep agent filesystem/network isolation enabled for K-candidate runs; requested
  security boundaries fail closed when the required host controls are unavailable.
- Treat `raw/observability/events.jsonl`, retry mirrors, and other model-writable
  workspace files as non-authoritative. Use `angerona audit-trace` to verify the
  external hash-chained event ledger.
- Review generated workspaces before sharing them.

## Sharing source for review

Use `python scripts/check_git_hygiene.py --staged` and `--history` as described
in [the Git sharing guide](docs/SHARING.md). Do not copy the entire
working directory: raw provider logs, workspaces, databases and target artifacts
may contain private material. Real keys belong in local environment/configuration
outside the shared source tree.

Git hygiene checks block recognized credential patterns and use exact hash-bound
exceptions for documented synthetic scanner/redaction fixtures. Index mode reads
staged blobs; history mode reads reachable/reflog commits. Neither guarantees
recognition of every secret format. `.gitignore` does not remove tracked content.
