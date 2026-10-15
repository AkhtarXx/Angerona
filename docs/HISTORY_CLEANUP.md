# History privacy cleanup

This record describes the private predecessor. The fresh public repository
starts from an audited source baseline and does not include that historical
commit graph, provider caches or workflow logs.

The 2026-10-15 cleanup removes private/local material throughout the repository's
reachable history and retains the current verified source. Useful engineering
history is preserved where possible; commits made empty by removal are pruned.

- 97 historical paths are removed, including app packages, generated executables,
  captured target metadata, internal research/memory, local acceptance scripts,
  generated symbol/history catalogs and workspace output.
- Commit author/committer contact metadata uses a generic project identity.
  Public license/copyright attribution remains intact.
- Host-specific paths are replaced with generic examples in historical text and
  the current source fixtures. Commit-message contact trailers are scrubbed.
- The ignore policy, staged-blob checker and pre-commit guard prevent accidental
  reintroduction. Exact documented synthetic scanner fixtures remain allowed.

Private backups and detailed rewrite maps are kept outside the tracked source.
Do not publish those backups: they intentionally retain the original material.
Repository/environment Actions secrets are independent of Git content and are
not deleted by this cleanup.

After a rewritten history is published, use a fresh clone or carefully transplant
clean changes. Merging old history can restore removed files. Other clones,
forks, provider caches, pull-request references and stored workflow logs are
outside a Git force-push's deletion authority. GitHub may require a separate
support purge for genuinely sensitive cached data. See
[GitHub's removal guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

The previous remote audit found no unresolved credential-pattern matches across
109 commits, 1,331 blob objects and 60 workflow log files. This cleanup additionally
removes private/generated material and contact metadata; neither pattern scanning
nor history rewriting proves that every possible secret format is absent.

Fresh-clone backend qualification after filtering: **1,848 passed, 0 failed,
38 skipped**. The candidate contains 103 retained historical commits plus one
verified-source integration commit. Index/history privacy checks pass. The
rewrite commit skips push-triggered CI/deployment to avoid an unrelated site
release; later pushes retain normal workflow behavior.
