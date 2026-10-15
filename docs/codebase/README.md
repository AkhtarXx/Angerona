# Codebase reference

This directory maps the current application for reviewers and maintainers.
Start with the root [README](../../README.md) and [review guide](../../REVIEW_GUIDE.md).

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Components, execution flow, state and trust boundaries |
| [Features](FEATURES.md) | Package/module navigation and implemented capabilities |
| [Interfaces](INTERFACES.md) | CLI, HTTP, MCP, configuration and output artifacts |
| [Testing and status](TESTING_AND_STATUS.md) | Current qualification scope and test entry points |

The current runtime is a local modular monolith. The separate
[microservices document](../architecture/MICROSERVICES.md) is a future design,
not the deployed architecture.

[Verification](../VERIFICATION.md) is the authoritative human-readable record of
the latest tested snapshot. Source presence, module counts and historical commit
messages are not evidence of successful execution. The review ZIP intentionally
omits internal memory, stale generated symbol catalogs and historical Git notes;
read the current source when assessing a function or trust boundary.
