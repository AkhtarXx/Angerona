# Angerona service architecture

This document is a future extraction design. As verified on `2026-08-04`, Angerona
is a local modular monolith; these services are not independently deployed. The goal
is to extract them without weakening evidence integrity.

## Service boundaries

1. **Intake service** validates a sample, computes its content identity, and creates a run.
2. **Analysis service** owns IDA/Ghidra execution and immutable static-analysis artifacts.
3. **Execution service** owns sandboxed native, Unicorn, symbolic, and fuzzing jobs.
4. **Verification service** consumes immutable evidence and returns one of:
   `succeeded`, `contradicted`, `unverifiable`, or `failed`.
5. **Orchestration service** schedules work but cannot manufacture or rewrite evidence.
6. **Workspace service** owns run metadata, artifact references, and atomic state transitions.
7. **Web gateway** is a control plane only; it never executes analysis logic directly.

`src.services.contracts` is the transport-neutral API. Local adapters use it in-process.
Remote adapters must preserve the same JSON fields over HTTP/gRPC or a durable queue.

## Non-negotiable invariants

- Every evidence record is bound to the source binary SHA-256.
- Synthetic/test evidence is explicitly marked and is never admissible as execution proof.
- Infrastructure failure is `failed` or `unverifiable`, never success.
- Commands are idempotent by `request_id`; traces correlate by `trace_id`.
- The current local runtime already has a hash-chained SQLite/WAL observability ledger,
  but that is not a substitute for authenticated cross-service OpenTelemetry.
- Workers write immutable artifacts; only the workspace service changes run state.
- Execution workers are isolated, network-denied by default, resource-limited, and disposable.

## Deployment migration

The current local adapters remain the development runtime. Extraction order:

1. execution workers;
2. analysis engine workers;
3. verification service;
4. workspace/event store;
5. web gateway and orchestration service.

Each extraction requires authentication, request-size limits, retry/idempotency tests,
OpenTelemetry traces, health/readiness endpoints, and a dead-letter queue before it is
considered production-ready.
