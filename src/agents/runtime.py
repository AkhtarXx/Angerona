"""Subscription-driven agent runtimes (no API keys).

Drives the user's installed ``claude`` (Claude Code) and ``codex`` CLIs in FULL
AGENTIC mode with the Ghidra MCP server attached. Auth comes from the CLIs'
existing subscription logins (~/.claude, ~/.codex/auth.json) — no ANTHROPIC/
OpenAI API key is ever read or required.

The subprocess pattern (activity-aware Popen with idle/wall timeouts and a
SIGTERM->SIGKILL escalation) is adapted from thoth's providers/cli_process.py.

Unlike thoth — which uses these CLIs as *text-only backends* (``--max-turns 1``,
tools disabled) — this module runs them as autonomous agents: the CLI executes
its own tool loop and calls the Ghidra MCP tools directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import uuid
import fcntl
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Callable, TypeVar, cast

from ..observability import (
    capture_tree,
    content_descriptor,
    current_span_id,
    external_event_descriptor,
    ledger_for_workspace,
)

from .context_harness import (
    RECOVERY_CHECKPOINT_VERSION,
    ContextHarnessConfig,
    RecoveryCheckpoint,
    RecoveryInputAttachment,
    RecoveryTask,
    apply_observed_context_limit,
    build_recovery_task,
    configure_claude_context_env,
    configure_generic_context,
    configure_tool_output_governor_env,
    context_checkpoint_system_prompt,
    is_context_overflow,
    load_recovery_snapshot,
    parse_context_overflow_details,
    parse_trusted_context_overflow_details,
    prepare_initial_task,
    write_recovery_checkpoint,
)
from .scratch_quota import (
    AUTH_SEED_MAX_BYTES,
    DEFAULT_PROCESS_MEMORY_BYTES,
    DEFAULT_PROCESS_TASKS,
    DEFAULT_SCRATCH_WRITE_BYTES,
    DEFAULT_SCRATCH_WRITE_DIRECTORIES,
    DEFAULT_SCRATCH_WRITE_FILES,
    SCRATCH_QUOTA_EXIT,
    bounded_tree_usage,
    install_export,
    read_export_socket,
    reconstruction_authority,
)
from .network_guard import (
    NETWORK_POLICY_EXIT,
    CandidateNetworkBroker,
    configure_proxy_environment,
    configure_trusted_provider_gateway,
    resolve_candidate_network_policy,
)

_CANDIDATE_SCRATCH_WRITE_BYTES = DEFAULT_SCRATCH_WRITE_BYTES
_CANDIDATE_SCRATCH_WRITE_FILES = DEFAULT_SCRATCH_WRITE_FILES
_CANDIDATE_SCRATCH_WRITE_DIRECTORIES = DEFAULT_SCRATCH_WRITE_DIRECTORIES
_CANDIDATE_PROCESS_MEMORY_BYTES = DEFAULT_PROCESS_MEMORY_BYTES
_CANDIDATE_PROCESS_TASKS = DEFAULT_PROCESS_TASKS
_REQUIRED_ENV_EXECUTION_CONTROLS = frozenset({
    "BASH_ENV", "BASHOPTS", "CDPATH", "ENV", "GLOBIGNORE", "SHELLOPTS",
    "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_EXEC_PATH", "GIT_SSH_COMMAND",
    "GIT_TEMPLATE_DIR", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
    "LD_AUDIT", "LD_DEBUG", "LD_LIBRARY_PATH", "LD_PRELOAD",
    "NODE_OPTIONS", "NODE_PATH", "PERL5LIB", "PERL5OPT", "PROMPT_COMMAND",
    "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH", "PYTHONSTARTUP",
    "RUBYLIB", "RUBYOPT", "ZDOTDIR", "_JAVA_OPTIONS",
    # Interpreter instrumentation injection that a hostile host could preload
    # into the candidate.  DYLD_INSERT_LIBRARIES is an exact key (not caught by
    # the DYLD_ prefix).  ANGR_STATIC_PRELOAD / FRIDA_* let angr/frida inject
    # into the candidate process.  (ELITE-2 verdict fix: enum was incomplete.)
    "DYLD_INSERT_LIBRARIES", "ANGR_STATIC_PRELOAD", "FRIDA_SCRIPT",
    "FRIDA_SCRIPT_PATH", "OBJC_DISABLE_INITIALIZE_FORK_SAFETY",
})
_REQUIRED_ENV_EXECUTION_PREFIXES = ("DYLD_", "GIT_CONFIG_", "NPM_CONFIG_", "FRIDA_")

# Trusted provider URLs that bed-conflict-with candidate sandbox
# (ELITE-2 roadmap F1: env-leak class; pop before candidate launch)
#
# Originally a 5-key denylist, which silently passed every non-enumerated
# provider-URL var (ANGERONA_LOCAL_BASE_URL, GEMINI_BASE_URL, and any future
# *_BASE_URL).  Converted to an allowlist model: the sanitizer strips ALL
# *_BASE_URL / *_API_BASE / *_API_KEY keys that point at a *public* host,
# preserving only loopback URLs (the trusted synthetic testing endpoint that
# configure_trusted_provider_gateway alias-rewrites downstream).  This closes
# the enum-drift leak class at once instead of patching the enum one key at a
# time.  (ELITE-2 verdict round-2 fix: denylist -> allowlist.)
_REQUIRED_ENV_PROVIDER_URLS = frozenset({
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_BASE",
    "CLAUDE_API_BASE",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
})
# Suffixes that mark a key as a provider-URL/credential surface for the
# allowlist strip.  Keys ending in one of these (matched CASE-INSENSITIVELY,
# see _sanitize_required_provider_environment) are sanitized below so that
# mixed-case spellings (Anthropic_Base_Url, anthropic_base_url) cannot survive
# by relying on the host's ALL-CAPS naming convention.  (ELITE-2 verdict
# round-5 fix: the prior str.endswith was case-sensitive and the comment
# falsely claimed case-insensitivity — mixed-case *_base_url keys with a
# public host leaked untouched.)
_PROVIDER_URL_KEY_SUFFIXES = (
    "_BASE_URL", "_API_BASE", "_API_KEY", "_API_URL", "_API_HOST",
    "_ENDPOINT", "_SERVER_URL", "_AUTH_TOKEN", "_OAUTH_TOKEN",
    "_SECRET", "_BEARER", "_PASSWORD", "_TOKEN",
    # Credential-spelling suffixes added round-5: the prior set missed real
    # gateway credential env-var spellings, so ANTHROPIC_ACCESS_KEY /
    # ANTHROPIC_CREDENTIAL / AWS_SECRET_ACCESS_KEY leaked.  (_SECRET already
    # covered AWS_SECRET_ACCESS_KEY's tail, but _SECRET_KEY / _CREDENTIAL /
    # _CRED / _ACCESS_KEY are distinct tails used by Bedrock/Vertex/Anthropic.)
    "_ACCESS_KEY", "_CREDENTIAL", "_CRED", "_SECRET_KEY",
    "_ACCESS_KEY_ID",
    # Bare-suffix credential spellings added round-6: the prior allowlist
    # leaked keys ending in a bare _URL / _KEY / _PROXY / _APIKEY — e.g.
    # ANTHROPIC_URL=https://api.anthropic.com, ANTHROPIC_KEY=sk-ant-...,
    # ANTHROPIC_PROXY=http://gateway, OPENAI_KEY=...  These are real gateway
    # credential/endpoint spellings (a value is a URL or a credential string);
    # a loopback-valued URL is preserved by _provider_url_is_loopback below.
    # NOTE: bare _HOST / _API / _AUTH are deliberately NOT added — a *_HOST
    # value is a bare hostname (not a URL), and stripping loopback hostnames
    # like DB_HOST=localhost would false-positive on legitimate non-credential
    # host config; those are handled by the network egress allowlist instead.
    # (ELITE-2 verdict round-6 fix.)
    "_URL", "_KEY", "_PROXY", "_APIKEY",
    # Credential-FILE-path suffixes added round-7: keys whose value is a PATH
    # to a credential file (ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_key,
    # GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json) leak the
    # file path into the candidate env.  Even though the file itself may be
    # masked in the sandbox, the path reveals where a secret lives on the host
    # and the key name is a credential-bearing spelling.  Strip these.
    # (ELITE-2 verdict round-7 fix: *_KEY_FILE / _CREDENTIALS / _CREDENTIALS_FILE
    # leaked untouched — ANTHROPIC_API_KEY_FILE confirmed.  The round-7
    # independent F2 corpus additionally caught the SINGULAR _CREDENTIAL_FILE
    # spelling (AWS_CREDENTIAL_FILE) which the plural-only entry missed.)
    "_KEY_FILE", "_CREDENTIALS", "_CREDENTIALS_FILE", "_CREDENTIAL_FILE",
    "_SERVICE_ACCOUNT",
)
# Pre-upcased tuple for the case-insensitive suffix comparison so the hot path
# does not allocate per key.  Compared against key.upper().
_PROVIDER_URL_KEY_SUFFIXES_UPPER = tuple(s.upper() for s in _PROVIDER_URL_KEY_SUFFIXES)
_AUTH_SEED_PATHS = {
    "claude-credentials": (".claude", ".credentials.json"),
    "claude-settings": (".claude", "settings.json"),
    "claude-state": (".claude.json",),
    "home-credentials": (".credentials.json",),
    "codex-auth": (".codex", "auth.json"),
}
from .retry_harness import (
    RetryLedger,
    RetryLeaseBusy,
    RetryPolicy,
    RetrySession,
    RetryStateError,
    TransientFailure,
    classify_transient_failure,
    dispatch_key as retry_dispatch_key,
    retry_recovery_task,
    sleep_before_retry,
)


@dataclass
class AgentResult:
    ok: bool
    final_text: str
    events: list[dict] = field(default_factory=list)
    returncode: int = 0
    seconds: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""
    context_observations: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class CandidateWorkspaceSnapshot:
    """Validated non-authoritative scratch state carried to one later attempt."""

    payload: bytes
    sha256: str


def _open_sealed_input(payload: bytes, *, label: str) -> int:
    """Create an immutable inherited input without exposing a mutable host path."""

    import fcntl

    memfd_flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(
        os, "MFD_ALLOW_SEALING", 0x0002
    )
    if hasattr(os, "memfd_create"):
        descriptor = os.memfd_create(f"angerona-{label}", flags=memfd_flags)
    elif sys.platform.startswith("linux"):
        # Some standalone/embedded CPython builds omit the os.memfd_create and
        # fcntl sealing constants even though the host libc and kernel support
        # them. Use the same Linux API directly instead of weakening the sealed
        # inherited-FD transport or falling back to a mutable path.
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        memfd_create = getattr(libc, "memfd_create", None)
        if memfd_create is None:
            raise RuntimeError("sealed recovery input transport is unavailable")
        memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
        memfd_create.restype = ctypes.c_int
        descriptor = memfd_create(f"angerona-{label}".encode(), memfd_flags)
        if descriptor < 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    else:
        raise RuntimeError("sealed recovery input transport is unavailable")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("sealed recovery input write made no progress")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        )
        add_seals = getattr(fcntl, "F_ADD_SEALS", 1033)
        get_seals = getattr(fcntl, "F_GET_SEALS", 1034)
        fcntl.fcntl(descriptor, add_seals, seals)
        if fcntl.fcntl(descriptor, get_seals) & seals != seals:
            raise RuntimeError("sealed recovery input could not be made immutable")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _materialize_recovery_inputs(
    input_text: str | None,
) -> tuple[str | None, tuple[int, ...]]:
    if input_text is None:
        return None, ()
    attachments = getattr(input_text, "trusted_attachments", ())
    if not attachments:
        return str(input_text), ()
    if not isinstance(attachments, tuple) or not all(
        isinstance(item, RecoveryInputAttachment) for item in attachments
    ):
        raise RuntimeError("recovery input attachment contract is invalid")
    materialized = str(input_text)
    descriptors: list[int] = []
    try:
        for attachment in attachments:
            if materialized.count(attachment.placeholder) != 1:
                raise RuntimeError("recovery input placeholder is invalid")
            if hashlib.sha256(attachment.payload).hexdigest() != attachment.sha256:
                raise RuntimeError("recovery input attachment digest mismatch")
            descriptor = _open_sealed_input(
                attachment.payload,
                label=attachment.sha256[:12],
            )
            descriptors.append(descriptor)
            materialized = materialized.replace(
                attachment.placeholder, str(descriptor), 1
            )
        return materialized, tuple(descriptors)
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


EventCallback = Callable[[str, dict], None]
ContextWindowApplier = Callable[[int], ContextHarnessConfig]
ContextObservationCallback = Callable[
    [dict, ContextWindowApplier], ContextHarnessConfig
]
_RunCallable = TypeVar("_RunCallable", bound=Callable[..., AgentResult])
_ACTIVE_RETRY_LEDGERS: ContextVar[list[RetryLedger] | None] = ContextVar(
    "angerona_active_retry_ledgers", default=None
)


def _retry_lease_lifecycle(method: _RunCallable) -> _RunCallable:
    """Unconditionally release every retry lease opened during one runtime call."""

    @wraps(method)
    def wrapped(*args: object, **kwargs: object) -> AgentResult:
        token = _ACTIVE_RETRY_LEDGERS.set([])
        try:
            return method(*args, **kwargs)
        finally:
            ledgers = _ACTIVE_RETRY_LEDGERS.get() or []
            for ledger in reversed(ledgers):
                ledger.close()
            _ACTIVE_RETRY_LEDGERS.reset(token)

    return cast(_RunCallable, wrapped)


def _register_retry_ledger(ledger: RetryLedger) -> None:
    ledgers = _ACTIVE_RETRY_LEDGERS.get()
    if ledgers is not None:
        ledgers.append(ledger)


def _requested_wall_deadline_unix_ns(wall_timeout: float | None) -> int | None:
    if wall_timeout is None or wall_timeout <= 0:
        return None
    return time.time_ns() + int(wall_timeout * 1_000_000_000)


def _remaining_wall_seconds(deadline_unix_ns: int | None) -> float | None:
    if deadline_unix_ns is None:
        return None
    return max(0.0, (deadline_unix_ns - time.time_ns()) / 1_000_000_000)


def _retry_workspace_root(cwd: str) -> Path:
    resolved = Path(cwd).expanduser().resolve()
    return resolved.parent if resolved.name == "code" else resolved


def _retry_control_root(cwd: str) -> Path:
    """Return durable supervisor state that is never mounted writable to agents."""

    workspace_root = _retry_workspace_root(cwd)
    configured = (os.environ.get("ANGERONA_AGENT_CONTROL_STATE_DIR") or "").strip()
    if configured:
        base = Path(configured).expanduser().resolve()
    else:
        state_home = Path(
            os.environ.get("XDG_STATE_HOME")
            or (Path.home() / ".local" / "state")
        ).expanduser().resolve()
        base = state_home / "angerona" / "agent-control"
    workspace_id = hashlib.sha256(
        str(workspace_root).encode("utf-8", errors="surrogatepass")
    ).hexdigest()
    root = (base / "workspaces" / workspace_id).resolve()
    if _is_relative_to(root, workspace_root):
        raise ValueError("agent control state must be outside the model workspace")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("agent control state root is not a directory")
    os.chmod(root, 0o700)
    return root


def _execution_file_identity(
    path_value: str | None,
    *,
    bind_path: bool = True,
) -> dict[str, object] | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        resolved = path.resolve(strict=True)
        descriptor = os.open(
            resolved,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        return {"path": str(path), "available": False}
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            return {"path": str(resolved), "available": False}
        digest = hashlib.sha256()
        remaining = int(initial.st_size)
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("execution contract file was truncated while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("execution contract file grew while hashing")
        final = os.fstat(descriptor)
        current = os.stat(resolved, follow_symlinks=False)
        identity = (
            initial.st_dev,
            initial.st_ino,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        )
        if identity != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ) or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError("execution contract file changed while hashing")
        identity_record: dict[str, object] = {
            "available": True,
            "size": initial.st_size,
            "sha256": digest.hexdigest(),
        }
        if bind_path:
            identity_record["path"] = str(resolved)
        return identity_record
    finally:
        os.close(descriptor)


def _execution_contract_sha256(contract: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            contract,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _emit_retry_event(
    events: list[dict],
    on_event: EventCallback | None,
    *,
    phase: str,
    **data: object,
) -> None:
    event = {"type": "angerona_agent_retry", "phase": phase, **data}
    events.append(event)
    if on_event is not None:
        on_event("agent_retry", dict(event))


def _open_retry_ledger(
    *,
    agent_family: str,
    model_name: str,
    cwd: str,
    task: str,
    system_prompt: str,
    execution_contract_sha256: str,
    events: list[dict],
    on_event: EventCallback | None,
    lock_timeout_seconds: float,
    wall_deadline_unix_ns: int | None,
) -> tuple[str, RetryLedger | None, RetrySession | None, bool]:
    key = retry_dispatch_key(
        agent_family=agent_family,
        model_name=model_name,
        cwd=cwd,
        task=task,
        system_prompt=system_prompt,
        execution_contract_sha256=execution_contract_sha256,
    )
    ledger = None
    try:
        ledger = RetryLedger(
            _retry_control_root(cwd),
            key,
            mirror_root=_retry_workspace_root(cwd),
        )
        session = ledger.acquire_session(
            lock_timeout_seconds=lock_timeout_seconds,
            wall_deadline_unix_ns=wall_deadline_unix_ns,
        )
    except RetryLeaseBusy as exc:
        if ledger is not None:
            ledger.close()
        _emit_retry_event(
            events, on_event, phase="duplicate_suppressed", dispatch_key=key,
            reason="active_predecessor", error=str(exc),
        )
        return key, None, None, True
    except (OSError, ValueError, RetryStateError) as exc:
        if ledger is not None:
            ledger.close()
        _emit_retry_event(
            events, on_event, phase="disabled", dispatch_key=key,
            reason="durable_ledger_unavailable", error=str(exc),
        )
        return key, None, None, False
    _register_retry_ledger(ledger)
    if session.resumed_after_crash:
        _emit_retry_event(
            events, on_event, phase="resumed", dispatch_key=key,
            session_id=session.session_id, attempts_used=session.attempts_used,
        )
    if session.duplicate_suppressed:
        _emit_retry_event(
            events, on_event, phase="duplicate_suppressed", dispatch_key=key,
            session_id=session.session_id,
        )
    return key, ledger, session, False


def _record_context_checkpoint(
    session: RetrySession | None,
    checkpoint: RecoveryCheckpoint,
    *,
    attempt: int,
) -> None:
    if session is None:
        return
    session.record(
        "context_checkpoint_committed",
        attempt=attempt,
        checkpoint_id=checkpoint.checkpoint_id,
        manifest_path=str(checkpoint.manifest_path),
        manifest_sha256=checkpoint.manifest_sha256,
        manifest_version=checkpoint.manifest_version,
        execution_contract_sha256=checkpoint.execution_contract_sha256,
        original_task_path=str(checkpoint.original_task_path),
        transcript_path=str(checkpoint.transcript_path),
        stderr_path=str(checkpoint.stderr_path),
        handoff_path=str(checkpoint.handoff_path),
        snapshot_path=(str(checkpoint.snapshot_path) if checkpoint.snapshot_path else None),
        workspace_root=str(checkpoint.workspace_root),
    )


def _resume_context_checkpoint(
    session: RetrySession,
    config: ContextHarnessConfig,
    execution_contract_sha256: str,
) -> tuple[RecoveryCheckpoint, str, CandidateWorkspaceSnapshot | None, int] | None:
    record = next(
        (
            item
            for item in reversed(session.state.get("records", []))
            if item.get("session_id") == session.session_id
            and item.get("kind") == "context_checkpoint_committed"
        ),
        None,
    )
    if record is None:
        return None
    data = record.get("data")
    if not isinstance(data, dict):
        raise RetryStateError("durable context checkpoint record is malformed")
    attempt = data.get("attempt")
    required_strings = (
        "checkpoint_id",
        "manifest_path",
        "manifest_sha256",
        "original_task_path",
        "transcript_path",
        "stderr_path",
        "handoff_path",
        "workspace_root",
        "execution_contract_sha256",
    )
    if (
        not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or not all(isinstance(data.get(key), str) and data.get(key) for key in required_strings)
        or data.get("manifest_version") != RECOVERY_CHECKPOINT_VERSION
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(data.get("execution_contract_sha256") or "")
        )
        or data.get("execution_contract_sha256") != execution_contract_sha256
        or (
            data.get("snapshot_path") is not None
            and not isinstance(data.get("snapshot_path"), str)
        )
    ):
        raise RetryStateError("durable context checkpoint record is invalid")
    checkpoint = RecoveryCheckpoint(
        checkpoint_id=str(data["checkpoint_id"]),
        original_task_path=Path(str(data["original_task_path"])),
        transcript_path=Path(str(data["transcript_path"])),
        stderr_path=Path(str(data["stderr_path"])),
        handoff_path=Path(str(data["handoff_path"])),
        manifest_path=Path(str(data["manifest_path"])),
        workspace_root=Path(str(data["workspace_root"])),
        recent_capsule="",
        snapshot_path=(
            Path(str(data["snapshot_path"]))
            if data.get("snapshot_path") is not None
            else None
        ),
        execution_contract_sha256=str(data["execution_contract_sha256"]),
        manifest_sha256=str(data["manifest_sha256"]),
        manifest_version=int(data["manifest_version"]),
    )
    try:
        task = build_recovery_task(checkpoint, config)
        snapshot_payload = load_recovery_snapshot(checkpoint, config)
    except (OSError, ValueError) as exc:
        raise RetryStateError("durable context checkpoint failed validation") from exc
    if task.checkpoint_attempt != attempt:
        raise RetryStateError("durable context checkpoint attempt anchor mismatch")
    snapshot = (
        CandidateWorkspaceSnapshot(
            payload=snapshot_payload,
            sha256=hashlib.sha256(snapshot_payload).hexdigest(),
        )
        if snapshot_payload is not None
        else None
    )
    return checkpoint, task, snapshot, attempt


def _compose_agent_task_prompt(system_prompt: str, task: str) -> str:
    """Prefix policy without discarding sealed recovery attachments."""

    prompt = f"{system_prompt}\n\n# TASK\n{task}\n"
    if isinstance(task, RecoveryTask):
        return RecoveryTask(
            prompt,
            trusted_attachments=task.trusted_attachments,
            checkpoint_attempt=task.checkpoint_attempt,
        )
    return prompt


def _transient_recovery_task(
    task: str,
    failure: TransientFailure,
    attempt: int,
) -> str:
    """Wrap a retry prompt without losing sealed original-task transport."""

    wrapped = retry_recovery_task(task, failure, attempt)
    if isinstance(task, RecoveryTask):
        return RecoveryTask(
            wrapped,
            trusted_attachments=task.trusted_attachments,
            checkpoint_attempt=task.checkpoint_attempt,
        )
    return wrapped


def _restore_context_after_crash(
    *,
    session: RetrySession,
    config: ContextHarnessConfig,
    execution_contract_sha256: str,
    events: list[dict],
    on_event: EventCallback | None,
) -> tuple[RecoveryCheckpoint, str, CandidateWorkspaceSnapshot | None, int] | None:
    restored = _resume_context_checkpoint(
        session,
        config,
        execution_contract_sha256,
    )
    if restored is None:
        return None
    checkpoint, task, snapshot, attempt = restored
    event = {
        "type": "angerona_context_recovery",
        "phase": "resumed_after_crash",
        "compaction_id": checkpoint.checkpoint_id,
        "attempt": attempt,
        "manifest_path": str(checkpoint.manifest_path),
        "manifest_sha256": checkpoint.manifest_sha256,
        "manifest_version": checkpoint.manifest_version,
        "snapshot_present": snapshot is not None,
    }
    events.append(event)
    if on_event is not None:
        on_event("context_compaction", dict(event))
    return checkpoint, task, snapshot, attempt


def _duplicate_suppressed_result(
    *, events: list[dict], ledger: RetryLedger | None
) -> AgentResult:
    if ledger is not None:
        ledger.close()
    message = (
        "[agent-error rc=75] duplicate deterministic dispatch suppressed after "
        "a concurrent predecessor completed"
    )
    return AgentResult(
        ok=False,
        final_text=message,
        events=events,
        returncode=os.EX_TEMPFAIL,
        seconds=0.0,
        raw_stdout="",
        raw_stderr=message,
    )


def _resumed_retry_budget_exhausted_result(
    *,
    events: list[dict],
    on_event: EventCallback | None,
    ledger: RetryLedger,
    session: RetrySession,
    dispatch_key: str,
) -> AgentResult:
    _record_retry_terminal(
        session, events, on_event, kind="exhausted",
        dispatch_key=dispatch_key, reason="crash_resume_budget_exhausted",
    )
    _emit_retry_event(
        events, on_event, phase="exhausted", dispatch_key=dispatch_key,
        session_id=session.session_id,
        reason="crash_resume_budget_exhausted",
    )
    ledger.close()
    message = "[agent-error rc=75] transient retry budget exhausted after process crash"
    return AgentResult(
        ok=False, final_text=message, events=events,
        returncode=os.EX_TEMPFAIL, seconds=0.0,
        raw_stdout="", raw_stderr=message,
    )


def _resumed_wall_deadline_exhausted_result(
    *,
    events: list[dict],
    on_event: EventCallback | None,
    ledger: RetryLedger,
    session: RetrySession,
    dispatch_key: str,
) -> AgentResult:
    _record_retry_terminal(
        session, events, on_event, kind="exhausted",
        dispatch_key=dispatch_key, reason="crash_resume_wall_timeout_exhausted",
    )
    _emit_retry_event(
        events, on_event, phase="exhausted", dispatch_key=dispatch_key,
        session_id=session.session_id,
        reason="crash_resume_wall_timeout_exhausted",
    )
    ledger.close()
    message = "[agent-error rc=124] original wall timeout exhausted before crash resume"
    return AgentResult(
        ok=False, final_text=message, events=events,
        returncode=124, seconds=0.0,
        raw_stdout="", raw_stderr=message,
    )


def _record_retry_terminal(
    session: RetrySession | None,
    events: list[dict],
    on_event: EventCallback | None,
    *,
    kind: str,
    dispatch_key: str,
    **data: object,
) -> None:
    if session is not None:
        try:
            session.record(kind, **data)
        except (OSError, RetryStateError) as exc:
            _emit_retry_event(
                events, on_event, phase="ledger_error",
                dispatch_key=dispatch_key, error=str(exc),
            )


def _start_retry_attempt(
    session: RetrySession | None,
    events: list[dict],
    on_event: EventCallback | None,
    *,
    dispatch_key: str,
    launch_kind: str,
) -> int | None:
    if session is None:
        return None
    try:
        attempt = session.start_attempt(launch_kind=launch_kind)
    except (OSError, RetryStateError) as exc:
        _emit_retry_event(
            events, on_event, phase="ledger_error",
            dispatch_key=dispatch_key, error=str(exc),
        )
        return None
    _emit_retry_event(
        events, on_event, phase="attempt_started", dispatch_key=dispatch_key,
        session_id=session.session_id, attempt=attempt,
        launch_kind=launch_kind,
    )
    return attempt


def _schedule_transient_retry(
    *,
    returncode: int,
    attempt_events: list[dict],
    stderr: str,
    session: RetrySession | None,
    policy: RetryPolicy,
    deadline: float | None,
    dispatch_key: str,
    events: list[dict],
    on_event: EventCallback | None,
) -> TransientFailure | None:
    failure = classify_transient_failure(
        returncode=returncode,
        events=attempt_events,
        stderr=stderr,
    )
    if failure is None:
        return None
    if session is None:
        _emit_retry_event(
            events, on_event, phase="exhausted", dispatch_key=dispatch_key,
            category=failure.category, reason="durable_ledger_unavailable",
        )
        return None
    if session.transient_retries_used >= policy.max_attempts - 1:
        try:
            session.record(
                "exhausted", category=failure.category,
                reason="attempt_budget_exhausted",
            )
        except (OSError, RetryStateError) as exc:
            _emit_retry_event(
                events, on_event, phase="ledger_error",
                dispatch_key=dispatch_key, error=str(exc),
            )
            return None
        _emit_retry_event(
            events, on_event, phase="exhausted", dispatch_key=dispatch_key,
            session_id=session.session_id, category=failure.category,
            reason="attempt_budget_exhausted",
        )
        return None
    failed_attempt = session.transient_retries_used + 1
    delay = policy.delay_seconds(
        failed_attempt=failed_attempt,
        dispatch_key=dispatch_key,
        retry_after_seconds=failure.retry_after_seconds,
    )
    remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
    if remaining is not None and remaining < delay + policy.min_remaining_seconds:
        try:
            session.record(
                "exhausted", category=failure.category,
                reason="wall_deadline_insufficient", remaining_seconds=remaining,
                planned_delay_seconds=delay,
            )
        except (OSError, RetryStateError) as exc:
            _emit_retry_event(
                events, on_event, phase="ledger_error",
                dispatch_key=dispatch_key, error=str(exc),
            )
            return None
        _emit_retry_event(
            events, on_event, phase="exhausted", dispatch_key=dispatch_key,
            session_id=session.session_id, category=failure.category,
            reason="wall_deadline_insufficient", remaining_seconds=remaining,
        )
        return None
    next_retry = session.transient_retries_used + 1
    try:
        session.record(
            "transient_retry_scheduled",
            retry=next_retry,
            category=failure.category,
            source=failure.source,
            delay_seconds=delay,
            retry_after_seconds=failure.retry_after_seconds,
        )
    except (OSError, RetryStateError) as exc:
        _emit_retry_event(
            events, on_event, phase="ledger_error",
            dispatch_key=dispatch_key, error=str(exc),
        )
        return None
    session.transient_retries_used = next_retry
    _emit_retry_event(
        events, on_event, phase="scheduled", dispatch_key=dispatch_key,
        session_id=session.session_id, retry=session.transient_retries_used,
        category=failure.category, source=failure.source,
        delay_seconds=delay,
    )
    sleep_before_retry(delay)
    return failure


DEFAULT_AGENT_CAPTURE_CHARS = 200_000
DEFAULT_AGENT_EVENT_LINE_CHARS = 1_000_000
DEFAULT_AGENT_EVENT_STREAM_BYTES = 32 * 1024 * 1024
DEFAULT_AGENT_EVENT_COUNT = 50_000
AGENT_EVENT_BOUNDARY_EXIT = 75

_CLAUDE_COMPAT_GATEWAY_ENV = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_BASE",
    "CLAUDE_API_BASE",
)
_CLAUDE_MODEL_ENV = (
    "ANTHROPIC_MODEL",
    "CLAUDE_MODEL",
    "ANGERONA_CLAUDE_MODEL",
)
_NON_ANTHROPIC_MODEL_MARKERS = (
    "glm",
    "kimi",
    "qwen",
    "deepseek",
    "moonshot",
    "yi-",
)

_MCP_CONTEXT_ENV_KEYS = (
    "ANGERONA_AGENT_WORKSPACE_ROOT",
    "ANGERONA_RUN_CWD",
    "ANGERONA_ALLOWED_ROOTS",
    "ANGERONA_ALLOWED_INPUT_BINARY",
    "ANGERONA_TARGET_BINARY",
    "ANGERONA_MCP_ALLOW_WRITE",
    "ANGERONA_CONTEXT_TRIGGER_TOKENS",
    "ANGERONA_TOOL_OUTPUT_MAX_TOKENS",
    "ANGERONA_TOOL_OUTPUT_SESSION_BUDGET_TOKENS",
    "ANGERONA_TOOL_OUTPUT_PREVIEW_CHARS",
    "ANGERONA_TOOL_OUTPUT_ARTIFACT_DIR",
    "ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_BYTES",
    "ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_FILES",
)


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _truthy(value: str | None, *, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _provider_url_is_loopback(raw: str) -> bool:
    """True when a provider base URL points at a loopback host.

    A loopback URL is the *trusted synthetic endpoint* the candidate sandbox's
    own settings wire for testing — ``configure_trusted_provider_gateway``
    rewrites it into a private alias.  It is NOT the env-leak class F1 targets;
    the leak class is a host-supplied *public* provider URL (e.g.
    ``https://api.anthropic.com``) that overrides the synthetic endpoint.

    KNOWN CARVE-OUT (ELITE-2 verdict round-6): blind loopback preservation
    treats ``http://localhost:NNNN`` as trusted, but a host could run an SSH
    reverse-tunnel (``localhost:3457`` → ``api.anthropic.com``) so the
    'trusted' endpoint is actually the real public provider bypassing the
    egress allowlist.  Mitigations: (1) the network broker enforces an EXACT
    host:port allowlist, so a loopback-preserved URL still cannot reach an
    arbitrary host — it can only reach the one loopback port the gateway
    proxy binds; (2) the candidate's loopback gateway is bound by
    ``configure_trusted_provider_gateway`` which the operator controls; (3)
    all numeric loopback encodings are normalized below (0x7f000001, 127.1,
    127.0.0.1, ::1) so a non-canonical encoding cannot evade detection.  The
    residual risk (an operator-provisioned loopback tunnel to the real
    provider) is a host-trust decision, not an F1 env-strip gap — it is
    documented here rather than closed, because closing it would require F1
    to inspect settings.json, which is the candidate's trusted wiring channel.
    """
    from urllib.parse import urlsplit
    import ipaddress
    try:
        parsed = urlsplit(raw.strip())
    except ValueError:
        return False
    host = parsed.hostname
    if not host:
        return False
    if host.lower() in ("localhost", "ip6-localhost"):
        return True
    # Normalize numeric loopback encodings (ELITE-2 verdict round-6): a host
    # could write http://0x7f000001:1234 or http://127.1:1234 to evade a naive
    # '127.0.0.1'/'localhost' check.  ipaddress.ip_address only accepts
    # canonical decimal IPv4 (127.0.0.1) and IPv6 (::1); it rejects hex
    # (0x7f000001) and short-form (127.1) IPv4.  inet_aton accepts those forms,
    # so use it to get the canonical 4-byte address and re-check is_loopback.
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        from socket import inet_aton
        packed = inet_aton(host)  # accepts 0x7f000001, 127.1, 127.0.0.1
        return ipaddress.ip_address(int.from_bytes(packed, "big")).is_loopback
    except (OSError, ValueError):
        return False


def _sanitize_required_provider_environment(env: dict[str, str]) -> None:
    """Drop host-side interpreter/config injection controls before K dispatch."""

    for key in tuple(env):
        if key in _REQUIRED_ENV_EXECUTION_CONTROLS or key.startswith(
            _REQUIRED_ENV_EXECUTION_PREFIXES
        ):
            env.pop(key, None)
    # Strip provider-URL/credential surfaces so a host-supplied *public*
    # ANTHROPIC_BASE_URL (or GEMINI_BASE_URL, ANGERONA_LOCAL_BASE_URL, or any
    # future *_BASE_URL) never overrides the fake/synthetic endpoint the
    # candidate sandbox's own settings (e.g., ~/.claude/settings.json) wire for
    # testing.  This is now an ALLOWLIST: every key ending in a provider-URL
    # suffix is dropped unless its value points at a loopback host (the trusted
    # synthetic endpoint that ``configure_trusted_provider_gateway`` rewrites
    # downstream).  The explicit 5-key set above is retained as a documented
    # baseline, but the suffix match is what closes the enum-drift leak class.
    # (ELITE-2 verdict round-2 fix: denylist -> allowlist.)
    for key in tuple(env):
        # CASE-INSENSITIVE suffix match (ELITE-2 verdict round-5 fix): the
        # prior key.endswith(_PROVIDER_URL_KEY_SUFFIXES) was case-sensitive,
        # so mixed-case spellings (Anthropic_Base_Url, anthropic_base_url)
        # with a public host survived untouched.  Compare the upcased key
        # against the pre-upcased suffix tuple so the host's ALL-CAPS naming
        # convention is not a silent security dependency.
        if not key.upper().endswith(_PROVIDER_URL_KEY_SUFFIXES_UPPER):
            continue
        value = env.get(key)
        if value is None:
            continue
        if _provider_url_is_loopback(value):
            continue
        env.pop(key, None)


def _open_candidate_auth_seeds(env: dict[str, str]) -> dict[str, int]:
    """Open bounded trusted auth/config snapshots without mounting their paths."""

    host_home = Path(env.get("HOME") or str(Path.home())).expanduser().resolve()
    opened: dict[str, int] = {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        for name, parts in _AUTH_SEED_PATHS.items():
            path = host_home.joinpath(*parts)
            try:
                descriptor = os.open(path, flags)
            except FileNotFoundError:
                continue
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= AUTH_SEED_MAX_BYTES:
                os.close(descriptor)
                raise RuntimeError("required candidate auth seed is unsafe or oversized")
            opened[name] = descriptor
        return opened
    except Exception:
        for descriptor in opened.values():
            os.close(descriptor)
        raise


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


_RECOVERY_INSTRUCTION_FILES = (
    ".mcp.json",
    "AGENTS.md",
    "AGENTS.override.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
)
_RECOVERY_INSTRUCTION_DIRECTORIES = (".claude", ".codex")
_RECOVERY_QUARANTINE_PREFIX = ".angerona-recovery-instructions-"
_RECOVERY_QUARANTINE_ENTRY_LIMIT = 4_096

# Per-run state directories under runtime/.claude/ that a non-isolation run
# persists on the host.  These can carry secrets (shell snapshots with env
# tokens, session state) and must be masked from the seed path of the NEXT
# isolated candidate.  ``plugins``/``projects`` are added per-run below when
# not in recovery mode.  (ELITE-2 verdict round-6: cross-run isolation.)
_WORKSPACE_CLAUDE_STATE_DIRS = (
    "session-env",
    "shell-snapshots",
    "cache",
    "jobs",
    "todos",
)


def _lexical_workspace_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise RuntimeError("recovery instruction quarantine path is invalid")
    return root.joinpath(*path.parts)


def _remove_quarantined_instruction_entry(path: Path, budget: list[int]) -> None:
    """Remove one dead-provider instruction entry without following symlinks."""

    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    budget[0] -= 1
    if budget[0] < 0:
        raise RuntimeError("recovery instruction cleanup exceeds bounds")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        path.unlink()
        return
    with os.scandir(path) as iterator:
        children = [Path(entry.path) for entry in iterator]
    for child in children:
        _remove_quarantined_instruction_entry(child, budget)
    path.rmdir()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_directory_beneath(root_fd: int, parts: tuple[str, ...]) -> int:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _remove_instruction_entry_at(
    parent_fd: int,
    name: str,
    budget: list[int],
) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    budget[0] -= 1
    if budget[0] < 0:
        raise RuntimeError("recovery instruction cleanup exceeds bounds")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        with os.scandir(directory_fd) as iterator:
            children = [entry.name for entry in iterator]
        for child in children:
            _remove_instruction_entry_at(directory_fd, child, budget)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


class _RecoveryInstructionQuarantine:
    """Temporarily move instruction symlinks, then restore them byte-exactly.

    Bind mounts follow a destination symlink and can therefore hide its innocent
    target.  A supervisor-held workspace lock plus a durable external journal
    lets recovery mask the link name itself without exposing the quarantined
    link inside the provider mount namespace.  Crash recovery repairs any
    interrupted quarantine before a new provider is launched.
    """

    def __init__(self, cwd: str, env: dict[str, str]):
        self.workspace = Path(
            env.get("ANGERONA_AGENT_WORKSPACE_ROOT") or cwd
        ).expanduser().resolve()
        self.control_root = _retry_control_root(Path(cwd))
        self.journal_path = self.control_root / "instruction-quarantine.json"
        self.lock_fd = -1
        self.entries: list[dict[str, str]] = []

    def _write_journal(self) -> None:
        payload = json.dumps(
            {"version": 1, "entries": self.entries},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        temporary = self.control_root / f".instruction-quarantine-{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise RuntimeError("instruction quarantine journal write stalled")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.journal_path)
        root_fd = os.open(self.control_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def _load_journal(self) -> list[dict[str, str]]:
        try:
            descriptor = os.open(
                self.journal_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return []
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= 1024 * 1024:
                raise RuntimeError("instruction quarantine journal is unsafe")
            chunks: list[bytes] = []
            remaining = int(info.st_size)
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise RuntimeError("instruction quarantine journal ended early")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise RuntimeError("instruction quarantine journal grew during read")
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("instruction quarantine journal is invalid") from exc
        entries = decoded.get("entries") if isinstance(decoded, dict) else None
        if (
            not isinstance(decoded, dict)
            or decoded.get("version") != 1
            or not isinstance(entries, list)
        ):
            raise RuntimeError("instruction quarantine journal is invalid")
        clean: list[dict[str, str]] = []
        seen_originals: set[str] = set()
        seen_quarantines: set[str] = set()
        if len(entries) > _RECOVERY_QUARANTINE_ENTRY_LIMIT:
            raise RuntimeError("instruction quarantine journal exceeds bounds")
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"original", "quarantine", "target"}
                or not all(isinstance(entry[key], str) for key in entry)
            ):
                raise RuntimeError("instruction quarantine journal is invalid")
            original = _lexical_workspace_path(self.workspace, entry["original"])
            quarantine = _lexical_workspace_path(self.workspace, entry["quarantine"])
            canonical_original = original.relative_to(self.workspace).as_posix()
            quarantine_relative = quarantine.relative_to(self.workspace)
            canonical_quarantine = quarantine_relative.as_posix()
            if original.name not in {
                *_RECOVERY_INSTRUCTION_FILES,
                *_RECOVERY_INSTRUCTION_DIRECTORIES,
            } or (
                entry["original"] != canonical_original
                or entry["quarantine"] != canonical_quarantine
                or quarantine.parent.parent != original.parent
                or re.fullmatch(
                    re.escape(_RECOVERY_QUARANTINE_PREFIX) + r"[0-9a-f]{32}",
                    quarantine.parent.name,
                ) is None
                or re.fullmatch(r"entry-[0-9]+", quarantine.name) is None
                or len(quarantine_relative.parts) < 2
                or canonical_original in seen_originals
                or canonical_quarantine in seen_quarantines
            ):
                raise RuntimeError("instruction quarantine journal scope is invalid")
            seen_originals.add(canonical_original)
            seen_quarantines.add(canonical_quarantine)
            clean.append({
                "original": canonical_original,
                "quarantine": canonical_quarantine,
                "target": entry["target"],
            })
        return clean

    def _restore(self, entries: list[dict[str, str]]) -> None:
        root_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        root_fd = os.open(self.workspace, root_flags)
        prepared: list[dict[str, object]] = []
        quarantine_groups: dict[
            tuple[tuple[str, ...], str],
            dict[str, object],
        ] = {}
        try:
            # Validate the entire journal and every no-follow parent identity
            # before deleting or renaming a single workspace entry.
            for entry in entries:
                original_relative = Path(entry["original"])
                quarantine_relative = Path(entry["quarantine"])
                parent_parts = tuple(original_relative.parts[:-1])
                quarantine_name = quarantine_relative.parts[-1]
                quarantine_directory = quarantine_relative.parts[-2]
                parent_fd = _open_directory_beneath(root_fd, parent_parts)
                quarantine_fd = -1
                try:
                    parent_info = os.fstat(parent_fd)
                    parent_identity = (parent_info.st_dev, parent_info.st_ino)
                    try:
                        quarantine_fd = os.open(
                            quarantine_directory,
                            root_flags,
                            dir_fd=parent_fd,
                        )
                    except FileNotFoundError:
                        quarantine_identity = None
                        quarantined_info = None
                    except OSError as exc:
                        raise RuntimeError(
                            "instruction quarantine parent is unsafe"
                        ) from exc
                    else:
                        quarantine_info = os.fstat(quarantine_fd)
                        quarantine_identity = (
                            quarantine_info.st_dev,
                            quarantine_info.st_ino,
                        )
                        try:
                            quarantined_info = os.stat(
                                quarantine_name,
                                dir_fd=quarantine_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            quarantined_info = None
                    if quarantined_info is None:
                        try:
                            current_info = os.stat(
                                original_relative.name,
                                dir_fd=parent_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError as exc:
                            raise RuntimeError(
                                "quarantined instruction link was lost"
                            ) from exc
                        if (
                            not stat.S_ISLNK(current_info.st_mode)
                            or os.readlink(
                                original_relative.name, dir_fd=parent_fd
                            ) != entry["target"]
                        ):
                            raise RuntimeError(
                                "quarantined instruction link changed"
                            )
                        quarantine_present = False
                    else:
                        if (
                            not stat.S_ISLNK(quarantined_info.st_mode)
                            or os.readlink(
                                quarantine_name, dir_fd=quarantine_fd
                            ) != entry["target"]
                        ):
                            raise RuntimeError(
                                "quarantined instruction link changed"
                            )
                        quarantine_present = True
                    prepared.append({
                        "entry": entry,
                        "parent_parts": parent_parts,
                        "parent_identity": parent_identity,
                        "quarantine_directory": quarantine_directory,
                        "quarantine_name": quarantine_name,
                        "quarantine_identity": quarantine_identity,
                        "quarantine_present": quarantine_present,
                    })
                    group_key = (parent_parts, quarantine_directory)
                    group = quarantine_groups.setdefault(group_key, {
                        "identity": quarantine_identity,
                        "expected": set(),
                    })
                    if group["identity"] != quarantine_identity:
                        raise RuntimeError(
                            "instruction quarantine parent identity changed"
                        )
                    if quarantine_present:
                        cast(set[str], group["expected"]).add(quarantine_name)
                finally:
                    if quarantine_fd >= 0:
                        os.close(quarantine_fd)
                    os.close(parent_fd)

            for (parent_parts, quarantine_directory), group in quarantine_groups.items():
                identity = group["identity"]
                if identity is None:
                    continue
                parent_fd = _open_directory_beneath(root_fd, parent_parts)
                quarantine_fd = -1
                try:
                    quarantine_fd = os.open(
                        quarantine_directory,
                        root_flags,
                        dir_fd=parent_fd,
                    )
                    info = os.fstat(quarantine_fd)
                    if (info.st_dev, info.st_ino) != identity:
                        raise RuntimeError(
                            "instruction quarantine parent identity changed"
                        )
                    with os.scandir(quarantine_fd) as iterator:
                        names = {entry.name for entry in iterator}
                    if names != cast(set[str], group["expected"]):
                        raise RuntimeError(
                            "instruction quarantine directory has extra entries"
                        )
                finally:
                    if quarantine_fd >= 0:
                        os.close(quarantine_fd)
                    os.close(parent_fd)

            budget = [_RECOVERY_QUARANTINE_ENTRY_LIMIT * 2]
            for item in reversed(prepared):
                if not item["quarantine_present"]:
                    continue
                entry = cast(dict[str, str], item["entry"])
                parent_fd = _open_directory_beneath(
                    root_fd, cast(tuple[str, ...], item["parent_parts"])
                )
                quarantine_fd = -1
                try:
                    parent_info = os.fstat(parent_fd)
                    if (parent_info.st_dev, parent_info.st_ino) != item["parent_identity"]:
                        raise RuntimeError(
                            "instruction quarantine original parent changed"
                        )
                    quarantine_fd = os.open(
                        cast(str, item["quarantine_directory"]),
                        root_flags,
                        dir_fd=parent_fd,
                    )
                    quarantine_info = os.fstat(quarantine_fd)
                    if (
                        quarantine_info.st_dev,
                        quarantine_info.st_ino,
                    ) != item["quarantine_identity"]:
                        raise RuntimeError(
                            "instruction quarantine parent identity changed"
                        )
                    quarantine_name = cast(str, item["quarantine_name"])
                    info = os.stat(
                        quarantine_name,
                        dir_fd=quarantine_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISLNK(info.st_mode)
                        or os.readlink(quarantine_name, dir_fd=quarantine_fd)
                        != entry["target"]
                    ):
                        raise RuntimeError(
                            "quarantined instruction link changed"
                        )
                    original_name = Path(entry["original"]).name
                    _remove_instruction_entry_at(parent_fd, original_name, budget)
                    os.rename(
                        quarantine_name,
                        original_name,
                        src_dir_fd=quarantine_fd,
                        dst_dir_fd=parent_fd,
                    )
                    os.fsync(quarantine_fd)
                    os.fsync(parent_fd)
                finally:
                    if quarantine_fd >= 0:
                        os.close(quarantine_fd)
                    os.close(parent_fd)

            for (parent_parts, quarantine_directory), group in sorted(
                quarantine_groups.items(),
                key=lambda item: -len(item[0][0]),
            ):
                if group["identity"] is None:
                    continue
                parent_fd = _open_directory_beneath(root_fd, parent_parts)
                try:
                    os.rmdir(quarantine_directory, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except FileNotFoundError:
                    pass
                finally:
                    os.close(parent_fd)
        finally:
            os.close(root_fd)
        try:
            self.journal_path.unlink()
        except FileNotFoundError:
            pass
        _fsync_directory(self.control_root)

    def _discover(self) -> list[Path]:
        found: list[Path] = []
        visited = 0
        for dirpath, dirnames, filenames in os.walk(
            self.workspace, topdown=True, followlinks=False
        ):
            visited += 1
            if visited > _RECOVERY_QUARANTINE_ENTRY_LIMIT:
                raise RuntimeError("recovery instruction traversal exceeds bounds")
            current = Path(dirpath)
            for name in (*_RECOVERY_INSTRUCTION_FILES, *_RECOVERY_INSTRUCTION_DIRECTORIES):
                if name not in filenames and name not in dirnames:
                    continue
                path = current / name
                try:
                    info = os.stat(path, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(info.st_mode):
                    found.append(path)
                    if len(found) > _RECOVERY_QUARANTINE_ENTRY_LIMIT:
                        raise RuntimeError("recovery instruction symlink count exceeds bounds")
            dirnames[:] = [
                name for name in dirnames
                if name != "runtime"
                and not name.startswith(_RECOVERY_QUARANTINE_PREFIX)
                and name not in _RECOVERY_INSTRUCTION_DIRECTORIES
                and not (current / name).is_symlink()
            ]
        return sorted(found, key=str)

    def enter(self, *, quarantine: bool = True) -> None:
        lock_path = self.control_root / "instruction-quarantine.lock"
        self.lock_fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        orphaned = self._load_journal()
        if orphaned:
            self._restore(orphaned)
        if not quarantine:
            return
        symlinks = self._discover()
        if not symlinks:
            return
        grouped: dict[Path, Path] = {}
        entries: list[dict[str, str]] = []
        for index, original in enumerate(symlinks):
            quarantine_parent = grouped.get(original.parent)
            if quarantine_parent is None:
                quarantine_parent = original.parent / (
                    _RECOVERY_QUARANTINE_PREFIX + uuid.uuid4().hex
                )
                quarantine_parent.mkdir(mode=0o700)
                _fsync_directory(original.parent)
                grouped[original.parent] = quarantine_parent
            quarantine = quarantine_parent / f"entry-{index}"
            entries.append({
                "original": original.relative_to(self.workspace).as_posix(),
                "quarantine": quarantine.relative_to(self.workspace).as_posix(),
                "target": os.readlink(original),
            })
        self.entries = entries
        self._write_journal()
        for entry in self.entries:
            original = _lexical_workspace_path(self.workspace, entry["original"])
            quarantine = _lexical_workspace_path(self.workspace, entry["quarantine"])
            os.rename(original, quarantine)
            _fsync_directory(original.parent)
            if quarantine.parent != original.parent:
                _fsync_directory(quarantine.parent)

    def close(self) -> None:
        try:
            if self.entries:
                self._restore(self.entries)
                self.entries = []
        finally:
            if self.lock_fd >= 0:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                os.close(self.lock_fd)
                self.lock_fd = -1


def _recovery_instruction_masks(
    run_cwd: Path,
    agent_workspace: Path,
) -> tuple[list[Path], list[Path], tuple[str, ...]]:
    """Mask every model-writable startup-instruction source on the cwd ancestry."""

    if not _is_relative_to(run_cwd, agent_workspace):
        raise RuntimeError("recovery cwd is outside its controlled workspace")
    file_paths: set[Path] = set()
    directory_paths: set[Path] = set()
    relatives: set[str] = set()

    def mask_file(path: Path) -> None:
        relatives.add(path.relative_to(agent_workspace).as_posix())
        try:
            info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            file_paths.add(path)
            return
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("recovery instruction symlink was not quarantined")
        if stat.S_ISREG(info.st_mode):
            file_paths.add(path)
        elif stat.S_ISDIR(info.st_mode):
            directory_paths.add(path)

    def mask_directory(path: Path) -> None:
        relatives.add(path.relative_to(agent_workspace).as_posix())
        try:
            info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            directory_paths.add(path)
            return
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("recovery instruction symlink was not quarantined")
        if stat.S_ISDIR(info.st_mode):
            directory_paths.add(path)
        else:
            file_paths.add(path)

    visited_directories = 0
    for dirpath, dirnames, _filenames in os.walk(
        agent_workspace,
        topdown=True,
        followlinks=False,
    ):
        visited_directories += 1
        if visited_directories > 4_096:
            raise RuntimeError("recovery instruction-source traversal exceeds bounds")
        current = Path(dirpath)
        quarantine_names = [
            name for name in dirnames
            if name.startswith(_RECOVERY_QUARANTINE_PREFIX)
        ]
        for name in quarantine_names:
            path = current / name
            relatives.add(path.relative_to(agent_workspace).as_posix())
            directory_paths.add(path)
        for name in _RECOVERY_INSTRUCTION_FILES:
            mask_file(current / name)
        for name in _RECOVERY_INSTRUCTION_DIRECTORIES:
            mask_directory(current / name)
        dirnames[:] = [
            name for name in dirnames
            if name != "runtime"
            and not name.startswith(_RECOVERY_QUARANTINE_PREFIX)
            and name not in _RECOVERY_INSTRUCTION_DIRECTORIES
            and not (current / name).is_symlink()
        ]
    return (
        sorted(file_paths, key=str),
        sorted(directory_paths, key=str),
        tuple(sorted(relatives)),
    )


# /usr/share credential-surface scan (ELITE-2 verdict round-5/7).
# These trees are mostly NON-secret package data (locale, zoneinfo, glibc
# shared data) that the candidate's interpreter needs at runtime — a wholesale
# --tmpfs would break the sandbox.  We shadow only credential-bearing FILES
# with /dev/null so the candidate cannot read them while keeping the rest of
# the tree usable.  (round-5: filename-based hits.  round-7: filename-only has
# a blind spot — a benignly-named config file like config.json with an embedded
# API key is NOT caught by extension/name hits and stays readable.  Extend the
# pass to also scan the *content* of small config-like files for credential
# fingerprints and shadow them too, bounded to small files + a bounded read.)
_USR_SHARE_CRED_EXTS = (".pem", ".key", ".p12", ".pfx", ".crt", ".csr")
_USR_SHARE_CRED_NAME_HITS = ("credential", "secret", "_key", "id_rsa",
                             "id_ecdsa", "id_ed25519")
_USR_SHARE_CFG_EXTS = (".json", ".conf", ".yaml", ".yml", ".env",
                      ".ini", ".toml", ".cfg", ".properties", ".config")
_USR_SHARE_CRED_PATTERNS = (
    b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY", b"BEGIN PRIVATE KEY",
    b"sk-ant-", b"sk-live-", b"xoxb-", b"ghp_", b"gho_",
    b"api_key", b"apikey", b"api-key", b"secret_key", b"access_key",
    b"private_key", b"client_secret", b"refresh_token",
    b"-----BEGIN", b"aws_secret_access_key",
)
_USR_SHARE_SCAN_MAX_BYTES = 16384
_USR_SHARE_FILE_MAX_SIZE = 262144  # 256 KiB
_USR_SHARE_SKIP_DIRS = frozenset({
    "locale", "zoneinfo", "doc", "man", "info", "fonts", "icons", "mime",
    "applications", "bash-completion", "tabset", "i18n", "dict",
})


def _find_usr_share_credential_files(root: Path) -> list[Path]:
    """Return the credential-bearing files under a /usr/share(-local) tree.

    A file is shadowed when (a) its name matches a credential extension or
    spelling hit, OR (b) it is a small config-like file whose content carries
    a credential fingerprint.  Symlinks are skipped.  The walk skips the huge
    non-credential data trees (locale/zoneinfo/doc/...) so we do not stat tens
    of thousands of files.  OSError during traversal yields an empty result
    rather than aborting sandbox construction.
    """
    hits: list[Path] = []
    if not root.is_dir():
        return hits
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in _USR_SHARE_SKIP_DIRS
                           and not d.startswith(".")]
            for fn in filenames:
                low = fn.lower()
                cred_file = Path(dirpath) / fn
                if not cred_file.is_file() or cred_file.is_symlink():
                    continue
                filename_hit = (low.endswith(_USR_SHARE_CRED_EXTS)
                                or any(h in low for h in _USR_SHARE_CRED_NAME_HITS))
                if filename_hit:
                    hits.append(cred_file)
                    continue
                if not low.endswith(_USR_SHARE_CFG_EXTS):
                    continue
                try:
                    if cred_file.stat().st_size > _USR_SHARE_FILE_MAX_SIZE:
                        continue
                    with open(cred_file, "rb") as cf:
                        blob = cf.read(_USR_SHARE_SCAN_MAX_BYTES)
                except OSError:
                    continue
                if any(p in blob for p in _USR_SHARE_CRED_PATTERNS):
                    hits.append(cred_file)
    except OSError:
        pass
    return hits


def _bwrap_parent_dirs(path: Path) -> list[str]:
    """Create destination parents inside a bubblewrap sandbox before bind-mounting."""
    dirs: list[str] = []
    cur = path.resolve().parent
    for parent in reversed(cur.parents):
        if str(parent) == "/":
            continue
        dirs.extend(["--dir", str(parent)])
    dirs.extend(["--dir", str(cur)])
    return dirs


def _bwrap_ro_bind(cmd: list[str], source: Path, dest: Path | None = None) -> None:
    source = source.expanduser().resolve()
    if not source.exists():
        return
    # Preserve an explicit lexical destination. Resolving it on the host loses
    # version-selector paths such as uv's cpython-3.11-linux-* symlink, while a
    # sandbox may need that exact path as an interpreter's absolute link target.
    dest = source if dest is None else Path(os.path.abspath(dest.expanduser()))
    cmd.extend(_bwrap_parent_dirs(dest))
    cmd.extend(["--ro-bind", str(source), str(dest)])


def _bwrap_python_runtime(cmd: list[str]) -> None:
    """Expose a managed interpreter's stdlib/shared library, not its install root."""
    base = Path(sys.base_prefix).resolve()
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    if stdlib.is_relative_to(Path("/usr")) or not stdlib.is_relative_to(base):
        return
    library_dir = Path(sysconfig.get_config_var("LIBDIR") or base / "lib").resolve()
    name = sysconfig.get_config_var("INSTSONAME") or sysconfig.get_config_var("LDLIBRARY")
    if not isinstance(name, str) or Path(name).name != name or not name.startswith("libpython"):
        return
    library = library_dir / name
    if not stdlib.is_dir() or not library.is_file() or not library_dir.is_relative_to(base):
        return
    if not library.resolve().is_relative_to(library_dir):
        return
    _bwrap_ro_bind(cmd, stdlib)
    global_packages = stdlib / "site-packages"
    if global_packages.is_dir():
        cmd.extend(["--tmpfs", str(global_packages)])
    _bwrap_ro_bind(cmd, library, library)
    # Never retain the host's loader search path. This value is derived from
    # the running interpreter and contains only the pinned library/stdlib view.
    cmd.extend(["--setenv", "LD_LIBRARY_PATH", str(library_dir)])


def _bwrap_bind(cmd: list[str], source: Path, dest: Path | None = None) -> None:
    source = source.expanduser().resolve()
    if not source.exists():
        return
    dest = (dest or source).expanduser().resolve()
    cmd.extend(_bwrap_parent_dirs(dest))
    cmd.extend(["--bind", str(source), str(dest)])


def _extract_mcp_config_paths(args: list[str]) -> list[Path]:
    paths: list[Path] = []
    for idx, arg in enumerate(args):
        if arg == "--mcp-config" and idx + 1 < len(args):
            paths.append(Path(args[idx + 1]))
    return paths


def _mcp_config_env_values(args: list[str], name: str) -> list[str]:
    values: list[str] = []
    for config_path in _extract_mcp_config_paths(args):
        try:
            data = json.loads(config_path.expanduser().read_text())
        except (OSError, json.JSONDecodeError):
            continue
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            continue
        for spec in servers.values():
            if not isinstance(spec, dict):
                continue
            server_env = spec.get("env")
            if not isinstance(server_env, dict):
                continue
            value = server_env.get(name)
            if isinstance(value, str) and value:
                values.append(value)
    return values


def _editable_python_roots(python_path: str | None) -> list[Path]:
    """Return local editable source roots needed by a venv Python.

    Some MCP dependencies (notably ``ida-pro-mcp`` in developer installs) are
    installed editable, so the venv's ``site-packages`` contains a ``.pth`` file
    pointing at a source checkout such as ``/tmp/ida-pro-mcp/src``. A bwrap
    tmpfs over ``/tmp`` hides that checkout unless we bind it explicitly.
    """
    if not python_path:
        return []
    # Do not resolve the interpreter before deriving the venv root: repo-local
    # venv Python binaries may be symlinks to a managed interpreter, and resolving
    # them loses the venv-local site-packages that contains editable ``.pth`` files.
    py = Path(python_path).expanduser()
    roots: list[Path] = []
    seen: set[Path] = set()
    candidates: list[Path] = []
    if py.exists():
        venv = py.parent.parent if py.parent.name in {"bin", "Scripts"} else py.parent
        candidates.extend((venv / "lib").glob("python*/site-packages"))
        candidates.append(venv / "Lib" / "site-packages")
    for site_packages in candidates:
        if not site_packages.is_dir():
            continue
        for pth in sorted(site_packages.glob("*.pth")):
            try:
                lines = pth.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                entry = line.strip()
                if not entry or entry.startswith("#") or entry.startswith("import "):
                    continue
                src = Path(entry).expanduser()
                if not src.is_absolute():
                    src = (site_packages / src)
                try:
                    src = src.resolve()
                except OSError:
                    continue
                if not src.exists():
                    continue
                # Editable packages commonly point to ``repo/src``. Bind the
                # repo root when obvious so metadata/direct-url checks that
                # reference the parent path also work inside the sandbox.
                root = src.parent if src.name == "src" and (src.parent / "pyproject.toml").exists() else src
                if root not in seen:
                    seen.add(root)
                    roots.append(root)
    return roots


def _workspace_sandbox_command(
    args: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    network_fds: tuple[int, ...] = (),
    auth_seed_fds: dict[str, int] | None = None,
    trusted_input_fds: tuple[int, ...] = (),
    recovery_seed_fd: int | None = None,
    recovery_seed_size: int = 0,
    recovery_seed_sha256: str = "",
) -> list[str]:
    """Wrap an agent command in an OS filesystem sandbox when enabled.

    The agent still runs with its normal CLI flags (including Claude Code's
    ``--dangerously-skip-permissions``), but the process tree only sees:
    * system/runtime directories read-only,
    * the Angerona repo read-only with ``workspaces/`` replaced by an empty tmpfs,
    * the current run/worker workspace writable,
    * the target binary and MCP config files read-only.
    """
    isolation_required = _truthy(
        env.get("ANGERONA_REQUIRE_AGENT_FS_SANDBOX"), default=False
    )
    recovery_active = _truthy(
        env.get("ANGERONA_CONTEXT_RECOVERY_ACTIVE"), default=False
    )
    if not _truthy(env.get("ANGERONA_AGENT_FS_SANDBOX"), default=True):
        env["ANGERONA_AGENT_FS_SANDBOX_ACTIVE"] = "0"
        if isolation_required or recovery_active:
            raise RuntimeError(
                "context recovery filesystem sandbox is disabled"
            )
        return args
    bwrap = shutil.which("bwrap")
    if not bwrap:
        env["ANGERONA_AGENT_FS_SANDBOX_ACTIVE"] = "0"
        env["ANGERONA_AGENT_FS_SANDBOX_REASON"] = "bwrap not found"
        if isolation_required or recovery_active:
            raise RuntimeError(
                "context recovery filesystem sandbox is unavailable: bwrap not found"
            )
        return args

    run_cwd = Path(cwd).expanduser().resolve()
    provider_args = list(args)
    provider_executable: Path | None = None
    provider_companion_executables: list[Path] = []
    sandbox_provider_executable = Path("/tmp/angerona-provider/executable")
    if isolation_required:
        executable_value = provider_args[0] if provider_args else ""
        resolved_value = (
            shutil.which(executable_value, path=env.get("PATH"))
            if executable_value and os.sep not in executable_value
            else executable_value
        )
        try:
            provider_executable = Path(resolved_value or "").expanduser().resolve(strict=True)
            executable_info = provider_executable.stat()
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(
                "required K-candidate provider executable is unavailable"
            ) from exc
        if not stat.S_ISREG(executable_info.st_mode) or not os.access(
            provider_executable, os.X_OK
        ):
            raise RuntimeError("required K-candidate provider executable is unsafe")
        if provider_executable.name == "codex":
            code_mode_host = provider_executable.parent / "codex-code-mode-host"
            try:
                host_info = code_mode_host.stat(follow_symlinks=False)
            except OSError:
                host_info = None
            if (
                host_info is not None
                and stat.S_ISREG(host_info.st_mode)
                and os.access(code_mode_host, os.X_OK)
            ):
                # Current standalone Codex resolves its tool host beside argv[0].
                # Mount only that verified executable, never the surrounding
                # package/config tree.
                provider_companion_executables.append(code_mode_host)
        provider_args[0] = str(sandbox_provider_executable)
    agent_workspace = Path(env.get("ANGERONA_AGENT_WORKSPACE_ROOT") or run_cwd).expanduser().resolve()
    instruction_file_masks: list[Path] = []
    instruction_directory_masks: list[Path] = []
    instruction_mask_relatives: tuple[str, ...] = ()
    if recovery_active:
        (
            instruction_file_masks,
            instruction_directory_masks,
            instruction_mask_relatives,
        ) = _recovery_instruction_masks(run_cwd, agent_workspace)
    target_binary = env.get("ANGERONA_TARGET_BINARY") or env.get("ANGERONA_ALLOWED_INPUT_BINARY")
    host_home = Path(env.get("HOME") or str(Path.home())).expanduser().resolve()
    runtime_root = agent_workspace / "runtime"
    runtime_home = runtime_root / "home"
    runtime_claude = runtime_home / ".claude"
    workspace_claude = runtime_root / ".claude"
    workspace_cache = runtime_root / ".cache"
    workspace_config = runtime_root / ".config"
    workspace_data = runtime_root / ".local" / "share"
    workspace_idapro = runtime_root / ".idapro"
    mount_runtime_home = runtime_home
    mount_runtime_claude = runtime_claude
    if isolation_required:
        mount_runtime_home = Path("/tmp/angerona-workspace/runtime/home")
        mount_runtime_claude = mount_runtime_home / ".claude"
    if not isolation_required:
        for d in (
            workspace_claude / "session-env",
            workspace_claude / "shell-snapshots",
            workspace_claude / "cache",
            workspace_claude / "jobs",
            workspace_claude / "plugins",
            workspace_claude / "todos",
            workspace_claude / "projects",
            workspace_cache,
            workspace_config,
            workspace_data,
            workspace_idapro / ".cache",
            workspace_idapro / "mcp",
        ):
            d.mkdir(parents=True, exist_ok=True)

    export_socket = ""
    reconstruction_relative = ""
    seed_usage = None
    scratch_input = Path("/tmp/angerona-candidate-seed")
    scratch_export = Path("/tmp/angerona-export-channel/export.sock")
    auth_seed_fds = auth_seed_fds or {}
    if isolation_required:
        if not network_fds or any(fd < 3 for fd in network_fds):
            # Fail-closed: K-candidate sandbox REQUIRES a network broker when isolation
            # is required.  Without one we refuse the launch outright rather than
            # degrading into an un-sandboxed execution.  (ELITE-2 wave-11/12
            # pointed out the silent-fallback; process otherwise launches with
            # all isolation policies as no-ops.)
            raise RuntimeError("required K-candidate network broker is unavailable")
        try:
            export_socket = str(Path(env["ANGERONA_SCRATCH_EXPORT_SOCKET"]).resolve())
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("required K-candidate scratch export channel is missing") from exc
        try:
            channel_info = os.stat(export_socket, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("required K-candidate scratch export channel is unavailable") from exc
        if not stat.S_ISSOCK(channel_info.st_mode):
            raise RuntimeError("required K-candidate scratch export channel is invalid")
        reconstruction_relative = str(
            env.get("ANGERONA_SCRATCH_RECONSTRUCTION_RELATIVE")
            or reconstruction_authority(run_cwd)
        )
        # Cross-run isolation (ELITE-2 verdict round-6 at runtime.py:2234):
        # the agent_workspace seed ro-bind re-exposes prior-run runtime/.claude/
        # state (session-env, shell-snapshots, etc.) and runtime/home.  Exclude
        # those trees from BOTH the baseline measurement (bounded_tree_usage,
        # host-side) and the scratch_quota _copy_seed (same excluded set passed
        # via --instruction-mask-relative) so the seed identity check does not
        # desync when the tmpfs masks below shadow them inside the namespace.
        _workspace_state_mask_relatives: tuple[str, ...] = ()
        for state_sub in _WORKSPACE_CLAUDE_STATE_DIRS:
            state_host = runtime_root / ".claude" / state_sub
            if state_host.exists():
                _workspace_state_mask_relatives += (
                    f"runtime/.claude/{state_sub}",
                )
        runtime_home_host = runtime_root / "home"
        if runtime_home_host.exists():
            _workspace_state_mask_relatives += ("runtime/home",)
        _all_mask_relatives = instruction_mask_relatives + _workspace_state_mask_relatives
        seed_usage = (
            bounded_tree_usage(
                agent_workspace,
                excluded_paths=_all_mask_relatives,
            )
            if _all_mask_relatives
            else bounded_tree_usage(agent_workspace)
        )
        if _CANDIDATE_SCRATCH_WRITE_BYTES <= 0:
            raise RuntimeError("candidate scratch byte quota is invalid")

    cmd = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-ipc",
        "--unshare-pid",
        "--as-pid-1",
        "--cap-drop", "ALL",
        "--proc", "/proc",
    ]
    if isolation_required:
        # --unshare-net gives the K-candidate a fresh, empty network namespace.
        # This ALSO empties /proc/net/* (tcp, route, etc.) so the candidate
        # cannot fingerprint host listening sockets, docker bridges, or the
        # routing table via /proc/net.  (ELITE-2 verdict round-2: the verdict
        # worried that --proc /proc exposes /proc/net — --unshare-net already
        # closes that, since /proc/net is namespace-scoped.)
        cmd.append("--unshare-net")
        cmd.extend([
            "--dir", "/dev",
            "--dev-bind", "/dev/null", "/dev/null",
            "--dev-bind", "/dev/zero", "/dev/zero",
            "--dev-bind", "/dev/random", "/dev/random",
            "--dev-bind", "/dev/urandom", "/dev/urandom",
            "--symlink", "/proc/self/fd", "/dev/fd",
            "--symlink", "/proc/self/fd/0", "/dev/stdin",
            "--symlink", "/proc/self/fd/1", "/dev/stdout",
            "--symlink", "/proc/self/fd/2", "/dev/stderr",
            # Bound /run like /tmp and /dev/shm so a candidate cannot fill it
            # up to the cgroup memory ceiling (scratch_quota only monitors /tmp).
            # (ELITE-2 verdict round-3 fix: /run had no --size bound.)
            "--size", str(_CANDIDATE_SCRATCH_WRITE_BYTES), "--tmpfs", "/run",
        ])
    else:
        # Bound /tmp on the non-isolation path too: bwrap --tmpfs defaults to
        # the kernel tmpfs ceiling (~50% of host RAM), so an unbounded /tmp
        # lets a trusted-provider candidate exhaust host RAM / induce OOM.
        # The isolation path bounds /tmp via scratch_bytes (above); apply the
        # same default ceiling here so the default path is not unbounded.
        # (ELITE-2 verdict round-7 fix: non-isolation /tmp had no --size.)
        cmd.extend([
            "--dev", "/dev",
            "--size", str(_CANDIDATE_SCRATCH_WRITE_BYTES), "--tmpfs", "/tmp",
        ])
        # Mask /proc/net on the non-isolation path so the candidate cannot
        # fingerprint host listening sockets, the routing table, or unix
        # socket inodes via /proc/net/{tcp,udp,route,unix,...}.  The isolation
        # path closes this via --unshare-net (a fresh net namespace empties
        # /proc/net/*); the non-isolation path shares the host net namespace,
        # so /proc/net is live.  Mount an empty tmpfs over /proc/net so every
        # file under it reads as empty (bwrap --tmpfs over a procfs subdir
        # works; per-file /dev/null shadowing does not because procfs net
        # files are generated on read and the source does not pre-exist).
        # This extends the F1-unconditional principle to net-ns visibility.
        # (ELITE-2 verdict round-7 fix: /proc/net fingerprinting.)
        cmd.extend(["--tmpfs", "/proc/net"])

    system_dirs = ["/usr", "/bin", "/lib", "/lib64"]
    if not isolation_required:
        # Non-isolation (trusted-provider) path: the candidate is not hostile
        # in this mode, BUT the F1-unconditional rationale applies — a security
        # control gated on the opt-in flag is off by default.  /opt and /run
        # are therefore NOT wholesale ro-bound here either; /opt is bound via
        # the same narrow subdir allowlist as the isolation path (only the
        # bare-binary bin/lib dirs the candidate's toolchain needs), and /run
        # is a size-bounded tmpfs (a wholesale /run ro-bind would re-expose
        # host docker.sock / postgres / redis / systemd-private sockets and
        # secrets).  (ELITE-2 verdict round-5 fix: the non-isolation path
        # previously wholesale-bound /opt and /run, inconsistent with the
        # F1-unconditional and /etc-default-deny fixes on the same path.)
        for opt_subdir in ("/opt/bin", "/opt/lib", "/opt/lib64"):
            p = Path(opt_subdir)
            if p.is_dir():
                cmd.extend(["--ro-bind", str(p), str(p)])
        cmd.extend([
            "--size", str(_CANDIDATE_SCRATCH_WRITE_BYTES), "--tmpfs", "/run",
        ])
    else:
        # K-candidate isolation path: /opt commonly holds IDA/Ghidra/conda
        # install trees with license files.  Do NOT wholesale ro-bind /opt
        # here — bind only the specific /opt subdirs the candidate needs
        # (read-only).  This avoids exposing third-party tool
        # license/credential surfaces.  (ELITE-2 verdict round-2/3 fix.)
        for opt_subdir in ("/opt/bin", "/opt/lib", "/opt/lib64"):
            p = Path(opt_subdir)
            if p.is_dir():
                cmd.extend(["--ro-bind", str(p), str(p)])
    # /etc DEFAULT-DENY for BOTH paths: mount an empty tmpfs over /etc, then
    # ro-bind back ONLY the files/dirs the candidate needs (name service, CA
    # certs, SSL certs, passwd/group).  Every credential/fingerprint surface
    # (kubernetes admin.conf, letsencrypt privkey.pem, wireguard, krb5.keytab,
    # shadow, ssh host keys, docker, apt auth tokens) is absent by default —
    # no per-name shadowing allowlist to drift.  (ELITE-2 verdict round-3/4
    # fix: applied to both isolation AND non-isolation paths; previously the
    # non-isolation path wholesale-bound /etc.)
    etc_keep_files = (
        "passwd", "group", "nsswitch.conf", "gai.conf",
        "protocols", "services", "rpc", "ethertypes",
        "ssl/certs/ca-certificates.crt", "ssl/certs/ca-certificates.crt.r1",
        "ca-certificates.crt",
    )
    etc_keep_dirs = ("ssl/certs",)
    cmd.extend(["--tmpfs", "/etc"])
    for rel in etc_keep_files:
        host_file = Path("/etc") / rel
        if host_file.exists() and host_file.is_file() and not host_file.is_symlink():
            sandbox_file = Path("/etc") / rel
            cmd.extend(_bwrap_parent_dirs(sandbox_file))
            cmd.extend(["--ro-bind", str(host_file), str(sandbox_file)])
    for rel in etc_keep_dirs:
        host_dir = Path("/etc") / rel
        if host_dir.is_dir():
            sandbox_dir = Path("/etc") / rel
            cmd.extend(_bwrap_parent_dirs(sandbox_dir))
            cmd.extend(["--ro-bind", str(host_dir), str(sandbox_dir)])
    for system_dir in system_dirs:
        p = Path(system_dir)
        if p.exists():
            cmd.extend(["--ro-bind", str(p), str(p)])
    # /usr credential-surface mask (ELITE-2 verdict round-5 fix): the
    # unconditional --ro-bind /usr /usr above re-exposes /usr/local/etc,
    # /usr/share, /usr/local/share read-only on BOTH sandbox paths, defeating
    # the /etc default-deny for any credential surface the host mirrors under
    # /usr (OSTree /usr/etc shadow+ssh-host-keys+kubernetes-admin.conf, plus
    # /usr/local/etc credential mirrors and /usr/share snakeoil .pem/.key +
    # service confs).  A later mount over the same path WINS in bwrap's mount
    # ordering, so mask each /usr credential-bearing subpath after the
    # wholesale ro-bind.  This runs on BOTH isolation and non-isolation paths
    # — the /etc default-deny rationale (a security control gated on the
    # opt-in flag is off by default) applies identically to the parallel /usr
    # credential tree.  (The round-4 fix masked /usr/etc only in the isolation
    # path; round-5 removes the guard and adds /usr/local/etc + the /usr/share
    # + /usr/local/share credential-file shadow pass.)
    for usr_cred_subpath in ("/usr/etc", "/usr/local/etc"):
        usr_cred = Path(usr_cred_subpath)
        if usr_cred.is_dir():
            cmd.extend(_bwrap_parent_dirs(usr_cred))
            cmd.extend(["--tmpfs", str(usr_cred)])
    # /usr/share and /usr/local/share are mostly NON-secret package data
    # (locale, zoneinfo, glibc shared data) that the candidate's interpreter
    # needs at runtime — a wholesale --tmpfs would break the sandbox.  Instead
    # shadow only the credential-bearing FILES under them (snakeoil
    # .pem/.key/.p12 certs, service confs with embedded secrets) with /dev/null
    # so the candidate cannot read them, while keeping the rest of the tree
    # usable.  Bwrap --ro-bind /dev/null over a file shadows it read-only.
    # (ELITE-2 verdict round-5 fix: the verdict confirmed /usr/share on this
    # host contains snakeoil .pem/.key and service confs re-exposed by the
    # wholesale --ro-bind /usr /usr.)
    credential_parent_dirs: set[str] = set()
    for usr_share_root in ("/usr/share", "/usr/local/share"):
        root = Path(usr_share_root)
        if not root.is_dir():
            continue
        for cred_file in _find_usr_share_credential_files(root):
            parents = _bwrap_parent_dirs(cred_file)
            for index in range(0, len(parents), 2):
                parent = parents[index + 1]
                if parent not in credential_parent_dirs:
                    cmd.extend(["--dir", parent])
                    credential_parent_dirs.add(parent)
            cmd.extend(["--ro-bind", "/dev/null", str(cred_file)])
    # In the K-candidate isolation path, host-home toolchain dirs are NOT bound:
    # they can carry credential files (.npmrc tokens, cargo credentials.toml,
    # solana id.json wallets) that a hostile candidate must not read.  The
    # candidate runs from its own scratch and does not need the host's
    # npm/cargo/solana toolchain.  (ELITE-2 verdict fix: support-bind loop was
    # unconditioned and leaked host toolchain credentials.)
    support_dirs: list[Path] = []
    if not isolation_required:
        support_dirs.extend([
            host_home / ".npm-global",
            host_home / ".cargo" / "bin",
            host_home / ".avm",
            host_home / ".local" / "bin",
            host_home / ".local" / "share" / "solana",
            host_home / ".local" / "share" / "uv" / "python",
        ])
    else:
        # K-candidate: bind ONLY the bare-binary bin dirs, not the
        # credential-bearing share/home dirs.  cargo/bin and .local/bin are
        # binary-only; .npm-global, .avm, solana, and uv/python are NOT bound.
        support_dirs.extend([
            host_home / ".cargo" / "bin",
            host_home / ".local" / "bin",
        ])
    for support in support_dirs:
        _bwrap_ro_bind(cmd, support)
    # A repo venv may point at a uv-managed interpreter through an absolute,
    # version-selector symlink. HOME can be intentionally replaced in tests and
    # required sandboxes, so mount the distribution parent that contains both
    # the version-selector link and its concrete interpreter directory.
    python_executable = Path(sys.executable).expanduser()
    sandbox_runner_python = python_executable
    try:
        python_real_executable = python_executable.resolve(strict=True)
        python_real_root = python_real_executable.parent.parent
    except OSError:
        python_real_executable = None
        python_real_root = None
    if python_real_root is not None:
        # Bind the *distribution parent* so a uv version-selector symlink and its
        # concrete interpreter dir are both visible. But never bind an ancestor
        # that would re-expose host secret surfaces. When the interpreter lives
        # under /usr (the common case), the parent is "/" and --ro-bind / / would
        # re-expose the entire host root. When it lives under a venv inside /home
        # (e.g. /home/ubuntu/.local/share/uv/python/cpython-3.11.../bin/python),
        # the distribution parent is /home/ubuntu — binding that read-only would
        # re-expose ~/.ssh, ~/.gnupg, ~/.aws and all host-home credentials,
        # defeating the support_dirs allowlist below. /usr, /lib, /lib64, /bin,
        # /opt, /etc are already mounted individually above; the host-home
        # tree must never be wholesale re-bound.
        # (ELITE-2 verdict round-2 fix: the `!= Path("/")` guard was too narrow
        #  and leaked the entire host home for venv/uv deployments.)
        parent_to_bind = python_real_root.parent
        def _safe_python_parent(path: Path) -> bool:
            # Never bind "/" or any ancestor of the host home directory, since
            # that would re-expose host-home credential surfaces read-only.
            # Also never bind a top-level system directory ("/opt", "/usr",
            # "/var", "/srv", "/mnt") as a wholesale parent — these carry
            # third-party tool license/credential trees (/opt/conda,
            # /opt/ida) that the verdict round-3 confirmed leak.  Only narrow
            # leaf subdirs of /opt are intentionally bound above.
            # (ELITE-2 verdict round-3 fix: _safe_python_parent rejected "/"
            #  and host-home but NOT /opt, so a /opt/conda interpreter
            #  re-wholesale-bound /opt.  Also extended to editable roots below
            #  where the same guard was previously dropped.)
            if path == Path("/"):
                return False
            if host_home is not None:
                try:
                    path.resolve(strict=False).relative_to(host_home.resolve(strict=False))
                    return False  # path is inside/at host home -> would leak it
                except (ValueError, OSError):
                    pass
            try:
                top = path.resolve(strict=False).parts[1] if len(path.resolve(strict=False).parts) > 1 else ""
            except (ValueError, OSError):
                top = ""
            if top in {"opt", "var", "srv", "mnt", "media", "usr", "lib", "lib64", "bin", "sbin", "boot", "root"}:
                return False
            return True
        if _safe_python_parent(parent_to_bind):
            _bwrap_ro_bind(cmd, parent_to_bind)
        # uv's standalone CPython is built with /install as its base prefix.
        # Binding the exact interpreter as a required provider changes argv[0]
        # to /tmp/angerona-provider/executable, so expose its immutable runtime
        # at that compiled-in prefix as well.
        # (ELITE-2 verdict round-6 fix: the prior guard was only
        # ``python_real_root != Path("/usr")``, which let a python_real_root of
        # Path("/") through on a NON-usrmerge distro where sys.executable is
        # /bin/python3 (parent /bin, python_real_root = '/').  That wholesale
        # ro-bound the ENTIRE host root to /install with NO masking — a
        # --ro-bind / / leak by another name.  Apply the SAME _safe_python_parent
        # screening to python_real_root: if it is '/', a host-home ancestor,
        # or any top-level system dir, it is NOT safe to bind wholesale and we
        # skip the /install bind — the interpreter tree under /usr is already
        # bound wholesale at line ~1996, and /bin/lib/lib64 are in system_dirs.)
        uv_runtime = (
            python_real_executable is not None
            and python_real_executable.parent == python_real_root / "bin"
            and python_real_root.name.startswith("cpython-")
            and python_real_root.parent.name == "python"
            and python_real_root.parent.parent.name == "uv"
            and python_real_root.parent.parent.parent.name == "share"
            and python_real_root.parent.parent.parent.parent.name == ".local"
        )
        if uv_runtime:
            # Bind only the immutable CPython distribution, never its uv cache
            # parent or the operator's home. The standalone build uses /install
            # as its compiled prefix, so this also makes stdlib and extension
            # modules available to the quota runner without exposing sibling
            # credentials under ~/.local/share.
            _bwrap_ro_bind(cmd, python_real_root, Path("/install"))
            sandbox_runner_python = Path("/install/bin") / python_real_executable.name
        elif python_real_root != Path("/usr") and _safe_python_parent(python_real_root):
            _bwrap_ro_bind(cmd, python_real_root, Path("/install"))
            # The distribution root is mounted at /install, so the quota runner's
            # argv[0] must use that same prefix. Leaving it at the host path
            # ENOENTs when python_real_root is a depth-2 dir (e.g. /tools/bin/
            # python3), whose parent "/" is never bound above.
            sandbox_runner_python = Path("/install/bin") / python_real_executable.name
    _bwrap_python_runtime(cmd)
    editable_python_paths = [env.get("ANGERONA_IDA_MCP_PYTHON")]
    editable_python_paths.extend(_mcp_config_env_values(args, "ANGERONA_IDA_MCP_PYTHON"))
    for python_path in editable_python_paths:
        for editable_root in _editable_python_roots(python_path):
            # Apply the SAME safety guard as the interpreter parent above: a
            # .pth-pointed editable root under /home or a top-level system
            # dir would re-bind host credential surfaces read-only.
            # (ELITE-2 verdict round-3 fix: this guard was dropped here.)
            if _safe_python_parent(editable_root):
                _bwrap_ro_bind(cmd, editable_root)

    # The MCP server needs Angerona source/vendor read-only, but old workspaces
    # must not be visible. Mount repo read-only, then hide workspaces with tmpfs,
    # then bind only the current run/worker workspace back in.
    _bwrap_ro_bind(cmd, _REPO_ROOT)
    workspaces = _REPO_ROOT / "workspaces"
    cmd.extend(_bwrap_parent_dirs(workspaces))
    cmd.extend(["--tmpfs", str(workspaces)])
    # Mask repo-level secret/credential surfaces so a K-candidate cannot read
    # them even though _REPO_ROOT is ro-bound.  Individual secret files are
    # shadowed with /dev/null (bwrap will not mount a file over a directory,
    # so directories are masked by shadowing their sensitive *files* rather
    # than the dir itself).  This includes the VCS credential surface
    # (.git/config can carry an embedded PAT), host auth/notes, and memory.
    # (ELITE-2 verdict fix.)
    #
    # KNOWN LIMITATION (kernel, not bwrap): /proc/self/mountinfo inside the
    # sandbox mount namespace reveals every bind-mount SOURCE as a host
    # absolute path AND shows which files were shadowed with /dev/null (the
    # /dev/null source appears in the mount table).  procfs special files
    # CANNOT be shadowed by bwrap bind mounts, --ro-bind-data, or tmpfs
    # overlays — the kernel always serves the live mount-namespace table.
    # This is a metadata leak (which host paths exist + which are masked),
    # NOT a content leak: the masked secrets themselves are unreadable
    # (the /dev/null bind makes open() fail with Permission denied).  A
    # candidate can fingerprint host layout but cannot read the secrets.
    # Closing this fully requires a landlock/LSM path deny on /proc/self/*
    # (Python landlock bindings are not available on this host); the
    # seccomp filter in scratch_quota.py denies mount/unshare but cannot
    # deny open-by-path (seccomp sees the path pointer, not the path).
    for secret_relpath in (
        ".git/config",
        ".git/credentials",
        ".git/credential-cache",
        "MEMORY.md",
        ".claude/.credentials.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        "RESEARCH_REPORT_SOTA.md",
        ".mcp.json",
    ):
        secret_path = _REPO_ROOT / secret_relpath
        if secret_path.exists():
            cmd.extend(["--ro-bind", "/dev/null", str(secret_path)])
    # Whole secret directories that contain ONLY non-source secrets get an
    # empty tmpfs so their full contents (and any future-added secrets) are
    # hidden, not just known files.  memory/ and the memory-doc mirror hold
    # operator notes and auto-memory files — no source the candidate needs.
    for secret_relpath in ("memory", "docs/codebase", ".claude/plans"):
        secret_path = _REPO_ROOT / secret_relpath
        if secret_path.is_dir():
            cmd.extend(_bwrap_parent_dirs(secret_path))
            cmd.extend(["--tmpfs", str(secret_path)])
    if isolation_required:
        assert seed_usage is not None
        scratch_bytes = max(
            1024 * 1024,
            seed_usage.allocated_bytes
            + _CANDIDATE_SCRATCH_WRITE_BYTES
            + max(0, recovery_seed_size),
        )
        cmd.extend(["--size", str(scratch_bytes), "--tmpfs", "/tmp"])
        workspace_dir = "/tmp/angerona-workspace"
        cmd.extend(["--dir", workspace_dir])
        # /dev/shm: use private tmpfs (size-bounded), not host bind.
        # Host bind made host /dev/shm visible+writable to the sandbox, which
        # breaks isolation boundaries.  A private /dev/shm (-tmpfs) is
        # constructed inside the sandbox, matches upstream expectations, and
        # is semantically clean (ELITE-2 wave-11).
        # (ELITE-2 verdict round-2: removed a duplicate --tmpfs /tmp directive
        #  leftover from the wave-11 edit — bwrap last-mount-wins made the
        #  first dead code; both used the identical scratch_bytes so quota
        #  behaviour was unchanged, but the duplicate misled reviewers.)
        cmd.extend(["--size", "33554432", "--tmpfs", "/dev/shm"])  # 32mb tmpfs cover
        cmd.extend(["--dir", "/dev/shm"])
        _bwrap_ro_bind(cmd, agent_workspace, scratch_input)
        # Mask agent_workspace-internal prior-run state that the ro-bind above
        # just re-exposed into the sandbox seed.  The seed path mounts the WHOLE
        # agent_workspace tree read-only, including the runtime/ subtree written
        # by prior runs (non-isolation runs persist runtime/.claude/session-env/,
        # runtime/.claude/shell-snapshots/, etc. on the host; these can carry
        # shell-snapshot env tokens and session state).  The _REPO_ROOT secret
        # masking above does NOT cover agent_workspace-internal paths.
        # bwrap is last-mount-wins, so a --tmpfs over the seed-side copy shadows
        # those state dirs inside the sandbox AND in the scratch_quota _copy_seed
        # view (the provider reads through the same mount namespace).  Empty
        # when the host dirs don't exist (isolation-only workspace, fresh tree).
        # (ELITE-2 verdict round-6 fix: cross-run isolation gap at runtime.py:2234.)
        for state_sub in _WORKSPACE_CLAUDE_STATE_DIRS:
            state_host = runtime_root / ".claude" / state_sub
            if state_host.exists():
                state_seed = scratch_input / "runtime" / ".claude" / state_sub
                cmd.extend(_bwrap_parent_dirs(state_seed))
                cmd.extend(["--tmpfs", str(state_seed)])
        # runtime/home can carry a planted/persisted credential surface from a
        # prior non-isolation run; mask the whole tree when it exists on the host.
        runtime_home_host = runtime_root / "home"
        if runtime_home_host.exists():
            runtime_home_seed = scratch_input / "runtime" / "home"
            cmd.extend(_bwrap_parent_dirs(runtime_home_seed))
            cmd.extend(["--tmpfs", str(runtime_home_seed)])
        # Narrow the export-socket bind (ELITE-2 verdict round-6 fix at
        # runtime.py:2235).  The prior code --ro-bound the WHOLE host mkdtemp
        # parent dir, leaking its directory listing and any sibling-file
        # metadata to the same-uid candidate (mkdtemp default is 0700, which
        # does not protect against the owner).  bwrap cannot --ro-bind a Unix
        # socket file directly, so the parent must be bound — but we bind the
        # host mkdtemp dir to a private sandbox tmpfs dest (not the host path),
        # and the host dir itself is chmod 0o500 after socket creation (see
        # _stream_process_unobserved) so no sibling can be added in the
        # microsecond race window.  The candidate therefore sees only the clean
        # sandbox path /tmp/angerona-export-channel/export.sock, never the host
        # mkdtemp name, and the listing surface is a single 0o500 dir holding
        # exactly one 0o222 write-only socket.
        _bwrap_ro_bind(cmd, Path(export_socket).parent, scratch_export.parent)
        assert provider_executable is not None
        _bwrap_ro_bind(cmd, provider_executable, sandbox_provider_executable)
        for companion in provider_companion_executables:
            _bwrap_ro_bind(
                cmd,
                companion,
                sandbox_provider_executable.parent / companion.name,
            )
        cmd.extend(_bwrap_parent_dirs(agent_workspace))
        cmd.extend(["--symlink", "/tmp/angerona-workspace", str(agent_workspace)])
    else:
        _bwrap_bind(cmd, agent_workspace)

    # Give every agent a real writable HOME inside its current run/worker
    # workspace. Claude Code's Bash tool writes shell/session state under
    # ~/.claude; putting HOME in the workspace lets Bash, cache, snapshots, and
    # temp state work normally while the bwrap boundary still hides old runs and
    # host-home writable state.
    #
    # The visible HOME is a tmpfs inside the sandbox. We bind only non-secret,
    # per-run writable state directories from the workspace into it. Auth and
    # settings are exposed as narrow read-only mounts into tmpfs paths, so they
    # are usable by the CLI but do not get copied into run artifacts.
    cmd.extend(_bwrap_parent_dirs(mount_runtime_home))
    if isolation_required:
        cmd.extend(["--dir", str(mount_runtime_home)])
    else:
        cmd.extend(["--tmpfs", str(mount_runtime_home)])
    state_names = _WORKSPACE_CLAUDE_STATE_DIRS + (() if recovery_active else ("plugins", "projects"))
    if not recovery_active:
        state_names += ("plugins", "projects")
    if isolation_required:
        for state_name in state_names:
            cmd.extend(_bwrap_parent_dirs(mount_runtime_claude / state_name))
            cmd.extend(["--dir", str(mount_runtime_claude / state_name)])
        for directory in (
            mount_runtime_home / ".cache",
            mount_runtime_home / ".config",
            mount_runtime_home / ".local" / "share",
        ):
            cmd.extend(_bwrap_parent_dirs(directory))
            cmd.extend(["--dir", str(directory)])
    else:
        for state_name in state_names:
            _bwrap_bind(cmd, workspace_claude / state_name, mount_runtime_claude / state_name)
        _bwrap_bind(cmd, workspace_cache, mount_runtime_home / ".cache")
        _bwrap_bind(cmd, workspace_config, mount_runtime_home / ".config")
        _bwrap_bind(cmd, workspace_data, mount_runtime_home / ".local" / "share")

    host_claude = host_home / ".claude"
    if host_claude.exists():
        if isolation_required:
            # Required candidates receive bounded snapshots only as runner-owned
            # inherited FDs; raw host config paths never enter their mount namespace.
            pass
        else:
            for name in ("settings.json", "mcp-needs-auth-cache.json"):
                _bwrap_ro_bind(cmd, host_claude / name, mount_runtime_claude / name)
            _bwrap_ro_bind(
                cmd, host_claude / ".credentials.json",
                mount_runtime_claude / ".credentials.json",
            )
            for name in (".claude.json", ".credentials.json"):
                _bwrap_ro_bind(cmd, host_home / name, mount_runtime_home / name)
    host_codex = host_home / ".codex"
    if host_codex.exists():
        runtime_codex = mount_runtime_home / ".codex"
        if isolation_required:
            cmd.extend(_bwrap_parent_dirs(runtime_codex))
            cmd.extend(["--dir", str(runtime_codex)])
        else:
            runtime_codex.mkdir(parents=True, exist_ok=True)
        if isolation_required:
            pass
        else:
            for name in ("auth.json", "config.toml"):
                _bwrap_ro_bind(cmd, host_codex / name, runtime_codex / name)

    # IDA/idapro needs its per-user license/config/plugins under ~/.idapro even
    # when the worker HOME is isolated into the run workspace. Required
    # K-candidate isolation builds a fresh tmpfs view: approved top-level host
    # entries are mounted read-only and only cache/MCP state is candidate-local
    # and writable. Mounting the whole host tree read-only first is invalid:
    # bubblewrap cannot create the child mountpoints beneath that read-only bind.
    host_idapro = host_home / ".idapro"
    if host_idapro.exists():
        runtime_idapro = mount_runtime_home / ".idapro"
        if isolation_required:
            cmd.extend(_bwrap_parent_dirs(runtime_idapro))
            cmd.extend(["--dir", str(runtime_idapro)])
            # K-candidate isolation: narrow to a file WHITELIST rather than
            # ro-binding every non-.cache/non-mcp top-level entry (which
            # exposed subdirectories like plugins/ in full and any sensitive
            # config they carry).  Bind only the known IDA license/config
            # files the candidate needs; everything else stays hidden.  This
            # matches the narrow approach already used for host_claude and
            # host_codex.  (ELITE-2 verdict round-2 fix.)
            _IDA_NARROW_FILES = (
                "ida.reg", "ida.cfg", "idagui.cfg", "idausr.cfg",
                "idatui.cfg", "idauser.cfg", "hexrays.cfg",
            )
            for fname in _IDA_NARROW_FILES:
                entry = host_idapro / fname
                if entry.exists() and entry.is_file():
                    _bwrap_ro_bind(cmd, entry, runtime_idapro / entry.name)
            for directory in (runtime_idapro / ".cache", runtime_idapro / "mcp"):
                cmd.extend(_bwrap_parent_dirs(directory))
                cmd.extend(["--dir", str(directory)])
        else:
            _bwrap_bind(cmd, host_idapro, runtime_idapro)
            _bwrap_bind(cmd, workspace_idapro / ".cache", runtime_idapro / ".cache")
            _bwrap_bind(cmd, workspace_idapro / "mcp", runtime_idapro / "mcp")

    if target_binary:
        target = Path(target_binary).expanduser().resolve()
        if target.exists() and not _is_relative_to(target, agent_workspace) and not _is_relative_to(target, _REPO_ROOT):
            _bwrap_ro_bind(cmd, target)

    for config_path in _extract_mcp_config_paths(args):
        _bwrap_ro_bind(cmd, config_path)

    if recovery_active and not isolation_required:
        for path in instruction_file_masks:
            cmd.extend(_bwrap_parent_dirs(path))
            cmd.extend(["--ro-bind", "/dev/null", str(path)])
        for path in instruction_directory_masks:
            cmd.extend(_bwrap_parent_dirs(path))
            try:
                info = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            if info is not None and not stat.S_ISDIR(info.st_mode):
                cmd.extend(["--ro-bind", "/dev/null", str(path)])
            else:
                cmd.extend(["--tmpfs", str(path)])

    cmd.extend(["--setenv", "ANGERONA_AGENT_FS_SANDBOX_ACTIVE", "1"])
    cmd.extend(["--setenv", "HOME", str(runtime_home)])
    cmd.extend(["--setenv", "XDG_CONFIG_HOME", str(runtime_home / ".config")])
    cmd.extend(["--setenv", "XDG_CACHE_HOME", str(runtime_home / ".cache")])
    cmd.extend(["--setenv", "XDG_DATA_HOME", str(runtime_home / ".local" / "share")])
    if isolation_required:
        assert seed_usage is not None
        cmd.extend(["--chdir", str(agent_workspace)])
        cmd.extend([
            str(sandbox_runner_python),
            str(_REPO_ROOT / "src" / "agents" / "scratch_quota.py"),
            "--input-root", str(scratch_input),
            "--workspace", "/tmp/angerona-workspace",
            "--cwd", str(run_cwd),
            "--reconstruction", reconstruction_relative,
            "--export-socket", str(scratch_export),
            "--seed-files", str(seed_usage.files),
            "--seed-directories", str(seed_usage.directories),
            "--seed-bytes", str(seed_usage.bytes),
            "--seed-manifest-sha256", seed_usage.manifest_sha256,
            "--write-bytes", str(_CANDIDATE_SCRATCH_WRITE_BYTES),
            "--write-files", str(_CANDIDATE_SCRATCH_WRITE_FILES),
            "--write-directories", str(_CANDIDATE_SCRATCH_WRITE_DIRECTORIES),
            "--network-fds", ",".join(str(fd) for fd in network_fds),
            "--trusted-input-fds", ",".join(str(fd) for fd in trusted_input_fds),
            "--recovery-seed-fd", str(recovery_seed_fd if recovery_seed_fd is not None else -1),
            "--recovery-seed-size", str(recovery_seed_size),
            "--recovery-seed-sha256", recovery_seed_sha256,
            *[
                value
                for relative in _all_mask_relatives
                for value in ("--instruction-mask-relative", relative)
            ],
            *[
                value
                for name, fd in sorted(auth_seed_fds.items())
                for value in ("--auth-seed", f"{name}:{fd}")
            ],
            "--",
            *provider_args,
        ])
    else:
        cmd.extend(["--chdir", str(run_cwd)])
        cmd.extend(provider_args)
    env["ANGERONA_AGENT_FS_SANDBOX_ACTIVE"] = "1"
    env["HOME"] = str(runtime_home)
    env["XDG_CONFIG_HOME"] = str(runtime_home / ".config")
    env["XDG_CACHE_HOME"] = str(runtime_home / ".cache")
    env["XDG_DATA_HOME"] = str(runtime_home / ".local" / "share")
    if isolation_required:
        systemd_run = shutil.which("systemd-run")
        if not systemd_run and Path("/usr/bin/systemd-run").is_file():
            systemd_run = "/usr/bin/systemd-run"
        if not systemd_run:
            raise RuntimeError(
                "required K-candidate cgroup boundary is unavailable (systemd-run missing)"
            )
        memory_max = _CANDIDATE_PROCESS_MEMORY_BYTES + scratch_bytes
        tasks_max = min(
            _CANDIDATE_PROCESS_TASKS,
            _CANDIDATE_SCRATCH_WRITE_FILES,
            _CANDIDATE_SCRATCH_WRITE_DIRECTORIES,
        )
        if tasks_max < 8:
            raise RuntimeError("candidate scratch inode quota is too small for isolation")
        cmd = [
            systemd_run,
            "--user", "--scope", "--quiet", "--collect",
            "-p", f"MemoryMax={memory_max}",
            "-p", "MemorySwapMax=0",
            "-p", f"TasksMax={tasks_max}",
            "--",
            *cmd,
        ]
    return cmd


def _supervised_agent_env(cwd: str) -> dict[str, str]:
    env = dict(os.environ)
    run_cwd = Path(cwd).resolve()
    agent_workspace = run_cwd.parent if run_cwd.name == "code" else run_cwd
    env["ANGERONA_SUPERVISOR_CONTROLLED"] = "1"
    env["ANGERONA_DISABLE_NESTED_AGENTS"] = "1"
    env["ANGERONA_NETWORK_ALLOWED"] = "1"
    env["ANGERONA_NETWORK_PRIVACY_POLICY"] = (
        "Internet may be used for public docs/signatures only; never upload or paste "
        "customer binaries, decompiled code, private strings, secrets, addresses, or artifacts."
    )
    env["ANGERONA_RUN_CWD"] = str(run_cwd)
    env["ANGERONA_AGENT_WORKSPACE_ROOT"] = str(agent_workspace)
    env["ANGERONA_ALLOWED_ROOTS"] = os.pathsep.join([str(run_cwd), str(agent_workspace)])
    env.setdefault("ANGERONA_AGENT_FS_SANDBOX", "1")
    env["ANGERONA_OLD_RUNS_POLICY"] = (
        "Old workspaces are archives/debug evidence only. Do not read them unless the "
        "supervisor explicitly gives an exact path in the task."
    )
    env.setdefault("CODEBASE_MEMORY_PROJECT", "angerona")
    env["CODEBASE_MEMORY_READ_ONLY"] = "1"
    env["CODEBASE_MEMORY_DISABLE_WRITE"] = "1"
    env["CODEBASE_MEMORY_DISABLE_INDEXING"] = "1"
    return env


def _mcp_runtime_env(
    process_env: dict[str, str],
    configured_env: dict[str, str],
) -> dict[str, str]:
    """Build the explicit MCP child allowlist used by restrictive CLI runtimes."""

    forwarded = dict(configured_env)
    for key in _MCP_CONTEXT_ENV_KEYS:
        value = process_env.get(key)
        if value is not None:
            forwarded[key] = value
    return forwarded


def _claude_runtime_error(env: dict[str, str], model: str | None) -> str | None:
    """Reject accidental Claude-compatible non-Claude backends unless opted in."""
    if env.get("ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY", "").lower() in {"1", "true", "yes", "on"}:
        return None
    model_values = [model or ""]
    model_values.extend(env.get(name, "") for name in _CLAUDE_MODEL_ENV)
    lowered_models = " ".join(model_values).lower()
    if any(marker in lowered_models for marker in _NON_ANTHROPIC_MODEL_MARKERS):
        return (
            "Claude runtime validation failed: requested model/env looks like a "
            "Claude-compatible non-Anthropic backend. Use a real Claude model, or set "
            "ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY=1 to opt in explicitly."
        )
    gateway_keys = [name for name in _CLAUDE_COMPAT_GATEWAY_ENV if env.get(name)]
    if gateway_keys and not any(name.lower().startswith(("claude", "anthropic")) for name in model_values if name):
        return (
            "Claude runtime validation failed: custom Claude API gateway env is set "
            f"({', '.join(gateway_keys)}) but no explicit Claude/Anthropic model was selected. "
            "Set the model to a real Claude model or opt in with "
            "ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY=1."
        )
    return None


def _local_only_runtime_error(env: dict[str, str], family: str) -> str | None:
    """Fail closed when local-only policy has no loopback provider endpoint."""
    if not _truthy(env.get("ANGERONA_LOCAL_ONLY")):
        return None
    keys = (
        ("OPENAI_BASE_URL", "ANGERONA_LOCAL_BASE_URL")
        if family == "codex"
        else ("ANTHROPIC_BASE_URL", "CLAUDE_CODE_BASE_URL")
    )
    endpoint = next((env.get(key, "") for key in keys if env.get(key)), "")
    if not endpoint or not _provider_url_is_loopback(endpoint):
        return f"local-only policy requires a loopback {family} provider endpoint"
    return None


def _env_int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name) or os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(0, value)


@dataclass
class _BoundedTextCapture:
    """Keep only a bounded tail while preserving total-output accounting."""

    name: str
    limit_chars: int
    tail: str = ""
    total_chars: int = 0
    total_bytes: int = 0
    dropped_chars: int = 0

    def append(self, text: str) -> None:
        if not text:
            return
        self.total_chars += len(text)
        self.total_bytes += len(text.encode("utf-8", errors="replace"))
        if self.limit_chars <= 0:
            self.dropped_chars += len(text)
            self.tail = ""
            return
        merged = self.tail + text
        overflow = len(merged) - self.limit_chars
        if overflow > 0:
            self.dropped_chars += overflow
            self.tail = merged[overflow:]
        else:
            self.tail = merged

    def render(self) -> str:
        if self.dropped_chars <= 0:
            return self.tail
        return (
            f"[angerona] {self.name} capture truncated: "
            f"total_chars={self.total_chars} total_bytes={self.total_bytes} "
            f"captured_tail_chars={len(self.tail)} dropped_prefix_chars={self.dropped_chars}\n"
            f"{self.tail}"
        )


def _dispatch_complete_lines(
    buffer: str,
    *,
    on_line: Callable[[str], None] | None,
) -> str:
    if on_line is None or "\n" not in buffer:
        return buffer
    parts = buffer.split("\n")
    for line in parts[:-1]:
        try:
            on_line(line.rstrip("\r"))
        except Exception:  # noqa: BLE001
            pass
    return parts[-1]


def _authorized_artifact_sender(
    peer_pid: int,
    *,
    boundary_pid: int,
    expected_runner: bytes,
    max_depth: int = 4,
) -> bool:
    """Authenticate a scratch-export sender by executable and process lineage."""
    try:
        status_text = Path(f"/proc/{peer_pid}/status").read_text(
            encoding="utf-8", errors="strict"
        )
        parent_line = next(
            line for line in status_text.splitlines() if line.startswith("PPid:")
        )
        ancestor = int(parent_line.split(":", 1)[1].strip())
        command_parts = Path(f"/proc/{peer_pid}/cmdline").read_bytes().split(b"\0")
        descendant = False
        for _depth in range(max_depth):
            if ancestor == boundary_pid:
                descendant = True
                break
            ancestor_status = Path(f"/proc/{ancestor}/status").read_text(
                encoding="utf-8", errors="strict"
            )
            ancestor_line = next(
                line for line in ancestor_status.splitlines() if line.startswith("PPid:")
            )
            ancestor = int(ancestor_line.split(":", 1)[1].strip())
        return descendant and expected_runner in command_parts
    except (OSError, StopIteration, ValueError):
        return False


def _rmtree_unlocking(directory: Path) -> None:
    """Remove a tree whose root was locked 0o500 (verdict round-6 export dir).

    Restores owner write on the root before delegating to shutil.rmtree so the
    0o222 socket inside can be unlinked.  Errors are swallowed to match the
    prior ``shutil.rmtree(..., ignore_errors=True)`` behaviour.
    """
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    shutil.rmtree(directory, ignore_errors=True)


def _terminate_process_group(proc: subprocess.Popen) -> None:
    """Terminate a process group, escalating after a bounded grace period."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _parent_death_signal_preexec(parent_pid: int):
    """Return a preexec_fn that kernel-fences the child on supervisor death.

    PR_SET_PDEATHSIG (prctl 1) makes the kernel deliver SIGKILL to this child if
    its parent exits for ANY reason (crash, OOM-kill, SIGKILL). A watchdog thread
    living inside the supervisor cannot fire after the supervisor is gone, so the
    guard must live in the kernel. This closes the worker-lease gap on the direct
    (non-bwrap) spawn path; the bwrap paths already carry ``--die-with-parent``.

    The trailing getppid() check closes the fork→prctl race: if the real parent
    died before the signal was installed the child was reparented, pdeathsig
    would never fire, and it reaps itself now.
    """
    import ctypes

    def _set() -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG = 1
            if os.getppid() != parent_pid:
                os.kill(os.getpid(), signal.SIGKILL)
        except Exception:  # noqa: BLE001 — fencing is best-effort, never blocks launch
            pass

    return _set


def _stream_process_unobserved(
    args: list[str],
    *,
    input_text: str | None,
    cwd: str,
    env: dict[str, str],
    idle_timeout: float | None,
    wall_timeout: float | None,
    on_line: Callable[[str], None] | None = None,
    on_heartbeat: Callable[[dict], None] | None = None,
    recovery_seed: CandidateWorkspaceSnapshot | None = None,
    snapshot_sink: list[CandidateWorkspaceSnapshot] | None = None,
    on_network_event: Callable[[str, str, dict[str, object]], None] | None = None,
) -> tuple[int, str, str, float]:
    """Stream a process and enforce its timeouts from launch.

    Reported elapsed time also includes trusted preparation and cleanup.
    """
    input_text, trusted_input_fds = _materialize_recovery_inputs(input_text)
    recovery_seed_fd = -1
    if recovery_seed is not None:
        if hashlib.sha256(recovery_seed.payload).hexdigest() != recovery_seed.sha256:
            for descriptor in trusted_input_fds:
                os.close(descriptor)
            raise RuntimeError("candidate recovery seed digest mismatch")
        try:
            recovery_seed_fd = _open_sealed_input(
                recovery_seed.payload,
                label=f"scratch-{recovery_seed.sha256[:12]}",
            )
        except Exception:
            for descriptor in trusted_input_fds:
                os.close(descriptor)
            raise
    started = time.monotonic()
    last_activity = started
    capture_limit = _env_int(env, "ANGERONA_MAX_AGENT_CAPTURE_CHARS", DEFAULT_AGENT_CAPTURE_CHARS)
    event_line_limit = _env_int(env, "ANGERONA_MAX_AGENT_EVENT_LINE_CHARS", DEFAULT_AGENT_EVENT_LINE_CHARS)
    event_stream_byte_limit = min(
        DEFAULT_AGENT_EVENT_STREAM_BYTES,
        _env_int(
            env,
            "ANGERONA_MAX_AGENT_EVENT_STREAM_BYTES",
            DEFAULT_AGENT_EVENT_STREAM_BYTES,
        ),
    )
    event_count_limit = min(
        DEFAULT_AGENT_EVENT_COUNT,
        _env_int(env, "ANGERONA_MAX_AGENT_EVENT_COUNT", DEFAULT_AGENT_EVENT_COUNT),
    )
    stdout_capture = _BoundedTextCapture("stdout", capture_limit)
    stderr_capture = _BoundedTextCapture("stderr", capture_limit)
    lock = threading.Lock()
    event_boundary_hit = threading.Event()
    event_stream_bytes = 0
    event_count = 0
    export_server: socket.socket | None = None
    export_directory: Path | None = None
    export_path: Path | None = None
    export_stop = threading.Event()
    export_result: dict[str, object] = {"error": None, "payload": None}
    reconstruction_relative = ""
    export_root_fd = -1
    export_root_identity: tuple[int, int] | None = None
    isolation_required = _truthy(
        env.get("ANGERONA_REQUIRE_AGENT_FS_SANDBOX"), default=False
    )
    recovery_active = _truthy(
        env.get("ANGERONA_CONTEXT_RECOVERY_ACTIVE"), default=False
    )
    network_broker: CandidateNetworkBroker | None = None
    network_fds: tuple[int, ...] = ()
    auth_seed_fds: dict[str, int] = {}
    instruction_quarantine: _RecoveryInstructionQuarantine | None = None
    # F1 sanitization (env-URL/credential + execution-control stripping) runs
    # UNCONDITIONALLY, not just for the K-candidate isolation path.  A
    # host-supplied public provider URL or an interpreter-injection env var
    # is a leak/attack vector on BOTH the trusted-provider and the isolation
    # paths — gating a security control on the opt-in sandbox flag means it
    # is off by default.  (ELITE-2 verdict round-4 fix: F1 was gated on
    #  isolation_required, so the leak class was live without the opt-in flag.)
    _sanitize_required_provider_environment(env)
    if isolation_required:
        auth_seed_fds = _open_candidate_auth_seeds(env)
        root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        export_root_fd = os.open(Path(cwd).expanduser().absolute(), root_flags)
        root_info = os.fstat(export_root_fd)
        export_root_identity = (root_info.st_dev, root_info.st_ino)
        reconstruction_relative = reconstruction_authority(export_root_fd)
        env["ANGERONA_SCRATCH_RECONSTRUCTION_RELATIVE"] = reconstruction_relative
        export_directory = Path(tempfile.mkdtemp(prefix="angerona-scratch-export-"))
        export_path = export_directory / "export.sock"
        export_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        export_server.bind(str(export_path))
        os.chmod(export_path, 0o222)
        # Lock the parent dir to r-x for the owner so no sibling file can be
        # added between here and bwrap exec (the same-uid microsecond race the
        # verdict round-6 flagged).  The candidate can still list the dir
        # (metadata leak of a single empty dir + the write-only socket), but
        # cannot have a planted sibling to read.  (ELITE-2 verdict round-6.)
        os.chmod(export_directory, 0o500)
        export_server.listen(16)
        export_server.settimeout(0.2)
        env["ANGERONA_SCRATCH_EXPORT_SOCKET"] = str(export_path)
        trusted_gateway = configure_trusted_provider_gateway(env)
        network_policy = resolve_candidate_network_policy(
            env, trusted_gateway=trusted_gateway
        )
        configure_proxy_environment(env)
        network_broker = CandidateNetworkBroker(network_policy, on_event=on_network_event)
        network_fds = network_broker.start()
    try:
        # Every launch sharing a workspace takes the same supervisor-only lock.
        # Recovery launches additionally quarantine instruction symlinks.  A
        # normal launch can therefore never overlap with or mutate live
        # quarantine state from another dispatch.
        instruction_quarantine = _RecoveryInstructionQuarantine(cwd, env)
        instruction_quarantine.enter(quarantine=recovery_active)
        popen_args = _workspace_sandbox_command(
            args, cwd=cwd, env=env, network_fds=network_fds,
            auth_seed_fds=auth_seed_fds,
            trusted_input_fds=trusted_input_fds,
            recovery_seed_fd=(recovery_seed_fd if recovery_seed_fd >= 0 else None),
            recovery_seed_size=(len(recovery_seed.payload) if recovery_seed else 0),
            recovery_seed_sha256=(recovery_seed.sha256 if recovery_seed else ""),
        )
        inherited_fds = (
            network_fds + tuple(auth_seed_fds.values()) + trusted_input_fds
            + ((recovery_seed_fd,) if recovery_seed_fd >= 0 else ())
        )
        proc = subprocess.Popen(
            popen_args,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
            bufsize=1,
            start_new_session=True,
            preexec_fn=_parent_death_signal_preexec(os.getpid()),
            pass_fds=inherited_fds,
        )
        process_started = time.monotonic()
        last_activity = process_started
        if network_broker is not None:
            network_broker.release_candidate_channels()
        for descriptor in auth_seed_fds.values():
            os.close(descriptor)
        auth_seed_fds.clear()
        for descriptor in trusted_input_fds:
            os.close(descriptor)
        trusted_input_fds = ()
        if recovery_seed_fd >= 0:
            os.close(recovery_seed_fd)
            recovery_seed_fd = -1
    except Exception:
        quarantine_close_error: Exception | None = None
        if instruction_quarantine is not None:
            try:
                instruction_quarantine.close()
            except Exception as exc:  # noqa: BLE001
                quarantine_close_error = exc
            instruction_quarantine = None
        for descriptor in auth_seed_fds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        auth_seed_fds.clear()
        for descriptor in trusted_input_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        trusted_input_fds = ()
        if recovery_seed_fd >= 0:
            try:
                os.close(recovery_seed_fd)
            except OSError:
                pass
            recovery_seed_fd = -1
        if network_broker is not None:
            network_broker.close()
        if export_server is not None:
            export_server.close()
        if export_directory is not None:
            _rmtree_unlocking(export_directory)
        if export_root_fd >= 0:
            os.close(export_root_fd)
        if quarantine_close_error is not None:
            raise RuntimeError(
                "recovery instruction quarantine failed during launch cleanup"
            ) from quarantine_close_error
        raise

    def pump_stdout() -> None:
        nonlocal last_activity, event_stream_bytes, event_count
        assert proc.stdout is not None
        line_buffer = ""

        def dispatch_bounded(line: str) -> None:
            nonlocal event_stream_bytes, event_count
            encoded_size = len(line.encode("utf-8", errors="replace")) + 1
            with lock:
                if (
                    event_count >= event_count_limit
                    or event_stream_bytes + encoded_size > event_stream_byte_limit
                ):
                    event_boundary_hit.set()
                    return
                event_count += 1
                event_stream_bytes += encoded_size
            if on_line is not None:
                on_line(line)

        for chunk in iter(lambda: proc.stdout.read(8192), ""):
            with lock:
                stdout_capture.append(chunk)
                last_activity = time.monotonic()
            if on_line is not None:
                line_buffer += chunk
                line_buffer = _dispatch_complete_lines(
                    line_buffer,
                    on_line=dispatch_bounded,
                )
                if len(line_buffer) > event_line_limit:
                    event_boundary_hit.set()
                    line_buffer = ""
                    break
        if on_line is not None and line_buffer:
            try:
                dispatch_bounded(line_buffer.rstrip("\r"))
            except Exception:  # noqa: BLE001
                pass
        proc.stdout.close()

    def pump_stderr() -> None:
        nonlocal last_activity
        assert proc.stderr is not None
        for chunk in iter(lambda: proc.stderr.read(8192), ""):
            with lock:
                stderr_capture.append(chunk)
                last_activity = time.monotonic()
        proc.stderr.close()

    def write_stdin() -> None:
        if input_text is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except BrokenPipeError:
            pass

    def receive_artifacts() -> None:
        if export_server is None:
            return
        last_payload: bytes | None = None
        last_error: Exception | None = None
        idle_after_stop = 0
        while True:
            try:
                connection, _address = export_server.accept()
            except socket.timeout:
                if export_stop.is_set():
                    idle_after_stop += 1
                    if idle_after_stop >= 2:
                        break
                continue
            except OSError as exc:
                last_error = exc
                break
            idle_after_stop = 0
            try:
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                )
                peer_pid, _peer_uid, _peer_gid = struct.unpack("3i", credentials)
                authorized_peer = _authorized_artifact_sender(
                    peer_pid,
                    boundary_pid=proc.pid,
                    expected_runner=str(
                        _REPO_ROOT / "src" / "agents" / "scratch_quota.py"
                    ).encode(),
                )
            except (OSError, struct.error):
                authorized_peer = False
            if not authorized_peer:
                connection.close()
                last_error = RuntimeError("unauthorized candidate artifact sender")
                continue
            if export_path is not None:
                try:
                    export_path.unlink()
                except FileNotFoundError:
                    pass
                except PermissionError:
                    # The export parent dir is locked 0o500 to close the
                    # same-uid sibling race (verdict round-6).  Temporarily
                    # restore write permission to unlink the socket the
                    # candidate just connected to, then re-lock.
                    try:
                        os.chmod(export_directory, 0o700)
                        export_path.unlink()
                        os.chmod(export_directory, 0o500)
                    except OSError:
                        pass
            with connection:
                try:
                    last_payload = read_export_socket(connection, timeout=None)
                    last_error = None
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
            break
        if last_payload is None:
            export_result["error"] = last_error or RuntimeError(
                "candidate artifact stream was not produced"
            )
            return
        # Validation and transport happen concurrently, but host mutation is delayed
        # until provider status, timeout state, and network policy are all final.
        export_result["payload"] = last_payload

    threads = [
        threading.Thread(target=pump_stdout, daemon=True),
        threading.Thread(target=pump_stderr, daemon=True),
        threading.Thread(target=write_stdin, daemon=True),
    ]
    if export_server is not None:
        threads.append(threading.Thread(target=receive_artifacts, daemon=True))
    for t in threads:
        t.start()

    timed_out = False
    event_boundary_failed = False
    last_heartbeat = process_started
    heartbeat_interval = _env_int(env, "ANGERONA_AGENT_HEARTBEAT_SECONDS", 30)
    while proc.poll() is None:
        now = time.monotonic()
        with lock:
            idle_for = now - last_activity
        if on_heartbeat is not None and heartbeat_interval > 0 and now - last_heartbeat >= heartbeat_interval:
            last_heartbeat = now
            try:
                on_heartbeat({
                    "pid": proc.pid,
                    "elapsed_seconds": round(now - started, 1),
                    "idle_seconds": round(idle_for, 1),
                    "cwd": cwd,
                    "status": "running",
                })
            except Exception:  # noqa: BLE001
                pass
        if wall_timeout and now - process_started > wall_timeout:
            timed_out = True
            break
        if idle_timeout and idle_for > idle_timeout:
            timed_out = True
            break
        if event_boundary_hit.is_set():
            event_boundary_failed = True
            break
        time.sleep(0.2)

    if event_boundary_hit.is_set():
        event_boundary_failed = True

    if timed_out or event_boundary_failed:
        _terminate_process_group(proc)

    rc = proc.wait()
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    export_stop.set()
    for t in threads:
        t.join(timeout=10 if t is threads[-1] and export_server is not None else 2)
    # A fast provider may exit before its stdout reader drains the final events.
    # Apply boundaries detected during that drain before accepting its exit code.
    if event_boundary_hit.is_set():
        event_boundary_failed = True
    if export_server is not None and threads[-1].is_alive():
        export_result["error"] = RuntimeError(
            "candidate artifact receiver did not terminate"
        )
    quarantine_error: Exception | None = None
    if instruction_quarantine is not None:
        try:
            instruction_quarantine.close()
        except Exception as exc:  # noqa: BLE001
            quarantine_error = exc
        instruction_quarantine = None
    if export_server is not None:
        export_server.close()
    if export_directory is not None:
        _rmtree_unlocking(export_directory)
    network_stats = network_broker.close() if network_broker is not None else None
    if timed_out:
        stderr_capture.append(f"\n[angerona] timed out (idle={idle_timeout}, wall={wall_timeout})")
        # SIGTERM/SIGKILL normally produce a negative return code. Normalize every
        # supervisor-enforced timeout so provider-neutral retry classification sees it.
        rc = 124
    elif event_boundary_failed:
        stderr_capture.append(
            "\n[angerona] provider event stream exceeded its hard count/byte boundary"
        )
        rc = AGENT_EVENT_BOUNDARY_EXIT
    if quarantine_error is not None:
        stderr_capture.append(
            "\n[angerona] recovery instruction quarantine failed closed: "
            + type(quarantine_error).__name__
        )
        rc = 78
    if network_stats is not None and network_stats["violations"]:
        reason_counts = network_stats.get("violation_reasons")
        reason_summary = ""
        if isinstance(reason_counts, dict):
            reason_summary = "; reasons=" + ",".join(
                f"{str(reason).replace(' ', '_')}:{count}"
                for reason, count in sorted(reason_counts.items())
            )
        if _truthy(env.get("ANGERONA_NETWORK_DIAGNOSTICS"), default=False):
            denied = network_stats.get("denied_endpoints")
            if isinstance(denied, dict):
                reason_summary += "; endpoints=" + ",".join(
                    f"{endpoint}:{count}" for endpoint, count in sorted(denied.items())
                )
        stderr_capture.append(
            "\n[angerona] candidate network policy rejected "
            f"{network_stats['violations']} request(s){reason_summary}"
        )
        if not timed_out:
            rc = NETWORK_POLICY_EXIT
    export_error = export_result.get("error")
    export_payload = export_result.get("payload")
    if export_server is not None and rc == 0 and export_error is None:
        if not isinstance(export_payload, bytes):
            export_error = RuntimeError("candidate artifact payload is unavailable")
        else:
            try:
                assert export_root_identity is not None and export_root_fd >= 0
                live_before = os.stat(
                    Path(cwd).expanduser().absolute(), follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(live_before.st_mode)
                    or (live_before.st_dev, live_before.st_ino) != export_root_identity
                ):
                    raise RuntimeError(
                        "candidate export root identity changed before commit"
                    )
                install_export(
                    export_root_fd, reconstruction_relative, export_payload
                )
                live_after = os.stat(
                    Path(cwd).expanduser().absolute(), follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(live_after.st_mode)
                    or (live_after.st_dev, live_after.st_ino) != export_root_identity
                ):
                    raise RuntimeError(
                        "candidate export root identity changed during commit"
                    )
            except Exception as exc:  # noqa: BLE001
                export_error = exc
    elif (
        export_server is not None
        and rc != 0
        and export_error is None
        and isinstance(export_payload, bytes)
        and snapshot_sink is not None
    ):
        snapshot_sink.append(CandidateWorkspaceSnapshot(
            payload=export_payload,
            sha256=hashlib.sha256(export_payload).hexdigest(),
        ))
    if export_server is not None and export_error is not None:
        stderr_capture.append(
            "\n[angerona] candidate scratch artifacts rejected: "
            + type(export_error).__name__
        )
        if not timed_out and rc == 0:
            rc = SCRATCH_QUOTA_EXIT
    if (
        network_stats is not None
        and _truthy(env.get("ANGERONA_NETWORK_DIAGNOSTICS"), default=False)
    ):
        accepted = network_stats.get("accepted_endpoints")
        if isinstance(accepted, dict):
            stderr_capture.append(
                "\n[angerona] candidate network diagnostic accepted="
                + ",".join(
                    f"{endpoint}:{count}" for endpoint, count in sorted(accepted.items())
                )
            )
    if export_root_fd >= 0:
        os.close(export_root_fd)
    return rc, stdout_capture.render(), stderr_capture.render(), time.monotonic() - started


def _stream_process(
    args: list[str],
    *,
    input_text: str | None,
    cwd: str,
    env: dict[str, str],
    idle_timeout: float | None,
    wall_timeout: float | None,
    on_line: Callable[[str], None] | None = None,
    on_heartbeat: Callable[[dict], None] | None = None,
    recovery_seed: CandidateWorkspaceSnapshot | None = None,
    snapshot_sink: list[CandidateWorkspaceSnapshot] | None = None,
) -> tuple[int, str, str, float]:
    """Observed provider boundary with complete stream and workspace-delta telemetry."""

    workspace_hint = env.get("ANGERONA_AGENT_WORKSPACE_ROOT") or cwd
    ledger = ledger_for_workspace(workspace_hint)
    parent_span = current_span_id()
    span = ledger.start_span(
        component="runtime",
        category="subprocess",
        action="provider_process",
        parent_span_id=parent_span,
        attributes={
            "command": content_descriptor(json.dumps(args, ensure_ascii=False)),
            "executable": Path(args[0]).name if args else "",
            "cwd": str(Path(cwd).expanduser().absolute()),
            "stdin": content_descriptor(input_text),
            "idle_timeout": idle_timeout,
            "wall_timeout": wall_timeout,
            "isolation_required": _truthy(
                env.get("ANGERONA_REQUIRE_AGENT_FS_SANDBOX"), default=False
            ),
            "recovery_active": _truthy(
                env.get("ANGERONA_CONTEXT_RECOVERY_ACTIVE"), default=False
            ),
            "recovery_seed": (
                None
                if recovery_seed is None
                else {"bytes": len(recovery_seed.payload), "sha256": recovery_seed.sha256}
            ),
        },
    )
    env.update(ledger.child_environment(parent_span_id=span.span_id))
    try:
        before = capture_tree(cwd)
    except BaseException as exc:
        span.finish(
            status="error",
            attributes={
                "exception": type(exc).__name__,
                "observation_stage": "initial_tree_capture",
            },
        )
        raise

    def observed_line(line: str) -> None:
        try:
            parsed: object = json.loads(line)
        except (TypeError, ValueError):
            parsed = {"line": content_descriptor(line)}
        span.event(
            "stream_line",
            category="provider",
            attributes={
                "line": content_descriptor(line),
                "parsed": external_event_descriptor(parsed),
            },
            trust="trusted_host_observation",
        )
        if on_line is not None:
            on_line(line)

    def observed_heartbeat(data: dict) -> None:
        span.event(
            "heartbeat",
            category="subprocess",
            status="running",
            attributes=external_event_descriptor(data),  # type: ignore[arg-type]
        )
        if on_heartbeat is not None:
            on_heartbeat(data)

    def observed_network_event(
        action: str, status: str, attributes: dict[str, object]
    ) -> None:
        span.event(
            action,
            category="network",
            status=status,
            attributes=attributes,
            trust="trusted_host_observation",
        )

    try:
        result = _stream_process_unobserved(
            args,
            input_text=input_text,
            cwd=cwd,
            env=env,
            idle_timeout=idle_timeout,
            wall_timeout=wall_timeout,
            on_line=observed_line,
            on_heartbeat=observed_heartbeat,
            recovery_seed=recovery_seed,
            snapshot_sink=snapshot_sink,
            on_network_event=observed_network_event,
        )
    except BaseException as exc:
        final_attributes: dict[str, object] = {
            "exception": type(exc).__name__,
            "message": content_descriptor(str(exc)),
        }
        try:
            final_attributes["child_events_imported"] = ledger.import_child_spools(
                cwd, parent_span_id=span.span_id
            )
            after = capture_tree(cwd)
            final_attributes["filesystem_changes"] = ledger.record_tree_delta(
                before, after, component="runtime", parent_span_id=span.span_id
            )
        except BaseException as observation_exc:
            final_attributes["final_observation_error"] = type(observation_exc).__name__
        span.finish(
            status="error",
            attributes=final_attributes,
        )
        raise
    rc, stdout, stderr, seconds = result
    child_events = ledger.import_child_spools(cwd, parent_span_id=span.span_id)
    after = capture_tree(cwd)
    changes = ledger.record_tree_delta(
        before,
        after,
        component="runtime",
        parent_span_id=span.span_id,
    )
    span.finish(
        status="ok" if rc == 0 else "error",
        attributes={
            "returncode": rc,
            "seconds": seconds,
            "stdout": content_descriptor(stdout),
            "stderr": content_descriptor(stderr),
            "filesystem_changes": changes,
            "child_events_imported": child_events,
        },
    )
    return result


# --------------------------------------------------------------------- Claude


class ClaudeCodeAgent:
    """Drive `claude` (Claude Code) in agentic --print mode with the Ghidra MCP server."""

    def __init__(self, command: str | None = None):
        self.command = command or os.environ.get("ANGERONA_CLAUDE_CMD") or "claude"

    def available(self) -> bool:
        return shutil.which(self.command) is not None

    @_retry_lease_lifecycle
    def run(
        self,
        task: str,
        *,
        system_prompt: str,
        mcp_config_path: str,
        allowed_tools: list[str],
        cwd: str,
        target_binary: str | None = None,
        model: str | None = None,
        skip_permissions: bool = True,
        idle_timeout: float = 300.0,
        wall_timeout: float | None = 1800.0,
        on_event: EventCallback | None = None,
        context_window_tokens: int | None = None,
        on_context_observation: ContextObservationCallback | None = None,
        isolation_required: bool = False,
    ) -> AgentResult:
        runtime_started = time.monotonic()
        requested_deadline_unix_ns = _requested_wall_deadline_unix_ns(wall_timeout)
        env = _supervised_agent_env(cwd)
        env["ANGERONA_AGENT_PROVIDER_FAMILY"] = "claude"
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        env["DISABLE_AUTOUPDATER"] = "1"
        env["DISABLE_TELEMETRY"] = "1"
        env["DISABLE_ERROR_REPORTING"] = "1"
        if isolation_required:
            env["ANGERONA_REQUIRE_AGENT_FS_SANDBOX"] = "1"
        if context_window_tokens is not None:
            env["ANGERONA_CONTEXT_WINDOW_TOKENS"] = str(context_window_tokens)
        if target_binary:
            env["ANGERONA_ALLOWED_INPUT_BINARY"] = str(Path(target_binary).expanduser().resolve())
        validation_error = _local_only_runtime_error(env, "claude") or _claude_runtime_error(env, model)
        if validation_error:
            return AgentResult(
                ok=False,
                final_text=f"[agent-error] {validation_error}",
                events=[],
                returncode=78,
                seconds=0.0,
                raw_stdout="",
                raw_stderr=validation_error,
            )

        context_config = configure_claude_context_env(env, model_hint=model)
        configure_tool_output_governor_env(env, config=context_config, cwd=cwd)
        effective_system_prompt = (
            f"{system_prompt}\n\n{context_checkpoint_system_prompt(context_config)}"
        )

        args = [
            self.command,
            "--print",
            "--output-format", "stream-json",
            "--verbose",
            "--strict-mcp-config",
            "--mcp-config", mcp_config_path,
            "--disallowedTools", "TaskCreate,Task,Agent",
            "--no-session-persistence",
            "--append-system-prompt", effective_system_prompt,
        ]
        if skip_permissions:
            args.append("--dangerously-skip-permissions")
        else:
            args += ["--permission-mode", "acceptEdits"]
            if allowed_tools:
                args += ["--allowedTools", ",".join(allowed_tools)]
        if model:
            args += ["--model", model]

        events: list[dict] = [{
            "type": "angerona_context_config",
            "context_window_tokens": context_config.context_window_tokens,
            "effective_window_tokens": context_config.effective_window_tokens,
            "proactive_trigger_tokens": context_config.proactive_trigger_tokens,
            "compact_percent": context_config.compact_percent,
            "max_recoveries": context_config.max_recoveries,
            "context_window_source": context_config.context_window_source,
            "model_name": context_config.model_name,
            "agent_family": context_config.agent_family,
            "compact_prompt_source": context_config.compact_prompt_source,
            "tool_output_token_limit": context_config.tool_output_token_limit,
            "tool_output_session_budget_tokens": context_config.tool_output_session_budget_tokens,
            "strategy": "proactive-compact+lossless-offload+fresh-recovery",
        }]
        retry_policy = RetryPolicy.from_env(env)
        events.append({
            "type": "angerona_retry_config",
            "max_attempts": retry_policy.max_attempts,
            "base_delay_seconds": retry_policy.base_delay_seconds,
            "max_delay_seconds": retry_policy.max_delay_seconds,
            "jitter_ratio": retry_policy.jitter_ratio,
            "min_remaining_seconds": retry_policy.min_remaining_seconds,
        })
        context_observations: list[dict] = []
        original_task = task
        task, preflight = prepare_initial_task(
            task,
            system_prompt=effective_system_prompt,
            cwd=cwd,
            config=context_config,
        )
        if preflight is not None:
            events.append(preflight)
            if on_event is not None:
                on_event("context_compaction", dict(preflight))
        retry_base_task = task
        execution_contract_sha256 = _execution_contract_sha256({
            "schema_version": 1,
            "provider_command": _execution_file_identity(
                shutil.which(self.command) or self.command
            ),
            "target_binary": _execution_file_identity(target_binary),
            "mcp_config": _execution_file_identity(
                mcp_config_path,
                bind_path=False,
            ),
            "provider_backend_sha256": hashlib.sha256(
                next(
                    (
                        env.get(name, "").strip()
                        for name in (
                            "ANTHROPIC_BASE_URL",
                            "ANTHROPIC_API_BASE",
                            "CLAUDE_API_BASE",
                            "ANGERONA_LOCAL_BASE_URL",
                        )
                        if env.get(name, "").strip()
                    ),
                    "default-provider",
                ).encode("utf-8", errors="surrogatepass")
            ).hexdigest(),
            "allowed_tools": sorted(set(allowed_tools)),
            "permission_mode": (
                "dangerously_skip" if skip_permissions else "accept_edits"
            ),
            "isolation_required": bool(isolation_required),
        })
        retry_lock_timeout = (
            30.0 if wall_timeout is None
            else max(0.0, min(30.0, runtime_started + wall_timeout - time.monotonic()))
        )
        retry_key, retry_ledger, retry_session, retry_blocked = _open_retry_ledger(
            agent_family=context_config.agent_family,
            model_name=context_config.model_name,
            cwd=cwd,
            task=original_task,
            system_prompt=system_prompt,
            execution_contract_sha256=execution_contract_sha256,
            events=events,
            on_event=on_event,
            lock_timeout_seconds=retry_lock_timeout,
            wall_deadline_unix_ns=requested_deadline_unix_ns,
        )
        if retry_blocked:
            return _duplicate_suppressed_result(events=events, ledger=None)
        if retry_session is not None and retry_session.duplicate_suppressed:
            return _duplicate_suppressed_result(events=events, ledger=retry_ledger)
        deadline_unix_ns = (
            retry_session.wall_deadline_unix_ns
            if retry_session is not None
            else requested_deadline_unix_ns
        )
        if (
            retry_session is not None
            and retry_session.resumed_after_crash
            and _remaining_wall_seconds(deadline_unix_ns) == 0.0
        ):
            assert retry_ledger is not None
            return _resumed_wall_deadline_exhausted_result(
                events=events, on_event=on_event, ledger=retry_ledger,
                session=retry_session, dispatch_key=retry_key,
            )
        if retry_session is not None and retry_session.resumed_after_crash:
            durable_remaining = _remaining_wall_seconds(deadline_unix_ns)
            live_remaining = (
                durable_remaining
                if wall_timeout is None or wall_timeout <= 0
                else min(wall_timeout, durable_remaining)
                if durable_remaining is not None
                else wall_timeout
            )
            deadline = (
                None if live_remaining is None
                else runtime_started + live_remaining
            )
        else:
            deadline = (
                runtime_started + wall_timeout
                if wall_timeout is not None and wall_timeout > 0
                else None
            )
        if (
            retry_session is not None
            and retry_session.resumed_after_crash
            and retry_session.attempts_used >= retry_policy.max_attempts
        ):
            assert retry_ledger is not None
            return _resumed_retry_budget_exhausted_result(
                events=events, on_event=on_event, ledger=retry_ledger,
                session=retry_session, dispatch_key=retry_key,
            )
        recoveries = 0
        parent_checkpoint: RecoveryCheckpoint | None = None
        recovery_seed: CandidateWorkspaceSnapshot | None = None
        if retry_session is not None and retry_session.resumed_after_crash:
            try:
                restored_context = _restore_context_after_crash(
                    session=retry_session,
                    config=context_config,
                    execution_contract_sha256=execution_contract_sha256,
                    events=events,
                    on_event=on_event,
                )
            except RetryStateError:
                message = (
                    "[agent-error rc=78] durable context checkpoint failed "
                    "closed validation"
                )
                failure_event = {
                    "type": "angerona_context_recovery",
                    "phase": "failed",
                    "status": "failed",
                    "reason": "invalid_durable_context_checkpoint",
                }
                events.append(failure_event)
                if on_event is not None:
                    on_event("context_compaction", dict(failure_event))
                _record_retry_terminal(
                    retry_session,
                    events,
                    on_event,
                    kind="permanent_failure",
                    dispatch_key=retry_key,
                    reason="invalid_durable_context_checkpoint",
                )
                return AgentResult(
                    ok=False,
                    final_text=message,
                    events=events,
                    returncode=78,
                    raw_stderr=message,
                    context_observations=context_observations,
                )
            if restored_context is not None:
                parent_checkpoint, task, recovery_seed, recoveries = restored_context
                retry_base_task = task
                env["ANGERONA_CONTEXT_RECOVERY_ACTIVE"] = "1"
                if "--setting-sources" not in args:
                    args += [
                        "--setting-sources", "user", "--disable-slash-commands",
                    ]
            else:
                task = _transient_recovery_task(
                    retry_base_task,
                    TransientFailure("interrupted_attempt", "durable_ledger"),
                    retry_session.attempts_used + 1,
                )
        final_text = ""

        def on_line(line: str) -> None:
            nonlocal final_text
            if not line.strip():
                return
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                return
            events.append(ev)
            _emit_claude_event(ev, on_event)
            if ev.get("type") == "result":
                final_text = str(ev.get("result") or final_text)

        def on_heartbeat(data: dict) -> None:
            ev = {"type": "angerona_heartbeat", **data}
            events.append(ev)
            if on_event is not None:
                on_event("heartbeat", data)

        total_seconds = 0.0
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        rc = 1
        while True:
            attempt_wall_timeout = wall_timeout
            if deadline is not None:
                attempt_wall_timeout = max(0.0, deadline - time.monotonic())
                if attempt_wall_timeout <= 0:
                    rc = 124
                    final_text = "[agent-error rc=124] overall wall timeout exhausted"
                    stderr_parts.append(final_text)
                    _record_retry_terminal(
                        retry_session, events, on_event, kind="exhausted",
                        dispatch_key=retry_key, reason="wall_timeout_exhausted",
                    )
                    break
            launch_kind = (
                "context_recovery" if recoveries
                else "transient_retry" if retry_session and retry_session.transient_retries_used
                else "initial"
            )
            started_attempt = _start_retry_attempt(
                retry_session, events, on_event,
                dispatch_key=retry_key, launch_kind=launch_kind,
            )
            if retry_session is not None and started_attempt is None:
                retry_session = None
                if retry_ledger is not None:
                    retry_ledger.close()
                    retry_ledger = None
            attempt_start = len(events)
            final_text = ""
            attempt_snapshots: list[CandidateWorkspaceSnapshot] = []
            rc, out, err, secs = _stream_process(
                args, input_text=task, cwd=cwd, env=env,
                idle_timeout=idle_timeout, wall_timeout=attempt_wall_timeout, on_line=on_line,
                on_heartbeat=on_heartbeat,
                recovery_seed=recovery_seed,
                snapshot_sink=attempt_snapshots if isolation_required else None,
            )
            total_seconds += secs
            stdout_parts.append(out)
            stderr_parts.append(err)
            attempt_events = events[attempt_start:]
            if not final_text:
                final_text = _last_assistant_text(attempt_events) or err.strip()[-1000:]
            if rc == 0:
                _record_retry_terminal(
                    retry_session, events, on_event, kind="success",
                    dispatch_key=retry_key,
                )
                if retry_session is not None and retry_session.transient_retries_used:
                    _emit_retry_event(
                        events, on_event, phase="succeeded", dispatch_key=retry_key,
                        session_id=retry_session.session_id,
                        retries=retry_session.transient_retries_used,
                    )
                break

            overflow = rc != AGENT_EVENT_BOUNDARY_EXIT and is_context_overflow(
                final_text,
                err,
                out[-20_000:],
                attempt_events[-80:],
            )
            if not overflow or recoveries >= context_config.max_recoveries:
                transient = _schedule_transient_retry(
                    returncode=rc,
                    attempt_events=attempt_events[-80:],
                    stderr=err,
                    session=retry_session,
                    policy=retry_policy,
                    deadline=deadline,
                    dispatch_key=retry_key,
                    events=events,
                    on_event=on_event,
                )
                if transient is not None:
                    task = _transient_recovery_task(
                        retry_base_task,
                        transient,
                        (retry_session.transient_retries_used + 1)
                        if retry_session is not None else 2,
                    )
                    continue
                if not any(
                    event.get("type") == "angerona_agent_retry"
                    and event.get("phase") == "exhausted"
                    for event in events[-3:]
                ):
                    _record_retry_terminal(
                        retry_session, events, on_event, kind="permanent_failure",
                        dispatch_key=retry_key, returncode=rc,
                    )
                break

            recoveries += 1
            overflow_details = parse_context_overflow_details(
                final_text,
                err,
                out[-20_000:],
                attempt_events[-80:],
            )
            trusted_overflow_details = parse_trusted_context_overflow_details(
                attempt_events[-80:]
            )
            if isolation_required:
                if not trusted_overflow_details or len(attempt_snapshots) != 1:
                    final_text = (
                        "[agent-error] required context recovery state was not "
                        "authoritatively captured"
                    )
                    stderr_parts.append(final_text)
                    break
                recovery_seed = attempt_snapshots[0]
            configured_window = context_config.planning_window_tokens
            if trusted_overflow_details:
                observation = {
                    "source": "typed_provider_error",
                    "agent_family": context_config.agent_family,
                    "model_name": context_config.model_name,
                    "configured_context_window_tokens": configured_window,
                    **trusted_overflow_details,
                }
                context_observations.append(observation)
                if on_context_observation is not None:
                    applied = False

                    def apply_window(window: int) -> ContextHarnessConfig:
                        nonlocal applied
                        if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
                            raise ValueError("invalid authoritative context window")
                        applied = True
                        return apply_observed_context_limit(
                            env, context_config, trusted_overflow_details,
                            trusted=True,
                            authoritative_window_tokens=window,
                            persist_profile=True,
                        )

                    updated_context = on_context_observation(
                        dict(observation), apply_window
                    )
                    if not applied or not isinstance(updated_context, ContextHarnessConfig):
                        raise ValueError(
                            "context observation callback did not atomically apply "
                            "an authoritative window"
                        )
                else:
                    updated_context = apply_observed_context_limit(
                        env, context_config, trusted_overflow_details, trusted=True
                    )
            else:
                updated_context = context_config
            context_config = updated_context
            effective_system_prompt = (
                f"{system_prompt}\n\n{context_checkpoint_system_prompt(context_config)}"
            )
            args[args.index("--append-system-prompt") + 1] = effective_system_prompt
            compaction_id = uuid.uuid4().hex
            compaction_started = time.monotonic()
            pre_compact_event = {
                "type": "angerona_context_compaction",
                "phase": "started",
                "compaction_id": compaction_id,
                "trigger": "auto",
                "reason": "context_limit",
                "attempt": recoveries,
                "context_window_source": context_config.context_window_source,
                **overflow_details,
            }
            events.append(pre_compact_event)
            if on_event is not None:
                on_event("context_compaction", dict(pre_compact_event))
            try:
                checkpoint = write_recovery_checkpoint(
                    cwd=cwd,
                    original_task=original_task,
                    events=attempt_events,
                    stderr=err or final_text,
                    attempt=recoveries,
                    config=context_config,
                    checkpoint_id=compaction_id,
                    overflow_details=overflow_details,
                    parent_checkpoint=parent_checkpoint,
                    enforce_seed_budget=isolation_required,
                    recovery_snapshot=(
                        recovery_seed.payload if recovery_seed is not None else None
                    ),
                    execution_contract_sha256=execution_contract_sha256,
                )
                recovery_task = build_recovery_task(checkpoint, context_config)
                _record_context_checkpoint(
                    retry_session,
                    checkpoint,
                    attempt=recoveries,
                )
            except (OSError, ValueError, RetryStateError) as exc:
                failure_event = {
                    "type": "angerona_context_compaction",
                    "phase": "failed",
                    "status": "failed",
                    "compaction_id": compaction_id,
                    "trigger": "auto",
                    "reason": "context_limit",
                    "attempt": recoveries,
                    "error": str(exc),
                }
                events.append(failure_event)
                if on_event is not None:
                    on_event("context_compaction", dict(failure_event))
                break
            post_compact_event = {
                "type": "angerona_context_compaction",
                "phase": "completed",
                "status": "completed",
                "compaction_id": compaction_id,
                "trigger": "auto",
                "reason": "context_limit",
                "attempt": recoveries,
                "duration_ms": round((time.monotonic() - compaction_started) * 1000),
                "handoff_path": str(checkpoint.handoff_path),
                "manifest_path": str(checkpoint.manifest_path),
                "manifest_sha256": checkpoint.manifest_sha256,
                "manifest_version": checkpoint.manifest_version,
                **overflow_details,
            }
            events.append(post_compact_event)
            if on_event is not None:
                on_event("context_compaction", dict(post_compact_event))
            recovery_event = {
                "type": "angerona_context_recovery",
                "compaction_id": compaction_id,
                "attempt": recoveries,
                "original_task_path": str(checkpoint.original_task_path),
                "transcript_path": str(checkpoint.transcript_path),
                "stderr_path": str(checkpoint.stderr_path),
                "handoff_path": str(checkpoint.handoff_path),
                "manifest_path": str(checkpoint.manifest_path),
                "manifest_sha256": checkpoint.manifest_sha256,
                "manifest_version": checkpoint.manifest_version,
                "workspace_root": str(checkpoint.workspace_root),
            }
            events.append(recovery_event)
            if on_event is not None:
                on_event("context_compaction", dict(recovery_event))
            task = recovery_task
            retry_base_task = task
            parent_checkpoint = checkpoint
            env["ANGERONA_CONTEXT_RECOVERY_ACTIVE"] = "1"
            if "--setting-sources" not in args:
                args += ["--setting-sources", "user", "--disable-slash-commands"]

        raw_stdout = "\n".join(stdout_parts)[-DEFAULT_AGENT_CAPTURE_CHARS:]
        raw_stderr = "\n".join(stderr_parts)[-DEFAULT_AGENT_CAPTURE_CHARS:]
        if retry_ledger is not None:
            retry_ledger.close()
        return AgentResult(
            ok=rc == 0,
            final_text=final_text,
            events=events,
            returncode=rc,
            seconds=total_seconds,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            context_observations=context_observations,
        )


def _emit_claude_event(ev: dict, on_event: EventCallback | None) -> None:
    if on_event is None:
        return
    t = ev.get("type")
    if t == "assistant":
        for block in (ev.get("message") or {}).get("content", []):
            if block.get("type") == "text" and block.get("text", "").strip():
                on_event("text", {"text": block["text"]})
            elif block.get("type") == "tool_use":
                on_event("tool_use", {"name": block.get("name"), "input": block.get("input")})
    elif t == "user":
        for block in (ev.get("message") or {}).get("content", []):
            if block.get("type") == "tool_result":
                on_event("tool_result", {"content": block.get("content")})
    elif t == "result":
        on_event("result", {"text": ev.get("result"), "usage": ev.get("usage"),
                             "cost_usd": ev.get("total_cost_usd")})


def _last_assistant_text(events: list[dict]) -> str:
    for ev in reversed(events):
        if ev.get("type") == "assistant":
            texts = [b.get("text", "") for b in (ev.get("message") or {}).get("content", [])
                     if b.get("type") == "text"]
            if any(texts):
                return "\n".join(t for t in texts if t)
    return ""


# ---------------------------------------------------------------------- Codex


class CodexAgent:
    """Drive `codex exec` in agentic mode with the Ghidra MCP server via -c overrides."""

    def __init__(self, command: str | None = None):
        self.command = command or os.environ.get("ANGERONA_CODEX_CMD") or "codex"

    def available(self) -> bool:
        return shutil.which(self.command) is not None

    @_retry_lease_lifecycle
    def run(
        self,
        task: str,
        *,
        system_prompt: str,
        mcp_command: str,
        mcp_args: list[str],
        mcp_env: dict[str, str],
        cwd: str,
        server_name: str = "ghidra",
        target_binary: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        sandbox: str = "read-only",
        full_access: bool = False,
        idle_timeout: float = 300.0,
        wall_timeout: float | None = 1800.0,
        on_event: EventCallback | None = None,
        context_window_tokens: int | None = None,
        enable_mcp: bool = True,
        on_context_observation: ContextObservationCallback | None = None,
        isolation_required: bool = False,
    ) -> AgentResult:
        runtime_started = time.monotonic()
        requested_deadline_unix_ns = _requested_wall_deadline_unix_ns(wall_timeout)
        env = _supervised_agent_env(cwd)
        env["ANGERONA_AGENT_PROVIDER_FAMILY"] = "codex"
        if isolation_required:
            env["ANGERONA_REQUIRE_AGENT_FS_SANDBOX"] = "1"
        if context_window_tokens is not None:
            env["ANGERONA_CONTEXT_WINDOW_TOKENS"] = str(context_window_tokens)
        if target_binary:
            env["ANGERONA_ALLOWED_INPUT_BINARY"] = str(Path(target_binary).expanduser().resolve())
        validation_error = _local_only_runtime_error(env, "codex")
        if validation_error:
            return AgentResult(
                ok=False,
                final_text=f"[agent-error] {validation_error}",
                events=[],
                returncode=78,
                seconds=0.0,
                raw_stdout="",
                raw_stderr=validation_error,
            )
        context_config = configure_generic_context(
            env,
            model_hint=model,
            agent_family="codex",
        )
        configure_tool_output_governor_env(env, config=context_config, cwd=cwd)
        effective_system_prompt = (
            f"{system_prompt}\n\n{context_checkpoint_system_prompt(context_config)}"
        )
        original_task = task
        task, preflight = prepare_initial_task(
            task,
            system_prompt=effective_system_prompt,
            cwd=cwd,
            config=context_config,
        )
        prompt = _compose_agent_task_prompt(effective_system_prompt, task)
        base_args = [self.command]
        if full_access:
            # Approval policy is a global Codex option. Keep it before the
            # subcommand for compatibility with current `codex exec` parsing.
            base_args += ["--dangerously-bypass-approvals-and-sandbox"]
        else:
            base_args += ["--ask-for-approval", "never"]
        base_args += [
            "exec", "--json", "--color", "never", "--skip-git-repo-check",
        ]
        # Authentication remains available, while all intended MCP/config and
        # prompt policy is injected explicitly by the supervisor.
        base_args += ["--ignore-user-config", "--ignore-rules", "--ephemeral"]
        base_args += [
            "-c", "project_doc_max_bytes=0",
            "-c", "project_doc_fallback_filenames=[]",
        ]
        if not full_access:
            base_args += ["--sandbox", sandbox]
        if enable_mcp:
            base_args += [
                "-c", f"mcp_servers.{server_name}.command={_toml_str(mcp_command)}",
                "-c", f"mcp_servers.{server_name}.args={_toml_array(mcp_args)}",
            ]
        base_args += ["-c", f"compact_prompt={_toml_str(context_config.compact_prompt)}"]
        if model:
            base_args += ["--model", model]
        if reasoning_effort:
            if reasoning_effort not in {"low", "medium", "high", "xhigh", "max", "ultra"}:
                raise ValueError(f"unsupported Codex reasoning effort: {reasoning_effort!r}")
            base_args += ["-c", f"model_reasoning_effort={reasoning_effort}"]
        base_args += ["--cd", cwd, "-"]

        events: list[dict] = [{
            "type": "angerona_context_config",
            "context_window_tokens": context_config.context_window_tokens,
            "effective_window_tokens": context_config.effective_window_tokens,
            "proactive_trigger_tokens": context_config.proactive_trigger_tokens,
            "compact_percent": context_config.compact_percent,
            "max_recoveries": context_config.max_recoveries,
            "context_window_source": context_config.context_window_source,
            "model_name": context_config.model_name,
            "agent_family": context_config.agent_family,
            "compact_prompt_source": context_config.compact_prompt_source,
            "tool_output_token_limit": context_config.tool_output_token_limit,
            "tool_output_session_budget_tokens": context_config.tool_output_session_budget_tokens,
            "strategy": "native-compact+lossless-offload+fresh-recovery",
        }]
        retry_policy = RetryPolicy.from_env(env)
        events.append({
            "type": "angerona_retry_config",
            "max_attempts": retry_policy.max_attempts,
            "base_delay_seconds": retry_policy.base_delay_seconds,
            "max_delay_seconds": retry_policy.max_delay_seconds,
            "jitter_ratio": retry_policy.jitter_ratio,
            "min_remaining_seconds": retry_policy.min_remaining_seconds,
        })
        context_observations: list[dict] = []
        if preflight is not None:
            events.append(preflight)
            if on_event is not None:
                on_event("context_compaction", dict(preflight))
        retry_base_task = task
        execution_contract_sha256 = _execution_contract_sha256({
            "schema_version": 1,
            "provider_command": _execution_file_identity(
                shutil.which(self.command) or self.command
            ),
            "target_binary": _execution_file_identity(target_binary),
            "mcp_command": {
                "value": mcp_command,
                "identity": _execution_file_identity(
                    shutil.which(mcp_command) or mcp_command
                ),
            },
            "mcp_args": list(mcp_args),
            "mcp_env_sha256": hashlib.sha256(
                json.dumps(
                    mcp_env,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest(),
            "provider_backend_sha256": hashlib.sha256(
                next(
                    (
                        env.get(name, "").strip()
                        for name in (
                            "OPENAI_BASE_URL",
                            "ANGERONA_LOCAL_BASE_URL",
                        )
                        if env.get(name, "").strip()
                    ),
                    "default-provider",
                ).encode("utf-8", errors="surrogatepass")
            ).hexdigest(),
            "server_name": server_name,
            "enable_mcp": bool(enable_mcp),
            "sandbox": sandbox,
            "full_access": bool(full_access),
            "isolation_required": bool(isolation_required),
        })
        retry_lock_timeout = (
            30.0 if wall_timeout is None
            else max(0.0, min(30.0, runtime_started + wall_timeout - time.monotonic()))
        )
        retry_key, retry_ledger, retry_session, retry_blocked = _open_retry_ledger(
            agent_family=context_config.agent_family,
            model_name=context_config.model_name,
            cwd=cwd,
            task=original_task,
            system_prompt=system_prompt,
            execution_contract_sha256=execution_contract_sha256,
            events=events,
            on_event=on_event,
            lock_timeout_seconds=retry_lock_timeout,
            wall_deadline_unix_ns=requested_deadline_unix_ns,
        )
        if retry_blocked:
            return _duplicate_suppressed_result(events=events, ledger=None)
        if retry_session is not None and retry_session.duplicate_suppressed:
            return _duplicate_suppressed_result(events=events, ledger=retry_ledger)
        deadline_unix_ns = (
            retry_session.wall_deadline_unix_ns
            if retry_session is not None
            else requested_deadline_unix_ns
        )
        if (
            retry_session is not None
            and retry_session.resumed_after_crash
            and _remaining_wall_seconds(deadline_unix_ns) == 0.0
        ):
            assert retry_ledger is not None
            return _resumed_wall_deadline_exhausted_result(
                events=events, on_event=on_event, ledger=retry_ledger,
                session=retry_session, dispatch_key=retry_key,
            )
        if retry_session is not None and retry_session.resumed_after_crash:
            durable_remaining = _remaining_wall_seconds(deadline_unix_ns)
            live_remaining = (
                durable_remaining
                if wall_timeout is None or wall_timeout <= 0
                else min(wall_timeout, durable_remaining)
                if durable_remaining is not None
                else wall_timeout
            )
            deadline = (
                None if live_remaining is None
                else runtime_started + live_remaining
            )
        else:
            deadline = (
                runtime_started + wall_timeout
                if wall_timeout is not None and wall_timeout > 0
                else None
            )
        if (
            retry_session is not None
            and retry_session.resumed_after_crash
            and retry_session.attempts_used >= retry_policy.max_attempts
        ):
            assert retry_ledger is not None
            return _resumed_retry_budget_exhausted_result(
                events=events, on_event=on_event, ledger=retry_ledger,
                session=retry_session, dispatch_key=retry_key,
            )
        recoveries = 0
        parent_checkpoint: RecoveryCheckpoint | None = None
        recovery_seed: CandidateWorkspaceSnapshot | None = None
        if retry_session is not None and retry_session.resumed_after_crash:
            try:
                restored_context = _restore_context_after_crash(
                    session=retry_session,
                    config=context_config,
                    execution_contract_sha256=execution_contract_sha256,
                    events=events,
                    on_event=on_event,
                )
            except RetryStateError:
                message = (
                    "[agent-error rc=78] durable context checkpoint failed "
                    "closed validation"
                )
                failure_event = {
                    "type": "angerona_context_recovery",
                    "phase": "failed",
                    "status": "failed",
                    "reason": "invalid_durable_context_checkpoint",
                }
                events.append(failure_event)
                if on_event is not None:
                    on_event("context_compaction", dict(failure_event))
                _record_retry_terminal(
                    retry_session,
                    events,
                    on_event,
                    kind="permanent_failure",
                    dispatch_key=retry_key,
                    reason="invalid_durable_context_checkpoint",
                )
                return AgentResult(
                    ok=False,
                    final_text=message,
                    events=events,
                    returncode=78,
                    raw_stderr=message,
                    context_observations=context_observations,
                )
            if restored_context is not None:
                parent_checkpoint, task, recovery_seed, recoveries = restored_context
                retry_base_task = task
                env["ANGERONA_CONTEXT_RECOVERY_ACTIVE"] = "1"
            else:
                task = _transient_recovery_task(
                    retry_base_task,
                    TransientFailure("interrupted_attempt", "durable_ledger"),
                    retry_session.attempts_used + 1,
                )
            prompt = _compose_agent_task_prompt(effective_system_prompt, task)

        item_started_at: dict[str, tuple[int, int]] = {}

        def on_line(line: str) -> None:
            if not line.strip():
                return
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                return
            received_monotonic_ns = time.monotonic_ns()
            received_time_ns = time.time_ns()
            ev["_angerona_received_monotonic_ns"] = received_monotonic_ns
            ev["_angerona_received_time_ns"] = received_time_ns
            item = ev.get("item") if isinstance(ev.get("item"), dict) else None
            item_id = str(item.get("id") or "") if item else ""
            if item_id and ev.get("type") == "item.started":
                item_started_at[item_id] = (received_monotonic_ns, received_time_ns)
            elif item_id and ev.get("type") == "item.completed":
                started = item_started_at.pop(item_id, None)
                if started is not None:
                    ev["_angerona_started_monotonic_ns"] = started[0]
                    ev["_angerona_started_time_ns"] = started[1]
                    ev["_angerona_duration_ms"] = round(
                        (received_monotonic_ns - started[0]) / 1_000_000, 3
                    )
            events.append(ev)
            _emit_codex_event(ev, on_event)

        def on_heartbeat(data: dict) -> None:
            ev = {"type": "angerona_heartbeat", **data}
            events.append(ev)
            if on_event is not None:
                on_event("heartbeat", data)

        total_seconds = 0.0
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        rc = 1
        text = ""
        while True:
            args = list(base_args)
            if context_config.context_window_tokens is not None:
                config_index = args.index("--cd")
                args[config_index:config_index] = [
                    "-c",
                    f"model_auto_compact_token_limit={context_config.proactive_trigger_tokens}",
                ]
            config_index = args.index("--cd")
            child_env_args: list[str] = []
            if enable_mcp:
                for key, value in _mcp_runtime_env(env, mcp_env).items():
                    child_env_args += [
                        "-c",
                        f"mcp_servers.{server_name}.env.{key}={_toml_str(value)}",
                    ]
            args[config_index:config_index] = child_env_args
            attempt_wall_timeout = wall_timeout
            if deadline is not None:
                attempt_wall_timeout = max(0.0, deadline - time.monotonic())
                if attempt_wall_timeout <= 0:
                    rc = 124
                    text = ""
                    stderr_parts.append("overall wall timeout exhausted")
                    _record_retry_terminal(
                        retry_session, events, on_event, kind="exhausted",
                        dispatch_key=retry_key, reason="wall_timeout_exhausted",
                    )
                    break
            launch_kind = (
                "context_recovery" if recoveries
                else "transient_retry" if retry_session and retry_session.transient_retries_used
                else "initial"
            )
            started_attempt = _start_retry_attempt(
                retry_session, events, on_event,
                dispatch_key=retry_key, launch_kind=launch_kind,
            )
            if retry_session is not None and started_attempt is None:
                retry_session = None
                if retry_ledger is not None:
                    retry_ledger.close()
                    retry_ledger = None
            attempt_start = len(events)
            attempt_snapshots: list[CandidateWorkspaceSnapshot] = []
            rc, out, err, secs = _stream_process(
                args, input_text=prompt, cwd=cwd, env=env,
                idle_timeout=idle_timeout, wall_timeout=attempt_wall_timeout, on_line=on_line,
                on_heartbeat=on_heartbeat,
                recovery_seed=recovery_seed,
                snapshot_sink=attempt_snapshots if isolation_required else None,
            )
            total_seconds += secs
            stdout_parts.append(out)
            stderr_parts.append(err)
            attempt_events = events[attempt_start:]
            text = _codex_final_text(attempt_events) or ""
            if rc == 0 and text.strip():
                _record_retry_terminal(
                    retry_session, events, on_event, kind="success",
                    dispatch_key=retry_key,
                )
                if retry_session is not None and retry_session.transient_retries_used:
                    _emit_retry_event(
                        events, on_event, phase="succeeded", dispatch_key=retry_key,
                        session_id=retry_session.session_id,
                        retries=retry_session.transient_retries_used,
                    )
                break
            overflow = rc != AGENT_EVENT_BOUNDARY_EXIT and is_context_overflow(
                text,
                err,
                out[-20_000:],
                attempt_events[-80:],
            )
            if not overflow or recoveries >= context_config.max_recoveries:
                transient = _schedule_transient_retry(
                    returncode=rc,
                    attempt_events=attempt_events[-80:],
                    stderr=err,
                    session=retry_session,
                    policy=retry_policy,
                    deadline=deadline,
                    dispatch_key=retry_key,
                    events=events,
                    on_event=on_event,
                )
                if transient is not None:
                    task = _transient_recovery_task(
                        retry_base_task,
                        transient,
                        (retry_session.transient_retries_used + 1)
                        if retry_session is not None else 2,
                    )
                    prompt = _compose_agent_task_prompt(effective_system_prompt, task)
                    continue
                if not any(
                    event.get("type") == "angerona_agent_retry"
                    and event.get("phase") == "exhausted"
                    for event in events[-3:]
                ):
                    _record_retry_terminal(
                        retry_session, events, on_event, kind="permanent_failure",
                        dispatch_key=retry_key, returncode=rc,
                    )
                break

            recoveries += 1
            overflow_details = parse_context_overflow_details(
                text,
                err,
                out[-20_000:],
                attempt_events[-80:],
            )
            trusted_overflow_details = parse_trusted_context_overflow_details(
                attempt_events[-80:]
            )
            if isolation_required:
                if not trusted_overflow_details or len(attempt_snapshots) != 1:
                    text = ""
                    stderr_parts.append(
                        "required context recovery state was not authoritatively captured"
                    )
                    break
                recovery_seed = attempt_snapshots[0]
            configured_window = context_config.planning_window_tokens
            if trusted_overflow_details:
                observation = {
                    "source": "typed_provider_error",
                    "agent_family": context_config.agent_family,
                    "model_name": context_config.model_name,
                    "configured_context_window_tokens": configured_window,
                    **trusted_overflow_details,
                }
                context_observations.append(observation)
                if on_context_observation is not None:
                    applied = False

                    def apply_window(window: int) -> ContextHarnessConfig:
                        nonlocal applied
                        if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
                            raise ValueError("invalid authoritative context window")
                        applied = True
                        return apply_observed_context_limit(
                            env, context_config, trusted_overflow_details,
                            trusted=True,
                            authoritative_window_tokens=window,
                            persist_profile=True,
                        )

                    updated_context = on_context_observation(
                        dict(observation), apply_window
                    )
                    if not applied or not isinstance(updated_context, ContextHarnessConfig):
                        raise ValueError(
                            "context observation callback did not atomically apply "
                            "an authoritative window"
                        )
                else:
                    updated_context = apply_observed_context_limit(
                        env, context_config, trusted_overflow_details, trusted=True
                    )
            else:
                updated_context = context_config
            context_config = updated_context
            effective_system_prompt = (
                f"{system_prompt}\n\n{context_checkpoint_system_prompt(context_config)}"
            )
            compaction_id = uuid.uuid4().hex
            compaction_started = time.monotonic()
            pre_compact_event = {
                "type": "angerona_context_compaction",
                "phase": "started",
                "compaction_id": compaction_id,
                "trigger": "auto",
                "reason": "context_limit",
                "attempt": recoveries,
                "context_window_source": context_config.context_window_source,
                **overflow_details,
            }
            events.append(pre_compact_event)
            if on_event is not None:
                on_event("context_compaction", dict(pre_compact_event))
            try:
                checkpoint = write_recovery_checkpoint(
                    cwd=cwd,
                    original_task=original_task,
                    events=attempt_events,
                    stderr=err or text,
                    attempt=recoveries,
                    config=context_config,
                    checkpoint_id=compaction_id,
                    overflow_details=overflow_details,
                    parent_checkpoint=parent_checkpoint,
                    enforce_seed_budget=isolation_required,
                    recovery_snapshot=(
                        recovery_seed.payload if recovery_seed is not None else None
                    ),
                    execution_contract_sha256=execution_contract_sha256,
                )
                recovery_task = build_recovery_task(checkpoint, context_config)
                _record_context_checkpoint(
                    retry_session,
                    checkpoint,
                    attempt=recoveries,
                )
            except (OSError, ValueError, RetryStateError) as exc:
                failure_event = {
                    "type": "angerona_context_compaction",
                    "phase": "failed",
                    "status": "failed",
                    "compaction_id": compaction_id,
                    "trigger": "auto",
                    "reason": "context_limit",
                    "attempt": recoveries,
                    "error": str(exc),
                }
                events.append(failure_event)
                if on_event is not None:
                    on_event("context_compaction", dict(failure_event))
                break
            post_compact_event = {
                "type": "angerona_context_compaction",
                "phase": "completed",
                "status": "completed",
                "compaction_id": compaction_id,
                "trigger": "auto",
                "reason": "context_limit",
                "attempt": recoveries,
                "duration_ms": round((time.monotonic() - compaction_started) * 1000),
                "handoff_path": str(checkpoint.handoff_path),
                "manifest_path": str(checkpoint.manifest_path),
                "manifest_sha256": checkpoint.manifest_sha256,
                "manifest_version": checkpoint.manifest_version,
                **overflow_details,
            }
            events.append(post_compact_event)
            if on_event is not None:
                on_event("context_compaction", dict(post_compact_event))
            recovery_event = {
                "type": "angerona_context_recovery",
                "compaction_id": compaction_id,
                "attempt": recoveries,
                "original_task_path": str(checkpoint.original_task_path),
                "transcript_path": str(checkpoint.transcript_path),
                "stderr_path": str(checkpoint.stderr_path),
                "handoff_path": str(checkpoint.handoff_path),
                "manifest_path": str(checkpoint.manifest_path),
                "manifest_sha256": checkpoint.manifest_sha256,
                "manifest_version": checkpoint.manifest_version,
                "workspace_root": str(checkpoint.workspace_root),
            }
            events.append(recovery_event)
            if on_event is not None:
                on_event("context_compaction", dict(recovery_event))
            retry_base_task = recovery_task
            prompt = _compose_agent_task_prompt(
                effective_system_prompt,
                recovery_task,
            )
            parent_checkpoint = checkpoint
            env["ANGERONA_CONTEXT_RECOVERY_ACTIVE"] = "1"

        # #1 (critique R1): never treat agent stderr / infra error as a report.
        # If the agent did not produce a real message (ok=False or empty), discard
        # the stderr and surface a hard error so the loop can fail the worker
        # instead of echoing auth/error logs into the model context (false pass).
        if text is None or not text.strip():
            text = ""
            if rc != 0:
                text = f"[agent-error rc={rc}] no model output produced"
        raw_stdout = "\n".join(stdout_parts)[-DEFAULT_AGENT_CAPTURE_CHARS:]
        raw_stderr = "\n".join(stderr_parts)[-DEFAULT_AGENT_CAPTURE_CHARS:]
        if retry_ledger is not None:
            retry_ledger.close()
        return AgentResult(
            ok=rc == 0 and bool(text),
            final_text=text,
            events=events,
            returncode=rc,
            seconds=total_seconds,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            context_observations=context_observations,
        )


def _emit_codex_event(ev: dict, on_event: EventCallback | None) -> None:
    if on_event is None:
        return
    etype = ev.get("type", "")
    # Newer Codex schema: {"type":"item.completed","item":{"type":"agent_message"|"mcp_tool_call"|...}}
    if etype in ("item.started", "item.completed"):
        item = ev.get("item") or {}
        itype = item.get("type", "")
        if itype in ("agent_message", "assistant_message", "message") and etype == "item.completed":
            txt = item.get("text") or item.get("message") or ""
            if txt.strip():
                on_event("text", {"text": txt})
        elif itype in ("mcp_tool_call", "tool_call", "function_call"):
            name = item.get("tool") or item.get("name")
            if etype == "item.started":
                on_event("tool_use", {"name": name, "input": item.get("arguments"),
                                      "call_id": item.get("id")})
            else:
                raw_result = item.get("result") or item.get("output") or item.get("error")
                if raw_result is not None and not isinstance(
                    raw_result, (str, bytes, bytearray, memoryview)
                ):
                    raw_result = json.dumps(raw_result, sort_keys=True, default=str)
                failed = bool(item.get("error")) or item.get("status") in {
                    "failed", "error", "cancelled"
                }
                on_event("tool_result", {
                    "name": name,
                    "call_id": item.get("id"),
                    "status": "failed" if failed else "succeeded",
                    "is_error": failed,
                    "duration_ms": ev.get("_angerona_duration_ms"),
                    "content": content_descriptor(raw_result),
                })
        elif itype == "command_execution":
            if etype == "item.started":
                on_event("tool_use", {"name": "shell", "input": item.get("command"),
                                      "call_id": item.get("id")})
            else:
                exit_code = item.get("exit_code")
                failed = exit_code != 0 or item.get("status") in {
                    "failed", "error", "cancelled"
                }
                on_event("tool_result", {
                    "name": "shell",
                    "call_id": item.get("id"),
                    "status": "failed" if failed else "succeeded",
                    "is_error": failed,
                    "exit_code": exit_code,
                    "duration_ms": ev.get("_angerona_duration_ms"),
                    "content": content_descriptor(item.get("aggregated_output") or ""),
                })
        return
    # Older schema: {"msg":{"type":"agent_message","message":...}}
    msg = ev.get("msg") if isinstance(ev.get("msg"), dict) else None
    if not msg:
        return
    mtype = msg.get("type", "")
    if mtype in ("agent_message", "agent_message_delta"):
        txt = msg.get("message") or msg.get("delta") or ""
        if txt.strip():
            on_event("text", {"text": txt})
    elif mtype in ("mcp_tool_call_begin", "tool_call", "mcp_tool_call"):
        on_event("tool_use", {"name": msg.get("tool") or msg.get("name"), "input": msg.get("arguments")})


def _codex_final_text(events: list[dict]) -> str:
    # Newer schema: last completed agent_message.
    for ev in reversed(events):
        if ev.get("type") == "item.completed":
            item = ev.get("item") or {}
            if item.get("type") in ("agent_message", "assistant_message", "message"):
                txt = item.get("text") or item.get("message") or ""
                if txt.strip():
                    return txt
    # Older schema.
    for ev in reversed(events):
        msg = ev.get("msg") if isinstance(ev.get("msg"), dict) else ev
        if msg.get("type") == "agent_message" and (msg.get("message") or "").strip():
            return msg["message"]
    return ""


def _toml_str(s: str) -> str:
    return json.dumps(s)  # JSON string literal is valid TOML basic string


def _toml_array(items: list[str]) -> str:
    return "[" + ",".join(json.dumps(x) for x in items) + "]"
