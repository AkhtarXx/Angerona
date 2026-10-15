"""Resolved, secret-free execution contract for exact audit resumption."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from ..subprocess_observability import observed_run
from typing import Any, Mapping

from ..analysis.anchor_idl import (
    anchor_idl_contract,
    resolve_anchor_idl,
    validate_anchor_resolution_binary,
)
from ..analysis.similarity_corpus import similarity_corpus_contract
from ..analysis.simindex import AUDIT_SIMILARITY_POLICY
from ..config import Config
from ..mcp.config import allowed_tool_patterns, server_launch_spec
from ..observability import observability_policy_contract
from .audit_state import AuditStateError
from .budget_harness import AuditBudgetPolicy
from .context_harness import (
    RECOVERY_CHECKPOINT_VERSION,
    ContextHarnessConfig,
    resolve_model_selector,
)
from .retry_harness import RetryPolicy
from .scratch_quota import scratch_quota_contract
from .network_guard import candidate_network_contract


_SAFE_PROVIDER_ENV = (
    "ANGERONA_AGENT_MODEL",
    "ANGERONA_CLAUDE_MODEL",
    "ANGERONA_CODEX_MODEL",
    "ANGERONA_LOCAL_MODEL_NAME",
    "ANTHROPIC_MODEL",
    "CLAUDE_MODEL",
    "OPENAI_MODEL",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_BASE",
    "CLAUDE_API_BASE",
    "OPENAI_BASE_URL",
    "ANGERONA_LOCAL_BASE_URL",
)

_BEHAVIOR_INT_DEFAULTS = {
    "ANGERONA_MAX_AGENT_CAPTURE_CHARS": 200_000,
    "ANGERONA_MAX_AGENT_EVENT_LINE_CHARS": 1_000_000,
    "ANGERONA_AGENT_HEARTBEAT_SECONDS": 30,
    "ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_BYTES": 256 * 1024 * 1024,
    "ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_FILES": 4_096,
}

_AUTO_ANCHOR_RESOLUTION = object()


def _resolved_bool_env(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _resolved_int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def _file_identity(path_value: str | Path | None) -> dict[str, Any] | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return {"path": str(path), "available": False}
    if not resolved.is_file():
        return {"path": str(resolved), "available": False}
    digest = hashlib.sha256()
    size = 0
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {
        "path": str(resolved),
        "available": True,
        "size": size,
        "sha256": digest.hexdigest(),
    }


def _command_identity(command: str) -> dict[str, Any]:
    resolved = shutil.which(command) or command
    identity = _file_identity(resolved) or {"path": command, "available": False}
    version = ""
    if identity.get("available"):
        try:
            result = observed_run(
                [str(identity["path"]), "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=5,
                check=False,
            )
            version = (result.stdout or "").strip()[:1_000]
        except (OSError, subprocess.SubprocessError):
            version = ""
    return {**identity, "version": version}


def _python_distribution_identity(
    python_value: str | Path | None,
    distribution: str,
) -> dict[str, Any] | None:
    """Hash an installed Python tool, not merely its interpreter path."""

    executable = _file_identity(python_value)
    if executable is None:
        return None
    result: dict[str, Any] = {"executable": executable, "distribution": distribution}
    if not executable.get("available"):
        return result
    script = (
        "import hashlib,importlib.metadata as m,json,pathlib\n"
        f"d=m.distribution({distribution!r})\n"
        "h=hashlib.sha256(); rows=[]\n"
        "for rel in sorted(d.files or [],key=lambda x:str(x)):\n"
        " p=pathlib.Path(d.locate_file(rel))\n"
        " if not p.is_file(): continue\n"
        " b=p.read_bytes(); name=str(rel).replace('\\\\','/')\n"
        " fh=hashlib.sha256(b).hexdigest(); rows.append([name,len(b),fh])\n"
        " h.update(name.encode()); h.update(b'\\0'); h.update(bytes.fromhex(fh))\n"
        "print(json.dumps({'version':d.version,'tree_sha256':h.hexdigest(),'files':rows},sort_keys=True))\n"
    )
    try:
        completed = observed_run(
            [str(executable["path"]), "-c", script],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        if completed.returncode == 0:
            result["installed"] = json.loads((completed.stdout or "").strip())
        else:
            result["installed"] = {
                "available": False,
                "probe_sha256": hashlib.sha256(
                    (completed.stdout or "").encode("utf-8", errors="replace")
                ).hexdigest(),
            }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        result["installed"] = {
            "available": False,
            "error_type": type(exc).__name__,
        }
    return result


def _source_identity() -> dict[str, Any]:
    src_root = Path(__file__).resolve().parents[1]
    selected = sorted(
        path for path in src_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".py", ".java", ".json", ".toml"}
    )
    entries: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for path in sorted(set(selected)):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        relative = path.relative_to(src_root).as_posix()
        file_digest = hashlib.sha256(raw).hexdigest()
        entries.append({"path": relative, "sha256": file_digest, "size": len(raw)})
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_digest))
    return {"tree_sha256": digest.hexdigest(), "files": entries}


def _model_identity(model: str | None, agent_names: list[str]) -> dict[str, str]:
    if model:
        return {"value": str(model), "source": "explicit"}
    families = {str(agent) for agent in agent_names if agent}
    if len(families) == 1:
        value, source = resolve_model_selector(
            os.environ,
            model_hint=None,
            agent_family=next(iter(families)),
        )
        if value != "unknown":
            return {"value": value, "source": source}
    elif families:
        return {"value": "per-agent", "source": "agent_models"}
    # Provider defaults cannot be named without making a model request. Pin all
    # locally observable selectors and label this honestly rather than inventing
    # a model ID.
    return {
        "value": "provider-default",
        "source": "provider-default (locally pinned; remote alias must remain stable)",
    }


def resolve_agent_models(
    *,
    requested_model: str | None,
    configured_agents: set[str],
    agents: set[str],
    env: Mapping[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    """Resolve one honest model identity per provider/runtime."""

    source = env if env is not None else os.environ
    owners = {str(agent) for agent in configured_agents if agent}
    if requested_model and len(owners) != 1:
        raise ValueError(
            "one --model override cannot target multiple agent runtimes; "
            "use provider-specific model environments for mixed-agent audits"
        )
    explicit_owner = next(iter(owners)) if requested_model else ""
    resolved: dict[str, dict[str, str]] = {}
    for agent in sorted({str(item) for item in agents if item}):
        hint = requested_model if agent == explicit_owner else None
        value, selector_source = resolve_model_selector(
            source,
            model_hint=hint,
            agent_family=agent,
        )
        if value == "unknown":
            value = "provider-default"
            selector_source = (
                "provider-default (locally pinned; remote alias must remain stable)"
            )
        resolved[agent] = {"value": value, "source": selector_source}
    return resolved


def _agent_configuration(agent: str) -> list[dict[str, Any]]:
    home = Path.home()
    source_root = Path(__file__).resolve().parents[2]
    if agent == "codex":
        candidates = [home / ".codex" / "config.toml", source_root / ".codex" / "config.toml"]
    else:
        candidates = [
            home / ".claude.json",
            home / ".claude" / "settings.json",
            source_root / ".claude" / "settings.json",
            source_root / ".claude" / "settings.local.json",
            source_root / "CLAUDE.md",
        ]
    return [identity for path in candidates if (identity := _file_identity(path)) is not None]


def _engine_identity(config: Config) -> dict[str, Any]:
    if config.engine == "ida":
        markers = [getattr(config, "idat", None), getattr(config, "libidalib", None)]
        install = getattr(config, "ida_install", None)
    else:
        markers = [getattr(config, "analyze_headless", None)]
        install = getattr(config, "ghidra_install", None)
        if install:
            markers.append(Path(install) / "Ghidra" / "application.properties")
    return {
        "engine": config.engine,
        "install": str(Path(install).resolve()) if install else None,
        "markers": [_file_identity(marker) for marker in markers if marker],
        "java_home": str(getattr(config, "java_home", "") or ""),
        "sandbox": bool(getattr(config, "sandbox", False)),
    }


def _similarity_runtime_identity(configured: bool) -> dict[str, Any]:
    if not configured:
        return {"configured": False, "policy": AUDIT_SIMILARITY_POLICY}
    import numpy as np

    try:
        core_path = np._core._multiarray_umath.__file__  # type: ignore[attr-defined]
    except AttributeError:
        core_path = None
    return {
        "configured": True,
        "policy": AUDIT_SIMILARITY_POLICY,
        "numpy_version": np.__version__,
        "numpy_module": _file_identity(np.__file__),
        "numpy_core": _file_identity(core_path),
    }


def build_run_contract(
    *,
    config: Config,
    binary: str,
    model: str | None,
    supervisor: str,
    worker_analyst: str,
    worker_reviewer: str,
    idle_timeout: float,
    wall_timeout: float | None,
    cheap_agent: str | None = None,
    available_agents: set[str] | None = None,
    agent_models: Mapping[str, Mapping[str, str]] | None = None,
    pinned_context_windows: Mapping[str, int] | None = None,
    audit_budget_policy: AuditBudgetPolicy | None = None,
    anchor_idl: str | Path | None = None,
    anchor_idl_resolution: dict[str, Any] | None | object = _AUTO_ANCHOR_RESOLUTION,
    similarity_corpus_resolution: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Resolve everything that can alter future model/tool behavior, excluding secrets."""

    configured_agents = {supervisor, worker_analyst, worker_reviewer}
    agents = sorted(
        configured_agents
        | ({cheap_agent} if cheap_agent else set())
        | set(available_agents or set())
    )
    commands = {
        "claude": os.environ.get("ANGERONA_CLAUDE_CMD") or "claude",
        "codex": os.environ.get("ANGERONA_CODEX_CMD") or "codex",
    }
    try:
        mcp_command, mcp_args, mcp_env = server_launch_spec(binary, config)
    except AttributeError:
        # Lightweight fake configs are used by deterministic unit tests. The
        # production Config path always resolves the complete MCP identity.
        mcp_command, mcp_args, mcp_env = ("unavailable", [], {})
    target = str(Path(binary).expanduser().resolve())
    source_root = str(Path(__file__).resolve().parents[2])

    def normalize(value: str) -> str:
        return value.replace(target, "<TARGET>").replace(source_root, "<ANGERONA_SOURCE>")

    model_identity = _model_identity(model, agents)
    discovered_agent_models = resolve_agent_models(
        requested_model=model,
        configured_agents=configured_agents,
        agents=set(agents),
    )
    resolved_agent_models = (
        {
            str(agent): {
                "value": str(identity.get("value") or "provider-default"),
                "source": str(identity.get("source") or "provider-default"),
            }
            for agent, identity in agent_models.items()
        }
        if agent_models is not None
        else discovered_agent_models
    )
    if set(resolved_agent_models) != set(agents):
        raise ValueError("per-agent model map does not match executable agent set")
    if resolved_agent_models != discovered_agent_models:
        raise ValueError("per-agent model map does not match provider selectors")
    retry_policy = RetryPolicy.from_env(os.environ)
    budget_policy = audit_budget_policy or AuditBudgetPolicy.from_env(os.environ)
    resolved_anchor_idl = (
        resolve_anchor_idl(binary, anchor_idl)
        if anchor_idl_resolution is _AUTO_ANCHOR_RESOLUTION
        else anchor_idl_resolution
    )
    validate_anchor_resolution_binary(binary, resolved_anchor_idl)
    context_contract = {}
    for agent in agents:
        agent_model = resolved_agent_models[agent]
        model_hint = (
            None if agent_model["value"] == "provider-default" else agent_model["value"]
        )
        discovered_context = ContextHarnessConfig.from_env(
            os.environ,
            model_hint=model_hint,
            agent_family=agent,
        )
        pinned_window = int(
            (pinned_context_windows or {}).get(agent)
            or discovered_context.planning_window_tokens
        )
        pinned_env = dict(os.environ)
        pinned_env["ANGERONA_CONTEXT_WINDOW_TOKENS"] = str(pinned_window)
        context = ContextHarnessConfig.from_env(
            pinned_env,
            model_hint=model_hint,
            agent_family=agent,
        )
        context_contract[agent] = {
            "model_name": context.model_name,
            "pinned_context_window_tokens": pinned_window,
            "compact_percent": context.compact_percent,
            "max_recoveries": context.max_recoveries,
            "inline_payload_tokens": context.inline_payload_tokens,
            "recent_capsule_chars": context.recent_capsule_chars,
            "compact_prompt_sha256": hashlib.sha256(
                context.compact_prompt.encode("utf-8")
            ).hexdigest(),
            "tool_output_token_limit": context.tool_output_token_limit,
            "tool_output_token_limit_ceiling": context.tool_output_token_limit_ceiling,
            "tool_output_session_budget_tokens": context.tool_output_session_budget_tokens,
            "tool_output_preview_chars": context.tool_output_preview_chars,
            "recovery_checkpoint_version": RECOVERY_CHECKPOINT_VERSION,
        }
    contract: dict[str, Any] = {
        "schema_version": 13,
        "model": model_identity,
        "agent_models": resolved_agent_models,
        "provider_environment": {
            key: os.environ.get(key, "") for key in _SAFE_PROVIDER_ENV
        },
        "agents": {agent: _command_identity(commands[agent]) for agent in agents},
        "agent_configuration": {
            agent: _agent_configuration(agent) for agent in agents
        },
        "engine": _engine_identity(config),
        "mcp": {
            "command": _command_identity(mcp_command),
            "args": [normalize(str(item)) for item in mcp_args],
            "env": {
                key: normalize(str(value))
                for key, value in sorted(mcp_env.items())
            },
            "allowed_tools": allowed_tool_patterns(config.engine),
            "upstream_runtime": (
                _python_distribution_identity(
                    mcp_env.get("ANGERONA_IDA_MCP_PYTHON"), "ida-pro-mcp"
                )
                if config.engine == "ida"
                else None
            ),
        },
        "context": context_contract,
        "transient_retry": {
            "max_attempts": retry_policy.max_attempts,
            "base_delay_seconds": retry_policy.base_delay_seconds,
            "max_delay_seconds": retry_policy.max_delay_seconds,
            "jitter_ratio": retry_policy.jitter_ratio,
            "min_remaining_seconds": retry_policy.min_remaining_seconds,
        },
        "audit_budget": {
            **budget_policy.as_dict(),
            "policy_sha256": budget_policy.sha256,
        },
        "anchor_idl": anchor_idl_contract(resolved_anchor_idl),
        "similarity_corpus": similarity_corpus_contract(
            similarity_corpus_resolution or []
        ),
        "similarity_runtime": _similarity_runtime_identity(
            bool(similarity_corpus_resolution)
        ),
        "runtime_policy": {
            "observability": observability_policy_contract(os.environ),
            "candidate_scratch": scratch_quota_contract(),
            "candidate_network": candidate_network_contract(os.environ),
            "agent_fs_sandbox": _resolved_bool_env(
                "ANGERONA_AGENT_FS_SANDBOX", default=True
            ),
            "mcp_allow_write": _resolved_bool_env(
                "ANGERONA_MCP_ALLOW_WRITE", default=False
            ),
            "allow_claude_compat_gateway": _resolved_bool_env(
                "ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY", default=False
            ),
            "mcp_timeout": os.environ.get("MCP_TIMEOUT", ""),
            "mcp_tool_timeout": os.environ.get("MCP_TOOL_TIMEOUT", ""),
            "ida_mcp_child_command_sha256": hashlib.sha256(
                os.environ.get("ANGERONA_IDA_MCP_CHILD_CMD", "").encode("utf-8")
            ).hexdigest(),
            "allow_full_ida_sweep": _resolved_bool_env(
                "ANGERONA_ALLOW_FULL_IDA_SWEEP", default=False
            ),
            **{
                key.lower(): _resolved_int_env(key, default)
                for key, default in _BEHAVIOR_INT_DEFAULTS.items()
            },
        },
        "timeouts": {
            "idle_seconds": float(idle_timeout),
            "wall_seconds": None if wall_timeout is None else float(wall_timeout),
        },
        "source": _source_identity(),
        "exact_resume_ready": all(
            identity["value"] != "provider-default"
            for identity in resolved_agent_models.values()
        ),
    }
    contract["sha256"] = hashlib.sha256(_canonical(contract)).hexdigest()
    return contract


def validate_run_contract(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> None:
    if not expected.get("exact_resume_ready"):
        raise AuditStateError(
            "exact resume refused because the original audit used an unresolved provider-default "
            "model; start resumable audits with --model or a pinned model environment variable"
        )
    if dict(expected) == dict(actual):
        return
    differing = sorted(
        key for key in set(expected) | set(actual) if expected.get(key) != actual.get(key)
    )
    raise AuditStateError(
        "audit execution contract changed; exact resume refused (drift: "
        + ", ".join(differing)
        + ")"
    )
