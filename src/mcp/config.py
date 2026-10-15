"""Generate and register the active engine's MCP server with Claude Code and Codex.

Engine-aware:
* ``ghidra`` — our stdlib Ghidra MCP server (``python -m src.mcp.server``),
  registered under the server name ``ghidra``.
* ``ida``    — the upstream ``ida-pro-mcp`` headless supervisor
  (``python -m ida_pro_mcp.idalib_supervisor --stdio``) from a repo-local venv,
  registered under the server name ``ida``.

Both Claude Code and Codex speak MCP natively; this writes the client-specific
launch spec so a subscription-driven agent can discover the RE tools.
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..config import Config, load_config, ida_mcp_venv

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# ida-pro-mcp is MIT-licensed and installed from the upstream repo. Pinned to a specific
# commit for reproducibility + supply-chain safety (override with ANGERONA_IDA_MCP_COMMIT
# for a newer commit/tag, or ANGERONA_IDA_MCP_PACKAGE for a full pip/uv spec or local path).
IDA_MCP_COMMIT = os.environ.get("ANGERONA_IDA_MCP_COMMIT", "abb2732ad0d759d750c2e38b616f7f3e949ed2f9")
IDA_MCP_PACKAGE = os.environ.get(
    "ANGERONA_IDA_MCP_PACKAGE",
    f"https://github.com/mrexodia/ida-pro-mcp/archive/{IDA_MCP_COMMIT}.zip",
)
IDA_MCP_PYTHON_VERSION = os.environ.get("ANGERONA_IDA_MCP_PYTHON_VERSION", "3.12")

GHIDRA_TOOL_NAMES = [
    "ghidra_status", "ghidra_analyze", "binary_security_properties", "detonate_sample",
    "list_functions", "decompile_function", "disassemble_function", "list_strings",
    "list_imports", "list_exports", "list_symbols", "get_xrefs", "search",
    # BinDiff structural verification (the "reality anchor")
    "bindiff_match", "verify_understanding", "verify_reconstruction", "verify_claims",
    "verify_capabilities",
]

# idalib-mcp tools (management + read + common modification). Not exhaustive — the
# agent runs with permissions bypassed so this list is advisory, not a hard gate.
IDA_TOOL_NAMES = [
    "idb_open", "idb_list", "idb_save", "server_health",
    "decompile", "disasm", "analyze_funcs", "list_funcs", "list_globals", "lookup_funcs",
    "imports", "xrefs_to", "xrefs_to_field", "callees", "callgraph", "basic_blocks",
    "get_string", "get_bytes", "get_int", "get_global_value", "int_convert",
    "find", "find_regex", "find_bytes", "find_insns", "stack_frame",
    "read_struct", "search_structs", "export_funcs", "infer_types",
    "set_comments", "rename", "declare_type", "set_type",
    # engine-agnostic tools injected by our IDA MCP proxy (parity with Ghidra mode)
    "binary_security_properties", "detonate_sample",
    # BinDiff structural verification (parity with Ghidra mode)
    "bindiff_match", "verify_understanding", "verify_reconstruction", "verify_claims",
    "verify_capabilities",
]


def server_name(engine: str) -> str:
    return "ida" if engine == "ida" else "ghidra"


def tool_names(engine: str) -> list[str]:
    return IDA_TOOL_NAMES if engine == "ida" else GHIDRA_TOOL_NAMES


def allowed_tool_patterns(engine: str = "ghidra") -> list[str]:
    """Client allowed-tool identifiers (``mcp__<server>__<tool>``) for the engine."""
    name = server_name(engine)
    return [f"mcp__{name}__{t}" for t in tool_names(engine)]


# ----------------------------------------------------------------- ida provisioning

def ensure_ida_mcp_env(config: Config | None = None) -> tuple[bool, str]:
    """Ensure a repo-local venv with ``ida-pro-mcp`` exists. Idempotent.

    Uses ``uv`` when available (fast, can fetch a managed interpreter), else the
    stdlib ``venv`` + ``pip``. Returns (ok, message).
    """
    config = config or load_config("ida")
    venv = ida_mcp_venv()
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def _importable() -> bool:
        if not py.exists():
            return False
        # Verify the package is actually installed (a half-finished venv has a python
        # but no ida_pro_mcp). This imports the supervisor, which does NOT import idapro.
        r = subprocess.run([str(py), "-c", "import ida_pro_mcp.idalib_supervisor"],
                           capture_output=True, text=True, check=False)
        return r.returncode == 0

    if _importable():
        return True, f"ida-pro-mcp already provisioned at {venv}"

    uv = shutil.which("uv")
    try:
        if uv:
            r = subprocess.run([uv, "venv", "--python", IDA_MCP_PYTHON_VERSION, str(venv)],
                               capture_output=True, text=True, check=False)
            if not py.exists():
                return False, f"`uv venv` failed:\n{(r.stdout + r.stderr)[-1500:]}"
            r = subprocess.run([uv, "pip", "install", "--python", str(py), IDA_MCP_PACKAGE],
                               capture_output=True, text=True, check=False)
        else:
            import sys as _sys
            if _sys.version_info < (3, 11):
                return False, ("ida-pro-mcp requires Python >= 3.11 but no `uv` is available and "
                               f"this interpreter is {_sys.version_info.major}.{_sys.version_info.minor}. "
                               "Install uv (https://astral.sh/uv) or a Python >= 3.11.")
            r = subprocess.run([_sys.executable, "-m", "venv", str(venv)],
                               capture_output=True, text=True, check=False)
            if not py.exists():
                return False, f"`python -m venv` failed:\n{(r.stdout + r.stderr)[-1500:]}"
            r = subprocess.run([str(py), "-m", "pip", "install", "-q", IDA_MCP_PACKAGE],
                               capture_output=True, text=True, check=False)
    except Exception as exc:  # noqa: BLE001
        return False, f"provisioning error: {exc}"

    if r.returncode != 0:
        return False, f"installing ida-pro-mcp failed:\n{(r.stdout + r.stderr)[-1800:]}"
    if not _importable():
        return False, "installed ida-pro-mcp but `import ida_pro_mcp.idalib_supervisor` still fails"
    return True, f"provisioned ida-pro-mcp into {venv}"


# ------------------------------------------------------------------- launch spec

def server_launch_spec(binary: str | None, config: Config | None = None) -> tuple[str, list[str], dict[str, str]]:
    """Return (command, args, env) that launches the active engine's stdio MCP server."""
    config = config or load_config()
    if config.engine == "ida":
        return _ida_launch_spec(binary, config)
    return _ghidra_launch_spec(binary, config)


def _target_scope_env(binary: str | None) -> dict[str, str]:
    if not binary:
        return {}
    path = Path(binary).expanduser().resolve()
    env = {
        "ANGERONA_TARGET_BINARY": str(path),
        "ANGERONA_REQUIRE_TARGET_BINARY": "1",
    }
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        env["ANGERONA_TARGET_SHA256"] = h.hexdigest()
    except OSError:
        pass
    return env


def _ghidra_launch_spec(binary, config: Config) -> tuple[str, list[str], dict[str, str]]:
    command = sys.executable or "python3"
    args = ["-m", "src.mcp.server"]
    if binary:
        args += ["--binary", str(Path(binary).expanduser().resolve())]
    env: dict[str, str] = {"PYTHONPATH": str(REPO_ROOT), **_target_scope_env(binary)}
    if config.ghidra_install:
        env["GHIDRA_INSTALL_DIR"] = str(config.ghidra_install)
    if config.java_home:
        env["JAVA_HOME"] = config.java_home
    env["ANGERONA_HOME"] = str(config.state_dir)
    if config.sandbox:
        env["ANGERONA_SANDBOX"] = "1"
    return command, args, env


def _ida_launch_spec(binary, config: Config) -> tuple[str, list[str], dict[str, str]]:
    # We launch OUR proxy (stdlib, in this repo), which spawns the real idalib-mcp and
    # (a) wraps its output as untrusted data and (b) injects binary_security_properties +
    # detonate_sample so IDA mode has Ghidra-mode safety-tool parity.
    py = config.ida_mcp_python or (ida_mcp_venv() / "bin" / "python")
    # One idalib worker per supervisor: each agent (supervisor + workers) launches its own
    # server, so keep the per-server DB count minimal to avoid N IDA kernels on one host.
    max_workers = os.environ.get("ANGERONA_IDA_MAX_WORKERS", "1")
    command = sys.executable or "python3"
    args = ["-m", "src.mcp.ida_proxy"]
    # NB: we deliberately do NOT pass the binary positionally — auto-opening at startup
    # would block the MCP handshake on a large binary. The agent calls idb_open itself.
    env: dict[str, str] = {
        "PYTHONPATH": str(REPO_ROOT),
        "ANGERONA_IDA_MCP_PYTHON": str(py),
        "IDA_MCP_MAX_WORKERS": str(max_workers),
        "ANGERONA_HOME": str(config.state_dir),
        "ANGERONA_IDA_LOCK_FILE": str(config.state_dir / "locks" / "ida.lock"),
        **_target_scope_env(binary),
    }
    if config.ida_install:
        env["IDADIR"] = str(config.ida_install)
    if config.sandbox:
        env["ANGERONA_SANDBOX"] = "1"
    return command, args, env


# ------------------------------------------------------------------- claude/codex

def claude_mcp_config(binary: str | None, config: Config | None = None) -> dict:
    config = config or load_config()
    command, args, env = server_launch_spec(binary, config)
    return {"mcpServers": {server_name(config.engine): {"command": command, "args": args, "env": env}}}


def write_claude_mcp_config(path: str | Path, binary: str | None, config: Config | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(claude_mcp_config(binary, config), indent=2))
    return path


def install_claude_user(binary: str | None = None, config: Config | None = None) -> tuple[bool, str]:
    """Register the active engine's MCP server with Claude Code at user scope."""
    config = config or load_config()
    claude = shutil.which(os.environ.get("ANGERONA_CLAUDE_CMD", "claude"))
    if not claude:
        return False, "claude CLI not found on PATH"
    name = server_name(config.engine)
    command, args, env = server_launch_spec(binary, config)
    subprocess.run([claude, "mcp", "remove", name, "--scope", "user"],
                   capture_output=True, text=True, check=False)
    cmd = [claude, "mcp", "add", name, "--scope", "user"]
    for k, v in env.items():
        cmd += ["--env", f"{k}={v}"]
    cmd += ["--", command, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ok = proc.returncode == 0
    return ok, (proc.stdout + proc.stderr).strip()


def codex_config_block(binary: str | None, config: Config | None = None) -> str:
    config = config or load_config()
    name = server_name(config.engine)
    command, args, env = server_launch_spec(binary, config)
    lines = [f"[mcp_servers.{name}]", f"command = {json.dumps(command)}",
             f"args = [{', '.join(json.dumps(a) for a in args)}]"]
    if env:
        lines.append(f"[mcp_servers.{name}.env]")
        for k, v in env.items():
            lines.append(f"{k} = {json.dumps(v)}")
    return "\n".join(lines) + "\n"


def install_codex(binary: str | None = None, config: Config | None = None,
                  config_path: str | Path | None = None) -> tuple[bool, str]:
    """Append/replace the ``[mcp_servers.<engine>]`` block in ~/.codex/config.toml."""
    config = config or load_config()
    name = server_name(config.engine)
    section = f"[mcp_servers.{name}]"
    env_section = f"[mcp_servers.{name}.env]"
    path = Path(config_path or os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    if path.is_dir():
        path = path / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text() if path.exists() else ""
    block = codex_config_block(binary, config)

    if section in existing:
        lines = existing.splitlines(keepends=True)
        out: list[str] = []
        skipping = False
        for line in lines:
            stripped = line.strip()
            if stripped == section or stripped == env_section:
                skipping = True
                continue
            # A new top-level section that is NOT our block header ends the skip. Exact
            # match (not startswith) so a sibling like [mcp_servers.idafoo] isn't swallowed.
            if skipping and stripped.startswith("[") and stripped not in (section, env_section):
                skipping = False
            if not skipping:
                out.append(line)
        existing = "".join(out).rstrip() + "\n"

    new_content = (existing.rstrip() + "\n\n" + block) if existing.strip() else block
    if path.exists():
        backup = path.with_suffix(".toml.angerona-backup")
        if not backup.exists():
            backup.write_text(path.read_text())
    path.write_text(new_content)
    return True, f"wrote {section} to {path}"
