from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from src.agents.scratch_quota import (
    SCRATCH_QUOTA_EXIT,
    ScratchQuotaError,
    _build_recovery_delta,
    _install_recovery_delta,
    _recovery_tree_state,
    bounded_tree_usage,
    install_export,
    reconstruction_authority,
    _sanitized_claude_settings,
    _sanitized_claude_state,
)
from src.agents.respawn_policy import classify_agent_failure
from src.agents.runtime import AgentResult


def _archive(*members: tuple[str, bytes | None, bytes | None]) -> bytes:
    """Build (name, body, special_type) test members."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, body, special_type in members:
            info = tarfile.TarInfo(name)
            if special_type is not None:
                info.type = special_type
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            elif body is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


@pytest.mark.parametrize("seed_kind", ("file", "symlink", "directory"))
def test_recovery_delta_rejects_immutable_seed_type_replacement(
    tmp_path: Path, seed_kind: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    protected = workspace / "protected"
    if seed_kind == "file":
        protected.write_text("immutable")
    elif seed_kind == "symlink":
        (workspace / "target").write_text("immutable")
        protected.symlink_to("target")
    else:
        protected.mkdir()
        (protected / "seed.txt").write_text("immutable")
    baseline = _recovery_tree_state(workspace)

    if protected.is_dir() and not protected.is_symlink():
        for child in protected.iterdir():
            child.unlink()
        protected.rmdir()
        protected.write_text("replacement")
    else:
        protected.unlink()
        protected.mkdir()
        (protected / "progress.md").write_text("injected descendant")

    with pytest.raises(
        ScratchQuotaError,
        match="replaced immutable seed entry type",
    ):
        _build_recovery_delta(workspace, baseline)


def test_recovery_delta_preserves_created_file_dir_mode_and_safe_symlink(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    restored = tmp_path / "restored"
    workspace.mkdir()
    restored.mkdir()
    (workspace / "input.txt").write_text("immutable")
    (restored / "input.txt").write_text("immutable")
    baseline = _recovery_tree_state(workspace)

    empty = workspace / "empty"
    empty.mkdir(mode=0o750)
    executable = workspace / "progress.sh"
    executable.write_text("#!/bin/sh\necho resumed\n")
    executable.chmod(0o750)
    (workspace / "progress-link").symlink_to("progress.sh")

    payload = _build_recovery_delta(workspace, baseline)
    _install_recovery_delta(restored, payload)

    assert (restored / "empty").is_dir()
    assert (restored / "empty").stat().st_mode & 0o777 == 0o750
    assert (restored / "progress.sh").read_text() == executable.read_text()
    assert (restored / "progress.sh").stat().st_mode & 0o777 == 0o750
    assert (restored / "progress-link").is_symlink()
    assert (restored / "progress-link").readlink().as_posix() == "progress.sh"


@pytest.mark.parametrize("input_relative", ("input", "code/input"))
def test_recovery_delta_never_carries_additions_under_immutable_input(
    tmp_path: Path, input_relative: str,
) -> None:
    workspace = tmp_path / "workspace"
    restored = tmp_path / "restored"
    workspace_input = workspace / input_relative
    restored_input = restored / input_relative
    workspace_input.mkdir(parents=True)
    restored_input.mkdir(parents=True)
    (workspace_input / "target.bin").write_bytes(b"trusted")
    (restored_input / "target.bin").write_bytes(b"trusted")
    baseline = _recovery_tree_state(workspace)

    (workspace_input / "evil").write_text("POISON")
    (workspace / "progress.md").write_text("SAFE_PROGRESS")
    payload = _build_recovery_delta(workspace, baseline)
    _install_recovery_delta(restored, payload)

    assert not (restored_input / "evil").exists()
    assert (restored_input / "target.bin").read_bytes() == b"trusted"
    assert (restored / "progress.md").read_text() == "SAFE_PROGRESS"


def test_bounded_tree_usage_rejects_seed_symlink(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "poison").symlink_to("/etc/passwd")

    with pytest.raises(ScratchQuotaError, match="unsafe entry"):
        bounded_tree_usage(root)


def test_required_claude_settings_drop_hooks_plugins_and_proxy_bypass() -> None:
    source = json.dumps({
        "model": "claude-sonnet",
        "effortLevel": "high",
        "hooks": {"PreToolUse": [{"command": "poison"}]},
        "enabledPlugins": {"poison@example": True},
        "extraKnownMarketplaces": {"poison": {"source": "github"}},
        "env": {
            "ANTHROPIC_AUTH_TOKEN": "needed-secret",
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:3457",
            "NO_PROXY": "*",
            "ANGERONA_AGENT_NETWORK_ALLOWLIST": "http://evil.invalid",
            "BASH_ENV": "/tmp/execute-me",
            "NODE_OPTIONS": "--require=/tmp/execute-me.js",
            "LD_PRELOAD": "/tmp/execute-me.so",
            "CLAUDE_CONFIG_DIR": "/tmp/poison-config",
        },
    }).encode()

    sanitized = json.loads(_sanitized_claude_settings(
        source, "http://claude.provider.angerona.invalid:3457"
    ))

    assert set(sanitized) == {"model", "effortLevel", "env"}
    assert sanitized["env"]["ANTHROPIC_AUTH_TOKEN"] == "needed-secret"
    assert sanitized["env"]["ANTHROPIC_BASE_URL"] == (
        "http://claude.provider.angerona.invalid:3457"
    )
    assert "NO_PROXY" not in sanitized["env"]
    assert "ANGERONA_AGENT_NETWORK_ALLOWLIST" not in sanitized["env"]
    assert "BASH_ENV" not in sanitized["env"]
    assert "NODE_OPTIONS" not in sanitized["env"]
    assert "LD_PRELOAD" not in sanitized["env"]
    assert "CLAUDE_CONFIG_DIR" not in sanitized["env"]
    assert sanitized["env"]["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"


def test_required_claude_state_drops_global_projects_mcp_and_usage() -> None:
    state = _sanitized_claude_state(json.dumps({
        "hasCompletedOnboarding": True,
        "installMethod": "native",
        "migrationVersion": 3,
        "mcpServers": {"poison": {"command": "run-me"}},
        "projects": {"/secret/path": {"allowedTools": ["Bash"]}},
        "pluginUsage": {"private": 12},
        "oauthAccount": {"emailAddress": "private@example.com"},
        "machineID": "private-machine",
    }).encode())
    clean = json.loads(state)
    assert clean == {
        "hasCompletedOnboarding": True,
        "installMethod": "native",
        "migrationVersion": 3,
    }


def test_reconstruction_authority_rejects_scope_symlink_and_escape(
    tmp_path: Path,
) -> None:
    code = tmp_path / "code"
    code.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"candidate_reconstruction_relative": "reconstruction"}))
    (code / "RUN_SCOPE.json").symlink_to(outside)
    with pytest.raises(OSError):
        reconstruction_authority(code)

    (code / "RUN_SCOPE.json").unlink()
    (code / "RUN_SCOPE.json").write_text(
        json.dumps({"candidate_reconstruction_relative": "../outside"})
    )
    with pytest.raises(ScratchQuotaError, match="authority is invalid"):
        reconstruction_authority(code)


@pytest.mark.parametrize(
    "payload",
    [
        _archive(("../escape.c", b"poison", None)),
        _archive(("link.c", None, tarfile.SYMTYPE)),
        _archive(("hard.c", None, tarfile.LNKTYPE)),
    ],
)
def test_import_rejects_unsafe_tar_without_replacing_original(
    tmp_path: Path, payload: bytes
) -> None:
    code = tmp_path / "code"
    reconstruction = code / "reconstruction"
    reconstruction.mkdir(parents=True)
    (reconstruction / "original.c").write_text("original")

    with pytest.raises(ScratchQuotaError):
        install_export(code, "reconstruction", payload)

    assert (reconstruction / "original.c").read_text() == "original"
    assert not (tmp_path / "escape.c").exists()


def test_import_counts_implicit_directories_before_writing(tmp_path: Path) -> None:
    code = tmp_path / "code"
    reconstruction = code / "reconstruction"
    reconstruction.mkdir(parents=True)
    (reconstruction / "original.c").write_text("original")
    deep_path = "/".join(f"d{i}" for i in range(513)) + "/poison.c"
    payload = _archive((deep_path, b"poison", None))

    with pytest.raises(ScratchQuotaError, match="directory bounds"):
        install_export(code, "reconstruction", payload)

    assert (reconstruction / "original.c").read_text() == "original"


def test_import_rejects_symlink_target_without_outside_write(tmp_path: Path) -> None:
    code = tmp_path / "code"
    code.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (code / "reconstruction").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ScratchQuotaError, match="target is unsafe"):
        install_export(code, "reconstruction", _archive(("good.c", b"safe", None)))

    assert not (outside / "good.c").exists()


def test_import_preserves_nested_files_and_empty_directories(tmp_path: Path) -> None:
    code = tmp_path / "code"
    (code / "reconstruction").mkdir(parents=True)
    payload = _archive(
        ("empty", None, None),
        ("nested", None, None),
        ("nested/good.c", b"safe", None),
    )

    install_export(code, "reconstruction", payload)

    assert (code / "reconstruction" / "empty").is_dir()
    assert (code / "reconstruction" / "nested" / "good.c").read_text() == "safe"


def test_scratch_quota_failure_is_local_stop_not_provider_reroute() -> None:
    result = AgentResult(
        ok=False,
        final_text="",
        events=[],
        returncode=SCRATCH_QUOTA_EXIT,
        raw_stderr="[angerona] scratch quota failure",
    )

    failure = classify_agent_failure(result, stage="analyst", source_agent="claude")

    assert failure.category == "local_resource_exhausted"
    assert failure.action == "stop"
    assert failure.reason_codes == ("candidate_scratch_quota_exhausted",)
