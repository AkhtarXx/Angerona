from pathlib import Path
import json
import subprocess

import pytest

from src.mcp.radare2_provider import Radare2McpProvider


def test_radare2_mcp_plan_is_readonly_sandboxed_and_ignores_user_state(
    tmp_path: Path, monkeypatch
) -> None:
    server = tmp_path / "r2mcp"
    server.write_text("binary")
    server.chmod(0o755)
    monkeypatch.setattr(
        "src.mcp.radare2_provider.shutil.which",
        lambda name: "/usr/bin/r2pm" if name == "r2pm" else None,
    )
    monkeypatch.setattr(Radare2McpProvider, "server_executable", staticmethod(lambda: str(server)))

    plan = Radare2McpProvider().launch_plan(tmp_path)

    assert plan.argv == (
        "/usr/bin/r2pm", "-r", "r2mcp", "-R", "-s", str(tmp_path.resolve()),
        "-n", "-N", "-m",
    )
    assert plan.metadata["readonly"] is True
    assert plan.metadata["load_user_config"] is False
    assert plan.metadata["load_prompts"] is False


def test_radare2_mcp_plan_rejects_non_directory(tmp_path: Path, monkeypatch) -> None:
    server = tmp_path / "r2mcp"
    server.write_text("binary")
    server.chmod(0o755)
    monkeypatch.setattr(
        "src.mcp.radare2_provider.shutil.which",
        lambda name: "/usr/bin/r2pm" if name == "r2pm" else None,
    )
    monkeypatch.setattr(Radare2McpProvider, "server_executable", staticmethod(lambda: str(server)))
    target = tmp_path / "sample"
    target.write_text("not a directory")

    with pytest.raises(ValueError, match="must be a directory"):
        Radare2McpProvider().launch_plan(target)


def test_installed_radare2_mcp_speaks_stdio_and_hides_dangerous_tools(tmp_path: Path) -> None:
    provider = Radare2McpProvider()
    if not provider.available():
        pytest.skip("official radare2 MCP server is not installed")
    plan = provider.launch_plan(tmp_path)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "angerona-test", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    completed = subprocess.run(
        plan.argv,
        input="".join(json.dumps(row) + "\n" for row in requests),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith("{")]
    listed = next(row for row in responses if row.get("id") == 2)
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert names
    assert "run_command" not in names
    assert "run_javascript" not in names
