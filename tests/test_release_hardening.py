from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace


def _prime_privacy_env(monkeypatch) -> None:
    # Register every key with monkeypatch before the function mutates os.environ
    # directly, so pytest restores the process environment after each test.
    defaults = {
        "ANGERONA_SANDBOX": "0",
        "ANGERONA_LOCAL_ONLY": "0",
        "ANGERONA_LOCAL_MODEL": "0",
        "ANGERONA_MCP_ALLOW_WRITE": "1",
        "ANGERONA_DISABLE_DYNAMIC": "0",
        "ANGERONA_LOCAL_BASE_URL": "http://localhost:11434/v1",
        "ANGERONA_LOCAL_MODEL_NAME": "rex86:latest",
        "OPENAI_BASE_URL": "http://localhost:11434/v1",
        "OPENAI_API_KEY": "test",
    }
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)


def test_privacy_mode_enforces_local_codex_and_disables_dynamic_tools(monkeypatch):
    from src import cli

    _prime_privacy_env(monkeypatch)
    ns = SimpleNamespace(privacy_mode=True, sandbox=False, agent="codex", model=None)

    assert cli._apply_privacy_mode(ns) is None
    assert ns.sandbox is True
    assert ns.model == "rex86:latest"
    assert cli.os.environ["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
    assert cli.os.environ["ANGERONA_MCP_ALLOW_WRITE"] == "0"
    assert cli.os.environ["ANGERONA_DISABLE_DYNAMIC"] == "1"


def test_privacy_mode_rejects_cloud_endpoint_and_claude(monkeypatch):
    from src import cli

    _prime_privacy_env(monkeypatch)
    monkeypatch.setenv("ANGERONA_LOCAL_BASE_URL", "https://api.example.invalid/v1")
    ns = SimpleNamespace(privacy_mode=True, sandbox=False, agent="codex", model=None)
    assert "loopback" in (cli._apply_privacy_mode(ns) or "")

    monkeypatch.setenv("ANGERONA_LOCAL_BASE_URL", "http://127.0.0.1:11434/v1")
    ns = SimpleNamespace(privacy_mode=True, sandbox=False, agent="claude", model=None)
    assert "--agent codex" in (cli._apply_privacy_mode(ns) or "")


def test_local_only_runtime_requires_loopback_endpoint():
    from src.agents.runtime import _local_only_runtime_error

    assert _local_only_runtime_error({"ANGERONA_LOCAL_ONLY": "0"}, "codex") is None
    assert _local_only_runtime_error({
        "ANGERONA_LOCAL_ONLY": "1",
        "OPENAI_BASE_URL": "http://127.0.0.1:11434/v1",
    }, "codex") is None
    assert "loopback" in (_local_only_runtime_error({
        "ANGERONA_LOCAL_ONLY": "1",
        "OPENAI_BASE_URL": "https://api.openai.com/v1",
    }, "codex") or "")


def test_ida_detonation_tool_requires_explicit_write_authority(monkeypatch):
    from src.mcp.ida_proxy import _local_tool_authorized

    monkeypatch.delenv("ANGERONA_MCP_ALLOW_WRITE", raising=False)
    assert not _local_tool_authorized("detonate_sample")
    assert _local_tool_authorized("verify_claims")
    monkeypatch.setenv("ANGERONA_MCP_ALLOW_WRITE", "1")
    assert _local_tool_authorized("detonate_sample")


def test_web_token_validation_and_remote_bind_policy(monkeypatch):
    from src.web import server

    assert server._request_token_valid({"Authorization": "Bearer secret"}, "secret")
    assert server._request_token_valid({"X-Angerona-Token": "secret"}, "secret")
    assert not server._request_token_valid({"Authorization": "Bearer wrong"}, "secret")
    monkeypatch.delenv("ANGERONA_WEB_AUTH_TOKEN", raising=False)
    assert server.serve("0.0.0.0", 8765, allow_remote=True) == 2


def test_doctor_runs_real_engine_probe_contract(monkeypatch, tmp_path):
    from src import cli

    binary = tmp_path / "sample"
    binary.write_bytes(b"sample")

    class Config:
        def ghidra_ready(self):
            return True, "configured"

    class Engine:
        def __init__(self, config):
            self.config = config

        def analyze(self, path, **kwargs):
            assert path == str(binary)
            assert kwargs == {
                "decompile": False,
                "max_functions": 1,
                "force": True,
                "timeout": 17,
            }
            return {"_cache": "/tmp/cache.json"}

    monkeypatch.setattr(cli, "load_config", lambda name: Config())
    monkeypatch.setattr(cli, "GhidraEngine", Engine)
    result = cli._doctor_engine("ghidra", str(binary), 17)
    assert result["configured"] is True
    assert result["operational"] is True
    assert result["cache"] == "/tmp/cache.json"


def test_ghidra_subprocess_config_is_writable_state():
    from src.config import load_config

    cfg = load_config("ghidra")
    config_home = cfg.subprocess_env()["XDG_CONFIG_HOME"]
    assert config_home == str(cfg.state_dir / "config")
    assert Path(config_home).is_dir()


def test_ida_subprocess_uses_writable_seeded_user_state(monkeypatch, tmp_path):
    from src.config import load_config

    home = tmp_path / "home"
    host_idapro = home / ".idapro"
    host_idapro.mkdir(parents=True)
    (host_idapro / "ida.reg").write_text("activated")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("IDAUSR", raising=False)

    cfg = load_config("ida")
    cfg.state_dir = tmp_path / "state"
    env = cfg.ida_env()

    ida_user = cfg.state_dir / "ida-user"
    assert env["IDAUSR"] == str(ida_user)
    assert (ida_user / "ida.reg").read_text() == "activated"
    assert (ida_user / "ida.reg").stat().st_mode & 0o077 == 0


def test_ida_subprocess_preserves_updated_state_registry(monkeypatch, tmp_path):
    from src.config import load_config

    host_idapro = tmp_path / "home" / ".idapro"
    host_idapro.mkdir(parents=True)
    (host_idapro / "ida.reg").write_text("host")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("IDAUSR", raising=False)

    cfg = load_config("ida")
    cfg.state_dir = tmp_path / "state"
    state_registry = cfg.state_dir / "ida-user" / "ida.reg"
    state_registry.parent.mkdir(parents=True)
    state_registry.write_text("updated-by-ida")

    cfg.ida_env()

    assert state_registry.read_text() == "updated-by-ida"


def test_packaged_runtime_assets_exist():
    from src.analysis import detonate
    from src.config import SCRIPTS_DIR

    assert detonate._DOCKERFILE.is_file()
    assert (detonate.Path(__file__).resolve().parents[1] / "src" / "analysis" / "signatures.yaml").is_file()
    assert (SCRIPTS_DIR / "REDump.java").is_file()
    assert (SCRIPTS_DIR / "GhidraWriteback.java").is_file()


def test_legacy_probe_runner_delegates_to_implemented_backends():
    from src.execution.backend_selector import ProbeRunner

    available = ProbeRunner().available()
    assert {"native", "unicorn", "symbolic"}.issubset(available)


def test_custom_processor_reports_partial_decode_coverage():
    from src.processors.base import Instruction, ProcessorModule
    from src.processors.loader import VmBytecodeLoader

    class PartialProcessor(ProcessorModule):
        name = "partial"
        arch = "partial"

        def decode(self, data, addr, *, metadata=None):
            if data[0] == 1:
                return Instruction(address=addr, mnemonic="one", size=1, bytes=data[:1])
            return None

        def emulate(self, insn):
            return []

    graph = VmBytecodeLoader(PartialProcessor()).load(b"\x01\xff")
    assert graph.metadata["processor_maturity"] == "experimental"
    assert graph.metadata["unknown_instruction_count"] == 1
    assert graph.metadata["decoded_instruction_ratio"] == 0.5
    assert graph.metadata["function_model"] == "synthetic_single_function"


def test_batch_dependencies_skip_after_analysis_failure(monkeypatch, tmp_path):
    from src.orchestration.batch_spine import BatchJobSpec, BatchSpine

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))

    class FailingSpine(BatchSpine):
        def _stage_analyze(self, spec, artifacts):
            raise RuntimeError("engine failed")

    spec = BatchJobSpec(
        binary="/bin/true",
        engine="ghidra",
        output_dir=str(tmp_path),
        stages=["analyze", "signatures", "types", "xref"],
    )
    result = FailingSpine(state_dir=tmp_path / "state").run(spec)
    by_stage = {row["stage"]: row for row in result.stage_logs}
    assert by_stage["analyze"]["status"] == "error"
    for stage in ("signatures", "types", "xref"):
        assert by_stage[stage]["status"] == "skipped"
        assert by_stage[stage]["reason"] == "analysis graph unavailable"
