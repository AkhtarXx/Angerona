from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from src.observability import (
    ChildTraceSpool,
    ObservabilityError,
    ObservabilityLedger,
    capture_tree,
    content_descriptor,
)


def _workspace(tmp_path: Path, *, stable: str = "1" * 32, trace: str = "2" * 32) -> Path:
    root = tmp_path / "workspace"
    for name in ("code", "docs", "raw"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "run.json").write_text(
        json.dumps(
            {
                "binary": "/tmp/target",
                "observability_id": stable,
                "trace_id": trace,
            }
        ),
        encoding="utf-8",
    )
    return root


def test_observability_chain_spans_and_secret_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    ledger = ObservabilityLedger(root)

    with ledger.span(
        component="orchestrator",
        category="model",
        action="dispatch",
        attributes={
            "model": "pinned-model",
            "authorization": "Bearer top-secret-token",
            "task": content_descriptor("analyze this target"),
        },
    ) as span:
        span.event(
            "provider_event",
            attributes={"api_key": "sk-never-persist-this", "event_type": "assistant"},
        )

    verdict = ledger.verify()
    assert verdict["valid"] is True
    assert verdict["events"] == 3
    events = ledger.events(limit=10)
    assert [event["phase"] for event in events] == ["start", "event", "end"]
    assert events[1]["span_id"] == events[0]["span_id"] == events[2]["span_id"]
    authority = ledger.db_path.read_bytes()
    mirror = (root / "raw" / "observability" / "events.jsonl").read_bytes()
    assert b"top-secret-token" not in authority + mirror
    assert b"never-persist-this" not in authority + mirror
    assert events[0]["attributes"]["authorization"]["redacted"] is True
    assert events[1]["attributes"]["api_key"]["redacted"] is True


def test_observability_concurrent_sequence_is_contiguous(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    ledgers = [ObservabilityLedger(root) for _ in range(4)]

    def writer(index: int) -> None:
        for offset in range(25):
            ledgers[index].emit(
                component="test",
                category="concurrency",
                action="append",
                attributes={"writer": index, "offset": offset},
            )

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    verdict = ledgers[0].verify()
    assert verdict["events"] == 100
    assert [event["sequence"] for event in ledgers[0].events(limit=200)] == list(
        range(1, 101)
    )


def test_authoritative_tamper_is_detected_and_mirror_has_no_authority(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    ledger = ObservabilityLedger(root)
    ledger.emit(component="test", category="state", action="before")
    mirror = root / "raw" / "observability" / "events.jsonl"
    mirror.write_text("forged\n", encoding="utf-8")
    assert ledger.verify()["events"] == 1
    ledger.rebuild_mirror()
    assert json.loads(mirror.read_text(encoding="utf-8"))["action"] == "before"

    with sqlite3.connect(ledger.db_path) as conn:
        conn.execute("UPDATE events SET attributes_json = ? WHERE sequence = 1", ('{"x":1}',))
        conn.commit()
    with pytest.raises(ObservabilityError, match="hash mismatch"):
        ledger.verify()


def test_tree_delta_records_every_created_modified_and_deleted_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    (root / "code" / "modified.txt").write_text("before", encoding="utf-8")
    (root / "code" / "deleted.txt").write_text("gone", encoding="utf-8")
    before = capture_tree(root)
    (root / "code" / "modified.txt").write_text("after", encoding="utf-8")
    (root / "code" / "deleted.txt").unlink()
    (root / "code" / "created.txt").write_text("new", encoding="utf-8")
    after = capture_tree(root)

    ledger = ObservabilityLedger(root)
    assert ledger.record_tree_delta(before, after, component="runtime") == 4
    changes = {
        (event["action"], event["attributes"]["path"])
        for event in ledger.events(limit=10)
    }
    assert changes == {
        ("created", "code/created.txt"),
        ("modified", "code/modified.txt"),
        ("deleted", "code/deleted.txt"),
        ("modified", "code"),
    }


def test_observability_event_budget_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_MAX_EVENTS", "2")
    ledger = ObservabilityLedger(_workspace(tmp_path))
    ledger.emit(component="test", category="budget", action="one")
    ledger.emit(component="test", category="budget", action="two")
    with pytest.raises(ObservabilityError, match="event limit"):
        ledger.emit(component="test", category="budget", action="three")
    assert ledger.verify()["events"] == 2


def test_observability_authority_survives_workspace_relocation(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path, stable="a" * 32, trace="b" * 32)
    first = ObservabilityLedger(root)
    first.emit(component="test", category="resume", action="before_move")
    first.close()
    relocated = tmp_path / "relocated"
    shutil.move(root, relocated)
    resumed = ObservabilityLedger(relocated)
    resumed.emit(component="test", category="resume", action="after_move")
    assert resumed.trace_id == "b" * 32
    assert resumed.verify()["events"] == 2


def test_observability_commit_survives_process_exit(tmp_path, monkeypatch):
    control = tmp_path / "control"
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(control))
    root = _workspace(tmp_path)
    code = (
        "from src.observability import ObservabilityLedger; "
        f"ledger=ObservabilityLedger({str(root)!r}); "
        "ledger.emit(component='child', category='crash', action='committed'); "
        "__import__('os')._exit(23)"
    )
    env = dict(os.environ)
    env["ANGERONA_AGENT_CONTROL_STATE_DIR"] = str(control)
    proc = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parents[1], env=env)
    assert proc.returncode == 23
    resumed = ObservabilityLedger(root)
    assert resumed.verify()["events"] == 1
    assert resumed.events()[0]["action"] == "committed"


def test_child_spool_is_untrusted_redacted_and_imported_once(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    monkeypatch.setenv("ANGERONA_TRACE_ID", "2" * 32)
    monkeypatch.setenv("ANGERONA_PARENT_SPAN_ID", "3" * 32)
    child = ChildTraceSpool(root, component="mcp.test", session_id="4" * 32)
    child.emit(
        category="jsonrpc",
        action="request",
        attributes={"authorization": "Bearer child-secret", "method": "tools/call"},
    )
    child.close()

    spools = list((root / "raw" / "observability").glob(f"child-{'4' * 32}-*.jsonl"))
    assert len(spools) == 1
    spool = spools[0]
    assert b"child-secret" not in spool.read_bytes()
    ledger = ObservabilityLedger(root)
    assert ledger.import_child_spools(root, parent_span_id="3" * 32) == 1
    assert ledger.import_child_spools(root, parent_span_id="3" * 32) == 0
    event = ledger.events(limit=10)[0]
    assert event["trust"] == "untrusted_child"
    assert event["parent_span_id"] == "3" * 32


def test_lone_surrogate_attributes_commit_and_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    ledger = ObservabilityLedger(root)

    # os.fsdecode(surrogateescape) yields lone surrogates for non-UTF-8 paths.
    name = "bad\udcffname"
    ledger.emit(
        component="auditor",
        category="tree",
        action="snapshot",
        attributes={"cwd": name, "root": "/workspace/" + name},
    )
    assert ledger.verify()["valid"] is True
    assert ledger.events(limit=10)[0]["attributes"]["cwd"] == name

    monkeypatch.setenv("ANGERONA_TRACE_ID", "2" * 32)
    monkeypatch.setenv("ANGERONA_PARENT_SPAN_ID", "3" * 32)
    child = ChildTraceSpool(root, component="mcp.test", session_id="4" * 32)
    child.emit(category="jsonrpc", action="request", attributes={"path": name})
    child.close()
    assert ledger.import_child_spools(root, parent_span_id="3" * 32) == 1
    assert ledger.verify()["valid"] is True


def test_ghidra_mcp_records_every_jsonrpc_request_and_response(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_WORKSPACE", str(root))
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_CHILD_SESSION", "5" * 32)
    monkeypatch.setenv("ANGERONA_TRACE_ID", "2" * 32)
    monkeypatch.setenv("ANGERONA_PARENT_SPAN_ID", "3" * 32)
    from src.mcp.server import GhidraMCPServer

    server = GhidraMCPServer()
    response = server.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})
    assert response == {"jsonrpc": "2.0", "id": 9, "result": {}}
    assert server.observability is not None
    server.observability.close()
    ledger = ObservabilityLedger(root)
    assert ledger.import_child_spools(root, parent_span_id="3" * 32) == 2
    records = [
        event["attributes"]["record"]
        for event in ledger.events(limit=10)
    ]
    assert [(record["action"], record["status"]) for record in records] == [
        ("request", "running"),
        ("response", "ok"),
    ]


def test_ida_proxy_records_local_rejection_request_and_response(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_WORKSPACE", str(root))
    monkeypatch.setenv("ANGERONA_OBSERVABILITY_CHILD_SESSION", "6" * 32)
    monkeypatch.setenv("ANGERONA_TRACE_ID", "2" * 32)
    monkeypatch.setenv("ANGERONA_PARENT_SPAN_ID", "3" * 32)
    monkeypatch.setenv("ANGERONA_TARGET_BINARY", "/tmp/target")
    monkeypatch.setenv("ANGERONA_REQUIRE_TARGET_BINARY", "1")
    from src.mcp.ida_proxy import IdaMcpProxy

    proxy = IdaMcpProxy([sys.executable, "missing.py"], dict(os.environ))
    request = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {"name": "idb_open", "arguments": {"input_path": "/tmp/other"}},
    }
    proxy._handle_request(json.dumps(request), request)
    assert json.loads(capsys.readouterr().out)["id"] == 12
    assert proxy.observability is not None
    proxy.observability.close()

    ledger = ObservabilityLedger(root)
    assert ledger.import_child_spools(root, parent_span_id="3" * 32) == 2
    records = [event["attributes"]["record"] for event in ledger.events(limit=10)]
    assert [record["action"] for record in records] == ["request", "response"]
    assert records[1]["status"] == "error"


def test_secure_artifact_and_checkpoint_mutations_are_observed(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    from src.models.checkpoint_db import CheckpointDB
    from src.secure_artifacts import SecureArtifactStore

    store = SecureArtifactStore(root, "raw/state")
    assert store.write_text_atomic("one.txt", "secret audit state") is True
    store.replace_bytes_atomic("one.txt", b"replacement")
    store.append_line("events.log", "tiny change")
    store.close()
    db = CheckpointDB(root / "checkpoints.db")
    checkpoint = db.create_checkpoint("analyst", "inspect risky path")
    db.record_mutation(checkpoint.id, "symbols", "secret-row", "name", None, "main")
    db.set_state("cursor", {"offset": 7})

    ledger = ObservabilityLedger(root)
    actions = [event["action"] for event in ledger.events(limit=100)]
    assert {"created", "replaced", "appended"} <= set(actions)
    assert {"schema_ready", "checkpoint_created", "mutation_recorded", "state_set"} <= set(actions)
    serialized = json.dumps(ledger.events(limit=100))
    assert "secret audit state" not in serialized
    assert "secret-row" not in serialized


def test_multiprocess_writers_keep_one_contiguous_chain(tmp_path, monkeypatch):
    control = tmp_path / "control"
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(control))
    root = _workspace(tmp_path)
    script = """
import sys
from src.observability import ObservabilityLedger
ledger = ObservabilityLedger(sys.argv[1])
for i in range(25):
    ledger.emit(component='process', category='test', action='write', attributes={'i': i})
"""
    env = dict(os.environ)
    env["ANGERONA_AGENT_CONTROL_STATE_DIR"] = str(control)
    processes = [
        subprocess.Popen([sys.executable, "-c", script, str(root)], cwd=str(Path(__file__).parents[1]), env=env)
        for _ in range(4)
    ]
    assert [process.wait(timeout=30) for process in processes] == [0, 0, 0, 0]
    verdict = ObservabilityLedger(root).verify()
    assert verdict["events"] == 100


def test_child_import_does_not_follow_spool_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    directory = root / "raw" / "observability"
    directory.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n")
    (directory / f"child-{'7' * 32}-evil-1.jsonl").symlink_to(outside)
    assert ObservabilityLedger(root).import_child_spools(root) == 0


def test_cli_and_web_expose_verified_trace(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    runs = tmp_path / "runs"
    from src import cli
    from src.web import server as web
    from src.workspace import RunWorkspace

    workspace = RunWorkspace.create(runs, "/tmp/target")
    workspace.observability.emit(
        component="operator_test", category="test", action="visible", attributes={"value": 1}
    )
    assert cli.main([
        "audit-trace", str(workspace.root), "--component", "operator_test", "--json"
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verification"]["valid"] is True
    assert [event["action"] for event in output["events"]] == ["visible"]

    monkeypatch.setattr(web, "_runs_dir", lambda: runs)
    response = web.observability_events(workspace.root.name, since=0, limit=100)
    assert response["verification"]["valid"] is True
    assert any(event["action"] == "visible" for event in response["events"])


def test_host_subprocess_records_result_and_each_workspace_change(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_AGENT_CONTROL_STATE_DIR", str(tmp_path / "control"))
    root = _workspace(tmp_path)
    from src.subprocess_observability import observed_run

    result = observed_run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('raw/helper.txt').write_text('helper payload'); print('done')",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    events = ObservabilityLedger(root).events(limit=100)
    process_events = [event for event in events if event["component"] == "host_subprocess"]
    assert [event["phase"] for event in process_events if event["action"] == "run"] == [
        "start",
        "end",
    ]
    assert any(
        event["category"] == "filesystem"
        and event["action"] == "created"
        and event["attributes"]["path"] == "raw/helper.txt"
        for event in process_events
    )
    assert "helper payload" not in json.dumps(process_events)


def test_progress_subprocess_continues_while_output_grows(tmp_path):
    from src.subprocess_observability import observed_progress_run

    output = tmp_path / "growing.txt"
    script = (
        "import sys,time\n"
        "for i in range(6):\n"
        " sys.stdout.write('progress-%d\\n' % i); sys.stdout.flush(); time.sleep(0.08)\n"
    )
    with output.open("wb") as stdout:
        result = observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=0.2,
            wall_timeout=2.0,
            poll_interval=0.02,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    assert result.returncode == 0
    assert result.elapsed_seconds > 0.2
    assert result.progress_bytes == output.stat().st_size
    assert result.progress_events >= 2


def test_progress_subprocess_terminates_only_after_real_inactivity(tmp_path):
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        observed_progress_run,
    )

    output = tmp_path / "stalled.txt"
    script = "import sys,time; print('started', flush=True); time.sleep(10)"
    with output.open("wb") as stdout, pytest.raises(ProgressTimeoutExpired) as raised:
        observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=0.2,
            wall_timeout=2.0,
            poll_interval=0.02,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    assert raised.value.reason == "idle-timeout"
    assert raised.value.progress_bytes == output.stat().st_size
    assert raised.value.progress_bytes > 0


def test_progress_subprocess_accepts_quiet_cpu_work_as_progress(tmp_path):
    from src.subprocess_observability import observed_progress_run

    output = tmp_path / "quiet.txt"
    script = (
        "import time\n"
        "end=time.monotonic()+0.5\n"
        "value=0\n"
        "while time.monotonic()<end: value=(value+1)%1000003\n"
    )
    with output.open("wb") as stdout:
        result = observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=0.15,
            wall_timeout=2.0,
            poll_interval=0.03,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    assert result.returncode == 0
    assert result.elapsed_seconds > 0.15
    assert result.cpu_ticks > 0


def test_progress_subprocess_cpu_spin_is_idle_when_cpu_is_not_progress(tmp_path):
    """cpu_is_progress=False: a 100%-CPU silent loop must trigger idle-timeout.

    This is the IDA decompiler-hang case — a function stuck mid-pass spins the
    CPU without ever emitting an ANGERONA_IDA_PROGRESS heartbeat.  Counting
    those ticks as progress would make the idle watchdog unreachable for exactly
    the pathological case it exists to bound, so IDA opts out via
    cpu_is_progress=False and only output growth resets the idle deadline.
    """
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        observed_progress_run,
    )

    output = tmp_path / "quiet.txt"
    # Same quiet CPU-burning loop shape as the default-behavior test above, but
    # bounded at 10s so a regression that fails to idle-kill still terminates.
    script = (
        "import time\n"
        "end=time.monotonic()+10\n"
        "value=0\n"
        "while time.monotonic()<end: value=(value+1)%1000003\n"
    )
    with output.open("wb") as stdout, pytest.raises(ProgressTimeoutExpired) as raised:
        observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=0.2,
            wall_timeout=2.0,
            poll_interval=0.02,
            cpu_is_progress=False,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    assert raised.value.reason == "idle-timeout"


def test_progress_subprocess_enforces_output_quota(tmp_path):
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        observed_progress_run,
    )

    output = tmp_path / "large.txt"
    script = (
        "import sys,time\n"
        "while True:\n"
        " sys.stdout.write('x'*4096); sys.stdout.flush(); time.sleep(0.01)\n"
    )
    with output.open("wb") as stdout, pytest.raises(ProgressTimeoutExpired) as raised:
        observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=1.0,
            wall_timeout=10.0,
            poll_interval=0.02,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            resource_paths=[output],
            max_output_bytes=32 * 1024,
        )
    assert raised.value.reason == "output-bytes-limit"


def test_progress_subprocess_rechecks_quota_after_fast_exit(tmp_path):
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        observed_progress_run,
    )

    output = tmp_path / "fast-large.txt"
    with output.open("wb") as stdout, pytest.raises(ProgressTimeoutExpired) as raised:
        observed_progress_run(
            [sys.executable, "-c", "import sys;sys.stdout.write('x'*1048576)"],
            progress_path=output,
            idle_timeout=2.0,
            wall_timeout=5.0,
            poll_interval=0.25,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            resource_paths=[output],
            max_output_bytes=1024,
        )
    assert raised.value.reason == "output-bytes-limit"


def test_progress_subprocess_enforces_output_item_quota_after_fast_exit(tmp_path):
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        observed_progress_run,
    )

    output = tmp_path / "many-files"
    output.mkdir()
    script = (
        "from pathlib import Path\n"
        f"p=Path({str(output)!r})\n"
        "[(p/f'{i}.txt').write_text('x') for i in range(20)]\n"
    )
    with pytest.raises(ProgressTimeoutExpired) as raised:
        observed_progress_run(
            [sys.executable, "-c", script],
            progress_path=output,
            idle_timeout=2.0,
            wall_timeout=5.0,
            poll_interval=0.25,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            resource_paths=[output],
            max_output_items=10,
        )
    assert raised.value.reason == "output-items-limit"


def test_atomic_publish_directory_exchanges_existing_tree(tmp_path):
    from src.subprocess_observability import atomic_publish_directory

    destination = tmp_path / "evidence"
    staging = tmp_path / ".evidence.staging"
    destination.mkdir()
    staging.mkdir()
    (destination / "generation.txt").write_text("old")
    (staging / "generation.txt").write_text("new")

    atomic_publish_directory(staging, destination)

    assert (destination / "generation.txt").read_text() == "new"
    assert not staging.exists()
