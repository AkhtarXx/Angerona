#!/usr/bin/env python3
"""Run real public CLI workflows and retain exact commands, outcomes and hashes.

Run on Linux from an installed checkout. No target downloads or AI calls are made.
Optional APK input is analyzed statically; Docker runs the local /bin/true executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--pe", type=Path)
    parser.add_argument("--docker", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["ANGERONA_HOME"] = str(output / "state")
    env["ANGERONA_AGENT_CONTROL_STATE_DIR"] = str(output / "control")
    env["ANGERONA_JADX_WALL_TIMEOUT_SECONDS"] = "120"
    env["ANGERONA_JADX_IDLE_TIMEOUT_SECONDS"] = "120"
    env["ANGERONA_JADX_ATTEMPTS"] = "1"
    report = {
        "schema": "angerona/e2e-verification/v1", "host": platform.platform(),
        "python": sys.version, "source_root": str(ROOT), "cases": [], "targets": [],
        "scope": "actual CLI/native-engine/static APK workflows; no AI quality certification",
    }

    def save():
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(name, command, validate=None, timeout=300, input_text=None, expected_exit_codes=(0,)):
        start = time.monotonic()
        row = {"name": name, "command": command, "kind": "real-process"}
        print(f"VERIFY {name}", flush=True)
        try:
            completed = subprocess.run(command, cwd=ROOT, env=env, input=input_text,
                                       capture_output=True, text=True, timeout=timeout)
            (output / f"{name}.stdout").write_text(completed.stdout)
            (output / f"{name}.stderr").write_text(completed.stderr)
            row["exit_code"] = completed.returncode
            row["stdout_sha256"] = hashlib.sha256(completed.stdout.encode()).hexdigest()
            row["stderr_sha256"] = hashlib.sha256(completed.stderr.encode()).hexdigest()
            row["expected_exit_codes"] = list(expected_exit_codes)
            row["passed"] = completed.returncode in expected_exit_codes
            if row["passed"] and validate:
                validate(completed.stdout)
        except Exception as exc:
            row["passed"] = False
            row["error"] = f"{type(exc).__name__}: {exc}"
        row["seconds"] = round(time.monotonic() - start, 3)
        report["cases"].append(row)
        save()
        return row

    cli = [sys.executable, "-m", "src"]
    fixture = ROOT / "samples/crackme"
    run("build-c-fixture", ["gcc", "-O0", "-g", "-fno-builtin", "-fno-stack-protector", "-no-pie",
                            str(ROOT / "samples/crackme.c"), "-o", str(fixture)])
    targets = [("system-true", Path("/bin/true")), ("system-printf", Path("/usr/bin/printf")), ("c-fixture", fixture)]
    if args.pe:
        targets.append(("windows-python", args.pe))
    for name, target in targets:
        report["targets"].append({"name": name, "path": str(target), "sha256": digest(target), "bytes": target.stat().st_size})
        def identified(text, expected="pe" if name == "windows-python" else "elf"):
            data = json.loads(text)
            assert data["profile"]["family"] == expected, "unexpected format classification"
        run(f"identify-{name}", [*cli, "analyze-any", str(target), "--json"], identified)

    def analyzed(text):
        data = json.loads(text)
        assert data.get("functions"), "engine returned no function observations"

    def decompiled(text):
        data = json.loads(text)
        assert "strcpy" in data.get("decompiled", ""), "expected source-known strcpy call absent"

    run("ghidra-analyze-fixture", [*cli, "analyze", str(fixture), "--engine", "ghidra", "--decompile", "--json"], analyzed, timeout=600)
    run("ghidra-decompile-main", [*cli, "decompile", str(fixture), "main", "--engine", "ghidra", "--json"], decompiled, timeout=300)
    run("ghidra-analyze-system", [*cli, "analyze", "/bin/true", "--engine", "ghidra", "--decompile", "--json"], analyzed, timeout=600)
    run("ghidra-analyze-printf", [*cli, "analyze", "/usr/bin/printf", "--engine", "ghidra", "--decompile", "--json"], analyzed, timeout=600)
    if args.pe:
        run("ghidra-analyze-pe", [*cli, "analyze", str(args.pe), "--engine", "ghidra", "--decompile", "--json"], analyzed, timeout=600)

    def batch(text):
        data = json.loads(text)
        assert data.get("return_code") == 0, "batch reported unsuccessful stages"
        assert Path(data["workspace"]).is_dir(), "batch workspace missing"
        row = json.loads((Path(data["workspace"]) / "raw/batch_report.json").read_text())
        assert row, "empty persisted batch report"

    run("deterministic-batch", [*cli, "sota-batch", str(fixture), "--engine", "ghidra", "--output-dir", str(output / "state/runs"), "--json"], batch, timeout=600)
    full = run("full-re-no-ai", [*cli, "full-re", str(fixture), "--engine", "ghidra", "--no-ai", "--output-dir", str(output / "state/runs"), "--json"], batch, timeout=600)
    if full["passed"]:
        workspace = json.loads((output / "full-re-no-ai.stdout").read_text())["workspace"]
        def resumed(text):
            batch(text)
            assert json.loads(text)["workspace"] == workspace, "resume created another workspace"
        run("full-re-resume", [*cli, "full-re", str(fixture), "--engine", "ghidra", "--no-ai", "--resume-workspace", workspace, "--json"], resumed)
        def pseudocode(text):
            assert json.loads(text).get("functions"), "no pseudocode generated"
        def summary(text):
            rows = json.loads(text).get("summaries", [])
            assert rows and rows[0].get("purpose"), "no function summary generated"
        def nonempty(text):
            assert json.loads(text), "empty derived analysis"
        run("structured-pseudocode", [*cli, "pseudocode", workspace, "--function", "main", "--structured", "--json"], pseudocode)
        run("function-summary", [*cli, "function-summary", workspace, "--function", "main", "--json"], summary)
        run("control-flow-graph", [*cli, "cfg-build", workspace, "--function", "main", "--json"], nonempty)
        run("stack-frame-recovery", [*cli, "stack-frames", workspace, "--function", "main", "--json"], nonempty)
        run("compiler-detection", [*cli, "compiler-detect", str(fixture), "--json"], nonempty)
    run("sandboxed-static-analysis", [*cli, "analyze", str(fixture), "--engine", "ghidra", "--sandbox", "--force", "--json"], analyzed, timeout=600)

    mcp_root = output / "mcp-session"
    for directory in ("code", "docs", "raw"):
        (mcp_root / directory).mkdir(parents=True, exist_ok=True)
    env["ANGERONA_AGENT_WORKSPACE_ROOT"] = str(mcp_root)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "verification", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "binary_security_properties", "arguments": {"binary": str(fixture)}}},
    ]

    def mcp(text):
        rows = {item["id"]: item for line in text.splitlines() if line.startswith("{") and "id" in (item := json.loads(line))}
        assert all(key in rows for key in (1, 2, 3)), "missing MCP response"
        assert rows[2]["result"]["tools"], "empty MCP catalog"
        result = rows[3]["result"]
        assert not result.get("isError"), "MCP tool returned failure"
        assert "mitigations" in json.dumps(result), "real binary property evidence missing"

    run("mcp-stdio", [sys.executable, "-m", "src.mcp.server"], mcp,
        input_text="".join(json.dumps(row) + "\n" for row in requests), timeout=60)
    # Read the actual batch workspace through the public HTTP API.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with (output / "web.log").open("w") as log:
        web = subprocess.Popen([sys.executable, "-m", "src.web.server", "--port", str(port)], cwd=ROOT, env=env, stdout=log, stderr=log)
        start = time.monotonic()
        row = {"name": "web-batch-artifacts", "kind": "real-http"}
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(50):
                try:
                    with urllib.request.urlopen(base + "/api/runs", timeout=2) as reply:
                        runs = json.load(reply)["runs"]
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("web server did not become ready")
            assert runs, "real batch run absent from web API"
            # The runs directory also contains category folders (e.g. batch).
            # Select the actual workspace produced by this invocation.
            run_id = next(r["id"] for r in runs if (output / "state" / "runs" / r["id"] / "raw" / "batch_report.json").is_file())
            with urllib.request.urlopen(base + f"/api/runs/{run_id}/file?path=raw%2Fbatch_report.json", timeout=3) as reply:
                artifact = json.load(reply)
            assert artifact.get("content") and not artifact.get("error"), "batch artifact unavailable through HTTP"
            (output / "web-artifact.json").write_text(json.dumps(artifact, indent=2) + "\n")
            row["passed"] = True
        except Exception as exc:
            row.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        finally:
            web.terminate()
            web.wait(timeout=5)
        row["seconds"] = round(time.monotonic() - start, 3)
        report["cases"].append(row)
        save()
    from src.analysis.bequiv import behavioral_check
    behavioral_dir = output / "behavioral"
    behavioral_dir.mkdir(exist_ok=True)
    reference = behavioral_dir / "reference.c"
    equivalent = behavioral_dir / "equivalent.c"
    divergent = behavioral_dir / "divergent.c"
    template = '#include <stdio.h>\n#include <stdlib.h>\nint main(int n,char **v){long x=n>1?strtol(v[1],0,10):0; printf("%ld\\n",EXPRESSION); return 0;}\n'
    reference.write_text(template.replace("EXPRESSION", "x+1"))
    equivalent.write_text(template.replace("EXPRESSION", "1+x"))
    divergent.write_text(template.replace("EXPRESSION", "x-1"))
    for name, candidate, expected in [("behavior-equivalent", equivalent, True), ("behavior-divergent", divergent, False)]:
        start = time.monotonic()
        result = behavioral_check(candidate, reference, test_inputs=["0", "1", "-1", "127"])
        (output / f"{name}.json").write_text(json.dumps(result.as_dict(), indent=2) + "\n")
        report["cases"].append({"name": name, "kind": "real-process", "passed": result.compiled and result.ran and result.equivalent == expected and result.inputs_tested == 4, "seconds": round(time.monotonic() - start, 3)})
        save()
    from src.execution.runners.native_runner import NativeAppcallRunner
    from types import SimpleNamespace
    started = time.monotonic()
    native = NativeAppcallRunner().run(SimpleNamespace(function_name="add", args=[2, 3]), str(fixture))
    (output / "native-appcall.json").write_text(json.dumps({"status": native.status, "note": native.note, "detail": native.detail}, indent=2) + "\n")
    report["cases"].append({"name": "native-appcall", "kind": "real-process", "passed": native.status == "success" and native.detail.get("return_value") == 5, "seconds": round(time.monotonic() - started, 3)})
    save()
    if args.apk:
        report["targets"].append({"name": "public-apk", "path": str(args.apk), "sha256": digest(args.apk), "bytes": args.apk.stat().st_size})
        apk_report = output / "android-audit.json"

        def audited(_text):
            data = json.loads(apk_report.read_text())
            assert data["status"] != "error", "Android input/tool pipeline failed"
            assert data["metadata"]["artifact_validation"]["status"] == "valid"
            assert "apksigner_bridge" in data["steps_executed"]
            assert data["metadata"].get("binary_inventory"), "APK member inventory missing"

        # Exit 3 intentionally reports incomplete audit coverage. Validate that
        # partial result without misrepresenting it as a completed security audit.
        run("android-static-audit", [*cli, "android-audit", str(args.apk), "--timeout", "120", "--output", str(apk_report)], audited, timeout=600, expected_exit_codes=(0, 3))
    if args.docker:
        from src.analysis.detonate import detonate
        start = time.monotonic()
        result = detonate("/bin/true", timeout_seconds=5)
        (output / "docker-detonation.json").write_text(json.dumps(result, indent=2) + "\n")
        report["cases"].append({"name": "docker-detonation", "kind": "real-process", "passed": result.get("ok") is True and result.get("cleanup_complete") is True and result.get("sample_exit_code") == 0, "seconds": round(time.monotonic() - start, 3)})
    report["passed"] = all(row["passed"] for row in report["cases"])
    save()
    print(json.dumps({"passed": report["passed"], "cases": len(report["cases"]), "output": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
