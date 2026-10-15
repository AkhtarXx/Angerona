"""Regressions for evidence integrity and resource-lifecycle boundaries."""
from __future__ import annotations

import http.client
import subprocess
import threading
import zipfile
from pathlib import Path
from unittest.mock import patch

from src.analysis import archive_router, bequiv, detonate
from src.updater import _safe_extract


def _completed(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def test_unparsed_compiler_failure_is_not_success(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text("int main(void) { return 0; }")
    with patch.object(bequiv, "_have", return_value=True), patch.object(
        bequiv, "_sandbox_compile", side_effect=lambda cmd, *args: cmd
    ), patch.object(bequiv, "observed_run", return_value=_completed(1, stderr="ld: final link failed")):
        ok, detail = bequiv.compile_check(source)
    assert not ok
    assert "compiler exited 1" in detail


def test_matching_crashes_cannot_confirm_equivalence(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text("int main(void) { return 0; }")
    with patch.object(bequiv, "_have", return_value=True), patch.object(
        bequiv, "_sandbox_compile", side_effect=lambda cmd, *args: cmd
    ), patch("src.analysis.sandbox.available", return_value=True), patch(
        "src.analysis.sandbox.wrap", side_effect=lambda cmd, **kw: cmd
    ), patch.object(bequiv, "observed_run", side_effect=[_completed(), _completed(), _completed(-11), _completed(-11)]):
        result = bequiv.behavioral_check(source, source)
    assert not result.equivalent
    assert not result.ran
    assert "signal termination" in result.mismatches[0]


def test_archive_member_names_cannot_overwrite_evidence(tmp_path):
    archive = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a/b.txt", "first")
        z.writestr("a_b.txt", "second")
    result = archive_router.route(archive)
    assert len({child.extracted_path for child in result.children}) == 2
    assert [Path(child.extracted_path).read_text() for child in result.children] == ["first", "second"]


def test_archive_limit_records_incomplete_coverage(tmp_path):
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for n in range(201):
            z.writestr(f"{n}.txt", str(n))
    result = archive_router.route(archive)
    assert len(result.children) == 200
    assert result.truncated
    assert any("fan-out" in reason for reason in result.unresolved)


def test_normal_zip_extracts_with_native_path_semantics(tmp_path):
    archive = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("directory/file.txt", "safe")
    _safe_extract(archive, tmp_path / "out")
    assert (tmp_path / "out/directory/file.txt").read_text() == "safe"


def test_detonation_timeout_removes_exact_owned_container(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"known fixture")
    calls = []

    def run(args, timeout):
        calls.append(args)
        if args[0] == "create":
            return _completed(stdout="container-id")
        if args[0] == "start":
            raise subprocess.TimeoutExpired(args, timeout)
        return _completed()

    with patch.object(detonate, "docker_available", return_value=True), patch.object(
        detonate, "build_image", return_value=(True, "ready")
    ), patch.object(detonate, "_run", side_effect=run):
        result = detonate.detonate(sample)
    assert not result["ok"]
    assert result["cleanup_complete"]
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ["rm", "--force", name]


def test_docker_failure_cannot_confirm_execution(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"fixture")
    with patch.object(detonate, "docker_available", return_value=True), patch.object(
        detonate, "build_image", return_value=(True, "ready")
    ), patch.object(detonate, "_run", side_effect=[_completed(125, stderr="daemon failure"), _completed()]):
        result = detonate.detonate(sample)
    assert not result["ok"]
    assert "creation failed" in result["error"]


def test_cross_origin_write_is_rejected_before_dispatch():
    from src.web.server import Handler, ThreadingHTTPServer
    handler = type("QuietHandler", (Handler,), {"log_message": lambda *args: None})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch("src.web.server.pause_run") as action:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("POST", "/api/runs/example/pause", body='{}', headers={"Origin": "https://attacker.example", "Content-Type": "text/plain"})
            response = connection.getresponse()
            assert response.status == 403
            response.read()
            connection.close()
            action.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
