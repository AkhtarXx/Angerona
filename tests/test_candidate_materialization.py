from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from src.agents.audit_state import AuditStateError, AuditStateStore
from src.agents.loop import ConvergenceLoop, attest_isolation_capable_dispatch
from src.agents.runtime import AgentResult, _stream_process, _supervised_agent_env
from src.workspace import RunWorkspace


def _result(text: str) -> AgentResult:
    return AgentResult(
        ok=True,
        final_text=text,
        events=[],
        returncode=0,
        seconds=0.01,
        raw_stdout=text,
        raw_stderr="",
    )


def _attested(dispatch):
    return attest_isolation_capable_dispatch(dispatch)


def _loop(tmp_path: Path, *, dispatch=None, reconstruction_dir=None) -> tuple[RunWorkspace, ConvergenceLoop]:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    loop = ConvergenceLoop(
        binary="/bin/true",
        objective="x",
        workspace=ws,
        dispatch=_attested(
            dispatch or (lambda *_args, **_kwargs: _result("unused"))
        ),
        max_rounds=1,
        k_candidates=2,
        strict_verify=False,
        reconstruction_dir=reconstruction_dir,
        target_anchors=("0x401000",),
    )
    return ws, loop


@pytest.mark.parametrize("root_name", ["code", "raw"])
def test_candidate_seed_refuses_input_symlinks_without_partial_tree(
    tmp_path: Path, root_name: str
) -> None:
    ws, loop = _loop(tmp_path)
    root = ws.code_dir if root_name == "code" else ws.raw_dir
    (root / "escape").symlink_to("/etc/passwd")
    names = loop._candidate_raw_input_names()

    with pytest.raises(RuntimeError, match="symlink"):
        loop._candidate_code_dir(1, 1, raw_input_names=names)

    candidates = ws.root / "candidates"
    assert not (candidates / "round_1_seed").exists()
    assert not (candidates / "round_1_k1").exists()
    assert not any(path.name.endswith(".tmp") for path in candidates.iterdir())


def test_candidate_seed_refuses_nested_symlink_directory(tmp_path: Path) -> None:
    ws, loop = _loop(tmp_path)
    nested = ws.code_dir / "nested"
    nested.mkdir()
    (nested / "outside").symlink_to("/etc", target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlink"):
        loop._candidate_code_dir(1, 1, raw_input_names=())

    assert not (ws.root / "candidates" / "round_1_seed").exists()


def test_candidate_seed_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    ws, loop = _loop(tmp_path)
    fifo = ws.code_dir / "hostile.pipe"
    os.mkfifo(fifo)

    with pytest.raises(RuntimeError, match="non-regular"):
        loop._candidate_code_dir(1, 1, raw_input_names=())


def test_regular_to_fifo_swap_is_nonblocking_and_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, loop = _loop(tmp_path)
    source = ws.code_dir / "race.bin"
    source.write_bytes(b"regular")
    real_open = os.open
    observed_flags = 0
    swapped = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal observed_flags, swapped
        if path == "race.bin" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            observed_flags = flags
            source.unlink()
            os.mkfifo(source)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("src.agents.loop.os.open", racing_open)
    with pytest.raises(RuntimeError, match="changed while freezing"):
        loop._candidate_code_dir(1, 1, raw_input_names=())
    assert swapped is True
    assert observed_flags & os.O_NONBLOCK


def test_candidate_input_file_quota_fails_before_candidate_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, loop = _loop(tmp_path)
    monkeypatch.setattr("src.agents.loop._MAX_CANDIDATE_INPUT_FILES", 2)
    for index in range(3):
        (ws.code_dir / f"f{index}.txt").write_text(str(index))

    with pytest.raises(RuntimeError, match="entry bounds|file bounds"):
        loop._candidate_code_dir(1, 1, raw_input_names=())

    assert not (ws.root / "candidates" / "round_1_k1").exists()


def test_candidate_input_byte_quota_fails_before_candidate_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, loop = _loop(tmp_path)
    monkeypatch.setattr("src.agents.loop._MAX_CANDIDATE_INPUT_BYTES", 4)
    (ws.raw_dir / "large.bin").write_bytes(b"12345")

    with pytest.raises(RuntimeError, match="byte bounds"):
        loop._candidate_code_dir(
            1, 1, raw_input_names=loop._candidate_raw_input_names()
        )

    assert not (ws.root / "candidates" / "round_1_seed").exists()


def test_candidate_byte_quota_is_aggregate_across_code_and_raw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, loop = _loop(tmp_path)
    monkeypatch.setattr("src.agents.loop._MAX_CANDIDATE_INPUT_BYTES", 6)
    (ws.code_dir / "code.bin").write_bytes(b"1234")
    (ws.raw_dir / "raw.bin").write_bytes(b"5678")

    with pytest.raises(RuntimeError, match="byte bounds"):
        loop._candidate_code_dir(
            1, 1, raw_input_names=loop._candidate_raw_input_names()
        )


def test_source_mutation_during_seed_copy_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, loop = _loop(tmp_path)
    source = ws.code_dir / "moving.bin"
    source.write_bytes(b"a" * (2 * 1024 * 1024))
    real_read = os.read
    mutated = False

    def racing_read(fd: int, size: int) -> bytes:
        nonlocal mutated
        chunk = real_read(fd, size)
        if chunk and not mutated:
            mutated = True
            source.write_bytes(b"b" * (2 * 1024 * 1024))
        return chunk

    monkeypatch.setattr("src.agents.loop.os.read", racing_read)
    with pytest.raises(RuntimeError, match="changed while freezing"):
        loop._candidate_code_dir(1, 1, raw_input_names=())
    assert mutated is True
    assert not (ws.root / "candidates" / "round_1_seed").exists()


def test_preplanted_candidate_seed_has_no_authority(tmp_path: Path) -> None:
    ws, loop = _loop(tmp_path)
    planted = ws.root / "candidates" / "round_1_seed"
    (planted / "code").mkdir(parents=True)
    (planted / "raw").mkdir()
    (planted / "raw" / "poison.txt").write_text("attacker-controlled")

    with pytest.raises(RuntimeError, match="without live authority"):
        loop._candidate_code_dir(1, 1, raw_input_names=())

    assert not (ws.root / "candidates" / "round_1_k1").exists()


def test_first_candidate_cannot_poison_frozen_seed_for_second(tmp_path: Path) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        assert (Path(args[4]).parent / "raw" / "facts.bin").read_bytes() == b"TRUSTED"
        seed_file = ws.root / "candidates" / "round_1_seed" / "raw" / "facts.bin"
        seed_file.write_bytes(b"POISON!")
        return _result("0x401000 VALID HIGH AUDIT REPORT")

    ws, loop = _loop(tmp_path, dispatch=_attested(dispatch))
    (ws.raw_dir / "facts.bin").write_bytes(b"TRUSTED")

    with pytest.raises(RuntimeError, match="seed identity changed"):
        loop.run()
    assert calls == 1
    assert not (ws.root / "candidates" / "round_1_k2").exists()


def test_actual_crash_staging_names_are_reclaimed(tmp_path: Path) -> None:
    ws, loop = _loop(tmp_path)
    candidate_root = ws.root / "candidates"
    names = (
        ".round_1_seed.0123456789abcdef0123456789abcdef.tmp",
        ".round_1_k1.1123456789abcdef0123456789abcdef.tmp",
        ".round_1_k2_result.2123456789abcdef0123456789abcdef.tmp",
    )
    for name in names:
        (candidate_root / name / "bulk").mkdir(parents=True)
        (candidate_root / name / "bulk" / "data").write_bytes(b"residue")
    outside = tmp_path / "outside-staging"
    outside.mkdir()
    symlink_name = ".round_1_k2.3123456789abcdef0123456789abcdef.tmp"
    (candidate_root / symlink_name).symlink_to(outside, target_is_directory=True)

    loop._candidate_code_dir(1, 1, raw_input_names=())

    assert all(not (candidate_root / name).exists() for name in (*names, symlink_name))
    assert outside.exists()


def test_round_seed_freezes_existing_raw_bytes_between_candidates(tmp_path: Path) -> None:
    calls = 0
    observed: list[bytes] = []

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls <= 2:
            candidate_raw = Path(args[4]).parent / "raw"
            observed.append((candidate_raw / "facts.bin").read_bytes())
            if calls == 1:
                ws.raw_dir.joinpath("facts.bin").write_bytes(b"mutated")
            return _result(f"0x401000 VALID AUDIT REPORT {calls}")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws, loop = _loop(tmp_path, dispatch=_attested(dispatch))
    (ws.raw_dir / "facts.bin").write_bytes(b"frozen")
    loop._verify_understanding_step = lambda *_args: (True, "")

    assert loop.run().converged is True
    assert observed == [b"frozen", b"frozen"]


def test_only_one_full_candidate_clone_is_live_during_dispatch(tmp_path: Path) -> None:
    calls = 0
    live_counts: list[int] = []

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls <= 2:
            candidate_root = Path(args[4]).parent.parent
            live = [
                path
                for path in candidate_root.iterdir()
                if path.is_dir() and path.name.startswith("round_1_k")
            ]
            live_counts.append(len(live))
            return _result(f"0x401000 VALID AUDIT REPORT {calls}")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws, loop = _loop(tmp_path, dispatch=_attested(dispatch))
    (ws.code_dir / "input.bin").write_bytes(b"x" * 4096)
    loop._verify_understanding_step = lambda *_args: (True, "")

    assert loop.run().converged is True
    assert live_counts == [1, 1]
    assert not (ws.root / "candidates" / "round_1_seed").exists()


def test_dispatch_exception_removes_seed_and_partial_candidate(tmp_path: Path) -> None:
    def dispatch(*_args, **_kwargs):
        raise RuntimeError("provider adapter crashed")

    ws, loop = _loop(tmp_path, dispatch=_attested(dispatch))
    (ws.code_dir / "input.bin").write_bytes(b"safe")

    with pytest.raises(RuntimeError, match="adapter crashed"):
        loop.run()

    candidates = ws.root / "candidates"
    assert not list(candidates.iterdir())


def test_preplanted_results_symlink_cannot_capture_reconstruction(
    tmp_path: Path,
) -> None:
    ws = RunWorkspace.create(tmp_path, "/bin/true")
    canonical = ws.code_dir / "reconstruction"
    canonical.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        k_candidates=2, reconstruction_dir=str(canonical),
    )
    candidate_code = ws.root / "candidates" / "round_1_k1" / "code"
    (candidate_code / "reconstruction").mkdir(parents=True)
    (candidate_code / "reconstruction" / "safe.c").write_text("safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    (ws.root / "candidates" / "round_1_results").symlink_to(
        outside, target_is_directory=True
    )

    with pytest.raises(OSError):
        loop._seal_candidate_reconstruction(candidate_code, 1, 1)
    assert not list(outside.iterdir())


def test_later_candidate_cannot_poison_sealed_winner(tmp_path: Path) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            (Path(args[4]) / "reconstruction" / "selected.c").write_text("SAFE_K1")
            return _result("0x401000 VALID HIGH AUDIT REPORT")
        if calls == 2:
            sealed = (
                ws.root / "candidates" / "round_1_results" / "k1"
                / "code" / "reconstruction" / "selected.c"
            )
            sealed.write_text("POISON_BY_K2")
            (Path(args[4]) / "reconstruction" / "selected.c").write_text("SAFE_K2")
            return _result("0x401000 VALID LOW AUDIT REPORT")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=_attested(dispatch),
        max_rounds=1, k_candidates=2, strict_verify=False,
        reconstruction_dir=str(reconstruction), target_anchors=("0x401000",),
    )
    loop._score_candidate = lambda report: 1.0 if "HIGH" in report else 0.0
    loop._verify_understanding_step = lambda *_args: (True, "")

    result = loop.run()
    assert result.converged is True
    assert result.final_report == "0x401000 VALID LOW AUDIT REPORT"
    assert (reconstruction / "selected.c").read_text() == "SAFE_K2"


def test_later_candidate_cannot_rename_sealed_winner_empty_directory(
    tmp_path: Path,
) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            candidate_reconstruction = Path(args[4]) / "reconstruction"
            (candidate_reconstruction / "safe-empty").mkdir()
            return _result("0x401000 VALID HIGH AUDIT REPORT")
        if calls == 2:
            candidate_reconstruction = Path(args[4]) / "reconstruction"
            sealed_reconstruction = (
                ws.root / "candidates" / "round_1_results" / "k1"
                / "code" / "reconstruction"
            )
            (sealed_reconstruction / "safe-empty").rename(
                sealed_reconstruction / "poison-empty"
            )
            (candidate_reconstruction / "fallback.c").write_text("SAFE_K2")
            return _result("0x401000 VALID LOW AUDIT REPORT")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=_attested(dispatch), max_rounds=1, k_candidates=2,
        strict_verify=False, reconstruction_dir=str(reconstruction),
        target_anchors=("0x401000",),
    )
    loop._score_candidate = lambda report: 1.0 if "HIGH" in report else 0.0
    loop._verify_understanding_step = lambda *_args: (True, "")

    result = loop.run()

    assert result.converged is True
    assert result.final_report == "0x401000 VALID LOW AUDIT REPORT"
    assert not (reconstruction / "poison-empty").exists()
    assert (reconstruction / "fallback.c").read_text() == "SAFE_K2"


def test_real_quota_runtime_exports_then_promotes_only_selected_candidate(
    tmp_path: Path,
) -> None:
    if not shutil.which("bwrap"):
        pytest.skip("bubblewrap not installed")
    analyst_calls = 0

    def dispatch(agent, task, sp, on_event, cwd=None, **kwargs):
        nonlocal analyst_calls
        if cwd is None:
            return _result("REVIEW_VERDICT: SATISFIED")
        analyst_calls += 1
        label = "HIGH" if analyst_calls == 1 else "LOW"
        content = "SELECTED_K1" if analyst_calls == 1 else "LOSER_K2"
        report = f"0x401000 VALID {label} AUDIT REPORT"
        env = _supervised_agent_env(cwd)
        if kwargs.get("isolation_required"):
            env["ANGERONA_REQUIRE_AGENT_FS_SANDBOX"] = "1"
        rc, stdout, stderr, seconds = _stream_process(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    f"Path('reconstruction/selected.c').write_text({content!r}); "
                    f"print({report!r})"
                ),
            ],
            input_text=None,
            cwd=cwd,
            env=env,
            idle_timeout=5,
            wall_timeout=10,
        )
        return AgentResult(
            ok=rc == 0,
            final_text=stdout.strip(),
            events=[],
            returncode=rc,
            seconds=seconds,
            raw_stdout=stdout,
            raw_stderr=stderr,
        )

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true",
        objective="x",
        workspace=ws,
        dispatch=_attested(dispatch),
        max_rounds=1,
        k_candidates=2,
        reconstruction_dir=str(reconstruction),
        target_anchors=("0x401000",),
    )
    loop._score_candidate = lambda report: 1.0 if "HIGH" in report else 0.0
    loop._verify_understanding_step = lambda *_args: (True, "")

    result = loop.run()

    assert result.converged is True
    assert result.final_report == "0x401000 VALID HIGH AUDIT REPORT"
    assert (reconstruction / "selected.c").read_text() == "SELECTED_K1"


@pytest.mark.parametrize("nested_parent", [False, True])
def test_promotion_parent_swap_cannot_escape_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested_parent: bool
) -> None:
    ws = RunWorkspace.create(tmp_path / "run", "/bin/true")
    parent = ws.code_dir / "nested" if nested_parent else ws.code_dir
    parent.mkdir(exist_ok=True)
    reconstruction = parent / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        k_candidates=2, reconstruction_dir=str(reconstruction),
    )
    candidate_code = ws.root / "candidates" / "round_1_k1" / "code"
    candidate_reconstruction = (
        candidate_code / "nested" / "reconstruction"
        if nested_parent else candidate_code / "reconstruction"
    )
    candidate_reconstruction.mkdir(parents=True)
    (candidate_reconstruction / "x.c").write_text("selected")
    sealed = loop._seal_candidate_reconstruction(candidate_code, 1, 1)
    outside = tmp_path / "outside"
    outside.mkdir()
    original_parent = parent.with_name(parent.name + "-original")
    real_mkdir = os.mkdir
    swapped = False

    def racing_mkdir(path, *args, **kwargs):
        nonlocal swapped
        if str(path).startswith(".reconstruction.candidate-") and not swapped:
            swapped = True
            parent.rename(original_parent)
            parent.symlink_to(outside, target_is_directory=True)
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr("src.agents.loop.os.mkdir", racing_mkdir)
    try:
        with pytest.raises((OSError, RuntimeError)):
            loop._promote_candidate_reconstruction(sealed)
        assert swapped is True
        assert not (outside / "reconstruction" / "x.c").exists()
    finally:
        if parent.is_symlink():
            parent.unlink()
        if original_parent.exists():
            original_parent.rename(parent)


def test_k_candidates_require_isolation_attestation_before_provider_call(
    tmp_path: Path,
) -> None:
    calls = 0

    def legacy_dispatch(agent, task, system_prompt, on_event, cwd):
        nonlocal calls
        calls += 1
        return _result("0x401000 VALID AUDIT REPORT")

    _ws, loop = _loop(tmp_path, dispatch=legacy_dispatch)
    with pytest.raises(RuntimeError, match="isolation-capable"):
        loop.run()
    assert calls == 0


@pytest.mark.parametrize("tamper", ["metadata", "status_downgrade"])
def test_resume_recomputes_promoted_tree_metadata(
    tmp_path: Path, tamper: str
) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls <= 2:
            (Path(args[4]) / "reconstruction" / "selected.c").write_text("SAFE")
            return _result(f"0x401000 VALID AUDIT REPORT {calls}")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=_attested(dispatch),
        max_rounds=1, k_candidates=2, strict_verify=False,
        reconstruction_dir=str(reconstruction), target_anchors=("0x401000",),
    )
    loop._verify_understanding_step = lambda *_args: (True, "")
    assert loop.run().converged is True

    with AuditStateStore(ws.root) as store:
        payload = dict(store.load_latest().payload)
        selection = dict(payload["last_candidate_selection"])
        promotion = dict(selection["promotion"])
        if tamper == "metadata":
            promotion["tree_sha256"] = "0" * 64
            promotion["bytes"] = max(0, promotion["bytes"] - 1)
        else:
            promotion = {"status": "not_applicable"}
        selection["promotion"] = promotion
        payload["last_candidate_selection"] = selection
        store.checkpoint(payload)

    resumed = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        max_rounds=1, k_candidates=2, strict_verify=False,
        reconstruction_dir=str(reconstruction), target_anchors=("0x401000",),
    )
    expected = (
        "does not match checkpoint authority"
        if tamper == "metadata" else "status contradicts configuration"
    )
    with pytest.raises(AuditStateError, match=expected):
        resumed.run()


def test_single_candidate_internal_reconstruction_resumes_not_applicable(
    tmp_path: Path,
) -> None:
    calls = 0

    def dispatch(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _result(
            "REVIEW_VERDICT: SATISFIED" if calls == 2 else "VALID K1 AUDIT REPORT"
        )

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=_attested(dispatch),
        max_rounds=1, k_candidates=1, strict_verify=False,
        reconstruction_dir=str(reconstruction),
    )
    loop._verify_understanding_step = lambda *_args: (True, "")
    assert loop.run().converged is True

    resumed = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        max_rounds=1, k_candidates=1, strict_verify=False,
        reconstruction_dir=str(reconstruction),
    )
    assert resumed.run().converged is True


def test_seal_rejection_without_promotion_attempt_resumes_not_applicable(
    tmp_path: Path,
) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            (Path(args[4]) / "reconstruction" / "escape.c").symlink_to("/etc/passwd")
            return _result("0x401000 VALID AUDIT REPORT")
        if calls == 2:
            return AgentResult(
                ok=False, final_text="provider failed", events=[], returncode=75,
                seconds=0.01, raw_stdout="", raw_stderr="provider overloaded",
            )
        return _result("REVIEW_VERDICT: NEEDS_WORK")

    ws = RunWorkspace.create(tmp_path, "/bin/true")
    reconstruction = ws.code_dir / "reconstruction"
    reconstruction.mkdir()
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=_attested(dispatch),
        max_rounds=1, k_candidates=2, strict_verify=False,
        reconstruction_dir=str(reconstruction), target_anchors=("0x401000",),
    )
    loop._verify_understanding_step = lambda *_args: (True, "")
    assert loop.run().converged is False

    resumed = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=RunWorkspace.open(ws.root),
        dispatch=lambda *_args, **_kwargs: _result("unused"),
        max_rounds=1, k_candidates=2, strict_verify=False,
        reconstruction_dir=str(reconstruction), target_anchors=("0x401000",),
    )
    assert resumed.run().converged is False


def test_seed_clone_rejects_symlink_swap_before_second_dispatch(tmp_path: Path) -> None:
    calls = 0

    def dispatch(*args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            canonical = ws.raw_dir / "facts.bin"
            canonical.unlink()
            canonical.symlink_to("/etc/passwd")
        if calls <= 2:
            assert (Path(args[4]).parent / "raw" / "facts.bin").read_bytes() == b"safe"
            return _result(f"0x401000 VALID AUDIT REPORT {calls}")
        return _result("REVIEW_VERDICT: SATISFIED")

    ws, loop = _loop(tmp_path, dispatch=_attested(dispatch))
    (ws.raw_dir / "facts.bin").write_bytes(b"safe")
    loop._verify_understanding_step = lambda *_args: (True, "")

    with pytest.raises(AuditStateError, match="non-regular file"):
        loop.run()
    assert calls == 3
