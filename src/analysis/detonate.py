"""Disposable-container detonation for dynamic (behavioural) analysis.

A professional never runs malware on their host — they detonate it in a throwaway,
isolated environment and watch what it does. This module runs an untrusted sample in
a FRESH Docker container with:

  * --network none            (no C2 / kill-switch / exfil / lateral movement)
  * --cap-drop ALL, SYS_PTRACE for strace, and no-new-privileges
  * --read-only root + a small exec tmpfs for the sample
  * --memory / --pids-limit   (resource bomb protection)
  * a hard timeout, and --rm  (container destroyed afterwards)

It runs the sample under ``strace`` and returns the observed behaviour (network /
file / process syscalls, stdout/stderr, exit code). Nothing touches the host or the
network. The agent invokes this via the ``detonate_sample`` MCP tool.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import uuid
from pathlib import Path

from ..subprocess_observability import observed_run

IMAGE = "gra-detonate:latest"
_DOCKER = ["docker"]
_REPO_DOCKERFILE = Path(__file__).resolve().parent.parent.parent / "docker" / "detonate.Dockerfile"
_PACKAGED_DOCKERFILE = Path(__file__).resolve().parent / "resources" / "detonate.Dockerfile"
_DOCKERFILE = _REPO_DOCKERFILE if _REPO_DOCKERFILE.is_file() else _PACKAGED_DOCKERFILE


def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    # Program output is untrusted arbitrary bytes. This is a bounded diagnostic
    # text report, not the byte-exact equivalence oracle.
    return observed_run([*_DOCKER, *args], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=timeout, check=False)


def docker_available() -> bool:
    try:
        return _run(["info"], timeout=25).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def image_present() -> bool:
    try:
        return _run(["image", "inspect", IMAGE], timeout=25).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def build_image() -> tuple[bool, str]:
    if image_present():
        return True, "detonation image already built"
    if not _DOCKERFILE.is_file():
        return False, f"detonation build recipe missing: {_DOCKERFILE}"
    try:
        r = _run(["build", "-t", IMAGE, "-f", str(_DOCKERFILE), str(_DOCKERFILE.parent)], timeout=900)
    except subprocess.TimeoutExpired:
        return False, "image build timed out"
    return r.returncode == 0, (r.stdout + r.stderr)[-2000:]


def _summarize(strace_text: str) -> dict:
    def _grab(pattern: str, limit: int = 25) -> list[str]:
        out, seen = [], set()
        for m in re.finditer(pattern, strace_text):
            s = m.group(0)[:200]
            if s not in seen:
                seen.add(s)
                out.append(s)
            if len(out) >= limit:
                break
        return out

    return {
        "network": _grab(r"(socket|connect|bind|sendto|recvfrom|getaddrinfo)\([^\n]*"),
        "processes": _grab(r"(execve|clone|fork|vfork)\([^\n]*"),
        "files": _grab(r"(openat?|unlink|rename|chmod|creat)\([^\n]*"),
    }


def detonate(sample: str | Path, *, timeout_seconds: int = 20, argv: list[str] | None = None) -> dict:
    """Run ``sample`` in a fresh disposable no-network container; capture behaviour."""
    sample = Path(sample).expanduser().resolve()
    if not sample.is_file():
        return {"ok": False, "error": f"sample not found: {sample}"}
    if not docker_available():
        return {"ok": False, "error": "Docker daemon not available (start it: sudo systemctl start docker)."}
    built, msg = build_image()
    if not built:
        return {"ok": False, "error": f"detonation image not available: {msg}"}

    timeout_seconds = max(1, min(int(timeout_seconds), 120))
    quoted_args = " ".join(shlex.quote(a) for a in (argv or []))
    script = (
        "cp /ro/sample /work/s 2>/dev/null; chmod +x /work/s 2>/dev/null; "
        f"timeout -k 2 {timeout_seconds} strace -f -qq -e trace=network,file,process "
        f"-o /work/strace.log /work/s {quoted_args} >/work/out 2>/work/err; "
        'echo \"EXIT=$?\"; '
        'echo \"=== STDOUT ===\"; head -c 4000 /work/out; '
        'echo; echo \"=== STDERR ===\"; head -c 4000 /work/err; '
        'echo; echo \"=== STRACE ===\"; head -c 12000 /work/strace.log'
    )
    container_name = "angerona-detonate-" + uuid.uuid4().hex
    run_args = [
        "create", "--name", container_name, "--network", "none",
        "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/work:rw,exec,size=128m,mode=1777",
        "--memory", "512m", "--pids-limit", "128",
        "-v", f"{sample}:/ro/sample:ro",
        IMAGE, "sh", "-c", script,
    ]
    result: dict = {"ok": False, "container_name": container_name}
    try:
        created = _run(run_args, timeout=60)
        if created.returncode != 0:
            result["error"] = f"container creation failed: {(created.stderr or '')[-2000:]}"
        else:
            result["container_id"] = (created.stdout or "").strip()
            r = _run(["start", "--attach", container_name], timeout=timeout_seconds + 30)
            out = r.stdout or ""
            exit_m = re.search(r"(?m)^EXIT=(\d+)$", out)
            if r.returncode != 0 or exit_m is None or "=== STRACE ===" not in out:
                result["error"] = f"container execution not verified (rc={r.returncode}): {(r.stderr or out)[-2000:]}"
            else:
                result.update({
                    "ok": True,
                    "isolation": "docker --network none --cap-drop ALL --cap-add SYS_PTRACE --read-only --pids-limit 128",
                    "output_decoding": "utf-8 with replacement; diagnostic text, not byte-exact output",
                    "sample_exit_code": int(exit_m.group(1)),
                    "behavior_summary": _summarize(out.split("=== STRACE ===", 1)[1]),
                    "raw_output": out[-12000:],
                })
    except subprocess.TimeoutExpired:
        result["error"] = "detonation wall-timeout"
    except OSError as exc:
        result["error"] = f"container launch failed: {exc}"
    finally:
        # The Docker daemon owns the container independently of our CLI process.
        # Always remove the exact unique resource, including partial launches.
        try:
            removed = _run(["rm", "--force", container_name], timeout=30)
            cleaned = removed.returncode == 0 or "No such container" in (removed.stderr or "")
            result["cleanup_complete"] = cleaned
            if not cleaned:
                result["cleanup_error"] = (removed.stderr or "container cleanup failed")[-2000:]
                result["ok"] = False
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["cleanup_complete"] = False
            result["cleanup_error"] = str(exc)
            result["ok"] = False
    return result
