"""Minimal isolation for running Ghidra on untrusted (malware) samples.

Wraps a command with bubblewrap so the ONLY thing that touches the sample —
Ghidra's ``analyzeHeadless`` — runs with:
  * NO network            (--unshare-net): ransomware can't reach C2/kill-switch.
  * read-only host         (--ro-bind / /): the sample/parser can't modify the host.
  * one writable dir       (the analysis cache, holds only benign Ghidra output).
  * dropped caps / new ns  (defense in depth).

The sample is never executed (static analysis only); this contains the parse step.
Kept deliberately small.
"""

from __future__ import annotations

import shutil
from pathlib import Path

BWRAP = "bwrap"


def available() -> bool:
    return shutil.which(BWRAP) is not None


def wrap(cmd: list[str], writable_dirs: list[Path], readonly_binds: list[Path] | None = None) -> list[str]:
    """Prefix ``cmd`` with a locked-down bwrap invocation.

    The whole host is read-only, but ``$HOME`` is hidden with a tmpfs so the
    sample/parser cannot read credentials (~/.ssh, ~/.claude, ~/.codex, ~/.aws,
    browser profiles, etc.). Only ``readonly_binds`` (tool/Ghidra/JDK/sample) are
    brought back read-only, and ``writable_dirs`` (the benign analysis cache) are
    writable. HOME is redirected into the writable cache.
    """
    home = str(Path.home())
    writable_dirs = [Path(d) for d in writable_dirs]
    readonly_binds = [Path(d) for d in (readonly_binds or [])]
    prefix = [
        BWRAP,
        "--ro-bind", "/", "/",         # whole host read-only
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", home,               # HIDE all of $HOME (credentials, keys, tokens)
    ]
    for d in readonly_binds:           # bring back only what Ghidra needs, read-only
        if d.exists():
            prefix += ["--ro-bind", str(d), str(d)]
    for d in writable_dirs:            # only the benign analysis cache is writable
        prefix += ["--bind", str(d), str(d)]
    if writable_dirs:                  # give Ghidra a writable HOME (not the real one)
        h = writable_dirs[0]
        prefix += [
            "--setenv", "HOME", str(h),
            "--setenv", "XDG_CONFIG_HOME", str(h / ".config"),
            "--setenv", "XDG_CACHE_HOME", str(h / ".cache"),
        ]
    prefix += [
        "--unshare-net",               # no network
        "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--cap-drop", "ALL",
        "--die-with-parent", "--new-session",
    ]
    return prefix + list(cmd)
