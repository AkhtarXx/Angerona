"""Configuration and environment discovery for Angerona.

Everything is install-agnostic and portable: it works the same on a laptop or a
cloud instance because every runtime is located dynamically — never hard-coded.

Two reverse-engineering engines are supported:

* ``ida``   — IDA Pro (default). Headless analysis via ``idalib`` and the
  ``ida-pro-mcp`` (``idalib-mcp``) MCP server. Located via ``IDA_INSTALL_DIR``,
  a vendored ``vendor/ida*`` copy, or common install paths. This is the
  **default and recommended** engine: a licensed IDA Pro gives higher-quality
  decompilation than the open-source Ghidra, and the vendored copy + idalib
  venv are already provisioned in this repo.
* ``ghidra`` — Ghidra headless (``analyzeHeadless`` + ``REDump.java``). Located
  via ``GHIDRA_INSTALL_DIR``, a vendored ``vendor/ghidra_*_PUBLIC``, or common
  paths. Free / no license, fully wired — a solid fallback when IDA is unavailable.

Select the active engine with ``--engine`` on the CLI or the ``ANGERONA_ENGINE``
environment variable (default ``ida``).
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
VENDOR_DIR = REPO_ROOT / "vendor"

# Engines ---------------------------------------------------------------------

ENGINES = ("ida", "ghidra")
DEFAULT_ENGINE = "ida"


def default_engine() -> str:
    """Active engine from env, falling back to IDA. Unknown values use the default."""
    val = (os.environ.get("ANGERONA_ENGINE") or DEFAULT_ENGINE).strip().lower()
    return val if val in ENGINES else DEFAULT_ENGINE


# Local-model mode (P2-10, research Part 5/17) ------------------------------------
# Air-gapped / privacy runs route LLM calls to a LOCAL OpenAI-compatible server
# (Ollama, vLLM, llama.cpp) instead of a cloud API. REx86 (ACSAC'25, 7B x86 RE model)
# is the research-validated local option. This is a CONTRACT the calling harness
# reads: when ANGERONA_LOCAL_MODEL=1, the agent framework should point its OpenAI-
# compatible client at ANGERONA_LOCAL_BASE_URL (default http://localhost:11434/v1,
# Ollama's API) and use ANGERONA_LOCAL_MODEL_NAME as the model. Cloud keys are not
# required in this mode.
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"   # Ollama OpenAI-compatible API
DEFAULT_LOCAL_MODEL = "rex86:latest"                   # local RE model (override via env)


def local_model_config() -> dict | None:
    """Return local-model connection config, or None if local mode is off.

    Used by the agent harness to bind LLM calls to a local endpoint. Returns None
    when ANGERONA_LOCAL_MODEL != '1' so the cloud path is the default.
    """
    if os.environ.get("ANGERONA_LOCAL_MODEL", "") != "1":
        return None
    return {
        "base_url": os.environ.get("ANGERONA_LOCAL_BASE_URL", DEFAULT_LOCAL_BASE_URL),
        "model": os.environ.get("ANGERONA_LOCAL_MODEL_NAME", DEFAULT_LOCAL_MODEL),
        "api_key": os.environ.get("ANGERONA_LOCAL_API_KEY", "local"),  # local servers ignore it
    }


# ------------------------------------------------------------- Ghidra discovery

def parse_ghidra_version(name: str) -> tuple[int, ...]:
    """'ghidra_12.1.2_PUBLIC' -> (12, 1, 2); unknown -> (0,)."""
    m = re.search(r"ghidra_(\d+(?:\.\d+)*)_PUBLIC", name)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def _vendored_installs() -> list[Path]:
    """Vendored Ghidra releases, newest version first (proper numeric sort)."""
    vendor = VENDOR_DIR
    if not vendor.exists():
        return []
    installs = [c for c in vendor.glob("ghidra_*_PUBLIC")
                if (c / "support" / "analyzeHeadless").exists()]
    return sorted(installs, key=lambda p: parse_ghidra_version(p.name), reverse=True)


def find_ghidra_install() -> Path | None:
    """Locate a Ghidra installation directory.

    Order: GHIDRA_INSTALL_DIR env -> newest vendored release under repo/vendor ->
    common install locations -> analyzeHeadless on PATH.
    """
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and (Path(env) / "support" / "analyzeHeadless").exists():
        return Path(env)

    vendored = _vendored_installs()
    if vendored:
        return vendored[0]

    common: list[Path] = []
    for base in ("/opt", "/usr/local", str(Path.home()), "/usr/share"):
        common.extend(Path(base).glob("ghidra_*_PUBLIC"))
        common.extend(Path(base).glob("ghidra*"))
    common = sorted(
        (c for c in common if (c / "support" / "analyzeHeadless").exists()),
        key=lambda p: parse_ghidra_version(p.name), reverse=True,
    )
    if common:
        return common[0]

    which = shutil.which("analyzeHeadless")
    if which:
        p = Path(which).resolve().parent.parent
        if (p / "support" / "analyzeHeadless").exists():
            return p
    return None


def find_java_home() -> str | None:
    """Locate a JDK 21+ for Ghidra (JAVA_HOME env or common JVM dirs)."""
    env = os.environ.get("JAVA_HOME")
    if env and (Path(env) / "bin" / "java").exists():
        return env
    for base in ("/usr/lib/jvm", "/Library/Java/JavaVirtualMachines", "/opt/java"):
        b = Path(base)
        if not b.exists():
            continue
        for cand in sorted(b.glob("*"), reverse=True):
            java = cand / "bin" / "java"
            if not java.exists():
                java = cand / "Contents" / "Home" / "bin" / "java"
            if java.exists():
                return str(java.parent.parent)
    return None


# ---------------------------------------------------------------- IDA discovery

def _idalib_name() -> str:
    """Platform-specific idalib shared-library filename (matches py-activate-idalib.py)."""
    system = platform.system()
    if system == "Windows":
        return "idalib.dll"
    if system == "Darwin":
        return "libidalib.dylib"
    return "libidalib.so"


def _idat_names() -> tuple[str, ...]:
    """Candidate headless-IDA executable names by platform."""
    if platform.system() == "Windows":
        return ("idat64.exe", "idat.exe", "idat64", "idat")
    return ("idat64", "idat", "idat64.exe", "idat.exe")


def is_valid_ida_dir(path: str | Path) -> bool:
    """A dir is a usable IDA install if it has idalib + IDA help/kernel markers.

    Mirrors the check in IDA's own ``py-activate-idalib.py`` (``ida.hlp`` +
    the idalib shared library), so the same folder that activates idalib is the
    one we detect.
    """
    d = Path(path)
    if not d.is_dir():
        return False
    has_idalib = (d / _idalib_name()).is_file()
    has_marker = (d / "ida.hlp").is_file() or any((d / n).is_file() for n in _idat_names())
    return has_idalib and has_marker


def parse_ida_version(name: str) -> tuple[int, ...]:
    """'ida-9.1' / 'ida_9.1' / 'idapro-9.0' -> (9, 1); unknown -> (0,)."""
    m = re.search(r"(?:ida|idapro)[-_ ]?(\d+(?:\.\d+)*)", name, re.IGNORECASE)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def _vendored_ida_installs() -> list[Path]:
    """Vendored IDA installs under repo/vendor, newest version first."""
    if not VENDOR_DIR.exists():
        return []
    cands: list[Path] = []
    for pat in ("ida-*", "ida_*", "ida", "idapro*", "IDA*"):
        cands.extend(VENDOR_DIR.glob(pat))
    installs = [c for c in cands if is_valid_ida_dir(c)]
    # de-dup preserving type
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in installs:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return sorted(uniq, key=lambda p: parse_ida_version(p.name), reverse=True)


def find_ida_install() -> Path | None:
    """Locate an IDA Pro installation directory (one containing idalib).

    Order: ``IDA_INSTALL_DIR``/``IDADIR`` env -> newest vendored ``vendor/ida*``
    -> common install locations -> ``idat``/``idat64`` on PATH -> the path
    recorded in ``~/.idapro/ida-config.json`` (written by py-activate-idalib.py).
    """
    for var in ("IDA_INSTALL_DIR", "IDADIR"):
        env = os.environ.get(var)
        if env and is_valid_ida_dir(env):
            return Path(env)

    vendored = _vendored_ida_installs()
    if vendored:
        return vendored[0]

    common: list[Path] = []
    home = Path.home()
    bases = ["/opt", "/usr/local", str(home), "/Applications",
             str(home / ".idapro")]
    globs = ["ida-*", "ida_*", "idapro*", "IDA*", "ida*",
             "IDA Professional*", "IDA Pro*", "IDA Freeware*"]
    for base in bases:
        b = Path(base)
        if not b.exists():
            continue
        for g in globs:
            common.extend(b.glob(g))
    valid = [c for c in common if is_valid_ida_dir(c)]
    valid = sorted(valid, key=lambda p: parse_ida_version(p.name), reverse=True)
    if valid:
        return valid[0]

    for name in _idat_names():
        which = shutil.which(name)
        if which:
            p = Path(which).resolve().parent
            if is_valid_ida_dir(p):
                return p

    # Fall back to the activation config written by py-activate-idalib.py.
    cfg = ida_config_json_path()
    try:
        import json
        if cfg.is_file():
            data = json.loads(cfg.read_text())
            d = (data.get("Paths") or {}).get("ida-install-dir") or ""
            if d and is_valid_ida_dir(d):
                return Path(d)
    except Exception:  # noqa: BLE001
        pass
    return None


def ida_config_json_path() -> Path:
    """Location of IDA's user config (holds the activated idalib install dir)."""
    if platform.system() == "Windows":
        base = Path(os.getenv("APPDATA", str(Path.home()))) / "Hex-Rays" / "IDA Pro"
    else:
        base = Path.home() / ".idapro"
    return base / "ida-config.json"


def ida_mcp_venv() -> Path:
    """Repo-local virtualenv that holds ``ida-pro-mcp`` (created by `install`)."""
    return VENDOR_DIR / "ida-mcp-venv"


# ----------------------------------------------------------- BinDiff / BinExport

def find_bindiff() -> Path | None:
    """Locate the ``bindiff`` command-line differ.

    Order: ``BINDIFF_PATH`` env (may point at the binary or its dir) ->
    vendored ``vendor/bindiff*`` -> common install locations -> ``PATH``.
    Returns the path to the executable, or None if not found.
    """
    exe_names = ("bindiff", "differ", "bindiff.exe")

    env = os.environ.get("BINDIFF_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            return p
        if p.is_dir():
            for n in exe_names:
                cand = p / n
                if cand.is_file():
                    return cand

    if VENDOR_DIR.exists():
        for pat in ("bindiff*", "BinDiff*"):
            for base in sorted(VENDOR_DIR.glob(pat), reverse=True):
                for sub in ("", "bin", "usr/bin"):
                    for n in exe_names:
                        cand = base / sub / n if sub else base / n
                        if cand.is_file():
                            return cand

    for base in ("/opt/bindiff/bin", "/usr/bin", "/usr/local/bin", "/opt/local/bin"):
        for n in exe_names:
            cand = Path(base) / n
            if cand.is_file():
                return cand

    for n in exe_names:
        which = shutil.which(n)
        if which:
            return Path(which)
    return None


def find_binexport_ghidra() -> Path | None:
    """Locate the Ghidra BinExport extension (a directory installed under a
    Ghidra install's ``Ghidra/Extensions/BinExport``).

    Order: ``BINEXPORT_GHIDRA_ZIP`` env -> vendored ``vendor/*BinExport*.zip``
    -> installed extension under ANY discovered vendored Ghidra version (so we
    can use the newest Ghidra that actually has the extension, even if it is
    not the globally newest Ghidra install)
    -> ``Ghidra/Extensions/BinExport`` inside any discovered ``GHIDRA_INSTALL_DIR``.
    The BinExport post-script is run from the returned extension directory.
    """
    env = os.environ.get("BINEXPORT_GHIDRA_ZIP")
    if env and Path(env).is_file():
        return Path(env)
    if VENDOR_DIR.exists():
        cands = sorted(VENDOR_DIR.glob("*BinExport*.zip"), reverse=True)
        if cands:
            return cands[0]

    # Vendored fallback first: pick the newest vendored Ghidra install whose
    # Extensions directory contains BinExport. A vendored extension lives
    # under a full Ghidra install, so analyzeHeadless and the extension are
    # guaranteed to match. This matters when the active engine is a newer
    # Ghidra (e.g. 12.x) that does not ship the extension but an older
    # vendored copy (e.g. 11.x) does.
    for ghidra in _vendored_installs():
        ext = ghidra / "Ghidra" / "Extensions" / "BinExport"
        if ext.is_dir() and ((ext / "extension.properties").is_file()
                             or (ext / "ghidra_scripts" / "BinExport2.py").is_file()):
            return ext

    # Installed extension directory inside the active/explicit Ghidra install,
    # or the user's activated-extensions dir (~/.ghidra/<ver>/Extensions).
    # Only prefer these if a full Ghidra install is discoverable; otherwise
    # the extension directory alone cannot run analyzeHeadless.
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR") or find_ghidra_install()
    candidates = []
    if ghidra:
        candidates.append(Path(ghidra) / "Ghidra" / "Extensions" / "BinExport")
    home = os.environ.get("HOME")
    if home:
        import glob as _glob
        # Note: the versioned dir is dot-prefixed (.ghidra_<ver>_PUBLIC), so a
        # leading-`*` glob won't match it; use `.*` to include hidden entries.
        candidates += [
            Path(p) for p in _glob.glob(
                os.path.join(home, ".ghidra", ".*", "Extensions", "BinExport")
            )
        ]
    for ext in candidates:
        if ext.is_dir() and ((ext / "extension.properties").is_file()
                             or (ext / "ghidra_scripts" / "BinExport2.py").is_file()):
            return ext
    return None


def find_ida_mcp_python() -> Path | None:
    """Locate the Python interpreter that has ``ida-pro-mcp`` installed.

    Order: ``ANGERONA_IDA_MCP_PYTHON`` env -> repo-local ``vendor/ida-mcp-venv``.
    Returns None if not yet provisioned (run ``angerona install --engine ida``).
    """
    env = os.environ.get("ANGERONA_IDA_MCP_PYTHON")
    if env and Path(env).exists():
        return Path(env)
    for sub in ("bin/python", "bin/python3", "Scripts/python.exe"):
        cand = ida_mcp_venv() / sub
        if cand.exists():
            return cand
    return None


def _dot_element(path: Path) -> str | None:
    """Return the first path element starting with '.', if any (Ghidra rejects these
    in project paths, e.g. ~/.angerona)."""
    for part in Path(path).resolve().parts:
        if part not in ("/", "") and part.startswith("."):
            return part
    return None


def state_home() -> Path:
    """State/cache/workspaces root. Defaults to ``<repo>/workspaces`` (inside the project,
    NOT the user's home dir) so runs are discoverable and don't clutter ``~``. It is a
    dot-free path because Ghidra rejects project locations with '.'-prefixed elements.
    Override with ``ANGERONA_HOME``."""
    home = os.environ.get("ANGERONA_HOME")
    root = Path(home) if home else (REPO_ROOT / "workspaces")
    root.mkdir(parents=True, exist_ok=True)
    return root


@dataclass
class Config:
    # engine selection
    engine: str
    # ghidra
    ghidra_install: Path | None
    java_home: str | None
    # ida
    ida_install: Path | None
    ida_mcp_python: Path | None
    # bindiff (structural verification)
    bindiff: Path | None
    binexport_ghidra: Path | None
    # shared
    scripts_dir: Path
    state_dir: Path
    projects_dir: Path
    cache_dir: Path
    analysis_timeout: int = 900
    sandbox: bool = False

    # ---------------------------------------------------------------- ghidra

    @property
    def analyze_headless(self) -> Path | None:
        if not self.ghidra_install:
            return None
        return self.ghidra_install / "support" / "analyzeHeadless"

    def ghidra_ready(self) -> tuple[bool, str]:
        if not self.ghidra_install:
            return False, (
                "Ghidra not found. Set GHIDRA_INSTALL_DIR to a Ghidra install "
                "(the folder containing support/analyzeHeadless)."
            )
        if not self.analyze_headless or not self.analyze_headless.exists():
            return False, f"analyzeHeadless missing under {self.ghidra_install}"
        if not self.java_home:
            return False, "JDK 21+ not found. Install a JDK and/or set JAVA_HOME."
        bad = _dot_element(self.projects_dir)
        if bad:
            return False, (
                f"Ghidra rejects project paths containing a dot-prefixed element ('{bad}'). "
                f"Set ANGERONA_HOME to a path with no '.'-prefixed folder "
                f"(current projects dir: {self.projects_dir})."
            )
        return True, "ok"

    # ------------------------------------------------------------------- ida

    @property
    def idat(self) -> Path | None:
        if not self.ida_install:
            return None
        for name in _idat_names():
            p = self.ida_install / name
            if p.exists():
                return p
        return None

    @property
    def libidalib(self) -> Path | None:
        if not self.ida_install:
            return None
        p = self.ida_install / _idalib_name()
        return p if p.exists() else None

    @property
    def idalib_python_dir(self) -> Path | None:
        """The ``idalib/python`` dir inside the IDA install (holds py-activate-idalib.py)."""
        if not self.ida_install:
            return None
        p = self.ida_install / "idalib" / "python"
        return p if p.exists() else None

    def ida_activated(self) -> bool:
        """True if idalib appears activated for the current user (config json points at
        a valid install) OR IDADIR is set. Note: this does not validate the license —
        IDA verifies that itself at runtime."""
        if os.environ.get("IDADIR") and is_valid_ida_dir(os.environ["IDADIR"]):
            return True
        try:
            import json
            cfg = ida_config_json_path()
            if cfg.is_file():
                d = (json.loads(cfg.read_text()).get("Paths") or {}).get("ida-install-dir") or ""
                return bool(d) and is_valid_ida_dir(d)
        except Exception:  # noqa: BLE001
            return False
        return False

    def ida_ready(self) -> tuple[bool, str]:
        """Whether the IDA engine + MCP server can be launched. Licensing is validated
        by IDA itself at first database open, not here."""
        if not self.ida_install:
            return False, (
                "IDA Pro not found. Set IDA_INSTALL_DIR to an IDA install (the folder "
                "containing libidalib.so / ida.hlp), or vendor it under vendor/ida-*."
            )
        if not self.libidalib:
            return False, f"idalib ({_idalib_name()}) missing under {self.ida_install}"
        if not self.ida_mcp_python:
            return False, (
                "ida-pro-mcp not provisioned. Run `angerona install --engine ida` to "
                "create vendor/ida-mcp-venv (or set ANGERONA_IDA_MCP_PYTHON)."
            )
        return True, "ok"

    # -------------------------------------------------------------- bindiff

    def bindiff_ready(self) -> tuple[bool, str]:
        """Whether structural (BinDiff) verification can run for the active engine.

        Requires the ``bindiff`` differ plus an engine-specific BinExport exporter:
        Ghidra needs the BinExport extension zip; IDA ships BinExport with idalib.
        """
        if not self.bindiff:
            return False, (
                "BinDiff not found. Install it (https://github.com/google/bindiff), "
                "set BINDIFF_PATH, or vendor it under vendor/bindiff*."
            )
        if self.engine == "ghidra" and not self.binexport_ghidra:
            return False, (
                "Ghidra BinExport extension not found. Download the BinExport release "
                "for your Ghidra version, set BINEXPORT_GHIDRA_ZIP, or vendor it under "
                "vendor/*BinExport*.zip."
            )
        return True, "ok"

    # ---------------------------------------------------------------- shared

    def ready(self) -> tuple[bool, str]:
        """Readiness of the *active* engine."""
        if self.engine == "ida":
            return self.ida_ready()
        if self.engine == "ghidra":
            return self.ghidra_ready()
        return False, f"unsupported engine: {self.engine!r}"

    def subprocess_env(self) -> dict[str, str]:
        """Env for Ghidra subprocesses with writable config and Java on PATH."""
        env = dict(os.environ)
        config_home = self.state_dir / "config"
        config_home.mkdir(parents=True, exist_ok=True)
        # Ghidra's launcher persists the selected JDK even in headless mode.
        # Keep that write in Angerona state rather than requiring a writable
        # user home (which is intentionally read-only inside the sandbox).
        env["XDG_CONFIG_HOME"] = str(config_home)
        if self.java_home:
            env["JAVA_HOME"] = self.java_home
            env["PATH"] = f"{self.java_home}/bin:" + env.get("PATH", "")
        return env

    def ida_env(self) -> dict[str, str]:
        """Build an IDA/idalib environment with writable per-user state.

        IDA updates ``ida.reg`` while opening a database.  A read-only home is
        therefore insufficient even when the license is installed and valid
        (as it is inside Angerona's sandbox and many CI/container runtimes).
        Seed the small set of required user files into Angerona's writable
        state directory and point IDA at that copy with ``IDAUSR``.
        """
        env = dict(os.environ)
        if self.ida_install:
            env["IDADIR"] = str(self.ida_install)

        source_user_dir = Path(env.get("IDAUSR") or (Path.home() / ".idapro"))
        ida_user_dir = self.state_dir / "ida-user"
        ida_user_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            ida_user_dir.chmod(0o700)
        except OSError:
            # Some non-POSIX filesystems do not support chmod. IDA can still use
            # the directory, and the containing state directory remains scoped.
            pass

        # Seed only the user files IDA needs.  Never overwrite the state copy:
        # IDA legitimately updates it after startup, and concurrent workers may
        # share the same configured state directory.
        seed_names = (
            "ida.reg",
            "ida.cfg",
            "idagui.cfg",
            "idausr.cfg",
            "idatui.cfg",
            "idauser.cfg",
            "hexrays.cfg",
            "idapro.hexlic",
        )
        if source_user_dir.resolve() != ida_user_dir.resolve():
            for name in seed_names:
                source = source_user_dir / name
                target = ida_user_dir / name
                if not source.is_file() or target.exists():
                    continue
                temporary: Path | None = None
                try:
                    with tempfile.NamedTemporaryFile(
                        dir=ida_user_dir, prefix=f".{name}.", delete=False
                    ) as handle:
                        temporary = Path(handle.name)
                        with source.open("rb") as source_handle:
                            shutil.copyfileobj(source_handle, handle)
                    temporary.chmod(0o600)
                    # Another worker may have seeded the same file. Replacing it
                    # is safe here because both copies came from the same source.
                    os.replace(temporary, target)
                    temporary = None
                except OSError:
                    # IDA's own diagnostics remain authoritative if an optional
                    # user config file cannot be copied.
                    pass
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
        env["IDAUSR"] = str(ida_user_dir)

        # idalib refuses to import when IDA_IS_INTERACTIVE=1 (that flag means "inside the
        # IDA GUI"). Ensure a stray inherited value can't break headless analysis.
        env.pop("IDA_IS_INTERACTIVE", None)
        return env


def load_config(engine: str | None = None) -> Config:
    selected_engine = engine or default_engine()
    if selected_engine not in {"ida", "ghidra"}:
        raise ValueError(f"unsupported engine: {selected_engine!r}")
    state = state_home()
    projects = state / "projects"
    cache = state / "cache"
    projects.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    timeout = int(os.environ.get("ANGERONA_ANALYSIS_TIMEOUT", "900"))
    sandbox = os.environ.get("ANGERONA_SANDBOX", "").strip().lower() in {"1", "true", "yes", "on"}
    return Config(
        engine=selected_engine,
        ghidra_install=find_ghidra_install(),
        java_home=find_java_home(),
        ida_install=find_ida_install(),
        ida_mcp_python=find_ida_mcp_python(),
        bindiff=find_bindiff(),
        binexport_ghidra=find_binexport_ghidra(),
        scripts_dir=SCRIPTS_DIR,
        state_dir=state,
        projects_dir=projects,
        cache_dir=cache,
        analysis_timeout=timeout,
        sandbox=sandbox,
    )
