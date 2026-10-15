"""Owned, disposable Android Emulator targets for authorized APK analysis.

The default backend is the official Android Emulator with a rootable AOSP
system image.  A lease owns its AVD directory, emulator process, private ADB
server, Frida server, and teardown receipt.  Nothing in this module treats an
arbitrary connected device as an Angerona-owned target.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..subprocess_observability import observed_run


class AndroidRuntimeError(RuntimeError):
    """A fail-closed managed-target preparation error."""


@dataclass(frozen=True)
class ApkRuntimeRequirements:
    apk_sha256: str
    apk_bytes: int
    apk_uncompressed_bytes: int
    native_abis: tuple[str, ...]
    min_sdk: int | None = None
    target_sdk: int | None = None


@dataclass(frozen=True)
class AndroidRuntimePolicy:
    provider: str = "auto"  # auto | avd | connected
    api: int = 35
    abi: str = "auto"
    image_tag: str = "default"
    avd_name: str = ""
    sdk_root: str = ""
    state_root: str = ""
    auto_provision: bool = False
    allow_native_translation: bool = False
    allow_software_acceleration: bool = False
    boot_timeout: int = 360
    memory_mb: int = 3072
    data_partition_mb: int = 4096
    network_policy: str = "deny"  # deny | allow
    # Produced by the disposable-worker controller, not by the APK harness.
    # The digest is supplied out-of-band so an untrusted job cannot silently
    # replace the controller's containment attestation.
    containment_receipt_path: str = ""
    containment_receipt_sha256: str = ""


@dataclass(frozen=True)
class AndroidSdkToolchain:
    sdk_root: str
    adb: str
    emulator: str
    avdmanager: str
    sdkmanager: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ManagedAndroidTarget:
    serial: str
    adb_server_port: int
    avd_name: str
    image_package: str
    api: int
    abi: str
    job_dir: str
    receipt: dict[str, Any] = field(default_factory=dict)
    # Ephemeral control-plane secret.  It must never be serialized into the
    # public lease receipt or command/evidence logs.
    frida_token: str = field(default="", repr=False)


CONTAINMENT_RECEIPT_SCHEMA = "angerona.android.host-containment/v1"
_MAX_CONTAINMENT_RECEIPT_BYTES = 64 * 1024
_MAX_CONTAINMENT_RECEIPT_LIFETIME_S = 24 * 60 * 60


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _containment_receipt_location(
    policy: AndroidRuntimePolicy,
) -> tuple[str, str]:
    return (
        policy.containment_receipt_path
        or os.environ.get("ANGERONA_ANDROID_CONTAINMENT_RECEIPT", ""),
        policy.containment_receipt_sha256
        or os.environ.get("ANGERONA_ANDROID_CONTAINMENT_RECEIPT_SHA256", ""),
    )


def verify_host_containment_receipt(
    policy: AndroidRuntimePolicy,
    *,
    apk_sha256: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify a pinned, controller-owned disposable-worker attestation.

    This receipt does not attempt to configure containment.  It is a strict
    hand-off from the worker controller which configured and independently
    verified the boundary before Angerona started.  Both its absolute path and
    SHA-256 must be supplied explicitly through policy or environment.
    """
    configured_path, expected_sha256 = _containment_receipt_location(policy)
    if not configured_path or not expected_sha256:
        raise AndroidRuntimeError("host-containment-receipt-and-sha256-required")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise AndroidRuntimeError("host-containment-receipt-sha256-invalid")
    raw_path = Path(configured_path).expanduser()
    if not raw_path.is_absolute():
        raise AndroidRuntimeError("host-containment-receipt-path-must-be-absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(raw_path, flags)
    except OSError as exc:
        raise AndroidRuntimeError("host-containment-receipt-unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw_receipt = stream.read(_MAX_CONTAINMENT_RECEIPT_BYTES + 1)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise AndroidRuntimeError("host-containment-receipt-not-regular-file")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_CONTAINMENT_RECEIPT_BYTES:
        raise AndroidRuntimeError("host-containment-receipt-size-invalid")
    # The audit worker can mint current-UID files and matching hashes itself;
    # only the external root/controller authority may attest host containment.
    if metadata.st_uid != 0:
        raise AndroidRuntimeError("host-containment-receipt-owner-invalid")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AndroidRuntimeError("host-containment-receipt-is-group-or-world-writable")
    observed_sha256 = hashlib.sha256(raw_receipt).hexdigest()
    if not secrets.compare_digest(observed_sha256, expected_sha256.lower()):
        raise AndroidRuntimeError("host-containment-receipt-sha256-mismatch")
    try:
        payload = json.loads(raw_receipt.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AndroidRuntimeError("host-containment-receipt-json-invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema") != CONTAINMENT_RECEIPT_SCHEMA:
        raise AndroidRuntimeError("host-containment-receipt-schema-invalid")
    if payload.get("controller") != "angerona-worker-controller":
        raise AndroidRuntimeError("host-containment-receipt-controller-invalid")
    for field_name in ("worker_id", "engagement_id"):
        if not isinstance(payload.get(field_name), str) or not payload[field_name].strip():
            raise AndroidRuntimeError(f"host-containment-receipt-{field_name}-invalid")
    if payload.get("isolated_worker") is not True:
        raise AndroidRuntimeError("host-containment-isolated-worker-unverified")
    if payload.get("imds_denied") is not True:
        raise AndroidRuntimeError("host-containment-imds-denial-unverified")
    egress = payload.get("egress_policy")
    if not isinstance(egress, dict) or egress.get("enforced") is not True:
        raise AndroidRuntimeError("host-containment-egress-policy-unverified")
    if egress.get("scope") not in {"host", "vpc", "host+vpc"}:
        raise AndroidRuntimeError("host-containment-egress-scope-invalid")
    if egress.get("mode") not in {"deny", "allowlist"}:
        raise AndroidRuntimeError("host-containment-egress-mode-invalid")
    if egress.get("mode") == "allowlist":
        destinations = egress.get("destinations")
        broad_destinations = {"*", "0.0.0.0/0", "::/0", "any"}
        if (
            not isinstance(destinations, list)
            or not destinations
            or any(
                not isinstance(item, str)
                or not item.strip()
                or item.strip().lower() in broad_destinations
                for item in destinations
            )
        ):
            raise AndroidRuntimeError("host-containment-egress-allowlist-invalid")
    issued_at = payload.get("issued_at_unix")
    expires_at = payload.get("expires_at_unix")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise AndroidRuntimeError("host-containment-receipt-validity-invalid")
    current = int(time.time()) if now is None else int(now)
    if issued_at > current + 300 or expires_at <= current:
        raise AndroidRuntimeError("host-containment-receipt-not-current")
    if expires_at <= issued_at or expires_at - issued_at > _MAX_CONTAINMENT_RECEIPT_LIFETIME_S:
        raise AndroidRuntimeError("host-containment-receipt-lifetime-invalid")
    receipt_apk_sha256 = str(payload.get("apk_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_apk_sha256):
        raise AndroidRuntimeError("host-containment-receipt-apk-sha256-invalid")
    if apk_sha256 and not secrets.compare_digest(receipt_apk_sha256, apk_sha256):
        raise AndroidRuntimeError("host-containment-receipt-apk-mismatch")
    return {
        "schema": CONTAINMENT_RECEIPT_SCHEMA,
        "receipt_path": str(raw_path),
        "receipt_sha256": observed_sha256,
        "controller": payload["controller"],
        "worker_id": payload["worker_id"],
        "engagement_id": payload["engagement_id"],
        "apk_sha256": receipt_apk_sha256,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "isolated_worker": True,
        "imds_denied": True,
        "egress_policy": dict(egress),
        "apk_binding_checked": apk_sha256 is not None,
        "verified": True,
    }


def profile_apk(apk_path: str | Path) -> ApkRuntimeRequirements:
    """Derive the immutable size/hash and packaged native ABI requirements."""
    apk = Path(apk_path).expanduser().resolve()
    if not apk.is_file():
        raise AndroidRuntimeError("apk-not-found")
    abis: set[str] = set()
    uncompressed_bytes = 0
    min_sdk: int | None = None
    target_sdk: int | None = None
    try:
        with zipfile.ZipFile(apk) as archive:
            for member in archive.infolist():
                name = member.filename
                uncompressed_bytes += max(0, int(member.file_size))
                match = re.fullmatch(r"lib/([^/]+)/[^/]+\.so", name)
                if match:
                    abis.add(match.group(1))
            # Plain XML is common in test fixtures. Binary AXML is deliberately
            # not guessed; a missing value never becomes a compatibility fact.
            raw_manifest = archive.read("AndroidManifest.xml")
            if raw_manifest.lstrip().startswith(b"<"):
                manifest = raw_manifest.decode("utf-8", "replace")
                for attr, destination in (
                    ("minSdkVersion", "min"), ("targetSdkVersion", "target")
                ):
                    match = re.search(rf"{attr}\s*=\s*[\"'](\d+)[\"']", manifest)
                    if match and destination == "min":
                        min_sdk = int(match.group(1))
                    elif match:
                        target_sdk = int(match.group(1))
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise AndroidRuntimeError(f"apk-profile-failed:{type(exc).__name__}") from exc
    return ApkRuntimeRequirements(
        apk_sha256=_sha256(apk),
        apk_bytes=apk.stat().st_size,
        apk_uncompressed_bytes=uncompressed_bytes,
        native_abis=tuple(sorted(abis)),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
    )


def _candidate_sdk_roots(explicit: str = "") -> list[Path]:
    candidates: list[Path] = []
    for value in (
        explicit,
        os.environ.get("ANGERONA_ANDROID_SDK_ROOT", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
        os.environ.get("ANDROID_HOME", ""),
        str(Path.home() / "Android" / "Sdk"),
        "/opt/android-sdk",
        "/usr/lib/android-sdk",
    ):
        if value:
            path = Path(value).expanduser().resolve()
            if path not in candidates:
                candidates.append(path)
    return candidates


def _latest_cmdline_tool(root: Path, tool: str) -> Path | None:
    direct = root / "cmdline-tools" / "latest" / "bin" / tool
    if direct.is_file():
        return direct
    matches = sorted((root / "cmdline-tools").glob(f"*/bin/{tool}"))
    return matches[-1] if matches else None


def discover_android_toolchain(sdk_root: str = "") -> AndroidSdkToolchain:
    """Find one coherent SDK root; mixed global tools are rejected."""
    errors: list[str] = []
    # An explicit root is an immutable reproducibility boundary.  Falling back
    # to a different SDK when it is incomplete would make doctor and execution
    # inspect different emulator/tool revisions.
    roots = (
        [Path(sdk_root).expanduser().resolve()]
        if sdk_root else _candidate_sdk_roots()
    )
    for root in roots:
        adb = root / "platform-tools" / "adb"
        emulator = root / "emulator" / "emulator"
        avdmanager = _latest_cmdline_tool(root, "avdmanager")
        sdkmanager = _latest_cmdline_tool(root, "sdkmanager")
        missing = [
            name for name, path in (
                ("adb", adb), ("emulator", emulator),
                ("avdmanager", avdmanager), ("sdkmanager", sdkmanager),
            ) if path is None or not path.is_file()
        ]
        if not missing:
            return AndroidSdkToolchain(
                sdk_root=str(root), adb=str(adb), emulator=str(emulator),
                avdmanager=str(avdmanager), sdkmanager=str(sdkmanager),
            )
        errors.append(f"{root}:{','.join(missing)}")
    raise AndroidRuntimeError(
        "android-sdk-toolchain-incomplete:" + (";".join(errors) or "no-sdk-root")
    )


def _choose_abi(requirements: ApkRuntimeRequirements, policy: AndroidRuntimePolicy) -> str:
    if policy.abi != "auto":
        chosen = policy.abi
    else:
        host = platform.machine().lower()
        host_abi = "arm64-v8a" if host in {"aarch64", "arm64"} else "x86_64"
        if not requirements.native_abis or host_abi in requirements.native_abis:
            chosen = host_abi
        elif requirements.native_abis == ("armeabi-v7a",) and host_abi == "arm64-v8a":
            chosen = "arm64-v8a"
        else:
            chosen = requirements.native_abis[0]
    host = platform.machine().lower()
    accelerated = (
        (chosen == "x86_64" and host in {"x86_64", "amd64"})
        or (chosen == "arm64-v8a" and host in {"aarch64", "arm64"})
    )
    if not accelerated and not policy.allow_native_translation:
        raise AndroidRuntimeError(
            f"native-runner-required:apk-abis={requirements.native_abis or ('dex-only',)}:"
            f"selected={chosen}:host={host}"
        )
    return chosen


def _host_android_abi() -> str:
    return "arm64-v8a" if platform.machine().lower() in {"aarch64", "arm64"} else "x86_64"


def _free_tcp_port() -> int:
    # Keep the socket open only during selection; Angerona serializes AVD
    # creation in one process and validates the exact serial after launch.
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        return port
    raise AndroidRuntimeError("unable-to-allocate-local-port")


def _select_emulator_console_port(lock_path: Path) -> tuple[int, Any]:
    """Select an official even console port while holding an interprocess lock."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    try:
        if platform.system() != "Windows":
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        for port in range(5554, 5683, 2):
            sockets: list[socket.socket] = []
            try:
                for candidate in (port, port + 1):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                    sock.bind(("127.0.0.1", candidate))
                    sockets.append(sock)
                return port, handle
            except OSError:
                continue
            finally:
                for sock in sockets:
                    sock.close()
    except Exception:
        handle.close()
        raise
    handle.close()
    raise AndroidRuntimeError("no-free-emulator-console-port-in-5554-5682")


def _ports_unbound(ports: list[int]) -> bool:
    """Return true when no runtime control endpoint is actively listening.

    A post-shutdown TCP TIME_WAIT entry may temporarily prevent rebinding even
    though no process owns a listener.  Cleanup attests the latter, so probe
    listeners directly on both loopback families.
    """
    for port in ports:
        for family, address in (
            (socket.AF_INET, ("127.0.0.1", port)),
            (socket.AF_INET6, ("::1", port)),
        ):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.25)
                    if probe.connect_ex(address) == 0:
                        return False
            except OSError:
                continue
    return True


def _run(
    command: list[str], *, env: dict[str, str] | None = None,
    timeout: int = 120, input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return observed_run(
            command, env=env, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AndroidRuntimeError(
            f"command-failed:{Path(command[0]).name}:{type(exc).__name__}"
        ) from exc


def _adb_command(toolchain: AndroidSdkToolchain, server_port: int, *args: str) -> list[str]:
    return [toolchain.adb, "-P", str(server_port), *args]


def _adb_env(server_port: int) -> dict[str, str]:
    env = os.environ.copy()
    env["ANDROID_ADB_SERVER_PORT"] = str(server_port)
    return env


def _ensure_image(
    toolchain: AndroidSdkToolchain, image: str, *, auto_provision: bool,
) -> None:
    image_dir = Path(toolchain.sdk_root).joinpath(*image.split(";"))
    if (image_dir / "package.xml").is_file() or (image_dir / "system.img").is_file():
        return
    if not auto_provision:
        raise AndroidRuntimeError(f"system-image-not-installed:{image}")
    # Licenses are never auto-accepted here. sdkmanager fails if the operator
    # has not accepted them through the official interactive workflow.
    result = _run(
        [toolchain.sdkmanager, f"--sdk_root={toolchain.sdk_root}", image],
        timeout=1800,
    )
    if result.returncode != 0:
        raise AndroidRuntimeError(
            f"system-image-provision-failed:{result.stdout[-500:]}{result.stderr[-500:]}"
        )


def _system_image_identity(toolchain: AndroidSdkToolchain, image: str) -> dict[str, Any]:
    root = Path(toolchain.sdk_root).joinpath(*image.split(";"))
    files: dict[str, dict[str, Any]] = {}
    for name in ("package.xml", "source.properties", "system.img", "ramdisk.img", "kernel-ranchu"):
        path = root / name
        if path.is_file():
            files[name] = {"bytes": path.stat().st_size, "sha256": _sha256(path)}
    if not files or "system.img" not in files:
        raise AndroidRuntimeError(f"system-image-identity-incomplete:{image}")
    return {"package": image, "root": str(root), "files": files}


def _frida_version() -> tuple[str, str]:
    cli = shutil.which("frida")
    if not cli:
        root_cli = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "frida"
        cli = str(root_cli) if root_cli.is_file() else ""
    if not cli:
        raise AndroidRuntimeError("frida-client-not-found")
    result = _run([cli, "--version"], timeout=30)
    version = result.stdout.strip().splitlines()[0] if result.returncode == 0 else ""
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-.][A-Za-z0-9]+)?", version):
        raise AndroidRuntimeError("frida-client-version-unavailable")
    return cli, version


def _frida_authenticated_smoke(endpoint: str, token: str) -> tuple[bool, str]:
    """Use Frida's Python transport so the bearer token never enters argv."""
    manager = None
    added = False
    try:
        import frida

        manager = frida.get_device_manager()
        device = manager.add_remote_device(endpoint, token=token)
        added = True
        processes = device.enumerate_processes()
        return bool(processes), f"enumerated-processes={len(processes)}"
    except Exception as exc:  # Frida exposes several transport exception types.
        return False, f"{type(exc).__name__}:{str(exc)[:300]}"
    finally:
        if manager is not None and added:
            try:
                manager.remove_remote_device(endpoint)
            except Exception:
                pass


def _frida_server_asset_abi(abi: str) -> str:
    mapping = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}
    if abi not in mapping:
        raise AndroidRuntimeError(f"unsupported-frida-abi:{abi}")
    return mapping[abi]


def _ensure_frida_server(
    version: str, abi: str, cache_dir: Path, *, auto_provision: bool,
) -> tuple[Path, str]:
    override = os.environ.get("ANGERONA_FRIDA_SERVER_PATH", "")
    if override:
        path = Path(override).expanduser().resolve()
        if not path.is_file():
            raise AndroidRuntimeError("configured-frida-server-not-found")
        return path, _sha256(path)
    asset_abi = _frida_server_asset_abi(abi)
    destination = cache_dir / f"frida-server-{version}-android-{asset_abi}"
    if destination.is_file():
        return destination, _sha256(destination)
    if not auto_provision:
        raise AndroidRuntimeError(
            f"frida-server-not-cached:{destination}; set ANGERONA_FRIDA_SERVER_PATH "
            "or enable runtime auto-provision"
        )
    cache_dir.mkdir(parents=True, exist_ok=True)
    asset_name = destination.name + ".xz"
    api_url = f"https://api.github.com/repos/frida/frida/releases/tags/{version}"
    with urllib.request.urlopen(api_url, timeout=30) as response:
        release = json.load(response)
    assets = [item for item in release.get("assets", []) if item.get("name") == asset_name]
    if len(assets) != 1:
        raise AndroidRuntimeError(f"frida-server-asset-not-found:{asset_name}")
    asset = assets[0]
    expected_digest = str(asset.get("digest") or "")
    if not expected_digest.startswith("sha256:"):
        raise AndroidRuntimeError("frida-release-missing-sha256-digest")
    with tempfile.NamedTemporaryFile(dir=cache_dir, suffix=".xz", delete=False) as temp:
        compressed = Path(temp.name)
        with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as response:
            shutil.copyfileobj(response, temp)
    try:
        if _sha256(compressed) != expected_digest.removeprefix("sha256:"):
            raise AndroidRuntimeError("frida-server-download-digest-mismatch")
        raw = lzma.decompress(compressed.read_bytes())
        staged = destination.with_suffix(".new")
        staged.write_bytes(raw)
        staged.chmod(0o700)
        os.replace(staged, destination)
    finally:
        compressed.unlink(missing_ok=True)
    return destination, _sha256(destination)


def managed_runtime_readiness(policy: AndroidRuntimePolicy | None = None) -> dict[str, Any]:
    """Read-only readiness report used by doctor and CI preflight."""
    policy = policy or AndroidRuntimePolicy()
    report: dict[str, Any] = {"ready": False, "blockers": [], "policy": asdict(policy)}
    try:
        report["host_containment"] = verify_host_containment_receipt(policy)
    except AndroidRuntimeError as exc:
        report["blockers"].append(str(exc))
    tools: AndroidSdkToolchain | None = None
    try:
        tools = discover_android_toolchain(policy.sdk_root)
        report["toolchain"] = tools.as_dict()
    except AndroidRuntimeError as exc:
        report["blockers"].append(str(exc))
    if platform.system() == "Linux":
        kvm = Path("/dev/kvm")
        if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
            report["blockers"].append("kvm-unavailable-or-not-accessible")
        if policy.network_policy == "deny":
            if not shutil.which("systemd-run") or not shutil.which("systemctl"):
                report["blockers"].append("host-emulator-containment-unavailable")
            else:
                probe = subprocess.run(
                    ["systemctl", "--user", "show-environment"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=15, check=False,
                )
                if probe.returncode != 0:
                    report["blockers"].append("host-emulator-containment-unavailable")
    storage_probe = Path(policy.state_root).expanduser() if policy.state_root else Path.home()
    free_bytes = shutil.disk_usage(storage_probe).free
    required_bytes = (policy.data_partition_mb + 1024) * 1024 * 1024
    report["host_storage"] = {
        "path": str(storage_probe), "free_bytes": free_bytes,
        "required_bytes": required_bytes,
    }
    if free_bytes < required_bytes:
        report["blockers"].append(
            f"host-storage-insufficient:required={required_bytes}:free={free_bytes}"
        )
    if tools is not None:
        doctor_abi = (
            policy.abi if policy.abi != "auto" else _host_android_abi()
        )
        image = f"system-images;android-{policy.api};{policy.image_tag};{doctor_abi}"
        image_dir = Path(tools.sdk_root).joinpath(*image.split(";"))
        if not image_dir.exists():
            report["blockers"].append(f"system-image-not-installed:{image}")
    try:
        _cli, version = _frida_version()
        report["frida_client_version"] = version
        if tools is not None:
            state_root = Path(
                policy.state_root
                or os.environ.get("ANGERONA_ANDROID_RUNTIME_STATE", "")
                or (Path.home() / ".cache" / "angerona" / "android-runtime")
            ).expanduser().resolve()
            doctor_abi = policy.abi if policy.abi != "auto" else _host_android_abi()
            path, digest = _ensure_frida_server(
                version, doctor_abi, state_root / "frida", auto_provision=False
            )
            report["frida_server"] = {"path": str(path), "sha256": digest}
    except AndroidRuntimeError as exc:
        report["blockers"].append(str(exc))
    report["ready"] = not report["blockers"]
    return report


class AndroidRuntimeManager(AbstractContextManager[ManagedAndroidTarget]):
    """Provision and own one official headless AOSP AVD for one audit."""

    def __init__(self, apk_path: str | Path, policy: AndroidRuntimePolicy | None = None):
        self.apk_path = Path(apk_path).expanduser().resolve()
        self.policy = policy or AndroidRuntimePolicy()
        self.target: ManagedAndroidTarget | None = None
        self._process: subprocess.Popen[str] | None = None
        self._frida_process: subprocess.Popen[str] | None = None
        self._frida_log_handle: Any = None
        self._log_handle: Any = None
        self._toolchain: AndroidSdkToolchain | None = None
        self._avd_env: dict[str, str] | None = None
        self._console_port_lock: Any = None
        self._containment_scope = ""

    def __enter__(self) -> ManagedAndroidTarget:
        requirements = profile_apk(self.apk_path)
        # This gate intentionally precedes SDK discovery, image provisioning,
        # AVD creation, and installation.  Managed execution is unavailable
        # unless the external worker controller pinned a current receipt to the
        # exact APK bytes being analyzed.
        host_containment = verify_host_containment_receipt(
            self.policy, apk_sha256=requirements.apk_sha256,
        )
        tools = discover_android_toolchain(self.policy.sdk_root)
        self._toolchain = tools
        abi = _choose_abi(requirements, self.policy)
        api = max(self.policy.api, requirements.min_sdk or 1)
        image = f"system-images;android-{api};{self.policy.image_tag};{abi}"
        _ensure_image(tools, image, auto_provision=self.policy.auto_provision)
        image_identity = _system_image_identity(tools, image)
        if (
            platform.system() == "Linux"
            and not self.policy.allow_software_acceleration
            and (not Path("/dev/kvm").exists()
                 or not os.access("/dev/kvm", os.R_OK | os.W_OK))
        ):
            raise AndroidRuntimeError("kvm-unavailable-or-not-accessible")

        state_root = Path(
            self.policy.state_root
            or os.environ.get("ANGERONA_ANDROID_RUNTIME_STATE", "")
            or (Path.home() / ".cache" / "angerona" / "android-runtime")
        ).expanduser().resolve()
        state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_root.chmod(0o700)
        host_free = shutil.disk_usage(state_root).free
        host_required = (
            self.policy.data_partition_mb * 1024 * 1024
            + max(requirements.apk_uncompressed_bytes * 3, requirements.apk_bytes * 4)
            + 1024 * 1024 * 1024
        )
        if host_free < host_required:
            raise AndroidRuntimeError(
                f"host-storage-insufficient:required={host_required}:free={host_free}"
            )
        job_id = f"run-{int(time.time())}-{secrets.token_hex(6)}"
        job_dir = state_root / "jobs" / job_id
        avd_home = job_dir / "avd-home"
        avd_home.mkdir(parents=True, mode=0o700)
        job_dir.chmod(0o700)
        avd_home.chmod(0o700)
        avd_name = self.policy.avd_name or f"angerona_{job_id.replace('-', '_')}"
        avd_dir = avd_home / f"{avd_name}.avd"
        adb_server_port = _free_tcp_port()
        console_port, self._console_port_lock = _select_emulator_console_port(
            state_root / "console-port.lock"
        )
        serial = f"emulator-{console_port}"
        env = os.environ.copy()
        env.pop("ADB_SERVER_SOCKET", None)
        env.pop("ANDROID_ADB_SERVER_ADDRESS", None)
        env.update({
            "ANDROID_SDK_ROOT": tools.sdk_root,
            "ANDROID_AVD_HOME": str(avd_home),
            "ANDROID_EMULATOR_HOME": str(job_dir / "emulator-home"),
            # The emulator uses this legacy variable for its own registration
            # and housekeeping calls.  Do not set ADB_SERVER_SOCKET or
            # ANDROID_ADB_SERVER_ADDRESS here: either makes `adb start-server`
            # treat the endpoint as a remote daemon and refuse to create it.
            "ANDROID_ADB_SERVER_PORT": str(adb_server_port),
        })
        self._avd_env = env
        receipt: dict[str, Any] = {
            "provider": "official-android-emulator",
            "owned": True,
            "job_id": job_id,
            "toolchain": tools.as_dict(),
            "image_package": image,
            "image_identity": image_identity,
            "api": api,
            "abi": abi,
            "host_abi": _host_android_abi(),
            "guest_abi": abi,
            "execution_mode": (
                "host-native-virtualized" if abi == _host_android_abi()
                else "non-native-exploratory"
            ),
            "apk_requirements": asdict(requirements),
            "host_containment": host_containment,
            "native_abis_eligible": [abi] if requirements.native_abis else [],
            "native_abis_exercised": [],
            "native_abis_unexercised": [
                item for item in requirements.native_abis if item != abi
            ],
            # Image compatibility is not execution evidence. Native completion
            # requires runtime-loaded module hashes/build-ids/base/RVA mapped to
            # the static IDA ledger; that producer is not yet present here.
            "native_coverage_complete": not requirements.native_abis,
            "adb_server_port": adb_server_port,
            "serial": serial,
            "avd_name": avd_name,
            "cold_clean_boot": False,
            "host_storage_preflight": {
                "required_bytes": host_required, "free_bytes": host_free,
                "complete": True,
            },
            "frida_ready": False,
            "cleanup": {"attempted": False, "success": False, "steps": []},
        }
        self.target = ManagedAndroidTarget(
            serial=serial, adb_server_port=adb_server_port, avd_name=avd_name,
            image_package=image, api=api, abi=abi, job_dir=str(job_dir), receipt=receipt,
        )
        try:
            created = _run(
                [tools.avdmanager, "create", "avd", "--force", "--name", avd_name,
                 "--package", image, "--path", str(avd_dir), "--device", "pixel_2"],
                env=env, timeout=180, input_text="no\n",
            )
            if created.returncode != 0:
                raise AndroidRuntimeError(
                    f"avd-create-failed:{created.stdout[-500:]}{created.stderr[-500:]}"
                )
            server = _run(
                _adb_command(tools, adb_server_port, "start-server"), env=env, timeout=30
            )
            if server.returncode != 0:
                raise AndroidRuntimeError("private-adb-server-start-failed")
            log_path = job_dir / "emulator.log"
            self._log_handle = log_path.open("w", encoding="utf-8")
            log_path.chmod(0o600)
            emulator_command = [
                tools.emulator, "-avd", avd_name, "-port", str(console_port),
                "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot",
                "-no-snapstorage", "-wipe-data", "-gpu", "swiftshader",
                "-memory", str(self.policy.memory_mb),
                "-partition-size", str(self.policy.data_partition_mb),
                "-no-metrics",
            ]
            command = emulator_command
            if self.policy.network_policy == "deny":
                systemd_run = shutil.which("systemd-run")
                if not systemd_run:
                    raise AndroidRuntimeError("host-emulator-containment-unavailable")
                self._containment_scope = f"angerona-avd-{job_id}.scope"
                command = [
                    systemd_run, "--user", "--scope", "--quiet",
                    "--unit", self._containment_scope,
                    "--property=IPAddressDeny=any",
                    "--property=IPAddressAllow=localhost",
                    f"--property=MemoryMax={max(6144, self.policy.memory_mb * 2)}M",
                    "--property=TasksMax=512",
                    "--", *emulator_command,
                ]
            self._process = subprocess.Popen(
                command, env=env, stdout=self._log_handle, stderr=subprocess.STDOUT,
                text=True, start_new_session=True,
            )
            receipt["emulator_pid"] = self._process.pid
            receipt["emulator_command"] = command
            receipt["emulator_inner_command"] = emulator_command
            if self._containment_scope:
                containment_deadline = time.monotonic() + 20
                containment_show = subprocess.CompletedProcess([], -1, "", "")
                while time.monotonic() < containment_deadline:
                    containment_show = _run(
                        [
                            "systemctl", "--user", "show", self._containment_scope,
                            "--property=ActiveState", "--property=ControlGroup",
                            "--property=IPAddressDeny", "--property=IPAddressAllow",
                            "--property=MemoryMax", "--property=TasksMax",
                        ], env=env, timeout=15,
                    )
                    properties = containment_show.stdout
                    if (
                        containment_show.returncode == 0
                        and "ActiveState=active" in properties
                        and "IPAddressDeny=0.0.0.0/0 ::/0" in properties
                        and "IPAddressAllow=::1/128 127.0.0.0/8" in properties
                        and "ControlGroup=" in properties
                    ):
                        break
                    if self._process.poll() is not None:
                        break
                    time.sleep(0.5)
                else:
                    properties = containment_show.stdout
                if not (
                    containment_show.returncode == 0
                    and "ActiveState=active" in properties
                    and "IPAddressDeny=0.0.0.0/0 ::/0" in properties
                    and "IPAddressAllow=::1/128 127.0.0.0/8" in properties
                ):
                    raise AndroidRuntimeError("host-emulator-containment-unverified")
                try:
                    process_cgroup = Path(
                        f"/proc/{self._process.pid}/cgroup"
                    ).read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    raise AndroidRuntimeError(
                        "host-emulator-containment-membership-unreadable"
                    ) from exc
                control_group = next(
                    (
                        line.partition("=")[2].strip()
                        for line in properties.splitlines()
                        if line.startswith("ControlGroup=")
                    ),
                    "",
                )
                if not control_group or control_group not in process_cgroup:
                    raise AndroidRuntimeError(
                        "host-emulator-containment-membership-unverified"
                    )
                receipt["host_emulator_scope"] = {
                    "unit": self._containment_scope,
                    "verified": True,
                    "properties": properties.strip().splitlines(),
                    "process_cgroup": process_cgroup.strip().splitlines(),
                }
            deadline = time.monotonic() + self.policy.boot_timeout
            boot_values: dict[str, str] = {}
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise AndroidRuntimeError(
                        f"emulator-exited-before-boot:rc={self._process.returncode}"
                    )
                devices = _run(
                    _adb_command(tools, adb_server_port, "devices"), env=env, timeout=15
                ).stdout
                if f"{serial}\tdevice" not in devices:
                    time.sleep(1)
                    continue
                if self._console_port_lock is not None:
                    self._console_port_lock.close()
                    self._console_port_lock = None
                for prop in ("sys.boot_completed", "dev.bootcomplete", "init.svc.bootanim"):
                    result = _run(
                        _adb_command(tools, adb_server_port, "-s", serial, "shell", "getprop", prop),
                        env=env, timeout=15,
                    )
                    boot_values[prop] = result.stdout.strip()
                package_manager = _run(
                    _adb_command(tools, adb_server_port, "-s", serial, "shell", "pm", "path", "android"),
                    env=env, timeout=20,
                )
                if (
                    boot_values.get("sys.boot_completed") == "1"
                    and boot_values.get("dev.bootcomplete") in {"", "1"}
                    and boot_values.get("init.svc.bootanim") in {"", "stopped"}
                    and package_manager.returncode == 0
                    and "package:" in package_manager.stdout
                ):
                    break
                time.sleep(2)
            else:
                raise AndroidRuntimeError(f"emulator-boot-timeout:{boot_values}")
            receipt["cold_clean_boot"] = True
            receipt["boot_properties"] = boot_values

            rooted = _run(
                _adb_command(tools, adb_server_port, "-s", serial, "root"),
                env=env, timeout=45,
            )
            root_output = (rooted.stdout + rooted.stderr).strip()
            receipt["adb_root_output"] = root_output[-1000:]
            if "cannot run as root" in root_output.lower():
                raise AndroidRuntimeError("aosp-image-adb-root-failed:release-image")
            # `adb root` deliberately restarts adbd.  Depending on timing, adb
            # may return a transport-disconnect rc even though the restart is
            # succeeding.  The authoritative gate is a reconnected transport
            # whose effective uid is 0, not that transient client exit code.
            uid = subprocess.CompletedProcess([], -1, "", "")
            root_deadline = time.monotonic() + 45
            while time.monotonic() < root_deadline:
                time.sleep(1)
                uid = _run(
                    _adb_command(
                        tools, adb_server_port, "-s", serial,
                        "shell", "id", "-u",
                    ), env=env, timeout=15,
                )
                if uid.returncode == 0 and uid.stdout.strip() == "0":
                    break
            if uid.returncode != 0 or uid.stdout.strip() != "0":
                raise AndroidRuntimeError(
                    f"managed-target-is-not-root:adb-root-rc={rooted.returncode}:"
                    f"output={root_output[-300:]}"
                )
            receipt["root_verified"] = True

            if self.policy.network_policy not in {"deny", "allow"}:
                raise AndroidRuntimeError(
                    f"unsupported-runtime-network-policy:{self.policy.network_policy}"
                )
            network_commands: list[list[str]] = []
            if self.policy.network_policy == "deny":
                network_commands = [
                    ["shell", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                    ["shell", "ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                    ["shell", "iptables", "-P", "OUTPUT", "DROP"],
                    ["shell", "ip6tables", "-P", "OUTPUT", "DROP"],
                ]
                for args in network_commands:
                    result = _run(
                        _adb_command(tools, adb_server_port, "-s", serial, *args),
                        env=env, timeout=30,
                    )
                    if result.returncode != 0:
                        raise AndroidRuntimeError("guest-egress-deny-policy-failed")
                for firewall in ("iptables", "ip6tables"):
                    verify = _run(
                        _adb_command(
                            tools, adb_server_port, "-s", serial, "shell",
                            firewall, "-S", "OUTPUT",
                        ), env=env, timeout=30,
                    )
                    if (
                        verify.returncode != 0
                        or "-P OUTPUT DROP" not in verify.stdout
                        or "-A OUTPUT -o lo -j ACCEPT" not in verify.stdout
                    ):
                        raise AndroidRuntimeError(
                            f"guest-egress-deny-policy-unverified:{firewall}"
                        )
            receipt["network_policy"] = {
                "mode": self.policy.network_policy,
                "guest_egress_denied": self.policy.network_policy == "deny",
                "verified_in_guest": True,
                "host_containment_verified": bool(
                    host_containment.get("verified") is True
                    and host_containment.get("apk_binding_checked") is True
                ),
                "host_containment_receipt_sha256": host_containment["receipt_sha256"],
                "host_or_vpc_egress_policy": dict(host_containment["egress_policy"]),
                "limitation": "coverage is limited to the controller-attested worker boundary",
            }

            frida_cli, frida_version = _frida_version()
            server_path, server_sha = _ensure_frida_server(
                frida_version, abi, state_root / "frida", auto_provision=self.policy.auto_provision
            )
            remote = f"/data/local/tmp/.angerona-{secrets.token_hex(8)}"
            for args, reason in (
                (("push", str(server_path), remote), "frida-server-push-failed"),
                (("shell", "chmod", "0700", remote), "frida-server-chmod-failed"),
            ):
                result = _run(
                    _adb_command(tools, adb_server_port, "-s", serial, *args), env=env, timeout=120
                )
                if result.returncode != 0:
                    raise AndroidRuntimeError(reason)
            remote_version = _run(
                _adb_command(tools, adb_server_port, "-s", serial, "shell", remote, "--version"),
                env=env, timeout=30,
            )
            if remote_version.returncode != 0 or remote_version.stdout.strip() != frida_version:
                raise AndroidRuntimeError("frida-client-server-version-mismatch")
            server_help = _run(
                _adb_command(
                    tools, adb_server_port, "-s", serial, "shell", remote, "--help"
                ), env=env, timeout=30,
            )
            client_help = _run([frida_cli, "--help"], env=env, timeout=30)
            server_help_text = server_help.stdout + server_help.stderr
            client_help_text = client_help.stdout + client_help.stderr
            if server_help.returncode != 0 or "--listen" not in server_help_text:
                raise AndroidRuntimeError("frida-loopback-listen-support-unproven")
            token_supported = bool(
                client_help.returncode == 0
                and "--token" in client_help_text
                and "--token" in server_help_text
            )
            guest_frida_port = 20000 + secrets.randbelow(40000)
            frida_token = secrets.token_urlsafe(32) if token_supported else ""
            server_options = [f"--listen=127.0.0.1:{guest_frida_port}"]
            remote_token_path = ""
            remote_launcher = f"{remote}.launch.sh"
            remote_log = f"{remote}.server.log"
            receipt.update({
                "frida_remote_path": remote,
                "frida_token_remote_path": remote_token_path,
                "frida_launcher_remote_path": remote_launcher,
                "frida_server_log_remote_path": remote_log,
            })
            if frida_token:
                remote_token_path = f"{remote}.token"
                receipt["frida_token_remote_path"] = remote_token_path
                local_token_path = job_dir / f"frida-token-{secrets.token_hex(6)}"
                local_token_path.write_text(frida_token, encoding="utf-8")
                local_token_path.chmod(0o600)
                try:
                    for args, reason in (
                        (("push", str(local_token_path), remote_token_path),
                         "frida-token-push-failed"),
                        (("shell", "chmod", "0600", remote_token_path),
                         "frida-token-chmod-failed"),
                    ):
                        result = _run(
                            _adb_command(tools, adb_server_port, "-s", serial, *args),
                            env=env, timeout=30,
                        )
                        if result.returncode != 0:
                            raise AndroidRuntimeError(reason)
                finally:
                    local_token_path.unlink(missing_ok=True)
            else:
                raise AndroidRuntimeError("frida-authentication-token-unavailable")
            # Avoid adb-shell's multi-layer quoting ambiguity. The fixed,
            # controller-authored launcher consumes the 0600 token file inside
            # the guest and only receives non-secret paths/options in host argv.
            local_launcher = job_dir / f"frida-launch-{secrets.token_hex(6)}.sh"
            local_launcher.write_text(
                "#!/system/bin/sh\n"
                "token_path=\"$1\"\nserver_path=\"$2\"\nlisten=\"$3\"\nlog_path=\"$4\"\n"
                "token=$(cat \"$token_path\") || exit 10\n"
                "rm -f \"$token_path\"\n"
                "exec \"$server_path\" \"--listen=$listen\" \"--token=$token\" "
                ">>\"$log_path\" 2>&1\n",
                encoding="utf-8",
            )
            local_launcher.chmod(0o700)
            try:
                for args, reason in (
                    (("push", str(local_launcher), remote_launcher),
                     "frida-launcher-push-failed"),
                    (("shell", "chmod", "0700", remote_launcher),
                     "frida-launcher-chmod-failed"),
                ):
                    result = _run(
                        _adb_command(tools, adb_server_port, "-s", serial, *args),
                        env=env, timeout=30,
                    )
                    if result.returncode != 0:
                        raise AndroidRuntimeError(reason)
            finally:
                local_launcher.unlink(missing_ok=True)
            frida_host_log = job_dir / "frida-server-transport.log"
            self._frida_log_handle = frida_host_log.open("w", encoding="utf-8")
            frida_host_log.chmod(0o600)
            self._frida_process = subprocess.Popen(
                _adb_command(
                    tools, adb_server_port, "-s", serial, "shell", "sh",
                    remote_launcher, remote_token_path, remote,
                    f"127.0.0.1:{guest_frida_port}", remote_log,
                ),
                env=env,
                stdout=self._frida_log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            time.sleep(2)
            if self._frida_process.poll() is not None:
                self._frida_log_handle.flush()
                diagnostic = frida_host_log.read_text(errors="replace")[-1000:]
                raise AndroidRuntimeError(
                    f"frida-server-start-failed:{diagnostic}"
                )
            receipt["frida_host_transport_log"] = str(frida_host_log)
            forwarded = _run(
                _adb_command(
                    tools, adb_server_port, "-s", serial,
                    "forward", "tcp:0", f"tcp:{guest_frida_port}",
                ), env=env, timeout=30,
            )
            forwarded_port = forwarded.stdout.strip()
            if (
                forwarded.returncode != 0
                or not forwarded_port.isdigit()
                or not 1 <= int(forwarded_port) <= 65535
            ):
                raise AndroidRuntimeError("frida-private-forward-failed")
            frida_endpoint = f"127.0.0.1:{forwarded_port}"
            if not frida_token:
                raise AndroidRuntimeError("frida-authentication-token-unavailable")
            smoke_ok = False
            smoke_detail = "not-attempted"
            smoke_deadline = time.monotonic() + 30
            while time.monotonic() < smoke_deadline:
                smoke_ok, smoke_detail = _frida_authenticated_smoke(
                    frida_endpoint, frida_token
                )
                if smoke_ok:
                    break
                time.sleep(1)
            if not smoke_ok:
                server_diagnostics = _run(
                    _adb_command(
                        tools, adb_server_port, "-s", serial, "shell", "sh", "-c",
                        f"ps -A | grep {Path(remote).name}; tail -c 1000 {remote_log}",
                    ), env=env, timeout=30,
                )
                diagnostic = re.sub(
                    re.escape(frida_token), "[REDACTED]",
                    (server_diagnostics.stdout + server_diagnostics.stderr)[-1200:],
                )
                raise AndroidRuntimeError(
                    f"frida-handshake-failed:{smoke_detail}:guest={diagnostic}"
                )
            receipt.update({
                "frida_ready": True,
                "frida_client_version": frida_version,
                "frida_server_sha256": server_sha,
                "frida_remote_path": remote,
                "frida_token_remote_path": remote_token_path,
                "frida_launcher_remote_path": remote_launcher,
                "frida_server_log_remote_path": remote_log,
                "frida_forwarded_port": int(forwarded_port),
                "frida_host_endpoint": frida_endpoint,
                "frida_handshake": "frida-python-api-enumerate-processes-success",
                "frida_handshake_detail": smoke_detail,
                "frida_transport": {
                    "guest_bind": "127.0.0.1",
                    "guest_port": guest_frida_port,
                    "host_endpoint": frida_endpoint,
                    "authenticated": bool(frida_token),
                    "token_support_proven": token_supported,
                    "complete": bool(frida_token),
                    "limitation": (
                        "" if frida_token else
                        "installed Frida token support was not proven; runtime completion refused"
                    ),
                },
            })
            self.target.frida_token = frida_token
            return self.target
        except BaseException:
            # KeyboardInterrupt/SystemExit must not strand an emulator, AVD
            # directory, Frida server, or private adb daemon.
            self._teardown()
            raise

    def _teardown(self) -> None:
        target = self.target
        tools = self._toolchain
        if target is None:
            return
        if self._console_port_lock is not None:
            self._console_port_lock.close()
            self._console_port_lock = None
        cleanup = target.receipt.setdefault(
            "cleanup", {"attempted": True, "success": True, "steps": []}
        )
        cleanup["attempted"] = True
        cleanup["success"] = True
        env = self._avd_env or os.environ.copy()

        def step(action: str, success: bool, output: str = "") -> None:
            cleanup["steps"].append({
                "action": action, "success": success, "output": output[-1000:],
            })
            cleanup["success"] = bool(cleanup["success"] and success)

        def cleanup_run(command: list[str], *, timeout: int = 30):
            try:
                return _run(command, env=env, timeout=timeout)
            except AndroidRuntimeError as exc:
                return subprocess.CompletedProcess(command, -1, "", str(exc))

        if tools:
            remote = str(target.receipt.get("frida_remote_path") or "")
            remote_token = str(target.receipt.get("frida_token_remote_path") or "")
            remote_launcher = str(
                target.receipt.get("frida_launcher_remote_path") or ""
            )
            remote_log = str(
                target.receipt.get("frida_server_log_remote_path") or ""
            )
            forwarded_port = int(target.receipt.get("frida_forwarded_port") or 0)
            if forwarded_port:
                result = cleanup_run(
                    _adb_command(
                        tools, target.adb_server_port, "-s", target.serial,
                        "forward", "--remove", f"tcp:{forwarded_port}",
                    ), timeout=30,
                )
                step(
                    "remove-frida-forward", result.returncode == 0,
                    result.stdout + result.stderr,
                )
            if remote:
                result = cleanup_run(
                    _adb_command(
                        tools, target.adb_server_port, "-s", target.serial, "shell",
                        "sh", "-c",
                        f"pkill -f {remote} >/dev/null 2>&1; "
                        f"rm -f {remote} {remote_token} {remote_launcher} {remote_log}",
                    ), timeout=30,
                )
                step("stop-and-remove-frida-server", result.returncode == 0, result.stdout + result.stderr)
            if self._frida_process is not None:
                try:
                    self._frida_process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self._frida_process.pid, signal.SIGTERM)
                        self._frida_process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        try:
                            os.killpg(self._frida_process.pid, signal.SIGKILL)
                        except OSError:
                            pass
                step(
                    "frida-adb-transport-gone",
                    self._frida_process.poll() is not None,
                )
            result = cleanup_run(
                _adb_command(tools, target.adb_server_port, "-s", target.serial, "emu", "kill"),
                timeout=30,
            )
            step("request-emulator-stop", result.returncode == 0, result.stdout + result.stderr)
        if self._process is not None:
            try:
                self._process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self._process.pid, signal.SIGTERM)
                    self._process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(self._process.pid, signal.SIGKILL)
                    except OSError:
                        pass
            step("emulator-process-gone", self._process.poll() is not None)
        if self._containment_scope:
            result = cleanup_run(
                ["systemctl", "--user", "stop", self._containment_scope], timeout=30
            )
            inactive = cleanup_run(
                [
                    "systemctl", "--user", "show", self._containment_scope,
                    "--property=ActiveState",
                ], timeout=30,
            )
            step(
                "host-emulator-containment-scope-gone",
                result.returncode == 0
                and "ActiveState=active" not in inactive.stdout,
                result.stdout + result.stderr + inactive.stdout + inactive.stderr,
            )
        if tools:
            result = cleanup_run(
                _adb_command(tools, target.adb_server_port, "kill-server"), timeout=30
            )
            step("private-adb-server-stop", result.returncode == 0, result.stdout + result.stderr)
        console_port = int(target.serial.removeprefix("emulator-") or 0)
        runtime_ports = [
            target.adb_server_port, console_port, console_port + 1,
        ]
        ports_clear = False
        ports_deadline = time.monotonic() + 10
        while time.monotonic() < ports_deadline:
            ports_clear = _ports_unbound(runtime_ports)
            if ports_clear:
                break
            time.sleep(0.25)
        step("runtime-control-ports-unbound", ports_clear)
        job_dir = Path(target.job_dir).resolve()
        state_root = Path(
            self.policy.state_root
            or os.environ.get("ANGERONA_ANDROID_RUNTIME_STATE", "")
            or (Path.home() / ".cache" / "angerona" / "android-runtime")
        ).expanduser().resolve()
        safe = job_dir != state_root and state_root in job_dir.parents and job_dir.name.startswith("run-")
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
        if self._frida_log_handle is not None:
            self._frida_log_handle.close()
            self._frida_log_handle = None
        if safe:
            try:
                shutil.rmtree(job_dir)
                step("delete-disposable-avd", not job_dir.exists())
            except OSError as exc:
                step("delete-disposable-avd", False, str(exc))
        else:
            step("delete-disposable-avd", False, "unsafe-job-directory-refused")

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self._teardown()
        return False
