"""Fail-closed network boundary for untrusted K-candidate providers.

The provider and every subprocess run in a private network namespace.  A small
HTTP proxy inside that namespace can reach only a bounded pool of inherited
socketpairs.  Their host ends enforce an exact endpoint allowlist, resolve DNS
outside the sandbox, reject unsafe address classes, and verify TLS SNI before
relaying bytes.  The provider never receives a host-network file descriptor.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import re
import select
import selectors
import socket
import stat
import struct
import threading
from dataclasses import dataclass
from types import TracebackType
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit


NETWORK_POLICY_VERSION = 2
NETWORK_POLICY_EXIT = 74
NETWORK_PROXY_PORT = 39081
NETWORK_MAX_CONNECTIONS = 64
NETWORK_MAX_CONCURRENT = 16
NETWORK_MAX_TOTAL_BYTES = 256 * 1024 * 1024
NETWORK_CONNECT_TIMEOUT_SECONDS = 10.0
NETWORK_IO_TIMEOUT_SECONDS = 30.0
NETWORK_HEADER_MAX_BYTES = 16 * 1024
NETWORK_TLS_HELLO_MAX_BYTES = 64 * 1024
NETWORK_SETTINGS_MAX_BYTES = 1024 * 1024
NETWORK_GATEWAY_ENV = "ANGERONA_CANDIDATE_PROVIDER_BASE_URL"
_FRAME_MAGIC = b"ANGERONA_NET_V1\x00"
_STATUS_OK = b"\x00"
_STATUS_DENIED = b"\x01"
_STATUS_UPSTREAM_ERROR = b"\x02"
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

_DEFAULT_ENDPOINTS: dict[str, tuple[str, ...]] = {
    "claude": (
        "https://api.anthropic.com",
        "https://claude.ai",
        "https://mcp-proxy.anthropic.com",
    ),
    "codex": (
        "https://api.openai.com",
        "https://auth.openai.com",
        "https://chatgpt.com",
        "https://ab.chatgpt.com",
        "https://*.oaiusercontent.com",
    ),
}
_BASE_URL_KEYS: dict[str, tuple[str, ...]] = {
    "claude": ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE", "CLAUDE_API_BASE"),
    "codex": ("OPENAI_BASE_URL",),
}


class NetworkPolicyError(RuntimeError):
    """The candidate network boundary or its protocol was violated."""


class _UpstreamError(RuntimeError):
    """An allowed upstream was unavailable without a policy violation."""


class _UnusedChannel(RuntimeError):
    """A preallocated broker channel was closed without being consumed."""


@dataclass(frozen=True, order=True)
class NetworkEndpoint:
    scheme: str
    host: str
    port: int
    allow_private: bool = False
    connect_host: str = ""
    connect_port: int = 0
    path_prefix: str = "/"
    allow_loopback: bool = False

    @property
    def mode(self) -> str:
        return "tls" if self.scheme == "https" else "plain"

    def as_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "allow_private": self.allow_private,
            "connect_host": self.connect_host or self.host,
            "connect_port": self.connect_port or self.port,
            "path_prefix": self.path_prefix,
            "allow_loopback": self.allow_loopback,
        }


@dataclass(frozen=True)
class ProviderGateway:
    """Trusted local provider URL rewritten to a candidate-only proxy alias."""

    source: str
    env_key: str
    candidate_base_url: str
    endpoint: NetworkEndpoint

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "env_key": self.env_key,
            "candidate_base_url": self.candidate_base_url,
            "endpoint": self.endpoint.as_dict(),
        }


@dataclass(frozen=True)
class CandidateNetworkPolicy:
    endpoints: tuple[NetworkEndpoint, ...]
    max_connections: int = NETWORK_MAX_CONNECTIONS
    max_concurrent: int = NETWORK_MAX_CONCURRENT
    max_total_bytes: int = NETWORK_MAX_TOTAL_BYTES
    connect_timeout_seconds: float = NETWORK_CONNECT_TIMEOUT_SECONDS

    def endpoint(self, mode: str, host: str, port: int) -> NetworkEndpoint | None:
        scheme = "https" if mode == "tls" else "http"
        for endpoint in self.endpoints:
            matches = endpoint.host == host
            if endpoint.host.startswith("*."):
                suffix = endpoint.host[2:]
                prefix = host[:-(len(suffix) + 1)] if host.endswith("." + suffix) else ""
                matches = bool(prefix) and "." not in prefix
            if (endpoint.scheme, endpoint.port) == (scheme, port) and matches:
                if endpoint.host != host:
                    return NetworkEndpoint(
                        endpoint.scheme,
                        host,
                        endpoint.port,
                        endpoint.allow_private,
                        endpoint.connect_host,
                        endpoint.connect_port,
                        endpoint.path_prefix,
                        endpoint.allow_loopback,
                    )
                return endpoint
        return None

    def as_dict(self) -> dict[str, object]:
        return {
            "policy_version": NETWORK_POLICY_VERSION,
            "proxy_protocol": "http-connect-exact-host+sni-v1",
            "endpoints": [endpoint.as_dict() for endpoint in self.endpoints],
            "max_connections": self.max_connections,
            "max_concurrent": self.max_concurrent,
            "max_total_bytes": self.max_total_bytes,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "proxy_port": NETWORK_PROXY_PORT,
            "unsafe_address_classes": "deny-unless-explicit-private;link-local-always-deny",
        }


def _canonical_host(value: str) -> str:
    if not isinstance(value, str):
        raise NetworkPolicyError("network host must be text")
    host = value[:-1] if value.endswith(".") else value
    if (
        not host
        or len(host) > 253
        or any(ord(char) <= 32 or ord(char) == 127 for char in host)
        or any(char in host for char in "/\\@%?#")
    ):
        raise NetworkPolicyError("network host is malformed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError) as exc:
            raise NetworkPolicyError("network host IDNA encoding failed") from exc
        labels = ascii_host.split(".")
        if any(not _DNS_LABEL.fullmatch(label) for label in labels):
            raise NetworkPolicyError("network host contains an invalid DNS label")
        return ascii_host
    return literal.compressed.lower()


def _canonical_path_scope(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise NetworkPolicyError("network endpoint path scope is malformed")
    index = 0
    normalized: list[str] = []
    while index < len(value):
        if value[index] != "%":
            if ord(value[index]) > 127:
                raise NetworkPolicyError("network endpoint path scope must be ASCII")
            normalized.append(value[index])
            index += 1
            continue
        if index + 2 >= len(value) or not re.fullmatch(
            r"[0-9A-Fa-f]{2}", value[index + 1:index + 3]
        ):
            raise NetworkPolicyError("network endpoint path has an invalid escape")
        decoded = int(value[index + 1:index + 3], 16)
        if decoded in {ord("."), ord("/"), ord("\\"), ord("%") }:
            raise NetworkPolicyError("network endpoint path has an unsafe escape")
        normalized.append("%" + value[index + 1:index + 3].upper())
        index += 3
    result = "".join(normalized)
    if any(segment in {".", ".."} for segment in result.split("/")):
        raise NetworkPolicyError("network endpoint path has a traversal segment")
    return result if result == "/" else result.rstrip("/")


def _parse_endpoint(
    value: str,
    *,
    allow_private: bool,
    allow_path: bool,
) -> NetworkEndpoint:
    raw = value.strip()
    if not raw:
        raise NetworkPolicyError("network endpoint is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path not in {"", "/"})
    ):
        raise NetworkPolicyError("network endpoint must be an HTTP(S) authority")
    try:
        host_value = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise NetworkPolicyError("network endpoint port is invalid") from exc
    if host_value is None or not 1 <= port <= 65535:
        raise NetworkPolicyError("network endpoint authority is invalid")
    wildcard = bool(host_value.startswith("*."))
    canonical = _canonical_host(host_value[2:] if wildcard else host_value)
    endpoint_allows_private = False
    try:
        literal = ipaddress.ip_address(canonical)
    except ValueError:
        literal = None
    if allow_private and literal is not None:
        if literal.is_loopback:
            raise NetworkPolicyError(
                "loopback endpoints require a trusted provider gateway"
            )
        endpoint_allows_private = literal.is_private
    return NetworkEndpoint(
        scheme=parsed.scheme,
        host=("*." + canonical if wildcard else canonical),
        port=port,
        allow_private=endpoint_allows_private,
        path_prefix=_canonical_path_scope(parsed.path or "/"),
    )


def _truthy(value: str | None) -> bool:
    return bool(value and value.strip().lower() in {"1", "true", "yes", "on"})


def _bounded_json_file(path: os.PathLike[str] | str) -> dict[str, object] | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= NETWORK_SETTINGS_MAX_BYTES:
            raise NetworkPolicyError("provider settings are unsafe or oversized")
        chunks: list[bytes] = []
        remaining = NETWORK_SETTINGS_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > NETWORK_SETTINGS_MAX_BYTES
            or after.st_size != info.st_size
            or after.st_mtime_ns != info.st_mtime_ns
            or after.st_ctime_ns != info.st_ctime_ns
        ):
            raise NetworkPolicyError("provider settings changed during policy resolution")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkPolicyError("provider settings are malformed") from exc
    if not isinstance(payload, dict):
        raise NetworkPolicyError("provider settings root must be an object")
    return payload


def trusted_provider_gateway(
    env: Mapping[str, str], *, provider_family: str | None = None
) -> ProviderGateway | None:
    """Discover an exact loopback gateway from trusted host-side provider config.

    Only Claude currently stores a base URL in JSON settings.  The returned
    endpoint advertises a synthetic hostname to the candidate HTTP client while
    retaining the exact loopback address as the host-side connect target.
    """

    family = (provider_family or env.get("ANGERONA_AGENT_PROVIDER_FAMILY") or "").lower()
    raw: str | None = None
    source = ""
    env_key = ""
    for key in _BASE_URL_KEYS.get(family, ()):
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            raw = value
            source = f"process-env:{key}"
            env_key = key
            break
    if raw is None:
        local_base = env.get("ANGERONA_LOCAL_BASE_URL")
        if isinstance(local_base, str) and local_base.strip():
            raw = local_base
            source = "process-env:ANGERONA_LOCAL_BASE_URL"
            env_key = "ANGERONA_LOCAL_BASE_URL"
    if raw is None and family == "claude":
        home = os.path.abspath(
            os.path.expanduser(env.get("HOME") or str(os.path.expanduser("~")))
        )
        settings = _bounded_json_file(os.path.join(home, ".claude", "settings.json"))
        if settings is not None:
            configured = settings.get("env")
            if configured is not None and not isinstance(configured, dict):
                raise NetworkPolicyError("provider settings env must be an object")
            value = (configured or {}).get("ANTHROPIC_BASE_URL")
            if isinstance(value, str) and value.strip():
                raw = value
                source = "claude-settings:ANTHROPIC_BASE_URL"
                env_key = "ANTHROPIC_BASE_URL"
    if raw is None:
        return None
    parsed = urlsplit(raw.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        # Public/custom HTTPS endpoints already use the ordinary exact proxy.
        return None
    try:
        host_value = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise NetworkPolicyError("trusted provider gateway port is invalid") from exc
    if host_value is None:
        raise NetworkPolicyError("trusted provider gateway host is missing")
    host = _canonical_host(host_value)
    is_loopback = host == "localhost"
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    path_prefix = _canonical_path_scope(parsed.path or "/")
    if is_loopback:
        if parsed.scheme != "http":
            raise NetworkPolicyError(
                "trusted loopback HTTPS gateway cannot be safely aliased"
            )
        alias = f"{family}.provider.angerona.invalid"
        authority = alias if port == 80 else f"{alias}:{port}"
        candidate_url = f"http://{authority}{parsed.path or ''}"
        endpoint = NetworkEndpoint(
            scheme="http",
            host=alias,
            port=port,
            allow_private=False,
            connect_host=host,
            connect_port=port,
            path_prefix=path_prefix,
            allow_loopback=True,
        )
    else:
        endpoint = _parse_endpoint(raw, allow_private=False, allow_path=True)
        default_port = 443 if endpoint.scheme == "https" else 80
        display_host = (
            f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
        )
        authority = display_host if endpoint.port == default_port else (
            f"{display_host}:{endpoint.port}"
        )
        candidate_url = f"{endpoint.scheme}://{authority}{parsed.path or ''}"
    return ProviderGateway(
        source=source,
        env_key=env_key,
        candidate_base_url=candidate_url,
        endpoint=endpoint,
    )


def configure_trusted_provider_gateway(
    env: dict[str, str], *, provider_family: str | None = None
) -> ProviderGateway | None:
    """Install only the candidate alias; never export the real host URL."""

    env.pop(NETWORK_GATEWAY_ENV, None)
    gateway = trusted_provider_gateway(env, provider_family=provider_family)
    if gateway is not None:
        env[NETWORK_GATEWAY_ENV] = gateway.candidate_base_url
        env[gateway.env_key] = gateway.candidate_base_url
    return gateway


def _settings_loopback_gateway(
    env: Mapping[str, str], *, family: str
) -> ProviderGateway | None:
    """Construct a gateway from the candidate's own settings.json only.

    ``trusted_provider_gateway`` prefers the process env, but a candidate's
    JSON settings is the *primary* trusted wiring (e.g. the exact-loopback
    bridge test).  When the host also sets a loopback env URL, the settings
    gateway must still be independently allowlisted so the candidate can reach
    its own configured endpoint.  (ELITE-2 roadmap F1-fix.)
    """
    if family != "claude":
        return None
    home = os.path.abspath(
        os.path.expanduser(env.get("HOME") or str(os.path.expanduser("~")))
    )
    settings = _bounded_json_file(os.path.join(home, ".claude", "settings.json"))
    if not isinstance(settings, dict):
        return None
    configured = settings.get("env")
    if configured is None or not isinstance(configured, dict):
        return None
    raw = configured.get("ANTHROPIC_BASE_URL")
    if not isinstance(raw, str) or not raw.strip():
        return None
    # Reuse the same parsing/aliasing as trusted_provider_gateway by handing it
    # a synthetic env carrying only the settings URL, so it cannot be shadowed
    # by the process env.
    synthetic_env = dict(env)
    synthetic_env.pop("ANGERONA_LOCAL_BASE_URL", None)
    for key in _BASE_URL_KEYS.get(family, ()):
        synthetic_env.pop(key, None)
    synthetic_env["ANTHROPIC_BASE_URL"] = raw
    return trusted_provider_gateway(synthetic_env, provider_family=family)


def resolve_candidate_network_policy(
    env: Mapping[str, str],
    *,
    provider_family: str | None = None,
    trusted_gateway: ProviderGateway | None = None,
) -> CandidateNetworkPolicy:
    """Resolve a provider-neutral, exact endpoint policy from trusted host env."""

    family = (provider_family or env.get("ANGERONA_AGENT_PROVIDER_FAMILY") or "").lower()
    private_allowed = _truthy(env.get("ANGERONA_AGENT_NETWORK_ALLOW_PRIVATE"))
    endpoints: set[NetworkEndpoint] = set()
    for value in _DEFAULT_ENDPOINTS.get(family, ()):
        endpoints.add(_parse_endpoint(value, allow_private=False, allow_path=False))
    gateway = trusted_gateway or trusted_provider_gateway(env, provider_family=family)
    if gateway is not None:
        endpoints.add(gateway.endpoint)
    # Independently allowlist a gateway wired in the candidate's own JSON
    # settings.  When the host process env ALSO carries a loopback provider URL
    # (e.g. this session's own gateway), ``trusted_provider_gateway`` prefers
    # the env URL; without this, the settings-wired endpoint would be silently
    # un-allowlisted and the candidate could not reach its own config.  (F1-fix)
    settings_gateway = _settings_loopback_gateway(env, family=family)
    if settings_gateway is not None and settings_gateway.endpoint not in endpoints:
        endpoints.add(settings_gateway.endpoint)
    for key in _BASE_URL_KEYS.get(family, ()):
        if gateway is not None and key == gateway.env_key:
            continue
        value = env.get(key)
        if value:
            endpoints.add(
                _parse_endpoint(value, allow_private=private_allowed, allow_path=True)
            )
    local_base = env.get("ANGERONA_LOCAL_BASE_URL")
    if local_base and not (
        gateway is not None and gateway.env_key == "ANGERONA_LOCAL_BASE_URL"
    ):
        endpoints.add(
            _parse_endpoint(local_base, allow_private=private_allowed, allow_path=True)
        )
    additions = env.get("ANGERONA_AGENT_NETWORK_ALLOWLIST", "")
    for value in additions.split(","):
        if value.strip():
            endpoints.add(
                _parse_endpoint(value, allow_private=private_allowed, allow_path=False)
            )
    return CandidateNetworkPolicy(endpoints=tuple(sorted(endpoints)))


def candidate_network_contract(
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return all security-relevant network inputs for checkpoints/resume."""

    source = os.environ if env is None else env
    gateways = {
        family: trusted_provider_gateway(source, provider_family=family)
        for family in sorted(_DEFAULT_ENDPOINTS)
    }
    return {
        "policy_version": NETWORK_POLICY_VERSION,
        "providers": {
            family: resolve_candidate_network_policy(
                source, provider_family=family, trusted_gateway=gateways[family]
            ).as_dict()
            for family in sorted(_DEFAULT_ENDPOINTS)
        },
        "allowlist_override": source.get("ANGERONA_AGENT_NETWORK_ALLOWLIST", ""),
        "allow_private": _truthy(source.get("ANGERONA_AGENT_NETWORK_ALLOW_PRIVATE")),
        "trusted_gateways": {
            family: gateway.as_dict() if gateway is not None else None
            for family, gateway in gateways.items()
        },
    }


def configure_proxy_environment(env: dict[str, str]) -> None:
    proxy = f"http://127.0.0.1:{NETWORK_PROXY_PORT}"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env[key] = proxy
    for key in ("ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        env.pop(key, None)
    env["ANGERONA_NETWORK_ALLOWED"] = "restricted"
    env["ANGERONA_NETWORK_ENFORCEMENT"] = "private-netns+exact-proxy+sni"


def _safe_ip(
    address: str, *, allow_private: bool, allow_loopback: bool = False
) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip in {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }:
        return False
    if ip.is_loopback:
        return allow_loopback
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_global:
        return True
    return allow_private and ip.is_private


def _resolve_endpoint(endpoint: NetworkEndpoint) -> list[tuple[int, int, int, tuple]]:
    resolution_host = endpoint.connect_host or endpoint.host
    try:
        pinned_literal = ipaddress.ip_address(resolution_host)
    except ValueError:
        pinned_literal = None
    try:
        rows = socket.getaddrinfo(
            resolution_host,
            endpoint.connect_port or endpoint.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise _UpstreamError("allowed endpoint DNS lookup failed") from exc
    unique: list[tuple[int, int, int, tuple]] = []
    seen: set[tuple[int, str, int]] = set()
    for family, socktype, proto, _canonname, sockaddr in rows:
        address = str(sockaddr[0])
        if pinned_literal is not None and ipaddress.ip_address(
            address.split("%", 1)[0]
        ) != pinned_literal:
            raise NetworkPolicyError("literal endpoint resolved to a different address")
        if not _safe_ip(
            address,
            allow_private=endpoint.allow_private,
            allow_loopback=endpoint.allow_loopback,
        ):
            raise NetworkPolicyError("allowed endpoint resolved to a forbidden address")
        key = (family, address, int(sockaddr[1]))
        if key not in seen:
            seen.add(key)
            unique.append((family, socktype, proto, sockaddr))
    if not unique:
        raise _UpstreamError("allowed endpoint has no usable addresses")
    return unique


def _connect_endpoint(endpoint: NetworkEndpoint, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in _resolve_endpoint(endpoint):
        candidate = socket.socket(family, socktype, proto)
        candidate.settimeout(timeout)
        try:
            candidate.connect(sockaddr)
            peer = str(candidate.getpeername()[0])
            if not _safe_ip(
                peer,
                allow_private=endpoint.allow_private,
                allow_loopback=endpoint.allow_loopback,
            ):
                raise NetworkPolicyError("connected endpoint peer is forbidden")
            candidate.settimeout(NETWORK_IO_TIMEOUT_SECONDS)
            return candidate
        except NetworkPolicyError:
            candidate.close()
            raise
        except OSError as exc:
            last_error = exc
            candidate.close()
    raise _UpstreamError("allowed endpoint connection failed") from last_error


def _recv_exact(channel: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = channel.recv(remaining)
        if not chunk:
            raise NetworkPolicyError("network broker frame ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(channel: socket.socket) -> tuple[dict[str, object], bytes]:
    first = channel.recv(len(_FRAME_MAGIC))
    if not first:
        raise _UnusedChannel
    magic = first + _recv_exact(channel, len(_FRAME_MAGIC) - len(first))
    if magic != _FRAME_MAGIC:
        raise NetworkPolicyError("network broker frame magic is invalid")
    size = struct.unpack("!I", _recv_exact(channel, 4))[0]
    if not 1 <= size <= 4096:
        raise NetworkPolicyError("network broker frame size is invalid")
    try:
        request = json.loads(_recv_exact(channel, size).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkPolicyError("network broker frame JSON is invalid") from exc
    if not isinstance(request, dict):
        raise NetworkPolicyError("network broker request is invalid")
    prelude_size = struct.unpack("!I", _recv_exact(channel, 4))[0]
    if prelude_size > NETWORK_HEADER_MAX_BYTES * 2:
        raise NetworkPolicyError("network broker prelude is oversized")
    return request, _recv_exact(channel, prelude_size)


def _send_frame(
    channel: socket.socket,
    *,
    mode: str,
    host: str,
    port: int,
    prelude: bytes,
) -> None:
    request = json.dumps(
        {"mode": mode, "host": host, "port": port},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    channel.sendall(
        _FRAME_MAGIC
        + struct.pack("!I", len(request))
        + request
        + struct.pack("!I", len(prelude))
        + prelude
    )


def _parse_tls_sni(handshake: bytes) -> str:
    if len(handshake) < 4 or handshake[0] != 1:
        raise NetworkPolicyError("TLS stream does not start with ClientHello")
    declared = int.from_bytes(handshake[1:4], "big")
    if declared + 4 != len(handshake):
        raise NetworkPolicyError("TLS ClientHello length is invalid")
    body = memoryview(handshake)[4:]
    offset = 0

    def take(size: int) -> memoryview:
        nonlocal offset
        if size < 0 or offset + size > len(body):
            raise NetworkPolicyError("TLS ClientHello is truncated")
        value = body[offset:offset + size]
        offset += size
        return value

    take(2 + 32)
    take(int.from_bytes(take(1), "big"))
    take(int.from_bytes(take(2), "big"))
    take(int.from_bytes(take(1), "big"))
    extensions_size = int.from_bytes(take(2), "big")
    extensions_end = offset + extensions_size
    if extensions_end != len(body):
        raise NetworkPolicyError("TLS ClientHello extensions are malformed")
    names: list[str] = []
    while offset < extensions_end:
        extension_type = int.from_bytes(take(2), "big")
        extension = take(int.from_bytes(take(2), "big"))
        if extension_type != 0:
            continue
        if len(extension) < 2 or int.from_bytes(extension[:2], "big") != len(extension) - 2:
            raise NetworkPolicyError("TLS SNI extension is malformed")
        cursor = 2
        while cursor < len(extension):
            if cursor + 3 > len(extension):
                raise NetworkPolicyError("TLS SNI name is truncated")
            name_type = extension[cursor]
            name_size = int.from_bytes(extension[cursor + 1:cursor + 3], "big")
            cursor += 3
            if cursor + name_size > len(extension):
                raise NetworkPolicyError("TLS SNI name length is invalid")
            if name_type == 0:
                try:
                    names.append(bytes(extension[cursor:cursor + name_size]).decode("ascii"))
                except UnicodeDecodeError as exc:
                    raise NetworkPolicyError("TLS SNI is not ASCII") from exc
            cursor += name_size
    if len(names) != 1:
        raise NetworkPolicyError("TLS ClientHello must contain exactly one SNI host")
    return _canonical_host(names[0])


def _read_tls_client_hello(channel: socket.socket) -> bytes:
    records: list[bytes] = []
    handshake = bytearray()
    required: int | None = None
    while required is None or len(handshake) < required:
        header = _recv_exact(channel, 5)
        if header[0] != 22 or header[1] != 3:
            raise NetworkPolicyError("TLS ClientHello record is invalid")
        size = int.from_bytes(header[3:5], "big")
        if not 1 <= size <= 18432:
            raise NetworkPolicyError("TLS ClientHello record length is invalid")
        payload = _recv_exact(channel, size)
        records.append(header + payload)
        handshake.extend(payload)
        if len(handshake) > NETWORK_TLS_HELLO_MAX_BYTES:
            raise NetworkPolicyError("TLS ClientHello exceeds policy bounds")
        if required is None and len(handshake) >= 4:
            required = 4 + int.from_bytes(handshake[1:4], "big")
            if required > NETWORK_TLS_HELLO_MAX_BYTES:
                raise NetworkPolicyError("TLS ClientHello declared size is excessive")
    if required != len(handshake):
        raise NetworkPolicyError("TLS ClientHello record carries ambiguous trailing data")
    return b"".join(records)


def _parse_header_block(data: bytes) -> tuple[list[bytes], bytes]:
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        raise NetworkPolicyError("HTTP proxy request header is incomplete")
    block = data[:marker]
    remainder = data[marker + 4:]
    if b"\x00" in block or b"\n" in block.replace(b"\r\n", b""):
        raise NetworkPolicyError("HTTP proxy request contains control bytes")
    lines = block.split(b"\r\n")
    if not lines or any(not line for line in lines):
        raise NetworkPolicyError("HTTP proxy request header is malformed")
    return lines, remainder


def _authority(value: str, default_port: int) -> tuple[str, int]:
    if "@" in value or "/" in value or "\\" in value:
        raise NetworkPolicyError("HTTP proxy authority is malformed")
    parsed = urlsplit("//" + value)
    try:
        host_value = parsed.hostname
        port = parsed.port or default_port
    except ValueError as exc:
        raise NetworkPolicyError("HTTP proxy authority port is invalid") from exc
    if host_value is None or parsed.path or not 1 <= port <= 65535:
        raise NetworkPolicyError("HTTP proxy authority is invalid")
    return _canonical_host(host_value), port


def _header_rows(lines: list[bytes]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for raw in lines:
        if raw[:1] in {b" ", b"\t"} or b":" not in raw:
            raise NetworkPolicyError("HTTP proxy header folding is forbidden")
        name, value = raw.split(b":", 1)
        try:
            name_text = name.decode("ascii").lower()
            value_text = value.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise NetworkPolicyError("HTTP proxy headers must be ASCII") from exc
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name_text):
            raise NetworkPolicyError("HTTP proxy header name is invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in value_text):
            raise NetworkPolicyError("HTTP proxy header value is invalid")
        rows.append((name_text, value_text))
    return rows


def _plain_body_remaining(
    headers: list[tuple[str, str]], remainder: bytes
) -> int:
    lengths = [value for name, value in headers if name == "content-length"]
    if len(lengths) > 1:
        raise NetworkPolicyError("plain HTTP request has duplicate Content-Length")
    if lengths:
        if not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]):
            raise NetworkPolicyError("plain HTTP Content-Length is invalid")
        declared = int(lengths[0])
    else:
        declared = 0
    if declared > NETWORK_MAX_TOTAL_BYTES:
        raise NetworkPolicyError("plain HTTP request body exceeds policy bounds")
    if len(remainder) > declared:
        raise NetworkPolicyError("plain HTTP request contains trailing or pipelined bytes")
    return declared - len(remainder)


def _path_in_scope(target: str, prefix: str) -> bool:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise NetworkPolicyError("plain broker request target is malformed")
    path = _canonical_path_scope(parsed.path)
    normalized = _canonical_path_scope(prefix or "/")
    if normalized == "/":
        return path.startswith("/") and not path.startswith("//")
    base = normalized.rstrip("/")
    return path == base or path.startswith(base + "/")


def _parse_proxy_request(data: bytes) -> tuple[str, str, int, bytes]:
    lines, remainder = _parse_header_block(data)
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise NetworkPolicyError("HTTP proxy request line is invalid") from exc
    if version != "HTTP/1.1" or not re.fullmatch(r"[A-Z]+", method):
        raise NetworkPolicyError("HTTP proxy request line is unsupported")
    headers = _header_rows(lines[1:])
    hosts = [value for name, value in headers if name == "host"]
    if len(hosts) != 1:
        raise NetworkPolicyError("HTTP proxy request requires one Host header")
    if any(name in {"transfer-encoding", "proxy-authorization"} for name, _ in headers):
        raise NetworkPolicyError("HTTP proxy request uses a forbidden header")
    if method == "CONNECT":
        host, port = _authority(target, 443)
        header_host, header_port = _authority(hosts[0], 443)
        if (header_host, header_port) != (host, port) or remainder:
            raise NetworkPolicyError("HTTP CONNECT authority is inconsistent")
        if any(name == "content-length" and value != "0" for name, value in headers):
            raise NetworkPolicyError("HTTP CONNECT body is forbidden")
        return "tls", host, port, b""
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
        raise NetworkPolicyError("plain proxy request requires an absolute HTTP URL")
    try:
        host_value = parsed.hostname
        port = parsed.port or 80
    except ValueError as exc:
        raise NetworkPolicyError("plain proxy URL port is invalid") from exc
    if host_value is None or parsed.fragment:
        raise NetworkPolicyError("plain proxy URL is malformed")
    host = _canonical_host(host_value)
    header_host, header_port = _authority(hosts[0], 80)
    if (header_host, header_port) != (host, port):
        raise NetworkPolicyError("plain proxy Host does not match its URL")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    _plain_body_remaining(headers, remainder)
    kept = [
        (name, value)
        for name, value in headers
        if name not in {
            "connection", "proxy-connection", "proxy-authorization"
        }
    ]
    # Claude Code's configured local Cloudflare gateway reuses its HTTP
    # connection across tool turns.  The broker validates every subsequent
    # request before forwarding it, so keep-alive remains bounded and exact.
    kept.append(("connection", "keep-alive"))
    prelude = (
        f"{method} {path} HTTP/1.1\r\n".encode("ascii")
        + b"".join(f"{name}: {value}\r\n".encode("ascii") for name, value in kept)
        + b"\r\n"
        + remainder
    )
    if len(prelude) > NETWORK_HEADER_MAX_BYTES * 2:
        raise NetworkPolicyError("plain proxy prelude is oversized")
    return "plain", host, port, prelude


def _validate_plain_prelude(prelude: bytes, endpoint: NetworkEndpoint) -> int:
    lines, remainder = _parse_header_block(prelude)
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise NetworkPolicyError("plain broker request line is invalid") from exc
    if (
        version != "HTTP/1.1"
        or not re.fullmatch(r"[A-Z]+", method)
        or not target.startswith("/")
        or target.startswith("//")
    ):
        raise NetworkPolicyError("plain broker request target is invalid")
    if not _path_in_scope(target, endpoint.path_prefix):
        raise NetworkPolicyError("plain broker request path is outside endpoint scope")
    headers = _header_rows(lines[1:])
    hosts = [value for name, value in headers if name == "host"]
    if len(hosts) != 1 or _authority(hosts[0], 80) != (endpoint.host, endpoint.port):
        raise NetworkPolicyError("plain broker Host is invalid")
    if any(name in {"transfer-encoding", "proxy-authorization", "proxy-connection"} for name, _ in headers):
        raise NetworkPolicyError("plain broker headers are unsafe")
    connections = [value.lower() for name, value in headers if name == "connection"]
    if connections != ["keep-alive"]:
        raise NetworkPolicyError("plain broker request must use validated keep-alive")
    return _plain_body_remaining(headers, remainder)


def _rewrite_plain_prelude(prelude: bytes, endpoint: NetworkEndpoint) -> bytes:
    """Rewrite only Host for a trusted alias-to-loopback gateway mapping."""

    if not endpoint.connect_host:
        return prelude
    lines, remainder = _parse_header_block(prelude)
    connect_port = endpoint.connect_port or endpoint.port
    default_port = 80 if endpoint.scheme == "http" else 443
    host_value = endpoint.connect_host
    if ":" in host_value and not host_value.startswith("["):
        host_value = f"[{host_value}]"
    authority = host_value if connect_port == default_port else f"{host_value}:{connect_port}"
    rewritten = [lines[0]]
    for line in lines[1:]:
        name, _separator, _value = line.partition(b":")
        if name.lower() == b"host":
            rewritten.append(b"Host: " + authority.encode("ascii"))
        else:
            rewritten.append(line)
    return b"\r\n".join(rewritten) + b"\r\n\r\n" + remainder


def _relay(
    left: socket.socket,
    right: socket.socket,
    *,
    stop: threading.Event,
    account: "_ByteAccount | None" = None,
) -> None:
    open_read = {left, right}
    while open_read and not stop.is_set():
        try:
            readable, _writable, _exceptional = select.select(
                list(open_read), [], list(open_read), 0.2
            )
        except (OSError, ValueError):
            return
        for source in readable:
            target = right if source is left else left
            try:
                chunk = source.recv(64 * 1024)
            except (OSError, socket.timeout):
                return
            if not chunk:
                open_read.discard(source)
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            if account is not None:
                account.consume(len(chunk))
            try:
                target.sendall(chunk)
            except (OSError, socket.timeout):
                return


def _relay_plain_http(
    client: socket.socket,
    upstream: socket.socket,
    *,
    request_body_remaining: int,
    endpoint: NetworkEndpoint,
    stop: threading.Event,
    account: "_ByteAccount",
) -> None:
    """Relay HTTP keep-alive while validating every length-delimited request."""

    upstream_open = True
    client_open = True
    client_buffer = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(upstream, selectors.EVENT_READ)
    selector.register(client, selectors.EVENT_READ)

    def next_request_size() -> int | None:
        marker = client_buffer.find(b"\r\n\r\n")
        if marker < 0:
            if len(client_buffer) > NETWORK_HEADER_MAX_BYTES:
                raise NetworkPolicyError("HTTP proxy request header exceeds policy bounds")
            return None
        header_size = marker + 4
        lines, remainder = _parse_header_block(bytes(client_buffer[:header_size]))
        if remainder:
            raise NetworkPolicyError("plain HTTP header split is inconsistent")
        headers = _header_rows(lines[1:])
        lengths = [value for name, value in headers if name == "content-length"]
        if len(lengths) > 1:
            raise NetworkPolicyError("plain HTTP request has duplicate Content-Length")
        if lengths:
            if not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]):
                raise NetworkPolicyError("plain HTTP Content-Length is invalid")
            body_size = int(lengths[0])
        else:
            body_size = 0
        if body_size > NETWORK_MAX_TOTAL_BYTES:
            raise NetworkPolicyError("plain HTTP request body exceeds policy bounds")
        total = header_size + body_size
        return total if len(client_buffer) >= total else None

    def forward_complete_requests() -> None:
        while request_body_remaining == 0:
            total = next_request_size()
            if total is None:
                return
            request = bytes(client_buffer[:total])
            del client_buffer[:total]
            header_end = request.index(b"\r\n\r\n") + 4
            header = request[:header_end]
            body = request[header_end:]
            mode, host, port, prelude = _parse_proxy_request(header)
            if mode != "plain" or host != endpoint.host or port != endpoint.port:
                raise NetworkPolicyError("plain keep-alive endpoint changed")
            if _validate_plain_prelude(prelude, endpoint) != len(body):
                raise NetworkPolicyError("plain keep-alive request is incomplete")
            prelude = _rewrite_plain_prelude(prelude, endpoint)
            account.consume(len(prelude) + len(body))
            upstream.sendall(prelude)
            if body:
                upstream.sendall(body)

    try:
        while upstream_open and client_open and not stop.is_set():
            for key, _mask in selector.select(0.2):
                source = key.fileobj
                if source is upstream:
                    chunk = upstream.recv(64 * 1024)
                    if not chunk:
                        upstream_open = False
                        break
                    account.consume(len(chunk))
                    client.sendall(chunk)
                    continue
                if not isinstance(source, socket.socket):
                    continue
                chunk = source.recv(64 * 1024)
                if not chunk:
                    selector.unregister(client)
                    client_open = False
                    if request_body_remaining or client_buffer:
                        raise NetworkPolicyError("plain HTTP request ended early")
                    continue
                if request_body_remaining:
                    body = chunk[:request_body_remaining]
                    request_body_remaining -= len(body)
                    account.consume(len(body))
                    upstream.sendall(body)
                    chunk = chunk[len(body):]
                if chunk:
                    client_buffer.extend(chunk)
                forward_complete_requests()
    finally:
        selector.close()


class _ByteAccount:
    def __init__(self, limit: int):
        self.limit = limit
        self.total = 0
        self.lock = threading.Lock()

    def consume(self, size: int) -> None:
        with self.lock:
            if self.total + size > self.limit:
                raise NetworkPolicyError("candidate network byte budget exceeded")
            self.total += size


class CandidateNetworkBroker:
    """Host-side endpoint validator and bounded relay for one provider launch."""

    def __init__(
        self,
        policy: CandidateNetworkPolicy,
        *,
        on_event: Callable[[str, str, dict[str, object]], None] | None = None,
    ):
        if (
            policy.max_connections <= 0
            or policy.max_concurrent <= 0
            or policy.max_total_bytes <= 0
        ):
            raise NetworkPolicyError("candidate network limits are invalid")
        self.policy = policy
        self.on_event = on_event
        self.stop_event = threading.Event()
        self.account = _ByteAccount(policy.max_total_bytes)
        self.violations = 0
        self.accepted = 0
        self.upstream_errors = 0
        self.violation_reasons: dict[str, int] = {}
        self.denied_endpoints: dict[str, int] = {}
        self.accepted_endpoints: dict[str, int] = {}
        self._lock = threading.Lock()
        self._selector = selectors.DefaultSelector()
        self._host_channels: set[socket.socket] = set()
        self._candidate_channels: list[socket.socket] = []
        self._workers: list[threading.Thread] = []
        self._dispatcher: threading.Thread | None = None

    def _observe(self, action: str, status: str, attributes: dict[str, object]) -> None:
        if self.on_event is not None:
            self.on_event(action, status, attributes)

    def start(self) -> tuple[int, ...]:
        if self._dispatcher is not None:
            raise NetworkPolicyError("candidate network broker already started")
        for _index in range(self.policy.max_connections):
            host, candidate = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            host.settimeout(NETWORK_IO_TIMEOUT_SECONDS)
            candidate.set_inheritable(True)
            self._host_channels.add(host)
            self._candidate_channels.append(candidate)
            self._selector.register(host, selectors.EVENT_READ)
        self._dispatcher = threading.Thread(target=self._dispatch, daemon=True)
        self._dispatcher.start()
        return tuple(channel.fileno() for channel in self._candidate_channels)

    def release_candidate_channels(self) -> None:
        for channel in self._candidate_channels:
            channel.close()
        self._candidate_channels.clear()

    def _record(self, field: str) -> None:
        with self._lock:
            setattr(self, field, int(getattr(self, field)) + 1)

    def _record_violation(self, reason: str) -> None:
        with self._lock:
            self.violations += 1
            self.violation_reasons[reason] = self.violation_reasons.get(reason, 0) + 1

    def _record_denied_endpoint(self, mode: str, host: str, port: int) -> None:
        endpoint = f"{mode}://{host}:{port}"
        with self._lock:
            self.denied_endpoints[endpoint] = self.denied_endpoints.get(endpoint, 0) + 1

    def _record_accepted_endpoint(self, mode: str, host: str, port: int) -> None:
        endpoint = f"{mode}://{host}:{port}"
        with self._lock:
            self.accepted += 1
            self.accepted_endpoints[endpoint] = self.accepted_endpoints.get(endpoint, 0) + 1

    def _dispatch(self) -> None:
        while not self.stop_event.is_set():
            try:
                events = self._selector.select(0.2)
            except (OSError, ValueError):
                return
            for key, _mask in events:
                channel = key.fileobj
                if not isinstance(channel, socket.socket):
                    continue
                try:
                    self._selector.unregister(channel)
                except (KeyError, ValueError):
                    continue
                self._host_channels.discard(channel)
                worker = threading.Thread(
                    target=self._serve_channel, args=(channel,), daemon=True
                )
                self._workers.append(worker)
                worker.start()

    def _serve_channel(self, channel: socket.socket) -> None:
        upstream: socket.socket | None = None
        mode: object = None
        host_value: object = None
        port: object = None
        started = threading.get_native_id()
        try:
            request, prelude = _recv_frame(channel)
            if set(request) != {"mode", "host", "port"}:
                raise NetworkPolicyError("network broker request fields are invalid")
            mode = request.get("mode")
            host_value = request.get("host")
            port = request.get("port")
            self._observe(
                "request",
                "running",
                {
                    "mode": mode,
                    "host": host_value,
                    "port": port,
                    "prelude_bytes": len(prelude),
                    "worker_native_id": started,
                },
            )
            if mode not in {"tls", "plain"} or not isinstance(host_value, str):
                raise NetworkPolicyError("network broker request type is invalid")
            if type(port) is not int or not 1 <= port <= 65535:
                raise NetworkPolicyError("network broker request port is invalid")
            host = _canonical_host(host_value)
            if host != host_value:
                raise NetworkPolicyError("network broker host is not canonical")
            endpoint = self.policy.endpoint(mode, host, port)
            if endpoint is None:
                self._record_denied_endpoint(mode, host, port)
                raise NetworkPolicyError("network endpoint is not allowlisted")
            if mode == "tls" and prelude:
                raise NetworkPolicyError("TLS broker request has an unexpected prelude")
            request_body_remaining = 0
            if mode == "plain":
                request_body_remaining = _validate_plain_prelude(prelude, endpoint)
                prelude = _rewrite_plain_prelude(prelude, endpoint)
            upstream = _connect_endpoint(endpoint, self.policy.connect_timeout_seconds)
            channel.sendall(_STATUS_OK)
            if mode == "tls":
                client_hello = _read_tls_client_hello(channel)
                # Reassemble handshake bytes from the record sequence for SNI validation.
                cursor = 0
                handshake = bytearray()
                while cursor < len(client_hello):
                    size = int.from_bytes(client_hello[cursor + 3:cursor + 5], "big")
                    handshake.extend(client_hello[cursor + 5:cursor + 5 + size])
                    cursor += 5 + size
                if _parse_tls_sni(bytes(handshake)) != endpoint.host:
                    raise NetworkPolicyError("TLS SNI does not match allowlisted endpoint")
                self.account.consume(len(client_hello))
                upstream.sendall(client_hello)
            else:
                self.account.consume(len(prelude))
                upstream.sendall(prelude)
            self._record_accepted_endpoint(mode, host, port)
            self._observe(
                "accepted",
                "ok",
                {"mode": mode, "host": host, "port": port, "bytes_total": self.account.total},
            )
            if mode == "plain":
                _relay_plain_http(
                    channel,
                    upstream,
                    request_body_remaining=request_body_remaining,
                    endpoint=endpoint,
                    stop=self.stop_event,
                    account=self.account,
                )
            else:
                _relay(
                    channel,
                    upstream,
                    stop=self.stop_event,
                    account=self.account,
                )
        except _UnusedChannel:
            pass
        except NetworkPolicyError as exc:
            self._record_violation(str(exc))
            self._observe(
                "denied",
                "error",
                {
                    "mode": mode,
                    "host": host_value,
                    "port": port,
                    "reason": str(exc),
                },
            )
            try:
                channel.sendall(_STATUS_DENIED)
            except OSError:
                pass
        except (_UpstreamError, OSError, socket.timeout) as exc:
            self._record("upstream_errors")
            self._observe(
                "upstream_error",
                "error",
                {
                    "mode": mode,
                    "host": host_value,
                    "port": port,
                    "exception": type(exc).__name__,
                },
            )
            try:
                channel.sendall(_STATUS_UPSTREAM_ERROR)
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()
            channel.close()

    def close(self) -> dict[str, object]:
        self.stop_event.set()
        self.release_candidate_channels()
        for channel in list(self._host_channels):
            try:
                self._selector.unregister(channel)
            except (KeyError, ValueError):
                pass
            channel.close()
        self._host_channels.clear()
        self._selector.close()
        if self._dispatcher is not None:
            self._dispatcher.join(timeout=2)
        for worker in self._workers:
            worker.join(timeout=2)
        return {
            "accepted": self.accepted,
            "violations": self.violations,
            "upstream_errors": self.upstream_errors,
            "bytes": self.account.total,
            "violation_reasons": dict(sorted(self.violation_reasons.items())),
            "denied_endpoints": dict(sorted(self.denied_endpoints.items())),
            "accepted_endpoints": dict(sorted(self.accepted_endpoints.items())),
        }

    def __enter__(self) -> "CandidateNetworkBroker":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _read_proxy_header(client: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        # Do not consume request-body or a following keep-alive request while
        # looking for the first header terminator.
        peeked = client.recv(4096, socket.MSG_PEEK)
        if not peeked:
            raise NetworkPolicyError("HTTP proxy client disconnected during header")
        marker = peeked.find(b"\r\n\r\n")
        wanted = marker + 4 if marker >= 0 else len(peeked)
        chunk = client.recv(wanted)
        if not chunk:
            raise NetworkPolicyError("HTTP proxy client disconnected during header")
        data.extend(chunk)
        if len(data) > NETWORK_HEADER_MAX_BYTES:
            raise NetworkPolicyError("HTTP proxy request header exceeds policy bounds")
    return bytes(data)


class CandidateLoopbackProxy:
    """Candidate-side proxy; only this trusted runner owns broker socketpairs."""

    def __init__(self, network_fds: Iterable[int]):
        fds = tuple(network_fds)
        if not fds or len(fds) > NETWORK_MAX_CONNECTIONS or len(set(fds)) != len(fds):
            raise NetworkPolicyError("candidate network channel set is invalid")
        self.channels: queue.Queue[socket.socket] = queue.Queue(maxsize=len(fds))
        for fd in fds:
            if fd < 3:
                raise NetworkPolicyError("candidate network channel descriptor is invalid")
            channel = socket.socket(fileno=fd)
            channel.settimeout(NETWORK_IO_TIMEOUT_SECONDS)
            self.channels.put_nowait(channel)
        self.stop_event = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", NETWORK_PROXY_PORT))
        self.listener.listen(NETWORK_MAX_CONCURRENT)
        self.listener.settimeout(0.2)
        self.semaphore = threading.BoundedSemaphore(NETWORK_MAX_CONCURRENT)
        self.workers: list[threading.Thread] = []
        self.violations = 0
        self._violation_lock = threading.Lock()
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def _record_violation(self) -> None:
        with self._violation_lock:
            self.violations += 1

    def start(self) -> None:
        self.thread.start()

    def _accept(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.semaphore.acquire(blocking=False):
                self._record_violation()
                try:
                    client.sendall(b"HTTP/1.1 503 Proxy Busy\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                client.close()
                continue
            worker = threading.Thread(target=self._handle, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _handle(self, client: socket.socket) -> None:
        channel: socket.socket | None = None
        try:
            client.settimeout(NETWORK_IO_TIMEOUT_SECONDS)
            mode, host, port, prelude = _parse_proxy_request(_read_proxy_header(client))
            try:
                channel = self.channels.get_nowait()
            except queue.Empty:
                self._record_violation()
                client.sendall(b"HTTP/1.1 503 Proxy Budget Exhausted\r\nConnection: close\r\n\r\n")
                return
            _send_frame(
                channel, mode=mode, host=host, port=port, prelude=prelude
            )
            status = _recv_exact(channel, 1)
            if status != _STATUS_OK:
                response = b"403 Forbidden" if status == _STATUS_DENIED else b"502 Bad Gateway"
                client.sendall(b"HTTP/1.1 " + response + b"\r\nConnection: close\r\n\r\n")
                return
            if mode == "tls":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _relay(client, channel, stop=self.stop_event)
        except NetworkPolicyError:
            self._record_violation()
            try:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        except (OSError, socket.timeout):
            try:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if channel is not None:
                channel.close()
            client.close()
            self.semaphore.release()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)
        while True:
            try:
                self.channels.get_nowait().close()
            except queue.Empty:
                break
        for worker in self.workers:
            worker.join(timeout=2)

    def __enter__(self) -> "CandidateLoopbackProxy":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
