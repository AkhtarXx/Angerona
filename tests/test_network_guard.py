import socket
import ssl
import json

import pytest

import src.agents.network_guard as guard


def _client_hello(server_name: str) -> bytes:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    client = ssl.create_default_context().wrap_bio(
        incoming, outgoing, server_side=False, server_hostname=server_name
    )
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    records = outgoing.read()
    cursor = 0
    handshake = bytearray()
    while cursor < len(records):
        size = int.from_bytes(records[cursor + 3:cursor + 5], "big")
        handshake.extend(records[cursor + 5:cursor + 5 + size])
        cursor += 5 + size
    return bytes(handshake)


def test_policy_is_provider_neutral_exact_and_canonical():
    policy = guard.resolve_candidate_network_policy({
        "ANGERONA_AGENT_PROVIDER_FAMILY": "codex",
        "ANGERONA_AGENT_NETWORK_ALLOWLIST": "https://Example.COM.,http://public.example:8080",
    })
    rows = {(row.scheme, row.host, row.port) for row in policy.endpoints}
    assert ("https", "example.com", 443) in rows
    assert ("http", "public.example", 8080) in rows
    assert ("https", "api.openai.com", 443) in rows
    assert policy.endpoint("tls", "files.oaiusercontent.com", 443) is not None
    assert policy.endpoint("tls", "a.b.oaiusercontent.com", 443) is None
    assert policy.endpoint("tls", "oaiusercontent.com", 443) is None

    with pytest.raises(guard.NetworkPolicyError):
        guard.resolve_candidate_network_policy({
            "ANGERONA_AGENT_NETWORK_ALLOWLIST": "https://**.example.com",
        })
    with pytest.raises(guard.NetworkPolicyError):
        guard.resolve_candidate_network_policy({
            "ANGERONA_AGENT_NETWORK_ALLOWLIST": "https://user@example.com",
        })
    with pytest.raises(guard.NetworkPolicyError, match="trusted provider gateway"):
        guard.resolve_candidate_network_policy({
            "ANGERONA_AGENT_NETWORK_ALLOWLIST": "http://127.0.0.1:8080",
            "ANGERONA_AGENT_NETWORK_ALLOW_PRIVATE": "1",
        })


def test_dns_rebinding_and_link_local_are_rejected(monkeypatch):
    public = guard.NetworkEndpoint("https", "api.example", 443)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
    ])
    with pytest.raises(guard.NetworkPolicyError, match="forbidden address"):
        guard._resolve_endpoint(public)

    private = guard.NetworkEndpoint("http", "metadata.example", 80, allow_private=True)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 80)),
    ])
    with pytest.raises(guard.NetworkPolicyError, match="forbidden address"):
        guard._resolve_endpoint(private)
    assert not guard._safe_ip("fd00:ec2::254", allow_private=True)
    assert not guard._safe_ip(
        "127.0.0.1", allow_private=True, allow_loopback=False
    )


def test_tls_sni_is_required_and_exact():
    assert guard._parse_tls_sni(_client_hello("api.openai.com")) == "api.openai.com"
    with pytest.raises(guard.NetworkPolicyError):
        guard._parse_tls_sni(_client_hello("api.openai.com").replace(
            b"api.openai.com", b"api.openai.co\x00"
        ))


@pytest.mark.parametrize("payload", [
    b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
    b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"CONNECT user@api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n",
    b"GET http://api.openai.com/ HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\n\r\n",
])
def test_proxy_rejects_authority_confusion_and_smuggling(payload):
    with pytest.raises(guard.NetworkPolicyError):
        guard._parse_proxy_request(payload)


def test_contract_pins_limits_profiles_and_overrides():
    contract = guard.candidate_network_contract({
        "ANGERONA_AGENT_NETWORK_ALLOWLIST": "https://mirror.example",
        "ANGERONA_AGENT_NETWORK_ALLOW_PRIVATE": "1",
    })
    assert contract["policy_version"] == guard.NETWORK_POLICY_VERSION
    assert contract["allow_private"] is True
    assert contract["allowlist_override"] == "https://mirror.example"
    assert set(contract["providers"]) == {"claude", "codex"}
    for provider in contract["providers"].values():
        assert provider["max_connections"] == guard.NETWORK_MAX_CONNECTIONS
        assert provider["max_total_bytes"] == guard.NETWORK_MAX_TOTAL_BYTES


def test_trusted_loopback_gateway_is_aliased_and_contract_bound(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:3457/v1"},
        "hooks": {"PreToolUse": [{"command": "poison"}]},
    }))
    env = {"HOME": str(tmp_path), "ANGERONA_AGENT_PROVIDER_FAMILY": "claude"}

    gateway = guard.trusted_provider_gateway(env)

    assert gateway is not None
    assert gateway.candidate_base_url == "http://claude.provider.angerona.invalid:3457/v1"
    assert gateway.endpoint.host == "claude.provider.angerona.invalid"
    assert gateway.endpoint.connect_host == "127.0.0.1"
    assert gateway.endpoint.allow_private is False
    assert gateway.endpoint.allow_loopback is True
    policy = guard.resolve_candidate_network_policy(env)
    endpoint = policy.endpoint("plain", gateway.endpoint.host, 3457)
    assert endpoint == gateway.endpoint
    contract = guard.candidate_network_contract(env)
    assert contract["trusted_gateways"]["claude"] == gateway.as_dict()


def test_trusted_gateway_connects_exact_upstream_and_rewrites_host(monkeypatch):
    endpoint = guard.NetworkEndpoint(
        "http", "claude.provider.angerona.invalid", 3457, True,
        "127.0.0.1", 3457, "/", True,
    )
    seen = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **_kwargs: (
        seen.append((host, port)) or [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))
        ]
    ))
    rows = guard._resolve_endpoint(endpoint)
    assert seen == [("127.0.0.1", 3457)]
    assert rows[0][3] == ("127.0.0.1", 3457)

    prelude = (
        b"POST /v1/messages HTTP/1.1\r\n"
        b"Host: claude.provider.angerona.invalid:3457\r\n"
        b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n"
    )
    guard._validate_plain_prelude(prelude, endpoint)
    rewritten = guard._rewrite_plain_prelude(prelude, endpoint)
    assert b"Host: 127.0.0.1:3457\r\n" in rewritten
    assert b"claude.provider.angerona.invalid" not in rewritten


def test_plain_gateway_enforces_base_path_and_rejects_pipelining():
    endpoint = guard.NetworkEndpoint(
        "http", "claude.provider.angerona.invalid", 3457, True,
        "127.0.0.1", 3457, "/v1",
    )
    allowed = (
        b"POST /v1/messages HTTP/1.1\r\n"
        b"Host: claude.provider.angerona.invalid:3457\r\n"
        b"Content-Length: 4\r\nConnection: keep-alive\r\n\r\nbody"
    )
    assert guard._validate_plain_prelude(allowed, endpoint) == 0

    outside = allowed.replace(b"/v1/messages", b"/admin")
    with pytest.raises(guard.NetworkPolicyError, match="outside endpoint scope"):
        guard._validate_plain_prelude(outside, endpoint)

    for traversal in (b"/v1/../admin", b"/v1/%2e%2e/admin", b"/v1/%2F..%2Fadmin"):
        with pytest.raises(guard.NetworkPolicyError, match="path"):
            guard._validate_plain_prelude(
                allowed.replace(b"/v1/messages", traversal), endpoint
            )

    pipelined = allowed + (
        b"GET /admin HTTP/1.1\r\nHost: internal-admin\r\n\r\n"
    )
    with pytest.raises(guard.NetworkPolicyError, match="pipelined"):
        guard._validate_plain_prelude(pipelined, endpoint)

    duplicate_length = allowed.replace(
        b"Content-Length: 4\r\n", b"Content-Length: 4\r\nContent-Length: 4\r\n"
    )
    with pytest.raises(guard.NetworkPolicyError, match="duplicate"):
        guard._validate_plain_prelude(duplicate_length, endpoint)


def test_https_base_url_from_claude_settings_is_in_exact_policy(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "https://Gateway.Example:8443/v1"}
    }))
    env = {"HOME": str(tmp_path), "ANGERONA_AGENT_PROVIDER_FAMILY": "claude"}
    gateway = guard.configure_trusted_provider_gateway(env)
    assert gateway is not None
    assert gateway.candidate_base_url == "https://gateway.example:8443/v1"
    assert env[guard.NETWORK_GATEWAY_ENV] == gateway.candidate_base_url
    policy = guard.resolve_candidate_network_policy(env, trusted_gateway=gateway)
    endpoint = policy.endpoint("tls", "gateway.example", 8443)
    assert endpoint is not None
    assert endpoint.path_prefix == "/v1"


@pytest.mark.parametrize(("family", "key"), [
    ("claude", "ANTHROPIC_BASE_URL"),
    ("codex", "OPENAI_BASE_URL"),
])
def test_loopback_process_env_is_rewritten_to_exact_provider_alias(family, key):
    env = {"ANGERONA_AGENT_PROVIDER_FAMILY": family, key: "http://127.0.0.1:3457/v1"}
    gateway = guard.configure_trusted_provider_gateway(env)
    assert gateway is not None
    assert gateway.source == f"process-env:{key}"
    assert gateway.env_key == key
    assert env[key] == f"http://{family}.provider.angerona.invalid:3457/v1"
    policy = guard.resolve_candidate_network_policy(env, trusted_gateway=gateway)
    endpoint = policy.endpoint("plain", f"{family}.provider.angerona.invalid", 3457)
    assert endpoint is not None
    assert endpoint.connect_host == "127.0.0.1"
    assert endpoint.allow_loopback is True


@pytest.mark.parametrize(("family", "key"), [
    ("claude", "ANTHROPIC_BASE_URL"),
    ("codex", "OPENAI_BASE_URL"),
])
def test_public_ipv6_provider_base_keeps_bracketed_authority(family, key):
    env = {
        "ANGERONA_AGENT_PROVIDER_FAMILY": family,
        key: "https://[2606:4700:4700::1111]:8443/v1",
    }
    gateway = guard.configure_trusted_provider_gateway(env)
    assert gateway is not None
    assert gateway.candidate_base_url == (
        "https://[2606:4700:4700::1111]:8443/v1"
    )
    policy = guard.resolve_candidate_network_policy(env, trusted_gateway=gateway)
    endpoint = policy.endpoint("tls", "2606:4700:4700::1111", 8443)
    assert endpoint is not None and endpoint.path_prefix == "/v1"


def test_trusted_gateway_rejects_symlinked_settings(tmp_path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:1"}}')
    (claude / "settings.json").symlink_to(outside)
    with pytest.raises(OSError):
        guard.trusted_provider_gateway({"HOME": str(tmp_path)}, provider_family="claude")


def test_trusted_localhost_gateway_accepts_only_loopback_dns(monkeypatch, tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text('{"env":{"ANTHROPIC_BASE_URL":"http://localhost:3457"}}')
    gateway = guard.trusted_provider_gateway(
        {"HOME": str(tmp_path)}, provider_family="claude"
    )
    assert gateway is not None and gateway.endpoint.allow_loopback is True
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 3457, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 3457)),
    ])
    rows = guard._resolve_endpoint(gateway.endpoint)
    assert {row[3][0] for row in rows} == {"::1", "127.0.0.1"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 3457)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.5", 3457)),
    ])
    with pytest.raises(guard.NetworkPolicyError, match="forbidden address"):
        guard._resolve_endpoint(gateway.endpoint)
