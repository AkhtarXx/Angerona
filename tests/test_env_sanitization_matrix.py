"""Env-sanitization matrix per provider family (ELITE-2 roadmap F2).

Verifies that a host-supplied *public* provider base URL is stripped from the
candidate env before a K-sandbox launch, while a *loopback* URL (the trusted
synthetic endpoint the candidate sandbox itself wires) is preserved.  The
sanitizer distinguishes the leak class (public override) from the legitimate
gateway bridge (loopback alias) — see F1-fix.
"""
from __future__ import annotations

from src.agents.runtime import _sanitize_required_provider_environment


def _env_with(url_key: str, url_value: str) -> dict[str, str]:
    """Build a minimal env carrying exactly one provider URL to test."""
    env: dict[str, str] = {}
    env[url_key] = url_value
    return env


POISON = "https://poison.example.com"
LOOPBACK = "http://127.0.0.1:3457/v1"
LOCALHOST = "http://localhost:3457/v1"


def test_env_sanitization_matrix_claude() -> None:
    # public ANTHROPIC_* / CLAUDE_* URLs are stripped across the claude family
    for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE", "CLAUDE_API_BASE"):
        env = _env_with(key, POISON)
        _sanitize_required_provider_environment(env)
        assert key not in env, f"{key} should be stripped for public URL"


def test_env_sanitization_matrix_codex() -> None:
    for key in ("OPENAI_BASE_URL", "OPENAI_API_BASE"):
        env = _env_with(key, POISON)
        _sanitize_required_provider_environment(env)
        assert key not in env
    # CLAUDE_API_BASE is also a claude-family leak even on a codex dispatch
    env = _env_with("CLAUDE_API_BASE", POISON)
    _sanitize_required_provider_environment(env)
    assert "CLAUDE_API_BASE" not in env


def test_env_sanitization_matrix_openai() -> None:
    for key in ("OPENAI_BASE_URL", "OPENAI_API_BASE"):
        env = _env_with(key, POISON)
        _sanitize_required_provider_environment(env)
        assert key not in env


def test_env_sanitization_matrix_gemini() -> None:
    env = _env_with("ANTHROPIC_BASE_URL", POISON)
    _sanitize_required_provider_environment(env)
    assert "ANTHROPIC_BASE_URL" not in env


def test_loopback_provider_url_is_preserved() -> None:
    # A loopback URL is the trusted synthetic endpoint, not a leak.
    for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE", "CLAUDE_API_BASE"):
        env = _env_with(key, LOOPBACK)
        _sanitize_required_provider_environment(env)
        assert env.get(key) == LOOPBACK, f"{key} loopback bridge must survive"
    for key in ("OPENAI_BASE_URL", "OPENAI_API_BASE"):
        env = _env_with(key, LOCALHOST)
        _sanitize_required_provider_environment(env)
        assert env.get(key) == LOCALHOST


def test_unknown_provider_url_key_is_stripped_by_allowlist() -> None:
    """Adversarial enum-drift tripwire (ELITE-2 verdict round-2 fix).

    Originally the sanitizer was a 5-key denylist and this test pinned the
    enum-drift GAP — a non-enumerated *_BASE_URL (e.g. GEMINI_BASE_URL) was
    NOT stripped and silently leaked the host's real provider endpoint to
    the candidate.  The verdict flagged this as the F1 leak class.

    The fix converted the denylist to an allowlist: the sanitizer now strips
    ANY key ending in _BASE_URL / _API_BASE / _API_KEY whose value points at a
    public host, preserving only loopback URLs.  This test now asserts the FIX
    (unknown keys ARE stripped) so a regression back to a denylist fails loudly.
    """
    env = _env_with("GEMINI_BASE_URL", POISON)
    _sanitize_required_provider_environment(env)
    assert "GEMINI_BASE_URL" not in env, (
        "unknown *_BASE_URL key survived sanitization — the allowlist strip "
        "regressed back to a denylist; non-enumerated provider URLs leak again"
    )


def test_unknown_provider_url_loopback_is_preserved() -> None:
    """An unknown *_BASE_URL pointing at loopback is the trusted synthetic
    gateway and must survive the allowlist strip (loopback == not a leak)."""
    env = _env_with("GEMINI_BASE_URL", LOOPBACK)
    _sanitize_required_provider_environment(env)
    assert env.get("GEMINI_BASE_URL") == LOOPBACK


def test_execution_control_env_always_stripped() -> None:
    # Interpreter/config injection controls are always removed, regardless of
    # value — they are never legitimate candidate inputs.
    for key in ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "LD_PRELOAD",
                "ANGR_STATIC_PRELOAD", "DYLD_INSERT_LIBRARIES"):
        env = _env_with(key, "anything")
        _sanitize_required_provider_environment(env)
        assert key not in env, f"{key} execution control must always be stripped"


def test_provider_auth_tokens_are_stripped() -> None:
    """Adversarial: the actual Claude/Claude-Code credential env vars are
    *_AUTH_TOKEN / *_OAUTH_TOKEN / *_TOKEN, not *_API_KEY.  The allowlist suffix
    set must catch all of them, or the live host OAuth token leaks to the
    candidate.  (ELITE-2 verdict round-3 fix: suffix set lacked the token
    variants.)"""
    for key in (
        "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_API_TOKEN",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    ):
        env = _env_with(key, "sk-ant-poison-12345")
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"{key} auth token/api key survived sanitization — the credential "
            "leaked to the K-candidate env"
        )


def test_provider_url_spelling_variants_are_stripped() -> None:
    """Adversarial: provider credential vars use many spellings beyond
    *_BASE_URL — *_API_URL, *_ENDPOINT, *_SERVER_URL, *_SECRET, *_BEARER,
    *_PASSWORD.  The allowlist suffix set must cover the common variants
    or each new spelling leaks the live credential.  (ELITE-2 verdict
    round-4 fix: suffix set missed these variants.)"""
    for key in (
        "ANTHROPIC_API_URL", "ANTHROPIC_ENDPOINT", "ANTHROPIC_SERVER_URL",
        "ANTHROPIC_SECRET", "ANTHROPIC_BEARER", "ANTHROPIC_PASSWORD",
        "OPENAI_API_HOST",
    ):
        env = _env_with(key, "sk-ant-poison-12345")
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"{key} credential survived sanitization — a provider-credential "
            "spelling variant leaked to the candidate env"
        )


def test_provider_credential_suffixes_are_stripped() -> None:
    """Adversarial: real gateway credential env vars use _ACCESS_KEY /
    _CREDENTIAL / _CRED / _SECRET_KEY spellings the prior suffix set missed
    (ANTHROPIC_ACCESS_KEY, ANTHROPIC_CREDENTIAL, AWS_SECRET_ACCESS_KEY,
    VERTEX_CREDENTIAL).  (ELITE-2 verdict round-5 fix.)"""
    for key in (
        "ANTHROPIC_ACCESS_KEY", "ANTHROPIC_CREDENTIAL", "ANTHROPIC_CRED",
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "VERTEX_CREDENTIAL",
        "GCP_CREDENTIAL", "BEDROCK_CRED",
    ):
        env = _env_with(key, "AKIA-poison-12345")
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"{key} credential survived sanitization — a gateway-credential "
            "spelling variant leaked to the candidate env"
        )


def test_mixed_case_provider_url_key_is_stripped_case_insensitive() -> None:
    """Adversarial: the suffix match MUST be case-insensitive.  A mixed-case
    *_base_url / *_api_key key carrying a public host must be stripped just
    like its ALL-CAPS twin — the host's naming convention is not a security
    dependency.  The prior str.endswith was case-sensitive and the code
    comment falsely claimed case-insensitivity, so Anthropic_Base_Url /
    anthropic_base_url leaked untouched.  (ELITE-2 verdict round-5 fix.)"""
    for key in (
        "Anthropic_Base_Url", "anthropic_base_url",
        "GEMINI_base_url", "OpenAI_API_KEY", "openai_api_key",
        "Claude_Code_OAuth_Token", "ANTHROPIC_Secret", "Anthropic_Access_Key",
        "OpenAI_Credential", "aws_Secret_Access_Key",
    ):
        env = _env_with(key, "https://poison.example.com")
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"mixed-case {key} with a public host survived sanitization — the "
            "case-sensitive suffix match leaked the credential to the candidate"
        )


def test_mixed_case_loopback_provider_url_is_preserved() -> None:
    """Symmetric to the above: a mixed-case *_base_url whose value IS loopback
    must SURVIVE (it is the trusted synthetic endpoint).  Case-insensitive
    matching must not over-strip loopback endpoints.  (ELITE-2 verdict
    round-5 fix.)"""
    for key in ("Anthropic_Base_Url", "anthropic_base_url", "GEMINI_base_url"):
        env = _env_with(key, "http://127.0.0.1:1234")
        _sanitize_required_provider_environment(env)
        assert key in env, (
            f"loopback {key} was stripped — the trusted synthetic endpoint "
            "was removed by the case-insensitive suffix match"
        )


def test_bare_suffix_credential_keys_are_stripped() -> None:
    """Adversarial: real gateways also use bare _URL / _KEY / _PROXY / _APIKEY
    spellings the prior suffix set missed — ANTHROPIC_URL,
    ANTHROPIC_KEY=sk-ant-..., ANTHROPIC_PROXY, OPENAI_KEY, OPENAI_APIKEY.  A
    public-valued bare-suffix key is a credential/endpoint leak and must be
    stripped.  (ELITE-2 verdict round-6 fix.)"""
    for key, val in (
        ("ANTHROPIC_URL", "https://api.anthropic.com"),
        ("ANTHROPIC_KEY", "sk-ant-poison-12345"),
        ("ANTHROPIC_PROXY", "http://gateway.example.com:8080"),
        ("OPENAI_KEY", "sk-poison"),
        ("OPENAI_APIKEY", "sk-poison"),
        ("CLAUDE_URL", "https://api.anthropic.com"),
        ("CLAUDE_PROXY", "http://gateway.example.com"),
    ):
        env = _env_with(key, val)
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"bare-suffix {key}={val!r} survived sanitization — the credential/"
            "endpoint leaked to the candidate env"
        )


def test_bare_suffix_loopback_url_is_preserved() -> None:
    """A bare _URL whose value IS loopback (the trusted synthetic endpoint)
    must survive — the case-insensitive suffix match must not over-strip the
    candidate's own loopback gateway.  (ELITE-2 verdict round-6 fix.)"""
    for key in ("ANTHROPIC_URL", "CLAUDE_URL", "OPENAI_URL"):
        env = _env_with(key, "http://127.0.0.1:1234")
        _sanitize_required_provider_environment(env)
        assert key in env, (
            f"loopback bare-suffix {key} was stripped — the trusted synthetic "
            "endpoint was removed"
        )


def test_numeric_loopback_encodings_normalized_and_preserved() -> None:
    """Adversarial: a host could write a loopback URL in a non-canonical
    numeric encoding (0x7f000001, 127.1, 127.0.1.2, 0177.0.0.1) to evade a naive
    '127.0.0.1'/'localhost' check and either (a) get a public-URL stripped by
    being treated as non-loopback, or (b) sneak a non-loopback through.  The
    loopback detector must normalize ALL encodings and treat them as loopback
    consistently.  (ELITE-2 verdict round-6 fix: numeric encoding gap.)"""
    from src.agents.runtime import _provider_url_is_loopback
    for url in (
        "http://127.0.0.1:1234", "http://0x7f000001:1234", "http://127.1:1234",
        "http://127.0.1.2:1234", "http://0177.0.0.1:1234", "http://[::1]:1234",
        "http://localhost:1234",
    ):
        assert _provider_url_is_loopback(url) is True, (
            f"loopback encoding {url!r} was NOT detected as loopback — a host "
            f"could evade the loopback carve-out with a non-canonical encoding"
        )
    # Non-loopback must still be False — no false positives.
    for url in ("http://8.8.8.8:1234", "https://api.anthropic.com", "http://10.0.0.1"):
        assert _provider_url_is_loopback(url) is False, (
            f"non-loopback {url!r} was misdetected as loopback"
        )


def test_credential_file_path_suffixes_are_stripped() -> None:
    """ELITE-2 verdict round-7: keys whose value is a PATH to a credential file
    (ANTHROPIC_API_KEY_FILE, GOOGLE_APPLICATION_CREDENTIALS, *_CREDENTIALS_FILE)
    leak the file path into the candidate env, revealing where a secret lives
    on the host.  Even if the file itself is masked, the path is a
    credential-bearing spelling that must be stripped by F1.
    """
    for key, val in (
        ("ANTHROPIC_API_KEY_FILE", "/run/secrets/anthropic_key"),
        ("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/service-account.json"),
        ("ANTHROPIC_CREDENTIALS", "/home/ubuntu/.config/anthropic/creds.json"),
        ("ANTHROPIC_CREDENTIALS_FILE", "/etc/anthropic/creds.json"),
        ("GCP_SERVICE_ACCOUNT", "/etc/gcp/sa.json"),
    ):
        env = _env_with(key, val)
        _sanitize_required_provider_environment(env)
        assert key not in env, (
            f"credential-file-path key {key}={val!r} survived sanitization — "
            f"the credential file path leaked to the candidate env"
        )


# --- F2 tautology fix (ELITE-2 verdict round-7) ------------------------------
# The prior F2 matrix tested the sanitizer against the SUFFIX TUPLE defined in
# the same module (runtime.py) by the same author — so a suffix the author forgot
# in BOTH the sanitizer and the test would never be caught.  The corpus below is
# an INDEPENDENT list of real-world credential-bearing env-var names, maintained
# here in the test file, derived from public provider docs / SDK conventions
# rather than from runtime.py's suffix tuple.  The fuzz test drives the
# sanitizer with each name and asserts it is stripped — so a suffix forgotten in
# both places still surfaces as a leaked key here.  (The corpus is deliberately
# broader than any single suffix tuple; it is the independent oracle F2 lacked.)
_INDEPENDENT_CREDENTIAL_KEY_CORPUS = (
    # Anthropic / Claude family
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY_FILE", "ANTHROPIC_CREDENTIALS",
    "CLAUDE_API_BASE", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_API_TOKEN",
    "ANTHROPIC_ACCESS_KEY", "ANTHROPIC_SECRET_KEY", "ANTHROPIC_CREDENTIAL",
    # OpenAI / Codex family
    "OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_API_BASE",
    # Google / Vertex / GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT",
    "VERTEX_API_KEY", "GOOGLE_API_KEY", "GCLOUD_API_KEY_FILE",
    # AWS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN", "AWS_CREDENTIAL_FILE",
    # Azure
    "AZURE_CLIENT_SECRET", "AZURE_API_KEY",
    # Generic gateway / proxy spellings
    "PROVIDER_BASE_URL", "MODEL_BASE_URL", "LLM_BASE_URL",
    "API_KEY", "API_TOKEN", "API_SECRET",
    "MODEL_API_KEY", "INFERENCE_API_KEY",
    # Hugging Face / Cohere / Mistral / Bedrock
    "HF_TOKEN", "HUGGING_FACE_TOKEN", "COHERE_API_KEY",
    "MISTRAL_API_KEY", "BEDROCK_API_KEY",
    # NOTE: OPENAI_ORGANIZATION and AZURE_TENANT_ID are NON-secret identifiers
    # (org/tenant GUIDs), not credentials — deliberately excluded so the corpus
    # does not demand stripping of non-credential config.  APIKEY (bare, no
    # prefix) is excluded too: the suffix-based design keys off a provider-
    # prefixed spelling; a prefix-less bare key would false-positive on any
    # short env var ending in those chars.
)


def test_independent_credential_corpus_all_stripped() -> None:
    """F2 tautology fix (ELITE-2 verdict round-7).

    Drive _sanitize_required_provider_environment with an INDEPENDENT corpus of
    real-world credential-bearing env-var names (maintained in this test file,
    NOT derived from runtime.py's suffix tuple) carrying a public/secret value,
    and assert every one is stripped.  This catches a suffix forgotten in BOTH
    the sanitizer and the prior co-derived test matrix — the class of gap the
    verdict flagged as F2's suffix-vs-suffix tautology.  A failure here means a
    real credential spelling leaks because it is absent from runtime.py's suffix
    set AND from the test corpus, i.e. the independent oracle caught a true gap.
    """
    leaked: list[str] = []
    for key in _INDEPENDENT_CREDENTIAL_KEY_CORPUS:
        val = "sk-ant-poison-DEADBEEF" if "KEY" in key or "TOKEN" in key or "SECRET" in key or "CRED" in key else "https://poison.example.com"
        env = _env_with(key, val)
        _sanitize_required_provider_environment(env)
        if key in env:
            leaked.append(key)
    assert not leaked, (
        "independent credential corpus leaked keys that the co-derived F2 "
        f"matrix could never catch: {leaked}"
    )
