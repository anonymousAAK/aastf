"""Secret redaction for trace/report serialization.

Agent traces captured during scanning can contain API keys, tokens, or other
secrets. This module scrubs credential-like strings from text and nested data
structures so secrets are never persisted into reports, logs, or storage.

Two entry points:

- :func:`redact_text` — redact secrets in a single string (e.g. a serialized
  JSON report) in place. A no-op on content with no credential-like substrings.
- :func:`redact_secrets` — recursively redact a JSON-like structure (dict/list/
  str), additionally blanking any value whose *key name* looks sensitive
  (``password``, ``api_key``, ``authorization``, ...).

Patterns are deliberately credential-focused (not generic PII) to avoid
mangling legitimate report content. ``aggressive=True`` additionally redacts
long high-entropy tokens.
"""
from __future__ import annotations

import math
import re
from typing import Any

PLACEHOLDER = "[REDACTED]"

# Key names whose values are always redacted in structured data.
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey",
    "api-key", "token", "access_token", "refresh_token", "id_token", "auth",
    "authorization", "private_key", "secret_key", "aws_secret_access_key",
    "session_token", "cookie", "set-cookie",
})

# High-confidence credential value patterns.
_PATTERNS: list[re.Pattern[str]] = [
    # PEM private key blocks (multi-line).
    re.compile(
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    # OpenAI / Stripe style: sk-..., sk_live_..., pk_live_..., rk_test_...
    re.compile(r"\b[spr]k[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{16,}\b"),
    # AWS access key id.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # GitHub tokens.
    re.compile(r"\bgh[posru]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    # Slack tokens.
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # Google API key.
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # JWT (three base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # Bearer tokens in Authorization headers.
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
]

# key=value / key: value where the key name is sensitive (redacts the value).
_KV_PATTERN = re.compile(
    r"(?i)(\b(?:" + "|".join(re.escape(k) for k in _SENSITIVE_KEYS) + r")\b\s*[=:]\s*['\"]?)"
    r"([^'\"\s,}]{6,})",
)

# Long high-entropy token (aggressive mode only).
_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+/=_\-]{32,}\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact_text(text: str, *, aggressive: bool = False) -> str:
    """Return ``text`` with credential-like substrings replaced by a placeholder."""
    if not text:
        return text
    redacted = text
    for pattern in _PATTERNS:
        redacted = pattern.sub(PLACEHOLDER, redacted)
    redacted = _KV_PATTERN.sub(lambda m: m.group(1) + PLACEHOLDER, redacted)
    if aggressive:
        redacted = _ENTROPY_TOKEN.sub(
            lambda m: PLACEHOLDER if _shannon_entropy(m.group(0)) >= 4.0 else m.group(0),
            redacted,
        )
    return redacted


def redact_secrets(value: Any, *, aggressive: bool = False) -> Any:
    """Recursively redact secrets in a JSON-like structure.

    - strings are passed through :func:`redact_text`;
    - dict values are recursed, but any value under a sensitive key name is
      blanked entirely regardless of its content;
    - lists/tuples are recursed element-wise.
    Non-string scalars (int/float/bool/None) are returned unchanged.
    """
    if isinstance(value, str):
        return redact_text(value, aggressive=aggressive)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                out[k] = PLACEHOLDER
            else:
                out[k] = redact_secrets(v, aggressive=aggressive)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_secrets(v, aggressive=aggressive) for v in value]
    return value
