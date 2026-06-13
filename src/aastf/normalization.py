"""Evasion-resistant text normalization for detection.

Attackers obfuscate forbidden payloads to slip past naive substring matching:
homoglyph (Cyrillic/Greek lookalikes), zero-width characters, mixed casing,
and encodings (base64, hex, percent/URL, ROT13). This module exposes:

- ``normalize_text`` — Unicode NFKC + confusable folding + lowercase +
  zero-width/whitespace stripping, producing a canonical comparison form.
- decoder helpers (``decode_base64_segments`` etc.) that surface the *decoded*
  content of obfuscated blobs so it can be scanned with the same rules.
- ``scan_variants`` — every normalized representation of a string worth
  scanning (the text itself plus any decoded payloads), and
  ``contains_normalized`` — a drop-in "needle in haystack" check that is robust
  to all of the above.

Stdlib only. These helpers only ever ADD candidate match surfaces; callers keep
their existing checks and fall back to these for additional coverage.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# --------------------------------------------------------------------------- #
# Confusable / homoglyph folding
# --------------------------------------------------------------------------- #

# Map of common Cyrillic and Greek (and a few symbol) lookalikes to their ASCII
# counterparts. NFKC already handles many compatibility forms; this table covers
# script-confusables that NFKC deliberately leaves alone (they are distinct
# characters), which is exactly what attackers exploit.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase lookalikes
    "а": "a",  # а
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "с": "c",  # с
    "у": "y",  # у
    "х": "x",  # х
    "і": "i",  # і
    "ј": "j",  # ј
    "һ": "h",  # һ
    "ԁ": "d",  # ԁ
    "ԛ": "q",  # ԛ
    "ԝ": "w",  # ԝ
    "ո": "n",  # Armenian ո (n-like)
    "ց": "g",  # Armenian, occasionally abused
    "ɡ": "g",  # ɡ latin small script g
    "ɱ": "m",  # ɱ
    # Cyrillic uppercase lookalikes
    "А": "a",  # А
    "В": "b",  # В
    "Е": "e",  # Е
    "К": "k",  # К
    "М": "m",  # М
    "Н": "h",  # Н
    "О": "o",  # О
    "Р": "p",  # Р
    "С": "c",  # С
    "Т": "t",  # Т
    "Х": "x",  # Х
    # Greek lookalikes
    "α": "a",  # α
    "ε": "e",  # ε
    "ι": "i",  # ι
    "ο": "o",  # ο
    "ρ": "p",  # ρ
    "υ": "u",  # υ
    "χ": "x",  # χ
    "Α": "a",  # Α
    "Β": "b",  # Β
    "Ε": "e",  # Ε
    "Η": "h",  # Η
    "Ι": "i",  # Ι
    "Κ": "k",  # Κ
    "Μ": "m",  # Μ
    "Ν": "n",  # Ν
    "Ο": "o",  # Ο
    "Ρ": "p",  # Ρ
    "Τ": "t",  # Τ
    "Χ": "x",  # Χ
    # Fullwidth / symbol confusables not always folded predictably
    "․": ".",  # ․ one-dot leader
    "⁄": "/",  # ⁄ fraction slash
    "∕": "/",  # ∕ division slash
}

_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}

# Zero-width and invisible formatting characters used to break up keywords.
_ZERO_WIDTH = (
    "​"  # zero width space
    "‌"  # zero width non-joiner
    "‍"  # zero width joiner
    "⁠"  # word joiner
    "﻿"  # zero width no-break space / BOM
    "­"  # soft hyphen
    "᠎"  # mongolian vowel separator
    "͏"  # combining grapheme joiner
)
_ZERO_WIDTH_TABLE = {ord(c): None for c in _ZERO_WIDTH}

_WHITESPACE_RE = re.compile(r"\s+")


def fold_confusables(s: str) -> str:
    """Replace known Cyrillic/Greek/symbol homoglyphs with ASCII equivalents."""
    return s.translate(_CONFUSABLE_TABLE)


def strip_zero_width(s: str) -> str:
    """Remove zero-width and invisible formatting characters."""
    return s.translate(_ZERO_WIDTH_TABLE)


def normalize_text(s: str) -> str:
    """Return an evasion-resistant canonical form of *s*.

    Steps: Unicode NFKC normalization, zero-width/invisible-char stripping,
    homoglyph/confusable folding to ASCII, lowercasing, and whitespace
    collapsing. The result is suitable for substring comparison against an
    equally-normalized needle.
    """
    if not s:
        return ""
    out = unicodedata.normalize("NFKC", s)
    out = strip_zero_width(out)
    out = fold_confusables(out)
    out = out.lower()
    out = _WHITESPACE_RE.sub(" ", out).strip()
    return out


# --------------------------------------------------------------------------- #
# Encoding decoders — surface obfuscated payloads for scanning
# --------------------------------------------------------------------------- #

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}){4,}")
_URL_ENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return printable / len(text)


def decode_base64_segments(s: str) -> list[str]:
    """Decode base64-looking blobs in *s*; return plausibly-textual results."""
    results: list[str] = []
    for blob in _BASE64_RE.findall(s):
        # Pad to a multiple of 4 so partial captures still decode.
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode(
                "utf-8", errors="ignore"
            )
        except (binascii.Error, ValueError):
            continue
        if decoded and _printable_ratio(decoded) >= 0.8:
            results.append(decoded)
    return results


def decode_hex_segments(s: str) -> list[str]:
    """Decode hex-encoded byte sequences in *s*; return plausibly-textual results."""
    results: list[str] = []
    for blob in _HEX_RE.findall(s):
        h = blob[2:] if blob.lower().startswith("0x") else blob
        if len(h) % 2:
            h = h[:-1]
        try:
            decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if decoded and _printable_ratio(decoded) >= 0.8:
            results.append(decoded)
    return results


def decode_url_encoded(s: str) -> list[str]:
    """Decode percent/URL-encoded sequences in *s*.

    Returns a whole-string decode (covers payloads where only some characters
    are escaped) plus each contiguous escaped run decoded on its own.
    """
    results: list[str] = []
    if "%" in s:
        try:
            from urllib.parse import unquote

            whole = unquote(s, errors="ignore")
            if whole and whole != s:
                results.append(whole)
        except (ValueError, TypeError):
            pass
    return results


def decode_rot13(s: str) -> list[str]:
    """Return the ROT13-decoded form of *s* (only if it differs)."""
    decoded = codecs.encode(s, "rot_13")
    return [decoded] if decoded != s else []


_BACKSLASH_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}")


def decode_backslash_escapes(s: str) -> list[str]:
    """Decode Python/JSON ``\\uXXXX`` / ``\\xXX`` escape sequences in *s*.

    Stringifying a dict of tool inputs (``str({...})``) escapes invisible and
    non-ASCII characters as literal ``\\u200b``-style text, which would otherwise
    defeat zero-width stripping and homoglyph folding. Re-interpreting those
    escapes surfaces the real characters for normalization. Only the escaped
    runs are decoded so legitimate backslashes elsewhere are preserved.
    """
    if "\\u" not in s and "\\x" not in s:
        return []

    def _sub(m: re.Match[str]) -> str:
        try:
            return codecs.decode(m.group(0), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return m.group(0)

    decoded = _BACKSLASH_ESCAPE_RE.sub(_sub, s)
    return [decoded] if decoded != s else []


def decoded_variants(s: str) -> list[str]:
    """All decoded representations of *s* across supported encodings."""
    if not s:
        return []
    variants: list[str] = []
    variants.extend(decode_backslash_escapes(s))
    variants.extend(decode_base64_segments(s))
    variants.extend(decode_hex_segments(s))
    variants.extend(decode_url_encoded(s))
    variants.extend(decode_rot13(s))
    return variants


# --------------------------------------------------------------------------- #
# Combined scanning surface
# --------------------------------------------------------------------------- #


def scan_variants(s: str) -> list[str]:
    """Every normalized string worth scanning for a forbidden needle.

    Includes the normalized original plus the normalized form of each decoded
    representation (base64/hex/url/rot13). De-duplicated, order preserved.
    """
    if not s:
        return []
    seen: set[str] = set()
    out: list[str] = []
    candidates = [s, *decoded_variants(s)]
    for cand in candidates:
        norm = normalize_text(cand)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def contains_normalized(haystack: str, needle: str) -> bool:
    """True if *needle* appears in any normalized/decoded variant of *haystack*.

    Robust to homoglyphs, zero-width chars, casing, and base64/hex/url/rot13
    obfuscation. Intended as an additive fallback alongside plain substring
    matching — it only ever reports *more* matches, never fewer.
    """
    if not haystack or not needle:
        return False
    norm_needle = normalize_text(needle)
    if not norm_needle:
        return False
    return any(norm_needle in variant for variant in scan_variants(haystack))


def first_match(haystack: str, needles: list[str]) -> str | None:
    """Return the first needle from *needles* that ``contains_normalized`` finds."""
    if not haystack:
        return None
    variants = scan_variants(haystack)
    if not variants:
        return None
    for needle in needles:
        norm_needle = normalize_text(needle)
        if not norm_needle:
            continue
        if any(norm_needle in variant for variant in variants):
            return needle
    return None
