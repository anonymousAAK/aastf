"""Tests for the composable prompt converter pipeline."""

from __future__ import annotations

import base64
import json

import pytest

from aastf.converters import (
    Base64Converter,
    Base64DecodeConverter,
    BaseConverter,
    CamelCaseConverter,
    CharSplitConverter,
    ConverterChain,
    ConverterRegistry,
    JSONWrapConverter,
    LeetSpeakConverter,
    MarkdownWrapConverter,
    ReverseConverter,
    ROT13Converter,
    UnicodeHomoglyphConverter,
)

# ── Base64 ──────────────────────────────────────────────────────────────────

class TestBase64Converter:
    def test_encode_simple(self):
        c = Base64Converter()
        assert c.convert("hello") == base64.b64encode(b"hello").decode()

    def test_name(self):
        assert Base64Converter().name == "base64"

    def test_encode_empty(self):
        assert Base64Converter().convert("") == ""

    def test_encode_unicode(self):
        result = Base64Converter().convert("cafe\u0301")
        decoded = base64.b64decode(result).decode("utf-8")
        assert decoded == "cafe\u0301"


class TestBase64DecodeConverter:
    def test_decode_simple(self):
        encoded = base64.b64encode(b"world").decode()
        assert Base64DecodeConverter().convert(encoded) == "world"

    def test_name(self):
        assert Base64DecodeConverter().name == "base64_decode"


# ── Round-trip: base64 ─────────────────────────────────────────────────────

class TestBase64RoundTrip:
    @pytest.mark.parametrize("text", ["hello", "", "special chars !@#$%", "unicode: \u00e9\u00e8\u00ea"])
    def test_roundtrip(self, text):
        chain = Base64Converter() | Base64DecodeConverter()
        assert chain.convert(text) == text


# ── ROT13 ──────────────────────────────────────────────────────────────────

class TestROT13Converter:
    def test_alpha(self):
        assert ROT13Converter().convert("hello") == "uryyb"

    def test_name(self):
        assert ROT13Converter().name == "rot13"

    def test_non_alpha_unchanged(self):
        assert ROT13Converter().convert("123!@#") == "123!@#"

    def test_roundtrip(self):
        c = ROT13Converter()
        assert c.convert(c.convert("Attack!")) == "Attack!"

    def test_empty(self):
        assert ROT13Converter().convert("") == ""


# ── LeetSpeak ──────────────────────────────────────────────────────────────

class TestLeetSpeakConverter:
    def test_basic(self):
        result = LeetSpeakConverter().convert("aest")
        assert result == "4357"

    def test_name(self):
        assert LeetSpeakConverter().name == "leetspeak"

    def test_preserves_non_mapped(self):
        result = LeetSpeakConverter().convert("b d f")
        assert result == "b d f"

    def test_uppercase(self):
        result = LeetSpeakConverter().convert("AEST")
        assert result == "4357"

    def test_empty(self):
        assert LeetSpeakConverter().convert("") == ""


# ── Unicode Homoglyph ─────────────────────────────────────────────────────

class TestUnicodeHomoglyphConverter:
    def test_replaces_a(self):
        result = UnicodeHomoglyphConverter().convert("a")
        assert result == "\u0430"
        assert result != "a"  # visually same, different codepoint

    def test_name(self):
        assert UnicodeHomoglyphConverter().name == "unicode_homoglyph"

    def test_preserves_non_mapped(self):
        assert UnicodeHomoglyphConverter().convert("123") == "123"

    def test_empty(self):
        assert UnicodeHomoglyphConverter().convert("") == ""

    def test_mixed(self):
        result = UnicodeHomoglyphConverter().convert("ace")
        assert result == "\u0430\u0441\u0435"


# ── Reverse ────────────────────────────────────────────────────────────────

class TestReverseConverter:
    def test_basic(self):
        assert ReverseConverter().convert("hello") == "olleh"

    def test_name(self):
        assert ReverseConverter().name == "reverse"

    def test_empty(self):
        assert ReverseConverter().convert("") == ""

    def test_roundtrip(self):
        c = ReverseConverter()
        assert c.convert(c.convert("test")) == "test"

    def test_palindrome(self):
        assert ReverseConverter().convert("racecar") == "racecar"


# ── CamelCase ──────────────────────────────────────────────────────────────

class TestCamelCaseConverter:
    def test_basic(self):
        assert CamelCaseConverter().convert("hello world foo") == "helloWorldFoo"

    def test_name(self):
        assert CamelCaseConverter().name == "camelcase"

    def test_single_word(self):
        assert CamelCaseConverter().convert("hello") == "hello"

    def test_empty(self):
        assert CamelCaseConverter().convert("") == ""

    def test_uppercase_input(self):
        assert CamelCaseConverter().convert("HELLO WORLD") == "helloWorld"


# ── CharSplit ──────────────────────────────────────────────────────────────

class TestCharSplitConverter:
    def test_default_dot(self):
        assert CharSplitConverter().convert("hello") == "h.e.l.l.o"

    def test_name(self):
        assert CharSplitConverter().name == "charsplit"

    def test_custom_separator(self):
        assert CharSplitConverter(" ").convert("hi") == "h i"

    def test_empty(self):
        assert CharSplitConverter().convert("") == ""

    def test_single_char(self):
        assert CharSplitConverter().convert("x") == "x"

    def test_repr(self):
        assert "separator" in repr(CharSplitConverter("-"))


# ── MarkdownWrap ───────────────────────────────────────────────────────────

class TestMarkdownWrapConverter:
    def test_basic(self):
        result = MarkdownWrapConverter().convert("code")
        assert result == "```\ncode\n```"

    def test_name(self):
        assert MarkdownWrapConverter().name == "markdown_wrap"

    def test_with_language(self):
        result = MarkdownWrapConverter("python").convert("print(1)")
        assert result == "```python\nprint(1)\n```"

    def test_empty(self):
        result = MarkdownWrapConverter().convert("")
        assert result == "```\n\n```"


# ── JSONWrap ───────────────────────────────────────────────────────────────

class TestJSONWrapConverter:
    def test_basic(self):
        result = JSONWrapConverter().convert("hello")
        assert json.loads(result) == {"prompt": "hello"}

    def test_name(self):
        assert JSONWrapConverter().name == "json_wrap"

    def test_custom_key(self):
        result = JSONWrapConverter("input").convert("test")
        assert json.loads(result) == {"input": "test"}

    def test_special_chars_escaped(self):
        result = JSONWrapConverter().convert('he said "hi"\nnewline')
        parsed = json.loads(result)
        assert parsed["prompt"] == 'he said "hi"\nnewline'

    def test_empty(self):
        result = JSONWrapConverter().convert("")
        assert json.loads(result) == {"prompt": ""}


# ── ConverterChain ─────────────────────────────────────────────────────────

class TestConverterChain:
    def test_pipe_creates_chain(self):
        chain = Base64Converter() | ROT13Converter()
        assert isinstance(chain, ConverterChain)
        assert len(chain) == 2

    def test_chain_applies_in_order(self):
        chain = ROT13Converter() | ReverseConverter()
        result = chain.convert("ab")
        # ROT13("ab") = "no", reversed = "on"
        assert result == "on"

    def test_chain_pipe_extends(self):
        c1 = ROT13Converter() | ReverseConverter()
        c2 = c1 | Base64Converter()
        assert len(c2) == 3

    def test_chain_pipe_chain(self):
        c1 = ROT13Converter() | ReverseConverter()
        c2 = Base64Converter() | LeetSpeakConverter()
        c3 = c1 | c2
        assert len(c3) == 4

    def test_converter_pipe_chain(self):
        chain = Base64Converter() | ROT13Converter()
        result = ReverseConverter() | chain
        assert len(result) == 3

    def test_chain_name(self):
        chain = ROT13Converter() | ReverseConverter()
        assert chain.name == "rot13 | reverse"

    def test_chain_repr(self):
        chain = ROT13Converter() | ReverseConverter()
        r = repr(chain)
        assert "ConverterChain" in r
        assert "ROT13Converter" in r

    def test_empty_chain(self):
        chain = ConverterChain([])
        assert chain.convert("hello") == "hello"

    def test_single_element_chain(self):
        chain = ConverterChain([ReverseConverter()])
        assert chain.convert("abc") == "cba"


# ── ConverterRegistry ─────────────────────────────────────────────────────

class TestConverterRegistry:
    def test_builtins_populated(self):
        reg = ConverterRegistry()
        assert len(reg) == 10

    def test_list_converters(self):
        reg = ConverterRegistry()
        names = reg.list_converters()
        assert "base64" in names
        assert "rot13" in names
        assert names == sorted(names)

    def test_get_existing(self):
        reg = ConverterRegistry()
        c = reg.get("rot13")
        assert isinstance(c, ROT13Converter)

    def test_get_missing_raises(self):
        reg = ConverterRegistry()
        with pytest.raises(KeyError, match="not_real"):
            reg.get("not_real")

    def test_register_custom(self):
        reg = ConverterRegistry()

        class UpperConverter(BaseConverter):
            @property
            def name(self) -> str:
                return "upper"

            def convert(self, text: str) -> str:
                return text.upper()

        reg.register(UpperConverter())
        assert "upper" in reg
        assert reg.get("upper").convert("hi") == "HI"

    def test_register_overwrites(self):
        reg = ConverterRegistry()
        reg.get("rot13")  # ensure it exists before overwrite
        reg.register(ReverseConverter.__new__(ReverseConverter))
        # Still has same count because reverse already exists
        # but let's test explicit overwrite with a renamed one
        class FakeROT13(BaseConverter):
            @property
            def name(self) -> str:
                return "rot13"

            def convert(self, text: str) -> str:
                return text.upper()

        reg.register(FakeROT13())
        assert reg.get("rot13").convert("hi") == "HI"

    def test_build_chain(self):
        reg = ConverterRegistry()
        chain = reg.build_chain(["rot13", "reverse"])
        assert isinstance(chain, ConverterChain)
        assert len(chain) == 2
        assert chain.convert("ab") == "on"

    def test_build_chain_missing_raises(self):
        reg = ConverterRegistry()
        with pytest.raises(KeyError):
            reg.build_chain(["rot13", "nonexistent"])

    def test_contains(self):
        reg = ConverterRegistry()
        assert "base64" in reg
        assert "nonexistent" not in reg

    def test_no_builtins(self):
        reg = ConverterRegistry(populate_builtins=False)
        assert len(reg) == 0

    def test_build_empty_chain(self):
        reg = ConverterRegistry()
        chain = reg.build_chain([])
        assert chain.convert("hello") == "hello"


# ── Abstract base ─────────────────────────────────────────────────────────

class TestBaseConverter:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseConverter()  # type: ignore[abstract]

    def test_repr(self):
        c = ReverseConverter()
        assert repr(c) == "ReverseConverter()"
