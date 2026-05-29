"""Composable prompt transformation converters for filter bypass testing."""

from __future__ import annotations

import base64
import codecs
import json
from abc import ABC, abstractmethod
from typing import ClassVar


class BaseConverter(ABC):
    """Abstract base for all prompt converters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique converter name used for registry lookup."""

    @abstractmethod
    def convert(self, text: str) -> str:
        """Transform *text* and return the result."""

    def __or__(self, other: BaseConverter | ConverterChain) -> ConverterChain:
        if isinstance(other, ConverterChain):
            return ConverterChain([self, *other.converters])
        return ConverterChain([self, other])

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class ConverterChain(BaseConverter):
    """Applies a sequence of converters left-to-right."""

    def __init__(self, converters: list[BaseConverter]) -> None:
        self.converters = list(converters)

    @property
    def name(self) -> str:
        return " | ".join(c.name for c in self.converters)

    def convert(self, text: str) -> str:
        for converter in self.converters:
            text = converter.convert(text)
        return text

    def __or__(self, other: BaseConverter | ConverterChain) -> ConverterChain:
        if isinstance(other, ConverterChain):
            return ConverterChain([*self.converters, *other.converters])
        return ConverterChain([*self.converters, other])

    def __repr__(self) -> str:
        inner = " | ".join(repr(c) for c in self.converters)
        return f"ConverterChain({inner})"

    def __len__(self) -> int:
        return len(self.converters)


# ---------------------------------------------------------------------------
# Built-in converters
# ---------------------------------------------------------------------------


class Base64Converter(BaseConverter):
    """Encode text to base64."""

    @property
    def name(self) -> str:
        return "base64"

    def convert(self, text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")


class Base64DecodeConverter(BaseConverter):
    """Decode base64 back to text."""

    @property
    def name(self) -> str:
        return "base64_decode"

    def convert(self, text: str) -> str:
        return base64.b64decode(text.encode("ascii")).decode("utf-8")


class ROT13Converter(BaseConverter):
    """Apply ROT13 cipher (self-inverse)."""

    @property
    def name(self) -> str:
        return "rot13"

    def convert(self, text: str) -> str:
        return codecs.encode(text, "rot_13")


class LeetSpeakConverter(BaseConverter):
    """Replace characters with leet equivalents."""

    TABLE: ClassVar[dict[str, str]] = {
        "a": "4",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "5",
        "t": "7",
        "l": "1",
        "g": "9",
        "A": "4",
        "E": "3",
        "I": "1",
        "O": "0",
        "S": "5",
        "T": "7",
        "L": "1",
        "G": "9",
    }

    @property
    def name(self) -> str:
        return "leetspeak"

    def convert(self, text: str) -> str:
        return "".join(self.TABLE.get(c, c) for c in text)


class UnicodeHomoglyphConverter(BaseConverter):
    """Replace ASCII chars with visually similar Unicode chars."""

    TABLE: ClassVar[dict[str, str]] = {
        "a": "\u0430",  # Cyrillic а
        "c": "\u0441",  # Cyrillic с
        "e": "\u0435",  # Cyrillic е
        "o": "\u043e",  # Cyrillic о
        "p": "\u0440",  # Cyrillic р
        "x": "\u0445",  # Cyrillic х
        "y": "\u0443",  # Cyrillic у
        "A": "\u0410",  # Cyrillic А
        "B": "\u0412",  # Cyrillic В
        "C": "\u0421",  # Cyrillic С
        "E": "\u0415",  # Cyrillic Е
        "H": "\u041d",  # Cyrillic Н
        "K": "\u041a",  # Cyrillic К
        "M": "\u041c",  # Cyrillic М
        "O": "\u041e",  # Cyrillic О
        "P": "\u0420",  # Cyrillic Р
        "T": "\u0422",  # Cyrillic Т
        "X": "\u0425",  # Cyrillic Х
    }

    @property
    def name(self) -> str:
        return "unicode_homoglyph"

    def convert(self, text: str) -> str:
        return "".join(self.TABLE.get(c, c) for c in text)


class ReverseConverter(BaseConverter):
    """Reverse the string."""

    @property
    def name(self) -> str:
        return "reverse"

    def convert(self, text: str) -> str:
        return text[::-1]


class CamelCaseConverter(BaseConverter):
    """Join words in camelCase."""

    @property
    def name(self) -> str:
        return "camelcase"

    def convert(self, text: str) -> str:
        words = text.split()
        if not words:
            return ""
        return words[0].lower() + "".join(w.capitalize() for w in words[1:])


class CharSplitConverter(BaseConverter):
    """Insert a separator between every character.

    Default separator is ``"."`` but can be customised.
    """

    def __init__(self, separator: str = ".") -> None:
        self.separator = separator

    @property
    def name(self) -> str:
        return "charsplit"

    def convert(self, text: str) -> str:
        return self.separator.join(text)

    def __repr__(self) -> str:
        return f"CharSplitConverter(separator={self.separator!r})"


class MarkdownWrapConverter(BaseConverter):
    """Wrap text in a markdown fenced code block."""

    def __init__(self, language: str = "") -> None:
        self.language = language

    @property
    def name(self) -> str:
        return "markdown_wrap"

    def convert(self, text: str) -> str:
        return f"```{self.language}\n{text}\n```"

    def __repr__(self) -> str:
        return f"MarkdownWrapConverter(language={self.language!r})"


class JSONWrapConverter(BaseConverter):
    """Wrap text as a JSON string value under key ``"prompt"``."""

    def __init__(self, key: str = "prompt") -> None:
        self.key = key

    @property
    def name(self) -> str:
        return "json_wrap"

    def convert(self, text: str) -> str:
        return json.dumps({self.key: text})

    def __repr__(self) -> str:
        return f"JSONWrapConverter(key={self.key!r})"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_BUILTIN_CONVERTERS: list[BaseConverter] = [
    Base64Converter(),
    Base64DecodeConverter(),
    ROT13Converter(),
    LeetSpeakConverter(),
    UnicodeHomoglyphConverter(),
    ReverseConverter(),
    CamelCaseConverter(),
    CharSplitConverter(),
    MarkdownWrapConverter(),
    JSONWrapConverter(),
]


class ConverterRegistry:
    """Central registry for converter look-up and chain building."""

    def __init__(self, *, populate_builtins: bool = True) -> None:
        self._converters: dict[str, BaseConverter] = {}
        if populate_builtins:
            for c in _BUILTIN_CONVERTERS:
                self.register(c)

    def register(self, converter: BaseConverter) -> None:
        """Register a converter (overwrites if name already exists)."""
        self._converters[converter.name] = converter

    def get(self, name: str) -> BaseConverter:
        """Look up a converter by name. Raises *KeyError* if not found."""
        try:
            return self._converters[name]
        except KeyError:
            raise KeyError(
                f"Converter {name!r} not found. "
                f"Available: {', '.join(sorted(self._converters))}"
            ) from None

    def list_converters(self) -> list[str]:
        """Return sorted list of registered converter names."""
        return sorted(self._converters)

    def build_chain(self, names: list[str]) -> ConverterChain:
        """Build a :class:`ConverterChain` from a list of converter names."""
        return ConverterChain([self.get(n) for n in names])

    def __len__(self) -> int:
        return len(self._converters)

    def __contains__(self, name: str) -> bool:
        return name in self._converters
