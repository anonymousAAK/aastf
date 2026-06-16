"""Tests for secret redaction in trace/report serialization."""
from __future__ import annotations

from aastf.redaction import PLACEHOLDER, redact_secrets, redact_text


class TestRedactText:
    def test_openai_style_key(self):
        out = redact_text("key is sk-abcdefghijklmnop1234567890 here")
        assert "sk-abcdefghijklmnop" not in out
        assert PLACEHOLDER in out

    def test_aws_access_key(self):
        assert "AKIA" not in redact_text("AKIAIOSFODNN7EXAMPLE")

    def test_github_pat(self):
        out = redact_text("token ghp_" + "a" * 36)
        assert "ghp_" not in out

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiI.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4"
        assert jwt not in redact_text(f"auth={jwt}")

    def test_bearer_token(self):
        assert "abcdef1234567890ABCDEF" not in redact_text("Bearer abcdef1234567890ABCDEF")

    def test_pem_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg\n-----END PRIVATE KEY-----"
        out = redact_text(pem)
        assert "MIIBVgIBADANBg" not in out
        assert PLACEHOLDER in out

    def test_key_value_pair(self):
        out = redact_text('password = "hunter2supersecret"')
        assert "hunter2supersecret" not in out

    def test_clean_text_unchanged(self):
        clean = "This is a normal finding description with no secrets."
        assert redact_text(clean) == clean

    def test_empty_string(self):
        assert redact_text("") == ""

    def test_aggressive_entropy(self):
        token = "Zk9xQ2pW7mNbV3cX1aS5dF8gH0jK2lP4oR6tY9uI"  # high entropy
        assert token in redact_text(f"val {token}")  # not redacted without aggressive
        assert token not in redact_text(f"val {token}", aggressive=True)


class TestRedactSecrets:
    def test_sensitive_key_blanked(self):
        out = redact_secrets({"api_key": "anything-at-all", "name": "ok"})
        assert out["api_key"] == PLACEHOLDER
        assert out["name"] == "ok"

    def test_nested_structure(self):
        data = {"outer": {"password": "x", "items": ["sk-abcdefghijklmnop1234567890"]}}
        out = redact_secrets(data)
        assert out["outer"]["password"] == PLACEHOLDER
        assert PLACEHOLDER in out["outer"]["items"][0]

    def test_non_string_scalars_unchanged(self):
        data = {"count": 5, "ratio": 1.5, "ok": True, "none": None}
        assert redact_secrets(data) == data

    def test_list_of_strings(self):
        out = redact_secrets(["clean", "Bearer abcdef1234567890ABCDEF"])
        assert out[0] == "clean"
        assert PLACEHOLDER in out[1]
