"""Tests for outbound-URL scheme validation (SSRF / local-file-read hardening)."""

from __future__ import annotations

import pytest

from aastf.netsec import UnsafeURLError, validate_outbound_url


class TestValidateOutboundURL:
    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/webhook",
            "https://hooks.slack.com/services/x/y/z",
            "http://127.0.0.1:8080/hook",  # internal is allowed (operator's choice)
        ],
    )
    def test_allows_http_and_https(self, url: str):
        assert validate_outbound_url(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "ftp://internal/secret",
            "gopher://169.254.169.254/",
            "file://localhost/etc/shadow",
        ],
    )
    def test_rejects_dangerous_schemes(self, url: str):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url(url)

    def test_rejects_hostless_url(self):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("http:///nohost")


class TestAlertingHonorsValidation:
    def test_http_post_refuses_file_scheme(self):
        from aastf.alerting import _http_post

        # Returns 0 (failure) without ever opening the file:// URL.
        assert _http_post("file:///etc/passwd", {"x": 1}) == 0
