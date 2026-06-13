"""Network-safety helpers for AASTF's outbound integrations.

Operator-supplied destinations (``--webhook-url``, ``sarif_endpoint``, Slack
URLs) are passed straight to ``urllib``. Python's default opener also enables
the ``file://`` and ``ftp://`` handlers, so an unvalidated value such as
``file:///etc/passwd`` turns a "send results to my webhook" feature into a
local-file read / SSRF probe. Restricting the scheme to http(s) removes that
vector while still allowing legitimate internal webhooks.
"""

from __future__ import annotations

from urllib.parse import urlparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class UnsafeURLError(ValueError):
    """Raised when an outbound URL uses a disallowed scheme."""


def validate_outbound_url(url: str) -> str:
    """Return ``url`` unchanged if it is an http(s) URL, else raise.

    Rejects ``file://``, ``ftp://``, ``gopher://`` and other non-web schemes
    (and empty/host-less URLs) that could be abused for local-file access or
    SSRF against non-web services.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(
            f"Refusing to use non-http(s) URL {url!r} "
            f"(scheme {parsed.scheme!r}); only http and https are allowed."
        )
    if not parsed.netloc:
        raise UnsafeURLError(f"Refusing to use URL without a host: {url!r}")
    return url
