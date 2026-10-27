"""Safety guardrails for the read-only staging API probe."""

from __future__ import annotations

import urllib.parse

PRODUCTION_HOSTS = {
    "neuralbridge.io",
    "www.neuralbridge.io",
    "assurance-register.fly.dev",
    "neuralbridge.vercel.app",
}


def validate_base_url(value: str) -> str:
    """Validate a staging URL and refuse known production hosts."""
    url = value.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"https", "http"} or not host:
        raise ValueError("Set a valid http(s) staging base URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "Credentials, query strings and fragments are not permitted in the base URL."
        )
    if host in PRODUCTION_HOSTS or host.endswith(".neuralbridge.io"):
        raise ValueError(f"Refusing known production host: {host}")
    is_loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError("Non-loopback staging hosts must use HTTPS.")
    return url
