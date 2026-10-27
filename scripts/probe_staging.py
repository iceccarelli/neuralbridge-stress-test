#!/usr/bin/env python3
"""Read-only smoke probe for an isolated NeuralBridge staging API."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PRODUCTION_HOSTS = {
    "neuralbridge.io",
    "www.neuralbridge.io",
    "assurance-register.fly.dev",
    "neuralbridge.vercel.app",
}
MAX_BODY_BYTES = 1024 * 1024


def validate_base_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"https", "http"} or not host:
        raise ValueError("Set a valid http(s) staging base URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query strings and fragments are not permitted in the base URL.")
    if host in PRODUCTION_HOSTS or host.endswith(".neuralbridge.io"):
        raise ValueError(f"Refusing known production host: {host}")
    is_loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError("Non-loopback staging hosts must use HTTPS.")
    return url


def get_json(base_url: str, path: str) -> tuple[int, object]:
    url = f"{base_url}/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "neuralbridge-staging-probe/0.1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(MAX_BODY_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY_BYTES + 1)
        status = exc.code
    if len(body) > MAX_BODY_BYTES:
        raise RuntimeError(f"{path}: response exceeded {MAX_BODY_BYTES} bytes")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = {"non_json_response": True}
    return status, decoded


def main() -> int:
    value = os.environ.get("NEURALBRIDGE_STAGING_BASE_URL", "")
    if not value:
        print("BLOCKED: set NEURALBRIDGE_STAGING_BASE_URL to an isolated staging API host.")
        return 2
    try:
        base_url = validate_base_url(value)
    except ValueError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    failures = 0
    for path in ("healthz", "v1/plans"):
        try:
            status, payload = get_json(base_url, path)
            ok = status == 200 and isinstance(payload, dict)
            if path == "healthz" and isinstance(payload, dict):
                ok = ok and payload.get("ok") is True
            print(f"{'PASS' if ok else 'FAIL'} GET /{path}: HTTP {status}")
            if path == "healthz" and isinstance(payload, dict):
                safe_fields = {key: payload[key] for key in ("ok", "auth_mode", "stores_open") if key in payload}
                print(f"   health fields: {json.dumps(safe_fields, sort_keys=True)}")
            if path == "v1/plans" and isinstance(payload, dict):
                print(f"   response fields: {sorted(payload.keys())}")
            if not ok:
                failures += 1
        except Exception as exc:
            print(f"FAIL GET /{path}: {exc}", file=sys.stderr)
            failures += 1
    print("NOTE: read-only smoke probe only; it does not verify checkout, webhooks, tenancy, restore, or product correctness.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
