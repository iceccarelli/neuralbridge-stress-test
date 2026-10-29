"""Start the product's REAL API on loopback for tests: a uvicorn subprocess, temporary state.

Evidence level of anything that uses it: product API, local process, loopback only, isolated
temporary state, throwaway keys. Not hosted staging, not production.

The server's environment is built from scratch, so no Stripe or other secret can leak into it.
Accounts are arranged by calling the product's own AccountStore in a subprocess (arrangement
only; expected results never come from the product).
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from conftest import PRODUCT_SRC


def api_importable() -> tuple[bool, str]:
    if not PRODUCT_SRC:
        return False, "no product checkout"
    done = subprocess.run(
        [sys.executable, "-c", "import fastapi, uvicorn, assurance.api.service"],
        env={**os.environ, "PYTHONPATH": PRODUCT_SRC}, capture_output=True, text=True,
        check=False)
    if done.returncode == 0:
        return True, ""
    lines = done.stderr.strip().splitlines()
    return False, lines[-1] if lines else "import failed"


def call(base: str, method: str, path: str, *, key: str | None = None, body=None,
         raw: bytes | None = None, content_type: str = "application/json") -> tuple[int, dict]:
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = content_type
    if key is not None:
        headers["X-API-Key"] = key
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read(4 * 1024 * 1024).decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        text = exc.read(4 * 1024 * 1024).decode("utf-8", "replace")
        status = exc.code
    except (ConnectionError, urllib.error.URLError) as exc:
        # An early refusal of a body the server will not read can reset the connection while
        # the client is still sending, before the client can read the 413. That is a refusal
        # whose status was not observed: status 0, never a success. Tests that accept it must
        # also prove the server stayed healthy.
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        if not isinstance(reason, ConnectionError):
            raise
        return 0, {"_transport": type(reason).__name__}
    try:
        return status, json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return status, {"_non_json": text[:200]}


@dataclass
class LiveApi:
    base: str
    operator_key: str
    state: Path

    def make_account(self, email: str, tier: str = "cell") -> str:
        """A real account on ``tier`` in this server's account store; returns its API key."""
        code = ("import sys, json\n"
                "from assurance.billing.accounts import AccountStore\n"
                "s = AccountStore(sys.argv[1])\n"
                "a = s.upsert_account(email=sys.argv[2], tier=sys.argv[3])\n"
                "print(json.dumps({'key': s.issue_key(a.id)}))\n")
        done = subprocess.run(
            [sys.executable, "-c", code, str(self.state / "accounts.db"), email, tier],
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
            capture_output=True, text=True, check=True)
        return json.loads(done.stdout)["key"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def live_api():
    operator_key = secrets.token_urlsafe(24)       # throwaway; never printed
    port = _free_port()
    with tempfile.TemporaryDirectory(prefix="nb-api-test-") as tmp:
        state = Path(tmp)
        env = {
            "PATH": os.environ.get("PATH", ""), "HOME": tmp, "PYTHONPATH": PRODUCT_SRC,
            "PYTHONDONTWRITEBYTECODE": "1",
            "ASSURANCE_LEDGER": str(state / "register.db"),
            "ASSURANCE_ACCOUNTS": str(state / "accounts.db"),
            "ASSURANCE_TENANT_LEDGERS": str(state / "tenants"),
            "ASSURANCE_ATTEST_LOGS": str(state / "attest-logs"),
            "ASSURANCE_API_KEYS": operator_key,
        }
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "assurance.api.service:app", "--host",
             "127.0.0.1", "--port", str(port), "--log-level", "error"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError("API exited during start-up: " + (server.stderr.read()
                                                                       or "")[-500:])
                try:
                    if call(base, "GET", "/healthz")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.3)
            else:
                raise RuntimeError("API did not answer /healthz within 30 s")
            yield LiveApi(base, operator_key, state)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
