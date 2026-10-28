#!/usr/bin/env python3
"""Start the product's real API on loopback and record how every route answers.

Evidence level of what this produces: product API, local process, loopback only, isolated
temporary state, throwaway operator key. Not hosted staging, not production.

For every operation in the product's own ``public/openapi.json`` it sends one request as
three identities (no key, a bad key, the throwaway operator key) with an empty ``{}`` body,
and records the HTTP status. This is DISCOVERY: it shows which routes are open, which refuse
with 401/402/403 and which reject the empty body with 422, so assertions can be written
against the real contract instead of an invented one. It asserts nothing.

Safety: the server environment is built from scratch (no inherited variables, so no Stripe
or other secret can leak in), state lives in a temp directory, nothing but 127.0.0.1 is
contacted, and the operator key is generated per run and never printed or stored.

Exit codes: 0 ran, 3 BLOCKED (a dependency or the product checkout is missing), 2 the
server could not be started.
"""

from __future__ import annotations

import argparse
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
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKED = 3
METHODS = ("get", "post", "put", "patch", "delete")


def find_product_src() -> Path | None:
    for candidate in (os.environ.get("NEURALBRIDGE_SRC"), ROOT.parent / "neuralbridge" / "src",
                      "/workspaces/neuralbridge/src"):
        if candidate and (Path(candidate) / "assurance").is_dir():
            return Path(candidate).resolve()
    return None


def operations(openapi: dict) -> list[tuple[str, str]]:
    out = []
    for path, item in sorted(openapi.get("paths", {}).items()):
        for method in METHODS:
            if method in item:
                out.append((method.upper(), path))
    return out


def concrete(path: str) -> str:
    """Fill every path parameter with an id that exists nowhere."""
    parts = []
    for segment in path.split("/"):
        parts.append("harness-unknown-id" if segment.startswith("{") else segment)
    return "/".join(parts)


def request(base: str, method: str, path: str, key: str | None) -> tuple[int, str]:
    data = b"{}" if method in {"POST", "PUT", "PATCH"} else None
    headers = {"Accept": "application/json", "User-Agent": "neuralbridge-stress-probe/0.1"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if key is not None:
        headers["X-API-Key"] = key
    req = urllib.request.Request(base + concrete(path), data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp.read(1024 * 1024)
            return resp.status, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        exc.read(1024 * 1024)
        return exc.code, exc.headers.get("Content-Type", "")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"transport error: {type(exc).__name__}"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def product_sha(src: Path) -> str:
    try:
        done = subprocess.run(["git", "-C", str(src.parent), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=False)
        return done.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "derived" / "api_probe.json")
    ap.add_argument("--dry-run", action="store_true",
                    help="list the requests that would be sent; start nothing")
    args = ap.parse_args(argv)

    src = find_product_src()
    if src is None:
        print("BLOCKED: no product checkout. Set NEURALBRIDGE_SRC to the product's src "
              "directory or clone iceccarelli/neuralbridge beside this repository.")
        return BLOCKED
    spec_path = src.parent / "public" / "openapi.json"
    if not spec_path.is_file():
        print(f"BLOCKED: {spec_path} not found in the product checkout.")
        return BLOCKED
    ops = operations(json.loads(spec_path.read_text(encoding="utf-8")))
    if args.dry_run:
        for method, path in ops:
            print(f"{method:6} {concrete(path)}")
        print(f"\n{len(ops)} operations x 3 identities (none, bad key, throwaway operator key)")
        return 0

    check = subprocess.run(
        [sys.executable, "-c", "import fastapi, uvicorn, assurance.api.service"],
        env={**os.environ, "PYTHONPATH": str(src)}, capture_output=True, text=True, check=False)
    if check.returncode != 0:
        lines = check.stderr.strip().splitlines()
        print("BLOCKED: the product API cannot be imported here "
              f"({lines[-1] if lines else 'no detail'}). "
              "Install it with: pip install -e '<product>[assurance-api]'")
        return BLOCKED

    operator_key = secrets.token_urlsafe(24)       # throwaway; never printed or stored
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="nb-probe-") as tmp:
        state = Path(tmp)
        env = {                                    # built from scratch: nothing inherited
            "PATH": os.environ.get("PATH", ""), "HOME": tmp, "PYTHONPATH": str(src),
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
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    print("the server exited during start-up:\n" + (server.stderr.read() or ""))
                    return 2
                if request(base, "GET", "/healthz", None)[0] == 200:
                    break
                time.sleep(0.3)
            else:
                print("the server did not answer /healthz within 30 s")
                return 2
            rows = []
            for method, path in ops:
                row = {"method": method, "path": path}
                for name, key in (("no_key", None), ("bad_key", "not-a-key"),
                                  ("operator", operator_key)):
                    row[name], _ = request(base, method, path, key)
                rows.append(row)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()

    report = {
        "evidence_level": "product API, local process, loopback only, isolated temp state",
        "product_sha": product_sha(src), "probed_at": datetime.now(UTC).isoformat(),
        "operations": len(rows), "rows": rows,
        "open_without_key": [f"{r['method']} {r['path']}" for r in rows
                             if 200 <= r["no_key"] < 300],
        "transport_errors": [f"{r['method']} {r['path']}" for r in rows
                             if 0 in (r["no_key"], r["bad_key"], r["operator"])],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{'METHOD':7}{'PATH':52}{'no key':>8}{'bad key':>9}{'operator':>10}")
    for r in rows:
        print(f"{r['method']:7}{r['path']:52}{r['no_key']:>8}{r['bad_key']:>9}{r['operator']:>10}")
    print(f"\n{len(rows)} operations. {len(report['open_without_key'])} answered 2xx with no "
          f"key (review each: free-by-design, or a gap?). Written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
