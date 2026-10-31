"""Drive the product's REAL MCP server over stdio, as an MCP client would.

Evidence level of anything that uses it: product MCP server (``python -m assurance.mcp.server``)
as a subprocess speaking the MCP protocol over stdio, with the official ``mcp`` client SDK.
The API behind it is either the product's real FastAPI app on loopback (``live_api``) or a
RECORDING stand-in that only logs what the MCP server sent, so a test can prove what was and
was not sent. Throwaway keys and state; never hosted, never production.

Nothing here reimplements a tool: expected values come from the tests' own principles.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from conftest import PRODUCT_SRC


def mcp_importable() -> tuple[bool, str]:
    if not PRODUCT_SRC:
        return False, "no product checkout"
    try:
        import httpx  # noqa: F401
        import mcp  # noqa: F401
        from mcp.client.stdio import stdio_client  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    import subprocess
    done = subprocess.run(
        [sys.executable, "-c", "import assurance.mcp.server"],
        env={**os.environ, "PYTHONPATH": PRODUCT_SRC}, capture_output=True, text=True,
        check=False)
    if done.returncode:
        lines = done.stderr.strip().splitlines()
        return False, lines[-1] if lines else "import failed"
    return True, ""


@dataclass
class ToolResult:
    is_error: bool
    text: str
    structured: Any = None

    def json(self) -> Any:
        return json.loads(self.text)


def run_mcp(env: dict[str, str], work: Callable[[Any], Awaitable[Any]]) -> Any:
    """Start the MCP server with exactly ``env`` (plus PATH/PYTHONPATH), run ``work(session)``."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "assurance.mcp.server"],
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC,
             "PYTHONDONTWRITEBYTECODE": "1", **env})

    async def main():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await work(session)

    return asyncio.run(asyncio.wait_for(main(), timeout=90))


async def call_tool(session, name: str, args: dict[str, Any] | None = None) -> ToolResult:
    res = await session.call_tool(name, args or {})
    text = "".join(getattr(c, "text", "") for c in res.content)
    return ToolResult(bool(res.is_error), text, getattr(res, "structured_content", None))


def one_call(env: dict[str, str], name: str, args: dict[str, Any] | None = None) -> ToolResult:
    async def work(session):
        return await call_tool(session, name, args)
    return run_mcp(env, work)


def list_tools(env: dict[str, str] | None = None):
    async def work(session):
        return (await session.list_tools()).tools
    return run_mcp(env or {}, work)


# ------------------------------------------------------------------ a recording stand-in
@dataclass
class Seen:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: Any


@dataclass
class Recorder:
    """Logs every request it receives and answers 200 ``{"recorded": true}`` (or what the
    test set in ``reply``)."""

    port: int
    requests: list[Seen] = field(default_factory=list)
    reply: Callable[[Seen], tuple[int, Any, dict[str, str]]] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def paths(self) -> list[tuple[str, str]]:
        return [(r.method, r.path) for r in self.requests]


class recording_server:  # noqa: N801 - used as a context manager
    def __init__(self, bind: str = "127.0.0.1", reply=None):
        self.bind, self.reply = bind, reply

    def __enter__(self) -> Recorder:
        rec = Recorder(0, reply=self.reply)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: D401
                pass

            def _serve(self):
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    body = raw.decode("utf-8", "replace")
                parts = urlsplit(self.path)
                seen = Seen(self.command, parts.path, parse_qs(parts.query),
                            {k.lower(): v for k, v in self.headers.items()}, body)
                rec.requests.append(seen)
                status, payload, headers = (rec.reply(seen) if rec.reply
                                            else (200, {"recorded": True}, {}))
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _serve  # noqa: N815

        self.server = ThreadingHTTPServer((self.bind, 0), Handler)
        rec.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return rec

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
