"""Run the product's real command line, against real files, as a subprocess.

This is the product boundary for CLI-level scenarios: the harness writes plain JSON, invokes
``python -m assurance ...`` and asserts on exit status, standard output and standard error.
It imports nothing from the product, so it cannot reuse the product's own calculation.
Evidence level of anything that uses it: **product CLI, local, isolated temp directory,
real SQLite persistence**. Not API, not hosted staging.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from conftest import PRODUCT_SRC

TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class Run:
    args: tuple[str, ...]
    exit: int
    out: str
    err: str

    def json(self):
        return json.loads(self.out)


def assurance(*args: str, cwd: Path, extra_env: dict[str, str] | None = None) -> Run:
    """``python -m assurance *args`` in ``cwd`` with the product's source on the path."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (PRODUCT_SRC, env.get("PYTHONPATH", "")) if p)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        env.update(extra_env)
    done = subprocess.run(
        [sys.executable, "-m", "assurance", *args], cwd=cwd, env=env, text=True,
        capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    return Run(tuple(args), done.returncode, done.stdout, done.stderr)


def synthetic_manifest(serial: str, parts: list[tuple[str, str, str]], *,
                       manifest_id: str | None = None, taken_at: str = "2026-10-27T08:00:00Z",
                       supplier: str = "Rockwell Automation") -> dict:
    """A SYNTHETIC safety manifest for machine ``serial``.

    ``parts`` is ``[(item_id, catalog_number, version), ...]``. Hashes are placeholders of the
    right shape and say nothing about any real device.
    """
    return {
        "manifest_id": manifest_id or f"SYN-{serial}-{taken_at[:10]}",
        "machine": {"manufacturer": "SynthCo", "model": "Cell-1", "serial": serial},
        "source": "as_found", "taken_at": taken_at,
        "taken_by": {"identifier": "synthetic.tech", "role": "synthetic", "kind": "person"},
        "method": "synthetic fixture", "notes": "SYNTHETIC: invented machine, not a customer.",
        "items": [{
            "item_id": item_id, "kind": "firmware", "name": catalog, "version": version,
            "content_hash": f"{(i + 1):x}" * 64, "hash_source": "read_from_machine",
            "supplier": supplier, "implements": ["SF-1"], "modifiable_in_field": False,
        } for i, (item_id, catalog, version) in enumerate(parts)],
        "functions": [{"function_id": "SF-1", "description": "synthetic safe stop",
                       "required_performance": "", "verified_by": ["stop_time"]}],
    }


NETAUDIT_DIR = str(Path(__file__).parent / "netaudit")


def audited(*args: str, cwd: Path, log: Path) -> tuple[Run, list[dict]]:
    """Run the product CLI with the independent observer loaded; return (run, events seen)."""
    env = {
        "NB_NET_LOG": str(log),
        "PYTHONPATH": os.pathsep.join(
            p for p in (NETAUDIT_DIR, PRODUCT_SRC, os.environ.get("PYTHONPATH", "")) if p),
    }
    result = assurance(*args, cwd=cwd, extra_env=env)
    events = ([json.loads(x) for x in log.read_text().splitlines() if x.strip()]
              if log.exists() else [])
    return result, events


def audited_python(code: str, *, cwd: Path, log: Path) -> list[dict]:
    """Run ``python -c code`` under the same observer (used as a positive control)."""
    env = dict(os.environ)
    env["NB_NET_LOG"] = str(log)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (NETAUDIT_DIR, env.get("PYTHONPATH", "")) if p)
    subprocess.run([sys.executable, "-c", code], cwd=cwd, env=env, text=True,
                   capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    if not log.exists():
        return []
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
