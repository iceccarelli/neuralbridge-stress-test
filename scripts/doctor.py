#!/usr/bin/env python3
"""Local, offline-first check of the stress-test repository setup."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from neuralbridge_stress.registry import (  # noqa: E402
    load_json,
    validate_scenarios,
    validate_sources,
)


def main() -> int:
    print(f"Repository: {ROOT}")
    print(f"Python: {platform.python_version()} ({sys.executable})")
    problems: list[str] = []
    if sys.version_info < (3, 11):
        problems.append("Python 3.11 or newer is required.")

    problems.extend(validate_sources())
    problems.extend(validate_scenarios())

    for relative in (
        "data/fixtures/rockwell_advisories.json",
        "data/fixtures/evidence_events.json",
    ):
        try:
            load_json(ROOT / relative)
            print(f"OK fixture: {relative}")
        except Exception as exc:  # doctor should report corrupt/unreadable fixtures clearly
            problems.append(f"Cannot load {relative}: {exc}")

    if (ROOT.parent / "neuralbridge" / ".git").exists():
        print(f"Product checkout detected: {ROOT.parent / 'neuralbridge'}")
    else:
        print("Product checkout not found at ../neuralbridge; product integration is not wired yet.")

    if problems:
        print("\nFAIL: repository doctor found problems:")
        for problem in problems:
            print(f" - {problem}")
        return 1

    print("PASS: repository structure, source registry and initial fixtures are readable.")
    print("NOTE: this is not an end-to-end NeuralBridge product validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
