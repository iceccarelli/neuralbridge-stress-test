#!/usr/bin/env python3
"""Write the committable provenance record from the local ingestion manifest.

    python scripts/fetch_sources.py            # writes data/raw/ingestion-manifest.json (ignored)
    python scripts/write_provenance.py         # writes data/provenance/sources.json (commit this)

Refuses to write a record that fails validation (no observations, a failed fetch, a bad hash).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from neuralbridge_stress import provenance  # noqa: E402

MANIFEST = ROOT / "data" / "raw" / "ingestion-manifest.json"
SOURCES = ROOT / "configs" / "sources.json"
OUT = ROOT / "data" / "provenance" / "sources.json"


def main() -> int:
    if not MANIFEST.is_file():
        print(f"BLOCKED: {MANIFEST.relative_to(ROOT)} not found. "
              "Run scripts/fetch_sources.py first.")
        return 3
    record = provenance.build(json.loads(MANIFEST.read_text(encoding="utf-8")),
                              json.loads(SOURCES.read_text(encoding="utf-8")))
    bad = provenance.problems(record) + [f"fetch failure: {f}" for f in record["failures"]]
    if bad:
        print("not written; the record is not trustworthy:\n  " + "\n  ".join(bad))
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(record['records'])} observation(s), no payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
