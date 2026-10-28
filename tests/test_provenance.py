"""The provenance record: well-formed records pass, and every kind of bad record is refused.

Harness-level (no product needed). If a record has been committed under data/provenance/ it is
validated too, so a hand-edited or payload-carrying record fails CI.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from neuralbridge_stress import provenance

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = {
    "generated_at_utc": "2026-10-28T12:00:00+00:00",
    "failures": [],
    "observations": [{
        "source_id": "first_epss", "url": "https://api.first.org/data/v1/epss?cve=CVE-0000-0000",
        "retrieved_at_utc": "2026-10-28T12:00:00+00:00", "http_status": 200,
        "bytes_received": 388, "sha256": "9" * 64, "saved_path": "data/raw/first_epss/epss.json"}],
}
SOURCES = {"sources": [{"id": "first_epss", "publisher": "FIRST.org",
                        "reuse_status": "preserve source and score date"}]}


def test_a_built_record_is_well_formed_and_states_what_it_cannot_prove():
    record = provenance.build(MANIFEST, SOURCES)
    assert provenance.problems(record) == []
    row = record["records"][0]
    assert "time-sensitive" in row["boundary_of_proof"]
    assert "saved_path" not in row                  # no local path, no payload


@pytest.mark.parametrize("label,mutate", [
    ("no observations", lambda r: r.update(records=[])),
    ("payload flag", lambda r: r.update(payloads_committed=True)),
    ("bad hash", lambda r: r["records"][0].update(sha256="xyz")),
    ("no timezone", lambda r: r["records"][0].update(retrieved_at="2026-10-28T12:00:00")),
    ("http", lambda r: r["records"][0].update(url="http://example.invalid/x")),
    ("non-200", lambda r: r["records"][0].update(http_status=500)),
    ("zero bytes", lambda r: r["records"][0].update(bytes=0)),
    ("payload smuggled in", lambda r: r["records"][0].update(payload={"cve": "x"})),
    ("boundary removed", lambda r: r["records"][0].update(boundary_of_proof="")),
])
def test_every_kind_of_bad_record_is_refused(label, mutate):
    record = copy.deepcopy(provenance.build(MANIFEST, SOURCES))
    mutate(record)
    assert provenance.problems(record), label


def test_the_committed_record_if_any_is_valid():
    path = ROOT / "data" / "provenance" / "sources.json"
    if not path.is_file():
        pytest.skip("no committed provenance record yet; run scripts/write_provenance.py")
    assert provenance.problems(json.loads(path.read_text(encoding="utf-8"))) == []
