"""Turn a local ingestion manifest into a committable provenance record.

The raw payloads under ``data/raw/`` are Git-ignored on purpose. What can be committed safely
is the *record of what was fetched*: which source, which URL, when, with what status, how many
bytes and the SHA-256 of the exact bytes, plus what that observation can and cannot prove.
No payload is copied. A record is a statement that these bytes were seen at that time, not
that they are true, complete, current, or about any customer's device.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

SCHEMA = "neuralbridge-stress.provenance/1"

#: What each source's observation does and does not establish. Keyed by source_id.
BOUNDARIES: dict[str, str] = {
    "nvd_cve_api": (
        "Establishes what NVD published for the requested CVE at retrieval time. Does not show "
        "that any customer runs an affected product; NVD records are revised after the fact."),
    "first_epss": (
        "Establishes the EPSS score FIRST published on the score date for the requested CVEs. "
        "EPSS is time-sensitive and is a probability estimate, not evidence of exploitation."),
    "cisa_kev": (
        "Establishes which CVEs CISA listed as known-exploited at retrieval time. Absence from "
        "the catalogue is not proof that a vulnerability does not exist or cannot be exploited."),
}
_DEFAULT_BOUNDARY = (
    "Establishes only that these exact bytes were received from this URL at this time. It does "
    "not show the content is true, complete, current, or about any customer's device.")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED = ("source_id", "url", "retrieved_at", "http_status", "bytes", "sha256",
             "reuse_status", "boundary_of_proof")


def build(manifest: Mapping[str, Any], sources: Mapping[str, Any]) -> dict[str, Any]:
    """Provenance record for every observation in ``manifest`` (as written by fetch_sources)."""
    reuse = {s["id"]: s.get("reuse_status", "unreviewed") for s in sources.get("sources", [])}
    publishers = {s["id"]: s.get("publisher", "") for s in sources.get("sources", [])}
    records = []
    for obs in manifest.get("observations", []):
        sid = obs["source_id"]
        records.append({
            "source_id": sid,
            "publisher": publishers.get(sid, ""),
            "url": obs["url"],
            "retrieved_at": obs["retrieved_at_utc"],
            "http_status": obs["http_status"],
            "bytes": obs["bytes_received"],
            "sha256": obs["sha256"],
            "reuse_status": reuse.get(sid, "unreviewed"),
            "boundary_of_proof": BOUNDARIES.get(sid, _DEFAULT_BOUNDARY),
        })
    return {
        "schema": SCHEMA,
        "manifest_generated_at": manifest.get("generated_at_utc", ""),
        "failures": list(manifest.get("failures", [])),
        "payloads_committed": False,
        "records": records,
    }


def problems(record: Mapping[str, Any]) -> list[str]:
    """Everything wrong with a provenance record; empty means it is well formed."""
    out: list[str] = []
    if record.get("schema") != SCHEMA:
        out.append(f"schema is {record.get('schema')!r}, expected {SCHEMA!r}")
    if record.get("payloads_committed") is not False:
        out.append("payloads_committed must be false: raw payloads are never committed")
    rows = record.get("records")
    if not isinstance(rows, list) or not rows:
        out.append("records is empty: a provenance record of nothing proves nothing")
        return out
    for i, row in enumerate(rows):
        tag = f"records[{i}] ({row.get('source_id', '?')})"
        for field in _REQUIRED:
            if row.get(field) in (None, ""):
                out.append(f"{tag}: {field} is missing")
        if not str(row.get("url", "")).startswith("https://"):
            out.append(f"{tag}: url is not https")
        if not _HEX64.match(str(row.get("sha256", ""))):
            out.append(f"{tag}: sha256 is not 64 lowercase hex characters")
        try:
            when = datetime.fromisoformat(str(row.get("retrieved_at", "")))
            if when.tzinfo is None:
                out.append(f"{tag}: retrieved_at has no timezone")
        except ValueError:
            out.append(f"{tag}: retrieved_at is not an ISO timestamp")
        if row.get("http_status") != 200:
            out.append(f"{tag}: http_status is {row.get('http_status')!r}, not 200")
        if not isinstance(row.get("bytes"), int) or row["bytes"] <= 0:
            out.append(f"{tag}: bytes must be a positive integer")
        extra = set(row) - set(_REQUIRED) - {"publisher"}
        if extra:
            out.append(f"{tag}: unexpected fields {sorted(extra)} "
                       "(payload content must not be here)")
    return out
