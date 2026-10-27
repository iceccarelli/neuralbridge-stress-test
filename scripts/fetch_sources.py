#!/usr/bin/env python3
"""Fetch bounded, focused public observations with provenance. No write endpoints."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from neuralbridge_stress.registry import load_json  # noqa: E402

USER_AGENT = "neuralbridge-stress-test/0.1.0 (public-source validation harness)"
MAX_BYTES = 25 * 1024 * 1024
ROCKWELL_FIXTURE = ROOT / "data" / "fixtures" / "rockwell_advisories.json"
RAW_ROOT = ROOT / "data" / "raw"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def read_url(url: str, *, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS sources are permitted.")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Network request failed for {url}: {exc}") from exc

    if status != 200:
        raise RuntimeError(f"Unexpected HTTP status {status} from {url}")
    if len(body) > MAX_BYTES:
        raise RuntimeError(f"Response exceeds {MAX_BYTES} bytes; refusing to store it.")
    return status, body


def write_observation(
    source_id: str,
    relative_path: str,
    url: str,
    status: int,
    body: bytes,
    manifest: list[dict[str, Any]],
) -> Any:
    output = RAW_ROOT / relative_path
    output.parent.mkdir(parents=True, exist_ok=True)
    parsed = json.loads(body.decode("utf-8"))
    output.write_text(json.dumps(parsed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entry = {
        "source_id": source_id,
        "url": url,
        "retrieved_at_utc": utc_now(),
        "http_status": status,
        "bytes_received": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "saved_path": str(output.relative_to(ROOT)),
    }
    manifest.append(entry)
    print(f"OK {source_id}: {len(body)} bytes sha256={entry['sha256']}")
    return parsed


def load_cves() -> list[str]:
    fixture = load_json(ROCKWELL_FIXTURE)
    cves: set[str] = set()
    for record in fixture["records"]:
        if record.get("cve_id"):
            cves.add(record["cve_id"])
        cves.update(record.get("cve_ids", []))
    return sorted(cves)


def main() -> int:
    RAW_ROOT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    failures: list[str] = []
    cves = load_cves()

    # CISA KEV catalogue is useful as a high-confidence positive signal, not as a
    # complete list of all vulnerabilities or a product applicability database.
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        status, body = read_url(cisa_url)
        payload = write_observation(
            "cisa_kev", "cisa_kev/known_exploited_vulnerabilities.json",
            cisa_url, status, body, manifest
        )
        entries = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        cisa_ids = {item.get("cveID") for item in entries if isinstance(item, dict)}
        matches = sorted(cisa_ids.intersection(cves))
        print(f"   Catalogue entries: {len(entries)}; fixture CVEs present in KEV: {matches}")
    except Exception as exc:
        failures.append(f"cisa_kev: {exc}")
        print(f"FAIL cisa_kev: {exc}", file=sys.stderr)

    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    for index, cve in enumerate(cves):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(
            {"cveId": cve}
        )
        headers = {"apiKey": nvd_key} if nvd_key else None
        try:
            status, body = read_url(url, headers=headers)
            payload = write_observation(
                "nvd_cve_api", f"nvd/{cve}.json", url, status, body, manifest
            )
            items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
            print(f"   {cve}: {len(items)} NVD result(s)")
        except Exception as exc:
            failures.append(f"nvd {cve}: {exc}")
            print(f"FAIL nvd {cve}: {exc}", file=sys.stderr)
        if index < len(cves) - 1:
            # NVD has a strict unauthenticated request budget; keep this sequential.
            time.sleep(6)

    epss_url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode(
        {"cve": ",".join(cves)}
    )
    try:
        status, body = read_url(epss_url)
        payload = write_observation(
            "first_epss", "first_epss/epss.json", epss_url, status, body, manifest
        )
        entries = payload.get("data", []) if isinstance(payload, dict) else []
        returned_ids = {item.get("cve") for item in entries if isinstance(item, dict)}
        missing = sorted(set(cves) - returned_ids)
        print(f"   EPSS scores returned: {len(entries)}; not returned: {missing}")
    except Exception as exc:
        failures.append(f"first_epss: {exc}")
        print(f"FAIL first_epss: {exc}", file=sys.stderr)

    manifest_path = RAW_ROOT / "ingestion-manifest.json"
    manifest_doc = {
        "schema_version": "1.0",
        "generated_at_utc": utc_now(),
        "note": "Observations are time-sensitive. This manifest and raw payloads are local and Git-ignored.",
        "cve_ids_requested": cves,
        "observations": manifest,
        "failures": failures,
    }
    manifest_path.write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Manifest: {manifest_path.relative_to(ROOT)}")
    if failures:
        print(f"BLOCKED/FAILED: {len(failures)} source request(s) failed. See manifest.", file=sys.stderr)
        return 1
    print("PASS: all configured bootstrap source requests completed. Review observations; this is not product validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
