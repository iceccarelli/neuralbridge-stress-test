#!/usr/bin/env python3
"""One command that runs the whole harness and says exactly what ran.

    python scripts/validate.py              # human table
    python scripts/validate.py --json out.json   # also a machine-readable report
    python scripts/validate.py --api        # also start the real API on loopback and probe it
    python scripts/validate.py --sources    # also fetch the public sources (needs network)

Each tier gets one of the harness's four statuses and its evidence level. A tier that did not
run is BLOCKED or UNCHECKED, never PASS; a green table here is not hosted-staging evidence.

Exit codes: 0 every required tier PASS; 1 any tier FAIL; 3 nothing failed but a required
tier is BLOCKED or UNCHECKED (a gate that did not run is not a pass).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_api import BLOCKED as PROBE_BLOCKED  # noqa: E402
from probe_api import find_product_src, product_sha  # noqa: E402

REQUIRED = ("doctor", "lint", "tests")


def run(cmd: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                          check=False)


def tier(name: str, status: str, level: str, command: str, detail: str = "",
         exit_code: int | None = None, counts: dict | None = None) -> dict:
    return {"tier": name, "status": status, "evidence_level": level, "command": command,
            "exit": exit_code, "counts": counts or {}, "detail": detail}


def doctor() -> dict:
    done = run([sys.executable, "scripts/doctor.py"])
    return tier("doctor", "PASS" if done.returncode == 0 else "FAIL", "repository structure",
                "python scripts/doctor.py", done.stdout.strip().splitlines()[-1:][0]
                if done.stdout.strip() else done.stderr[-200:], done.returncode)


def lint() -> dict:
    done = run([sys.executable, "-m", "ruff", "check", "."])
    if done.returncode != 0 and "No module named ruff" in done.stderr:
        binary = shutil.which("ruff")
        if binary is None:
            return tier("lint", "BLOCKED", "static", "ruff check .", "ruff is not installed")
        done = run([binary, "check", "."])
    return tier("lint", "PASS" if done.returncode == 0 else "FAIL", "static",
                "ruff check .", (done.stdout.strip().splitlines() or [""])[-1], done.returncode)


def tests() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "junit.xml"
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
               f"--junitxml={xml_path}"]
        done = run(cmd)
        counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
        if xml_path.is_file():
            suite = ET.parse(xml_path).getroot()
            suite = suite if suite.tag == "testsuite" else suite.find("testsuite")
            total = int(suite.get("tests", 0))
            counts.update(failed=int(suite.get("failures", 0)), errors=int(suite.get("errors", 0)),
                          skipped=int(suite.get("skipped", 0)))
            counts["passed"] = total - counts["failed"] - counts["errors"] - counts["skipped"]
    src = find_product_src()
    if src is None:
        level = "harness only (no product checkout: product suites are BLOCKED, not passed)"
    else:
        level = (f"library + product CLI, local subprocess, real SQLite; product "
                 f"{product_sha(src)}")
    if done.returncode != 0:
        status = "FAIL"
    elif counts["skipped"] or src is None:
        status = "BLOCKED"          # a skip is a gate that did not run
    else:
        status = "PASS"
    return tier("tests", status, level, "pytest -q", "", done.returncode, counts)


def api() -> dict:
    out = Path(tempfile.mkdtemp(prefix="nb-api-")) / "probe.json"
    done = run([sys.executable, "scripts/probe_api.py", "--out", str(out)], timeout=900)
    if done.returncode == PROBE_BLOCKED:
        return tier("api", "BLOCKED", "product API, local loopback",
                    "python scripts/probe_api.py", done.stdout.strip()[-300:], done.returncode)
    if done.returncode != 0:
        return tier("api", "FAIL", "product API, local loopback",
                    "python scripts/probe_api.py", done.stdout.strip()[-300:], done.returncode)
    report = json.loads(out.read_text())
    bad = report["transport_errors"]
    return tier("api", "FAIL" if bad else "PASS",
                "product API, local loopback, isolated temp state (discovery: asserts only "
                "that every route answers; not an authorization test)",
                "python scripts/probe_api.py",
                f"{report['operations']} operations answered; "
                f"{len(report['open_without_key'])} open without a key",
                0, {"operations": report["operations"]})


def sources() -> dict:
    done = run([sys.executable, "scripts/fetch_sources.py"], timeout=900)
    return tier("sources", "PASS" if done.returncode == 0 else "FAIL",
                "public sources, real network, provenance recorded under data/raw (ignored)",
                "python scripts/fetch_sources.py", (done.stdout.strip() or done.stderr)[-300:],
                done.returncode)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", type=Path, help="also write the report here")
    ap.add_argument("--api", action="store_true")
    ap.add_argument("--sources", action="store_true")
    args = ap.parse_args(argv)

    results = [doctor(), lint(), tests()]
    results.append(api() if args.api else tier(
        "api", "UNCHECKED", "product API, local loopback", "python scripts/validate.py --api",
        "not requested"))
    results.append(sources() if args.sources else tier(
        "sources", "UNCHECKED", "public sources, real network",
        "python scripts/validate.py --sources", "not requested"))
    results.append(tier("hosted staging", "UNCHECKED", "hosted staging",
                        "scripts/probe_staging.py", "needs an explicitly approved staging URL"))

    src = find_product_src()
    report = {"run_at": datetime.now(UTC).isoformat(),
              "product_sha": product_sha(src) if src else None, "tiers": results}
    for r in results:
        c = r["counts"]
        extra = (f"  {c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped, "
                 f"{c['errors']} errors") if "passed" in c else ""
        print(f"{r['tier']:15}{r['status']:10}{r['evidence_level']}{extra}")
        if r["detail"]:
            print(f"{'':25}{r['detail']}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if any(r["status"] == "FAIL" for r in results):
        return 1
    if any(r["status"] != "PASS" for r in results if r["tier"] in REQUIRED):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
