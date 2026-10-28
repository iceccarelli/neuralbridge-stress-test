"""NB-001 / NB-002 through the product's real CLI.

EVIDENCE LEVEL: product CLI, run locally as a subprocess in an isolated temp directory, with a
real SQLite ledger on disk. NOT the HTTP API, NOT hosted staging, NOT production.

Sources of expected results: the reviewed vendor facts in data/fixtures/rockwell_advisories.json
(Rockwell SD1780, retrieved/reviewed 2026-10-27), the scenario's ``expected_behavior`` in
configs/scenarios.json, and the exit-code contract the CLI documents (0 clear, 1 finding, 2 could
not run). The machines are SYNTHETIC. The advisory file is written as plain JSON by this test; no
product class is imported.

What this does not prove: that any customer owns any listed device, that the fixture matches the
current vendor advisory, or anything about the API/MCP/hosted layers.
"""
import json
from pathlib import Path

import pytest
from support_cli import assurance, synthetic_manifest

FIXTURE = json.loads(
    (Path(__file__).resolve().parent.parent / "data/fixtures/rockwell_advisories.json")
    .read_text(encoding="utf-8"))
SD1780 = next(r for r in FIXTURE["records"] if r["advisory_id"] == "SD1780")
VENDOR = "Rockwell Automation"
EARLIER = " and earlier"


def advisory_json():
    """The reviewed fixture, written out in the product's advisory file format."""
    affected, fixed = [], []
    for p in SD1780["affected_products"]:
        text = p["affected_firmware"]
        ranged = text.endswith(EARLIER)
        affected.append({
            "supplier": VENDOR, "name": p["catalog_number"],
            "versions": [text[: -len(EARLIER)] if ranged else text],
            "content_hashes": [], "version_note": text if ranged else ""})
        if p["corrected_firmware"]:
            fixed.append(p["corrected_firmware"])
    return {
        "advisory_id": SD1780["advisory_id"], "issued_by": VENDOR,
        "issued_at": "2026-10-27T00:00:00Z", "title": SD1780["product_family"],
        "summary": "SYNTHETIC adapter record built from the reviewed fixture.",
        "severity": "safety_relevant", "affected": affected, "remedy": "",
        "reference": SD1780["source_url"], "fixed_versions": fixed, "fixed_hashes": [],
    }


MACHINES = {
    "A": [("ITM-1", "1756-EN2", "V12.001")],    # the vendor's affected version
    "B": [("ITM-1", "1756-EN2", "V12.002")],    # the vendor's corrected version
    "C": [("ITM-1", "1756-EN2", "V11.010")],    # inside the vendor's words "and earlier"
    "D": [("ITM-1", "1756-ENBT", "V6.006")],    # discontinued, no fix (NB-002)
    "E": [("ITM-1", "1756-L83E", "V35.011")],   # a Rockwell part the advisory never names
}


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    work = tmp_path_factory.mktemp("nb001cli")
    for serial, parts in MACHINES.items():
        path = work / f"m_{serial}.json"
        path.write_text(json.dumps(synthetic_manifest(serial, parts)), encoding="utf-8")
        run = assurance("machinery", "record-manifest", str(path), "--ledger", "fleet.db",
                        "--actor", "synthetic.tech", cwd=work)
        assert run.exit == 0, run.err
    (work / "adv.json").write_text(json.dumps(advisory_json()), encoding="utf-8")
    run = assurance("fleet", "advisory", "adv.json", "--ledger", "fleet.db", "--json", cwd=work)
    return work, run


@pytest.fixture(scope="module")
def report(fleet):
    _, run = fleet
    assert run.exit in (0, 1), f"exit {run.exit}: {run.err}"
    return run.json()["advisories"][0]


def klass(report, serial):
    return next(c for c in report["machine_classification"]
                if c["machine"].endswith(f"#{serial}"))


def affected(report):
    return {m.rsplit("#", 1)[1] for m in report["machines_affected"]}


# ---- NB-001 -----------------------------------------------------------------------------
def test_a_finding_exits_1_not_0(fleet):
    """CLI contract: `fleet advisory` exits non-zero on a finding."""
    _, run = fleet
    assert run.exit == 1


def test_NB001_the_vendors_affected_version_is_flagged_but_only_as_a_label(report):
    c = klass(report, "A")
    assert "A" in affected(report)
    assert c["basis"] == "version" and "label" in c["uncertainty"]
    exposure = next(e for e in report["exposures"] if e["machine"].endswith("#A"))
    assert exposure["confidence"] == "probable"          # never "confirmed" from a label


def test_NB001_the_vendors_corrected_version_is_not_flagged(report):
    assert "B" not in affected(report)
    assert klass(report, "B")["classification"] == "no_match_found"


def test_NB001_a_version_inside_the_vendors_words_is_not_cleared(report):
    """'V12.001 and earlier' is a range the product does not parse: a person must look."""
    c = klass(report, "C")
    assert "C" in affected(report)
    exposure = next(e for e in report["exposures"] if e["machine"].endswith("#C"))
    assert exposure["needs_a_human"] is True and c["classification"] != "no_match_found"


def test_NB001_a_part_the_advisory_does_not_name_is_not_flagged(report):
    assert "E" not in affected(report)


def test_NB001_applicability_is_not_ownership_the_result_says_so(report):
    """The advisory arrives as a bare file: unauthenticated, inspect-only, no consequences."""
    p = report["provenance"]
    assert p["inspect_only"] is True and p["automated_consequences_permitted"] is False
    assert p["trust_state"] == "unauthenticated_file" and p["trust_basis"] == "none"
    assert report["clear_is_complete"] is False


def test_NB001_absence_from_the_report_is_not_claimed_as_safety(report):
    skipped = " ".join(report["checks_skipped"]).lower()
    assert "absence" in skipped and "not evidence of safety" in skipped


# ---- NB-002 -----------------------------------------------------------------------------
def test_NB002_the_discontinued_module_is_flagged_and_no_fix_is_invented(report):
    assert "D" in affected(report)
    mentions = json.dumps([c for c in report["machine_classification"]
                           if c["machine"].endswith("#D")]
                          + [e for e in report["exposures"] if e["machine"].endswith("#D")])
    assert "V12.002" not in mentions            # the EN2/EN3 fix is not offered for ENBT
    assert "remedy" not in mentions.lower() and "upgrade" not in mentions.lower()


# ---- failure behaviour at the CLI boundary ---------------------------------------------
def test_an_unreadable_advisory_is_exit_2_with_a_message_not_a_pass(fleet):
    work, _ = fleet
    (work / "bad.json").write_text("{not json", encoding="utf-8")
    run = assurance("fleet", "advisory", "bad.json", "--ledger", "fleet.db", cwd=work)
    assert run.exit == 2 and run.err.strip()


def test_a_missing_ledger_is_exit_2_not_an_empty_fleet(tmp_path):
    (tmp_path / "adv.json").write_text(json.dumps(advisory_json()), encoding="utf-8")
    run = assurance("fleet", "advisory", "adv.json", "--ledger", "nope.db", cwd=tmp_path)
    assert run.exit == 2


def test_an_advisory_naming_no_version_or_hash_is_refused_not_matched_to_everything(fleet):
    work, _ = fleet
    adv = advisory_json()
    adv["affected"] = [{"supplier": VENDOR, "name": "1756-EN2", "versions": [],
                        "content_hashes": [], "version_note": ""}]
    (work / "empty_adv.json").write_text(json.dumps(adv), encoding="utf-8")
    run = assurance("fleet", "advisory", "empty_adv.json", "--ledger", "fleet.db", cwd=work)
    assert run.exit == 2 and "version" in run.err.lower()
