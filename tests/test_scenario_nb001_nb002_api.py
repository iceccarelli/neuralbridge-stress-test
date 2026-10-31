"""NB-001 / NB-002 through the product's real API, with the reviewed Rockwell SD1780 facts.

EVIDENCE LEVEL: the product's real FastAPI app on loopback, a throwaway Cell account, SYNTHETIC
machines, an advisory written from the reviewed fixture data/fixtures/rockwell_advisories.json
(Rockwell SD1780, reviewed 2026-10-27). Not hosted staging, not a customer, not the vendor's feed.

Independent expectations (same as the CLI-level suite, now at the API boundary):
* the vendor's affected version is flagged but only as a label (probable, never confirmed);
* the vendor's corrected version is not flagged;
* 'V12.001 and earlier' is a range the product does not parse: a person must look;
* a part the advisory never names is not flagged;
* the discontinued module with no fix is flagged and NO fix is invented for it (neither the
  EN2/EN3 corrected version nor an 'upgrade' or 'patch' is offered);
* the advisory arrives as a bare body: unauthenticated, inspect-only, no automated consequence,
  and the result is not claimed as safety for machines it did not assess;
* the API says the same as the CLI for the same machines and the same advisory.
What this does not prove: that any customer owns any listed device, that the fixture matches the
vendor's current advisory, or anything about hosted staging.
"""
import json

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance, synthetic_manifest
from test_scenario_nb001_nb002_cli import MACHINES, advisory_json, affected, klass

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
pytestmark = pytest.mark.skipif(
    not _ok or PRODUCT_SRC is None, reason=f"BLOCKED: product API not runnable ({_why})")


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def cell(api):
    key = api.make_account("nb002@example.invalid", "cell")
    for serial, parts in MACHINES.items():
        status, body = call(api.base, "POST", "/v1/machinery/manifest", key=key, body={
            "manifest": synthetic_manifest(serial, parts), "actor": "synthetic.tech"})
        assert status == 200, body
    return key


@pytest.fixture(scope="module")
def report(api, cell):
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=cell,
                        body={"advisory": advisory_json()})
    assert status == 200, body
    return body


@pytest.fixture(scope="module")
def cli_report(tmp_path_factory):
    work = tmp_path_factory.mktemp("nb002cli")
    for serial, parts in MACHINES.items():
        (work / f"m_{serial}.json").write_text(json.dumps(synthetic_manifest(serial, parts)))
        assert assurance("machinery", "record-manifest", f"m_{serial}.json", "--ledger", "f.db",
                         "--actor", "synthetic.tech", cwd=work).exit == 0
    (work / "adv.json").write_text(json.dumps(advisory_json()))
    run = assurance("fleet", "advisory", "adv.json", "--ledger", "f.db", "--json", cwd=work)
    assert run.exit == 1
    return run.json()["advisories"][0]


def test_NB001_the_vendors_affected_version_is_flagged_only_as_a_label(report):
    c = klass(report, "A")
    assert "A" in affected(report) and c["basis"] == "version" and "label" in c["uncertainty"]
    exposure = next(e for e in report["exposures"] if e["machine"].endswith("#A"))
    assert exposure["confidence"] == "probable"


def test_NB001_the_vendors_corrected_version_is_not_flagged(report):
    assert "B" not in affected(report)
    assert klass(report, "B")["classification"] == "no_match_found"


def test_NB001_a_version_inside_the_vendors_words_is_not_cleared(report):
    exposure = next(e for e in report["exposures"] if e["machine"].endswith("#C"))
    assert "C" in affected(report) and exposure["needs_a_human"] is True


def test_NB001_a_part_the_advisory_does_not_name_is_not_flagged(report):
    assert "E" not in affected(report)


def test_NB001_applicability_is_not_ownership_and_the_advisory_is_inspect_only(report):
    p = report["provenance"]
    assert p["inspect_only"] is True and p["automated_consequences_permitted"] is False
    assert p["trust_state"] == "unauthenticated_input" and p["trust_basis"] == "none"
    assert report["clear_is_complete"] is False


def test_NB001_absence_from_the_report_is_not_claimed_as_safety(report):
    skipped = " ".join(report["checks_skipped"]).lower()
    assert "absence" in skipped and "not evidence of safety" in skipped


def test_NB002_the_discontinued_module_is_flagged_and_no_fix_is_invented(report):
    assert "D" in affected(report)
    mentions = json.dumps([c for c in report["machine_classification"]
                           if c["machine"].endswith("#D")]
                          + [e for e in report["exposures"] if e["machine"].endswith("#D")])
    assert "V12.002" not in mentions
    lowered = mentions.lower()
    for invented in ("upgrade", "patch", "update to", "remedy", "corrected"):
        assert invented not in lowered, invented


def test_NB002_mitigation_text_is_never_presented_as_a_vendor_patch(api, cell):
    """An advisory that offers only a mitigation: the result must not call it a fix."""
    adv = advisory_json()
    adv["remedy"] = "Mitigation: segment the network and disable the web server. No patch exists."
    adv["fixed_versions"] = []
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=cell, body={"advisory": adv})
    assert status == 200
    d = [e for e in body["exposures"] if e["machine"].endswith("#D")]
    text = json.dumps(d).lower()
    assert "d" in {m.rsplit("#", 1)[1].lower() for m in body["machines_affected"]}
    assert "patched" not in text and "corrected version" not in text and "fixed in" not in text


def test_the_api_and_the_cli_classify_every_machine_identically(report, cli_report):
    def view(r):
        return {c["machine"].rsplit("#", 1)[1]: (c["classification"], c["basis"])
                for c in r["machine_classification"]}
    assert view(report) == view(cli_report)
    assert report["verdict"] == cli_report["verdict"]
    assert report["machines_affected"] == cli_report["machines_affected"]


def test_the_free_single_machine_check_agrees_for_the_discontinued_module(api, cell):
    status, one = call(api.base, "POST", "/v1/fleet/advisory/check", key=cell, body={
        "advisory": advisory_json(),
        "manifest": synthetic_manifest("D", MACHINES["D"])})
    assert status == 200 and one["affected"] is True
    assert "V12.002" not in json.dumps(one) and "upgrade" not in json.dumps(one).lower()
