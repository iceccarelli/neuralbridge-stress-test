"""ATTACK MATRIX, fleet impact: product CLI, real API on loopback, and the free per-machine check.

Evidence level: ``python -m assurance fleet ...`` as a subprocess against a real SQLite ledger,
the product's real FastAPI app (uvicorn, loopback) with throwaway Cell accounts, SYNTHETIC
machines and synthetic advisories. The advisories use real-looking Rockwell catalogue numbers
only as labels; nothing here is vendor data and no machine is a customer's. Not hosted.

Independent expectations, from the brief and plain logic (not from the product's code):

* a match on a name and version LABEL is probable, never confirmed; only a hash read FROM THE
  MACHINE that equals a hash the supplier published confirms; a supplier-supplied hash,
  a placeholder hash or a prefix proves nothing about the unit;
* a label that says affected beside a machine hash the supplier lists as fixed is contradictory
  (a person must look), never affected and never clear;
* a missing version or supplier is unknown, never clear;
* a similar model name, another supplier's component of the same name or a corrected version
  is not an affected machine;
* one advisory affects only the machines whose own evidence matches it; per-machine uncertainty
  is preserved (the report never flattens to a single fleet-wide yes/no);
* the answer does not depend on enrolment order, repeated enrolment, or which surface asked;
* "nothing matched" is only clear when it is complete: an empty fleet, a ledger whose chain does
  not verify, or an unknown machine is never reported clear;
* assessing an advisory records nothing.
"""
from __future__ import annotations

import copy
import json
import random
import sqlite3

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance, synthetic_manifest

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

R = "Rockwell Automation"
H_AFF, H_FIX, H_OTHER = "a1" * 32, "b2" * 32, "c3" * 32


def item(item_id, name, version, hash_=H_OTHER, src="read_from_machine", supplier=R):
    return {"item_id": item_id, "kind": "firmware", "name": name, "version": version,
            "content_hash": hash_, "hash_source": src, "supplier": supplier,
            "implements": ["SF-1"], "modifiable_in_field": False}


def machine(serial, *items):
    m = synthetic_manifest(serial, [("X", "x", "1")])
    m["items"] = list(items)
    return m


FLEET = {
    "M01": machine("M01", item("I", "1756-EN2T", "V5.001")),                  # label affected
    "M02": machine("M02", item("I", "1756-EN2T", "V5.002")),                  # corrected version
    "M03": machine("M03", item("I", "1756-EN2TR", "V5.001")),                 # similar model name
    "M04": machine("M04", item("I", "1756-EN2T/D", "V5.001")),                # revision suffix
    "M05": machine("M05", item("I", "1756-EN2T", "V5.001", supplier="ACME")),  # other supplier
    "M06": machine("M06", item("I", "1756-EN2T", "")),                        # version unknown
    "M07": machine("M07", item("I", "1756-EN2T", "V5.001", supplier="")),     # supplier unknown
    "M08": machine("M08", item("I", "1756-L83E", "V35.011", H_AFF)),          # hash read: affected
    "M09": machine("M09", item("I", "1756-L83E", "V35.011", H_FIX)),          # label vs fixed hash
    "M10": machine("M10", item("I", "1756-L83E", "V35.011", H_AFF, "supplied_by_vendor")),
    "M11": machine("M11", item("I", "1756-L83E", "V35.011", "0" * 64)),       # placeholder hash
    "M12": machine("M12", item("I", "1756-L83E", "V35.012")),                 # unlisted version
    "M13": machine("M13", item("I", "1756-EN2T", "V5.002"),
                   item("J", "1756-EN2T", "V5.001")),                         # two of the part
    "M14": machine("M14", item("I", "1769-L33ER", "V32.011")),                # unrelated part
}


def advisory(adv_id, name, versions, *, hashes=(), fixed_versions=(), fixed_hashes=(),
             supplier=R):
    return {"advisory_id": adv_id, "issued_by": supplier, "issued_at": "2026-10-27T00:00:00Z",
            "title": "synthetic", "summary": "synthetic advisory for stress testing",
            "severity": "safety_relevant",
            "affected": [{"supplier": supplier, "name": name, "versions": list(versions),
                          "content_hashes": list(hashes), "version_note": ""}],
            "remedy": "", "reference": "https://example.invalid/" + adv_id,
            "fixed_versions": list(fixed_versions), "fixed_hashes": list(fixed_hashes)}


A1 = advisory("ADV-A1", "1756-EN2T", ["V5.001"], fixed_versions=["V5.002"])
A2 = advisory("ADV-A2", "1756-L83E", ["V35.011"], hashes=[H_AFF], fixed_hashes=[H_FIX])
SUPPLIER_OF = {"M05": "ACME"}

#: per-machine expected classification, by advisory. The reasoning is in the module docstring.
EXPECT_A1 = {
    "M01": "match_by_version_only", "M02": "no_match_found", "M03": "no_match_found",
    "M04": "no_match_found", "M05": "no_match_found", "M06": "possible_match_name_only",
    "M07": "possible_match_name_only", "M08": "no_match_found", "M09": "no_match_found",
    "M10": "no_match_found", "M11": "no_match_found", "M12": "no_match_found",
    "M13": "match_by_version_only", "M14": "no_match_found",
}
EXPECT_A2 = {
    "M01": "no_match_found", "M02": "no_match_found", "M03": "no_match_found",
    "M04": "no_match_found", "M05": "no_match_found", "M06": "no_match_found",
    "M07": "no_match_found", "M08": "match_by_hash", "M09": "contradictory_label_vs_hash",
    "M10": "match_by_version_only", "M11": "contradictory_label_vs_hash",
    "M12": "no_match_found", "M13": "no_match_found", "M14": "no_match_found",
}


def enrol_cli(work, manifests, ledger="fleet.db"):
    for serial, m in manifests.items():
        path = work / f"m_{serial}.json"
        path.write_text(json.dumps(m), encoding="utf-8")
        run = assurance("machinery", "record-manifest", str(path), "--ledger", ledger,
                        "--actor", "synthetic.tech", cwd=work)
        assert run.exit == 0, (serial, run.err)


def assess_cli(work, adv, ledger="fleet.db"):
    path = work / f"{adv['advisory_id']}.json"
    path.write_text(json.dumps(adv), encoding="utf-8")
    run = assurance("fleet", "advisory", path.name, "--ledger", ledger, "--json", cwd=work)
    return run, (run.json()["advisories"][0] if run.out.strip().startswith("{") else None)


def classes(report):
    return {c["machine"].rsplit("#", 1)[1]: c["classification"]
            for c in report["machine_classification"]}


def exposure_conf(report):
    return {e["machine"].rsplit("#", 1)[1]: e["confidence"] for e in report["exposures"]}


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    work = tmp_path_factory.mktemp("fleetattack")
    enrol_cli(work, FLEET)
    return work


@pytest.fixture(scope="module")
def r1(fleet):
    return assess_cli(fleet, A1)


@pytest.fixture(scope="module")
def r2(fleet):
    return assess_cli(fleet, A2)


# ------------------------------------------------------------------------------ per machine
@pytest.mark.parametrize("serial", sorted(FLEET))
def test_each_machine_is_classified_as_its_own_evidence_warrants_for_a_label_advisory(r1, serial):
    _, report = r1
    assert classes(report)[serial] == EXPECT_A1[serial]


@pytest.mark.parametrize("serial", sorted(FLEET))
def test_each_machine_is_classified_as_its_own_evidence_warrants_for_a_hash_advisory(r2, serial):
    _, report = r2
    assert classes(report)[serial] == EXPECT_A2[serial]


def test_only_a_hash_read_from_the_machine_is_ever_confirmed(r1, r2):
    assert {m for m, c in exposure_conf(r2[1]).items() if c == "confirmed"} == {"M08"}
    assert "confirmed" not in exposure_conf(r1[1]).values()          # labels alone: never


def test_a_label_match_is_probable_and_says_a_label_is_not_an_artefact(r1):
    _, report = r1
    one = next(c for c in report["machine_classification"] if c["machine"].endswith("#M01"))
    assert exposure_conf(report)["M01"] == "probable"
    assert "label" in one["uncertainty"].lower()


def test_unknown_version_or_supplier_is_possible_never_clear_and_is_not_affected_silently(r1):
    _, report = r1
    assert exposure_conf(report)["M06"] == "possible" and exposure_conf(report)["M07"] == "possible"
    assert "M06" not in {m for m, c in classes(report).items() if c == "no_match_found"}


def test_a_supplier_listed_fixed_hash_beside_an_affected_label_is_contradictory(r2):
    _, report = r2
    assert exposure_conf(report)["M09"] == "contradictory"
    assert report["verdict"] != "clear"


def test_a_vendor_supplied_hash_is_not_evidence_about_the_unit(r2):
    _, report = r2
    assert classes(report)["M10"] == "match_by_version_only"
    assert exposure_conf(report)["M10"] != "confirmed"


def test_a_placeholder_hash_is_never_treated_as_equality_with_the_affected_hash(r2):
    _, report = r2
    assert classes(report)["M11"] != "match_by_hash"
    assert exposure_conf(report)["M11"] != "confirmed"


def test_the_fixed_version_and_the_similar_and_foreign_parts_are_not_in_the_affected_list(r1):
    _, report = r1
    affected = {m.rsplit("#", 1)[1] for m in report["machines_affected"]}
    assert affected.isdisjoint({"M02", "M03", "M05", "M08", "M09", "M10", "M11", "M12", "M14"})
    assert affected == {"M01", "M06", "M07", "M13"}


def test_a_duplicate_part_in_one_machine_makes_that_machine_affected_once(r1):
    _, report = r1
    assert [m for m in report["machines_affected"] if m.endswith("#M13")] == [
        "SynthCo/Cell-1#M13"]


def test_the_report_never_flattens_to_one_fleet_wide_answer(r1, r2):
    for _, report in (r1, r2):
        assert report["machines_in_fleet"] == 14
        assert len({c["classification"] for c in report["machine_classification"]}) >= 3
        assert report["verdict"] not in {"affected", "all_affected", "clear"}
        assert report["clear_is_complete"] is False


def test_a_finding_exits_1_and_a_mixed_report_is_never_exit_0(r1, r2):
    assert r1[0].exit == 1 and r2[0].exit == 1


def test_the_report_states_that_a_manifest_not_ownership_is_what_was_matched(r1):
    skipped = " ".join(r1[1]["checks_skipped"]).lower()
    assert "manifest" in skipped
    uncertainty = " ".join(c["uncertainty"] for c in r1[1]["machine_classification"]
                           if c["classification"] == "no_match_found").lower()
    assert "complete" in uncertainty                       # "rests on the manifest being complete"


def test_the_revision_suffix_limit_is_stated_not_hidden(r1):
    """KNOWN LIMIT, asserted so nobody mistakes it for coverage: a catalogue number with a
    series suffix ('1756-EN2T/D') is not matched to '1756-EN2T'. The report must say its
    'no match' rests on names matching and on the manifest being complete."""
    _, report = r1
    one = next(c for c in report["machine_classification"] if c["machine"].endswith("#M04"))
    assert one["classification"] == "no_match_found"
    assert "complete" in one["uncertainty"].lower()


def test_assessing_an_advisory_records_nothing(fleet):
    db = fleet / "fleet.db"

    def length():
        con = sqlite3.connect(db)
        try:
            return con.execute("SELECT count(*) FROM chain").fetchone()[0]
        finally:
            con.close()

    before = length()
    assess_cli(fleet, A1)
    assess_cli(fleet, A2)
    assert length() == before


# ----------------------------------------------------------------- independence of path/order
def test_enrolment_order_and_repeated_enrolment_do_not_change_the_answer(tmp_path):
    work = tmp_path
    order = sorted(FLEET, reverse=True)
    random.Random(7).shuffle(order)
    enrol_cli(work, {s: FLEET[s] for s in order}, "f.db")
    enrol_cli(work, {s: FLEET[s] for s in order[:5]}, "f.db")        # enrolled twice
    for adv, expect in ((A1, EXPECT_A1), (A2, EXPECT_A2)):
        _, report = assess_cli(work, adv, "f.db")
        assert classes(report) == expect
        assert report["machines_in_fleet"] == 14                    # not 19


def test_a_machine_re_enrolled_after_an_update_is_judged_on_its_newest_manifest(tmp_path):
    enrol_cli(tmp_path, {"M01": FLEET["M01"]}, "f.db")
    assert classes(assess_cli(tmp_path, A1, "f.db")[1])["M01"] == "match_by_version_only"
    updated = copy.deepcopy(FLEET["M01"])
    updated["manifest_id"] = "SYN-M01-after-update"
    updated["taken_at"] = "2026-10-28T08:00:00Z"
    updated["items"][0]["version"] = "V5.002"
    enrol_cli(tmp_path, {"M01": updated}, "f.db")
    assert classes(assess_cli(tmp_path, A1, "f.db")[1])["M01"] == "no_match_found"


def test_one_advisory_over_a_thirty_machine_fleet_marks_exactly_the_three_it_matches(tmp_path):
    manifests = {}
    for i in range(30):
        version = "V5.001" if i in (4, 17, 29) else ("V5.002" if i % 2 else "V4.020")
        manifests[f"S{i:02d}"] = machine(f"S{i:02d}", item("I", "1756-EN2T", version))
    enrol_cli(tmp_path, manifests, "f.db")
    run, report = assess_cli(tmp_path, A1, "f.db")
    assert report["machines_in_fleet"] == 30
    assert {m.rsplit("#", 1)[1] for m in report["machines_affected"]} == {"S04", "S17", "S29"}
    assert run.exit == 1


def test_an_advisory_matching_no_component_in_a_complete_fleet_is_clear_and_exit_0(tmp_path):
    enrol_cli(tmp_path, {k: FLEET[k] for k in ("M02", "M03", "M14")}, "f.db")
    nothing = advisory("ADV-NONE", "1756-EN2T", ["V5.001"])
    run, report = assess_cli(tmp_path, nothing, "f.db")
    assert run.exit == 0 and report["verdict"] == "clear"
    assert report["machines_affected"] == [] and report["clear_is_complete"] is True


EMPTY_FLEET_DEFECT = (
    "PRODUCT DEFECT, PARTLY FIXED (neuralbridge#83, retested against 851fae1): with no machine "
    "enrolled the CLI now exits 3 and clear_is_complete is false (both asserted by passing "
    "tests), but `verdict` is still 'clear' and the human headline still reads 'CLEAR — no "
    "machine in this fleet matches this advisory'. Remove this marker when the verdict and the "
    "headline stop saying clear for a fleet nothing was assessed in.")


def _empty_fleet_report(tmp_path):
    """A ledger that exists and holds evidence, but no machine."""
    run = assurance("art14", "--ledger", "has-no-machines.db", "signal", "C1", "--by",
                    "t:analyst", "--at", "2026-10-01T08:00:00Z", "--description", "d",
                    "--product", "P", "--version", "1", cwd=tmp_path)
    assert run.exit == 0, run.err
    run, report = assess_cli(tmp_path, A1, "has-no-machines.db")
    assert report["machines_in_fleet"] == 0                       # the premise
    return run, report


def test_an_empty_fleet_is_not_a_clean_exit_and_not_a_complete_clear(tmp_path):
    """FIXED upstream (neuralbridge#83): what automation reads."""
    run, report = _empty_fleet_report(tmp_path)
    assert run.exit == 3, run.exit
    assert report["clear_is_complete"] is False


@pytest.mark.xfail(strict=True, reason=EMPTY_FLEET_DEFECT + " [CLI]")
def test_an_empty_fleet_is_never_reported_clear(tmp_path):
    _, report = _empty_fleet_report(tmp_path)
    assert report["verdict"] != "clear"


def test_a_ledger_path_that_does_not_exist_is_could_not_run_and_creates_nothing(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(A1))
    run = assurance("fleet", "advisory", "a.json", "--ledger", "typo.db", "--json", cwd=tmp_path)
    assert run.exit == 2 and not (tmp_path / "typo.db").exists()


def test_a_ledger_whose_chain_does_not_verify_clears_nothing(tmp_path):
    enrol_cli(tmp_path, {k: FLEET[k] for k in ("M02", "M03")}, "f.db")
    con = sqlite3.connect(tmp_path / "f.db")
    (payload,) = con.execute("SELECT payload FROM chain WHERE seq=1").fetchone()
    con.execute("UPDATE chain SET payload=? WHERE seq=1", (payload.replace("V5.002", "V9.999"),))
    con.commit()
    con.close()
    run, report = assess_cli(tmp_path, advisory("ADV-NONE", "1756-EN2T", ["V5.001"]), "f.db")
    assert run.exit != 0, "a tampered ledger produced a clean exit"
    assert report is None or (report["verdict"] != "clear" and report["chain_verified"] is False)


@pytest.mark.parametrize("name,mutate", [
    ("blank fixed version", lambda a: a.__setitem__("fixed_versions", [""])),
    ("blank fixed hash", lambda a: a.__setitem__("fixed_hashes", [" "])),
    ("no affected", lambda a: a.__setitem__("affected", [])),
    ("no reference", lambda a: a.__setitem__("reference", "")),
    ("naive issued_at", lambda a: a.__setitem__("issued_at", "2026-10-27T00:00:00")),
    ("affected names nothing", lambda a: a["affected"][0].update(versions=[], content_hashes=[])),
    ("blank version entry", lambda a: a["affected"][0].update(versions=[""])),
    ("blank supplier", lambda a: a["affected"][0].update(supplier="")),
])
def test_a_malformed_advisory_is_refused_by_the_cli_and_cleared_nowhere(tmp_path, name, mutate):
    enrol_cli(tmp_path, {"M02": FLEET["M02"]}, "f.db")
    bad = copy.deepcopy(A1)
    mutate(bad)
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    run = assurance("fleet", "advisory", "bad.json", "--ledger", "f.db", "--json", cwd=tmp_path)
    assert run.exit != 0, (name, run.out[:200])
    assert "Traceback" not in run.err
    assert "clear" not in run.out.lower()


# ------------------------------------------------------------------------------- API parity
_ok, _why = api_importable()
needs_api = pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})")


@pytest.fixture(scope="module")
def api():
    if not _ok:
        pytest.skip(f"BLOCKED: product API not runnable ({_why})")
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def cell(api):
    key = api.make_account("fleet-cell@example.invalid", "cell")
    for serial, m in FLEET.items():
        status, body = call(api.base, "POST", "/v1/machinery/manifest", key=key,
                            body={"manifest": m, "actor": "synthetic.tech"})
        assert status == 200, (serial, body)
    return key


@needs_api
@pytest.mark.parametrize("adv,expect", [(A1, EXPECT_A1), (A2, EXPECT_A2)],
                         ids=["label-advisory", "hash-advisory"])
def test_the_api_classifies_every_machine_exactly_as_the_cli_does(api, cell, r1, r2, adv, expect):
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=cell, body={"advisory": adv})
    assert status == 200
    assert classes(body) == expect
    cli = (r1 if adv is A1 else r2)[1]
    for field in ("verdict", "machines_in_fleet", "machines_affected", "clear_is_complete",
                  "functions_newly_in_question", "unknown_machines", "incomplete"):
        assert body[field] == cli[field], field
    assert exposure_conf(body) == exposure_conf(cli)


@needs_api
@pytest.mark.parametrize("serial", sorted(FLEET))
def test_the_free_single_machine_check_agrees_with_the_fleet_fan_out_for_every_machine(
        api, cell, r1, r2, serial):
    for adv, report in ((A1, r1[1]), (A2, r2[1])):
        status, one = call(api.base, "POST", "/v1/fleet/advisory/check", key=cell,
                           body={"advisory": adv, "manifest": FLEET[serial]})
        assert status == 200, one
        fleet_class = classes(report)[serial]
        if fleet_class == "no_match_found":
            assert one["affected"] is False and one["matches"] == [], (serial, adv["advisory_id"])
        else:
            assert one["affected"] is True and one["matches"], (serial, adv["advisory_id"])
            basis = {c["machine"].rsplit("#", 1)[1]: c["basis"]
                     for c in report["machine_classification"]}[serial]
            assert {m["basis"] for m in one["matches"]} == {basis}, serial


@needs_api
def test_the_free_check_never_says_confirmed_for_a_label_and_says_what_it_did_not_do(api):
    status, one = call(api.base, "POST", "/v1/fleet/advisory/check",
                       body={"advisory": A1, "manifest": FLEET["M01"]})
    assert status == 200 and {m["confidence"] for m in one["matches"]} == {"probable"}
    assert any("one manifest" in s for s in one["checks_skipped"])
    assert any("published no artefact hashes" in s for s in one["checks_skipped"])


@needs_api
def test_another_accounts_fleet_is_invisible_and_its_answer_is_its_own(api, cell):
    other = api.make_account("fleet-other@example.invalid", "cell")
    assert call(api.base, "POST", "/v1/machinery/manifest", key=other, body={
        "manifest": FLEET["M02"], "actor": "synthetic.tech"})[0] == 200
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=other, body={"advisory": A1})
    assert status == 200 and body["machines_in_fleet"] == 1 and body["machines_affected"] == []
    assert body["verdict"] == "clear"
    status, mine = call(api.base, "GET", "/v1/fleet/machines", key=other)
    assert status == 200 and "M01" not in json.dumps(mine)
    # and the first account still has all fourteen
    assert call(api.base, "POST", "/v1/fleet/advisory", key=cell,
                body={"advisory": A1})[1]["machines_in_fleet"] == 14


@needs_api
def test_an_account_with_no_machines_is_not_told_its_clear_is_complete(api):
    """FIXED upstream (neuralbridge#83)."""
    empty = api.make_account("fleet-empty-flag@example.invalid", "cell")
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=empty, body={"advisory": A1})
    assert status == 200 and body["machines_in_fleet"] == 0
    assert body["clear_is_complete"] is False


@needs_api
@pytest.mark.xfail(strict=True, reason=EMPTY_FLEET_DEFECT + " [API]")
def test_an_account_with_no_machines_is_not_told_its_fleet_is_clear(api):
    empty = api.make_account("fleet-empty@example.invalid", "cell")
    status, body = call(api.base, "POST", "/v1/fleet/advisory", key=empty, body={"advisory": A1})
    assert status == 200 and body["machines_in_fleet"] == 0
    assert body["verdict"] != "clear", body["verdict"]


@needs_api
def test_assessing_over_the_api_records_nothing(api, cell):
    def length():
        return call(api.base, "GET", "/v1/ledger/verify", key=cell)[1]["attestation"]["length"]
    before = length()
    for adv in (A1, A2):
        status, _ = call(api.base, "POST", "/v1/fleet/advisory", key=cell, body={"advisory": adv})
        assert status == 200
    assert length() == before


@needs_api
@pytest.mark.parametrize("name,body", [
    ("extra field", {"advisory": A1, "machines": ["x"]}),
    ("advisory not an object", {"advisory": "ADV-A1"}),
    ("advisory missing", {}),
    ("affected not a list", {"advisory": {**A1, "affected": "all"}}),
    ("naive issued_at", {"advisory": {**A1, "issued_at": "2026-10-27T00:00:00"}}),
    ("blank fixed version", {"advisory": {**A1, "fixed_versions": [""]}}),
    ("unknown severity", {"advisory": {**A1, "severity": "catastrophic"}}),
    ("year 9999 issued_at", {"advisory": {**A1, "issued_at": "9999-12-31T23:59:59-23:59"}}),
    ("huge affected list", {"advisory": {**A1, "affected": [A1["affected"][0]] * 20000}}),
])
def test_a_malformed_advisory_over_the_api_is_4xx_never_5xx_and_never_a_verdict(api, cell, name,
                                                                                body):
    status, resp = call(api.base, "POST", "/v1/fleet/advisory", key=cell, body=body)
    assert 400 <= status < 500 or status == 0, (name, status, str(resp)[:200])
    assert "verdict" not in resp
    assert call(api.base, "GET", "/healthz")[0] == 200
