"""ATTACK MATRIX, the watch: what runs when nobody is looking (``assurance watch``).

Evidence level: product CLI as subprocesses, real SQLite ledger, a SYNTHETIC cell (the offline
kit's export folder built by tests/test_attack_offline_kit.make_kit), real Ed25519 keys for the
feed cases, and for ``watch push`` a RECORDING listener on loopback that proves exactly what is
and is not sent. Never a real host, never a real key, never the hosted API.

Independent expectations, from the module's own promises and plain logic:

* "I could not look" and "nothing moved" never share an exit code or a status: a folder that is an
  export of a machine, not a look at it, is never reported as unchanged; a missing export is a
  gap, not silence; a watch that has stopped is itself a finding;
* a change is detected where the content moved and not where only a declared stamp moved;
* a path that leads out of the export folder is not followed;
* a draft is not a filing: nothing is recorded as submitted;
* a supplier feed that is not the one the configured key signed produces no finding that could
  act, and an unreadable feed is a failure to look, not an empty feed;
* ``watch push`` sends only what it says it sends (no paths, no file contents, no failure reason),
  only to the host named, never follows a redirect, never prints or stores the key, refuses a URL
  the product's own policy refuses, and retries a bounded number of times.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest
from support_cli import assurance, audited
from support_mcp import recording_server
from test_attack_offline_kit import make_kit

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

QUIET, CHANGED, COULD_NOT_LOOK, USAGE = 0, 1, 2, 2
KEY_ENV = "NB_TEST_WATCH_KEY"
KEY_VALUE = "nb_SYNTHETIC_WATCH_KEY_must_never_appear_in_output_0123456789"


class Cell:
    def __init__(self, work: Path, *, read_from_machine=True, **config):
        self.work = work
        self.site = make_kit(work)
        self.root = self.site / "exports" / "CELL-0412"
        target = {"serial": "CELL-0412", "plan": str(self.site / "plans/cell.json"),
                  "root": str(self.root), "site": "Hall 2", "country": "DE", "year": "2026",
                  "read_from_machine": read_from_machine}
        self.config = {"watch_id": "W1", "max_age_hours": 24, "targets": [target], **config}
        self.write_config()

    def write_config(self):
        (self.work / "watch.json").write_text(json.dumps(self.config))

    def run(self, *flags):
        return assurance("watch", "run", "watch.json", "--ledger", "l.db", *flags, cwd=self.work)

    def run_json(self):
        run = self.run("--json")
        return run, (json.loads(run.out) if run.out.strip().startswith("{") else {})

    def status(self, *flags):
        return assurance("watch", "status", "watch.json", "--ledger", "l.db", "--json", *flags,
                         cwd=self.work)

    def kinds(self):
        con = sqlite3.connect(self.work / "l.db")
        try:
            return dict(con.execute("SELECT kind, count(*) FROM chain GROUP BY kind"))
        finally:
            con.close()

    def ledger_len(self):
        path = self.work / "l.db"
        if not path.exists():
            return 0
        con = sqlite3.connect(path)
        try:
            return con.execute("SELECT count(*) FROM chain").fetchone()[0]
        finally:
            con.close()

    def outcome(self, report):
        return report["outcomes"][0]


@pytest.fixture()
def cell(tmp_path):
    return Cell(tmp_path)


def before_kinds_plus_observation(before):
    """A quiet pass records that it looked (an observation and a run record) and seals nothing
    else: no manifest, no divergence, no case."""
    after = dict(before)
    after["watch.observation"] = after.get("watch.observation", 0) + 1
    after["watch.run"] = after.get("watch.run", 0) + 1
    return after


# ------------------------------------------------------------------ quiet, changed, could not look
def test_the_first_pass_is_a_finding_and_an_identical_second_pass_on_the_machine_is_quiet(cell):
    run, report = cell.run_json()
    assert run.exit == CHANGED and report["verdict"] == "findings"
    assert cell.outcome(report)["status"] == "first_seen"
    assert report["sealed"] and "manifest" in report["sealed"][0]
    before = cell.kinds()
    run, report = cell.run_json()
    assert run.exit == QUIET and report["verdict"] != "findings", report["verdict"]
    assert cell.outcome(report)["status"] == "observed"     # looked at the machine; nothing moved
    assert report["sealed"] == [] and cell.kinds() == before_kinds_plus_observation(before)


def test_an_export_folder_is_never_reported_unchanged_it_is_not_a_look_at_the_machine(tmp_path):
    cell = Cell(tmp_path, read_from_machine=False)
    assert cell.run().exit == CHANGED
    run, report = cell.run_json()
    assert run.exit == COULD_NOT_LOOK and report["verdict"] == "degraded"
    out = cell.outcome(report)
    assert out["status"] != "unchanged" and "not a look at the machine" in out["detail"]
    assert "not_a_look" in out and "supplied by a vendor" in out["not_a_look"]


def test_a_change_to_the_content_is_detected_and_names_the_item_and_the_function(cell):
    assert cell.run().exit == CHANGED
    assert cell.run().exit == QUIET
    (cell.root / "scanner-zones.cfg").write_text("# Exported 2026-10-28\nzone1=0.9\n")
    run, report = cell.run_json()
    out = cell.outcome(report)
    assert run.exit == CHANGED and out["status"] == "changed"
    assert "ITM-ZONES" in out["drift_items"] and "SF-01" in out["affected_functions"]
    assert out["configuration_hash"] != out["previous_configuration"]


def test_only_the_declared_stamp_moving_is_not_a_change(cell):
    """Changed label, unchanged content: the plan declares the scanner export header a stamp."""
    assert cell.run().exit == CHANGED
    (cell.root / "scanner-zones.cfg").write_text("# Exported 2030-01-01\nzone1=0.5\n")
    run, report = cell.run_json()
    assert run.exit == QUIET and cell.outcome(report)["status"] == "observed"


def test_content_changed_but_the_same_stamp_is_still_a_change(cell):
    """Unchanged label, changed content."""
    assert cell.run().exit == CHANGED
    (cell.root / "scanner-zones.cfg").write_text("# Exported 2026-10-27\nzone1=0.1\n")
    run, report = cell.run_json()
    assert run.exit == CHANGED and cell.outcome(report)["status"] == "changed"


def test_a_firmware_swap_with_the_same_name_is_a_change(cell):
    assert cell.run().exit == CHANGED
    (cell.root / "controller-fw.bin").write_bytes(b"\x00FW a different image")
    run, report = cell.run_json()
    assert run.exit == CHANGED and "ITM-FW" in cell.outcome(report)["drift_items"]


def test_a_change_in_the_plc_program_member_is_a_change_a_member_timestamp_is_not(cell):
    assert cell.run().exit == CHANGED
    archive = cell.root / "plc-project.zip"
    with zipfile.ZipFile(archive, "w") as z:                         # same program, new stamps
        z.writestr(zipfile.ZipInfo("program/main.st", (2030, 1, 1, 0, 0, 0)),
                   "PROGRAM main END_PROGRAM")
        z.writestr("meta/build.txt", "build 99")
    run, report = cell.run_json()
    assert run.exit == QUIET and cell.outcome(report)["status"] == "observed"
    with zipfile.ZipFile(archive, "w") as z:                         # the program itself moves
        z.writestr("program/main.st", "PROGRAM main (* edited *) END_PROGRAM")
    run, report = cell.run_json()
    assert run.exit == CHANGED and "ITM-PLC" in cell.outcome(report)["drift_items"]


def test_a_missing_export_is_loud_incomplete_and_opens_a_case_never_silence(cell):
    assert cell.run().exit == CHANGED
    assert cell.run().exit == QUIET
    (cell.root / "controller-fw.bin").unlink()
    run, report = cell.run_json()
    out = cell.outcome(report)
    assert run.exit == CHANGED and report["verdict"] == "findings"
    assert out["collection_complete"] is False and out["status"] not in ("observed", "unchanged")
    assert "ITM-FW" in out["drift_items"] and "ITM-FW" in out["detail"]
    assert any("not found" in w and "covers less than the plan" in w for w in out["warnings"])
    assert any(x.startswith("case ") for x in report["sealed"]), "no case was opened"


FW_ADVISORY = {
    "advisory_id": "ADV-FW", "issued_by": "SynthCo", "issued_at": "2026-10-27T00:00:00Z",
    "title": "synthetic", "summary": "s", "severity": "safety_relevant",
    "affected": [{"supplier": "SynthCo", "name": "Safety controller firmware", "versions": ["V1"],
                  "content_hashes": [], "version_note": ""}],
    "remedy": "", "reference": "https://example.invalid/fw", "fixed_versions": [],
    "fixed_hashes": []}


def firmware_advisory(cell):
    (cell.work / "adv.json").write_text(json.dumps(FW_ADVISORY))
    run = assurance("fleet", "advisory", "adv.json", "--ledger", "l.db", "--json", cwd=cell.work)
    return run, run.json()["advisories"][0]


def test_the_control_before_any_gap_an_advisory_against_the_firmware_matches(cell):
    assert cell.run().exit == CHANGED
    run, adv = firmware_advisory(cell)
    assert run.exit == CHANGED and adv["machines_affected"] == ["SynthCo/Cell-1#CELL-0412"]


GAP_DEFECT = (
    "PRODUCT DEFECT (safety-relevant, false negative): when a plan item's export is briefly "
    "missing, the watch seals a manifest WITHOUT that item and makes it the machine's current "
    "configuration; `fleet advisory` then reports no match for an advisory against the missing "
    "item (exit 0). When the export returns, the watch compares against the older complete look, "
    "says 'unchanged at <hash>' (quiet, exit 0), seals nothing, and the fleet view keeps the "
    "machine without that item. An advisory against the safety controller firmware is then "
    "missed until something else changes. Remove the marker when the fleet view cannot silently "
    "lose an item to a transient read failure.")


@pytest.mark.xfail(strict=True, reason=GAP_DEFECT + " [during the gap]")
def test_during_a_gap_an_advisory_against_the_missing_item_is_not_cleared(cell):
    assert cell.run().exit == CHANGED
    (cell.root / "controller-fw.bin").unlink()
    assert cell.run().exit == CHANGED
    run, adv = firmware_advisory(cell)
    cls = {c["classification"] for c in adv["machine_classification"]}
    assert cls != {"no_match_found"} and run.exit != QUIET, (
        "an incomplete look of the machine was read as 'the advisory does not apply'")


@pytest.mark.xfail(strict=True, reason=GAP_DEFECT + " [after the export returns]")
def test_after_the_export_returns_the_fleet_view_has_the_item_again(cell):
    assert cell.run().exit == CHANGED
    fw = cell.root / "controller-fw.bin"
    data = fw.read_bytes()
    fw.unlink()
    assert cell.run().exit == CHANGED
    fw.write_bytes(data)
    cell.run()
    run, adv = firmware_advisory(cell)
    assert adv["machines_affected"] == ["SynthCo/Cell-1#CELL-0412"], (
        "the machine's firmware is back, the watch is quiet, and the fleet still has no firmware")


def test_a_restored_export_completes_the_look_and_the_watch_compares_with_the_last_complete_one(
        cell):
    assert cell.run().exit == CHANGED
    fw = cell.root / "controller-fw.bin"
    data = fw.read_bytes()
    fw.unlink()
    assert cell.run().exit == CHANGED
    fw.write_bytes(data)
    run, report = cell.run_json()
    out = cell.outcome(report)
    assert out["collection_complete"] is True and not out["warnings"]
    assert out["configuration_hash"] == out["previous_configuration"] or "unchanged at" in out[
        "detail"]


def test_a_vanished_export_folder_is_could_not_look_not_unchanged(cell):
    assert cell.run().exit == CHANGED
    shutil.rmtree(cell.root)
    run, report = cell.run_json()
    assert run.exit == COULD_NOT_LOOK and cell.outcome(report)["status"] != "unchanged"
    assert report["verdict"] == "degraded"


def test_a_zero_byte_or_directory_where_a_file_belongs_is_reported_not_crashed(cell):
    assert cell.run().exit == CHANGED
    (cell.root / "robot-params.json").write_text("")
    run, report = cell.run_json()
    assert "Traceback" not in run.err and run.exit in (CHANGED, COULD_NOT_LOOK)
    (cell.root / "scanner-zones.cfg").unlink()
    (cell.root / "scanner-zones.cfg").mkdir()
    run, report = cell.run_json()
    assert "Traceback" not in run.err and run.exit in (CHANGED, COULD_NOT_LOOK)


def test_a_dry_run_writes_nothing_and_a_dry_run_can_be_repeated(cell):
    for _ in range(2):
        run = cell.run("--dry-run")
        assert run.exit in (QUIET, CHANGED, COULD_NOT_LOOK) and "Traceback" not in run.err
    assert cell.ledger_len() == 0 and not (cell.work / "l.db").exists() or cell.ledger_len() == 0


def test_the_ledger_after_a_run_still_verifies(cell):
    cell.run()
    (cell.root / "scanner-zones.cfg").write_text("# Exported x\nzone1=0.7\n")
    cell.run()
    verdict = assurance("art14", "--ledger", "l.db", "verify", cwd=cell.work)
    assert verdict.exit == 0, verdict.err


def test_run_and_status_open_no_socket(cell):
    log = cell.work / "net.jsonl"
    run, events = audited("watch", "run", "watch.json", "--ledger", "l.db", "--json",
                          cwd=cell.work, log=log)
    assert run.exit in (CHANGED, QUIET) and events == [], events
    run, events = audited("watch", "status", "watch.json", "--ledger", "l.db", "--json",
                          cwd=cell.work, log=log)
    assert events == []


# ---------------------------------------------------------------------------- staleness
@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: `watch status` replays the last run's stored verdict and never compares it "
    "with the clock. The config says max_age_hours exists so that 'a watch that stopped running "
    "is not mistaken for a fleet that stopped changing'; but staleness is only computed inside a "
    "`run`, and a watch that has stopped never runs. A monitor polling `status` (or a person) "
    "reads 'quiet' from a run made weeks ago. Remove this marker when `status` reports a run "
    "older than max_age_hours as degraded (exit 2) with the age."))
def test_status_of_a_watch_that_has_stopped_does_not_read_quiet(tmp_path):
    cell = Cell(tmp_path, max_age_hours=0.0002)                       # 0.72 seconds
    assert cell.run().exit == CHANGED
    assert cell.run().exit == QUIET                                   # the last verdict: quiet
    time.sleep(2.0)
    late = cell.status()
    body = json.loads(late.out)
    assert late.exit == COULD_NOT_LOOK and body["verdict"] == "degraded", (
        f"status said {body['verdict']!r} (exit {late.exit}) about a run older than max_age_hours")


def test_status_reports_the_last_run_faithfully_while_it_is_fresh(cell):
    assert cell.run().exit == CHANGED
    assert cell.run().exit == QUIET
    fresh = cell.status()
    assert fresh.exit == QUIET and json.loads(fresh.out)["verdict"] == "quiet"


def test_status_before_any_run_is_not_a_quiet_fleet(cell):
    run = cell.status()
    assert run.exit != QUIET and "Traceback" not in run.err


# ------------------------------------------------------------------------- path escapes
def test_a_symlink_in_the_export_folder_that_leads_outside_it_is_not_followed(cell, tmp_path):
    outside = tmp_path / "outside-secret.cfg"
    outside.write_text("# Exported x\nthis is not the scanner's file\n")
    target = cell.root / "scanner-zones.cfg"
    target.unlink()
    target.symlink_to(outside)
    run, report = cell.run_json()
    out = cell.outcome(report)
    followed = out["collection_complete"] is True and out["status"] in ("first_seen", "changed")
    assert not followed, "a symlink out of the export folder was read as the scanner's export"
    assert "Traceback" not in run.err


def test_a_plan_item_that_names_a_path_outside_the_root_is_refused(cell):
    plan_path = cell.site / "plans/cell.json"
    plan = json.loads(plan_path.read_text())
    plan["items"][0]["source"] = "../../../../../../etc/hostname"
    plan_path.write_text(json.dumps(plan))
    run, report = cell.run_json()
    out = report["outcomes"][0] if report.get("outcomes") else {}
    assert run.exit == COULD_NOT_LOOK and out.get("collection_complete") is not True
    assert "Traceback" not in run.err


def test_an_absolute_plan_source_is_refused(cell):
    plan_path = cell.site / "plans/cell.json"
    plan = json.loads(plan_path.read_text())
    plan["items"][0]["source"] = "/etc/hostname"
    plan_path.write_text(json.dumps(plan))
    run, report = cell.run_json()
    out = report["outcomes"][0] if report.get("outcomes") else {}
    assert run.exit == COULD_NOT_LOOK and out.get("collection_complete") is not True


# ----------------------------------------------------------------- configuration validation
BAD_CONFIGS = {
    "no_targets": {"watch_id": "W", "targets": []},
    "no_watch_id": {"watch_id": "", "targets": [{"serial": "S", "plan": "p", "root": "r"}]},
    "target_missing_plan": {"watch_id": "W", "targets": [{"serial": "S", "root": "r"}]},
    "target_missing_serial": {"watch_id": "W", "targets": [{"plan": "p", "root": "r"}]},
    "blank_root": {"watch_id": "W", "targets": [{"serial": "S", "plan": "p", "root": ""}]},
    "duplicate_serial": {"watch_id": "W", "targets": [
        {"serial": "S", "plan": "p", "root": "r"}, {"serial": "S", "plan": "p", "root": "r"}]},
    "zero_max_age": {"watch_id": "W", "max_age_hours": 0,
                     "targets": [{"serial": "S", "plan": "p", "root": "r"}]},
    "negative_max_age": {"watch_id": "W", "max_age_hours": -5,
                         "targets": [{"serial": "S", "plan": "p", "root": "r"}]},
    "text_max_age": {"watch_id": "W", "max_age_hours": "soon",
                     "targets": [{"serial": "S", "plan": "p", "root": "r"}]},
    "duplicate_feed": {"watch_id": "W", "targets": [{"serial": "S", "plan": "p", "root": "r"}],
                       "feeds": [{"supplier_id": "a", "feed": "f", "public_key": "k"},
                                 {"supplier_id": "a", "feed": "f", "public_key": "k"}]},
    "feed_without_key": {"watch_id": "W", "targets": [{"serial": "S", "plan": "p", "root": "r"}],
                         "feeds": [{"supplier_id": "a", "feed": "f", "public_key": ""}]},
    "manufacturer_without_receiver": {
        "watch_id": "W", "targets": [{"serial": "S", "plan": "p", "root": "r"}],
        "article_14": {"as_manufacturer": True, "received_by": ""}},
    "targets_not_a_list": {"watch_id": "W", "targets": "all"},
    "json_array": [1, 2, 3], "json_null": None, "json_scalar": 42,
}


@pytest.mark.parametrize("name", sorted(BAD_CONFIGS))
def test_a_malformed_watch_is_refused_with_a_message_and_watches_nothing(tmp_path, name):
    (tmp_path / "watch.json").write_text(json.dumps(BAD_CONFIGS[name]))
    run = assurance("watch", "run", "watch.json", "--ledger", "l.db", cwd=tmp_path)
    assert run.exit == USAGE and "Traceback" not in run.err and run.err.strip()
    assert not (tmp_path / "l.db").exists() or sqlite3.connect(
        tmp_path / "l.db").execute("SELECT count(*) FROM chain").fetchone()[0] == 0


@pytest.mark.parametrize("raw", [b"", b"not json", b"\x00\x01", b"{" * 5000, b'{"a":' * 3000])
def test_an_unreadable_watch_file_is_refused_not_a_traceback(tmp_path, raw):
    (tmp_path / "watch.json").write_bytes(raw)
    run = assurance("watch", "run", "watch.json", "--ledger", "l.db", cwd=tmp_path)
    assert run.exit == USAGE and "Traceback" not in run.err


def test_a_missing_ledger_directory_or_config_is_could_not_run(tmp_path):
    run = assurance("watch", "run", "nope.json", "--ledger", "l.db", cwd=tmp_path)
    assert run.exit == USAGE and "Traceback" not in run.err


# ------------------------------------------------------------------------ Article 14 drafts
DUTY = {"as_manufacturer": True, "received_by": "psirt@example.invalid"}
def test_without_a_declared_duty_no_regulatory_intake_is_drafted_and_the_run_says_why(
        tmp_path, feeds):
    cell = Cell(tmp_path)
    _with_feed(cell, "good.jsonl")
    run, report = cell.run_json()
    assert report["advisories"]["findings"], "the premise: an advisory found"
    assert report["filings"]["enabled"] is False and report["filings"]["prompts"] == []
    assert "No Article 14 duty is declared" in " ".join(report["checks_skipped"])


def test_a_declared_manufacturer_gets_drafts_that_are_not_filings_and_decide_nothing(
        tmp_path, feeds):
    cell = Cell(tmp_path, article_14=DUTY)
    _with_feed(cell, "good.jsonl")
    run, report = cell.run_json()
    assert report["filings"]["enabled"] is True and report["filings"]["prompts"], report["filings"]
    con = sqlite3.connect(cell.work / "l.db")
    kinds = {k for (k,) in con.execute("SELECT DISTINCT kind FROM chain")}
    assert "art14.filing" not in kinds, "a draft prompt was recorded as a submission"
    assert not [k for k in kinds if "awareness" in k], "the watch decided awareness"
    assert not [k for k in kinds if k.startswith("art14.") and k != "art14.signal"], kinds
    prompt = json.dumps(report["filings"]["prompts"]).lower()
    assert "awareness" in prompt


def test_a_target_with_no_country_is_a_named_gap_not_a_guess(tmp_path):
    cell = Cell(tmp_path)
    cell.config["targets"][0].pop("country")
    cell.write_config()
    run, report = cell.run_json()
    assert any("no country recorded" in c and "CELL-0412" in c for c in report["checks_skipped"])


def test_a_manufacturer_without_a_named_receiver_is_refused_at_load(tmp_path):
    cell = Cell(tmp_path, article_14={"as_manufacturer": True, "received_by": ""})
    run = cell.run()
    assert run.exit == USAGE and "received_by" in run.err


# --------------------------------------------------------------------------- supplier feeds
@pytest.fixture()
def feeds(tmp_path):
    work = tmp_path
    for name in ("s", "x"):
        assert assurance("supplier", "keygen", "--out", f"{name}.key", "--public-out",
                         f"{name}.pub", cwd=work).exit == 0
    adv = {"advisory_id": "ADV-W1", "issued_by": "SynthCo", "issued_at": "2026-10-27T00:00:00Z",
           "title": "synthetic", "summary": "s", "severity": "safety_relevant",
           "affected": [{"supplier": "SynthCo", "name": "Safety scanner zone set",
                         "versions": ["V1"], "content_hashes": [], "version_note": ""}],
           "remedy": "", "reference": "https://example.invalid/w1", "fixed_versions": [],
           "fixed_hashes": []}
    (work / "adv.json").write_text(json.dumps(adv))
    ident = ["--supplier-id", "synthco", "--legal-name", "SynthCo", "--key-contact",
             "x@example.invalid"]
    assert assurance("supplier", "publish", "adv.json", "--feed", "good.jsonl", "--key", "s.key",
                     *ident, cwd=work).exit == 0
    assert assurance("supplier", "publish", "adv.json", "--feed", "forged.jsonl", "--key",
                     "x.key", *ident, cwd=work).exit == 0
    return work


def _with_feed(cell, feed, key="s.pub"):
    cell.config["feeds"] = [{"supplier_id": "synthco", "feed": str(cell.work / feed),
                             "public_key": str(cell.work / key)}]
    cell.write_config()


def test_a_feed_signed_by_the_configured_key_produces_a_finding(tmp_path, feeds):
    cell = Cell(tmp_path)
    _with_feed(cell, "good.jsonl")
    run, report = cell.run_json()
    assert report["advisories"]["feeds"] and report["advisories"]["findings"], report["advisories"]
    assert run.exit == CHANGED


def test_a_feed_signed_by_another_key_produces_no_finding_that_could_act(tmp_path, feeds):
    cell = Cell(tmp_path)
    _with_feed(cell, "forged.jsonl")                    # signed by x, checked against s.pub
    run, report = cell.run_json()
    findings = report["advisories"]["findings"]
    assert findings == [] or all(f.get("automated_consequences_permitted") is not True
                                 and not f.get("case_id") for f in findings), findings
    feed = report["advisories"]["feeds"][0]
    assert feed["status"] == "unverifiable" and feed["new"] == [] and feed["cleared"] == 0
    assert "Do not act on this advisory" in json.dumps(feed["problems"])


@pytest.mark.parametrize("content", [b"", b"junk", b"[1]", b"\x00\x01"])
def test_an_unreadable_feed_is_a_failure_to_look_never_an_empty_feed(tmp_path, feeds, content):
    cell = Cell(tmp_path)
    (cell.work / "bad.jsonl").write_bytes(content)
    _with_feed(cell, "bad.jsonl")
    run, report = cell.run_json()
    assert run.exit != QUIET or report["verdict"] != "quiet", report["verdict"]
    assert "Traceback" not in run.err


def test_a_missing_feed_file_is_a_failure_to_look(tmp_path, feeds):
    cell = Cell(tmp_path)
    _with_feed(cell, "no-such-feed.jsonl")
    run, report = cell.run_json()
    assert report["verdict"] in ("degraded", "findings") and run.exit != QUIET


# ------------------------------------------------------------------------------ watch push
def _pushed_cell(tmp_path):
    cell = Cell(tmp_path)
    assert cell.run().exit == CHANGED
    return cell


def push(cell, url, *flags, key=KEY_VALUE):
    return assurance("watch", "push", "watch.json", "--ledger", "l.db", "--api-url", url,
                     "--key-env", KEY_ENV, *flags, cwd=cell.work,
                     extra_env={KEY_ENV: key} if key else {})


def test_push_dry_run_prints_the_bodies_opens_no_connection_and_never_the_key(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server() as rec:
        run = push(cell, rec.url, "--dry-run")
        assert rec.requests == []
    assert run.exit == 0, run.err
    assert KEY_VALUE not in run.out + run.err and "CELL-0412" in run.out


def test_what_leaves_the_plant_contains_no_path_no_file_content_and_no_failure_reason(tmp_path):
    cell = _pushed_cell(tmp_path)
    (cell.root / "controller-fw.bin").unlink()                 # a failed look, with a path in it
    cell.run()
    with recording_server(reply=lambda s: (200, {"accepted": True}, {})) as rec:
        run = push(cell, rec.url)
        sent = json.dumps([r.body for r in rec.requests])
    assert rec.requests and run.exit in (0, 1, 2), run.err
    for needle in (str(cell.work), str(cell.root), str(cell.site), "zone1=0.5",
                   "PROGRAM main END_PROGRAM", "FW synthetic", "/exports/", "plans/cell.json"):
        assert needle not in sent, needle
    assert KEY_VALUE not in sent
    assert all(r.path == "/v1/watch/report" and r.method == "POST" for r in rec.requests)


def test_the_key_goes_only_to_the_named_host_in_the_documented_header(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server() as rec:
        run = push(cell, rec.url)
    assert rec.requests and all(r.headers.get("x-api-key") == KEY_VALUE for r in rec.requests)
    assert KEY_VALUE not in run.out + run.err
    assert not any(KEY_VALUE in json.dumps(r.body) for r in rec.requests)


def test_a_redirect_is_never_followed_and_the_key_goes_nowhere_else(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server(bind="0.0.0.0") as elsewhere:     # noqa: S104
        def redirect(_):
            return 307, b"", {"location": f"http://127.0.0.1:{elsewhere.port}/stolen"}
        with recording_server(reply=redirect) as rec:
            run = push(cell, rec.url)
        assert elsewhere.requests == [], "a redirect was followed with the key"
    assert run.exit != 0 and KEY_VALUE not in run.out + run.err


@pytest.mark.parametrize("url_template", [
    "http://127.0.0.2:{port}", "http://user:pw@127.0.0.1:{port}", "http://127.0.0.1:{port}?x=1",
    "ftp://127.0.0.1:{port}", "file:///etc/passwd", "http://localhost.evil.example:{port}"])
def test_a_url_the_products_own_policy_refuses_is_refused_and_nothing_is_sent(tmp_path,
                                                                             url_template):
    cell = _pushed_cell(tmp_path)
    with recording_server(bind="0.0.0.0") as rec:           # noqa: S104
        run = push(cell, url_template.format(port=rec.port))
        assert rec.requests == [], url_template
    assert run.exit != 0 and KEY_VALUE not in run.out + run.err and "Traceback" not in run.err


def test_a_server_that_always_fails_is_retried_a_bounded_number_of_times(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server(reply=lambda s: (503, {"error": "down"}, {})) as rec:
        run = push(cell, rec.url, "--retries", "2", "--retry-wait", "0.05", "--timeout", "5")
        n = len(rec.requests)
    assert run.exit != 0 and 1 < n <= 3, n
    assert KEY_VALUE not in run.out + run.err


def test_a_401_is_not_retried_and_is_shown_without_the_key(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server(reply=lambda s: (401, {"detail": "bad key"}, {})) as rec:
        run = push(cell, rec.url, "--retries", "3", "--retry-wait", "0.05")
        assert len(rec.requests) == 1
    assert run.exit != 0 and KEY_VALUE not in run.out + run.err


def test_a_body_over_the_cap_is_refused_before_anything_is_sent(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server() as rec:
        run = push(cell, rec.url, "--max-body-bytes", "200")
        assert rec.requests == []
    assert run.exit != 0 and "Traceback" not in run.err


@pytest.mark.parametrize("argv", [["--key", "SYNTHETIC-KEY"], ["--api-key", "SYNTHETIC-KEY"]])
def test_a_key_given_on_the_command_line_is_refused_and_not_echoed(tmp_path, argv):
    cell = _pushed_cell(tmp_path)
    run = assurance("watch", "push", "watch.json", "--ledger", "l.db", "--api-url",
                    "http://127.0.0.1:9", "--key-env", KEY_ENV, *argv, cwd=cell.work)
    assert run.exit == USAGE and "SYNTHETIC-KEY" not in run.out + run.err


def test_an_unset_key_variable_is_a_clear_error_and_sends_nothing(tmp_path):
    cell = _pushed_cell(tmp_path)
    with recording_server() as rec:
        run = push(cell, rec.url, key=None)
        assert rec.requests == []
    assert run.exit != 0 and "Traceback" not in run.err


@pytest.mark.parametrize("name", ["", "has space", "1BAD", "A;B", "$(id)", "a" * 500])
def test_a_hostile_environment_variable_name_is_refused(tmp_path, name):
    cell = _pushed_cell(tmp_path)
    run = assurance("watch", "push", "watch.json", "--ledger", "l.db", "--api-url",
                    "http://127.0.0.1:9", "--key-env", name, cwd=cell.work)
    assert run.exit != 0 and "Traceback" not in run.err


def test_a_failed_look_is_pushed_as_a_failed_look_never_as_unchanged(tmp_path):
    cell = _pushed_cell(tmp_path)
    (cell.root / "controller-fw.bin").unlink()
    cell.run()
    with recording_server() as rec:
        push(cell, rec.url)
        bodies = json.dumps([r.body for r in rec.requests]).lower()
    statuses = {m["status"] for body in [r.body for r in rec.requests]
                for m in body.get("machines", [])}
    assert statuses and "unchanged" not in statuses, statuses
    assert statuses & {"incomplete", "uncollectable"}, (statuses, bodies[:300])
