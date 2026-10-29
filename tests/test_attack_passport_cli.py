"""ATTACK MATRIX, product CLI level: the machine passport is what a customer hands an auditor,
and `machinery check` is how the auditor re-checks it without trusting the producer.

Evidence level: product CLI, local subprocess, real SQLite, SYNTHETIC machine.

Independent expectations (stated here, not read from the product):
* any edit to anything the passport prints must make `machinery check` fail, or else the
  check must say, by name, that the edited part was not checked. In particular the printed
  evidence tier floor is the field that says community or validated: raising it by hand must
  never survive a check that reports ok;
* a passport that is truncated, empty or the wrong JSON type fails cleanly (no traceback);
* a passport is only vouched for against the ledger it was sealed into.
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from support_cli import assurance, synthetic_manifest

KEY = "SynthCo/Cell-1#S1"


@pytest.fixture()
def world(tmp_path):
    ledger, manifest = tmp_path / "l.db", tmp_path / "m.json"
    manifest.write_text(json.dumps(synthetic_manifest("S1", [("P", "x", "1")])))
    (tmp_path / "iv.json").write_text(json.dumps({
        "intervention_id": "INT-1", "machine_key": KEY, "item_id": "P", "kind": "update",
        "occurred_at": "2026-10-01T09:30:00Z",
        "performed_by": {"identifier": "synthetic.tech", "role": "service technician",
                         "kind": "person"},
        "reason": "SYNTHETIC firmware update", "from_hash": "a" * 64, "to_hash": "d" * 64,
        "affects_functions": ["SF-1"], "authorization": None, "revalidation": None,
        "notes": "SYNTHETIC"}))
    assert assurance("machinery", "record-manifest", str(manifest), "--ledger", str(ledger),
                     cwd=tmp_path).exit == 0
    assert assurance("machinery", "record-change", str(tmp_path / "iv.json"), "--ledger",
                     str(ledger), cwd=tmp_path).exit == 0
    passport = tmp_path / "p.json"
    made = assurance("machinery", "passport", str(manifest), "--ledger", str(ledger), "--actor",
                     "synthetic.tech", "--out", str(passport), cwd=tmp_path)
    assert passport.is_file(), made.err

    class W:
        root, db, file = tmp_path, ledger, passport

        @staticmethod
        def check(path=passport, db=ledger):
            args = ["machinery", "check", str(path), "--json"]
            if db is not None:
                args += ["--ledger", str(db)]
            run = assurance(*args, cwd=tmp_path)
            body = json.loads(run.out) if run.out.strip().startswith("{") else {}
            return run, body

        @staticmethod
        def edited(mutate):
            doc = json.loads(passport.read_text())
            mutate(doc)
            out = tmp_path / "edited.json"
            out.write_text(json.dumps(doc))
            return out
    return W


def test_an_untouched_passport_checks_ok_against_its_own_ledger(world):
    run, body = world.check()
    assert run.exit == 0 and body["ok"] is True


@pytest.mark.parametrize("field,value", [
    ("evidence_tier_floor", "validated"),
    ("configuration_hash", "0" * 64),
    ("manifest_id", "SOME-OTHER-MANIFEST"),
    ("assessed_at", "2030-01-01T00:00:00Z"),
    ("machine", "SynthCo/Cell-1#OTHER-UNIT"),
])
def test_an_edit_to_the_printed_coverage_block_is_not_accepted(world, field, value):
    path = world.edited(lambda d: d["coverage"].__setitem__(field, value))
    run, body = world.check(path)
    assert run.exit != 0 and body.get("ok") is False, (
        f"printed coverage.{field} changed to {value!r} and the check still said ok")


@pytest.mark.parametrize("field,value", [
    ("reason", "Routine inspection, nothing changed"),
    ("affects_functions", []),
    ("occurred_at", "2020-01-01T00:00:00Z"),
    ("kind", "inspection"),
])
def test_an_edit_to_a_printed_intervention_is_caught_against_the_ledger(world, field, value):
    path = world.edited(lambda d: d["interventions"][0].__setitem__(field, value))
    run, body = world.check(path)
    assert run.exit != 0 and body.get("ok") is False, (
        f"printed intervention.{field} was rewritten and the check against the ledger said ok")


def test_without_a_ledger_an_unchecked_intervention_list_is_named_not_waved_through(world):
    path = world.edited(lambda d: d["interventions"][0].__setitem__("reason", "nothing"))
    run, body = world.check(path, db=None)
    text = json.dumps(body)
    assert body.get("ok") is False or "intervention" in text.split("NOT CHECKED")[-1].lower(), \
        "an edited intervention passed with no statement that interventions were not checked"


@pytest.mark.parametrize("kind", ["truncated", "empty", "array", "binary"])
def test_a_malformed_passport_fails_cleanly(world, kind):
    path = world.root / "bad.json"
    text = world.file.read_text()
    if kind == "truncated":
        path.write_text(text[: len(text) // 2])
    elif kind == "empty":
        path.write_text("")
    elif kind == "array":
        path.write_text("[]")
    else:
        path.write_bytes(b"\xff\xfe\x00\x80")
    run, body = world.check(path)
    assert run.exit != 0 and "Traceback" not in run.err
    assert body.get("ok") is not True


def test_a_passport_is_not_vouched_for_by_a_different_ledger(world):
    other = world.root / "other.db"
    spare = world.root / "spare.json"
    spare.write_text(json.dumps(synthetic_manifest("ZZ", [("P", "x", "1")])))
    assert assurance("machinery", "record-manifest", str(spare), "--ledger", str(other),
                     cwd=world.root).exit == 0
    run, body = world.check(db=other)
    assert run.exit != 0 and body["ok"] is False


def test_a_passport_cannot_be_produced_from_a_tampered_ledger_as_if_nothing_were_wrong(world):
    con = sqlite3.connect(world.db)
    con.execute("UPDATE chain SET subject = 'tampered' WHERE seq = 1")
    con.commit()
    con.close()
    out = world.root / "p2.json"
    run = assurance("machinery", "passport", str(world.root / "m.json"), "--ledger",
                    str(world.db), "--actor", "synthetic.tech", "--out", str(out),
                    cwd=world.root)
    assert run.exit != 0
    if out.is_file():
        _, body = world.check(out)
        assert body.get("ok") is not True
