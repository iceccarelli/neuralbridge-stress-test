"""ATTACK MATRIX, product CLI level: `machinery coverage` is a gate; it must not pass on
a ledger that has been tampered with.

Evidence level: product CLI, local subprocess, real SQLite, SYNTHETIC machine. The envelope
and trace are INPUT files copied from the product's examples directory (see
data/fixtures/machine/; inputs only, no expected results taken from the product).

Independent expectations:
* a safety function with no verification is never covered;
* a verified function becomes stale after a later intervention touches it;
* if that intervention row is deleted from the ledger, the chain no longer verifies and a
  coverage gate must not report 'covered' (exit 0) from the remaining rows.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from support_cli import assurance, synthetic_manifest

FIX = Path(__file__).parent.parent / "data" / "fixtures" / "machine"
KEY = "SynthCo/Cell-1#S1"


def _manifest():
    m = synthetic_manifest("S1", [("P1", "1756-EN2T", "11.001")])
    m["functions"][0]["verified_by"] = ["workspace_containment", "mode_consistency"]
    return m


def _intervention():
    return {
        "intervention_id": "INT-1", "machine_key": KEY, "item_id": "P1", "kind": "update",
        "occurred_at": "2026-10-01T09:30:00Z",
        "performed_by": {"identifier": "synthetic.tech", "role": "service technician",
                         "kind": "person"},
        "reason": "SYNTHETIC firmware update", "from_hash": "a" * 64, "to_hash": "d" * 64,
        "affects_functions": ["SF-1"], "authorization": None, "revalidation": None,
        "notes": "SYNTHETIC"}


@pytest.fixture()
def world(tmp_path):
    (tmp_path / "m.json").write_text(json.dumps(_manifest()))
    (tmp_path / "iv.json").write_text(json.dumps(_intervention()))
    (tmp_path / "other.json").write_text(
        json.dumps(synthetic_manifest("ZZ", [("P1", "x", "1")])))
    ledger = tmp_path / "l.db"

    def step(*args):
        r = assurance(*args, cwd=tmp_path)
        return r

    def coverage():
        r = step("machinery", "coverage", str(tmp_path / "m.json"), "--ledger", str(ledger),
                 "--json")
        return r, (r.json() if r.out.strip().startswith("{") else {})
    return tmp_path, ledger, step, coverage


def _verify(step, ledger):
    r = step("machine", "verify", "--envelope", str(FIX / "envelope.json"), "--trace",
             str(FIX / "trace.json"), "--actor", "synthetic.tech", "--ledger", str(ledger),
             "--subject", KEY)
    # the example trace violates other checks, so a non-zero exit is expected; what matters
    # is that the verification was sealed
    assert r.exit in (0, 1), r.err[-300:]


def test_a_function_with_no_verification_is_not_covered(world):
    root, ledger, step, coverage = world
    assert step("machinery", "record-manifest", str(root / "m.json"), "--ledger",
                str(ledger)).exit == 0
    r, j = coverage()
    assert r.exit != 0 and j["verdict"] != "covered"
    assert j["functions"][0]["coverage"] == "never_verified"


def test_a_later_intervention_makes_the_function_stale(world):
    root, ledger, step, coverage = world
    _verify(step, ledger)
    step("machinery", "record-manifest", str(root / "m.json"), "--ledger", str(ledger))
    r, j = coverage()
    assert r.exit == 0 and j["functions"][0]["coverage"] == "current"
    assert step("machinery", "record-change", str(root / "iv.json"), "--ledger",
                str(ledger)).exit == 0
    r, j = coverage()
    assert r.exit != 0 and j["functions"][0]["coverage"] == "stale"


def test_deleting_the_invalidating_intervention_does_not_restore_cover(world):
    root, ledger, step, coverage = world
    _verify(step, ledger)
    step("machinery", "record-manifest", str(root / "m.json"), "--ledger", str(ledger))
    step("machinery", "record-change", str(root / "iv.json"), "--ledger", str(ledger))
    # a later record, so the deletion breaks the chain in the middle rather than at the tail
    step("machinery", "record-manifest", str(root / "other.json"), "--ledger", str(ledger))
    assert coverage()[0].exit != 0           # stale before the attack
    con = sqlite3.connect(ledger)
    con.execute("DELETE FROM chain WHERE kind = 'machinery.intervention'")
    con.commit()
    con.close()
    # the other readers already refuse this ledger; the gate must agree
    assert step("fleet", "list", "--ledger", str(ledger)).exit == 2
    r, j = coverage()
    assert r.exit != 0, f"covered={j.get('verdict')} on a ledger whose chain is broken"
    assert j.get("verdict") != "covered" if j else True
