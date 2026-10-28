"""ATTACK MATRIX, product CLI level: duplicate delivery of the same manifest.

Evidence level: product CLI, local subprocess, real SQLite, SYNTHETIC machine.

Independent expectation: re-delivering byte-identical evidence must not change what the
product says about the fleet, and must stay identifiable as the same content (same hash), so
an auditor can see it was a redelivery and not two observations.

Not asserted here (a product-design decision, reported separately): what should happen when a
DIFFERENT manifest reuses an existing manifest_id.
"""
from __future__ import annotations

import json
import sqlite3

from support_cli import assurance, synthetic_manifest


def _fleet(tmp, ledger):
    r = assurance("fleet", "list", "--ledger", str(ledger), "--json", cwd=tmp)
    return r.exit, r.json()


def test_an_identical_redelivery_changes_nothing_the_fleet_reports(tmp_path):
    ledger = tmp_path / "l.db"
    m = tmp_path / "m.json"
    m.write_text(json.dumps(synthetic_manifest("S1", [("P1", "1756-EN2T", "11.001")])))
    first = assurance("machinery", "record-manifest", str(m), "--ledger", str(ledger),
                      cwd=tmp_path)
    assert first.exit == 0
    before = _fleet(tmp_path, ledger)
    second = assurance("machinery", "record-manifest", str(m), "--ledger", str(ledger),
                       cwd=tmp_path)
    assert second.exit == 0
    after = _fleet(tmp_path, ledger)
    assert before[0] == after[0]
    assert before[1]["machines"] == after[1]["machines"]
    # still identifiable as the same content: the sealed hash is stated in both outputs
    seal = first.out.split("sealed ", 1)[1].split()[0]
    assert second.out.split("sealed ", 1)[1].split()[0] == seal
    con = sqlite3.connect(ledger)
    hashes = [r[0] for r in con.execute("select content_hash from chain order by seq")]
    assert len(hashes) == 2 and hashes[0] == hashes[1]
    # and the chain still verifies with the duplicate in it
    assert _fleet(tmp_path, ledger)[1].get("chain_verified", True) is True
