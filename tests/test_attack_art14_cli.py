"""ATTACK MATRIX, product CLI level: the Article 14 register under operator mistakes.

Evidence level: product CLI, local subprocess, real SQLite, SYNTHETIC cases.

Independent expectations (stated here, not read from the product):
* a mistake by the person at the keyboard (a second signal on a case, an unknown case, a time
  that cannot be read or has no timezone) is "could not do that": exit 2, a message on stderr,
  no traceback, and NOTHING written to the ledger;
* a case that does not exist is never shown as a case in some state: asking for it is an
  error, the same answer `art14 export` and the hosted API (404) already give;
* after any refused command the ledger still verifies.
"""
from __future__ import annotations

import sqlite3

import pytest
from support_cli import assurance

BY = ("--by", "t:analyst")


@pytest.fixture()
def reg(tmp_path):
    ledger = tmp_path / "l.db"

    def run(*args):
        return assurance("art14", "--ledger", str(ledger), *args, cwd=tmp_path)

    def entries():
        if not ledger.exists():
            return 0
        con = sqlite3.connect(ledger)
        try:
            return con.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
        finally:
            con.close()

    assert run("signal", "C1", *BY, "--description", "synthetic").exit == 0
    run.entries, run.root = entries, tmp_path
    return run


REFUSALS = {
    "a second signal on the same case": ("signal", "C1", *BY, "--description", "again"),
    "triage on a case with no track": ("triage", "C1", *BY),
    "triage on an unknown case": ("triage", "NOPE", *BY),
    "an unreadable time": ("signal", "C2", *BY, "--at", "not-a-time", "--description", "d"),
    "a time with no timezone": ("signal", "C3", *BY, "--at", "2026-10-20T09:00:00",
                                "--description", "d"),
}


@pytest.mark.parametrize("label", list(REFUSALS))
def test_an_operator_mistake_is_exit_2_with_a_message_and_writes_nothing(reg, label):
    before = reg.entries()
    run = reg(*REFUSALS[label])
    assert run.exit == 2, f"{label}: exit {run.exit}"
    assert "Traceback" not in run.err, label
    assert run.err.strip(), f"{label}: no message on stderr"
    assert reg.entries() == before, f"{label}: the ledger changed"
    assert reg("verify").exit == 0


def test_asking_for_a_case_that_does_not_exist_is_an_error_not_an_empty_case(reg):
    run = reg("case", "NOPE")
    assert run.exit == 2
    assert "signal_received" not in run.out
    assert "NOPE" in run.err
    assert "NOPE" not in reg("register").out
    assert reg("case", "C1").exit == 0            # a real case still shows
