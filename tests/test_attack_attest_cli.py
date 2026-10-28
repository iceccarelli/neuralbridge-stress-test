"""ATTACK MATRIX, product CLI level: the attestation log as the rollback witness.

Evidence level: product CLI, local subprocess, isolated temp directory, real SQLite and a
real signing key. Not API, not hosted staging.

Independent expectation (stated here, not read from the product): ``attest verify`` is the
check that a ledger was not rolled back. A log that is missing, empty, or removed has
established nothing about the ledger, so it must never exit 0 / report ``ok``. An attacker
who can truncate the ledger can also delete the attestation log; that must not turn a
rollback into a pass.
"""
from __future__ import annotations

import shutil
import sqlite3

import pytest
from support_cli import assurance, synthetic_manifest


@pytest.fixture()
def attested(tmp_path):
    import json
    work = tmp_path / "w"
    keys = tmp_path / "keys"
    work.mkdir()
    keys.mkdir()
    ledger, log = work / "l.db", work / "att.log"
    for i, serial in enumerate(("S1", "S2", "S3")):
        m = work / f"m{i}.json"
        m.write_text(json.dumps(synthetic_manifest(serial, [("P1", "1756-EN2T", "11.001")])))
        r = assurance("machinery", "record-manifest", str(m), "--ledger", str(ledger),
                      cwd=work)
        assert r.exit == 0, r.err
    k = assurance("attest", "keygen", "--out", str(keys / "k.key"), "--public-out",
                  str(keys / "k.pub"), cwd=work)
    assert k.exit == 0, k.err
    s = assurance("attest", "sign", "--ledger", str(ledger), "--key", str(keys / "k.key"),
                  "--log", str(log), cwd=work)
    assert s.exit == 0, s.err
    return work, ledger, log, keys / "k.pub", keys / "k.key"


def verify(work, log, pub, ledger=None, *extra):
    args = ["attest", "verify", "--log", str(log), "--public-key", str(pub), *extra]
    if ledger is not None:
        args += ["--ledger", str(ledger)]
    return assurance(*args, "--json", cwd=work)


def test_intact_ledger_verifies(attested):
    work, ledger, log, pub, _ = attested
    r = verify(work, log, pub, ledger)
    assert r.exit == 0 and r.json()["ok"] is True and r.json()["checked"] == 1


def test_rollback_is_detected(attested):
    work, ledger, log, pub, _ = attested
    con = sqlite3.connect(ledger)
    con.execute("DELETE FROM chain WHERE seq = (SELECT MAX(seq) FROM chain)")
    con.commit()
    con.close()
    r = verify(work, log, pub, ledger)
    assert r.exit != 0 and r.json()["ok"] is False


def test_wrong_key_is_refused(attested, tmp_path):
    work, ledger, log, pub, _ = attested
    other = tmp_path / "keys2"
    other.mkdir()
    assert assurance("attest", "keygen", "--out", str(other / "o.key"), "--public-out",
                     str(other / "o.pub"), cwd=work).exit == 0
    r = verify(work, log, other / "o.pub", ledger)
    assert r.exit != 0 and r.json()["ok"] is False


@pytest.mark.parametrize("how", ["missing", "empty"])
@pytest.mark.parametrize("with_ledger", [True, False])
def test_missing_or_empty_log_is_never_a_pass(attested, how, with_ledger):
    """Deleting or emptying the attestation log after a rollback must not read as OK."""
    work, ledger, log, pub, _ = attested
    if how == "missing":
        log.unlink()
    else:
        log.write_bytes(b"")
    r = verify(work, log, pub, ledger if with_ledger else None)
    assert r.exit != 0, f"exit 0 with a {how} log: {r.out}"
    assert r.json()["ok"] is False


def test_sign_refuses_a_tampered_ledger_and_writes_nothing(attested):
    work, ledger, log, pub, key = attested
    before = log.read_bytes()
    con = sqlite3.connect(ledger)
    con.execute("UPDATE chain SET subject = 'tampered' WHERE seq = 2")
    con.commit()
    con.close()
    r = assurance("attest", "sign", "--ledger", str(ledger), "--key", str(key), "--log",
                  str(log), cwd=work)
    assert r.exit != 0 and log.read_bytes() == before


def test_tampered_ledger_is_not_listed_as_healthy(attested):
    work, ledger, log, pub, _ = attested
    shutil.copy(ledger, work / "pristine.db")
    con = sqlite3.connect(ledger)
    con.execute("UPDATE chain SET subject = 'tampered' WHERE seq = 2")
    con.commit()
    con.close()
    r = assurance("fleet", "list", "--ledger", str(ledger), cwd=work)
    assert r.exit != 0
