"""ATTACK MATRIX, product CLI level: key rotation and backup/restore of an attested ledger.

Evidence level: product CLI, local subprocess, real SQLite and real Ed25519 keys, SYNTHETIC data.

Independent expectations (stated here, not read from the product):
* a signing key must not change silently: a different key is refused unless the operator says
  it is a rotation, and a refused attempt writes nothing;
* a log signed by two keys must never be certified by ONE of them alone;
* restoring the ledger from a backup that is identical to the current ledger changes nothing;
* restoring an OLDER backup is a rollback: it must be detected by `attest verify --ledger`,
  and the signer must refuse to attest the rolled-back ledger, leaving the log untouched.

Known limit, reported not asserted: after a legitimate rotation no single `attest verify`
call can pass (the CLI has no per-span verification), so a rotated deployment reads red.
"""
from __future__ import annotations

import json
import shutil

import pytest
from support_cli import assurance, synthetic_manifest


@pytest.fixture()
def lab(tmp_path):
    work, keys = tmp_path / "w", tmp_path / "keys"
    work.mkdir()
    keys.mkdir()
    ledger, log = work / "l.db", work / "a.log"

    class Lab:
        def record(self, serial):
            p = work / f"{serial}.json"
            p.write_text(json.dumps(synthetic_manifest(serial, [("P", "x", "1")])))
            assert assurance("machinery", "record-manifest", str(p), "--ledger", str(ledger),
                             cwd=work).exit == 0

        def keygen(self, name):
            assert assurance("attest", "keygen", "--out", str(keys / f"{name}.key"),
                             "--public-out", str(keys / f"{name}.pub"), cwd=work).exit == 0

        def sign(self, name, *extra):
            return assurance("attest", "sign", "--ledger", str(ledger), "--key",
                             str(keys / f"{name}.key"), "--log", str(log), *extra, "--json",
                             cwd=work)

        def verify(self, name, with_ledger=False):
            args = ["attest", "verify", "--log", str(log), "--public-key",
                    str(keys / f"{name}.pub"), "--json"]
            if with_ledger:
                args += ["--ledger", str(ledger)]
            r = assurance(*args, cwd=work)
            return r, (r.json() if r.out.strip().startswith("{") else {})

    lab = Lab()
    lab.work, lab.ledger, lab.log = work, ledger, log
    return lab


def test_a_different_key_is_refused_without_the_rotation_flag_and_writes_nothing(lab):
    lab.keygen("a")
    lab.keygen("b")
    lab.record("S1")
    assert lab.sign("a").exit == 0
    before = lab.log.read_bytes()
    r = lab.sign("b")
    assert r.exit != 0
    assert lab.log.read_bytes() == before


def test_a_log_signed_by_two_keys_is_never_certified_by_one_of_them(lab):
    lab.keygen("a")
    lab.keygen("b")
    lab.record("S1")
    assert lab.sign("a").exit == 0
    lab.record("S2")
    assert lab.sign("b", "--rotating").exit == 0
    for name in ("a", "b"):
        r, body = lab.verify(name)
        assert r.exit != 0 and body["ok"] is False, f"key {name} certified a mixed-key log"


def test_restoring_an_identical_backup_changes_nothing(lab):
    lab.keygen("a")
    lab.record("S1")
    assert lab.sign("a").exit == 0
    backup = lab.work / "backup.db"
    shutil.copy(lab.ledger, backup)
    shutil.copy(backup, lab.ledger)                 # restore
    r, body = lab.verify("a", with_ledger=True)
    assert r.exit == 0 and body["ok"] is True


def test_restoring_an_older_backup_is_a_detected_rollback(lab):
    lab.keygen("a")
    lab.record("S1")
    lab.record("S2")
    assert lab.sign("a").exit == 0
    backup = lab.work / "backup.db"
    shutil.copy(lab.ledger, backup)
    lab.record("S3")
    assert lab.sign("a").exit == 0
    shutil.copy(backup, lab.ledger)                 # operator restores the older backup
    r, body = lab.verify("a", with_ledger=True)
    assert r.exit != 0 and body["ok"] is False
    assert any("removed" in p for p in body["problems"]), body["problems"]
    before = lab.log.read_bytes()
    assert lab.sign("a").exit != 0        # the signer will not attest a rolled-back ledger
    assert lab.log.read_bytes() == before
