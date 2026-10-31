"""ATTACK MATRIX, product CLI level: backing up and restoring the service's data directory.

Evidence level: product CLI (``python -m assurance.evidence.restore_check``), local subprocess,
isolated temporary directory, real SQLite, real Ed25519 attestation keys, SYNTHETIC signals and
throwaway accounts. Not API, not hosted staging, and not the production volume.

The data directory under test is built with the product's own public writers (the ``art14``
CLI, ``attest sign`` and ``AccountStore``) and then damaged from OUTSIDE, the way a hostile
operator, a bad restore or a failing disk would.

Independent expectations, stated here and not read from the product:

* an intact backup verifies (exit 0) and the manifest names every ledger, log and account;
* a restore that is missing, shorter than, older than, forked from, or different from what was
  backed up is a FINDING (exit 1), never a pass;
* a directory with no manifest can be consistent but cannot show that nothing is missing: that
  is "unchecked" (exit 3), never exit 0;
* a cut that the manifest alone could not catch (an attacker who also rewrote the manifest or
  removed it) is still caught when a signed attestation log remembers the longer ledger;
* the limit is real and is asserted, not hidden: with no manifest AND no attestation, a cut
  tail is invisible, and the tool must say "unchecked", not "ok";
* damaged files, symbolic links, unknown or foreign ledgers and unreadable manifests are
  findings, never a traceback and never exit 0;
* a backup leaves unclaimed plaintext checkout keys behind and is private to its owner.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from support_cli import assurance

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

OK, FINDING, COULD_NOT_RUN, UNCHECKED = 0, 1, 2, 3


def restore_check(*args: str, cwd: Path):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (PRODUCT_SRC, env.get("PYTHONPATH", "")) if p)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    done = subprocess.run([sys.executable, "-m", "assurance.evidence.restore_check", *args],
                          cwd=cwd, env=env, text=True, capture_output=True, timeout=120,
                          check=False)
    body = {}
    if done.stdout.strip().startswith("{"):
        body = json.loads(done.stdout)
    return done.returncode, body, done.stderr


def _accounts(path: Path, *emails: str) -> list[str]:
    code = ("import sys, json\n"
            "from assurance.billing.accounts import AccountStore\n"
            "s = AccountStore(sys.argv[1])\n"
            "ids = [s.upsert_account(email=e, tier='cell').id for e in sys.argv[2:]]\n"
            "print(json.dumps(ids))\n")
    done = subprocess.run([sys.executable, "-c", code, str(path), *emails],
                          env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def _signals(ledger: Path, work: Path, n: int, prefix: str = "C") -> None:
    for i in range(1, n + 1):
        run = assurance("art14", "--ledger", str(ledger), "signal", f"{prefix}{i}", "--by",
                        "t:analyst", "--at", f"2026-10-{i:02d}T08:00:00Z", "--description",
                        f"synthetic signal {prefix}{i}", "--product", "P", "--version", "1",
                        cwd=work)
        assert run.exit == 0, run.err


class Volume:
    """A throwaway data directory shaped like the service's volume."""

    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"
        self.keys = root / "keys"
        (self.data / "tenants").mkdir(parents=True)
        (self.data / "attestations").mkdir()
        self.keys.mkdir()
        self.acc_a, self.acc_b = _accounts(self.data / "accounts.db", "a@example.invalid",
                                           "b@example.invalid")
        self.op = self.data / "art14-register.db"
        self.ta = self.data / "tenants" / f"{self.acc_a}.db"
        self.tb = self.data / "tenants" / f"{self.acc_b}.db"
        self.log_a = self.data / "attestations" / f"{self.acc_a}.jsonl"
        _signals(self.op, root, 2, "OP")
        _signals(self.ta, root, 4, "A")
        _signals(self.tb, root, 3, "B")
        assert assurance("attest", "keygen", "--out", str(self.keys / "k.key"), "--public-out",
                         str(self.keys / "k.pub"), cwd=root).exit == 0
        self.sign()

    def sign(self) -> None:
        run = assurance("attest", "sign", "--ledger", str(self.ta), "--key",
                        str(self.keys / "k.key"), "--log", str(self.log_a), cwd=self.root)
        assert run.exit == 0, run.err

    def backup(self, name: str) -> Path:
        out = self.root / name
        code, body, err = restore_check("backup", str(self.data), str(out), cwd=self.root)
        assert code == 0, err
        assert body["manifest_sha256"]
        return out


def copy_of(backup: Path, tmp: Path, name: str) -> Path:
    dest = tmp / name
    shutil.copytree(backup, dest, symlinks=True)
    return dest


def delete_last_record(path: Path) -> None:
    db = sqlite3.connect(path)
    db.execute("DELETE FROM chain WHERE seq=(SELECT MAX(seq) FROM chain)")
    db.commit()
    db.close()


def snapshot_dir(vol: Volume, tmp: Path, name: str) -> Path:
    """A consistent copy of the live data dir (no SQLite sidecar files), without a manifest."""
    dest = tmp / name
    code, _, err = restore_check("backup", str(vol.data), str(dest), cwd=tmp)
    assert code == 0, err
    (dest / "backup-manifest.json").unlink()
    return dest


def verify(target: Path, *flags: str, cwd: Path):
    return restore_check("verify", *flags, str(target), cwd=cwd)


def problems(body) -> str:
    return " | ".join(body.get("problems", []))


@pytest.fixture()
def vol(tmp_path):
    return Volume(tmp_path)


@pytest.fixture()
def good(vol, tmp_path):
    """An intact backup of ``vol``, and a function that returns a fresh disposable copy."""
    base = vol.backup("backup-good")

    def fresh(name="victim"):
        return copy_of(base, tmp_path, name)
    fresh.base = base
    return fresh


# ------------------------------------------------------------------------- the baseline
def test_an_intact_backup_verifies_and_says_what_it_cannot_show(vol, good, tmp_path):
    code, body, _ = verify(good(), cwd=tmp_path)
    assert code == OK and body["status"] == "ok" and body["problems"] == []
    assert len(body["not_established"]) >= 3     # the limits are stated, not implied


def test_the_manifest_names_every_ledger_log_and_account_with_its_head(vol, good):
    m = json.loads((good.base / "backup-manifest.json").read_text())
    assert set(m["accounts"]) == {vol.acc_a, vol.acc_b}
    files = m["files"]
    assert {"accounts.db", "art14-register.db", f"tenants/{vol.acc_a}.db",
            f"tenants/{vol.acc_b}.db", f"attestations/{vol.acc_a}.jsonl"} <= set(files)
    assert files[f"tenants/{vol.acc_a}.db"]["entries"] == 4
    assert files[f"tenants/{vol.acc_b}.db"]["entries"] == 3
    assert files["art14-register.db"]["entries"] == 2
    assert len(files[f"tenants/{vol.acc_a}.db"]["head_link_hash"]) == 64
    assert files[f"attestations/{vol.acc_a}.jsonl"]["records"] == 1


def test_a_backup_is_private_to_its_owner(good):
    root = good.base
    assert stat.S_IMODE(root.stat().st_mode) & 0o077 == 0
    for p in root.rglob("*"):
        if p.is_file():
            assert stat.S_IMODE(p.stat().st_mode) & 0o077 == 0, p


def test_unclaimed_plaintext_checkout_keys_are_not_copied_into_a_backup(vol, tmp_path):
    secret = "nb_live_SYNTHETIC_UNCLAIMED_KEY_0123456789"
    db = sqlite3.connect(vol.data / "accounts.db")
    db.execute("INSERT INTO pending_keys (session_id, account_id, api_key, tier, created_at) "
               "VALUES ('cs_synthetic', ?, ?, 'cell', '2026-10-30T00:00:00Z')",
               (vol.acc_a, secret))
    db.commit()
    db.close()
    out = vol.backup("backup-with-pending")
    assert secret.encode() not in (out / "accounts.db").read_bytes()
    code, _, _ = restore_check("backup", str(vol.data), str(tmp_path / "again"), cwd=tmp_path)
    assert code == 0


def test_backup_stdout_never_prints_a_key(vol, tmp_path):
    code, body, err = restore_check("backup", str(vol.data), str(tmp_path / "b"), cwd=tmp_path)
    blob = json.dumps(body) + err
    assert code == 0 and "nb_live" not in blob and "PRIVATE KEY" not in blob


def test_backing_up_into_a_directory_that_holds_files_is_refused(vol, tmp_path):
    out = tmp_path / "occupied"
    out.mkdir()
    (out / "stale.db").write_text("x")
    code, _, err = restore_check("backup", str(vol.data), str(out), cwd=tmp_path)
    assert code == COULD_NOT_RUN and (out / "stale.db").read_text() == "x"
    assert "Traceback" not in err


def test_backing_up_a_missing_source_is_could_not_run_not_a_traceback(tmp_path):
    code, _, err = restore_check("backup", str(tmp_path / "nope"), str(tmp_path / "o"),
                                 cwd=tmp_path)
    assert code == COULD_NOT_RUN and "Traceback" not in err


def test_the_backup_is_a_snapshot_not_a_live_file_copy(vol, tmp_path):
    """The source stays untouched and a later write does not leak into the earlier backup."""
    out = vol.backup("snap")
    before = (out / "backup-manifest.json").read_text()
    _signals(vol.ta, tmp_path, 1, "LATE")
    assert (out / "backup-manifest.json").read_text() == before
    code, body, _ = verify(out, cwd=tmp_path)
    assert code == OK, problems(body)


# -------------------------------------------------------------- damage to the backed-up files
@pytest.mark.parametrize("which", ["ta", "tb", "op"])
def test_rewriting_a_payload_in_any_ledger_is_a_finding(vol, good, tmp_path, which):
    victim = good()
    rel = {"ta": f"tenants/{vol.acc_a}.db", "tb": f"tenants/{vol.acc_b}.db",
           "op": "art14-register.db"}[which]
    db = sqlite3.connect(victim / rel)
    (payload,) = db.execute("SELECT payload FROM chain WHERE seq=2").fetchone()
    db.execute("UPDATE chain SET payload=? WHERE seq=2", (payload.replace("2026", "2027"),))
    db.commit()
    db.close()
    code, body, err = verify(victim, cwd=tmp_path)
    assert code == FINDING and body["status"] == "failed" and "Traceback" not in err
    assert rel in problems(body)


@pytest.mark.parametrize("rel_name", ["accounts.db", "art14-register.db", "tenant_a", "tenant_b",
                                      "attestation_a"])
def test_a_file_the_manifest_lists_that_has_gone_is_a_finding(vol, good, tmp_path, rel_name):
    victim = good()
    rel = {"tenant_a": f"tenants/{vol.acc_a}.db", "tenant_b": f"tenants/{vol.acc_b}.db",
           "attestation_a": f"attestations/{vol.acc_a}.jsonl"}.get(rel_name, rel_name)
    (victim / rel).unlink()
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and rel in problems(body)


@pytest.mark.parametrize("damage", ["flip_record_bytes", "truncate_half", "garbage_header",
                                    "empty_file"])
def test_a_damaged_tenant_ledger_is_a_finding_never_a_traceback_or_ok(vol, good, tmp_path,
                                                                        damage):
    victim = good()
    path = victim / "tenants" / f"{vol.acc_a}.db"
    raw = bytearray(path.read_bytes())
    if damage == "flip_record_bytes":
        at = bytes(raw).find(b'"kind"')
        assert at > 0
        for i in range(at, at + 40):
            raw[i] ^= 0xFF
    elif damage == "truncate_half":
        raw = raw[: len(raw) // 2]
    elif damage == "garbage_header":
        raw[:16] = b"NOT A SQLITE FILE"[:16]
    else:
        raw = bytearray()
    path.write_bytes(bytes(raw))
    code, body, err = verify(victim, cwd=tmp_path)
    assert code == FINDING and "Traceback" not in err, (code, body, err)


def test_cutting_the_tail_of_a_ledger_in_a_manifested_backup_is_a_finding(vol, good, tmp_path):
    victim = good()
    delete_last_record(victim / "tenants" / f"{vol.acc_b}.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "sha256 differs" in problems(body)


def test_an_unlisted_extra_file_is_a_finding(vol, good, tmp_path):
    victim = good()
    (victim / "tenants" / "notes.txt").write_text("planted")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "not in the manifest" in problems(body)


def test_a_tenant_ledger_belonging_to_no_account_is_a_finding(vol, good, tmp_path):
    victim = good()
    shutil.copy(victim / "tenants" / f"{vol.acc_a}.db",
                victim / "tenants" / "acc_deadbeefdeadbeef.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "belongs to no account" in problems(body)


def test_a_tenant_file_with_a_hostile_name_is_a_finding(vol, good, tmp_path):
    victim = good()
    shutil.copy(victim / "tenants" / f"{vol.acc_a}.db", victim / "tenants" / "evil name.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "not a tenant ledger name" in problems(body)


def test_a_symbolic_link_standing_in_for_a_ledger_is_a_finding(vol, good, tmp_path):
    victim = good()
    outside = tmp_path / "elsewhere.db"
    shutil.copy(victim / "tenants" / f"{vol.acc_b}.db", outside)
    target = victim / "tenants" / f"{vol.acc_b}.db"
    target.unlink()
    target.symlink_to(outside)
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "symbolic link" in problems(body)


def test_swapping_one_tenants_ledger_for_anothers_is_a_finding(vol, good, tmp_path):
    victim = good()
    shutil.copy(victim / "tenants" / f"{vol.acc_b}.db", victim / "tenants" / f"{vol.acc_a}.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING


def test_an_account_removed_from_accounts_db_is_a_finding(vol, good, tmp_path):
    victim = good()
    db = sqlite3.connect(victim / "accounts.db")
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("DELETE FROM api_keys WHERE account_id=?", (vol.acc_b,))
    db.execute("DELETE FROM accounts WHERE id=?", (vol.acc_b,))
    db.commit()
    db.close()
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and vol.acc_b in problems(body)


# ------------------------------------------------------------------------------ the manifest
def test_a_missing_manifest_is_unchecked_never_ok(vol, good, tmp_path):
    victim = good()
    (victim / "backup-manifest.json").unlink()
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == UNCHECKED and body["status"] == "unchecked" and body["ok"] is False
    assert body["unchecked"]


@pytest.mark.parametrize("content", ["not json", "[]", '{"format": "something-else"}', ""])
def test_an_unreadable_or_foreign_manifest_is_a_finding(vol, good, tmp_path, content):
    victim = good()
    (victim / "backup-manifest.json").write_text(content)
    code, body, err = verify(victim, cwd=tmp_path)
    assert code == FINDING and "backup-manifest.json" in problems(body) and "Traceback" not in err


@pytest.mark.parametrize("hostile", ["../../etc/passwd", "/etc/passwd", ""])
def test_a_manifest_naming_paths_outside_the_backup_is_refused_not_followed(vol, good, tmp_path,
                                                                            hostile):
    victim = good()
    mp = victim / "backup-manifest.json"
    m = json.loads(mp.read_text())
    m["files"][hostile] = {"size": 1, "sha256": "0" * 64}
    mp.write_text(json.dumps(m))
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "refusing the entry" in problems(body)


def test_a_manifest_with_no_file_list_is_a_finding(vol, good, tmp_path):
    victim = good()
    mp = victim / "backup-manifest.json"
    m = json.loads(mp.read_text())
    m["files"] = "none"
    mp.write_text(json.dumps(m))
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "no file list" in problems(body)


def test_a_manifest_edited_to_match_a_cut_ledger_is_still_caught_by_the_attestation_log(
        vol, good, tmp_path):
    """An attacker who cuts account A's newest records and rewrites the manifest to match is
    caught by the signed attestation that remembers the longer ledger."""
    victim = good()
    ledger = victim / "tenants" / f"{vol.acc_a}.db"
    delete_last_record(ledger)
    mp = victim / "backup-manifest.json"
    m = json.loads(mp.read_text())
    rel = f"tenants/{vol.acc_a}.db"
    import hashlib
    m["files"][rel]["size"] = ledger.stat().st_size
    m["files"][rel]["sha256"] = hashlib.sha256(ledger.read_bytes()).hexdigest()
    m["files"][rel]["entries"] -= 1
    mp.write_text(json.dumps(m))
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "attestations/" in problems(body), body


def test_removing_the_manifest_and_cutting_a_signed_ledger_is_still_a_finding(vol, good,
                                                                              tmp_path):
    victim = good()
    (victim / "backup-manifest.json").unlink()
    delete_last_record(victim / "tenants" / f"{vol.acc_a}.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "attestations/" in problems(body), body


def test_the_stated_limit_with_no_manifest_and_no_attestation_a_cut_is_not_ok(vol, good,
                                                                              tmp_path):
    """Account B has no attestation log. Remove the manifest and cut B's tail: the files are
    internally consistent, so nothing can show the loss. The tool must say it cannot (3), and
    must never say ok."""
    victim = good()
    (victim / "backup-manifest.json").unlink()
    delete_last_record(victim / "tenants" / f"{vol.acc_b}.db")
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == UNCHECKED and body["ok"] is False


@pytest.mark.parametrize("how", ["garbage", "empty_file", "torn_tail_only"])
def test_a_damaged_attestation_log_is_a_finding_or_flagged_never_a_silent_ok(vol, good,
                                                                              tmp_path, how):
    victim = good()
    log = victim / "attestations" / f"{vol.acc_a}.jsonl"
    original = log.read_bytes()
    if how == "garbage":
        log.write_bytes(b"\x00\xffnot-json\n" + original)
    elif how == "empty_file":
        log.write_bytes(b"")
    else:
        log.write_bytes(original + b'{"torn": ')
    code, body, err = verify(victim, cwd=tmp_path)
    assert "Traceback" not in err
    assert code == FINDING and body["ok"] is False        # manifest hash differs in all three


def test_an_attestation_log_for_a_ledger_that_is_gone_says_evidence_was_lost(vol, good,
                                                                             tmp_path):
    victim = good()
    (victim / "tenants" / f"{vol.acc_a}.db").unlink()
    (victim / "backup-manifest.json").unlink()
    code, body, _ = verify(victim, cwd=tmp_path)
    assert code == FINDING and "evidence was lost" in problems(body)


# ------------------------------------------------------- restoring over a running service
def test_a_volume_that_only_grew_since_the_backup_is_ok_with_live(vol, good, tmp_path):
    _signals(vol.ta, tmp_path, 1, "LATER")
    _signals(vol.op, tmp_path, 1, "OPLATER")
    # the live data dir carries the old backup's manifest, as a service under backup does
    live = snapshot_dir(vol, tmp_path, "live")
    shutil.copy(good.base / "backup-manifest.json", live / "backup-manifest.json")
    code, body, _ = verify(live, "--live", cwd=tmp_path)
    assert code == OK, problems(body)


def test_growth_without_live_is_reported_as_a_difference_not_ignored(vol, good, tmp_path):
    _signals(vol.ta, tmp_path, 1, "LATER")
    live = snapshot_dir(vol, tmp_path, "live")
    shutil.copy(good.base / "backup-manifest.json", live / "backup-manifest.json")
    code, body, _ = verify(live, cwd=tmp_path)
    assert code == FINDING and "differs from the manifest" in problems(body)


def test_restoring_an_older_ledger_over_a_newer_volume_is_a_detected_rollback(vol, good,
                                                                              tmp_path):
    older_backup = good.base
    _signals(vol.ta, tmp_path, 2, "GROW")
    newer_backup = vol.backup("backup-newer")
    restored = copy_of(newer_backup, tmp_path, "restored")
    # an operator "restores" the OLD ledger file into a volume whose manifest remembers more
    shutil.copy(older_backup / "tenants" / f"{vol.acc_a}.db",
                restored / "tenants" / f"{vol.acc_a}.db")
    for flags in ((), ("--live",)):
        code, body, _ = verify(restored, *flags, cwd=tmp_path)
        assert code == FINDING, (flags, body)
    live_text = problems(verify(restored, "--live", cwd=tmp_path)[1])
    assert "removed since" in live_text or "attestations/" in live_text


def test_a_forked_history_of_the_same_length_is_a_finding_under_live(vol, good, tmp_path):
    """Same record count, different records: only the recorded head link hash shows it."""
    live = snapshot_dir(vol, tmp_path, "live")
    shutil.copy(good.base / "backup-manifest.json", live / "backup-manifest.json")
    fork = tmp_path / "fork.db"
    _signals(fork, tmp_path, 4, "FORK")
    # B had 3 records; the fork has 4, so by length alone it looks like ordinary growth
    shutil.copy(fork, live / "tenants" / f"{vol.acc_b}.db")
    code, body, _ = verify(live, "--live", cwd=tmp_path)
    assert code == FINDING and "history was rewritten" in problems(body), body


def test_verify_a_path_that_is_not_a_directory_is_could_not_run_or_finding_not_ok(tmp_path):
    code, body, err = verify(tmp_path / "does-not-exist", cwd=tmp_path)
    assert code != OK and "Traceback" not in err


def test_wrong_usage_prints_help_and_exits_2(tmp_path):
    for args in ((), ("verify",), ("backup", "only-one"), ("explode", "x")):
        code, _, err = restore_check(*args, cwd=tmp_path)
        assert code == COULD_NOT_RUN and "Traceback" not in err, args


# --------------------------------------------- a restored volume with the real service on it
SIGNAL = {"received_at": "2026-10-01T08:00:00Z", "channel": "other",
          "description": "synthetic signal", "actor": {"identifier": "t", "role": "analyst"}}


def _restored_volume_with_service(vol, good, tmp_path):
    """Restore a backup into a new directory and start the product's real API on it."""
    import secrets
    import time

    from support_api import _free_port, call
    restored = copy_of(good.base, tmp_path, "restored")
    for sidecar in restored.rglob("*-[sw][ha][ml]"):
        sidecar.unlink()
    port, op = _free_port(), secrets.token_urlsafe(16)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "PYTHONPATH": PRODUCT_SRC,
           "PYTHONDONTWRITEBYTECODE": "1",
           "ASSURANCE_LEDGER": str(restored / "art14-register.db"),
           "ASSURANCE_ACCOUNTS": str(restored / "accounts.db"),
           "ASSURANCE_TENANT_LEDGERS": str(restored / "tenants"),
           "ASSURANCE_ATTEST_LOGS": str(restored / "attestations"), "ASSURANCE_API_KEYS": op}
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "assurance.api.service:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "error"], env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        if call(base, "GET", "/healthz")[0] == 200:
            return restored, server, base, call, op
        time.sleep(0.3)
    server.kill()
    raise RuntimeError("API did not start on the restored volume")


SIDECARS = ("accounts.db-wal", "accounts.db-shm")


def real_problems(body) -> list[str]:
    """Findings other than the SQLite sidecar noise that the strict-xfail test is about."""
    return [p for p in body.get("problems", []) if not p.startswith(SIDECARS)]


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT (restore_check verify): it is meant to be read-only, but on a restored "
    "volume that the real service has opened (accounts.db is in WAL mode) `verify` itself "
    "creates accounts.db-wal and accounts.db-shm in the directory it checks, then lists them "
    "as 'not in the manifest - added since the backup was taken' and exits 1 on a healthy "
    "volume. Remove this marker when verify leaves the directory as it found it."))
def test_a_healthy_restored_volume_with_the_service_running_verifies_under_live(vol, good,
                                                                                tmp_path):
    restored, server, *_ = _restored_volume_with_service(vol, good, tmp_path)
    server.terminate()
    server.wait(timeout=10)
    for sidecar in restored.rglob("*-[sw][ha][ml]"):
        sidecar.unlink()                      # the service is stopped: nothing of its is left
    before = sorted(p.relative_to(restored).as_posix() for p in restored.rglob("*"))
    code, body, _ = verify(restored, "--live", cwd=tmp_path)
    after = sorted(p.relative_to(restored).as_posix() for p in restored.rglob("*"))
    changed = set(after) ^ set(before)
    assert after == before, f"verify changed the directory it was asked to check: {changed}"
    assert code == OK, problems(body)


def test_growth_made_by_the_real_service_is_growth_and_a_later_cut_is_still_a_finding(
        vol, good, tmp_path):
    """On a restored volume the service itself appends to the operator ledger (growth, ok).
    Then the newest record of a tenant ledger is cut (a finding). SQLite sidecar findings are
    filtered out: they are what the strict-xfail test above is about."""
    restored, server, base, call, operator_key = _restored_volume_with_service(vol, good,
                                                                               tmp_path)
    try:
        status, _ = call(base, "POST", "/v1/cases/GROW-1/signal", key=operator_key, body=SIGNAL)
        assert status == 201
    finally:
        server.terminate()
        server.wait(timeout=10)
    _, body, _ = verify(restored, "--live", cwd=tmp_path)
    assert real_problems(body) == [], real_problems(body)       # growth is not a finding
    _, body, _ = verify(restored, cwd=tmp_path)                 # strict mode sees the difference
    assert any(p.startswith("art14-register.db") for p in real_problems(body))
    delete_last_record(restored / "tenants" / f"{vol.acc_b}.db")
    code, body, _ = verify(restored, "--live", cwd=tmp_path)
    assert code == FINDING and any("removed since" in p for p in real_problems(body))
