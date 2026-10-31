"""Structural attacks on the evidence ledger file: timestamp, event type, reorder, duplicate
row, foreign splice, truncation, damaged backup. Evidence level: product library, in-process,
temporary SQLite state, the attacker editing the file directly (a hostile operator or a bad
disk). Complements tests/test_ledger_integrity.py, which covers payload, link, actor, key
injection, payload swap and middle deletion.

Expected results come from the principle, not from reading the product back:

* every column the record's meaning depends on (when, what kind, which subject, order) must
  be covered by the chain, so editing one must not leave a passing ledger;
* a hash chain ALONE cannot show that the newest records were cut off; only a head recorded
  elsewhere can. That limit is asserted here, not hidden;
* a damaged file is reported as damaged. It is never reported as intact.
"""
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from assurance.core import Actor
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import Art14Register, Awareness, Signal, SignalChannel, Track

ACTOR = Actor("tester", "stress-test")
T0 = datetime(2026, 9, 19, 6, 30, tzinfo=UTC)


def seeded(tmp_path, name="l.db", case="C1"):
    path = tmp_path / name
    reg = Art14Register(EvidenceLedger(path))
    reg.record_signal(case, Signal(T0, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    reg.record_awareness(case, Awareness(T0, T0, T0, "t", "judged"), Track.INCIDENT, ACTOR)
    reg.record_signal(case + "b", Signal(T0 + timedelta(days=1), SignalChannel.CVD_INBOX, "t2",
                                         "d2"), ACTOR)
    return path


def ok(path):
    return EvidenceLedger(path).verify_chain()[0]


def edit(path, sql, *args):
    db = sqlite3.connect(path)
    db.execute(sql, args)
    db.commit()
    db.close()


def test_baseline_is_intact(tmp_path):
    assert ok(seeded(tmp_path)) is True


def test_changing_a_timestamp_column_is_detected(tmp_path):
    path = seeded(tmp_path)
    edit(path, "UPDATE chain SET at='2026-01-01T00:00:00Z' WHERE seq=2")
    assert ok(path) is False


def test_changing_the_event_type_column_is_detected(tmp_path):
    path = seeded(tmp_path)
    edit(path, "UPDATE chain SET kind='something_else' WHERE seq=2")
    assert ok(path) is False


def test_changing_the_subject_column_is_detected(tmp_path):
    path = seeded(tmp_path)
    edit(path, "UPDATE chain SET subject='C-other' WHERE seq=2")
    assert ok(path) is False


def test_swapping_two_records_positions_is_detected(tmp_path):
    path = seeded(tmp_path)
    db = sqlite3.connect(path)
    db.execute("UPDATE chain SET seq=99 WHERE seq=2")
    db.execute("UPDATE chain SET seq=2 WHERE seq=3")
    db.execute("UPDATE chain SET seq=3 WHERE seq=99")
    db.commit()
    db.close()
    assert ok(path) is False


def test_inserting_a_byte_for_byte_copy_of_a_record_is_refused_by_storage(tmp_path):
    """The schema makes link_hash UNIQUE, so a raw copy cannot even be written. (A replayed
    event re-sealed at a new position is a different attack; see test_scenario_nb005.)"""
    path = seeded(tmp_path)
    db = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO chain (at, kind, subject, content_hash, prev_hash, link_hash,"
               " actor, payload) SELECT at, kind, subject, content_hash, prev_hash, link_hash,"
               " actor, payload FROM chain WHERE seq=2")
    db.close()
    assert ok(path) is True  # the refused write left the ledger untouched


def test_splicing_a_record_from_another_ledger_is_detected(tmp_path):
    a = seeded(tmp_path, "a.db", "A")
    b = seeded(tmp_path, "b.db", "B")
    row = sqlite3.connect(b).execute(
        "SELECT at, kind, subject, content_hash, prev_hash, link_hash, actor, payload "
        "FROM chain WHERE seq=3").fetchone()
    edit(a, "DELETE FROM chain WHERE seq=3")
    edit(a, "INSERT INTO chain (at, kind, subject, content_hash, prev_hash, link_hash, actor,"
            " payload) VALUES (?,?,?,?,?,?,?,?)", *row)
    assert ok(a) is False


def test_cutting_the_newest_records_is_invisible_to_the_chain_alone(tmp_path):
    """The limit the brief insists on: a bare hash chain does not detect truncation. A head
    recorded before the cut does."""
    path = seeded(tmp_path)
    before = EvidenceLedger(path).head_attestation()
    edit(path, "DELETE FROM chain WHERE seq=3")
    cut = EvidenceLedger(path)
    assert cut.verify_chain()[0] is True                       # chain alone: still passes
    after = cut.head_attestation()
    assert after["head_seq"] < before["head_seq"]              # the earlier head exposes it
    assert after["head_link_hash"] != before["head_link_hash"]


def test_a_snapshot_is_a_faithful_copy_with_the_same_head(tmp_path):
    path = seeded(tmp_path)
    live = EvidenceLedger(path)
    copy = live.snapshot_to(tmp_path / "backup.db")
    assert ok(copy) is True
    a, b = live.head_attestation(), EvidenceLedger(copy).head_attestation()
    assert (a["length"], a["head_seq"], a["head_link_hash"]) == \
           (b["length"], b["head_seq"], b["head_link_hash"])


@pytest.mark.parametrize("damage", ["flip_middle", "truncate_half", "garbage_header", "empty"])
def test_a_damaged_backup_is_never_reported_intact(tmp_path, damage):
    path = seeded(tmp_path)
    copy = EvidenceLedger(path).snapshot_to(tmp_path / "backup.db")
    raw = bytearray(copy.read_bytes())
    if damage == "flip_middle":
        # Flip bytes inside a stored record. Flipping "the middle" can land in unused pages
        # and change nothing, which is not a test of anything.
        at = bytes(raw).find(b'"kind"')
        assert at > 0, "fixture changed: no stored record found to damage"
        for i in range(at, at + 40):
            raw[i] ^= 0xFF
    elif damage == "truncate_half":
        raw = raw[: len(raw) // 2]
    elif damage == "garbage_header":
        raw[:16] = b"NOT A SQLITE FILE"[:16]
    else:
        raw = bytearray()
    copy.write_bytes(bytes(raw))
    try:
        verdict = ok(copy)
    except Exception:  # noqa: BLE001 - refusing loudly is an acceptable outcome
        return
    # An emptied file is a brand-new empty ledger; it must not equal the original's history.
    if damage == "empty":
        assert EvidenceLedger(copy).head_attestation()["length"] == 0
    else:
        assert verdict is False


def test_restoring_an_older_snapshot_verifies_but_is_distinguishable_from_the_live_head(tmp_path):
    path = seeded(tmp_path)
    old = EvidenceLedger(path).snapshot_to(tmp_path / "old.db")
    reg = Art14Register(EvidenceLedger(path))
    reg.record_signal("C9", Signal(T0 + timedelta(days=2), SignalChannel.CVD_INBOX, "t", "d"),
                      ACTOR)
    live_head = EvidenceLedger(path).head_attestation()
    restored = EvidenceLedger(old).head_attestation()
    assert ok(old) is True                                     # a rollback is a valid chain
    assert restored["length"] < live_head["length"]            # ... only a held head shows it
