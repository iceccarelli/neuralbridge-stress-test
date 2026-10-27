"""Tamper-evidence and concurrency of the evidence ledger, attacked from outside.

The attacker here edits the SQLite file directly (no product API), which is what
a hostile operator or a corrupted disk looks like.
"""
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from assurance.core import Actor
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    Art14Register, Awareness, CaseError, Signal, SignalChannel, Track,
)

UTC = timezone.utc
ACTOR = Actor("tester", "stress-test")
T0 = datetime(2026, 9, 19, 6, 30, tzinfo=UTC)


def seeded(tmp_path):
    path = tmp_path / "l.db"
    reg = Art14Register(EvidenceLedger(path))
    reg.record_signal("C1", Signal(T0, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    reg.record_awareness("C1", Awareness(T0, T0, T0, "t", "judged"), Track.INCIDENT, ACTOR)
    return path, reg


def verified(path):
    ok, problems = EvidenceLedger(path).verify_chain()
    return ok, problems


def test_clean_ledger_verifies(tmp_path):
    path, _ = seeded(tmp_path)
    assert verified(path)[0] is True


def test_editing_a_payload_in_place_is_detected(tmp_path):
    path, _ = seeded(tmp_path)
    db = sqlite3.connect(path)
    (payload,) = db.execute("SELECT payload FROM chain WHERE seq=2").fetchone()
    db.execute("UPDATE chain SET payload=? WHERE seq=2", (payload.replace("2026-09-19", "2026-09-29"),))
    db.commit()
    db.close()
    ok, problems = verified(path)
    assert ok is False and problems


def test_deleting_a_middle_entry_is_detected(tmp_path):
    path, _ = seeded(tmp_path)
    db = sqlite3.connect(path)
    db.execute("DELETE FROM chain WHERE seq=1")
    db.commit()
    db.close()
    assert verified(path)[0] is False


def test_rewriting_a_link_hash_without_the_payload_is_detected(tmp_path):
    path, _ = seeded(tmp_path)
    db = sqlite3.connect(path)
    db.execute("UPDATE chain SET link_hash=? WHERE seq=2", ("0" * 64,))
    db.commit()
    db.close()
    assert verified(path)[0] is False


def test_concurrent_awareness_writers_produce_one_awareness_entry(tmp_path):
    path = tmp_path / "l.db"
    reg = Art14Register(EvidenceLedger(path))
    reg.record_signal("C1", Signal(T0, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    barrier = threading.Barrier(8)
    results = []

    def go(i):
        at = T0 + timedelta(days=i)
        barrier.wait()
        try:
            reg.record_awareness("C1", Awareness(at, T0, at, "t", "judged"), Track.INCIDENT, ACTOR)
            results.append("ok")
        except CaseError:
            results.append("refused")

    ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("ok") == 1
    assert len([e for e in reg.ledger.entries(subject="C1") if "awareness" in e.kind]) == 1
    assert verified(path)[0] is True  # racing writers must not fork or corrupt the chain
