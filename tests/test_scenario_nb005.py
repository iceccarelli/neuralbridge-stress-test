"""NB-005 against the product's evidence ledger, driven by the synthetic fixture.

Scope, stated plainly: this exercises the ledger's own verifier and its signed-anchor export
(library level, the layer the CLI, API and MCP sit on). Not covered, and said so rather than
faked: the fixture's NB005-ORDER case (events delivered out of application order). The
ledger orders by arrival and carries no per-asset event-sequence checker at this layer, so
there is no product interface to assert against; API-level idempotency is not exercised here.

The fixture's events are synthetic and say so. They are not a real machine or customer.
"""
import copy
import json
import sqlite3
from pathlib import Path

import pytest
from assurance.core import Actor
from assurance.core.evidence import Evidence, Origin
from assurance.evidence.ledger import AnchorContradictsLedgerError, EvidenceLedger

FIXTURE = json.loads(
    (Path(__file__).resolve().parent.parent / "data/fixtures/evidence_events.json")
    .read_text(encoding="utf-8"))
ACTOR = Actor("synthetic-recorder", "synthetic fixture")


def sealed(event):
    return Evidence(
        kind=event["event_type"], body={k: v for k, v in event.items() if k != "integrity"},
        actor=ACTOR, origin=Origin(system="stress-test.fixture", reference=event["event_id"],
                                   method="synthetic"),
    ).seal()


@pytest.fixture
def events():
    return copy.deepcopy(FIXTURE["events"])


@pytest.fixture
def ledger(tmp_path, events):
    led = EvidenceLedger(tmp_path / "l.db")
    for e in events:
        led.append(sealed(e), subject=e["asset_id"])
    return led


def edit(ledger, sql, args=()):
    db = sqlite3.connect(ledger.path)
    db.execute(sql, args)
    db.commit()
    db.close()


def test_the_untouched_fixture_history_verifies(ledger):
    ok, problems = ledger.verify_chain()
    assert ok and problems == [] and len(ledger.entries()) == len(FIXTURE["events"])


def test_NB005_TAMPER_a_changed_payload_fails_integrity(ledger):
    row = sqlite3.connect(ledger.path).execute(
        "SELECT payload FROM chain WHERE seq = 1").fetchone()[0]
    assert "V12.001" in row
    edit(ledger, "UPDATE chain SET payload = ? WHERE seq = 1", (row.replace("V12.001", "V12.002"),))
    ok, problems = ledger.verify_chain()
    assert not ok and any("seq 1" in p for p in problems)


def test_NB005_TRUNCATE_a_removed_middle_event_is_an_incomplete_history(ledger):
    edit(ledger, "DELETE FROM chain WHERE seq = 2")
    ok, problems = ledger.verify_chain()
    assert not ok and any("gap" in p or "removed" in p or "prev_hash" in p for p in problems)


def test_NB005_TRUNCATE_cutting_the_tail_is_caught_only_against_a_signed_head(ledger):
    """The chain alone cannot show the end was cut off. A signed head can: the export refuses
    an anchor that is longer than, or disagrees with, the ledger it is asked to cover."""
    entries = ledger.entries()
    head = entries[-1]
    anchor = {"ledger_length": len(entries), "head_seq": head.seq,
              "head_link_hash": head.link_hash, "attested_at": "2026-10-27T00:00:00Z"}
    ledger.export(anchor=anchor)  # the untouched ledger agrees with its own head
    edit(ledger, "DELETE FROM chain WHERE seq = ?", (head.seq,))
    assert ledger.verify_chain()[0] is True  # a valid prefix: nothing inside it is wrong
    with pytest.raises(AnchorContradictsLedgerError):
        ledger.export(anchor=anchor)


def test_NB005_DUPLICATE_a_redelivered_event_is_identifiable_not_silently_a_new_fact(
        ledger, events):
    """Fixture: 'duplicate_detected_or_idempotently_ignored'. The ledger records both
    deliveries (it is append-only) but they carry the identical content hash, so the
    duplicate is detectable by any consumer. Idempotent ingestion is the API layer's job
    and is not tested here."""
    again = sealed(events[0])
    ledger.append(again, subject=events[0]["asset_id"])
    same = [e for e in ledger.entries() if e.content_hash == again.content_hash]
    assert len(same) == 2 and same[0].content_hash == same[1].content_hash
    assert ledger.verify_chain()[0] is True


def test_the_original_fixture_events_are_not_mutated_by_processing(events):
    before = copy.deepcopy(events)
    for e in events:
        sealed(e)
    assert events == before == FIXTURE["events"]
