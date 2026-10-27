"""Signed supplier-advisory feed: attacks from someone who controls the file, not the key."""
import json
from datetime import UTC, datetime

import pytest
from assurance.attest.keys import SigningKey
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.supplier.publish import (
    AdvisoryFeed,
    SupplierIdentity,
    publish,
    verify_feed,
    withdraw,
)

NOW = datetime(2026, 9, 12, tzinfo=UTC)
ID = SupplierIdentity("controlco", "ControlCo GmbH", "datasheet p.2 fingerprint")


def adv(n):
    return ComponentAdvisory(
        advisory_id=f"ADV-{n}", issued_by="ControlCo GmbH", issued_at=NOW, title="t", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact("ControlCo GmbH", "SafeScan", versions=("4.0",)),),
        reference="https://example.invalid/x")


@pytest.fixture
def feed(tmp_path):
    key = SigningKey.generate()
    f = AdvisoryFeed(tmp_path / "feed.jsonl")
    publish(adv(1), ID, key, f, now=NOW)
    publish(adv(2), ID, key, f, now=NOW)
    withdraw("ADV-1", "published in error", ID, key, f, now=NOW)
    return f, key


def lines(f):
    return [ln for ln in f.path.read_text("utf-8").splitlines() if ln.strip()]


def test_intact_feed_verifies_and_withdrawal_removes_the_advisory(feed):
    f, key = feed
    v = verify_feed(f.read(), key.verifying)
    assert v.ok and [r.advisory_id for r in v.live] == ["ADV-2"] and v.withdrawn == ("ADV-1",)


def test_removing_a_middle_record_is_detected(feed):
    f, key = feed
    ls = lines(f)
    f.path.write_text("\n".join([ls[0], ls[2]]) + "\n", "utf-8")
    assert verify_feed(f.read(), key.verifying).ok is False


def test_editing_a_signed_field_is_detected(feed):
    f, key = feed
    ls = lines(f)
    ls[0] = ls[0].replace("ControlCo GmbH", "AttackerCo", 1)
    f.path.write_text("\n".join(ls) + "\n", "utf-8")
    assert verify_feed(f.read(), key.verifying).ok is False


def test_a_foreign_key_does_not_verify(feed):
    f, _ = feed
    assert verify_feed(f.read(), SigningKey.generate().verifying).ok is False


def test_empty_feed_never_reads_as_nothing_affects_you(tmp_path):
    v = verify_feed([], SigningKey.generate().verifying)
    assert v.ok is False and v.live == ()


def test_dropping_the_newest_record_is_not_silently_accepted(feed):
    """Tail truncation re-presents a withdrawn advisory as standing.

    The chain cannot show a missing tail by itself. Acceptable outcomes: the
    verdict is not ok, or it states plainly that the newest records were not
    checked and a caller can pin a minimum sequence.
    """
    f, key = feed
    f.path.write_text("\n".join(lines(f)[:2]) + "\n", "utf-8")  # drop the withdrawal
    v = verify_feed(f.read(), key.verifying)
    assert [r.advisory_id for r in v.live] == ["ADV-1", "ADV-2"]  # the withdrawn one stands again
    words = ("newest", "truncat", "rolled back", "rollback")
    said_so = any(w in s.lower() for s in v.checks_skipped for w in words)
    assert (not v.ok) or said_so, "truncated feed verified ok, no caveat on newest records"


def test_a_pinned_minimum_sequence_rejects_a_rolled_back_feed(feed):
    f, key = feed
    f.path.write_text("\n".join(lines(f)[:2]) + "\n", "utf-8")
    v = verify_feed(f.read(), key.verifying, min_sequence=3)
    assert v.ok is False


def test_unknown_format_string_is_not_verified_as_current(feed):
    f, key = feed
    ls = lines(f)
    d = json.loads(ls[0])
    d["format"] = "neuralbridge-advisory/99"
    ls[0] = json.dumps(d)
    f.path.write_text("\n".join(ls) + "\n", "utf-8")
    assert verify_feed(f.read(), key.verifying).ok is False


def test_a_feed_replaced_by_a_different_history_fails_the_remembered_head(feed, tmp_path):
    f, key = feed
    seen = verify_feed(f.read(), key.verifying)
    other = AdvisoryFeed(tmp_path / "other.jsonl")
    for n in (1, 2, 9):
        publish(adv(n), ID, key, other, now=NOW)
    v = verify_feed(other.read(), key.verifying, min_sequence=seen.head_sequence,
                    expect_head=seen.head_hash)
    assert v.ok is False
