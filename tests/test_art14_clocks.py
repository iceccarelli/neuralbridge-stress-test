"""CRA Art. 14 clocks, checked against the regulation text, not the product.

Expected values are written out by hand from:
  Art. 14(2)(a) early warning   24 h from becoming aware
  Art. 14(2)(b) notification    72 h from becoming aware
  Art. 14(2)(c) vuln. final     14 days after a corrective OR mitigating measure
  Art. 14(4)(c) incident final  one calendar month after the 72 h notification
"""
from datetime import UTC, datetime, timedelta

import pytest
from assurance.core import Actor, ClockError, EvidenceIncompleteError
from assurance.core.identity import parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    Art14Register,
    Awareness,
    CaseError,
    Signal,
    SignalChannel,
    Stage,
    Track,
)

UTC = UTC
ACTOR = Actor("tester", "stress-test")


def utc(*a):
    return datetime(*a, tzinfo=UTC)


def open_case(tmp_path, track, aware_at, case="C1"):
    reg = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    reg.record_signal(case, Signal(aware_at, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    reg.record_awareness(case, Awareness(aware_at, aware_at, aware_at, "t", "judged"), track, ACTOR)
    return reg


@pytest.mark.parametrize("track", list(Track))
def test_early_warning_and_notification_run_from_awareness(tmp_path, track):
    aware = utc(2026, 9, 19, 6, 30)
    d = open_case(tmp_path, track, aware).case("C1").deadlines
    assert d.early_warning.due_at == utc(2026, 9, 20, 6, 30)
    assert d.notification.due_at == utc(2026, 9, 22, 6, 30)


def test_awareness_given_with_an_offset_is_the_same_instant_in_utc(tmp_path):
    # 08:30+02:00 is 06:30Z: the deadline must not drift by the offset.
    aware = parse_utc("2026-09-19T08:30:00+02:00")
    d = open_case(tmp_path, Track.VULNERABILITY, aware).case("C1").deadlines
    assert d.early_warning.due_at == utc(2026, 9, 20, 6, 30)


def test_naive_timestamp_is_refused_not_guessed():
    with pytest.raises(ValueError):
        parse_utc("2026-09-19T06:30:00")


@pytest.mark.parametrize("text", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_unrepresentable_instants_are_a_value_error_not_an_overflow(text):
    with pytest.raises(ValueError):
        parse_utc(text)


def test_vulnerability_final_is_14_days_after_a_mitigating_measure_not_awareness(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    assert reg.case("C1").deadlines.final is None  # no measure yet: no invented deadline
    reg.record_measure_available("C1", utc(2026, 9, 25, 12), "documented workaround", ACTOR)
    assert reg.case("C1").deadlines.final.due_at == utc(2026, 10, 9, 12)


def test_no_final_deadline_is_computed_without_a_measure(tmp_path):
    reg = open_case(tmp_path, Track.VULNERABILITY, utc(2026, 9, 19, 6, 30))
    d = reg.case("C1").deadlines
    assert d.final is None
    with pytest.raises(ClockError):
        d.require_final()


@pytest.mark.parametrize(
    "submitted, due",
    [
        (utc(2026, 9, 21, 9, 0), utc(2026, 10, 21, 9, 0)),
        (utc(2027, 1, 31, 10, 0), utc(2027, 2, 28, 10, 0)),    # clamp to Feb 28
        (utc(2028, 1, 31, 10, 0), utc(2028, 2, 29, 10, 0)),    # leap year
        (utc(2026, 12, 31, 23, 59), utc(2027, 1, 31, 23, 59)),  # year rollover
        (utc(2026, 3, 31, 0, 0), utc(2026, 4, 30, 0, 0)),      # 31 -> 30-day month
    ],
)
def test_incident_final_is_one_calendar_month_after_the_72h_notification(tmp_path, submitted, due):
    aware = submitted - timedelta(hours=40)
    reg = open_case(tmp_path, Track.INCIDENT, aware)
    reg.record_filing("C1", Stage.NOTIFICATION, submitted, {}, ACTOR)
    assert reg.case("C1").deadlines.final.due_at == due


def test_a_filing_after_the_deadline_is_reported_late_and_on_the_deadline_is_on_time(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    reg.record_filing("C1", Stage.EARLY_WARNING, utc(2026, 9, 20, 6, 30), {}, ACTOR)
    one_second_over = utc(2026, 9, 22, 6, 30) + timedelta(seconds=1)
    reg.record_filing("C1", Stage.NOTIFICATION, one_second_over, {}, ACTOR)
    d = reg.case("C1").deadlines
    assert d.early_warning.status == "filed_on_time"   # exactly at 24 h is within 24 h
    assert d.notification.status == "filed_late"       # one second over 72 h is late


def test_a_filing_dated_before_awareness_is_refused(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    with pytest.raises(CaseError):
        reg.record_filing("C1", Stage.EARLY_WARNING, aware - timedelta(hours=1), {}, ACTOR)


def test_a_later_measure_never_pushes_the_14_day_clock_out(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    reg.record_measure_available("C1", utc(2026, 9, 21), "workaround", ACTOR)
    reg.record_measure_available("C1", utc(2026, 10, 30), "patch", ACTOR)
    assert reg.case("C1").deadlines.final.due_at == utc(2026, 10, 5)


def test_re_recording_awareness_cannot_move_the_deadlines(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    with pytest.raises(CaseError):
        reg.record_awareness(
            "C1", Awareness(aware + timedelta(days=5), aware, aware, "t", "again"),
            Track.VULNERABILITY, ACTOR,
        )
    assert reg.case("C1").deadlines.early_warning.due_at == utc(2026, 9, 20, 6, 30)


def test_a_second_signal_for_the_same_case_is_refused(tmp_path):
    aware = utc(2026, 9, 19, 6, 30)
    reg = open_case(tmp_path, Track.VULNERABILITY, aware)
    with pytest.raises(CaseError):
        reg.record_signal("C1", Signal(aware, SignalChannel.CVD_INBOX, "t", "replay"), ACTOR)


def test_awareness_before_the_signal_is_refused(tmp_path):
    reg = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    got = utc(2026, 9, 19, 6, 30)
    reg.record_signal("C1", Signal(got, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    early = got - timedelta(hours=2)
    with pytest.raises(CaseError):
        reg.record_awareness("C1", Awareness(early, early, early, "t", "r"), Track.INCIDENT, ACTOR)


def test_awareness_without_reasoning_is_not_evidence(tmp_path):
    reg = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    got = utc(2026, 9, 19, 6, 30)
    reg.record_signal("C1", Signal(got, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    with pytest.raises(EvidenceIncompleteError):
        reg.record_awareness("C1", Awareness(got, got, got, "t", "   "), Track.INCIDENT, ACTOR)
    assert reg.case("C1").awareness is None
