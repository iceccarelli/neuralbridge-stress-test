"""CRA Article 14 workflow, attacked through the real CLI and the real API.

Evidence level: ``python -m assurance art14 ...`` (subprocess, real SQLite) and the product's real
FastAPI app on loopback (throwaway Register-tier account), SYNTHETIC cases. Complements
tests/test_art14_clocks.py (library level) with: the same clocks through both surfaces, instants
given in other offsets and across daylight-saving transitions, filing boundaries, what a draft
does and does not do, and Member State validation. Not hosted staging; not legal advice.

SOURCES AND WHAT IS NOT ESTABLISHED. The rules tested are those recorded in this repository's
earlier lab work from Regulation (EU) 2024/2847 Art. 14(2) and 14(4) and Commission guidance
C(2026) 5252: 24 h and 72 h from becoming aware; 14 days after a corrective or mitigating
measure (vulnerabilities); one month after the 72 h notification (incidents). The primary text
could NOT be re-fetched in this session (eur-lex.europa.eu is unreachable from the sandbox), so:

* UNCHECKED: whether day and month periods are counted under Regulation (EEC, Euratom) No
  1182/71 (a period in days ends with the last hour of its last day, the event's own day not
  counted) rather than as elapsed time. The product computes elapsed time in UTC and clamps
  months; it does not say which convention it follows. These tests assert the product's stated
  rule and its internal consistency across surfaces. They do NOT assert it is the legally
  correct reading, and this suite does not claim legal advice or conformity.
* Hour periods (24 h, 72 h) are elapsed hours and are asserted against independent arithmetic.

Independent expectations, from the brief and plain logic:

* an instant given with any offset is the same instant; the deadline does not drift with the
  offset or with a daylight-saving transition, because hours elapse in UTC;
* two local times that are the same wall-clock reading but different instants (the repeated hour
  at the autumn change) give deadlines exactly one hour apart;
* a deadline computed for a truncated instant is never LATER than the true one;
* a filing exactly at the deadline is on time, one second later is late; a filing cannot predate
  awareness; a filing that has not happened yet cannot be recorded as a submission that met a
  deadline; a draft check is not a submission and records nothing;
* the CLI and the API give the same deadlines for the same case.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

ACTOR = {"identifier": "t", "role": "analyst"}
_ok, _why = api_importable()
needs_api = pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})")


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


@pytest.fixture(scope="module")
def api():
    if not _ok:
        pytest.skip(f"BLOCKED: product API not runnable ({_why})")
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def key(api):
    k = api.make_account("art14@example.invalid", "register")
    api._art14_key = k                    # shared with helpers that are not fixtures
    return k


_n = {"i": 0}


def case_id() -> str:
    _n["i"] += 1
    return f"T{_n['i']:04d}"


def open_case(api, key, track, aware_text, *, signal_hours_before=2):
    """Signal then awareness, with ``aware_text`` passed to the API exactly as given."""
    cid = case_id()
    aware = datetime.fromisoformat(aware_text.replace("Z", "+00:00").replace("z", "+00:00"))
    sig = aware - timedelta(hours=signal_hours_before)
    status, body = call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key, body={
        "received_at": sig.isoformat(), "channel": "other", "description": "synthetic",
        "actor": ACTOR})
    assert status == 201, body
    status, body = call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key, body={
        "established_at": aware_text, "assessment_started_at": sig.isoformat(),
        "assessment_completed_at": aware_text, "track": track, "reasoning": "synthetic reasoning",
        "actor": ACTOR})
    return cid, status, body


def deadlines(api, key, cid):
    status, body = call(api.base, "GET", f"/v1/cases/{cid}", key=key)
    assert status == 200, body
    return {d["stage"]: d for d in body["deadlines"]["deadlines"]}


# ------------------------------------------------------------------ hour clocks, any offset
AWARENESS_INSTANTS = [
    ("utc", "2026-03-28T23:30:00Z"),
    ("spring-forward day, before the gap, CET", "2026-03-29T01:30:00+01:00"),
    ("spring-forward day, after the gap, CEST", "2026-03-29T03:30:00+02:00"),
    ("autumn change, first 02:30 (CEST)", "2026-10-25T02:30:00+02:00"),
    ("autumn change, second 02:30 (CET)", "2026-10-25T02:30:00+01:00"),
    ("year boundary at -12:00", "2026-12-31T23:59:59-12:00"),
    ("leap day at +05:30", "2028-02-29T12:00:00+05:30"),
    ("friday evening, across a weekend", "2026-10-30T17:00:00Z"),
    ("offset +14:00", "2026-06-01T09:00:00+14:00"),
    ("offset -12:00", "2026-06-01T09:00:00-12:00"),
    ("explicit +00:00", "2026-10-01T08:00:00+00:00"),
]


@needs_api
@pytest.mark.parametrize("label,text", AWARENESS_INSTANTS, ids=[a for a, _ in AWARENESS_INSTANTS])
def test_early_warning_and_notification_are_24_and_72_elapsed_hours_whatever_the_offset(
        api, key, label, text):
    aware = datetime.fromisoformat(text)
    cid, status, body = open_case(api, key, "actively_exploited_vulnerability", text)
    assert status == 201, body
    d = deadlines(api, key, cid)
    assert parse(d["early_warning"]["due_at"]) == aware.astimezone(UTC) + timedelta(hours=24)
    assert parse(d["notification"]["due_at"]) == aware.astimezone(UTC) + timedelta(hours=72)
    assert parse(d["early_warning"]["runs_from"]) == aware.astimezone(UTC)


@needs_api
def test_a_weekend_is_not_skipped_72_hours_from_friday_evening_is_monday_evening(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-10-30T17:00:00Z")
    assert deadlines(api, key, cid)["notification"]["due_at"] == "2026-11-02T17:00:00Z"


@needs_api
def test_the_repeated_hour_at_the_autumn_change_gives_deadlines_exactly_one_hour_apart(api, key):
    first, _, _ = open_case(api, key, "actively_exploited_vulnerability",
                            "2026-10-25T02:30:00+02:00")
    second, _, _ = open_case(api, key, "actively_exploited_vulnerability",
                             "2026-10-25T02:30:00+01:00")
    a = parse(deadlines(api, key, first)["early_warning"]["due_at"])
    b = parse(deadlines(api, key, second)["early_warning"]["due_at"])
    assert b - a == timedelta(hours=1)


@needs_api
def test_the_same_instant_in_two_offsets_gives_the_same_deadlines(api, key):
    a, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-06-01T09:00:00+14:00")
    b, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-05-31T19:00:00Z")
    c, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-05-31T07:00:00-12:00")
    got = {deadlines(api, key, x)["early_warning"]["due_at"] for x in (a, b, c)}
    assert got == {"2026-06-01T19:00:00Z"}


@needs_api
@pytest.mark.parametrize("fraction", ["0.1", "0.5", "0.999", "0.000001"])
def test_a_fractional_second_never_makes_a_deadline_later_than_the_true_one(api, key, fraction):
    text = f"2026-10-01T08:00:00.{fraction[2:]}Z"
    cid, status, _ = open_case(api, key, "actively_exploited_vulnerability", text)
    assert status == 201
    true_due = datetime.fromisoformat(text.replace("Z", "+00:00")) + timedelta(hours=24)
    assert parse(deadlines(api, key, cid)["early_warning"]["due_at"]) <= true_due


# -------------------------------------------------- vulnerability and incident final reports
@needs_api
@pytest.mark.parametrize("measure,expected", [
    ("2026-10-31T10:00:00Z", "2026-11-14T10:00:00Z"),
    ("2026-10-10T10:00:00Z", "2026-10-24T10:00:00Z"),          # across the autumn change
    ("2026-02-20T12:00:00Z", "2026-03-06T12:00:00Z"),          # across the end of February
    ("2028-02-20T12:00:00Z", "2028-03-05T12:00:00Z"),          # leap year
    ("2026-12-25T23:00:00Z", "2027-01-08T23:00:00Z"),          # across the year
    ("2026-06-01T09:00:00+14:00", "2026-06-14T19:00:00Z"),     # offset input, same instant rule
])
def test_the_vulnerability_final_report_is_14_days_after_the_measure_in_elapsed_time(
        api, key, measure, expected):
    """The product's stated rule (elapsed time, UTC). Whether the law counts the last day to its
    end instead (Reg. 1182/71) is UNCHECKED, see the module docstring."""
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    status, body = call(api.base, "POST", f"/v1/cases/{cid}/measure", key=key, body={
        "available_at": measure, "description": "workaround", "actor": ACTOR})
    assert status == 201, body
    assert deadlines(api, key, cid)["final"]["due_at"] == expected


@needs_api
def test_no_final_report_date_is_invented_before_a_measure_is_recorded(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    assert "final" not in deadlines(api, key, cid)
    status, body = call(api.base, "GET", f"/v1/cases/{cid}", key=key)
    assert any("not computable" in p for p in body["deadlines"]["pending_facts"])


@needs_api
@pytest.mark.parametrize("submitted,expected", [
    ("2028-01-31T10:00:00Z", "2028-02-29T10:00:00Z"),          # clamp to a leap February
    ("2027-01-31T10:00:00Z", "2027-02-28T10:00:00Z"),          # clamp to a common February
    ("2026-03-31T23:30:00Z", "2026-04-30T23:30:00Z"),          # 31 -> 30-day month
    ("2026-12-31T23:30:00Z", "2027-01-31T23:30:00Z"),          # across the year
    ("2028-02-29T08:00:00Z", "2028-03-29T08:00:00Z"),          # from the leap day
    ("2026-05-31T00:00:00Z", "2026-06-30T00:00:00Z"),
    ("2026-10-15T12:00:00Z", "2026-11-15T12:00:00Z"),
])
def test_the_incident_final_report_is_one_calendar_month_after_the_notification_submission(
        api, key, submitted, expected):
    aware = datetime.fromisoformat(submitted.replace("Z", "+00:00")) - timedelta(hours=10)
    cid, _, _ = open_case(api, key, "severe_incident", iso(aware))
    status, body = call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
        "stage": "notification", "submitted_at": submitted, "payload": {}, "actor": ACTOR})
    assert status == 201, body
    assert deadlines(api, key, cid)["final"]["due_at"] == expected


@needs_api
def test_filing_the_notification_early_brings_the_incident_final_report_forward(api, key):
    cid, _, _ = open_case(api, key, "severe_incident", "2026-03-01T00:00:00Z")
    for at in ("2026-03-03T23:00:00Z", "2026-03-02T01:00:00Z"):         # the earlier one wins
        assert call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
            "stage": "notification", "submitted_at": at, "payload": {}, "actor": ACTOR})[0] == 201
    assert deadlines(api, key, cid)["final"]["due_at"] == "2026-04-02T01:00:00Z"


# ------------------------------------------------------------------------- filing boundaries
@needs_api
@pytest.mark.parametrize("offset_seconds,status_expected", [
    (-3600, "filed_on_time"), (-1, "filed_on_time"), (0, "filed_on_time"),
    (1, "filed_late"), (3600, "filed_late"),
])
def test_a_filing_on_the_deadline_is_on_time_and_one_second_after_it_is_late(
        api, key, offset_seconds, status_expected):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    due = parse(deadlines(api, key, cid)["early_warning"]["due_at"])
    status, body = call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
        "stage": "early_warning", "submitted_at": iso(due + timedelta(seconds=offset_seconds)),
        "payload": {}, "actor": ACTOR})
    assert status == 201, body
    assert deadlines(api, key, cid)["early_warning"]["status"] == status_expected


@needs_api
def test_a_filing_dated_before_awareness_is_refused_and_nothing_is_recorded(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    before = call(api.base, "GET", f"/v1/cases/{cid}", key=key)[1]["deadlines"]["deadlines"]
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
        "stage": "early_warning", "submitted_at": "2026-02-01T07:59:59Z", "payload": {},
        "actor": ACTOR})
    assert 400 <= status < 500
    assert call(api.base, "GET", f"/v1/cases/{cid}", key=key)[1]["deadlines"][
        "deadlines"] == before


@needs_api
def test_a_deadline_is_open_not_met_until_a_filing_is_recorded(api, key):
    """The product must not assume a filing happened: a fresh case's clocks are open."""
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    d = deadlines(api, key, cid)
    assert d["early_warning"]["status"] == "open" and d["early_warning"]["submitted_at"] is None
    assert d["notification"]["status"] == "open"


@needs_api
def test_a_draft_check_is_not_a_submission_and_records_nothing(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    length = call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"]["length"]
    status, body = call(api.base, "POST", "/v1/spec/validate", key=key, body={
        "track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {
            "title": "t", "summary": "s", "product_name": "P"}})
    assert status == 200 and body["submittable"] is False
    assert call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"][
        "length"] == length
    assert deadlines(api, key, cid)["early_warning"]["status"] == "open"


def test_the_cli_draft_check_is_not_a_submission_either(tmp_path):
    ledger = tmp_path / "l.db"
    run = assurance("art14", "--ledger", str(ledger), "signal", "C1", "--by", "t:analyst", "--at",
                    "2026-02-01T06:00:00Z", "--description", "d", "--product", "P", "--version",
                    "1", cwd=tmp_path)
    assert run.exit == 0, run.err
    (tmp_path / "p.json").write_text(json.dumps({"title": "t"}))
    before = ledger.read_bytes()
    run = assurance("art14", "--ledger", str(ledger), "validate", "--track",
                    "actively_exploited_vulnerability", "--stage", "early_warning", "--payload",
                    "p.json", cwd=tmp_path)
    assert run.exit != 0                                     # not submittable
    assert ledger.read_bytes() == before                     # and nothing was written


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: POST /v1/cases/{id}/filings (and `art14 file`) records a submission dated "
    "in the FUTURE. A filing that has not happened yet cannot meet a deadline, but the case then "
    "shows the clock as filed_on_time. Remove this marker when a future-dated submission is "
    "refused (a small clock-skew allowance is the company's call)."))
@needs_api
def test_a_filing_dated_in_the_future_cannot_mark_a_deadline_as_met(api, key):
    aware = datetime.now(UTC) - timedelta(hours=1)
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", iso(aware))
    future = iso(datetime.now(UTC) + timedelta(hours=10))           # inside the 24 h window
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
        "stage": "early_warning", "submitted_at": future, "payload": {}, "actor": ACTOR})
    met = deadlines(api, key, cid)["early_warning"]["status"] == "filed_on_time"
    assert status >= 400 or not met, "a submission that has not happened was recorded as on time"


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: a filing whose payload is empty, or lacks every field the product's own "
    "validator calls blocking for that stage, marks the deadline filed_on_time with nothing in "
    "the case view saying the recorded content is incomplete. The product knows the difference "
    "(POST /v1/spec/validate says submittable:false; an empty filing is overridden by a later "
    "complete one), but a lone incomplete filing reads as a met legal deadline. Remove this "
    "marker when such a filing is refused or shown as incomplete."))
@needs_api
def test_a_filing_with_none_of_the_required_content_does_not_read_as_a_met_deadline(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
        "stage": "early_warning", "submitted_at": "2026-02-01T10:00:00Z", "payload": {},
        "actor": ACTOR})
    state = deadlines(api, key, cid)["early_warning"]["status"]
    assert status >= 400 or state != "filed_on_time", state


@needs_api
def test_a_late_complete_filing_after_an_early_empty_one_is_reported_late(api, key):
    """Control for the above: the product does tell complete from empty when both exist."""
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    full = {"notification_type": "Vulnerability", "title": "t", "summary": "s",
            "product_name": "P", "product_version": "1.0",
            "member_states_available": ["DE"], "awareness_datetime": "2026-02-01T08:00:00Z"}
    for at, payload in (("2026-02-01T10:00:00Z", {}), ("2026-02-03T10:00:00Z", full)):
        assert call(api.base, "POST", f"/v1/cases/{cid}/filings", key=key, body={
            "stage": "early_warning", "submitted_at": at, "payload": payload,
            "actor": ACTOR})[0] == 201
    assert deadlines(api, key, cid)["early_warning"]["status"] == "filed_late"


# --------------------------------------------------------- missing / invalid timestamps
@needs_api
@pytest.mark.parametrize("bad", [
    "yesterday", "", None, 1e18, "now",
    "2026-13-01T08:00:00Z", "2026-02-30T08:00:00Z", "2026-02-01T25:00:00Z",
    "2026-02-01T08:00:00+25:00", "0000-01-01T00:00:00Z", "9999-12-31T23:59:60Z",
])
def test_an_unusable_awareness_time_is_refused_and_starts_no_clock(api, key, bad):
    cid = case_id()
    assert call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key, body={
        "received_at": "2026-02-01T06:00:00Z", "channel": "other", "description": "d",
        "actor": ACTOR})[0] == 201
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key, body={
        "established_at": bad, "assessment_started_at": "2026-02-01T06:00:00Z",
        "assessment_completed_at": "2026-02-01T08:00:00Z",
        "track": "actively_exploited_vulnerability", "reasoning": "x", "actor": ACTOR})
    assert 400 <= status < 500, (bad, status)
    case = call(api.base, "GET", f"/v1/cases/{cid}", key=key)[1]
    assert case["awareness"] is None and case["state"] == "signal_received"


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: a date-only value ('2026-02-01', parsed as a naive midnight) for an "
    "awareness time answers a bare 500; see the naive-timestamp matrix below. Remove this "
    "marker when it answers 4xx."))
@needs_api
def test_a_date_only_awareness_time_is_refused_not_a_500(api, key):
    cid = case_id()
    assert call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key,
                body=_naive_body("signal", "description") | {"description": "d"})[0] == 201
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key,
                     body=_naive_body("awareness", "established_at") | {
                         "established_at": "2026-02-01"})
    assert 400 <= status < 500, status


NAIVE = "2026-02-01T08:00:00"
NAIVE_DEFECT = (
    "PRODUCT DEFECT: a timestamp with no offset is refused with 422 on /signal and /measure, "
    "but on /awareness (all three time fields), /filings (submitted_at) and /user-notification "
    "(at) it answers a bare 500 Internal Server Error (nothing is written). The library refuses "
    "it correctly; the API does not map the error. Remove this marker when each answers 4xx.")


def _naive_body(route, field):
    base = {
        "awareness": {"established_at": "2026-02-01T08:00:00Z",
                      "assessment_started_at": "2026-02-01T06:00:00Z",
                      "assessment_completed_at": "2026-02-01T08:00:00Z",
                      "track": "actively_exploited_vulnerability", "reasoning": "x",
                      "actor": ACTOR},
        "filings": {"stage": "early_warning", "submitted_at": "2026-02-01T10:00:00Z",
                    "payload": {}, "actor": ACTOR},
        "user-notification": {"at": "2026-02-01T10:00:00Z", "scope": "all", "content": "c",
                              "actor": ACTOR},
        "measure": {"available_at": "2026-02-01T10:00:00Z", "description": "m", "actor": ACTOR},
        "signal": {"received_at": "2026-02-01T06:00:00Z", "channel": "other",
                   "description": "d", "actor": ACTOR},
    }[route]
    return {**base, field: NAIVE}


NAIVE_ROUTES = [
    ("signal", "received_at", False), ("measure", "available_at", False),
    ("awareness", "established_at", True), ("awareness", "assessment_started_at", True),
    ("awareness", "assessment_completed_at", True), ("filings", "submitted_at", True),
    ("user-notification", "at", True),
]


def _naive_params():
    for route, field, broken in NAIVE_ROUTES:
        yield pytest.param(route, field, id=f"{route}.{field}", marks=(
            [pytest.mark.xfail(strict=True, reason=NAIVE_DEFECT)] if broken else []))


@needs_api
@pytest.mark.parametrize("route,field", list(_naive_params()))
def test_a_timestamp_without_an_offset_is_refused_on_every_route_not_guessed_and_not_a_500(
        api, key, route, field):
    cid = case_id()
    if route != "signal":
        assert call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key, body=_naive_body(
            "signal", "description") | {"description": "d"})[0] == 201
        if route in ("filings", "user-notification", "measure"):
            assert call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key, body=_naive_body(
                "awareness", "reasoning") | {"reasoning": "x"})[0] == 201
    before = call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"]["length"]
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/{route}", key=key,
                     body=_naive_body(route, field))
    assert 400 <= status < 500, status
    assert call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"][
        "length"] == before


@needs_api
def test_awareness_before_the_first_signal_is_refused(api, key):
    cid = case_id()
    call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key, body={
        "received_at": "2026-02-01T10:00:00Z", "channel": "other", "description": "d",
        "actor": ACTOR})
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key, body={
        "established_at": "2026-02-01T09:59:59Z", "assessment_started_at": "2026-02-01T09:00:00Z",
        "assessment_completed_at": "2026-02-01T09:59:59Z",
        "track": "actively_exploited_vulnerability", "reasoning": "x", "actor": ACTOR})
    assert 400 <= status < 500


@needs_api
def test_awareness_cannot_be_recorded_without_a_signal(api, key):
    status, _ = call(api.base, "POST", f"/v1/cases/{case_id()}/awareness", key=key, body={
        "established_at": "2026-02-01T09:59:59Z", "assessment_started_at": "2026-02-01T09:00:00Z",
        "assessment_completed_at": "2026-02-01T09:59:59Z",
        "track": "actively_exploited_vulnerability", "reasoning": "x", "actor": ACTOR})
    assert 400 <= status < 500


@needs_api
def test_awareness_without_reasoning_is_not_evidence_over_the_api(api, key):
    cid = case_id()
    call(api.base, "POST", f"/v1/cases/{cid}/signal", key=key, body={
        "received_at": "2026-02-01T06:00:00Z", "channel": "other", "description": "d",
        "actor": ACTOR})
    status, _ = call(api.base, "POST", f"/v1/cases/{cid}/awareness", key=key, body={
        "established_at": "2026-02-01T09:00:00Z", "assessment_started_at": "2026-02-01T06:00:00Z",
        "assessment_completed_at": "2026-02-01T09:00:00Z",
        "track": "actively_exploited_vulnerability", "reasoning": "", "actor": ACTOR})
    assert status == 422


@needs_api
def test_a_later_measure_never_pushes_the_14_day_clock_out(api, key):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", "2026-02-01T08:00:00Z")
    for at in ("2026-02-10T00:00:00Z", "2026-02-20T00:00:00Z"):
        assert call(api.base, "POST", f"/v1/cases/{cid}/measure", key=key, body={
            "available_at": at, "description": "m", "actor": ACTOR})[0] == 201
    assert deadlines(api, key, cid)["final"]["due_at"] == "2026-02-24T00:00:00Z"


# ------------------------------------------------------------------------ CLI and API agree
@needs_api
@pytest.mark.parametrize("label,text", AWARENESS_INSTANTS[:6], ids=[a for a, _ in
                                                                    AWARENESS_INSTANTS[:6]])
def test_the_cli_and_the_api_give_the_same_deadlines_for_the_same_awareness(
        api, key, tmp_path, label, text):
    cid, _, _ = open_case(api, key, "actively_exploited_vulnerability", text)
    api_deadlines = {k: v["due_at"] for k, v in deadlines(api, key, cid).items()}
    ledger = tmp_path / "l.db"
    aware = datetime.fromisoformat(text)
    sig = aware - timedelta(hours=2)
    assert assurance("art14", "--ledger", str(ledger), "signal", "C1", "--by", "t:analyst", "--at",
                     sig.isoformat(), "--description", "d", "--product", "P", "--version", "1",
                     cwd=tmp_path).exit == 0
    run = assurance("art14", "--ledger", str(ledger), "awareness", "C1", "--by", "t:analyst",
                    "--at", text, "--started", sig.isoformat(), "--completed", text, "--track",
                    "actively_exploited_vulnerability", "--because", "synthetic reasoning",
                    cwd=tmp_path)
    assert run.exit == 0, run.err
    shown = assurance("art14", "--ledger", str(ledger), "case", "C1", "--json", cwd=tmp_path)
    cli_deadlines = {d["stage"]: d["due_at"] for d in json.loads(shown.out)["deadlines"][
        "deadlines"]}
    assert cli_deadlines == api_deadlines


# ----------------------------------------------------------------- Member State validation
def _member_issues(api, codes, key=None):
    # an authenticated caller: the anonymous validator is capped at 20 a day per address
    status, body = call(api.base, "POST", "/v1/spec/validate", key=api._art14_key, body={
        "track": "actively_exploited_vulnerability", "stage": "early_warning",
        "payload": {"member_states_available": codes}})
    assert status == 200
    return [i for i in body["issues"] if i["field_name"] == "member_states_available"]


@needs_api
def test_eu_member_states_are_accepted(api, key):
    assert _member_issues(api, ["DE", "FR", "AT", "NL", "HR", "IE", "SE"]) == []


@needs_api
@pytest.mark.parametrize("code", ["CH", "UK", "GB", "US", "XX", "ZZ", "TR", "RU"])
def test_a_territory_outside_the_eu_is_a_blocking_issue(api, key, code):
    issues = _member_issues(api, ["DE", code])
    assert any(i["severity"] == "blocking" and code in i["message"] for i in issues), issues


@needs_api
@pytest.mark.parametrize("code", ["NO", "IS", "LI"])
def test_an_eea_state_that_is_not_an_eu_member_is_flagged_not_assumed(api, key, code):
    issues = _member_issues(api, ["DE", code])
    assert any(code in i["message"] and "EEA" in i["message"] for i in issues), issues


@needs_api
@pytest.mark.parametrize("bad", [" de ", "D", "DEU", "de-DE", "", "1", "D E", "Germany"])
def test_a_malformed_country_code_is_blocking_and_not_silently_normalised(api, key, bad):
    issues = _member_issues(api, ["DE", bad])
    assert any(i["severity"] == "blocking" for i in issues), (bad, issues)


@needs_api
def test_an_empty_member_state_list_is_not_accepted_as_nothing_to_report(api, key):
    status, body = call(api.base, "POST", "/v1/spec/validate", key=key, body={
        "track": "actively_exploited_vulnerability", "stage": "early_warning",
        "payload": {"member_states_available": []}})
    assert status == 200 and body["submittable"] is False


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT (wording, low severity): entering 'EL' is reported as 'not an EU Member "
    "State'. EL is the EU institutions' own code for Greece (ISO 3166-1 uses GR). Telling a "
    "person that Greece is not a Member State is wrong; the issue should say 'use GR (ISO "
    "3166-1 alpha-2)' or accept it. Which code the ENISA platform expects is UNCHECKED here. "
    "Remove this marker when the message no longer says EL is not a Member State."))
@needs_api
def test_the_eus_own_code_for_greece_is_not_called_a_non_member(api, key):
    issues = _member_issues(api, ["DE", "EL"])
    text = " ".join(i["message"] for i in issues)
    assert "EL" not in text or "not EU Member States" not in text, text


@needs_api
def test_greece_by_its_iso_code_is_accepted(api, key):
    assert _member_issues(api, ["GR"]) == []
