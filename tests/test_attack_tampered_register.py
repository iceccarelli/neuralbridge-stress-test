"""ATTACK, product CLI and API: what the Article 14 register shows and accepts once its ledger
file has been edited.

Evidence level: product CLI (subprocess) and the real API (uvicorn on loopback), temporary
state, SYNTHETIC cases. The ledger file is edited from outside, as a hostile operator, a
restore gone wrong or a failing disk would.

Independent expectation: a CRA reporting deadline is a legal clock. Once the product can know
the chain no longer verifies (its own verifier says so), it must not (a) hand the customer a
deadline derived from the edited record as though nothing were wrong, or (b) keep appending
new legal records to a chain it knows is broken. Refusing, or showing the deadline together
with a visible integrity failure, are both acceptable; showing it plainly is not.

The control tests pass today and establish that the attack is real: one edited field moves
the early-warning deadline ten days, and the verifier does notice. The strict-xfail tests are
the defect (neuralbridge issue linked in the reason); they must be removed when it is fixed.
"""
from __future__ import annotations

import re
import sqlite3

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

ORIGINAL_AWARE = "2026-10-01T09:00:00Z"
SHIFTED_AWARE = "2026-10-11T09:00:00Z"
ORIGINAL_DUE = "2026-10-02T09:00:00Z"        # 24 h after awareness, Art. 14(2)(a)
SHIFTED_DUE = "2026-10-12T09:00:00Z"

DEFECT = ("PRODUCT DEFECT: the Article 14 register shows and extends a ledger whose own "
          "verifier reports it broken. Remove this marker when reads are refused or visibly "
          "flagged and writes are refused while the chain does not verify.")


def _edit_awareness_date(ledger_path):
    db = sqlite3.connect(ledger_path)
    (payload,) = db.execute("SELECT payload FROM chain WHERE kind LIKE '%awareness%'").fetchone()
    assert ORIGINAL_AWARE in payload
    db.execute("UPDATE chain SET payload=? WHERE kind LIKE '%awareness%'",
               (payload.replace(ORIGINAL_AWARE, SHIFTED_AWARE),))
    db.commit()
    db.close()


def _flags_integrity(text: str) -> bool:
    return bool(re.search(r"integrity|does not verify|verification failed|tamper|chain|edited"
                          r"|broken", text, re.IGNORECASE))


# --------------------------------------------------------------------------------- CLI
@pytest.fixture()
def cli_ledger(tmp_path):
    ledger = tmp_path / "l.db"
    run = assurance("art14", "--ledger", str(ledger), "signal", "C1", "--by", "t:analyst", "--at",
                    "2026-10-01T08:00:00Z", "--description", "synthetic", "--product", "P",
                    "--version", "1", cwd=tmp_path)
    assert run.exit == 0, run.err
    run = assurance("art14", "--ledger", str(ledger), "awareness", "C1", "--by", "t:analyst",
                    "--at", ORIGINAL_AWARE, "--started", "2026-10-01T08:00:00Z", "--completed",
                    ORIGINAL_AWARE, "--track", "actively_exploited_vulnerability", "--because",
                    "synthetic reasoning", cwd=tmp_path)
    assert run.exit == 0, run.err
    return tmp_path, ledger


def _case(work, ledger):
    return assurance("art14", "--ledger", str(ledger), "case", "C1", cwd=work)


def test_control_cli_one_edited_field_moves_the_deadline_and_only_verify_notices(cli_ledger):
    work, ledger = cli_ledger
    assert ORIGINAL_DUE in _case(work, ledger).out
    _edit_awareness_date(ledger)
    shown = _case(work, ledger)
    assert SHIFTED_DUE in shown.out and ORIGINAL_DUE not in shown.out      # the attack works
    verdict = assurance("art14", "--ledger", str(ledger), "verify", cwd=work)
    assert verdict.exit == 1 and "edited" in (verdict.out + verdict.err)   # and is detectable


@pytest.mark.xfail(strict=True, reason=DEFECT + " [CLI read]")
def test_cli_a_case_read_from_an_edited_ledger_is_refused_or_visibly_flagged(cli_ledger):
    work, ledger = cli_ledger
    _edit_awareness_date(ledger)
    shown = _case(work, ledger)
    if shown.exit != 0:
        return
    assert _flags_integrity(shown.out + shown.err), (
        "the edited deadline was printed with exit 0 and no integrity warning:\n" + shown.out)


@pytest.mark.xfail(strict=True, reason=DEFECT + " [CLI write]")
def test_cli_a_new_record_is_not_appended_to_a_chain_that_does_not_verify(cli_ledger):
    work, ledger = cli_ledger
    _edit_awareness_date(ledger)
    run = assurance("art14", "--ledger", str(ledger), "signal", "C2", "--by", "t:analyst", "--at",
                    "2026-10-02T08:00:00Z", "--description", "after edit", "--product", "P",
                    "--version", "1", cwd=work)
    assert run.exit != 0, "a legal record was appended to a ledger its own verifier calls broken"


# --------------------------------------------------------------------------------- API
_ok, _why = api_importable()
SIGNAL = {"received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": "synthetic",
          "actor": {"identifier": "t", "role": "analyst"}}
AWARE = {"established_at": ORIGINAL_AWARE, "assessment_started_at": "2026-10-01T08:00:00Z",
         "assessment_completed_at": ORIGINAL_AWARE, "track": "actively_exploited_vulnerability",
         "reasoning": "synthetic reasoning", "actor": {"identifier": "t", "role": "analyst"}}


@pytest.fixture()
def api_tenant():
    if not _ok:
        pytest.skip(f"BLOCKED: product API not runnable ({_why})")
    with live_api() as api:
        key = api.make_account("t@example.invalid")
        assert call(api.base, "POST", "/v1/cases/C1/signal", key=key, body=SIGNAL)[0] == 201
        assert call(api.base, "POST", "/v1/cases/C1/awareness", key=key, body=AWARE)[0] == 201
        (ledger,) = list((api.state / "tenants").glob("*.db"))
        yield api, key, ledger


def _api_case(api, key):
    return call(api.base, "GET", "/v1/cases/C1", key=key)


def test_control_api_one_edited_field_moves_the_deadline_and_verify_notices(api_tenant):
    api, key, ledger = api_tenant
    assert ORIGINAL_DUE in str(_api_case(api, key)[1])
    _edit_awareness_date(ledger)
    status, body = _api_case(api, key)
    assert status == 200 and SHIFTED_DUE in str(body)                     # the attack works
    status, verdict = call(api.base, "GET", "/v1/ledger/verify", key=key)
    assert status == 200 and verdict["verified"] is False                 # and is detectable


@pytest.mark.xfail(strict=True, reason=DEFECT + " [API read]")
def test_api_a_case_read_from_an_edited_ledger_is_refused_or_visibly_flagged(api_tenant):
    api, key, ledger = api_tenant
    _edit_awareness_date(ledger)
    assert call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["verified"] is False
    status, body = _api_case(api, key)
    if status != 200:
        return
    assert _flags_integrity(" ".join(map(str, body.keys()))), (
        "the edited deadline was served 200 with no integrity field after the same service "
        "had just reported the chain broken")


@pytest.mark.xfail(strict=True, reason=DEFECT + " [API write]")
def test_api_a_new_record_is_not_appended_after_the_service_reported_the_chain_broken(api_tenant):
    api, key, ledger = api_tenant
    _edit_awareness_date(ledger)
    assert call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["verified"] is False
    status, body = call(api.base, "POST", "/v1/cases/C2/signal", key=key, body=SIGNAL)
    assert not (200 <= status < 300), (
        f"POST answered {status}: a legal record was appended to a chain the same service had "
        "just reported broken")
