"""ATTACK MATRIX: opening a change case from a signed supplier advisory
(``POST /v1/change/assess/advisory/signed``).

Evidence level: the product's real FastAPI app on loopback, throwaway Cell accounts with a
throwaway individual 'decider' operator, real Ed25519 keys made by the product's CLI, SYNTHETIC
supplier, advisories and machines. If the product revision lacks the route every test is skipped
as BLOCKED. Not hosted staging.

This is where supplier trust turns into an automated consequence: a case opens without a named
person. Independent expectations, from the route's stated rule and plain logic:

* only an advisory whose signatures are valid under a key THIS ACCOUNT pinned for THIS supplier,
  on an intact chain, opens a case without a named person; and the case says which basis did it;
* anything else (no pin, an operator-supplied key, an edited or foreign-key record, a revoked or
  retired key, an unreadable feed, a translation nobody authenticated) opens nothing unless a
  named 'decider' operator accepts it, explicitly, with a reason, and the case says that;
* the route never closes, rejects, defers or resolves anything, and the same call twice is one
  case, not two;
* a case opens only when the advisory touches a machine; nothing matched is not a case;
* trust and cases are per account.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from support_api import api_importable, call, live_api
from test_attack_supplier_api import SUPPLIER_ID, Cell
from test_attack_supplier_trust_cli import Pack

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
_has_route = bool(PRODUCT_SRC) and "assess/advisory/signed" in (
    __import__("pathlib").Path(PRODUCT_SRC) / "assurance" / "api" / "change_routes.py"
).read_text(encoding="utf-8")
pytestmark = pytest.mark.skipif(
    not (_ok and _has_route), reason="BLOCKED: this revision has no signed-advisory case route")

ROUTE = "/v1/change/assess/advisory/signed"


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    pack = Pack(tmp_path_factory.mktemp("signed-case"))
    return {"pack": pack, "text": (pack.work / "feed.jsonl").read_text(),
            "lines": (pack.work / "feed.jsonl").read_text().splitlines(),
            "pem_s": (pack.work / "s.pub").read_text(), "pem_x": (pack.work / "x.pub").read_text(),
            "pem_y": (pack.work / "y.pub").read_text(), "fp_s": pack.fp_s}


@pytest.fixture()
def cell(api):
    n = {"i": 0}

    def make(machines=("M01", "M02", "M08")):
        n["i"] += 1
        c = Cell(api, f"sc{n['i']}-{id(n)}")
        c.enrol(machines)
        return c
    return make


def open_case(api, c, text, advisory_id="ADV-A1", *, key=None, **extra):
    return call(api.base, "POST", ROUTE, key=key or c.account_key, body={
        "feed": text, "expect_supplier": SUPPLIER_ID, "advisory_id": advisory_id, **extra})


def cases(api, c):
    status, body = call(api.base, "GET", "/v1/change/cases", key=c.account_key)
    assert status == 200, body
    return body["cases"]


# ----------------------------------------------------------------------------- the one way in
def test_a_pinned_key_and_a_valid_chain_open_the_case_and_the_case_says_why(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"], expected_fingerprint=signer["fp_s"])[0] == 201
    status, body = open_case(api, c, signer["text"])
    assert status == 200 and body["opened"] is True, body
    case = body["case"]
    assert case["trigger_type"] == "supplier_advisory" and case["trigger_id"] == "ADV-A1"
    assert case["status"] == "open" and case["machines"] == ["SynthCo/Cell-1#M01"]
    assert body["advisory_trust"]["trust_basis"] == "pinned_key_policy"
    assert body["advisory_trust"]["automated_consequences_permitted"] is True
    assert body["feed_trust"]["trust_state"] == "trusted"
    assert "Alice" not in json.dumps(case), "automation was recorded as if a person had decided"


def test_the_case_is_open_not_closed_and_nothing_is_ready_to_close(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    detail = open_case(api, c, signer["text"])[1]["case"]
    summary = call(api.base, "GET", "/v1/change/cases", key=c.account_key)[1]["summary"]
    assert summary["open"] == 1 and summary["ready_to_close"] == 0
    assert cases(api, c)[0]["status"] == "open"
    assert detail["required_actions"] and "verification evidence" in " ".join(
        detail["required_actions"]).lower()
    assert detail["evidence_current"]["SynthCo/Cell-1#M01/SF-1"] == "never_verified"


def test_the_same_call_twice_is_one_case_not_two(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    first = open_case(api, c, signer["text"])[1]
    second = open_case(api, c, signer["text"])[1]
    assert first["case"]["case_id"] == second["case"]["case_id"]
    assert len(cases(api, c)) == 1


def test_an_advisory_that_matches_no_machine_opens_nothing(api, signer, cell):
    c = cell(machines=("M02",))                       # the corrected version only
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = open_case(api, c, signer["text"])
    assert status == 200 and body["opened"] is False and body["case"] is None
    assert cases(api, c) == []


# ------------------------------------------------------------------ everything else is refused
def _refused_and_nothing_opened(api, c, status, body):
    assert 400 <= status < 500, (status, body)
    assert cases(api, c) == []


def test_without_a_pin_no_case_opens_and_the_refusal_says_a_named_person_is_needed(api, signer,
                                                                                 cell):
    c = cell()
    status, body = open_case(api, c, signer["text"])
    _refused_and_nothing_opened(api, c, status, body)
    assert "named person" in json.dumps(body)


def test_a_key_the_caller_merely_holds_is_not_trust(api, signer, cell):
    c = cell()
    status, body = open_case(api, c, signer["text"], candidate_public_key_pem=signer["pem_s"])
    _refused_and_nothing_opened(api, c, status, body)


def test_an_attackers_key_signing_the_real_suppliers_identity_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    pack = signer["pack"]
    (pack.work / "evil.json").write_text(json.dumps({
        **json.loads((pack.work / "a1.json").read_text()), "advisory_id": "ADV-EVIL"}))
    assert pack.publish_as("x.key", "evil.jsonl", "evil.json").exit == 0
    evil = (pack.work / "evil.jsonl").read_text()
    status, body = open_case(api, c, evil, "ADV-EVIL")
    _refused_and_nothing_opened(api, c, status, body)


def test_an_advisory_edited_after_signing_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    record = json.loads(signer["lines"][0])
    record["advisory"]["affected"][0]["versions"] = ["V5.001", "V9.999"]
    status, body = open_case(api, c, json.dumps(record) + "\n")
    _refused_and_nothing_opened(api, c, status, body)


def test_a_revoked_key_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    revoked = c.post("/v1/supplier/trust/revoke", {
        "supplier_id": SUPPLIER_ID, "fingerprint": signer["fp_s"], "reason": "compromised"})
    assert revoked[0] == 200
    status, body = open_case(api, c, signer["text"])
    _refused_and_nothing_opened(api, c, status, body)


def test_a_retired_key_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    assert c.post("/v1/supplier/trust/rotate", {
        "supplier_id": SUPPLIER_ID, "new_public_key_pem": signer["pem_y"],
        "retire_fingerprint": signer["fp_s"], "effective_at": "2026-01-01T00:00:00Z",
        "obtained_via": "phone call to the supplier"})[0] == 201
    status, body = open_case(api, c, signer["text"])
    _refused_and_nothing_opened(api, c, status, body)


def test_another_accounts_pin_does_not_open_a_case_here(api, signer, cell):
    a, b = cell(), cell()
    assert a.pin(signer["pem_s"])[0] == 201
    assert open_case(api, a, signer["text"])[0] == 200
    status, body = open_case(api, b, signer["text"])
    _refused_and_nothing_opened(api, b, status, body)
    assert len(cases(api, a)) == 1


@pytest.mark.parametrize("feed", ["", "\n", "junk", "[1]", "null", "{" * 300, "\x00\x01"])
def test_an_unreadable_feed_opens_nothing_and_is_a_4xx(api, signer, cell, feed):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = open_case(api, c, feed)
    _refused_and_nothing_opened(api, c, status, body)


def test_an_advisory_that_is_not_in_the_feed_is_a_404_and_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = open_case(api, c, signer["text"], "ADV-NOT-THERE")
    assert status == 404 and body["detail"]["error"] == "advisory_not_in_feed"
    assert cases(api, c) == []


def test_a_withdrawn_advisory_opens_nothing(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    pack = signer["pack"]
    # a copy of the pack's feed with a signed withdrawal of ADV-A1
    (pack.work / "wfeed.jsonl").write_text(signer["text"])
    done = pack.sup("withdraw", "ADV-A1", "--reason", "published in error", "--feed",
                    "wfeed.jsonl", "--key", "s.key", "--supplier-id", SUPPLIER_ID, "--legal-name",
                    "Rockwell Automation", "--key-contact", "security@example.invalid")
    assert done.exit == 0, done.err
    status, body = open_case(api, c, (pack.work / "wfeed.jsonl").read_text())
    assert status == 404 and cases(api, c) == []


# --------------------------------------------------------------- a named person, explicitly
def test_an_account_key_cannot_accept_an_unauthenticated_advisory_even_by_asking(api, signer,
                                                                                cell):
    c = cell()
    status, body = open_case(api, c, signer["text"], accept_unsigned=True,
                             reason="i say so", actor="Dr. Somebody, CISO")
    _refused_and_nothing_opened(api, c, status, body)
    assert status in (403, 409)


def test_a_decider_operator_can_accept_it_and_the_case_names_them_and_the_reason(api, signer,
                                                                                cell):
    c = cell()
    status, body = open_case(api, c, signer["text"], key=c.decider_key, accept_unsigned=True,
                             reason="read against the vendor PDF by phone")
    assert status == 200 and body["opened"] is True, body
    text = json.dumps(body)
    assert "Alice Decider" in text and "read against the vendor PDF" in text
    assert body["advisory_trust"]["trust_basis"] != "pinned_key_policy"
    assert body["advisory_trust"]["automated_consequences_permitted"] is False


def test_a_contributor_operator_cannot_accept_an_unauthenticated_advisory(api, signer, cell):
    c = cell()
    status, body = open_case(api, c, signer["text"], key=c.contributor_key, accept_unsigned=True,
                             reason="r")
    _refused_and_nothing_opened(api, c, status, body)


def test_a_typed_name_cannot_stand_in_for_the_deciders_name(api, signer, cell):
    c = cell()
    status, body = open_case(api, c, signer["text"], key=c.decider_key, accept_unsigned=True,
                             reason="r", actor="Someone Else")
    assert status == 403 and body["detail"]["error"] == "actor_mismatch"
    assert cases(api, c) == []


# ---------------------------------------------------------- a translation nobody authenticated
HAND_SIGN = """
import sys, json, base64, dataclasses
from pathlib import Path
from assurance.attest.keys import SigningKey
from assurance.core.identity import format_utc, utc_now
from assurance.supplier.publish import FEED_FORMAT, SignedAdvisory, SupplierIdentity
key = SigningKey.load(Path(sys.argv[1]))
adv = json.loads(Path(sys.argv[2]).read_text())
ident = SupplierIdentity(supplier_id=sys.argv[4], legal_name=adv["issued_by"],
                         key_contact="x@example.invalid")
rec = SignedAdvisory(format=FEED_FORMAT, sequence=1, supplier=ident,
                     key_fingerprint=key.fingerprint, published_at=format_utc(utc_now()),
                     previous="", advisory=adv)
rec = dataclasses.replace(rec, signature=base64.b64encode(key.sign(rec.signed_payload())).decode())
Path(sys.argv[3]).write_text(json.dumps(rec.to_dict(), sort_keys=True) + "\\n")
"""


def test_a_pinned_key_does_not_let_a_csaf_translation_open_a_case_on_its_own(api, signer, cell,
                                                                           tmp_path):
    from support_cli import assurance
    from test_attack_csaf_cli import BASE
    (tmp_path / "csaf.json").write_text(json.dumps(BASE))
    assert assurance("fleet", "import-csaf", "csaf.json", "--out", "adv.json",
                     cwd=tmp_path).exit == 0
    pack = signer["pack"]
    done = subprocess.run(
        [sys.executable, "-c", HAND_SIGN, str(pack.work / "s.key"), "adv.json",
         str(tmp_path / "feed.jsonl"), "syn-cert"], cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
        capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr[-300:]
    c = Cell(api, f"csafcase-{id(tmp_path)}")
    for serial, version in (("A", "12.001"), ("B", "12.002")):
        from support_cli import synthetic_manifest
        assert call(api.base, "POST", "/v1/machinery/manifest", key=c.account_key, body={
            "manifest": synthetic_manifest(serial, [("P1", "1756-EN2T", version)],
                                           supplier="Rockwell Automation"),
            "actor": "synthetic.tech"})[0] == 200
    assert c.pin((pack.work / "s.pub").read_text(), supplier="syn-cert")[0] == 201
    status, body = call(api.base, "POST", ROUTE, key=c.account_key, body={
        "feed": (tmp_path / "feed.jsonl").read_text(), "expect_supplier": "syn-cert",
        "advisory_id": "SYN-CSAF-1"})
    assert 400 <= status < 500, (status, str(body)[:300])
    assert cases(api, c) == []


# ----------------------------------------------------------------------------- the edges
def test_the_route_demands_a_key_and_the_cell_plan(api, signer):
    assert call(api.base, "POST", ROUTE, body={"feed": signer["text"],
                                               "advisory_id": "ADV-A1"})[0] == 401
    free = api.make_account("sc-free@example.invalid", "free")
    assert call(api.base, "POST", ROUTE, key=free, body={"feed": signer["text"],
                                                         "advisory_id": "ADV-A1"})[0] == 402
    reg = api.make_account("sc-reg@example.invalid", "register")
    assert call(api.base, "POST", ROUTE, key=reg, body={"feed": signer["text"],
                                                        "advisory_id": "ADV-A1"})[0] == 402


@pytest.mark.parametrize("body", [
    {}, {"advisory_id": "ADV-A1"}, {"feed": "x"}, {"feed": "x", "advisory_id": ""},
    {"feed": "x", "advisory_id": "A", "unexpected": 1}, {"feed": 5, "advisory_id": "A"},
    {"feed": "x", "advisory_id": ["A"]}, {"feed": "x" * 4_500_000, "advisory_id": "A"},
    {"feed": "x", "advisory_id": "A" * 300},
])
def test_a_malformed_request_is_4xx_and_opens_nothing(api, cell, body):
    c = cell()
    status, resp = call(api.base, "POST", ROUTE, key=c.account_key, body=body)
    assert 400 <= status < 500 or status == 0, (status, str(resp)[:200])
    assert cases(api, c) == []
    assert call(api.base, "GET", "/healthz")[0] == 200


def test_nothing_in_this_route_can_close_decide_or_resume_a_case(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    cid = open_case(api, c, signer["text"])[1]["case"]["case_id"]
    for verb in ("decision", "resume", "resolve-decision", "waive-reverification"):
        status, _ = call(api.base, "POST", f"/v1/change/cases/{cid}/{verb}", key=c.account_key,
                         body={"decision": "close", "actor": "bot", "reason": "r"})
        assert status in (403, 409, 422), (verb, status)
    assert cases(api, c)[0]["status"] == "open"


def test_the_mcp_server_has_no_tool_for_this_route():
    try:
        from support_mcp import list_tools, mcp_importable
    except ImportError:
        pytest.skip("BLOCKED: MCP harness unavailable")
    if not mcp_importable()[0]:
        pytest.skip("BLOCKED: product MCP server not runnable")
    assert not [t.name for t in list_tools() if "advisory" in t.name and "assess" in t.name]
