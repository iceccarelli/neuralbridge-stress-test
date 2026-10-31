"""ATTACK MATRIX, product API level: the evidence ledger behind a running service.

Evidence level: the product's REAL FastAPI app in a uvicorn subprocess on 127.0.0.1, throwaway
state, throwaway accounts and a throwaway signing key, SYNTHETIC signals; the ledger FILES are
attacked from outside while the server runs (a hostile operator or a bad disk). Not hosted
staging and never production.

Independent expectations, stated here and not read from the product:

* each account has its own chain: another account can neither read, export, count nor
  attest against it, and a tenant write never touches the shared operator ledger;
* an on-disk edit to any sealed column (payload, actor, time, kind, subject, link) is reported
  by ``GET /v1/ledger/verify`` and stops an export; it never reaches a customer as a clean
  bundle, and it never spreads to another account;
* a hash chain cannot show that the newest records were cut off, and the API says so: a
  truncated ledger still verifies, but a head the holder declared earlier is refused (409)
  and a signed anchor makes the export refuse (409);
* a counter-signature signs only what the holder declared and says it did not look at the
  ledger; it refuses a shorter or forked head, and the tenant can never set ``rotating``;
* refused input (malformed, nested, oversized, replayed, unauthorised) never writes, never
  returns 5xx and never leaks a server path or key material;
* concurrent writers cannot fork the chain.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
pytestmark = pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})")

SIGNAL = {"received_at": "2026-10-01T08:00:00Z", "channel": "other",
          "description": "synthetic signal", "actor": {"identifier": "t", "role": "analyst"}}
AWARE = {"established_at": "2026-10-01T09:00:00Z", "assessment_started_at": "2026-10-01T08:00:00Z",
         "assessment_completed_at": "2026-10-01T09:00:00Z",
         "track": "actively_exploited_vulnerability", "reasoning": "synthetic reasoning",
         "actor": {"identifier": "t", "role": "analyst"}}


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    d = tmp_path_factory.mktemp("signer")
    run = assurance("attest", "keygen", "--out", str(d / "k.key"), "--public-out",
                    str(d / "k.pub"), cwd=d)
    assert run.exit == 0, run.err
    return d


@pytest.fixture(scope="module")
def api(signer):
    with live_api({"ASSURANCE_ATTEST_KEY": str(signer / "k.key")}) as running:
        yield running


class Tenant:
    """A throwaway paying account with a ledger that already holds one record."""

    def __init__(self, api, label: str, tier: str = "cell"):
        self.api = api
        before = set((api.state / "tenants").glob("*.db"))
        self.key = api.make_account(f"{label}@example.invalid", tier)
        self.email = f"{label}@example.invalid"
        if tier != "free":
            assert self.post("SEED", "signal", SIGNAL)[0] == 201
            new = set((api.state / "tenants").glob("*.db")) - before
            assert len(new) == 1
            self.ledger: Path = new.pop()
            self.account_id = self.ledger.stem

    def get(self, path: str):
        return call(self.api.base, "GET", path, key=self.key)

    def post(self, case: str, verb: str, body):
        return call(self.api.base, "POST", f"/v1/cases/{case}/{verb}", key=self.key, body=body)

    def head(self) -> dict:
        status, body = self.get("/v1/ledger/verify")
        assert status == 200, body
        return body

    def length(self) -> int:
        return self.head()["attestation"]["length"]

    def attest(self, **body):
        return call(self.api.base, "POST", "/v1/ledger/attest", key=self.key, body=body)

    def declare_current_head(self):
        h = self.head()["attestation"]
        return self.attest(ledger_length=h["length"], head_seq=h["head_seq"],
                           head_link_hash=h["head_link_hash"])

    def edit(self, sql: str, *args):
        db = sqlite3.connect(self.ledger)
        db.execute(sql, args)
        db.commit()
        db.close()


def _tenant_counter(api):
    n = {"i": 0}

    def make(tier="cell"):
        n["i"] += 1
        return Tenant(api, f"t{n['i']}-{os.getpid()}", tier)
    return make


@pytest.fixture()
def tenant(api):
    return _tenant_counter(api)()


@pytest.fixture()
def two(api):
    make = _tenant_counter(api)
    return make(), make()


def _build_history(t: Tenant, cases=("H1", "H2")):
    for c in cases:
        assert t.post(c, "signal", SIGNAL)[0] == 201
    assert t.post("H1", "awareness", AWARE)[0] == 201


# -------------------------------------------------------------------------- the baseline
def test_an_intact_tenant_ledger_verifies_and_reports_its_own_length(tenant):
    _build_history(tenant)
    body = tenant.head()
    assert body["verified"] is True and body["problems"] == []
    assert body["attestation"]["length"] == 4            # SEED + H1 + H2 + awareness
    assert body["attestation"]["head_seq"] == 4
    assert len(body["attestation"]["head_link_hash"]) == 64


def test_the_verify_note_does_not_overclaim(tenant):
    note = tenant.head()["note"].lower()
    assert "determined insider" in note        # it names its own limit


# ------------------------------------------------------------------------ tenant boundary
def test_another_account_cannot_read_or_export_a_case_it_did_not_open(two):
    a, b = two
    assert a.post("ONLY-A", "signal", SIGNAL)[0] == 201
    status, body = b.get("/v1/cases/ONLY-A")
    assert status == 404 and "description" not in json.dumps(body)
    assert b.get("/v1/cases/ONLY-A/export")[0] == 404
    assert "ONLY-A" not in json.dumps(b.get("/v1/cases")[1])
    assert "ONLY-A" in json.dumps(a.get("/v1/cases")[1])


def test_each_accounts_chain_has_its_own_length_and_head(two):
    a, b = two
    _build_history(a)
    assert a.length() == 4 and b.length() == 1
    assert a.head()["attestation"]["head_link_hash"] != b.head()["attestation"]["head_link_hash"]


def test_a_tenants_attestations_are_invisible_to_another_tenant(two):
    a, b = two
    assert a.declare_current_head()[0] == 200
    assert a.get("/v1/ledger/attest/log")[1]["count"] == 1
    assert b.get("/v1/ledger/attest/log")[1]["count"] == 0


def test_one_tenants_declared_head_does_not_constrain_another(two):
    """A declares a long head; B (shorter) must not be refused as a rewind of A."""
    a, b = two
    _build_history(a)
    assert a.declare_current_head()[0] == 200
    assert b.declare_current_head()[0] == 200


def test_tenant_writes_never_touch_the_shared_operator_ledger(api, tenant):
    shared = api.state / "register.db"
    def fingerprint():
        if not shared.exists():
            return None
        db = sqlite3.connect(f"file:{shared}?mode=ro", uri=True)
        try:
            return db.execute("SELECT count(*), coalesce(max(link_hash),'') FROM chain").fetchone()
        finally:
            db.close()
    before = fingerprint()
    _build_history(tenant)
    assert fingerprint() == before


def test_the_operator_ledger_is_not_readable_with_a_tenant_key(api, tenant):
    status, body = call(api.base, "GET", "/v1/cases", key=tenant.key)
    assert status == 200 and "SEED" in json.dumps(body)       # only the tenant's own case
    assert call(api.base, "GET", "/v1/cases/OP-ONLY-CASE", key=tenant.key)[0] == 404


# ----------------------------------------------------------------- on-disk edit matrix
def _edit_payload(t):
    t.edit("UPDATE chain SET payload=replace(payload,'2026-10-01','2027-10-01') WHERE seq=2")

def _edit_actor(t):
    t.edit("UPDATE chain SET actor='mallory' WHERE seq=2")

def _edit_time(t):
    t.edit("UPDATE chain SET at='2026-01-01T00:00:00Z' WHERE seq=2")

def _edit_kind(t):
    t.edit("UPDATE chain SET kind='art14.something_else' WHERE seq=2")

def _edit_subject(t):
    t.edit("UPDATE chain SET subject='H9' WHERE seq=2")

def _edit_link(t):
    t.edit("UPDATE chain SET link_hash=? WHERE seq=2", "0" * 64)

def _delete_middle(t):
    t.edit("DELETE FROM chain WHERE seq=2")

def _swap_payloads(t):
    db = sqlite3.connect(t.ledger)
    p1, p2 = [r[0] for r in db.execute("SELECT payload FROM chain WHERE seq IN (2,3) ORDER BY seq")]
    db.execute("UPDATE chain SET payload=? WHERE seq=2", (p2,))
    db.execute("UPDATE chain SET payload=? WHERE seq=3", (p1,))
    db.commit()
    db.close()


EDITS = [_edit_payload, _edit_actor, _edit_time, _edit_kind, _edit_subject, _edit_link,
         _delete_middle, _swap_payloads]


@pytest.mark.parametrize("edit", EDITS, ids=lambda f: f.__name__.strip("_"))
def test_an_edit_to_the_ledger_file_is_reported_and_stops_the_export(two, edit):
    victim, bystander = two
    _build_history(victim)
    assert victim.get("/v1/cases/H1/export")[0] == 200       # exportable before the edit
    edit(victim)
    status, body = victim.get("/v1/ledger/verify")
    assert status == 200 and body["verified"] is False and body["problems"], body
    status, body = victim.get("/v1/cases/H1/export")
    assert status != 200 and "ledger_integrity" in json.dumps(body), (status, body)
    assert bystander.head()["verified"] is True                # no spill-over to another tenant


def test_a_refused_export_leaks_no_server_path_or_key_material(api, two):
    victim, _ = two
    _build_history(victim)
    _edit_payload(victim)
    blob = json.dumps([victim.get("/v1/cases/H1/export"), victim.get("/v1/ledger/verify")])
    for needle in (str(api.state), "/tmp/", "PRIVATE KEY", victim.key, api.operator_key):
        assert needle not in blob, needle


# ------------------------------------------- truncation: what the chain cannot show
def test_cutting_the_newest_records_still_verifies_and_the_api_does_not_claim_otherwise(tenant):
    _build_history(tenant)
    tenant.edit("DELETE FROM chain WHERE seq=4")
    body = tenant.head()
    assert body["verified"] is True                  # the documented limit of a bare chain
    assert body["attestation"]["length"] == 3
    assert "insider" in body["note"].lower()


def test_a_head_declared_before_the_cut_makes_the_cut_a_409(tenant):
    _build_history(tenant)
    assert tenant.declare_current_head()[0] == 200           # holder keeps this receipt
    tenant.edit("DELETE FROM chain WHERE seq=4")
    status, body = tenant.declare_current_head()
    assert status == 409 and body["detail"]["error"] == "attestation_refused"
    assert "does not get shorter" in body["detail"]["finding"]


def test_a_forked_history_at_the_same_length_is_a_409_fork(tenant):
    _build_history(tenant)
    h = tenant.head()["attestation"]
    assert tenant.attest(ledger_length=h["length"], head_seq=h["head_seq"],
                         head_link_hash=h["head_link_hash"])[0] == 200
    status, body = tenant.attest(ledger_length=h["length"], head_seq=h["head_seq"],
                                 head_link_hash="ab" * 32)
    assert status == 409 and "fork" in body["detail"]["finding"]


def test_a_signed_anchor_makes_an_export_of_a_cut_ledger_a_409(signer, tenant):
    """Anchor read FROM the ledger by the operator's CLI; then the ledger is cut."""
    _build_history(tenant)
    log = tenant.api.state / "attest-logs" / f"{tenant.account_id}.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    run = assurance("attest", "sign", "--ledger", str(tenant.ledger), "--key",
                    str(signer / "k.key"), "--log", str(log), cwd=signer)
    assert run.exit == 0, run.err
    status, bundle = tenant.get("/v1/cases/H1/export")
    assert status == 200 and bundle.get("anchor"), "the export should carry the signed anchor"
    tenant.edit("DELETE FROM chain WHERE seq=4")
    status, body = tenant.get("/v1/cases/H1/export")
    assert status == 409 and "anchor_contradicts_ledger" in json.dumps(body), (status, body)
    # the explicit opt-out is allowed, and is then only as strong as a bare chain
    status, bare = tenant.get("/v1/cases/H1/export?anchor=false")
    assert status == 200 and not bare.get("anchor")


def test_an_api_export_verifies_offline_with_the_cli_and_an_edit_to_it_does_not(
        signer, tenant, tmp_path):
    _build_history(tenant)
    status, bundle = tenant.get("/v1/cases/H1/export")
    assert status == 200 and bundle["chain_verified"] is True
    good = tmp_path / "good.json"
    good.write_text(json.dumps(bundle))
    run = assurance("evidence", "verify", str(good), "--json", cwd=tmp_path)
    assert run.exit in (0, 3), (run.exit, run.out, run.err)
    if run.exit == 0:       # a pass without a key must say completeness was not checked
        assert "complete" in run.out.lower()
    bad = json.loads(good.read_text())
    bad["entries"][0]["evidence"]["body"]["signal"]["description"] = "rewritten by an attacker"
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    run = assurance("evidence", "verify", str(tmp_path / "bad.json"), "--json", cwd=tmp_path)
    assert run.exit in (1, 2), (run.exit, run.out)


# ------------------------------------------------------------------- counter-signature
def test_the_counter_signature_says_it_did_not_look_at_the_ledger(tenant):
    status, body = tenant.declare_current_head()
    assert status == 200
    assert body["attestation"]["basis"] == "declared_by_holder"
    assert any("did not verify your chain" in s for s in body["checks_skipped"])


def test_a_replayed_declaration_is_a_new_numbered_receipt_not_an_error(tenant):
    assert tenant.declare_current_head()[0] == 200
    status, body = tenant.declare_current_head()
    assert status == 200 and body["attestation"]["sequence"] == 2 and body["count"] == 2


def test_a_declaration_of_a_shorter_head_than_one_already_signed_is_refused(tenant):
    _build_history(tenant)
    assert tenant.declare_current_head()[0] == 200
    status, body = tenant.attest(ledger_length=1, head_seq=1, head_link_hash="ab" * 32)
    assert status == 409 and body["detail"]["error"] == "attestation_refused"


def test_tenant_text_is_signed_but_flagged_as_the_tenants_own(tenant):
    h = tenant.head()["attestation"]
    status, body = tenant.attest(ledger_length=h["length"], head_seq=h["head_seq"],
                                 head_link_hash=h["head_link_hash"],
                                 note="THE KEY HOLDER CERTIFIES THIS LEDGER IS COMPLETE")
    assert status == 200 and body["note_is_tenant_supplied"] is True
    assert any("requester's free text" in s for s in body["checks_skipped"])


@pytest.mark.parametrize("body", [
    {"ledger_length": 1, "head_seq": 1, "head_link_hash": "z" * 64},
    {"ledger_length": 1, "head_seq": 1, "head_link_hash": "ab" * 31},
    {"ledger_length": -1, "head_seq": 1, "head_link_hash": "ab" * 32},
    {"ledger_length": 1, "head_seq": -5, "head_link_hash": "ab" * 32},
    {"ledger_length": "many", "head_seq": 1, "head_link_hash": "ab" * 32},
    {"ledger_length": 1, "head_seq": 1, "head_link_hash": "ab" * 32, "rotating": True},
    {"ledger_length": 1, "head_seq": 1, "head_link_hash": "ab" * 32, "note": "x" * 501},
    {"ledger_length": 10**15, "head_seq": 1, "head_link_hash": "ab" * 32},
    {"ledger_length": 1, "head_seq": 1},
    {},
], ids=lambda b: json.dumps(b)[:60])
def test_a_malformed_declaration_is_422_and_signs_nothing(tenant, body):
    status, resp = tenant.attest(**body)
    assert status == 422, (status, resp)
    assert tenant.get("/v1/ledger/attest/log")[1]["count"] == 0


def test_a_tenant_cannot_acknowledge_a_key_rotation(tenant):
    status, _ = tenant.attest(ledger_length=1, head_seq=1, head_link_hash="ab" * 32,
                              rotating=True)
    assert status == 422


# ---------------------------------------------------------- refused input never writes
def _bodies():
    deep = "[" * 600 + "]" * 600
    return {
        "not_json": b"{{{{ not json",
        "empty_body": b"",
        "json_array": b"[1,2,3]",
        "json_null": b"null",
        "deep_nesting": deep.encode(),
        "deep_object": (b'{"a":' * 600) + b"1" + (b"}" * 600),
        "huge_whitespace": b" " * (6 * 1024 * 1024) + b"{}",
        "wrong_types": json.dumps({**SIGNAL, "received_at": 12345}).encode(),
        "description_list": json.dumps({**SIGNAL, "description": ["a"]}).encode(),
        "naive_timestamp": json.dumps({**SIGNAL, "received_at": "2026-10-01T08:00:00"}).encode(),
        "empty_description": json.dumps({**SIGNAL, "description": ""}).encode(),
        "huge_description": json.dumps({**SIGNAL, "description": "x" * 5000}).encode(),
        "extra_field": json.dumps({**SIGNAL, "ledger_seq": 1}).encode(),
        "no_actor": json.dumps({k: v for k, v in SIGNAL.items() if k != "actor"}).encode(),
        "empty_actor": json.dumps({**SIGNAL, "actor": {"identifier": ""}}).encode(),
        "nul_bytes": json.dumps({**SIGNAL, "description": "a\u0000b"}).encode(),
        "year_9999_offset": json.dumps({**SIGNAL,
                                        "received_at": "9999-12-31T23:59:59-23:59"}).encode(),
        "year_0001_offset": json.dumps({**SIGNAL,
                                        "received_at": "0001-01-01T00:00:00+23:59"}).encode(),
    }


DEFECT_INPUTS = {
    "wrong_types": "an integer is accepted as a timestamp (12345 became 1970-01-01T03:25:45Z "
                   "in a legal-deadline record; the unit is a guess)",
    "year_9999_offset": "a timestamp that overflows on conversion to UTC is an unhandled 500",
    "year_0001_offset": "a timestamp that underflows on conversion to UTC is an unhandled 500",
}


def _matrix_params():
    for name in sorted(_bodies()):
        if name in DEFECT_INPUTS:
            yield pytest.param(name, marks=pytest.mark.xfail(
                strict=True, reason=f"PRODUCT DEFECT: {DEFECT_INPUTS[name]}. Remove when fixed."))
        else:
            yield pytest.param(name)


@pytest.mark.parametrize("name", list(_matrix_params()))
def test_refused_input_is_4xx_writes_nothing_and_the_server_stays_healthy(api, tenant, name):
    raw = _bodies()[name]
    before = tenant.length()
    status, body = call(api.base, "POST", "/v1/cases/BAD/signal", key=tenant.key, raw=raw)
    if name == "nul_bytes":
        # acceptable either way, but if it was accepted it must have been written exactly once
        assert status in (201, 400, 422), (status, body)
        assert tenant.length() == before + (1 if status == 201 else 0)
    else:
        assert status in (0, 400, 413, 422), (name, status, body)
        assert tenant.length() == before, "a refused request must not append a record"
    assert call(api.base, "GET", "/healthz")[0] == 200
    assert tenant.head()["verified"] is True


def test_a_replayed_write_is_refused_and_does_not_grow_the_ledger(tenant):
    before = tenant.length()
    status, body = tenant.post("SEED", "signal", SIGNAL)
    assert status == 409 and body["detail"]["error"] == "case_state"
    assert tenant.length() == before


def test_a_second_awareness_for_a_case_is_refused_and_cannot_move_the_deadlines(tenant):
    assert tenant.post("D1", "signal", SIGNAL)[0] == 201
    assert tenant.post("D1", "awareness", AWARE)[0] == 201
    first = tenant.get("/v1/cases/D1")[1]["deadlines"]
    later = {**AWARE, "established_at": "2026-10-09T09:00:00Z",
             "assessment_completed_at": "2026-10-09T09:00:00Z"}
    status, _ = tenant.post("D1", "awareness", later)
    assert status in (409, 422)
    assert tenant.get("/v1/cases/D1")[1]["deadlines"] == first


def test_concurrent_awareness_writers_over_http_produce_one_record_and_an_intact_chain(tenant):
    assert tenant.post("RACE", "signal", SIGNAL)[0] == 201
    results, barrier = [], threading.Barrier(8)

    def go(i):
        body = {**AWARE, "established_at": f"2026-10-0{i + 1}T09:00:00Z",
                "assessment_completed_at": f"2026-10-0{i + 1}T09:00:00Z"}
        barrier.wait()
        results.append(tenant.post("RACE", "awareness", body)[0])

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(201) == 1, results
    assert all(s in (409, 422, 503) for s in results if s != 201), results
    head = tenant.head()
    assert head["verified"] is True and head["attestation"]["length"] == 3   # SEED+signal+1


def test_concurrent_writers_to_different_cases_all_land_and_the_chain_stays_one_line(tenant):
    barrier, statuses = threading.Barrier(10), []

    def go(i):
        barrier.wait()
        statuses.append(tenant.post(f"P{i}", "signal", SIGNAL)[0])

    threads = [threading.Thread(target=go, args=(i,)) for i in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert statuses.count(201) == 10, statuses
    head = tenant.head()
    assert head["verified"] is True and head["attestation"]["length"] == 11


# --------------------------------------------------------- authentication and entitlement
WRITE_PATHS = ["/v1/cases/X/signal", "/v1/cases/X/awareness", "/v1/cases/X/triage",
               "/v1/cases/X/availability", "/v1/cases/X/measure", "/v1/cases/X/filings",
               "/v1/cases/X/user-notification", "/v1/ledger/attest"]


@pytest.mark.parametrize("path", WRITE_PATHS)
def test_a_ledger_write_without_a_key_is_401_and_with_a_wrong_key_is_401(api, path):
    assert call(api.base, "POST", path, body={})[0] == 401
    assert call(api.base, "POST", path, key="nb_not_a_real_key", body={})[0] == 401


@pytest.mark.parametrize("path", ["/v1/cases", "/v1/cases/SEED", "/v1/cases/SEED/export",
                                  "/v1/ledger/verify", "/v1/ledger/attest/log"])
def test_a_ledger_read_without_a_key_is_401(api, path):
    assert call(api.base, "GET", path)[0] == 401
    assert call(api.base, "GET", path, key="nb_not_a_real_key")[0] == 401


@pytest.mark.parametrize("path", WRITE_PATHS[:3])
def test_an_unentitled_but_authenticated_account_is_402_and_nothing_is_written(api, path):
    free = Tenant(api, f"free-{os.getpid()}-{path[-6:]}", "free")
    status, body = call(api.base, "POST", path.replace("/X/", "/Z/"), key=free.key, body={})
    assert status == 402, (status, body)
    assert not list((api.state / "tenants").glob(f"*{free.email}*"))


def test_an_unentitled_account_cannot_verify_export_or_attest(api):
    free = Tenant(api, f"free2-{os.getpid()}", "free")
    for method, path in (("GET", "/v1/ledger/verify"), ("GET", "/v1/cases"),
                         ("GET", "/v1/cases/SEED/export"), ("GET", "/v1/ledger/attest/log")):
        assert call(api.base, method, path, key=free.key)[0] == 402, path
    assert call(api.base, "POST", "/v1/ledger/attest", key=free.key,
                body={"ledger_length": 0, "head_seq": 0, "head_link_hash": "0" * 64})[0] == 402


def test_the_anonymous_attestation_verifier_and_public_key_need_no_account(api):
    status, body = call(api.base, "GET", "/v1/ledger/attest/key")
    assert status == 200 and body["algorithm"] == "Ed25519"
    assert "PRIVATE" not in json.dumps(body)
    assert any("second route" in s for s in body["checks_skipped"])


# --------------------------------------------------------------------- cross-surface
def test_the_cli_and_the_api_agree_on_what_a_tampered_ledger_is(tenant, tmp_path):
    """The same ledger file, judged by the product's CLI verifier and by the API."""
    _build_history(tenant)
    ok_cli = assurance("art14", "--ledger", str(tenant.ledger), "verify", cwd=tmp_path)
    assert ok_cli.exit == 0 and tenant.head()["verified"] is True
    _edit_payload(tenant)
    bad_cli = assurance("art14", "--ledger", str(tenant.ledger), "verify", cwd=tmp_path)
    assert bad_cli.exit == 1 and tenant.head()["verified"] is False
    api_problems = " ".join(tenant.head()["problems"])
    assert "seq 2" in api_problems and "seq 2" in (bad_cli.out + bad_cli.err)


def test_a_case_the_cli_writes_into_a_tenant_ledger_is_seen_by_the_api(tenant, tmp_path):
    run = assurance("art14", "--ledger", str(tenant.ledger), "signal", "FROM-CLI", "--by",
                    "t:analyst", "--at", "2026-10-02T08:00:00Z", "--description", "via cli",
                    "--product", "P", "--version", "1", cwd=tmp_path)
    assert run.exit == 0, run.err
    status, body = tenant.get("/v1/cases/FROM-CLI")
    assert status == 200 and body["signal"]["description"] == "via cli"
    assert tenant.head()["verified"] is True


def test_the_operator_ledger_and_tenant_ledger_files_are_separate_files(api, tenant):
    assert tenant.ledger.parent == api.state / "tenants"
    assert tenant.ledger != api.state / "register.db"
    assert subprocess.run([sys.executable, "-c", "pass"], check=False).returncode == 0
    assert PRODUCT_SRC


# --------------------------------------------- a 500 that still wrote, and what it breaks
HOSTILE_AWARENESS = {**AWARE, "established_at": "9999-12-31T23:59:59Z",
                     "assessment_completed_at": "9999-12-31T23:59:59Z"}


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: POST /v1/cases/{id}/awareness with established_at 9999-12-31T23:59:59Z "
    "answers a bare 500 but the record IS appended; the case then 500s on read and cannot be "
    "corrected (409). Remove this marker when a deadline that cannot be computed is a 4xx and "
    "writes nothing."))
def test_an_awareness_whose_deadlines_cannot_be_computed_is_refused_and_writes_nothing(tenant):
    assert tenant.post("HX", "signal", SIGNAL)[0] == 201
    before = tenant.length()
    status, body = tenant.post("HX", "awareness", HOSTILE_AWARENESS)
    assert 400 <= status < 500, (status, body)
    assert tenant.length() == before, "the request was refused but a record was appended"


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT: after the request above, GET /v1/register and /v1/register/breaches (the "
    "readiness view across EVERY case of the account) answer 500, so one bad case blinds the "
    "whole register. Remove this marker when the register survives one unreadable case."))
def test_one_unreadable_case_does_not_blind_the_whole_register(tenant):
    assert tenant.post("OK1", "signal", SIGNAL)[0] == 201
    assert tenant.post("OK1", "awareness", AWARE)[0] == 201
    assert tenant.post("HY", "signal", SIGNAL)[0] == 201
    tenant.post("HY", "awareness", HOSTILE_AWARENESS)
    for path in ("/v1/register", "/v1/register/breaches"):
        status, body = tenant.get(path)
        assert status == 200, (path, status, body)


def test_a_poisoned_case_is_at_least_visible_and_the_chain_still_verifies(tenant):
    """What is true today, stated so the damage is bounded: the ledger itself stays intact
    and other cases stay readable. The damage is to the register view, not the evidence."""
    assert tenant.post("OK2", "signal", SIGNAL)[0] == 201
    assert tenant.post("OK2", "awareness", AWARE)[0] == 201
    assert tenant.post("HZ", "signal", SIGNAL)[0] == 201
    tenant.post("HZ", "awareness", HOSTILE_AWARENESS)
    assert tenant.head()["verified"] is True
    assert tenant.get("/v1/cases/OK2")[0] == 200
    assert "HZ" in tenant.get("/v1/cases")[1]
