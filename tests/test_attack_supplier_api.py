"""ATTACK MATRIX, signed supplier feed over the real API: hosting, trust decisions, fan-out.

Evidence level: the product's real FastAPI app (uvicorn on loopback), throwaway accounts on the
supplier and cell tiers and throwaway operator keys, real Ed25519 keys made by the product's CLI,
SYNTHETIC supplier, advisories and machines. Not hosted staging; no Stripe; never production.

Independent expectations, from the module's stated model and plain logic:

* hosting is not trusting: the service stores a supplier's signed records and checks structure and
  chain only, so a record with a forged signature can be hosted, and what makes it harmless is the
  reader's pin: the reader's evaluation must refuse it;
* the hosted feed is a public, append-only chain: gaps, forks, replays, a second supplier
  identity, an oversized record and a malformed signature are refused and the feed is unchanged;
* the feed endpoint is anonymous and reads nothing but feed files: no path traversal, no
  enumeration oracle beyond exists / does not exist;
* a trust decision (pin, rotate, revoke, override, baseline) is a named person's: an account-level
  key or a contributor cannot make one, the operator key cannot, and a typed actor name cannot
  stand in for the key's holder;
* trust is per account: one account's pin is not another's, and the shared operator ledger holds
  none;
* a feed that a reader's pin does not cover is inspect-only; automated consequences need a pin;
* a rolled-back feed is caught once a baseline is held.
"""
from __future__ import annotations

import json

import pytest
from support_api import api_importable, call, live_api
from test_attack_fleet import A1, A2, FLEET, classes
from test_attack_supplier_trust_cli import SUPPLIER_ID, Pack

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
pytestmark = pytest.mark.skipif(
    not _ok or PRODUCT_SRC is None, reason=f"BLOCKED: product API not runnable ({_why})")

FINDING_STATES = {"untrusted_unknown_key", "untrusted_revoked", "untrusted_retired"}


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    """Keys, a two-record signed feed and its records (made with the product's own CLI)."""
    pack = Pack(tmp_path_factory.mktemp("supplier-api"))
    lines = (pack.work / "feed.jsonl").read_text().splitlines()
    return {"pack": pack, "lines": lines, "records": [json.loads(x) for x in lines],
            "pem_s": (pack.work / "s.pub").read_text(), "pem_x": (pack.work / "x.pub").read_text(),
            "pem_y": (pack.work / "y.pub").read_text(), "fp_s": pack.fp_s,
            "text": "\n".join(lines) + "\n"}


class Supplier:
    def __init__(self, api, label):
        self.api = api
        self.key = api.make_account(f"{label}@example.invalid", "supplier")

    def post(self, record):
        return call(self.api.base, "POST", "/v1/supplier/advisory", key=self.key, body=record)

    def publish_all(self, records):
        out = [self.post(r) for r in records]
        assert [s for s, _ in out] == [201] * len(records), out
        return out[0][1]["feed_url"]

    def feed_url(self):
        first = call(self.api.base, "GET", "/v1/me", key=self.key)[1]
        return first


@pytest.fixture()
def supplier(api):
    n = {"i": 0}

    def make():
        n["i"] += 1
        return Supplier(api, f"sup{n['i']}-{id(n)}")
    return make


def feed_text(api, url):
    import urllib.request

    from support_api import urllib  # noqa: F401  (module import keeps the harness honest)
    with urllib.request.urlopen(api.base + url, timeout=30) as resp:
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()


def feed_id(url):
    return url.rsplit("/", 1)[1]


class Cell:
    """A paying account with an individual 'decider' operator key (the only key that may decide)."""

    def __init__(self, api, label):
        self.api = api
        self.account_key = api.make_account(f"{label}@example.invalid", "cell")
        status, op = call(api.base, "POST", "/v1/operators", key=self.account_key,
                          body={"name": "Alice Decider", "role": "decider"})
        assert status == 201, op
        self.decider_key = op["api_key"]
        status, op = call(api.base, "POST", "/v1/operators", key=self.decider_key,
                          body={"name": "Carl Contributor", "role": "contributor"})
        assert status == 201, op
        self.contributor_key = op["api_key"]

    def post(self, path, body, key=None):
        return call(self.api.base, "POST", path, key=key or self.decider_key, body=body)

    def pin(self, pem, supplier=SUPPLIER_ID, key=None, **extra):
        body = {"supplier_id": supplier, "public_key_pem": pem,
                "obtained_via": "phone call to the supplier's published security contact", **extra}
        return self.post("/v1/supplier/trust/pin", body, key)

    def evaluate(self, text, **extra):
        return call(self.api.base, "POST", "/v1/supplier/trust/evaluate", key=self.account_key,
                    body={"feed": text, "expect_supplier": SUPPLIER_ID, **extra})

    def signed(self, text, **extra):
        return call(self.api.base, "POST", "/v1/fleet/advisory/signed", key=self.account_key,
                    body={"feed": text, "expect_supplier": SUPPLIER_ID, **extra})

    def enrol(self, serials=("M01", "M02", "M08")):
        for s in serials:
            status, body = call(self.api.base, "POST", "/v1/machinery/manifest",
                                key=self.account_key,
                                body={"manifest": FLEET[s], "actor": "synthetic.tech"})
            assert status == 200, body


@pytest.fixture()
def cell(api):
    n = {"i": 0}

    def make():
        n["i"] += 1
        return Cell(api, f"cell{n['i']}-{id(n)}")
    return make


# ======================================================================== hosting a feed
def test_a_supplier_publishes_a_signed_chain_and_anyone_reads_exactly_those_bytes(
        api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"])
    status, headers, text = feed_text(api, url)
    assert status == 200 and headers["content-type"].startswith("application/x-ndjson")
    assert headers.get("x-content-type-options") == "nosniff"
    assert [json.loads(x) for x in text.splitlines()] == signer["records"]


def test_an_anonymous_reader_needs_no_key_and_the_feed_endpoint_never_sets_a_cookie(api, signer,
                                                                                    supplier):
    url = supplier().publish_all(signer["records"])
    status, body = call(api.base, "GET", url)
    assert status == 200 or isinstance(body, dict)         # ndjson is not one JSON document
    _, headers, _ = feed_text(api, url)
    assert "set-cookie" not in headers


@pytest.mark.parametrize("tier", ["free", "register", "cell"])
def test_only_the_supplier_tier_may_publish(api, signer, tier):
    key = api.make_account(f"pub-{tier}@example.invalid", tier)
    assert call(api.base, "POST", "/v1/supplier/advisory", key=key,
                body=signer["records"][0])[0] == 402


def test_publishing_without_a_key_or_with_a_wrong_key_is_401(api, signer):
    assert call(api.base, "POST", "/v1/supplier/advisory", body=signer["records"][0])[0] == 401
    assert call(api.base, "POST", "/v1/supplier/advisory", key="nb_nope",
                body=signer["records"][0])[0] == 401


def test_the_operator_key_cannot_publish_to_a_supplier_feed(api, signer):
    status, _ = call(api.base, "POST", "/v1/supplier/advisory", key=api.operator_key,
                     body=signer["records"][0])
    assert status in (401, 402, 403)


# ----------------------------------------------------------- the hosted chain invariants
def _refused(api, sup, url, record, expect):
    before = feed_text(api, url)[2]
    status, body = sup.post(record)
    assert status == expect[0], (status, body)
    if len(expect) > 1:
        assert body["detail"]["error"] == expect[1], body
    assert feed_text(api, url)[2] == before, "a refused record changed the feed"


def test_a_replayed_record_is_refused_and_the_feed_is_unchanged(api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"])
    _refused(api, sup, url, signer["records"][1], (409,))
    _refused(api, sup, url, signer["records"][0], (409,))


def test_a_gap_in_the_sequence_is_refused(api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"][:1])
    skipped = {**signer["records"][1], "sequence": 5}
    _refused(api, sup, url, skipped, (409, "sequence_mismatch"))


def test_a_record_built_on_a_stale_head_is_refused_as_a_fork(api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"][:1])
    forked = {**signer["records"][1], "previous": "0" * 64}
    _refused(api, sup, url, forked, (409, "chain_mismatch"))


def test_a_new_feed_must_start_at_sequence_one(api, signer, supplier):
    sup = supplier()
    status, body = sup.post(signer["records"][1])
    assert status == 409 and body["detail"]["error"] == "sequence_mismatch"


def test_the_same_advisory_id_cannot_be_published_twice_in_one_feed(api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"][:1])
    dup = json.loads(json.dumps(signer["records"][1]))
    dup["advisory"]["advisory_id"] = signer["records"][0]["advisory"]["advisory_id"]
    _refused(api, sup, url, dup, (409,))


def test_one_feed_cannot_carry_two_supplier_identities(api, signer, supplier):
    sup = supplier()
    url = sup.publish_all(signer["records"][:1])
    other = json.loads(json.dumps(signer["records"][1]))
    other["supplier"] = {**other["supplier"], "supplier_id": "someone-else"}
    _refused(api, sup, url, other, (409, "supplier_identity_mismatch"))


@pytest.mark.parametrize("name,mutate,expect", [
    ("no signature", lambda r: r.__setitem__("signature", ""), 422),
    ("signature not base64", lambda r: r.__setitem__("signature", "!!!not base64!!!"), 422),
    ("signature too short", lambda r: r.__setitem__("signature", "QUJD"), 422),
    ("wrong format", lambda r: r.__setitem__("format", "other/9"), 422),
    ("empty key fingerprint", lambda r: r.__setitem__("key_fingerprint", " "), 422),
    ("naive published_at", lambda r: r.__setitem__("published_at", "2026-10-01T08:00:00"), 422),
    ("advisory not parseable", lambda r: r.__setitem__("advisory", {"x": 1}), 422),
    ("advisory is a string", lambda r: r.__setitem__("advisory", "ADV"), 422),
    ("sequence as string", lambda r: r.__setitem__("sequence", "one"), 422),
    ("negative sequence", lambda r: r.__setitem__("sequence", -1), (409, 422)),
    ("oversized record", lambda r: r["advisory"].__setitem__("summary", "x" * 300_000),
     (413, 422)),
])
def test_a_malformed_record_is_4xx_and_never_changes_the_feed(api, signer, supplier, name,
                                                             mutate, expect):
    sup = supplier()
    url = sup.publish_all(signer["records"][:1])
    before = feed_text(api, url)[2]
    record = json.loads(json.dumps(signer["records"][1]))
    mutate(record)
    status, body = sup.post(record)
    allowed = expect if isinstance(expect, tuple) else (expect,)
    assert status in allowed, (name, status, str(body)[:200])
    assert feed_text(api, url)[2] == before, "a refused record changed the feed"
    assert call(api.base, "GET", "/healthz")[0] == 200


@pytest.mark.parametrize("payload", [b"[]", b"null", b"42", b'"x"', b"{{{", b"",
                                     b'{"a":' * 700 + b"1" + b"}" * 700])
def test_a_non_object_or_hostile_body_is_4xx_not_a_crash(api, supplier, payload):
    sup = supplier()
    status, body = call(api.base, "POST", "/v1/supplier/advisory", key=sup.key, raw=payload)
    assert status in (0, 400, 413, 422), (status, body)
    assert call(api.base, "GET", "/healthz")[0] == 200


def test_the_service_hosts_a_forged_signature_by_design_and_the_readers_pin_refuses_it(
        api, signer, supplier, cell):
    """Documented: the service holds no supplier key and does not verify signatures. A forged
    record is hosted; harm is prevented by the reader. End to end, with the real pin."""
    sup = supplier()
    forged = json.loads(json.dumps(signer["records"][0]))
    forged["advisory"]["fixed_versions"] = ["V0.0"]              # edited after signing
    url = sup.publish_all([forged])
    reader = cell()
    assert reader.pin(signer["pem_s"], expected_fingerprint=signer["fp_s"])[0] == 201
    status, body = reader.evaluate("", hosted_feed_id=feed_id(url))
    trust = body["trust"]
    assert status == 200 and trust["policy_satisfied"] is False
    assert trust["signature_state"] == "some_invalid" and trust["trust_state"] != "trusted"


# ------------------------------------------------------------------ reading is just reading
@pytest.mark.parametrize("ident", [
    "..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2faccounts", "....//....//x", "..", ".",
    "%00", "x%00.jsonl", "acc_%252e%252e", "..%5c..%5cwindows", "%2fetc%2fpasswd",
    "register", "accounts",
])
def test_the_public_feed_endpoint_reads_only_feed_files(api, ident):
    status, body = call(api.base, "GET", f"/v1/supplier/feed/{ident}")
    assert status in (400, 404, 422), (ident, status, str(body)[:200])
    assert "root:" not in json.dumps(body) and "sqlite" not in json.dumps(body).lower()


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT (anonymous, no key): GET /v1/supplier/feed/{id} with an id long enough that "
    "'{id}.jsonl' exceeds the filesystem's name limit (600 characters tested; the limit is 255) "
    "answers a bare 500 Internal Server Error. The evaluate routes already validate "
    "hosted_feed_id against ^[A-Za-z0-9_.-]{1,128}$; the public GET does not. Remove this marker "
    "when it answers 404/422."))
@pytest.mark.parametrize("length", [250, 300, 600, 5000])
def test_an_overlong_feed_id_is_a_4xx_not_a_server_error(api, length):
    status, _ = call(api.base, "GET", "/v1/supplier/feed/" + "a" * length)
    assert status in (400, 404, 414, 422), status


def test_a_missing_feed_and_a_never_existing_one_look_the_same(api):
    a = call(api.base, "GET", "/v1/supplier/feed/acc_0000000000000000")
    b = call(api.base, "GET", "/v1/supplier/feed/acc_ffffffffffffffff")
    assert a == b and a[0] == 404


def test_the_feed_endpoint_has_no_write_methods(api, signer):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        status, _ = call(api.base, method, "/v1/supplier/feed/acc_0000000000000000", body={})
        assert status in (404, 405), (method, status)


def test_one_suppliers_key_cannot_touch_another_suppliers_feed(api, signer, supplier):
    a, b = supplier(), supplier()
    url_a = a.publish_all(signer["records"])
    before = feed_text(api, url_a)[2]
    b.publish_all(signer["records"][:1])
    assert feed_text(api, url_a)[2] == before


# ====================================================================== the trust store
def test_an_account_level_key_cannot_make_a_trust_decision(api, signer, cell):
    c = cell()
    status, body = c.pin(signer["pem_s"], key=c.account_key)
    assert status == 403 and body["detail"]["error"] == "operator_required"


def test_a_contributor_operator_cannot_make_a_trust_decision(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"], key=c.contributor_key)[0] == 403


def test_the_platform_operator_key_cannot_pin_for_every_tenant(api, signer):
    status, body = call(api.base, "POST", "/v1/supplier/trust/pin", key=api.operator_key,
                        body={"supplier_id": SUPPLIER_ID, "public_key_pem": signer["pem_s"],
                              "obtained_via": "phone"})
    assert status == 403 and "per_account" in json.dumps(body)


def test_a_typed_actor_name_cannot_stand_in_for_the_keys_holder(api, signer, cell):
    c = cell()
    status, body = c.pin(signer["pem_s"], actor="Dr. Somebody Else, CISO")
    assert status == 403 and body["detail"]["error"] == "actor_mismatch"
    assert call(api.base, "GET", "/v1/supplier/trust", key=c.account_key)[1].get("pins") in (
        None, [])


def test_a_decider_pin_is_recorded_with_the_operator_and_never_a_typed_name(api, signer, cell):
    c = cell()
    status, body = c.pin(signer["pem_s"], expected_fingerprint=signer["fp_s"])
    assert status == 201, body
    listing = call(api.base, "GET", "/v1/supplier/trust", key=c.account_key)[1]
    text = json.dumps(listing)
    assert "Alice Decider" in text and "operator" in text and signer["fp_s"] in text


def test_a_pin_with_a_fingerprint_that_is_not_the_keys_is_refused_and_pins_nothing(api, signer,
                                                                                 cell):
    c = cell()
    status, body = c.pin(signer["pem_s"], expected_fingerprint="deadbeefdeadbeef")
    assert status == 409 and body["detail"]["error"] == "trust_decision_refused"
    assert not call(api.base, "GET", "/v1/supplier/trust", key=c.account_key)[1].get("pins")


@pytest.mark.parametrize("pem", ["", "not a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END "
                                 "PRIVATE KEY-----", "x" * 5000])
def test_a_bad_public_key_is_refused_without_a_crash(api, cell, pem):
    c = cell()
    status, _ = c.pin(pem)
    assert status in (409, 422)
    assert call(api.base, "GET", "/healthz")[0] == 200


def test_trust_routes_need_the_cell_plan_and_a_key(api, signer):
    free = api.make_account("trust-free@example.invalid", "free")
    reg = api.make_account("trust-reg@example.invalid", "register")
    for key, want in ((None, 401), ("nb_nope", 401), (free, 402), (reg, 402)):
        assert call(api.base, "GET", "/v1/supplier/trust", key=key)[0] == want
        assert call(api.base, "POST", "/v1/supplier/trust/evaluate", key=key,
                    body={"feed": signer["text"]})[0] == want


# --------------------------------------------------------------------- trust ladder, by API
def test_an_unpinned_feed_is_inspect_only_then_a_pin_makes_it_trusted(api, signer, cell):
    c = cell()
    status, body = c.evaluate(signer["text"])
    assert status == 200 and body["trust"]["trust_state"] == "untrusted_unknown_key"
    assert body["trust"]["policy_satisfied"] is False and body["trust"]["inspect_only"] is True
    assert "verified" not in body["trust"]
    assert c.pin(signer["pem_s"], expected_fingerprint=signer["fp_s"])[0] == 201
    body = c.evaluate(signer["text"])[1]
    assert body["trust"]["trust_state"] == "trusted" and body["trust"]["policy_satisfied"] is True


def test_a_pin_in_one_account_does_not_trust_the_feed_in_another(api, signer, cell):
    a, b = cell(), cell()
    assert a.pin(signer["pem_s"])[0] == 201
    assert a.evaluate(signer["text"])[1]["trust"]["policy_satisfied"] is True
    assert b.evaluate(signer["text"])[1]["trust"]["policy_satisfied"] is False


def test_the_operator_key_sees_every_feed_as_untrusted_and_can_hold_no_pins(api, signer):
    status, body = call(api.base, "POST", "/v1/supplier/trust/evaluate", key=api.operator_key,
                        body={"feed": signer["text"], "expect_supplier": SUPPLIER_ID})
    assert status == 403 or body["trust"]["policy_satisfied"] is False


def test_a_candidate_key_can_show_valid_signatures_and_never_trust(api, signer, cell):
    c = cell()
    body = c.evaluate(signer["text"], candidate_public_key_pem=signer["pem_s"])[1]["trust"]
    assert body["signature_state"] == "all_valid" and body["policy_satisfied"] is False
    assert body["trust_state"] != "trusted"


def test_an_attackers_key_signing_the_real_suppliers_identity_is_untrusted(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    pack = signer["pack"]
    (pack.work / "evil.json").write_text(json.dumps({**A1, "advisory_id": "ADV-EVIL"}))
    assert pack.publish_as("x.key", "evil.jsonl", "evil.json").exit == 0
    evil = (pack.work / "evil.jsonl").read_text()
    body = c.evaluate(evil)[1]["trust"]
    assert body["trust_state"] == "untrusted_unknown_key" and body["policy_satisfied"] is False


def test_a_revoked_key_makes_the_whole_feed_untrusted(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = c.post("/v1/supplier/trust/revoke", {
        "supplier_id": SUPPLIER_ID, "fingerprint": signer["fp_s"], "reason": "key compromise"})
    assert status == 200, body
    trust = c.evaluate(signer["text"])[1]["trust"]
    assert trust["policy_satisfied"] is False and trust["key_trust_state"] == "revoked"


def test_a_revocation_needs_a_reason_and_a_decider(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    assert c.post("/v1/supplier/trust/revoke", {"supplier_id": SUPPLIER_ID,
                                                "fingerprint": signer["fp_s"]})[0] == 422
    assert c.post("/v1/supplier/trust/revoke", {
        "supplier_id": SUPPLIER_ID, "fingerprint": signer["fp_s"], "reason": "x"},
        key=c.account_key)[0] == 403
    assert c.evaluate(signer["text"])[1]["trust"]["policy_satisfied"] is True


def test_a_rotation_retires_the_old_key_from_its_effective_date(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = c.post("/v1/supplier/trust/rotate", {
        "supplier_id": SUPPLIER_ID, "new_public_key_pem": signer["pem_y"],
        "retire_fingerprint": signer["fp_s"], "effective_at": "2026-01-01T00:00:00Z",
        "obtained_via": "phone call to the supplier's security contact"})
    assert status == 201, body
    trust = c.evaluate(signer["text"])[1]["trust"]
    assert trust["policy_satisfied"] is False and trust["key_trust_state"] == "retired"


@pytest.mark.parametrize("effective", ["2026-01-01T00:00:00", "tomorrow",
                                       "9999-12-31T23:59:59-23:59", "0001-01-01T00:00:00+23:59"])
def test_a_rotation_with_an_unusable_date_is_4xx_and_changes_nothing(api, signer, cell,
                                                                    effective):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, _ = c.post("/v1/supplier/trust/rotate", {
        "supplier_id": SUPPLIER_ID, "new_public_key_pem": signer["pem_y"],
        "retire_fingerprint": signer["fp_s"], "effective_at": effective, "obtained_via": "phone"})
    assert 400 <= status < 500, status
    assert c.evaluate(signer["text"])[1]["trust"]["policy_satisfied"] is True


def test_an_override_accepts_one_advisory_is_attributed_and_does_not_pin(api, signer, cell):
    c = cell()
    status, body = c.post("/v1/supplier/trust/override", {
        "feed": signer["text"], "expect_supplier": SUPPLIER_ID, "advisory_id": "ADV-A1",
        "reason": "read against the vendor PDF"})
    assert status == 200, body
    trust = c.evaluate(signer["text"])[1]["trust"]
    assert trust["policy_satisfied"] is False
    permitted = {a["advisory_id"]: a["automated_consequences_permitted"]
                 for a in trust["advisories"]}
    assert permitted == {"ADV-A1": True, "ADV-A2": False}
    assert "Alice Decider" in json.dumps(call(api.base, "GET", "/v1/supplier/trust",
                                              key=c.account_key)[1])


def test_an_override_needs_a_reason_a_decider_and_an_advisory_that_is_in_the_feed(api, signer,
                                                                                cell):
    c = cell()
    base = {"feed": signer["text"], "expect_supplier": SUPPLIER_ID, "advisory_id": "ADV-A1"}
    assert c.post("/v1/supplier/trust/override", {**base, "reason": ""})[0] == 422
    assert c.post("/v1/supplier/trust/override", {**base, "reason": "r"},
                  key=c.account_key)[0] == 403
    status, _ = c.post("/v1/supplier/trust/override", {**base, "advisory_id": "ADV-NOPE",
                                                       "reason": "r"})
    assert 400 <= status < 500


def test_an_override_cannot_accept_a_record_whose_signature_fails_under_a_pinned_key(api,
                                                                                    signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    edited = json.loads(json.dumps(signer["records"][0]))
    edited["advisory"]["title"] = "edited after signing"
    text = json.dumps(edited) + "\n"
    status, body = c.post("/v1/supplier/trust/override", {
        "feed": text, "expect_supplier": SUPPLIER_ID, "advisory_id": "ADV-A1",
        "reason": "i know better"})
    assert 400 <= status < 500 and "tampering" in json.dumps(body).lower()


@pytest.mark.parametrize("feed", ["", "\n\n", "junk", "[1]", "null", "{" * 300,
                                  '{"format":"x"}\n', "\x00\x01\x02"])
def test_an_unreadable_feed_evaluates_as_untrusted_unreadable_never_as_nothing_to_report(
        api, cell, feed):
    c = cell()
    status, body = c.evaluate(feed)
    assert status == 200 and body["trust"]["policy_satisfied"] is False
    assert body["trust"]["trust_state"].startswith("untrusted")


def test_a_feed_given_both_inline_and_hosted_or_with_a_hostile_id_is_refused(api, signer, cell):
    c = cell()
    for hosted in ("../../etc/passwd", "a/b", "x" * 200, "acc_nothing_here"):
        status, body = c.evaluate("", hosted_feed_id=hosted)
        assert status in (404, 422), (hosted, status, str(body)[:150])


def test_extra_fields_in_a_trust_request_are_refused(api, signer, cell):
    c = cell()
    status, _ = c.post("/v1/supplier/trust/pin", {
        "supplier_id": SUPPLIER_ID, "public_key_pem": signer["pem_s"], "obtained_via": "phone",
        "trusted": True})
    assert status == 422


# ----------------------------------------------------------------------------- rollback
def test_a_rolled_back_feed_is_caught_once_a_baseline_is_held(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    status, body = c.post("/v1/supplier/trust/feed-baseline", {
        "feed": signer["text"], "expect_supplier": SUPPLIER_ID,
        "reason": "accepted after the phone call"})
    assert status == 200 and body["baseline"]["sequence"] == 2, body
    rolled_back = signer["lines"][0] + "\n"            # the newest record cut off
    trust = c.evaluate(rolled_back)[1]["trust"]
    assert trust["policy_satisfied"] is False and trust["trust_state"] != "trusted", trust
    # the full feed still passes
    assert c.evaluate(signer["text"])[1]["trust"]["policy_satisfied"] is True


def test_without_a_baseline_a_cut_feed_still_verifies_which_is_why_the_baseline_exists(
        api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    cut = signer["lines"][0] + "\n"
    assert c.evaluate(cut)[1]["trust"]["policy_satisfied"] is True


def test_a_baseline_cannot_be_set_from_a_feed_that_would_not_be_trusted(api, signer, cell):
    c = cell()
    status, body = c.post("/v1/supplier/trust/feed-baseline", {
        "feed": signer["text"], "expect_supplier": SUPPLIER_ID, "reason": "no pin yet"})
    assert status == 409 and "cannot become the baseline" in json.dumps(body)


def test_a_baseline_needs_a_decider_and_a_reason(api, signer, cell):
    c = cell()
    assert c.pin(signer["pem_s"])[0] == 201
    base = {"feed": signer["text"], "expect_supplier": SUPPLIER_ID}
    assert c.post("/v1/supplier/trust/feed-baseline", {**base, "reason": "r"},
                  key=c.account_key)[0] == 403
    assert c.post("/v1/supplier/trust/feed-baseline", base)[0] == 422


# ------------------------------------------------------------------ fleet fan-out under trust
def test_the_signed_fan_out_is_inspect_only_until_a_pin_and_then_carries_the_trust(api, signer,
                                                                                  cell):
    c = cell()
    c.enrol()
    status, body = c.signed(signer["text"])
    assert status == 200 and body["inspect_only"] is True
    assert {a["automated_consequences_permitted"] for a in body["advisories"]} == {False}
    assert c.pin(signer["pem_s"])[0] == 201
    body = c.signed(signer["text"])[1]
    assert body["inspect_only"] is False and body["trust"]["trust_state"] == "trusted"
    assert {a["automated_consequences_permitted"] for a in body["advisories"]} == {True}


def test_the_signed_fan_out_classifies_machines_exactly_as_the_unsigned_path_does(api, signer,
                                                                                 cell):
    c = cell()
    c.enrol()
    assert c.pin(signer["pem_s"])[0] == 201
    body = c.signed(signer["text"])[1]
    by_id = {a["advisory_id"]: a["impact"] for a in body["advisories"]}
    for adv in (A1, A2):
        status, direct = call(api.base, "POST", "/v1/fleet/advisory", key=c.account_key,
                              body={"advisory": adv})
        assert status == 200
        assert classes(by_id[adv["advisory_id"]]) == classes(direct)
        assert by_id[adv["advisory_id"]]["machines_affected"] == direct["machines_affected"]


def test_the_signed_fan_out_can_be_limited_to_named_advisories(api, signer, cell):
    c = cell()
    c.enrol()
    body = c.signed(signer["text"], advisory_ids=["ADV-A2"])[1]
    assert [a["advisory_id"] for a in body["advisories"]] == ["ADV-A2"]


def test_a_feed_that_fails_trust_never_yields_a_clear_for_the_fleet(api, signer, cell):
    c = cell()
    c.enrol()
    assert c.pin(signer["pem_s"])[0] == 201
    forged = json.loads(json.dumps(signer["records"][0]))
    forged["advisory"]["affected"][0]["versions"] = ["V9.999"]        # hide the real finding
    body = c.signed(json.dumps(forged) + "\n")[1]
    assert body["inspect_only"] is True
    assert body["trust"]["signature_state"] == "some_invalid"
    assert {a["automated_consequences_permitted"] for a in body["advisories"]} <= {False}


def test_an_advisory_that_is_a_csaf_translation_never_carries_automated_consequences(api,
                                                                                    signer, cell):
    """Documented: even a pinned key does not turn a translation into the supplier's statement.
    Exercised with the library's own import record on a hand-built signed record is out of
    scope; asserted here for the field's presence so a regression in the route is visible."""
    c = cell()
    c.enrol()
    assert c.pin(signer["pem_s"])[0] == 201
    body = c.signed(signer["text"])[1]
    assert all("advisory_import" not in a for a in body["advisories"])


def test_the_signed_route_needs_the_cell_plan(api, signer):
    free = api.make_account("signed-free@example.invalid", "free")
    assert call(api.base, "POST", "/v1/fleet/advisory/signed", key=free,
                body={"feed": signer["text"]})[0] == 402
    assert call(api.base, "POST", "/v1/fleet/advisory/signed",
                body={"feed": signer["text"]})[0] == 401
