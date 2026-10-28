"""ATTACK MATRIX, product API level: authentication, authorization, tenant isolation, junk input.

Evidence level: the product's REAL API (uvicorn subprocess) on 127.0.0.1, isolated temporary
state, throwaway keys, SYNTHETIC data. Not hosted staging, not production, no Stripe.

BLOCKED (skipped with a 'BLOCKED:' reason) where fastapi/uvicorn or the product checkout is
missing; run it where scripts/bootstrap.sh has been run.

Independent expectations, derived from the product's stated rules (CLAUDE.md: 401 with no or an
invalid key, per-account ledgers, the shared ledger is operator-only; the free evidence
verifier says what can and cannot be established, never a bare 'valid'), not from copying what
the API happens to answer:

* a presented-but-invalid key is never accepted on any route (only the three static
  public routes ignore keys);
* without a key, only the documented anonymous doors answer 2xx;
* account-data routes answer exactly 401 without a key;
* no route answers 5xx on this unconfigured server except the signing-key route, which is
  honestly unavailable (503) because no signing key was configured;
* one account never sees another's machines, nor the operator's shared ledger;
* junk given to the anonymous verifier is never reported as ok, and never crashes it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from support_api import api_importable, call, live_api
from support_cli import synthetic_manifest

_OK, _WHY = api_importable()
pytestmark = pytest.mark.skipif(not _OK, reason=f"BLOCKED: product API not runnable ({_WHY})")

STATIC_PUBLIC = {"GET /", "GET /healthz", "GET /v1/plans"}
ANONYMOUS_DOORS = STATIC_PUBLIC | {"POST /v1/evidence/verify", "GET /v1/me"}
#: Routes that carry an account's data or authority. Each must be exactly 401 with no key.
ACCOUNT_DATA = {
    "GET /v1/cases", "GET /v1/change/cases", "GET /v1/fleet/machines",
    "GET /v1/fleet/observations", "GET /v1/fleet/report", "GET /v1/register",
    "GET /v1/register/breaches", "GET /v1/usage", "GET /v1/value", "GET /v1/keys",
    "POST /v1/keys", "POST /v1/keys/revoke", "GET /v1/operators", "POST /v1/operators",
    "GET /v1/ledger/verify", "GET /v1/ledger/attest/log", "POST /v1/ledger/attest",
    "POST /v1/machinery/manifest", "POST /v1/machinery/intervention",
    "POST /v1/machinery/coverage", "POST /v1/machinery/passport",
    "POST /v1/fleet/declare", "POST /v1/watch/report", "POST /v1/supplier/trust/pin",
}
HONESTLY_UNAVAILABLE = {"GET /v1/ledger/attest/key"}      # 503: no signing key configured


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def operations():
    from conftest import PRODUCT_SRC
    data = json.loads((Path(PRODUCT_SRC).parent / "public" / "openapi.json").read_text())
    return [(m.upper(), p) for p, item in sorted(data["paths"].items())
            for m in item if m in {"get", "post", "put", "patch", "delete"}]


@pytest.fixture(scope="module")
def matrix(api, operations):
    out = {}
    for method, path in operations:
        concrete = "/".join("harness-unknown-id" if s.startswith("{") else s
                            for s in path.split("/"))
        body = {} if method == "POST" else None
        out[f"{method} {path}"] = {
            "no_key": call(api.base, method, concrete, body=body)[0],
            "bad_key": call(api.base, method, concrete, key="not-a-key", body=body)[0],
            "operator": call(api.base, method, concrete, key=api.operator_key, body=body)[0],
        }
    return out


def test_every_route_was_probed_and_the_declared_lists_name_real_routes(matrix):
    assert len(matrix) >= 70
    for name in ACCOUNT_DATA | ANONYMOUS_DOORS | HONESTLY_UNAVAILABLE:
        assert name in matrix, f"{name} is not in the product's OpenAPI: update this harness"


def test_a_bad_key_is_never_accepted(matrix):
    accepted = [n for n, r in matrix.items()
                if 200 <= r["bad_key"] < 300 and n not in STATIC_PUBLIC]
    assert accepted == []


def test_without_a_key_only_the_documented_anonymous_doors_answer_2xx(matrix):
    open_routes = {n for n, r in matrix.items() if 200 <= r["no_key"] < 300}
    assert open_routes <= ANONYMOUS_DOORS, sorted(open_routes - ANONYMOUS_DOORS)


def test_account_data_routes_are_exactly_401_without_a_key(matrix):
    wrong = {n: matrix[n]["no_key"] for n in ACCOUNT_DATA if matrix[n]["no_key"] != 401}
    assert wrong == {}


def test_nothing_crashes_on_an_unconfigured_server(matrix):
    crashed = {n: s for n, r in matrix.items() for s in r.values()
               if s >= 500 and n not in HONESTLY_UNAVAILABLE}
    assert crashed == {}


def test_unknown_routes_are_404_and_wrong_methods_are_405(api):
    assert call(api.base, "GET", "/v1/definitely-not-a-route", key=api.operator_key)[0] == 404
    assert call(api.base, "DELETE", "/v1/plans")[0] in {404, 405}


def test_one_account_never_sees_another_accounts_machines_or_the_operators(api):
    key_a = api.make_account("tenant-a@example.invalid")
    key_b = api.make_account("tenant-b@example.invalid")
    manifest = synthetic_manifest("TENANT-A-7731", [("P1", "1756-EN2T", "11.001")])
    status, _ = call(api.base, "POST", "/v1/machinery/manifest", key=key_a,
                     body={"manifest": manifest, "actor": "synthetic.tech"})
    assert status == 200
    mine = json.dumps(call(api.base, "GET", "/v1/fleet/machines", key=key_a)[1])
    assert "TENANT-A-7731" in mine                       # the write really landed for A
    for who, key in (("account B", key_b), ("operator", api.operator_key)):
        status, body = call(api.base, "GET", "/v1/fleet/machines", key=key)
        assert status == 200, who
        assert "TENANT-A-7731" not in json.dumps(body), f"{who} can see account A's machine"


def test_account_b_can_enrol_the_same_serial_without_touching_account_a(api):
    key_a = api.make_account("tenant-c@example.invalid")
    key_b = api.make_account("tenant-d@example.invalid")
    for key, version in ((key_a, "11.001"), (key_b, "99.9")):
        status, _ = call(api.base, "POST", "/v1/machinery/manifest", key=key, body={
            "manifest": synthetic_manifest("SHARED-SERIAL-55", [("P1", "1756-EN2T", version)]),
            "actor": "synthetic.tech"})
        assert status == 200
    fleet_a = json.dumps(call(api.base, "GET", "/v1/fleet/machines", key=key_a)[1])
    assert "99.9" not in fleet_a


JUNK = [b"{}", b"[]", b"null", b'"x"', b"0", b'{"a": 1}', b"{not json", b"\xff\xfe\x00"]


@pytest.mark.parametrize("raw", JUNK)
def test_junk_given_to_the_anonymous_verifier_is_never_ok_and_never_a_crash(api, raw):
    status, body = call(api.base, "POST", "/v1/evidence/verify", raw=raw)
    assert status < 500
    if status == 200:
        assert body.get("ok") is False, body


def test_the_anonymous_verifier_demands_json_and_caps_the_body(api):
    assert call(api.base, "POST", "/v1/evidence/verify", raw=b"{}",
                content_type="text/plain")[0] == 415
    status, _ = call(api.base, "POST", "/v1/evidence/verify", raw=b"[" + b"0," * 3_000_000 + b"0]")
    assert status in {413, 422}


def test_an_empty_signed_feed_is_inspect_only_and_not_trusted(api):
    status, body = call(api.base, "POST", "/v1/fleet/advisory/signed", key=api.operator_key,
                        body={})
    assert status == 200
    trust = body["trust"]
    assert trust["policy_satisfied"] is False and trust["inspect_only"] is True
    assert body["advisories"] == []
