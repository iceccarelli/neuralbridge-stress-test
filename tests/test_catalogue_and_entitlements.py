"""The declared capability catalogue and the pricing table, checked against what is enforced.

Evidence level: the product's real CLI (subprocess), real MCP server (stdio), and real FastAPI
app on loopback with throwaway accounts on each tier. Not hosted, not production.

Independent expectations, stated here and not read from the product:

* ``GET /v1/capabilities`` is a claim about three surfaces. Every command it says exists must
  run, every route it lists must exist in the OpenAPI document and every route in the OpenAPI
  document must be listed, and its MCP tools must be exactly the tools the MCP server has;
* a capability the catalogue marks "by design: a human's decision" has no MCP tool;
* its counts agree with its own rows;
* the pricing table is the contract: for every gated route and every tier, the route is open
  exactly when the PUBLIC ``/v1/plans`` limits say that tier has the flag, 402 when
  authenticated but not entitled, 401 with no or an invalid key. "If it is not enforced in
  code it is not on the pricing page" is tested here, not assumed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from support_api import api_importable, call, live_api
from support_mcp import list_tools, mcp_importable

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
pytestmark = pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})")

#: Routes the catalogue deliberately does not list: liveness and the service root.
UNLISTED_ON_PURPOSE = {"GET /", "GET /healthz"}

#: gate flag in the catalogue -> the public limit that states it, per /v1/plans.
FLAG_TO_PUBLIC_LIMIT = {
    "register": "register_access",
    "evidence_readout": "verifiable_export",
    "signed_attestation": "signed_attestation",
    "machine_verification": "machine_verification",
    "supplier_publish": "supplier_publish",
}
#: The supplier tier is not purchasable and so not in /v1/plans; its entitlement is stated by
#: the catalogue itself (only it may publish). Cell and below must not.
SUPPLIER_ONLY = {"supplier_publish"}


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def catalogue(api):
    status, body = call(api.base, "GET", "/v1/capabilities")
    assert status == 200
    return body


@pytest.fixture(scope="module")
def plans(api):
    status, body = call(api.base, "GET", "/v1/plans")
    assert status == 200
    return {p["tier"]: p for p in body}


@pytest.fixture(scope="module")
def keys(api):
    return {t: api.make_account(f"ent-{t}@example.invalid", t)
            for t in ("free", "register", "cell", "supplier")}


# ------------------------------------------------------------------- the catalogue is honest
def test_the_catalogue_counts_agree_with_its_own_rows(catalogue):
    for surface in ("cli", "api", "mcp"):
        tally: dict[str, int] = {}
        for row in catalogue["capabilities"]:
            tally[row[surface]["status"]] = tally.get(row[surface]["status"], 0) + 1
        assert tally == catalogue["counts"][surface], surface


def test_every_capability_id_is_unique_and_each_row_names_a_reason_when_not_present(catalogue):
    ids = [r["id"] for r in catalogue["capabilities"]]
    assert len(ids) == len(set(ids))
    for row in catalogue["capabilities"]:
        for surface in ("cli", "api", "mcp"):
            cell = row[surface]
            if cell["status"] != "present":
                assert cell.get("reason"), (row["id"], surface)
            else:
                assert cell.get("names"), (row["id"], surface)


def test_every_cli_command_the_catalogue_says_exists_actually_runs(catalogue):
    names = sorted({n for r in catalogue["capabilities"] if r["cli"]["status"] == "present"
                    for n in r["cli"]["names"]})
    assert len(names) >= 80
    env = {**os.environ, "PYTHONPATH": PRODUCT_SRC, "PYTHONDONTWRITEBYTECODE": "1"}

    def help_exit(name: str):
        done = subprocess.run([sys.executable, "-m", "assurance", *name.split(), "--help"],
                              env=env, capture_output=True, text=True, check=False)
        return name, done.returncode, done.stderr[-200:]

    with ThreadPoolExecutor(8) as pool:
        failures = [r for r in pool.map(help_exit, names) if r[1] != 0]
    assert failures == []


def test_the_catalogue_and_the_openapi_document_list_the_same_routes(api, catalogue):
    status, doc = call(api.base, "GET", "/openapi.json")
    assert status == 200
    real = {f"{m.upper()} {p}" for p, item in doc["paths"].items() for m in item
            if m in {"get", "post", "put", "patch", "delete"}}
    listed = {n for r in catalogue["capabilities"] for n in r["api"].get("names", [])}
    assert real - listed - UNLISTED_ON_PURPOSE == set(), "a real route the catalogue omits"
    assert listed - real == set(), "a route the catalogue lists that does not exist"


@pytest.mark.skipif(not mcp_importable()[0], reason="BLOCKED: product MCP server not runnable")
def test_the_catalogues_mcp_tools_are_exactly_the_servers_tools(catalogue):
    declared = {n for r in catalogue["capabilities"] if r["mcp"]["status"] == "present"
                for n in r["mcp"]["names"]}
    actual = {t.name for t in list_tools()}
    assert declared == actual, (sorted(declared ^ actual))


HUMAN_STEMS = {"decision", "resume", "waive", "resolve", "file", "close", "triage",
               "awareness", "signal"}


@pytest.mark.skipif(not mcp_importable()[0], reason="BLOCKED: product MCP server not runnable")
def test_a_capability_declared_a_humans_decision_has_no_agent_tool(catalogue):
    human = [r for r in catalogue["capabilities"] if r["mcp"]["status"] == "by_design"
             and "named person" in r["mcp"].get("reason", "").lower()]
    assert human, "the catalogue should declare the human-decision capabilities"
    words = {w for t in list_tools() for w in t.name.split("_")}
    assert words & HUMAN_STEMS == set(), "an MCP tool name carries a human-decision verb"


def test_the_catalogue_says_what_present_means_and_does_not_overclaim(catalogue):
    text = " ".join(catalogue["limits"]).lower()
    assert "does not prove" in text and "planned gaps are known" in text


# ----------------------------------------------------------- the pricing table is enforced
def _gated_routes(catalogue):
    out = []
    for row in catalogue["capabilities"]:
        for route, flags in row["api"].get("gates", {}).items():
            if flags:
                out.append((route, tuple(flags)))
    return sorted(set(out))


def _concrete(path: str) -> str:
    return "/".join("harness-unknown-id" if seg.startswith("{") else seg for seg in path.split("/"))


def _expected_open(tier: str, flags: tuple[str, ...], plans) -> bool:
    for flag in flags:
        if flag in SUPPLIER_ONLY:
            if tier != "supplier":
                return False
            continue
        if tier == "supplier":
            return True            # an operator-assigned tier: only the 401/402 split is tested
        if not plans[tier]["limits"][FLAG_TO_PUBLIC_LIMIT[flag]]:
            return False
    return True


def test_there_are_gated_routes_to_test(catalogue):
    routes = _gated_routes(catalogue)
    assert len(routes) >= 40
    assert {f for _, flags in routes for f in flags} <= set(FLAG_TO_PUBLIC_LIMIT)


@pytest.mark.parametrize("tier", ["free", "register", "cell"])
def test_each_tier_can_reach_exactly_the_gated_routes_its_public_plan_says(api, catalogue, plans,
                                                                         keys, tier):
    wrong = {}
    for route, flags in _gated_routes(catalogue):
        method, path = route.split(" ", 1)
        status, _ = call(api.base, method, _concrete(path), key=keys[tier],
                         body={} if method == "POST" else None)
        open_ = status not in (401, 402)
        if open_ != _expected_open(tier, flags, plans) or status == 401:
            wrong[route] = (flags, status)
    assert wrong == {}, f"{tier}: {wrong}"


def test_the_supplier_door_is_closed_to_every_purchasable_tier_and_open_to_the_supplier(
        api, keys):
    for tier in ("free", "register", "cell"):
        status, body = call(api.base, "POST", "/v1/supplier/advisory", key=keys[tier], body={})
        assert status == 402, (tier, status, body)
    status, _ = call(api.base, "POST", "/v1/supplier/advisory", key=keys["supplier"], body={})
    assert status not in (401, 402)


def test_without_a_key_and_with_a_wrong_key_every_gated_route_is_401_never_402_or_2xx(
        api, catalogue):
    wrong = {}
    for route, _flags in _gated_routes(catalogue):
        method, path = route.split(" ", 1)
        for key in (None, "nb_not_a_real_key"):
            status, _ = call(api.base, method, _concrete(path), key=key,
                             body={} if method == "POST" else None)
            if status != 401:
                wrong[(route, key)] = status
    assert wrong == {}


def test_the_402_names_the_plan_that_would_unlock_it_and_the_next_step(api, keys):
    status, body = call(api.base, "POST", "/v1/machine/verify", key=keys["register"], body={})
    assert status == 402
    text = str(body)
    assert "cell" in text.lower() and ("/v1/plans" in text or "checkout" in text.lower())


def test_every_public_price_in_the_plan_table_is_unvalidated_and_says_it_is_not_a_sale(plans):
    """CLAUDE.md: prices are unvalidated assertions. The API may state them; it must not
    state that they are validated, discounted, or sold-out."""
    blob = str(plans).lower()
    for claim in ("customers worldwide", "trusted by", "best-selling", "limited time",
                  "sold out", "guaranteed", "certified", "compliant"):
        assert claim not in blob, claim
