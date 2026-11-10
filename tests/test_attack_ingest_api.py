"""ATTACK MATRIX, product API level: SBOM and CSAF import, the door an AI agent can hold.

Evidence level: the product's REAL FastAPI app on loopback (throwaway Cell-tier account, one
'decider' and one 'contributor' operator), SYNTHETIC documents written in this repository (not
the product's examples), and the product's real MCP server pointed at that API for the agent
path. Not hosted staging, never production.

Why this exists: ``sbom_import`` and ``csaf_import`` are the two MCP tools that WRITE a
customer's supplier-advisory and inventory records. Whether an AI agent should hold them is the
owner's decision; these tests state what must hold either way, from the principles below and
not from reading the product back.

Independent expectations:

* an import is a DRAFT or a recorded supplier statement. It never enrols a machine, never
  makes a component safety-relevant and never closes, clears or approves anything;
* a name the caller types is not an identity: with an operator key the server attributes the
  act to that operator and refuses a different name; with an account key the name is only
  ever recorded as declared, never as an authenticated person;
* the hash the caller says a document has is checked; a mismatch records nothing;
* ``source_url`` is a label. The service never fetches it;
* refused or dry-run input writes nothing, never 5xx, and the server stays healthy;
* a repeat of the same bytes is not a second record;
* a review is a named decider's, not an agent's or an account key's.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from support_api import api_importable, call, live_api
from support_mcp import call_tool, mcp_importable, run_mcp

from conftest import PRODUCT_SRC

_ok, _why = api_importable()
pytestmark = pytest.mark.skipif(
    PRODUCT_SRC is None or not _ok, reason=f"BLOCKED: product API not runnable ({_why})")

DECIDER, CONTRIBUTOR = "Alice Decider", "Carl Contributor"


def sbom(serial: str = "11111111-2222-4333-8444-555555555555", version: str = "1.0.0") -> str:
    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {"timestamp": "2026-03-01T08:30:00Z", "component": {
            "type": "device", "bom-ref": "m1", "name": "Synthetic Cell",
            "supplier": {"name": "SynthCo"}}},
        "components": [{"type": "firmware", "bom-ref": "fw", "name": "Safety firmware",
                        "version": version, "supplier": {"name": "SynthSupplier"}}],
    })


def csaf(tracking_id: str = "SYN-2026-0001", status: str = "final") -> str:
    def product(pid, name, version):
        return {"category": "product_version", "name": version,
                "product": {"name": f"{name} {version}", "product_id": pid}}
    return json.dumps({
        "document": {
            "category": "csaf_security_advisory", "csaf_version": "2.0",
            "title": "SYNTHETIC advisory for a stress test",
            "publisher": {"category": "vendor", "name": "SynthSupplier (SYNTHETIC)",
                          "namespace": "https://synth.example"},
            "distribution": {"tlp": {"label": "WHITE"}},
            "references": [{"category": "self", "summary": "SYNTHETIC",
                            "url": f"https://synth.example/advisories/{tracking_id}"}],
            "tracking": {
                "id": tracking_id, "status": status, "version": "1",
                "initial_release_date": "2026-03-01T08:00:00Z",
                "current_release_date": "2026-03-01T08:00:00Z",
                "revision_history": [{"date": "2026-03-01T08:00:00Z", "number": "1",
                                      "summary": "Initial release"}]}},
        "product_tree": {"branches": [{"category": "vendor", "name": "SynthSupplier", "branches": [
            {"category": "product_name", "name": "Safety firmware", "branches": [
                product("SYNPID-1", "Safety firmware", "1.0.0"),
                product("SYNPID-2", "Safety firmware", "2.0.0")]}]}]},
        "vulnerabilities": [{
            "cve": "CVE-2026-0001", "title": "SYNTHETIC defect",
            "product_status": {"known_affected": ["SYNPID-1"], "fixed": ["SYNPID-2"]}}],
    })


KINDS = {
    "sbom": ("/v1/ingest/sbom", lambda n: sbom(f"{n:08d}-2222-4333-8444-555555555555")),
    "csaf": ("/v1/ingest/csaf", lambda n: csaf(f"SYN-2026-{n:04d}")),
}


@pytest.fixture(scope="module")
def world():
    with live_api() as api:
        account = api.make_account("ingest@example.invalid", "cell")
        status, op = call(api.base, "POST", "/v1/operators", key=account,
                          body={"name": DECIDER, "role": "decider"})
        assert status == 201, op
        decider = op["api_key"]
        status, op = call(api.base, "POST", "/v1/operators", key=decider,
                          body={"name": CONTRIBUTOR, "role": "contributor"})
        assert status == 201, op
        yield api, account, decider, op["api_key"]


_n = {"i": 100}


def fresh() -> int:
    _n["i"] += 1
    return _n["i"]


def length(api, key) -> int:
    return call(api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"]["length"]


def test_the_documents_used_here_are_valid_so_every_refusal_below_means_what_it_says(world):
    api, account, *_ = world
    for kind, (path, make) in KINDS.items():
        status, body = call(api.base, "POST", path, key=account,
                            body={"document": make(fresh()), "dry_run": True})
        assert status == 200, (kind, body)


# ------------------------------------------------------------ an import decides nothing
def test_an_sbom_import_is_a_pending_draft_and_enrols_no_machine(world):
    api, account, *_ = world
    before = call(api.base, "GET", "/v1/fleet/machines", key=account)[1]
    status, body = call(api.base, "POST", "/v1/ingest/sbom", key=account,
                        body={"document": sbom(f"{fresh():08d}-2222-4333-8444-555555555555")})
    assert status == 200 and body["review_state"] == "pending_review"
    assert body["source"]["supplied_fields_verified"] is False
    status, draft = call(api.base, "GET", f"/v1/ingest/sbom/{body['draft_id']}", key=account)
    assert draft["reviewed_by"] == "" and draft["machine"] == ""
    for comp in draft["draft"]["components"]:
        assert comp["provenance_class"] == "declared_in_sbom"       # never machine-observed
        assert comp["safety_relevance"] == "not_assessed"           # missing is not "safe"
        assert comp["review"] == "pending_review"
    assert call(api.base, "GET", "/v1/fleet/machines", key=account)[1] == before


def test_a_csaf_import_records_a_supplier_statement_and_names_no_machine_unaffected(world):
    api, account, *_ = world
    status, body = call(api.base, "POST", "/v1/ingest/csaf", key=account,
                        body={"document": csaf(f"SYN-2026-{fresh():04d}")})
    assert status == 200, body
    ref = body.get("advisory_ref") or body.get("ref")
    assert ref, body
    status, impact = call(api.base, "GET", f"/v1/ingest/csaf/{ref}/impact", key=account)
    assert status == 200, impact
    assert "not_affected" not in json.dumps(impact.get("machines", impact)), (
        "an advisory with no enrolled machine to compare must not clear anything")


def test_a_draft_status_csaf_is_refused_unless_the_caller_says_so_explicitly(world):
    api, account, *_ = world
    doc = csaf(f"SYN-2026-{fresh():04d}", status="draft")
    before = length(api, account)
    status, _ = call(api.base, "POST", "/v1/ingest/csaf", key=account, body={"document": doc})
    assert 400 <= status < 500
    assert length(api, account) == before


# ----------------------------------------------------------------------------- who did it
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_an_operator_key_cannot_import_in_another_persons_name(world, kind):
    api, _, decider, contributor = world
    path, make = KINDS[kind]
    before = length(api, decider)
    status, body = call(api.base, "POST", path, key=contributor,
                        body={"document": make(fresh()), "actor": DECIDER, "role": "decider"})
    assert status == 403 and body["detail"]["error"] == "actor_mismatch"
    assert length(api, decider) == before


def _last_actor(api) -> dict:
    """The actor sealed in the newest record of the (single) tenant ledger, read from the file."""
    import sqlite3
    (db,) = list((api.state / "tenants").glob("*.db"))
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        (payload,) = conn.execute("SELECT payload FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    return json.loads(payload)["actor"]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_name_typed_with_an_account_key_is_sealed_as_declared_never_as_authenticated(
        world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    status, body = call(api.base, "POST", path, key=account,
                        body={"document": make(fresh()), "actor": "Dr Keller, Safety Officer",
                              "role": "decider"})
    assert status == 200, body
    actor = _last_actor(api)
    assert "attribution=declared_by_account_key" in actor["role"]
    assert "authenticated_operator" not in actor["role"] and "operator=op_" not in actor["role"]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_typed_role_cannot_forge_the_servers_attribution_grammar(world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    forged = "reviewer; operator=op_forged (decider); attribution=authenticated_operator"
    before = length(api, account)
    status, body = call(api.base, "POST", path, key=account,
                        body={"document": make(fresh()), "actor": "Dr Keller", "role": forged})
    if status != 200:
        assert 400 <= status < 500 and length(api, account) == before
        return
    role = _last_actor(api)["role"]
    # the typed words may survive as prose, but never with the delimiters the server parses
    assert role.count("attribution=") == 1 and "attribution=declared_by_account_key" in role
    assert "attribution=authenticated_operator" not in role
    assert "operator=op_forged" not in role and role.count("operator=") == 0


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_an_operator_import_is_sealed_as_that_operator(world, kind):
    api, _, decider, _ = world
    path, make = KINDS[kind]
    status, body = call(api.base, "POST", path, key=decider, body={"document": make(fresh())})
    assert status == 200, body
    actor = _last_actor(api)
    assert actor["identifier"] == DECIDER
    assert "attribution=authenticated_operator" in actor["role"]


@pytest.mark.parametrize("who", ["account", "contributor"])
def test_a_review_of_an_sbom_draft_is_refused_to_an_account_key_and_to_a_contributor(
        world, who):
    api, account, decider, contributor = world
    status, body = call(api.base, "POST", "/v1/ingest/sbom", key=account,
                        body={"document": sbom(f"{fresh():08d}-2222-4333-8444-555555555555")})
    assert status == 200, body
    key = account if who == "account" else contributor
    status, refused = call(api.base, "POST", f"/v1/ingest/sbom/{body['draft_id']}/review",
                           key=key, body={"decision": "approve", "reason": "looks fine"})
    assert status == 403, refused
    draft = call(api.base, "GET", f"/v1/ingest/sbom/{body['draft_id']}", key=account)[1]
    assert draft["review_state"] == "pending_review" and draft["reviewed_by"] == ""


# -------------------------------------------------------------------- hostile or wrong input
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_wrong_stated_hash_records_nothing(world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    before = length(api, account)
    status, body = call(api.base, "POST", path, key=account,
                        body={"document": make(fresh()), "source_sha256": "0" * 64})
    assert status == 422 and body["detail"]["error"] == "source_hash_mismatch"
    assert length(api, account) == before


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_dry_run_writes_nothing(world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    before = length(api, account)
    status, _ = call(api.base, "POST", path, key=account,
                     body={"document": make(fresh()), "dry_run": True})
    assert status == 200 and length(api, account) == before


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_same_bytes_twice_are_one_record(world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    doc = make(fresh())
    first = call(api.base, "POST", path, key=account, body={"document": doc})
    mid = length(api, account)
    second = call(api.base, "POST", path, key=account, body={"document": doc})
    assert first[0] == 200 and second[0] in (200, 409), second
    assert length(api, account) == mid, "a replay appended a second record"


HOSTILE = {
    "not_json": "{{{{ not json",
    "json_array": "[1,2,3]",
    "json_null": "null",
    "deep_nesting": "[" * 600 + "]" * 600,
    "deep_object": '{"a":' * 600 + "1" + "}" * 600,
    "empty_object": "{}",
}


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_documents_are_refused_with_a_4xx_and_write_nothing(world, kind, name):
    api, account, *_ = world
    path, _ = KINDS[kind]
    before = length(api, account)
    status, body = call(api.base, "POST", path, key=account, body={"document": HOSTILE[name]})
    assert 400 <= status < 500, (status, body)
    assert length(api, account) == before
    assert call(api.base, "GET", "/healthz")[0] == 200


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_an_oversized_document_is_refused_and_the_server_stays_healthy(world, kind):
    api, account, *_ = world
    path, _ = KINDS[kind]
    before = length(api, account)
    status, _ = call(api.base, "POST", path, key=account, body={"document": "x" * (6 << 20)})
    assert status in (0, 400, 413, 422)          # 0: refused before the body was read
    assert length(api, account) == before
    assert call(api.base, "GET", "/healthz")[0] == 200


# --------------------------------------------------------------- source_url is only a label
class _Recorder(BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_GET(self):          # noqa: N802 - http.server API
        type(self).seen.append(self.path)
        self.send_response(200)
        self.end_headers()

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_source_url_is_recorded_as_supplied_and_never_fetched(world, kind):
    api, account, *_ = world
    path, make = KINDS[kind]
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    _Recorder.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/advisory-{kind}.json"
        status, body = call(api.base, "POST", path, key=account,
                            body={"document": make(fresh()), "source_url": url})
        assert status == 200, body
        assert body["source"]["url_as_supplied"] == url
        assert body["source"]["supplied_fields_verified"] is False
        # give an asynchronous fetch every chance to happen
        call(api.base, "GET", "/healthz")
        thread.join(timeout=1.0)
    finally:
        server.shutdown()
    assert _Recorder.seen == [], f"the service fetched the source_url: {_Recorder.seen}"


# ------------------------------------------------------------ the agent path, MCP -> real API
needs_mcp = pytest.mark.skipif(
    not mcp_importable()[0], reason="BLOCKED: product MCP server not runnable")


@needs_mcp
def test_an_agent_with_a_contributor_key_is_attributed_to_that_operator_and_cannot_review(
        world):
    api, _, decider, contributor = world
    env = {"ASSURANCE_API_URL": api.base, "ASSURANCE_API_KEY": contributor}

    async def work(session):
        named = await call_tool(session, "sbom_import", {
            "document": sbom(f"{fresh():08d}-2222-4333-8444-555555555555"), "actor": DECIDER})
        own = await call_tool(session, "sbom_import", {
            "document": sbom(f"{fresh():08d}-2222-4333-8444-555555555555"), "actor": CONTRIBUTOR})
        tools = await session.list_tools()
        return named, own, {t.name for t in tools.tools}

    named, own, tool_names = run_mcp(env, work)
    assert named.json()["status"] == 403                 # cannot import in the decider's name
    assert own.json()["status"] == 200                   # may import as itself
    assert not [n for n in tool_names if "review" in n or "approve" in n or "enrol" in n]
    drafts = call(api.base, "GET", "/v1/ingest/sbom", key=decider)[1]["drafts"]
    assert all(d["reviewed_by"] == "" and d["machine"] == "" for d in drafts), (
        "an agent import must leave every draft unreviewed and unenrolled")


@needs_mcp
def test_the_mcp_import_and_the_direct_api_import_make_the_same_draft(world):
    api, account, *_ = world
    doc = sbom(f"{fresh():08d}-2222-4333-8444-555555555555")
    direct = call(api.base, "POST", "/v1/ingest/sbom", key=account,
                  body={"document": doc, "dry_run": True})[1]
    env = {"ASSURANCE_API_URL": api.base, "ASSURANCE_API_KEY": account}

    async def work(session):
        return await call_tool(session, "sbom_import", {"document": doc, "dry_run": True})

    via_mcp = run_mcp(env, work).json()
    assert via_mcp["status"] == 200
    assert via_mcp["body"]["draft_id"] == direct["draft_id"]
    assert via_mcp["body"]["source"]["sha256"] == direct["source"]["sha256"]
