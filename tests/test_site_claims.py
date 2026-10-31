"""Public-claim acceptance: what the website SOURCE says, checked against the running product.

Evidence level: the Next.js site's checked-in source (``app/``, ``public/``, ``docs/``) read as
data from the product checkout, against the product's real FastAPI app on loopback (throwaway
accounts and state), its real CLI and its real MCP server. This is NOT the live site: the
laboratory's network policy denies ``neuralbridge.io`` (BLOCKED, recorded in
configs/scenarios.json), the site is not modified, and a source audit is not proof that what is
deployed matches the source. It is proof that what the source promises is, or is not, what the
product does. A pricing page is not evidence that a paid workflow works; a local API is not a
hosted one.

Independent expectations, stated here and not read from the product:

* every route, command and tool the site names exists, with the method the site gives it;
* every internal link and anchor resolves to a page that exists;
* the pricing copy is the plan table the API serves, verbatim, per tier;
* each number on the site (daily caps, counts, prices) is the number enforced;
* each behavioural promise in the plan copy is true when exercised: "cases are not metered",
  "if the subscription ends you keep read, verify and export", "answers 503 until a signing key
  is configured", "20 validations per day";
* the published OpenAPI document is the one the app generates, and the MCP page lists the
  tools, routes and tiers the server actually has.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from support_api import api_importable, call, live_api
from support_mcp import list_tools, mcp_importable, one_call, recording_server

from conftest import PRODUCT_SRC

ROOT = Path(PRODUCT_SRC).parent if PRODUCT_SRC else None
APP, PUBLIC, DOCS = (ROOT / "app", ROOT / "public", ROOT / "docs") if ROOT else (None,) * 3

_ok, _why = api_importable()
pytestmark = [
    pytest.mark.skipif(ROOT is None or not APP.is_dir(),
                       reason="BLOCKED: the product checkout has no site source (app/)"),
    pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})"),
]


@pytest.fixture(scope="module")
def api():
    with live_api() as running:
        yield running


@pytest.fixture(scope="module")
def openapi(api):
    status, doc = call(api.base, "GET", "/openapi.json")
    assert status == 200
    return doc


@pytest.fixture(scope="module")
def live_plans(api):
    status, body = call(api.base, "GET", "/v1/plans")
    assert status == 200
    return {p["tier"]: p for p in body}


def _site_files(*roots, suffixes=(".tsx", ".ts", ".md", ".txt")):
    for root in roots:
        if root is None:
            continue
        for path in sorted(Path(root).rglob("*")):
            if path.is_file() and path.suffix in suffixes and "node_modules" not in path.parts:
                yield path


def _norm_path(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", path.rstrip("/"))


# --------------------------------------------------------------------------- pricing copy
@pytest.fixture(scope="module")
def fallback_plans():
    if not shutil.which("node"):
        pytest.skip("BLOCKED: node is not available to read app/lib/plans.ts")
    script = ("import('" + (APP / "lib" / "plans.ts").as_posix() + "')"
              ".then(m=>console.log(JSON.stringify(m.FALLBACK_PLANS)))")
    done = subprocess.run(["node", "--experimental-strip-types", "--no-warnings", "-e", script],
                          capture_output=True, text=True, check=False, cwd=str(ROOT),
                          env={"PATH": os.environ.get("PATH", ""), "HOME": str(ROOT)})
    if done.returncode:
        pytest.skip(f"BLOCKED: node could not load plans.ts ({done.stderr[-160:]})")
    return {p["tier"]: p for p in json.loads(done.stdout)}


@pytest.mark.parametrize("tier", ["free", "register", "cell"])
def test_the_sites_fallback_plan_is_the_plan_the_api_serves_word_for_word(fallback_plans,
                                                                         live_plans, tier):
    site, live = fallback_plans[tier], live_plans[tier]
    for field in ("name", "blurb", "price", "includes", "limits"):
        assert site[field] == live[field], f"{tier}.{field} differs between the site and the API"


def test_the_site_and_the_api_list_the_same_tiers(fallback_plans, live_plans):
    assert set(fallback_plans) == set(live_plans) == {"free", "register", "cell"}


def test_no_purchasable_tier_is_offered_by_a_deployment_with_no_billing_configured(live_plans):
    assert all(p["purchasable"] is False for p in live_plans.values())


# ----------------------------------------------------------------------- routes the site names
ROUTE_RE = re.compile(
    r"(?:\b(GET|POST|PUT|PATCH|DELETE)\s+)?(/v1/[A-Za-z0-9_\-/{}.*]*[A-Za-z0-9_}*])")
#: The /ai control plane is a separate service with its own OpenAPI; its routes are not in the
#: assurance document and are not audited here.
SEPARATE_SERVICE = ("/v1/ai", "/v1/connections", "/v1/logs")
#: Prose that names a route family or an example, not a single route.
FAMILY_OK = ("/v1/change/*", "/v1/*")


def _mentions():
    found = {}
    for path in _site_files(APP, PUBLIC / "llms.txt", DOCS):
        text = (path.read_text(encoding="utf-8", errors="replace")
                .replace("&#123;", "{").replace("&#125;", "}"))
        for m in ROUTE_RE.finditer(text):
            if "${" in text[max(0, m.start() - 2): m.end() + 2]:
                continue
            found.setdefault((m.group(1) or "", m.group(2)), set()).add(
                path.relative_to(ROOT).as_posix())
    return found


def test_every_route_the_site_or_docs_name_exists_in_the_openapi_document(openapi):
    real: dict[str, set[str]] = {}
    for p, item in openapi["paths"].items():
        real.setdefault(_norm_path(p), set()).update(m.upper() for m in item)
    templates = {re.compile("^" + re.escape(t).replace(r"\{\}", "[^/]+") + "$"): t for t in real}

    def resolve(route: str):
        n = _norm_path(route)
        return next((t for rx, t in templates.items() if rx.match(n)), None)

    missing = {}
    for (method, route), where in _mentions().items():
        if route.startswith(SEPARATE_SERVICE) or "..." in route \
                or route.count("{") != route.count("}"):
            continue                        # another service, an example, or a brace list
        if route in FAMILY_OK or route.endswith("*"):
            prefix = _norm_path(route.rstrip("*").rstrip("/"))
            if not any(r == prefix or r.startswith(prefix + "/") for r in real):
                missing[(method, route)] = sorted(where)
            continue
        template = resolve(route)
        if template is None:
            if any(r.startswith(_norm_path(route) + "/") for r in real):
                continue                    # a prefix of longer routes: a navigation mention
            missing[(method, route)] = sorted(where)
        elif method and method not in real[template]:
            missing[(method, route)] = sorted(where)
    assert missing == {}, "\n".join(f"{k}: {v[:3]}" for k, v in sorted(missing.items()))


def test_the_published_openapi_json_is_the_one_the_app_generates(openapi):
    published = json.loads((PUBLIC / "openapi.json").read_text(encoding="utf-8"))

    def ops(doc):
        return {f"{m.upper()} {p}" for p, item in doc["paths"].items() for m in item
                if m in {"get", "post", "put", "patch", "delete"}}
    assert ops(published) == ops(openapi), (sorted(ops(published) ^ ops(openapi)))
    assert published.get("components", {}).get("schemas", {}).keys() == \
        openapi.get("components", {}).get("schemas", {}).keys()


# ---------------------------------------------------------------------- links and anchors
def _route_exists(url_path: str) -> bool:
    parts = [p for p in url_path.strip("/").split("/") if p]
    if not parts:
        return (APP / "page.tsx").is_file()
    here = APP
    for part in parts:
        if (here / part).is_dir():
            here = here / part
            continue
        dyn = [d for d in here.glob("[[]*[]]") if d.is_dir()]
        if not dyn:
            return False
        here = dyn[0]
        if here.name.startswith("[[..."):          # optional catch-all: any depth is routed
            return (here / "page.tsx").is_file()
    if (here / "page.tsx").is_file() or (here / "route.ts").is_file() or here == APP:
        return True
    return any((d / "page.tsx").is_file() for d in here.glob("[[][[]...*[]][]]"))


class _PublicFiles(dict):
    def __contains__(self, key):
        return (PUBLIC / str(key).lstrip("/")).is_file()

    def __getitem__(self, key):
        return PUBLIC / str(key).lstrip("/")


def _static_assets():
    return _PublicFiles()


def _all_ids() -> set[str]:
    ids: set[str] = set()
    for path in _site_files(APP, suffixes=(".tsx", ".ts")):
        text = path.read_text(encoding="utf-8", errors="replace")
        ids.update(re.findall(r"""\bid=["']([A-Za-z0-9_-]+)["']""", text))
        ids.update(re.findall(r"""\bid:\s*["']([A-Za-z0-9_-]+)["']""", text))
    return ids


def _internal_links():
    links = {}
    for path in _site_files(APP, suffixes=(".tsx", ".ts")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"""(?:href|to|url)\s*[=:]\s*["'`{]+\s*["'`]?(/[A-Za-z0-9_\-/#.]*)""",
                             text):
            links.setdefault(m.group(1), set()).add(path.relative_to(ROOT).as_posix())
    return links


def test_every_internal_link_on_the_site_resolves_to_a_page_or_a_static_file():
    assets = _static_assets()
    dead = {}
    for link, where in _internal_links().items():
        if link.endswith("/") and link != "/":
            continue                        # the stem of a templated link, e.g. /solutions/${slug}
        path = link.split("#")[0] or "/"
        if path in assets:
            ok = assets[path].is_file()
        else:
            ok = _route_exists(path)
        if not ok:
            dead[link] = sorted(where)[:3]
    assert dead == {}


def test_every_anchor_the_site_links_to_exists_in_the_site_source():
    ids = _all_ids()
    dead = {link: sorted(where)[:2] for link, where in _internal_links().items()
            if "#" in link and link.split("#", 1)[1] and link.split("#", 1)[1] not in ids}
    assert dead == {}


def test_every_url_in_llms_txt_that_points_at_the_site_resolves():
    text = (PUBLIC / "llms.txt").read_text(encoding="utf-8")
    dead = []
    for url in sorted(set(re.findall(r"https://neuralbridge\.io(/[A-Za-z0-9_\-/.#]*)", text))):
        path = url.split("#")[0].rstrip("/") or "/"
        if path in _static_assets():
            continue
        if path != "/" and not _route_exists(path) and not (DOCS / "index.md").exists() \
                and path == "/docs":
            continue
        if not _route_exists(path):
            dead.append(url)
    assert dead == []


def test_the_solutions_pages_the_site_links_to_all_exist():
    sols = (APP / "solutions" / "[slug]" / "page.tsx").read_text(encoding="utf-8")
    slugs = set(re.findall(r"""slug:\s*["']([a-z0-9-]+)["']""", sols)) or set(
        re.findall(r"""slug:\s*["']([a-z0-9-]+)["']""", "".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in _site_files(APP / "lib", suffixes=(".ts", ".tsx")))))
    linked = set(re.findall(r"/solutions/([a-z0-9-]+)", (PUBLIC / "llms.txt").read_text()))
    assert linked and linked <= slugs, (sorted(linked - slugs))


# ----------------------------------------------------------------------- CLI the site names
def test_every_command_the_site_shows_in_code_exists_in_the_real_cli():
    shown = set()
    for path in _site_files(APP, suffixes=(".tsx", ".ts")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"(?:python -m )?assurance ((?:[a-z][a-z0-9-]*)(?: [a-z][a-z0-9-]*)?)"
                             r"(?=[ \n`'\"<\\]|$)", text):
            shown.add(m.group(1))
    env = {**os.environ, "PYTHONPATH": PRODUCT_SRC, "PYTHONDONTWRITEBYTECODE": "1"}
    top = subprocess.run([sys.executable, "-m", "assurance", "--help"], env=env,
                         capture_output=True, text=True, check=False)
    domains = set(re.findall(r"^\s{2,}([a-z][a-z0-9-]+)\s", top.stdout + top.stderr, re.M))
    missing = []
    for cmd in sorted(shown):
        first = cmd.split()[0]
        if first not in domains:
            continue                       # prose such as "assurance product", not a command
        done = subprocess.run([sys.executable, "-m", "assurance", *cmd.split(), "--help"],
                              env=env, capture_output=True, text=True, check=False)
        if done.returncode != 0:
            # "kit run" is a command; "evidence verify" is; "watch push" is. A second word that
            # is merely the next English word of a sentence is retried on the domain alone.
            alone = subprocess.run([sys.executable, "-m", "assurance", first, "--help"], env=env,
                                   capture_output=True, text=True, check=False)
            if alone.returncode != 0 or len(cmd.split()) == 1:
                missing.append(cmd)
    assert missing == []


# ----------------------------------------------------------------- the MCP page vs the server
def _mcp_page_tools():
    text = (APP / "connectors" / "mcp" / "page.tsx").read_text(encoding="utf-8")
    return [dict(name=n, route=r, tier=t) for n, r, t in re.findall(
        r"\{ name: '([a-z_]+)', route: '([A-Z]+ [^']+)', tier: '([a-z]+)'", text)]


@pytest.mark.skipif(not mcp_importable()[0], reason="BLOCKED: product MCP server not runnable")
def test_the_mcp_page_lists_exactly_the_tools_the_server_has():
    page = {t["name"] for t in _mcp_page_tools()}
    assert page == {t.name for t in list_tools()}, sorted(page ^ {t.name for t in list_tools()})


@pytest.mark.skipif(not mcp_importable()[0], reason="BLOCKED: product MCP server not runnable")
def test_the_route_the_mcp_page_gives_each_tool_is_the_route_the_tool_really_calls():
    from test_attack_mcp import BENIGN_ARGS, env_for
    wrong = {}
    for tool in _mcp_page_tools():
        with recording_server() as rec:
            one_call(env_for(rec), tool["name"], BENIGN_ARGS[tool["name"]])
        sent = rec.requests[0]
        want_method, want_path = tool["route"].split(" ", 1)
        pattern = re.sub(r"\{[^}]*\}", "[^/]+", re.escape(want_path).replace(r"\{", "{")
                         .replace(r"\}", "}"))
        pattern = re.sub(r"\\?\{[^}]*\\?\}", "[^/]+", want_path)
        if sent.method != want_method or not re.fullmatch(pattern, sent.path):
            wrong[tool["name"]] = (tool["route"], f"{sent.method} {sent.path}")
    assert wrong == {}


def test_the_tier_the_mcp_page_gives_each_tool_is_the_tier_that_unlocks_its_route(api):
    keys = {t: api.make_account(f"site-{t}@example.invalid", t)
            for t in ("free", "register", "cell")}
    rank = {"free": 0, "register": 1, "cell": 2}
    wrong = {}
    for tool in _mcp_page_tools():
        method, path = tool["route"].split(" ", 1)
        concrete = re.sub(r"\{[^}]*\}", "case-0000000000000000", path)
        for tier, key in keys.items():
            status, _ = call(api.base, method, concrete, key=key,
                             body={} if method == "POST" else None)
            open_ = status not in (401, 402)
            should = rank[tier] >= rank[tool["tier"]]
            if open_ != should:
                wrong[(tool["name"], tier)] = (tool["tier"], status)
    assert wrong == {}


def test_the_mcp_page_says_how_many_tools_it_has_and_the_count_is_computed_not_typed():
    text = (APP / "connectors" / "mcp" / "page.tsx").read_text(encoding="utf-8")
    assert "TOOL_COUNT = MCP_TOOLS.length" in text
    typed = re.findall(r"\b(\d{2}) tools\b", text + (PUBLIC / "llms.txt").read_text())
    assert all(int(n) == len(_mcp_page_tools()) for n in typed), typed


# ------------------------------------------------------------- numbers and promises in the copy
def test_the_daily_caps_the_copy_states_are_the_caps_the_plan_table_enforces(live_plans):
    free = live_plans["free"]["limits"]
    copy = (PUBLIC / "llms.txt").read_text(encoding="utf-8")
    assert free["validations_per_day"] == 20 and "20 a day" in copy
    assert free["diffs_per_day"] == 10 and "manifest diff allows 10 a day" in copy
    assert any("20 validations and 20 separation" in line
               for line in live_plans["free"]["includes"])


@pytest.fixture()
def fresh_api():
    with live_api() as running:
        yield running


def test_the_free_validator_stops_at_exactly_twenty_a_day_and_says_what_to_do(fresh_api):
    body = {"track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {}}
    statuses = [call(fresh_api.base, "POST", "/v1/spec/validate", body=body)[0] for _ in range(22)]
    assert statuses[:20] == [200] * 20 and statuses[20:] == [429, 429], statuses
    status, over = call(fresh_api.base, "POST", "/v1/spec/validate", body=body)
    assert status == 429 and over["detail"]["limit"] == 20 and over["detail"]["remedy"]
    # a paid caller is not capped
    key = fresh_api.make_account("uncapped@example.invalid", "register")
    assert call(fresh_api.base, "POST", "/v1/spec/validate", key=key, body=body)[0] == 200


def test_cases_are_not_metered_on_the_register_plan(fresh_api):
    key = fresh_api.make_account("cases@example.invalid", "register")
    signal = {"received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": "synthetic",
              "actor": {"identifier": "t", "role": "analyst"}}
    statuses = {call(fresh_api.base, "POST", f"/v1/cases/N{i}/signal", key=key, body=signal)[0]
                for i in range(60)}
    assert statuses == {201}
    status, listed = call(fresh_api.base, "GET", "/v1/cases", key=key)
    assert status == 200 and len(listed) == 60
    assert call(fresh_api.base, "GET", "/v1/usage", key=key)[0] in (200, 404)


def _lapsed_account(api, email: str) -> str:
    code = ("import sys\n"
            "from assurance.billing.accounts import AccountStore\n"
            "s = AccountStore(sys.argv[1])\n"
            "a = s.upsert_account(email=sys.argv[2], tier='register',\n"
            "                     stripe_customer_id='cus_SYNTHETIC_LAPSE')\n"
            "key = s.issue_key(a.id)\n"
            "print(key)\n")
    done = subprocess.run([sys.executable, "-c", code, str(api.state / "accounts.db"), email],
                          env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
                          capture_output=True, text=True, check=True)
    return done.stdout.strip()


def _lapse(api) -> None:
    code = ("import sys\n"
            "from assurance.billing.accounts import AccountStore\n"
            "AccountStore(sys.argv[1]).set_status(stripe_customer_id='cus_SYNTHETIC_LAPSE',\n"
            "                                     status='cancelled', event_created=4102444800)\n")
    subprocess.run([sys.executable, "-c", code, str(api.state / "accounts.db")],
                   env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
                   capture_output=True, text=True, check=True)


def test_when_the_subscription_ends_evidence_stays_readable_and_new_records_stop(fresh_api):
    """The Register plan's own promise: 'you keep read, verify and export of your own
    evidence; new records and the operational views stop'."""
    key = _lapsed_account(fresh_api, "lapse@example.invalid")
    signal = {"received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": "synthetic",
              "actor": {"identifier": "t", "role": "analyst"}}
    assert call(fresh_api.base, "POST", "/v1/cases/KEEP/signal", key=key, body=signal)[0] == 201
    _lapse(fresh_api)
    # kept
    assert call(fresh_api.base, "GET", "/v1/cases", key=key)[0] == 200
    assert call(fresh_api.base, "GET", "/v1/cases/KEEP", key=key)[0] == 200
    assert call(fresh_api.base, "GET", "/v1/cases/KEEP/export", key=key)[0] == 200
    status, verdict = call(fresh_api.base, "GET", "/v1/ledger/verify", key=key)
    assert status == 200 and verdict["verified"] is True
    # stopped
    assert call(fresh_api.base, "POST", "/v1/cases/NEW/signal", key=key, body=signal)[0] == 402
    assert call(fresh_api.base, "GET", "/v1/register", key=key)[0] == 402
    assert call(fresh_api.base, "GET", "/v1/register/breaches", key=key)[0] == 402
    # and nothing new was written by the refused call
    assert call(fresh_api.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"][
        "length"] == 1


def test_a_plan_that_says_attestation_answers_503_without_a_key_does_exactly_that(fresh_api):
    cell = fresh_api.make_account("attest503@example.invalid", "cell")
    status, body = call(fresh_api.base, "POST", "/v1/ledger/attest", key=cell, body={
        "ledger_length": 0, "head_seq": 0, "head_link_hash": "0" * 64})
    assert status == 503 and body["detail"]["error"] == "no_attestation_key_configured"
    assert call(fresh_api.base, "GET", "/v1/ledger/attest/key")[0] == 503
    assert "PRIVATE" not in json.dumps(body)


def test_the_always_free_checks_the_plan_copy_lists_really_need_no_account(fresh_api):
    free_routes = [
        ("POST", "/v1/machine/bundle/check", {"bundle": {}}),
        ("POST", "/v1/fleet/advisory/check", {"advisory": {}, "manifest": {}}),
        ("POST", "/v1/fleet/declaration/check", {}),
        ("POST", "/v1/ledger/attest/verify", {}),
        ("POST", "/v1/machine/separation", {}),
        ("POST", "/v1/machinery/diff", {}),
        ("GET", "/v1/spec/fields", None),
    ]
    for method, path, body in free_routes:
        status, _ = call(fresh_api.base, method, path, body=body)
        assert status not in (401, 402), (method, path, status)


def test_the_supplier_tier_is_unlisted_as_the_copy_says(live_plans):
    assert "supplier" not in live_plans
    assert "unlisted" in (PUBLIC / "llms.txt").read_text(encoding="utf-8").lower()


def test_checkout_answers_503_price_not_configured_as_agent_json_says(fresh_api):
    """agent.json: 'POST /v1/checkout answers 503 price_not_configured until an operator
    configures Stripe prices'. Exercised on a server with no billing configuration."""
    claim = json.loads((PUBLIC / ".well-known" / "agent.json").read_text(encoding="utf-8"))
    assert "price_not_configured" in json.dumps(claim["pricing"])
    who = {"email": "synthetic@example.invalid"}
    status, body = call(fresh_api.base, "POST", "/v1/checkout", body={"tier": "register", **who})
    assert status == 503 and "price_not_configured" in json.dumps(body), (status, body)
    assert "cs_live" not in json.dumps(body) and "sk_live" not in json.dumps(body)
    assert call(fresh_api.base, "POST", "/v1/checkout", body={"tier": "cell", **who})[0] == 503


def test_agent_json_prices_are_the_plan_table_prices(live_plans):
    claim = json.loads((PUBLIC / ".well-known" / "agent.json").read_text(encoding="utf-8"))
    tiers = {t["name"]: t for t in claim["pricing"]["tiers"]}
    assert live_plans["register"]["price"] == "€390 / month" and tiers["Register"]["price"] == 390
    assert live_plans["cell"]["price"] == "€1,290 / month" and tiers["Cell"]["price"] == 1290
