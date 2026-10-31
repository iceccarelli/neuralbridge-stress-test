"""The website in a real browser, wired to the product's real API.

Evidence level: the product's website BUILT FROM ITS COMMITTED SOURCE (scripts/build_site.sh, into
Git-ignored data/derived/site-build) and served on http://localhost:3000, driven by Chromium
(Playwright), talking to the product's REAL FastAPI app on http://127.0.0.1:18765 with throwaway
accounts and state. A dashboard build is not evidence of integration; this is the integration.
Not the live site (see test_live_site.py), not hosted, no real key, no real customer.

If the build has not been made, every test here is skipped with the command that makes it (BLOCKED:
a skip is a gate that did not run); it is never a pass.

Independent expectations, from the brief and plain logic:

* the pricing the visitor sees is the plan table the API serves, and no call to action leaves the
  site for a payment page while no price is configured;
* an API key typed into the console goes to the API origin only, in the documented header, and is
  never written to storage, a cookie, the URL or the page title, and does not survive a reload;
* a refusal (401 no key, 402 not entitled) is shown as the API's real answer, not as a success;
* text that an outsider controls (a case description) is shown as text and never runs;
* a file handed to the verifier is judged: an edited bundle does not read as verified;
* a page that takes a key can be framed by another origin today (neuralbridge#85); recorded as a
  strict xfail that flips when frame protection is served.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from support_api import api_importable, call, live_api

from conftest import PRODUCT_SRC

LAB = Path(__file__).resolve().parent.parent
BUILD = LAB / "data" / "derived" / "site-build"
CHROME = next(iter(sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome"))), None)
API_PORT, SITE = 18765, "http://localhost:3000"
KEY_TEXT = "nb_SYNTHETIC_BROWSER_KEY_do_not_persist_0123456789"

try:
    from playwright.sync_api import sync_playwright
    _playwright = True
except ImportError:                                           # pragma: no cover
    _playwright = False

_ok, _why = api_importable()
_blocked = (None if (BUILD / ".next").is_dir() and _playwright and CHROME and _ok and PRODUCT_SRC
            else "BLOCKED: browser tests need a site build (bash scripts/build_site.sh), "
                 "playwright, Chromium and the product API")
pytestmark = pytest.mark.skipif(_blocked is not None, reason=_blocked or "")


@pytest.fixture(scope="module")
def stack():
    site = subprocess.Popen(["npx", "next", "start", "-p", "3000"], cwd=BUILD,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with live_api(port=API_PORT) as api:
            import time
            for _ in range(60):
                try:
                    if call(SITE, "GET", "/")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError("the site did not start")
            yield api
    finally:
        site.terminate()
        site.wait(timeout=15)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=str(CHROME), args=["--no-sandbox"])
        yield b
        b.close()


class Page:
    """A fresh browser context with a record of every request and every dialog."""

    def __init__(self, browser):
        self.ctx = browser.new_context()
        self.page = self.ctx.new_page()
        self.requests = []
        self.dialogs = []
        self.page.on("request", lambda r: self.requests.append(
            (r.method, r.url, {k.lower(): v for k, v in r.headers.items()})))
        self.page.on("dialog", lambda d: (self.dialogs.append(d.message), d.dismiss()))

    def go(self, path):
        self.page.goto(SITE + path, wait_until="networkidle")
        return self.page

    def close(self):
        self.ctx.close()


@pytest.fixture()
def pg(browser, stack):
    p = Page(browser)
    yield p
    p.close()


def route_button(page, method, path):
    """The console's button for exactly ``METHOD path`` (its text is 'GET /v1/cases  Register')."""
    # the element's text content has no whitespace between its spans: 'GET/v1/casesRegister…'
    pattern = re.compile(r"^" + method + r"\s*" + re.escape(path) + r"\s*(Validator|Register|Cell)")
    return page.locator("button").filter(has_text=pattern).first


def run_route(page, method, path):
    """Select the route, then press Run (selecting alone sends nothing)."""
    route_button(page, method, path).click()
    page.get_by_role("button", name="Run", exact=True).click()


def api_requests(pg):
    return [r for r in pg.requests if f":{API_PORT}" in r[1]]


# ----------------------------------------------------------------------------- pricing
def test_the_pricing_the_visitor_sees_is_the_plan_table_the_api_serves(pg, stack):
    status, plans = call(stack.base, "GET", "/v1/plans")
    assert status == 200
    page = pg.go("/")
    assert any(m == "GET" and u.endswith("/v1/plans") for m, u, _ in api_requests(pg)), (
        "the home page did not fetch the live plan table")
    text = re.sub(r"\s+", " ", page.inner_text("body"))
    for plan in plans:
        if plan["tier"] in ("register", "cell"):
            assert plan["price"].replace(" / month", "") .split()[0] in text or \
                plan["price"].replace(" / month", "/mo") in text, plan["price"]


def test_no_call_to_action_on_the_pricing_leaves_the_site_for_a_payment_page(pg):
    page = pg.go("/")
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    external = [h for h in hrefs if not h.startswith((SITE, f"http://127.0.0.1:{API_PORT}",
                                                      "mailto:", "https://github.com"))]
    assert not [h for h in external if "stripe" in h or "checkout" in h], external
    assert not [r for r in pg.requests if "stripe.com" in r[1]]


def test_the_page_makes_no_request_to_any_host_but_the_site_and_the_api(pg):
    pg.go("/")
    pg.go("/console")
    pg.go("/verify")
    hosts = {re.match(r"https?://([^/]+)", u).group(1) for _, u, _ in pg.requests
             if re.match(r"https?://", u)}
    assert hosts <= {"localhost:3000", f"127.0.0.1:{API_PORT}"}, hosts


# ------------------------------------------------------------------------------ the key
def _type_key(pg, key=KEY_TEXT):
    page = pg.go("/console")
    box = page.locator("input[type=password]").first
    box.fill(key)
    return page


def test_a_typed_key_is_sent_only_to_the_api_origin_and_only_in_the_documented_header(pg, stack):
    page = _type_key(pg)
    run_route(page, "GET", "/v1/cases")
    page.wait_for_timeout(1500)
    carrying = [(m, u) for m, u, h in pg.requests if KEY_TEXT in json.dumps(h)]
    assert carrying, "the key was never sent: the console did not call the API"
    assert all(u.startswith(f"http://127.0.0.1:{API_PORT}/") for _, u in carrying), carrying
    assert all(h.get("x-api-key") == KEY_TEXT for m, u, h in pg.requests
               if KEY_TEXT in json.dumps(h)), "the key travelled in a header other than X-API-Key"
    assert not any(KEY_TEXT in u for _, u, _ in pg.requests), "the key is in a URL"


def test_a_typed_key_stays_in_this_tab_only_as_the_site_says_and_nowhere_durable(pg):
    """The source says the key lives in this tab's sessionStorage and nowhere else. Tested as
    stated: not in localStorage, a cookie, the URL or the title; not visible from a new tab."""
    page = _type_key(pg)
    run_route(page, "GET", "/v1/plans")
    page.wait_for_timeout(800)
    dump = page.evaluate("""() => JSON.stringify({
        local: Object.entries(localStorage), cookie: document.cookie, title: document.title,
        url: location.href, referrer: document.referrer})""")
    assert KEY_TEXT not in dump
    other = pg.ctx.new_page()
    other.goto(SITE + "/console", wait_until="networkidle")
    assert other.locator("input[type=password]").first.input_value() == ""
    assert KEY_TEXT not in other.evaluate("() => JSON.stringify(Object.entries(sessionStorage))")
    assert KEY_TEXT not in json.dumps([c for c in pg.ctx.cookies()])


def test_a_wrong_key_is_shown_as_the_apis_401_and_not_as_a_result(pg):
    page = _type_key(pg, "nb_definitely_not_a_key")
    run_route(page, "GET", "/v1/cases")
    page.wait_for_timeout(1500)
    body = page.inner_text("body")
    assert "401" in body, "the console did not show the API's refusal"
    shown = " ".join(page.locator("pre, code, output").all_inner_texts())
    assert "nb_definitely_not_a_key" not in shown


def test_a_free_account_is_shown_the_apis_402_and_the_plan_that_unlocks_it(pg, stack):
    free = stack.make_account("browser-free@example.invalid", "free")
    page = _type_key(pg, free)
    run_route(page, "GET", "/v1/cases")
    page.wait_for_timeout(1500)
    body = page.inner_text("body")
    assert "402" in body and "register" in body.lower()


# ----------------------------------------------------------------- a real case, end to end
def test_the_first_case_form_records_a_case_in_the_ledger_through_the_real_api(pg, stack):
    key = stack.make_account("browser-reg@example.invalid", "register")
    page = _type_key(pg, key)
    before = call(stack.base, "GET", "/v1/ledger/verify", key=key)[1]["attestation"]["length"]
    inputs = page.locator("input:not([type=password]):not([type=file]), textarea")
    page.get_by_placeholder("e.g. Line 4 welder").fill("Browser Test Welder")
    page.get_by_placeholder("e.g. Unexpected outbound connection from the line controller"
                            ).fill("synthetic report typed in a browser")
    for box in page.get_by_placeholder("e.g. you@company.com").all():
        box.fill("tester@example.invalid")
    assert inputs.count() >= 3
    page.get_by_role("button", name="Open this case").click()
    page.wait_for_timeout(2000)
    after = call(stack.base, "GET", "/v1/ledger/verify", key=key)[1]
    assert after["attestation"]["length"] == before + 1 and after["verified"] is True
    status, cases = call(stack.base, "GET", "/v1/cases", key=key)
    assert status == 200 and len(cases) == 1
    detail = call(stack.base, "GET", f"/v1/cases/{cases[0]}", key=key)[1]
    assert detail["state"] == "signal_received" and detail["deadlines"] is None


def test_the_form_without_a_key_records_nothing_and_says_why(pg, stack):
    page = pg.go("/console")
    page.get_by_placeholder("e.g. Line 4 welder").fill("No Key Welder")
    page.get_by_placeholder("e.g. Unexpected outbound connection from the line controller"
                            ).fill("should not be recorded")
    for box in page.get_by_placeholder("e.g. you@company.com").all():
        box.fill("tester@example.invalid")
    page.get_by_role("button", name="Open this case").click()
    page.wait_for_timeout(1200)
    signals = [r for r in api_requests(pg) if r[0] == "POST" and "/signal" in r[1]]
    assert all(r[2].get("x-api-key") is None for r in signals)
    text = page.inner_text("body").lower()
    assert "401" in text or "key" in text


# -------------------------------------------------------------------------------- hostile text
XSS = ('<img src=x onerror="window.__pwn=1"><script>window.__pwn=2</script>'
       '"><svg onload=window.__pwn=3>')


def test_text_an_outsider_controls_is_shown_as_text_and_never_runs(pg, stack):
    """The API accepts a case id containing markup, so the page that lists case ids must show it
    as text. The id is rendered into the console's result and the test checks the DOM, not just
    the absence of a dialog."""
    import urllib.parse
    hostile_id = 'x"><img src=x onerror="window.__pwn=7">'
    key = stack.make_account("browser-xss@example.invalid", "cell")
    quoted = urllib.parse.quote(hostile_id, safe="")
    assert call(stack.base, "POST", f"/v1/cases/{quoted}/signal", key=key, body={
        "received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": XSS,
        "product_name": XSS, "actor": {"identifier": "t", "role": "r"}})[0] == 201
    page = _type_key(pg, key)
    run_route(page, "GET", "/v1/cases")
    page.wait_for_timeout(1500)
    shown = " ".join(page.locator("pre, code, output").all_inner_texts())
    assert "onerror" in shown, "the hostile id never reached the page: the test proved nothing"
    assert page.evaluate("() => window.__pwn") is None
    assert pg.dialogs == []
    assert page.locator("main img[src='x']").count() == 0
    assert page.locator("main script:not([src])", has_text="__pwn").count() == 0


def test_the_verifier_shows_a_hostile_filename_and_error_text_as_text(pg, tmp_path):
    page = pg.go("/verify")
    hostile = tmp_path / '"><img src=x onerror=window.__pwn=9>.json'
    hostile.write_text("this is not json {")
    page.set_input_files("input[type=file]", str(hostile))
    page.get_by_role("button", name="Check this file").click()
    page.wait_for_timeout(1500)
    assert page.evaluate("() => window.__pwn") is None and pg.dialogs == []


# ------------------------------------------------------------------------------ the verifier
def _export(stack, label):
    key = stack.make_account(f"{label}@example.invalid", "register")
    call(stack.base, "POST", "/v1/cases/V1/signal", key=key, body={
        "received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": "synthetic",
        "actor": {"identifier": "t", "role": "r"}})
    return call(stack.base, "GET", "/v1/cases/V1/export", key=key)[1]


def _verify_file(pg, path):
    page = pg.go("/verify")
    page.set_input_files("input[type=file]", str(path))
    page.get_by_role("button", name="Check this file").click()
    page.wait_for_timeout(2000)
    return re.sub(r"\s+", " ", page.inner_text("main")).lower()


def test_an_intact_export_verifies_and_the_page_says_completeness_was_not_checked(pg, stack,
                                                                                 tmp_path):
    f = tmp_path / "good.json"
    f.write_text(json.dumps(_export(stack, "v-good")))
    text = _verify_file(pg, f)
    assert "complete" in text and ("not checked" in text or "not established" in text
                                   or "cannot" in text), text[:400]


def test_an_edited_export_does_not_read_as_verified(pg, stack, tmp_path):
    bundle = _export(stack, "v-bad")
    bundle["entries"][0]["evidence"]["body"]["signal"]["description"] = "rewritten"
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(bundle))
    text = _verify_file(pg, f)
    assert any(w in text for w in ("does not verify", "not verified", "edited", "failed",
                                   "mismatch", "invalid", "tamper")), text[:500]
    assert "verified: yes" not in text and "chain verified" not in text.replace("not ", "")[:0]


def test_a_non_evidence_file_is_refused_without_a_stack_trace(pg, tmp_path):
    f = tmp_path / "junk.json"
    f.write_text("[1, 2, 3]")
    text = _verify_file(pg, f)
    for needle in ("traceback", "typeerror", "undefined", "internal server error", "[object"):
        assert needle not in text, needle


# ------------------------------------------------------------------------ framing (xfail)
class _Attacker(BaseHTTPRequestHandler):
    def do_GET(self):                                          # noqa: N802
        body = (f'<iframe id="victim" src="{SITE}/console" width="800" height="600"></iframe>'
                ).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.mark.xfail(strict=True, reason=(
    "SITE DEFECT neuralbridge#85, confirmed in the build from source: /console (the page where a "
    "visitor pastes an API key) is framed by an unrelated origin without any frame protection. "
    "Remove this marker when X-Frame-Options or a CSP frame-ancestors is served."))
def test_the_key_entry_page_cannot_be_framed_by_another_origin(browser, stack):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Attacker)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ctx = browser.new_context()
    try:
        page = ctx.new_page()
        page.goto(f"http://127.0.0.1:{server.server_address[1]}/", wait_until="networkidle")
        frame = next((f for f in page.frames if f.url.startswith(SITE)), None)
        framed = frame is not None and frame.locator("input[type=password]").count() > 0
        assert not framed, "the key-entry page rendered inside another origin's frame"
    finally:
        ctx.close()
        server.shutdown()
