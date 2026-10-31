"""Live-site acceptance: https://neuralbridge.io, read-only.

Evidence level: HTTPS GET requests to the PUBLIC marketing site only (pages, sitemap, robots,
llms.txt, openapi.json, agent.json and the static JavaScript every visitor downloads), made with
curl, a descriptive user-agent and a small fixed set of URLs. No POST, no form, no login, no
checkout, no API host, no key. A page that answers 200 is not evidence that the backend works:
the site itself says its hosted API is not deployed, and this suite does not probe one.

If the site is unreachable from where the suite runs, every test here is skipped with the reason
BLOCKED (a skip is a gate that did not run, and the summary says so); it is never a pass.

Independent expectations, stated here and not read from the product:

* every page the site links to, lists in its sitemap or tells agents to read answers 200, and an
  unknown address answers a real 404;
* the deployed ``llms.txt``, ``openapi.json`` and ``agent.json`` are the files in the source tree
  under test (a deployment that drifted from its source is a finding, and which commit is
  deployed is UNCHECKED: the site does not say);
* the site does not offer a purchase it cannot complete: no Stripe checkout link anywhere, and
  its own pricing statements (list prices, "launch hypotheses", "checkout isn't live yet") are
  present together;
* a page that takes an API key or a customer's file is not frameable and not sniffable;
* no public script carries a secret or a private key;
* no error page leaks a stack trace or a server path.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from functools import cache
from pathlib import Path

import pytest

from conftest import PRODUCT_SRC

BASE = "https://neuralbridge.io"
UA = "neuralbridge-stress-test/readonly-site-audit (independent test laboratory)"
ROOT = Path(PRODUCT_SRC).parent if PRODUCT_SRC else None


def _curl(url: str, *, head: bool = False, follow: bool = False, limit: int = 8_000_000):
    if not shutil.which("curl"):
        return None
    cmd = ["curl", "-sS", "-m", "30", "-A", UA, "--max-filesize", str(limit),
           "-o", "-", "-D", "-", "-w", "\n%{http_code}"]
    if follow:
        cmd.append("-L")
    if head:
        cmd += ["-I"]
    done = subprocess.run(cmd + [url], capture_output=True, check=False)
    if done.returncode not in (0, 63):
        return None
    raw = done.stdout
    status = int(raw.rsplit(b"\n", 1)[1] or 0)
    raw = raw.rsplit(b"\n", 1)[0]
    head_block, _, body = raw.partition(b"\r\n\r\n")
    while body.startswith(b"HTTP/"):                   # a proxy CONNECT line precedes the reply
        head_block, _, body = body.partition(b"\r\n\r\n")
    headers = {}
    for line in head_block.decode("latin-1").splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"status": status, "headers": headers, "body": body}


@cache
def get(path: str):
    return _curl(BASE + path)


def _reachable() -> bool:
    got = get("/robots.txt")
    return bool(got and got["status"] == 200)


pytestmark = pytest.mark.skipif(
    not _reachable(), reason="BLOCKED: https://neuralbridge.io is not reachable from here")

#: The pages a visitor is sent to from the home page and header; each must be a real page.
CRITICAL = ["/", "/developers", "/applications", "/cli", "/connectors/mcp", "/connectors/cursor",
            "/console", "/verify", "/status", "/security", "/privacy", "/contact", "/ai",
            "/investigate", "/assurance", "/docs/getting-started", "/docs/assurance/attest",
            "/docs/assurance/fleet", "/docs/assurance/kit",
            "/docs/assurance/machine", "/docs/assurance/machinery", "/docs/assurance/watch",
            "/solutions/manufacturer", "/solutions/plant-operator",
            "/solutions/compliance-officer", "/solutions/insurer-auditor", "/solutions/ai-ops"]


def _text(path: str) -> str:
    return get(path)["body"].decode("utf-8", "replace")


def _internal_links(html: str) -> set[str]:
    out = set()
    for href in re.findall(r"""href=["'](/[^"'#?]*)""", html):
        if href.startswith(("/_next", "/favicon", "//")) or re.search(r"\.(css|js|png|svg|ico)$",
                                                                       href):
            continue
        out.add(href)
    return out


def _sitemap_urls() -> list[str]:
    return re.findall(r"<loc>([^<]+)</loc>", _text("/sitemap.xml"))


# ---------------------------------------------------------------------------------- pages
@pytest.mark.parametrize("path", CRITICAL)
def test_each_critical_page_answers_200_html_with_a_title(path):
    got = get(path)
    assert got["status"] == 200, (path, got["status"])
    assert got["headers"]["content-type"].startswith("text/html")
    assert re.search(r"<title>[^<]{5,}</title>", got["body"].decode("utf-8", "replace"))


def test_an_unknown_address_is_a_real_404_not_a_soft_200():
    got = get("/this-page-does-not-exist-stress-test")
    assert got["status"] == 404


def test_error_pages_leak_no_stack_trace_or_server_path():
    for path in ("/this-page-does-not-exist-stress-test", "/docs/does/not/exist",
                 "/solutions/not-a-real-slug"):
        body = _text(path)
        for needle in ("Traceback", "node_modules", "/home/", "/var/task", "at Object.", "ENOENT"):
            assert needle not in body, (path, needle)


#: Linked from the home page and 404 on the live site; reported to the company.
KNOWN_DEAD_PAGES = {"/docs", "/roadmap", "/docs/assurance/deploy"}


@pytest.mark.xfail(strict=True, reason=(
    "SITE DEFECT: the home page, header, agent.json and (for /roadmap) the sitemap and llms.txt "
    "send visitors and agents to /docs, /roadmap and /docs/assurance/deploy, and all three "
    "answer 404 on the live site. /roadmap is the page llms.txt names as the honest 'shipped "
    "versus planned'. Remove this marker when all three resolve."))
def test_every_page_the_home_page_links_to_resolves():
    dead = {p: get(p)["status"] for p in sorted(_internal_links(_text("/"))) if
            get(p)["status"] != 200}
    assert dead == {}, dead


def test_the_only_dead_links_on_the_home_page_are_the_ones_already_reported():
    dead = {p for p in _internal_links(_text("/")) if get(p)["status"] != 200}
    assert dead <= KNOWN_DEAD_PAGES, f"a NEW dead link on the home page: {dead}"


@pytest.mark.xfail(strict=True, reason=(
    "SITE DEFECT: /roadmap is in the sitemap and answers 404 (ROADMAP.md was removed from the "
    "repository but the page and its sitemap entry remain). Remove when the sitemap lists only "
    "pages that exist."))
def test_every_url_in_the_sitemap_answers_200():
    bad = {u: get(u.replace(BASE, ""))["status"] for u in _sitemap_urls()
           if get(u.replace(BASE, ""))["status"] != 200}
    assert bad == {}, bad


def test_the_only_sitemap_entry_that_is_dead_is_the_one_already_reported():
    bad = {u.replace(BASE, "") for u in _sitemap_urls()
           if get(u.replace(BASE, ""))["status"] != 200}
    assert bad <= {"/roadmap"}, f"a NEW dead sitemap entry: {bad}"


def test_the_sitemap_is_https_on_the_canonical_host_and_has_no_duplicates():
    urls = _sitemap_urls()
    assert len(urls) >= 20 and len(urls) == len(set(urls))
    assert all(u.startswith(BASE + "/") or u == BASE for u in urls)


def test_robots_allows_crawling_and_points_at_the_sitemap():
    text = _text("/robots.txt")
    assert "Sitemap: https://neuralbridge.io/sitemap.xml" in text
    assert not re.search(r"^Disallow:\s*/\s*$", text, re.M)


# ------------------------------------------------------------- deployed files vs the source
@pytest.mark.skipif(ROOT is None, reason="BLOCKED: no product checkout to compare with")
@pytest.mark.parametrize("path,repo_file", [
    ("/llms.txt", "public/llms.txt"), ("/openapi.json", "public/openapi.json"),
    ("/.well-known/agent.json", "public/.well-known/agent.json")])
def test_the_deployed_file_is_the_file_in_the_source_tree_under_test(path, repo_file):
    live = get(path)["body"]
    source = (ROOT / repo_file).read_bytes()
    if path.endswith(".json"):
        assert json.loads(live) == json.loads(source)
    else:
        assert live.decode() == source.decode()


def test_which_commit_is_deployed_is_not_stated_by_the_site_so_drift_cannot_be_ruled_out():
    """UNCHECKED, recorded as an assertion about the site: there is no build id, commit or
    version in the pages or headers, so a green comparison above is about three files only."""
    home = _text("/")
    headers = get("/")["headers"]
    assert not re.search(r"\b[0-9a-f]{40}\b", home)
    assert not any(k in headers for k in ("x-commit", "x-git-sha", "x-build-id", "x-app-version"))


# ---------------------------------------------------------------------- commercial state
def test_no_page_offers_a_stripe_checkout_link_the_site_says_checkout_is_not_live():
    for path in ("/", "/developers", "/applications", "/console", "/status", "/contact",
                 "/connectors/mcp", "/docs/getting-started"):
        html = _text(path)
        assert "checkout.stripe.com" not in html and "buy.stripe.com" not in html, path
        assert not re.search(r"sk_(live|test)_[A-Za-z0-9]{10,}", html), path


def test_the_home_page_states_list_prices_next_to_the_statement_that_they_are_unvalidated():
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(
        r"<(script|style).*?</\1>", "", _text("/"), flags=re.S)))
    assert "€390/mo" in text and "€1,290/mo" in text
    assert "launch hypotheses" in text
    assert "checkout isn't live yet" in text or "checkout isn&#x27;t live yet" in text


def test_the_hosted_api_is_described_as_not_deployed_wherever_a_live_call_is_offered():
    html = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", _text("/")))
    assert "not hosted publicly yet" in html


def test_agent_json_prices_and_purchasability_match_the_pricing_copy():
    doc = json.loads(get("/.well-known/agent.json")["body"])
    tiers = {t["name"]: t for t in doc["pricing"]["tiers"]}
    assert (tiers["Register"]["price"], tiers["Cell"]["price"]) == (390, 1290)
    assert [tiers[n]["purchasable_now"] for n in ("Register", "Cell")] == [False, False]
    assert "unvalidated" in tiers["Cell"]["price_status"]


def test_every_documentation_url_agent_json_lists_is_a_real_page():
    doc = json.loads(get("/.well-known/agent.json")["body"])
    dead = {u: get(u.replace(BASE, ""))["status"] for u in doc["documentation"]
            if get(u.replace(BASE, ""))["status"] != 200}
    known = {BASE + p for p in KNOWN_DEAD_PAGES}
    assert set(dead) <= known, f"a NEW dead documentation url: {dead}"


# ---------------------------------------------------------------------------- web security
@pytest.mark.parametrize("path", ["/", "/console", "/verify", "/developers"])
def test_https_is_enforced_with_a_long_hsts_lifetime(path):
    hsts = get(path)["headers"].get("strict-transport-security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    assert m and int(m.group(1)) >= 31_536_000, hsts


@pytest.mark.xfail(strict=True, reason=(
    "SITE DEFECT: neither the live site nor the repository (next.config.js, vercel.json) sets "
    "a Content-Security-Policy / frame-ancestors, X-Content-Type-Options or Referrer-Policy, "
    "including on /console (where a visitor pastes an API key) and /verify (where a visitor "
    "supplies an evidence file). Remove this marker when these headers are served."))
@pytest.mark.parametrize("path", ["/console", "/verify"])
def test_a_page_that_takes_a_key_or_a_file_is_not_frameable_and_not_sniffable(path):
    h = get(path)["headers"]
    frame_ok = "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "")
    assert frame_ok, "framing is not restricted"
    assert h.get("x-content-type-options", "").lower() == "nosniff"
    assert "referrer-policy" in h


def test_no_response_header_names_the_framework_version_or_a_server_path():
    for path in ("/", "/console"):
        h = get(path)["headers"]
        blob = " ".join(f"{k}: {v}" for k, v in h.items())
        assert "x-powered-by" not in h, blob
        assert not re.search(r"/(home|var|usr|tmp)/", blob), blob


def test_no_public_script_contains_a_secret_or_a_private_key():
    scripts = set()
    for path in ("/", "/console", "/developers", "/verify"):
        scripts |= set(re.findall(r"""(?:src|href)=["'](/_next/static/[^"']+\.js)["']""",
                                  _text(path)))
    assert scripts, "no scripts found to scan: the page structure changed"
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"sk_(live|test)_[A-Za-z0-9]{16,}",
                r"whsec_[A-Za-z0-9]{16,}", r"AKIA[0-9A-Z]{16}", r"service_role",
                r"ASSURANCE_API_KEYS\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}",
                r"nb_live_[A-Za-z0-9]{12,}"]
    leaks = {}
    for script in sorted(scripts)[:60]:
        body = (get(script) or {"body": b""})["body"].decode("utf-8", "replace")
        for pat in patterns:
            if re.search(pat, body):
                leaks.setdefault(script, []).append(pat)
    assert leaks == {}


def test_the_published_openapi_document_exposes_no_server_path_or_secret():
    text = _text("/openapi.json")
    for needle in ("/home/", "/tmp/", "/var/", ".db\"", "sk_live", "sk_test", "PRIVATE KEY",
                   "ASSURANCE_API_KEYS"):
        assert needle not in text, needle
    doc = json.loads(text)
    servers = [s.get("url", "") for s in doc.get("servers", [])]
    assert all(u.startswith(("https://", "/")) for u in servers), servers


def test_plain_http_is_not_served_in_the_clear():
    """http://neuralbridge.io must redirect to https or refuse; it must not answer 200."""
    got = _curl("http://neuralbridge.io/")
    if got is None:
        pytest.skip("BLOCKED: plain http is not reachable from here (proxy policy)")
    assert got["status"] in (301, 302, 307, 308), got["status"]
    assert got["headers"].get("location", "").startswith("https://neuralbridge.io")
