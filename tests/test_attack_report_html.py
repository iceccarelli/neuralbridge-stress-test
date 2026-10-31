"""The HTML evidence report is a document people open in a browser; outsiders write its content.

Evidence level: product CLI (``report build``), SYNTHETIC machines and an advisory whose every
free-text field carries markup. The output is parsed as HTML, not grepped.

Independent expectations:
* text from a manifest, a supplier advisory, a declaration or a command-line argument is shown as
  text: it creates no element, no attribute and no script, in the report;
* a link in an advisory reference that is not http(s) is never rendered as a clickable link;
* the report is a static document: it loads nothing from another host (no external script,
  stylesheet, image or frame) and opens no network connection by itself.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser

import pytest
from support_cli import assurance, synthetic_manifest

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

MARK = "HOSTILE"
PAYLOADS = {
    "img": f'"><img src=x onerror="window.{MARK}=1">',
    "script": f"<script>window.{MARK}=2</script>",
    "svg": f"<svg onload=window.{MARK}=3>",
    "attr": f'" onmouseover="window.{MARK}=4" x="',
    "style": f"<style>body{{background:url(//evil.example/{MARK})}}</style>",
    "iframe": f'<iframe src="//evil.example/{MARK}"></iframe>',
    "entity": f"&lt;b&gt;{MARK}&lt;/b&gt; &#60;i&#62;",
}
ALL = "".join(PAYLOADS.values())


class Collect(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    handle_startendtag = handle_starttag


def parse(html: str) -> Collect:
    c = Collect()
    c.feed(html)
    return c


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    work = tmp_path_factory.mktemp("htmlreport")
    m = synthetic_manifest("S1", [("I1", "1756-EN2T", "V5.001")])
    m["machine"] = {"manufacturer": ALL, "model": ALL, "serial": "S1", "site": ALL,
                    "year": "2026", "country": "DE"}
    m["manifest_id"] = "HOSTILE-MANIFEST"
    m["taken_by"] = {"identifier": ALL, "role": ALL, "kind": "person"}
    m["notes"] = ALL
    m["method"] = ALL
    m["items"][0].update(name=ALL, version=ALL, supplier=ALL)
    m["functions"][0]["description"] = ALL
    (work / "m.json").write_text(json.dumps(m))
    run = assurance("machinery", "record-manifest", "m.json", "--ledger", "l.db", "--actor", ALL,
                    cwd=work)
    if run.exit != 0:
        pytest.skip(f"BLOCKED: the product refused the hostile manifest outright: {run.err[:160]}")
    adv = {"advisory_id": "ADV-" + ALL, "issued_by": ALL, "issued_at": "2026-10-27T00:00:00Z",
           "title": ALL, "summary": ALL, "severity": "safety_relevant",
           "affected": [{"supplier": ALL, "name": ALL, "versions": [ALL], "content_hashes": [],
                         "version_note": ALL}],
           "remedy": ALL, "reference": "javascript:window.HOSTILE=5",
           "fixed_versions": [ALL], "fixed_hashes": []}
    (work / "adv.json").write_text(json.dumps(adv))
    run = assurance("report", "build", "--ledger", "l.db", "--out", "r.html", "--organisation",
                    ALL, "--prepared-by", ALL, "--notice", ALL, "--advisory", "adv.json",
                    cwd=work)
    assert run.exit in (0, 1, 3), run.err
    return (work / "r.html").read_text(encoding="utf-8")


def test_the_report_was_built_and_contains_the_hostile_text_so_the_test_proves_something(report):
    assert len(report) > 2000 and "<html" in report.lower()
    assert MARK in report, "the hostile text never reached the report"


def test_no_hostile_text_became_an_element_or_an_event_handler(report):
    tags = parse(report).tags
    names = [t for t, _ in tags]
    assert "img" not in names or all("onerror" not in a for t, a in tags if t == "img")
    for tag, attrs in tags:
        for name, value in attrs.items():
            assert not name.startswith("on"), (tag, name, value)
            assert MARK not in (value or "") or tag in {"a", "meta", "title"} and name == "href", (
                tag, name, value)
    assert "svg" not in names and "iframe" not in names


def test_no_script_in_the_report_contains_the_hostile_marker(report):
    c = parse(report)
    scripts = [t for t, _ in c.tags if t == "script"]
    for match in re.finditer(r"<script\b[^>]*>(.*?)</script>", report, re.S | re.I):
        assert MARK not in match.group(1), match.group(1)[:200]
    assert len(scripts) == len(re.findall(r"<script\b", report, re.I))


def test_the_markup_is_present_only_in_escaped_form(report):
    assert "&lt;script&gt;" in report or "&lt;" in report
    assert "<script>window.HOSTILE" not in report
    assert "onerror=\"window.HOSTILE" not in report.replace("&quot;", '"').replace(
        "&lt;", "<").replace("&gt;", ">") or "&lt;img" in report


def test_a_javascript_reference_is_never_a_clickable_link(report):
    for tag, attrs in parse(report).tags:
        if tag == "a":
            assert not (attrs.get("href") or "").strip().lower().startswith(
                ("javascript:", "data:", "vbscript:")), attrs


def test_the_report_loads_nothing_from_another_host(report):
    for tag, attrs in parse(report).tags:
        for name in ("src", "href", "action", "data", "poster"):
            value = (attrs.get(name) or "").strip()
            if tag in {"script", "img", "iframe", "link", "source", "video", "audio", "form",
                       "object", "embed"} and re.match(r"(https?:)?//", value):
                pytest.fail(f"<{tag} {name}={value!r}> fetches from another host")
    for match in re.finditer(r"<style\b[^>]*>(.*?)</style>", report, re.S | re.I):
        css = match.group(1)
        assert "@import" not in css and "evil.example" not in css and "url(//" not in css
