"""ATTACK MATRIX, product CLI level: an unsigned CSAF import is inspect-only and conservative.

Evidence level: product CLI, local subprocess, real SQLite, SYNTHETIC advisory and fleet
(invented vendor document; nothing here is a real advisory about a real device).

Independent expectations:
* parsing a CSAF document does not authenticate it; the result must say it is unauthenticated
  and inspect-only, and it must never produce a 'clear' verdict;
* a version range is text for a human, not something the importer may evaluate to clear a
  machine; only a machine on an explicitly listed fixed version is not flagged;
* 'known_not_affected' never clears a machine that the same document also lists as affected;
* documents that cannot be mapped faithfully are refused, with no advisory written.
"""
from __future__ import annotations

import copy
import json

import pytest
from support_cli import assurance, synthetic_manifest


def _version(pid, name, ranged=False):
    return {"category": "product_version_range" if ranged else "product_version",
            "name": name, "product": {"product_id": pid, "name": name}}


BASE = {
    "document": {
        "csaf_version": "2.0", "title": "SYNTHETIC advisory",
        "publisher": {"name": "Synthetic CERT", "category": "vendor",
                      "namespace": "https://example.invalid"},
        "tracking": {"id": "SYN-CSAF-1", "current_release_date": "2026-10-20T00:00:00Z",
                     "status": "final", "version": "1",
                     "initial_release_date": "2026-10-20T00:00:00Z", "revision_history": []},
        "references": [{"category": "self", "url": "https://example.invalid/syn-csaf-1"}]},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Rockwell Automation", "branches": [{
            "category": "product_name", "name": "1756-EN2T", "branches": [
                _version("P-RANGE", "<12.002", ranged=True),
                _version("P-FIXED", "12.002"),
                _version("P-NOTAFF", "11.001")]}]}]},
    "vulnerabilities": [{
        "cve": "CVE-0000-0000",
        "product_status": {"known_affected": ["P-RANGE"], "fixed": ["P-FIXED"]},
        "remediations": [{"category": "vendor_fix", "details": "Upgrade to 12.002"}]}],
}


@pytest.fixture()
def fleet(tmp_path):
    ledger = tmp_path / "l.db"
    for serial, version in (("A", "12.001"), ("B", "12.002"), ("C", "11.001")):
        path = tmp_path / f"m{serial}.json"
        path.write_text(json.dumps(synthetic_manifest(
            serial, [("P1", "1756-EN2T", version)], supplier="Rockwell Automation")))
        assert assurance("machinery", "record-manifest", str(path), "--ledger", str(ledger),
                         cwd=tmp_path).exit == 0
    return tmp_path, ledger


def _import(tmp_path, doc, name="csaf.json"):
    src = tmp_path / name
    src.write_text(json.dumps(doc))
    out = tmp_path / (name + ".adv.json")
    return assurance("fleet", "import-csaf", str(src), "--out", str(out), cwd=tmp_path), out


def _advisory(tmp_path, ledger, adv, *extra):
    return assurance("fleet", "advisory", str(adv), "--ledger", str(ledger), "--json", *extra,
                     cwd=tmp_path)


def test_imported_csaf_is_unauthenticated_inspect_only_and_never_clear(fleet):
    tmp, ledger = fleet
    r, out = _import(tmp, BASE)
    assert r.exit == 0, r.err
    run = _advisory(tmp, ledger, out)
    a = run.json()["advisories"][0]
    assert a["provenance"]["trust_state"] == "unauthenticated_file"
    assert a["provenance"]["inspect_only"] is True
    assert a["provenance"]["automated_consequences_permitted"] is False
    assert a["verdict"] != "clear" and a["clear_is_complete"] is False
    assert run.exit != 0


def test_range_text_flags_the_product_for_a_human_and_only_the_fixed_version_is_unflagged(fleet):
    tmp, ledger = fleet
    _, out = _import(tmp, BASE)
    a = _advisory(tmp, ledger, out).json()["advisories"][0]
    by_serial = {c["machine"].rpartition("#")[2] if "machine" in c else "?": c["classification"]
                 for c in a["machine_classification"]}
    assert by_serial["B"] == "no_match_found"            # explicitly listed fixed version
    assert by_serial["A"] != "no_match_found"            # below the fix: a person must read it
    assert by_serial["C"] != "no_match_found"            # range text is never evaluated away


def test_known_not_affected_never_clears_a_machine(fleet):
    tmp, ledger = fleet
    doc = copy.deepcopy(BASE)
    doc["vulnerabilities"][0]["product_status"]["known_not_affected"] = ["P-NOTAFF", "P-RANGE"]
    _, out = _import(tmp, doc)
    a = _advisory(tmp, ledger, out).json()["advisories"][0]
    classes = {c["machine"].rpartition("#")[2]: c["classification"]
               for c in a["machine_classification"]}
    assert classes["C"] != "no_match_found"
    assert a["verdict"] != "clear"


@pytest.mark.parametrize("label,mutate", [
    ("wrong csaf version", lambda d: d["document"].update(csaf_version="2.1")),
    ("release date without timezone", lambda d: d["document"]["tracking"].update(
        current_release_date="2026-10-20T00:00:00")),
    ("no vulnerabilities", lambda d: d.update(vulnerabilities=[])),
    ("only known_not_affected", lambda d: d["vulnerabilities"][0].update(
        product_status={"known_not_affected": ["P-RANGE"]})),
    ("no publisher", lambda d: d["document"]["publisher"].update(name="")),
    ("no reference url", lambda d: d["document"].update(references=[])),
])
def test_a_document_that_cannot_be_mapped_is_refused_and_writes_nothing(tmp_path, label, mutate):
    doc = copy.deepcopy(BASE)
    mutate(doc)
    r, out = _import(tmp_path, doc)
    assert r.exit != 0, label
    assert not out.exists(), f"{label}: an advisory file was written"
    assert "Traceback" not in r.err


def test_a_non_json_csaf_is_refused_cleanly(tmp_path):
    src = tmp_path / "bad.json"
    src.write_text("{not json")
    r = assurance("fleet", "import-csaf", str(src), "--out", str(tmp_path / "o.json"),
                  cwd=tmp_path)
    assert r.exit != 0 and "Traceback" not in r.err and not (tmp_path / "o.json").exists()


def test_override_flags_do_not_promote_a_bare_unauthenticated_file(fleet):
    """The override exists for signed feeds that miss the trust policy. Passing it with a
    bare file (which has no signature at all) must not lift it out of inspect-only."""
    tmp, ledger = fleet
    _, out = _import(tmp, BASE)
    for extra in (
        ("--unsigned-anyway",),
        ("--unsigned-anyway", "--override-actor", "synthetic.lead", "--override-reason", "x"),
    ):
        run = _advisory(tmp, ledger, out, *extra)
        if run.out.strip().startswith("{"):
            a = run.json()["advisories"][0]
            assert a["provenance"]["inspect_only"] is True, extra
            assert a["provenance"]["automated_consequences_permitted"] is False, extra
            assert a["verdict"] != "clear", extra
        else:
            assert run.exit != 0, extra
