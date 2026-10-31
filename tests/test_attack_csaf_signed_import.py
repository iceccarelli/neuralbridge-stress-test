"""A CSAF translation that somebody signs anyway: CLI and API, with the real trust store.

Evidence level: product CLI and real API on loopback; real Ed25519 keys; SYNTHETIC advisory and
machines. The hand-signed feed is ARRANGEMENT: it is built with the product's own record type
and key, because the publisher refuses to build it (that refusal is test 1). Expected results come
from the module's stated principle, not from reading the product back:

* the publisher must refuse to put a supplier's signature on an unauthenticated import;
* if such a record exists anyway (a different tool, a hand-edit), a PINNED key proves who signed
  the bytes. It does not turn a translation nobody authenticated into a statement the supplier
  made, so no automated consequence may follow, on any surface, whatever the pin says;
* the report keeps saying it is a translation, and 'nothing matched' is not 'nothing affected'.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from support_api import api_importable, call, live_api
from support_cli import assurance, synthetic_manifest
from test_attack_csaf_cli import BASE

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")
SUPPLIER = "syn-cert"

HAND_SIGN = """
import sys, json
from pathlib import Path
from assurance.attest.keys import SigningKey
from assurance.core.identity import format_utc, utc_now
from assurance.supplier.publish import FEED_FORMAT, SignedAdvisory, SupplierIdentity
import base64, dataclasses
key = SigningKey.load(Path(sys.argv[1]))
adv = json.loads(Path(sys.argv[2]).read_text())
ident = SupplierIdentity(supplier_id=sys.argv[4], legal_name=adv["issued_by"],
                         key_contact="x@example.invalid")
rec = SignedAdvisory(format=FEED_FORMAT, sequence=1, supplier=ident,
                     key_fingerprint=key.fingerprint, published_at=format_utc(utc_now()),
                     previous="", advisory=adv)
rec = dataclasses.replace(rec, signature=base64.b64encode(key.sign(rec.signed_payload())).decode())
Path(sys.argv[3]).write_text(json.dumps(rec.to_dict(), sort_keys=True) + "\\n")
"""


@pytest.fixture()
def pack(tmp_path):
    work = tmp_path
    for s, v in (("A", "12.001"), ("B", "12.002"), ("C", "11.001")):
        (work / f"m{s}.json").write_text(json.dumps(synthetic_manifest(
            s, [("P1", "1756-EN2T", v)], supplier="Rockwell Automation")))
        assert assurance("machinery", "record-manifest", f"m{s}.json", "--ledger", "l.db",
                         cwd=work).exit == 0
    (work / "csaf.json").write_text(json.dumps(BASE))
    assert assurance("fleet", "import-csaf", "csaf.json", "--out", "adv.json",
                     cwd=work).exit == 0
    assert assurance("supplier", "keygen", "--out", "s.key", "--public-out", "s.pub",
                     cwd=work).exit == 0
    done = subprocess.run(
        [sys.executable, "-c", HAND_SIGN, "s.key", "adv.json", "feed.jsonl", SUPPLIER],
        cwd=work, env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": PRODUCT_SRC},
        capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr[-400:]
    return work


def pin(work):
    run = assurance("supplier", "trust", "pin", "--ledger", "l.db", "--supplier-id", SUPPLIER,
                    "--public-key", "s.pub", "--obtained-via", "phone call to the supplier",
                    "--actor", "tech:alice", cwd=work)
    assert run.exit == 0, run.err


def test_the_publisher_refuses_to_sign_an_unauthenticated_import(pack):
    run = assurance("supplier", "publish", "adv.json", "--feed", "refused.jsonl", "--key", "s.key",
                    "--supplier-id", SUPPLIER, "--legal-name", "Synthetic CERT", "--key-contact",
                    "x@example.invalid", cwd=pack)
    assert run.exit != 0 and "unsigned import" in run.err + run.out
    assert not (pack / "refused.jsonl").exists() or not (pack / "refused.jsonl").read_text()


def test_the_hand_signed_record_really_verifies_so_the_test_is_not_vacuous(pack):
    run = assurance("supplier", "verify", "--feed", "feed.jsonl", "--public-key", "s.pub",
                    "--expect-supplier", SUPPLIER, "--json", cwd=pack)
    assert run.exit == 0 and json.loads(run.out)["ok"] is True


def test_a_pinned_key_does_not_make_a_translation_the_suppliers_statement_in_the_cli(pack):
    pin(pack)
    run = assurance("fleet", "advisory", "--feed", "feed.jsonl", "--expect-supplier", SUPPLIER,
                    "--ledger", "l.db", "--json", cwd=pack)
    assert run.exit in (1, 3), (run.exit, run.err)
    report = run.json()["advisories"][0]
    assert report["provenance"]["automated_consequences_permitted"] is False
    assert report["provenance"]["inspect_only"] is True or report["advisory_import"]
    assert report["advisory_import"], "the report stopped saying this is a translation"
    assert report["verdict"] != "clear" and report["clear_is_complete"] is False


def test_the_translation_marker_survives_signing_and_names_its_origin(pack):
    pin(pack)
    run = assurance("fleet", "advisory", "--feed", "feed.jsonl", "--expect-supplier", SUPPLIER,
                    "--ledger", "l.db", "--json", cwd=pack)
    note = json.dumps(run.json()["advisories"][0]["advisory_import"]).lower()
    assert "unsigned csaf" in note or "not been authenticated" in note


_ok, _why = api_importable()


@pytest.mark.skipif(not _ok, reason=f"BLOCKED: product API not runnable ({_why})")
def test_a_pinned_key_does_not_make_a_translation_the_suppliers_statement_in_the_api(pack):
    with live_api() as api:
        key = api.make_account("csaf@example.invalid", "cell")
        status, op = call(api.base, "POST", "/v1/operators", key=key,
                          body={"name": "Alice Decider", "role": "decider"})
        assert status == 201
        for s, v in (("A", "12.001"), ("B", "12.002"), ("C", "11.001")):
            assert call(api.base, "POST", "/v1/machinery/manifest", key=key, body={
                "manifest": synthetic_manifest(s, [("P1", "1756-EN2T", v)],
                                               supplier="Rockwell Automation"),
                "actor": "synthetic.tech"})[0] == 200
        assert call(api.base, "POST", "/v1/supplier/trust/pin", key=op["api_key"], body={
            "supplier_id": SUPPLIER, "public_key_pem": (pack / "s.pub").read_text(),
            "obtained_via": "phone call to the supplier"})[0] == 201
        status, body = call(api.base, "POST", "/v1/fleet/advisory/signed", key=key, body={
            "feed": (pack / "feed.jsonl").read_text(), "expect_supplier": SUPPLIER})
        assert status == 200 and body["trust"]["trust_state"] == "trusted"
        entry = body["advisories"][0]
        assert entry["automated_consequences_permitted"] is False
        assert entry["inspect_only"] is True and entry["advisory_import"]
        assert body["inspect_only"] is True
        assert entry["impact"]["verdict"] != "clear"
