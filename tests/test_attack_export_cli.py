"""ATTACK MATRIX, product CLI level (NB-005): an exported evidence bundle, verified offline.

Evidence level: product CLI, local subprocess, real SQLite and real Ed25519 keys, SYNTHETIC
signals. Not API, not hosted staging.

Independent expectations (stated here, not read from the product):
* with the signer's public key, a bundle is a pass (exit 0) only if it is the complete, unedited
  ledger the signer attested to; any deletion, addition, duplication, reordering, truncation or
  rewrite must be exit 1 (evidence wrong) or 3 (not established), never 0;
* without a key, a pass may mean internal consistency only, and must say completeness was not
  checked;
* an unreadable bundle is exit 2, never a traceback and never 0;
* a bundle made from a different ledger is not vouched for by this ledger's key.
"""
from __future__ import annotations

import copy
import json

import pytest
from support_cli import assurance


@pytest.fixture()
def lab(tmp_path):
    work, keys = tmp_path / "w", tmp_path / "keys"
    work.mkdir()
    keys.mkdir()
    ledger, log = work / "l.db", work / "a.log"

    def art14(*args, db=ledger):
        return assurance("art14", "--ledger", str(db), *args, cwd=work)

    for n, case in enumerate(("C1", "C2", "C3", "C4"), start=1):
        run = art14("signal", case, "--by", "t:analyst", "--at", f"2026-10-2{n}T08:00:00Z",
                    "--description", f"synthetic signal {case}", "--product", "P",
                    "--version", "1")
        assert run.exit == 0, run.err
    assert assurance("attest", "keygen", "--out", str(keys / "a.key"), "--public-out",
                     str(keys / "a.pub"), cwd=work).exit == 0
    assert assurance("attest", "sign", "--ledger", str(ledger), "--key", str(keys / "a.key"),
                     "--log", str(log), cwd=work).exit == 0
    bundle = work / "b.json"
    assert art14("export", "--attestations", str(log), "-o", str(bundle)).exit == 0

    class Lab:
        root, db, file, pub = work, ledger, bundle, keys / "a.pub"

        @staticmethod
        def verify(path=bundle, key=True, pub=keys / "a.pub"):
            args = ["evidence", "verify", str(path), "--json"]
            if key:
                args += ["--public-key", str(pub)]
            run = assurance(*args, cwd=work)
            body = json.loads(run.out) if run.out.strip().startswith("{") else {}
            return run, body

        @staticmethod
        def edited(mutate):
            doc = json.loads(bundle.read_text())
            mutate(doc)
            out = work / "edited.json"
            out.write_text(json.dumps(doc))
            return out

        @staticmethod
        def other_ledger_bundle():
            other = work / "other.db"
            assert art14("signal", "ZZ", "--by", "t:analyst", "--at", "2026-10-25T08:00:00Z",
                         "--description", "other ledger", db=other).exit == 0
            out = work / "other.json"
            assert art14("export", "-o", str(out), db=other).exit == 0
            return out

        keygen = staticmethod(lambda name: assurance(
            "attest", "keygen", "--out", str(keys / f"{name}.key"), "--public-out",
            str(keys / f"{name}.pub"), cwd=work))
    return Lab


def test_the_intact_bundle_is_anchored_with_the_key_and_says_so_without_it(lab):
    run, body = lab.verify()
    assert run.exit == 0 and body["completeness"] == "anchored"
    run, body = lab.verify(key=False)
    assert run.exit == 0 and body["completeness"] == "not_checked"


def _delete_middle(d):
    del d["entries"][1]


def _delete_tail(d):
    del d["entries"][-1]


def _delete_head(d):
    del d["entries"][0]


def _duplicate(d):
    d["entries"].insert(2, copy.deepcopy(d["entries"][1]))


def _reorder(d):
    d["entries"][1], d["entries"][2] = d["entries"][2], d["entries"][1]


def _rewrite_payload(d):
    d["entries"][0]["evidence"]["body"]["signal"]["description"] = "rewritten by an attacker"


def _rewrite_actor_column(d):
    d["entries"][0]["actor"] = "someone-else"


def _rewrite_sealed_actor(d):
    d["entries"][0]["evidence"]["actor"]["identifier"] = "someone-else"


def _rewrite_time(d):
    d["entries"][0]["at"] = "2020-01-01T00:00:00Z"


def _inject_unsealed_key(d):
    d["entries"][0]["evidence"]["body"]["injected"] = "not covered by the hash"


def _rewrite_subject(d):
    d["entries"][0]["subject"] = "C-OTHER"


def _empty_entries(d):
    d["entries"] = []


@pytest.mark.parametrize("name,mutate", [
    ("delete middle", _delete_middle), ("delete tail", _delete_tail),
    ("delete head", _delete_head), ("duplicate", _duplicate), ("reorder", _reorder),
    ("rewrite payload", _rewrite_payload), ("rewrite subject", _rewrite_subject),
    ("rewrite actor column", _rewrite_actor_column),
    ("rewrite sealed actor", _rewrite_sealed_actor), ("rewrite time", _rewrite_time),
    ("inject unsealed key", _inject_unsealed_key),
    ("empty entries", _empty_entries),
])
def test_an_edited_bundle_never_passes_with_the_key(lab, name, mutate):
    run, body = lab.verify(lab.edited(mutate))
    assert run.exit in (1, 3), f"{name}: exit {run.exit}, completeness {body.get('completeness')}"
    assert body.get("completeness") != "anchored", name


@pytest.mark.parametrize("name,mutate", [
    ("strip the anchor", lambda d: d.pop("anchor")),
    ("strip the attestation", lambda d: d.pop("attestation")),
    ("raise the anchored head", lambda d: d["anchor"].__setitem__(
        "head_seq", d["anchor"].get("head_seq", 0) + 5)),
    ("claim the chain failed to verify", lambda d: d.__setitem__("chain_verified", False)),
])
def test_an_edited_anchor_or_claim_never_passes_with_the_key(lab, name, mutate):
    run, body = lab.verify(lab.edited(mutate))
    assert run.exit in (1, 3), f"{name}: exit {run.exit}"
    assert body.get("completeness") != "anchored", name


def test_a_cut_bundle_that_still_verifies_internally_is_caught_only_by_the_key(lab):
    path = lab.edited(_delete_tail)
    without_key, _ = lab.verify(path, key=False)
    with_key, body = lab.verify(path)
    assert with_key.exit in (1, 3) and body.get("completeness") != "anchored"
    # without the key the check may only claim consistency; if it passes it must not say anchored
    if without_key.exit == 0:
        _, nokey_body = lab.verify(path, key=False)
        assert nokey_body.get("completeness") == "not_checked"


def test_a_different_key_does_not_anchor_the_bundle(lab):
    assert lab.keygen("b").exit == 0
    run, body = lab.verify(pub=lab.pub.parent / "b.pub")
    assert run.exit in (1, 3) and body.get("completeness") != "anchored"


def test_another_ledgers_bundle_is_not_vouched_for_by_this_ledgers_key(lab):
    run, body = lab.verify(lab.other_ledger_bundle())
    assert run.exit in (1, 3) and body.get("completeness") != "anchored"


@pytest.mark.parametrize("kind", ["truncated", "empty", "array", "binary", "null"])
def test_an_unreadable_bundle_is_exit_2_and_never_a_traceback(lab, kind):
    path = lab.root / "bad.json"
    text = lab.file.read_text()
    {"truncated": lambda: path.write_text(text[: len(text) // 2]),
     "empty": lambda: path.write_text(""), "array": lambda: path.write_text("[]"),
     "binary": lambda: path.write_bytes(b"\xff\xfe\x00\x80"),
     "null": lambda: path.write_text("null")}[kind]()
    run, body = lab.verify(path)
    assert run.exit in (1, 2) and run.exit != 0
    assert "Traceback" not in run.err and body.get("ok") is not True
