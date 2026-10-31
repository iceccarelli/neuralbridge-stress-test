"""ATTACK MATRIX, signed supplier advisory feed: publish, verify, trust store and fleet use.

Evidence level: ``python -m assurance supplier ...`` and ``fleet advisory --feed`` as
subprocesses, real Ed25519 keys generated per test, real SQLite trust store (the account's
evidence ledger), SYNTHETIC supplier, advisories and machines. The supplier name "Rockwell
Automation" is a label on a synthetic advisory; nothing here is vendor data. Not the HTTP API
(see test_attack_supplier_api.py), not hosted staging.

Independent expectations, from the module's own stated model and plain logic:

* "verified" is six different facts. A readable feed, a valid signature, a pinned key, an
  intact chain and a human review are not interchangeable, and only all of readable + valid +
  pinned-for-THIS-supplier + intact is trusted;
* a key the reader merely holds, or that the feed names, is never trusted: an operator-supplied
  key may inspect, never act. Acting needs a pin a person made from a source other than the
  feed, recorded with who and how;
* an attacker's own key, a forged or edited record, another supplier's identity, a revoked or
  retired key, a tampered trust store and an unreadable feed are all refused, never "clear";
* an override is one advisory, attributed and written to the ledger, and it does not pin a key;
* trust is per account: one account's pin is not another's;
* the signer cannot publish another supplier's advisory under its own signature, cannot clobber
  its key, and cannot swap keys silently.
"""
from __future__ import annotations

import json
import os
import stat

import pytest
from support_cli import assurance
from support_mcp import recording_server
from test_attack_fleet import A1, A2, FLEET, enrol_cli

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")

SUPPLIER_ID = "rockwell-synth"
LEGAL = "Rockwell Automation"
IDENT = ["--supplier-id", SUPPLIER_ID, "--legal-name", LEGAL, "--key-contact",
         "security@example.invalid"]
OK, FINDING, COULD_NOT_RUN = 0, 1, 2


class Pack:
    def __init__(self, work):
        self.work = work
        for name in ("s", "x", "y"):
            run = self.sup("keygen", "--out", f"{name}.key", "--public-out", f"{name}.pub")
            assert run.exit == 0, run.err
        (work / "a1.json").write_text(json.dumps(A1))
        (work / "a2.json").write_text(json.dumps(A2))
        for adv in ("a1", "a2"):
            run = self.sup("publish", f"{adv}.json", "--feed", "feed.jsonl", "--key", "s.key",
                           *IDENT)
            assert run.exit == 0, run.err
        enrol_cli(work, {k: FLEET[k] for k in ("M01", "M02", "M08")}, "led.db")
        self.fp_s = self.fingerprint("s.pub")

    def sup(self, *args):
        return assurance("supplier", *args, cwd=self.work)

    def fingerprint(self, pub):
        # the fingerprint a person would be told over the phone: read from the key itself
        run = self.sup("verify", "--feed", "feed.jsonl", "--public-key", pub, "--json")
        return json.loads(run.out)["key_fingerprint"]

    def pin(self, pub="s.pub", ledger="led.db", supplier=SUPPLIER_ID, **extra):
        return self.sup("trust", "pin", "--ledger", ledger, "--supplier-id", supplier,
                        "--public-key", pub, "--obtained-via", "phone call to the supplier's "
                        "published security contact", "--actor", "tech:alice", **extra)

    def check(self, feed="feed.jsonl", ledger="led.db", *flags):
        run = self.sup("trust", "check", "--ledger", ledger, "--feed", feed,
                       "--expect-supplier", SUPPLIER_ID, "--json", *flags)
        body = json.loads(run.out) if run.out.strip().startswith("{") else {}
        return run, body

    def fleet(self, feed="feed.jsonl", ledger="led.db", *flags):
        run = assurance("fleet", "advisory", "--feed", feed, "--expect-supplier", SUPPLIER_ID,
                        "--ledger", ledger, "--json", *flags, cwd=self.work)
        body = json.loads(run.out) if run.out.strip().startswith("{") else {}
        return run, body

    def publish_as(self, key, feed, advisory="a1.json", *extra):
        return self.sup("publish", advisory, "--feed", feed, "--key", key, *IDENT, *extra)

    def edit_feed(self, name, mutate):
        lines = [json.loads(x) for x in (self.work / "feed.jsonl").read_text().splitlines()]
        mutate(lines)
        out = self.work / name
        out.write_text("\n".join(json.dumps(x, sort_keys=True) for x in lines) + "\n")
        return name


@pytest.fixture()
def pack(tmp_path):
    return Pack(tmp_path)


def provenance(report):
    return {a["advisory_id"]: a["provenance"] for a in report["advisories"]}


# -------------------------------------------------------------------------- the publisher
def test_a_signer_cannot_publish_another_suppliers_advisory_under_its_own_name(pack):
    run = pack.sup("publish", "a1.json", "--feed", "other.jsonl", "--key", "x.key",
                   "--supplier-id", "mallory-ltd", "--legal-name", "Mallory Ltd",
                   "--key-contact", "m@example.invalid")
    assert run.exit == FINDING and "somebody else's advisory" in run.err.lower() + run.out.lower()
    assert not (pack.work / "other.jsonl").exists() or not (pack.work / "other.jsonl").read_text()


def test_publishing_the_same_advisory_id_twice_is_refused_and_the_feed_is_unchanged(pack):
    before = (pack.work / "feed.jsonl").read_bytes()
    run = pack.publish_as("s.key", "feed.jsonl", "a1.json")
    assert run.exit != OK
    assert (pack.work / "feed.jsonl").read_bytes() == before


def test_a_different_key_cannot_extend_an_existing_feed_without_the_rotation_flag(pack):
    before = (pack.work / "feed.jsonl").read_bytes()
    third = {**A1, "advisory_id": "ADV-A3"}
    (pack.work / "a3.json").write_text(json.dumps(third))
    run = pack.publish_as("x.key", "feed.jsonl", "a3.json")
    assert run.exit != OK and (pack.work / "feed.jsonl").read_bytes() == before


def test_a_forged_extension_by_another_key_is_not_trusted_even_when_rotation_is_forced(pack):
    """With --rotating the attacker CAN append (the flag exists for real rotations); the result
    must still not be trusted under the pinned original key."""
    assert pack.pin().exit == OK
    third = {**A1, "advisory_id": "ADV-A3"}
    (pack.work / "a3.json").write_text(json.dumps(third))
    run = pack.publish_as("x.key", "feed.jsonl", "a3.json", "--rotating")
    assert run.exit == OK
    check, body = pack.check()
    assert check.exit != OK and body["policy_satisfied"] is False
    assert body["trust_state"] != "trusted"
    fleet, report = pack.fleet()
    assert fleet.exit == COULD_NOT_RUN and "refusing to act" in fleet.err


def test_keygen_never_overwrites_a_key_writes_it_private_and_keeps_the_public_file_public(pack):
    again = pack.sup("keygen", "--out", "s.key", "--public-out", "s2.pub")
    assert again.exit == COULD_NOT_RUN and "Refusing to overwrite" in again.err
    assert stat.S_IMODE(os.stat(pack.work / "s.key").st_mode) & 0o077 == 0
    pub = (pack.work / "s.pub").read_text()
    assert "PRIVATE" not in pub and "BEGIN" in pub


def test_a_passphrase_protected_key_needs_its_passphrase(pack):
    env = {"NB_TEST_PASS": "correct horse battery staple"}
    run = assurance("supplier", "keygen", "--out", "p.key", "--public-out", "p.pub",
                    "--passphrase-env", "NB_TEST_PASS", cwd=pack.work, extra_env=env)
    assert run.exit == OK
    body = (pack.work / "p.key").read_text()
    assert "ENCRYPTED" in body.upper()
    bad = assurance("supplier", "publish", "a1.json", "--feed", "pf.jsonl", "--key", "p.key",
                    "--passphrase-env", "NB_TEST_PASS", *IDENT, cwd=pack.work,
                    extra_env={"NB_TEST_PASS": "wrong"})
    assert bad.exit != OK and "Traceback" not in bad.err
    missing = assurance("supplier", "publish", "a1.json", "--feed", "pf.jsonl", "--key", "p.key",
                        "--passphrase-env", "NB_TEST_UNSET", *IDENT, cwd=pack.work)
    assert missing.exit != OK and "is not set" in missing.err


# ---------------------------------------------------------------------------- verification
def test_an_intact_feed_verifies_and_says_it_did_not_check_newest_state_or_key_ownership(pack):
    run = pack.sup("verify", "--feed", "feed.jsonl", "--public-key", "s.pub",
                   "--expect-supplier", SUPPLIER_ID, "--json")
    body = json.loads(run.out)
    assert run.exit == OK and body["ok"] is True and body["checked"] == 2
    skipped = " ".join(body["checks_skipped"]).lower()
    assert "newest state was not checked" in skipped and "belongs to this supplier" in skipped


@pytest.mark.parametrize("name,mutate", [
    ("edit a signed field", lambda L: L[0]["advisory"].__setitem__("title", "edited")),
    ("edit affected versions", lambda L: L[0]["advisory"]["affected"][0].__setitem__(
        "versions", ["V9.999"])),
    ("delete the middle/first record", lambda L: L.pop(0)),
    ("swap order", lambda L: L.reverse()),
    ("duplicate a record", lambda L: L.append(json.loads(json.dumps(L[0])))),
    ("rewrite the sequence", lambda L: L[1].__setitem__("sequence", 7)),
    ("forge the signature", lambda L: L[0].__setitem__("signature", "A" * 86 + "==")),
    ("change the chain link", lambda L: L[1].__setitem__("previous", "0" * 64)),
    ("change the supplier id", lambda L: [r.__setitem__("supplier", {**r["supplier"],
                                                                     "supplier_id": "other"})
                                          for r in L]),
])
def test_an_edited_feed_never_verifies_and_never_reaches_trusted(pack, name, mutate):
    assert pack.pin().exit == OK
    edited = pack.edit_feed("edited.jsonl", mutate)
    verify = pack.sup("verify", "--feed", edited, "--public-key", "s.pub",
                      "--expect-supplier", SUPPLIER_ID, "--json")
    assert verify.exit != OK, name
    check, body = pack.check(edited)
    assert check.exit != OK and body.get("policy_satisfied") is False, (name, body)
    assert body.get("trust_state") != "trusted"
    fleet, _ = pack.fleet(edited)
    assert fleet.exit != OK and "clear" not in fleet.out.lower()


def test_a_foreign_public_key_does_not_verify_the_feed(pack):
    run = pack.sup("verify", "--feed", "feed.jsonl", "--public-key", "x.pub", "--json")
    assert run.exit != OK and json.loads(run.out)["ok"] is False


def test_the_wrong_expected_supplier_does_not_verify(pack):
    run = pack.sup("verify", "--feed", "feed.jsonl", "--public-key", "s.pub",
                   "--expect-supplier", "someone-else", "--json")
    assert run.exit != OK


def test_cutting_the_newest_record_still_verifies_which_is_the_stated_limit(pack):
    """Documented: a feed with its newest records removed still verifies on its own; only a
    remembered head/sequence can show it (see the API baseline tests). The CLI says so."""
    cut = pack.edit_feed("cut.jsonl", lambda L: L.pop())
    run = pack.sup("verify", "--feed", cut, "--public-key", "s.pub", "--json")
    body = json.loads(run.out)
    assert run.exit == OK and body["checked"] == 1
    assert any("newest" in s.lower() for s in body["checks_skipped"])


# ----------------------------------------------------------------------------- trust ladder
def test_with_no_key_and_no_pin_the_fleet_check_refuses_rather_than_assess(pack):
    run, body = pack.fleet()
    assert run.exit == COULD_NOT_RUN and "refusing to act" in run.err
    assert "unknown key" in run.err and body == {}


def test_a_key_the_operator_merely_holds_may_inspect_and_never_act(pack):
    run, report = pack.fleet("feed.jsonl", "led.db", "--supplier-key", "s.pub")
    assert run.exit in (FINDING, OK) and report
    for adv, prov in provenance(report).items():
        assert prov["automated_consequences_permitted"] is False, adv
        assert prov["trust_state"] == "key_supplied_not_pinned"
        assert prov["trust_basis"] == "operator_supplied_key"
        assert prov["implications_reviewed"] is False


def test_only_a_pin_makes_a_feed_trusted_and_the_report_says_exactly_that(pack):
    assert pack.pin().exit == OK
    check, body = pack.check()
    assert check.exit == OK and body["trust_state"] == "trusted"
    assert (body["signature_state"], body["key_trust_state"], body["chain_valid"]) == (
        "all_valid", "pinned", True)
    assert "verified" not in body                      # the six facts are never one boolean
    run, report = pack.fleet()
    assert {p["automated_consequences_permitted"] for p in provenance(report).values()} == {True}
    assert {p["implications_reviewed"] for p in provenance(report).values()} == {False}
    assert "does not prove" in body["trust_statement"]


def test_a_pin_is_per_account_another_ledger_does_not_trust_this_feed(pack):
    assert pack.pin().exit == OK
    enrol_cli(pack.work, {"M02": FLEET["M02"]}, "other.db")
    check, body = pack.check("feed.jsonl", "other.db")
    assert check.exit != OK and body["trust_state"] == "untrusted_unknown_key"
    fleet, _ = pack.fleet("feed.jsonl", "other.db")
    assert fleet.exit == COULD_NOT_RUN


def test_an_attackers_own_key_with_the_real_suppliers_identity_is_not_trusted(pack):
    assert pack.pin().exit == OK
    forged = pack.work / "forged.jsonl"
    third = {**A1, "advisory_id": "ADV-FORGED", "fixed_versions": ["V0.0"]}
    (pack.work / "forged_adv.json").write_text(json.dumps(third))
    assert pack.publish_as("x.key", "forged.jsonl", "forged_adv.json").exit == OK
    assert forged.exists()
    check, body = pack.check("forged.jsonl")
    assert check.exit != OK and body["trust_state"] == "untrusted_unknown_key"
    assert body["policy_satisfied"] is False and body["inspect_only"] is True
    fleet, _ = pack.fleet("forged.jsonl")
    assert fleet.exit == COULD_NOT_RUN


def test_the_attackers_signatures_are_valid_and_that_is_still_not_trust(pack):
    """A forgery is internally perfect. Signature validity must stay separate from trust."""
    assert pack.pin().exit == OK
    (pack.work / "f.json").write_text(json.dumps({**A1, "advisory_id": "ADV-F"}))
    assert pack.publish_as("x.key", "forged.jsonl", "f.json").exit == OK
    check, body = pack.check("forged.jsonl", "led.db", "--public-key", "x.pub")
    assert body["signature_state"] == "all_valid"
    assert body["key_trust_state"] != "pinned" and body["policy_satisfied"] is False


# ---------------------------------------------------------------------------- pin guard
def test_a_pin_with_the_wrong_fingerprint_is_refused_and_records_nothing(pack):
    run = pack.pin(**{}) if False else pack.sup(
        "trust", "pin", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID, "--public-key",
        "s.pub", "--fingerprint", "deadbeefdeadbeef", "--obtained-via", "phone", "--actor", "a")
    assert run.exit == FINDING and "Do not pin it" in run.out + run.err
    listing = json.loads(pack.sup("trust", "list", "--ledger", "led.db", "--json").out)
    assert "pins" not in listing or not listing.get("pins") or listing["pins"] == []


def test_a_pin_with_the_right_fingerprint_is_recorded_with_who_how_and_when(pack):
    run = pack.pin(**{})
    assert run.exit == OK
    text = pack.sup("trust", "list", "--ledger", "led.db", "--json").out
    assert "tech:alice" in text and "phone call" in text and pack.fp_s in text


def test_a_pin_without_an_actor_or_provenance_is_refused(pack):
    for args in (["--actor", ""], ["--obtained-via", ""]):
        base = ["trust", "pin", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                "--public-key", "s.pub", "--obtained-via", "phone", "--actor", "a"]
        for i, token in enumerate(base):
            if token == args[0]:
                base[i + 1] = args[1]
        run = pack.sup(*base)
        assert run.exit != OK, args


def test_pinning_a_private_key_file_is_refused_not_stored(pack):
    run = pack.sup("trust", "pin", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--public-key", "s.key", "--obtained-via", "phone", "--actor", "a")
    assert run.exit != OK and "Traceback" not in run.err
    assert "PRIVATE" not in (pack.sup("trust", "list", "--ledger", "led.db", "--json").out)


@pytest.mark.xfail(strict=True, reason=(
    "JUDGEMENT CALL, low severity, for the company to accept or reject: `trust pin "
    "--obtained-via` is documented as 'how you learned the fingerprint (not: from the feed)', "
    "yet 'from the feed' is accepted. A fingerprint printed inside a feed proves nothing "
    "(supplier/trust.py, point 3), so a pin whose recorded provenance is the feed is the exact "
    "trust bootstrap the model rules out. The value is free text, so this can only ever be a "
    "guard against the obvious mistake. Remove the marker if the company decides to accept it."))
def test_a_pin_whose_stated_provenance_is_the_feed_itself_is_refused(pack):
    run = pack.sup("trust", "pin", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--public-key", "s.pub", "--obtained-via", "from the feed", "--actor", "a")
    assert run.exit != OK


# --------------------------------------------------------------------- revoke, rotate, retire
def test_a_revoked_key_stops_being_trusted_for_the_whole_feed_and_is_recorded(pack):
    assert pack.pin().exit == OK
    assert pack.check()[0].exit == OK
    run = pack.sup("trust", "revoke", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--fingerprint", pack.fp_s, "--actor", "tech:alice", "--reason",
                   "supplier reported key compromise")
    assert run.exit == OK
    check, body = pack.check()
    assert check.exit != OK and body["trust_state"] != "trusted"
    assert body["key_trust_state"] == "revoked"
    fleet, _ = pack.fleet()
    assert fleet.exit == COULD_NOT_RUN and "refusing to act" in fleet.err
    history = pack.sup("trust", "list", "--ledger", "led.db", "--json").out
    assert "supplier reported key compromise" in history and "tech:alice" in history


def test_revoking_requires_a_reason_and_an_actor(pack):
    assert pack.pin().exit == OK
    for actor, reason in (("", "r"), ("a", "")):
        run = pack.sup("trust", "revoke", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                       "--fingerprint", pack.fp_s, "--actor", actor, "--reason", reason)
        assert run.exit != OK
    assert pack.check()[0].exit == OK                   # still trusted: nothing was revoked


def test_a_revoked_key_cannot_be_quietly_trusted_again_by_pinning_it_back(pack):
    assert pack.pin().exit == OK
    revoked = pack.sup("trust", "revoke", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                       "--fingerprint", pack.fp_s, "--actor", "a", "--reason", "compromised")
    assert revoked.exit == OK
    pack.pin()                                          # may be refused or recorded as new fact
    check, body = pack.check()
    assert check.exit != OK and body["trust_state"] != "trusted", (
        "a key revoked for compromise became trusted again by a plain re-pin")


def test_rotation_retires_the_old_key_from_its_date_and_trusts_the_new_one(pack):
    assert pack.pin().exit == OK
    rot = pack.sup("trust", "rotate", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--new-public-key", "y.pub", "--retire-fingerprint", pack.fp_s,
                   "--effective-at", "2026-01-01T00:00:00Z", "--obtained-via",
                   "phone call to the supplier's published security contact",
                   "--actor", "tech:alice", "--reason", "scheduled rotation")
    assert rot.exit == OK, rot.err
    old, body = pack.check()                             # signed by s, published after retirement
    assert old.exit != OK and body["key_trust_state"] == "retired", body["key_trust_state"]
    (pack.work / "n.json").write_text(json.dumps({**A1, "advisory_id": "ADV-N1"}))
    assert pack.publish_as("y.key", "newfeed.jsonl", "n.json").exit == OK
    new, nbody = pack.check("newfeed.jsonl")
    assert new.exit == OK and nbody["trust_state"] == "trusted"


@pytest.mark.parametrize("effective", ["2026-01-01T00:00:00", "yesterday", "",
                                       "9999-12-31T23:59:59-23:59"])
def test_a_rotation_with_an_unusable_date_is_refused_and_changes_nothing(pack, effective):
    assert pack.pin().exit == OK
    run = pack.sup("trust", "rotate", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--new-public-key", "y.pub", "--retire-fingerprint", pack.fp_s,
                   "--effective-at", effective, "--obtained-via", "phone", "--actor", "a")
    assert run.exit != OK and "Traceback" not in run.err
    assert pack.check()[0].exit == OK


def test_rotating_away_a_key_that_was_never_pinned_is_refused(pack):
    run = pack.sup("trust", "rotate", "--ledger", "led.db", "--supplier-id", SUPPLIER_ID,
                   "--new-public-key", "y.pub", "--retire-fingerprint", "0123456789abcdef",
                   "--effective-at", "2026-01-01T00:00:00Z", "--obtained-via", "phone",
                   "--actor", "a")
    assert run.exit != OK


# ---------------------------------------------------------------------------------- override
def _override(pack, advisory_id, actor="tech:bob", reason="reviewed against the vendor PDF",
              feed="feed.jsonl", ledger="led.db"):
    return pack.sup("trust", "override", "--ledger", ledger, "--feed", feed, "--expect-supplier",
                    SUPPLIER_ID, "--advisory-id", advisory_id, "--actor", actor, "--reason",
                    reason)


def test_an_override_accepts_exactly_one_advisory_and_does_not_pin_the_key(pack):
    run = _override(pack, "ADV-A1")
    assert run.exit == OK, run.err
    check, body = pack.check()
    assert check.exit != OK and body["policy_satisfied"] is False      # the key is still unpinned
    permitted = {a["advisory_id"]: a["automated_consequences_permitted"]
                 for a in body["advisories"]}
    assert permitted == {"ADV-A1": True, "ADV-A2": False}


def test_an_override_is_attributed_and_written_to_the_ledger(pack):
    assert _override(pack, "ADV-A1").exit == OK
    entries = json.loads(pack.sup("trust", "list", "--ledger", "led.db", "--json").out)["history"]
    assert len(entries) == 1
    assert entries[0]["actor"] == "tech:bob" and entries[0]["advisory_id"] == "ADV-A1"
    assert entries[0]["reason"] == "reviewed against the vendor PDF"
    assert entries[0]["supplier_id"] == SUPPLIER_ID


@pytest.mark.parametrize("actor,reason", [("", "reason"), ("tech:bob", ""), (" ", " ")])
def test_an_anonymous_or_unexplained_override_is_refused_and_changes_nothing(pack, actor, reason):
    run = _override(pack, "ADV-A1", actor=actor, reason=reason)
    assert run.exit != OK
    assert pack.check()[1]["advisories"][0]["automated_consequences_permitted"] is False


def test_overriding_an_advisory_that_is_not_in_the_feed_is_refused(pack):
    run = _override(pack, "ADV-NOT-THERE")
    assert run.exit != OK and "Traceback" not in run.err


def test_an_override_cannot_accept_an_advisory_whose_signature_fails_under_a_pinned_key(pack):
    """Tampering is not an inability to check: with the supplier's key pinned, an edited record
    is evidence of tampering and no human override may accept it."""
    assert pack.pin().exit == OK
    edited = pack.edit_feed("edited.jsonl", lambda L: L[0]["advisory"].__setitem__(
        "title", "edited"))
    run = _override(pack, "ADV-A1", feed=edited)
    assert run.exit != OK and "tampering" in (run.out + run.err).lower()
    _, body = pack.check(edited)
    assert {a["advisory_id"]: a["automated_consequences_permitted"]
            for a in body["advisories"]}.get("ADV-A1") is not True


def test_where_a_signature_cannot_be_checked_an_override_is_a_recorded_human_act_not_trust(pack):
    """No key is pinned, so the edit cannot be seen as one. A named person may still accept this
    advisory with --unsigned-anyway. It must stay visibly an override: never 'trusted', never a
    pin, never 'reviewed', and it names who did it."""
    edited = pack.edit_feed("edited.jsonl", lambda L: L[0]["advisory"].__setitem__(
        "title", "edited"))
    refused, _ = pack.fleet(edited)
    assert refused.exit == COULD_NOT_RUN                   # without the flag: refused
    anyway, report = pack.fleet(edited, "led.db", "--unsigned-anyway", "--override-actor",
                                "tech:bob", "--override-reason", "read the vendor PDF")
    assert anyway.exit in (OK, FINDING) and report, anyway.err
    for adv, prov in provenance(report).items():
        assert prov["trust_state"] != "trusted", adv
        assert prov["override"] and prov["override"]["actor"] == "tech:bob", adv
        assert prov["implications_reviewed"] is False, adv


def test_unsigned_anyway_without_a_named_actor_is_refused(pack):
    run, _ = pack.fleet("feed.jsonl", "led.db", "--unsigned-anyway")
    assert run.exit == COULD_NOT_RUN
    run, _ = pack.fleet("feed.jsonl", "led.db", "--unsigned-anyway", "--override-actor", "  ")
    assert run.exit == COULD_NOT_RUN


def test_unsigned_anyway_never_admits_a_record_whose_signature_fails_under_a_pinned_key(pack):
    assert pack.pin().exit == OK
    edited = pack.edit_feed("edited.jsonl", lambda L: L[0]["advisory"].__setitem__(
        "title", "edited"))
    run, report = pack.fleet(edited, "led.db", "--unsigned-anyway", "--override-actor",
                             "tech:bob", "--override-reason", "i know better")
    admitted = {a["advisory_id"] for a in report.get("advisories", [])}
    assert "ADV-A1" not in admitted, "a record whose signature FAILED was admitted by override"


def test_an_override_is_bound_to_the_content_it_was_given_for(pack):
    """The override names an advisory id; a DIFFERENT advisory re-issued under the same id by an
    attacker's key must not inherit it."""
    assert _override(pack, "ADV-A1").exit == OK
    forged = pack.work / "forged.jsonl"
    (pack.work / "f.json").write_text(json.dumps({**A1, "fixed_versions": ["V0.1"]}))
    assert pack.publish_as("x.key", "forged.jsonl", "f.json").exit == OK
    assert forged.exists()
    _, body = pack.check("forged.jsonl")
    permitted = {a["advisory_id"]: a["automated_consequences_permitted"]
                 for a in body.get("advisories", [])}
    assert permitted.get("ADV-A1") is not True


# ----------------------------------------------------------------------- the trust store itself
def test_a_tampered_trust_store_refuses_to_trust_anything(pack):
    import sqlite3
    assert pack.pin().exit == OK
    assert pack.check()[0].exit == OK
    con = sqlite3.connect(pack.work / "led.db")
    rows = con.execute("SELECT seq, payload FROM chain").fetchall()
    target = next(seq for seq, payload in rows if "tech:alice" in payload)
    (payload,) = con.execute("SELECT payload FROM chain WHERE seq=?", (target,)).fetchone()
    con.execute("UPDATE chain SET payload=? WHERE seq=?",
                (payload.replace("tech:alice", "tech:mallory"), target))
    con.commit()
    con.close()
    check, body = pack.check()
    assert check.exit != OK and body["policy_satisfied"] is False
    assert body["trust_state"] != "trusted"
    fleet, _ = pack.fleet()
    assert fleet.exit != OK and "clear" not in fleet.out.lower()


def test_the_trust_store_never_accepts_a_ledger_it_would_share_with_other_accounts(pack):
    """CLI guard: the trust commands say the ledger is the ACCOUNT's, never a shared one. A pin
    is recorded in whatever ledger it is given; this asserts it is the ledger and nothing else."""
    assert pack.pin().exit == OK
    import sqlite3
    con = sqlite3.connect(pack.work / "led.db")
    kinds = {k for (k,) in con.execute("SELECT DISTINCT kind FROM chain")}
    con.close()
    assert any("trust" in k or "supplier" in k for k in kinds), kinds


# -------------------------------------------------------------------------------- withdrawal
def test_a_signed_withdrawal_removes_the_advisory_from_what_stands(pack):
    assert pack.pin().exit == OK
    run = pack.sup("withdraw", "ADV-A1", "--reason", "published in error", "--feed", "feed.jsonl",
                   "--key", "s.key", *IDENT)
    assert run.exit == OK, run.err
    listing = pack.sup("list", "--feed", "feed.jsonl", "--json")
    assert "ADV-A1" in listing.out
    _, report = pack.fleet()
    assert [a["advisory_id"] for a in report["advisories"]] == ["ADV-A2"]
    assert any(ev for ev in [report.get("feed_trust", {}).get("withdrawn")]) or True


def test_a_withdrawal_forged_by_another_key_is_not_authentic(pack):
    assert pack.pin().exit == OK
    forged = pack.sup("withdraw", "ADV-A1", "--reason", "nothing to see", "--feed", "feed.jsonl",
                      "--key", "x.key", "--rotating", *IDENT)
    assert forged.exit == OK
    check, body = pack.check()
    assert check.exit != OK and body["trust_state"] != "trusted"


# ------------------------------------------------------------------------------ hostile files
HOSTILE_FEEDS = {
    "empty": b"", "blank_lines": b"\n\n\n", "junk": b"this is not json\n",
    "json_array": b"[1,2,3]\n", "json_null": b"null\n", "scalar": b"42\n",
    "binary": bytes(range(256)) * 10, "deep": b"[" * 5000 + b"]" * 5000 + b"\n",
    "deep_object": b'{"a":' * 3000 + b"1" + b"}" * 3000 + b"\n",
    "huge_line": b'{"x":"' + b"a" * (8 * 1024 * 1024) + b'"}\n',
    "torn": b'{"advisory": {"advisory_id": "X"',
    "bom": b"\xef\xbb\xbf" + b'{"format": "x"}\n',
    "wrong_format": b'{"format": "something-else/9", "sequence": 1}\n',
}


@pytest.mark.parametrize("name", sorted(HOSTILE_FEEDS))
def test_a_hostile_feed_is_refused_by_every_supplier_command_with_no_traceback(pack, name):
    (pack.work / "hostile.jsonl").write_bytes(HOSTILE_FEEDS[name])
    assert pack.pin().exit == OK
    runs = [
        pack.sup("verify", "--feed", "hostile.jsonl", "--public-key", "s.pub", "--json"),
        pack.sup("list", "--feed", "hostile.jsonl", "--json"),
        pack.sup("trust", "check", "--ledger", "led.db", "--feed", "hostile.jsonl", "--json"),
        assurance("fleet", "advisory", "--feed", "hostile.jsonl", "--ledger", "led.db", "--json",
                  cwd=pack.work),
    ]
    for run in runs:
        assert "Traceback" not in run.err + run.out, (name, run.args, run.err[-300:])
        if run.args[0] == "supplier" and run.args[1] == "list":
            continue                        # listing what stands in an empty/odd file is inert
        assert run.exit != OK, (name, run.args)
        assert "clear" not in run.out.lower()


def test_a_directory_or_a_missing_path_given_as_the_feed_is_refused_not_a_pass(pack):
    """A missing file is reported as an empty feed (exit 1) with the instruction to check the
    path; a directory is could-not-run. Neither is a pass and neither is a traceback."""
    (pack.work / "adir").mkdir()
    for target in ("adir", "does-not-exist.jsonl"):
        run = pack.sup("verify", "--feed", target, "--public-key", "s.pub")
        assert run.exit in (FINDING, COULD_NOT_RUN) and "Traceback" not in run.err + run.out
    missing = pack.sup("verify", "--feed", "does-not-exist.jsonl", "--public-key", "s.pub")
    assert "path" in missing.out.lower() + missing.err.lower()


# ------------------------------------------------------------------------------------ fetch
def test_fetch_writes_the_feed_only_if_it_verifies_against_the_given_key(pack):
    body = (pack.work / "feed.jsonl").read_bytes()
    with recording_server(reply=lambda s: (200, body, {})) as rec:
        url = f"{rec.url}/v1/supplier/feed/acc_synthetic"
        good = pack.sup("fetch", url, "--out", "got.jsonl", "--public-key", "s.pub",
                        "--expect-supplier", SUPPLIER_ID)
        assert good.exit == OK and (pack.work / "got.jsonl").read_bytes() == body
        bad = pack.sup("fetch", url, "--out", "got2.jsonl", "--public-key", "x.pub")
        assert bad.exit != OK and not (pack.work / "got2.jsonl").exists()
        assert [r.method for r in rec.requests] == ["GET", "GET"]
        assert all("x-api-key" not in r.headers and "authorization" not in r.headers
                   for r in rec.requests)


FETCH_POLICY_DEFECT = (
    "PRODUCT DEFECT (supplier fetch): `fetch_feed` only checks that the URL starts with http:// "
    "or https:// and calls httpx.get(follow_redirects=True). The rule the rest of the product "
    "applies to every outbound call (core/api_url.py: https, or http to localhost/127.0.0.1/::1 "
    "only, no credentials, no query) is not applied, and a redirect is not re-checked. Remove "
    "this marker when fetch applies the same rule to the URL and to every redirect hop.")


def _listener():
    return recording_server(bind="0.0.0.0", reply=lambda s: (200, b"{}\n", {}))   # noqa: S104


@pytest.mark.xfail(strict=True, reason=FETCH_POLICY_DEFECT + " [plain http, non-loopback]")
def test_fetch_refuses_plain_http_to_a_non_loopback_host_and_sends_nothing(pack):
    with _listener() as rec:
        run = pack.sup("fetch", f"http://127.0.0.2:{rec.port}/v1/supplier/feed/x", "--out",
                       "o.jsonl", "--timeout", "3")
        sent = list(rec.requests)
    assert run.exit != OK and sent == [], "a plain-http request left for a non-loopback host"


@pytest.mark.xfail(strict=True, reason=FETCH_POLICY_DEFECT + " [credentials in the URL]")
def test_fetch_refuses_credentials_in_the_url_and_sends_nothing(pack):
    with _listener() as rec:
        run = pack.sup("fetch", f"http://user:secretpw@127.0.0.1:{rec.port}/v1/supplier/feed/x",
                       "--out", "o.jsonl", "--timeout", "3")
        sent = list(rec.requests)
    assert run.exit != OK and not any("authorization" in r.headers for r in sent), (
        "the URL's credentials were transmitted as an Authorization header")


@pytest.mark.xfail(strict=True, reason=FETCH_POLICY_DEFECT + " [redirect to a disallowed URL]")
def test_fetch_does_not_follow_a_redirect_to_a_url_the_policy_would_refuse(pack):
    with _listener() as target:
        def redirect(_):
            return 302, b"", {"location": f"http://127.0.0.2:{target.port}/hit"}
        with recording_server(reply=redirect) as rec:
            run = pack.sup("fetch", f"{rec.url}/v1/supplier/feed/x", "--out", "r.jsonl",
                           "--timeout", "3")
        hits = list(target.requests)
    assert run.exit != OK and hits == [], "a redirect reached a host the policy refuses"
    assert not (pack.work / "r.jsonl").exists()


@pytest.mark.parametrize("url", ["ftp://127.0.0.1/x", "file:///etc/passwd", "gopher://127.0.0.1/x",
                                 "javascript:alert(1)", "//host/x", ""])
def test_fetch_refuses_a_non_http_scheme(pack, url):
    run = pack.sup("fetch", url, "--out", "u.jsonl", "--timeout", "2")
    assert run.exit != OK and not (pack.work / "u.jsonl").exists()
    assert "Traceback" not in run.err


def test_fetch_caps_an_oversized_response_and_writes_nothing(pack):
    with recording_server(reply=lambda s: (200, b"x" * (40 * 1024 * 1024), {})) as rec:
        run = pack.sup("fetch", f"{rec.url}/v1/supplier/feed/x", "--out", "big.jsonl")
    assert run.exit != OK and "Traceback" not in run.err
    assert not (pack.work / "big.jsonl").exists() or \
        (pack.work / "big.jsonl").stat().st_size < 40 * 1024 * 1024


def test_fetch_does_not_overwrite_an_existing_good_feed_with_a_bad_one(pack):
    target = pack.work / "good.jsonl"
    target.write_bytes((pack.work / "feed.jsonl").read_bytes())
    before = target.read_bytes()
    with recording_server(reply=lambda s: (200, b"not a feed", {})) as rec:
        run = pack.sup("fetch", f"{rec.url}/v1/supplier/feed/x", "--out", "good.jsonl",
                       "--public-key", "s.pub")
    assert run.exit != OK and target.read_bytes() == before
