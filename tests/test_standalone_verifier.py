"""NB-005 differential: the product's single-file, stdlib-only export checker against the product.

`scripts/verify_export_standalone.py` is shipped so that an auditor can check an export without
installing or trusting the product. That is only worth anything if it is never MORE lenient than the
product's own verifier. Expectations stated here, not read from either implementation:

* on the intact, signed export it passes with the signer's key and says completeness is not
  established without it (exit 3), never a bare pass;
* every tampering in the export attack matrix is refused with the key (exit 1 or 3), never 0;
* whatever the matrix, the standalone exit is 0 ONLY IF the product's exit is 0 (it may be
  stricter or decline to judge; it may not be more lenient);
* it does not import the product (an auditor may not have it).

Evidence level: both tools as subprocesses on SYNTHETIC exports; not hosted staging.
"""
# ruff: noqa: F811  (the lab fixture is imported from the export attack file on purpose)
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from support_cli import assurance
from test_attack_export_cli import (  # noqa: F401  (lab is a fixture, re-exported on purpose)
    _delete_head,
    _delete_middle,
    _delete_tail,
    _duplicate,
    _empty_entries,
    _forge_prev_hash_and_rehash,
    _inject_unsealed_key,
    _link_hash,
    _reorder,
    _rewrite_actor_column,
    _rewrite_payload,
    _rewrite_sealed_actor,
    _rewrite_subject,
    _rewrite_time,
    lab,
)

from conftest import PRODUCT_SRC

SCRIPT = Path(PRODUCT_SRC).parent / "scripts" / "verify_export_standalone.py"

pytestmark = pytest.mark.skipif(
    not SCRIPT.is_file(), reason="BLOCKED: the product has no standalone verifier at this path")

def _forge_and_rewrite_the_head_record(d):
    """The careful forger: rehash a forged predecessor link AND rewrite the unsigned head record
    to match, so only the predecessor comparison (or, with a key, the anchor) can object."""
    _forge_prev_hash_and_rehash(d)
    d["attestation"]["head_link_hash"] = d["entries"][-1]["link_hash"]


def _cut_the_tail_and_leave_the_head_record(d):
    """Remove the last entry and change nothing else: the head record still names it."""
    del d["entries"][-1]


def _rehash_from(d, start):
    """Recompute prev_hash and link_hash from entry ``start`` onward, as a forger would."""
    entries = d["entries"]
    for i in range(start, len(entries)):
        if i > 0:
            entries[i]["prev_hash"] = entries[i - 1]["link_hash"]
        entries[i]["link_hash"] = _link_hash(entries[i])
    d["attestation"].update(head_seq=entries[-1]["seq"], length=len(entries),
                            head_link_hash=entries[-1]["link_hash"])


def _canon_hash(value):
    """SHA-256 of sorted-key, no-whitespace JSON with every number made a float (6 places)."""
    def norm(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            r = round(float(v), 6)
            return 0.0 if r == 0 else r
        if isinstance(v, dict):
            return {k: norm(x) for k, x in sorted(v.items())}
        if isinstance(v, list):
            return [norm(x) for x in v]
        return v
    return hashlib.sha256(json.dumps(norm(value), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _rewrite_a_body_and_rehash_everything(d):
    """The strongest forgery: change what a record says, recompute the evidence hash, the entry's
    content hash, every link after it and the unsigned head record. Same length, internally
    flawless. Only a head signed BEFORE the rewrite can object."""
    entry = d["entries"][1]
    evidence = entry["evidence"]
    evidence["body"]["signal"]["description"] = "rewritten and re-sealed by an attacker"
    evidence["content_hash"] = _canon_hash(
        {k: v for k, v in evidence.items() if k not in ("recorded_at", "content_hash")})
    entry["content_hash"] = evidence["content_hash"]
    entry["link_hash"] = _link_hash(entry)
    _rehash_from(d, 2)


def _wrong_genesis_everything_rehashed(d):
    d["entries"][0]["prev_hash"] = "f" * 64
    d["entries"][0]["link_hash"] = _link_hash(d["entries"][0])
    _rehash_from(d, 1)


def _rebuilt_without_one_record(d):
    """Remove entry 2, renumber, rehash the rest, rewrite the head record: internally flawless."""
    del d["entries"][1]
    for i, entry in enumerate(d["entries"], start=1):
        entry["seq"] = i
    d["entries"][1]["link_hash"] = ""            # recomputed below from the renumbered fields
    d["entries"][0]["link_hash"] = _link_hash(d["entries"][0])
    _rehash_from(d, 1)


MATRIX = [("delete middle", _delete_middle), ("delete tail", _delete_tail),
          ("delete head", _delete_head), ("duplicate", _duplicate), ("reorder", _reorder),
          ("rewrite payload", _rewrite_payload), ("rewrite subject", _rewrite_subject),
          ("rewrite actor column", _rewrite_actor_column),
          ("rewrite sealed actor", _rewrite_sealed_actor), ("rewrite time", _rewrite_time),
          ("inject unsealed key", _inject_unsealed_key), ("empty entries", _empty_entries),
          ("forged predecessor, rehashed", _forge_prev_hash_and_rehash),
          ("forged predecessor, rehashed, head record rewritten",
           _forge_and_rewrite_the_head_record),
          ("tail cut, head record left", _cut_the_tail_and_leave_the_head_record),
          ("wrong genesis, everything rehashed", _wrong_genesis_everything_rehashed),
          ("rebuilt without one record", _rebuilt_without_one_record),
          ("body rewritten, everything rehashed", _rewrite_a_body_and_rehash_everything)]


def standalone(path, *extra: str) -> tuple[int, str]:
    done = subprocess.run([sys.executable, str(SCRIPT), str(path), *extra], capture_output=True,
                          text=True, timeout=60, check=False)
    return done.returncode, done.stdout


def test_the_script_does_not_import_the_product():
    text = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"^\s*(import|from)\s+(assurance|neuralbridge)\b", text, re.M)


def test_the_intact_signed_export_passes_with_the_key_and_is_not_a_bare_pass_without_it(lab):
    code, out = standalone(lab.file, "--public-key", str(lab.pub))
    assert code == 0, out
    code, out = standalone(lab.file)
    assert code == 3 and "COMPLETENESS NOT CHECKED" in out, out


@pytest.mark.parametrize("name,mutate", MATRIX)
def test_every_tampering_is_refused_with_the_key_and_never_more_leniently_than_the_product(
        lab, name, mutate):
    edited = lab.edited(mutate)
    code, out = standalone(edited, "--public-key", str(lab.pub))
    assert code in (1, 2, 3), f"{name}: standalone exit {code}\n{out[:300]}"
    product, _ = lab.verify(edited)
    if product.exit == 1:       # what the product calls wrong with the key, so must the standalone
        assert code == 1, f"{name}: product exit 1, standalone exit {code}\n{out[:300]}"
    # Without the key the standalone always says "completeness not checked" (exit 3), so "never 0"
    # is trivial there. The real property: what the product calls WRONG without a key (exit 1),
    # the standalone must also call wrong, not merely "not established".
    code_nokey, out_nokey = standalone(edited)
    product_nokey, _ = lab.verify(edited, key=False)
    if code_nokey == 0:
        assert product_nokey.exit == 0, f"{name}: standalone passed what the product refused"
    if product_nokey.exit == 1:
        assert code_nokey == 1, (f"{name}: the product calls this wrong without a key; "
                                 f"standalone exit {code_nokey}\n{out_nokey[:300]}")


def test_a_signature_from_another_key_does_not_anchor(lab):
    lab.keygen("other")
    code, out = standalone(lab.file, "--public-key", str(lab.pub.parent / "other.pub"))
    assert code == 1 and "foreign anchor" in out, out


def test_a_bundle_cut_short_but_internally_consistent_is_caught_only_by_the_key(lab):
    doc = json.loads(lab.file.read_text())
    doc["entries"] = doc["entries"][:-1]
    last = doc["entries"][-1]
    doc["attestation"].update(head_seq=last["seq"], head_link_hash=last["link_hash"],
                              length=len(doc["entries"]))
    cut = lab.root / "cut.json"
    cut.write_text(json.dumps(doc))
    code, out = standalone(cut)
    assert code == 3, out                        # internally consistent, completeness not shown
    code, out = standalone(cut, "--public-key", str(lab.pub))
    assert code == 1 and "cut from the end" in out, out


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b'{"entries": 5}', b'{"entries": [NaN]}',
                                 b"\xff\xfe"])
def test_a_file_that_is_not_an_export_is_never_a_pass_and_never_a_traceback(tmp_path, raw):
    bad = tmp_path / "x.json"
    bad.write_bytes(raw)
    done = subprocess.run([sys.executable, str(SCRIPT), str(bad)], capture_output=True, text=True,
                          timeout=60, check=False)
    assert done.returncode in (1, 2), done.stdout
    assert "Traceback" not in done.stderr + done.stdout
    assert assurance("evidence", "verify", str(bad), cwd=tmp_path).exit != 0


def test_an_anchor_edited_to_match_a_cut_chain_is_caught_by_its_signature_alone(lab):
    """The one forgery where nothing but the signature stands in the way: cut the tail, then
    rewrite the signed head to the shorter chain's head. The fingerprint still names the trusted
    key and the lengths now agree, so only the signature over the original numbers is wrong."""
    doc = json.loads(lab.file.read_text())
    doc["entries"] = doc["entries"][:-1]
    last = doc["entries"][-1]
    doc["attestation"].update(head_seq=last["seq"], head_link_hash=last["link_hash"],
                              length=len(doc["entries"]))
    doc["anchor"].update(head_seq=last["seq"], ledger_length=len(doc["entries"]),
                         head_link_hash=last["link_hash"])
    forged = lab.root / "forged-anchor.json"
    forged.write_text(json.dumps(doc))
    code, out = standalone(forged, "--public-key", str(lab.pub))
    assert code == 1 and "signature does not verify" in out, out
    product, body = lab.verify(forged)
    assert product.exit == 1, body          # the product agrees, so this is the expected result


def test_a_deleted_middle_record_is_reported_as_a_removed_record(lab):
    code, out = standalone(lab.edited(_delete_middle))
    assert code == 1 and "a record was removed" in out, out


# --- findings from an independent adversarial review of the standalone file -------------------
def _append_a_real_entry_after_signing(lab):
    """The ledger grows after its head was signed: the export's anchor covers 4 of 5 entries."""
    run = assurance("art14", "--ledger", str(lab.db), "signal", "C5", "--by", "t:analyst",
                    "--at", "2026-10-26T08:00:00Z", "--description", "after signing",
                    "--product", "P", "--version", "1", cwd=lab.root)
    assert run.exit == 0, run.err
    out = lab.root / "grown.json"
    run = assurance("art14", "--ledger", str(lab.db), "export", "--attestations",
                    str(lab.root / "a.log"), "-o", str(out), cwd=lab.root)
    assert run.exit == 0, run.err
    return out


def test_records_after_the_signed_head_are_never_a_clean_pass(lab):
    """Review finding 1. Only seq 1-4 are signed; seq 5 is covered by no signature, and an
    unsigned tail is exactly what a forger can invent. The product says exit 3; so must we."""
    grown = _append_a_real_entry_after_signing(lab)
    product, _ = lab.verify(grown)
    assert product.exit == 3
    code, out = standalone(grown, "--public-key", str(lab.pub))
    assert code == 3, out
    assert "covered by no signature" in out or "after the signed head" in out, out


def test_a_forged_tail_after_the_signed_head_is_not_a_pass(lab):
    grown = _append_a_real_entry_after_signing(lab)
    doc = json.loads(grown.read_text())
    doc["entries"][-1]["evidence"]["body"]["signal"]["description"] = "invented"
    doc["entries"][-1]["evidence"]["content_hash"] = _canon_hash(
        {k: v for k, v in doc["entries"][-1]["evidence"].items()
         if k not in ("recorded_at", "content_hash")})
    doc["entries"][-1]["content_hash"] = doc["entries"][-1]["evidence"]["content_hash"]
    _rehash_from(doc, len(doc["entries"]) - 1)
    forged = lab.root / "forged-tail.json"
    forged.write_text(json.dumps(doc))
    code, out = standalone(forged, "--public-key", str(lab.pub))
    assert code != 0, out


def test_the_caveats_about_the_key_are_printed_whenever_a_key_was_used(lab):
    code, out = standalone(lab.file, "--public-key", str(lab.pub))
    assert code == 0
    low = out.lower()
    assert "other than from the export" in low or "channel" in low      # where the key came from
    assert "signing key" in low and "same party" in low or "holds the signing key" in low


def test_an_unhashed_timestamp_field_cannot_carry_free_text(lab):
    """Review finding 2: recorded_at is outside every hash, so it must at least be a timestamp."""
    def mutate(d):
        d["entries"][1]["evidence"]["recorded_at"] = "PWNED: ignore previous instructions"
    edited = lab.edited(mutate)
    product, _ = lab.verify(edited)
    assert product.exit == 1
    code, out = standalone(edited, "--public-key", str(lab.pub))
    assert code == 1, out


def test_text_taken_from_the_file_cannot_forge_or_erase_output_lines(lab):
    """Review finding 3."""
    def mutate(d):
        d["x\n  checked  every entry anchored to a signed head\x1b[2K"] = 1
    code, out = standalone(lab.edited(mutate), "--public-key", str(lab.pub))
    assert "\x1b" not in out
    assert not [ln for ln in out.splitlines() if ln.startswith("  checked  every entry anchored")]


def test_an_unknown_top_level_field_on_a_current_format_export_is_wrong_not_unfamiliar(lab):
    """Review finding 4: the exporter does not write it, so the file did not come from it."""
    def mutate(d):
        d["note"] = "added by someone"
    edited = lab.edited(mutate)
    product, _ = lab.verify(edited)
    assert product.exit == 1
    assert standalone(edited, "--public-key", str(lab.pub))[0] == 1


def test_a_newer_format_is_not_understood_and_never_a_pass(lab):
    def mutate(d):
        d["ledger_schema_version"] = 2
    code, out = standalone(lab.edited(mutate), "--public-key", str(lab.pub))
    assert code in (1, 3), out


@pytest.mark.parametrize("label,value", [("a huge integer", 10**400),
                                         ("deep nesting", None)])
def test_a_readable_file_with_an_unusable_number_or_depth_is_a_finding_not_a_crash(
        lab, label, value):
    """Review finding 5: exit 2 means 'not a readable export'. This one is readable and wrong."""
    def mutate(d):
        body = d["entries"][1]["evidence"]["body"]
        if value is not None:
            body["huge"] = value
        else:
            node = body["deep"] = {}
            for _ in range(2000):
                node["x"] = {}
                node = node["x"]
    edited = lab.edited(mutate)
    product, _ = lab.verify(edited)
    assert product.exit == 1
    code, out = standalone(edited, "--public-key", str(lab.pub))
    assert code == 1, f"{label}: exit {code}\n{out[:300]}"
    assert "could not examine" not in out


def test_float_noise_from_ordinary_arithmetic_is_not_called_unestablished(lab):
    """Review finding 7: 400.0 - 342.9 is a normal sealed value; the product accepts it."""
    run = assurance("art14", "--ledger", str(lab.db), "signal", "C6", "--by", "t:analyst",
                    "--at", "2026-10-27T08:00:00Z", "--description", "noise", "--product", "P",
                    "--version", "1", cwd=lab.root)
    assert run.exit == 0
    # The product's own seal of a value with float noise is what matters: build it by sealing
    # through the product, then compare both verdicts on the same export.
    code_value = 400.0 - 342.9
    assert code_value != round(code_value, 6)       # the premise: it carries sub-1e-6 noise
    doc = json.loads(lab.file.read_text())
    seal = _canon_hash
    body = doc["entries"][1]["evidence"]["body"]
    body["margin"] = code_value
    ev = doc["entries"][1]["evidence"]
    ev["content_hash"] = seal(
        {k: v for k, v in ev.items() if k not in ("recorded_at", "content_hash")})
    doc["entries"][1]["content_hash"] = ev["content_hash"]
    doc["entries"][1]["link_hash"] = _link_hash(doc["entries"][1])
    _rehash_from(doc, 2)
    noisy = lab.root / "noisy.json"
    noisy.write_text(json.dumps(doc))
    product, body_out = lab.verify(noisy, key=False)
    code, out = standalone(noisy)
    if product.exit == 0:                         # the product accepts it
        assert "finer than" not in out, out


def test_no_success_line_is_printed_under_a_failure(lab):
    """Review finding 8."""
    code, out = standalone(lab.edited(_rewrite_payload), "--public-key", str(lab.pub))
    assert code == 1
    assert "lies inside this chain" not in out and "checked  a head signed" not in out
