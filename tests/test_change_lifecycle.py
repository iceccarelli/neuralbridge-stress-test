"""Verified -> change recorded -> evidence stale -> new verification -> current again.

Priority 3 of the laboratory brief, attacked at the product library level
(``assurance.machinery.staleness.assess_coverage``). Evidence level: product library,
in-process, synthetic machine "Acme AR-7 #0412". Not a CLI, API, MCP or hosted result.

Expected results come from the principle, not from reading the product back:

* a verification describes the machine as it was when the run began;
* a change that touches a safety item ends cover for the functions that item serves, and
  only those;
* only a *new sealed verification that began after the change* restores cover; a claim of
  revalidation, a reversal to an earlier version, or a missing hash does not;
* a record that cannot be dated or attributed is refused or read in the unsafe direction.
"""
from datetime import UTC, datetime, timedelta, timezone

import pytest
from assurance.core import Actor
from assurance.machinery.intervention import (
    Intervention,
    InterventionError,
    InterventionKind,
    Revalidation,
)
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

T0 = datetime(2026, 3, 2, 8, 0, tzinfo=UTC)
H = "a" * 64
TECH = Actor("t.ng", "technician")
MACHINE = MachineIdentity("Acme", "AR-7", "0412")
OTHER_MACHINE = MachineIdentity("Acme", "AR-7", "0999")


def item(item_id, kind, implements):
    return SafetyItem(item_id, kind, item_id, "1", H, HashSource.READ_FROM_MACHINE,
                      implements=tuple(implements))


def manifest(machine=MACHINE):
    return SafetyManifest(
        manifest_id="m", machine=machine, source=ManifestSource.AS_FOUND, taken_at=T0,
        taken_by=TECH,
        items=(item("safety-plc-fw", ItemKind.FIRMWARE, ["SF-STOP"]),
               item("scanner-cfg", ItemKind.SAFETY_CONFIGURATION, ["SF-SCAN"]),
               item("hmi-skin", ItemKind.PARAMETER_SET, [])),
        functions=(SafetyFunction("SF-STOP", "protective stop", verified_by=("stop-time",)),
                   SafetyFunction("SF-SCAN", "scanner zone", verified_by=("zone-radius",))),
    )


def verification(seq, at, verified=("stop-time", "zone-radius"), **kw):
    return VerificationRecord(
        content_hash=f"{seq:064x}", effective_at=at, ledger_seq=seq, product="p",
        product_version="1", verdict="pass", tier="validated",
        checks_verified=tuple(verified), **kw)


def change(at, item_id="safety-plc-fw", kind=InterventionKind.UPDATE, machine=MACHINE,
           frm="b" * 64, to="c" * 64, affects=("SF-STOP",), cid="CH-1", **kw):
    return Intervention(
        intervention_id=cid, machine_key=machine.key, item_id=item_id, kind=kind,
        occurred_at=at, performed_by=TECH, reason="vendor update", from_hash=frm, to_hash=to,
        affects_functions=tuple(affects), **kw)


def states(verifs, changes, m=None):
    report = assess_coverage(m or manifest(), verifs, changes)
    return {f.function_id: f for f in report.functions}


# ---------------------------------------------------------------------------- baseline
def test_verified_with_no_change_is_current():
    s = states([verification(1, T0)], [])
    assert s["SF-STOP"].coverage is Coverage.CURRENT
    assert s["SF-SCAN"].coverage is Coverage.CURRENT


# ------------------------------------------------------------------ the full lifecycle
def test_change_makes_old_evidence_stale_and_names_the_function_and_the_change():
    s = states([verification(1, T0)], [change(T0 + timedelta(days=5))])
    stop = s["SF-STOP"]
    assert stop.coverage is Coverage.STALE
    assert stop.invalidated_by == "CH-1"
    assert stop.invalidating_item == "safety-plc-fw"
    assert stop.last_verified_hash == f"{1:064x}"


def test_a_change_does_not_invalidate_functions_it_does_not_touch():
    """The brief: do not claim a change invalidates every verification."""
    s = states([verification(1, T0)], [change(T0 + timedelta(days=5))])
    assert s["SF-SCAN"].coverage is Coverage.CURRENT


def test_a_change_to_an_item_serving_no_function_invalidates_nothing():
    s = states([verification(1, T0)],
               [change(T0 + timedelta(days=5), item_id="hmi-skin", affects=())])
    assert {f.coverage for f in s.values()} == {Coverage.CURRENT}


def test_new_verification_after_the_change_restores_cover_with_new_evidence():
    ch = change(T0 + timedelta(days=5))
    s = states([verification(1, T0), verification(2, T0 + timedelta(days=6))], [ch])
    assert s["SF-STOP"].coverage is Coverage.CURRENT
    assert s["SF-STOP"].last_verified_hash == f"{2:064x}"


def test_a_new_verification_of_only_another_check_does_not_restore_the_stopped_function():
    ch = change(T0 + timedelta(days=5))
    s = states([verification(1, T0),
                verification(2, T0 + timedelta(days=6), verified=("zone-radius",))], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE


def test_verification_that_began_before_the_change_but_was_filed_after_is_still_stale():
    """effective_at is when the run began; filing it late must not buy cover."""
    ch = change(T0 + timedelta(days=5))
    late_filed = verification(2, T0 + timedelta(days=1), filed_at=T0 + timedelta(days=9))
    s = states([late_filed], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE


def test_verification_at_the_very_instant_of_the_change_is_not_trusted():
    s = states([verification(1, T0)], [change(T0)])
    assert s["SF-STOP"].coverage is Coverage.STALE


# --------------------------------------------------------- claims that must not count
def test_a_revalidation_claim_without_sealed_evidence_does_not_restore_cover():
    ch = change(T0 + timedelta(days=5), revalidation=Revalidation(
        T0 + timedelta(days=5), TECH, "re-ran stop test", evidence_hash=""))
    s = states([verification(1, T0)], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE


def test_a_revalidation_hash_that_is_not_in_the_ledger_does_not_restore_cover():
    ch = change(T0 + timedelta(days=5), revalidation=Revalidation(
        T0 + timedelta(days=5), TECH, "re-ran stop test", evidence_hash="d" * 64))
    s = states([verification(1, T0)], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE
    assert s["SF-STOP"].intervention_revalidated is True  # claimed ...
    assert "not in this ledger" in s["SF-STOP"].detail    # ... and said not to count


def test_reversal_to_the_earlier_version_does_not_resurrect_old_verification():
    update = change(T0 + timedelta(days=5), frm="b" * 64, to="c" * 64)
    revert = change(T0 + timedelta(days=6), kind=InterventionKind.RESTORE, cid="CH-2",
                    frm="c" * 64, to="b" * 64)
    s = states([verification(1, T0)], [update, revert])
    assert s["SF-STOP"].coverage is Coverage.STALE


def test_a_change_with_no_hashes_still_ends_cover():
    ch = change(T0 + timedelta(days=5), frm="", to="")
    assert states([verification(1, T0)], [ch])["SF-STOP"].coverage is Coverage.STALE


def test_a_change_with_conflicting_hash_to_the_manifest_still_ends_cover():
    """The manifest item says H; the change claims it moved from a different hash."""
    ch = change(T0 + timedelta(days=5), frm="e" * 64, to="f" * 64)
    assert states([verification(1, T0)], [ch])["SF-STOP"].coverage is Coverage.STALE


def test_a_blank_or_mistyped_affects_list_cannot_hide_a_change():
    for affects in ((), ("SF-STOPP",), ("nonsense",)):
        ch = change(T0 + timedelta(days=5), affects=affects)
        s = states([verification(1, T0)], [ch])
        assert s["SF-STOP"].coverage is Coverage.STALE, affects


def test_a_lying_affects_list_cannot_invalidate_an_unrelated_function_by_name_only_silently():
    """A change to hmi-skin that *names* SF-SCAN is a claim; it is taken as the safe
    direction (stale), never as 'current'."""
    ch = change(T0 + timedelta(days=5), item_id="hmi-skin", affects=("SF-SCAN",))
    s = states([verification(1, T0)], [ch])
    assert s["SF-SCAN"].coverage is Coverage.STALE
    assert s["SF-STOP"].coverage is Coverage.CURRENT


# ---------------------------------------------------------------- machine separation
def test_a_change_recorded_for_another_machine_does_not_stale_this_one():
    ch = change(T0 + timedelta(days=5), machine=OTHER_MACHINE)
    s = states([verification(1, T0)], [ch])
    assert s["SF-STOP"].coverage is Coverage.CURRENT


def test_one_machines_change_does_not_stale_its_twin_but_does_stale_itself():
    ch = change(T0 + timedelta(days=5), machine=OTHER_MACHINE)
    twin = states([verification(1, T0)], [ch], m=manifest(OTHER_MACHINE))
    assert twin["SF-STOP"].coverage is Coverage.STALE


# ----------------------------------------------------------- time and attribution
def test_an_instant_expressed_in_another_offset_is_ordered_by_the_instant():
    """10:00+02:00 is 08:00Z. A verification at 09:00Z therefore *follows* the change."""
    plus2 = timezone(timedelta(hours=2))
    ch = change(datetime(2026, 3, 9, 10, 0, tzinfo=plus2))
    s = states([verification(1, datetime(2026, 3, 9, 9, 0, tzinfo=UTC))], [ch])
    assert s["SF-STOP"].coverage is Coverage.CURRENT
    s = states([verification(1, datetime(2026, 3, 9, 7, 59, tzinfo=UTC))], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE


def test_a_change_across_the_spring_dst_gap_is_ordered_by_instant():
    """Europe/Berlin 2026-03-29 02:30 does not exist; 01:59Z is 02:59+... after the jump.
    Ordering must use UTC instants, not wall-clock labels."""
    cet, cest = timezone(timedelta(hours=1)), timezone(timedelta(hours=2))
    before = datetime(2026, 3, 29, 1, 59, tzinfo=cet)   # 00:59Z
    after = datetime(2026, 3, 29, 3, 0, tzinfo=cest)    # 01:00Z
    assert before < after and (after - before) == timedelta(minutes=1)
    ch = change(after)
    assert states([verification(1, before)], [ch])["SF-STOP"].coverage is Coverage.STALE
    assert states([verification(1, after + timedelta(minutes=1))], [ch]
                  )["SF-STOP"].coverage is Coverage.CURRENT


def test_naive_change_timestamp_is_refused_not_guessed():
    with pytest.raises(InterventionError):
        change(datetime(2026, 3, 9, 8, 0))


def test_naive_verification_timestamp_is_refused_not_guessed():
    from assurance.machinery.staleness import VerificationRecordError
    with pytest.raises(VerificationRecordError):
        verification(1, datetime(2026, 3, 9, 8, 0))


def test_a_change_with_no_named_actor_is_refused():
    with pytest.raises(InterventionError):
        Intervention("CH-9", MACHINE.key, "safety-plc-fw", InterventionKind.UPDATE,
                     T0, Actor("", "technician"), "vendor update")


def test_a_change_with_no_reason_is_refused():
    with pytest.raises(InterventionError):
        Intervention("CH-9", MACHINE.key, "safety-plc-fw", InterventionKind.UPDATE,
                     T0, TECH, "")


def test_an_update_whose_before_and_after_hash_are_identical_is_refused():
    with pytest.raises(InterventionError):
        change(T0, frm="b" * 64, to="b" * 64)


def test_a_pass_that_cannot_be_dated_is_never_current():
    s = states([verification(1, T0, date_suspect=True)], [])
    assert s["SF-STOP"].coverage is Coverage.STALE


# ----------------------------------------------------- change with no later verification
def test_a_change_with_no_subsequent_verification_stays_stale_however_long_it_waits():
    ch = change(T0 + timedelta(days=5))
    s = states([verification(1, T0)], [ch])
    assert s["SF-STOP"].coverage is Coverage.STALE
    assert not s["SF-STOP"].coverage.is_covered


def test_input_order_does_not_change_the_lifecycle_answer():
    ch = change(T0 + timedelta(days=5))
    v = [verification(1, T0), verification(2, T0 + timedelta(days=6))]
    a = states(v, [ch])["SF-STOP"].coverage
    b = states(list(reversed(v)), [ch])["SF-STOP"].coverage
    assert a is b is Coverage.CURRENT
