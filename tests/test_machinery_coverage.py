"""Coverage must never read 'current' from evidence that also says the check failed.

Expected values come from the principle the module states: cover needs EVERY declared check,
a newer failing run ends older cover, and a function with nothing verified is not covered.
"""
from datetime import UTC, datetime, timedelta

from assurance.core import Actor
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

T0 = datetime(2026, 1, 1, tzinfo=UTC)
H = "a" * 64


def manifest(*checks):
    return SafetyManifest(
        manifest_id="m", machine=MachineIdentity("Acme", "AR-7", "0412"),
        source=ManifestSource.AS_FOUND, taken_at=T0, taken_by=Actor("t", "tech"),
        items=(SafetyItem("fw", ItemKind.FIRMWARE, "fw", "1", H, HashSource.READ_FROM_MACHINE,
                          implements=("SF-1",)),),
        functions=(SafetyFunction("SF-1", "safe stop", verified_by=tuple(checks)),),
    )


def record(seq, days, verified=(), not_verified=(), n_a=(), tier="validated"):
    return VerificationRecord(
        content_hash=f"{seq:064x}", effective_at=T0 + timedelta(days=days), ledger_seq=seq,
        product="p", product_version="1", verdict="pass", tier=tier,
        checks_verified=tuple(verified), checks_not_verified=tuple(not_verified),
        checks_not_applicable=tuple(n_a),
    )


def coverage(m, records):
    report = assess_coverage(m, records, [])
    return {f.function_id: f.coverage for f in report.functions}["SF-1"]


def test_all_checks_verified_is_current():
    assert coverage(manifest("a", "b"), [record(1, 1, verified=("a", "b"))]) is Coverage.CURRENT


def test_one_check_of_two_is_not_cover():
    assert coverage(manifest("a", "b"), [record(1, 1, verified=("a",))]) is Coverage.NEVER_VERIFIED


def test_a_newer_failure_ends_older_cover():
    old = record(1, 1, verified=("a",))
    new = record(2, 5, not_verified=("a",))
    assert coverage(manifest("a"), [old, new]) is Coverage.FAILING


def test_not_applicable_is_not_a_failure_and_is_not_cover():
    r = record(1, 1, not_verified=("a",), n_a=("a",))
    assert coverage(manifest("a"), [r]) is Coverage.NEVER_VERIFIED


def test_a_function_with_no_declared_checks_is_not_demonstrable():
    assert coverage(manifest(), [record(1, 1, verified=("a",))]) is Coverage.NOT_DEMONSTRABLE


def test_a_record_that_lists_a_check_as_both_verified_and_failed_is_failing():
    """Contradictory evidence in one record must not be read in the favourable direction."""
    r = record(1, 1, verified=("a",), not_verified=("a",))
    assert coverage(manifest("a"), [r]) is Coverage.FAILING


def test_input_order_does_not_change_the_answer():
    recs = [record(1, 1, verified=("a",)), record(2, 5, not_verified=("a",)),
            record(3, 9, verified=("a",))]
    forward = coverage(manifest("a"), recs)
    backward = coverage(manifest("a"), list(reversed(recs)))
    assert forward is backward is Coverage.CURRENT  # the newest run passed
