"""Divergence between a baseline and an observed manifest must never read 'unchanged'
from missing or placeholder evidence.

Principle (the module's own stated purpose): an item with no usable hash is invisible to
comparison, and a clean report over such items means nothing was seen. So a placeholder
that is not a real digest must be refused or treated as not comparable, never compared as
equal.
"""
from datetime import UTC, datetime

import pytest
from assurance.core import Actor
from assurance.machinery.divergence import ChangeKind, compare
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestError,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)

H1 = "a" * 64
H2 = "b" * 64
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def item(h, version="1.0", item_id="fw", implements=("SF-1",), source=HashSource.READ_FROM_MACHINE):
    return SafetyItem(item_id, ItemKind.FIRMWARE, "controller firmware", version, h, source,
                      supplier="ControlCo", implements=implements)


def manifest(*items, serial="0412", source=ManifestSource.AS_FOUND):
    return SafetyManifest(
        manifest_id="m-" + serial, machine=MachineIdentity("Acme", "AR-7", serial),
        source=source, taken_at=T0, taken_by=Actor("tech", "technician"), items=tuple(items),
        functions=(SafetyFunction("SF-1", "safe stop", verified_by=("stop_time",)),),
    )


@pytest.mark.parametrize("placeholder", ["n/a", "unknown", "0", "   ", "TBD", "x" * 10, "sha256:"])
def test_a_placeholder_hash_is_never_compared_as_equal(placeholder):
    """Both sides say 'n/a' and claim they were read from the machine: that is no evidence."""
    try:
        b = manifest(item(placeholder))
        o = manifest(item(placeholder))
    except ManifestError:
        return  # refused at construction: acceptable
    d = compare(b, o)
    assert not d.identical or d.uncompared, (
        f"{placeholder!r} on both sides read as an unchanged, comparable artefact"
    )


def test_a_real_change_to_a_safety_item_is_the_finding():
    d = compare(manifest(item(H1)), manifest(item(H2)))
    changes = [c for c in d.changes if c.kind is ChangeKind.CONTENT_CHANGED]
    assert changes and changes[0].severity.value == "safety_relevant"
    assert "SF-1" in d.affected_functions


def test_a_relabel_with_an_identical_hash_is_not_a_safety_finding():
    d = compare(manifest(item(H1, "1.0")), manifest(item(H1, "1.0.1")))
    assert [c.kind for c in d.changes] == [ChangeKind.VERSION_RELABELLED]
    assert d.changes[0].severity.value == "administrative"


def test_an_unhashed_item_is_reported_as_not_compared_never_as_unchanged():
    declared = item("", source=HashSource.DECLARED)
    d = compare(manifest(declared), manifest(declared))
    assert d.uncompared == ("fw",) and not d.identical or d.uncompared


def test_a_removed_safety_item_is_a_safety_finding():
    other = item(H2, item_id="scanner", implements=())
    d = compare(manifest(item(H1), other), manifest(other))
    assert any(c.kind is ChangeKind.REMOVED and c.severity.value == "safety_relevant"
               for c in d.changes)


def test_two_different_machines_are_not_compared():
    with pytest.raises(ValueError):
        compare(manifest(item(H1), serial="0412"), manifest(item(H1), serial="0413"))


def test_a_vendor_supplied_hash_on_the_observed_side_is_not_an_unchanged_machine():
    o = manifest(item(H1, source=HashSource.SUPPLIED_BY_VENDOR))
    d = compare(manifest(item(H1)), o)
    assert "fw" in d.uncompared


def test_an_observed_manifest_that_is_only_intended_says_it_looked_at_nothing():
    d = compare(manifest(item(H1)), manifest(item(H1), source=ManifestSource.AS_INTENDED))
    assert d.observed_as_found is False
    assert any("not 'as_found'" in c for c in d.checks_skipped)
