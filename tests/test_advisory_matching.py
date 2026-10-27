"""Advisory matching must never turn missing or unparsed information into 'clear'.

Rules asserted (from the product's stated purpose, not its code):
  * a supplier's range in free text cannot be parsed, so an unlisted version is
    UNKNOWN (a human must look), never silently clear;
  * a hash not read from this machine is not evidence about this machine;
  * a hash prefix is not a hash;
  * the order a supplier lists entries cannot change the answer;
  * an advisory that would match everything is refused at construction.
"""
from datetime import UTC, datetime

import pytest
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem

H1 = "a" * 64
H2 = "b" * 64


def item(version="4.0", supplier="ControlCo", name="SafeScan", content_hash=H1,
         source=HashSource.READ_FROM_MACHINE):
    return SafetyItem(item_id="i1", kind=ItemKind.FIRMWARE, name=name, version=version,
                      content_hash=content_hash, hash_source=source, supplier=supplier)


def advisory(*affected, fixed_versions=(), fixed_hashes=()):
    return ComponentAdvisory(
        advisory_id="ADV-1", issued_by="ControlCo PSIRT",
        issued_at=datetime(2026, 9, 1, tzinfo=UTC), title="t", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT, affected=tuple(affected),
        reference="https://example.invalid/adv-1",
        fixed_versions=tuple(fixed_versions), fixed_hashes=tuple(fixed_hashes),
    )


def art(**kw):
    kw.setdefault("supplier", "ControlCo")
    kw.setdefault("name", "SafeScan")
    return AffectedArtefact(**kw)


def test_unlisted_version_with_a_supplier_range_note_is_not_cleared():
    adv = advisory(art(versions=("4.2",), version_note="all versions up to and including 4.2"))
    found = match_item(adv, item(version="4.0", content_hash=H1))
    assert found is not None, "range in free text + unlisted version was silently cleared"
    assert found[0].needs_a_human or found[0] is MatchBasis.NAME_ONLY


def test_listed_version_matches_on_label_only_when_no_hash_is_published():
    adv = advisory(art(versions=("4.0",)))
    basis, _ = match_item(adv, item(version="4.0"))
    assert basis is MatchBasis.VERSION


def test_hash_read_from_machine_that_matches_is_confirmed():
    adv = advisory(art(versions=("4.0",), content_hashes=(H1,)))
    assert match_item(adv, item())[0] is MatchBasis.HASH


def test_vendor_supplied_hash_is_not_treated_as_evidence_about_the_machine():
    adv = advisory(art(versions=("9.9",), content_hashes=(H1,)))
    found = match_item(adv, item(version="4.0", source=HashSource.SUPPLIED_BY_VENDOR))
    assert found is None or found[0] is not MatchBasis.HASH


def test_a_hash_prefix_is_not_a_match():
    adv = advisory(art(versions=("9.9",), content_hashes=(H1,)))
    found = match_item(adv, item(version="4.0", content_hash=H1[:32]))
    assert found is None or found[0] is not MatchBasis.HASH


def test_label_says_affected_but_machine_hash_is_listed_fixed_is_contradictory_not_clear():
    adv = advisory(art(versions=("4.0",)), fixed_hashes=(H2,))
    basis, _ = match_item(adv, item(version="4.0", content_hash=H2))
    assert basis is MatchBasis.HASH_MISMATCH and basis.needs_a_human


def test_no_supplier_recorded_is_possible_never_clear():
    adv = advisory(art(versions=("4.0",)))
    basis, _ = match_item(adv, item(supplier=""))
    assert basis is MatchBasis.NAME_ONLY


def test_a_different_supplier_with_the_same_component_name_does_not_match():
    adv = advisory(art(versions=("4.0",)))
    assert match_item(adv, item(supplier="OtherCo")) is None


def test_entry_order_cannot_change_the_answer():
    a = art(versions=("4.0",), content_hashes=(H1,))
    b = art(versions=("4.0",))
    assert match_item(advisory(a, b), item())[0] is match_item(advisory(b, a), item())[0]


@pytest.mark.parametrize("label", ["4.0 ", " 4.0\t", "４.０"])
def test_unicode_and_whitespace_variants_of_an_affected_label_still_match(label):
    adv = advisory(art(versions=("4.0",)))
    found = match_item(adv, item(version=label, content_hash=H1))
    assert found is not None and found[0] in (MatchBasis.VERSION, MatchBasis.HASH)


def test_an_advisory_naming_neither_version_nor_hash_is_refused():
    with pytest.raises(AdvisoryError):
        art(versions=(), content_hashes=())


def test_blank_fixed_hash_is_refused_not_read_as_remedied():
    with pytest.raises(AdvisoryError):
        advisory(art(versions=("4.0",)), fixed_hashes=("  ",))


def test_an_advisory_without_a_reference_is_refused():
    with pytest.raises(AdvisoryError):
        ComponentAdvisory(
            advisory_id="X", issued_by="Y", issued_at=datetime(2026, 9, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.INFORMATIONAL,
            affected=(art(versions=("4.0",)),), reference="",
        )
