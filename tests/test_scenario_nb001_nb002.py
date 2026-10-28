"""NB-001 / NB-002 against the product's matching logic, driven by the cited fixture.

Scope, stated plainly: this runs the product's *library* matcher (``match_item``), the same
domain function the CLI, API and MCP call. It is not an HTTP or hosted-staging test. The
expected results come from the fixture's cited vendor facts (Rockwell SD1780 / SD1796) and
the scenario's expected_behavior, not from the matcher.

A vendor advisory is applicability, not proof that a customer owns the asset; the matcher
must also never turn the vendor's wording ("V12.001 and earlier") into a clear for a
version it cannot place.
"""
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem

FIXTURE = json.loads(
    (Path(__file__).resolve().parent.parent / "data/fixtures/rockwell_advisories.json")
    .read_text(encoding="utf-8"))
VENDOR = "Rockwell Automation"
ISSUED = datetime(2026, 10, 27, tzinfo=UTC)
_EARLIER = re.compile(r"^(?P<v>.+?)\s+and earlier$", re.I)


def advisory_from_fixture(advisory_id):
    """Independent test adapter: fixture record -> the product's ComponentAdvisory."""
    rec = next(r for r in FIXTURE["records"] if r["advisory_id"] == advisory_id)
    affected, fixed = [], []
    for p in rec["affected_products"]:
        text = p["affected_firmware"]
        m = _EARLIER.match(text)
        affected.append(AffectedArtefact(
            supplier=VENDOR, name=p["catalog_number"],
            versions=(m.group("v") if m else text,),
            version_note=text if m else ""))
        if p["corrected_firmware"]:
            fixed.append(p["corrected_firmware"])
    return ComponentAdvisory(
        advisory_id=advisory_id, issued_by=VENDOR, issued_at=ISSUED,
        title=rec["product_family"], summary="synthetic adapter record",
        severity=AdvisorySeverity.SAFETY_RELEVANT, affected=tuple(affected),
        reference=rec["source_url"], fixed_versions=tuple(fixed))


def unit(catalog, version, supplier=VENDOR):
    """A synthetic customer item; the hash is a declared version only (no artefact read)."""
    return SafetyItem(
        item_id="I-1", kind=ItemKind.FIRMWARE, name=catalog, version=version,
        content_hash="", hash_source=HashSource.DECLARED, supplier=supplier,
        implements=("SF-1",))


SD1780 = advisory_from_fixture("SD1780")
SD1796 = advisory_from_fixture("SD1796")


# ---- NB-001: affected versus corrected --------------------------------------------------
@pytest.mark.parametrize("catalog", ["1756-EN2", "1756-EN3"])
def test_the_vendor_listed_affected_version_matches_but_only_as_a_label(catalog):
    found = match_item(SD1780, unit(catalog, "V12.001"))
    assert found is not None
    basis, detail = found
    assert basis is MatchBasis.VERSION and basis.confidence == "probable"
    assert "label" in detail  # applicability from a label is not an artefact match


@pytest.mark.parametrize("catalog", ["1756-EN2", "1756-EN3"])
def test_the_vendor_listed_corrected_version_is_not_affected(catalog):
    assert match_item(SD1780, unit(catalog, "V12.002")) is None


@pytest.mark.parametrize("version", ["V11.010", "V10.000", "V12.000"])
def test_a_version_inside_the_vendors_words_is_never_cleared_nor_called_confirmed(version):
    """'V12.001 and earlier' is a range the matcher does not parse: those versions need a
    person, not a clear and not a confirmed hit."""
    found = match_item(SD1780, unit("1756-EN2", version))
    assert found is not None, f"{version} is covered by the vendor's wording and was cleared"
    assert found[0] is MatchBasis.NAME_ONLY and found[0].confidence != "confirmed"


def test_an_unrecorded_version_is_possible_not_clear():
    found = match_item(SD1780, unit("1756-EN2", ""))
    assert found is not None and found[0] is MatchBasis.NAME_ONLY


def test_the_corrected_version_of_one_series_does_not_clear_or_flag_the_other():
    c, b = "1756-HIST2G/C", "1756-HIST2G/B"
    assert match_item(SD1796, unit(c, "7.101")) is not None      # affected (series C)
    assert match_item(SD1796, unit(c, "7.102")) is None           # corrected (series C)
    assert match_item(SD1796, unit(b, "5.202")) is not None      # affected (series B)
    assert match_item(SD1796, unit(b, "5.203")) is None           # corrected (series B)
    # a version that is affected in the other series is not thereby affected here
    assert match_item(SD1796, unit(c, "5.202")) is None
    assert match_item(SD1796, unit(b, "7.101")) is None


def test_a_different_product_or_supplier_with_the_same_version_is_not_matched():
    assert match_item(SD1780, unit("1756-ENET", "V12.001")) is None
    assert match_item(SD1780, unit("1756-EN2", "V12.001", supplier="OtherCo")) is None


def test_the_advisory_asserts_no_customer_or_asset():
    """Applicability is vendor-published fact: the advisory carries no ownership claim."""
    fields = set(SD1780.to_dict())
    assert not fields & {"customer", "customers", "machine", "machines", "asset", "assets",
                         "site", "sites", "owner"}


# ---- NB-002: discontinued hardware, no fix ---------------------------------------------
def test_the_discontinued_module_is_affected_and_no_fix_is_invented():
    found = match_item(SD1780, unit("1756-ENBT", "V6.006"))
    assert found is not None and found[0] is MatchBasis.VERSION
    assert "V12.002" not in found[1]  # the EN2/EN3 fix is not offered for ENBT
    enbt = next(a for a in SD1780.affected if a.name == "1756-ENBT")
    assert enbt.versions == ("V6.006",)
    assert SD1780.remedy == ""        # the adapter states no vendor patch/remedy


def test_the_fix_for_other_modules_does_not_clear_the_discontinued_one():
    # V12.002 is listed corrected for EN2/EN3 only. It must not read as 'fixed' for ENBT.
    found = match_item(SD1780, unit("1756-ENBT", "V12.002"))
    assert found is None or found[0] is not MatchBasis.VERSION
