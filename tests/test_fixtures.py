from neuralbridge_stress.registry import REPO_ROOT, load_json


def test_rockwell_source_fixture_has_required_provenance_and_unique_advisories():
    fixture = load_json(REPO_ROOT / "data/fixtures/rockwell_advisories.json")
    assert fixture["fixture_class"] == "minimized_public_fact_extraction"
    assert fixture["reviewed_on"]
    assert fixture["warning"]
    records = fixture["records"]
    assert records
    advisory_ids = [record["advisory_id"] for record in records]
    assert len(advisory_ids) == len(set(advisory_ids))
    for record in records:
        assert record["source_url"].startswith("https://")
        assert record["source_id"]
        assert record.get("cve_id") or record.get("cve_ids")


def test_discontinued_module_is_not_given_an_invented_fix():
    fixture = load_json(REPO_ROOT / "data/fixtures/rockwell_advisories.json")
    sd1780 = next(
        record for record in fixture["records"] if record["advisory_id"] == "SD1780"
    )
    enbt = next(
        item
        for item in sd1780["affected_products"]
        if item["catalog_number"] == "1756-ENBT"
    )
    assert enbt["availability"] == "discontinued_no_fix_available"
    assert enbt["corrected_firmware"] is None


def test_corrected_versions_are_explicitly_distinct_from_affected_versions():
    fixture = load_json(REPO_ROOT / "data/fixtures/rockwell_advisories.json")
    for record in fixture["records"]:
        for product in record["affected_products"]:
            if product["availability"] == "corrected_version_listed":
                assert product["corrected_firmware"]
                assert product["corrected_firmware"] != product["affected_firmware"]


def test_evidence_fixture_is_explicitly_synthetic_and_has_mutation_cases():
    fixture = load_json(REPO_ROOT / "data/fixtures/evidence_events.json")
    assert fixture["fixture_class"] == "synthetic"
    assert fixture["warning"]
    assert {case["case_id"] for case in fixture["mutation_cases"]} == {
        "NB005-TAMPER", "NB005-DUPLICATE", "NB005-ORDER", "NB005-TRUNCATE"
    }
