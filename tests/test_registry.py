from neuralbridge_stress.registry import validate_scenarios, validate_sources


def test_source_registry_is_valid():
    assert validate_sources() == []


def test_scenario_registry_is_valid_and_uses_known_sources():
    assert validate_scenarios() == []
