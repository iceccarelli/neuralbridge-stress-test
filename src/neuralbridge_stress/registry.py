"""Loading and basic validation of source and scenario registries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_json(path: str | Path) -> Any:
    """Load a UTF-8 JSON document and return its decoded value."""
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def validate_sources(path: str | Path | None = None) -> list[str]:
    """Return validation errors for the source registry; an empty list means valid."""
    registry_path = Path(path) if path else REPO_ROOT / "configs" / "sources.json"
    errors: list[str] = []
    try:
        document = load_json(registry_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot load source registry {registry_path}: {exc}"]

    if document.get("schema_version") != "1.0":
        errors.append("sources.json must declare schema_version 1.0")

    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        return errors + ["sources.json must contain a non-empty sources list"]

    seen: set[str] = set()
    for index, source in enumerate(sources):
        label = f"sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
        elif source_id in seen:
            errors.append(f"duplicate source id: {source_id}")
        else:
            seen.add(source_id)

        url = source.get("url", "")
        if url and not (isinstance(url, str) and url.startswith("https://")):
            errors.append(f"{label}.url must be empty or HTTPS")
        if "initially_loaded" not in source:
            errors.append(f"{label} must state initially_loaded explicitly")
        if not source.get("publisher"):
            errors.append(f"{label}.publisher is required")
        if not source.get("reuse_status"):
            errors.append(f"{label}.reuse_status is required")
    return errors


def validate_scenarios(
    path: str | Path | None = None,
    sources_path: str | Path | None = None,
) -> list[str]:
    """Validate scenario identity and source references, not product behavior."""
    scenario_path = Path(path) if path else REPO_ROOT / "configs" / "scenarios.json"
    registry_path = Path(sources_path) if sources_path else REPO_ROOT / "configs" / "sources.json"
    errors: list[str] = []
    try:
        document = load_json(scenario_path)
        source_document = load_json(registry_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot load scenario/source registry: {exc}"]

    source_ids = {
        item.get("id") for item in source_document.get("sources", []) if isinstance(item, dict)
    }
    scenarios = document.get("scenarios")
    if document.get("schema_version") != "1.0":
        errors.append("scenarios.json must declare schema_version 1.0")
    if not isinstance(scenarios, list) or not scenarios:
        return errors + ["scenarios.json must contain a non-empty scenarios list"]

    seen: set[str] = set()
    for index, scenario in enumerate(scenarios):
        label = f"scenarios[{index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{label} must be an object")
            continue
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
        elif scenario_id in seen:
            errors.append(f"duplicate scenario id: {scenario_id}")
        else:
            seen.add(scenario_id)
        if not scenario.get("title"):
            errors.append(f"{label}.title is required")
        if not isinstance(scenario.get("expected_behavior"), list) or not scenario[
            "expected_behavior"
        ]:
            errors.append(f"{label}.expected_behavior must be a non-empty list")
        for source_id in scenario.get("source_ids", []):
            if source_id not in source_ids:
                errors.append(f"{label} references unknown source id: {source_id}")
    return errors
