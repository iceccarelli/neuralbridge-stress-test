# NeuralBridge Stress Test

Independent, adversarial validation harness for NeuralBridge. This repository is the test authority; the product implementation remains in iceccarelli/neuralbridge.

## Objectives

- Compare product outputs with independently established expectations grounded in authoritative sources.
- Detect false applicability, incorrect affected/fixed-version mapping, unsupported conclusions, corrupted evidence, duplicate events, and unsafe recovery behavior.
- Exercise the real NeuralBridge API or CLI through public contracts; do not mock the calculation or verification logic being tested.
- Keep source provenance, retrieval time, checksums, licence/terms status, and fixture classification explicit.
- Route implementation fixes to the product repository and keep reproductions/regression tests here.

## Current scope

The initial source-backed fixtures are minimized fact extractions from Rockwell Automation security advisories SD1780 and SD1796. The data-fetch script retrieves the current CISA KEV catalog, focused NVD CVE records, and focused FIRST EPSS scores. Their current values are snapshots, not timeless truth.

The Rockwell fixture establishes vendor-published product/version facts only. It does not establish that a specific customer owns or operates any of those assets. Customer and site assets used in tests must be clearly synthetic unless supported by customer-authorized evidence.

## Repository layout

- configs/ — source registry and scenario index
- data/fixtures/ — small reviewed facts and synthetic evidence records safe to commit
- data/raw/ — fetched source payloads; ignored by Git, not committed
- data/derived/ — future normalized outputs; ignored by Git
- docs/ — architecture and operational rules
- scripts/ — environment checks, bounded data retrieval, read-only staging probe
- src/neuralbridge_stress/ — shared validation utilities
- tests/ — source-contract, fixture, safety, and eventual product-integration tests

## Local setup

From a Python 3.11+ environment:

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python scripts/doctor.py
    ruff check .
    pytest -q

In Codespaces, run these commands from the repository root. Never commit .venv, downloaded raw feeds, API keys, customer records, or private assurance evidence.

## Retrieve the initial public data

    python scripts/fetch_sources.py

The fetcher makes bounded, read-only HTTPS requests to:
- CISA's official KEV JSON catalogue;
- NVD's CVE API for the CVEs in the reviewed Rockwell fixture;
- FIRST's EPSS API for those same CVEs.

It stores raw responses and an ingestion manifest under data/raw/, which is Git-ignored. It records source URL, UTC retrieval time, HTTP status, byte count and SHA-256. NVD access may be rate-limited; NVD_API_KEY is optional and is read from the environment if present. Never paste the key into chat or a command line, and never print it.

An API response that omits a CVE is not proof that the CVE does not exist or that the product is unaffected. A missing score is not zero. These are source observations that need explicit interpretation.

## Hosted staging

The read-only probe needs NEURALBRIDGE_STAGING_BASE_URL to point to an isolated staging API, not neuralbridge.io, www.neuralbridge.io, or the known production Fly hostname. It only GETs /healthz and /v1/plans, sends no credentials, and never performs checkout, writes, migrations, or restores.

    export NEURALBRIDGE_STAGING_BASE_URL="https://YOUR-ISOLATED-STAGING-HOST"
    python scripts/probe_staging.py

Do not run the probe against production. If no isolated staging API exists yet, leave this check blocked and prepare staging in the product repository.

## First scenarios

- NB-001: Rockwell affected firmware versus corrected firmware.
- NB-002: discontinued hardware where the vendor states that a fix is unavailable.
- NB-003: refresh CVE/KEV/EPSS source observations without losing source history or duplicating records.
- NB-005: tampered, truncated, duplicated, missing and out-of-order evidence records.

Each scenario needs an independent expected result and a product-level integration test. Fixture validation alone is not an end-to-end product pass.

## Release semantics

Use PASS only when the described test ran and assertions passed. Use FAIL when it ran and contradicted an expectation. Use BLOCKED when the environment, access, fixture rights, source, or required dependency is unavailable. Do not treat unrun tests, mocks, green lint, a READY frontend deployment, or a copied source advisory as proof of hosted product correctness.

Raw data access and reuse terms must be reviewed per source. Do not download the large ICS-NAD corpus or the historical RITICS data until the exact dataset version, terms, storage budget and intended test value have been reviewed. Add OSV package queries only where a package identity/version exists; OSV is not a universal industrial firmware applicability oracle.
