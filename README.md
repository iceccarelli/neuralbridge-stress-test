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

## One command, for people and agents

    bash scripts/bootstrap.sh          # once: sibling product checkout, one venv, dependencies
    python scripts/validate.py --api   # doctor, lint, all tests, and the real API on loopback
    python scripts/validate.py --json report.json   # same, plus a machine-readable report

`validate.py` prints one row per tier with its status (PASS, FAIL, BLOCKED, UNCHECKED) and
evidence level, and exits 0 only when every required tier passed (1 on a failure, 3 when a
required gate did not run). `--api` starts the product's real API on 127.0.0.1 with throwaway
state and no inherited environment (see `scripts/probe_api.py`); `--sources` fetches the public
sources with provenance. A fresh Codespace runs `bootstrap.sh` itself (`.devcontainer/`).

In Codespaces, run the commands above from the repository root. Never commit .venv, downloaded raw feeds, API keys, customer records, or private assurance evidence.

## Browser and live-site tiers

Two tiers need more than a product checkout, and say so when they cannot run (a skip names the missing piece; it is never a pass):

    bash scripts/build_site.sh            # once per product revision: builds the website from the product's committed source into data/derived/site-build (Git-ignored)
    python -m playwright --version        # tests/test_browser_site.py drives Chromium against that build and the product's real API on loopback

`tests/test_live_site.py` makes read-only GET requests to https://neuralbridge.io (pages, sitemap, robots, llms.txt, openapi.json, agent.json, public scripts). It sends no POST, no key and never touches the hosted API. If the site is unreachable from where the suite runs, it is skipped as BLOCKED.

Known defects are recorded as strict `xfail` tests that name the company issue; when the company fixes one the suite goes red until the marker is removed.

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

The GitHub Actions CI workflow runs Ruff, pytest and the offline repository doctor on Python 3.11, 3.12 and 3.13. A green CI run is required before merging; it still does not prove hosted product integration.

## Product-level adversarial suites (run against the real product code)

`tests/test_art14_clocks.py`, `test_ledger_integrity.py`, `test_advisory_matching.py` and
`test_supplier_feed.py` import the product's public modules directly, with no HTTP layer and
no copied logic. Expected values come from the cited CRA Art. 14 provisions, from outside
attacks on the ledger file, and from the stated purpose of the matcher and signed feed.

    NEURALBRIDGE_SRC=/path/to/neuralbridge/src python -m pytest -q

The product is looked for at `../neuralbridge/src` (or `/workspaces/neuralbridge/src`) unless
`NEURALBRIDGE_SRC` is set. These tests also need `cryptography` (`pip install -e ".[dev]"`).
With no product checkout they are not collected and the run header and summary say BLOCKED:
that is a gate that did not run, not a pass.

Each defect regression was also run against the pre-fix product commit and failed there.
Not covered yet: HTTP/API contracts and tenant isolation (need the product's FastAPI stack),
billing events, NB-001 and NB-005 through the product API.
