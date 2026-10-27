# Claude Code working agreement — NeuralBridge stress tests

## Mission

This repository is the independent test authority for NeuralBridge. It owns source provenance, minimized fixtures, synthetic adversarial inputs, independent expected results, and reproducible regressions. It does not own production implementation.

Canonical product repository: `iceccarelli/neuralbridge`.
Expected Codespaces sibling checkout: `/workspaces/neuralbridge`.
Product changes must be made in a separate product branch, never copied into this repository.

## Before every work session

1. Inspect the current branch, HEAD, worktree status, and upstream. Preserve uncommitted changes; never run reset, clean, force-push or automatic stash.
2. Read `README.md`, `docs/architecture.md`, `configs/sources.json`, and `configs/scenarios.json`.
3. If the sibling product checkout exists, inspect its `CLAUDE.md`, `HANDOFF.md`, `DEPLOY_NOW.md`, `ROADMAP.md`, and the relevant implementation/tests. Confirm exact product HEAD instead of assuming it.
4. Run `python scripts/doctor.py`, `ruff check .` and `pytest -q` before changing the harness.

## Data and evidence rules

- A vendor advisory states product/version applicability; it does not establish which device a customer owns or what firmware is installed at their site.
- Distinguish source facts, inferences, customer-provided evidence and synthetic inputs. The initial evidence-event fixture is synthetic.
- Keep raw downloads and derived data under Git-ignored `data/raw/` and `data/derived/`. Never commit API keys, customer inventories, signed customer attestations, proprietary evidence or complete source datasets.
- Capture source URL/identity, retrieval time, response status, byte count and SHA-256. Preserve time-indexed observations rather than silently replacing history.
- Missing data is unknown, not zero. Absence from CISA KEV is not proof that a vulnerability does not exist or cannot be exploited. EPSS is time-sensitive.
- Review the exact dataset release, licence/terms, attribution, storage and redistribution rights before bulk acquisition. Do not bulk-download ICS-NAD or RITICS during bootstrap.
- Do not treat a source fetch succeeding as proof of the product's conclusion.

## Scenario status

Use only:
- PASS — the stated test ran against the stated target and its assertions passed.
- FAIL — the test ran and contradicted the independent expectation.
- BLOCKED — required host, access, data, licence review or dependency is missing.
- UNCHECKED — the test was not executed.

A fixture test is not a product-integration test. A local test is not a hosted-staging test. A READY Vercel website is not proof that the assurance API, checkout or billing works.

## Safety and change control

- Work on feature branches; never commit to `main`.
- First create a minimal failing reproducer for a confirmed product defect. Keep the independent test here and fix implementation in the product repository.
- Use isolated local services or explicitly approved staging only. Never run destructive/recovery scenarios on production.
- Never enable live Stripe, create live charges, apply production migrations, change production secrets or deploy without explicit owner-controlled authorization.
- Do not print secrets or paste them into Claude/chat. Use environment variables and approved secret managers.
- Do not add unrelated features, duplicate the product implementation, or create extra status/audit Markdown files.
- Do not change expected outcomes merely to make tests pass.

## Current initial scope

- NB-001: affected firmware versus corrected firmware.
- NB-002: discontinued hardware with no vendor fix.
- NB-003: source refresh, deduplication, missing values and historical observations.
- NB-005: tampered, truncated, duplicated, missing and out-of-order evidence.

Prioritize NB-001 and NB-005 for initial product integration. Read the actual implementation and existing product tests to identify the supported CLI/API contracts; do not invent endpoints. If no safe local product interface exists, return a precise blocker and the next safe implementation step rather than mocking the core logic.
