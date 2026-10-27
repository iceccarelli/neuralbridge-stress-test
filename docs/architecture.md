# Architecture and data governance

## Test authority

This repository defines scenarios, curated source facts, synthetic adversarial inputs and expected results. NeuralBridge product code remains in the separate product repository. The harness must exercise the product through its documented CLI/API where relevant; it must not copy product internals or reimplement the production decision engine as its oracle.

## Data layers

1. Source registry: stable source identity, publisher, retrieval method and terms/reuse status.
2. Raw observations: exact bounded response bytes stored locally under data/raw, with UTC retrieval time and SHA-256. Raw observations are Git-ignored.
3. Curated facts: small reviewed extracts with a source URL, review date and explicit scope. Do not store a full advisory if a few facts suffice.
4. Synthetic fixtures: invented customer assets, event sequences and corruptions labelled as synthetic.
5. Expected results: documented independently, including unknown and not-applicable states.
6. Product integration runs: request/response evidence, product commit, source-manifest hash and test result. Do not record secrets or customer-confidential payloads.

## Data policies

- Every source update creates a new observation or immutable archival object; it does not silently replace the historical observation.
- Every result distinguishes source fact, inference, customer-provided evidence and synthetic input.
- A vendor advisory describes an affected product/version, not the inventory or firmware running at a particular customer site.
- CISA KEV membership is evidence of inclusion in that catalogue. Absence is not evidence that a vulnerability does not exist.
- NVD and vendor records may differ, lag or omit fields. Preserve each source independently and record conflicts; do not silently pick one.
- EPSS is a time-sensitive exploitation-probability estimate, not proof of exploitation or device applicability.
- OSV is intended for versioned software/package queries. Do not use it as a universal firmware/CPE mapping engine.
- No bulk dataset is acquired until the exact release, terms/licence, attribution, size, retention, and test purpose are approved.
- ICS-NAD is explicitly deferred during bootstrap because of its reported scale and unresolved acquisition/redistribution review.
- No passwords, API keys, certificates, customer assets or signed customer evidence belong in this public repository.

## Scenario lifecycle

DRAFT -> SOURCE_REVIEWED -> FIXTURE_REVIEWED -> PRODUCT_INTEGRATION -> INDEPENDENT_REVIEW -> ACCEPTED.

A fixture-only contract test must not be marked as product integration. A test against the production website is not an acceptable substitute for an isolated staging rehearsal.
