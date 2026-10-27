# neuralbridge-stress-test
Independent adversarial assurance tests for NeuralBridge

## Running

```bash
python -m pytest -q          # product found at ../neuralbridge/src
NEURALBRIDGE_SRC=/path/to/neuralbridge/src python -m pytest -q
```

Needs only `pytest`; the targeted modules are stdlib-only. Expected values are
written from the cited provisions (CRA Art. 14) and from outside attacks on the
ledger file, never read back from the product. A test here that passes on a
known-defective commit is not evidence, so each defect regression is checked
against the pre-fix commit.

## Scope today (what this does *not* cover)

Art. 14 clock arithmetic and register write rules; hash-chain tamper detection
and a concurrent-writer attack. Not yet covered: HTTP/API boundaries (needs the
product's FastAPI dependencies), tenant isolation, entitlements, billing events,
advisory matching (no scenario registry exists in either repository).
