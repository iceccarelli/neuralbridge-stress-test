"""Locate the product under test; report BLOCKED, never a silent pass, when it is absent.

Product-level suites import the product's public modules directly. Expected values in
those tests come from the cited provisions or independent attacks, never from reading the
product back. Set NEURALBRIDGE_SRC to the product's ``src`` directory.
"""
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
PRODUCT_TESTS = [
    "tests/test_art14_clocks.py",
    "tests/test_ledger_integrity.py",
    "tests/test_advisory_matching.py",
    "tests/test_supplier_feed.py",
]


def _find_product_src():
    candidates = [os.environ.get("NEURALBRIDGE_SRC"), str(_ROOT.parent / "neuralbridge" / "src"),
                  "/workspaces/neuralbridge/src"]
    for c in candidates:
        if c and Path(c, "assurance").is_dir():
            return c
    return None


PRODUCT_SRC = _find_product_src()
if PRODUCT_SRC:
    sys.path.insert(0, PRODUCT_SRC)
else:
    collect_ignore = PRODUCT_TESTS


def pytest_report_header(config):
    if PRODUCT_SRC:
        return f"neuralbridge product under test: {PRODUCT_SRC}"
    return "neuralbridge product: BLOCKED (no checkout found; set NEURALBRIDGE_SRC)"


def pytest_terminal_summary(terminalreporter):
    if not PRODUCT_SRC:
        terminalreporter.write_line(
            f"BLOCKED: {len(PRODUCT_TESTS)} product-level suites were not collected; "
            "they did not run and prove nothing.", yellow=True)
