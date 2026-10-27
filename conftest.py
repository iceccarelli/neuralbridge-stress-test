"""Locate the product under test.

This repository holds *independent* expectations. It imports the product only
through its public modules and never copies product logic: every expected value
in tests/ is derived from the cited provision, not read back from the product.
Point NEURALBRIDGE_SRC at the product's ``src`` directory (default: a sibling
checkout).
"""
import os
import sys
from pathlib import Path

_src = os.environ.get("NEURALBRIDGE_SRC") or str(
    Path(__file__).resolve().parent.parent / "neuralbridge" / "src"
)
if not Path(_src, "assurance").is_dir():
    raise RuntimeError(f"NEURALBRIDGE_SRC={_src!r} does not contain the assurance package")
sys.path.insert(0, _src)
