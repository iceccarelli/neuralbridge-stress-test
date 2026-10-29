"""NB-001 fleet: the shipped five-machine fleet pack, read the way a plant manager reads it.

Evidence level: the product's own `examples/fleet/run.py` driving the product CLI, local
subprocesses, real SQLite, SYNTHETIC machines. Not hosted staging, not a real fleet.

Independent expectations, from the documentation and plain logic (not from the product's code):
* `fleet list` is documented as "worst coverage first": in its JSON, every machine with a gap must
  come before every machine without one, so a consumer reading the first row sees the worst;
* a machine nobody re-verified after its firmware was changed has a gap (stale), never "covered";
* a machine with no verification at all has a gap, never "covered";
* cover resting on a run only its filer declared is below validated and is not reported as
  validated cover;
* an advisory against a firmware the fleet runs is a finding (exit 1), and where a machine's
  label and its artefact hash disagree the product must not call it clear.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import PRODUCT_SRC

RUN = Path(PRODUCT_SRC).parent / "examples" / "fleet" / "run.py"
pytestmark = pytest.mark.skipif(
    not RUN.is_file(), reason="BLOCKED: the product has no fleet pack at this path")


@pytest.fixture(scope="module")
def fleet():
    env = dict(os.environ)      # the runner launches `python -m assurance`: use THIS product
    env["PYTHONPATH"] = os.pathsep.join(p for p in (PRODUCT_SRC, env.get("PYTHONPATH", "")) if p)
    done = subprocess.run([sys.executable, str(RUN), "--json"], capture_output=True, text=True,
                          timeout=300, check=False, env=env)
    assert done.returncode == 0, done.stdout[-600:] + done.stderr[-300:]
    return json.loads(done.stdout)


def test_the_pack_says_it_is_synthetic(fleet):
    assert fleet["synthetic"] is True and fleet["ok"] is True


def test_fleet_list_json_is_worst_first(fleet):
    order = fleet["facts"]["order"]
    verdicts = fleet["facts"]["machines"]
    assert len(order) == 5
    gap = [verdicts[m]["verdict"] == "gaps" for m in order]
    assert gap == sorted(gap, reverse=True), f"a gap comes after a machine without one: {order}"
    assert gap[0] is True and gap[-1] is False


def test_each_machines_position_is_what_its_history_implies(fleet):
    m = fleet["facts"]["machines"]
    assert (m["FLEET-04"]["verdict"], m["FLEET-04"]["worst"]) == ("gaps", "stale")
    assert (m["FLEET-05"]["verdict"], m["FLEET-05"]["worst"]) == ("gaps", "never_verified")
    assert m["FLEET-03"]["verdict"] == "covered_at_community"
    assert m["FLEET-03"]["tier_floor"] == "community"
    for ok in ("FLEET-01", "FLEET-02"):
        assert m[ok]["verdict"] == "covered" and m[ok]["tier_floor"] == "validated"


def test_the_advisory_is_a_finding_and_a_contradictory_machine_is_not_called_clear(fleet):
    adv = fleet["facts"]["advisory"]["advisories"][0]
    assert adv["verdict"] != "clear" and adv["clear_is_complete"] is False
    affected = set(adv["machines_affected"])
    assert {"DemoCo/AR-7#FLEET-02", "DemoCo/AR-7#FLEET-05"} <= affected
    contradictory = [c for c in adv["machine_classification"]
                     if c["machine"].endswith("FLEET-03")]
    assert contradictory and contradictory[0]["classification"] != "clear"
    steps = {s["step"]: s for s in fleet["steps"]}
    assert steps["fleet advisory CTRL-2026-11: expected a MATCH"]["exit"] == 1
