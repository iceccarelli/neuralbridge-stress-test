"""ATTACK MATRIX, product CLI (NB-006): does a recorded run stay inside its declared envelope?

Evidence level: product CLI (`python -m assurance machine verify`), local subprocess, SYNTHETIC
envelope and traces written by this file. Not hosted staging, no recorder attestation, so every
accepted result is at most community and may not claim physical behaviour.

Independent expectations, from the envelope's own numbers and plain geometry (not from the
product's code):
* a run whose every sample is inside the stated workspace, at or under the stated speed for its
  mode, and at a stated distance well beyond any plausible stopping need, passes (exit 0);
* one sample outside the workspace, over the speed cap of its mode, moving in a mode capped at
  zero, or with a separation of zero while moving, is a FAIL (exit 1) naming that check;
* the stop figures were measured at 500 mm/s: a run well under that is covered by them, a run
  above it is not;
* missing or unusable data is never a pass: no samples, no separation recorded, a non-finite
  speed. Missing is unknown, not compliant.
"""
from __future__ import annotations

import json

import pytest
from support_cli import assurance

ENVELOPE = {
    "envelope_id": "ENV-STRESS-1", "product": "STRESS PRODUCT", "product_version": "1.0",
    "workspace": {"minimum": [-1000.0, -1000.0, 0.0], "maximum": [1000.0, 1000.0, 2000.0],
                  "frame": "cell"},
    "max_tcp_speed_mm_s": {"automatic": 2000.0, "ssm": 750.0, "reduced_speed": 250.0,
                           "stopped": 0.0},
    "stop": {"reaction_time_s": 0.1, "stop_time_s": 0.25, "stop_distance_mm": 120.0,
             "measured_at_speed_mm_s": 500.0,
             "basis": {"kind": "measured", "reference": "SYNTHETIC stop test",
                       "date": "2026-02-01"}},
    "uncertainty": {"human_position_mm": 100.0, "robot_position_mm": 50.0,
                    "basis": {"kind": "measured", "reference": "SYNTHETIC calibration",
                              "date": "2026-02-01"}},
    "intrusion_distance_mm": 850.0, "human_approach_speed_mm_s": 1600.0, "pfl_limits_hash": "",
    "declared_by": {"identifier": "t.engineer", "role": "safety engineer", "kind": "person"},
    "notes": "SYNTHETIC; written by the stress-test harness.",
}


def sample(i: int, **over) -> dict:
    base = {"t": round(i / 50, 2), "tcp": [0.0, 500.0, 900.0], "tcp_speed": 400.0,
            "mode": "ssm", "separation": 6000.0, "human_speed": None}
    base.update(over)
    return base


def trace(samples: list[dict]) -> dict:
    return {"trace_id": "RUN-STRESS", "provenance": "field", "source_system": "SYNTHETIC",
            "started_at": "2026-03-10T10:00:00Z", "sample_rate_hz": 50.0, "conditions": {},
            "samples": samples}


def run_verify(tmp_path, samples):
    (tmp_path / "e.json").write_text(json.dumps(ENVELOPE))
    (tmp_path / "t.json").write_text(json.dumps(trace(samples)))      # allow_nan on purpose
    done = assurance("machine", "verify", "--envelope", "e.json", "--trace", "t.json",
                     "--actor", "stress", "--json", cwd=tmp_path)
    try:
        result = done.json()["result"]
    except (ValueError, KeyError):
        result = {}
    return done, result


def violated(result: dict) -> set[str]:
    return {c["name"] for c in result.get("checks", []) if c.get("violation_count", 0) > 0}


def run_of(n: int = 100, **over) -> list[dict]:
    return [sample(i, **over) for i in range(n)]


def test_a_run_inside_every_stated_limit_passes_and_claims_nothing_physical(tmp_path):
    done, result = run_verify(tmp_path, run_of())
    assert done.exit == 0, done.err
    assert result["verdict"] == "pass" and result["tier"] == "community"
    assert result["may_claim_physical_behaviour"] is False


@pytest.mark.parametrize("label,samples,check", [
    ("outside the workspace", run_of() + [sample(100, tcp=[1300.0, 0.0, 900.0])],
     "workspace_containment"),
    ("below the workspace floor", run_of() + [sample(100, tcp=[0.0, 0.0, -50.0])],
     "workspace_containment"),
    ("over the speed cap of its mode", run_of() + [sample(100, tcp_speed=800.0)], "speed_limit"),
    ("moving in a mode capped at zero", run_of() + [sample(100, mode="stopped", tcp_speed=10.0)],
     "speed_limit"),
    ("above the speed the stop figures were measured at",
     run_of() + [sample(100, tcp_speed=700.0)], "stop_characterisation"),
    ("zero separation while moving", run_of() + [sample(100, separation=0.0)],
     "ssm_separation"),
])
def test_one_bad_sample_is_a_fail_naming_the_check(tmp_path, label, samples, check):
    done, result = run_verify(tmp_path, samples)
    assert done.exit == 1, f"{label}: exit {done.exit}\n{done.out[:300]}"
    assert result["verdict"] == "fail", label
    assert check in violated(result), f"{label}: violated {violated(result)}"


def test_the_stop_figures_cover_a_run_under_the_speed_they_were_measured_at(tmp_path):
    done, result = run_verify(tmp_path, run_of(tcp_speed=499.0))
    assert done.exit == 0 and result["verdict"] == "pass", done.out[:300]


@pytest.mark.parametrize("label,samples", [
    ("no samples at all", []),
    ("no separation recorded in a mode that needs it", run_of(separation=None)),
    ("a non-finite speed", run_of() + [sample(100, tcp_speed=float("nan"))]),
    ("an infinite position", run_of() + [sample(100, tcp=[float("inf"), 0.0, 900.0])]),
])
def test_missing_or_unusable_data_is_never_a_pass(tmp_path, label, samples):
    done, result = run_verify(tmp_path, samples)
    assert done.exit != 0, f"{label}: exit 0, verdict {result.get('verdict')}"
    assert result.get("verdict") != "pass", label
