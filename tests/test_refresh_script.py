"""Regression tests for the independent harness entry points."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_refresh_creates_derived_directory_before_redirecting_build_log():
    script = (ROOT / "scripts" / "refresh.sh").read_text(encoding="utf-8")
    mkdir = script.index('mkdir -p "$LAB/data/derived"')
    build_log_redirect = script.index('> "$LAB/data/derived/site-build.log"')
    test_log_assignment = script.index('LOG="$LAB/data/derived/last-run.log"')

    assert mkdir < build_log_redirect
    assert mkdir < test_log_assignment
