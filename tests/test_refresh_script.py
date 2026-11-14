"""Regression tests for the independent harness entry points."""

ROOT = __file__.rsplit("/", 2)[0]


def test_refresh_creates_derived_directory_before_redirecting_build_log():
    with open(f"{ROOT}/scripts/refresh.sh", encoding="utf-8") as stream:
        script = stream.read()
    mkdir = script.index('mkdir -p "$LAB/data/derived"')
    build_log_redirect = script.index('> "$LAB/data/derived/site-build.log"')
    test_log_assignment = script.index('LOG="$LAB/data/derived/last-run.log"')

    assert mkdir < build_log_redirect
    assert mkdir < test_log_assignment
