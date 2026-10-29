"""ATTACK MATRIX, product CLI level: no verb answers an operator's wrong file with a crash.

Evidence level: the product's real CLI entry point called in-process on temporary files, with
SYNTHETIC garbage. Verbs and arguments are discovered from the product's own parsers.

Independent expectation: handing a verb a JSON array where it wants an object, a directory where
it wants a file, or a file that is not a database where it wants the ledger is "could not do
that". It may refuse with any non-zero code and a message, but it must never end in an uncaught
exception (a traceback, which a shell reports as exit 1, the code several tools use for a finding).
"""
from __future__ import annotations

import pytest
from support_sweep import argv_for, verbs

CASES = [("array", "input"), ("dir", "input"), ("junk-ledger", "ledger")]


def _bad(kind, root):
    if kind == "array":
        path = root / "bad.json"
        path.write_text("[]")
    elif kind == "dir":
        path = root / "bad-dir"
        path.mkdir()
    else:
        path = root / "bad-ledger.db"
        path.write_text("this is not a sqlite database")
    return str(path)


@pytest.mark.parametrize("kind,role", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("domain,path", verbs(),
                         ids=lambda v: v if isinstance(v, str) else "-".join(v))
def test_a_wrong_file_is_refused_not_a_crash(tmp_path, monkeypatch, capsys, domain, path, kind,
                                             role):
    from assurance.cli import main
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "env-ledger.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "env-accounts.db"))
    argv = argv_for(domain, path, bad=_bad(kind, tmp_path), bad_role=role,
                    fresh=str(tmp_path / "missing-input.json"),
                    output=str(tmp_path / "fresh-output"))
    said = ""
    try:
        code = main(argv)
    except SystemExit as stop:                       # argparse and explicit exits are answers
        code = stop.code if isinstance(stop.code, int) else 2
        said = stop.code if isinstance(stop.code, str) else ""     # SystemExit("error: ...")
    except BaseException as exc:                     # noqa: BLE001 - this is the finding
        pytest.fail(f"{' '.join(argv[:3])} ... ended in an uncaught {type(exc).__name__}: {exc}")
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    if code not in (0, None):
        # a refusal says why: on stderr, in the exit message, or (a verifier's verdict) on stdout
        assert (captured.err + captured.out + said).strip(), f"exit {code} with no message"
