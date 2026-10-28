"""ATTACK MATRIX, product CLI level: the offline kit and offline commands open no sockets.

Evidence level: product CLI, local subprocess, synthetic kit, real SQLite. The oracle is an
independent ``sys.addaudithook`` observer (tests/netaudit/sitecustomize.py), not the
product's own air-gap record. What this does NOT show: a hostile build that removes the
hook's visibility via a C extension or another process; containment is a firewall's job.
"""
from __future__ import annotations

import json
import zipfile

import pytest
from support_cli import assurance, audited, audited_python, synthetic_manifest

NETWORK = {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind",
           "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
           "socket.getnameinfo"}
SPAWN = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork"}


def make_kit(root):
    """A complete SYNTHETIC kit: valid config, plan and export files."""
    assurance("kit", "init", str(root / "site"), cwd=root)
    site = root / "site"
    kit = json.loads((site / "kit.json").read_text())
    kit.update(organisation="Synthetic Test GmbH", prepared_by="synthetic.tech@example.invalid")
    (site / "kit.json").write_text(json.dumps(kit))
    plan = json.loads((site / "plans/cell.json").read_text())
    plan.update(manufacturer="SynthCo", model="Cell-1")
    for item in plan["items"]:
        item["supplier"] = "SynthCo"
    (site / "plans/cell.json").write_text(json.dumps(plan))
    exp = site / "exports/CELL-0412"
    (exp / "scanner-zones.cfg").write_text("# Exported 2026-10-27\nzone1=0.5\n")
    (exp / "robot-params.json").write_text(json.dumps(
        {"export": {"timestamp": "t", "operator": "o"}, "firmware": {"version": "1.2.3"}}))
    with zipfile.ZipFile(exp / "plc-project.zip", "w") as z:
        z.writestr("program/main.st", "PROGRAM main END_PROGRAM")
    (exp / "controller-fw.bin").write_bytes(b"\x00FW synthetic")
    return site


def test_the_observer_can_fail(tmp_path):
    """Positive control: a real connect and a real spawn ARE seen. Without this the clean
    results below would prove nothing."""
    events = audited_python(
        "import socket,subprocess\n"
        "s=socket.socket()\n"
        "try: s.connect(('127.0.0.1',9))\n"
        "except OSError: pass\n"
        "subprocess.run(['true'])\n", cwd=tmp_path, log=tmp_path / "ctl.log")
    names = {e["event"] for e in events}
    assert "socket.connect" in names and "subprocess.Popen" in names


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    return make_kit(tmp_path_factory.mktemp("kit"))


def test_kit_check_and_run_touch_no_network_and_spawn_nothing(site, tmp_path):
    chk, ev1 = audited("kit", "check", str(site / "kit.json"), cwd=site, log=tmp_path / "a.log")
    run, ev2 = audited("kit", "run", str(site / "kit.json"), "--out", str(site / "out"),
                       "--json", cwd=site, log=tmp_path / "b.log")
    assert chk.exit == 0, chk.err
    assert run.exit == 0, run.err
    leaked = [e for e in ev1 + ev2 if e["event"] in NETWORK | SPAWN]
    assert leaked == []
    airgap = run.json()["airgap"]
    assert airgap["held"] is True and airgap["attempts"] == []


def test_proxy_environment_does_not_make_the_kit_reach_out(site, tmp_path):
    run, ev = audited("kit", "run", str(site / "kit.json"), "--out", str(site / "out2"),
                      "--json", cwd=site, log=tmp_path / "p.log")
    assert run.exit == 0
    assert [e for e in ev if e["event"] in NETWORK | SPAWN] == []


def test_a_url_as_an_export_source_is_not_fetched(site, tmp_path):
    """A plan whose item 'source' is a URL must be refused or found missing, never fetched."""
    plan_path = site / "plans/cell.json"
    original = plan_path.read_text()
    plan = json.loads(original)
    plan["items"][3]["source"] = "http://127.0.0.1:9/controller-fw.bin"
    plan_path.write_text(json.dumps(plan))
    try:
        run, ev = audited("kit", "run", str(site / "kit.json"), "--out", str(site / "out3"),
                          "--json", cwd=site, log=tmp_path / "u.log")
    finally:
        plan_path.write_text(original)
    assert [e for e in ev if e["event"] in NETWORK | SPAWN] == []
    assert run.exit != 0, "a source that is not a file in the export folder was accepted"


@pytest.mark.parametrize("cmd", ["check", "run"])
def test_a_directory_instead_of_kit_json_is_exit_2_not_a_crash(site, cmd):
    """Documented contract: 2 = the kit could not run at all. 1 means a finding."""
    r = assurance("kit", cmd, str(site), cwd=site)
    assert r.exit == 2, f"exit {r.exit}; stderr tail: {r.err[-200:]!r}"
    assert "Traceback" not in r.err


def test_offline_ledger_commands_open_no_sockets(tmp_path):
    ledger = tmp_path / "l.db"
    m = tmp_path / "m.json"
    m.write_text(json.dumps(synthetic_manifest("S1", [("P1", "1756-EN2T", "11.001")])))
    cmds = [
        ("machinery", "record-manifest", str(m), "--ledger", str(ledger)),
        ("fleet", "list", "--ledger", str(ledger)),
        ("machinery", "coverage", str(m), "--ledger", str(ledger)),
    ]
    for i, args in enumerate(cmds):
        r, ev = audited(*args, cwd=tmp_path, log=tmp_path / f"c{i}.log")
        assert r.exit in (0, 1), (args, r.exit, r.err[-300:])
        assert [e for e in ev if e["event"] in NETWORK | SPAWN] == [], args
