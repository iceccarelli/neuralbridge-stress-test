"""NB-003 on the product side: public-source observations (KEV, NVD, EPSS, CSAF) via
``assurance intel``.

Evidence level: the product CLI as a subprocess, a real SQLite observation store in a temp
directory, feeds written by this suite in the sources' real JSON shapes (SYNTHETIC values; the
CVE ids are invented) plus, when ``data/raw`` was fetched by scripts/fetch_sources.py, the real
public files. Never a live fetch: ``refresh --live`` is exercised only in the form that must
refuse. If the product revision has no ``intel`` command, every test is skipped as BLOCKED.

Independent expectations, from the brief and the source semantics:

* every observation records where it came from, when, how many bytes and the SHA-256 of exactly
  those bytes; re-observing identical bytes is recorded as such and changes nothing; changed bytes
  are a new observation whose diff names what was added, removed and modified; history is
  append-only and a refresh never rewrites an earlier observation;
* a missing value is unknown, never zero: an absent EPSS score is not 0.0 and a real 0.0 is not
  "absent"; absence from KEV does not establish the vulnerability is not exploited; before any KEV
  was observed the answer is "unchecked", not "not listed";
* EPSS is time-sensitive: the score is shown with its own date, and older scores stay retrievable;
* a rejected input is recorded with its hash and reason, changes no baseline and stores no
  payload; nothing malformed is ever accepted as a partial success;
* these sources alone never make a machine affected: they carry no firmware applicability;
* the offline verbs open no socket; a live refresh needs an explicit flag; a key is never printed.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from support_cli import assurance, audited

from conftest import PRODUCT_SRC

pytestmark = pytest.mark.skipif(PRODUCT_SRC is None, reason="BLOCKED: no product checkout")
RAW = Path(__file__).resolve().parent.parent / "data" / "raw"


def _has_intel() -> bool:
    if not PRODUCT_SRC:
        return False
    return (Path(PRODUCT_SRC) / "assurance" / "intel" / "cli.py").is_file()


pytestmark = [pytestmark, pytest.mark.skipif(
    not _has_intel(), reason="BLOCKED: this product revision has no `assurance intel`")]

OK, REJECTED, COULD_NOT_RUN = 0, 1, 2
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def kev(*cves, version="2026.10.30", released="2026-10-30T17:02:45.3665Z", extra=None):
    items = [{"cveID": c, "vendorProject": "SynthVendor", "product": "SynthProduct",
              "vulnerabilityName": f"Synthetic {c}", "dateAdded": "2026-10-01",
              "shortDescription": "synthetic", "requiredAction": "apply updates",
              "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown", "notes": "",
              "cwes": []} for c in cves]
    doc = {"title": "SYNTHETIC KEV", "catalogVersion": version, "dateReleased": released,
           "count": len(items), "vulnerabilities": items}
    doc.update(extra or {})
    return doc


def epss(scores, date="2026-10-31"):
    return {"status": "OK", "status-code": 200, "version": "1.0", "access": "public",
            "total": len(scores), "offset": 0, "limit": 100,
            "data": [{"cve": c, "epss": s, "percentile": p, "date": date}
                     for c, (s, p) in scores.items()]}


def nvd(cve, *, score=7.5, status="Analyzed", modified="2026-10-20T10:00:00.000"):
    return {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "format": "NVD_CVE",
            "version": "2.0", "timestamp": "2026-10-31T12:00:00.000", "vulnerabilities": [{
                "cve": {"id": cve, "sourceIdentifier": "synthetic@example.invalid",
                        "published": "2026-10-01T00:00:00.000", "lastModified": modified,
                        "vulnStatus": status,
                        "descriptions": [{"lang": "en", "value": "synthetic"}],
                        "metrics": {"cvssMetricV31": [{
                            "source": "nvd@nist.gov", "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": score,
                                         "baseSeverity": "HIGH",
                                         "vectorString": VECTOR}}]}}}]}


class Store:
    def __init__(self, work: Path):
        self.work = work
        self.n = 0

    def write(self, name: str, doc) -> Path:
        path = self.work / name
        path.write_bytes(doc if isinstance(doc, bytes) else json.dumps(doc).encode())
        return path

    def intel(self, *args):
        return assurance("intel", *args, "--store", "s.db", cwd=self.work) if args[0] in (
            "ingest", "history", "candidates") else assurance(
            "intel", args[0], "--store", "s.db", *args[1:], cwd=self.work)

    def ingest(self, **files):
        args = []
        for flag, path in files.items():
            args += [f"--{flag}", str(path)]
        return assurance("intel", "ingest", "--store", "s.db", *args, cwd=self.work)

    def history(self):
        run = assurance("intel", "history", "--store", "s.db", "--json", cwd=self.work)
        assert run.exit == OK, run.err
        return json.loads(run.out)

    def show_cve(self, cve):
        run = assurance("intel", "show", "--store", "s.db", "--cve", cve, "--json", cwd=self.work)
        assert run.exit == OK, run.err
        return json.loads(run.out)

    def conn(self):
        return sqlite3.connect(self.work / "s.db")


@pytest.fixture()
def st(tmp_path):
    return Store(tmp_path)


# ------------------------------------------------------------------------------ provenance
def test_an_observation_records_source_time_size_and_the_sha256_of_exactly_those_bytes(st):
    path = st.write("kev.json", kev("CVE-2099-0001", "CVE-2099-0002"))
    run = st.ingest(kev=path)
    assert run.exit == OK, run.err
    (obs,) = st.history()
    data = path.read_bytes()
    assert obs["source"] == "cisa_kev" and obs["url"] == KEV_URL
    assert obs["sha256"] == hashlib.sha256(data).hexdigest()
    assert obs["byte_length"] == len(data) and obs["record_count"] == 2
    assert obs["disposition"] == "first" and obs["parse_result"] == "ok"
    assert obs["via"] == "file" and obs["locator"].endswith("kev.json")
    assert obs["parser_version"] and obs["retrieved_at"].endswith("Z")
    assert obs["feed_stamp"] == "2026-10-30T17:02:45.3665Z"


def test_re_observing_identical_bytes_is_recorded_as_unchanged_and_stores_no_second_copy(st):
    path = st.write("kev.json", kev("CVE-2099-0001"))
    assert st.ingest(kev=path).exit == OK
    assert st.ingest(kev=path).exit == OK
    first, second = st.history()
    assert (first["disposition"], second["disposition"]) == ("first", "unchanged")
    assert first["sha256"] == second["sha256"]
    assert st.conn().execute("SELECT count(*) FROM blobs").fetchone()[0] == 1


def test_changed_bytes_are_a_new_observation_and_the_diff_names_exactly_what_moved(st):
    assert st.ingest(kev=st.write("a.json", kev("CVE-2099-0001", "CVE-2099-0002",
                                                "CVE-2099-0003"))).exit == OK
    changed = kev("CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004", version="2026.10.31")
    changed["vulnerabilities"][1]["requiredAction"] = "a different action"      # 0003 modified
    assert st.ingest(kev=st.write("b.json", changed)).exit == OK
    first, second = st.history()
    assert second["disposition"] == "changed" and second["sha256"] != first["sha256"]
    diff = second["diff"]
    assert sorted(diff["added"]) == ["CVE-2099-0004"]
    assert sorted(diff["removed"]) == ["CVE-2099-0001"]
    assert sorted(diff["modified"]) == ["CVE-2099-0003"]


def test_history_is_append_only_an_earlier_observation_is_never_rewritten(st):
    st.ingest(kev=st.write("a.json", kev("CVE-2099-0001")))
    before = st.history()[0]
    st.ingest(kev=st.write("b.json", kev("CVE-2099-0001", "CVE-2099-0002", version="2026.10.31")))
    st.ingest(epss=st.write("e.json", epss({"CVE-2099-0001": ("0.5", "0.9")})))
    assert st.history()[0] == before


def test_the_store_aborts_an_update_or_a_delete_of_an_observation(st):
    st.ingest(kev=st.write("a.json", kev("CVE-2099-0001")))
    con = st.conn()
    for sql in ("UPDATE observations SET sha256='0'", "DELETE FROM observations",
                "UPDATE blobs SET body=x''", "DELETE FROM blobs"):
        with pytest.raises(sqlite3.DatabaseError):
            con.execute(sql)
            con.commit()
        con.rollback()
    assert len(st.history()) == 1


def _foreign_store(st):
    other = st.work / "s.db"
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE precious (x)")
    con.execute("INSERT INTO precious VALUES (42)")
    con.commit()
    con.close()
    return other


def test_a_store_that_is_not_an_intel_store_is_refused_and_its_contents_survive(st):
    other = _foreign_store(st)
    run = st.ingest(kev=st.write("a.json", kev("CVE-2099-0001")))
    assert run.exit == COULD_NOT_RUN and "Traceback" not in run.err
    assert "not an intel observation store" in run.err
    con = sqlite3.connect(other)
    assert list(con.execute("SELECT x FROM precious")) == [(42,)]
    assert [r[0] for r in con.execute("SELECT name FROM sqlite_master")] == ["precious"]


@pytest.mark.xfail(strict=True, reason=(
    "PRODUCT DEFECT (low): `intel ingest --store FILE` where FILE is somebody else's SQLite "
    "database refuses it (exit 2, correct) but only AFTER switching it to WAL journal mode "
    "(header bytes 18-19 change from 1 to 2; a -wal/-shm pair can appear). A command that decides "
    "a file is not its own must not have modified it. Remove this marker when the application-id "
    "check runs before any pragma that writes."))
def test_a_refused_foreign_store_is_byte_for_byte_untouched(st):
    other = _foreign_store(st)
    before = other.read_bytes()
    st.ingest(kev=st.write("a.json", kev("CVE-2099-0001")))
    assert other.read_bytes() == before


# --------------------------------------------------------------------------- unknown is not zero
def test_a_real_zero_epss_is_available_and_a_missing_score_is_unavailable_never_zero(st):
    st.ingest(epss=st.write("e.json", epss({"CVE-2099-0001": ("0.000000000", "0.000000000")})))
    real = st.show_cve("CVE-2099-0001")["epss"]
    assert real["status"] == "available" and real["score"] == 0.0
    missing = st.show_cve("CVE-2099-0002")["epss"]
    assert missing["status"] == "unavailable" and missing.get("score") is None
    assert missing.get("score") != 0.0 and "not a score of 0.0" in json.dumps(missing)


def test_before_any_kev_observation_the_answer_is_unchecked_not_not_listed(st):
    st.ingest(epss=st.write("e.json", epss({"CVE-2099-0001": ("0.1", "0.5")})))
    assert st.show_cve("CVE-2099-0001")["kev"]["status"] == "unchecked"


def test_absence_from_kev_is_stated_as_unestablished_not_as_not_exploited(st):
    st.ingest(kev=st.write("k.json", kev("CVE-2099-0001")))
    absent = st.show_cve("CVE-2099-0002")["kev"]
    assert absent["status"] == "not_listed_in_kev"
    assert "does not establish" in absent["not_established"]
    assert "not exploited" in absent["not_established"]
    listed = st.show_cve("CVE-2099-0001")["kev"]
    assert listed["status"] == "listed" and listed["citation"]["observation_seq"] == 1


def test_a_cve_nvd_never_returned_is_unknown_not_a_nonexistent_cve(st):
    st.ingest(nvd=st.write("n.json", nvd("CVE-2099-0001")))
    assert st.show_cve("CVE-2099-0001")["nvd"]["status"] == "present"
    assert st.show_cve("CVE-2099-0009")["nvd"]["status"] == "unknown"


def test_epss_is_shown_with_its_own_date_and_older_scores_stay_retrievable(st):
    st.ingest(epss=st.write("e1.json", epss({"CVE-2099-0001": ("0.10", "0.40")}, "2026-10-01")))
    st.ingest(epss=st.write("e2.json", epss({"CVE-2099-0001": ("0.60", "0.90")}, "2026-10-31")))
    now = st.show_cve("CVE-2099-0001")["epss"]
    assert now["score_date"] == "2026-10-31" and now["score"] == 0.6
    assert "time-sensitive" in now["note"]
    old = assurance("intel", "show", "--store", "s.db", "1", "--json", cwd=st.work)
    assert old.exit == OK and json.loads(old.out)["feed_stamp"] == "2026-10-01"
    assert [o["sha256"] for o in st.history()][0] != [o["sha256"] for o in st.history()][1]


def test_every_claim_cites_the_observation_that_supports_it(st):
    st.ingest(kev=st.write("k.json", kev("CVE-2099-0001")),
              epss=st.write("e.json", epss({"CVE-2099-0001": ("0.2", "0.5")})),
              nvd=st.write("n.json", nvd("CVE-2099-0001")))
    view = st.show_cve("CVE-2099-0001")
    hashes = {o["seq"]: o["sha256"] for o in st.history()}
    for key in ("kev", "epss", "nvd"):
        cite = view[key]["citation"]
        assert hashes[cite["observation_seq"]] == cite["sha256"], key
    assert view["cvss"][0]["citation"]["observation_seq"] == view["nvd"]["citation"][
        "observation_seq"]


# ------------------------------------------------------------------------- rejected input
BAD_INPUTS = {
    "not_json": b"{{{{",
    "empty": b"",
    "nul_bytes": b"\x00\x00\x00",
    "json_array": b"[1,2,3]",
    "json_null": b"null",
    "wrong_schema": json.dumps({"hello": "world"}).encode(),
    "deep_nesting": b"[" * 100_000 + b"]" * 100_000,
    "kev_vulnerabilities_not_a_list": json.dumps({**kev("CVE-2099-0001"),
                                                  "vulnerabilities": "all"}).encode(),
    "kev_malformed_cve_id": json.dumps(kev("CVE-2099-0001; DROP TABLE observations")).encode(),
    "kev_cve_id_lowercase_junk": json.dumps(kev("not-a-cve")).encode(),
    "kev_count_disagrees": json.dumps(kev("CVE-2099-0001", extra={"count": 999})).encode(),
    "kev_duplicate_ids": json.dumps(kev("CVE-2099-0001", "CVE-2099-0001")).encode(),
}


@pytest.mark.parametrize("name", sorted(BAD_INPUTS))
def test_a_bad_kev_file_is_recorded_as_rejected_with_its_hash_and_reason_and_stores_nothing(
        st, name):
    good = st.write("good.json", kev("CVE-2099-0001"))
    assert st.ingest(kev=good).exit == OK
    bad = st.write("bad.json", BAD_INPUTS[name])
    run = st.ingest(kev=bad)
    assert run.exit == REJECTED, (name, run.exit, run.err[:200])
    assert "Traceback" not in run.err
    last = st.history()[-1]
    assert last["disposition"] == "rejected" and last["reason"]
    assert last["sha256"] == hashlib.sha256(BAD_INPUTS[name]).hexdigest()
    assert st.conn().execute("SELECT count(*) FROM blobs").fetchone()[0] == 1   # no payload kept
    again = st.ingest(kev=good)                              # the baseline is untouched
    assert again.exit == OK and st.history()[-1]["disposition"] == "unchanged"


EPSS_BAD = {
    "score_above_one": epss({"CVE-2099-0001": ("1.5", "0.5")}),
    "score_negative": epss({"CVE-2099-0001": ("-0.1", "0.5")}),
    "score_nan": epss({"CVE-2099-0001": ("NaN", "0.5")}),
    "score_text": epss({"CVE-2099-0001": ("high", "0.5")}),
    "score_null": epss({"CVE-2099-0001": (None, "0.5")}),
    "percentile_above_one": epss({"CVE-2099-0001": ("0.5", "7")}),
    "bad_cve_id": epss({"CVE-2099-0001'; --": ("0.5", "0.5")}),
    "bad_date": epss({"CVE-2099-0001": ("0.5", "0.5")}, date="not-a-date"),
}


@pytest.mark.parametrize("name", sorted(EPSS_BAD))
def test_an_implausible_epss_feed_is_rejected_never_read_as_a_score(st, name):
    run = st.ingest(epss=st.write("e.json", EPSS_BAD[name]))
    assert run.exit == REJECTED, (name, run.out, run.err[:200])
    assert st.history()[-1]["disposition"] == "rejected"
    view = st.show_cve("CVE-2099-0001")["epss"]
    assert view["status"] != "available", f"{name}: a rejected feed produced a score"


def test_an_nvd_file_for_a_different_cve_than_it_claims_is_not_silently_accepted(st):
    doc = nvd("CVE-2099-0001")
    doc["vulnerabilities"][0]["cve"]["id"] = "CVE-2099-0002"
    st.ingest(nvd=st.write("n.json", doc))
    assert st.show_cve("CVE-2099-0001")["nvd"]["status"] != "present"


def test_an_oversized_file_is_rejected_not_loaded_into_memory(st):
    big = st.work / "big.json"
    with big.open("wb") as fh:
        fh.write(b'{"vulnerabilities": [')
        fh.write(b"0," * (9 * 1024 * 1024))                 # > 16 MiB of valid-looking noise
        fh.write(b"0]}")
    run = st.ingest(kev=big)
    assert run.exit in (REJECTED, COULD_NOT_RUN) and "Traceback" not in run.err
    assert all(o["disposition"] != "first" for o in st.history()) if (
        st.work / "s.db").exists() else True


def test_an_unreadable_path_is_could_not_run_and_records_nothing(st):
    run = assurance("intel", "ingest", "--store", "s.db", "--kev", "does-not-exist.json",
                    cwd=st.work)
    assert run.exit == COULD_NOT_RUN and "Traceback" not in run.err
    (st.work / "adir").mkdir()
    run = assurance("intel", "ingest", "--store", "s.db", "--kev", "adir", cwd=st.work)
    assert run.exit == COULD_NOT_RUN and "Traceback" not in run.err


def test_ingest_with_no_file_is_a_usage_error(st):
    run = assurance("intel", "ingest", "--store", "s.db", cwd=st.work)
    assert run.exit == COULD_NOT_RUN


@pytest.mark.parametrize("cve", ["CVE-2026-1' OR '1'='1", "../../etc/passwd", "CVE-2026",
                                 "cve-2026-0001", "", "CVE-2026-0001\nX: y", "CVE-26-1",
                                 "CVE-2026-0001; DROP TABLE blobs"])
def test_a_hostile_cve_argument_is_refused_without_touching_the_store(st, cve):
    st.ingest(kev=st.write("k.json", kev("CVE-2099-0001")))
    before = st.conn().execute("SELECT count(*) FROM observations").fetchone()[0]
    run = assurance("intel", "show", "--store", "s.db", "--cve", cve, cwd=st.work)
    assert "Traceback" not in run.err + run.out
    assert run.exit != OK or "kev:" in run.out           # refused, or answered about a literal id
    assert st.conn().execute("SELECT count(*) FROM observations").fetchone()[0] == before
    assert st.conn().execute("SELECT count(*) FROM blobs").fetchone()[0] >= 1


# ------------------------------------------------------------------- offline and secrets
def test_the_offline_verbs_open_no_socket(st):
    path = st.write("k.json", kev("CVE-2099-0001"))
    log = st.work / "net.jsonl"
    run, events = audited("intel", "ingest", "--store", "s.db", "--kev", str(path),
                          cwd=st.work, log=log)
    assert run.exit == OK and events == [], events
    run, events = audited("intel", "history", "--store", "s.db", cwd=st.work, log=log)
    assert run.exit == OK and events == []
    run, events = audited("intel", "candidates", "--store", "s.db", "--json", cwd=st.work,
                          log=log)
    assert run.exit == OK and events == []


def test_refresh_without_the_live_flag_refuses_and_opens_no_socket(st):
    log = st.work / "net.jsonl"
    run, events = audited("intel", "refresh", "--source", "kev", "--store", "s.db", cwd=st.work,
                          log=log)
    assert run.exit == COULD_NOT_RUN and events == []


def test_an_nvd_key_named_on_the_command_line_is_never_printed(st):
    secret = "SYNTHETIC-NVD-KEY-must-never-appear-0123456789"
    run = assurance("intel", "refresh", "--source", "nvd", "--store", "s.db", "--cve",
                    "CVE-2099-0001", "--api-key-env", "NB_TEST_NVD_KEY", cwd=st.work,
                    extra_env={"NB_TEST_NVD_KEY": secret})
    assert run.exit == COULD_NOT_RUN
    assert secret not in run.out + run.err
    store = st.work / "s.db"
    assert not store.exists() or secret.encode() not in store.read_bytes()


def test_the_key_is_not_accepted_as_a_command_line_value(st):
    run = assurance("intel", "refresh", "--source", "nvd", "--store", "s.db", "--live",
                    "--api-key", "SYNTHETIC", cwd=st.work)
    assert run.exit == COULD_NOT_RUN and "Traceback" not in run.err


# ------------------------------------------------------------------------------- concurrency
def test_two_refreshes_of_identical_new_bytes_record_one_first_and_one_unchanged(st):
    path = st.write("k.json", kev("CVE-2099-0001", "CVE-2099-0002"))
    assert st.ingest(epss=st.write("seed.json", epss({"CVE-2099-0001": ("0.1", "0.2")}))).exit == OK

    def go(_):
        return assurance("intel", "ingest", "--store", "s.db", "--kev", str(path), cwd=st.work)
    with ThreadPoolExecutor(6) as pool:
        runs = list(pool.map(go, range(6)))
    assert all(r.exit == OK for r in runs), [r.err[:100] for r in runs]
    kev_obs = [o for o in st.history() if o["source"] == "cisa_kev"]
    assert [o["disposition"] for o in kev_obs].count("first") == 1
    assert [o["disposition"] for o in kev_obs].count("unchanged") == 5
    assert len({o["seq"] for o in st.history()}) == len(st.history())


# ------------------------------------------------------------------------ what it may conclude
def test_kev_nvd_and_epss_alone_never_produce_an_advisory_or_make_a_machine_affected(st):
    st.ingest(kev=st.write("k.json", kev("CVE-2099-0001")),
              epss=st.write("e.json", epss({"CVE-2099-0001": ("0.9", "0.99")})),
              nvd=st.write("n.json", nvd("CVE-2099-0001")))
    run = assurance("intel", "candidates", "--store", "s.db", "--json", cwd=st.work)
    assert run.exit == OK
    body = json.loads(run.out)
    assert body["candidates"] == [], "public scores alone produced an advisory"
    enrichment = body["enrichments"][0]
    assert enrichment["cve_id"] == "CVE-2099-0001"
    assert enrichment["kev"]["status"] == "listed"


def test_a_csaf_candidate_is_inspect_only_and_still_never_clear(st):
    from test_attack_csaf_cli import BASE
    st.ingest(csaf=st.write("c.json", BASE))
    out = st.work / "cands"
    run = assurance("intel", "candidates", "--store", "s.db", "--out", str(out), "--json",
                    cwd=st.work)
    assert run.exit == OK
    files = sorted(out.glob("*.json"))
    assert files, json.loads(run.out)
    adv = json.loads(files[0].read_text())
    assert adv.get("import_record"), "the candidate lost its translation marker"
    assert "unsigned" in json.dumps(adv["import_record"]).lower() or "authenticated" in json.dumps(
        adv["import_record"]).lower()


# --------------------------------------------------------------------------- real public data
def _real(name):
    path = RAW / name
    return path if path.is_file() else None


@pytest.mark.skipif(not (RAW / "cisa_kev" / "known_exploited_vulnerabilities.json").is_file(),
                    reason="BLOCKED: run scripts/fetch_sources.py to fetch the real public data")
def test_the_real_cisa_catalogue_is_ingested_with_the_hash_of_the_file_and_an_exact_count(st):
    path = RAW / "cisa_kev" / "known_exploited_vulnerabilities.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    run = st.ingest(kev=path)
    assert run.exit == OK, run.err
    (obs,) = st.history()
    assert obs["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert obs["record_count"] == len(doc["vulnerabilities"]) == doc["count"]
    assert obs["feed_stamp"] == doc["dateReleased"]
    sample = doc["vulnerabilities"][0]["cveID"]
    assert st.show_cve(sample)["kev"]["status"] == "listed"


@pytest.mark.skipif(not (RAW / "first_epss" / "epss.json").is_file(),
                    reason="BLOCKED: run scripts/fetch_sources.py to fetch the real public data")
def test_the_reviewed_fixture_cve_is_not_in_the_real_kev_and_that_is_not_called_safe(st):
    fixture = json.loads((Path(__file__).resolve().parent.parent / "data" / "fixtures"
                          / "rockwell_advisories.json").read_text(encoding="utf-8"))
    cve = next(r["cve_id"] for r in fixture["records"] if r["advisory_id"] == "SD1780")
    kev_path = RAW / "cisa_kev" / "known_exploited_vulnerabilities.json"
    if not kev_path.is_file():
        pytest.skip("BLOCKED: the real KEV file is not fetched")
    assert st.ingest(kev=kev_path, epss=RAW / "first_epss" / "epss.json").exit == OK
    view = st.show_cve(cve)
    assert view["kev"]["status"] == "not_listed_in_kev"
    assert "does not establish" in view["kev"]["not_established"]
    assert view["epss"]["status"] == "available"
    assert "time-sensitive" in view["epss"]["note"] and view["epss"]["score_date"]
