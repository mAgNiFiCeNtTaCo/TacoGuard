"""tacoguard/lookup.py and its hooks (scan engine, real-time checker), plus Game mode in scans
and the checker. The HTTP layer is always faked: no test talks to abuse.ch."""
from __future__ import annotations

import hashlib
import io
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import zipfile

import pytest

from samples import MARKER, WEAK_MARKER, sample_bytes
from tacoguard import allowlist, learning, lookup, phase4, secrets
from tacoguard.guard.checker import RealtimeChecker
from tacoguard.model import CLEAN, MALWARE, SUSPICIOUS, Confidence, Finding, describe_finding
from tacoguard.scan import engine, walker
from tacoguard.store import Store

KEY = "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv12Wx34"   # made up, key-shaped
SHA = "a" * 64


# ---- fake HTTP layer --------------------------------------------------------------------------
class FakeResp:
    def __init__(self, body: bytes, status: int = 200):
        self.body, self.status, self.closed = body, status, False

    def read(self, n=-1):
        return self.body if n is None or n < 0 else self.body[:n]

    def close(self):
        self.closed = True


class FakeHTTP:
    """Stands in for lookup._open_request. `answer(sha256)` -> bytes | Exception | FakeResp."""

    def __init__(self, answer=None):
        self.requests: list[dict] = []
        self.answer = answer or (lambda sha: not_found())

    def __call__(self, req, timeout):
        form = urllib.parse.parse_qs(req.data.decode("ascii"))
        self.requests.append({"url": req.full_url, "method": req.get_method(), "timeout": timeout,
                              "headers": {k.lower(): v for k, v in req.header_items()}, "form": form})
        a = self.answer(form["hash"][0])
        if isinstance(a, BaseException):
            raise a
        return a if isinstance(a, FakeResp) else FakeResp(a)

    @property
    def count(self):
        return len(self.requests)


def found(sha, signature="AgentTesla", **extra) -> bytes:
    entry = {"sha256_hash": sha, "md5_hash": "0" * 32, "first_seen": "2024-01-02 03:04:05",
             "file_name": "invoice.exe", "file_type": "exe", "signature": signature,
             "tags": ["exe", "AgentTesla"], **extra}
    return json.dumps({"query_status": "ok", "data": [entry]}).encode()


def not_found() -> bytes:
    return json.dumps({"query_status": "hash_not_found"}).encode()


def http_error(code, body=b""):
    return urllib.error.HTTPError(lookup.API_URL, code, "error", {}, io.BytesIO(body))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Every test starts with an HTTP layer that fails the test if it is used."""
    def refuse(req, timeout):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr(lookup, "_open_request", refuse)
    secrets._cache.clear()
    yield
    secrets._cache.clear()


@pytest.fixture
def http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(lookup, "_open_request", fake)
    return fake


@pytest.fixture
def keyed(settings):
    secrets.set_key(settings, "abusech", KEY)
    return settings


# ---- lookup() ---------------------------------------------------------------------------------
def test_found_answer(keyed, store, http):
    http.answer = lambda sha: found(sha)
    info = lookup.lookup(keyed, store, SHA.upper())
    assert info["found"] and info["signature"] == "AgentTesla" and info["file_type"] == "exe"
    assert info["first_seen"] == "2024-01-02 03:04:05" and info["tags"] == ["exe", "AgentTesla"]
    assert info["link"] == f"https://bazaar.abuse.ch/sample/{SHA}/" and not info["cached"]
    (req,) = http.requests
    assert req["url"] == "https://mb-api.abuse.ch/api/v1/" and req["method"] == "POST"
    assert req["form"] == {"query": ["get_info"], "hash": [SHA]}
    assert req["headers"]["auth-key"] == KEY and req["timeout"] == 10
    assert KEY not in req["url"] and KEY not in json.dumps(req["form"])
    row = store.get_lookup(SHA)
    assert row["found"] and row["data"]["signature"] == "AgentTesla"
    assert "invoice.exe" not in json.dumps(row["data"])         # only the fields TacoGuard uses
    assert lookup.status(store)["state"] == "ok"


def test_not_found_answers(keyed, store, http):
    for state, sha in (("hash_not_found", "b" * 64), ("no_results", "c" * 64)):
        http.answer = lambda s, st=state: json.dumps({"query_status": st}).encode()
        info = lookup.lookup(keyed, store, sha)
        assert info["found"] is False and info["message"] == lookup.NOT_FOUND_NOTE
        assert store.get_lookup(sha)["found"] is False
        assert lookup.finding_for(info) is None


@pytest.mark.parametrize("answer", [http_error(401), http_error(403),
                                    json.dumps({"query_status": "unknown_auth_key"}).encode(),
                                    json.dumps({"query_status": "no_api_key"}).encode(),
                                    json.dumps({"query_status": "user_blacklisted"}).encode()])
def test_key_refused(keyed, store, http, answer, caplog):
    http.answer = lambda sha: answer
    with caplog.at_level(logging.DEBUG):
        assert lookup.lookup(keyed, store, SHA) is None
    st = lookup.status(store)
    assert st["state"] == "auth" and st["message"] == lookup.AUTH_MSG == (
        "abuse.ch didn't accept your key. Check it on auth.abuse.ch and paste it again in Settings.")
    assert store.get_lookup(SHA) is None
    assert KEY not in caplog.text
    # no asking again on its own with the same key ...
    assert lookup.lookup(keyed, store, "c" * 64) is None and http.count == 1
    # ... but at once after a new key is saved, and always for the Look up button
    secrets.set_key(keyed, "abusech", "N" * 40)
    lookup.lookup(keyed, store, "c" * 64)
    assert http.count == 2
    lookup.lookup(keyed, store, "d" * 64, force=True)
    assert http.count == 3


@pytest.mark.parametrize("answer, state", [
    (b"<html>oops</html>", "error"),
    (b"\xff\xfe\x00", "error"),
    (b"[1, 2]", "error"),
    (json.dumps({"query_status": "ok", "data": []}).encode(), "error"),
    (json.dumps({"query_status": "ok", "data": "x"}).encode(), "error"),
    (json.dumps({"query_status": "illegal_hash"}).encode(), "error"),
    (json.dumps({"query_status": "ok", "data": [{"sha256_hash": "f" * 64}]}).encode(), "error"),
    (TimeoutError("timed out"), "offline"),
    (urllib.error.URLError("no route"), "offline"),
    (ConnectionResetError(10054, "reset"), "offline"),
    (http_error(500), "busy"),
    (http_error(429), "busy"),
    (http_error(400, b'{"query_status": "http_post_expected"}'), "error"),
])
def test_bad_answers_and_errors_give_none(keyed, store, http, answer, state, caplog):
    http.answer = lambda sha: answer
    with caplog.at_level(logging.DEBUG):
        assert lookup.lookup(keyed, store, SHA) is None
    assert store.get_lookup(SHA) is None                       # nothing cached
    assert lookup.status(store)["state"] == state
    assert KEY not in caplog.text and "Traceback" not in caplog.text
    # waits 5 minutes before asking again by itself
    assert lookup.lookup(keyed, store, SHA) is None and http.count == 1


def test_oversize_answer_is_refused(keyed, store, http):
    big = found(SHA, comment="x" * (lookup.MAX_ANSWER + 10))
    http.answer = lambda sha: big
    assert lookup.lookup(keyed, store, SHA) is None
    assert lookup.status(store)["state"] == "error" and store.get_lookup(SHA) is None


def test_odd_field_values_are_cleaned(keyed, store, http):
    http.answer = lambda sha: found(sha, signature="Bad\r\nName" + "x" * 300, tags=["ok", 5, {"a": 1}, "t\x00ag"],
                                    file_type={"nested": 1}, first_seen=None)
    info = lookup.lookup(keyed, store, SHA)
    assert info["found"] and "\n" not in info["signature"] and len(info["signature"]) <= 100
    assert info["tags"] == ["ok", "5", "t ag"] and info["file_type"] == "" and info["first_seen"] == ""


def test_cache_and_its_time_limits(keyed, store, http, monkeypatch):
    http.answer = lambda sha: found(sha) if sha == SHA else not_found()
    other = "b" * 64
    assert lookup.lookup(keyed, store, SHA)["found"]
    assert lookup.lookup(keyed, store, other)["found"] is False
    assert http.count == 2
    assert lookup.lookup(keyed, store, SHA)["cached"] and lookup.lookup(keyed, store, other)["cached"]
    assert http.count == 2
    real = time.time
    monkeypatch.setattr(lookup.time, "time", lambda: real() + 2 * 24 * 3600)   # 2 days later
    assert lookup.lookup(keyed, store, SHA)["cached"]               # known: kept 7 days
    assert not lookup.lookup(keyed, store, other)["cached"]         # not known: 1 day
    assert http.count == 3
    monkeypatch.setattr(lookup.time, "time", lambda: real() + 8 * 24 * 3600)
    assert not lookup.lookup(keyed, store, SHA)["cached"]
    assert http.count == 4


def test_look_up_button_asks_again_unless_just_asked(keyed, store, http, monkeypatch):
    http.answer = lambda sha: not_found()
    lookup.lookup(keyed, store, SHA)
    assert lookup.lookup(keyed, store, SHA, force=True)["cached"]   # answer under 10 minutes old
    real = time.time
    monkeypatch.setattr(lookup.time, "time", lambda: real() + 3600)
    assert not lookup.lookup(keyed, store, SHA, force=True)["cached"]
    assert http.count == 2


def test_rate_limit_survives_a_new_store(keyed, store, http):
    for i in range(lookup.RATE_MAX):
        assert lookup.lookup(keyed, store, f"{i:064x}") is not None
    assert http.count == 30 and lookup.rate_left(store) == 0
    assert lookup.lookup(keyed, store, "e" * 64) is None
    assert lookup.status(store)["state"] == "limit"
    fresh = Store(keyed.db_path)                                    # e.g. after a restart
    try:
        assert lookup.lookup(keyed, fresh, "e" * 64, force=True) is None
        assert lookup.lookup(keyed, fresh, f"{3:064x}")["cached"]    # cached answers still work
    finally:
        fresh.close()
    assert http.count == 30


def test_rate_limit_window_moves_on(keyed, store, http, monkeypatch):
    stamps = [time.time() - 3700] * 30                              # all over an hour old
    store.set_meta(lookup.RATE_META, json.dumps(stamps))
    assert lookup.lookup(keyed, store, SHA) is not None and http.count == 1
    store.set_meta(lookup.RATE_META, "garbage")
    assert lookup.lookup(keyed, store, "b" * 64) is not None


def test_no_key_or_switched_off_means_no_network(settings, store):
    # no_network fails the test if anything is sent
    assert lookup.lookup(settings, store, SHA) is None
    assert lookup.lookup(settings, store, SHA, force=True) is None
    assert lookup.status(store)["state"] == "no_key"
    assert not lookup.ready(settings)
    secrets.set_key(settings, "abusech", KEY)
    assert lookup.ready(settings)
    settings.lookup_enabled = False
    assert not lookup.ready(settings)
    assert lookup.lookup(settings, store, SHA) is None
    assert lookup.lookup(settings, store, "not a hash", force=True) is None


def test_only_listed_hosts(keyed, store, http, monkeypatch):
    monkeypatch.setattr(lookup, "API_URL", "https://evil.example/api/")
    assert lookup.lookup(keyed, store, SHA) is None and http.count == 0


def test_redirects_are_never_followed():
    h = lookup._NoRedirects()
    assert h.redirect_request(None, None, 302, "Found", {}, "https://mb-api.abuse.ch/x") is None


def test_finding_for():
    assert lookup.finding_for(None) is None
    assert lookup.finding_for({"found": False}) is None
    known = {"found": True, "signature": "AgentTesla", "file_type": "exe", "first_seen": "2024-01-02",
             "link": f"https://bazaar.abuse.ch/sample/{SHA}/"}
    # a malware name AND no valid digital signature: HIGH
    f = lookup.finding_for(known, signed=False)
    assert (f.engine, f.rule, f.confidence, f.source) == ("lookup", "AgentTesla", Confidence.HIGH,
                                                          "MalwareBazaar (abuse.ch)")
    assert f.reference.endswith(f"/sample/{SHA}/")
    assert f.detail == "MalwareBazaar lists this exact file as 'AgentTesla' malware, first seen 2024-01-02 (exe file)"
    assert describe_finding(f).startswith("MalwareBazaar lookup 'AgentTesla' (MalwareBazaar (abuse.ch), high")
    # a validly signed file, or the signature not checked: MEDIUM, "not proof on its own"
    for signed in (True, None):
        m = lookup.finding_for(known, signed=signed)
        assert m.confidence == Confidence.MEDIUM and m.rule == "AgentTesla"
        assert m.detail.startswith("MalwareBazaar has a copy of this file (uploaded as 'AgentTesla'), which is not "
                                   "proof on its own")
        assert ("valid digital signature" in m.detail) == bool(signed)
    # no malware name: MEDIUM even for an unsigned file
    g = lookup.finding_for({"found": True, "signature": "", "link": ""}, signed=False)
    assert g.confidence == Confidence.MEDIUM and g.rule == "unnamed upload"
    assert g.detail == "MalwareBazaar has a copy of this file (uploaded as 'unnamed'), which is not proof on its own"
    assert lookup.found_words(known) == ("MalwareBazaar has a copy of this exact file, uploaded as 'AgentTesla' "
                                         "(first seen 2024-01-02).")


# ---- scan engine hook -------------------------------------------------------------------------
class Det:
    """MARKER -> HIGH, WEAK_MARKER -> MEDIUM (a suspicious file)."""

    def __init__(self, name="yara"):
        self.name, self.scans_members = name, True
        self.opened = self.closed = 0

    def status(self):
        return {"ready": True, "message": "", "version": "v1", "updated": 0, "count": 1}

    def version(self):
        return "v1"

    def open(self):
        self.opened += 1

    def close(self):
        self.closed += 1

    def has_signatures(self):
        return True

    def scan(self, item):
        data = item.data
        if data is None:
            with open(item.path, "rb") as f:
                data = f.read()
        if MARKER in data:
            return [Finding(self.name, "Test_Marker", Confidence.HIGH, "tests")]
        if WEAK_MARKER in data:
            return [Finding(self.name, "Test_Weak", Confidence.MEDIUM, "tests")]
        return []


class Clam(Det):
    def __init__(self):
        super().__init__("clamav")

    def scan(self, item):
        return [Finding("clamav", "TacoGuard.Test.HarmlessSample-1", Confidence.HIGH, "test signature")]


def check(settings, store, path, detectors=None):
    (e,) = [t for t in walker.walk([str(path)]) if isinstance(t, walker.FileEntry)]
    return engine.check_file(e, detectors or [Det()], allowlist.TrustChecker(store), settings, store, "v1")


def test_flagged_file_gets_the_high_lookup_finding(keyed, store, http, tmp_path):
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    http.answer = lambda s: found(s)
    r = check(keyed, store, p)
    assert r.level == MALWARE
    assert [(f.engine, f.rule, f.confidence) for f in r.findings] == [
        ("yara", "Test_Weak", Confidence.MEDIUM), ("lookup", "AgentTesla", Confidence.HIGH)]
    assert http.requests[0]["form"]["hash"] == [sha]
    assert "MalwareBazaar lookup 'AgentTesla'" in r.reason()


def test_not_known_adds_a_note(keyed, store, http, tmp_path):
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    r = check(keyed, store, p)
    assert r.level == SUSPICIOUS and r.notes == [lookup.NOT_FOUND_NOTE]
    r = check(keyed, store, p)                                      # cached: no second request
    assert r.notes == [lookup.NOT_FOUND_NOTE] and http.count == 1


def test_clean_files_are_never_looked_up(keyed, store, http, tmp_path):
    p = tmp_path / "ok.txt"
    p.write_bytes(b"just text")
    r = check(keyed, store, p)
    assert r.level == CLEAN and http.count == 0 and r.notes == []


def test_offline_changes_nothing(keyed, store, http, tmp_path):
    http.answer = lambda s: TimeoutError("slow")
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    r = check(keyed, store, p)
    assert r.level == SUSPICIOUS and r.notes == [] and [f.engine for f in r.findings] == ["yara"]


def test_switch_off_or_no_key_means_no_lookup(settings, store, tmp_path):
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    assert check(settings, store, p).level == SUSPICIOUS              # no key: no network (fixture)
    secrets.set_key(settings, "abusech", KEY)
    settings.lookup_enabled = False
    assert check(settings, store, p).level == SUSPICIOUS


def test_archive_members_are_never_looked_up_only_the_outer_file(keyed, store, http, tmp_path):
    p = tmp_path / "pack.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("inner/bad.exe", sample_bytes())
    outer = hashlib.sha256(p.read_bytes()).hexdigest()
    inner = hashlib.sha256(sample_bytes()).hexdigest()
    http.answer = lambda s: found(s, signature="Zipped")
    r = check(keyed, store, p)
    assert [req["form"]["hash"][0] for req in http.requests] == [outer]
    assert inner != outer
    lk = [f for f in r.findings if f.engine == "lookup"]
    assert len(lk) == 1 and lk[0].member == ""


def test_learning_cannot_soften_a_lookup_finding(keyed, store, http, tmp_path):
    for i in range(5):                                             # "not a threat" x5 for the same name
        store.add_verdict(f"{i:064x}", f"C:\\x{i}.exe", learning.NOT_A_THREAT,
                          [{"engine": "lookup", "rule": "AgentTesla"}])
    assert learning.learned_rules(store) == []
    lowered, _ = learning.adjust([Finding("lookup", "AgentTesla", Confidence.HIGH, "x")], store, keyed)
    assert lowered[0].confidence == Confidence.HIGH
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    http.answer = lambda s: found(s)
    r = check(keyed, store, p)
    assert r.level == MALWARE
    assert [f.confidence for f in r.findings if f.engine == "lookup"] == [Confidence.HIGH]


def test_a_signed_file_known_to_malwarebazaar_is_only_medium(keyed, store, http, tmp_path, monkeypatch):
    """Anyone can upload a file to MalwareBazaar, signed installers too: for a validly signed file
    the lookup is a MEDIUM match ("not proof on its own"), never HIGH."""
    from tacoguard.signing import SignatureInfo
    monkeypatch.setattr(engine.signing, "check_signature", lambda p: SignatureInfo(True, "Some Publisher"))
    p = tmp_path / "signed.exe"
    p.write_bytes(b"MZ" + MARKER)
    http.answer = lambda s: found(s)
    r = check(keyed, store, p)
    conf = {f.engine: f.confidence for f in r.findings}
    assert conf == {"yara": Confidence.MEDIUM, "lookup": Confidence.MEDIUM}
    (lk,) = [f for f in r.findings if f.engine == "lookup"]
    assert "not proof on its own" in lk.detail and "valid digital signature" in lk.detail


def test_an_unnamed_upload_is_only_medium(keyed, store, http, tmp_path):
    p = tmp_path / "weak.exe"
    p.write_bytes(b"x" + WEAK_MARKER)
    http.answer = lambda s: found(s, signature=None)
    r = check(keyed, store, p)
    (lk,) = [f for f in r.findings if f.engine == "lookup"]
    assert lk.confidence == Confidence.MEDIUM and "uploaded as 'unnamed'" in lk.detail


def test_scan_job_with_lookup(keyed, store, http, tmp_path):
    folder = tmp_path / "scan"
    folder.mkdir()
    (folder / "a.exe").write_bytes(b"x" + WEAK_MARKER)
    (folder / "b.txt").write_bytes(b"fine")
    http.answer = lambda s: found(s)
    job_id = store.create_job([str(folder)])
    engine.scan_job(keyed, store, job_id, [Det()])
    job = store.get_job(job_id)
    assert job["status"] == "done" and job["counts"]["malware"] == 1 and job["counts"]["clean"] == 1
    (res,) = store.list_results(job_id)
    assert res["level"] == MALWARE and {f["engine"] for f in res["findings"]} == {"yara", "lookup"}
    assert http.count == 1


# ---- real-time checker hook -------------------------------------------------------------------
@pytest.fixture
def watched(tmp_path):
    w = tmp_path / "watched"
    w.mkdir()
    return w


def test_checker_flagged_file_is_looked_up_and_needs_no_clamav(keyed, store, http, watched):
    clam = Clam()
    c = RealtimeChecker(keyed, store, [Det(), clam])
    try:
        (watched / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
        (watched / "ok.txt").write_bytes(b"fine")
        http.answer = lambda s: found(s)
        assert c.check_path(str(watched / "ok.txt")).level == CLEAN and http.count == 0
        r = c.check_path(str(watched / "weak.exe"))
        assert r.level == MALWARE and {f.engine for f in r.findings} == {"yara", "lookup"}
        assert clam.opened == 0 and http.count == 1
        event_id = c.report(r, "file")
        ev = store.get_guard_event(event_id)
        assert ev["level"] == MALWARE and "MalwareBazaar" in ev["message"]
    finally:
        c.close()


def test_checker_not_known_still_gets_the_clamav_second_opinion(keyed, store, http, watched):
    clam = Clam()
    c = RealtimeChecker(keyed, store, [Det(), clam])
    try:
        (watched / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
        r = c.check_path(str(watched / "weak.exe"))
        assert clam.opened == 1 and {f.engine for f in r.findings} == {"yara", "clamav"}
        assert lookup.NOT_FOUND_NOTE in r.notes and http.count == 1    # second check used the cache
    finally:
        c.close()


def test_checker_skips_clamav_in_game_mode(settings, store, watched):
    clam = Clam()
    c = RealtimeChecker(settings, store, [Det(), clam])
    try:
        (watched / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
        phase4.set_game_mode(store, True, manual=True)
        r = c.check_path(str(watched / "weak.exe"))
        assert r.level == SUSPICIOUS and clam.opened == 0 and not c.clamav_running
        phase4.set_game_mode(store, False, manual=True)
        r = c.check_path(str(watched / "weak.exe"))
        assert r.level == MALWARE and clam.opened == 1
    finally:
        c.close()


# ---- Game mode in scans -----------------------------------------------------------------------
def _start_scan(settings, store, folder):
    job_id = store.create_job([str(folder)])
    t = threading.Thread(target=engine.scan_job, args=(settings, store, job_id, [Det()]), daemon=True)
    t.start()
    return job_id, t


def _wait(fn, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return True
        time.sleep(0.05)
    return bool(fn())


@pytest.fixture
def files(tmp_path):
    folder = tmp_path / "many"
    folder.mkdir()
    for i in range(5):
        (folder / f"f{i}.txt").write_bytes(b"fine %d" % i)
    (folder / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
    return folder


def test_scan_waits_while_game_mode_is_on_and_finishes_after(settings, store, files, monkeypatch):
    monkeypatch.setattr(engine, "GAME_MODE_POLL_S", 0.2)
    phase4.set_game_mode(store, True, manual=False, reason="full-screen game")
    job_id, t = _start_scan(settings, store, files)
    assert _wait(lambda: store.get_job(job_id)["message"] == engine.GAME_MODE_WAIT_MSG)
    before = store.get_job(job_id)["heartbeat"]
    time.sleep(0.6)
    job = store.get_job(job_id)
    assert job["status"] == "running" and job["counts"].get("files", 0) == 0
    assert job["heartbeat"] > before                                # kept alive while waiting
    phase4.set_game_mode(store, False, manual=False)
    t.join(10)
    job = store.get_job(job_id)
    assert job["status"] == "done" and job["counts"]["files"] == 6 and job["counts"]["suspicious"] == 1
    assert job["counts"]["seconds"] < 0.6                         # the wait is not scan time


def test_pause_and_cancel_work_while_waiting(settings, store, files, monkeypatch):
    monkeypatch.setattr(engine, "GAME_MODE_POLL_S", 0.2)
    phase4.set_game_mode(store, True, manual=True)
    job_id, t = _start_scan(settings, store, files)
    assert _wait(lambda: store.get_job(job_id)["message"] == engine.GAME_MODE_WAIT_MSG)
    store.set_control(job_id, "pause")
    t.join(10)
    job = store.get_job(job_id)
    assert job["status"] == "paused" and job["checkpoint"] == ""
    # resumed after Game mode ended: every file checked once
    phase4.set_game_mode(store, False, manual=True)
    store.set_control(job_id, "")
    engine.scan_job(settings, store, job_id, [Det()])
    job = store.get_job(job_id)
    assert job["status"] == "done" and job["counts"]["files"] == 6
    assert len(store.list_results(job_id)) == 1

    phase4.set_game_mode(store, True, manual=True)
    job2, t2 = _start_scan(settings, store, files)
    assert _wait(lambda: store.get_job(job2)["message"] == engine.GAME_MODE_WAIT_MSG)
    store.set_control(job2, "cancel")
    t2.join(10)
    assert store.get_job(job2)["status"] == "cancelled"


def test_game_mode_mid_scan_keeps_the_checkpoint_right(settings, store, tmp_path, monkeypatch):
    """Game mode switched on part-way: the scan waits after the files already checked, a pause
    there keeps the checkpoint at the last checked file, and resume checks the rest once."""
    monkeypatch.setattr(engine, "GAME_MODE_POLL_S", 0.2)
    monkeypatch.setattr(engine, "GAME_MODE_CHECK_S", 0.0)          # look before every file
    folder = tmp_path / "mid"
    folder.mkdir()
    for i in range(6):
        (folder / f"f{i}.txt").write_bytes(b"x" + WEAK_MARKER if i == 4 else b"ok %d" % i)
    seen = []

    class Slow(Det):
        def scan(self, item):
            seen.append(item.display)
            if len(seen) == 3:
                phase4.set_game_mode(store, True, manual=True)
            return super().scan(item)

    job_id = store.create_job([str(folder)])
    t = threading.Thread(target=engine.scan_job, args=(settings, store, job_id, [Slow()]), daemon=True)
    t.start()
    assert _wait(lambda: store.get_job(job_id)["message"] == engine.GAME_MODE_WAIT_MSG)
    store.set_control(job_id, "pause")
    t.join(10)
    job = store.get_job(job_id)
    assert job["status"] == "paused" and job["counts"]["files"] == 3
    assert job["checkpoint"].endswith("f2.txt")
    phase4.set_game_mode(store, False, manual=True)
    store.set_control(job_id, "")
    engine.scan_job(settings, store, job_id, [Slow()])
    job = store.get_job(job_id)
    assert job["status"] == "done" and job["counts"]["files"] == 6 and job["counts"]["suspicious"] == 1
    assert len(seen) == 6 and len(set(seen)) == 6
