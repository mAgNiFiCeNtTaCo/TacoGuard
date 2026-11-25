"""The local page: security checks, the JSON API, the static page, and Defender status parsing.

The server runs in a thread on a free port with a temp data folder. Parts other helpers build
(scan jobs, detectors, quarantine) are used when they are implemented; while they still raise
NotImplementedError, small fakes stand in. Downloads (setup_fetch) and the Defender check are
always faked: tests never touch the network or the real machine's settings.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

from tacoguard import config, defender, detect, quarantine, setup_fetch
from tacoguard.model import Confidence, FileResult, Finding, SKIPPED, UNREADABLE
from tacoguard.scan import jobs
from tacoguard.store import Store
from tacoguard.web import server

# ---------------------------------------------------------------------------------------------
# fakes (used only where the real part is not implemented yet)
# ---------------------------------------------------------------------------------------------


class FakeJobs:
    @staticmethod
    def start_scan(settings, store, targets):
        for t in targets:
            if not os.path.exists(t):
                raise ValueError(f"Not found: {t}")
        job_id = store.create_job(list(targets))
        store.update_job(job_id, status="running", started=time.time(), message="Scanning",
                         counts={"files": 1, "bytes": 10, "clean": 1})
        return job_id

    @staticmethod
    def pause_scan(store, job_id):
        store.set_control(job_id, "pause")
        store.update_job(job_id, status="paused")

    @staticmethod
    def cancel_scan(store, job_id):
        store.set_control(job_id, "cancel")
        store.update_job(job_id, status="cancelled", finished=time.time())

    @staticmethod
    def resume_scan(settings, store, job_id):
        store.update_job(job_id, status="running", control="")

    @staticmethod
    def recover_interrupted(store):
        return []


class FakeQuarantine:
    def __init__(self, settings, store):
        self.store = store

    def put(self, path, reason, findings, result_id=0):
        qid = self.store.add_quarantine(path, "0" * 64, 5, reason, findings, "blob1", result_id)
        self.store.set_quarantine_state(qid, "quarantined")
        return qid

    def restore(self, qid, trust=False):
        self.store.set_quarantine_state(qid, "restored")
        return self.store.get_quarantine(qid)["original_path"]

    def delete(self, qid):
        self.store.set_quarantine_state(qid, "deleted")

    def items(self):
        return self.store.list_quarantine()

    def recover(self):
        return []

    def used_bytes(self):
        return sum(i["size"] for i in self.items())


def _implemented(fn) -> bool:
    try:
        fn()
        return True
    except NotImplementedError:
        return False
    except Exception:
        return True   # implemented, just unhappy with our probe arguments


FAKE_DEFENDER = {"available": True, "level": "ok", "message": defender.MSG_OK, "advice": "",
                 "realtime_on": True, "signature_updated": 0, "signature_version": "1.2.3"}


@pytest.fixture
def parts(settings, monkeypatch, tmp_path):
    """Install fakes where needed. Returns which parts are real."""
    probe_store = Store(tmp_path / "probe.db")
    real = {
        "jobs": _implemented(lambda: jobs.recover_interrupted(probe_store)),
        "quarantine": _implemented(lambda: quarantine.Quarantine(settings, probe_store)),
        "detect": _implemented(lambda: detect.signature_status(settings)),
    }
    probe_store.close()
    if not real["jobs"]:
        for name in ("start_scan", "pause_scan", "cancel_scan", "resume_scan", "recover_interrupted"):
            monkeypatch.setattr(jobs, name, getattr(FakeJobs, name))
    if not real["quarantine"]:
        monkeypatch.setattr(quarantine, "Quarantine", FakeQuarantine)
    if not real["detect"]:
        monkeypatch.setattr(detect, "signature_status", lambda s: {
            "hash": {"ready": True, "message": "Ready", "count": 3},
            "yara": {"ready": False, "message": "Not downloaded yet"},
            "clamav": {"ready": False, "message": "Not downloaded yet"}, "sig_version": "x"})
    monkeypatch.setattr(defender, "peek", lambda: dict(FAKE_DEFENDER))
    monkeypatch.setattr(setup_fetch, "fetch_all", lambda s, progress=print: {
        "clamav_program": {"ok": True, "message": "fake", "changed": False}})
    # Phase 2 modules (updater, self-update, signed metadata) are never the real ones here: those
    # go online. Tests that need them install fakes (see `phase2`).
    for name in ("_load_updater_module", "_load_selfupdate", "_load_signed"):
        monkeypatch.setattr(server, name, _missing_module)
    return real


def _missing_module():
    raise ImportError("not available in this test")


class Client:
    def __init__(self, app, port):
        self.app, self.port, self.token = app, port, app.token

    def raw(self, method, path, body=None, headers=None, host=None, token=True, ctype="application/json"):
        con = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        con.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        con.putheader("Host", host or f"127.0.0.1:{self.port}")
        if token:
            con.putheader("X-TacoGuard-Token", self.token if token is True else token)
        data = b""
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            if ctype:
                con.putheader("Content-Type", ctype)
        if method == "POST" or data:
            con.putheader("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            con.putheader(k, v)
        con.endheaders()
        if data:
            con.send(data)
        resp = con.getresponse()
        raw = resp.read()
        con.close()
        return resp.status, dict(resp.getheaders()), raw

    def get(self, path, **kw):
        status, headers, raw = self.raw("GET", path, **kw)
        return status, _json(raw)

    def post(self, path, body=None, **kw):
        status, headers, raw = self.raw("POST", path, body if body is not None else {}, **kw)
        return status, _json(raw)


def _json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return {"_raw": raw.decode("utf-8", "replace")}


@pytest.fixture
def live(settings, parts):
    app = server.App(settings)
    srv = server.make_server(app, port=0)
    app.startup()
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    c = Client(app, app.port)
    c.thread, c.srv, c.parts = t, srv, parts
    yield c
    srv.shutdown()
    srv.server_close()
    t.join(5)
    app.close()


def _add_detection(store: Store, path: str, confidence=Confidence.HIGH, sha="ab" * 32) -> tuple[int, int]:
    job_id = store.create_job([str(Path(path).parent)])
    r = FileResult(path=path, sha256=sha, size=10,
                   findings=[Finding("yara", "Generic_Test_Rule", confidence, "test rules")])
    rid = store.add_result(job_id, r)
    store.update_job(job_id, status="done", finished=time.time(), counts={"files": 1, "malware": 1})
    return job_id, rid


# ---------------------------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------------------------
def test_index_has_token_and_no_inline_script(live):
    status, headers, raw = live.raw("GET", "/", token=False)
    html = raw.decode("utf-8")
    assert status == 200
    assert f'<meta name="tacoguard-token" content="{live.token}">' in html
    assert server.TOKEN_PLACEHOLDER not in html
    for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.S | re.I):
        assert tag.strip() == ""                              # every script is an external file
    assert re.search(r"<script\b(?![^>]*\bsrc=)", html, flags=re.I) is None
    assert re.search(r"\son[a-z]+\s*=", html, flags=re.I) is None   # no onclick= etc.
    assert re.search(r"\sstyle\s*=", html, flags=re.I) is None      # no inline styles
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("path,ctype", [("/app.js", "text/javascript"), ("/style.css", "text/css"),
                                        ("/icon.svg", "image/svg+xml")])
def test_static_files_served_with_csp(live, path, ctype):
    status, headers, raw = live.raw("GET", path, token=False)
    assert status == 200 and raw
    assert headers["Content-Type"].startswith(ctype)
    assert headers["Content-Security-Policy"] == server.CSP
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_unknown_static_file_is_404(live):
    status, _, _ = live.raw("GET", "/../tacoguard/config.py", token=False)
    assert status == 404
    status, _, _ = live.raw("GET", "/server.py", token=False)
    assert status == 404


def test_api_requires_token(live):
    assert live.get("/api/status", token=False)[0] == 403
    assert live.get("/api/status", token="wrong")[0] == 403
    status, data = live.post("/api/quit", token=False)
    assert status == 403 and "error" in data
    assert live.thread.is_alive()
    status, data = live.get("/api/status")
    assert status == 200 and data["app"] == "TacoGuard"
    # ping is the only open API call and tells nothing but the app name
    status, data = live.get("/api/ping", token=False)
    assert status == 200 and set(data) == {"app", "version"}


def test_wrong_host_refused(live):
    for host in ("evil.example", f"evil.example:{live.port}", f"127.0.0.1:{live.port + 1}", ""):
        assert live.raw("GET", "/", token=False, host=host or " ")[0] == 403
        assert live.get("/api/status", host=host or " ")[0] == 403
    assert live.get("/api/status", host=f"localhost:{live.port}")[0] == 200


def test_foreign_origin_refused(live, tmp_path):
    body = {"kind": "hash", "value": "cd" * 32}
    status, data = live.post("/api/allowlist", body, headers={"Origin": "http://evil.example"})
    assert status == 403 and "other websites" in data["error"]
    status, _ = live.post("/api/allowlist", body, headers={"Origin": f"http://127.0.0.1:{live.port + 1}"})
    assert status == 403
    status, _ = live.post("/api/allowlist", body, headers={"Sec-Fetch-Site": "cross-site"})
    assert status == 403
    assert live.get("/api/allowlist")[1]["items"] == []
    status, _ = live.post("/api/allowlist", body, headers={"Origin": f"http://127.0.0.1:{live.port}"})
    assert status == 200


def test_body_limits_and_json_only(live):
    # too big: refused from the Content-Length alone, before reading the body
    con = http.client.HTTPConnection("127.0.0.1", live.port, timeout=10)
    con.putrequest("POST", "/api/allowlist", skip_host=True)
    con.putheader("Host", f"127.0.0.1:{live.port}")
    con.putheader("X-TacoGuard-Token", live.token)
    con.putheader("Content-Type", "application/json")
    con.putheader("Content-Length", str(2 * 1024 * 1024))
    con.endheaders()
    resp = con.getresponse()
    assert resp.status == 413
    assert "too big" in json.loads(resp.read())["error"]
    con.close()
    # not JSON
    status, data = live.post("/api/allowlist", b"kind=hash", ctype="application/x-www-form-urlencoded")
    assert status == 415
    status, data = live.post("/api/allowlist", b"{not json")
    assert status == 400 and "JSON" in data["error"]
    status, data = live.post("/api/allowlist", b"[1, 2]")
    assert status == 400


def test_methods_and_unknown_routes(live):
    assert live.raw("PUT", "/api/status", b"{}")[0] == 405
    assert live.raw("DELETE", "/api/allowlist/1")[0] == 405
    assert live.get("/api/nothing-here")[0] == 404
    assert live.get("/api/scan")[0] == 405          # exists, but only as POST
    assert live.get("/api/scan/999999")[0] == 404


def test_errors_are_plain_and_logged(live, monkeypatch, settings):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(live.app, "status", boom)
    status, headers, raw = live.raw("GET", "/api/status")
    text = raw.decode()
    assert status == 500
    assert "Traceback" not in text and "secret internal detail" not in text
    assert "error" in json.loads(text)
    log = (settings.log_dir / "web.log").read_text(encoding="utf-8")
    assert "secret internal detail" in log and live.token not in log


def test_single_instance(live, monkeypatch, capsys, settings):
    # a second server on the same port can't bind
    with pytest.raises(OSError):
        server.make_server(server.App(settings), port=live.port)
    # serve() on a port TacoGuard already uses just opens the browser there
    opened = []
    monkeypatch.setattr(server.webbrowser, "open", lambda url: opened.append(url))
    settings.port = live.port
    assert server.serve(settings, open_browser=True) == 0
    assert opened == [f"http://127.0.0.1:{live.port}/"]
    assert "already running" in capsys.readouterr().out


def test_port_taken_by_other_program(settings, monkeypatch, capsys):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        monkeypatch.setattr(server, "is_tacoguard_at", lambda p, timeout=3.0: False)
        monkeypatch.setattr(server.webbrowser, "open", lambda url: pytest.fail("must not open"))
        settings.port = port
        assert server.serve(settings, open_browser=True) == 1
        assert "another program" in capsys.readouterr().out
    finally:
        s.close()


def test_quit_stops_server(live):
    status, data = live.post("/api/quit")
    assert status == 200 and data["ok"]
    live.thread.join(5)
    assert not live.thread.is_alive()


# ---------------------------------------------------------------------------------------------
# API flows
# ---------------------------------------------------------------------------------------------
def test_status_shape(live):
    status, data = live.get("/api/status")
    assert status == 200
    for key in ("version", "signatures", "defender", "active_jobs", "recent_jobs", "counts",
                "quarantine", "data_dir", "notes", "busy", "setup"):
        assert key in data
    assert data["defender"]["message"] == defender.MSG_OK
    assert data["data_dir"] == str(live.app.settings.root)
    assert {"count", "bytes"} <= set(data["quarantine"])


def test_startup_problems_become_notes(settings, monkeypatch):
    def not_ready(*a, **k):
        raise NotImplementedError

    def broken(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(jobs, "recover_interrupted", not_ready)
    monkeypatch.setattr(quarantine, "Quarantine", broken)
    app = server.App(settings)
    app.startup()                              # must not raise
    assert len(app.notes) == 2
    assert all("disk on fire" not in n for n in app.notes)
    app.close()

    monkeypatch.setattr(jobs, "recover_interrupted", lambda store: [4, 5])
    monkeypatch.setattr(quarantine, "Quarantine", FakeQuarantine)
    app = server.App(settings)
    app.startup()
    assert any("2 scans were cut off" in n for n in app.notes)
    app.close()


def test_scan_flow(live, tmp_path):
    folder = tmp_path / "to_scan"
    folder.mkdir()
    (folder / "hello.txt").write_text("just a harmless text file\n", encoding="utf-8")
    status, data = live.post("/api/scan", {"targets": [str(folder)]})
    assert status == 200, data
    job_id = data["job_id"]
    assert data["job"]["targets"] == [str(folder)]

    status, data = live.get(f"/api/scan/{job_id}")
    assert status == 200
    assert data["job"]["id"] == job_id
    assert set(data["totals"]) == {"detections", "not_checked", "trusted"}

    st = data["job"]["status"]
    status, data = live.post(f"/api/scan/{job_id}/cancel")
    if st in ("done", "cancelled", "failed"):
        assert status == 409
    else:
        assert status == 200 and data["ok"]
    # wait for a real worker to stop before the temp folder goes away
    for _ in range(100):
        if live.app.store.get_job(job_id)["status"] not in ("queued", "running"):
            break
        time.sleep(0.1)

    status, data = live.post("/api/scan", {"targets": [str(tmp_path / "does-not-exist")]})
    assert status == 400 and data["error"]
    status, data = live.post("/api/scan", {"targets": []})
    assert status == 400
    status, data = live.post("/api/scan", {"targets": [1, 2]})
    assert status == 400


def test_pause_resume_with_fakes(live, tmp_path, monkeypatch):
    for name in ("start_scan", "pause_scan", "resume_scan", "cancel_scan"):
        monkeypatch.setattr(jobs, name, getattr(FakeJobs, name))
    status, data = live.post("/api/scan", {"targets": [str(tmp_path)]})
    job_id = data["job_id"]
    status, data = live.post(f"/api/scan/{job_id}/resume")
    assert status == 409                       # running: nothing to resume
    status, data = live.post(f"/api/scan/{job_id}/pause")
    assert status == 200 and data["job"]["status"] == "paused"
    status, data = live.post(f"/api/scan/{job_id}/resume")
    assert status == 200 and data["job"]["status"] == "running"
    status, data = live.get("/api/status")
    assert data["busy"] is True and data["active_jobs"][0]["id"] == job_id


def test_scan_results_sections_and_paging(live, tmp_path):
    store = live.app.store
    job_id, rid = _add_detection(store, str(tmp_path / "bad.exe"))
    for i in range(5):
        store.add_result(job_id, FileResult(path=str(tmp_path / f"big{i}.iso"), status=SKIPPED,
                                            notes=["Bigger than the 2 GB limit, so it was not checked."]))
    store.add_result(job_id, FileResult(path=str(tmp_path / "locked.db"), status=UNREADABLE,
                                        notes=["In use by another program."]))
    status, data = live.get(f"/api/scan/{job_id}?limit=2")
    assert data["totals"] == {"detections": 1, "not_checked": 6, "trusted": 0}
    assert len(data["not_checked"]) == 2
    det = data["detections"][0]
    assert det["level"] == "malware" and "Generic_Test_Rule" in det["reason"] and det["short"]
    status, page = live.get(f"/api/scan/{job_id}?section=not_checked&offset=4&limit=10")
    assert [r["status"] for r in page["not_checked"]] == ["skipped", "unreadable"]
    assert "detections" not in page


def test_result_actions(live, tmp_path):
    store = live.app.store
    f = tmp_path / "flagged.txt"
    f.write_bytes(b"harmless text pretending to be flagged\r\n")
    _, rid_q = _add_detection(store, str(f), sha="11" * 32)
    _, rid_t = _add_detection(store, str(tmp_path / "mod.exe"), Confidence.LOW, sha="22" * 32)

    status, data = live.get("/api/detections")
    assert status == 200 and {d["id"] for d in data["detections"]} >= {rid_q, rid_t}

    status, data = live.post(f"/api/result/{rid_t}/trust")
    assert status == 200 and data["message"].startswith("Trusted:")
    assert any(i["value"] == "22" * 32 for i in live.get("/api/allowlist")[1]["items"])
    assert live.post(f"/api/result/{rid_t}/trust")[0] == 409

    status, data = live.post(f"/api/result/{rid_t}/confirm")
    assert status == 200

    status, data = live.post(f"/api/result/{rid_q}/quarantine")
    assert status == 200, data
    assert data["message"].startswith("Quarantined:") and "Restore it only if you're sure" in data["message"]
    assert data["result"]["action"] == "quarantined"
    assert live.post(f"/api/result/{rid_q}/quarantine")[0] == 409

    status, data = live.get("/api/quarantine")
    assert status == 200 and len(data["items"]) == 1
    qid = data["items"][0]["id"]
    status, data = live.post(f"/api/quarantine/{qid}/restore", {"trust": "yes"})
    assert status == 400                       # must be true/false
    status, data = live.post(f"/api/quarantine/{qid}/restore", {"trust": False})
    assert status == 200 and data["message"].startswith("Restored:")
    assert live.post(f"/api/quarantine/{qid}/delete")[0] == 404   # not in quarantine any more

    assert live.post("/api/result/999999/quarantine")[0] == 404


def test_scan_results_are_counted_and_paged_in_sql(live, tmp_path, monkeypatch):
    """Review 2026-11-23: every 1.5 s poll loaded and decoded every stored result."""
    store = live.app.store
    job_id, _ = _add_detection(store, str(tmp_path / "bad.exe"))
    for i in range(1200):
        store.add_result(job_id, FileResult(path=str(tmp_path / f"locked{i:04}.db"), status=UNREADABLE,
                                            notes=["In use by another program."]))
    store.add_result(job_id, FileResult(path=str(tmp_path / "mine.exe"), status="trusted",
                                        notes=["On your trusted list."]))
    monkeypatch.setattr(Store, "list_results", lambda *a, **k: pytest.fail("must not load every result"))
    status, data = live.get(f"/api/scan/{job_id}")
    assert status == 200
    assert data["totals"] == {"detections": 1, "not_checked": 1200, "trusted": 1}
    assert len(data["not_checked"]) == 200 and data["not_checked"][0]["path"].endswith("locked0000.db")
    assert data["detections"][0]["short"] and data["trusted"][0]["status"] == "trusted"
    status, page = live.get(f"/api/scan/{job_id}?section=not_checked&offset=1150&limit=200")
    assert [os.path.basename(r["path"]) for r in page["not_checked"]][:1] == ["locked1150.db"]
    assert len(page["not_checked"]) == 50 and set(page) >= {"job", "totals", "offset", "limit"}
    assert live.get(f"/api/scan/{job_id}?section=nope")[0] == 400


def test_unexpected_windows_error_is_plain(live, tmp_path, monkeypatch):
    store = live.app.store
    f = tmp_path / "flagged3.txt"
    f.write_bytes(b"harmless text\r\n")
    _, rid = _add_detection(store, str(f), sha="44" * 32)

    class Boom:
        def __init__(self, *a):
            pass

        def put(self, *a, **k):
            raise OSError(22, "[WinError 1117] The request could not be performed because of an I/O "
                              "device error")
    monkeypatch.setattr(quarantine, "Quarantine", Boom)
    status, data = live.post(f"/api/result/{rid}/quarantine")
    assert status == 500 and "WinError" not in data["error"] and "I/O device error" in data["error"]


def test_same_user_check_with_fakes():
    me = "PC\\alex"
    no_sid = dict(sid_of=lambda pid: None, me_sid="S-1-5-21-1-2-3-1001")
    ok = server.same_user_client(("127.0.0.1", 5000), ("127.0.0.1", 8799), find_pid=lambda c, s: 1234,
                                 user_of=lambda pid: "pc\\Alex", me=me, **no_sid)
    assert ok is True
    other = server.same_user_client(("127.0.0.1", 5000), ("127.0.0.1", 8799), find_pid=lambda c, s: 1234,
                                    user_of=lambda pid: "PC\\guest", me=me, **no_sid)
    unknown_pid = server.same_user_client(("127.0.0.1", 5000), ("127.0.0.1", 8799),
                                          find_pid=lambda c, s: None, user_of=lambda pid: me, me=me)
    denied = server.same_user_client(("127.0.0.1", 5000), ("127.0.0.1", 8799), find_pid=lambda c, s: 1234,
                                     user_of=lambda pid: None, me=me, **no_sid)

    def broken(c, s):
        raise OSError("table unavailable")
    failed = server.same_user_client(("127.0.0.1", 5000), ("127.0.0.1", 8799), find_pid=broken, me=me)
    assert (other, unknown_pid, denied, failed) == (False, False, False, False)


def test_user_name_refused_falls_back_to_the_account_sid():
    """Review 2026-11-23: an elevated browser's user name can't be read (AccessDenied); the
    account SID from its token is compared instead, and only if that fails too it is refused
    with advice."""
    mine = "S-1-5-21-111-222-333-1001"
    args = (("127.0.0.1", 5000), ("127.0.0.1", 8799))
    kw = dict(find_pid=lambda c, s: 1234, user_of=lambda pid: None, me="PC\\alex", me_sid=mine)
    assert server.client_verdict(*args, sid_of=lambda pid: mine.lower(), **kw) == server.SAME
    assert server.client_verdict(*args, sid_of=lambda pid: "S-1-5-21-111-222-333-1002", **kw) == server.OTHER
    assert server.client_verdict(*args, sid_of=lambda pid: None, **kw) == server.UNCONFIRMED
    # our own name unreadable but the other side's readable: SIDs decide too
    kw.update(user_of=lambda pid: "PC\\alex", me="")
    assert server.client_verdict(*args, sid_of=lambda pid: mine, **kw) == server.SAME
    # the real thing: our own process, read through the token
    assert server.process_sid(os.getpid()) == server.my_sid() and server.my_sid().startswith("S-1-5-")
    assert server.process_sid(4) != server.my_sid()          # the System process (or None)


def test_failed_own_user_lookup_is_tried_again(monkeypatch):
    answers = [None, "PC\\alex"]
    monkeypatch.setattr(server, "process_user", lambda pid: answers.pop(0) if answers else "PC\\later")
    monkeypatch.setattr(server, "process_sid", lambda pid: None)
    monkeypatch.setattr(server, "_mine", {})
    assert server.my_user() is None and server.my_sid() is None
    assert server.my_user() == "PC\\alex"
    assert server.my_user() == "PC\\alex"                  # cached once it worked
    assert server.my_sid() is None                           # failed lookups are not cached


def test_unconfirmed_browser_gets_plain_advice(live, monkeypatch):
    monkeypatch.setattr(server, "client_verdict", lambda c, s, **kw: server.UNCONFIRMED)
    status, _, raw = live.raw("GET", "/", token=False)
    assert status == 403 and _json(raw)["error"] == server.UNCONFIRMED_MSG
    assert "administrator" in server.UNCONFIRMED_MSG and live.token not in raw.decode()


def test_real_connection_owner_is_found():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, addr = srv.accept()
    try:
        assert server.tcp_owner_pid(addr, srv.getsockname()) == os.getpid()
        assert server.tcp_owner_pid(("127.0.0.1", 1), srv.getsockname()) is None
        assert server.same_user_client(addr, srv.getsockname()) is True
        assert server.process_user(os.getpid()) == server.my_user()
        assert server.process_user(4) != server.my_user()            # the System process
        assert not server.same_user_client(addr, srv.getsockname(), find_pid=lambda c, s: 4)
    finally:
        for s in (conn, cli, srv):
            s.close()


def test_another_program_of_the_same_user_is_served(live):
    import subprocess
    import sys
    code = ("import http.client,sys; c=http.client.HTTPConnection('127.0.0.1', int(sys.argv[1]), timeout=10);"
            "c.request('GET','/', headers={'Host':'127.0.0.1:'+sys.argv[1]}); print(c.getresponse().status)")
    out = subprocess.run([sys.executable, "-c", code, str(live.port)], capture_output=True, text=True,
                         timeout=60, creationflags=0x08000000)
    assert out.stdout.strip() == "200", out.stderr


def test_other_windows_user_is_refused_page_and_api(live, monkeypatch):
    calls = []

    def other_user(client, srv_addr, **kw):
        calls.append(client)
        return server.OTHER
    monkeypatch.setattr(server, "client_verdict", other_user)
    status, headers, raw = live.raw("GET", "/", token=False)
    assert status == 403 and live.token not in raw.decode() and "Windows account" in _json(raw)["error"]
    assert live.get("/api/status")[0] == 403
    assert live.get("/api/ping", token=False)[0] == 403
    assert calls


def test_one_check_per_connection(live, monkeypatch):
    calls = []
    real = server.client_verdict
    monkeypatch.setattr(server, "client_verdict", lambda c, s, **kw: calls.append(c) or real(c, s))
    con = http.client.HTTPConnection("127.0.0.1", live.port, timeout=10)
    for _ in range(3):
        con.request("GET", "/api/status", headers={"Host": f"127.0.0.1:{live.port}",
                                                   "X-TacoGuard-Token": live.token})
        resp = con.getresponse()
        resp.read()
        assert resp.status == 200
    con.close()
    assert len(calls) == 1


def test_idle_connection_times_out(live, monkeypatch):
    monkeypatch.setattr(server.Handler, "timeout", 0.5)
    s = socket.create_connection(("127.0.0.1", live.port), timeout=10)
    try:
        t0 = time.monotonic()
        assert s.recv(100) == b""                 # the server hung up on the silent client
        assert time.monotonic() - t0 < 5
    finally:
        s.close()


def _drip(sock: socket.socket, stop: threading.Event, every: float = 0.2) -> None:
    """A slow client: one byte of a request line at a time, never finishing it."""
    try:
        sock.sendall(b"GET /api/status HTTP/1.1\r\nX-Slow: ")
        while not stop.wait(every):
            sock.sendall(b"a")
    except OSError:
        pass


def test_slow_drip_client_is_dropped_by_the_header_deadline(live, monkeypatch):
    """Review 2026-11-23: each read had its own 30 s timeout, so a byte every few seconds kept
    the connection (and its slot) forever."""
    monkeypatch.setattr(server.Handler, "header_deadline", 1.0)
    s = socket.create_connection(("127.0.0.1", live.port), timeout=10)
    stop = threading.Event()
    t = threading.Thread(target=_drip, args=(s, stop), daemon=True)
    t.start()
    try:
        t0 = time.monotonic()
        while True:                                 # the server hangs up within the deadline
            try:
                if s.recv(4096) == b"":
                    break
            except ConnectionError:
                break
        assert time.monotonic() - t0 < 4
    finally:
        stop.set()
        s.close()
        t.join(5)
    assert live.get("/api/status")[0] == 200


def test_slow_drip_clients_cannot_lock_out_the_page(settings, parts, monkeypatch):
    monkeypatch.setattr(server.Handler, "header_deadline", 1.5)
    app = server.App(settings)
    srv = server.TacoServer(app, 0)                  # the real 32 slots
    app.port, app.server = srv.server_address[1], srv
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    stop = threading.Event()
    socks = [socket.create_connection(("127.0.0.1", app.port), timeout=10)
             for _ in range(server.MAX_CONNECTIONS)]
    drips = [threading.Thread(target=_drip, args=(s, stop), daemon=True) for s in socks]
    try:
        for d in drips:
            d.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        assert Client(app, app.port).raw("GET", "/api/status")[0] == 503    # all slots taken
        while True:
            status = Client(app, app.port).raw("GET", "/api/status")[0]
            if status == 200:
                break
            assert time.monotonic() - t0 < 1.5 + 3, "locked out for longer than the deadline"
            time.sleep(0.1)
    finally:
        stop.set()
        for s in socks:
            s.close()
        srv.shutdown()
        srv.server_close()
        t.join(5)
        app.close()


def test_too_many_connections_get_a_quick_503(settings, parts):
    app = server.App(settings)
    srv = server.TacoServer(app, 0, max_connections=2)
    app.port, app.server = srv.server_address[1], srv
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    idle = [socket.create_connection(("127.0.0.1", app.port), timeout=10) for _ in range(2)]
    try:
        time.sleep(0.3)
        t0 = time.monotonic()
        status, _, raw = Client(app, app.port).raw("GET", "/api/status")
        assert status == 503 and time.monotonic() - t0 < 2
        assert "busy" in _json(raw)["error"]
        for s in idle:
            s.close()
        for _ in range(50):                       # the slots come back once they close
            status, _, _ = Client(app, app.port).raw("GET", "/api/status")
            if status == 200:
                break
            time.sleep(0.1)
        assert status == 200
    finally:
        for s in idle:
            s.close()
        srv.shutdown()
        srv.server_close()
        t.join(5)
        app.close()


def test_quarantine_delete(live, tmp_path):
    store = live.app.store
    f = tmp_path / "flagged2.txt"
    f.write_bytes(b"another harmless text file\r\n")
    _, rid = _add_detection(store, str(f), sha="33" * 32)
    assert live.post(f"/api/result/{rid}/quarantine")[0] == 200
    qid = live.get("/api/quarantine")[1]["items"][0]["id"]
    status, data = live.post(f"/api/quarantine/{qid}/delete")
    assert status == 200 and data["message"].startswith("Deleted for good")
    assert live.get("/api/quarantine")[1]["items"] == []
    assert store.get_result(rid)["action"] == "deleted"


def test_allowlist_add_remove(live, tmp_path):
    status, data = live.post("/api/allowlist", {"kind": "hash", "value": "not-a-hash"})
    assert status == 400 and "SHA-256" in data["error"]
    status, data = live.post("/api/allowlist", {"kind": "hash", "value": "AB" * 32})
    assert status == 200
    folder = tmp_path / "tools"
    folder.mkdir()
    status, data = live.post("/api/allowlist", {"kind": "folder", "value": str(folder)})
    assert status == 200
    status, data = live.post("/api/allowlist", {"kind": "folder", "value": "C:\\"})
    assert status == 400 and "drive" in data["error"]
    status, data = live.post("/api/allowlist", {"kind": "folder", "value": str(tmp_path / "nope")})
    assert status == 400
    items = live.get("/api/allowlist")[1]["items"]
    assert {i["kind"] for i in items} == {"hash", "folder"}
    for i in items:
        assert live.post(f"/api/allowlist/{i['id']}/remove")[0] == 200
    assert live.get("/api/allowlist")[1]["items"] == []


def test_browse(live, tmp_path):
    status, data = live.get("/api/browse?path=")
    assert status == 200 and data["drives"] and data["folders"]
    assert all(p["path"] for p in data["quick"])
    (tmp_path / "Alpha").mkdir()
    (tmp_path / "beta").mkdir()
    (tmp_path / "file.txt").write_text("x")
    from urllib.parse import quote
    status, data = live.get("/api/browse?path=" + quote(str(tmp_path)))
    assert status == 200
    names = [f["name"] for f in data["folders"]]
    assert "Alpha" in names and "beta" in names and "file.txt" not in names
    assert data["parent"]
    status, data = live.get("/api/browse?path=" + quote(str(tmp_path / "file.txt")))
    assert status == 400
    status, data = live.get("/api/browse?path=" + quote(str(tmp_path / "missing")))
    assert status == 404


def test_setup_runs_in_background_one_at_a_time(live, monkeypatch):
    gate = threading.Event()

    def slow_fetch(settings, progress=print):
        progress("Step one")
        gate.wait(5)
        progress("Step two")
        return {"yara_rules": {"ok": True, "message": "Rules ready", "changed": True}}
    monkeypatch.setattr(setup_fetch, "fetch_all", slow_fetch)
    status, data = live.post("/api/setup")
    assert status == 200
    status, data = live.post("/api/setup")
    assert status == 409 and "already" in data["error"]
    assert live.get("/api/setup")[1]["running"] is True
    gate.set()
    for _ in range(50):
        data = live.get("/api/setup")[1]
        if not data["running"]:
            break
        time.sleep(0.1)
    assert data["running"] is False
    assert [l["text"] for l in data["lines"]] == ["Step one", "Step two"]
    assert data["result"]["yara_rules"]["ok"] is True


def test_setup_failure_is_plain(live, monkeypatch):
    def fail(settings, progress=print):
        raise setup_fetch.FetchError("Could not reach github.com. Check your internet connection.")
    monkeypatch.setattr(setup_fetch, "fetch_all", fail)
    assert live.post("/api/setup")[0] == 200
    for _ in range(50):
        data = live.get("/api/setup")[1]
        if not data["running"]:
            break
        time.sleep(0.1)
    assert data["error"].startswith("Could not reach github.com")


def test_settings_get_and_post(live, settings):
    status, data = live.get("/api/settings")
    assert status == 200
    assert data["endpoints"] == config.ENDPOINTS
    assert data["limits"]["max_file_size"] == settings.limits.max_file_size
    assert isinstance(data["licenses"], list)

    status, data = live.post("/api/settings", {"max_file_size": 512 * 1024**2, "read_rate_mb_s": 40,
                                               "scan_priority": "below_normal"})
    assert status == 200, data
    saved = json.loads(settings.settings_path.read_text(encoding="utf-8"))
    assert saved["limits"]["max_file_size"] == 512 * 1024**2
    assert saved["limits"]["read_rate_mb_s"] == 40
    assert saved["scan_priority"] == "below_normal"
    assert live.app.settings.limits.max_file_size == 512 * 1024**2
    assert data["settings"]["clamav_threads"] == 4 and data["settings"]["clamav_threads_max"] == 8

    status, data = live.post("/api/settings", {"clamav_threads": 6})
    assert status == 200, data
    assert json.loads(settings.settings_path.read_text(encoding="utf-8"))["clamav_threads"] == 6
    assert live.app.settings.clamav_threads == 6 and data["settings"]["clamav_threads"] == 6

    for bad in ({"max_file_size": True}, {"max_file_size": "big"}, {"archive_max_depth": 99},
                {"archive_max_depth": 1.5}, {"port": 80}, {"scan_priority": "realtime"}, {},
                {"clamav_threads": 0}, {"clamav_threads": 9}, {"clamav_threads": 2.5},
                {"clamav_threads": True}, {"clamav_threads": "4"}):
        status, data = live.post("/api/settings", bad)
        assert status == 400 and data["error"], bad
    assert live.app.settings.limits.archive_max_depth == config.Limits().archive_max_depth
    assert live.app.settings.clamav_threads == 6


def test_trust_signed_programs_setting_round_trip(live, settings):
    status, data = live.get("/api/settings")
    assert status == 200 and data["trust_signed_programs"] is True
    status, data = live.post("/api/settings", {"trust_signed_programs": False})
    assert status == 200, data
    assert data["settings"]["trust_signed_programs"] is False
    assert json.loads(settings.settings_path.read_text(encoding="utf-8"))["trust_signed_programs"] is False
    assert live.app.settings.trust_signed_programs is False
    assert config.load_settings(settings.data_dir).trust_signed_programs is False
    for bad in ("no", 0, 1, None, []):
        status, data = live.post("/api/settings", {"trust_signed_programs": bad})
        assert status == 400 and data["error"], bad
    status, data = live.post("/api/settings", {"trust_signed_programs": True})
    assert status == 200 and live.get("/api/settings")[1]["trust_signed_programs"] is True


def test_clamav_thread_count_is_kept_in_range():
    for raw, want in ((4, 4), (0, 1), (-3, 1), (99, 8), ("x", 1), (None, 1), (2.7, 2)):
        assert config.clamav_thread_count(config.Settings(clamav_threads=raw)) == want


def test_read_licenses_tables(tmp_path):
    p = tmp_path / "L.md"
    p.write_text("# Title\n\nIntro **bold** text\nmore.\n\n## Used\n\n| What | License |\n|---|---|\n"
                 "| ClamAV | GPL-2.0 |\n| `cryptography` | Apache-2.0 |\n", encoding="utf-8")
    secs = server.read_licenses(p)
    assert secs[0]["blocks"] == [{"type": "p", "text": "Intro bold text more."}]
    table = secs[1]["blocks"][0]
    assert secs[1]["name"] == "Used"
    assert table["header"] == ["What", "License"]
    assert table["rows"] == [["ClamAV", "GPL-2.0"], ["cryptography", "Apache-2.0"]]


# ---------------------------------------------------------------------------------------------
# Defender status (no PowerShell needed: sample outputs)
# ---------------------------------------------------------------------------------------------
SAMPLE_ON = json.loads(r'''{"mp":{"AMServiceEnabled":true,"AntivirusEnabled":true,
 "RealTimeProtectionEnabled":true,"AntivirusSignatureAge":0,"AntivirusSignatureVersion":"1.441.112.0",
 "AntivirusSignatureLastUpdated":"2026-11-23T06:12:40.0000000Z","AMRunningMode":"Normal",
 "IsTamperProtected":true},
 "av":[{"displayName":"Windows Defender","productState":397568}]}''')


def test_defender_parse_on_and_current():
    st = defender.parse_status(SAMPLE_ON)
    assert st["available"] and st["realtime_on"] and st["level"] == "ok"
    assert st["message"] == ("Microsoft Defender is on and up to date. TacoGuard works next to it as a "
                             "second opinion.")
    assert st["signature_version"] == "1.441.112.0"
    assert st["signature_updated"] > 1_700_000_000
    assert st["other_products"] == []


def test_defender_parse_realtime_off():
    raw = json.loads(json.dumps(SAMPLE_ON))
    raw["mp"]["RealTimeProtectionEnabled"] = False
    st = defender.parse_status(raw)
    assert st["level"] == "off"
    assert "real-time protection is off" in st["message"]
    assert "Windows Security" in st["advice"] and "never changes" in st["advice"]


def test_defender_parse_old_signatures_ps5_date_and_other_av():
    raw = {"mp": {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
                  "AntivirusSignatureAge": 9, "AntivirusSignatureLastUpdated": "/Date(1763000000000)/",
                  "AMRunningMode": "Normal"},
           "av": {"displayName": "Other AV Suite", "productState": 266240}}
    st = defender.parse_status(raw)
    assert st["level"] == "warn" and "9 days old" in st["message"]
    assert st["signature_updated"] == 1763000000.0
    assert st["other_products"] == [{"name": "Other AV Suite", "on": True}]

    raw["mp"]["AMRunningMode"] = "Passive Mode"
    st = defender.parse_status(raw)
    assert st["level"] == "ok" and "passive mode" in st["message"] and "Other AV Suite" in st["message"]


def test_defender_parse_failures():
    st = defender.parse_status({"error": "Windows took too long to answer (more than 15 seconds)."})
    assert st["level"] == "unknown" and "Could not read" in st["message"]
    st = defender.parse_status({"mp_error": "Get-MpComputerStatus: 0x800106ba"})
    assert st["level"] == "unknown" and "0x800106ba" in st["message"]
    assert defender.parse_status("garbage")["level"] == "unknown"


def test_defender_get_status_caches(monkeypatch):
    calls = []
    monkeypatch.setattr(defender, "_run_powershell", lambda: calls.append(1) or SAMPLE_ON)
    monkeypatch.setattr(defender, "_cache", None)
    assert defender.get_status()["level"] == "ok"
    assert defender.get_status()["level"] == "ok"
    assert len(calls) == 1
    defender.get_status(force=True)
    assert len(calls) == 2


def test_defender_script_is_read_only():
    script = defender._SCRIPT
    commands = set(re.findall(r"\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b", script))
    assert commands <= {"Get-MpComputerStatus", "Get-CimInstance", "ForEach-Object", "ConvertTo-Json"}
    assert "Set-Mp" not in script and "Add-Mp" not in script and "Remove-Mp" not in script


# ---------------------------------------------------------------------------------------------
# Phase 2: updates, app update offer, learning (fakes for the updater and self-update)
# ---------------------------------------------------------------------------------------------
from types import SimpleNamespace  # noqa: E402

from tacoguard import learning  # noqa: E402

DAY = 86400


class FakeUpdater:
    instances: list = []

    def __init__(self, settings, store):
        self.settings, self.store = settings, store
        self.started = self.stopped = self.checks = self.recovered = 0
        self.gate = threading.Event()
        self.gate.set()
        self.checking = False
        now = time.time()
        self.components = {
            "clamav_signatures": {"version": "daily 27500", "updated": now - 2 * 3600, "state": "ok",
                                  "message": "Up to date.", "last_error": ""},
            "yara_rules": {"version": "2026-11-23", "updated": now - DAY, "state": "ok",
                           "message": "Up to date.", "last_error": ""},
            "ml_model": {"version": "2026.11.23", "updated": now - DAY, "state": "ok",
                         "message": "Up to date.", "last_error": ""},
            "app": {"version": "0.1.0", "updated": 0, "state": "ok", "message": "You have the newest version.",
                    "last_error": ""},
        }
        FakeUpdater.instances.append(self)

    def recover(self):
        self.recovered += 1
        return []

    def start(self, on_start=True):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def check_now(self, wait=False):
        self.checks += 1
        self.checking = True
        self.gate.wait(5)
        self.checking = False

    def status(self):
        return {"checking": self.checking, "last_check": time.time() - 600, "next_check": time.time() + 3 * 3600,
                "components": self.components, "app_update": None}


class FakeSelfUpdate:
    def __init__(self):
        self.offer = None
        self.installed = True
        self.previous = ""
        self.installs: list = []
        self.rollbacks = 0
        self.gate = threading.Event()
        self.gate.set()

    def available(self, settings):
        return dict(self.offer) if self.offer else None

    def install_update(self, settings, version, shutdown=None):
        self.installs.append(version)
        self.shutdown = shutdown
        self.gate.wait(5)
        return {"ok": True, "restarting": False, "message": f"TacoGuard {version} is installed."}

    def rollback(self, settings, shutdown=None):
        self.rollbacks += 1
        self.shutdown = shutdown
        return {"ok": True, "restarting": False, "message": "Back on the previous version."}

    def running_from_install(self):
        return self.installed

    def status(self, settings, app_update=None):
        return {"installed": self.installed, "previous": self.previous or None,
                "can_rollback": bool(self.previous), "busy": False, "last_result": None}


@pytest.fixture
def phase2(monkeypatch):
    FakeUpdater.instances = []
    sm = FakeSelfUpdate()
    mod = SimpleNamespace(Updater=FakeUpdater)
    monkeypatch.setattr(server, "_load_updater_module", lambda: mod)
    monkeypatch.setattr(server, "_load_selfupdate", lambda: sm)
    return SimpleNamespace(selfupdate=sm, module=mod)


def _wait(cond, seconds=5.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < seconds:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


PHASE2_ROUTES = [("GET", "/api/updates"), ("POST", "/api/updates/check"), ("POST", "/api/app/update"),
                 ("POST", "/api/app/rollback"), ("GET", "/api/learning"), ("POST", "/api/learning/forget"),
                 ("POST", "/api/learning/restore")]


@pytest.mark.parametrize("method,path", PHASE2_ROUTES)
def test_phase2_endpoints_need_the_token_and_same_origin(live, phase2, method, path):
    body = {"version": "0.2.0", "engine": "yara", "rule": "x"} if method == "POST" else None
    phase2.selfupdate.offer = {"version": "0.2.0", "notes": "Faster scans."}
    status, _, _ = live.raw(method, path, body, token=False)
    assert status == 403
    status, _, _ = live.raw(method, path, body, token="wrong")
    assert status == 403
    if method == "POST":
        status, _, _ = live.raw(method, path, body, headers={"Origin": "http://evil.example"})
        assert status == 403
    assert phase2.selfupdate.installs == [] and phase2.selfupdate.rollbacks == 0
    assert all(u.checks == 0 for u in FakeUpdater.instances)


def test_missing_update_modules_give_a_calm_note(live):
    status, data = live.get("/api/status")
    assert status == 200
    up = data["updates"]
    assert up["available"] is False and up["message"] == server.UPDATES_NOT_READY
    assert up["app"]["available"] is False and up["app"]["message"] == server.SELFUPDATE_NOT_READY
    status, data = live.post("/api/updates/check")
    assert status == 503 and data["error"] == server.UPDATES_NOT_READY
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 503 and data["error"] == server.SELFUPDATE_NOT_READY
    assert live.post("/api/app/rollback")[0] == 503
    assert live.get("/api/settings")[1]["signers"] == []
    live.app.start_updates()                       # what serve() does: nothing to start, no error
    assert live.app.updater is None and live.app.notes == []


def test_check_for_updates_starts_one_check_only(live, phase2):
    status, data = live.get("/api/updates")
    assert status == 200 and data["available"] is True and data["checking"] is False
    (u,) = FakeUpdater.instances
    u.gate.clear()
    status, data = live.post("/api/updates/check")
    assert status == 200 and "Checking for updates" in data["message"]
    for _ in range(3):
        status, data = live.post("/api/updates/check")
        assert status == 409 and "already checking" in data["error"]
    assert live.get("/api/status")[1]["updates"]["checking"] is True
    u.gate.set()
    assert _wait(lambda: not live.app.update_check["running"])
    assert u.checks == 1 and u.started == 0           # a click checks once; it doesn't start the timer
    # the updater's own timer is checking: the button waits too
    u.checking = True
    assert live.post("/api/updates/check")[0] == 409
    u.checking = False
    assert live.post("/api/updates/check")[0] == 200
    assert _wait(lambda: not live.app.update_check["running"]) and u.checks == 2


def test_failed_check_is_plain(live, phase2):
    live.get("/api/updates")
    (u,) = FakeUpdater.instances

    def boom(wait=False):
        raise RuntimeError("socket internals")
    u.check_now = boom
    assert live.post("/api/updates/check")[0] == 200
    assert _wait(lambda: not live.app.update_check["running"])
    err = live.get("/api/updates")[1]["check"]["error"]
    assert "kept what it had" in err and "socket" not in err


def test_updates_card_components_stale_and_rejected(live, phase2):
    live.get("/api/updates")
    (u,) = FakeUpdater.instances
    u.components["clamav_signatures"]["updated"] = time.time() - 10 * DAY - 60
    u.components["ml_model"].update(state="rejected", message="The ML model update was refused.")
    status, data = live.get("/api/updates")
    assert [c["label"] for c in data["components"]] == ["ClamAV signatures", "YARA rules", "ML model",
                                                         "TacoGuard app"]
    assert "ClamAV signatures were last updated 10 days ago" in data["stale"]["message"]
    assert "warns after 7 days" in data["stale"]["message"]
    assert data["rejected"] == ["ML model"] and data["rejected_message"] == server.REJECTED_MSG
    assert data["last_check"] and data["next_check"]
    # automatic updates off: no next check, and the warning says to press the button
    live.post("/api/settings", {"auto_update": False})
    data = live.get("/api/updates")[1]
    assert data["next_check"] == 0 and "press Check for updates" in data["stale"]["message"]
    # fresh again: no warning
    u.components["clamav_signatures"]["updated"] = time.time()
    assert live.get("/api/updates")[1]["stale"]["message"] == ""


def test_expired_update_list_shows_calmly_without_the_refused_banner(live, phase2):
    live.get("/api/updates")
    (u,) = FakeUpdater.instances
    calm = ("TacoGuard's own update list has expired, so no new app or model updates are installed "
            "until a new release is published. Signatures and rules keep updating.")
    for name in ("ml_model", "app"):
        u.components[name].update(state="expired", message=calm, last_error="")
    data = live.get("/api/updates")[1]
    assert data["rejected"] == [] and data["rejected_message"] == ""
    comps = {c["name"]: c for c in data["components"]}
    assert comps["ml_model"]["state"] == "expired" and comps["ml_model"]["message"] == calm
    assert comps["ml_model"]["rejected"] is False
    js = (Path(server.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    assert 'expired: "Paused until a new TacoGuard release is published"' in js
    assert '"rejected"];' in js and '"expired"];' not in js      # not a warning dot either


def test_stale_warning_without_the_updater_uses_the_signature_dates(live, monkeypatch):
    old = time.time() - 9 * DAY
    monkeypatch.setattr(detect, "signature_status", lambda s: {
        "hash": {"ready": True, "message": "Ready"},
        "clamav": {"ready": True, "message": "Ready", "updated": old},
        "yara": {"ready": False, "message": "Not downloaded yet", "updated": old}, "sig_version": "x"})
    up = live.get("/api/status")[1]["updates"]
    assert up["available"] is False
    assert [i["label"] for i in up["stale"]["items"]] == ["ClamAV signatures"]   # YARA isn't set up at all


def test_app_update_only_from_a_pending_offer(live, phase2):
    sm = phase2.selfupdate
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 409 and "no TacoGuard update waiting" in data["error"]
    for bad in ({}, {"version": ""}, {"version": 2}, {"version": "../../evil"}, {"version": "x" * 80}):
        assert live.post("/api/app/update", bad)[0] == 400, bad
    sm.offer = {"version": "0.2.0", "notes": "Faster scans and an ML check."}
    live.app._offer = (0.0, None)
    status, data = live.get("/api/status")
    offer = data["updates"]["app"]
    assert offer["offer"] == {"version": "0.2.0", "notes": "Faster scans and an ML check.", "can_install": True,
                              "message": ""}
    assert offer["installed"] is True and offer["note"] == ""
    assert sm.installs == []                         # showing the offer never installs it
    status, data = live.post("/api/app/update", {"version": "0.3.0"})
    assert status == 409 and "0.2.0" in data["error"]
    sm.gate.clear()
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 200 and "restarts by itself" in data["message"] and "goes back" in data["message"]
    assert live.post("/api/app/update", {"version": "0.2.0"})[0] == 409      # one at a time
    sm.gate.set()
    assert _wait(lambda: not live.app.app_action["running"])
    assert sm.installs == ["0.2.0"]
    assert live.get("/api/updates")[1]["app"]["state"]["message"] == "TacoGuard 0.2.0 is installed."
    # selfupdate gets a way to close this page so the new version can take the port
    assert callable(sm.shutdown) and live.thread.is_alive()
    sm.shutdown()
    live.thread.join(5)
    assert not live.thread.is_alive()


def test_app_update_not_downloaded_yet_is_refused_plainly(live, phase2):
    sm = phase2.selfupdate
    sm.offer = {"version": "0.2.0", "notes": "", "can_install": False,
                "message": "The update is not downloaded yet. Press 'Check for updates', then try again."}
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 409 and data["error"].startswith("The update is not downloaded yet")
    assert sm.installs == []
    assert live.post("/api/app/rollback")[0] == 409            # no earlier version either
    assert sm.rollbacks == 0


def test_app_update_waits_for_scans_and_needs_the_installed_copy(live, phase2, tmp_path):
    sm = phase2.selfupdate
    sm.offer = {"version": "0.2.0", "notes": ""}
    sm.installed = False
    data = live.get("/api/updates")[1]["app"]
    assert data["installed"] is False and data["note"] == server.PROJECT_FOLDER_NOTE
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 409 and data["error"] == server.PROJECT_FOLDER_NOTE
    assert live.post("/api/app/rollback")[0] == 409
    sm.installed = True
    job_id = live.app.store.create_job([str(tmp_path)])
    live.app.store.update_job(job_id, status="running")
    status, data = live.post("/api/app/update", {"version": "0.2.0"})
    assert status == 409 and "scan is running" in data["error"]
    assert live.post("/api/app/rollback")[0] == 409
    assert sm.installs == [] and sm.rollbacks == 0


def test_app_rollback_after_a_click(live, phase2):
    sm = phase2.selfupdate
    sm.previous = "0.1.0"
    data = live.get("/api/updates")[1]["app"]
    assert data["previous"] == "0.1.0" and data["offer"] is None
    status, data = live.post("/api/app/rollback")
    assert status == 200 and "TacoGuard 0.1.0" in data["message"]
    assert _wait(lambda: not live.app.app_action["running"]) and sm.rollbacks == 1


def test_app_update_error_is_plain(live, phase2):
    sm = phase2.selfupdate
    sm.offer = {"version": "0.2.0", "notes": ""}

    def broken(settings, version):
        raise OSError(22, "[WinError 1117] device error")
    sm.install_update = broken
    assert live.post("/api/app/update", {"version": "0.2.0"})[0] == 200
    assert _wait(lambda: not live.app.app_action["running"])
    err = live.get("/api/updates")[1]["app"]["state"]["error"]
    assert "WinError" not in err and "stayed on version" in err


def test_serve_recovers_then_starts_and_stops_the_updater(settings, parts, phase2, monkeypatch):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    settings.port = s.getsockname()[1]
    s.close()
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("rc", server.serve(settings, open_browser=False)),
                         daemon=True)
    t.start()
    assert _wait(lambda: server.is_tacoguard_at(settings.port, timeout=1), 10)
    (u,) = FakeUpdater.instances
    assert u.recovered == 1 and u.started == 1 and u.stopped == 0
    con = http.client.HTTPConnection("127.0.0.1", settings.port, timeout=10)
    con.request("GET", "/", headers={"Host": f"127.0.0.1:{settings.port}"})
    token = re.search(r'name="tacoguard-token" content="([^"]+)"', con.getresponse().read().decode()).group(1)
    con.close()
    c = Client(SimpleNamespace(token=token), settings.port)
    assert c.post("/api/quit")[0] == 200
    t.join(10)
    assert out["rc"] == 0 and u.stopped == 1


def test_auto_update_off_recovers_but_does_not_start_and_toggles(live, phase2, settings):
    live.app.settings.auto_update = False
    live.app.start_updates()
    (u,) = FakeUpdater.instances
    assert u.recovered == 1 and u.started == 0
    status, data = live.post("/api/settings", {"auto_update": True})
    assert status == 200 and "on" in data["message"] and u.started == 1
    status, data = live.post("/api/settings", {"auto_update": False})
    assert status == 200 and u.stopped == 1 and "Check for updates" in data["message"]
    live.app.close()                                # already stopped: not stopped twice
    assert u.stopped == 1


def test_settings_page_toggles_never_start_updates_in_tests(live, phase2):
    """Without serve() (manage_updates False) a settings change never starts the real timer."""
    live.post("/api/settings", {"auto_update": False})
    live.post("/api/settings", {"auto_update": True})
    assert all(u.started == 0 for u in FakeUpdater.instances)


def test_phase2_settings_round_trip_and_validation(live, settings):
    status, data = live.get("/api/settings")
    assert (data["auto_update"], data["update_interval_h"], data["ml_enabled"], data["learning_enabled"]) == \
        (True, 4.0, True, True)
    assert data["ml_max_file_size"] == 16 * 1024**2 and data["phase2_limits"]["update_interval_h"] == {"min": 1, "max": 24}
    body = {"auto_update": False, "update_interval_h": 12, "ml_enabled": False,
            "ml_max_file_size": 100 * 1024**2, "learning_enabled": False}
    status, data = live.post("/api/settings", body)
    assert status == 200, data
    saved = json.loads(settings.settings_path.read_text(encoding="utf-8"))
    for k, v in body.items():
        assert saved[k] == v and data["settings"][k] == v and getattr(live.app.settings, k) == v
    assert config.load_settings(settings.data_dir).update_interval_h == 12.0
    for bad in ({"auto_update": "yes"}, {"auto_update": 1}, {"ml_enabled": None}, {"learning_enabled": []},
                {"update_interval_h": 0}, {"update_interval_h": 25}, {"update_interval_h": True},
                {"update_interval_h": "4"}, {"update_interval_h": float("nan")}, {"ml_max_file_size": 1000},
                {"ml_max_file_size": 2 * 1024**3}, {"ml_max_file_size": 1024**2 + 0.5},
                {"signatures_max_age_days": 30}):
        status, data = live.post("/api/settings", bad)
        assert status == 400 and data["error"], bad
    assert live.app.settings.update_interval_h == 12.0 and live.app.settings.ml_max_file_size == 100 * 1024**2
    assert live.post("/api/settings", {"update_interval_h": 1.5})[0] == 200
    assert live.app.settings.update_interval_h == 1.5


def test_trusted_signers_shown_when_there_is_a_root(live, monkeypatch):
    root = {"_type": "root", "version": 1, "keys": {"ab" * 32: {"keytype": "ed25519", "public": "00"}},
            "roles": {"root": {"keyids": ["ab" * 32], "threshold": 1},
                      "targets": {"keyids": ["ab" * 32], "threshold": 1}}}
    monkeypatch.setattr(server, "_load_signed", lambda: SimpleNamespace(load_trusted_root=lambda s: root))
    signers = live.get("/api/settings")[1]["signers"]
    assert signers == [{"keyid": "ab" * 8, "keytype": "ed25519", "roles": ["root", "targets"]}]


def _rule_detection(store, i, rule="Win.Packed.Mikey-1", engine="clamav", conf=Confidence.HIGH, path=None):
    job_id = store.create_job(["D:\\Games"])
    r = FileResult(path=path or f"D:\\Games\\mod{i}.exe", sha256=f"{i:02x}" * 32, size=10,
                   findings=[Finding(engine, rule, conf, "tests")])
    return store.add_result(job_id, r)


def test_not_a_threat_says_what_is_learned(live):
    store = live.app.store
    rids = [_rule_detection(store, i) for i in range(1, 4)]
    status, data = live.post(f"/api/result/{rids[0]}/trust")
    assert status == 200 and data["message"].startswith("Trusted:")
    assert "1 of 3 different files matching 'Win.Packed.Mikey-1' are now marked safe" in data["message"]
    live.post(f"/api/result/{rids[1]}/trust")
    status, data = live.post(f"/api/result/{rids[2]}/trust")
    assert "marked 3 different files matching 'Win.Packed.Mikey-1' as safe" in data["message"]
    assert "counts for less" in data["message"]
    status, data = live.get("/api/learning")
    assert status == 200 and data["enabled"] is True and data["threshold"] == 3
    (rule,) = data["rules"]
    assert (rule["engine"], rule["rule"], rule["safe_files"], rule["active"]) == ("clamav", "Win.Packed.Mikey-1", 3, True)
    live.app.settings.learning_enabled = False
    rid = _rule_detection(store, 9)
    assert "Learning from your choices is off" in live.post(f"/api/result/{rid}/trust")[1]["message"]


def test_forget_and_use_again_from_the_page(live):
    store = live.app.store
    for i in range(1, 4):
        live.post(f"/api/result/{_rule_detection(store, i, rule='Tool_X', engine='yara')}/trust")
    for bad in ({}, {"engine": "yara"}, {"engine": 1, "rule": "Tool_X"}, {"engine": "yara", "rule": "x" * 2000}):
        assert live.post("/api/learning/forget", bad)[0] == 400, bad
    assert live.post("/api/learning/forget", {"engine": "yara", "rule": "Nope"})[0] == 404
    status, data = live.post("/api/learning/forget", {"engine": "yara", "rule": "Tool_X"})
    assert status == 200 and data["message"].startswith("Forgotten") and data["rules"][0]["state"] == "forgotten"
    f = Finding("yara", "Tool_X", Confidence.HIGH, "tests")
    assert learning.adjust([f], store, live.app.settings)[0][0].confidence == Confidence.HIGH
    status, data = live.post("/api/learning/restore", {"engine": "yara", "rule": "Tool_X"})
    assert status == 200 and data["rules"][0]["active"] is True
    assert live.post("/api/learning/restore", {"engine": "yara", "rule": "Tool_X"})[0] == 409
    assert learning.adjust([f], store, live.app.settings)[0][0].confidence == Confidence.MEDIUM


def test_its_a_threat_goes_on_your_known_bad_list(live, settings):
    store = live.app.store
    rid = _rule_detection(store, 5, path="D:\\Downloads\\bad.exe")
    listed = settings.hashset_dir / learning.CONFIRMED_LIST
    status, data = live.post(f"/api/result/{rid}/confirm")
    assert status == 200 and data["message"].startswith("Noted: you confirmed")
    assert "your own known-bad list" in data["message"]
    assert ("05" * 32) in listed.read_text(encoding="utf-8")
    assert live.get("/api/learning")[1]["confirmed_count"] == 1
    # changed their mind: off the list again
    status, data = live.post(f"/api/result/{rid}/trust")
    assert status == 200 and "off your own known-bad list" in data["message"] and not listed.exists()
    # learning off: confirmed, but not listed, and the page says so
    status, _ = live.post("/api/settings", {"learning_enabled": False})
    rid2 = _rule_detection(store, 6)
    status, data = live.post(f"/api/result/{rid2}/confirm")
    assert "Learning from your choices is off" in data["message"] and not listed.exists()
    live.post("/api/settings", {"learning_enabled": True})
    assert ("06" * 32) in listed.read_text(encoding="utf-8")       # rebuilt from your verdicts


def test_confirm_cancels_a_learned_rule_and_says_so(live):
    store = live.app.store
    for i in range(1, 4):
        live.post(f"/api/result/{_rule_detection(store, i)}/trust")
    status, data = live.post(f"/api/result/{_rule_detection(store, 7)}/confirm")
    assert "count normally again" in data["message"] and "'Win.Packed.Mikey-1'" in data["message"]
    assert live.get("/api/learning")[1]["rules"][0]["state"] == "cancelled"


def test_ml_score_is_on_the_result(live):
    store = live.app.store
    job_id = store.create_job(["C:\\Users\\me\\Desktop"])
    ml = Finding("ml", "TacoGuard ML model 2026.11.23", Confidence.MEDIUM, "TacoGuard's own model",
                 detail="machine-learning score 0.71 (suspicious at 0.65 or more)")
    rid = store.add_result(job_id, FileResult(path="C:\\Users\\me\\Desktop\\mod-loader.exe", sha256="7a" * 32,
                                              findings=[ml]))
    det = next(d for d in live.get("/api/detections")[1]["detections"] if d["id"] == rid)
    assert det["ml_score"] == 0.71 and det["signature_match"] is False and det["level"] == "suspicious"
    assert "0.71" in det["reason"]
    store.add_result(job_id, FileResult(path="C:\\x.exe", sha256="7b" * 32,
                                        findings=[ml, Finding("yara", "R", Confidence.LOW, "t")]))
    det = live.get("/api/detections")[1]["detections"][0]
    assert det["ml_score"] == 0.71 and det["signature_match"] is True


def test_real_phase2_modules_wire_up_without_going_online(settings, monkeypatch):
    """The real updater / self-update modules, read only: the Updates card and the app offer
    build from them. Nothing is started or checked (that would go online)."""
    pytest.importorskip("tacoguard.updates.updater")
    pytest.importorskip("tacoguard.selfupdate")
    monkeypatch.setattr(defender, "peek", lambda: dict(FAKE_DEFENDER))
    app = server.App(settings)
    try:
        view = app.updates_view()
        assert view["available"] is True and app.updater is not None
        assert {c["name"] for c in view["components"]} <= {n for n, _ in server.UPDATE_COMPONENTS}
        assert not getattr(app.updater, "_thread", None)          # built, never started
        a = view["app"]
        assert a["available"] is True and set(a) >= {"offer", "installed", "note", "previous"}
        if not a["installed"]:
            assert a["note"]
    finally:
        app.close()


def test_page_has_the_phase2_parts(live):
    html = live.raw("GET", "/", token=False)[2].decode()
    for part in ("card-updates", "btn-check-updates", "app-offer", "updates-stale", "phase2-form",
                 "learned-list", "auto_update", "learning_enabled", "ml_enabled"):
        assert part in html
    js = live.raw("GET", "/app.js", token=False)[2].decode()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js
    assert "/api/app/update" in js and "confirmBox" in js
