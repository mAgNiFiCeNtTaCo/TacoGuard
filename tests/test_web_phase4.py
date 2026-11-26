"""Phase 4 on the page: the dashboard, pausing protection, Game mode, website blocking (lists and the
hosts file), the abuse.ch key and MalwareBazaar lookups, and the Phase 4 settings.

The server runs in a thread on a free port with a temp data folder (never 8799). The website list,
hosts file and lookup modules are FAKES (no network, no admin prompt, never the real hosts file).
The key store is the real tacoguard.secrets, inside the temp data folder only.
"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

from tacoguard import defender, gamemode, phase4, setup_fetch
from tacoguard.config import load_settings
from tacoguard.model import Confidence, FileResult, Finding
from tacoguard.web import server
from tacoguard.webblock.hosts import CANCELLED_MSG as Outcome_said_no
from tacoguard.webblock.hosts import Outcome
from test_web import FAKE_DEFENDER, Client, _missing_module

KEY = "TestOnlyKey_0123456789abcdefWXYZ"      # made up; the shape of an abuse.ch Auth-Key


def _wait(cond, timeout=10.0, step=0.02) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


# ---------------------------------------------------------------------------------------------
# fakes for the other helpers' modules
# ---------------------------------------------------------------------------------------------
class FakeLists:
    def __init__(self):
        self.gate = threading.Event()
        self.gate.set()
        self.refreshed = 0
        self.answer = {"ok": True, "changed": True, "message": "12,000 sites in the phishing list.", "sources": {}}

    def status(self, settings):
        return {"enabled": bool(settings.webblock_enabled), "total": 12000, "sources": {
            "phishing": {"on": True, "label": "phishing list (Phishing.Database)", "kind": "phishing",
                         "count": 12000, "fetched": time.time() - 3600, "state": "ok", "message": ""},
            "urlhaus": {"on": True, "label": "malware-site list (URLhaus)", "kind": "malware", "count": 0,
                        "fetched": 0, "state": "no_key", "message": "Add your free abuse.ch key in Settings."}}}

    def refresh(self, settings, store=None, progress=None):
        self.gate.wait(10)
        self.refreshed += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class FakeHosts:
    def __init__(self):
        self.gate = threading.Event()
        self.gate.set()
        self.calls = []
        self.error = None
        self.applied = False
        self.answer_ok = True

    def plan(self, settings):
        return {"domains": 12000, "applied": self.applied, "last_applied": 0, "size": 400000,
                "message": "On: 12,000 websites are blocked." if self.applied else ""}

    def apply_elevated(self, settings):
        self.calls.append("apply")
        self.gate.wait(10)
        if self.error:
            raise self.error
        if not self.answer_ok:
            return Outcome(Outcome_said_no, ok=False, code="cancelled")
        self.applied = True
        return Outcome("Done: 12,000 websites are blocked in the hosts file.", ok=True, code="done")

    def remove_elevated(self, settings):
        self.calls.append("remove")
        self.gate.wait(10)
        if self.error:
            raise self.error
        if not self.answer_ok:
            return Outcome(Outcome_said_no, ok=False, code="cancelled")
        self.applied = False
        return Outcome("TacoGuard's block is out of the hosts file.", ok=True, code="removed")


class FakeLookup:
    def __init__(self):
        self.asked = []
        self.answer = "found"
        self.state = {"state": "", "message": "", "when": 0.0}

    def status(self, store):
        return dict(self.state)

    def rate_left(self, store):
        return 30 - len(self.asked)

    def lookup(self, settings, store, sha256, force=False):
        self.asked.append((sha256, force))
        if self.answer is None:
            self.state = {"state": "offline", "message": "Could not reach MalwareBazaar (abuse.ch). "
                                                         "TacoGuard will try again later.", "when": time.time()}
            return None
        found = self.answer == "found"
        data = {"signature": "AgentTesla", "file_type": "exe", "first_seen": "2026-11-01 10:00:00",
                "tags": ["stealer"]} if found else {}
        store.put_lookup(sha256, found, data)
        return dict(data, found=found, link=f"https://bazaar.abuse.ch/sample/{sha256}/",
                    message="MalwareBazaar lists this exact file as 'AgentTesla' malware, first seen "
                            "2026-11-01 10:00:00." if found else "MalwareBazaar doesn't know this exact file.")


@pytest.fixture
def fakes(monkeypatch):
    f = SimpleNamespace(lists=FakeLists(), hosts=FakeHosts(), lookup=FakeLookup())
    monkeypatch.setattr(server, "_load_webblock_lists", lambda: f.lists)
    monkeypatch.setattr(server, "_load_webblock_hosts", lambda: f.hosts)
    monkeypatch.setattr(server, "_load_lookup", lambda: f.lookup)
    return f


@pytest.fixture
def live(settings, monkeypatch, fakes):
    monkeypatch.setattr(defender, "peek", lambda: dict(FAKE_DEFENDER))
    monkeypatch.setattr(setup_fetch, "fetch_all", lambda s, progress=print: {})
    for name in ("_load_updater_module", "_load_selfupdate", "_load_signed"):
        monkeypatch.setattr(server, name, _missing_module)
    app = server.App(settings)
    srv = server.make_server(app, port=0)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    c = Client(app, app.port)
    c.thread, c.srv, c.fakes = t, srv, fakes
    yield c
    fakes.hosts.gate.set()
    fakes.lists.gate.set()
    srv.shutdown()
    srv.server_close()
    t.join(5)
    app.close()


def _flagged(store, path=r"C:\Users\me\Downloads\free-vbucks.exe", sha="ab" * 32, conf=Confidence.HIGH):
    job = store.create_job([r"C:\Users\me\Downloads"])
    rid = store.add_result(job, FileResult(path=path, sha256=sha, size=10,
                                           findings=[Finding("yara", "Generic_Test_Rule", conf, "test rules")]))
    store.update_job(job, status="done", finished=time.time(), counts={"files": 1, "malware": 1})
    return rid


def _log(live) -> str:
    p = live.app.settings.log_dir / "web.log"
    return p.read_text(encoding="utf-8") if p.exists() else ""


# ---------------------------------------------------------------------------------------------
# security: the new routes sit behind the same checks
# ---------------------------------------------------------------------------------------------
NEW_ROUTES = [("GET", "/api/dashboard"), ("GET", "/api/webblock"), ("POST", "/api/protection/pause"),
              ("POST", "/api/gamemode"), ("POST", "/api/webblock/hosts"), ("POST", "/api/webblock/refresh"),
              ("POST", "/api/secrets/abusech"), ("POST", "/api/lookup")]


@pytest.mark.parametrize("method,path", NEW_ROUTES)
def test_new_routes_need_the_token_and_same_origin(live, method, path):
    body = {"minutes": 60, "on": True, "action": "apply", "key": KEY, "result_id": 1}
    send = body if method == "POST" else None
    assert live.raw(method, path, send, token=False)[0] == 403
    assert live.raw(method, path, send, token="wrong")[0] == 403
    assert live.raw(method, path, send, host="evil.example:80")[0] == 403
    if method == "POST":
        assert live.post(path, body, headers={"Origin": "http://evil.example"})[0] == 403
        assert live.post(path, body, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
        assert live.raw("POST", path, b"key=1", ctype="application/x-www-form-urlencoded")[0] == 415
    # nothing happened
    assert not phase4.protection_paused(live.app.store) and not phase4.game_mode(live.app.store)["active"]
    assert live.fakes.hosts.calls == [] and live.fakes.lookup.asked == []
    assert not live.app.key_view()["set"]


@pytest.mark.parametrize("method,path", NEW_ROUTES)
def test_other_windows_user_is_refused(live, monkeypatch, method, path):
    monkeypatch.setattr(server, "client_verdict", lambda c, s: server.OTHER)
    status, _, raw = live.raw(method, path, {"on": True} if method == "POST" else None)
    assert status == 403 and b"your own" in raw


def test_wrong_methods(live):
    assert live.raw("GET", "/api/protection/pause")[0] == 405
    assert live.raw("POST", "/api/dashboard", {})[0] == 405
    assert live.raw("GET", "/api/secrets/abusech")[0] == 405


# ---------------------------------------------------------------------------------------------
# dashboard and status
# ---------------------------------------------------------------------------------------------
def test_dashboard_shape(live):
    status, d = live.get("/api/dashboard")
    assert status == 200, d
    assert set(d) >= {"protection", "modes", "alerts", "last_scan", "updates", "webblock", "lookup", "tray",
                      "self_protection"}
    assert d["protection"]["state"] == "off" and d["protection"]["paused_until"] == 0
    assert d["modes"]["game_mode"]["active"] is False and d["modes"]["game_mode"]["auto"] is True
    assert d["alerts"] == {"protection": 0, "detections": 0, "malware": 0, "total": 0}
    assert d["last_scan"] is None
    assert d["webblock"]["available"] and d["webblock"]["total"] == 12000
    assert [s["name"] for s in d["webblock"]["sources"]] == ["phishing", "urlhaus"]
    assert d["webblock"]["hosts"]["available"] and d["webblock"]["hosts"]["plan"]["domains"] == 12000
    assert d["lookup"]["available"] and d["lookup"]["key"]["set"] is False and d["lookup"]["ready"] is False
    assert d["tray"] == {"enabled": True, "managed": False, "running": False, "note": ""}
    assert d["self_protection"]["enabled"] is True and d["self_protection"]["hardened"] is None


def test_dashboard_counts_parts_and_notes(live):
    store = live.app.store
    rid = _flagged(store)
    store.add_guard_event("file", "suspicious", "Suspicious: Desktop\\mod.exe")
    parts = {"folders": {"state": "on", "watched": ["a"]}, "processes": {"state": "on"},
             "ransomware": {"state": "on"}, "persistence": {"state": "on"},
             "web": {"state": "on", "message": "Watching 12,000 websites."}}
    import os
    store.set_meta("guard_state", json.dumps({"pid": os.getpid(), "started": time.time(), "heartbeat": time.time(),
                                              "parts": parts, "notes": ["Windows has notifications switched off."]}))
    store.set_meta("selfprotect", json.dumps({"notes": ["TacoGuard's own files were checked: no changes."],
                                              "problems": "not a list", "message": 5}))
    d = live.get("/api/dashboard")[1]
    assert d["alerts"] == {"protection": 1, "detections": 1, "malware": 1, "total": 2}
    assert d["last_scan"]["result"] == "malware" and d["last_scan"]["short_targets"]
    names = [p["name"] for p in d["protection"]["parts"]]
    assert names == ["folders", "processes", "ransomware", "persistence", "web"]
    assert d["protection"]["summary"].endswith("start-up entries, bad websites.")
    assert d["webblock"]["part"] == {"state": "on", "message": "Watching 12,000 websites."}
    assert d["self_protection"]["notes"] == ["Windows has notifications switched off.",
                                             "TacoGuard's own files were checked: no changes."]
    assert rid


def test_dashboard_calm_when_phase4_parts_are_missing(live, monkeypatch):
    for name in ("_load_webblock_lists", "_load_webblock_hosts", "_load_lookup", "_load_secrets",
                 "_load_selfprotect"):
        monkeypatch.setattr(server, name, _missing_module)
    status, d = live.get("/api/dashboard")
    assert status == 200
    assert d["webblock"]["message"] == server.WEBBLOCK_NOT_READY
    assert d["webblock"]["hosts"]["message"] == server.HOSTS_NOT_READY
    assert d["lookup"]["message"] == server.LOOKUP_NOT_READY
    assert d["lookup"]["key"]["message"] == server.SECRETS_NOT_READY
    assert live.post("/api/webblock/hosts", {"action": "apply"})[0] == 503
    assert live.post("/api/webblock/refresh", {})[0] == 503
    assert live.post("/api/secrets/abusech", {"key": KEY})[0] == 503
    assert live.post("/api/lookup", {"result_id": 1})[0] == 503
    assert live.get("/api/settings")[0] == 200


def test_broken_status_of_another_module_is_calm(live, fakes, monkeypatch):
    monkeypatch.setattr(fakes.lists, "status", lambda s: 1 / 0)
    monkeypatch.setattr(fakes.hosts, "plan", lambda s: 1 / 0)
    d = live.get("/api/dashboard")[1]
    assert "Could not read the website lists" in d["webblock"]["message"]
    assert "Could not read the hosts file status" in d["webblock"]["hosts"]["message"]
    assert "ZeroDivisionError" not in json.dumps(d)


# ---------------------------------------------------------------------------------------------
# pause and Game mode
# ---------------------------------------------------------------------------------------------
def test_pause_and_resume(live):
    for bad in ({}, {"minutes": True}, {"minutes": -1}, {"minutes": 1441}, {"minutes": 1.5}, {"minutes": "60"},
                {"minutes": float("nan")}):
        status, data = live.post("/api/protection/pause", bad)
        assert status == 400 and "minutes" in data["error"], bad
    status, data = live.post("/api/protection/pause", {"minutes": 60})
    assert status == 200 and "paused until" in data["message"]
    until = phase4.protection_paused(live.app.store)
    assert 3500 < until - time.time() <= 3600
    assert data["modes"]["paused_until"] == pytest.approx(until)
    st = live.get("/api/status")[1]
    assert st["modes"]["paused_until"] == pytest.approx(until)
    assert live.get("/api/protection")[1]["guard"]["paused_until"] == pytest.approx(until)
    status, data = live.post("/api/protection/pause", {"minutes": 0})
    assert status == 200 and data["message"] == "Real-time protection is on again."
    assert phase4.protection_paused(live.app.store) == 0
    live.app.settings.realtime_enabled = False
    status, data = live.post("/api/protection/pause", {"minutes": 60})
    assert status == 409 and "nothing to pause" in data["error"]


def test_game_mode_switch(live):
    for bad in ({}, {"on": 1}, {"on": "yes"}, {"on": None}):
        assert live.post("/api/gamemode", bad)[0] == 400, bad
    status, data = live.post("/api/gamemode", {"on": True})
    assert status == 200 and "until you turn it off" in data["message"] and "4 hours" in data["message"]
    g = data["modes"]["game_mode"]
    assert g["active"] and g["manual"] and g["reason"] == gamemode.MANUAL_REASON
    assert live.get("/api/status")[1]["modes"]["game_mode"]["active"]
    status, data = live.post("/api/gamemode", {"on": False})
    assert status == 200 and data["message"] == "Game mode is off."
    # turned off while automatic Game mode was on: TacoGuard says it leaves it off for 2 hours
    phase4.set_game_mode(live.app.store, True, manual=False, reason="a full-screen game")
    status, data = live.post("/api/gamemode", {"on": False})
    assert "2 hours" in data["message"] and not phase4.game_mode(live.app.store)["active"]
    assert gamemode.respect_until(live.app.store) > time.time() + 7000


# ---------------------------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------------------------
def test_phase4_settings_view_and_validation(live):
    s = live.get("/api/settings")[1]
    for k in server.PHASE4_SWITCHES:
        assert s[k] is getattr(live.app.settings, k), k
    assert s["webblock_hosts_every_days"] == 7
    assert s["phase4_limits"]["webblock_hosts_every_days"] == {"min": 1, "max": 30}
    assert s["abusech_key"] == {"available": True, "set": False, "hint": "", "message": ""}
    for k in server.PHASE4_SWITCHES:
        for bad in (1, "true", None):
            status, data = live.post("/api/settings", {k: bad})
            assert status == 400 and "must be on or off" in data["error"], (k, bad)
    for bad in (0, 31, 1.5, "7", True, float("inf")):
        status, data = live.post("/api/settings", {"webblock_hosts_every_days": bad})
        assert status == 400 and "1 to 30 days" in data["error"], bad
    assert "webblock_pause_programs" not in server.PHASE4_SWITCHES and "webblock_pause_programs" not in s
    status, data = live.post("/api/settings", {"webblock_pause_programs": False})
    assert status == 400                                   # the switch is gone: websites never pause
    body = {"webblock_enabled": False, "webblock_phishing_list": False, "webblock_urlhaus_list": False,
            "lookup_enabled": False, "game_mode_auto": False,
            "self_protection": False, "tray_enabled": False, "webblock_hosts_every_days": 30}
    status, data = live.post("/api/settings", body)
    assert status == 200, data
    assert "only when you switch it on" in data["message"] and "Self-protection" in data["message"]
    disk = load_settings(live.app.settings.data_dir)
    for k, v in body.items():
        assert getattr(disk, k) == v and getattr(live.app.settings, k) == v and data["settings"][k] == v
    status, data = live.post("/api/settings", {"webblock_hosts_every_days": 1, "webblock_enabled": True})
    assert status == 200 and "Website blocking picks up the change" in data["message"]
    assert load_settings(live.app.settings.data_dir).webblock_hosts_every_days == 1


def test_auto_game_mode_off_in_settings_ends_an_automatic_one(live):
    phase4.set_game_mode(live.app.store, True, manual=False, reason="a full-screen game")
    live.post("/api/settings", {"game_mode_auto": False})
    assert live.app.gamemode.step() == "off"
    assert not phase4.game_mode(live.app.store)["active"]


def test_tray_switch_starts_and_stops_the_icon(live, monkeypatch):
    made = []

    class FakeTray:
        def __init__(self, app):
            self.running = False
            made.append(self)

        def start(self):
            self.running = True
            return True

        def stop(self):
            self.running = False

        def refresh(self):
            pass

    monkeypatch.setattr(server, "_load_tray", lambda: SimpleNamespace(Tray=FakeTray))
    live.app.start_tray()
    assert made and made[0].running
    status, data = live.post("/api/settings", {"tray_enabled": False})
    assert status == 200 and "gone from the taskbar" in data["message"] and not made[0].running
    assert live.get("/api/dashboard")[1]["tray"]["running"] is False
    status, data = live.post("/api/settings", {"tray_enabled": True})
    assert "in the taskbar" in data["message"] and made[-1].running and len(made) == 2

    class BrokenTray(FakeTray):
        def start(self):
            return False
    monkeypatch.setattr(server, "_load_tray", lambda: SimpleNamespace(Tray=BrokenTray))
    live.post("/api/settings", {"tray_enabled": False})
    status, data = live.post("/api/settings", {"tray_enabled": True})
    assert "could not be added" in data["message"]
    assert live.get("/api/dashboard")[1]["tray"]["note"]


# ---------------------------------------------------------------------------------------------
# the abuse.ch key: saved, never echoed, never logged
# ---------------------------------------------------------------------------------------------
def test_key_save_show_hint_remove(live):
    status, headers, raw = live.raw("POST", "/api/secrets/abusech", {"key": "  " + KEY + "\n"})
    assert status == 200
    data = json.loads(raw)
    assert set(data) == {"ok", "set", "hint", "message"}
    assert data["set"] is True and data["hint"] == "ending in ..." + KEY[-4:]
    assert KEY.encode() not in raw and KEY[:-4].encode() not in raw
    for path in ("/api/settings", "/api/dashboard", "/api/status", "/api/webblock"):
        raw2 = live.raw("GET", path)[2]
        assert KEY.encode() not in raw2 and KEY[:12].encode() not in raw2, path
    assert live.get("/api/settings")[1]["abusech_key"]["hint"] == "ending in ..." + KEY[-4:]
    d = live.get("/api/dashboard")[1]
    assert d["lookup"]["ready"] is True and d["modes"]["lookup_ready"] is True
    # stored encrypted in the temp data folder only
    files = list(live.app.settings.secrets_dir.iterdir())
    assert files and all(KEY.encode() not in f.read_bytes() for f in files)
    status, data = live.post("/api/secrets/abusech", {"clear": True})
    assert status == 200 and data["set"] is False and data["hint"] == "" and "Removed" in data["message"]
    status, data = live.post("/api/secrets/abusech", {"clear": True})
    assert status == 200 and "no key" in data["message"]
    assert KEY not in _log(live) and KEY[:12] not in _log(live)


@pytest.mark.parametrize("body", [{}, {"key": ""}, {"key": "   "}, {"key": 12345}, {"key": "short-key"},
                                  {"key": "has spaces and ! marks in it for sure"}, {"key": "x" * 2000},
                                  {"clear": "yes"}, {"key": KEY, "clear": True}])
def test_bad_key_requests(live, body):
    status, headers, raw = live.raw("POST", "/api/secrets/abusech", body)
    assert status == 400
    v = body.get("key")
    if isinstance(v, str) and v.strip():
        assert v.strip().encode()[:40] not in raw            # never echoed back
    assert not live.app.key_view()["set"]


def test_key_never_in_the_log_even_on_failure(live, monkeypatch):
    from tacoguard import secrets as tg_secrets

    def broken(settings, name, value):
        raise RuntimeError(f"something went wrong with {value}")
    monkeypatch.setattr(tg_secrets, "set_key", broken)
    status, headers, raw = live.raw("POST", "/api/secrets/abusech", {"key": KEY})
    assert status == 500 and KEY.encode() not in raw
    data = json.loads(raw)
    assert data["error"] == server.KEY_SAVE_FAILED

    def refuses(settings, name, value):
        raise ValueError(f"the key {value} is bad")
    monkeypatch.setattr(tg_secrets, "set_key", refuses)
    status, headers, raw = live.raw("POST", "/api/secrets/abusech", {"key": KEY})
    assert status == 400 and KEY.encode() not in raw and json.loads(raw)["error"] == server.KEY_BAD_MSG
    # a key sent in the address (the page never does that) is cut from the request log
    live.raw("POST", "/api/secrets/abusech?key=" + KEY, {})
    log = _log(live)
    assert "/api/secrets/abusech" in log and "(hidden)" in log
    assert KEY not in log and "RuntimeError" in log


# ---------------------------------------------------------------------------------------------
# MalwareBazaar lookups
# ---------------------------------------------------------------------------------------------
def _with_key(live):
    assert live.post("/api/secrets/abusech", {"key": KEY})[0] == 200


def test_lookup_needs_a_flagged_file_and_a_key(live, fakes):
    rid = _flagged(live.app.store)
    status, data = live.post("/api/lookup", {"result_id": rid})
    assert status == 409 and "abuse.ch key" in data["error"]
    _with_key(live)
    live.app.settings.lookup_enabled = False
    status, data = live.post("/api/lookup", {"result_id": rid})
    assert status == 409 and "off in Settings" in data["error"]
    live.app.settings.lookup_enabled = True
    for bad in ({}, {"result_id": "1"}, {"result_id": True}, {"result_id": 1, "sha256": "ab" * 32},
                {"sha256": "zz"}, {"sha256": 5}, {"event_id": -3}):
        assert live.post("/api/lookup", bad)[0] == 400, bad
    assert live.post("/api/lookup", {"result_id": 99999})[0] == 404
    assert live.post("/api/lookup", {"event_id": 99999})[0] == 404
    # a hash TacoGuard never flagged is never sent
    status, data = live.post("/api/lookup", {"sha256": "cd" * 32})
    assert status == 400 and "flagged" in data["error"]
    # an alert that isn't about a flagged file
    eid = live.app.store.add_guard_event("persistence", "warning", "New start-up entry")
    assert live.post("/api/lookup", {"event_id": eid})[0] == 400
    no_hash = _flagged(live.app.store, path=r"C:\Users\me\Desktop\locked.exe", sha="")
    status, data = live.post("/api/lookup", {"result_id": no_hash})
    assert status == 400 and "fingerprint" in data["error"]
    assert fakes.lookup.asked == []


def test_lookup_found_not_found_and_offline(live, fakes):
    _with_key(live)
    store = live.app.store
    rid = _flagged(store)
    status, data = live.post("/api/lookup", {"result_id": rid})
    assert status == 200, data
    assert data["found"] is True and "AgentTesla" in data["message"] and "free-vbucks.exe: " in data["message"]
    assert data["link"] == "https://bazaar.abuse.ch/sample/" + "ab" * 32 + "/"
    assert fakes.lookup.asked == [("ab" * 32, True)]
    det = live.get("/api/detections")[1]["detections"][0]
    assert det["lookup"]["found"] is True and "AgentTesla" in det["lookup"]["message"]
    job_view = live.get(f"/api/scan/{store.get_result(rid)['job_id']}")[1]
    assert job_view["detections"][0]["lookup"]["signature"] == "AgentTesla"
    # by hash (a flagged one) and by alert
    sha2 = "ef" * 32
    eid = store.add_guard_event("file", "suspicious", "Suspicious: Desktop\\mod.exe", path=r"C:\Users\me\Desktop\mod.exe",
                                sha256=sha2)
    fakes.lookup.answer = "not found"
    status, data = live.post("/api/lookup", {"event_id": eid})
    assert status == 200 and data["found"] is False and "doesn't make it safe" in data["message"]
    status, data = live.post("/api/lookup", {"sha256": sha2.upper()})
    assert status == 200 and fakes.lookup.asked[-1] == (sha2, True)
    ev = live.get("/api/protection")[1]["attention"][0]
    assert ev["lookup"]["found"] is False
    # offline: the lookup module's own plain words
    fakes.lookup.answer = None
    status, data = live.post("/api/lookup", {"result_id": rid})
    assert status == 503 and "Could not reach MalwareBazaar" in data["error"]
    d = live.get("/api/dashboard")[1]["lookup"]
    assert d["last_error"].startswith("Could not reach") and d["left"] == 30 - len(fakes.lookup.asked)


# ---------------------------------------------------------------------------------------------
# website blocking: the hosts file (one at a time, in the background) and the lists
# ---------------------------------------------------------------------------------------------
def test_hosts_apply_is_single_flight_and_reported(live, fakes):
    for bad in ({}, {"action": "delete"}, {"action": 1}):
        assert live.post("/api/webblock/hosts", bad)[0] == 400
    fakes.hosts.gate.clear()                     # the "admin prompt" waits for the user
    status, data = live.post("/api/webblock/hosts", {"action": "apply"})
    assert status == 200 and "administrator prompt" in data["message"]
    assert _wait(lambda: fakes.hosts.calls == ["apply"])
    status, data = live.post("/api/webblock/hosts", {"action": "apply"})
    assert status == 409 and "already" in data["error"]
    status, data = live.post("/api/webblock/hosts", {"action": "remove"})
    assert status == 409
    w = live.get("/api/webblock")[1]
    assert w["hosts"]["action"]["running"] is True and w["hosts"]["action"]["what"] == "apply"
    assert load_settings(live.app.settings.data_dir).webblock_hosts is False    # not before it's done
    fakes.hosts.gate.set()
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    w = live.get("/api/webblock")[1]["hosts"]
    assert w["action"]["message"].startswith("Done") and w["action"]["error"] == "" and w["action"]["ok"]
    assert w["plan"]["applied"] is True and w["enabled"] is True
    assert load_settings(live.app.settings.data_dir).webblock_hosts is True     # your choice is kept
    assert fakes.hosts.calls == ["apply"]
    # remove
    status, data = live.post("/api/webblock/hosts", {"action": "remove"})
    assert status == 200
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    assert fakes.hosts.calls == ["apply", "remove"]
    assert load_settings(live.app.settings.data_dir).webblock_hosts is False


def test_hosts_choice_is_saved_only_when_the_helper_did_it(live, fakes):
    fakes.hosts.answer_ok = False                          # you said No to Windows' prompt
    assert live.post("/api/webblock/hosts", {"action": "apply"})[0] == 200
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    a = live.get("/api/webblock")[1]["hosts"]["action"]
    assert a["error"] == Outcome_said_no and a["message"] == "" and a["ok"] is False
    assert load_settings(live.app.settings.data_dir).webblock_hosts is False
    # on, then a removal that fails: still on
    fakes.hosts.answer_ok = True
    live.post("/api/webblock/hosts", {"action": "apply"})
    assert _wait(lambda: load_settings(live.app.settings.data_dir).webblock_hosts is True)
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    fakes.hosts.answer_ok = False
    live.post("/api/webblock/hosts", {"action": "remove"})
    assert _wait(lambda: fakes.hosts.calls[-1] == "remove")
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    assert load_settings(live.app.settings.data_dir).webblock_hosts is True


def test_switching_blocking_off_offers_to_take_the_block_out(live, monkeypatch):
    monkeypatch.setattr(live.app, "_hosts_block_present", lambda: True)
    live.app._save_settings({"webblock_hosts": True})
    status, data = live.post("/api/settings", {"webblock_enabled": False})
    assert status == 200 and data["offer_hosts_remove"] is True and server.HOSTS_REMOVE_OFFER in data["message"]
    status, data = live.post("/api/settings", {"webblock_enabled": True})
    assert data["offer_hosts_remove"] is False
    monkeypatch.setattr(live.app, "_hosts_block_present", lambda: False)
    status, data = live.post("/api/settings", {"webblock_enabled": False})
    assert data["offer_hosts_remove"] is False                 # no block in the file: nothing to offer


def test_never_block_list_is_checked_and_saved(live):
    status, data = live.post("/api/settings", {"webblock_allow": [" My-Bank.Example ", "https://shop.example/x",
                                                                  "", "my-bank.example", "bücher.example"]})
    assert status == 200, data
    assert data["settings"]["webblock_allow"] == ["my-bank.example", "shop.example", "xn--bcher-kva.example"]
    assert load_settings(live.app.settings.data_dir).webblock_allow == data["settings"]["webblock_allow"]
    assert live.get("/api/webblock")[1]["allow"] == data["settings"]["webblock_allow"]
    for bad in ("*.example.com", "1.2.3.4", "not a site", 5):
        status, data = live.post("/api/settings", {"webblock_allow": [bad]})
        assert status == 400 and ("website name" in data["error"] or "list of website names" in data["error"]), bad
    assert live.post("/api/settings", {"webblock_allow": "example.com"})[0] == 400
    status, data = live.post("/api/settings", {"webblock_allow": [f"site{i}.example" for i in range(501)]})
    assert status == 400 and "500" in data["error"]
    assert live.get("/api/settings")[1]["phase4_limits"]["webblock_allow"] == {"max": 500}


def test_lists_refresh_respects_a_refresh_running_elsewhere(live, fakes):
    fakes.lists.busy = lambda settings: True
    status, data = live.post("/api/webblock/refresh", {})
    assert status == 409 and "already updating" in data["error"] and fakes.lists.refreshed == 0
    fakes.lists.busy = lambda settings: False
    fakes.lists.answer = {"ok": True, "busy": True, "message": "The website lists are being updated right now."}
    assert live.post("/api/webblock/refresh", {})[0] == 200
    assert _wait(lambda: not live.get("/api/webblock")[1]["refresh"]["running"])
    r = live.get("/api/webblock")[1]["refresh"]
    assert r["message"].startswith("The website lists are being updated") and r["error"] == ""


@pytest.mark.parametrize("error,words", [
    (ValueError("You said no to Windows' prompt, so the hosts file was not changed."), "You said no"),
    (PermissionError(5, "Access is denied", "C:\\Windows\\System32\\drivers\\etc\\hosts"), "Windows refused access"),
    (RuntimeError("internal detail"), "stopped with a problem"),
])
def test_hosts_errors_are_plain(live, fakes, error, words):
    fakes.hosts.error = error
    assert live.post("/api/webblock/hosts", {"action": "apply"})[0] == 200
    assert _wait(lambda: not live.get("/api/webblock")[1]["hosts"]["action"]["running"])
    a = live.get("/api/webblock")[1]["hosts"]["action"]
    assert words in a["error"] and "internal detail" not in a["error"] and "WinError" not in a["error"]


def test_lists_refresh_single_flight(live, fakes):
    fakes.lists.gate.clear()
    status, data = live.post("/api/webblock/refresh", {})
    assert status == 200 and "Updating" in data["message"]
    assert live.post("/api/webblock/refresh", {})[0] == 409
    assert live.get("/api/webblock")[1]["refresh"]["running"] is True
    fakes.lists.gate.set()
    assert _wait(lambda: not live.get("/api/webblock")[1]["refresh"]["running"])
    r = live.get("/api/webblock")[1]["refresh"]
    assert r["message"] == "12,000 sites in the phishing list." and fakes.lists.refreshed == 1
    fakes.lists.answer = {"ok": False, "message": "The phishing list was refused: it shrank by more than half."}
    live.post("/api/webblock/refresh", {})
    assert _wait(lambda: not live.get("/api/webblock")[1]["refresh"]["running"])
    assert "shrank" in live.get("/api/webblock")[1]["refresh"]["error"]
    fakes.lists.answer = OSError(28, "No space left on device")
    live.post("/api/webblock/refresh", {})
    assert _wait(lambda: not live.get("/api/webblock")[1]["refresh"]["running"])
    assert "the disk is full" in live.get("/api/webblock")[1]["refresh"]["error"]
    live.app.settings.webblock_enabled = False
    status, data = live.post("/api/webblock/refresh", {})
    assert status == 409 and "off in Settings" in data["error"]


# ---------------------------------------------------------------------------------------------
# Helper P's notes: hardened adopted guards, and alerts of other kinds
# ---------------------------------------------------------------------------------------------
class StuckGuard:
    """An adopted guard that doesn't stop, and that Windows won't let this page end."""
    pid = 4_000_000

    def __init__(self):
        self.kills = 0

    def wait(self, timeout=None):
        raise TimeoutError("still running")

    def kill(self):
        self.kills += 1
        raise PermissionError(5, "Access is denied")

    def is_running(self):
        return True

    def status(self):
        return "running"


def test_adopted_guard_that_cannot_be_ended_gets_a_plain_note(live, monkeypatch):
    sup = live.app.guard
    sup.stop_wait = 0.01
    stuck = StuckGuard()
    alive = {"yes": True}
    monkeypatch.setattr(server, "_guard_process",
                        lambda pid: stuck if alive["yes"] and int(pid or 0) == stuck.pid else None)
    live.app.store.set_meta("guard_state", json.dumps({"pid": stuck.pid, "heartbeat": time.time() - 100}))
    sup.adopted = stuck
    live.app.settings.realtime_enabled = False
    sup.step()
    assert stuck.kills == 1 and sup.stop_note == server.STILL_CLOSING_MSG
    sup.step()
    sup.step()
    assert stuck.kills == 1                                   # one try, never a loop
    g = live.get("/api/protection")[1]["guard"]
    assert g["state"] == "off" and g["note"] == server.STILL_CLOSING_MSG
    assert "Task Manager as administrator" in live.get("/api/dashboard")[1]["protection"]["note"]
    # it went away (no guard process behind the heartbeat): the note goes too
    alive["yes"] = False
    sup.step()
    assert sup.stop_note == "" and live.get("/api/protection")[1]["guard"]["note"] == ""


def test_self_and_web_alerts_are_not_file_alerts(live):
    store = live.app.store
    ids = [store.add_guard_event("self", "warning", "TacoGuard's own files were changed", "changed: tacoguard/x.py"),
           store.add_guard_event("web", "warning", "Phishing website: login-verify.example",
                                 "A program looked up a website on the phishing list.", path=r"C:\Program Files\X\x.exe",
                                 sha256="ab" * 32)]
    att = live.get("/api/protection")[1]["attention"]
    assert {e["id"] for e in att} >= set(ids)
    _with_key(live)
    for eid in ids:
        status, data = live.post("/api/protection/event", {"id": eid, "action": "quarantine"})
        assert status == 400 and "isn't about a file" in data["error"]
        assert live.post("/api/lookup", {"event_id": eid})[0] == 400
        assert live.post("/api/protection/event", {"id": eid, "action": "dismiss"})[0] == 200
    assert live.fakes.lookup.asked == []


# ---------------------------------------------------------------------------------------------
# the page itself
# ---------------------------------------------------------------------------------------------
def test_page_has_the_phase4_parts_and_stays_strict(live):
    status, headers, raw = live.raw("GET", "/", token=False)
    html = raw.decode("utf-8")
    for needle in ('id="card-status"', 'id="modes"', 'id="panel-web"', 'id="panel-key"', 'id="panel-more"',
                   'type="password"', 'href="https://auth.abuse.ch/"', 'rel="noopener noreferrer"',
                   'id="btn-hosts-apply"', 'name="webblock_hosts_every_days"', 'name="game_mode_auto"'):
        assert needle in html, needle
    assert 'name="webblock_allow"' in html and "webblock_pause_programs" not in html
    assert "an administrator still can" in html
    js = live.raw("GET", "/app.js", token=False)[2].decode("utf-8")
    assert "innerHTML" not in js and "eval(" not in js
    assert "/api/secrets/abusech" in js and "/api/dashboard" in js and "/api/lookup" in js
    # Defender: never suggest allowing anything there (review finding 11)
    assert "that's this one" not in js
    assert ("If Microsoft Defender warns about the hosts file, follow what Defender says. TacoGuard tells you "
            "if its block was taken out.") in js
    assert '\\"Windows PowerShell\\"' in js and "webblock_pause_programs" not in js
    assert "an administrator still can" in js and "up to 4 hours" in js
