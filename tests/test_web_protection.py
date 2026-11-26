"""Phase 3 on the page: /api/protection, the user's actions on guard events, paused programs and
start-up entries, the real-time settings, and the page process supervising the guard.

The server runs in a thread on a free port with a temp data folder (never 8799). procctl and the
start-up entry module are faked where a test would otherwise touch programs it did not start or
the real registry; the one real pause/resume test uses a harmless child process this test starts.
Guard supervision uses fake guard commands (a Python one-liner that sleeps), never the real guard.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
import winreg
from pathlib import Path
from types import SimpleNamespace

import pytest

from tacoguard import autostart, defender, setup_fetch
from tacoguard.guard import procctl
from tacoguard.model import Confidence, Finding
from tacoguard.web import server
from test_web import FAKE_DEFENDER, Client, _missing_module

NO_WINDOW = 0x08000000
SLEEPER = "import time\nwhile True: time.sleep(0.2)"
# a fake guard: exits when the stop file (argv[1]) appears, else sleeps
POLITE = ("import os, sys, time\nstop = sys.argv[1]\n"
          "while not os.path.exists(stop): time.sleep(0.05)\n")


def _wait(cond, timeout=10.0, step=0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


@pytest.fixture
def live(settings, monkeypatch):
    cfa = {"state": "on", "value": 1, "message": defender.CFA_STATES[1][1]}
    monkeypatch.setattr(defender, "peek", lambda: dict(FAKE_DEFENDER, cfa=cfa))
    monkeypatch.setattr(setup_fetch, "fetch_all", lambda s, progress=print: {})
    for name in ("_load_updater_module", "_load_selfupdate", "_load_signed"):
        monkeypatch.setattr(server, name, _missing_module)
    app = server.App(settings)
    srv = server.make_server(app, port=0)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    c = Client(app, app.port)
    c.thread, c.srv = t, srv
    yield c
    srv.shutdown()
    srv.server_close()
    t.join(5)
    app.close()


def _fast(sup, **kw):
    sup.poll_s, sup.stop_wait = 0.05, kw.get("stop_wait", 3.0)
    sup.backoff = kw.get("backoff", sup.backoff)


def _guard_state(store, pid, heartbeat=None, parts=None):
    st = {"pid": pid, "started": time.time() - 60, "heartbeat": heartbeat or time.time(), "version": "0.3.0",
          "parts": parts or {}}
    store.set_meta("guard_state", json.dumps(st))


ALL_ON = {
    "folders": {"state": "on", "message": "", "checked": 12,
                "watched": [r"C:\Users\me\Downloads", r"D:\Downloads", r"C:\Users\me\Desktop",
                            r"C:\Users\me\Documents", r"C:\Users\me\AppData\Roaming\Startup"]},
    "processes": {"state": "on", "message": "", "checked": 40},
    "ransomware": {"state": "on", "message": "", "watched": ["a", "b", "c", "d"]},
    "persistence": {"state": "on", "message": "", "checked": 120},
}

ML = {"engine": "ml", "rule": "TacoGuard ML model", "confidence": 2, "source": "TacoGuard's own model",
      "detail": "machine-learning score 0.97 (suspicious at 0.65 or more)"}
YARA = {"engine": "yara", "rule": "Generic_Stealer_Strings", "confidence": 3, "source": "open rule set"}


# ---------------------------------------------------------------------------------------------
# security: the new routes sit behind the same checks
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("method,path", [("GET", "/api/protection"), ("POST", "/api/protection/event"),
                                         ("POST", "/api/protection/paused"), ("POST", "/api/protection/startup")])
def test_protection_routes_need_the_token_and_same_origin(live, method, path):
    body = {"id": 1, "action": "dismiss"}
    assert live.raw(method, path, body if method == "POST" else None, token=False)[0] == 403
    assert live.raw(method, path, body if method == "POST" else None, token="wrong")[0] == 403
    if method == "POST":
        assert live.post(path, body, headers={"Origin": "http://evil.example"})[0] == 403
        assert live.post(path, body, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403


def test_other_windows_user_is_refused(live, monkeypatch):
    monkeypatch.setattr(server, "client_verdict", lambda c, s: server.OTHER)
    status, data = live.get("/api/protection")
    assert status == 403 and "your own" in data["error"]


# ---------------------------------------------------------------------------------------------
# the view
# ---------------------------------------------------------------------------------------------
def test_protection_shape_when_nothing_runs(live):
    status, data = live.get("/api/protection")
    assert status == 200
    assert set(data) >= {"guard", "events", "paused", "startup", "startup_undone", "attention", "counts", "cfa",
                         "autostart"}
    g = data["guard"]
    assert g["alive"] is False and g["state"] == "off" and "not running" in g["summary"]
    assert data["counts"] == {"attention": 0, "malware": 0}
    assert data["cfa"]["state"] == "on" and "decoy files" in data["cfa"]["note"]
    assert "never changes" in data["cfa"]["note"]
    assert data["autostart"]["installed"] is False and data["autostart"]["note"]
    st = live.get("/api/status")[1]
    assert st["protection"]["state"] == "off" and st["protection"]["attention"] == 0


def test_guard_summary_from_its_heartbeat(live):
    store = live.app.store
    _guard_state(store, os.getpid(), parts=ALL_ON)
    g = live.get("/api/protection")[1]["guard"]
    assert g["alive"] is True and g["state"] == "on"
    assert g["summary"] == ("Real-time protection is on: watching 5 folders, new programs, decoys in 4 folders, "
                            "start-up entries.")
    assert [p["name"] for p in g["parts"]] == ["folders", "processes", "ransomware", "persistence"]
    assert len(g["parts"][0]["short_watched"]) == 5 and g["parts"][0]["checked"] == 12
    parts = json.loads(json.dumps(ALL_ON))
    parts["processes"] = {"state": "off", "message": ""}
    parts["persistence"] = {"state": "error", "message": "Windows did not let TacoGuard read the Run keys."}
    _guard_state(store, os.getpid(), parts=parts)
    g = live.get("/api/protection")[1]["guard"]
    assert g["state"] == "warn" and "new programs" not in g["summary"] and "problem" in g["summary"]
    # an old heartbeat or a dead pid: not alive
    _guard_state(store, os.getpid(), heartbeat=time.time() - 120, parts=ALL_ON)
    assert live.get("/api/protection")[1]["guard"]["alive"] is False
    _guard_state(store, 4_000_000_000 // 4 + 3, parts=ALL_ON)
    assert live.get("/api/protection")[1]["guard"]["alive"] is False
    live.app.settings.realtime_enabled = False
    g = live.get("/api/protection")[1]["guard"]
    assert g["state"] == "off" and "Settings" in g["summary"]


def test_events_attention_history_and_dismiss(live):
    store = live.app.store
    info = store.add_guard_event("guard", "info", "Real-time protection started")
    sus = store.add_guard_event("file", "suspicious", "Suspicious: Desktop\\mod-loader.exe",
                                "ML score 0.71, no signature match.", path=r"C:\Users\me\Desktop\mod-loader.exe",
                                sha256="7a" * 32, findings=[dict(ML, detail="machine-learning score 0.71")])
    status, data = live.get("/api/protection")
    assert [e["id"] for e in data["attention"]] == [sus, info]
    e = data["attention"][0]
    assert e["ml_score"] == 0.71 and e["signature_match"] is False and e["short"]
    assert data["counts"]["attention"] == 2 and live.get("/api/status")[1]["protection"]["attention"] == 2
    for bad in ({}, {"id": "1", "action": "dismiss"}, {"id": True, "action": "dismiss"}, {"id": sus},
                {"id": sus, "action": "delete"}):
        assert live.post("/api/protection/event", bad)[0] == 400, bad
    assert live.post("/api/protection/event", {"id": 99999, "action": "dismiss"})[0] == 404
    status, data = live.post("/api/protection/event", {"id": info, "action": "seen"})
    assert status == 200 and store.get_guard_event(info)["state"] == "seen"
    status, data = live.post("/api/protection/event", {"id": sus, "action": "dismiss"})
    assert status == 200 and "history" in data["message"]
    ev = store.get_guard_event(sus)
    assert ev["state"] == "resolved" and ev["action"] == "dismissed"
    data = live.get("/api/protection")[1]
    assert sus not in [e["id"] for e in data["attention"]] and sus in [e["id"] for e in data["events"]]
    # not a file: nothing to trust or quarantine
    status, data = live.post("/api/protection/event", {"id": info, "action": "quarantine"})
    assert status == 400 and "isn't about a file" in data["error"]


def test_newest_100_events_only(live):
    for i in range(130):
        live.app.store.add_guard_event("file", "info", f"note {i}")
    data = live.get("/api/protection")[1]
    assert len(data["events"]) == 100 and data["events"][0]["title"] == "note 129"


def test_file_alert_trust_and_quarantine(live, tmp_path):
    store = live.app.store
    bad = tmp_path / "Downloads" / "free-vbucks.exe"
    bad.parent.mkdir()
    bad.write_bytes(b"harmless test file " * 10)
    eid = store.add_guard_event("file", "malware", "Quarantine suggested: Downloads\\free-vbucks.exe",
                                "Matched YARA rule 'Generic_Stealer_Strings'.", path=str(bad),
                                findings=[YARA, ML])
    status, data = live.post("/api/protection/event", {"id": eid, "action": "quarantine"})
    assert status == 200, data
    assert data["message"] == (f"Quarantined: {server._short(str(bad))}. Matched YARA rule 'Generic_Stealer_Strings' "
                               "(open rule set, high confidence) and the ML score was 0.97. Restore it only if "
                               "you're sure it's safe.")
    assert not bad.exists()
    q = store.get_quarantine(data["quarantine_id"])
    assert q["state"] == "quarantined" and q["findings"][0]["rule"] == "Generic_Stealer_Strings"
    ev = store.get_guard_event(eid)
    assert (ev["state"], ev["action"]) == ("resolved", "quarantined")
    assert live.post("/api/protection/event", {"id": eid, "action": "quarantine"})[0] == 409

    sus = store.add_guard_event("file", "suspicious", "Suspicious: Desktop\\mod-loader.exe", "ML score 0.71.",
                                path=str(tmp_path / "mod-loader.exe"), sha256="AB" * 32, findings=[ML])
    status, data = live.post("/api/protection/event", {"id": sus, "action": "trust"})
    assert status == 200 and data["message"].startswith("Trusted:")
    assert ("ab" * 32) in store.allowed_hashes()
    assert store.list_verdicts()[0]["verdict"] == "not_a_threat"
    assert store.get_guard_event(sus)["action"] == "trusted"
    assert live.post("/api/protection/event", {"id": sus, "action": "trust"})[0] == 409
    nohash = store.add_guard_event("file", "suspicious", "x", path=str(tmp_path / "y.exe"))
    status, data = live.post("/api/protection/event", {"id": nohash, "action": "trust"})
    assert status == 400 and "fingerprint" in data["error"]


# ---------------------------------------------------------------------------------------------
# paused programs
# ---------------------------------------------------------------------------------------------
class FakeProc:
    def __init__(self):
        self.alive, self.calls, self.fail = {}, [], None

    def install(self, monkeypatch):
        monkeypatch.setattr(procctl, "is_alive", lambda ref: self.alive.get(ref.pid, False))

        def resume(ref):
            self.calls.append(("resume", ref.pid))
            if self.fail:
                raise procctl.ProcError(self.fail)

        def terminate(ref, own=None, wait_s=5.0):
            self.calls.append(("terminate", ref.pid))
            if self.fail:
                raise procctl.ProcError(self.fail)
            self.alive[ref.pid] = False
        monkeypatch.setattr(procctl, "resume", resume)
        monkeypatch.setattr(procctl, "terminate", terminate)
        return self


def _paused(store, pid, exe, event_level="malware", event_id=None):
    if event_id is None:
        event_id = store.add_guard_event("process", event_level, f"Paused: {exe} (it looked like malware)",
                                         "Matched YARA rule 'Generic_Stealer_Strings'.", path=exe,
                                         findings=[YARA])
    return store.add_paused(pid, 1234.5, exe, Path(exe).name, "it looked like malware", event_id), event_id


def test_paused_resume_end_quarantine_with_fake_procctl(live, monkeypatch, tmp_path):
    fp = FakeProc().install(monkeypatch)
    store = live.app.store
    exe = tmp_path / "x.exe"
    exe.write_bytes(b"harmless test program")
    p1, e1 = _paused(store, 101, str(exe))
    p2, e2 = _paused(store, 102, str(tmp_path / "y.exe"))
    p3, e3 = _paused(store, 103, str(tmp_path / "gone.exe"))
    fp.alive.update({101: True, 102: True})
    data = live.get("/api/protection")[1]
    assert [p["id"] for p in data["paused"]] == [p2, p1]                 # 103 closed: marked gone
    assert store.get_paused(p3)["state"] == "gone"
    assert data["paused"][0]["event"]["level"] == "malware" and data["paused"][0]["alive"] is True
    assert e3 in [e["id"] for e in data["attention"]] and e1 not in [e["id"] for e in data["attention"]]
    assert data["counts"] == {"attention": 3, "malware": 3}

    for bad in ({"id": p1}, {"id": p1, "action": "kill"}, {"id": 0, "action": "resume"}):
        assert live.post("/api/protection/paused", bad)[0] == 400
    assert live.post("/api/protection/paused", {"id": 999, "action": "resume"})[0] == 404

    status, data = live.post("/api/protection/paused", {"id": p2, "action": "resume"})
    assert status == 200 and data["message"].startswith("Resumed:")
    assert store.get_paused(p2)["state"] == "resumed"
    assert (store.get_guard_event(e2)["state"], store.get_guard_event(e2)["action"]) == ("resolved", "resumed")
    assert live.post("/api/protection/paused", {"id": p2, "action": "end"})[0] == 409      # not paused now

    status, data = live.post("/api/protection/paused", {"id": p1, "action": "quarantine"})
    assert status == 200, data
    assert ("terminate", 101) in fp.calls and not exe.exists()
    assert data["message"].startswith("Quarantined:") and "Restore it only if" in data["message"]
    assert store.get_paused(p1)["state"] == "ended" and store.get_guard_event(e1)["action"] == "quarantined"


def test_paused_end_and_errors_are_plain(live, monkeypatch, tmp_path):
    fp = FakeProc().install(monkeypatch)
    store = live.app.store
    p1, e1 = _paused(store, 201, str(tmp_path / "a.exe"))
    fp.alive[201] = True
    fp.fail = "TacoGuard does not end this program: it is part of Windows."
    status, data = live.post("/api/protection/paused", {"id": p1, "action": "end"})
    assert status == 409 and data["error"] == fp.fail and store.get_paused(p1)["state"] == "paused"
    fp.fail = None
    status, data = live.post("/api/protection/paused", {"id": p1, "action": "end"})
    assert status == 200 and data["message"].startswith("Ended:") and store.get_guard_event(e1)["action"] == "ended"
    # quarantine of a missing file after ending: the program is ended, the event stays open
    p2, e2 = _paused(store, 202, str(tmp_path / "missing.exe"))
    fp.alive[202] = True
    status, data = live.post("/api/protection/paused", {"id": p2, "action": "quarantine"})
    assert status in (400, 404) and "WinError" not in data["error"] and "Traceback" not in data["error"]
    assert store.get_paused(p2)["state"] == "ended" and store.get_guard_event(e2)["state"] == "new"
    # resume of a program that closed in the meantime
    p3, _ = _paused(store, 203, str(tmp_path / "b.exe"))
    fp.fail = procctl.GONE
    status, data = live.post("/api/protection/paused", {"id": p3, "action": "resume"})
    assert status == 409 and data["error"] == procctl.GONE and store.get_paused(p3)["state"] == "gone"


def test_two_programs_paused_by_one_alarm(live, monkeypatch):
    fp = FakeProc().install(monkeypatch)
    store = live.app.store
    eid = store.add_guard_event("ransomware", "warning",
                                "Possible ransomware: a decoy file in Documents was changed. Paused 2 programs.")
    p1, _ = _paused(store, 301, r"C:\x\one.exe", event_id=eid)
    p2, _ = _paused(store, 302, r"C:\x\two.exe", event_id=eid)
    fp.alive.update({301: True, 302: True})
    data = live.get("/api/protection")[1]
    assert data["paused"][0]["event"]["title"].startswith("Possible ransomware") and data["attention"] == []
    live.post("/api/protection/paused", {"id": p1, "action": "resume"})
    assert store.get_guard_event(eid)["state"] == "new"                  # one is still paused
    live.post("/api/protection/paused", {"id": p2, "action": "end"})
    assert store.get_guard_event(eid)["state"] == "resolved"


def test_real_pause_then_resume_from_the_page(live):
    """A harmless child this test starts is paused with procctl (own=set()), then resumed by the page."""
    child = subprocess.Popen([sys.executable, "-c", SLEEPER], creationflags=NO_WINDOW)
    try:
        ref = None
        assert _wait(lambda: procctl.ref_of(child.pid) is not None)
        ref = procctl.ref_of(child.pid)
        procctl.suspend(ref, own=set())
        assert _wait(lambda: procctl.is_suspended(ref), 5)
        store = live.app.store
        pid_row = store.add_paused(ref.pid, ref.create_time, sys.executable, "python.exe", "test", 0)
        assert [p["id"] for p in live.get("/api/protection")[1]["paused"]] == [pid_row]
        status, data = live.post("/api/protection/paused", {"id": pid_row, "action": "resume"})
        assert status == 200, data
        assert _wait(lambda: not procctl.is_suspended(ref), 5) and procctl.is_alive(ref)
    finally:
        child.kill()
        child.wait(5)


# ---------------------------------------------------------------------------------------------
# start-up entries (guard/persistence.py is faked: no registry change)
# ---------------------------------------------------------------------------------------------
class FakeWatcher:
    made = []

    def __init__(self, settings, store, checker=None):
        self.store, self.checker = store, checker
        FakeWatcher.made.append(self)

    def keep(self, key):
        self.store.put_persistence(key, state="kept")

    def undo(self, key):
        if key.startswith("run:HKLM"):
            raise ValueError("This entry needs administrator rights to change: open Task Manager > Startup apps.")
        self.store.put_persistence(key, state="undone", backup='{"value": "x"}')
        return "Undone: 'Updater' won't start with Windows any more. TacoGuard kept a copy."

    def restore(self, key):
        self.store.put_persistence(key, state="kept", backup="")
        return ""


def test_startup_keep_undo_restore(live, monkeypatch):
    FakeWatcher.made = []
    monkeypatch.setattr(server, "_load_persistence", lambda: SimpleNamespace(PersistenceWatcher=FakeWatcher))
    store = live.app.store
    k1, k2 = r"run:HKCU:Software\Microsoft\Windows\CurrentVersion\Run:Updater", r"run:HKLM:Software\X\Run:Tool"
    e1 = store.add_guard_event("persistence", "warning", "New start-up entry: 'Updater' runs C:\\x\\upd.exe")
    store.put_persistence(k1, source="run", location="Your Run key", name="Updater", command=r"C:\x\upd.exe",
                          target=r"C:\x\upd.exe", state="new", event_id=e1)
    store.put_persistence(k2, source="run", location="All users' Run key", name="Tool", command="tool.exe",
                          state="new")
    data = live.get("/api/protection")[1]
    assert {s["key"] for s in data["startup"]} == {k1, k2} and data["attention"] == []
    assert data["startup"][0]["event"] is None or data["startup"][0]["event"]["id"] == e1
    for bad in ({"key": k1}, {"key": 5, "action": "keep"}, {"key": "", "action": "keep"},
                {"key": k1, "action": "delete"}):
        assert live.post("/api/protection/startup", bad)[0] == 400, bad
    assert live.post("/api/protection/startup", {"key": "nope", "action": "keep"})[0] == 404
    status, data = live.post("/api/protection/startup", {"key": k2, "action": "undo"})
    assert status == 400 and "administrator" in data["error"] and "Task Manager" in data["error"]
    status, data = live.post("/api/protection/startup", {"key": k1, "action": "undo"})
    assert status == 200 and data["message"].startswith("Undone:")
    assert store.get_guard_event(e1)["action"] == "undone"
    data = live.get("/api/protection")[1]
    assert [s["key"] for s in data["startup_undone"]] == [k1]
    assert live.post("/api/protection/startup", {"key": k1, "action": "keep"})[0] == 409
    status, data = live.post("/api/protection/startup", {"key": k1, "action": "restore"})
    assert status == 200 and data["message"] == "Put back: 'Updater' starts with Windows again."
    status, data = live.post("/api/protection/startup", {"key": k2, "action": "keep"})
    assert status == 200 and store.get_persistence(k2)["state"] == "kept"
    assert all(w.checker is None for w in FakeWatcher.made)


def test_startup_actions_without_the_module_are_calm(live):
    live.app.store.put_persistence("run:HKCU:x:Y", source="run", name="Y", state="new")
    # the real module may not exist yet (written in parallel); force "missing"
    import tacoguard.web.server as srv
    orig = srv._load_persistence
    srv._load_persistence = _missing_module
    try:
        status, data = live.post("/api/protection/startup", {"key": "run:HKCU:x:Y", "action": "keep"})
    finally:
        srv._load_persistence = orig
    assert status == 503 and data["error"] == server.PERSISTENCE_NOT_READY


# ---------------------------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------------------------
def test_phase3_settings_round_trip_and_validation(live, settings, tmp_path):
    status, data = live.get("/api/settings")
    assert status == 200
    for k in server.PHASE3_SWITCHES:
        assert data[k] is True, k
    assert data["watch_folders"] == [] and data["canary_folders"] == []
    assert data["realtime_max_file_size"] == 256 * 1024**2
    assert set(data["realtime_defaults"]) == {"watch_folders", "canary_folders"}
    a, b = tmp_path / "Games", tmp_path / "Work"
    a.mkdir(), b.mkdir()
    body = {"watch_processes": False, "ransomware_pause": False, "watch_folders": [str(a), str(b), str(a)],
            "canary_folders": [str(b)], "realtime_max_file_size": 64 * 1024**2,
            "realtime_clamav_second_opinion": False}
    status, data = live.post("/api/settings", body)
    assert status == 200, data
    assert "within a few seconds" in data["message"]
    saved = json.loads(settings.settings_path.read_text(encoding="utf-8"))
    assert saved["watch_folders"] == [str(a), str(b)] and saved["canary_folders"] == [str(b)]
    assert saved["watch_processes"] is False and saved["realtime_max_file_size"] == 64 * 1024**2
    assert live.app.settings.watch_folders == [str(a), str(b)]
    f = tmp_path / "file.txt"
    f.write_text("x")
    for bad in ({"realtime_enabled": "yes"}, {"ransomware_guard": 1}, {"watch_folders": str(a)},
                {"watch_folders": [str(tmp_path / "missing")]}, {"watch_folders": [str(f)]},
                {"watch_folders": [5]}, {"watch_folders": [str(a)] * 51}, {"canary_folders": ["C:\\"]},
                {"realtime_max_file_size": 1000}, {"realtime_max_file_size": 5 * 1024**3},
                {"realtime_max_file_size": True}, {"realtime_max_file_size": 1024**2 + 0.5},
                {"guard_dir": "x"}):
        status, data = live.post("/api/settings", bad)
        assert status == 400 and data["error"], bad
    assert "not found" in live.post("/api/settings", {"watch_folders": [str(tmp_path / "nope")]})[1]["error"]
    status, data = live.post("/api/settings", {"watch_folders": []})            # back to the defaults
    assert status == 200 and live.app.settings.watch_folders == []


def test_canary_folders_never_in_onedrive(live, tmp_path, monkeypatch):
    od = tmp_path / "OneDrive"
    (od / "Documents").mkdir(parents=True)
    monkeypatch.setenv("OneDrive", str(od))
    status, data = live.post("/api/settings", {"canary_folders": [str(od / "Documents")]})
    assert status == 400 and "OneDrive" in data["error"]
    assert live.post("/api/settings", {"watch_folders": [str(od / "Documents")]})[0] == 200   # watching is fine
    defaults = live.get("/api/settings")[1]["realtime_defaults"]["canary_folders"]
    assert not any(str(od).lower() in p.lower() for p in defaults)


@pytest.fixture
def run_key():
    base = rf"Software\TacoGuardTest\{uuid.uuid4().hex}"
    yield base + r"\Run"
    from test_autostart import _delete_tree
    _delete_tree(base)


def test_start_at_sign_in_from_settings_uses_the_installed_copy(live, run_key, tmp_path, monkeypatch):
    root = tmp_path / "Programs" / "TacoGuard"
    (root / "venv" / "Scripts").mkdir(parents=True)
    (root / "venv" / "Scripts" / "pythonw.exe").write_bytes(b"")
    (root / "TacoGuard.pyw").write_text("#", encoding="utf-8")
    (root / "current.json").write_text('{"version": "0.3.0"}', encoding="utf-8")
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(root))
    live.app.autostart_key = run_key
    status, data = live.post("/api/settings", {"start_at_sign_in": False})
    assert status == 200 and autostart.OFF_MSG in data["message"]
    status, data = live.post("/api/settings", {"start_at_sign_in": True})
    assert status == 200 and autostart.ON_MSG in data["message"]
    assert autostart.enabled(run_key)
    assert str(root / "TacoGuard.pyw") in autostart.status(run_key)["command"]
    assert live.get("/api/protection")[1]["autostart"]["enabled"] is True
    status, data = live.post("/api/settings", {"start_at_sign_in": False})
    assert not autostart.enabled(run_key)
    # no installed copy: saved, with a plain note, nothing registered
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(tmp_path / "none"))
    status, data = live.post("/api/settings", {"start_at_sign_in": True})
    assert status == 200 and "installed copy" in data["message"] and not autostart.enabled(run_key)


def test_settings_page_never_touches_the_real_run_key(live, tmp_path, monkeypatch):
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(tmp_path / "none"))
    before = autostart.enabled()
    live.post("/api/settings", {"start_at_sign_in": False})
    live.post("/api/settings", {"start_at_sign_in": True})
    assert autostart.enabled() == before


# ---------------------------------------------------------------------------------------------
# guard supervision (fake guard commands only)
# ---------------------------------------------------------------------------------------------
def _cmd(code, *extra):
    return lambda settings, parent: [sys.executable, "-c", code, *extra, "tacoguard.guard", "--parent", str(parent)]


def test_realtime_switch_starts_and_stops_the_guard(live, settings):
    app = live.app
    sup = app.guard
    _fast(sup)
    stop_file = str(settings.guard_dir / "stop")
    sup.command = _cmd(POLITE, stop_file)
    app.start_guard()
    assert _wait(lambda: sup.running)
    first = sup.proc
    assert sup.pid() == first.pid and sup.starts == 1
    assert live.get("/api/protection")[1]["guard"]["state"] == "starting"        # no heartbeat yet
    status, data = live.post("/api/settings", {"realtime_enabled": False})
    assert status == 200 and "off" in data["message"]
    assert _wait(lambda: first.poll() is not None, 5) and first.returncode == 0   # it saw the stop file
    assert _wait(lambda: not os.path.exists(stop_file), 5) and not sup.running
    status, data = live.post("/api/settings", {"realtime_enabled": True})
    assert "on" in data["message"]
    assert _wait(lambda: sup.running) and sup.proc.pid != first.pid and sup.starts == 2
    second = sup.proc
    app.close()
    assert second.poll() is not None and sup.crashes == []


def test_a_guard_that_ignores_stop_is_ended(live):
    sup = live.app.guard
    _fast(sup, stop_wait=0.5)
    sup.command = _cmd(SLEEPER)
    live.app.start_guard()
    assert _wait(lambda: sup.running)
    proc = sup.proc
    t0 = time.time()
    sup.close()
    assert proc.poll() is not None and time.time() - t0 < 6


def test_crash_backoff_then_give_up(live, settings):
    sup = live.app.guard                      # driven by hand: step() is one look
    sup.command = _cmd("raise SystemExit(3)")
    waits = []
    for n in range(1, 6):
        sup.step()
        assert sup.proc is not None
        sup.proc.wait(10)
        before = time.time()
        sup.step()                            # sees the crash
        if n < 5:
            waits.append(round(sup.next_start - before))
            assert "starts it again" in sup.message
            sup.next_start = 0                # don't wait in the test
    assert waits == [5, 30, 120, 120]
    assert sup.gave_up and sup.starts == 5 and "5 times in 10 minutes" in sup.message
    sup.step()
    assert sup.proc is None and sup.starts == 5                     # no more tries
    g = live.get("/api/protection")[1]["guard"]
    assert g["state"] == "error" and "stopped restarting" in g["summary"]
    # switching it off and on in Settings tries again
    settings.realtime_enabled = False
    sup.step()
    assert not sup.gave_up and sup.crashes == []
    settings.realtime_enabled = True
    sup.command = _cmd(SLEEPER)
    sup.step()
    assert sup.running
    sup.close()


def test_recycle_exit_restarts_at_once_and_is_not_a_crash(live):
    sup = live.app.guard
    sup.command = _cmd(f"raise SystemExit({server.GUARD_EXIT_RECYCLE})")
    sup.step()
    sup.proc.wait(10)
    sup.step()                                # sees exit 75: no crash, no wait
    assert sup.crashes == [] and not sup.gave_up and sup.next_start == 0.0
    sup.command = _cmd(SLEEPER)
    sup.step()
    assert sup.running and sup.starts == 2
    sup.close()


def test_old_crashes_fall_out_of_the_window(live):
    sup = live.app.guard
    sup.crashes = [time.time() - 700] * 4
    sup._crashed(1)
    assert not sup.gave_up and sup.crashes and len(sup.crashes) == 1 and "5 seconds" in sup.message


def test_adopts_a_guard_that_already_runs(live):
    store, sup = live.app.store, live.app.guard
    other = subprocess.Popen([sys.executable, "-c", SLEEPER, "tacoguard.guard"], creationflags=NO_WINDOW)
    try:
        _guard_state(store, other.pid)
        sup.command = lambda s, p: pytest.fail("must not start a second guard")
        sup.step()
        assert sup.adopted is not None and sup.adopted.pid == other.pid and sup.proc is None
        assert sup.pid() == other.pid
        sup.step()                                              # still running: nothing to do
        assert sup.proc is None
        other.kill()
        other.wait(5)
        sup.command = _cmd(SLEEPER)
        sup.step()                                              # it went away: start our own
        assert sup.adopted is None and sup.running and sup.crashes == []
    finally:
        if other.poll() is None:
            other.kill()
        sup.close()


def test_stale_heartbeat_or_other_program_is_not_adopted(live):
    store, sup = live.app.store, live.app.guard
    other = subprocess.Popen([sys.executable, "-c", SLEEPER, "tacoguard.guard"], creationflags=NO_WINDOW)
    plain = subprocess.Popen([sys.executable, "-c", SLEEPER], creationflags=NO_WINDOW)
    try:
        _guard_state(store, other.pid, heartbeat=time.time() - 300)
        assert sup._find_running_guard() is None
        _guard_state(store, plain.pid)                          # a reused pid: not a guard
        assert sup._find_running_guard() is None
        _guard_state(store, other.pid)
        assert sup._find_running_guard().pid == other.pid
    finally:
        other.kill()
        plain.kill()


def test_guard_missing_from_this_copy_is_calm(live):
    sup = live.app.guard
    sup.command = lambda s, p: None
    live.app.manage_guard = True
    sup.step()
    assert sup.unavailable and sup.proc is None
    g = live.get("/api/protection")[1]["guard"]
    assert g["state"] == "unavailable" and g["summary"] == server.GUARD_NOT_READY


def test_guard_command_shape(settings):
    cmd = server.guard_command(settings, 1234)
    if cmd is not None:                       # guard/__main__.py exists in this copy
        assert cmd[:4] == [sys.executable, "-m", "tacoguard.guard", "--data"]
        assert cmd[-2:] == ["--parent", "1234"] and str(settings.data_dir) in cmd


def test_app_never_starts_a_guard_by_itself(live):
    assert live.app.manage_guard is False and live.app.guard._thread is None
    live.post("/api/settings", {"realtime_enabled": False})
    live.post("/api/settings", {"realtime_enabled": True})
    assert live.app.guard.proc is None and live.app.guard._thread is None


def test_serve_does_not_start_the_guard_under_pytest(settings, monkeypatch):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    settings.port = s.getsockname()[1]
    s.close()
    monkeypatch.setattr(defender, "peek", lambda: dict(FAKE_DEFENDER))
    for name in ("_load_updater_module", "_load_selfupdate", "_load_signed"):
        monkeypatch.setattr(server, name, _missing_module)
    started = []
    monkeypatch.setattr(server.App, "start_guard", lambda self: started.append(1))
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("rc", server.serve(settings, open_browser=False)), daemon=True)
    t.start()
    assert _wait(lambda: server.is_tacoguard_at(settings.port, timeout=1), 10)
    import http.client
    import re
    con = http.client.HTTPConnection("127.0.0.1", settings.port, timeout=10)
    con.request("GET", "/", headers={"Host": f"127.0.0.1:{settings.port}"})
    token = re.search(r'name="tacoguard-token" content="([^"]+)"', con.getresponse().read().decode()).group(1)
    con.close()
    Client(SimpleNamespace(token=token), settings.port).post("/api/quit")
    t.join(10)
    assert out["rc"] == 0 and started == []


# ---------------------------------------------------------------------------------------------
# Controlled folder access (read only) and the page
# ---------------------------------------------------------------------------------------------
def test_cfa_parse():
    for value, state in ((0, "off"), (1, "on"), (2, "audit"), (3, "block_disk"), (4, "audit_disk")):
        st = defender.parse_status({"pref": {"EnableControlledFolderAccess": value}})
        assert st["cfa"]["state"] == state and st["cfa"]["value"] == value and st["cfa"]["message"]
    for raw in ({}, {"pref_error": "Access denied"}, {"pref": {"EnableControlledFolderAccess": 9}},
                {"pref": {"EnableControlledFolderAccess": True}}, {"pref": "x"}, "garbage"):
        assert defender.parse_status(raw)["cfa"]["state"] == "unknown"
    script = defender._SCRIPT
    assert "MSFT_MpPreference" in script and "EnableControlledFolderAccess" in script
    assert "Set-Mp" not in script and "Add-Mp" not in script and "Remove-Mp" not in script


def test_page_has_the_protection_parts(live):
    html = live.raw("GET", "/", token=False)[2].decode()
    for part in ('data-view="protection"', "badge-protection", "view-protection", "prot-attention",
                 "prot-history", "windowsdefender://ransomwareprotection", "phase3-form", "watch-list",
                 "canary-list", "realtime_enabled", "start_at_sign_in", "realtime_max_file_size"):
        assert part in html, part
    js = live.raw("GET", "/app.js", token=False)[2].decode()
    assert "/api/protection" in js and "visibilityState" in js and "3000" in js and "30000" in js
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js


# ---------------------------------------------------------------------------------------------
# review fixes (2026-11-24)
# ---------------------------------------------------------------------------------------------
def test_trust_and_quarantine_only_for_file_and_program_alerts(live, tmp_path):
    store = live.app.store
    target = tmp_path / "upd.exe"
    target.write_bytes(b"harmless test file " * 10)
    for kind in ("persistence", "ransomware", "guard"):
        eid = store.add_guard_event(kind, "warning", "New start-up entry: 'Updater' runs x", "x",
                                    path=str(target), sha256="ab" * 32, findings=[YARA])
        for action in ("trust", "quarantine"):
            status, data = live.post("/api/protection/event", {"id": eid, "action": action})
            assert status == 400 and "isn't about a file or a program" in data["error"], (kind, action)
        assert live.post("/api/protection/event", {"id": eid, "action": "dismiss"})[0] == 200
    assert target.exists() and ("ab" * 32) not in store.allowed_hashes()


def test_a_hung_guard_is_ended_and_counted_as_a_crash(live):
    import psutil
    sup = live.app.guard
    sup.command = _cmd(SLEEPER)
    sup.hung_s = 5
    sup.step()                                             # starts it
    proc = sup.proc
    assert proc is not None and proc.poll() is None
    # the venv's python.exe is a launcher: the real program is its child
    time.sleep(0.5)
    kids = [c.pid for c in psutil.Process(proc.pid).children(recursive=True)]
    # a fresh heartbeat: all is well
    sup.proc_started = time.time() - 60
    _guard_state(live.app.store, proc.pid)
    sup.step()
    assert sup.proc is proc and proc.poll() is None and sup.crashes == []
    # no heartbeat for longer than hung_s: ended (with its child) and counted
    _guard_state(live.app.store, proc.pid, heartbeat=time.time() - 30)
    sup.step()
    assert sup.proc is None and proc.poll() is not None and len(sup.crashes) == 1
    assert "starts it again" in sup.message
    def running(pid):
        try:
            return psutil.Process(pid).status() != "zombie"
        except psutil.Error:
            return False
    assert _wait(lambda: not any(running(k) for k in kids), 5)
    sup.close()


def test_a_just_started_guard_is_not_called_hung(live):
    sup = live.app.guard
    sup.command = _cmd(SLEEPER)
    sup.hung_s = 5
    sup.step()
    proc = sup.proc
    _guard_state(live.app.store, proc.pid, heartbeat=time.time() - 300)     # the old run's heartbeat
    sup.step()
    assert sup.proc is proc and proc.poll() is None
    sup.close()


def _place_decoys(settings, store, folder):
    from tacoguard.guard import ransom
    folder.mkdir(exist_ok=True)
    settings.canary_folders = [str(folder)]
    return ransom.RansomGuard(settings, store, None).place_decoys()


def test_switching_the_ransomware_guard_off_takes_the_decoys_away(live, settings, tmp_path, monkeypatch):
    from tacoguard.guard import ransom
    store = live.app.store
    placed = _place_decoys(settings, store, tmp_path / "Docs")
    assert placed and all(Path(p).exists() for p in placed)
    # only real-time protection off: the decoys stay for when it comes back
    assert live.post("/api/settings", {"realtime_enabled": False})[0] == 200
    assert all(Path(p).exists() for p in placed)
    # both off together (no guard runs to do it): taken away
    assert live.post("/api/settings", {"realtime_enabled": True})[0] == 200
    status, data = live.post("/api/settings", {"realtime_enabled": False, "ransomware_guard": False})
    assert status == 200, data
    assert not any(Path(p).exists() for p in placed) and not ransom.manifest_path(settings).exists()
    # the ransomware guard alone switched off while no guard runs
    live.post("/api/settings", {"realtime_enabled": True, "ransomware_guard": True})
    placed = _place_decoys(settings, store, tmp_path / "Docs")
    assert live.post("/api/settings", {"ransomware_guard": False})[0] == 200
    assert not any(Path(p).exists() for p in placed)
    # a guard runs with real-time protection on: it removes them itself (the page leaves them)
    live.post("/api/settings", {"ransomware_guard": True})
    placed = _place_decoys(settings, store, tmp_path / "Docs")
    monkeypatch.setattr(live.app, "_guard_alive", lambda: True)
    assert live.post("/api/settings", {"ransomware_guard": False})[0] == 200
    assert all(Path(p).exists() for p in placed)


def test_decoys_are_removed_once_a_stopping_guard_has_ended(live, settings, tmp_path, monkeypatch):
    store = live.app.store
    placed = _place_decoys(settings, store, tmp_path / "Docs")
    alive = {"n": 0}

    def guard_alive():                   # the guard is still stopping for a moment
        alive["n"] += 1
        return alive["n"] < 4
    monkeypatch.setattr(live.app, "_guard_alive", guard_alive)
    status, _ = live.post("/api/settings", {"realtime_enabled": False, "ransomware_guard": False})
    assert status == 200
    t = live.app._decoy_thread
    t.join(10)
    assert not t.is_alive() and alive["n"] >= 4
    assert not any(Path(p).exists() for p in placed)
