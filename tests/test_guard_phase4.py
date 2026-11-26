"""The guard's Phase 4 changes (guard/service.py): the "web" part, "Pause protection", Game mode
(no toasts), the watch over TacoGuard's own things, and starting the page again when it ends
without Quit. Fake parts and an injected launcher only: the real launcher, the real Run key and
the real data folder are never used.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import types

import pytest

from tacoguard import phase4
from tacoguard.guard import service

CHILD_PY = getattr(sys, "_base_executable", None) or sys.executable


class Part:
    made: list = []

    def __init__(self, name="x"):
        self.name = name
        self.started = self.stopped = 0
        Part.made.append(self)

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def status(self):
        return {"state": "on", "message": f"{self.name} on.", "watched": [], "checked": 1}


class FakeFolders(Part):
    def __init__(self):
        super().__init__("folders")
        self.roots = []
        self.queued = []

    def enqueue(self, files):
        self.queued += list(files)


def wait_for(fn, timeout=5.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


def heartbeat(store):
    return json.loads(store.get_meta("guard_state") or "{}")


@pytest.fixture
def fast(monkeypatch):
    for name, value in (("TICK_S", 0.05), ("SETTINGS_CHECK_S", 0.1), ("HEARTBEAT_S", 0.2),
                        ("PARENT_CHECK_S", 0.1), ("NOTIFY_CHECK_S", 0.1), ("RESTART_DELAY_S", 0.1),
                        ("PAUSE_CHECK_S", 0.1), ("OWN_CHECK_S", 0.1)):
        monkeypatch.setattr(service.Guard, name, value)
    Part.made = []
    specs = {name: ((lambda g, n=name: FakeFolders() if n == "folders" else Part(n)), spec[1], spec[2])
             for name, spec in service.PART_SPECS.items()}
    monkeypatch.setattr(service, "PART_SPECS", specs)
    return specs


def _guard(settings, store, **kw):
    for k, v in {"watch_processes": True, "ransomware_guard": True, "persistence_watch": True,
                 "webblock_enabled": True, **kw}.items():
        setattr(settings, k, v)
    settings.save()
    g = service.Guard(settings, store, detectors=[], hub=types.SimpleNamespace(start=lambda: None,
                                                                              stop=lambda: None))
    g.own_watch_factory = lambda guard: types.SimpleNamespace(check=lambda: [])
    return g


# ---- the "web" part ------------------------------------------------------------------------------
def test_web_part_is_registered():
    assert service.PART_NAMES[-1] == "web" and "web" in service.PART_SPECS
    make, enabled, key = service.PART_SPECS["web"]
    assert enabled(types.SimpleNamespace(webblock_enabled=True)) is True
    assert enabled(types.SimpleNamespace(webblock_enabled=False)) is False
    assert key(None) == ()


def test_web_part_factory_uses_webwatcher(settings, store, monkeypatch):
    made = []

    class WebWatcher(Part):
        def __init__(self, s, st, checker=None):
            super().__init__("web")
            made.append((s, st, checker))
    pkg = types.ModuleType("tacoguard.webblock")
    pkg.__path__ = []
    mod = types.ModuleType("tacoguard.webblock.watch")
    mod.WebWatcher = WebWatcher
    monkeypatch.setitem(sys.modules, "tacoguard.webblock", pkg)
    monkeypatch.setitem(sys.modules, "tacoguard.webblock.watch", mod)
    g = types.SimpleNamespace(settings=settings, store=store, checker="the checker")
    inst = service._make_web(g)
    assert isinstance(inst, WebWatcher) and made == [(settings, store, "the checker")]


def test_web_part_missing_module_is_not_a_crash(settings, store, fast, monkeypatch):
    specs = dict(service.PART_SPECS)
    specs["web"] = (service._make_web, specs["web"][1], specs["web"][2])
    monkeypatch.setattr(service, "PART_SPECS", specs)
    monkeypatch.setitem(sys.modules, "tacoguard.webblock.watch", None)       # import fails
    g = _guard(settings, store)
    g.start()
    try:
        hb = heartbeat(store)
        assert set(hb["parts"]) == {"folders", "processes", "ransomware", "persistence", "web"}
        assert hb["parts"]["web"]["state"] == "error"
        assert hb["parts"]["web"]["message"] == service.MISSING_PART_MSG
        assert hb["parts"]["folders"]["state"] == "on"
    finally:
        g.stop()


def test_web_part_follows_its_switch(settings, store, fast):
    g = _guard(settings, store, webblock_enabled=False)
    g.start()
    try:
        assert heartbeat(store)["parts"]["web"] == {"state": "off", "message": service.OFF_MSG,
                                                    "watched": [], "checked": 0}
        settings.webblock_enabled = True              # in place, as a settings reload does
        settings.save()
        assert wait_for(lambda: heartbeat(store)["parts"]["web"]["message"] == "web on.", timeout=5)
        assert g.parts["web"].state == "on"
        settings.webblock_enabled = False
        settings.save()
        assert wait_for(lambda: heartbeat(store)["parts"]["web"]["state"] == "off", timeout=5)
    finally:
        g.stop()


# ---- Pause protection ----------------------------------------------------------------------------
def test_pause_stops_parts_and_resume_starts_them(settings, store, fast, monkeypatch):
    g = _guard(settings, store, persistence_watch=False)
    caught = []
    monkeypatch.setattr(g, "_start_catch_up", lambda since=None: caught.append(since))
    g.start()
    try:
        assert all(g.parts[n].state == "on" for n in ("folders", "processes", "ransomware", "web"))
        first = {n: g.parts[n].inst for n in g.parts}
        until = phase4.pause_protection(store, 600)
        msg = service.paused_message(until)
        assert msg.startswith("Paused until ") and time.strftime("%H:%M", time.localtime(until)) in msg
        assert wait_for(lambda: g.parts["folders"].inst is None, timeout=3)
        hb = wait_for(lambda: (h := heartbeat(store)) and h["parts"]["web"]["state"] == "off" and h)
        for n in ("folders", "processes", "ransomware", "web"):
            assert hb["parts"][n]["state"] == "off" and hb["parts"][n]["message"] == msg
            assert first[n].stopped == 1
        assert hb["parts"]["persistence"]["message"] == service.OFF_MSG     # its own switch is off
        time.sleep(0.3)
        assert g.parts["web"].inst is None                                  # not restarted while paused
        phase4.resume_protection(store)
        assert wait_for(lambda: all(g.parts[n].state == "on" for n in ("folders", "processes", "ransomware", "web")))
        assert g.parts["persistence"].state == "off"
        assert g.parts["folders"].inst is not first["folders"]
        assert caught and caught[-1] > 0                                    # files changed meanwhile are caught up
    finally:
        g.stop()


def test_pause_ends_by_itself(settings, store, fast):
    g = _guard(settings, store)
    g.start()
    try:
        store.set_meta("protection_pause", json.dumps({"until": time.time() + 0.6}))
        assert wait_for(lambda: g.parts["processes"].inst is None, timeout=3)
        assert wait_for(lambda: g.parts["processes"].state == "on", timeout=5)   # the time passed
    finally:
        g.stop()


def test_paused_at_start_starts_no_part(settings, store, fast):
    phase4.pause_protection(store, 3600)
    g = _guard(settings, store)
    g.start()
    try:
        hb = heartbeat(store)
        assert all(p["state"] == "off" for p in hb["parts"].values())
        assert hb["parts"]["folders"]["message"].startswith("Paused until")
        assert Part.made == []
    finally:
        g.stop()


def test_paused_message_tomorrow():
    now = time.time()
    soon = now + 60
    if time.strftime("%d", time.localtime(soon)) == time.strftime("%d", time.localtime(now)):
        assert service.paused_message(soon, now=now) == f"Paused until {time.strftime('%H:%M', time.localtime(soon))}."
    assert service.paused_message(now + 25 * 3600, now=now).endswith("tomorrow.")


# ---- Game mode: no toasts ---------------------------------------------------------------------
def test_no_toasts_in_game_mode(settings, store, fast):
    g = _guard(settings, store)
    shown = []
    g.notify_fn = lambda ev: shown.append(ev["title"])
    g.start()
    try:
        phase4.set_game_mode(store, True, manual=True)
        store.add_guard_event("file", "malware", "During the game")
        time.sleep(0.5)
        assert shown == []
        assert [e["title"] for e in store.list_guard_events()] == ["During the game"]   # still written
        phase4.set_game_mode(store, False, manual=False)
        store.add_guard_event("file", "warning", "After the game")
        assert wait_for(lambda: shown, timeout=3)
        time.sleep(0.3)
        assert shown == ["After the game"]                    # the earlier one is not shown later
    finally:
        g.stop()


# ---- the watch over TacoGuard's own things ----------------------------------------------------
def test_own_watch_runs_in_the_control_loop(settings, store, fast):
    g = _guard(settings, store)
    calls = []
    g.own_watch_factory = lambda guard: types.SimpleNamespace(check=lambda: calls.append(1) or [])
    g.start()
    try:
        assert wait_for(lambda: len(calls) >= 2, timeout=3)
    finally:
        g.stop()
    settings.self_protection = False
    settings.save()
    g2 = _guard(settings, store, self_protection=False)
    g2.own_watch_factory = lambda guard: pytest.fail("no watch when self-protection is off")
    g2.start()
    try:
        assert g2.own_watch is None
    finally:
        g2.stop()


def test_own_watch_default_is_selfprotect(settings, store, fast):
    g = _guard(settings, store)
    g.own_watch_factory = None
    g.start()
    try:
        from tacoguard.selfprotect import OwnWatch
        assert isinstance(g.own_watch, OwnWatch)
        assert g.own_watch.installed is False           # this copy runs from the project folder
    finally:
        g.stop()


# ---- the page process ending without Quit -----------------------------------------------------
def _parent():
    return subprocess.Popen([CHILD_PY, "-c", "import time; time.sleep(60)"], creationflags=0x08000000)


def _run_until_page_gone(settings, store, stop_file_first=False):
    parent = _parent()
    try:
        g = _guard(settings, store)
        g.parent_pid = parent.pid
        launched = []
        g.page_launcher = lambda: launched.append(time.time())
        g.start()
        try:
            assert not g.wait(0.3)
            if stop_file_first:
                g.stop_file.write_text("stop")
                assert g.wait(3)
            parent.kill()
            parent.wait(10)
            assert g.wait(5)
        finally:
            g.stop()
        return g, launched
    finally:
        if parent.poll() is None:
            parent.kill()


def test_page_restarted_once_per_ten_minutes(settings, store, fast):
    g, launched = _run_until_page_gone(settings, store)
    assert g.page_lost and "page" in g.stop_reason
    assert g.restart_page_if_needed() is True
    assert len(launched) == 1
    evs = store.list_guard_events()
    assert [(e["kind"], e["level"], e["title"]) for e in evs] == [("self", "warning", service.PAGE_RESTARTED_TITLE)]
    assert g.restart_page_if_needed() is False                 # only once for this guard
    assert len(launched) == 1
    # the next guard sees its page end too, within 10 minutes: not started again, said so
    g2, launched2 = _run_until_page_gone(settings, store)
    assert g2.restart_page_if_needed() is False
    assert launched2 == []
    assert store.list_guard_events()[0]["title"] == service.PAGE_NOT_RESTARTED_TITLE
    # after the 10 minutes it is started again
    store.set_meta(service.PAGE_RESTART_KEY, str(time.time() - 11 * 60))
    g3, launched3 = _run_until_page_gone(settings, store)
    assert g3.restart_page_if_needed() is True and len(launched3) == 1


def test_no_page_restart_after_quit_or_without_launcher(settings, store, fast):
    g, launched = _run_until_page_gone(settings, store, stop_file_first=True)
    assert not g.page_lost
    assert g.restart_page_if_needed() is False and launched == []
    g2, _ = _run_until_page_gone(settings, store)
    g2.page_launcher = None                                    # the project-folder copy
    assert g2.restart_page_if_needed() is False
    assert store.list_guard_events() == []


def test_page_restart_failure_is_reported(settings, store, fast):
    g, _ = _run_until_page_gone(settings, store)

    def broken():
        raise OSError(2, "The system cannot find the file specified")
    assert g.restart_page_if_needed(launcher=broken) is False
    ev = store.list_guard_events()[0]
    assert ev["title"] == service.PAGE_NOT_RESTARTED_TITLE and "could not start it again" in ev["message"]


def test_main_never_restarts_the_page_from_tests(settings):
    assert service.page_launcher_for(settings) is None
