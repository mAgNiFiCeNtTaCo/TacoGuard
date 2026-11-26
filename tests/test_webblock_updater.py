"""The updater's "web_lists" component and Game mode (tacoguard/updates/updater.py). No network."""
from __future__ import annotations

import time

import pytest

from tacoguard import phase4
from tacoguard import setup_fetch as F
from tacoguard.updates import sources, updater as U


@pytest.fixture
def offline(monkeypatch):
    def no_net(url, headers=None):
        raise F.FetchError("Could not reach the internet. Nothing was changed.", kind="offline")
    monkeypatch.setattr(F, "_open", no_net)


class FakeRefresh:
    def __init__(self, answer=None):
        self.calls = 0
        self.answer = answer or {"ok": True, "changed": True, "message": "The phishing list was updated: "
                                 "60 sites. Add your free abuse.ch key in Settings to use URLhaus.",
                                 "sources": {"phishing": {"state": "ok", "count": 60, "changed": True,
                                                          "message": "..."},
                                             "urlhaus": {"state": "no_key", "count": 0, "changed": False,
                                                         "message": "..."}}}

    def __call__(self, settings, store, progress):
        self.calls += 1
        progress("Downloading the phishing list...")
        return self.answer


def make(settings, store, tmp_path, refresh):
    up = U.Updater(settings, store, source=sources.LocalFolderSource(tmp_path / "no-release"))
    up.ml_self_test = lambda folder: None
    up.web_lists_refresh = refresh
    return up


def test_web_lists_component(settings, store, tmp_path, offline):
    fake = FakeRefresh()
    up = make(settings, store, tmp_path, fake)
    up.check_now(wait=True)
    c = up.status()["components"]["web_lists"]
    assert fake.calls == 1
    assert c["state"] == "ok" and c["version"] == "60 sites" and c["updated"] > 0 and c["last_error"] == ""
    assert "Add your free abuse.ch key" in c["message"]
    assert "web_lists: Downloading the phishing list..." in (settings.root / "logs" / "updates.log").read_text()


@pytest.mark.parametrize("states, ok, want", [
    ({"phishing": "offline", "urlhaus": "no_key"}, True, "offline"),
    ({"phishing": "offline", "urlhaus": "offline"}, True, "offline"),
    ({"phishing": "refused", "urlhaus": "ok"}, False, "error"),
    ({"phishing": "off", "urlhaus": "no_key"}, True, "off"),
])
def test_web_lists_states(settings, store, tmp_path, offline, states, ok, want):
    answer = {"ok": ok, "changed": False, "message": "words",
              "sources": {k: {"state": v, "count": 0, "changed": False, "message": ""} for k, v in states.items()}}
    up = make(settings, store, tmp_path, FakeRefresh(answer))
    up.check_now(wait=True)
    c = up.status()["components"]["web_lists"]
    assert c["state"] == want and c["message"] == "words"
    assert (c["last_error"] == "words") == (want == "error")


def test_web_lists_off_and_a_crash_is_contained(settings, store, tmp_path, offline):
    settings.webblock_enabled = False
    fake = FakeRefresh()
    up = make(settings, store, tmp_path, fake)
    up.check_now(wait=True)
    assert up.status()["components"]["web_lists"]["state"] == "off" and fake.calls == 0
    settings.webblock_enabled = True

    def broken(settings, store, progress):
        raise RuntimeError("boom")
    up.web_lists_refresh = broken
    up.check_now(wait=True)
    c = up.status()["components"]["web_lists"]
    assert c["state"] == "error" and "boom" not in c["message"]
    assert up.status()["components"]["clamav_signatures"]["state"] != "checking"


def test_default_refresh_runs_without_network(settings, store, tmp_path, offline):
    up = U.Updater(settings, store, source=sources.LocalFolderSource(tmp_path / "no-release"))
    up.ml_self_test = lambda folder: None
    up.check_now(wait=True)                  # the real lists.refresh: offline in tests
    c = up.status()["components"]["web_lists"]
    assert c["state"] == "offline" and "No internet" in c["message"]


def test_game_mode_deferral_logs_once_and_gives_up_after_24_hours(settings, store, tmp_path, monkeypatch):
    lines = []
    monkeypatch.setattr(U, "log", lambda s, msg: lines.append(msg))
    up = make(settings, store, tmp_path, FakeRefresh())
    phase4.set_game_mode(store, False, manual=False, reason="")
    assert up._defer_for_game_mode() is False and lines == []
    phase4.set_game_mode(store, True, manual=False, reason="a full-screen game")
    for _ in range(30):                                       # half an hour of minute-by-minute looks
        assert up._defer_for_game_mode() is True
    assert lines == ["Game mode is on: the timed update check waits until it ends"]   # logged once
    up._game_deferred_since -= U.GAME_MODE_MAX_DEFER_S          # a whole day of Game mode
    assert up._defer_for_game_mode() is False                   # the check runs anyway
    assert "24 hours" in lines[-1]
    assert up._defer_for_game_mode() is True                    # the next wait starts again
    phase4.set_game_mode(store, False, manual=False)
    assert up._defer_for_game_mode() is False and lines[-1].startswith("Game mode ended")


def test_game_mode_skips_timed_checks_but_not_check_now(settings, store, tmp_path, offline, monkeypatch):
    monkeypatch.setattr(U, "GAME_MODE_RETRY_S", 0.3)
    phase4.set_game_mode(store, True, manual=True, reason="test")
    fake = FakeRefresh()
    up = make(settings, store, tmp_path, fake)
    up.start(on_start=True)
    try:
        time.sleep(1.0)
        st = up.status()
        assert fake.calls == 0 and st["last_check"] == 0          # the timed check waits
        assert 0 < st["next_check"] <= time.time() + 1
        up.check_now(wait=True)                                    # a manual check still runs
        assert fake.calls == 1
        first = up.status()["last_check"]
        # the timed check is due again (the manual one moved it 4 h on): pretend it is due now
        with up._lock:
            up._status["next_check"] = time.time()
        up._wake.set()
        time.sleep(1.0)
        assert fake.calls == 1                                     # still Game mode: skipped
        phase4.set_game_mode(store, False, manual=False)
        deadline = time.time() + 10
        while fake.calls < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert fake.calls == 2 and up.status()["last_check"] > first   # ran once Game mode ended
    finally:
        up.stop()
