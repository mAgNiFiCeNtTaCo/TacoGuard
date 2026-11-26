"""Game mode (tacoguard/gamemode.py): Windows' answer -> (active, reason), and who wins between the
automatic switch and yours. A fake detector and a fake clock; the store is a temp one."""
from __future__ import annotations

import time

import pytest

from tacoguard import gamemode, phase4


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, s):
        self.t += s


class Screen:
    """What the fake 'Windows' says is in front."""

    def __init__(self):
        self.state = (False, "")
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.state

    def game(self):
        self.state = (True, "a full-screen game")

    def slides(self):
        self.state = (True, "presentation mode")

    def desktop(self):
        self.state = (False, "")


@pytest.fixture
def w(settings, store):
    clock, screen = Clock(), Screen()
    watcher = gamemode.GameModeWatcher(settings, store, detector=screen, clock=clock)
    watcher.clock_, watcher.screen = clock, screen
    return watcher


def gm(store):
    return phase4.game_mode(store)


# ---------------------------------------------------------------------------------------------
# detect()
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("state,expected", [
    (gamemode.QUNS_RUNNING_D3D_FULL_SCREEN, (True, "a full-screen game")),
    (gamemode.QUNS_PRESENTATION_MODE, (True, "presentation mode")),
    (gamemode.QUNS_BUSY, (True, "a full-screen program")),
    (gamemode.QUNS_ACCEPTS_NOTIFICATIONS, (False, "")),
    (gamemode.QUNS_NOT_PRESENT, (False, "")),
    (gamemode.QUNS_QUIET_TIME, (False, "")),
    (gamemode.QUNS_APP, (False, "")),
    (None, (False, "")),
])
def test_detect_maps_windows_answers(state, expected):
    assert gamemode.detect(query=lambda: state) == expected


def test_real_query_answers_without_error():
    st = gamemode.query_state()
    assert st is None or isinstance(st, int)
    active, reason = gamemode.detect()
    assert isinstance(active, bool) and isinstance(reason, str)


# ---------------------------------------------------------------------------------------------
# automatic Game mode
# ---------------------------------------------------------------------------------------------
def test_auto_on_with_the_reason_and_kept(w, store):
    assert w.step() == "idle" and not gm(store)["active"]
    w.screen.game()
    assert w.step() == "on"
    g = gm(store)
    assert g["active"] and not g["manual"] and g["reason"] == "a full-screen game" and g["since"]
    since = g["since"]
    w.clock_.tick(10)
    assert w.step() == "kept" and gm(store)["since"] == since
    w.screen.slides()                       # the reason changes: written, "since" kept
    assert w.step() == "on"
    assert gm(store)["reason"] == "presentation mode" and gm(store)["since"] == since


def test_auto_ends_30_seconds_after_the_game(w, store):
    w.screen.game()
    w.step()
    w.screen.desktop()                      # alt-tab out for a moment
    w.clock_.tick(10)
    assert w.step() == "tail" and gm(store)["active"]
    w.clock_.tick(10)
    w.screen.game()                         # back in: the tail starts again later
    assert w.step() == "kept"
    w.screen.desktop()
    w.clock_.tick(29)
    assert w.step() == "tail" and gm(store)["active"]
    w.clock_.tick(1)
    assert w.step() == "off"
    g = gm(store)
    assert not g["active"] and not g["manual"] and g["since"] == 0


def test_manual_on_wins_until_you_turn_it_off(w, store):
    g = w.user_switch(True)
    assert g["active"] and g["manual"] and g["reason"] == gamemode.MANUAL_REASON
    assert w.step() == "manual"
    w.screen.game()
    assert w.step() == "manual" and gm(store)["manual"]
    w.screen.desktop()
    w.clock_.tick(3600)
    assert w.step() == "manual" and gm(store)["active"]          # never ended by the tail
    g = w.user_switch(False)
    assert not g["active"]
    assert gamemode.respect_until(store) == 0                     # nothing was running: no respect
    w.screen.game()
    assert w.step() == "on"                                       # a later game: automatic again


def test_manual_off_during_a_game_is_respected_for_2_hours(w, store):
    w.screen.game()
    assert w.step() == "on"
    w.clock_.tick(60)
    w.user_switch(False)
    assert not gm(store)["active"]
    assert gamemode.respect_until(store) == pytest.approx(w.clock_.t + gamemode.RESPECT_S)
    for _ in range(5):
        w.clock_.tick(600)
        assert w.step() == "respect" and not gm(store)["active"]
    w.clock_.tick(gamemode.RESPECT_S)                              # 2 hours later: automatic again
    assert w.step() == "on" and gm(store)["active"] and not gm(store)["manual"]


def test_manual_off_while_the_condition_is_seen_is_respected_too(w, store):
    # the user turned off a MANUAL Game mode while a game runs: auto would turn it on, so respect it
    w.user_switch(True)
    w.screen.game()
    w.step()
    w.user_switch(False)
    assert w.step() == "respect" and not gm(store)["active"]


def test_switching_on_clears_the_respect(w, store):
    w.screen.game()
    w.step()
    w.user_switch(False)
    assert gamemode.respect_until(store) > 0
    w.user_switch(True)
    assert gamemode.respect_until(store) == 0 and gm(store)["manual"]


def test_auto_off_in_settings(w, store, settings):
    w.screen.game()
    w.step()
    settings.game_mode_auto = False
    calls = w.screen.calls
    assert w.step() == "off" and not gm(store)["active"]
    assert w.step() == "disabled"
    assert w.screen.calls == calls                                 # Windows isn't even asked
    w.user_switch(True)                                            # a manual one stays
    assert w.step() == "disabled" and gm(store)["active"]


def test_a_broken_detector_counts_as_nothing_in_front(w, store):
    def boom():
        raise OSError("no")
    w.screen.game()
    w.step()
    w.detector = boom
    w.clock_.tick(31)
    assert w.step() == "off"


def test_thread_polls_and_stops(settings, store):
    screen = Screen()
    screen.game()
    watcher = gamemode.GameModeWatcher(settings, store, detector=screen, poll_s=0.02)
    watcher.start()
    try:
        end = time.time() + 5
        while time.time() < end and not phase4.game_mode(store)["active"]:
            time.sleep(0.02)
        assert phase4.game_mode(store)["active"]
        n = screen.calls
        time.sleep(0.15)
        assert screen.calls > n                                    # it keeps looking
    finally:
        watcher.stop()
    assert not watcher.running


def test_windows_busy_counts_only_after_3_minutes(w, store):
    w.screen.state = (True, "a full-screen program")         # QUNS_BUSY
    assert w.step() == "idle" and not gm(store)["active"]
    w.clock_.tick(gamemode.BUSY_AFTER_S - 10)
    assert w.step() == "idle"
    w.clock_.tick(10)
    assert w.step() == "on" and gm(store)["reason"] == "a full-screen program"
    # a short busy moment later on starts the 3 minutes again
    w.screen.desktop()
    w.clock_.tick(31)
    assert w.step() == "off"
    w.screen.state = (True, "a full-screen program")
    w.clock_.tick(60)
    assert w.step() == "idle"
    w.screen.game()                                           # a real full-screen game counts at once
    assert w.step() == "on"


def _age_game_mode(store, seconds):
    import json
    d = json.loads(store.get_meta("game_mode"))
    d["since"] -= seconds
    store.set_meta("game_mode", json.dumps(d))


def test_manual_game_mode_ends_after_4_hours(w, store):
    w.user_switch(True)
    _age_game_mode(store, phase4.MANUAL_GAME_MODE_MAX_S - 60)
    assert gm(store)["active"] and w.step() == "manual"
    _age_game_mode(store, 120)                               # now 4 hours and a minute old
    assert not gm(store)["active"]                            # every reader sees it off at once
    assert w.step() == "idle"
    import json
    assert json.loads(store.get_meta("game_mode"))["active"] is False   # and it is written off
    # an automatic one is not limited (it ends when the game ends)
    w.screen.game()
    w.step()
    _age_game_mode(store, 5 * 3600)
    assert gm(store)["active"]


def test_manual_game_mode_ends_when_tacoguard_starts_again(settings, store):
    gamemode.switch(store, True)
    assert gm(store)["active"]
    watcher = gamemode.GameModeWatcher(settings, store, detector=lambda: (False, ""), poll_s=5)
    watcher.start()
    try:
        assert not gm(store)["active"]
    finally:
        watcher.stop()


def test_switch_without_a_watcher(store):
    g = gamemode.switch(store, True)
    assert g["active"] and g["manual"]
    g = gamemode.switch(store, False)
    assert not g["active"] and gamemode.respect_until(store) == 0
    phase4.set_game_mode(store, True, manual=False, reason="a full-screen game")
    gamemode.switch(store, False)
    assert gamemode.respect_until(store) > time.time()
