"""Game mode: notice a full-screen game or a presentation and keep TacoGuard quiet meanwhile.

Contract (tacoguard/phase4.py): detect() -> (bool, reason) with Windows' own answer
(SHQueryUserNotificationState, no admin, no polling of other programs); a small thread in the
page process asks every 10 s while settings.game_mode_auto is on and writes
phase4.set_game_mode(store, ..., manual=False).

Rules (who wins):
- A manual switch wins. Game mode you turned on stays on until you turn it off, TacoGuard
  restarts (start() ends it), or 4 hours pass (phase4.MANUAL_GAME_MODE_MAX_S: every reader then
  sees it off, and step() writes it off).
- Windows' "busy" answer (QUNS_BUSY: some full-screen window, also a full-screen video or a
  maximised browser on some PCs) counts only after it lasted BUSY_AFTER_S (3 minutes); a
  full-screen game or presentation mode counts at once.
- You turned Game mode off while a game or presentation was running: TacoGuard respects that for
  2 hours (it doesn't switch Game mode on again by itself), then decides by itself again.
- Game mode that TacoGuard switched on by itself ends 30 s after the game or presentation ends
  (alt-tabbing out for a moment doesn't flip it off and on).
- Automatic Game mode switched off in Settings: an automatic Game mode that is on ends at once; a
  manual one stays.

Cost (measured 2026-11-26, this PC, 2,000 calls): one detect() takes about 0.25 ms, so polling
every 10 s costs about 0.003% of one CPU core.
"""
from __future__ import annotations

import ctypes
import json
import threading
import time

from . import phase4

POLL_S = 10.0
TAIL_S = 30.0                 # auto Game mode ends this long after the condition went away
RESPECT_S = 2 * 3600.0        # a manual "off" during a game is respected this long
RESPECT_KEY = "game_mode_respect"
BUSY_AFTER_S = 180.0          # Windows' "busy" (some full-screen program) counts after this long
MANUAL_MAX_S = phase4.MANUAL_GAME_MODE_MAX_S

# SHQueryUserNotificationState answers (shellapi.h QUERY_USER_NOTIFICATION_STATE)
QUNS_NOT_PRESENT = 1
QUNS_BUSY = 2
QUNS_RUNNING_D3D_FULL_SCREEN = 3
QUNS_PRESENTATION_MODE = 4
QUNS_ACCEPTS_NOTIFICATIONS = 5
QUNS_QUIET_TIME = 6
QUNS_APP = 7

REASONS = {
    QUNS_RUNNING_D3D_FULL_SCREEN: "a full-screen game",
    QUNS_PRESENTATION_MODE: "presentation mode",
    QUNS_BUSY: "a full-screen program",
}
MANUAL_REASON = "you switched it on"


def query_state() -> int | None:
    """Windows' QUERY_USER_NOTIFICATION_STATE for this session, or None when it can't say."""
    try:
        value = ctypes.c_int(0)
        hr = ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(value))
        return int(value.value) if hr == 0 else None
    except Exception:
        return None


def detect(query=query_state) -> tuple[bool, str]:
    """(True, reason) while a full-screen game, presentation mode or another full-screen program
    is in front; (False, "") otherwise (also when Windows can't say)."""
    state = query()
    reason = REASONS.get(state) if state is not None else None
    return (True, reason) if reason else (False, "")


def respect_until(store) -> float:
    try:
        return float(json.loads(store.get_meta(RESPECT_KEY) or "{}").get("until") or 0)
    except (ValueError, TypeError, AttributeError):
        return 0.0


def _set_respect(store, until: float) -> None:
    store.set_meta(RESPECT_KEY, json.dumps({"until": float(until)}))


class GameModeWatcher:
    """The automatic part. step() is one decision (tests call it with a fake detector and clock);
    start() runs it every poll_s seconds on a daemon thread until stop()."""

    def __init__(self, settings, store, detector=detect, clock=time.time, poll_s: float = POLL_S,
                 log=None):
        self.settings = settings
        self.store = store
        self.detector = detector
        self.clock = clock
        self.poll_s = poll_s
        self.tail_s = TAIL_S
        self.respect_s = RESPECT_S
        self.log = log
        self.condition: tuple[bool, str] = (False, "")
        self.busy_since = 0.0              # Windows said "busy" since then (0 = not busy)
        self.last_seen = clock()           # the condition was last seen (starts the tail after a restart)
        self.last_decision = ""
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- the user's switch (page and tray) ---------------------------------------------------
    def user_switch(self, on: bool) -> dict:
        """You turned Game mode on or off. Returns the new game_mode() state."""
        with self._lock:
            now = self.clock()
            gm = phase4.game_mode(self.store)
            if on:
                _set_respect(self.store, 0)
                phase4.set_game_mode(self.store, True, manual=True, reason=MANUAL_REASON)
            else:
                auto_on = gm["active"] and not gm["manual"]
                if auto_on or self.condition[0]:
                    _set_respect(self.store, now + self.respect_s)
                phase4.set_game_mode(self.store, False, manual=True, reason="")
            return phase4.game_mode(self.store)

    # ---- one decision --------------------------------------------------------------------------
    def step(self) -> str:
        """Look once and switch automatic Game mode on or off. Returns what happened (for tests and
        the log): "disabled", "manual", "on", "kept", "respect", "tail", "off" or "idle"."""
        with self._lock:
            now = self.clock()
            self._end_old_manual()
            gm = phase4.game_mode(self.store)
            if not getattr(self.settings, "game_mode_auto", True):
                self.condition = (False, "")
                if gm["active"] and not gm["manual"]:
                    phase4.set_game_mode(self.store, False, manual=False)
                    return self._done("off")
                return self._done("disabled")
            try:
                active, reason = self.detector()
            except Exception:
                active, reason = False, ""
            if active and reason == REASONS[QUNS_BUSY]:
                if not self.busy_since:
                    self.busy_since = now
                if now - self.busy_since < BUSY_AFTER_S:
                    active, reason = False, ""    # not yet: a short full-screen moment isn't a game
            else:
                self.busy_since = 0.0
            self.condition = (bool(active), str(reason or ""))
            if active:
                self.last_seen = now
            if gm["active"] and gm["manual"]:
                return self._done("manual")       # you switched it on: only you switch it off
            if active:
                if now < respect_until(self.store):
                    return self._done("respect")  # you switched it off during this game
                if not gm["active"] or gm["reason"] != reason:
                    phase4.set_game_mode(self.store, True, manual=False, reason=reason)
                    return self._done("on")
                return self._done("kept")
            if gm["active"]:                      # automatic, and the game or presentation ended
                if now - self.last_seen >= self.tail_s:
                    phase4.set_game_mode(self.store, False, manual=False)
                    return self._done("off")
                return self._done("tail")
            return self._done("idle")

    def _end_old_manual(self) -> None:
        """A manual Game mode older than 4 hours: written off (readers already see it off)."""
        try:
            d = json.loads(self.store.get_meta("game_mode") or "{}") or {}
        except (ValueError, TypeError):
            return
        if d.get("active") and d.get("manual") and d.get("since") and \
                time.time() - float(d["since"]) >= MANUAL_MAX_S:
            phase4.set_game_mode(self.store, False, manual=True, reason="")
            if self.log is not None:
                try:
                    self.log.info("Game mode you switched on ended after 4 hours")
                except Exception:
                    pass

    def end_manual_at_start(self) -> None:
        """TacoGuard (the page) starts: a Game mode you switched on earlier ends."""
        gm = phase4.game_mode(self.store)
        if gm["active"] and gm["manual"]:
            phase4.set_game_mode(self.store, False, manual=True, reason="")

    def _done(self, what: str) -> str:
        if what in ("on", "off") and self.log is not None:
            try:
                self.log.info("Game mode %s by itself (%s)", what, self.condition[1] or "the condition ended")
            except Exception:
                pass
        self.last_decision = what
        return what

    # ---- the thread ------------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is None:
            try:
                self.end_manual_at_start()
            except Exception:
                pass
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="tacoguard-gamemode", daemon=True)
            self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        t, self._thread = self._thread, None
        if t is not None and t is not threading.current_thread():
            t.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception:
                if self.log is not None:
                    try:
                        self.log.exception("Game mode check failed")
                    except Exception:
                        pass
            # while automatic Game mode is off there is nothing to look at: wake only for a change
            wait = self.poll_s if getattr(self.settings, "game_mode_auto", True) else 300.0
            self._wake.wait(wait)
            self._wake.clear()
        try:
            self.store.close()                   # this thread's SQLite connection
        except Exception:
            pass


def switch(store, on: bool, watcher: GameModeWatcher | None = None) -> dict:
    """The user's switch when no watcher runs (tests, the page before serve() started one)."""
    if watcher is not None:
        return watcher.user_switch(on)
    if on:
        _set_respect(store, 0)
        phase4.set_game_mode(store, True, manual=True, reason=MANUAL_REASON)
    else:
        gm = phase4.game_mode(store)
        if gm["active"] and not gm["manual"]:
            _set_respect(store, time.time() + RESPECT_S)
        phase4.set_game_mode(store, False, manual=True, reason="")
    return phase4.game_mode(store)
