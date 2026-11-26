"""The guard process (python -m tacoguard.guard --data DIR [--parent PID]) and its in-process form.

main() makes sure only one guard runs (a named mutex), lowers its own CPU and disk priority, caps
its memory at 512 MB (a Windows job object), then runs Guard until it is told to stop: CTRL_BREAK,
a "stop" file in settings.guard_dir, or the page process (--parent) ending.

Guard loads the detectors once (hash, YARA, ML; ClamAV only as a second opinion, see
checker.py), starts the parts the settings switch on (folders, processes, ransomware,
persistence), writes a heartbeat with every part's state into the store's meta table
("guard_state", JSON in guard/__init__.py) every 10 s, and re-reads settings.json when it
changes (checked every 5 s) to switch parts on and off live. A part that crashes is logged
(logs\\guard.log), shown as "error" and restarted after 60 s, at most 3 times an hour; it never
takes the guard down.

Phase 4 (contract in tacoguard/phase4.py):
- a fifth part "web" (tacoguard/webblock/watch.py WebWatcher, settings.webblock_enabled);
- "Pause protection": while phase4.protection_paused(store), every part is stopped (state "off",
  "Paused until HH:MM") and started again when the time passes or protection is resumed; files
  changed meanwhile in the watched folders are then caught up;
- Game mode: no notifications (toasts) while phase4.game_mode(store)["active"]; the events are
  still written and the page shows them;
- self-protection (tacoguard/selfprotect.py): main() hardens the process (settings.self_protection),
  and every 60 s OwnWatch looks at TacoGuard's own Run value and data folder ACL;
- the page process ending WITHOUT the stop file (it crashed or another program ended it): the guard
  of the INSTALLED copy starts the launcher again (--background) before it exits, at most once per
  10 minutes, and records an event kind "self".
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import logging.handlers
import os
import queue
import signal
import sys
import threading
import time
from collections import deque
from dataclasses import fields

from .. import __version__, winpath
from ..model import plain_error

log = logging.getLogger("tacoguard.guard")

MUTEX_NAME = "Local\\TacoGuardGuard"
MEMORY_LIMIT = 512 * 1024**2
ERROR_ALREADY_EXISTS = 183
EXIT_ALREADY_RUNNING = 3
EXIT_RECYCLE = 75          # "start me again now": not a crash (see Guard._maybe_recycle)
PART_NAMES = ("folders", "processes", "ransomware", "persistence", "web")
MISSING_PART_MSG = "This part is not included in this copy of TacoGuard, so it is not running."
OFF_MSG = "Turned off in Settings."
PAGE_RESTART_KEY = "page_restarted_at"
PAGE_RESTARTED_TITLE = "TacoGuard's page process was ended unexpectedly and was started again"
PAGE_NOT_RESTARTED_TITLE = "TacoGuard's page process was ended unexpectedly"


def paused_message(until: float, now: float | None = None) -> str:
    """"Paused until 14:30" ("... tomorrow" when that is another day)."""
    t = time.localtime(until)
    words = f"Paused until {time.strftime('%H:%M', t)}"
    if time.strftime("%Y%m%d", t) != time.strftime("%Y%m%d", time.localtime(now)):
        words += " tomorrow"
    return words + "."


def part_dict(state: str, message: str = "", watched=None, checked: int = 0) -> dict:
    return {"state": state, "message": message, "watched": [str(w) for w in (watched or [])],
            "checked": int(checked or 0)}


def _normalize_part(raw, fallback_state: str) -> dict:
    if not isinstance(raw, dict):
        return part_dict(fallback_state)
    state = raw.get("state") if raw.get("state") in ("on", "off", "starting", "error") else fallback_state
    try:
        checked = int(raw.get("checked") or 0)
    except (TypeError, ValueError):
        checked = 0
    watched = raw.get("watched") if isinstance(raw.get("watched"), (list, tuple)) else []
    return part_dict(state, str(raw.get("message") or ""), watched, checked)


# ---- the parts ------------------------------------------------------------------------------
def _make_folders(g: "Guard"):
    from .folders import FolderWatcher
    return FolderWatcher(g.settings, g.store, g.checker, g.hub)


def _make_processes(g: "Guard"):
    from .processes import ProcessWatcher
    return ProcessWatcher(g.settings, g.store, g.checker)


def _make_ransomware(g: "Guard"):
    from .ransom import RansomGuard
    return RansomGuard(g.settings, g.store, g.hub)


def _make_persistence(g: "Guard"):
    from .persistence import PersistenceWatcher
    try:        # it can share the hub to see the Startup folders change
        return PersistenceWatcher(g.settings, g.store, g.checker, hub=g.hub)
    except TypeError:
        return PersistenceWatcher(g.settings, g.store, g.checker)


def _make_web(g: "Guard"):
    from ..webblock.watch import WebWatcher       # Phase 4 (Helper M); missing -> "not included"
    return WebWatcher(g.settings, g.store, g.checker)


def _list_key(value) -> tuple:
    return tuple(winpath.norm_key(str(v)) for v in (value or []))


PART_SPECS = {
    # name: (factory, switched on?, settings that restart the part when they change)
    "folders": (_make_folders, lambda s: True, lambda s: _list_key(s.watch_folders)),
    "processes": (_make_processes, lambda s: bool(s.watch_processes), lambda s: ()),
    "ransomware": (_make_ransomware, lambda s: bool(s.ransomware_guard),
                   lambda s: _list_key(s.canary_folders)),
    "persistence": (_make_persistence, lambda s: bool(s.persistence_watch), lambda s: ()),
    "web": (_make_web, lambda s: bool(getattr(s, "webblock_enabled", False)), lambda s: ()),
}


class _Part:
    def __init__(self, name: str):
        self.name = name
        self.inst = None
        self.state = "off"
        self.message = OFF_MSG
        self.key: tuple = ()
        self.crashes: deque = deque()      # times (monotonic) of crashes in the last hour
        self.retry_at = 0.0
        self.permanent = False             # missing from this copy: do not retry


class Guard:
    """The guard, in-process. start() / stop(); request_stop() from any thread; wait()."""

    TICK_S = 1.0
    HEARTBEAT_S = 10.0
    SETTINGS_CHECK_S = 5.0
    PARENT_CHECK_S = 2.0
    DETECTOR_CHECK_S = 60.0
    NOTIFY_CHECK_S = 2.0
    RESTART_DELAY_S = 60.0
    MAX_RESTARTS_PER_HOUR = 3
    TRIM_AFTER_S = 30.0
    # Budget: page + guard under 150 MB idle; the page idles at ~35 MB (2026-11-24)
    RECYCLE_PRIVATE_MB = 115
    # Never more often than this (no restart loops). Measured 2026-11-24: every program the ML and
    # YARA checks read keeps a few MB (fragments), +55 MB after one big new program, so the guard
    # restarts whenever it is over the limit, at most every 2 min (~2 s of one core each time;
    # an 8-minute watch on this PC: 186 MB -> 87 MB, then 150 MB -> 86 MB; quiet page+guard ~113 MB).
    RECYCLE_MIN_GAP_S = 2 * 60
    RECYCLE_LOOK_S = 60.0
    CATCH_UP_LIMIT = 500
    CATCH_UP_MAX_AGE_S = 7 * 86400
    PAUSE_CHECK_S = 2.0                # "Pause protection" (phase4.protection_paused)
    OWN_CHECK_S = 60.0                 # selfprotect.OwnWatch: Run value, data folder ACL
    PAGE_RESTART_GAP_S = 10 * 60       # the page is started again at most this often

    def __init__(self, settings, store, detectors=None, hub=None):
        self.settings, self.store = settings, store
        self._given_detectors = detectors
        self._own_detectors = detectors is None
        self.detectors: list = []
        self.detector_notes: list[str] = []
        self._hub_given = hub is not None
        self.hub = hub
        self.checker = None
        self.parts = {name: _Part(name) for name in PART_NAMES}
        self.parent_pid: int | None = None
        self._parent_ctime: float | None = None
        self.notify_fn = None              # main(): callable(event dict), guard/notify.py's toast
        self.notes_fn = None               # main(): callable() -> plain note ("notifications are off")
        self.trim_memory = True
        self.recycle_enabled = False       # main() turns it on: only a real guard process restarts
        self.recycle = False               # set when this guard ends itself to give memory back
        self._trim_seen, self._trimmed_at = 0, -1     # -1: also once after loading the rules
        self._trim_last_change = 0.0
        self._recycle_look_at = time.monotonic()
        self._notify_q: queue.Queue = queue.Queue(200)
        self._notify_thread: threading.Thread | None = None
        self.stop_reason = ""
        self.started = 0.0
        self.last_heartbeat_before = 0.0   # the previous run's last heartbeat (catch-up)
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._catchup: threading.Thread | None = None
        self._settings_stamp = None
        self._sig_stamp = ""
        self._last_event_id = 0
        self._log_handler = None
        self._running = False
        # Phase 4
        self.paused_until = 0.0            # protection paused until (epoch); 0 = not paused
        self._paused_since = 0.0
        self.own_watch = None              # selfprotect.OwnWatch (made in start() when self_protection)
        self.own_watch_factory = None      # tests: callable(guard) -> object with check()
        self.page_launcher = None          # main(): callable() that starts the installed page again
        self.update_busy_fn = None         # main(): callable() -> True while a self-update runs
        self.page_lost = False             # the page process ended without the stop file
        self.hardened = None               # main(): what selfprotect.maybe_harden() said

    # ---- paths ----------------------------------------------------------------------------
    @property
    def stop_file(self):
        return self.settings.guard_dir / "stop"

    # ---- start / stop ---------------------------------------------------------------------
    def start(self) -> None:
        self.settings.guard_dir.mkdir(parents=True, exist_ok=True)
        self._setup_log()
        try:
            self.stop_file.unlink(missing_ok=True)
        except OSError:
            pass
        self.started = time.time()
        self.last_heartbeat_before = self._previous_heartbeat()
        self._settings_stamp = self._settings_file_stamp()
        self._stop_evt.clear()
        self._running = True
        log.info("Guard starting (pid %s, version %s)", os.getpid(), __version__)
        for p in self.parts.values():
            p.state, p.message = "starting", "Starting..."
        self._write_heartbeat()
        from .checker import RealtimeChecker
        self.checker = RealtimeChecker(self.settings, self.store, [])
        self._load_detectors()
        if self.hub is None:
            from .folders import WatchHub
            self.hub = WatchHub()
        self.hub.start()
        try:
            row = self.store._con().execute("SELECT COALESCE(MAX(id), 0) FROM guard_events").fetchone()
            self._last_event_id = int(row[0])
        except Exception:
            self._last_event_id = 0
        if self.parent_pid:
            try:
                import psutil
                self._parent_ctime = psutil.Process(self.parent_pid).create_time()
            except Exception:
                self._parent_ctime = None
                self.request_stop("the page process was not running")
        self.paused_until = self._read_pause()
        if self.paused_until:
            # files changed while protection was paused (and the guard down) are caught up on resume
            self._paused_since = self.last_heartbeat_before or time.time()
            log.info("Protection is paused until %s", time.strftime("%H:%M", time.localtime(self.paused_until)))
        self._apply_parts(initial=True)
        self._remove_leftover_decoys()
        self._make_own_watch()
        self._write_heartbeat()
        if not self.paused_until:
            self._start_catch_up()
        self._thread = threading.Thread(target=self._control_loop, name="tacoguard-guard", daemon=True)
        self._thread.start()

    def request_stop(self, reason: str = "") -> None:
        if not self._stop_evt.is_set():
            self.stop_reason = reason or self.stop_reason
            self._stop_evt.set()

    def wait(self, timeout: float | None = None) -> bool:
        """Blocks until a stop was requested. True when it was."""
        return self._stop_evt.wait(timeout)

    def stop(self) -> None:
        if not self._running:
            return
        self.request_stop(self.stop_reason or "stopped")
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(30)
        if self._catchup is not None:
            self._catchup.join(5)
        for p in self.parts.values():
            self._stop_part(p, "off", "The guard is not running.")
        self._stop_notify_thread()
        if self.checker is not None:
            self.checker.close()
        if self.hub is not None and not self._hub_given:
            self.hub.stop()
        self._write_heartbeat()
        log.info("Guard stopped (%s)", self.stop_reason or "stopped")
        self._running = False
        self._close_log()

    # ---- logging ----------------------------------------------------------------------------
    def _setup_log(self) -> None:
        try:
            self.settings.log_dir.mkdir(parents=True, exist_ok=True)
            h = logging.handlers.RotatingFileHandler(self.settings.log_dir / "guard.log", maxBytes=1024**2,
                                                     backupCount=3, encoding="utf-8", delay=True)
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s: %(message)s"))
            log.addHandler(h)
            log.setLevel(logging.INFO)
            self._log_handler = h
        except OSError:
            self._log_handler = None

    def _close_log(self) -> None:
        if self._log_handler is not None:
            log.removeHandler(self._log_handler)
            self._log_handler.close()
            self._log_handler = None

    # ---- detectors --------------------------------------------------------------------------
    def _load_detectors(self) -> None:
        """(Re)loads the checks. They are opened, used and closed on the checker's engine thread
        (YARA-X's scanner works only on the thread that made it); ClamAV is NOT started here."""
        if self._given_detectors is not None:
            found = list(self._given_detectors)
        else:
            try:
                from ..detect import load_detectors
                found = load_detectors(self.settings, self.store)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:          # also a Rust panic (pyo3 PanicException) in a detector
                log.error("Detectors could not be loaded", exc_info=(type(e), e, e.__traceback__))
                self.detector_notes = [f"The checks could not be loaded ({plain_error(e)})."]
                found = []
        try:
            notes = self.checker.load(found)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:
            log.error("The checks could not be opened", exc_info=(type(e), e, e.__traceback__))
            notes = [f"The checks could not be loaded ({plain_error(e)})."]
        self.detector_notes = notes
        for n in notes:
            log.info("%s", n)
        self.detectors = list(self.checker.detectors)
        if self._own_detectors:
            self._sig_stamp = self._signature_stamp()

    def _signature_stamp(self) -> str:
        """Changes when the installed signatures change or a check is switched on/off."""
        s = self.settings
        try:
            from ..detect import load_detectors
            fresh = load_detectors(s, self.store)
            names = "|".join(f"{d.name}={d.version()}" for d in fresh if d.name != "clamav")
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            names = "?"
        return names

    def _maybe_reload_detectors(self) -> None:
        if not self._own_detectors:
            return
        stamp = self._signature_stamp()
        if stamp == self._sig_stamp:
            return
        log.info("Signatures changed: loading the checks again")
        # checker.load() closes the old rules first (two rule sets are never in memory at once)
        # and no check runs while they are swapped
        self._load_detectors()

    # ---- parts ------------------------------------------------------------------------------
    def _apply_parts(self, initial: bool = False) -> None:
        now = time.monotonic()
        paused = paused_message(self.paused_until) if self.paused_until else ""
        for name, (make, enabled, key_of) in PART_SPECS.items():
            p = self.parts.get(name)
            if p is None:
                p = self.parts[name] = _Part(name)
            want = bool(self.settings.realtime_enabled) and enabled(self.settings)
            try:
                key = key_of(self.settings)
            except Exception:
                key = ()
            if not want:
                if p.inst is not None or p.state != "off" or p.message != OFF_MSG:
                    was_on = p.inst is not None
                    self._stop_part(p, "off", OFF_MSG)
                    if name == "ransomware" and was_on and not initial and not self.settings.ransomware_guard:
                        self._remove_decoys(make)
                continue
            if paused:
                # "Pause protection": the part does not check or pause anything until resumed
                if p.inst is not None or p.state != "off" or p.message != paused:
                    self._stop_part(p, "off", paused)
                continue
            if p.inst is not None and key != p.key:
                log.info("Settings for %s changed: restarting it", name)
                self._stop_part(p, "starting", "Starting...")
            if p.inst is None:
                if p.state == "error" and (p.permanent or now < p.retry_at):
                    continue
                self._start_part(p, make, key)

    def _start_part(self, p: _Part, make, key: tuple) -> None:
        p.key = key
        try:
            inst = make(self)
        except ImportError:
            log.info("Part %s is missing from this copy", p.name)
            p.state, p.message, p.permanent = "error", MISSING_PART_MSG, True
            return
        except Exception as e:
            self._part_crashed(p, e)
            return
        if not callable(getattr(inst, "start", None)):
            p.state, p.message, p.permanent = "error", MISSING_PART_MSG, True
            return
        try:
            p.state, p.message = "starting", "Starting..."
            inst.start()
        except Exception as e:
            try:
                if callable(getattr(inst, "stop", None)):
                    inst.stop()
            except Exception:
                pass
            self._part_crashed(p, e)
            return
        p.inst = inst
        p.state, p.message = "on", ""
        log.info("Part %s started", p.name)

    def _stop_part(self, p: _Part, state: str, message: str) -> None:
        inst, p.inst = p.inst, None
        if inst is not None:
            try:
                if callable(getattr(inst, "stop", None)):
                    inst.stop()
            except Exception:
                log.exception("Part %s did not stop cleanly", p.name)
        if p.state != "error" or state == "off":
            p.state, p.message = state, message
        if state == "off":
            p.permanent = p.permanent and p.message == MISSING_PART_MSG

    def _part_crashed(self, p: _Part, exc: BaseException | None, message: str = "") -> None:
        now = time.monotonic()
        if exc is not None:
            log.error("Part %s failed", p.name, exc_info=(type(exc), exc, exc.__traceback__))
        while p.crashes and now - p.crashes[0] > 3600:
            p.crashes.popleft()
        p.crashes.append(now)
        if len(p.crashes) <= self.MAX_RESTARTS_PER_HOUR:
            p.retry_at = now + self.RESTART_DELAY_S
            again = "TacoGuard tries again in a minute."
        else:
            p.retry_at = p.crashes[0] + 3600
            again = "It stopped several times, so TacoGuard waits an hour before trying again."
        why = message or (f"It stopped because of an unexpected problem ({plain_error(exc)})."
                          if exc is not None else "It stopped because of an unexpected problem.")
        p.state, p.message = "error", f"{why} {again}"

    def _part_status(self, p: _Part) -> dict:
        if p.inst is None:
            return part_dict(p.state, p.message)
        get = getattr(p.inst, "status", None)
        if not callable(get):
            return part_dict("on", p.message)
        try:
            return _normalize_part(get(), "on")
        except Exception:
            return part_dict("on", p.message)

    def _check_parts_health(self) -> None:
        for p in self.parts.values():
            if p.inst is None:
                continue
            st = self._part_status(p)
            if st["state"] == "error":
                log.error("Part %s reported a problem: %s", p.name, st["message"])
                inst, p.inst = p.inst, None
                try:
                    if callable(getattr(inst, "stop", None)):
                        inst.stop()
                except Exception:
                    pass
                self._part_crashed(p, None, st["message"])

    # ---- Phase 4: pause, own watch, page restart ------------------------------------------------
    def _read_pause(self) -> float:
        try:
            from ..phase4 import protection_paused
            return float(protection_paused(self.store) or 0.0)
        except Exception:
            return 0.0

    def _check_pause(self) -> None:
        """Stops the parts while protection is paused; starts them again when it ends."""
        until = self._read_pause()
        if until == self.paused_until:
            return
        was = self.paused_until
        self.paused_until = until
        if until and not was:
            self._paused_since = time.time()
            log.info("Protection paused until %s", time.strftime("%H:%M", time.localtime(until)))
        elif not until:
            log.info("Protection resumed")
        self._apply_parts()
        if not until and was:
            since, self._paused_since = self._paused_since, 0.0
            self._start_catch_up(since)
        self._write_heartbeat()

    def _make_own_watch(self) -> None:
        self.own_watch = None
        if not getattr(self.settings, "self_protection", False):
            return
        try:
            if self.own_watch_factory is not None:
                self.own_watch = self.own_watch_factory(self)
            else:
                from ..selfprotect import OwnWatch
                self.own_watch = OwnWatch(self.settings, self.store)
        except Exception:
            log.exception("The watch over TacoGuard's own files could not start")
            self.own_watch = None

    def _check_own(self) -> None:
        if self.hardened:
            # threads started by native code (not through Python's threading) since the last look
            try:
                from ..selfprotect import harden_threads
                harden_threads()
            except Exception:
                log.exception("Hardening the guard's threads failed")
        if self.own_watch is None or not getattr(self.settings, "self_protection", False):
            return
        try:
            self.own_watch.check()
        except Exception:
            log.exception("The watch over TacoGuard's own files failed")

    def restart_page_if_needed(self, launcher=None) -> bool:
        """After the guard stopped because its page process ended WITHOUT the stop file: start
        the installed page again (self.page_launcher, set by main() only for the installed copy),
        at most once per PAGE_RESTART_GAP_S, and record an event kind "self". True when the page
        was started. Not while Windows shuts down or a self-update is under way."""
        launcher = launcher or self.page_launcher
        if not self.page_lost or launcher is None:
            return False
        self.page_lost = False
        try:
            from ..selfprotect import windows_shutting_down
            if windows_shutting_down():
                log.info("The page ended while Windows shuts down: not starting it again")
                return False
        except Exception:
            pass
        try:
            if self.update_busy_fn is not None and self.update_busy_fn():
                log.info("The page ended during a self-update: the update starts it again")
                return False
        except Exception:
            pass
        now = time.time()
        try:
            last = float(self.store.get_meta(PAGE_RESTART_KEY) or 0)
        except Exception:
            last = 0.0
        if 0 <= now - last < self.PAGE_RESTART_GAP_S:
            log.warning("The page process ended unexpectedly again within %d minutes: not starting it again",
                        self.PAGE_RESTART_GAP_S // 60)
            self._self_event(PAGE_NOT_RESTARTED_TITLE,
                             "TacoGuard's page process ended again within a few minutes, so TacoGuard did not "
                             "start it again by itself (real-time protection is off until it runs). Start "
                             "TacoGuard from the Start menu. To close TacoGuard on purpose, use Quit in the "
                             "page or the tray icon.")
            return False
        try:
            self.store.set_meta(PAGE_RESTART_KEY, str(now))
        except Exception:
            pass
        try:
            launcher()
        except Exception as e:
            log.error("Could not start the page again", exc_info=(type(e), e, e.__traceback__))
            self._self_event(PAGE_NOT_RESTARTED_TITLE,
                             "TacoGuard's page process was ended by something other than Quit, and TacoGuard "
                             f"could not start it again ({plain_error(e)}). Start TacoGuard from the Start menu.")
            return False
        log.warning("The page process ended without Quit: started it again")
        self._self_event(PAGE_RESTARTED_TITLE,
                         "TacoGuard's page process ended without Quit (it crashed, or another program ended it), "
                         "so TacoGuard started it again. If this happens often, run a full scan. To close "
                         "TacoGuard on purpose, use Quit in the page or the tray icon.")
        return True

    def _self_event(self, title: str, message: str) -> None:
        try:
            self.store.add_guard_event("self", "warning", title, message)
        except Exception:
            log.exception("Could not record an event")

    def _remove_leftover_decoys(self) -> None:
        """At start: the ransomware guard is off but decoy files are still listed (it was switched
        off while the guard was not running, or together with real-time protection): take them away."""
        if self.settings.ransomware_guard:
            return
        try:
            from . import ransom
            if not ransom.manifest_path(self.settings).exists():
                return
            n = ransom.remove_decoys(self.settings)
            log.info("The ransomware guard is off: removed %s leftover decoy files", n)
        except ImportError:
            return
        except Exception:
            log.exception("Could not remove the leftover decoy files")

    def _remove_decoys(self, make) -> None:
        """The ransomware guard was switched off: take TacoGuard's decoy files away."""
        try:
            inst = make(self)
            remove = getattr(inst, "remove_decoys", None)
            if callable(remove):
                n = remove()
                log.info("Removed %s decoy files", n)
        except Exception:
            log.exception("Could not remove the decoy files")

    # ---- heartbeat ---------------------------------------------------------------------------
    def notes(self) -> list[str]:
        """Plain notes for the page (e.g. "Windows has notifications switched off")."""
        out = []
        if self.notes_fn is not None:
            try:
                note = self.notes_fn()
                if callable(note):          # tolerate a function handed back instead of its words
                    note = note()
                if note and isinstance(note, str):
                    out.append(note)
            except Exception:
                pass
        return out

    def state(self) -> dict:
        return {"pid": os.getpid(), "started": self.started, "heartbeat": time.time(),
                "version": __version__,
                "parts": {name: self._part_status(p) for name, p in self.parts.items()},
                "notes": self.notes()}

    def _write_heartbeat(self) -> None:
        try:
            self.store.set_meta("guard_state", json.dumps(self.state()))
        except Exception:
            log.exception("Could not write the heartbeat")

    def _previous_heartbeat(self) -> float:
        try:
            value = self.store.get_meta("guard_state")
            return float(json.loads(value).get("heartbeat") or 0) if value else 0.0
        except Exception:
            return 0.0

    # ---- settings ----------------------------------------------------------------------------
    def _settings_file_stamp(self):
        try:
            st = os.stat(self.settings.settings_path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _maybe_reload_settings(self) -> bool:
        stamp = self._settings_file_stamp()
        if stamp == self._settings_stamp:
            return False
        self._settings_stamp = stamp
        from ..config import load_settings
        fresh = load_settings(self.settings.data_dir)
        for f in fields(fresh):                     # in place: every part sees the new values
            if f.name != "data_dir":
                setattr(self.settings, f.name, getattr(fresh, f.name))
        log.info("Settings changed")
        if not self.settings.realtime_enabled:
            self.request_stop("real-time protection was turned off")
            return True
        self._apply_parts()
        self._maybe_reload_detectors()
        return True

    # ---- the control loop --------------------------------------------------------------------
    def _parent_gone(self) -> bool:
        if not self.parent_pid or self._parent_ctime is None:
            return False
        try:
            import psutil
            return abs(psutil.Process(self.parent_pid).create_time() - self._parent_ctime) > 0.01
        except Exception:
            return True

    def _control_loop(self) -> None:
        last = {"hb": time.monotonic(), "settings": time.monotonic(), "parent": 0.0,
                "detectors": time.monotonic(), "notify": time.monotonic(), "pause": 0.0,
                "own": time.monotonic()}

        def due(name: str, every: float) -> bool:
            now = time.monotonic()
            if now - last[name] >= every:
                last[name] = now
                return True
            return False

        while not self._stop_evt.wait(self.TICK_S):
            try:
                if self.stop_file.exists():
                    self.request_stop("a stop was asked for")
                    break
                if due("parent", self.PARENT_CHECK_S) and self._parent_gone():
                    # Quit writes the stop file before the page closes: without it, the page
                    # crashed or another program ended it (restart_page_if_needed, after stop)
                    self.page_lost = not self.stop_file.exists()
                    self.request_stop("the page process ended")
                    break
                if due("settings", self.SETTINGS_CHECK_S):
                    self._maybe_reload_settings()
                    if self._stop_evt.is_set():
                        break
                if due("pause", self.PAUSE_CHECK_S):
                    self._check_pause()
                if due("own", self.OWN_CHECK_S):
                    self._check_own()
                self._check_parts_health()
                self._apply_parts()            # restarts parts whose retry time came
                if due("detectors", self.DETECTOR_CHECK_S):
                    self._maybe_reload_detectors()
                if self.notify_fn is not None and due("notify", self.NOTIFY_CHECK_S):
                    self._notify_new_events()
                if due("hb", self.HEARTBEAT_S):
                    self._write_heartbeat()
                self._maybe_trim_memory()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:      # also a Rust panic (pyo3 PanicException): never end the loop
                log.error("Guard control loop problem", exc_info=(type(e), e, e.__traceback__))

    def _maybe_trim_memory(self) -> None:
        """Once checks have stopped for TRIM_AFTER_S, hand the memory pages they used back to
        Windows (EmptyWorkingSet on this process). Measured 2026-11-24: after checking the ~100
        running programs once, the ML feature code keeps about 55 MB it does not give back and
        YARA-X reads a big program whole (+211 MB for a 201 MB file, freed afterwards); the
        guard's working set stayed near 200 MB, and about 60 MB after the trim. Pages still
        needed come back by themselves on the next check."""
        if self.checker is None or not self.trim_memory:
            return
        now = time.monotonic()
        # On a busy PC new programs start every few seconds, so "no checks for 30 s" may never
        # come (measured 2026-11-24: the guard sat at 173 MB). The recycle look runs once a minute
        # whenever no check is in progress.
        if self.recycle_enabled and now - self._recycle_look_at >= self.RECYCLE_LOOK_S:
            self._recycle_look_at = now
            if not getattr(self.checker, "in_check", False) and self._maybe_recycle():
                return
        n = self.checker.checked
        if n != self._trim_seen:
            self._trim_seen, self._trim_last_change = n, now
            return
        if n != self._trimmed_at and now - self._trim_last_change >= self.TRIM_AFTER_S:
            self._trimmed_at = n
            try:
                import ctypes
                psapi = ctypes.WinDLL("psapi")
                psapi.EmptyWorkingSet.argtypes = (ctypes.c_void_p,)
                psapi.EmptyWorkingSet(ctypes.c_void_p(-1))      # -1 = this process
            except Exception:
                pass

    def _maybe_recycle(self) -> bool:
        """Trimming only moves pages out of RAM; the memory stays committed to the guard. When the
        guard holds more than RECYCLE_PRIVATE_MB while nothing is being checked, it ends itself
        with EXIT_RECYCLE and the page process starts a fresh one at once (about 2 s; files changed
        in between are caught up from the heartbeat, running programs are re-listed and found in
        the clean cache). Measured 2026-11-24: fresh guard 84 MB private, after checking ~100
        programs 170-180 MB (ML feature code and YARA-X keep what they used)."""
        if not self.recycle_enabled:
            return False
        try:
            import psutil
            private_mb = psutil.Process().memory_info().private / 1024**2
        except Exception:
            return False
        if private_mb <= self.RECYCLE_PRIVATE_MB:
            return False
        try:
            last = float(self.store.get_meta("guard_recycled_at") or 0)
        except (TypeError, ValueError):
            last = 0.0
        if time.time() - last < self.RECYCLE_MIN_GAP_S:
            return False
        try:
            self.store.set_meta("guard_recycled_at", str(time.time()))
        except Exception:
            return False
        log.info("Restarting to give back memory (%.0f MB held, limit %d MB)", private_mb,
                 self.RECYCLE_PRIVATE_MB)
        self.recycle = True
        self.request_stop("restarting to give back memory")
        return True

    def _notify_new_events(self) -> None:
        try:
            events = self.store.list_guard_events(after_id=self._last_event_id, limit=50)
        except Exception:
            return
        if not events:
            return
        try:
            from ..phase4 import game_mode
            quiet = bool(game_mode(self.store).get("active"))
        except Exception:
            quiet = False
        for ev in sorted(events, key=lambda e: e["id"]):
            self._last_event_id = max(self._last_event_id, ev["id"])
            if quiet:
                continue                    # Game mode: no toasts; the page and tray still show it
            if ev["level"] in ("malware", "suspicious", "warning"):
                self._ensure_notify_thread()
                try:
                    self._notify_q.put_nowait(ev)
                except queue.Full:
                    pass                    # a flood: the notifier merges them anyway

    def _ensure_notify_thread(self) -> None:
        """Showing a notification blocks for about a second: it gets its own thread, never the
        hub's, a check's or this control loop's."""
        if self._notify_thread is not None and self._notify_thread.is_alive():
            return

        def run():
            while True:
                ev = self._notify_q.get()
                if ev is None:
                    return
                try:
                    self.notify_fn(ev)
                except Exception:
                    log.exception("Could not show a notification")
        self._notify_thread = threading.Thread(target=run, name="tacoguard-notify", daemon=True)
        self._notify_thread.start()

    def _stop_notify_thread(self) -> None:
        if self._notify_thread is not None and self._notify_thread.is_alive():
            try:
                self._notify_q.put_nowait(None)
            except queue.Full:
                pass
            self._notify_thread.join(5)
        self._notify_thread = None

    # ---- catch-up at start -------------------------------------------------------------------
    def _start_catch_up(self, since: float | None = None) -> None:
        since = self.last_heartbeat_before if since is None else since
        if self._catchup is not None and self._catchup.is_alive():
            return
        part = self.parts["folders"].inst
        if not since or part is None:
            return                              # first start ever, or the folder part is off

        def run():
            try:
                from .folders import recent_files
                files = recent_files(part.roots, since, limit=self.CATCH_UP_LIMIT,
                                     skip=[str(self.settings.root)], max_age_s=self.CATCH_UP_MAX_AGE_S)
                if files and not self._stop_evt.is_set():
                    log.info("Catch-up: %d files changed while the guard was not running", len(files))
                    part.enqueue(files)
            except Exception:
                log.exception("Catch-up failed")

        self._catchup = threading.Thread(target=run, name="tacoguard-catchup", daemon=True)
        self._catchup.start()


# ---- the process ----------------------------------------------------------------------------
def mutex_name(settings) -> str:
    """The real data folder uses Local\\TacoGuardGuard; another data folder (tests, a measurement
    copy) gets its own name, so it never blocks or is blocked by the real guard."""
    from ..config import DEFAULT_DATA_DIR
    if winpath.norm_key(settings.data_dir) == winpath.norm_key(DEFAULT_DATA_DIR):
        return MUTEX_NAME
    return MUTEX_NAME + "-" + hashlib.sha256(winpath.norm_key(settings.data_dir).encode()).hexdigest()[:12]


_mutex = []


def take_mutex(name: str) -> bool:
    """True when this is the only guard (keeps the mutex for the life of the process)."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = ctypes.c_void_p
    k32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
    h = k32.CreateMutexW(None, False, name)
    if not h:
        return True             # Windows refused a mutex: run anyway rather than not protect
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        k32.CloseHandle.argtypes = (ctypes.c_void_p,)
        k32.CloseHandle(h)
        return False
    _mutex.append(h)
    return True


def release_mutex() -> None:
    """Lets a new guard start before this process has fully exited (the page restart)."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CloseHandle.argtypes = (ctypes.c_void_p,)
    while _mutex:
        try:
            k32.CloseHandle(_mutex.pop())
        except Exception:
            pass


def page_launcher_for(settings):
    """The page restart for main(): only the guard of the INSTALLED copy, never while pytest
    runs. None otherwise."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    try:
        from ..selfupdate import running_from_install
        if not running_from_install():
            return None
        from ..config import install_root
        from ..selfprotect import launch_page
    except Exception:
        return None
    root, data = install_root(), str(settings.data_dir)
    return lambda: launch_page(root, data)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tacoguard.guard")
    ap.add_argument("--data", default=None)
    ap.add_argument("--parent", type=int, default=0, help="stop when this process ends")
    args = ap.parse_args(argv)

    from ..config import load_settings
    from ..scan.worker import limit_memory, lower_priority
    from ..store import Store

    settings = load_settings(args.data)
    settings.ensure_dirs()
    if not take_mutex(mutex_name(settings)):
        return EXIT_ALREADY_RUNNING
    lower_priority("below_normal")
    limit_memory(MEMORY_LIMIT)
    try:
        from ..selfprotect import maybe_harden      # only admins may end / change this process
        hardened = maybe_harden(settings, log)
    except Exception:
        hardened = False
    store = Store(settings.db_path)
    guard = Guard(settings, store)
    guard.hardened = hardened
    guard.parent_pid = args.parent or None
    guard.recycle_enabled = bool(args.parent)      # only when a page process will start it again
    if args.parent:
        guard.page_launcher = page_launcher_for(settings)
        if guard.page_launcher is not None:
            from ..config import install_root
            from ..selfupdate import _busy
            guard.update_busy_fn = lambda: _busy(install_root())
    try:
        from . import notify as _notify        # a Windows notification for each new event

        def show(event: dict) -> None:
            _notify.notify_event(event, settings.port)
        guard.notify_fn = show
        guard.notes_fn = getattr(_notify, "off_message", None)
    except Exception:
        guard.notify_fn = None

    def on_signal(signum, frame):
        guard.request_stop("asked to stop")

    for name in ("SIGBREAK", "SIGINT", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, on_signal)
            except (ValueError, OSError):
                pass
    code = 0
    try:
        guard.start()
        if guard.hardened:
            log.info("Self-protection is on: only administrators can end or change this process")
        while not guard.wait(0.5):      # short waits so signals are handled promptly
            pass
    except Exception:
        log.exception("The guard stopped because of an unexpected problem")
        code = 1
    finally:
        try:
            guard.stop()
        except Exception:
            log.exception("The guard did not stop cleanly")
            code = code or 1
        if guard.page_lost and guard.page_launcher is not None:
            release_mutex()             # the new page's guard may start at once
            guard._setup_log()          # stop() closed guard.log
            try:
                guard.restart_page_if_needed()
            except Exception:
                log.exception("Could not start the page again")
            finally:
                guard._close_log()
        store.close()
    if code == 0 and guard.recycle:
        return EXIT_RECYCLE
    return code


if __name__ == "__main__":
    sys.exit(main())
