"""ProcessWatcher: the "processes" part. Checks the program file of every newly started program.

Once a second it compares the list of running process ids with the last one (cheap: no handles
are opened for programs it has seen). A new program's file is checked once on a worker thread;
results are cached by path + size + modified time (here and in the clean cache), so a program
started a thousand times is read once. TacoGuard's own processes and Windows' own programs in
C:\\Windows\\System32, SysWOW64 and WinSxS are skipped to keep the CPU use near zero.

A strong "malware" result with settings.pause_malware_processes pauses the program (procctl;
protected programs never), after recording the pause, and writes a "malware" event that says so.
A "suspicious" result only writes an event. A program that already ended is checked anyway (its
file stays), but nothing is paused.

A program TacoGuard already paused (or that you resumed, or that Windows refused to pause) is never
paused a second time and gets no second alert: after a guard restart (also the memory recycle) the
running programs are checked again, and a second pause would need a second Resume.

TEST ONLY: TACOGUARD_TEST_PAUSE_ONLY=<pid,pid,...> limits which programs may be paused
(procctl.pause_allowed); others are reported but not paused, with a log line. The app never sets it.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import OrderedDict

import psutil

from .. import winpath
from ..model import CLEAN, SCANNED, SUSPICIOUS, plain_error
from . import procctl

log = logging.getLogger("tacoguard.guard")

POLL_S = 1.0
OWN_REFRESH_S = 60.0
QUEUE_MAX = 1000
CLEAN_MEMO_MAX = 5000


def _windows_skip_dirs() -> tuple[str, ...]:
    win = os.environ.get("SystemRoot", r"C:\Windows")
    return tuple(winpath.norm_key(os.path.join(win, d)) + "\\" for d in ("System32", "SysWOW64", "WinSxS"))


class ProcessWatcher:
    """start() / stop() / status() -> PART dict.

    own: the set of process ids never to pause (tests pass set()); None = TacoGuard's own
    processes (procctl.tacoguard_pids()), looked up again whenever new programs appear.
    check_running: also check the programs already running when the part starts."""

    def __init__(self, settings, store, checker, own: set[int] | None = None, check_running: bool = True):
        self.settings, self.store, self.checker = settings, store, checker
        self.own = own
        self.check_running = check_running
        self._stop = threading.Event()
        self._queue: queue.Queue = queue.Queue(QUEUE_MAX)
        self._threads: list[threading.Thread] = []
        self._known: set[int] = set()
        self._clean: OrderedDict[str, tuple[int, int]] = OrderedDict()   # norm_key -> (size, mtime_ns)
        self._skip_dirs = _windows_skip_dirs()
        self._own_cache: set[int] | None = None
        self._own_at = 0.0
        self.checked = 0
        self.paused = 0
        self.error = ""

    # ---- part interface ------------------------------------------------------------------
    def start(self) -> None:
        self._stop.clear()
        self.error = ""
        try:
            self._known = set(psutil.pids())
        except Exception:
            self._known = set()
        first = sorted(self._known) if self.check_running else []
        self._threads = [threading.Thread(target=self._poll_loop, args=(first,), name="tacoguard-procs",
                                          daemon=True),
                         threading.Thread(target=self._work_loop, name="tacoguard-procs-check", daemon=True)]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(15)
        self._threads = []

    def status(self) -> dict:
        if self.error:
            return {"state": "error", "message": self.error, "watched": [], "checked": self.checked}
        msg = "Checking each program when it starts."
        if self.settings.pause_malware_processes:
            msg += " A program that looks like malware is paused until you decide."
        ready = getattr(self.checker, "ready", None)
        if callable(ready) and not ready():
            msg = ("Waiting for signatures: programs are not checked until signatures are installed "
                   "(press Get signatures on the Home page).")
        return {"state": "on", "message": msg, "watched": [], "checked": self.checked}

    # ---- finding new programs --------------------------------------------------------------
    def _own(self, fresh: bool = False) -> set[int]:
        """TacoGuard's own pids. procctl.tacoguard_pids() walks the process tree (about 15 ms per
        level: measured 160 ms under a deep chain of parents), so the poll loop uses a copy at
        most OWN_REFRESH_S old; pausing always asks afresh."""
        if self.own is not None:
            return set(self.own)
        now = time.monotonic()
        if fresh or self._own_cache is None or now - self._own_at > OWN_REFRESH_S:
            try:
                engines = self.settings.root / "engines"
            except Exception:
                engines = None
            self._own_cache, self._own_at = procctl.tacoguard_pids(engines_dir=engines), now
        return self._own_cache

    def _resolve(self, pid: int):
        """(ProcRef, exe display path, name) of a running program, or None (ended, no access,
        Windows' own, TacoGuard's own)."""
        try:
            p = psutil.Process(pid)
            ref = procctl.ProcRef(pid, p.create_time())
            exe = p.exe()
            name = p.name()
        except (psutil.Error, OSError, ValueError):
            return None
        exe = winpath.to_display(exe or "")
        if not os.path.isabs(exe):
            return None         # Windows' pseudo programs ("Registry", "MemCompression")
        if winpath.norm_key(exe).startswith(self._skip_dirs):
            return None
        return ref, exe, name

    def _poll_loop(self, first: list[int]) -> None:
        try:
            if first:
                self._queue_new(first)
            while not self._stop.wait(POLL_S):
                try:
                    now = set(psutil.pids())
                except Exception:
                    continue
                new = now - self._known
                self._known = now
                if new:
                    self._queue_new(sorted(new))
        except Exception as e:
            log.exception("The program watcher stopped")
            self.error = f"The program check stopped because of an unexpected problem ({plain_error(e)})."

    def _queue_new(self, pids: list[int]) -> None:
        own = self._own()
        for pid in pids:
            if self._stop.is_set():
                return
            if pid in own or pid in (0, 4):
                continue
            found = self._resolve(pid)
            if found is None:
                continue
            try:
                self._queue.put_nowait(found)
            except queue.Full:
                log.info("Program queue full: skipped %s", found[1])

    # ---- checking ---------------------------------------------------------------------------
    def _work_loop(self) -> None:
        try:
            while not self._stop.is_set():
                item = self._queue.get()
                if item is None:
                    return
                self.handle(*item)
        except Exception as e:
            log.exception("The program checker stopped")
            self.error = f"The program check stopped because of an unexpected problem ({plain_error(e)})."

    def _memo_hit(self, exe: str) -> tuple[str, tuple[int, int] | None]:
        key = winpath.norm_key(exe)
        try:
            st = os.stat(winpath.to_long(exe))
            stamp = (st.st_size, st.st_mtime_ns)
        except OSError:
            return key, None
        return key, stamp

    def handle(self, ref: procctl.ProcRef, exe: str, name: str) -> int | None:
        """Checks one program's file; pauses it / writes the event. Returns the event id."""
        key, stamp = self._memo_hit(exe)
        if stamp is not None and self._clean.get(key) == stamp:
            self._clean.move_to_end(key)
            return None
        r = self.checker.check_path(exe)
        if r is None:
            return None
        self.checked += 1
        if r.status != SCANNED or r.level == CLEAN:
            if r.status == SCANNED and not r.incomplete and stamp is not None:
                self._clean[key] = stamp
                if len(self._clean) > CLEAN_MEMO_MAX:
                    self._clean.popitem(last=False)
            return None
        short = winpath.short_display(r.path)
        data = {"pid": ref.pid, "create_time": ref.create_time}
        if r.level == SUSPICIOUS:
            return self.checker.report(r, "process", {"title": f"Suspicious: {short}", "data": data})
        # MALWARE
        if not procctl.is_alive(ref):
            return self.checker.report(r, "process", {
                "data": data, "note": "The program had already closed when the check finished."})
        if not self.settings.pause_malware_processes:
            return self.checker.report(r, "process", {"data": data})
        return self._pause(r, ref, name, short, data)

    def _known_pause(self, ref) -> dict | None:
        """The paused row TacoGuard already has for this exact program (paused, resumed by you, or
        refused by Windows), newest first; None when there is none."""
        try:
            rows = self.store.list_paused(("paused", "resumed", "not_paused"))
        except Exception:
            return None
        for row in rows:
            if int(row["pid"]) == ref.pid and abs(float(row["create_time"]) - ref.create_time) < 0.01:
                return row
        return None

    def _pause(self, r, ref, name, short, data) -> int | None:
        known = self._known_pause(ref)
        if known is not None:
            # checked again after a guard restart: no second pause, no second alert
            log.info("pid %s was already handled (paused row %s, %s)", ref.pid, known["id"], known["state"])
            return int(known["event_id"] or 0) or None
        own = self._own(fresh=True)
        try:
            why = procctl.protected_reason(psutil.Process(ref.pid), own)
        except psutil.Error:
            why = None
        if why is None and not procctl.pause_allowed(ref.pid):
            log.info("Test limit (TACOGUARD_TEST_PAUSE_ONLY): pid %s is not paused", ref.pid)
            why = "a test setting limits which programs it may pause"
        if why:
            return self.checker.report(r, "process", {
                "data": data, "dedupe": False,
                "note": f"TacoGuard did not pause the program: {why}."})
        if procctl.is_suspended(ref):
            # already paused (not by this guard): record it so you can decide, but no second pause
            event_id = self.checker.report(r, "process", {
                "title": f"Paused: {short} (it looked like malware)", "data": data, "dedupe": False,
                "note": "The program is paused. Choose: Resume, End it, or Quarantine the file."})
            paused_id = self.store.add_paused(ref.pid, ref.create_time, r.path, name, r.reason(),
                                              event_id=event_id or 0)
            if event_id:
                self.store.set_guard_event(event_id, data={**data, "paused_id": paused_id})
            return event_id
        event_id = self.checker.report(r, "process", {
            "title": f"Paused: {short} (it looked like malware)", "data": data, "dedupe": False,
            "note": "TacoGuard paused the program. Choose: Resume, End it, or Quarantine the file."})
        # Recorded BEFORE the pause, so a crash never leaves an unrecorded paused program.
        paused_id = self.store.add_paused(ref.pid, ref.create_time, r.path, name, r.reason(),
                                          event_id=event_id or 0)
        if event_id:
            self.store.set_guard_event(event_id, data={**data, "paused_id": paused_id})
        try:
            procctl.suspend(ref, own)
            self.paused += 1
            log.info("Paused pid %s (%s)", ref.pid, r.path)
        except procctl.ProcError as e:
            gone = not procctl.is_alive(ref)
            self.store.set_paused_state(paused_id, "gone" if gone else "not_paused")
            if event_id:
                self._not_paused(event_id, r, short, str(e))
            log.info("Could not pause pid %s: %s", ref.pid, e)
        except Exception as e:
            gone = not procctl.is_alive(ref)
            self.store.set_paused_state(paused_id, "gone" if gone else "not_paused")
            if event_id:
                self._not_paused(event_id, r, short, f"Windows did not allow it ({plain_error(e)}).")
        return event_id

    def _not_paused(self, event_id: int, r, short: str, why: str) -> None:
        """The event already says "Paused": correct its title and message. (store.py has no
        method to change an event's title, so this one UPDATE is done here.)"""
        title = f"Quarantine suggested: {short} (it could not be paused)"
        message = f"{r.reason()} TacoGuard could not pause the program: {why.rstrip('.')}."
        try:
            self.store._con().execute("UPDATE guard_events SET title=?, message=? WHERE id=?",
                                      (title, message, event_id))
        except Exception:
            log.exception("Could not update event %s", event_id)
