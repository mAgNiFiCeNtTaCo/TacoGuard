"""RealtimeChecker: checks one file for the guard's parts, and writes guard events.

It reuses the scan engine's check_file (trust lists, clean cache, archives, learning, the
signed-program rule, the lone-weak-ML rule) with the detectors the guard opened once (hash,
YARA, ML). ClamAV is not running normally: only when those checks flag a file (and
settings.realtime_clamav_second_opinion is on and ClamAV is set up) is ClamAV started, the file
checked again with it as well, and ClamAV stopped again after settings.clamav_idle_stop_s with
nothing to do.

Phase 4: a flagged file's fingerprint is asked on MalwareBazaar inside check_file (when lookups
are on and your abuse.ch key is saved); a file MalwareBazaar knows needs no ClamAV second
opinion. While Game mode is on (phase4.game_mode) ClamAV is not started for second opinions.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .. import winpath
from ..allowlist import TrustChecker
from ..model import (CLEAN, MALWARE, SCANNED, SKIPPED, SUSPICIOUS, TRUSTED, UNREADABLE, FileResult,
                     plain_error)
from ..scan import engine, walker

log = logging.getLogger("tacoguard.guard")

DEDUPE_S = 600                 # the same file (path + sha256) is reported once per 10 minutes
TRUST_REFRESH_S = 2.0


def too_big_note(size: int, limit: int) -> str:
    return (f"Bigger than {walker.fmt_size(limit)} ({walker.fmt_size(size)}), the limit for checking new "
            "files right away, so it was not checked. Scan it from the Scan tab to check it.")


def event_title(result: FileResult) -> str:
    short = winpath.short_display(result.path)
    if result.status == SKIPPED:
        return f"Not checked (too big): {short}"
    if result.level == MALWARE:
        return f"Quarantine suggested: {short}"
    return f"Suspicious: {short}"


class RealtimeChecker:
    """check_path(display_path) -> FileResult | None; report(result, kind, extra=None) -> int | None.

    Every check runs on ONE engine thread owned by the checker, whichever part asks: YARA-X's
    scanner may only be used on the thread that created it (another thread gets a Rust panic).
    So detectors are best opened with load() (on that thread), which also closes the old ones.

    `detectors`: first-check detectors that work from any thread (tests' fakes), or [] and then
    load(). A ClamAV detector in the list is taken out and kept (not opened) for second opinions;
    without one, a ClamAVDetector is made when needed."""

    def __init__(self, settings, store, detectors):
        self.settings, self.store = settings, store
        self._engine = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tacoguard-check")
        self._engine_thread = self._engine.submit(threading.current_thread).result()
        self._lock = threading.RLock()         # one check at a time (the guard holds it to swap rules)
        self._clam_lock = threading.Lock()     # starting / stopping ClamAV
        self._clam = None
        self._clam_open = False
        self._clam_last_use = 0.0
        self._clam_timer: threading.Thread | None = None
        self._clam_stop = threading.Event()
        self.clamav_factory = None             # tests: a callable(settings) -> detector
        self.trust = TrustChecker(store)
        self._trust_at = time.monotonic()
        self._reported: dict[tuple[str, str], tuple[float, int]] = {}
        self.checked = 0
        self.in_check = False
        self.set_detectors(detectors)

    # ---- detectors ---------------------------------------------------------------------------
    def set_detectors(self, detectors) -> None:
        """Swap in a new set of (opened) first-check detectors (after a signature update)."""
        first = [d for d in detectors if getattr(d, "name", "") != "clamav"]
        clam = [d for d in detectors if getattr(d, "name", "") == "clamav"]
        with self._lock:
            self.detectors = first
            if clam and not self._clam_open:      # never drop a running clamd
                self._clam = clam[0]
            self.sig_version = "|".join(_version(d) for d in first)

    def call(self, fn, *args):
        """Runs fn(*args) on the engine thread and returns its result (or raises its error)."""
        if threading.current_thread() is self._engine_thread:
            return fn(*args)
        ex = self._engine
        if ex is None:
            raise RuntimeError("the checker was closed")
        return ex.submit(fn, *args).result()

    def load(self, detectors) -> list[str]:
        """Closes the current first-check detectors and opens these instead, all on the engine
        thread. Returns plain notes about the ones that could not start."""
        def swap():
            with self._lock:
                engine.close_detectors(self.detectors)
                first = [d for d in detectors if getattr(d, "name", "") != "clamav"]
                opened, notes = [], []
                for d in first:             # one at a time: a Rust panic in one never drops the others
                    try:
                        o, n = engine.open_detectors([d])
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except BaseException as e:
                        log.error("Opening %s failed", getattr(d, "name", "?"), exc_info=(type(e), e, e.__traceback__))
                        label = engine.DETECTOR_LABELS.get(getattr(d, "name", ""), getattr(d, "name", "A check"))
                        o, n = [], [f"{label} not used: it could not start ({plain_error(e)})."]
                    opened += o
                    notes += n
                self.set_detectors(opened + [d for d in detectors if getattr(d, "name", "") == "clamav"])
                return notes
        return self.call(swap)

    def ready(self) -> bool:
        """False when no opened check can find anything (no signatures installed yet)."""
        return any(engine.has_signatures(d) for d in self.detectors)

    # ---- one file ----------------------------------------------------------------------------
    def check_path(self, display_path: str) -> FileResult | None:
        """Checks one file. None when it is gone, is a folder or a link, or nothing can check it
        yet (no signatures)."""
        display = winpath.to_display(os.path.abspath(winpath.to_display(str(display_path))))
        # check_file also asks MalwareBazaar about a flagged file (engine.add_lookup, Phase 4),
        # here on the engine thread, after the first checks.
        first = self.call(self._check, display)
        if first is None or first.status != SCANNED or first.level == CLEAN:
            return first
        if any(f.engine == "lookup" for f in first.findings):
            return first           # an exact known-malware match: ClamAV can't make it stronger
        clam = self._second_opinion_detector()     # may take a minute: not on the engine thread
        if clam is None:
            return first
        try:
            second = self.call(self._check, display, clam)
        finally:
            self._clam_last_use = time.monotonic()
        return second if second is not None else first

    def _check(self, display: str, extra=None) -> FileResult | None:
        self.in_check = True            # read by the guard's memory recycle (never mid-check)
        try:
            return self._check_inner(display, extra)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:      # e.g. a Rust panic inside a detector: never kill the caller
            log.error("Checking %s failed", display, exc_info=(type(e), e, e.__traceback__))
            return FileResult(path=display, incomplete=True,
                              notes=[f"This file could not be fully checked ({plain_error(e)})."])
        finally:
            self.in_check = False

    def _check_inner(self, display: str, extra=None) -> FileResult | None:
        with self._lock:
            detectors = self.detectors + ([extra] if extra is not None else [])
            if not any(engine.has_signatures(d) for d in detectors):
                return None
            long = winpath.to_long(display)
            try:
                st = os.lstat(long)
            except FileNotFoundError:
                return None
            except OSError as e:
                return FileResult(path=display, status=UNREADABLE, notes=[engine._unreadable_note(e)])
            if os.path.isdir(long) or getattr(st, "st_reparse_tag", 0) in (0xA0000003, 0xA000000C):
                return None                      # a folder, link or junction: not followed
            if winpath.is_cloud_placeholder(st):
                return FileResult(path=display, status=SKIPPED, size=st.st_size, notes=[walker.CLOUD_NOTE])
            limit = int(getattr(self.settings, "realtime_max_file_size", 0) or 0)
            if limit and st.st_size > limit:
                return FileResult(path=display, status=SKIPPED, size=st.st_size,
                                  notes=[too_big_note(st.st_size, limit)])
            if time.monotonic() - self._trust_at > TRUST_REFRESH_S:
                self.trust.refresh()
                self._trust_at = time.monotonic()
            entry = walker.FileEntry(long, display, st, walker.order_key(display))
            try:
                r = engine.check_file(entry, detectors, self.trust, self.settings, self.store,
                                      self.sig_version, throttle=None)
            except MemoryError:
                r = FileResult(path=display, size=st.st_size, notes=[engine.MEMORY_NOTE], incomplete=True)
            self.checked += 1
            return r

    # ---- ClamAV second opinion ---------------------------------------------------------------
    def _second_opinion_detector(self):
        s = self.settings
        if not (getattr(s, "realtime_clamav_second_opinion", True) and getattr(s, "clamav_enabled", True)):
            return None
        if _game_mode_on(self.store):     # Phase 4: no ClamAV while you play or present
            return None
        with self._clam_lock:
            if self._clam_open:
                self._clam_last_use = time.monotonic()
                return self._clam
            try:
                if self._clam is None:
                    if self.clamav_factory is not None:
                        self._clam = self.clamav_factory(s)
                    else:
                        from ..detect.clamav import ClamAVDetector
                        self._clam = ClamAVDetector(s)
                if not self._clam.status().get("ready"):
                    return None
                log.info("Starting ClamAV for a second opinion")
                self._clam.open()
            except Exception as e:
                log.info("ClamAV second opinion not available (%s)", plain_error(e))
                return None
            self._clam_open = True
            self._clam_last_use = time.monotonic()
            self._clam_stop.clear()
            self._clam_timer = threading.Thread(target=self._clam_idle_loop, name="tacoguard-clamav-idle",
                                                daemon=True)
            self._clam_timer.start()
            return self._clam

    def _clam_idle_loop(self) -> None:
        while True:
            idle_s = max(1.0, float(getattr(self.settings, "clamav_idle_stop_s", 600) or 600))
            left = idle_s - (time.monotonic() - self._clam_last_use)
            if left > 0:
                if self._clam_stop.wait(left):
                    return
                continue
            with self._clam_lock:
                with self._lock:             # never in the middle of a check
                    if time.monotonic() - self._clam_last_use < idle_s:
                        continue
                    self._close_clam()
            return

    def _close_clam(self) -> None:
        """Under both locks."""
        if self._clam_open and self._clam is not None:
            log.info("Stopping ClamAV (nothing to check)")
            try:
                self._clam.close()
            except Exception:
                pass
        self._clam_open = False

    @property
    def clamav_running(self) -> bool:
        return self._clam_open

    def close(self) -> None:
        """Stops ClamAV if it runs, closes the first-check detectors (on the engine thread) and
        ends the engine thread. Safe to call twice."""
        self._clam_stop.set()
        with self._clam_lock:
            with self._lock:
                self._close_clam()
        if self._engine is None:
            return
        try:
            def close_all():
                with self._lock:
                    engine.close_detectors(self.detectors)
            self.call(close_all)
        except RuntimeError:
            pass                           # the engine thread was already shut down
        self._engine.shutdown(wait=True)
        self._engine = None

    # ---- events -----------------------------------------------------------------------------
    def report(self, result: FileResult | None, kind: str, extra: dict | None = None) -> int | None:
        """Writes the guard event for a flagged (or too-big, not checked) result and returns its
        id. Clean, trusted and unreadable results write nothing. The same file (path + sha256)
        reported in the last 10 minutes is not written again: the earlier event's id is returned.

        extra (optional): {"title": str, "level": str, "note": sentence added to the message,
        "data": dict for the event, "dedupe": False to always write}."""
        if result is None:
            return None
        extra = extra or {}
        if result.status in (TRUSTED, UNREADABLE):
            return None
        if result.status == SKIPPED:
            level = "info"
        elif result.level in (MALWARE, SUSPICIOUS):
            level = result.level
        else:
            return None
        level = extra.get("level", level)
        key = (result.sha256 or "", winpath.norm_key(result.path))
        now = time.time()
        if extra.get("dedupe", True):
            seen = self._reported.get(key)
            if seen and now - seen[0] < DEDUPE_S:
                return seen[1]
            earlier = self._earlier_event(result, now, waiting=level != MALWARE)
            if earlier:
                self._reported[key] = (now, earlier)
                return earlier
        message = result.reason()
        if extra.get("note"):
            message = f"{message} {extra['note']}"
        event_id = self.store.add_guard_event(
            kind, level, extra.get("title") or event_title(result), message, path=result.path,
            sha256=result.sha256 or "", findings=[f.to_dict() for f in result.findings],
            data=extra.get("data") or {})
        self._reported[key] = (now, event_id)
        if len(self._reported) > 2000:
            cutoff = now - DEDUPE_S
            self._reported = {k: v for k, v in self._reported.items() if v[0] >= cutoff}
        log.info("Event %s (%s): %s", event_id, level, result.path)
        return event_id

    def _earlier_event(self, result: FileResult, now: float, waiting: bool = False) -> int:
        """An event for the same file in the last 10 minutes (also from before a restart). With
        `waiting`, also an older one for the same file that still waits for your answer, so a
        suspicious program you start again doesn't add a second alert (malware always gets a new one)."""
        try:
            sql = ("SELECT id FROM guard_events WHERE path = ? AND sha256 = ? AND (created > ?"
                   + (" OR state IN ('new', 'seen')" if waiting else "") + ") ORDER BY id DESC LIMIT 1")
            row = self.store._con().execute(sql, (result.path, result.sha256 or "", now - DEDUPE_S)).fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0


def _game_mode_on(store) -> bool:
    from .. import phase4
    try:
        return phase4.game_mode(store)["active"]
    except Exception:
        return False


def _version(d) -> str:
    try:
        return str(d.version())
    except Exception:
        return getattr(d, "name", "?") + "-unknown"
