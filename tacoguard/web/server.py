"""The local page: a small JSON API plus the static page, Python standard library only.

Security (the page can quarantine, restore and delete files, so it is locked down):
- listens on 127.0.0.1 only, one instance per port (SO_EXCLUSIVEADDRUSE);
- answers (page included) only programs running as the same Windows user: the connection's
  owner process is looked up in Windows' TCP table, once per connection, as soon as it is
  accepted (before it takes one of the connection slots); other accounts get a quick 403;
- idle connections close after 30 s, and a request's first line and headers must all arrive
  within 10 s; at most 32 connections at once, more get a quick 503;
- refuses any Host other than 127.0.0.1:<port> / localhost:<port> (stops DNS rebinding);
- every /api call needs the per-run token (X-TacoGuard-Token), which only the page itself knows
  (it is written into index.html when served); POSTs also need a same-origin (or absent) Origin,
  a JSON body and at most 1 MB;
- strict Content-Security-Policy (no inline script), no framing, no caching, nosniff.
Errors go to the page as {"error": plain English}; details go to <data>\\logs\\web.log.

Phase 2: the Updates card (updates/updater.py), the app-update offer (selfupdate.py: installed only
from the user's click on "Install update") and learning (learning.py). A Phase 2 module that is
missing gives a calm "not available yet" on the page, never an error.

Phase 3: the page process starts and watches the guard process (GuardSupervisor, only when serve()
asks: never in tests unless a test sets it up on purpose with a fake command), and the Protection
tab: /api/protection plus the user's actions on guard events, paused programs and start-up
entries (the guard never acts on files itself; the page does what the user clicked).

Phase 4 (contract: tacoguard/phase4.py): the Home dashboard (/api/dashboard), pausing protection
and Game mode (/api/protection/pause, /api/gamemode; gamemode.py decides automatic Game mode),
website blocking (/api/webblock: list status, refresh, the hosts file through Windows' admin
prompt on a background thread, one at a time), the abuse.ch key (/api/secrets/abusech: the answer
says only whether a key is set and its last 4 characters; the key is never echoed or logged) and
MalwareBazaar lookups of flagged files (/api/lookup). The tray icon (tray.py) runs in this process
when serve() starts it and settings.tray_enabled. Other helpers' Phase 4 modules (webblock,
lookup, secrets, selfprotect) are imported when first used: a missing one gives a calm "not part
of this copy yet" on the page.
"""
from __future__ import annotations

import ctypes
import hmac
import http.client
import importlib.util
import inspect
import io
import json
import logging
import logging.handlers
import math
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .. import (APP_NAME, __version__, allowlist, autostart, defender, detect, gamemode, learning, phase4,
                quarantine, setup_fetch, winpath)
from ..config import CLAMAV_THREADS_MAX, ENDPOINTS, clamav_thread_count, install_root, load_settings
from ..guard import procctl
from ..model import ENGINE_NAMES, MALWARE, SUSPICIOUS, Confidence, Finding, plain_error
from ..scan import jobs
from ..store import JOB_ACTIVE, Store

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_BODY = 1024 * 1024
CONNECTION_TIMEOUT_S = 30   # per connection: idle keep-alive or slow clients are dropped
HEADER_DEADLINE_S = 10      # a request's first line and headers, all together (slow-drip clients)
MAX_CONNECTIONS = 32        # handler threads at once; more get a quick 503
BUSY_MSG = "TacoGuard's page is busy right now. Try again in a moment."
TOKEN_HEADER = "X-TacoGuard-Token"
TOKEN_PLACEHOLDER = "__TACOGUARD_TOKEN__"

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/favicon.ico": ("icon.svg", "image/svg+xml"),
}
NOT_READY = "This part of TacoGuard is not finished yet."

# Limits the page may change: name -> (kind, minimum, maximum)
EDITABLE_LIMITS = {
    "max_file_size": (int, 1024**2, 64 * 1024**3),
    "archive_max_depth": (int, 0, 10),
    "archive_max_total": (int, 1024**2, 16 * 1024**3),
    "archive_max_entries": (int, 1, 1_000_000),
    "archive_max_ratio": (int, 2, 10_000),
    "archive_member_max": (int, 1024**2, 8 * 1024**3),
    "read_rate_mb_s": (float, 0, 10_000),
}
PRIORITIES = ("idle", "below_normal")

# Phase 2 settings the page may change: on/off switches, and numbers (kind, minimum, maximum)
PHASE2_SWITCHES = {
    "auto_update": "'Check for updates automatically'",
    "ml_enabled": "'Machine-learning check'",
    "learning_enabled": "'Learn from my choices'",
}
PHASE2_NUMBERS = {
    "update_interval_h": (float, 1, 24, "Hours between update checks must be from 1 to 24."),
    "ml_max_file_size": (int, 1024**2, 1024**3,
                         "The largest program the ML check scores must be from 1 to 1024 MB."),
}

# ---- Phase 2 parts built by other modules: imported when first used, so a missing one shows a
# calm "not available yet" on the page instead of breaking it.
UPDATES_NOT_READY = "Automatic updates are not available in this version yet."
SELFUPDATE_NOT_READY = "Updating TacoGuard itself is not available in this version yet."
PROJECT_FOLDER_NOTE = ("This copy of TacoGuard runs from its project folder, so it doesn't update itself. "
                       "Install TacoGuard (python -m tacoguard install) to get app updates with one click.")
REJECTED_MSG = ("An update was refused because it didn't pass TacoGuard's checks (its signature, its "
                "checksum or a test run). TacoGuard kept the last good set.")
UPDATE_COMPONENTS = (("clamav_signatures", "ClamAV signatures"), ("yara_rules", "YARA rules"),
                     ("ml_model", "ML model"), ("web_lists", "Website lists"), ("app", "TacoGuard app"))
REJECTED_STATES = ("rejected",)      # "expired" (an out-of-date signed list) is calm: no banner
OFFER_TTL_S = 60
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
_ML_SCORE_RE = re.compile(r"score\s+(\d+(?:\.\d+)?)", re.I)


def _load_updater_module():
    from ..updates import updater
    return updater


def _load_selfupdate():
    from .. import selfupdate
    return selfupdate


def _load_signed():
    from ..updates import signed
    return signed


# ---- Phase 3: real-time protection (contract: tacoguard/guard/__init__.py) ----------------------
PHASE3_SWITCHES = {
    "realtime_enabled": "'Real-time protection'",
    "start_at_sign_in": "'Start TacoGuard when I sign in'",
    "watch_processes": "'Check newly started programs'",
    "pause_malware_processes": "'Pause a program found to be malware'",
    "ransomware_guard": "'Ransomware guard'",
    "ransomware_pause": "'Pause programs that change a decoy file'",
    "persistence_watch": "'Report new start-up entries'",
    "realtime_clamav_second_opinion": "'Ask ClamAV for a second opinion'",
}
PHASE3_FOLDER_LISTS = {"watch_folders": "Watched folders", "canary_folders": "Decoy folders"}
PHASE3_MAX_FOLDERS = 50
REALTIME_MAX_FILE = (1024**2, 4 * 1024**3,
                     "The largest new file real-time protection checks must be from 1 to 4096 MB.")
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
GUARD_BACKOFF_S = (5, 30, 120)       # wait before restarting after the 1st, 2nd, 3rd+ crash
GUARD_EXIT_RECYCLE = 75              # guard/service.py EXIT_RECYCLE: restart at once, not a crash
GUARD_MAX_CRASHES = 5                # ... this many crashes within GUARD_CRASH_WINDOW_S: give up
GUARD_CRASH_WINDOW_S = 600
GUARD_STOP_WAIT_S = 5.0
GUARD_FRESH_S = 35                   # the guard writes its heartbeat every 10 s
GUARD_HUNG_S = 90                    # our guard runs but wrote no heartbeat for this long: it hangs
GUARD_POLL_S = 2.0                   # how often the page looks whether its guard still runs
PROTECTION_EVENTS = 100
GUARD_NOT_READY = "Real-time protection isn't part of this copy of TacoGuard yet."
STILL_CLOSING_MSG = ("Real-time protection is still closing. If it doesn't, restart Windows or end it from "
                     "Task Manager as administrator.")
PERSISTENCE_NOT_READY = "Start-up entry actions aren't available in this copy of TacoGuard yet."
PART_LABELS = (("folders", "New and changed files"), ("processes", "Newly started programs"),
               ("ransomware", "Ransomware decoys"), ("persistence", "Start-up entries"))
WEB_PART = ("web", "Bad websites")      # Phase 4 (webblock/watch.py), when the guard has it
CFA_ON_NOTE = ("Controlled folder access is on, so Windows may block TacoGuard from making its decoy files "
               "in protected folders such as Documents and Pictures. If Windows Security says it blocked "
               "pythonw.exe or python.exe, you can allow it there (Ransomware protection > Allow an app "
               "through Controlled folder access). TacoGuard never changes this setting itself.")


def _load_persistence():
    from ..guard import persistence
    return persistence


def _load_guard_folders():
    from ..guard import folders
    return folders


# ---- Phase 4: web blocking, lookups, tray, Game mode, self-protection (contract: phase4.py) ------
PHASE4_SWITCHES = {
    "webblock_enabled": "'Website blocking'",
    "webblock_phishing_list": "'Phishing website list'",
    "webblock_urlhaus_list": "'URLhaus malware website list'",
    "webblock_hosts": "'Block in every browser (hosts file)'",
    "lookup_enabled": "'MalwareBazaar lookups'",
    "tray_enabled": "'TacoGuard icon in the taskbar'",
    "game_mode_auto": "'Game mode by itself'",
    "self_protection": "'Self-protection'",
}
HOSTS_EVERY_DAYS = (1, 30, "TacoGuard can offer a hosts file update every 1 to 30 days.")
WEB_ALLOW_MAX = 500
HOSTS_REMOVE_OFFER = ("TacoGuard's block is still in Windows' hosts file. Take it out with 'Remove "
                      "TacoGuard's block' (one administrator prompt), or it keeps blocking those sites.")
PAUSE_MAX_MIN = 24 * 60
WEBBLOCK_NOT_READY = "Website blocking isn't part of this copy of TacoGuard yet."
HOSTS_NOT_READY = "Blocking in the hosts file isn't part of this copy of TacoGuard yet."
LOOKUP_NOT_READY = "MalwareBazaar lookups aren't part of this copy of TacoGuard yet."
SECRETS_NOT_READY = "Saving an abuse.ch key isn't part of this copy of TacoGuard yet."
KEY_BAD_MSG = ("That doesn't look like an abuse.ch key. Copy the Auth-Key from your account page on "
               "auth.abuse.ch and paste it again.")
KEY_SAVE_FAILED = "Windows could not save the key safely, so it was not saved. Try again."
ABUSECH = "abusech"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FLAGGED_LEVELS = (MALWARE, SUSPICIOUS)
SECRET_PATH_PREFIX = "/api/secrets/"
HOSTS_ACTIONS = {"apply": "apply_elevated", "remove": "remove_elevated"}


def _load_webblock_lists():
    from ..webblock import lists
    return lists


def _load_webblock_hosts():
    from ..webblock import hosts
    return hosts


def _load_lookup():
    from .. import lookup
    return lookup


def _load_secrets():
    from .. import secrets as tg_secrets      # TacoGuard's own key store, not Python's `secrets`
    return tg_secrets


def _load_selfprotect():
    from .. import selfprotect
    return selfprotect


def _load_tray():
    from .. import tray
    return tray


def _simple(value, depth: int = 0):
    """A copy of another module's status answer with only plain values (str, numbers, bools,
    short lists, small dicts), so nothing odd reaches the page."""
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, str):
        return value[:2000]
    if depth < 3 and isinstance(value, (list, tuple)):
        return [_simple(v, depth + 1) for v in list(value)[:50]]
    if depth < 3 and isinstance(value, dict):
        return {str(k)[:100]: _simple(v, depth + 1) for k, v in list(value.items())[:50]}
    return str(value)[:200]


def guard_command(settings, parent_pid: int) -> list[str] | None:
    """`python -m tacoguard.guard --data DIR --parent PID`, or None when this copy has no guard."""
    try:
        if importlib.util.find_spec("tacoguard.guard.__main__") is None:
            return None
    except (ImportError, ValueError):
        return None
    return [sys.executable, "-m", "tacoguard.guard", "--data", str(settings.data_dir),
            "--parent", str(int(parent_pid))]


def read_guard_state(store) -> dict:
    """meta "guard_state" (the guard's heartbeat), {} when missing or damaged."""
    try:
        if hasattr(store, "get_meta"):
            raw = store.get_meta("guard_state")
        else:
            row = store._one("SELECT value FROM meta WHERE key='guard_state'")
            raw = row["value"] if row else None
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _pid_exists(pid) -> bool:
    try:
        import psutil
        return int(pid) > 0 and psutil.pid_exists(int(pid))
    except Exception:
        return False


def _guard_process(pid):
    """The running guard process with this pid (its command line names tacoguard.guard), or None."""
    try:
        import psutil
        p = psutil.Process(int(pid))
        if "tacoguard.guard" in " ".join(p.cmdline()).lower():
            return p
    except Exception:
        pass
    return None


def _kill_tree(proc) -> None:
    """End a guard process WE started and everything it started (the venv's python.exe is a
    launcher: the real guard is its child)."""
    try:
        import psutil
        kids = psutil.Process(proc.pid).children(recursive=True)
    except Exception:
        kids = []
    for k in kids:
        try:
            k.kill()
        except Exception:
            pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        pass


def _wait_words(seconds: float) -> str:
    s = int(round(seconds))
    return f"{s} seconds" if s < 60 else (f"{s // 60} minute" + ("s" if s >= 120 else ""))


class GuardSupervisor:
    """Starts the guard process, restarts it after a crash (5 s, 30 s, 2 min), gives up after 5
    crashes in 10 minutes (with a plain note), adopts a guard that already runs (fresh heartbeat
    and pid alive with tacoguard.guard in its command line) and stops it cleanly: the "stop"
    file in settings.guard_dir, up to 5 s, then it is ended. One small thread that wakes every
    GUARD_POLL_S seconds (or at once when settings change)."""

    def __init__(self, app: "App"):
        self.app = app
        self.settings = app.settings
        self.command = guard_command          # (settings, parent_pid) -> list | None (tests: a fake)
        self.backoff = GUARD_BACKOFF_S
        self.max_crashes, self.window = GUARD_MAX_CRASHES, GUARD_CRASH_WINDOW_S
        self.stop_wait, self.poll_s, self.fresh_s = GUARD_STOP_WAIT_S, GUARD_POLL_S, GUARD_FRESH_S
        self.hung_s = GUARD_HUNG_S
        self.proc: subprocess.Popen | None = None
        self.proc_started = 0.0
        self.adopted = None                   # psutil.Process of a guard we found running
        self.crashes: list[float] = []
        self.gave_up = False
        self.unavailable = False
        self.next_start = 0.0
        self.starts = 0
        self.message = ""
        self.stop_note = ""                   # an adopted guard that could not be ended (STILL_CLOSING_MSG)
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._closing = False
        self._thread: threading.Thread | None = None

    # ---- control ------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="tacoguard-guard-watch", daemon=True)
            self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def close(self) -> None:
        self._closing = True
        self._wake.set()
        if self._thread is not None:
            self._thread.join(self.stop_wait + 5)
        with self._lock:
            self._stop_guard()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running()

    def pid(self) -> int | None:
        with self._lock:
            if self.proc is not None and self.proc.poll() is None:
                return self.proc.pid
            if self.adopted is not None:
                return self.adopted.pid
        return None

    # ---- the watch loop ---------------------------------------------------------------------
    def _loop(self) -> None:
        while not self._closing:
            try:
                self.step()
            except Exception:
                self.app.log.error("guard supervision failed\n%s", traceback.format_exc())
            self._wake.wait(self.poll_s)
            self._wake.clear()

    def step(self) -> None:
        """One look: start, restart, adopt or stop the guard as settings.realtime_enabled says."""
        with self._lock:
            if self._closing:
                return
            if not self.settings.realtime_enabled:
                if self._running():
                    self._stop_guard()
                elif self.stop_note and not _guard_process(read_guard_state(self.app.store).get("pid") or 0):
                    self.stop_note = ""           # the guard that was still closing has gone
                self.crashes.clear()
                self.gave_up = self.unavailable = False
                self.message, self.next_start = "", 0.0
                return
            self.stop_note = ""
            if self.adopted is not None:
                if self._adopted_alive():
                    return
                self.adopted = None           # it ended (its own page went away): start ours
            if self.proc is not None:
                rc = self.proc.poll()
                if rc is None:
                    if not self._hung():
                        return
                    self.app.log.error("the guard wrote no heartbeat for over %s s; ending it", self.hung_s)
                    _kill_tree(self.proc)
                    rc = "hung"
                self.proc = None
                if rc == GUARD_EXIT_RECYCLE:      # it gave its memory back: start a fresh one now
                    self.app.log.info("the guard restarted itself to give back memory")
                    self.next_start = 0.0
                else:
                    self._crashed(rc)
            if self.gave_up or self.unavailable or time.time() < self.next_start:
                return
            found = self._find_running_guard()
            if found is not None:
                self.adopted = found
                self.app.log.info("adopted the guard that was already running (pid %s)", found.pid)
                return
            self._launch()

    def _hung(self) -> bool:
        """Our own guard runs, started over hung_s ago, but its last heartbeat is older than
        hung_s: something inside it stopped (the control loop writes it every 10 s)."""
        now = time.time()
        if not self.proc_started or now - self.proc_started < self.hung_s:
            return False
        try:
            hb = float(read_guard_state(self.app.store).get("heartbeat") or 0)
        except (TypeError, ValueError):
            hb = 0.0
        return now - max(hb, self.proc_started) > self.hung_s

    def _running(self) -> bool:
        return (self.proc is not None and self.proc.poll() is None) or \
            (self.adopted is not None and self._adopted_alive())

    def _adopted_alive(self) -> bool:
        try:
            return self.adopted.is_running() and self.adopted.status() != "zombie"
        except Exception:
            return False

    def _find_running_guard(self):
        st = read_guard_state(self.app.store)
        try:
            fresh = time.time() - float(st.get("heartbeat") or 0) < self.fresh_s
        except (TypeError, ValueError):
            fresh = False
        if not fresh or not st.get("pid"):
            return None
        return _guard_process(st["pid"])

    def _crashed(self, rc) -> None:
        now = time.time()
        self.crashes = [t for t in self.crashes if now - t < self.window] + [now]
        n = len(self.crashes)
        self.app.log.error("the guard process stopped unexpectedly (exit code %s, %d in %d s)", rc, n,
                           self.window)
        if n >= self.max_crashes:
            self.gave_up = True
            self.message = (f"Real-time protection stopped unexpectedly {n} times in {self.window // 60} "
                            "minutes, so TacoGuard stopped restarting it. Details are in "
                            f"{self.settings.log_dir}. Switch real-time protection off and on in Settings, "
                            "or restart TacoGuard, to try again.")
            return
        delay = self.backoff[min(n - 1, len(self.backoff) - 1)]
        self.next_start = now + delay
        self.message = (f"Real-time protection stopped unexpectedly. TacoGuard starts it again in "
                        f"{_wait_words(delay)}.")

    def _console_log(self):
        try:
            self.settings.log_dir.mkdir(parents=True, exist_ok=True)
            path = self.settings.log_dir / "guard-console.log"
            if path.is_file() and path.stat().st_size > 1024**2:
                os.replace(path, path.with_name(path.name + ".1"))
            return open(path, "ab")
        except OSError:
            return None

    def _launch(self) -> None:
        cmd = self.command(self.settings, os.getpid())
        if not cmd:
            self.unavailable = True
            self.message = GUARD_NOT_READY
            return
        stop = self.settings.guard_dir / "stop"
        try:
            stop.unlink(missing_ok=True)      # a stop request left over from last time
        except OSError:
            pass
        out = self._console_log()
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=str(PROJECT_ROOT), stdin=subprocess.DEVNULL,
                stdout=out if out is not None else subprocess.DEVNULL, stderr=subprocess.STDOUT,
                close_fds=True, creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
            self.starts += 1
            self.proc_started = time.time()
            self.app.log.info("started the guard (pid %s)", self.proc.pid)
        except OSError:
            self.app.log.error("could not start the guard\n%s", traceback.format_exc())
            self.proc = None
            self._crashed("not started")
        finally:
            if out is not None:
                out.close()

    def _stop_guard(self) -> None:
        """Ask the guard to stop (the stop file), wait up to stop_wait, then end it."""
        proc, adopted = self.proc, self.adopted
        self.proc = self.adopted = None
        if proc is None and adopted is None:
            return
        stop = self.settings.guard_dir / "stop"
        try:
            stop.parent.mkdir(parents=True, exist_ok=True)
            stop.write_text("stop\n", encoding="utf-8")
        except OSError:
            pass
        try:
            if proc is not None and proc.poll() is None:
                try:
                    proc.wait(self.stop_wait)
                except subprocess.TimeoutExpired:
                    self.app.log.info("the guard did not stop within %s s; ending it", self.stop_wait)
                    _kill_tree(proc)
            if adopted is not None:
                try:
                    adopted.wait(self.stop_wait)
                except Exception:
                    # A guard this page didn't start is protected by self-protection: Windows refuses
                    # to end it without admin rights. One try, never a loop; then a plain note.
                    try:
                        adopted.kill()
                    except Exception:
                        self.app.log.info("the adopted guard (pid %s) did not stop within %s s and could "
                                          "not be ended", getattr(adopted, "pid", "?"), self.stop_wait)
                        self.stop_note = STILL_CLOSING_MSG
        finally:
            try:
                stop.unlink(missing_ok=True)
            except OSError:
                pass


def _event_for_page(e: dict) -> dict:
    return _result_for_page(e)        # adds "short", "ml_score", "signature_match"


def _findings_reason(findings: list[dict]) -> str:
    """"Matched YARA rule 'X' (source, high confidence) and the ML score was 0.97"."""
    sig = [f for f in findings or [] if f.get("engine") != "ml"]
    score = None
    for f in findings or []:
        if f.get("engine") == "ml":
            m = _ML_SCORE_RE.search(str(f.get("detail") or ""))
            if m:
                score = m.group(1)
    parts = ""
    if sig:
        top = max(sig, key=lambda f: int(f.get("confidence") or 1))
        try:
            word = Confidence(int(top.get("confidence") or 1)).word
        except ValueError:
            word = "low"
        parts = (f"Matched {ENGINE_NAMES.get(top.get('engine'), top.get('engine'))} '{top.get('rule')}' "
                 f"({top.get('source') or 'unknown source'}, {word} confidence)")
        if len(sig) > 1:
            parts += f" and {len(sig) - 1} more"
        if score:
            parts += f" and the ML score was {score}"
    elif score:
        parts = f"ML score {score}, no signature match"
    return parts


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
def _short(path: str) -> str:
    try:
        return winpath.short_display(path or "")
    except Exception:
        return path or ""


def _known_folder(guid: str) -> str | None:
    """Real location of a Windows known folder (Downloads may have been moved), else None."""
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort), ("d3", ctypes.c_ushort),
                        ("d4", ctypes.c_ubyte * 8)]
        g = GUID()
        ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(g))
        out = ctypes.c_wchar_p()
        ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out))
        value = out.value
        ctypes.windll.ole32.CoTaskMemFree(out)
        return value or None
    except Exception:
        return None


KNOWN_FOLDERS = [
    ("Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"),
    ("Desktop", "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"),
    ("Documents", "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"),
]
# The default decoy folders (Phase 3; the user's choice 2026-11-24). Never inside OneDrive.
CANARY_KNOWN_FOLDERS = [
    ("Documents", "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"),
    ("Desktop", "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"),
    ("Pictures", "{33E28130-4E1E-4676-835A-98395C3BC3BB}"),
    ("Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"),
]


def _in_onedrive(path: str) -> bool:
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(var)
        if root:
            try:
                if winpath.is_under(path, winpath.norm_key(root)):
                    return True
            except (OSError, ValueError):
                pass
    return False


def quick_picks() -> list[dict]:
    picks, seen = [], set()

    def add(label, path, kind):
        if not path:
            return
        try:
            if not os.path.isdir(winpath.to_long(path)):
                return
            key = winpath.norm_key(path)
        except (OSError, ValueError):
            return
        if key in seen:
            return
        seen.add(key)
        picks.append({"label": label, "path": winpath.to_display(path), "kind": kind})

    drives = list_drives()
    for d in drives:                      # e.g. D:\Downloads, where many browsers are pointed
        add(f"Downloads ({d['path'][:2]})", os.path.join(d["path"], "Downloads"), "folder")
    home = os.path.expanduser("~")
    for name, guid in KNOWN_FOLDERS:
        add(name, _known_folder(guid) or os.path.join(home, name), "folder")
    for d in drives:
        add(f"Drive {d['path'][:2]}", d["path"], "drive")
    return picks


def list_drives() -> list[dict]:
    try:
        drives = os.listdrives()
    except (AttributeError, OSError):
        drives = [f"{c}:\\" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
    out = []
    for d in drives:
        try:
            if os.path.exists(d):
                out.append({"name": d.rstrip("\\"), "path": d})
        except OSError:
            pass
    return out


def browse(path: str) -> dict:
    path = (path or "").strip().strip('"')
    if not path:
        return {"path": "", "parent": None, "folders": list_drives(), "drives": True,
                "quick": quick_picks()}
    if len(path) > 32000:
        raise ApiError(400, "That path is too long.")
    disp = winpath.to_display(path)
    if re.fullmatch(r"[A-Za-z]:", disp):
        disp += "\\"
    disp = winpath.to_display(os.path.abspath(disp))
    long = winpath.to_long(disp)
    if not os.path.exists(long):
        raise ApiError(404, f"Folder not found: {disp}")
    if not os.path.isdir(long):
        raise ApiError(400, f"That is a file, not a folder: {disp}")
    folders, hidden_errors = [], 0
    try:
        with os.scandir(long) as it:
            for e in it:
                try:
                    if not e.is_dir(follow_symlinks=False):
                        continue
                    st = e.stat(follow_symlinks=False)
                    if winpath.is_reparse(st):       # junctions like "Documents and Settings"
                        continue
                except OSError:
                    hidden_errors += 1
                    continue
                folders.append({"name": e.name, "path": os.path.join(disp, e.name)})
                if len(folders) >= 5000:
                    break
    except PermissionError:
        raise ApiError(403, f"Windows doesn't allow TacoGuard to open this folder: {disp}")
    except OSError as e:
        raise ApiError(400, f"Could not open this folder ({e.strerror or e}): {disp}")
    folders.sort(key=lambda f: f["name"].casefold())
    parent = os.path.dirname(disp.rstrip("\\")) if len(disp) > 3 else ""
    if parent and len(parent) == 2:
        parent += "\\"
    return {"path": disp, "parent": parent, "folders": folders, "drives": False,
            "skipped": hidden_errors}


def _plain(md: str) -> str:
    return re.sub(r"\*\*|`", "", md).strip()


def read_licenses(path: Path | None = None) -> list[dict]:
    """THIRD_PARTY_LICENSES.md as sections for the Settings page:
    [{"name": heading, "blocks": [{"type": "p", "text"} | {"type": "table", "header", "rows"}]}]"""
    p = path or PROJECT_ROOT / "THIRD_PARTY_LICENSES.md"
    if not p.is_file():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    sections: list[dict] = []
    cur = {"name": "About", "blocks": []}
    para: list[str] = []
    table: dict | None = None

    def flush_para():
        if para:
            cur["blocks"].append({"type": "p", "text": _plain(" ".join(para))})
            para.clear()

    for line in lines + [""]:
        s = line.strip()
        if s.startswith("|"):
            flush_para()
            cells = [_plain(c) for c in s.strip("|").split("|")]
            if table is None:
                table = {"type": "table", "header": cells, "rows": []}
                cur["blocks"].append(table)
            elif not all(re.fullmatch(r":?-{2,}:?", c.replace(" ", "")) for c in cells):
                table["rows"].append(cells)
            continue
        table = None
        m = re.match(r"^(#{1,4})\s+(.*)", s)
        if m:
            flush_para()
            if len(m.group(1)) == 1:
                continue                      # the document title
            if cur["blocks"]:
                sections.append(cur)
            cur = {"name": _plain(m.group(2)), "blocks": []}
        elif not s:
            flush_para()
        else:
            para.append(s)
    flush_para()
    if cur["blocks"]:
        sections.append(cur)
    return sections


def _result_for_page(r: dict) -> dict:
    r = dict(r)
    r["short"] = _short(r.get("path", ""))
    r["ml_score"], r["signature_match"] = None, False
    for f in r.get("findings") or []:
        f.setdefault("member", "")
        if f.get("engine") == "ml":
            m = _ML_SCORE_RE.search(str(f.get("detail") or ""))
            if m and r["ml_score"] is None:
                r["ml_score"] = float(m.group(1))
        else:
            r["signature_match"] = True
    return r


def _job_for_page(j: dict | None) -> dict | None:
    if not j:
        return None
    j = dict(j)
    j["short_targets"] = [_short(t) for t in j.get("targets") or []]
    j["current_short"] = _short(j.get("current") or "")
    j.pop("pid", None)
    return j


# ---------------------------------------------------------------------------------------------
# who is on the other end of a connection
# ---------------------------------------------------------------------------------------------
# The page holds the key to the API (it can quarantine, restore and delete), and 127.0.0.1 is
# reachable by every program and every Windows account on this PC. So every connection must
# come from a program running as the same Windows user as the server.
OTHER_USER_MSG = ("Refused: TacoGuard's page only answers programs running under your own "
                  "Windows account.")


class _TcpRow(ctypes.Structure):          # MIB_TCPROW_OWNER_PID
    _fields_ = [("state", ctypes.c_uint32), ("local_addr", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32), ("remote_addr", ctypes.c_uint32),
                ("remote_port", ctypes.c_uint32), ("pid", ctypes.c_uint32)]


def tcp_owner_pid(local: tuple[str, int], remote: tuple[str, int]) -> int | None:
    """Process id that owns the IPv4 TCP connection local -> remote, from Windows' own table
    (GetExtendedTcpTable, about a millisecond). None when there is no such connection."""
    want = (socket.inet_aton(local[0]), int(local[1]), socket.inet_aton(remote[0]), int(remote[1]))
    iphlp = ctypes.WinDLL("iphlpapi")
    size = ctypes.c_uint32(64 * 1024)
    for _ in range(5):
        buf = ctypes.create_string_buffer(size.value)
        # AF_INET = 2, TCP_TABLE_OWNER_PID_CONNECTIONS = 4
        rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 4, 0)
        if rc == 0:
            break
        if rc != 122:                     # ERROR_INSUFFICIENT_BUFFER: size was updated, retry
            return None
    else:
        return None
    count = ctypes.c_uint32.from_buffer(buf).value
    rows = (_TcpRow * count).from_buffer(buf, ctypes.sizeof(ctypes.c_uint32))
    for row in rows:
        if (row.local_addr.to_bytes(4, "little") == want[0]
                and socket.ntohs(row.local_port & 0xFFFF) == want[1]
                and row.remote_addr.to_bytes(4, "little") == want[2]
                and socket.ntohs(row.remote_port & 0xFFFF) == want[3]):
            return int(row.pid)
    return None


UNCONFIRMED_MSG = ("TacoGuard could not confirm this browser belongs to your Windows account. If you "
                   "run your browser as administrator, open TacoGuard's page in a normal browser window.")


def process_user(pid: int) -> str | None:
    """'DOMAIN\\user' that a process runs as; None when Windows won't say (another account's
    process usually can't be opened, an elevated one may refuse) or the process is gone."""
    try:
        import psutil
        return psutil.Process(pid).username()
    except Exception:
        return None


def process_sid(pid: int) -> str | None:
    """The Windows account (SID, like 'S-1-5-21-...') a process runs as, read straight from its
    token with the smallest rights Windows offers. Used when process_user() is refused. None
    when this fails too."""
    try:
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        process = k32.OpenProcess(0x1000, False, int(pid))   # PROCESS_QUERY_LIMITED_INFORMATION
        if not process:
            return None
        try:
            token = wintypes.HANDLE()
            if not adv.OpenProcessToken(process, 0x0008, ctypes.byref(token)):   # TOKEN_QUERY
                return None
            try:
                size = wintypes.DWORD(0)
                adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))   # 1 = TokenUser
                if not size.value:
                    return None
                buf = ctypes.create_string_buffer(size.value)
                if not adv.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
                    return None
                sid = ctypes.c_void_p.from_buffer(buf).value   # TOKEN_USER starts with the SID pointer
                text = wintypes.LPWSTR()
                if not adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                    return None
                try:
                    return text.value or None
                finally:
                    k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            finally:
                k32.CloseHandle(token)
        finally:
            k32.CloseHandle(process)
    except Exception:
        return None


# Our own account, looked up once it is known (a failed lookup is tried again next time).
_mine: dict[str, str] = {}


def my_user() -> str | None:
    if "user" not in _mine:
        user = process_user(os.getpid())
        if user:
            _mine["user"] = user
    return _mine.get("user")


def my_sid() -> str | None:
    if "sid" not in _mine:
        sid = process_sid(os.getpid())
        if sid:
            _mine["sid"] = sid
    return _mine.get("sid")


SAME, OTHER, UNCONFIRMED = "same", "other", "unconfirmed"


def client_verdict(client: tuple[str, int], server: tuple[str, int], *, find_pid=tcp_owner_pid,
                   user_of=process_user, sid_of=process_sid, me=None, me_sid=None) -> str:
    """Who is at the other end of this connection: SAME Windows user as TacoGuard, OTHER (a
    different account, or no such connection) or UNCONFIRMED (its account could not be read,
    for example a browser run as administrator)."""
    try:
        pid = find_pid(client, server)
    except Exception:
        return OTHER
    if not pid:
        return OTHER
    if pid == os.getpid():
        return SAME
    mine = me if me is not None else my_user()
    theirs = user_of(pid)
    if mine and theirs:
        return SAME if theirs.casefold() == mine.casefold() else OTHER
    mine_sid = me_sid if me_sid is not None else my_sid()
    theirs_sid = sid_of(pid)
    if mine_sid and theirs_sid:
        return SAME if theirs_sid.upper() == mine_sid.upper() else OTHER
    return UNCONFIRMED


def same_user_client(client: tuple[str, int], server: tuple[str, int], **kw) -> bool:
    """True only when the program at the other end of this connection is known to run as the
    same Windows user as TacoGuard. Unknown process, unreadable user -> False."""
    return client_verdict(client, server, **kw) == SAME


# ---------------------------------------------------------------------------------------------
# the application (state shared by all requests)
# ---------------------------------------------------------------------------------------------
class App:
    def __init__(self, settings, token: str | None = None):
        self.settings = settings
        self.store = Store(settings.db_path)
        self.token = token or secrets.token_urlsafe(32)
        self.notes: list[str] = []
        self.port = settings.port
        self.server: "TacoServer | None" = None
        self.setup_lock = threading.Lock()
        self.setup_state = {"running": False, "lines": [], "result": None, "started": 0.0,
                            "finished": 0.0, "error": ""}
        # Phase 2: updates (updates/updater.py) and self-update (selfupdate.py)
        self.updater = None
        self.updater_running = False
        self.manage_updates = False        # True once serve() started the updates (never in tests)
        self.update_lock = threading.Lock()
        self.update_check = {"running": False, "started": 0.0, "finished": 0.0, "error": ""}
        self.app_action_lock = threading.Lock()
        self.app_action = {"running": False, "what": "", "message": "", "error": "", "finished": 0.0}
        self._offer: tuple[float, dict | None] = (0.0, None)
        self.log = self._make_logger()
        self.static = self._load_static()
        # Phase 3: the guard process (started only by serve(); tests set a fake command first)
        self.manage_guard = False
        self.guard = GuardSupervisor(self)
        self.autostart_key: str | None = None   # tests: a key under HKCU\Software\TacoGuardTest
        # Phase 4: tray icon and automatic Game mode (started only by serve()), web blocking actions
        self.manage_tray = False
        self.tray = None
        self.tray_note = ""
        self.gamemode = gamemode.GameModeWatcher(settings, self.store, log=self.log)
        self.manage_gamemode = False
        self.hardened: bool | None = None       # self-protection result in this process (None = not tried)
        self.web_lock = threading.Lock()
        self.hosts_action = {"running": False, "what": "", "message": "", "error": "", "started": 0.0,
                             "finished": 0.0, "ok": False}
        self.lists_action = {"running": False, "message": "", "error": "", "started": 0.0, "finished": 0.0}

    def _make_logger(self) -> logging.Logger:
        log = logging.getLogger(f"tacoguard.web.{id(self)}")
        log.setLevel(logging.INFO)
        log.propagate = False
        try:
            self.settings.log_dir.mkdir(parents=True, exist_ok=True)
            h = logging.handlers.RotatingFileHandler(self.settings.log_dir / "web.log",
                                                     maxBytes=1024**2, backupCount=3, encoding="utf-8")
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            log.addHandler(h)
        except OSError:
            log.addHandler(logging.NullHandler())
        return log

    def close(self) -> None:
        self.stop_tray()
        try:
            self.gamemode.stop()
        except Exception:
            self.log.error("stopping Game mode detection failed\n%s", traceback.format_exc())
        try:
            self.guard.close()
        except Exception:
            self.log.error("stopping the guard failed\n%s", traceback.format_exc())
        self.stop_updates()
        for h in list(self.log.handlers):
            h.close()
            self.log.removeHandler(h)
        self.store.close()

    def _load_static(self) -> dict:
        files = {}
        for name in {v[0] for v in STATIC_FILES.values()}:
            files[name] = (STATIC_DIR / name).read_bytes()
        files["index.html"] = files["index.html"].replace(TOKEN_PLACEHOLDER.encode(), self.token.encode())
        return files

    # ---- start-up --------------------------------------------------------------------------
    def startup(self) -> None:
        """Tidy up after a crash: interrupted scans and half-done quarantine operations."""
        try:
            ids = jobs.recover_interrupted(self.store) or []
            if ids:
                n = len(ids)
                self.notes.append(f"{n} scan{'s were' if n > 1 else ' was'} cut off when TacoGuard last "
                                  "closed. You can resume from the Scan tab.")
        except NotImplementedError:
            self.notes.append("Could not look for scans cut off last time: the scan part of TacoGuard "
                              "is not finished yet.")
        except Exception:
            self.log.error("recover_interrupted failed\n%s", traceback.format_exc())
            self.notes.append("Could not look for scans cut off last time. Details are in the log.")
        try:
            for note in self.quarantine().recover() or []:
                self.notes.append(str(note))
        except NotImplementedError:
            self.notes.append("Quarantine is not ready yet: the quarantine part of TacoGuard is not "
                              "finished yet.")
        except Exception:
            self.log.error("quarantine recover failed\n%s", traceback.format_exc())
            self.notes.append("Could not check the quarantine for unfinished work. Details are in the log.")
        self.sync_learning()

    def sync_learning(self) -> None:
        """Your own known-bad list follows your verdicts (learning.py). Never raises."""
        try:
            learning.sync_confirmed_list(self.store, self.settings)
        except Exception:
            self.log.error("learning sync failed\n%s", traceback.format_exc())

    # ---- updates (Phase 2) ---------------------------------------------------------------
    def _optional(self, loader):
        """A Phase 2 module, or None when it is not there (yet)."""
        try:
            return loader()
        except ImportError:
            return None
        except Exception:
            self.log.error("could not load a module\n%s", traceback.format_exc())
            return None

    def get_updater(self):
        """The Updater (made once, not started), or None when updates are not available."""
        if self.updater is not None:
            return self.updater
        mod = self._optional(_load_updater_module)
        if mod is None:
            return None
        with self.update_lock:
            if self.updater is None:
                try:
                    self.updater = mod.Updater(self.settings, self.store)
                except Exception:
                    self.log.error("Updater failed to start\n%s", traceback.format_exc())
                    return None
        return self.updater

    def start_updates(self) -> None:
        """At serve() start: finish or roll back an update cut off last time, then (when
        settings.auto_update) start the background checks."""
        self.manage_updates = True
        u = self.get_updater()
        if u is None:
            return
        try:
            rec = getattr(u, "recover", None)
            if callable(rec):
                out = rec()
            else:
                mod_rec = getattr(self._optional(_load_updater_module), "recover", None)
                out = mod_rec(self.settings) if callable(mod_rec) else None
            if isinstance(out, (list, tuple)):
                self.notes.extend(str(n) for n in out if n)
        except Exception:
            self.log.error("update recover failed\n%s", traceback.format_exc())
            self.notes.append("TacoGuard could not tidy up an update that was cut off last time. "
                              "Details are in the log.")
        self._apply_auto_update()

    def _apply_auto_update(self) -> None:
        if not self.manage_updates:
            return
        u = self.get_updater()
        if u is None:
            return
        try:
            if self.settings.auto_update and not self.updater_running:
                u.start()
                self.updater_running = True
            elif not self.settings.auto_update and self.updater_running:
                u.stop()
                self.updater_running = False
        except Exception:
            self.log.error("starting/stopping the updater failed\n%s", traceback.format_exc())
            self.notes.append("Automatic updates could not start. Details are in the log.")

    def stop_updates(self) -> None:
        if self.updater is not None and self.updater_running:
            try:
                self.updater.stop()
            except Exception:
                self.log.error("stopping the updater failed\n%s", traceback.format_exc())
            self.updater_running = False

    def start_update_check(self) -> bool:
        """One check of every component in the background. False when one is already running."""
        u = self.get_updater()
        with self.update_lock:
            if self.update_check["running"]:
                return False
            try:
                if (u.status() or {}).get("checking"):
                    return False
            except Exception:
                pass
            self.update_check.update(running=True, started=time.time(), finished=0.0, error="")

        def work():
            try:
                u.check_now(wait=True)
            except Exception:
                self.log.error("update check failed\n%s", traceback.format_exc())
                self.update_check["error"] = ("The update check stopped with a problem. TacoGuard kept "
                                              "what it had. Details are in the log.")
            finally:
                self._offer = (0.0, None)
                self.update_check["finished"] = time.time()
                self.update_check["running"] = False
        threading.Thread(target=work, name="tacoguard-update-check", daemon=True).start()
        return True

    def _stale(self, comps: dict, sig: dict | None) -> dict:
        """Signatures older than settings.signatures_max_age_days."""
        try:
            days = max(1, int(self.settings.signatures_max_age_days))
        except (TypeError, ValueError):
            days = 7
        now, items = time.time(), []
        for key, sig_key, label in (("clamav_signatures", "clamav", "ClamAV signatures"),
                                    ("yara_rules", "yara", "YARA rules")):
            updated = (comps.get(key) or {}).get("updated") or 0
            if not updated:
                if sig is None:
                    sig = self.signature_status()
                s = sig.get(sig_key) if isinstance(sig, dict) else None
                updated = (s or {}).get("updated") or 0 if (s or {}).get("ready") else 0
            try:
                updated = float(updated)
            except (TypeError, ValueError):
                updated = 0
            if updated and now - updated > days * 86400:
                items.append({"label": label, "days": int((now - updated) // 86400), "updated": updated})
        if not items:
            return {"items": [], "message": ""}
        what = " and ".join(f"{i['label']} were last updated {i['days']} days ago" for i in items)
        msg = f"{what[0].upper()}{what[1:]} (TacoGuard warns after {days} days). "
        if self.settings.auto_update:
            msg += ("TacoGuard keeps trying in the background. If this stays, check the internet "
                    "connection or press Check for updates.")
        else:
            msg += "Automatic updates are off in Settings: press Check for updates to get new ones."
        return {"items": items, "message": msg}

    def updates_view(self, sig: dict | None = None) -> dict:
        """The Updates card on Home. Cheap, never raises."""
        s = self.settings
        out = {"available": False, "message": "", "checking": bool(self.update_check["running"]),
               "last_check": 0.0, "next_check": 0.0, "components": [], "rejected": [],
               "rejected_message": "", "auto_update": bool(s.auto_update),
               "interval_h": s.update_interval_h, "check": dict(self.update_check)}
        comps: dict = {}
        try:
            u = self.get_updater()
            if u is None:
                out["message"] = UPDATES_NOT_READY
            else:
                out["available"] = True
                try:
                    st = u.status() or {}
                except Exception:
                    self.log.error("updater status failed\n%s", traceback.format_exc())
                    st = {}
                    out["message"] = "Could not read the update status. Details are in the log."
                comps = st.get("components") if isinstance(st.get("components"), dict) else {}
                out["checking"] = out["checking"] or bool(st.get("checking"))
                out["last_check"] = st.get("last_check") or 0.0
                out["next_check"] = (st.get("next_check") or 0.0) if s.auto_update else 0.0
                for key, label in UPDATE_COMPONENTS:
                    c = comps.get(key)
                    if not isinstance(c, dict):
                        continue
                    state = str(c.get("state") or "")
                    item = {"name": key, "label": label, "version": str(c.get("version") or ""),
                            "updated": c.get("updated") or 0.0, "state": state,
                            "message": str(c.get("message") or ""),
                            "last_error": str(c.get("last_error") or ""),
                            "rejected": state in REJECTED_STATES}
                    out["components"].append(item)
                    if item["rejected"]:
                        out["rejected"].append(label)
                if out["rejected"]:
                    out["rejected_message"] = REJECTED_MSG
            out["stale"] = self._stale(comps, sig)
        except Exception:
            self.log.error("updates view failed\n%s", traceback.format_exc())
            out["message"] = "Could not read the update status. Details are in the log."
            out.setdefault("stale", {"items": [], "message": ""})
        out["app"] = self.app_update_view()
        return out

    # ---- self-update (Phase 2) -------------------------------------------------------------
    def _app_offer(self, sm, fresh: bool = False) -> dict | None:
        when, offer = self._offer
        if fresh or time.time() - when > OFFER_TTL_S:
            try:
                raw = sm.available(self.settings)
            except Exception:
                self.log.error("selfupdate.available failed\n%s", traceback.format_exc())
                raw = None
            offer = None
            if isinstance(raw, dict) and raw.get("version"):
                offer = {"version": str(raw["version"]), "notes": str(raw.get("notes") or ""),
                         "can_install": bool(raw.get("can_install", True)),
                         "message": str(raw.get("message") or "")}
            self._offer = (time.time(), offer)
        return offer

    def app_update_view(self) -> dict:
        state = dict(self.app_action)
        sm = self._optional(_load_selfupdate)
        if sm is None:
            return {"available": False, "message": SELFUPDATE_NOT_READY, "offer": None, "installed": False,
                    "note": "", "previous": "", "version": __version__, "state": state}
        try:
            installed = bool(sm.running_from_install())
        except Exception:
            self.log.error("selfupdate.running_from_install failed\n%s", traceback.format_exc())
            installed = False
        note = ""
        if not installed:
            note = next((str(getattr(sm, n)) for n in ("NOT_INSTALLED_MSG", "PROJECT_FOLDER_NOTE")
                         if isinstance(getattr(sm, n, None), str)), PROJECT_FOLDER_NOTE)
        previous, busy, last = "", False, None
        if installed and callable(getattr(sm, "status", None)):
            try:
                st = sm.status(self.settings) or {}
                previous = str(st.get("previous") or "") if st.get("can_rollback") else ""
                busy = bool(st.get("busy"))
                lr = st.get("last_result")
                if isinstance(lr, dict) and lr.get("message") and time.time() - float(lr.get("time") or 0) < 86400:
                    last = {"ok": bool(lr.get("ok")), "message": str(lr["message"])}
            except Exception:
                self.log.error("selfupdate.status failed\n%s", traceback.format_exc())
        return {"available": True, "message": "", "offer": self._app_offer(sm), "installed": installed,
                "note": note, "previous": previous, "busy": busy, "last_result": last,
                "version": __version__, "state": state}

    def call_selfupdate(self, fn, *args) -> dict:
        """selfupdate.install_update / rollback, given a way to close this page so the new
        version can take the port (only when the function asks for one)."""
        try:
            wants = "shutdown" in inspect.signature(fn).parameters
        except (TypeError, ValueError):
            wants = False
        if wants:
            return fn(self.settings, *args, shutdown=self._close_for_restart)
        return fn(self.settings, *args)

    def _close_for_restart(self, *a, **k) -> None:
        srv = self.server
        if srv is not None:
            threading.Thread(target=srv.shutdown, name="tacoguard-restart", daemon=True).start()

    def start_app_action(self, what: str, fn) -> bool:
        """Install an app update or go back, in the background (it restarts the page)."""
        with self.app_action_lock:
            if self.app_action["running"]:
                return False
            self.app_action.update(running=True, what=what, message="", error="", finished=0.0)

        def work():
            try:
                out = fn()
                if isinstance(out, dict):
                    if out.get("ok", True):
                        self.app_action["message"] = str(out.get("message") or "")
                    else:
                        self.app_action["error"] = str(out.get("message") or out.get("error") or
                                                       "That didn't work. TacoGuard stayed on this version.")
            except Exception as e:
                self.log.error("app %s failed\n%s", what, traceback.format_exc())
                self.app_action["error"] = self._plain_update_error(e)
            finally:
                self._offer = (0.0, None)
                self.app_action["finished"] = time.time()
                self.app_action["running"] = False
        threading.Thread(target=work, name=f"tacoguard-app-{what}", daemon=True).start()
        return True

    def _plain_update_error(self, e: Exception) -> str:
        plain_types = []
        signed = self._optional(_load_signed)
        if signed is not None and isinstance(getattr(signed, "UpdateRejected", None), type):
            plain_types.append(signed.UpdateRejected)
        sm = self._optional(_load_selfupdate)
        for name in ("Refused", "SelfUpdateError", "UpdateError"):
            if sm is not None and isinstance(getattr(sm, name, None), type):
                plain_types.append(getattr(sm, name))
        if plain_types and isinstance(e, tuple(plain_types)) and str(e):
            return str(e)
        return (f"That didn't work ({plain_error(e)}). TacoGuard stayed on version {__version__}. "
                "Details are in the log.")

    def trusted_signers(self) -> list[dict]:
        """The keys TacoGuard's own updates must be signed with (from the trusted root)."""
        signed = self._optional(_load_signed)
        if signed is None:
            return []
        try:
            root = signed.load_trusted_root(self.settings) or {}
            root = root.get("signed", root)
            roles = root.get("roles") or {}
            out = []
            for keyid, key in (root.get("keys") or {}).items():
                used = [name for name, role in roles.items() if keyid in (role.get("keyids") or [])]
                out.append({"keyid": str(keyid)[:16], "keytype": str((key or {}).get("keytype", "")),
                            "roles": used})
            return out
        except Exception:
            self.log.error("reading the trusted root failed\n%s", traceback.format_exc())
            return []

    def quarantine(self):
        return quarantine.Quarantine(self.settings, self.store)

    # ---- real-time protection (Phase 3) ------------------------------------------------------
    def start_guard(self) -> None:
        """serve() only: from now on the page starts and watches the guard process."""
        self.manage_guard = True
        self.guard.start()

    def apply_guard(self) -> None:
        """settings.realtime_enabled changed: start or stop the guard now (when we manage it)."""
        if self.manage_guard:
            self.guard.wake()

    def _guard_alive(self) -> bool:
        """A guard process runs for this data folder (ours, or one we found by its heartbeat)."""
        if self.guard.running:
            return True
        st = read_guard_state(self.store)
        return bool(st.get("pid")) and _guard_process(st["pid"]) is not None

    def remove_decoys_after_guard(self, wait_s: float = 20.0) -> None:
        """The ransomware guard was switched off: take TacoGuard's decoy files away. While a guard
        runs with real-time protection on, it does that itself when it sees the new settings.
        Otherwise they are removed once no guard runs any more (a guard still stopping would
        otherwise put a deleted decoy back)."""
        try:
            from ..guard import ransom
        except ImportError:
            return
        if self.settings.realtime_enabled and self._guard_alive():
            return                      # the running guard removes them itself

        def run():
            end = time.monotonic() + wait_s
            while self._guard_alive() and time.monotonic() < end:
                time.sleep(0.25)
            if self.settings.ransomware_guard or (self.settings.realtime_enabled and self._guard_alive()):
                return                  # switched on again meanwhile, or a guard took over
            try:
                n = ransom.remove_decoys(self.settings)
                if n:
                    self.log.info("removed %s decoy files (the ransomware guard is off)", n)
            except Exception:
                self.log.error("could not remove the decoy files\n%s", traceback.format_exc())

        if not self._guard_alive():
            run()
            return
        self._decoy_thread = threading.Thread(target=run, name="tacoguard-decoys-off", daemon=True)
        self._decoy_thread.start()

    def guard_view(self) -> dict:
        s, sup = self.settings, self.guard
        st = read_guard_state(self.store)
        try:
            hb = float(st.get("heartbeat") or 0)
        except (TypeError, ValueError):
            hb = 0.0
        alive = bool(st.get("pid")) and time.time() - hb < GUARD_FRESH_S and _pid_exists(st.get("pid"))
        raw_parts = st.get("parts") if isinstance(st.get("parts"), dict) else {}
        parts = []
        labels = PART_LABELS + ((WEB_PART,) if isinstance(raw_parts.get(WEB_PART[0]), dict) else ())
        if alive:
            for name, label in labels:
                p = raw_parts.get(name) if isinstance(raw_parts.get(name), dict) else {}
                watched = [w for w in (p.get("watched") or []) if isinstance(w, str)][:200]
                try:
                    checked = int(p.get("checked") or 0)
                except (TypeError, ValueError):
                    checked = 0
                parts.append({"name": name, "label": label, "state": str(p.get("state") or "starting"),
                              "message": str(p.get("message") or ""), "watched": watched,
                              "short_watched": [_short(w) for w in watched], "checked": checked})
        note = sup.message
        if not s.realtime_enabled:
            state, summary, note = "off", ("Real-time protection is off (you can turn it on in Settings). "
                                           "TacoGuard still checks files when you scan them."), sup.stop_note
        elif sup.gave_up:
            state, summary, note = "error", sup.message, ""
        elif alive:
            on = {p["name"]: p for p in parts if p["state"] == "on"}
            bits = []
            if "folders" in on:
                n = len(on["folders"]["watched"])
                bits.append(f"watching {n} folder{'s' if n != 1 else ''}" if n else "watching your folders")
            if "processes" in on:
                bits.append("new programs")
            if "ransomware" in on:
                n = len(on["ransomware"]["watched"])
                bits.append(f"decoys in {n} folder{'s' if n != 1 else ''}" if n else "decoy files")
            if "persistence" in on:
                bits.append("start-up entries")
            if WEB_PART[0] in on:
                bits.append("bad websites")
            summary = ("Real-time protection is on: " + ", ".join(bits) + "." if bits else
                       "Real-time protection is running, but each of its parts is switched off in Settings.")
            state = "warn" if any(p["state"] == "error" for p in parts) else "on"
            if state == "warn":
                summary += " One part has a problem (see below)."
            if sup.message and not sup.crashes:
                note = ""
        elif sup.unavailable:
            state, summary, note = "unavailable", GUARD_NOT_READY, ""
        elif self.manage_guard:
            state, summary = "starting", "Real-time protection is starting..."
        else:
            state, summary = "off", "Real-time protection is not running. It starts together with TacoGuard."
        return {"enabled": bool(s.realtime_enabled), "alive": alive, "state": state, "summary": summary,
                "note": note, "parts": parts, "started": st.get("started") or 0,
                "heartbeat": hb, "version": str(st.get("version") or ""),
                "managed": self.manage_guard, "gave_up": sup.gave_up,
                "paused_until": phase4.protection_paused(self.store)}

    def _event_brief(self, event_id, cache: dict) -> dict | None:
        if not event_id:
            return None
        ev = cache.get(event_id) or self.store.get_guard_event(int(event_id))
        if not ev:
            return None
        return {k: ev.get(k) for k in ("id", "title", "message", "level", "kind", "state", "created")}

    def protection_view(self) -> dict:
        """Everything the Protection tab shows. Programs paused by the guard that have closed in
        the meantime are marked "gone" here (their event stays, with the file actions)."""
        events = self.with_lookups([_event_for_page(e)
                                    for e in self.store.list_guard_events(limit=PROTECTION_EVENTS)])
        cache = {e["id"]: e for e in events}
        paused = []
        for row in self.store.list_paused(("paused",)):
            ref = procctl.ProcRef(int(row["pid"]), float(row["create_time"]))
            if not procctl.is_alive(ref):
                self.store.set_paused_state(row["id"], "gone")
                continue
            paused.append(dict(row, alive=True, short=_short(row["exe"]),
                               event=self._event_brief(row["event_id"], cache)))
        startup = [dict(r, short_target=_short(r.get("target") or ""),
                        event=self._event_brief(r.get("event_id"), cache))
                   for r in self.store.list_persistence(("new",))]
        undone = [dict(r, short_target=_short(r.get("target") or ""))
                  for r in self.store.list_persistence(("undone",))]
        linked = {p["event_id"] for p in paused if p["event_id"]} | \
                 {r["event_id"] for r in startup if r.get("event_id")}
        attention = self.with_lookups([_event_for_page(e) for e in self.store.list_guard_events(("new",), limit=200)
                                       if e["id"] not in linked])
        levels = [e["level"] for e in attention] + [(p["event"] or {}).get("level") for p in paused]
        return {
            "guard": self.guard_view(), "events": events, "paused": paused, "startup": startup,
            "startup_undone": undone, "attention": attention,
            "counts": {"attention": len(paused) + len(startup) + len(attention),
                       "malware": sum(1 for lv in levels if lv == MALWARE)},
            "cfa": self.cfa_view(), "autostart": self.autostart_view(),
        }

    def protection_brief(self) -> dict:
        """The Home card's line and the tab badge (cheap: counts only)."""
        try:
            g = self.guard_view()
            n_new = len(self.store.list_guard_events(("new",), limit=200))
            n_paused = len(self.store.list_paused(("paused",)))
            return {"state": g["state"], "summary": g["summary"], "alive": g["alive"],
                    "attention": n_new + n_paused}
        except Exception:
            self.log.error("protection brief failed\n%s", traceback.format_exc())
            return {"state": "unknown", "summary": "", "alive": False, "attention": 0}

    def cfa_view(self) -> dict:
        cfa = (self.defender_status() or {}).get("cfa")
        if not isinstance(cfa, dict):
            cfa = {"state": "checking", "value": None, "message": "Checking Windows Security..."}
        return dict(cfa, note=CFA_ON_NOTE if cfa.get("state") == "on" else "")

    def _installed_copy(self) -> bool:
        sm = self._optional(_load_selfupdate)
        try:
            return bool(sm and sm.running_from_install())
        except Exception:
            return False

    def autostart_view(self) -> dict:
        st = autostart.status(self.autostart_key)
        installed = self._installed_copy()
        return dict(st, installed=installed, setting=bool(self.settings.start_at_sign_in),
                    note="" if installed else autostart.NOT_INSTALLED_MSG)

    def apply_autostart(self) -> str:
        """settings.start_at_sign_in changed: add or remove the Run entry. Returns a plain sentence."""
        try:
            if self.settings.start_at_sign_in:
                return autostart.enable(install_root(), key_path=self.autostart_key)
            return autostart.disable(key_path=self.autostart_key, only_for_root=install_root())
        except autostart.AutostartError as e:
            return str(e)
        except Exception:
            self.log.error("start at sign-in failed\n%s", traceback.format_exc())
            return "TacoGuard could not change its start-at-sign-in entry. Details are in the log."

    def default_folders(self) -> dict:
        """What 'use the defaults' means for watched folders and decoy folders (display paths)."""
        import dataclasses
        watch: list[str] = []
        mod = self._optional(_load_guard_folders)
        fn = getattr(mod, "default_watch_folders", None) if mod else None
        if callable(fn):
            try:
                watch = [str(p) for p in fn(dataclasses.replace(self.settings, watch_folders=[]))]
            except Exception:
                self.log.error("default_watch_folders failed\n%s", traceback.format_exc())
        if not watch:
            watch = [p["path"] for p in quick_picks() if p["kind"] == "folder"]
            startup = os.path.join(os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming"),
                                   "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if os.path.isdir(startup):
                watch.append(startup)
        canary = []
        home = os.path.expanduser("~")
        for name, guid in CANARY_KNOWN_FOLDERS:
            p = _known_folder(guid) or os.path.join(home, name)
            if os.path.isdir(p) and not _in_onedrive(p) and p not in canary:
                canary.append(p)
        return {"watch_folders": watch, "canary_folders": canary}

    def _folder_list(self, key: str, value) -> list[str]:
        label = PHASE3_FOLDER_LISTS[key]
        if not isinstance(value, list) or len(value) > PHASE3_MAX_FOLDERS:
            raise ApiError(400, f"{label} must be a list of at most {PHASE3_MAX_FOLDERS} folders.")
        out, seen = [], set()
        for v in value:
            if not isinstance(v, str) or not v.strip() or len(v) > 32000:
                raise ApiError(400, f"{label}: one of the folders is empty or not a folder path.")
            raw = v.strip().strip('"')
            disp = winpath.to_display(raw)
            if re.fullmatch(r"[A-Za-z]:", disp):
                disp += "\\"
            disp = winpath.to_display(os.path.abspath(disp))
            if not os.path.isdir(winpath.to_long(disp)):
                raise ApiError(400, f"{label}: folder not found: {disp}")
            nk = winpath.norm_key(disp)
            if key == "canary_folders":
                if len(nk) <= 3:
                    raise ApiError(400, f"Decoy folders: pick folders, not a whole drive ({disp}).")
                if _in_onedrive(disp):
                    raise ApiError(400, f"Decoy folders can't be inside OneDrive (TacoGuard never puts decoy "
                                        f"files there): {disp}")
            if nk not in seen:
                seen.add(nk)
                out.append(disp)
        return out

    # ---- Phase 4: quit, open, pause, Game mode, tray, self-protection ---------------------------
    def quit(self) -> None:
        """The page's Stop button and the tray's Quit: the server stops, then serve() closes the
        rest (guard, updates, tray, Game mode) through close()."""
        srv = self.server
        if srv is not None:
            threading.Thread(target=srv.shutdown, name="tacoguard-quit", daemon=True).start()

    def open_page(self) -> None:
        webbrowser.open(f"http://127.0.0.1:{self.port}/")

    def pause_protection(self, seconds: float) -> float:
        until = phase4.pause_protection(self.store, seconds)
        self.log.info("real-time protection paused until %s",
                      time.strftime("%Y-%m-%d %H:%M", time.localtime(until)))
        self.refresh_tray()
        return until

    def resume_protection(self) -> None:
        phase4.resume_protection(self.store)
        self.log.info("real-time protection resumed")
        self.refresh_tray()

    def switch_game_mode(self, on: bool) -> dict:
        gm = self.gamemode.user_switch(bool(on))
        self.log.info("Game mode switched %s by you", "on" if on else "off")
        self.refresh_tray()
        return gm

    def start_gamemode(self) -> None:
        """serve() only: automatic Game mode looks at the screen every 10 s from now on."""
        self.manage_gamemode = True
        self.gamemode.start()

    def start_tray(self) -> None:
        """serve() only: the icon in the notification area (settings.tray_enabled)."""
        self.manage_tray = True
        self.apply_tray()

    def apply_tray(self) -> str:
        """settings.tray_enabled changed (or serve() started): add or take away the icon. Returns a
        plain sentence when something went wrong, else ""."""
        if not self.manage_tray:
            return ""
        if not self.settings.tray_enabled:
            self.stop_tray()
            self.tray_note = ""
            return ""
        if self.tray is not None and self.tray.running:
            return ""
        mod = self._optional(_load_tray)
        if mod is None:
            return ""
        ok = False
        try:
            self.tray = mod.Tray(self)
            ok = self.tray.start()
        except Exception:
            self.log.error("the tray icon failed to start\n%s", traceback.format_exc())
        self.tray_note = "" if ok else ("The TacoGuard icon could not be added to the taskbar. Details are "
                                        "in the log.")
        return self.tray_note

    def stop_tray(self) -> None:
        t, self.tray = self.tray, None
        if t is not None:
            try:
                t.stop()
            except Exception:
                self.log.error("stopping the tray icon failed\n%s", traceback.format_exc())

    def refresh_tray(self) -> None:
        """Show a change on the icon now instead of at its next 5-second look."""
        t = self.tray
        if t is not None and t.running:
            try:
                t.refresh()
            except Exception:
                self.log.error("tray refresh failed\n%s", traceback.format_exc())

    def harden(self) -> bool:
        """serve() only: self-protection for this process (selfprotect.maybe_harden: only when
        settings.self_protection, never under pytest)."""
        mod = self._optional(_load_selfprotect)
        fn = getattr(mod, "maybe_harden", None) if mod is not None else None
        if not callable(fn):
            return False
        self.hardened = bool(fn(self.settings, self.log))
        return self.hardened

    def modes_view(self) -> dict:
        """Cheap (two store reads): paused protection and Game mode, for the banner on every tab."""
        gm = phase4.game_mode(self.store)
        return {"paused_until": phase4.protection_paused(self.store),
                "game_mode": dict(gm, auto=bool(self.settings.game_mode_auto)),
                "lookup_ready": self.lookup_ready()}

    def selfprotect_view(self) -> dict:
        out = {"enabled": bool(self.settings.self_protection),
               "available": self._optional(_load_selfprotect) is not None,
               "hardened": self.hardened, "notes": []}
        notes: list[str] = []

        def take(items) -> None:
            if isinstance(items, (list, tuple)):
                notes.extend(n.strip() for n in items if isinstance(n, str) and n.strip())
        take(read_guard_state(self.store).get("notes"))
        try:
            raw = json.loads(self.store.get_meta("selfprotect") or "{}")
        except (ValueError, TypeError):
            raw = {}
        if isinstance(raw, dict):
            for key in ("notes", "problems", "messages", "alerts"):
                take(raw.get(key))
            if isinstance(raw.get("message"), str) and raw["message"].strip():
                notes.append(raw["message"].strip())
        seen: set[str] = set()
        out["notes"] = [n[:500] for n in notes if not (n in seen or seen.add(n))][:10]
        return out

    # ---- Phase 4: the abuse.ch key and MalwareBazaar lookups -----------------------------------------
    def key_view(self) -> dict:
        """Whether an abuse.ch key is saved, and its last 4 characters. Never the key."""
        sec = self._optional(_load_secrets)
        if sec is None:
            return {"available": False, "set": False, "hint": "", "message": SECRETS_NOT_READY}
        try:
            is_set = bool(sec.has_key(self.settings, ABUSECH))
            hint = str(sec.key_hint(self.settings, ABUSECH) or "") if is_set else ""
        except Exception as e:
            self.log.error("reading the abuse.ch key status failed (%s)", type(e).__name__)
            is_set, hint = False, ""
        msg = ""
        if is_set and not hint:
            msg = ("A key is saved, but TacoGuard can't read it (it may have been saved by another Windows "
                   "account). Paste your key again.")
        return {"available": True, "set": is_set, "hint": hint, "message": msg}

    def lookup_ready(self) -> bool:
        mod = self._optional(_load_lookup)
        if not self.settings.lookup_enabled or mod is None:
            return False
        if callable(getattr(mod, "ready", None)):
            try:
                return bool(mod.ready(self.settings))
            except Exception:
                return False
        sec = self._optional(_load_secrets)
        try:
            return bool(sec is not None and sec.has_key(self.settings, ABUSECH))
        except Exception:
            return False

    def lookup_view(self) -> dict:
        mod = self._optional(_load_lookup)
        key = self.key_view()
        out = {"enabled": bool(self.settings.lookup_enabled), "available": mod is not None, "key": key,
               "ready": False, "state": "", "message": "", "when": 0.0, "last_error": "", "left": None}
        if mod is None:
            out["message"] = LOOKUP_NOT_READY
            return out
        out["ready"] = out["enabled"] and key["set"]
        try:
            st = mod.status(self.store) or {}
            out.update(state=str(st.get("state") or ""), message=str(st.get("message") or ""),
                       when=float(st.get("when") or 0))
            if out["state"] not in ("", "ok"):
                out["last_error"] = out["message"]
        except Exception:
            self.log.error("lookup status failed\n%s", traceback.format_exc())
        try:
            out["left"] = int(mod.rate_left(self.store))
        except Exception:
            pass
        return out

    def lookup_note(self, sha256: str) -> dict | None:
        """A cached MalwareBazaar answer for this file, for its card (no network)."""
        sha = str(sha256 or "").lower()
        if not SHA256_RE.match(sha):
            return None
        try:
            row = self.store.get_lookup(sha)
        except Exception:
            return None
        if not row:
            return None
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        sig = str(data.get("signature") or "")[:200]
        if row.get("found"):
            text = f"MalwareBazaar has a copy of this exact file, uploaded as '{sig or 'unnamed'}'."
        else:
            text = "MalwareBazaar doesn't know this exact file."
        return {"found": bool(row.get("found")), "signature": sig, "message": text,
                "checked": float(row.get("checked") or 0), "link": f"https://bazaar.abuse.ch/sample/{sha}/"}

    def with_lookups(self, rows: list[dict]) -> list[dict]:
        for r in rows:
            r["lookup"] = self.lookup_note(r.get("sha256") or "") if r.get("level") in FLAGGED_LEVELS else None
        return rows

    # ---- Phase 4: website blocking -------------------------------------------------------------
    def webblock_view(self) -> dict:
        s = self.settings
        out = {"enabled": bool(s.webblock_enabled), "available": False, "message": "", "sources": [],
               "total": 0, "part": None, "busy": False, "allow": list(s.webblock_allow or []),
               "refresh": dict(self.lists_action), "hosts": self.hosts_view()}
        mod = self._optional(_load_webblock_lists)
        if mod is None:
            out["message"] = WEBBLOCK_NOT_READY
        else:
            try:
                st = mod.status(s) or {}
                sources = st.get("sources") if isinstance(st.get("sources"), dict) else {}
                for name in ("phishing", "urlhaus"):
                    if isinstance(sources.get(name), dict):
                        out["sources"].append(dict(_simple(sources[name]), name=name))
                out["total"] = int(st.get("total") or 0)
                out["busy"] = bool(st.get("busy"))
                out["available"] = True
            except Exception:
                self.log.error("website list status failed\n%s", traceback.format_exc())
                out["message"] = "Could not read the website lists. Details are in the log."
        parts = read_guard_state(self.store).get("parts")
        part = parts.get(WEB_PART[0]) if isinstance(parts, dict) else None
        if isinstance(part, dict):
            out["part"] = {"state": str(part.get("state") or ""), "message": str(part.get("message") or "")[:500]}
        return out

    _plan_cache: tuple[float, dict | None] = (0.0, None)

    def hosts_view(self) -> dict:
        s = self.settings
        out = {"enabled": bool(s.webblock_hosts), "every_days": int(s.webblock_hosts_every_days or 7),
               "available": False, "plan": {}, "message": "", "action": dict(self.hosts_action)}
        mod = self._optional(_load_webblock_hosts)
        if mod is None or not callable(getattr(mod, "plan", None)):
            out["message"] = HOSTS_NOT_READY
            return out
        out["available"] = True
        when, plan = self._plan_cache
        if plan is None or time.time() - when > 30 or self.hosts_action["running"]:
            try:
                raw = mod.plan(s)
                plan = _simple(raw) if isinstance(raw, dict) else {}
            except Exception:
                self.log.error("hosts plan failed\n%s", traceback.format_exc())
                plan = {}
                out["message"] = "Could not read the hosts file status. Details are in the log."
            self._plan_cache = (time.time(), plan)
        out["plan"] = plan
        return out

    def _save_settings(self, changes: dict) -> None:
        """Save a few settings onto what is on disk (as update_settings does)."""
        disk = load_settings(self.settings.data_dir)
        for target in (disk, self.settings):
            for k, v in changes.items():
                setattr(target, k, v)
        disk.save()

    def _plain_web_error(self, e: Exception, what: str) -> str:
        if isinstance(e, ValueError) and str(e):
            return str(e)
        if isinstance(e, OSError):
            return f"Windows stopped {what} ({plain_error(e)}). Details are in the log."
        return f"{what[0].upper()}{what[1:]} stopped with a problem. Details are in the log."

    def start_hosts_action(self, what: str) -> bool:
        """Apply or remove TacoGuard's block in the hosts file, on a background thread: Windows shows
        its admin prompt and the helper waits for your answer. One at a time; False when one runs."""
        mod = self._optional(_load_webblock_hosts)
        fn = getattr(mod, HOSTS_ACTIONS[what], None) if mod is not None else None
        if not callable(fn):
            raise ApiError(503, HOSTS_NOT_READY)
        with self.web_lock:
            if self.hosts_action["running"]:
                return False
            self.hosts_action.update(running=True, what=what, message="", error="", started=time.time(),
                                     finished=0.0, ok=False)
        words = "changing the hosts file" if what == "apply" else "taking TacoGuard's block out of the hosts file"

        def work():
            try:
                out = fn(self.settings)
                text = str(out or "").strip() or (
                    "Done." if what == "apply" else "TacoGuard's block is out of the hosts file.")
                ok = getattr(out, "ok", None)
                if ok is False:
                    self.hosts_action["error"] = text
                else:
                    self.hosts_action["message"] = text
                if ok is True:
                    # your choice is remembered only when the helper did it: keep the block up to
                    # date (Apply) or not (Remove)
                    self.hosts_action["ok"] = True
                    try:
                        self._save_settings({"webblock_hosts": what == "apply"})
                    except OSError:
                        self.log.error("saving the hosts choice failed\n%s", traceback.format_exc())
            except Exception as e:
                self.log.error("hosts %s failed\n%s", what, traceback.format_exc())
                self.hosts_action["error"] = self._plain_web_error(e, words)
            finally:
                self._plan_cache = (0.0, None)
                self.hosts_action["finished"] = time.time()
                self.hosts_action["running"] = False
        threading.Thread(target=work, name=f"tacoguard-hosts-{what}", daemon=True).start()
        return True

    def start_lists_refresh(self) -> bool:
        """Download the website lists now (webblock.lists.refresh waits at least 30 minutes between
        contacts with each list's server by itself). One at a time; False when one runs."""
        mod = self._optional(_load_webblock_lists)
        if mod is None or not callable(getattr(mod, "refresh", None)):
            raise ApiError(503, WEBBLOCK_NOT_READY)
        with self.web_lock:
            if self.lists_action["running"]:
                return False
            self.lists_action.update(running=True, message="", error="", started=time.time(), finished=0.0)

        def work():
            try:
                out = mod.refresh(self.settings, self.store) or {}
                msg = str(out.get("message") or "") if isinstance(out, dict) else ""
                if isinstance(out, dict) and out.get("busy"):
                    self.lists_action["message"] = msg or "The website lists are being updated right now."
                elif isinstance(out, dict) and out.get("ok") is False:
                    self.lists_action["error"] = msg or "A website list could not be updated. The last good list is kept."
                else:
                    self.lists_action["message"] = msg or "The website lists are up to date."
            except Exception as e:
                self.log.error("website list refresh failed\n%s", traceback.format_exc())
                self.lists_action["error"] = self._plain_web_error(e, "updating the website lists")
            finally:
                self._plan_cache = (0.0, None)    # the hosts plan counts the new lists at once
                self.lists_action["finished"] = time.time()
                self.lists_action["running"] = False
                try:
                    self.store.close()            # this thread's SQLite connection
                except Exception:
                    pass
        threading.Thread(target=work, name="tacoguard-lists-refresh", daemon=True).start()
        return True

    # ---- Phase 4: the Home dashboard ----------------------------------------------------------
    def dashboard_view(self) -> dict:
        g = self.guard_view()
        detections = self.store.latest_detections(500)
        open_ = [d for d in detections if not d.get("action")]
        n_events = len(self.store.list_guard_events(("new",), limit=200))
        n_paused = len(self.store.list_paused(("paused",)))
        recent = self.store.list_jobs(10)
        last = next((j for j in recent if j["status"] not in JOB_ACTIVE), None)
        active = next((j for j in recent if j["status"] in JOB_ACTIVE), None)
        sig = self.signature_status()
        up = self.updates_view(sig)
        sig_items = []
        if isinstance(sig, dict) and not sig.get("error"):
            for key, label in (("clamav", "ClamAV signatures"), ("yara", "YARA rules"),
                               ("hash", "Known-bad file lists"), ("ml", "Machine-learning model")):
                x = sig.get(key)
                if isinstance(x, dict):
                    sig_items.append({"name": key, "label": label, "ready": bool(x.get("ready")),
                                      "updated": x.get("updated") or 0})
        return {
            "protection": {k: g[k] for k in ("state", "summary", "alive", "note", "enabled", "paused_until")}
            | {"parts": [{k: p[k] for k in ("name", "label", "state", "message")} for p in g["parts"]]},
            "modes": self.modes_view(),
            "alerts": {"protection": n_events + n_paused, "detections": len(open_),
                       "malware": sum(1 for d in open_ if d["level"] == MALWARE),
                       "total": n_events + n_paused + len(open_)},
            "last_scan": self._scan_brief(last), "scanning": self._scan_brief(active),
            "updates": {"last_check": up.get("last_check") or 0.0, "next_check": up.get("next_check") or 0.0,
                        "auto_update": bool(up.get("auto_update")), "checking": bool(up.get("checking")),
                        "available": bool(up.get("available")),
                        "stale": (up.get("stale") or {}).get("message") or "", "signatures": sig_items},
            "webblock": self.webblock_view(),
            "lookup": self.lookup_view(),
            "tray": {"enabled": bool(self.settings.tray_enabled), "managed": self.manage_tray,
                     "running": bool(self.tray is not None and self.tray.running), "note": self.tray_note},
            "self_protection": self.selfprotect_view(),
        }

    @staticmethod
    def _scan_brief(j: dict | None) -> dict | None:
        if not j:
            return None
        c = j.get("counts") or {}
        result = ("malware" if c.get("malware") else "suspicious" if c.get("suspicious") else
                  "clean" if j["status"] == "done" else j["status"])
        return {"id": j["id"], "status": j["status"], "result": result, "counts": c,
                "started": j.get("started") or 0, "finished": j.get("finished") or 0,
                "short_targets": [_short(t) for t in j.get("targets") or []]}

    # ---- pieces of status ----------------------------------------------------------------
    def signature_status(self) -> dict:
        try:
            return detect.signature_status(self.settings)
        except NotImplementedError:
            return {"error": "Signature status is not available yet: this part of TacoGuard is not "
                             "finished yet."}
        except Exception:
            self.log.error("signature_status failed\n%s", traceback.format_exc())
            return {"error": "Could not read the signature status. Details are in the log."}

    def quarantine_summary(self) -> dict:
        try:
            q = self.quarantine()
            items = q.items()
            return {"available": True, "count": len(items), "bytes": int(q.used_bytes())}
        except NotImplementedError:
            items = self.store.list_quarantine()
            return {"available": False, "count": len(items), "bytes": sum(i["size"] for i in items),
                    "message": "Quarantine is not ready yet."}
        except Exception:
            self.log.error("quarantine summary failed\n%s", traceback.format_exc())
            return {"available": False, "count": 0, "bytes": 0,
                    "message": "Could not read the quarantine. Details are in the log."}

    def defender_status(self) -> dict:
        try:
            st = defender.peek()
        except Exception:
            self.log.error("defender status failed\n%s", traceback.format_exc())
            st = None
        return st or {"level": "checking", "message": "Checking Microsoft Defender's status..."}

    def status(self) -> dict:
        recent = [_job_for_page(j) for j in self.store.list_jobs(10)]
        active = [_job_for_page(j) for j in self.store.active_jobs() if j]
        last = next((j for j in recent if j["status"] not in JOB_ACTIVE), None)
        detections = self.store.latest_detections(500)
        open_ = [d for d in detections if not d.get("action")]
        sig = self.signature_status()
        return {
            "app": APP_NAME, "version": __version__,
            "signatures": sig,
            "updates": self.updates_view(sig),
            "defender": self.defender_status(),
            "active_jobs": active, "recent_jobs": recent, "last_job": last,
            "counts": {
                "open_detections": len(open_),
                "open_malware": sum(1 for d in open_ if d["level"] == MALWARE),
                "open_suspicious": sum(1 for d in open_ if d["level"] == SUSPICIOUS),
            },
            "quarantine": self.quarantine_summary(),
            "protection": self.protection_brief(),
            "modes": self.modes_view(),
            "setup": {"running": self.setup_state["running"]},
            "busy": bool(active) or self.setup_state["running"],
            "data_dir": str(self.settings.root),
            "notes": list(self.notes),
        }

    # ---- setup -----------------------------------------------------------------------------
    def start_setup(self) -> bool:
        with self.setup_lock:
            if self.setup_state["running"]:
                return False
            self.setup_state.update(running=True, lines=[], result=None, started=time.time(),
                                    finished=0.0, error="")

        def progress(msg):
            lines = self.setup_state["lines"]
            lines.append({"t": time.time(), "text": str(msg)})
            del lines[:-500]

        def work():
            try:
                self.setup_state["result"] = setup_fetch.fetch_all(self.settings, progress=progress)
            except NotImplementedError:
                self.setup_state["error"] = "Downloading signatures is not finished yet in this version."
            except Exception as e:
                self.log.error("setup failed\n%s", traceback.format_exc())
                msg = str(e) if isinstance(e, setup_fetch.FetchError) else \
                    "Something went wrong while getting signatures. Details are in the log."
                self.setup_state["error"] = msg
            finally:
                self.setup_state["finished"] = time.time()
                self.setup_state["running"] = False
        threading.Thread(target=work, name="tacoguard-setup", daemon=True).start()
        return True

    # ---- settings --------------------------------------------------------------------------
    def settings_view(self) -> dict:
        s = self.settings
        return {
            "limits": asdict(s.limits), "scan_priority": s.scan_priority,
            "clamav_threads": clamav_thread_count(s), "clamav_threads_max": CLAMAV_THREADS_MAX,
            "clamav_enabled": s.clamav_enabled, "yara_enabled": s.yara_enabled,
            "trust_signed_programs": bool(s.trust_signed_programs),
            "editable": {k: {"min": v[1], "max": v[2]} for k, v in EDITABLE_LIMITS.items()},
            "priorities": list(PRIORITIES),
            "endpoints": ENDPOINTS, "licenses": read_licenses(),
            "data_dir": str(s.root), "log_dir": str(s.log_dir),
            "quarantine_dir": str(s.quarantine_dir),
            "app": APP_NAME, "version": __version__,
            # Phase 2
            "auto_update": bool(s.auto_update), "update_interval_h": s.update_interval_h,
            "ml_enabled": bool(s.ml_enabled), "ml_max_file_size": s.ml_max_file_size,
            "learning_enabled": bool(s.learning_enabled),
            "signatures_max_age_days": s.signatures_max_age_days,
            "phase2_limits": {k: {"min": v[1], "max": v[2]} for k, v in PHASE2_NUMBERS.items()},
            "signers": self.trusted_signers(),
            # Phase 3
            **{k: bool(getattr(s, k)) for k in PHASE3_SWITCHES},
            **{k: [str(p) for p in (getattr(s, k) or []) if isinstance(p, str)] for k in PHASE3_FOLDER_LISTS},
            "realtime_max_file_size": s.realtime_max_file_size,
            "realtime_limits": {"realtime_max_file_size": {"min": REALTIME_MAX_FILE[0],
                                                           "max": REALTIME_MAX_FILE[1]}},
            "realtime_defaults": self.default_folders(),
            "autostart": self.autostart_view(),
            # Phase 4
            **{k: bool(getattr(s, k)) for k in PHASE4_SWITCHES},
            "webblock_hosts_every_days": int(s.webblock_hosts_every_days or 7),
            "webblock_allow": [str(x) for x in (s.webblock_allow or []) if isinstance(x, str)],
            "phase4_limits": {"webblock_hosts_every_days": {"min": HOSTS_EVERY_DAYS[0], "max": HOSTS_EVERY_DAYS[1]},
                              "webblock_allow": {"max": WEB_ALLOW_MAX}},
            "abusech_key": self.key_view(),
        }

    def update_settings(self, body: dict) -> dict:
        changes_limits, priority, threads, trust_signed = {}, None, None, None
        phase2: dict = {}
        phase3: dict = {}
        phase4_: dict = {}
        for key, value in body.items():
            if key in PHASE4_SWITCHES:
                if not isinstance(value, bool):
                    raise ApiError(400, f"{PHASE4_SWITCHES[key]} must be on or off.")
                phase4_[key] = value
                continue
            if key == "webblock_hosts_every_days":
                lo, hi, msg = HOSTS_EVERY_DAYS
                if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                        or value != int(value) or not lo <= value <= hi):
                    raise ApiError(400, msg)
                phase4_[key] = int(value)
                continue
            if key == "webblock_allow":
                phase4_[key] = self._web_allow(value)
                continue
            if key in PHASE3_SWITCHES:
                if not isinstance(value, bool):
                    raise ApiError(400, f"{PHASE3_SWITCHES[key]} must be on or off.")
                phase3[key] = value
                continue
            if key in PHASE3_FOLDER_LISTS:
                phase3[key] = self._folder_list(key, value)
                continue
            if key == "realtime_max_file_size":
                lo, hi, msg = REALTIME_MAX_FILE
                if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                        or value != int(value) or not lo <= value <= hi):
                    raise ApiError(400, msg)
                phase3[key] = int(value)
                continue
            if key in PHASE2_SWITCHES:
                if not isinstance(value, bool):
                    raise ApiError(400, f"{PHASE2_SWITCHES[key]} must be on or off.")
                phase2[key] = value
                continue
            if key in PHASE2_NUMBERS:
                kind, lo, hi, msg = PHASE2_NUMBERS[key]
                if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                        or not lo <= value <= hi or (kind is int and value != int(value))):
                    raise ApiError(400, msg)
                phase2[key] = kind(value)
                continue
            if key == "trust_signed_programs":
                if not isinstance(value, bool):
                    raise ApiError(400, "'Trust validly signed programs' must be on or off.")
                trust_signed = value
                continue
            if key == "scan_priority":
                if value not in PRIORITIES:
                    raise ApiError(400, "Scan priority must be 'idle' or 'below_normal'.")
                priority = value
                continue
            if key == "clamav_threads":
                if (isinstance(value, bool) or not isinstance(value, (int, float))
                        or not math.isfinite(value) or value != int(value)
                        or not 1 <= value <= CLAMAV_THREADS_MAX):
                    raise ApiError(400, f"Files ClamAV checks at once must be a whole number "
                                        f"from 1 to {CLAMAV_THREADS_MAX}.")
                threads = int(value)
                continue
            if key not in EDITABLE_LIMITS:
                raise ApiError(400, f"'{key}' can't be changed from the page.")
            kind, lo, hi = EDITABLE_LIMITS[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ApiError(400, f"'{key}' must be a number.")
            if kind is int and value != int(value):
                raise ApiError(400, f"'{key}' must be a whole number.")
            if not lo <= value <= hi:
                raise ApiError(400, f"'{key}' must be between {lo:g} and {hi:g}.")
            changes_limits[key] = kind(value)
        if (not changes_limits and priority is None and threads is None and trust_signed is None
                and not phase2 and not phase3 and not phase4_):
            raise ApiError(400, "Nothing to change.")
        before = {k: getattr(self.settings, k) for k in phase3}
        before4 = {k: getattr(self.settings, k) for k in phase4_}
        # save onto what is on disk (so a --port given on the command line is not stored)
        disk = load_settings(self.settings.data_dir)
        for target in (disk, self.settings):
            for k, v in changes_limits.items():
                setattr(target.limits, k, v)
            if priority:
                target.scan_priority = priority
            if threads is not None:
                target.clamav_threads = threads
            if trust_signed is not None:
                target.trust_signed_programs = trust_signed
            for k, v in phase2.items():
                setattr(target, k, v)
            for k, v in phase3.items():
                setattr(target, k, list(v) if isinstance(v, list) else v)
            for k, v in phase4_.items():
                setattr(target, k, v)
        disk.save()
        message = "Saved. The new settings apply to the next scan."
        changed4 = {k for k, v in phase4_.items() if before4.get(k) != v}
        if "tray_enabled" in changed4:
            note = self.apply_tray()
            if note:
                message += " " + note
            elif self.manage_tray:
                message += (" The TacoGuard icon is in the taskbar." if self.settings.tray_enabled
                            else " The TacoGuard icon is gone from the taskbar.")
        if "game_mode_auto" in changed4:
            self.gamemode.wake()
            message += (" Game mode now starts by itself during full-screen games and presentations."
                        if self.settings.game_mode_auto else
                        " Game mode now starts only when you switch it on.")
        if changed4 & {"webblock_enabled", "webblock_phishing_list", "webblock_urlhaus_list",
                       "webblock_allow"} and self.settings.realtime_enabled:
            message += " Website blocking picks up the change within a few seconds."
        offer_remove = False
        if (("webblock_enabled" in changed4 and not self.settings.webblock_enabled)
                or ("webblock_hosts" in changed4 and not self.settings.webblock_hosts)):
            offer_remove = self._hosts_block_present()
            if offer_remove:
                message += " " + HOSTS_REMOVE_OFFER
        if "webblock_allow" in changed4 and self._hosts_block_present():
            message += (" The hosts file block still lists the old choice until you update it "
                        "('Block in the hosts file', one administrator prompt).")
        self._plan_cache = (0.0, None)
        if "self_protection" in changed4:
            message += (" Self-protection applies the next time TacoGuard starts." if self.settings.self_protection
                        else " Self-protection is off from the next time TacoGuard starts.")
        changed3 = {k for k, v in phase3.items() if before.get(k) != v}
        if not self.settings.ransomware_guard and (
                "ransomware_guard" in changed3
                or ("realtime_enabled" in changed3 and not self.settings.realtime_enabled)):
            self.remove_decoys_after_guard()
        if "realtime_enabled" in changed3:
            self.apply_guard()
            message += (" Real-time protection is on." if self.settings.realtime_enabled
                        else " Real-time protection is off.")
        elif changed3 - {"start_at_sign_in"} and self.settings.realtime_enabled:
            message += " Real-time protection picks up the change within a few seconds."
        if "start_at_sign_in" in changed3 or ("start_at_sign_in" in phase3 and self._installed_copy()
                                              and autostart.enabled(self.autostart_key)
                                              != self.settings.start_at_sign_in):
            message += " " + self.apply_autostart()
        if "learning_enabled" in phase2:
            self.sync_learning()
        if "auto_update" in phase2:
            self._apply_auto_update()
            message += (" Automatic update checks are on." if self.settings.auto_update
                        else " Automatic update checks are off: use Check for updates on Home.")
        return {"ok": True, "message": message, "settings": self.settings_view(),
                "offer_hosts_remove": offer_remove}

    def _hosts_block_present(self) -> bool:
        """TacoGuard's block is in Windows' hosts file now (anyone may read it). False when the
        hosts module isn't part of this copy or the file can't be read."""
        mod = self._optional(_load_webblock_hosts)
        fn = getattr(mod, "read_block", None) if mod is not None else None
        if not callable(fn):
            return False
        try:
            return bool(fn(mod.default_hosts_path()).get("present"))
        except Exception:
            return False

    def _web_allow(self, value) -> list[str]:
        """Your "never block these sites" list: website names (example.com), checked and written
        the way the lists hold them; repeats dropped."""
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ApiError(400, "The 'never block' list must be a list of website names.")
        try:
            from ..webblock.lists import normalize
        except ImportError:
            normalize = None
        out: list[str] = []
        for raw in value:
            text = raw.strip()
            if not text:
                continue
            text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text, flags=re.I).split("/", 1)[0]
            if normalize is not None:
                name = normalize(text)
            else:
                name = text.lower() if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}",
                                                    text.lower()) else None
            if not name:
                shown = raw.strip()[:80]
                raise ApiError(400, f"'{shown}' isn't a website name. Write it like example.com "
                                    "(no * and no IP addresses).")
            if name not in out:
                out.append(name)
        if len(out) > WEB_ALLOW_MAX:
            raise ApiError(400, f"The 'never block' list can hold up to {WEB_ALLOW_MAX} websites.")
        return out


# ---------------------------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------------------------
ROUTES: list[tuple[str, re.Pattern, str]] = []


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), fn.__name__))
        return fn
    return deco


def _int(q: dict, name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int((q.get(name) or [default])[0])
    except ValueError:
        raise ApiError(400, f"'{name}' must be a whole number.")
    return max(lo, min(hi, v))


class Api:
    """One method per route. `self.app` is the App; methods get (match, query, body)."""

    def __init__(self, app: App):
        self.app = app
        self.store = app.store
        self.settings = app.settings

    @route("GET", r"/api/status")
    def get_status(self, m, q, body):
        return self.app.status()

    @route("POST", r"/api/quit")
    def post_quit(self, m, q, body):
        self.app.quit()
        return {"ok": True, "message": "TacoGuard's page is closing. You can close this tab."}

    # ---- scans ---------------------------------------------------------------------------
    @route("POST", r"/api/scan")
    def post_scan(self, m, q, body):
        targets = body.get("targets")
        if isinstance(targets, str):
            targets = [targets]
        if not isinstance(targets, list) or not targets:
            raise ApiError(400, "Pick at least one file, folder or drive to scan.")
        if len(targets) > 100 or not all(isinstance(t, str) and 0 < len(t.strip()) < 32000 for t in targets):
            raise ApiError(400, "Those scan targets don't look right.")
        targets = [t.strip().strip('"') for t in targets]
        job_id = jobs.start_scan(self.settings, self.store, targets)
        return {"ok": True, "job_id": job_id, "job": _job_for_page(self.store.get_job(job_id))}

    def _job(self, job_id: int) -> dict:
        j = self.store.get_job(job_id)
        if not j:
            raise ApiError(404, "That scan no longer exists.")
        return j

    @route("GET", r"/api/scan/(\d+)")
    def get_scan(self, m, q, body):
        job_id = int(m.group(1))
        job = self._job(job_id)
        offset = _int(q, "offset", 0, 0, 10**9)
        limit = _int(q, "limit", 200, 1, 1000)
        only = (q.get("section") or [""])[0]
        if only and only not in Store.RESULT_SECTIONS:
            raise ApiError(400, "Unknown section.")
        # counted and paged in SQL: this is polled every 1.5 s while a scan runs
        out = {"job": _job_for_page(job), "totals": self.store.count_result_sections(job_id),
               "offset": offset, "limit": limit}
        for k in Store.RESULT_SECTIONS:
            if not only or only == k:
                rows = self.store.list_result_section(job_id, k, offset if only else 0, limit)
                out[k] = [_result_for_page(r) for r in rows]
                if k == "detections":
                    self.app.with_lookups(out[k])
        return out

    @route("POST", r"/api/scan/(\d+)/(pause|cancel|resume)")
    def post_scan_control(self, m, q, body):
        job_id, what = int(m.group(1)), m.group(2)
        job = self._job(job_id)
        if what == "pause":
            if job["status"] not in JOB_ACTIVE:
                raise ApiError(409, "This scan isn't running, so it can't be paused.")
            jobs.pause_scan(self.store, job_id)
            msg = "Pausing after the current file."
        elif what == "cancel":
            if job["status"] in ("done", "cancelled", "failed"):
                raise ApiError(409, "This scan has already finished.")
            jobs.cancel_scan(self.store, job_id)
            msg = "Stopping the scan after the current file."
        else:
            if job["status"] not in ("paused", "interrupted"):
                raise ApiError(409, "Only a paused or interrupted scan can be resumed.")
            jobs.resume_scan(self.settings, self.store, job_id)
            msg = "Resuming where the scan left off."
        return {"ok": True, "message": msg, "job": _job_for_page(self.store.get_job(job_id))}

    @route("GET", r"/api/jobs")
    def get_jobs(self, m, q, body):
        return {"jobs": [_job_for_page(j) for j in self.store.list_jobs(_int(q, "limit", 20, 1, 200))]}

    @route("GET", r"/api/browse")
    def get_browse(self, m, q, body):
        return browse((q.get("path") or [""])[0])

    # ---- results ---------------------------------------------------------------------------
    @route("GET", r"/api/detections")
    def get_detections(self, m, q, body):
        limit = _int(q, "limit", 200, 1, 1000)
        return {"detections": self.app.with_lookups([_result_for_page(r) for r in self.store.latest_detections(limit)])}

    def _result(self, result_id: int) -> dict:
        r = self.store.get_result(result_id)
        if not r:
            raise ApiError(404, "That result no longer exists.")
        return r

    @route("POST", r"/api/result/(\d+)/(quarantine|trust|confirm)")
    def post_result(self, m, q, body):
        rid, what = int(m.group(1)), m.group(2)
        r = self._result(rid)
        short = _short(r["path"])
        if r["level"] not in (MALWARE, SUSPICIOUS):
            raise ApiError(400, "Only files TacoGuard flagged can be handled here.")
        if what != "confirm" and r.get("action") in ("quarantined", "deleted"):
            raise ApiError(409, f"{short} is already in quarantine or deleted.")
        if what == "trust" and r.get("action") == "trusted":
            raise ApiError(409, f"{short} is already on your trusted list.")
        if what == "quarantine":
            findings = [Finding.from_dict(f) for f in r["findings"]]
            qid = self.app.quarantine().put(r["path"], r["reason"], findings, result_id=rid)
            self.store.set_result_action(rid, "quarantined")
            msg = (f"Quarantined: {short}. It's locked away in encrypted form and can't run. "
                   "Restore it only if you're sure it's safe.")
            return {"ok": True, "message": msg, "quarantine_id": qid,
                    "result": _result_for_page(self.store.get_result(rid))}
        if what == "trust":
            was_listed = self._on_confirmed_list(r["sha256"])
            allow_id = allowlist.mark_not_a_threat(self.store, rid)
            self.app.sync_learning()
            msg = (f"Trusted: {short}. You said it's not a threat. TacoGuard remembers this exact file "
                   "and won't flag it again. You can undo this in the Trusted list.")
            if was_listed and not self._on_confirmed_list(r["sha256"]):
                msg += " It's off your own known-bad list now."
            msg += self._learning_after_trust(r["findings"])
            return {"ok": True, "message": msg, "allow_id": allow_id,
                    "result": _result_for_page(self.store.get_result(rid))}
        before = {(x["engine"], x["rule"]) for x in learning.learned_rules(self.store) if x["active"]}
        allowlist.mark_confirmed_threat(self.store, rid)
        self.app.sync_learning()
        msg = f"Noted: you confirmed {short} is a threat."
        if not self.settings.learning_enabled:
            msg += (" Learning from your choices is off in Settings, so it isn't added to your own "
                    "known-bad list.")
        elif self._on_confirmed_list(r["sha256"]):
            msg += (" Its fingerprint is now on your own known-bad list, so any copy of this exact file "
                    "is flagged as malware in later scans.")
        else:
            msg += " It has no fingerprint (it couldn't be read), so it can't go on your known-bad list."
        after = {(x["engine"], x["rule"]) for x in learning.learned_rules(self.store) if x["active"]}
        cancelled = sorted(before - after)
        if cancelled:
            names = ", ".join(f"'{rule}'" for _, rule in cancelled[:3])
            msg += f" Rules you had taught TacoGuard to count for less ({names}) count normally again."
        if r["sha256"] and r["sha256"].lower() in self.store.allowed_hashes():
            msg += " It's still on your Trusted list, so remove it there or it won't be checked."
        return {"ok": True, "message": msg, "result": _result_for_page(self.store.get_result(rid))}

    def _on_confirmed_list(self, sha256: str) -> bool:
        p = learning.confirmed_list_path(self.settings)
        try:
            return bool(sha256) and sha256.lower() in p.read_text(encoding="utf-8")
        except OSError:
            return False

    def _learning_after_trust(self, findings: list[dict]) -> str:
        """What 'Not a threat' taught TacoGuard about the rules that matched, in plain words."""
        if not self.settings.learning_enabled:
            return (" Learning from your choices is off in Settings, so other files matching the same "
                    "rule are not affected.")
        rules = []
        for f in findings or []:
            key = (str(f.get("engine", "")), str(f.get("rule", "")))
            if key[0] and key[1] and key[0] not in learning.NOT_LEARNED_ENGINES and key not in rules:
                rules.append(key)
        learned = {(x["engine"], x["rule"]): x for x in learning.learned_rules(self.store)}
        parts = []
        for engine, rule in rules[:2]:
            n = learning.safe_count(self.store, engine, rule)
            x = learned.get((engine, rule))
            if x and x["active"]:
                parts.append(f" You've now marked {n} different files matching '{rule}' as safe, so that rule "
                             "counts for less on other files (undo it in Settings, under What TacoGuard has "
                             "learned from you).")
            elif x and x["state"] == learning.FORGOTTEN:
                parts.append(f" You asked TacoGuard to forget rule '{rule}', so it doesn't learn from it.")
            elif x and x["state"] == learning.CANCELLED:
                parts.append(f" Rule '{rule}' keeps counting normally, because you confirmed a file "
                             "matching it as a threat.")
            else:
                parts.append(f" {n} of {learning.LEARN_AFTER} different files matching '{rule}' are now marked "
                             f"safe; at {learning.LEARN_AFTER}, that rule counts for less on other files.")
        return "".join(parts)

    # ---- updates and self-update (Phase 2) --------------------------------------------------
    @route("GET", r"/api/updates")
    def get_updates(self, m, q, body):
        return self.app.updates_view()

    @route("POST", r"/api/updates/check")
    def post_updates_check(self, m, q, body):
        if self.app.get_updater() is None:
            raise ApiError(503, UPDATES_NOT_READY)
        if not self.app.start_update_check():
            raise ApiError(409, "TacoGuard is already checking for updates. Wait for that to finish.")
        return {"ok": True, "message": "Checking for updates. This can take a few minutes; you can keep "
                                       "using the page."}

    def _selfupdate_for_click(self):
        sm = self.app._optional(_load_selfupdate)
        if sm is None:
            raise ApiError(503, SELFUPDATE_NOT_READY)
        view = self.app.app_update_view()
        if not view["installed"]:
            raise ApiError(409, view["note"] or PROJECT_FOLDER_NOTE)
        if self.store.active_jobs():
            raise ApiError(409, "A scan is running. Let it finish (or pause it) first, then try again.")
        return sm

    @route("POST", r"/api/app/update")
    def post_app_update(self, m, q, body):
        version = body.get("version")
        if not isinstance(version, str) or not _VERSION_RE.match(version):
            raise ApiError(400, "Say which version to install.")
        sm = self._selfupdate_for_click()
        offer = self.app._app_offer(sm, fresh=True)
        if not offer:
            raise ApiError(409, "There's no TacoGuard update waiting to be installed.")
        if offer["version"] != version:
            raise ApiError(409, f"The update on offer is now TacoGuard {offer['version']}. Reload the page "
                                "and try again.")
        if not offer["can_install"]:
            raise ApiError(409, offer["message"] or "This update can't be installed yet.")
        if not self.app.start_app_action("update", lambda: self.app.call_selfupdate(sm.install_update, version)):
            raise ApiError(409, "TacoGuard is already installing an update. Wait for that to finish.")
        return {"ok": True, "message": f"Installing TacoGuard {version}. The page restarts by itself in a "
                                       "minute or so. If the new version doesn't start, TacoGuard goes back "
                                       f"to {__version__} automatically."}

    @route("POST", r"/api/app/rollback")
    def post_app_rollback(self, m, q, body):
        sm = self._selfupdate_for_click()
        previous = self.app.app_update_view()["previous"]
        if not previous:
            raise ApiError(409, "There is no earlier version to go back to.")
        if not self.app.start_app_action("rollback", lambda: self.app.call_selfupdate(sm.rollback)):
            raise ApiError(409, "TacoGuard is already changing versions. Wait for that to finish.")
        target = f"TacoGuard {previous}" if previous else "the previous version"
        return {"ok": True, "message": f"Going back to {target}. The page restarts by itself in a minute "
                                       "or so."}

    # ---- learning (Phase 2) -------------------------------------------------------------------
    def _learning_view(self) -> dict:
        return {"enabled": bool(self.settings.learning_enabled), "threshold": learning.LEARN_AFTER,
                "rules": learning.learned_rules(self.store),
                "confirmed_count": learning.confirmed_count(self.store, self.settings)}

    def _learned_rule(self, body) -> tuple[str, str]:
        engine, rule = body.get("engine"), body.get("rule")
        if not (isinstance(engine, str) and isinstance(rule, str) and 0 < len(engine) <= 50
                and 0 < len(rule) <= 1000):
            raise ApiError(400, "Say which rule.")
        if not any(x["engine"] == engine and x["rule"] == rule for x in learning.learned_rules(self.store)):
            raise ApiError(404, "TacoGuard hasn't learned anything about that rule.")
        return engine, rule

    @route("GET", r"/api/learning")
    def get_learning(self, m, q, body):
        return self._learning_view()

    @route("POST", r"/api/learning/forget")
    def post_learning_forget(self, m, q, body):
        engine, rule = self._learned_rule(body)
        learning.forget_rule(self.store, engine, rule)
        return {"ok": True, "message": f"Forgotten: rule '{rule}' counts normally again, and TacoGuard won't "
                                       "learn from it unless you choose Use again.",
                **self._learning_view()}

    @route("POST", r"/api/learning/restore")
    def post_learning_restore(self, m, q, body):
        engine, rule = self._learned_rule(body)
        if not learning.unforget_rule(self.store, engine, rule):
            raise ApiError(409, "TacoGuard is already using what it learned about that rule.")
        return {"ok": True, "message": f"TacoGuard uses what you taught it about rule '{rule}' again.",
                **self._learning_view()}

    # ---- real-time protection (Phase 3) --------------------------------------------------------
    @route("GET", r"/api/protection")
    def get_protection(self, m, q, body):
        return self.app.protection_view()

    @staticmethod
    def _id(body) -> int:
        v = body.get("id")
        if isinstance(v, bool) or not isinstance(v, int) or not 0 < v < 2**62:
            raise ApiError(400, "Say which one.")
        return v

    @staticmethod
    def _action(body, allowed: tuple[str, ...]) -> str:
        a = body.get("action")
        if not isinstance(a, str) or a not in allowed:
            raise ApiError(400, "That action isn't possible here.")
        return a

    def _resolve_event(self, event_id, action: str) -> None:
        if event_id:
            self.store.set_guard_event(int(event_id), state="resolved", action=action)

    def _finish_paused_event(self, row: dict, action: str) -> None:
        """The event that paused this program is resolved once none of its programs is still paused."""
        if not row.get("event_id"):
            return
        others = [p for p in self.store.list_paused(("paused",))
                  if p["event_id"] == row["event_id"] and p["id"] != row["id"]]
        if others:
            self.store.set_guard_event(int(row["event_id"]), action=action)
        else:
            self._resolve_event(row["event_id"], action)

    @staticmethod
    def _quarantined_msg(short: str, findings: list) -> str:
        why = _findings_reason(findings)
        return f"Quarantined: {short}." + (f" {why}." if why else "") + " Restore it only if you're sure it's safe."

    @route("POST", r"/api/protection/event")
    def post_protection_event(self, m, q, body):
        eid = self._id(body)
        action = self._action(body, ("seen", "dismiss", "trust", "quarantine"))
        ev = self.store.get_guard_event(eid)
        if not ev:
            raise ApiError(404, "That alert no longer exists.")
        short = _short(ev["path"]) if ev["path"] else ""
        if action == "seen":
            if ev["state"] == "new":
                self.store.set_guard_event(eid, state="seen")
            return {"ok": True, "message": "Marked as seen."}
        if action == "dismiss":
            self.store.set_guard_event(eid, state="resolved", action=ev["action"] or "dismissed")
            return {"ok": True, "message": "Dismissed. It stays in the history below."}
        if not ev["path"] or ev["kind"] not in ("file", "process"):
            raise ApiError(400, "This alert isn't about a file or a program, so there is nothing to trust or "
                                "quarantine here.")
        if ev["action"] in ("quarantined", "deleted"):
            raise ApiError(409, f"{short} is already in quarantine or deleted.")
        if action == "trust":
            if ev["action"] == "trusted":
                raise ApiError(409, f"{short} is already on your trusted list.")
            sha = (ev["sha256"] or "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ApiError(400, "This file has no fingerprint (it couldn't be read), so it can't be trusted "
                                    "by its fingerprint. Scan it again from the Scan tab first.")
            self.store.add_verdict(sha, ev["path"], "not_a_threat", ev["findings"])
            allow_id = allowlist.trust_hash(self.store, sha, "You said: not a threat", ev["path"])
            self.app.sync_learning()
            self._resolve_event(eid, "trusted")
            return {"ok": True, "allow_id": allow_id,
                    "message": f"Trusted: {short}. You said it's not a threat. TacoGuard remembers this exact "
                               "file and won't flag it again. You can undo this in the Trusted list."}
        data = ev["data"] if isinstance(ev["data"], dict) else {}
        try:
            rid = int(data.get("result_id") or 0)
        except (TypeError, ValueError):
            rid = 0
        findings = [Finding.from_dict(f) for f in ev["findings"] if isinstance(f, dict)]
        reason = ev["message"] or _findings_reason(ev["findings"]) or ev["title"]
        qid = self.app.quarantine().put(ev["path"], reason, findings, result_id=rid)
        if rid and self.store.get_result(rid):
            self.store.set_result_action(rid, "quarantined")
        self._resolve_event(eid, "quarantined")
        return {"ok": True, "quarantine_id": qid, "message": self._quarantined_msg(short, ev["findings"])}

    @route("POST", r"/api/protection/paused")
    def post_protection_paused(self, m, q, body):
        paused_id = self._id(body)
        action = self._action(body, ("resume", "end", "quarantine"))
        row = self.store.get_paused(paused_id)
        if not row:
            raise ApiError(404, "That paused program is no longer listed.")
        short = _short(row["exe"]) if row["exe"] else (row["name"] or "The program")
        if row["state"] != "paused":
            raise ApiError(409, f"{short} isn't paused any more.")
        ref = procctl.ProcRef(int(row["pid"]), float(row["create_time"]))
        ev = self.store.get_guard_event(int(row["event_id"])) if row["event_id"] else None
        if action == "resume":
            try:
                procctl.resume(ref)
            except procctl.ProcError as e:
                if not procctl.is_alive(ref):
                    self.store.set_paused_state(paused_id, "gone")
                raise ApiError(409, str(e))
            self.store.set_paused_state(paused_id, "resumed")
            self._finish_paused_event(row, "resumed")
            return {"ok": True, "message": f"Resumed: {short}. It runs normally again."}
        if action == "quarantine" and not row["exe"]:
            raise ApiError(400, "TacoGuard doesn't know which file this program runs from, so it can't "
                                "quarantine it. Use End it instead.")
        if procctl.is_alive(ref):
            try:
                procctl.terminate(ref)
            except procctl.ProcError as e:
                if procctl.is_alive(ref):
                    raise ApiError(409, str(e))
        self.store.set_paused_state(paused_id, "ended")
        if action == "end":
            self._finish_paused_event(row, "ended")
            return {"ok": True, "message": f"Ended: {short}. Its program file is still there: scan it or "
                                           "quarantine it if you're not sure about it."}
        findings_raw = (ev or {}).get("findings") or []
        findings = [Finding.from_dict(f) for f in findings_raw if isinstance(f, dict)]
        reason = (ev or {}).get("message") or row["reason"] or "Paused by TacoGuard's real-time protection."
        try:
            qid = self.app.quarantine().put(row["exe"], reason, findings, result_id=0)
        except (quarantine.QuarantineError, ValueError) as e:
            raise ApiError(400, f"{short} was ended, but its file could not be quarantined: "
                                f"{str(e) or 'that did not work'}")
        except OSError as e:
            self.app.log.error("quarantine after end failed\n%s", traceback.format_exc())
            raise ApiError(400, f"{short} was ended, but its file could not be quarantined "
                                f"({plain_error(e)}). Try Quarantine again from the alert.")
        self._finish_paused_event(row, "quarantined")
        return {"ok": True, "quarantine_id": qid, "message": self._quarantined_msg(short, findings_raw)}

    def _persistence(self):
        """A PersistenceWatcher made just for one action (guard/persistence.py, Helper K)."""
        mod = self.app._optional(_load_persistence)
        if mod is None or not hasattr(mod, "PersistenceWatcher"):
            raise ApiError(503, PERSISTENCE_NOT_READY)
        return mod.PersistenceWatcher(self.settings, self.store, checker=None)

    STARTUP_FROM = {"keep": ("new",), "undo": ("new", "kept"), "restore": ("undone",)}
    STARTUP_DONE = {"keep": "kept", "undo": "undone", "restore": "restored"}

    @route("POST", r"/api/protection/startup")
    def post_protection_startup(self, m, q, body):
        key = body.get("key")
        if not isinstance(key, str) or not 0 < len(key) <= 4000:
            raise ApiError(400, "Say which start-up entry.")
        action = self._action(body, ("keep", "undo", "restore"))
        row = self.store.get_persistence(key)
        if not row:
            raise ApiError(404, "That start-up entry is no longer listed.")
        name = row["name"] or "This entry"
        if row["state"] not in self.STARTUP_FROM[action]:
            words = {"keep": (f"'{name}' was undone: use Put it back to restore it." if row["state"] == "undone"
                              else f"'{name}' was already handled."),
                     "undo": f"'{name}' can't be undone from here now.",
                     "restore": f"'{name}' wasn't undone, so there is nothing to put back."}
            raise ApiError(409, words[action])
        watcher = self._persistence()
        out = getattr(watcher, action)(key)
        if action == "keep":
            after = self.store.get_persistence(key)
            if after and after["state"] == row["state"]:
                self.store.put_persistence(key, state="kept")
        defaults = {"keep": f"Kept: '{name}' stays in your start-up programs.",
                    "undo": f"Undone: '{name}' won't start with Windows any more. TacoGuard kept a copy, so "
                            "you can put it back.",
                    "restore": f"Put back: '{name}' starts with Windows again."}
        self._resolve_event(row.get("event_id"), self.STARTUP_DONE[action])
        return {"ok": True, "message": out.strip() if isinstance(out, str) and out.strip() else defaults[action]}

    # ---- Phase 4: dashboard, pause, Game mode -----------------------------------------------------
    @route("GET", r"/api/dashboard")
    def get_dashboard(self, m, q, body):
        return self.app.dashboard_view()

    @route("POST", r"/api/protection/pause")
    def post_protection_pause(self, m, q, body):
        minutes = body.get("minutes")
        if (isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or not math.isfinite(minutes)
                or minutes != int(minutes) or not 0 <= minutes <= PAUSE_MAX_MIN):
            raise ApiError(400, f"Pause for 1 to {PAUSE_MAX_MIN} minutes, or 0 to resume.")
        if minutes == 0:
            self.app.resume_protection()
            msg = "Real-time protection is on again."
        else:
            if not self.settings.realtime_enabled:
                raise ApiError(409, "Real-time protection is off in Settings, so there is nothing to pause.")
            until = self.app.pause_protection(int(minutes) * 60)
            msg = (f"Real-time protection is paused until {time.strftime('%H:%M', time.localtime(until))}. "
                   "It starts again by itself then, or press Resume. Scans you start yourself still work.")
        return {"ok": True, "message": msg, "modes": self.app.modes_view()}

    @route("POST", r"/api/gamemode")
    def post_gamemode(self, m, q, body):
        on = body.get("on")
        if not isinstance(on, bool):
            raise ApiError(400, "Say whether Game mode should be on or off.")
        self.app.switch_game_mode(on)
        if on:
            msg = ("Game mode is on until you turn it off (at the latest for 4 hours, or until TacoGuard "
                   "restarts). Scans wait, update checks wait and TacoGuard shows no pop-up notifications. "
                   "Real-time checks keep running.")
        else:
            msg = "Game mode is off."
            if self.settings.game_mode_auto and gamemode.respect_until(self.store) > time.time():
                msg += " TacoGuard won't switch it on by itself again for the next 2 hours."
        return {"ok": True, "message": msg, "modes": self.app.modes_view()}

    # ---- Phase 4: website blocking ----------------------------------------------------------------
    @route("GET", r"/api/webblock")
    def get_webblock(self, m, q, body):
        return self.app.webblock_view()

    @route("POST", r"/api/webblock/hosts")
    def post_webblock_hosts(self, m, q, body):
        action = self._action(body, ("apply", "remove"))
        if not self.app.start_hosts_action(action):
            raise ApiError(409, "TacoGuard is already working on the hosts file. Answer Windows' prompt first "
                                "(it may be behind this window, blinking in the taskbar).")
        what = ("block these websites in the hosts file" if action == "apply"
                else "take TacoGuard's block out of the hosts file")
        return {"ok": True, "message": f"Windows now asks for permission to {what} (an administrator prompt). "
                                       "TacoGuard waits for your answer.",
                "hosts": self.app.hosts_view()}

    @route("POST", r"/api/webblock/refresh")
    def post_webblock_refresh(self, m, q, body):
        if not self.settings.webblock_enabled:
            raise ApiError(409, "Website blocking is off in Settings, so there are no lists to update.")
        mod = self.app._optional(_load_webblock_lists)
        busy = getattr(mod, "busy", None) if mod is not None else None
        if callable(busy):
            try:
                is_busy = bool(busy(self.settings))
            except Exception:
                is_busy = False
            if is_busy:
                raise ApiError(409, "TacoGuard is already updating the website lists in the background. "
                                    "Wait a few minutes; they show here when it's done.")
        if not self.app.start_lists_refresh():
            raise ApiError(409, "TacoGuard is already updating the website lists. Wait for that to finish.")
        return {"ok": True, "message": "Updating the website lists. This can take a minute."}

    # ---- Phase 4: the abuse.ch key (never echoed, never logged) ------------------------------------
    @route("POST", r"/api/secrets/abusech")
    def post_secret_abusech(self, m, q, body):
        sec = self.app._optional(_load_secrets)
        if sec is None:
            raise ApiError(503, SECRETS_NOT_READY)
        clear = body.get("clear", False)
        if not isinstance(clear, bool):
            raise ApiError(400, "Say whether to remove the key.")
        if clear and "key" in body:
            raise ApiError(400, "Either paste a key or remove it, not both.")
        if clear:
            try:
                removed = bool(sec.clear_key(self.settings, ABUSECH))
            except Exception as e:
                self.app.log.error("removing the abuse.ch key failed (%s)", type(e).__name__)
                raise ApiError(500, "Windows could not remove the key. Try again.")
            msg = ("Removed. MalwareBazaar lookups and the URLhaus list stop until you add a key again."
                   if removed else "There was no key to remove.")
        elif "key" in body:
            value = body.get("key")
            if not isinstance(value, str) or not value.strip() or len(value) > 1000:
                raise ApiError(400, KEY_BAD_MSG)
            try:
                sec.set_key(self.settings, ABUSECH, value)
            except ValueError as e:
                text = str(e)
                squeezed = re.sub(r"\s+", "", value)
                if not text or (squeezed and squeezed in text) or value.strip() in text:
                    text = KEY_BAD_MSG              # never show the key back, even by accident
                raise ApiError(400, text)
            except Exception as e:
                self.app.log.error("saving the abuse.ch key failed (%s)", type(e).__name__)
                raise ApiError(500, KEY_SAVE_FAILED)
            self.app.log.info("an abuse.ch key was saved")
            msg = "Saved. MalwareBazaar lookups and the URLhaus list can use your key now."
        else:
            raise ApiError(400, "Paste your abuse.ch key first, or choose Remove.")
        k = self.app.key_view()
        return {"ok": True, "set": k["set"], "hint": k["hint"], "message": msg}

    # ---- Phase 4: MalwareBazaar lookup of a flagged file ----------------------------------------------
    def _flagged_sha(self, body) -> tuple[str, str]:
        """(sha256, short name) of a file TacoGuard flagged; only those are ever looked up."""
        keys = [k for k in ("result_id", "event_id", "sha256") if k in body]
        if len(keys) != 1:
            raise ApiError(400, "Say which file to look up.")
        key, value = keys[0], body[keys[0]]
        if key in ("result_id", "event_id"):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**62:
                raise ApiError(400, "Say which file to look up.")
        if key == "result_id":
            r = self._result(value)
            if r["level"] not in FLAGGED_LEVELS:
                raise ApiError(400, "TacoGuard only looks up files it flagged.")
            sha, path = str(r.get("sha256") or ""), r["path"]
        elif key == "event_id":
            ev = self.store.get_guard_event(value)
            if not ev:
                raise ApiError(404, "That alert no longer exists.")
            if ev["level"] not in FLAGGED_LEVELS or not ev["path"] or ev["kind"] not in ("file", "process"):
                raise ApiError(400, "TacoGuard only looks up files it flagged.")
            sha, path = str(ev.get("sha256") or ""), ev["path"]
        else:
            if not isinstance(value, str) or not SHA256_RE.match(value.strip().lower()):
                raise ApiError(400, "That isn't a SHA-256 fingerprint (64 letters and digits).")
            sha = value.strip().lower()
            path = next((d["path"] for d in self.store.latest_detections(1000)
                         if (d.get("sha256") or "").lower() == sha and d["level"] in FLAGGED_LEVELS), "")
            if not path:
                path = next((e["path"] for e in self.store.list_guard_events(limit=1000)
                             if (e.get("sha256") or "").lower() == sha and e["level"] in FLAGGED_LEVELS
                             and e["path"]), "")
            if not path:
                raise ApiError(400, "TacoGuard only looks up files it flagged.")
        sha = sha.lower()
        if not SHA256_RE.match(sha):
            raise ApiError(400, "This file has no fingerprint (it couldn't be read), so it can't be looked up. "
                                "Scan it again first.")
        return sha, _short(path)

    @route("POST", r"/api/lookup")
    def post_lookup(self, m, q, body):
        mod = self.app._optional(_load_lookup)
        if mod is None:
            raise ApiError(503, LOOKUP_NOT_READY)
        sha, short = self._flagged_sha(body)
        if not self.settings.lookup_enabled:
            raise ApiError(409, "MalwareBazaar lookups are off in Settings.")
        if not self.app.key_view()["set"]:
            raise ApiError(409, "Add your free abuse.ch key in Settings first, then try again.")
        info = mod.lookup(self.settings, self.store, sha, force=True)
        if not isinstance(info, dict):
            msg = ""
            try:
                st = mod.status(self.store) or {}
                if st.get("state") not in ("", "ok"):
                    msg = str(st.get("message") or "")
            except Exception:
                pass
            raise ApiError(503, msg or "MalwareBazaar didn't answer. TacoGuard will try again later.")
        found = bool(info.get("found"))
        if found:
            sig = str(info.get("signature") or "")
            text = str(info.get("message") or "") or (
                f"MalwareBazaar has a copy of this exact file, uploaded as '{sig or 'unnamed'}'.")
        else:
            text = (str(info.get("message") or "") or "MalwareBazaar doesn't know this exact file.") + \
                " That doesn't make it safe: new or rare files are often not listed."
        return {"ok": True, "found": found, "message": f"{short}: {text}",
                "signature": str(info.get("signature") or ""), "file_type": str(info.get("file_type") or ""),
                "first_seen": str(info.get("first_seen") or ""),
                "tags": [str(t) for t in (info.get("tags") or []) if isinstance(t, str)][:20],
                "link": f"https://bazaar.abuse.ch/sample/{sha}/", "lookup": self.app.lookup_note(sha)}

    # ---- quarantine -------------------------------------------------------------------------
    @route("GET", r"/api/quarantine")
    def get_quarantine(self, m, q, body):
        try:
            qu = self.app.quarantine()
            items, used, available, note = qu.items(), int(qu.used_bytes()), True, ""
        except NotImplementedError:
            items = self.store.list_quarantine()
            used, available, note = sum(i["size"] for i in items), False, "Quarantine is not ready yet."
        for i in items:
            i["short"] = _short(i.get("original_path", ""))
        return {"items": items, "bytes": used, "available": available, "message": note,
                "folder": str(self.settings.quarantine_dir)}

    def _qitem(self, qid: int) -> dict:
        item = self.store.get_quarantine(qid)
        if not item or item["state"] != "quarantined":
            raise ApiError(404, "That file is no longer in quarantine.")
        return item

    @route("POST", r"/api/quarantine/(\d+)/(restore|delete)")
    def post_quarantine(self, m, q, body):
        qid, what = int(m.group(1)), m.group(2)
        item = self._qitem(qid)
        qu = self.app.quarantine()
        if what == "restore":
            trust = body.get("trust", False)
            if not isinstance(trust, bool):
                raise ApiError(400, "'trust' must be true or false.")
            where = qu.restore(qid, trust=trust)
            if item.get("result_id"):
                self.store.set_result_action(item["result_id"], "restored")
            msg = f"Restored: {_short(where)}."
            if trust:
                msg += " It's on your trusted list, so TacoGuard won't flag this exact file again."
            return {"ok": True, "message": msg, "path": where}
        qu.delete(qid)
        if item.get("result_id"):
            self.store.set_result_action(item["result_id"], "deleted")
        return {"ok": True, "message": f"Deleted for good: {_short(item['original_path'])}."}

    # ---- allowlist ---------------------------------------------------------------------------
    @route("GET", r"/api/allowlist")
    def get_allowlist(self, m, q, body):
        items = self.store.list_allow()
        for i in items:
            i["short"] = _short(i["value"]) if i["kind"] == "folder" else i["value"]
        return {"items": items}

    @route("POST", r"/api/allowlist")
    def post_allowlist(self, m, q, body):
        kind, value = body.get("kind"), body.get("value")
        note = body.get("note") or ""
        if not isinstance(value, str) or not value.strip() or len(value) > 32000:
            raise ApiError(400, "Type a file hash or pick a folder first.")
        if not isinstance(note, str) or len(note) > 500:
            raise ApiError(400, "The note is too long (500 characters at most).")
        if kind == "hash":
            allow_id = allowlist.trust_hash(self.store, value, note or "Added by you")
            msg = "Added. Any file with this exact hash won't be flagged."
        elif kind == "folder":
            allow_id = allowlist.trust_folder(self.store, value.strip().strip('"'), note or "Added by you")
            msg = "Added. Files inside this folder won't be checked any more."
        else:
            raise ApiError(400, "Choose whether to trust a file hash or a folder.")
        return {"ok": True, "id": allow_id, "message": msg}

    @route("POST", r"/api/allowlist/(\d+)/remove")
    def post_allowlist_remove(self, m, q, body):
        allowlist.untrust(self.store, int(m.group(1)))
        return {"ok": True, "message": "Removed from your trusted list. It will be checked again."}

    # ---- setup -------------------------------------------------------------------------------
    @route("GET", r"/api/setup")
    def get_setup(self, m, q, body):
        st = self.app.setup_state
        return {"running": st["running"], "lines": list(st["lines"][-200:]), "result": st["result"],
                "error": st["error"], "started": st["started"], "finished": st["finished"]}

    @route("POST", r"/api/setup")
    def post_setup(self, m, q, body):
        if not self.app.start_setup():
            raise ApiError(409, "Signatures are already being downloaded. Wait for that to finish.")
        return {"ok": True, "message": "Getting signatures. This can take a few minutes."}

    # ---- settings ----------------------------------------------------------------------------
    @route("GET", r"/api/settings")
    def get_settings(self, m, q, body):
        return self.app.settings_view()

    @route("POST", r"/api/settings")
    def post_settings(self, m, q, body):
        return self.app.update_settings(body)


# ---------------------------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------------------------
class _DeadlineReader(io.RawIOBase):
    """The connection's incoming side. Each wait is at most `idle` seconds, and while
    `deadline` is set (reading a request's first line and headers) no wait goes past it."""

    def __init__(self, sock: socket.socket, idle: float | None):
        self.sock = sock
        self.idle = idle
        self.deadline: float | None = None

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        wait = self.idle
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("the request did not arrive in time")
            wait = left if wait is None else min(wait, left)
        self.sock.settimeout(wait)
        return self.sock.recv_into(b)


class Handler(BaseHTTPRequestHandler):
    server_version = "TacoGuard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    timeout = CONNECTION_TIMEOUT_S   # an idle or slow connection is closed after this long
    header_deadline = HEADER_DEADLINE_S   # the request line + headers must all arrive within this

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def setup(self):
        super().setup()
        plain = self.rfile
        self._reader = _DeadlineReader(self.connection, self.timeout)
        self.rfile = io.BufferedReader(self._reader)
        plain.close()                        # (the socket itself stays open)

    def handle_one_request(self):
        # The clock starts while we wait for the request line and runs until the headers are
        # in, however slowly they drip in: a client that never finishes loses its slot.
        self._reader.deadline = time.monotonic() + self.header_deadline
        try:
            super().handle_one_request()
        finally:
            self._reader.deadline = None

    def parse_request(self):
        try:
            return super().parse_request()   # reads the headers
        finally:
            self._reader.deadline = None     # the body (if any) only has the idle timeout
            self.connection.settimeout(self.timeout)   # and so does sending the answer

    # ---- output ------------------------------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def send_error(self, code, message=None, explain=None):  # malformed requests: plain JSON, our headers
        self.close_connection = True
        try:
            self._error(int(code), message or HTTPStatus(code).phrase)
        except Exception:
            pass

    def log_message(self, fmt, *args):
        # Only the request line is logged, never a body. A query string on the key route is cut
        # off too, in case something ever sends a key that way.
        try:
            text = fmt % args
            if SECRET_PATH_PREFIX in text:
                text = re.sub(r"(/api/secrets/[^\s?\"]*)\?[^\s\"]*", r"\1?(hidden)", text)
            self.app.log.info("%s %s", self.address_string(), text)
        except Exception:
            pass

    def finish(self):
        try:
            super().finish()
        finally:
            try:
                self.app.store.close()   # this thread's SQLite connection
            except Exception:
                pass

    # ---- checks ------------------------------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.app.port
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        port = self.app.port
        return origin.strip().lower() in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

    def _token_ok(self) -> bool:
        got = self.headers.get(TOKEN_HEADER) or ""
        return hmac.compare_digest(got.encode("utf-8", "replace"), self.app.token.encode())

    def _read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise ApiError(411, "Send the request with a Content-Length.")
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "Bad Content-Length.")
        if length < 0:
            self.close_connection = True
            raise ApiError(400, "Bad Content-Length.")
        if length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "That request is too big (1 MB at most).")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if ctype != "application/json":
            raise ApiError(415, "Requests must be sent as JSON.")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(400, "The request was not valid JSON.")
        if not isinstance(body, dict):
            raise ApiError(400, "The request must be a JSON object.")
        return body

    # ---- dispatch ------------------------------------------------------------------------------
    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _not_allowed(self):
        self.close_connection = True
        self._error(405, "That method is not allowed.")

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _not_allowed

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except ApiError as e:
            self._error(e.status, e.message)
        except (ConnectionError, socket.timeout):
            self.close_connection = True
        except Exception:
            self.app.log.error("unexpected error on %s %s\n%s", method, self.path.split("?")[0],
                               traceback.format_exc())
            self._error(500, "Something went wrong on TacoGuard's side. Details were written to "
                             f"{self.app.settings.log_dir / 'web.log'}.")

    def _dispatch(self, method: str) -> None:
        # (the same-Windows-user check already ran when the connection was accepted,
        # see TacoServer.process_request)
        if not self._host_ok():
            self.close_connection = True
            raise ApiError(403, "Wrong address. Open TacoGuard at the address it printed when it started.")
        url = urlsplit(self.path)
        path = url.path
        if not path.startswith("/api/"):
            if method != "GET":
                self.close_connection = True
                raise ApiError(405, "That method is not allowed.")
            entry = STATIC_FILES.get(path)
            if not entry:
                raise ApiError(404, "Not found.")
            self._send(200, self.app.static[entry[0]], entry[1])
            return
        if path == "/api/ping" and method == "GET":
            self._json(200, {"app": APP_NAME, "version": __version__})
            return
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            self.close_connection = True
            raise ApiError(403, "Requests from other websites are refused.")
        if method != "GET" and not self._origin_ok():
            self.close_connection = True
            raise ApiError(403, "Requests from other websites are refused.")
        if not self._token_ok():
            self.close_connection = True
            raise ApiError(403, "Missing or wrong page key. Reload the TacoGuard page.")
        body = self._read_json() if method == "POST" else {}
        query = parse_qs(url.query, keep_blank_values=True)
        allowed_here = False
        for m_, pattern, name in ROUTES:
            match = pattern.match(path)
            if not match:
                continue
            allowed_here = True
            if m_ != method:
                continue
            api = Api(self.app)
            try:
                out = getattr(api, name)(match, query, body)
            except ApiError:
                raise
            except NotImplementedError:
                raise ApiError(503, NOT_READY)
            except (allowlist.AllowlistError, quarantine.QuarantineError, setup_fetch.FetchError) as e:
                raise ApiError(400, str(e) or "That didn't work.")
            except ValueError as e:
                raise ApiError(400, str(e) or "That didn't work.")
            except PermissionError as e:
                raise ApiError(403, f"Windows refused access: {winpath.to_display(e.filename or '') or e.strerror}")
            except FileNotFoundError as e:
                raise ApiError(404, f"Not found: {winpath.to_display(e.filename or '') or e.strerror}")
            except OSError as e:   # never show raw "[WinError 32] ..." text on the page
                self.app.log.error("Windows error on %s %s\n%s", method, path, traceback.format_exc())
                raise ApiError(500, f"Windows stopped that from finishing ({plain_error(e)}). "
                                    "Please try again.")
            self._json(200, out)
            return
        if allowed_here:
            raise ApiError(405, "That method is not allowed here.")
        raise ApiError(404, "Unknown address.")


class TacoServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, app: App, port: int, max_connections: int = MAX_CONNECTIONS):
        self.app = app
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(("127.0.0.1", port), Handler)

    # First: is the other end the same Windows user? If not, a quick 403 and the connection is
    # closed before it can take a slot. Then at most `max_connections` handler threads; over
    # that, answer 503 at once. Both answers come from the accepting thread, so it never waits
    # on the busy ones.
    def process_request(self, request, client_address):
        verdict = client_verdict(tuple(client_address[:2]), tuple(self.server_address[:2]))
        if verdict != SAME:
            self._refuse(request, "403 Forbidden",
                         UNCONFIRMED_MSG if verdict == UNCONFIRMED else OTHER_USER_MSG)
            return
        if not self.slots.acquire(blocking=False):
            self._refuse(request, "503 Service Unavailable", BUSY_MSG, ["Retry-After: 2"])
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def _refuse(self, request, status: str, message: str, extra: list[str] | None = None) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        head = [f"HTTP/1.1 {status}", "Content-Type: application/json; charset=utf-8",
                f"Content-Length: {len(body)}", "Connection: close", *(extra or [])]
        head += [f"{k}: {v}" for k, v in SECURITY_HEADERS.items()]
        try:
            request.settimeout(0.05)
            try:
                request.recv(64 * 1024)   # take the request first, so closing doesn't reset it
            except OSError:
                pass
            request.settimeout(1.0)
            request.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def make_server(app: App, port: int | None = None) -> TacoServer:
    """Bind (raises OSError when the port is taken). port=0 picks a free port (tests)."""
    srv = TacoServer(app, app.settings.port if port is None else port)
    app.port = srv.server_address[1]
    app.server = srv
    return srv


def is_tacoguard_at(port: int, timeout: float = 3.0) -> bool:
    try:
        con = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        con.request("GET", "/api/ping", headers={"Host": f"127.0.0.1:{port}"})
        resp = con.getresponse()
        data = json.loads(resp.read(4096).decode("utf-8", "replace"))
        con.close()
        return resp.status == 200 and data.get("app") == APP_NAME
    except (OSError, ValueError, http.client.HTTPException):
        return False


def serve(settings, open_browser: bool = True, guard: bool | None = None) -> int:
    """The page. guard=None starts real-time protection (the guard process, when
    settings.realtime_enabled), self-protection, automatic Game mode and the tray icon, except
    while pytest runs: a test never starts the real guard or adds a real icon."""
    if guard is None:
        guard = not os.environ.get("PYTEST_CURRENT_TEST")
    app = App(settings)
    port = settings.port
    try:
        httpd = make_server(app, port)
    except OSError:
        app.close()
        url = f"http://127.0.0.1:{port}/"
        if is_tacoguard_at(port):
            print(f"TacoGuard is already running at {url}")
            if open_browser:
                webbrowser.open(url)
            return 0
        print(f"Port {port} is already used by another program, so TacoGuard's page can't start.\n"
              f"Close that program, or start TacoGuard on another port: "
              f"python -m tacoguard serve --port {port + 1}")
        return 1
    url = f"http://127.0.0.1:{app.port}/"
    app.startup()
    app.start_updates()   # finishes an update cut off last time, then checks (settings.auto_update)
    if guard:
        app.harden()       # self-protection (settings.self_protection) before anything else starts
        app.start_guard()  # real-time protection (settings.realtime_enabled), stopped by app.close()
        app.start_gamemode()   # automatic Game mode (settings.game_mode_auto)
        app.start_tray()   # the notification-area icon (settings.tray_enabled), removed by app.close()
    defender.peek()  # start reading Defender's status in the background
    print(f"TacoGuard is running at {url}")
    print("Keep this window open while you use the page. Press Ctrl+C here to stop.")
    if open_browser:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Stopping TacoGuard's page.")
    finally:
        httpd.server_close()
        app.close()   # also stops the background update checks
    print("TacoGuard's page has stopped.")
    return 0
