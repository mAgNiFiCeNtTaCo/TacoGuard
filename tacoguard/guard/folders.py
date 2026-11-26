"""Watching folders: WatchHub (Windows' change notifications), FolderWatcher (the "folders" part).

WatchHub runs one thread per watched root folder. Each thread asks Windows for changes with
ReadDirectoryChangesW (overlapped I/O, so stop() wakes it at once) and hands every change to the
subscribers of that root as an FsEvent. The folder is opened with read/write/delete sharing, so
watching never stops anyone from renaming, deleting or unplugging it. A root that is missing or
goes away (a USB drive unplugged) is retried every 30 s; when it comes back the subscribers get
an "overflow" event, meaning "changes may have been missed: look again yourself".

FolderWatcher checks new and changed files in the watched folders: a file is checked once it has
been quiet for 2 s (no change events, size and time stable), files that are still downloading
(*.crdownload, *.part, ...) are left alone until they get their final name, and links are never
followed. One check at a time, on its own thread; at most 2,000 files wait, newest first.
"""
from __future__ import annotations

import ctypes
import heapq
import itertools
import logging
import os
import struct
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field

from .. import winpath
from ..model import MALWARE, SKIPPED, SUSPICIOUS, UNREADABLE
from ..scan import engine

log = logging.getLogger("tacoguard.guard")

# ---- Windows API --------------------------------------------------------------------------------
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_ALL = 0x7                     # read | write | delete
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a folder
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x002
FILE_NOTIFY_CHANGE_SIZE = 0x008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x010
NOTIFY_FILTER = (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE
                 | FILE_NOTIFY_CHANGE_LAST_WRITE)
BUFFER_BYTES = 64 * 1024
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
ERROR_NOTIFY_ENUM_DIR = 1022             # Windows' buffer overflowed: "enumerate the folder yourself"
ERROR_OPERATION_ABORTED = 995
INVALID_HANDLE = wintypes.HANDLE(-1).value

ACTIONS = {1: "added", 2: "removed", 3: "modified", 4: "renamed_from", 5: "renamed_to"}


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_k32.ReadDirectoryChangesW.restype = wintypes.BOOL
_k32.ReadDirectoryChangesW.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.BOOL,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                       ctypes.POINTER(OVERLAPPED), wintypes.LPVOID)
_k32.GetOverlappedResult.restype = wintypes.BOOL
_k32.GetOverlappedResult.argtypes = (wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
                                     ctypes.POINTER(wintypes.DWORD), wintypes.BOOL)
_k32.CancelIoEx.restype = wintypes.BOOL
_k32.CancelIoEx.argtypes = (wintypes.HANDLE, ctypes.POINTER(OVERLAPPED))
_k32.CreateEventW.restype = wintypes.HANDLE
_k32.CreateEventW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
_k32.SetEvent.argtypes = (wintypes.HANDLE,)
_k32.ResetEvent.argtypes = (wintypes.HANDLE,)
_k32.WaitForMultipleObjects.restype = wintypes.DWORD
_k32.WaitForMultipleObjects.argtypes = (wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL,
                                        wintypes.DWORD)
_k32.CloseHandle.argtypes = (wintypes.HANDLE,)
_k32.GetDriveTypeW.restype = wintypes.UINT
_k32.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)


# ---- events and the hub ---------------------------------------------------------------------------
@dataclass
class FsEvent:
    action: str        # "added" | "modified" | "removed" | "renamed_from" | "renamed_to" | "overflow"
    path: str          # display path (for "overflow": the watched root)
    ts: float = field(default_factory=time.time)


def _norm_root(root: str) -> str:
    return winpath.to_display(os.path.abspath(winpath.to_display(str(root))))


def parse_notify(raw: bytes) -> list[tuple[str, str]]:
    """FILE_NOTIFY_INFORMATION records -> [(action, name relative to the root)]."""
    out, off = [], 0
    while off + 12 <= len(raw):
        next_off, action, name_len = struct.unpack_from("<III", raw, off)
        name = raw[off + 12: off + 12 + name_len].decode("utf-16-le", "replace")
        if action in ACTIONS and name:
            out.append((ACTIONS[action], name))
        if next_off == 0:
            break
        off += next_off
    return out


class _RootWatch:
    """One watched folder: a thread blocked in ReadDirectoryChangesW."""

    def __init__(self, hub: "WatchHub", root: str):
        self.hub, self.root = hub, root
        self.long = winpath.to_long(root)
        self.state = "starting"          # starting | ok | missing
        self._stop_evt = _k32.CreateEventW(None, True, False, None)   # manual reset
        self._stopping = False
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread is None:
            self.thread = threading.Thread(target=self._run, name=f"tacoguard-watch {self.root}",
                                           daemon=True)
            self.thread.start()

    def stop(self, wait: float = 5.0) -> None:
        self._stopping = True
        _k32.SetEvent(self._stop_evt)
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(wait)
        if self.thread is None or not self.thread.is_alive():
            if self._stop_evt:
                _k32.CloseHandle(self._stop_evt)
                self._stop_evt = None

    def _wait_stop(self, seconds: float) -> bool:
        """Waits up to `seconds`; True when stop() was called."""
        if self._stopping:
            return True
        arr = (wintypes.HANDLE * 1)(self._stop_evt)
        _k32.WaitForMultipleObjects(1, arr, False, int(max(0.0, seconds) * 1000))
        return self._stopping

    def _run(self) -> None:
        first = True
        while not self._stopping:
            h = _k32.CreateFileW(self.long, FILE_LIST_DIRECTORY, FILE_SHARE_ALL, None, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, None)
            if not h or h == INVALID_HANDLE:
                if self.state != "missing":
                    log.info("Watched folder not available, retrying every %ss: %s",
                             self.hub.RETRY_S, self.root)
                self.state = "missing"
                if self._wait_stop(self.hub.RETRY_S):
                    break
                continue
            try:
                if not first:      # back after a gap: changes may have been missed
                    log.info("Watched folder is back: %s", self.root)
                    self.hub._dispatch(self.root, [FsEvent("overflow", self.root)])
                first = False
                self.state = "ok"
                self._read_loop(h)
            except Exception:
                log.exception("Watching %s failed", self.root)
            finally:
                _k32.CloseHandle(h)
            if self._stopping:
                break
            self.state = "missing"
            if self._wait_stop(self.hub.RETRY_S if not os.path.isdir(self.long) else 1.0):
                break

    def _read_loop(self, h) -> None:
        buf = (ctypes.c_uint32 * (BUFFER_BYTES // 4))()     # DWORD aligned, as Windows needs
        io_evt = _k32.CreateEventW(None, True, False, None)
        try:
            ov = OVERLAPPED()
            ov.hEvent = io_evt
            handles = (wintypes.HANDLE * 2)(io_evt, self._stop_evt)
            n = wintypes.DWORD(0)
            while not self._stopping:
                _k32.ResetEvent(io_evt)
                if not _k32.ReadDirectoryChangesW(h, buf, BUFFER_BYTES, True, NOTIFY_FILTER, None,
                                                  ctypes.byref(ov), None):
                    return          # the folder went away (or Windows refused): retry later
                r = _k32.WaitForMultipleObjects(2, handles, False, INFINITE)
                if r != WAIT_OBJECT_0:              # stop() was called (or the wait failed)
                    _k32.CancelIoEx(h, ctypes.byref(ov))
                    _k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(n), True)
                    return
                if not _k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(n), False):
                    if ctypes.get_last_error() == ERROR_NOTIFY_ENUM_DIR:
                        self.hub._dispatch(self.root, [FsEvent("overflow", self.root)])
                        continue
                    return
                if n.value == 0:                    # too many changes for the buffer
                    if not os.path.isdir(self.long):
                        return
                    self.hub._dispatch(self.root, [FsEvent("overflow", self.root)])
                    continue
                raw = ctypes.string_at(ctypes.addressof(buf), n.value)
                now = time.time()
                events = [FsEvent(action, os.path.join(self.root, name), now)
                          for action, name in parse_notify(raw)]
                if events:
                    self.hub._dispatch(self.root, events)
        finally:
            _k32.CloseHandle(io_evt)


class WatchHub:
    """One ReadDirectoryChangesW thread per watched root; parts subscribe to roots.

    subscribe(root, callback, recursive=True) -> token. callback(FsEvent) runs on the hub's
    thread and must be quick (queue the work). Several subscribers may share one root; a root's
    thread runs while it has subscribers and the hub is started."""

    RETRY_S = 30.0

    def __init__(self):
        self._lock = threading.Lock()
        self._roots: dict[str, _RootWatch] = {}           # norm_key(root) -> watch
        self._subs: dict[int, tuple[str, str, object, bool]] = {}   # token -> (key, root, cb, recursive)
        self._tokens = itertools.count(1)
        self._started = False

    def subscribe(self, root: str, callback, recursive: bool = True) -> int:
        disp = _norm_root(root)
        key = winpath.norm_key(disp)
        with self._lock:
            token = next(self._tokens)
            self._subs[token] = (key, disp, callback, recursive)
            watch = self._roots.get(key)
            if watch is None:
                watch = self._roots[key] = _RootWatch(self, disp)
                if self._started:
                    watch.start()
        return token

    def unsubscribe(self, token: int) -> None:
        stop = None
        with self._lock:
            sub = self._subs.pop(token, None)
            if sub is None:
                return
            key = sub[0]
            if not any(s[0] == key for s in self._subs.values()):
                stop = self._roots.pop(key, None)
        if stop is not None:
            stop.stop()

    def start(self) -> None:
        with self._lock:
            self._started = True
            watches = list(self._roots.values())
        for w in watches:
            w.start()

    def stop(self) -> None:
        with self._lock:
            self._started = False
            watches = list(self._roots.values())
            self._roots.clear()
            self._subs.clear()
        for w in watches:
            w.stop()

    def root_state(self, root: str) -> str:
        """'ok' | 'missing' | 'starting' | 'off' (not watched)."""
        with self._lock:
            w = self._roots.get(winpath.norm_key(_norm_root(root)))
        return w.state if w else "off"

    def _dispatch(self, root: str, events: list[FsEvent]) -> None:
        key = winpath.norm_key(root)
        with self._lock:
            subs = [(cb, rec) for k, _, cb, rec in self._subs.values() if k == key]
        if not subs:
            return
        prefix = len(root.rstrip("\\")) + 1
        for ev in events:
            direct = ev.action == "overflow" or "\\" not in ev.path[prefix:]
            for cb, recursive in subs:
                if not recursive and not direct:
                    continue
                try:
                    cb(ev)
                except Exception:
                    log.exception("A folder-change subscriber failed")


# ---- which folders ----------------------------------------------------------------------------
FOLDERID_DOWNLOADS = "{374DE290-123F-4565-9164-39C4925E467B}"
FOLDERID_DESKTOP = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
FOLDERID_DOCUMENTS = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"
FOLDERID_STARTUP = "{B97D20BB-F46A-4C97-BA10-5E3608430854}"
DRIVE_FIXED = 3


def _known_folder(guid: str) -> str | None:
    """Real location of a Windows known folder (Downloads may have been moved), else None.
    (A copy of web/server.py's helper: the guard does not import the web server.)"""
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


def _fixed_drives() -> list[str]:
    try:
        drives = os.listdrives()
    except (AttributeError, OSError):
        drives = [f"{c}:\\" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
    out = []
    for d in drives:
        try:
            if _k32.GetDriveTypeW(d) == DRIVE_FIXED:
                out.append(d)
        except Exception:
            pass
    return out


IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003      # junction
IO_REPARSE_TAG_SYMLINK = 0xA000000C


def is_link(st: os.stat_result) -> bool:
    """A symbolic link or junction (from os.lstat). OneDrive's cloud files are reparse points
    too, but they are ordinary files and folders, so they do not count."""
    return getattr(st, "st_reparse_tag", 0) in (IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK)


def default_watch_folders(settings) -> list[str]:
    """Your Downloads (the known folder, and "Downloads" at the top of each fixed drive),
    Desktop, Documents and your Startup folder. settings.watch_folders wins when not empty."""
    chosen = [str(p) for p in (getattr(settings, "watch_folders", None) or []) if str(p).strip()]
    if chosen:
        paths = [_norm_root(p) for p in chosen]
    else:
        home = os.path.expanduser("~")
        candidates = [_known_folder(FOLDERID_DOWNLOADS) or os.path.join(home, "Downloads")]
        candidates += [os.path.join(d, "Downloads") for d in _fixed_drives()]
        candidates += [_known_folder(FOLDERID_DESKTOP) or os.path.join(home, "Desktop"),
                       _known_folder(FOLDERID_DOCUMENTS) or os.path.join(home, "Documents"),
                       _known_folder(FOLDERID_STARTUP)]
        paths = []
        for c in candidates:
            if not c:
                continue
            try:
                if os.path.isdir(winpath.to_long(c)):
                    paths.append(_norm_root(c))
            except (OSError, ValueError):
                continue
    seen, unique = set(), []
    for p in paths:
        k = winpath.norm_key(p)
        if k not in seen:
            seen.add(k)
            unique.append(p)
    keep = set()
    for p in sorted(unique, key=lambda x: len(winpath.norm_key(x))):
        if not any(winpath.is_under(p, q) for q in keep):
            keep.add(p)
    return [p for p in unique if p in keep]


# ---- walking a folder without following links ---------------------------------------------------
def iter_files(root: str, skip: list[str] | None = None, max_entries: int = 300_000,
               deadline: float | None = None):
    """(display path, os.stat_result) of every file under `root`; links and junctions are not
    followed; folders in `skip` are left out. Stops after `max_entries` entries or at `deadline`
    (time.monotonic)."""
    skip_keys = [winpath.norm_key(s) for s in (skip or [])]
    stack = [_norm_root(root)]
    seen = 0
    while stack:
        disp = stack.pop()
        if any(winpath.is_under(disp, k) for k in skip_keys):
            continue
        try:
            with os.scandir(winpath.to_long(disp)) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            seen += 1
            if seen > max_entries or (deadline is not None and time.monotonic() > deadline):
                return
            try:
                if e.is_symlink() or e.is_junction():
                    continue
                child = os.path.join(disp, e.name)
                if e.is_dir(follow_symlinks=False):
                    stack.append(child)
                    continue
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if is_link(st):
                continue
            yield child, st


def changed_time(st: os.stat_result) -> float:
    """When a file last changed or arrived (files unpacked from an archive keep an old modified
    time but get a new creation time)."""
    born = getattr(st, "st_birthtime", None)
    return max(st.st_mtime, born if born is not None else st.st_ctime)


def recent_files(roots: list[str], since: float, limit: int = 500, skip: list[str] | None = None,
                 max_age_s: float = 7 * 86400, time_budget_s: float = 60.0) -> list[tuple[str, float]]:
    """The newest `limit` files under `roots` changed after `since` (and within `max_age_s`):
    [(display path, changed time)], newest first."""
    floor = max(since, time.time() - max_age_s)
    deadline = time.monotonic() + time_budget_s
    heap: list[tuple[float, str]] = []
    for root in roots:
        for disp, st in iter_files(root, skip=skip, deadline=deadline):
            t = changed_time(st)
            if t <= floor or not st.st_size:
                continue
            if len(heap) < limit:
                heapq.heappush(heap, (t, disp))
            elif t > heap[0][0]:
                heapq.heapreplace(heap, (t, disp))
    return [(d, t) for t, d in sorted(heap, reverse=True)]


# ---- the "folders" part ------------------------------------------------------------------------
PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp")
OVERFLOW_MSG = "Many files changed at once; TacoGuard checks the newest ones first."
PROGRAM_EXTS = frozenset({".exe", ".dll", ".scr", ".com", ".msi", ".msix", ".appx", ".sys", ".cpl",
                          ".zip", ".7z", ".rar", ".iso", ".img", ".vhd", ".vhdx", ".cab", ".jar"})


def is_partial(path: str) -> bool:
    """A name browsers and Office use while a file is still being written."""
    name = os.path.basename(path).lower()
    return name.startswith("~$") or name.endswith(PARTIAL_SUFFIXES)


@dataclass
class _Pending:
    display: str
    last_event: float               # time.monotonic() of the newest change event
    order: float                    # newest first (wall-clock time of the change)
    snap: tuple | None = None       # (size, mtime_ns) when last looked at
    due: float = 0.0                # not before this (monotonic)
    tries: int = 0
    is_new: bool = True             # added / renamed here (a folder: look inside it)


class FolderWatcher:
    """The "folders" part. start() / stop() / status() -> PART dict."""

    QUIET_S = 2.0
    QUEUE_MAX = 2000
    IN_USE_RETRY_S = 5.0
    IN_USE_TRIES = 3
    DIR_FILES_MAX = 2000           # files looked at inside a folder that was moved in
    OVERFLOW_SHOW_S = 120.0
    RESCAN_BATCH = 500             # files one rescan adds; file checks served between two rescans

    def __init__(self, settings, store, checker, hub):
        self.settings, self.store, self.checker, self.hub = settings, store, checker, hub
        self.roots: list[str] = []
        self._tokens: list[int] = []
        self._pending: dict[str, _Pending] = {}
        self._cond = threading.Condition()
        self._stop = False
        self._thread: threading.Thread | None = None
        # rescans asked for by an overflow: at most ONE waiting per root (norm_key -> [root, since])
        self._rescan: dict[str, list] = {}
        self._served_since_rescan = 0
        self.checked = 0
        self.flagged = 0
        self.overflowed_at = 0.0
        self.error = ""

    # ---- part interface ------------------------------------------------------------------
    def start(self) -> None:
        self.roots = default_watch_folders(self.settings)
        self._stop = False
        self.error = ""
        self._thread = threading.Thread(target=self._run, name="tacoguard-folders", daemon=True)
        self._thread.start()
        for r in self.roots:
            self._tokens.append(self.hub.subscribe(r, self._on_event))

    def stop(self) -> None:
        for t in self._tokens:
            self.hub.unsubscribe(t)
        self._tokens = []
        with self._cond:
            self._stop = True
            self._pending.clear()
            self._rescan.clear()
            self._cond.notify_all()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(15)
        self._thread = None

    def status(self) -> dict:
        if self.error:
            return {"state": "error", "message": self.error, "watched": list(self.roots),
                    "checked": self.checked}
        missing = [r for r in self.roots if self.hub.root_state(r) == "missing"]
        n = len(self.roots)
        if not n:
            msg = "No folders to watch: none of the usual folders were found."
        else:
            msg = f"Watching {n} folder{'s' if n != 1 else ''}; new and changed files are checked."
        if missing:
            msg += (f" {len(missing)} of them {'is' if len(missing) == 1 else 'are'} not there right "
                    f"now ({', '.join(missing[:3])}); TacoGuard keeps looking.")
        ready = getattr(self.checker, "ready", None)
        if callable(ready) and not ready():
            msg = ("Waiting for signatures: new files are not checked until signatures are "
                   "installed (press Get signatures on the Home page).")
        if self.overflowed_at and time.time() - self.overflowed_at < self.OVERFLOW_SHOW_S:
            msg += " " + OVERFLOW_MSG
        return {"state": "on", "message": msg, "watched": list(self.roots), "checked": self.checked}

    # ---- queueing ------------------------------------------------------------------------
    def _skip_path(self, display: str) -> bool:
        try:
            return winpath.is_under(display, str(self.settings.root))   # TacoGuard's own data
        except (OSError, ValueError):
            return True

    def _add(self, display: str, order: float, is_new: bool, due: float = 0.0) -> None:
        """Under self._cond."""
        key = winpath.norm_key(display)
        now = time.monotonic()
        p = self._pending.pop(key, None)
        if p is None:
            if len(self._pending) >= self.QUEUE_MAX:
                # the dict is in order of the last change (each change moves a file to the
                # end), so the first one is the file that changed longest ago: O(1) in a storm
                del self._pending[next(iter(self._pending))]
                if not self.overflowed_at or time.time() - self.overflowed_at > 10:
                    log.info("Folder queue full (%d files): dropping the oldest", self.QUEUE_MAX)
                self.overflowed_at = time.time()
            p = _Pending(display, now, order, is_new=is_new)
        else:
            p.last_event, p.order = now, max(p.order, order)
            p.is_new = p.is_new or is_new
        p.due = max(due, now + self.QUIET_S)
        self._pending[key] = p
        self._cond.notify()

    def enqueue(self, items: list[tuple[str, float]]) -> None:
        """Files to check without waiting for a change event (catch-up at start, rescans):
        [(display path, changed time)]. They still obey the quiet rule."""
        with self._cond:
            if self._stop:
                return
            for display, t in items:
                if self._skip_path(display) or is_partial(display):
                    continue
                self._add(display, t, False)
                self._pending[winpath.norm_key(display)].due = 0.0

    def _on_event(self, ev) -> None:
        """Runs on the hub's thread: only queues."""
        with self._cond:
            if self._stop:
                return
            if ev.action == "overflow":
                since = time.time() - 300
                key = winpath.norm_key(ev.path)
                waiting = self._rescan.get(key)
                if waiting is None:
                    self._rescan[key] = [ev.path, since]
                else:
                    waiting[1] = min(waiting[1], since)   # one rescan covers both overflows
                self.overflowed_at = time.time()
                self._cond.notify()
                return
            if self._skip_path(ev.path):
                return
            if ev.action in ("removed", "renamed_from"):
                self._pending.pop(winpath.norm_key(ev.path), None)
                return
            if is_partial(ev.path):
                return      # still downloading / being saved: its final name comes later
            self._add(ev.path, ev.ts, ev.action in ("added", "renamed_to"))

    def pending_count(self) -> int:
        with self._cond:
            return len(self._pending)

    # ---- the worker ----------------------------------------------------------------------
    def _next(self) -> _Pending | tuple | None:
        """Waits for the next file that is due (newest first), or a rescan request. Rescans never
        starve file checks: while files are due, a waiting rescan runs only after RESCAN_BATCH
        files were checked since the last one (each rescan adds at most RESCAN_BATCH files)."""
        with self._cond:
            while not self._stop:
                now = time.monotonic()
                due = [p for p in self._pending.values() if p.due <= now]
                if self._rescan and (not due or self._served_since_rescan >= self.RESCAN_BATCH):
                    key = next(iter(self._rescan))
                    root, since = self._rescan.pop(key)
                    self._served_since_rescan = 0
                    return ("rescan", (root, since))
                if not self._pending:
                    self._cond.wait()
                    continue
                if not due:
                    wait = min(p.due for p in self._pending.values()) - now
                    self._cond.wait(max(0.05, wait))
                    continue
                p = max(due, key=lambda x: x.order)
                del self._pending[winpath.norm_key(p.display)]
                self._served_since_rescan += 1
                return p
            return None

    def _run(self) -> None:
        try:
            while True:
                item = self._next()
                if item is None:
                    return
                if isinstance(item, tuple):
                    root, since = item[1]
                    self.enqueue(recent_files([root], since, limit=self.RESCAN_BATCH,
                                              skip=[str(self.settings.root)], time_budget_s=30.0))
                    continue
                self._visit(item)
        except Exception as e:
            log.exception("The folder watcher stopped")
            from ..model import plain_error
            self.error = f"The folder check stopped because of an unexpected problem ({plain_error(e)})."

    def _requeue(self, p: _Pending, due: float) -> None:
        with self._cond:
            if self._stop:
                return
            key = winpath.norm_key(p.display)
            if key in self._pending:          # a newer change event arrived meanwhile
                return
            p.due = due
            self._pending[key] = p
            self._cond.notify()

    def _visit(self, p: _Pending) -> None:
        long = winpath.to_long(p.display)
        try:
            st = os.lstat(long)
        except OSError:
            return              # gone (moved, deleted) or not reachable
        if is_link(st):
            return              # links and junctions are not followed
        if os.path.isdir(long):
            if p.is_new:        # a folder moved or copied in: its files bring no events of their own
                deadline = time.monotonic() + 10
                files = list(itertools.islice(iter_files(p.display, skip=[str(self.settings.root)],
                                                         deadline=deadline), self.DIR_FILES_MAX))
                self.enqueue([(d, changed_time(s)) for d, s in files if s.st_size])
            return
        if not st.st_size or self._linked_parent(p.display):
            return
        snap = (st.st_size, st.st_mtime_ns)
        if snap != p.snap and time.time() - st.st_mtime < self.QUIET_S:
            p.snap = snap       # still changing: look again once it has been quiet
            self._requeue(p, time.monotonic() + self.QUIET_S)
            return
        r = self.checker.check_path(p.display)
        if r is None:
            return
        self.checked += 1
        if r.status == UNREADABLE and r.notes and r.notes[0] == engine.IN_USE_NOTE \
                and p.tries < self.IN_USE_TRIES:
            p.tries += 1        # still held open by the program writing it
            self._requeue(p, time.monotonic() + self.IN_USE_RETRY_S)
            return
        if r.status == SKIPPED:
            too_big = r.size > int(self.settings.realtime_max_file_size)
            if not too_big or os.path.splitext(p.display)[1].lower() not in PROGRAM_EXTS:
                return          # an online-only cloud file, a big video or backup: no message
        if r.level in (MALWARE, SUSPICIOUS) or r.status == SKIPPED:
            self.flagged += 1
            self.checker.report(r, "file")

    def _linked_parent(self, display: str) -> bool:
        """True when a folder between the watched root and the file is a link or junction."""
        for root in self.roots:
            if winpath.is_under(display, root):
                rel = os.path.relpath(display, root)
                parts = rel.split("\\")[:-1]
                cur = root
                for part in parts:
                    cur = os.path.join(cur, part)
                    try:
                        if is_link(os.lstat(winpath.to_long(cur))):
                            return True
                    except OSError:
                        return True
                return False
        return False
