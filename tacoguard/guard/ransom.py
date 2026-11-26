"""The ransomware guard: the "ransomware" part of the guard process (contract: guard/__init__.py).

Two signals, both read from the folder hub's change events (no polling of folders):
  1. Decoys: 3 hidden, ordinary-looking documents per canary folder (guard/decoys.py). No program
     has a reason to change them. A decoy whose CONTENT differs from the manifest (sha256), or
     that was renamed to another extension, raises the alarm. Timestamps alone never do.
  2. A burst: >= 20 existing files in one canary folder renamed or rewritten within 10 s, where
     the result looks locked (an added extension that is not an ordinary file type, or scrambled
     content: entropy of the first 64 KB above 7.5 bits/byte without a known file header). New
     files (zip extraction, downloads, copies) make "added" events and are not counted, and
     neither do renames that drop a temporary extension (a finished download: .crdownload, .!qB).
A decoy simply deleted comes back after a few seconds without an alarm, unless files around it
are being locked at the same time.

Suspects: programs under your account whose disk writes grew DURING the triggering activity (one
Windows call lists every program's write counter: the cheap 1 s samples kept ONLY while a burst
is building, plus samples at the trigger and 0.5 s later; for a lone decoy change at the trigger,
+0.5 s and +1.0 s, with writes in both intervals), at least 2 MB/s. Programs with a valid
digital signature are left out (a game, Steam, a browser, OneDrive, OBS), except script hosts
(PowerShell, cmd, wscript, Python, ...), which can run an unsigned script. At most the top 2 are
paused (settings.ransomware_pause): a `paused` row first, then procctl.suspend; a program that
is already paused is never paused twice. One event per burst (cool-down 60 s; later triggers are
merged into it).

A changed decoy is never written over (it may hold something you typed into it, e.g. a decoy you
renamed by hand and then edited): once the alert is resolved, or after 10 minutes, it is dropped
from the manifest and a fresh decoy is made under another free name (exclusive create). After a
restart the alert's state in the store decides when.

Switching the part off removes only files that still match the manifest (path + sha256).

TEST ONLY: TACOGUARD_TEST_PAUSE_ONLY=<pid,pid,...> limits which programs may be paused
(procctl.pause_allowed); the others are still listed as suspects but never paused, with a log
line. The app never sets it.
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import math
import os
import queue
import random
import stat as _stat
import threading
import time
from pathlib import Path

import psutil

from .. import winpath
from ..model import plain_error
from . import decoys, procctl

log = logging.getLogger("tacoguard.guard.ransom")

MANIFEST_NAME = "decoys.json"
DECOYS_PER_FOLDER = 3
MAX_DECOY_BYTES = 8 * 1024 * 1024        # a "decoy" bigger than this was certainly replaced

KNOWN_FOLDERS = [
    ("Documents", "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"),
    ("Desktop", "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"),
    ("Pictures", "{33E28130-4E1E-4676-835A-98395C3BC3BB}"),
    ("Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"),
]
ONEDRIVE_ENV = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")

# Temporary names programs rename to/from while saving or downloading: never a sign of locking.
# (compared in lower case: qBittorrent's ".!qB" too)
TEMP_EXTS = frozenset({".tmp", ".temp", ".crdownload", ".part", ".partial", ".download", ".opdownload",
                       ".!ut", ".bc!", ".!qb", ".bak", ".swp", ".~tmp"})
# Extensions of ordinary file types: a rename that ADDS one of these ("x.tar" -> "x.tar.gz",
# "scan.jpg" -> "scan.jpg.pdf") is not a sign of locking.
KNOWN_EXTS = frozenset("""
.txt .rtf .md .csv .tsv .log .ini .cfg .json .xml .yaml .yml .html .htm .css .js .ts .py .c .h .cpp
.cs .java .go .rs .sql .doc .docx .docm .dot .dotx .xls .xlsx .xlsm .xlsb .ppt .pptx .pptm .odt .ods
.odp .pdf .epub .one .vsd .vsdx .pub .jpg .jpeg .png .gif .bmp .tif .tiff .webp .heic .heif .raw .cr2
.nef .arw .dng .psd .svg .ico .mp3 .wav .flac .aac .m4a .ogg .opus .wma .mid .mp4 .m4v .mkv .avi .mov
.wmv .webm .flv .mpg .mpeg .3gp .srt .zip .7z .rar .gz .tgz .bz2 .xz .zst .tar .cab .iso .img .vhd
.vhdx .exe .dll .msi .msix .appx .bat .cmd .ps1 .vbs .lnk .url .torrent .sqlite .db .eml .msg .pst .ics
.vcf .ttf .otf .woff .woff2 .apk .jar .dmg
""".split())
# Programs that run scripts: they stay eligible as suspects even with a valid signature (a
# signed interpreter can run an unsigned ransomware script).
SCRIPT_HOSTS = procctl.MAY_PAUSE_IN_WINDOWS | frozenset({
    "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "java.exe", "javaw.exe",
    "autohotkey.exe", "autohotkey64.exe", "autohotkey32.exe", "autoit3.exe", "autoit3_x64.exe",
})

# File headers of formats that are naturally high-entropy (compressed). Such content is normal.
_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"%PDF", b"7z\xbc\xaf",
          b"Rar!", b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"RIFF", b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2",
          b"\x1aE\xdf\xa3", b"OggS", b"fLaC", b"MZ", b"\xd0\xcf\x11\xe0", b"wOFF", b"wOF2", b"MSCF",
          b"(\xb5/\xfd", b"8BPS", b"II*\x00", b"MM\x00*", b"\x00\x00\x00\x0cjP", b"ITSF", b"SQLite format")

FOLDER_ACCESS_ERRORS = {5, 225, 1260}    # access denied, blocked as unsafe, blocked by policy

_STOP = object()
_KICK = object()


# ---------------------------------------------------------------------------------------------
# folders
# ---------------------------------------------------------------------------------------------
def _known_folder(guid: str) -> str | None:
    """Real location of a Windows known folder (it may have been moved), else None."""
    import ctypes
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


def in_onedrive(path: str) -> bool:
    """True for a folder inside OneDrive (decoys there would sync to your other devices)."""
    for var in ONEDRIVE_ENV:
        root = os.environ.get(var)
        if root and winpath.is_under(path, root):
            return True
    return any(part.startswith("onedrive") for part in winpath.norm_key(path).split("\\"))


def _label(folder: str) -> str:
    p = Path(winpath.to_display(folder))
    if p.name and p.parent == Path(p.anchor):          # D:\Downloads -> "Downloads (D:)"
        return f"{p.name} ({p.drive})"
    return p.name or winpath.to_display(folder)


def canary_folders(settings) -> tuple[list[str], list[str]]:
    """(folders that get decoys, plain-English notes about folders that don't)."""
    configured = [p for p in (getattr(settings, "canary_folders", None) or []) if isinstance(p, str) and p.strip()]
    if configured:
        cands = [(_label(p), p, True) for p in configured]
    else:
        home = os.path.expanduser("~")
        cands = [(name, _known_folder(guid) or os.path.join(home, name), False) for name, guid in KNOWN_FOLDERS]
        # "Downloads" at the top of a fixed drive (e.g. D:\Downloads, where a browser may save):
        # the same folders the file watch covers (folders.default_watch_folders)
        try:
            from .folders import _fixed_drives
            cands += [(f"Downloads ({d[:2]})", os.path.join(d, "Downloads"), False) for d in _fixed_drives()]
        except Exception:
            pass
    out, notes, seen = [], [], set()
    for label, path, chosen in cands:
        disp = winpath.to_display(os.path.abspath(winpath.to_display(path)))
        key = winpath.norm_key(disp)
        if key in seen:
            continue
        seen.add(key)
        if in_onedrive(disp):
            notes.append(f"{label} is inside OneDrive, so it gets no decoy files "
                         "(they would be copied to your other devices).")
            continue
        try:
            st = os.lstat(winpath.to_long(disp))
        except OSError:
            if chosen:
                notes.append(f"{label} was not found, so it gets no decoy files.")
            continue
        if winpath.is_reparse(st) or not _stat.S_ISDIR(st.st_mode):
            notes.append(f"{label} is a link to another place, so it gets no decoy files.")
            continue
        out.append(disp)
    return out, notes


def cfa_enabled() -> bool | None:
    """Is Microsoft Defender's Controlled Folder Access on? (read only; None = could not tell)"""
    import winreg
    found = None
    for sub in (r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as k:
                val, _ = winreg.QueryValueEx(k, "EnableControlledFolderAccess")
                if int(val) == 1:
                    return True
                found = False
        except (OSError, ValueError, TypeError):
            continue
    return found


def _blocked(exc: OSError) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in FOLDER_ACCESS_ERRORS


# ---------------------------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------------------------
def manifest_path(settings) -> Path:
    return Path(settings.guard_dir) / MANIFEST_NAME


def load_manifest(settings) -> list[dict]:
    try:
        raw = json.loads(manifest_path(settings).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for e in raw.get("decoys", []) if isinstance(raw, dict) else []:
        if isinstance(e, dict) and isinstance(e.get("path"), str) and isinstance(e.get("sha256"), str):
            e.setdefault("folder", str(Path(e["path"]).parent))
            out.append(e)
    return out


def save_manifest(settings, entries: list[dict]) -> None:
    """Atomic: written to a temp file next to it, then swapped in (os.replace)."""
    p = manifest_path(settings)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not entries:
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        return
    tmp = p.with_name(f"{MANIFEST_NAME}.{os.getpid()}.tmp")
    data = json.dumps({"version": 1, "decoys": entries}, indent=1).encode("utf-8")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _sha_of(path: str) -> str | None:
    """sha256 of a (small) file; None when it is missing. Raises OSError when it can't be read."""
    try:
        with open(winpath.to_long(path), "rb") as f:
            st = os.fstat(f.fileno())
            if st.st_size > MAX_DECOY_BYTES:
                return "too-big"
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None


def remove_decoys(settings) -> int:
    """Removes TacoGuard's decoy files (for switching the ransomware guard off and uninstalling).
    Only files that still match the manifest (path + sha256) are deleted: a changed file may hold
    something that is not ours, so it is left where it is and named in the log."""
    removed, keep = 0, []
    for e in load_manifest(settings):
        try:
            sha = _sha_of(e["path"])
        except OSError as exc:
            log.info("decoy %s could not be read (%s); it stays for the next try", e["path"], plain_error(exc))
            keep.append(e)
            continue
        if sha is None:
            continue
        if sha != e["sha256"]:
            log.warning("left alone (changed since TacoGuard made it): %s", e["path"])
            continue
        try:
            os.remove(winpath.to_long(e["path"]))
            removed += 1
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.info("decoy %s could not be removed (%s)", e["path"], plain_error(exc))
            keep.append(e)
    try:
        save_manifest(settings, keep)
    except OSError as exc:
        log.warning("decoy list could not be saved (%s)", plain_error(exc))
    return removed


# ---------------------------------------------------------------------------------------------
# content checks
# ---------------------------------------------------------------------------------------------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values())


def looks_encrypted(path: str, sample: int = 64 * 1024, limit: float = 7.5) -> bool:
    """Scrambled content: high entropy in the first 64 KB and no header of a known compressed
    format (zip/docx, jpeg, png, pdf, mp3, mp4, exe ... are high-entropy by nature)."""
    try:
        with open(winpath.to_long(path), "rb") as f:
            data = f.read(sample)
    except OSError:
        return False
    if len(data) < 256 or data.startswith(_MAGIC) or data[4:8] == b"ftyp":
        return False
    return entropy(data) > limit


_SPI_CREATE_TIME, _SPI_PID, _SPI_WRITE_BYTES = 32, 80, 240     # SYSTEM_PROCESS_INFORMATION (64-bit)
_EPOCH_AS_FILETIME = 116444736000000000


def process_writes() -> dict[int, tuple[float, int]]:
    """{pid: (create_time as epoch seconds, bytes written so far)} for every process, from ONE
    Windows call (NtQuerySystemInformation, SystemProcessInformation), the source Task Manager
    uses. psutil.io_counters() per process takes seconds on a busy PC (477 processes measured
    2026-11-24: 3-7 s); this takes ~20 ms. Raises OSError when Windows refuses."""
    import ctypes
    import struct
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError("64-bit Windows only")
    ntdll = ctypes.WinDLL("ntdll")
    fn = ntdll.NtQuerySystemInformation
    fn.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    fn.restype = ctypes.c_long
    size = 1 << 20
    for _ in range(6):
        buf = ctypes.create_string_buffer(size)
        need = ctypes.c_ulong(0)
        status = fn(5, buf, size, ctypes.byref(need)) & 0xFFFFFFFF
        if status == 0:
            break
        if status != 0xC0000004:                           # STATUS_INFO_LENGTH_MISMATCH: grow, try again
            raise OSError("Windows did not list the running programs")
        size = max(size * 2, need.value + 256 * 1024)
    else:
        raise OSError("Windows did not list the running programs")
    raw, out, off = buf.raw, {}, 0
    while off + 256 <= len(raw):
        nxt = struct.unpack_from("<I", raw, off)[0]
        ct = struct.unpack_from("<q", raw, off + _SPI_CREATE_TIME)[0]
        pid = struct.unpack_from("<Q", raw, off + _SPI_PID)[0]
        wb = struct.unpack_from("<q", raw, off + _SPI_WRITE_BYTES)[0]
        out[int(pid)] = ((ct - _EPOCH_AS_FILETIME) / 1e7 if ct else 0.0, int(wb))
        if not nxt:
            break
        off += nxt
    return out


def _names_list(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


# ---------------------------------------------------------------------------------------------
# the part
# ---------------------------------------------------------------------------------------------
class RansomGuard:
    BURST_COUNT = 20
    BURST_WINDOW_S = 10.0
    BUILDING_COUNT = 5            # from this many counted changes on, keep a 1 s write sample
    COOLDOWN_S = 60.0
    RECREATE_AFTER_S = 600.0      # changed decoys come back after this even if the alert is open
    RECREATE_DELAY_S = 5.0        # a deleted decoy comes back after this (when nothing else happens)
    NEW_FILE_GRACE_S = 30.0       # a file created less than this ago is "new", not an existing file
    SAMPLE_GAP_S = 0.5
    MIN_WRITE_RATE = 2 * 1024 * 1024  # bytes per second
    MAX_SUSPECTS = 5              # listed in the alert
    MAX_PAUSED = 2                # paused (the top ones)
    AWAIT_CHECK_S = 10.0          # how often an open alert's state is looked up (after a restart)
    QUEUE_MAX = 20_000

    def __init__(self, settings, store, hub, *, own_pids=None, pid_filter=None):
        """own_pids: callable -> set of pids never paused (default procctl.tacoguard_pids(); this
        process is always added). pid_filter: callable(pid) -> bool limiting which programs are
        looked at (tests limit it to the programs they started)."""
        self.settings = settings
        self.store = store
        self.hub = hub
        self._own_pids = own_pids
        self._pid_filter = pid_filter
        self._now = time.time
        self._rng = random.SystemRandom()
        self._lock = threading.RLock()
        self._q: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop_ev = threading.Event()
        self._tokens: list = []
        self._state = "off"
        self._error = ""
        self._entries: dict[str, dict] = {}        # norm_key(path) -> manifest entry
        self._folders: list[str] = []
        self._notes: list[str] = []
        self._changed_at_start: list[str] = []
        # burst bookkeeping (per canary folder key)
        self._ops: dict[str, collections.deque] = {}
        self._counted: dict[str, dict[str, float]] = {}
        self._added: collections.OrderedDict[str, tuple[float, str]] = collections.OrderedDict()
        self._rename_from: dict[str, tuple[float, str]] = {}
        self._looked_at: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._rolling: collections.deque = collections.deque(maxlen=12)
        self._sampling_until = 0.0
        self._last_sample = 0.0
        self.samples_taken = 0
        self._recreate_due: dict[str, float] = {}
        self._reverify: dict[str, tuple[float, int, str]] = {}
        self._overflowed: set[str] = set()
        self._alarm: dict | None = None
        self._await: dict[str, int] = {}          # changed decoy key -> its alert (from before a restart)
        self._await_checked = 0.0
        self._signed_cache: dict[tuple[str, int], bool] = {}

    # ---- life cycle --------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._state, self._error = "starting", ""
            self._stop_ev.clear()
            try:
                self.place_decoys()
            except Exception as exc:          # never let the guard process fall over
                log.exception("placing decoys failed")
                self._state = "error"
                self._error = f"TacoGuard could not set up its decoy files ({plain_error(exc)})."
                return
            if self.hub is not None:
                for folder in self._folders:
                    try:
                        self._tokens.append(self.hub.subscribe(
                            folder, lambda ev, root=folder: self._on_fs(root, ev), recursive=True))
                    except Exception as exc:
                        log.warning("could not watch %s (%s)", folder, plain_error(exc))
            self._thread = threading.Thread(target=self._run, name="tacoguard-ransom", daemon=True)
            self._thread.start()
            for key in self._changed_at_start:
                self._q.put(("offline", key))
            self._changed_at_start = []
            self._state = "on"

    def stop(self, remove: bool = False) -> None:
        with self._lock:
            tokens, self._tokens = self._tokens, []
        for t in tokens:
            try:
                self.hub.unsubscribe(t)
            except Exception:
                pass
        th = self._thread
        if th is not None:
            self._stop_ev.set()
            self._q.put(_STOP)
            th.join(timeout=5)
        with self._lock:
            self._thread = None
            self._state = "off"
        if remove:
            self.remove_decoys()

    def status(self) -> dict:
        with self._lock:
            n = len(self._entries)
            watched = list(self._folders)
            if self._state == "error":
                msg = self._error
            elif self._state == "off":
                msg = "The ransomware guard is off."
            elif not watched:
                msg = "No folder to put decoy files in."
            else:
                names = _names_list([_label(f) for f in watched])
                msg = f"Watching {names} with {n} hidden decoy file{'s' if n != 1 else ''}."
                if self.hub is None:
                    msg += " Folder watching is not available, so changes are not seen yet."
            if self._notes and self._state != "off":
                msg = (msg + " " + " ".join(self._notes)).strip()
            return {"state": self._state, "message": msg, "watched": watched, "checked": n}

    def flush(self, timeout: float = 10.0) -> bool:
        """Waits until every queued change was handled (tests, clean stops)."""
        with self._q.all_tasks_done:
            return self._q.all_tasks_done.wait_for(lambda: self._q.unfinished_tasks == 0, timeout)

    def _kick(self) -> None:
        """Run the timed checks now (tests; the worker also runs them on its own schedule)."""
        self._q.put(_KICK)

    # ---- decoys ------------------------------------------------------------------------
    def place_decoys(self) -> list[str]:
        """Makes sure every canary folder has its decoys; takes them away from folders no longer
        used. Returns the display paths of the decoys in place."""
        with self._lock:
            folders, notes = canary_folders(self.settings)
            entries = {winpath.norm_key(e["path"]): e for e in load_manifest(self.settings)}
            self._entries = entries
            fkeys = {winpath.norm_key(f) for f in folders}
            for key, e in list(entries.items()):          # a folder no longer protected
                if winpath.norm_key(e["folder"]) not in fkeys:
                    self._take_away(key, e)
            taken = {Path(e["path"]).name.casefold() for e in entries.values()}
            active, changed = [], []
            self._await = {}
            for folder in folders:
                fk = winpath.norm_key(folder)
                try:
                    good = 0
                    for key, e in [(k, e) for k, e in entries.items() if winpath.norm_key(e["folder"]) == fk]:
                        state = self._check(e)
                        if state == "ok":
                            e.pop("pending", None)
                            e.pop("reported", None)
                            e.pop("event", None)
                        if state == "missing":
                            if not self._recreate(key, e, new_file=True):
                                continue
                        elif state == "changed" and e.get("pending"):
                            # TacoGuard's own write was cut off by a crash: only its own bytes are there
                            self._recreate(key, e, new_file=False)
                        elif state == "changed" and self._already_reported(e):
                            # you were already told about it: never written over; a fresh decoy
                            # comes once that alert is dealt with (or 10 minutes after it)
                            if self._alert_done(e):
                                self._retire(key, e, make_new=False)
                                continue
                            self._await[key] = int(e.get("event") or 0)
                        elif state == "changed":
                            changed.append(key)
                        good += 1
                    tries = 0
                    while good < DECOYS_PER_FOLDER and tries < 10:
                        tries += 1
                        if self._new_decoy(folder, taken):
                            good += 1
                    active.append(folder)
                except OSError as exc:
                    label = _label(folder)
                    if _blocked(exc):
                        if cfa_enabled() is not False:
                            notes.append(f"Windows' Controlled Folder Access blocked TacoGuard's decoy files in "
                                         f"{label}. Add TacoGuard's Python under 'Allow an app through "
                                         f"Controlled folder access' to use them there.")
                        else:
                            notes.append(f"Windows refused access to {label}, so TacoGuard could not put its "
                                         f"decoy files there.")
                    else:
                        notes.append(f"TacoGuard could not put its decoy files in {label} ({plain_error(exc)}).")
                    log.warning("no decoys in %s (%s)", folder, plain_error(exc))
                    for key in [k for k, e in entries.items() if winpath.norm_key(e["folder"]) == fk]:
                        if self._check(entries[key]) == "missing":
                            entries.pop(key, None)
            self._folders = active
            self._notes = notes
            self._changed_at_start = changed
            self._save()
            return [e["path"] for e in entries.values()]

    def remove_decoys(self) -> int:
        with self._lock:
            n = remove_decoys(self.settings)
            self._entries = {winpath.norm_key(e["path"]): e for e in load_manifest(self.settings)}
            return n

    def _save(self) -> None:
        save_manifest(self.settings, list(self._entries.values()))

    def _check(self, e: dict) -> str:
        """ok | missing | changed | busy (could not read it right now)."""
        try:
            sha = _sha_of(e["path"])
        except OSError:
            return "busy"
        if sha is None:
            return "missing"
        return "ok" if sha == e["sha256"] else "changed"

    def _new_decoy(self, folder: str, taken: set[str]) -> bool:
        for _ in range(40):
            picks = decoys.plan(_label(folder), 1, self._rng, taken)
            if not picks:
                return False
            name, kind = picks[0]
            path = os.path.join(folder, name)
            if not os.path.lexists(winpath.to_long(path)):  # a file of yours with that name is never touched
                break
        else:
            return False
        data = decoys.make(kind, self._rng)
        key = winpath.norm_key(path)
        e = {"path": path, "folder": folder, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
             "created": time.time(), "pending": True}
        self._entries[key] = e
        self._save()            # listed first: a crash never leaves a file TacoGuard does not know about
        try:
            decoys.write_new(path, data, self._rng)
        except FileExistsError:
            self._entries.pop(key, None)
            self._save()
            return False
        except OSError:
            self._entries.pop(key, None)
            self._save()
            raise
        e.pop("pending", None)
        self._save()
        log.info("decoy placed: %s", path)
        return True

    def _recreate(self, key: str, e: dict, new_file: bool) -> bool:
        """Fresh content for a decoy path. new_file: the path must be free (exclusive create).
        new_file=False is ONLY for redoing TacoGuard's own write that a crash cut off (the entry
        is marked "pending" while writing); a decoy changed by anything else is never written
        over (see _retire)."""
        data = decoys.make(decoys.kind_of(e["path"]), self._rng)
        e.pop("reported", None)
        e.pop("event", None)
        e.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(), created=time.time(), pending=True)
        self._save()
        try:
            if new_file:
                decoys.write_new(e["path"], data, self._rng)
            else:
                try:
                    decoys.overwrite(e["path"], data, self._rng)
                except FileNotFoundError:
                    decoys.write_new(e["path"], data, self._rng)
        except FileExistsError:                            # someone else's file has that name now
            log.info("decoy name now used by another file; left alone: %s", e["path"])
            self._entries.pop(key, None)
            self._save()
            return False
        e.pop("pending", None)
        self._save()
        log.info("decoy put back: %s", e["path"])
        return True

    def _retire(self, key: str, e: dict, make_new: bool = True) -> None:
        """A changed decoy: left exactly as it is (it may hold something that is not ours) and
        dropped from the manifest; a fresh decoy is made under another free name instead."""
        self._entries.pop(key, None)
        self._recreate_due.pop(key, None)
        self._reverify.pop(key, None)
        self._await.pop(key, None)
        self._save()
        log.info("changed decoy left as it is; TacoGuard no longer uses it: %s", e["path"])
        if not make_new:
            return              # place_decoys tops the folder up itself
        folder = e["folder"]
        if not any(winpath.norm_key(f) == winpath.norm_key(folder) for f in self._folders):
            return
        n = sum(1 for x in self._entries.values() if winpath.norm_key(x["folder"]) == winpath.norm_key(folder))
        taken = {Path(x["path"]).name.casefold() for x in self._entries.values()}
        taken.add(Path(e["path"]).name.casefold())
        tries = 0
        while n < DECOYS_PER_FOLDER and tries < 10:
            tries += 1
            try:
                if self._new_decoy(folder, taken):
                    n += 1
            except OSError as exc:
                log.info("a fresh decoy could not be made in %s (%s)", folder, plain_error(exc))
                return

    def _alert_done(self, e: dict) -> bool:
        """The alert about this changed decoy was resolved (or is 10 minutes old, or unknown)."""
        eid = int(e.get("event") or 0)
        if not eid:
            return True
        try:
            ev = self.store.get_guard_event(eid)
        except Exception:
            return False
        if ev is None or ev.get("state") == "resolved":
            return True
        return self._now() - float(ev.get("created") or 0) >= self.RECREATE_AFTER_S

    def _already_reported(self, e: dict) -> bool:
        """This changed content was already in an alert (so a restart does not alert again)."""
        try:
            return bool(e.get("reported")) and _sha_of(e["path"]) == e["reported"]
        except OSError:
            return False

    def _mark_reported(self, e: dict) -> None:
        try:
            sha = _sha_of(e["path"])
        except OSError:
            return
        if sha and sha != e["sha256"]:
            e["reported"] = sha
            self._save()

    def _take_away(self, key: str, e: dict) -> None:
        try:
            sha = _sha_of(e["path"])
            if sha == e["sha256"]:
                os.remove(winpath.to_long(e["path"]))
            elif sha is not None:
                log.warning("left alone (changed since TacoGuard made it): %s", e["path"])
        except OSError as exc:
            log.info("decoy %s could not be removed (%s)", e["path"], plain_error(exc))
        self._entries.pop(key, None)

    # ---- events ------------------------------------------------------------------------
    def _on_fs(self, root: str, ev) -> None:
        """Hub callback (hub thread): queue only."""
        if self._q.qsize() >= self.QUEUE_MAX:
            self._overflowed.add(root)
            return
        self._q.put((root, getattr(ev, "action", ""), getattr(ev, "path", ""), self._now()))

    def _run(self) -> None:
        while True:
            try:
                item = self._q.get(timeout=self._next_timeout())
            except queue.Empty:
                item = None
            try:
                if item is _STOP:
                    return
                if item is not None and item is not _KICK:
                    with self._lock:
                        if item[0] == "offline":
                            self._offline_change(item[1])
                        else:
                            self._handle(*item)
                with self._lock:
                    self._tick(force=item is _KICK)
            except Exception:
                log.exception("ransomware guard: handling a change failed")
            finally:
                if item is not None:
                    self._q.task_done()

    def _next_timeout(self) -> float | None:
        now = self._now()
        waits = []
        if self._sampling_until > now:
            waits.append(1.0)
        if self._recreate_due:
            waits.append(max(0.05, min(self._recreate_due.values()) - now))
        if self._reverify:
            waits.append(max(0.05, min(v[0] for v in self._reverify.values()) - now))
        if self._alarm is not None:
            waits.append(10.0)
        if self._overflowed:
            waits.append(0.5)
        if self._await:
            waits.append(self.AWAIT_CHECK_S)
        return min(waits) if waits else None

    def _handle(self, root: str, action: str, path: str, ts: float) -> None:
        if not path and action != "overflow":
            return
        rk = winpath.norm_key(root)
        if action == "overflow":
            self._verify_root(root)
            return
        key = winpath.norm_key(path)
        entry = self._entries.get(key)
        if action == "added":
            self._added[key] = (ts, path)
            self._added.move_to_end(key)
            self._prune_added(ts)
            if entry:
                self._verify(key, entry, root, ts)
            return
        if action == "modified":
            if entry:
                self._verify(key, entry, root, ts)
                return
            if self._recently_added(key, ts) or key in self._counted.get(rk, {}):
                return
            last = self._looked_at.get(key)
            if last is not None and ts - last < 5.0:       # a file being written: look at most every 5 s
                return
            self._looked_at[key] = ts
            self._looked_at.move_to_end(key)
            while len(self._looked_at) > 2000:
                self._looked_at.popitem(last=False)
            if self._existing(path, ts) and looks_encrypted(path):
                self._count(root, key, path, ts)
            return
        if action == "renamed_from":
            self._rename_from[rk] = (ts, path)
            return
        if action == "renamed_to":
            prev = self._rename_from.pop(rk, None)
            old = prev[1] if prev and ts - prev[0] <= 2.0 else None
            old_key = winpath.norm_key(old) if old else None
            old_entry = self._entries.get(old_key) if old_key else None
            if old_entry:
                self._decoy_renamed(old_key, old_entry, path, root, ts)
                return
            if entry:                                   # something was renamed onto a decoy
                self._verify(key, entry, root, ts)
                return
            if old is None or self._recently_added(old_key, ts) or self._recently_added(key, ts):
                return
            if self._rename_locks(old, path) and self._existing(path, ts):
                counted = self._counted.get(rk, {})
                if old_key in counted:                  # rewritten, then renamed: one file
                    counted[key] = counted.pop(old_key)
                else:
                    self._count(root, key, path, ts)
            return
        if action == "removed":
            if entry:
                self._decoy_removed(key, entry, root, ts)
            return

    def _rename_locks(self, old: str, new: str) -> bool:
        """Does this rename look like a file being locked? Only when it ADDS an extension that is
        not an ordinary file type ("Budget.xlsx" -> "Budget.xlsx.locked"), or the renamed file's
        content looks scrambled. Saving and downloading renames (a temporary extension on either
        side, e.g. a finished download dropping ".crdownload" or ".!qB") never count."""
        on, nn = os.path.basename(old).casefold(), os.path.basename(new).casefold()
        if nn.startswith("~") or on.startswith("~"):
            return False
        oe, ne = os.path.splitext(on)[1], os.path.splitext(nn)[1]
        if oe in TEMP_EXTS or ne in TEMP_EXTS:
            return False
        if nn.startswith(on) and len(nn) > len(on) and ne and ne not in KNOWN_EXTS:
            return True
        return looks_encrypted(new)

    def _existing(self, path: str, ts: float) -> bool:
        """A file that was there before (not one just created: extraction, a download, a copy)."""
        try:
            st = os.stat(winpath.to_long(path))
        except OSError:
            return False
        if _stat.S_ISDIR(st.st_mode):
            return False
        born = getattr(st, "st_birthtime", st.st_ctime)
        return born <= ts - self.NEW_FILE_GRACE_S

    def _recently_added(self, key: str | None, ts: float) -> bool:
        hit = self._added.get(key) if key else None
        return bool(hit) and ts - hit[0] <= max(self.NEW_FILE_GRACE_S, 60.0)

    def _prune_added(self, ts: float) -> None:
        keep = max(self.NEW_FILE_GRACE_S, 60.0)
        while self._added:
            k, (t, _) = next(iter(self._added.items()))
            if ts - t > keep or len(self._added) > 5000:
                self._added.popitem(last=False)
            else:
                break

    def _window(self, rk: str, ts: float) -> collections.deque:
        dq = self._ops.setdefault(rk, collections.deque())
        counted = self._counted.setdefault(rk, {})
        while dq and dq[0][0] < ts - self.BURST_WINDOW_S:
            _, k, _ = dq.popleft()
            counted.pop(k, None)
        return dq

    def _building(self, root: str, ts: float) -> bool:
        return len(self._window(winpath.norm_key(root), ts)) >= self.BUILDING_COUNT

    def _count(self, root: str, key: str, path: str, ts: float) -> None:
        rk = winpath.norm_key(root)
        dq = self._window(rk, ts)
        dq.append((ts, key, path))
        self._counted[rk][key] = ts
        n = len(dq)
        if n >= self.BUILDING_COUNT:
            self._sampling_until = ts + self.BURST_WINDOW_S
            if time.monotonic() - self._last_sample >= 1.0:
                self._roll_sample()
        if n >= self.BURST_COUNT:
            self._trigger(root, "burst", ts, count=n, example=path)

    # ---- decoy events ------------------------------------------------------------------
    def _verify(self, key: str, e: dict, root: str, ts: float, tries: int = 0) -> None:
        state = self._check(e)
        if state == "ok":
            self._reverify.pop(key, None)
            return
        if state == "busy":                               # being written or scanned: look again soon
            if tries < 5:
                self._reverify[key] = (self._now() + 1.0, tries + 1, root)
            return
        self._reverify.pop(key, None)
        if state == "missing":
            self._decoy_removed(key, e, root, ts)
            return
        self._decoy_changed(key, e, root, ts, "changed")

    def _verify_root(self, root: str) -> None:
        rk = winpath.norm_key(root)
        now = self._now()
        for key, e in list(self._entries.items()):
            if winpath.norm_key(e["folder"]) == rk:
                self._verify(key, e, root, now)

    def _decoy_changed(self, key: str, e: dict, root: str, ts: float, how: str, new_path: str = "") -> None:
        self._recreate_due.pop(key, None)
        self._mark_reported(e)
        self._trigger(root, "decoy", ts, decoy=e["path"], how=how, new_path=new_path, restore=key)

    def _decoy_renamed(self, key: str, e: dict, new_path: str, root: str, ts: float) -> None:
        same_ext = os.path.splitext(new_path)[1].casefold() == os.path.splitext(e["path"])[1].casefold()
        try:
            same = same_ext and _sha_of(new_path) == e["sha256"]
        except OSError:
            same = False
        if same and not self._building(root, ts) and not self._alarm_open(ts):
            # renamed by hand (it is still our file, unchanged): follow it
            log.info("decoy renamed, content unchanged: %s -> %s", e["path"], new_path)
            self._entries.pop(key, None)
            e["path"] = new_path
            self._entries[winpath.norm_key(new_path)] = e
            self._save()
            return
        self._decoy_changed(key, e, root, ts, "renamed", new_path)

    def _decoy_removed(self, key: str, e: dict, root: str, ts: float) -> None:
        if self._alarm_open(ts):
            self._alarm["restore"].add(key)
            return
        if self._building(root, ts):
            self._decoy_changed(key, e, root, ts, "removed")
            return
        copy = self._locked_copy(e, ts)
        if copy:
            self._decoy_changed(key, e, root, ts, "replaced", copy)
            return
        log.info("decoy deleted; it will be put back: %s", e["path"])
        self._recreate_due[key] = self._now() + self.RECREATE_DELAY_S

    def _locked_copy(self, e: dict, ts: float) -> str:
        """A new file next to a deleted decoy that looks like its locked copy
        ('!Budget.xlsx' -> '!Budget.xlsx.locked' or scrambled '!Budget.xlsx'-like name)."""
        name = os.path.basename(e["path"]).casefold()
        stem = os.path.splitext(name)[0]
        folder = winpath.norm_key(os.path.dirname(e["path"]))
        for k, (t, disp) in reversed(self._added.items()):
            if ts - t > 15.0:
                break
            b = os.path.basename(disp).casefold()
            if b == name or winpath.norm_key(os.path.dirname(disp)) != folder:
                continue
            if b.startswith(name) or os.path.splitext(b)[0] == stem:
                if os.path.splitext(b)[1] != os.path.splitext(name)[1] or looks_encrypted(disp):
                    return disp
        return ""

    def _offline_change(self, key: str) -> None:
        e = self._entries.get(key)
        if not e or self._check(e) != "changed":
            return
        root = next((f for f in self._folders if winpath.norm_key(f) == winpath.norm_key(e["folder"])), e["folder"])
        self._mark_reported(e)
        self._trigger(root, "offline", self._now(), decoy=e["path"], how="changed", restore=key)

    # ---- timed work --------------------------------------------------------------------
    def _tick(self, force: bool = False) -> None:
        now = self._now()
        if self._sampling_until > now:
            if time.monotonic() - self._last_sample >= 1.0:
                self._roll_sample()
        elif self._rolling:
            self._rolling.clear()
        for root in list(self._overflowed):
            self._overflowed.discard(root)
            self._verify_root(root)
        for key, (due, tries, root) in list(self._reverify.items()):
            if due <= now or force:
                e = self._entries.get(key)
                self._reverify.pop(key, None)
                if e:
                    self._verify(key, e, root, now, tries)
        for key, due in list(self._recreate_due.items()):
            if due > now and not force:
                continue
            self._recreate_due.pop(key, None)
            e = self._entries.get(key)
            if e:
                self._deleted_due(key, e, now)
        a = self._alarm
        if a is not None and (force or now - a.get("checked", 0) >= 10.0):
            a["checked"] = now
            resolved = self._resolved(a, fresh=True)
            if a["restore"] and (resolved or now - a["ts"] >= self.RECREATE_AFTER_S):
                self._restore(a)
            if not a["restore"] and (resolved or now - a["last"] >= self.COOLDOWN_S):
                self._alarm = None
        self._check_await(force)

    def _deleted_due(self, key: str, e: dict, now: float) -> None:
        root = e["folder"]
        if self._alarm_open(now):
            self._alarm["restore"].add(key)
            return
        state = self._check(e)
        if state in ("ok", "busy"):
            return
        if state == "changed":                    # a file is back at that name, not ours
            self._decoy_changed(key, e, root, now, "changed")
            return
        if self._building(root, now):
            self._decoy_changed(key, e, root, now, "removed")
            return
        copy = self._locked_copy(e, now)
        if copy:
            self._decoy_changed(key, e, root, now, "replaced", copy)
            return
        try:
            self._recreate(key, e, new_file=True)
        except OSError as exc:
            log.info("decoy could not be put back: %s (%s)", e["path"], plain_error(exc))

    def _restore(self, a: dict) -> None:
        for key in list(a["restore"]):
            e = self._entries.get(key)
            if not e:
                a["restore"].discard(key)
                continue
            try:
                state = self._check(e)
                if state == "busy":
                    continue                    # in use right now: tried again on the next look
                a["restore"].discard(key)
                self._put_back(key, e, state)
            except OSError as exc:
                a["restore"].discard(key)
                log.info("decoy could not be put back: %s (%s)", e["path"], plain_error(exc))

    def _put_back(self, key: str, e: dict, state: str) -> None:
        """After an alert: a deleted decoy is made again at its own (free) path; a changed one is
        left alone and replaced by a fresh decoy under another name."""
        if state == "ok":
            e.pop("reported", None)
            e.pop("event", None)
            return
        if state == "missing":
            self._recreate(key, e, new_file=True)
            return
        self._retire(key, e)

    def _check_await(self, force: bool = False) -> None:
        """Changed decoys from before a restart: replaced once their alert is dealt with."""
        if not self._await:
            return
        now = time.monotonic()
        if not force and now - self._await_checked < self.AWAIT_CHECK_S:
            return
        self._await_checked = now
        for key in list(self._await):
            e = self._entries.get(key)
            if e is None:
                self._await.pop(key, None)
                continue
            if self._alarm_open(self._now()) and key in self._alarm["restore"]:
                self._await.pop(key, None)      # a new alert about it took over
                continue
            if not self._alert_done(e):
                continue
            try:
                state = self._check(e)
                if state == "busy":
                    continue
                self._await.pop(key, None)
                self._put_back(key, e, state)
            except OSError as exc:
                self._await.pop(key, None)
                log.info("decoy could not be put back: %s (%s)", e["path"], plain_error(exc))

    def _link_decoy_event(self, keys, event_id: int) -> None:
        """Remember which alert is about each changed decoy (for after a restart)."""
        changed = False
        for key in keys:
            e = self._entries.get(key)
            if e is not None and event_id and e.get("event") != event_id:
                e["event"] = event_id
                changed = True
        if changed:
            try:
                self._save()
            except OSError as exc:
                log.warning("decoy list could not be saved (%s)", plain_error(exc))

    # ---- write samples and suspects ----------------------------------------------------
    def _sample(self) -> tuple[float, dict[int, tuple[float, int]]]:
        try:
            snap = process_writes()
        except OSError:
            snap = None
        out: dict[int, tuple[float, int]] = {}
        if snap is not None:
            for pid, v in snap.items():
                if self._pid_filter is None or self._pid_filter(pid):
                    out[pid] = v
        else:                                              # slow (seconds on a busy PC): last resort
            for p in psutil.process_iter():
                if self._pid_filter is not None and not self._pid_filter(p.pid):
                    continue
                try:
                    out[p.pid] = (p.create_time(), p.io_counters().write_bytes)
                except (psutil.Error, OSError, AttributeError):
                    continue
        self.samples_taken += 1
        return time.monotonic(), out

    def _roll_sample(self) -> None:
        self._rolling.append(self._sample())
        self._last_sample = time.monotonic()

    def _own(self) -> set[int]:
        try:
            if self._own_pids is not None:
                own = set(self._own_pids())
            else:
                own = set(procctl.tacoguard_pids(engines_dir=Path(self.settings.root) / "engines"))
        except Exception:
            own = set()
        own.add(os.getpid())
        return own

    def _signed(self, exe: str) -> bool:
        """A valid digital signature (Windows' own check, offline), cached by path + modified time."""
        if not exe:
            return False
        try:
            st = os.stat(winpath.to_long(exe))
        except OSError:
            return False
        key = (winpath.norm_key(exe), st.st_mtime_ns)
        hit = self._signed_cache.get(key)
        if hit is None:
            try:
                from ..signing import check_signature
                hit = bool(check_signature(winpath.to_long(exe)).valid)
            except Exception:
                hit = False
            if len(self._signed_cache) > 1000:
                self._signed_cache.clear()
            self._signed_cache[key] = hit
        return hit

    def _write_samples(self) -> tuple[list[tuple[float, dict]], int]:
        """Write counters covering the triggering activity: the 1 s samples kept while a burst
        was building, then one at the trigger and one 0.5 s later; with no burst building (a
        lone decoy change), at the trigger, +0.5 s and +1.0 s."""
        history = list(self._rolling)
        now = [self._sample()]
        for _ in range(1 if history else 2):
            self._stop_ev.wait(self.SAMPLE_GAP_S)
            now.append(self._sample())
        return history + now, len(now)

    def _find_suspects(self, exclude: set[tuple[int, float]] = frozenset()) -> list[dict]:
        seq, n_now = self._write_samples()
        recent = seq[-n_now:]
        t_last, s_last = seq[-1]
        cands = []
        for pid, (ct, wb) in s_last.items():
            # still writing right now: growth in every interval since the trigger
            moving = True
            for (ta, sa), (tb, sb) in zip(recent, recent[1:]):
                a, b = sa.get(pid), sb.get(pid)
                if not a or not b or abs(a[0] - ct) >= 0.01 or abs(b[0] - ct) >= 0.01 or b[1] <= a[1]:
                    moving = False
                    break
            if not moving:
                continue
            first = next(((t, s[pid]) for t, s in seq if pid in s and abs(s[pid][0] - ct) < 0.01), None)
            if first is None or t_last <= first[0]:
                continue
            rate = (wb - first[1][1]) / (t_last - first[0])
            if rate >= self.MIN_WRITE_RATE:
                cands.append((rate, pid, ct))
        cands.sort(reverse=True)
        own = self._own()
        resumed = {(r["pid"], round(r["create_time"], 2)) for r in self._paused_rows(("resumed", "paused"))}
        out = []
        for rate, pid, ct in cands:
            if pid in own or (pid, round(ct, 2)) in resumed or (pid, round(ct, 2)) in exclude:
                continue
            try:
                p = psutil.Process(pid)
                if abs(p.create_time() - ct) > 0.01:      # the pid now belongs to another program
                    continue
                ct = p.create_time()                       # the value procctl compares with
                why = procctl.protected_reason(p, own)
                if why:
                    log.info("not a suspect: pid %s (%s)", pid, why)
                    continue
                name = p.name()
                try:
                    exe = winpath.to_display(p.exe() or "")
                except psutil.Error:
                    exe = ""
            except psutil.Error:
                continue
            if name.lower() not in SCRIPT_HOSTS and self._signed(exe):
                log.info("not a suspect: pid %s (%s has a valid digital signature)", pid, name)
                continue
            out.append({"pid": pid, "create_time": ct, "name": name, "exe": exe,
                        "write_mb_s": round(rate / (1024 * 1024), 1)})
            if len(out) >= self.MAX_SUSPECTS:
                break
        return out

    def _paused_rows(self, states: tuple[str, ...]) -> list[dict]:
        try:
            return self.store.list_paused(states)
        except Exception:
            return []

    @staticmethod
    def _reason(s: dict, cause: str) -> str:
        return (f"It was writing a lot to your disk at that moment ({s['write_mb_s']} MB/s, just as {cause}). "
                "If you know this program (a game, a download, a backup), press Resume.")

    def _pause_some(self, suspects: list[dict], cause: str, room: int) -> list[int]:
        """Pauses the top suspects (at most `room`); marks each suspect "paused" or "not_paused"."""
        own = self._own()
        rows: list[int] = []
        for s in suspects:
            if len(rows) >= room:
                break
            if not procctl.pause_allowed(s["pid"]):
                log.warning("test limit (TACOGUARD_TEST_PAUSE_ONLY): %s (pid %s) is a suspect but is not "
                            "paused", s["name"], s["pid"])
                continue
            row = self._pause(s, self._reason(s, cause), own)
            if row is not None:
                s["paused"] = True
                rows.append(row)
        return rows

    def _pause(self, s: dict, reason: str, own: set[int]) -> int | None:
        ref = procctl.ProcRef(s["pid"], s["create_time"])
        for r in self._paused_rows(("paused",)):        # already paused by TacoGuard: never twice
            if int(r["pid"]) == ref.pid and abs(float(r["create_time"]) - ref.create_time) < 0.01:
                log.info("%s (pid %s) is already paused", s["name"], s["pid"])
                return int(r["id"])
        if procctl.is_suspended(ref):
            log.info("%s (pid %s) is already paused; not paused again", s["name"], s["pid"])
            s["not_paused"] = "It was already paused."
            return None
        row = self.store.add_paused(s["pid"], s["create_time"], s["exe"], s["name"], reason)
        try:
            procctl.suspend(ref, own=own)
        except procctl.ProcError as exc:
            self.store.set_paused_state(row, "not_paused" if procctl.is_alive(ref) else "gone")
            s["not_paused"] = str(exc)
            log.warning("could not pause %s: %s", s["name"], exc)
            return None
        log.warning("paused %s (pid %s): %s", s["name"], s["pid"], reason)
        return row

    # ---- alarms ------------------------------------------------------------------------
    def _resolved(self, a: dict, fresh: bool = False) -> bool:
        now = time.monotonic()
        if fresh or now - a.get("resolved_at", 0) >= 2.0:
            a["resolved_at"] = now
            try:
                ev = self.store.get_guard_event(a["id"])
            except Exception:
                ev = None
            a["resolved"] = ev is None or ev.get("state") == "resolved"
        return a.get("resolved", False)

    def _alarm_open(self, ts: float) -> bool:
        a = self._alarm
        return a is not None and ts - a["last"] < self.COOLDOWN_S and not self._resolved(a)

    def _trigger(self, root: str, why: str, ts: float, *, decoy: str = "", how: str = "", new_path: str = "",
                 count: int = 0, example: str = "", restore: str = "") -> None:
        if self._alarm_open(ts):
            self._merge(self._alarm, decoy, count, restore, ts)
            return
        label = _label(root)
        pause_on = bool(getattr(self.settings, "ransomware_pause", True))
        suspects = [] if why == "offline" else self._find_suspects()
        paused_ids: list[int] = []
        if why == "decoy":
            cause = f"a decoy file in {label} was changed"
        else:
            cause = f"many files in {label} were changed at once"
        if pause_on and suspects:
            paused_ids = self._pause_some(suspects, cause, self.MAX_PAUSED)
        title, message = self._words(why, label, decoy, how, new_path, count, example, suspects,
                                     paused_ids, pause_on)
        data = {"paused_ids": paused_ids, "decoy": decoy, "suspects": [
            {k: s[k] for k in ("pid", "name", "exe", "write_mb_s")} for s in suspects],
            "folder": winpath.to_display(root), "trigger": why, "count": count,
            "decoys": [decoy] if decoy else []}
        eid = self.store.add_guard_event("ransomware", "warning", title, message,
                                         path=decoy or winpath.to_display(root), data=data)
        self._link_paused(paused_ids, eid)
        log.warning("%s", title)
        carry = set(self._alarm["restore"]) if self._alarm is not None else set()   # an older alert's decoys
        if restore:
            carry.add(restore)
            self._link_decoy_event([restore], eid)
        self._alarm = {"id": eid, "ts": ts, "last": ts, "data": data, "restore": carry,
                       "words": [why, label, decoy, how, new_path, count, example, list(suspects), pause_on],
                       "merge_sample": ts, "written": ts, "resolved": False, "resolved_at": time.monotonic(),
                       "known": {(s["pid"], round(s["create_time"], 2)) for s in suspects}}

    def _merge(self, a: dict, decoy: str, count: int, restore: str, ts: float) -> None:
        a["last"] = ts
        if restore:
            a["restore"].add(restore)
            self._link_decoy_event([restore], a["id"])
        d = a["data"]
        changed = False
        if decoy and decoy not in d["decoys"]:
            d["decoys"].append(decoy)
            changed = True
        if count > d.get("count", 0):
            d["count"] = count
        d["merged"] = d.get("merged", 0) + 1
        pause_on = bool(getattr(self.settings, "ransomware_pause", True))
        if (pause_on and ts - a["merge_sample"] >= 5.0 and len(d["paused_ids"]) < self.MAX_PAUSED
                and len(d["suspects"]) < 2 * self.MAX_SUSPECTS):
            a["merge_sample"] = ts
            found = self._find_suspects(exclude=a["known"])[: self.MAX_SUSPECTS]
            for s in found:
                a["known"].add((s["pid"], round(s["create_time"], 2)))
            rows = self._pause_some(found, "files were being locked", self.MAX_PAUSED - len(d["paused_ids"]))
            for s in found:
                d["suspects"].append({k: s[k] for k in ("pid", "name", "exe", "write_mb_s")})
                a["words"][7].append(s)
                changed = True
            if rows:
                d["paused_ids"].extend(rows)
                self._link_paused(rows, a["id"])
        if changed or ts - a["written"] >= 2.0:
            a["written"] = ts
            w = a["words"]
            title, message = self._words(*w[:7], w[7], d["paused_ids"], w[8])
            try:
                self.store.set_guard_event(a["id"], data=d, title=title, message=message)
            except Exception as exc:
                log.warning("could not update the alert (%s)", plain_error(exc))

    def _link_paused(self, paused_ids: list[int], event_id: int) -> None:
        """The page finds a paused program's alert through paused.event_id."""
        for row in paused_ids:
            try:
                self.store.set_paused_event(row, event_id)
            except Exception as exc:
                log.warning("could not link a paused program to its alert (%s)", plain_error(exc))

    @staticmethod
    def _words(why, label, decoy, how, new_path, count, example, suspects, paused_ids, pause_on):
        n = len(paused_ids)
        names = _names_list([s["name"] for s in suspects])
        paused = [s for s in suspects if s.get("paused")]
        paused_names = _names_list([s["name"] for s in paused])
        others = _names_list([s["name"] for s in suspects if not s.get("paused")])
        if n:
            phrase = f"Paused {n} program{'s' if n != 1 else ''}."
        elif suspects and not pause_on:
            phrase = "Nothing was paused (pausing is off in Settings)."
        elif suspects:
            phrase = "TacoGuard could not pause the program."
        else:
            phrase = "No program to pause was found."
        name = os.path.basename(decoy) if decoy else ""
        new_name = os.path.basename(new_path) if new_path else ""
        locks = " Ransomware does this when it locks (encrypts) your files to demand money."
        if why == "burst":
            title = f"Possible ransomware: many files in {label} were changed at once. {phrase}"
            what = (f"{count} files in {label} were renamed or rewritten within a few seconds, and the new "
                    f"versions look locked (a new file extension or scrambled contents)"
                    + (f", for example {os.path.basename(example)}." if example else ".") + locks)
        else:
            how_words = {"renamed": f"renamed to {new_name}", "replaced": f"replaced by {new_name}",
                         "removed": "deleted while other files there were being renamed or rewritten"
                         }.get(how, "changed")
            what = (f"TacoGuard keeps a few hidden decoy files in {label} that no program should ever touch. "
                    f"One of them, {name}, was {how_words}." + locks)
            if why == "offline":
                title = f"Possible ransomware: a decoy file in {label} was changed while TacoGuard was not running."
                return title, (what + " TacoGuard was not running at the time, so it cannot tell which program "
                               "did it. If you did not open or edit this hidden file yourself, run a full scan "
                               "from the Scan tab. A fresh decoy file is put back once you have dealt with this "
                               "alert (or after 10 minutes).")
            title = f"Possible ransomware: a decoy file in {label} was changed. {phrase}"
        if n:
            one = len(paused) <= 1
            act = (f" TacoGuard paused {paused_names or 'the program'}. {'It was' if one else 'They were'} "
                   f"writing a lot to your disk at that moment. If you know "
                   f"{'this program' if one else 'these programs'} (a game, a download, a backup), press "
                   "Resume. A paused program does nothing until you decide. If you don't know it, press End it "
                   "to close it, or Quarantine its program to close it and lock its file away. TacoGuard did "
                   "not delete or change any of your files.")
            if others:
                act += f" Also writing at that moment, not paused: {others}."
        elif suspects and not pause_on:
            act = (f" Pausing is switched off in Settings, so TacoGuard only reports this. The program writing "
                   f"the most at that moment: {names}. If you don't recognise it, close it in Task Manager and "
                   "run a full scan from the Scan tab.")
        elif suspects:
            act = (f" TacoGuard tried to pause {names} (the program writing the most at that moment), but "
                   "Windows did not allow it. If you don't recognise it, close it in Task Manager and run a "
                   "full scan from the Scan tab.")
        else:
            act = (" TacoGuard could not tell which program did it: no program under your account was writing "
                   "heavily to your disk a moment later. If you did not do this yourself, save your work, look "
                   "in Task Manager for programs you don't know and run a full scan from the Scan tab.")
        if why == "decoy":
            act += " A fresh decoy file is put back once you have dealt with this alert (or after 10 minutes)."
        return title, what + act
