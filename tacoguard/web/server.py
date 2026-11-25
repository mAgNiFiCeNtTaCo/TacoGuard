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
"""
from __future__ import annotations

import ctypes
import hmac
import http.client
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
import threading
import time
import traceback
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .. import APP_NAME, __version__, allowlist, defender, detect, learning, quarantine, setup_fetch, winpath
from ..config import CLAMAV_THREADS_MAX, ENDPOINTS, clamav_thread_count, load_settings
from ..model import MALWARE, SUSPICIOUS, Finding, plain_error
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
                     ("ml_model", "ML model"), ("app", "TacoGuard app"))
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
        }

    def update_settings(self, body: dict) -> dict:
        changes_limits, priority, threads, trust_signed = {}, None, None, None
        phase2: dict = {}
        for key, value in body.items():
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
        if not changes_limits and priority is None and threads is None and trust_signed is None and not phase2:
            raise ApiError(400, "Nothing to change.")
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
        disk.save()
        message = "Saved. The new settings apply to the next scan."
        if "learning_enabled" in phase2:
            self.sync_learning()
        if "auto_update" in phase2:
            self._apply_auto_update()
            message += (" Automatic update checks are on." if self.settings.auto_update
                        else " Automatic update checks are off: use Check for updates on Home.")
        return {"ok": True, "message": message, "settings": self.settings_view()}


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
        srv = self.app.server
        if srv is not None:
            threading.Thread(target=srv.shutdown, daemon=True).start()
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
        return {"detections": [_result_for_page(r) for r in self.store.latest_detections(limit)]}

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
        try:
            self.app.log.info("%s %s", self.address_string(), fmt % args)
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


def serve(settings, open_browser: bool = True) -> int:
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
