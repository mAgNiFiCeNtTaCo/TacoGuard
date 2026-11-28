"""Blocking the listed websites in Windows' hosts file (contract: tacoguard/phase4.py).

    plan(settings, hosts_path=None) -> dict      what a hosts update would write and whether the
                                                 block in the file is current (no admin needed)
    apply_elevated(settings, launcher=None) -> Outcome   ONE Windows admin prompt; plain words back
    remove_elevated(settings, launcher=None, cleanup=False) -> Outcome
        Outcome is a str (the plain words) with .ok (True when the hosts file now is as asked)
        and .code ("done", "removed", "cancelled", "blocked", ...).

How the admin step works (once installed, nothing it runs can be changed without administrator
rights; the install step itself copies the helper from your installed copy, so it is refused
while the install check finds TacoGuard's own files changed, TGUARD-20261127-04):
  - The user-level side (this module) prepares the names in settings.webblock_dir\\hosts-list.txt
    (malware sites first, your "never block" sites and protected names left out, at most 100,000,
    one name per line) and passes its path and SHA-256.
  - Windows' own PowerShell (System32, from GetSystemDirectoryW) runs the fixed script
    hosts-helper.ps1 from "<Program Files>\\TacoGuard" (SHGetKnownFolderPath): only administrators
    can change that folder. The script checks the list again itself (size, checksum, every line
    against a strict name pattern), changes only TacoGuard's marked block, keeps a copy of the
    original file once (hosts.tacoguard-original), and answers only with its exit code. It writes
    nothing in the data folder.
  - First use, or TacoGuard was updated (the installed helper's SHA-256 differs from the packaged
    one): the one admin prompt runs a short fixed installer (-EncodedCommand) that holds the
    script's bytes and their SHA-256, creates "<Program Files>\\TacoGuard" (it inherits Program
    Files' admin-only rights), writes the script there and runs it.
  - Afterwards this side reads the hosts file itself (anyone may read it) to see what happened.

Test hooks: `launcher(exe, params, timeout) -> exit code` replaces the admin prompt; helper_dir()
and packaged_script() are replaced so the tests run the real PowerShell (not elevated) on a copy of
the script that writes a temp hosts file. While pytest runs, the real prompt never shows.
"""
from __future__ import annotations

import base64
import ctypes
import gzip
import hashlib
import io
import json
import os
import re
import time
import uuid
from ctypes import wintypes
from pathlib import Path

from . import lists

TIMEOUT_S = 5 * 60
ERROR_CANCELLED = 1223
CAP = 100_000
SOURCES = ("urlhaus", "phishing")          # malware sites first when the cap is reached
BEGIN = "# BEGIN TacoGuard (do not edit this block)"
END = "# END TacoGuard"
NOTE_PREFIX = "# Added by TacoGuard"
HELPER_NAME = "hosts-helper.ps1"
LIST_NAME = "hosts-list.txt"
APPLIED_NAME = "hosts-applied.json"
BACKUP_NAME = "hosts.tacoguard-original"
MAX_LIST_BYTES = 8 * 1024 * 1024

# the helper's exit codes (hosts-helper.ps1) and the installer's (installer_script below)
EXIT_OK, EXIT_USAGE, EXIT_BAD_LIST, EXIT_SHA, EXIT_BLOCKED, EXIT_UNREADABLE = 0, 2, 3, 4, 5, 6
EXIT_CHANGED_BACK, EXIT_ERROR, EXIT_INSTALL_FAILED, EXIT_INSTALL_DAMAGED = 7, 9, 10, 11

# The same pattern the helper checks every line with: lower-case labels of a-z, 0-9 and hyphens
# (not at a label's start or end), at least one dot, a letter top-level domain or an xn-- one
# (so never an IP address), 253 characters at most.
STRICT_NAME_RX = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                            r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\Z", re.ASCII)
_LINES_RX = re.compile(r"[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+\Z")

CANCELLED_MSG = "Windows asked for permission and the answer was No, so the hosts file was not changed."
TIMEOUT_MSG = ("The administrator step didn't finish within 5 minutes, so TacoGuard stopped waiting. The "
               "hosts file may not have changed; look at its status again in a minute.")
NO_LISTS_MSG = ("There are no website lists yet, so there is nothing to block. TacoGuard downloads them "
                "with the next update check.")
NO_ANSWER_MSG = ("The administrator step ended, but the hosts file doesn't show the change. Look at the "
                 "hosts file status again in a minute.")
BLOCKED_MSG = ("Windows or your antivirus (Microsoft Defender) did not let TacoGuard change the hosts "
               "file, so nothing was changed. TacoGuard won't try to get around that.")
CHANGED_BACK_MSG = ("The hosts file was changed back right away (most likely by Microsoft Defender). "
                    "TacoGuard won't try again on its own.")
OPEN_FOLDER_MSG = ("The folder {dir} can be changed by other accounts, so TacoGuard won't run its "
                   "hosts helper from there. Delete that folder (Windows asks for administrator "
                   "permission) and try again.")
CODE_MSGS = {
    EXIT_USAGE: "TacoGuard's hosts helper didn't understand the request, so the hosts file was not changed.",
    EXIT_BAD_LIST: ("TacoGuard's hosts helper refused the prepared website list (an entry failed its "
                    "checks), so the hosts file was not changed."),
    EXIT_SHA: ("The prepared website list changed after you clicked, so the hosts file was not changed. "
               "Press the button again."),
    EXIT_BLOCKED: BLOCKED_MSG,
    EXIT_UNREADABLE: ("TacoGuard's hosts helper could not read the hosts file (or its text format is "
                      "unusual), so nothing was changed."),
    EXIT_CHANGED_BACK: CHANGED_BACK_MSG,
    EXIT_INSTALL_FAILED: ("Windows didn't let TacoGuard put its small hosts helper into {dir}, so the "
                          "hosts file was not changed."),
    EXIT_INSTALL_DAMAGED: "TacoGuard's hosts helper didn't arrive intact, so nothing was changed. Try again.",
}


class LaunchCancelled(Exception):
    pass


class LaunchTimeout(Exception):
    pass


class LaunchError(Exception):
    pass


class Outcome(str):
    """The plain words of an admin step, with .ok and .code."""

    def __new__(cls, message: str, ok: bool = False, code: str = "error"):
        obj = super().__new__(cls, message)
        obj.ok = bool(ok)
        obj.code = code
        return obj


# ---- where things are -------------------------------------------------------------------------------
def system_dir() -> Path:
    """C:\\Windows\\System32, from Windows itself (GetSystemDirectoryW), not an environment variable."""
    buf = ctypes.create_unicode_buffer(520)
    n = ctypes.windll.kernel32.GetSystemDirectoryW(buf, 520)
    if not n or n >= 520:
        raise OSError("Windows did not say where its System32 folder is.")
    return Path(buf.value)


def default_hosts_path() -> Path:
    return system_dir() / "drivers" / "etc" / "hosts"


def backup_path(hosts: Path) -> Path:
    return Path(hosts).with_name(BACKUP_NAME)


def powershell_exe() -> Path:
    return system_dir() / "WindowsPowerShell" / "v1.0" / "powershell.exe"


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


# FOLDERID_ProgramFiles {905e63b6-c1bf-494e-b29c-65b732d3d21a}
_FOLDERID_PROGRAM_FILES = _GUID(0x905E63B6, 0xC1BF, 0x494E, (ctypes.c_ubyte * 8)(
    0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A))


def program_files() -> Path:
    """Program Files from Windows (SHGetKnownFolderPath FOLDERID_ProgramFiles), not an
    environment variable another program could set."""
    shell32 = ctypes.WinDLL("shell32")
    ole32 = ctypes.WinDLL("ole32")
    shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE,
                                             ctypes.POINTER(ctypes.c_wchar_p)]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    out = ctypes.c_wchar_p()
    hr = shell32.SHGetKnownFolderPath(ctypes.byref(_FOLDERID_PROGRAM_FILES), 0, None, ctypes.byref(out))
    try:
        if hr != 0 or not out.value:
            raise OSError("Windows did not say where the Program Files folder is.")
        return Path(out.value)
    finally:
        if out:
            ole32.CoTaskMemFree(ctypes.cast(out, ctypes.c_void_p))


def helper_dir() -> Path:
    return program_files() / "TacoGuard"


def helper_path() -> Path:
    return helper_dir() / HELPER_NAME


def packaged_script_path() -> Path:
    return Path(__file__).with_name(HELPER_NAME)


def packaged_script() -> bytes:
    return packaged_script_path().read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def helper_state(script: bytes | None = None) -> str:
    """"current" (installed and the same as the packaged one), "missing", "old" (TacoGuard was
    updated: it differs) or "open" (its folder or file can be changed by other accounts)."""
    script = packaged_script() if script is None else script
    path = helper_path()
    try:
        data = path.read_bytes()
    except OSError:
        return "missing"
    if _sha(data) != _sha(script):
        return "old"
    try:
        from ..selfprotect import folder_open_to
        if folder_open_to(path.parent) or folder_open_to(path):
            return "open"
    except Exception:
        pass
    return "current"


# ---- reading the hosts file (the helper writes it; this side only reads) --------------------------
def decode_hosts(raw: bytes) -> str:
    """The file's text, the way the helper reads it (UTF-8 with or without BOM, UTF-16 with a BOM,
    other bytes one character each)."""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _entry_name(bare: str) -> str | None:
    parts = bare.split()
    return parts[1] if len(parts) == 2 and parts[0] == "0.0.0.0" else None


def block_names(text: str) -> tuple[bool, list[str], bool]:
    """(a TacoGuard block is there, its names in order, damaged: a BEGIN line without END)."""
    lines = _LINES_RX.findall(text)
    present, damaged, names = False, False, []
    i, n = 0, len(lines)
    while i < n:
        bare = lines[i].strip()
        if bare == BEGIN:
            present = True
            j = i + 1
            while j < n and lines[j].strip() != END:
                j += 1
            if j < n:
                names += [x for x in (_entry_name(ln.strip()) for ln in lines[i + 1:j]) if x]
                i = j + 1
                continue
            damaged = True
            j = i + 1
            while j < n:
                b = lines[j].strip()
                name = _entry_name(b)
                if name:
                    names.append(name)
                elif not b.startswith(NOTE_PREFIX):
                    break
                j += 1
            i = j
            continue
        i += 1
    return present, names, damaged


def names_sha256(names: list[str]) -> str:
    """The SHA-256 of names as the prepared list file holds them (one per line, LF, ASCII)."""
    return _sha("".join(n + "\n" for n in names).encode("ascii", errors="replace"))


def read_block(hosts) -> dict:
    """{"readable", "present", "count", "sha256", "damaged"} of the hosts file's TacoGuard block."""
    try:
        raw = Path(hosts).read_bytes()
    except FileNotFoundError:
        raw = b""
    except OSError:
        return {"readable": False, "present": False, "count": 0, "sha256": "", "damaged": False}
    present, names, damaged = block_names(decode_hosts(raw))
    return {"readable": True, "present": present, "count": len(names),
            "sha256": names_sha256(names) if present else "", "damaged": damaged}


def read_block_names(hosts) -> list[str]:
    """The names in the hosts file's TacoGuard block ([] when none or unreadable)."""
    try:
        return block_names(decode_hosts(Path(hosts).read_bytes()))[1]
    except OSError:
        return []


# ---- the prepared list ------------------------------------------------------------------------------
def allow_set(settings) -> frozenset[str]:
    """Your "never block these sites" list (settings.webblock_allow), checked names only."""
    out = set()
    for x in getattr(settings, "webblock_allow", None) or []:
        if isinstance(x, str):
            n = lists.normalize(x)
            if n:
                out.add(n)
    return frozenset(out)


def is_allowed(name: str, allow: frozenset[str]) -> bool:
    return bool(allow) and any(p in allow for p in lists.parents(name))


def _iter_list(settings, source: str):
    """The names of a current list, checked against its meta.json checksum, one at a time."""
    folder = lists.current_dir(settings, source)
    meta = lists.read_meta(settings, source)
    try:
        raw = (folder / "domains.txt").read_bytes()
    except OSError:
        return
    if not meta.get("sha256") or _sha(raw) != meta["sha256"]:
        raise lists.ListRefused(f"The saved {lists.LABELS.get(source, source)} doesn't match its checksum, "
                                "so it was not used.")
    for line in io.BytesIO(raw):
        name = line.strip().decode("ascii", errors="replace")
        if name:
            yield name


def _ready_sources(settings) -> dict[str, int]:
    out = {}
    for src in SOURCES:
        if not lists._source_on(settings, src):
            continue
        meta = lists.read_meta(settings, src)
        if meta.get("sha256") and (lists.current_dir(settings, src) / "domains.txt").exists():
            out[src] = int(meta.get("count") or 0)
    return out


def prepare(settings) -> dict:
    """{"names": [...], "counts": {source: n}, "sha256", "skipped"}: the names the hosts block gets
    (malware sites first, never a protected name, a name the helper's pattern refuses or one of
    your "never block" sites; at most CAP). Raises lists.ListRefused for a damaged list."""
    allow = allow_set(settings)
    seen: set[str] = set()
    names: list[str] = []
    counts: dict[str, int] = {}
    skipped = 0
    for src in _ready_sources(settings):
        n = 0
        for name in _iter_list(settings, src):
            if len(names) >= CAP:
                break
            if name in seen:
                continue
            if (not STRICT_NAME_RX.match(name) or lists.is_protected(name) or lists.is_ip(name)
                    or is_allowed(name, allow)):
                skipped += 1
                continue
            seen.add(name)
            names.append(name)
            n += 1
        counts[src] = n
    return {"names": names, "counts": counts, "sha256": names_sha256(names), "skipped": skipped}


_prepared_cache: dict = {}


def _prepared_summary(settings) -> dict:
    """prepare() without the names, cached until a list, a switch or your allow list changes."""
    key = (str(settings.webblock_dir), lists.stamp(settings), tuple(sorted(allow_set(settings))), CAP)
    hit = _prepared_cache.get("key") == key and _prepared_cache.get("value")
    if hit:
        return hit
    p = prepare(settings)
    value = {"count": len(p["names"]), "counts": p["counts"], "sha256": p["sha256"], "skipped": p["skipped"]}
    _prepared_cache.clear()
    _prepared_cache.update(key=key, value=value)
    return value


def list_path(settings) -> Path:
    return Path(settings.webblock_dir) / LIST_NAME


def write_list(settings, names: list[str]) -> tuple[Path, str]:
    """settings.webblock_dir\\hosts-list.txt (one name per line, LF, ASCII); (path, sha256)."""
    data = "".join(n + "\n" for n in names).encode("ascii")
    if len(data) > MAX_LIST_BYTES:
        raise ValueError("The website list is too big for the hosts file.")
    path = list_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return path, _sha(data)


def applied_path(settings) -> Path:
    return Path(settings.webblock_dir) / APPLIED_NAME


def _read_json(path: Path) -> dict:
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_applied(settings, data: dict) -> None:
    path = applied_path(settings)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


# ---- the plan ---------------------------------------------------------------------------------------
def plan(settings, hosts_path=None) -> dict:
    """{"ready", "domains", "malware", "phishing", "phishing_total", "capped", "cap", "size_bytes",
    "sha256", "applied": {...} | None, "block": {...}, "current", "changed_by_other", "offer_due",
    "offer_remove", "helper": {"state", "dir", "first_use"}, "message", "hosts_path"}. Reads small
    files and the hosts file; never raises."""
    hosts = Path(hosts_path) if hosts_path is not None else default_hosts_path()
    ready = _ready_sources(settings)
    try:
        prep = _prepared_summary(settings) if ready else {"count": 0, "counts": {}, "sha256": "", "skipped": 0}
        prep_error = ""
    except lists.ListRefused as e:
        prep, prep_error = {"count": 0, "counts": {}, "sha256": "", "skipped": 0}, str(e)
    total = prep["count"]
    applied = _read_json(applied_path(settings)) or None
    block = read_block(hosts)
    changed_by_other = False
    message = ""
    if applied and applied.get("present") and block["readable"]:
        if not block["present"]:
            changed_by_other = True
            message = ("TacoGuard's block was taken out of the hosts file by another program or by hand "
                       "(Microsoft Defender sometimes does this). TacoGuard didn't put it back.")
        elif block["sha256"] != applied.get("sha256"):
            changed_by_other = True
            message = ("TacoGuard's block in the hosts file was changed by another program or by hand. "
                       "TacoGuard didn't change it back.")
    current = bool(block["present"] and total and block["sha256"] == prep["sha256"] and not changed_by_other)
    if not message:
        if prep_error:
            message = prep_error
        elif not ready:
            message = NO_LISTS_MSG + (f" The hosts file still has a TacoGuard block with {block['count']:,} "
                                      "websites." if block["present"] else "")
        elif current:
            message = f"The hosts file blocks {block['count']:,} websites and is up to date."
        elif block["present"]:
            message = (f"The hosts file blocks {block['count']:,} websites; newer lists are ready "
                       f"({total:,} websites, one admin prompt updates it).")
        else:
            message = (f"The hosts file doesn't block these sites yet. Turning it on adds {total:,} "
                       "websites (one admin prompt).")
    if block["damaged"]:
        message += " The block's end line was missing; the next update repairs it."
    if not block["readable"]:
        message += " Windows didn't let TacoGuard read the hosts file."
    every = max(1, int(getattr(settings, "webblock_hosts_every_days", 7) or 7))
    last_time = float((applied or {}).get("time") or 0)
    offer_due = bool(getattr(settings, "webblock_hosts", False) and total and not current
                     and not changed_by_other and time.time() - last_time >= every * 86400)
    offer_remove = bool(block["present"] and (not getattr(settings, "webblock_enabled", True)
                                              or not getattr(settings, "webblock_hosts", False)))
    try:
        state, hdir = helper_state(), str(helper_dir())
    except Exception:
        state, hdir = "missing", ""
    malware = int(prep["counts"].get("urlhaus", 0))
    return {"ready": bool(ready) and total > 0, "domains": total, "malware": malware,
            "phishing": int(prep["counts"].get("phishing", 0)), "phishing_total": int(ready.get("phishing", 0)),
            "capped": sum(ready.values()) > CAP, "cap": CAP, "size_bytes": total * 30,
            "sha256": prep["sha256"], "applied": applied, "block": block, "current": current,
            "changed_by_other": changed_by_other, "offer_due": offer_due, "offer_remove": offer_remove,
            "helper": {"state": state, "dir": hdir, "first_use": state != "current"},
            "message": message, "hosts_path": str(hosts)}


# ---- the admin prompt -----------------------------------------------------------------------------
class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_FLAG_NO_UI = 0x00000400
SEE_MASK_NOASYNC = 0x00000100
SW_HIDE = 0
WAIT_TIMEOUT = 0x102


def shell_runas(exe: str, params: str, timeout: float) -> int:
    """Run `exe params` elevated (one Windows admin prompt), wait for it, return its exit code.
    Raises LaunchCancelled (the user said No), LaunchTimeout, LaunchError."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise LaunchError("Tests never show a real admin prompt.")
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = str(exe)
    info.lpParameters = params
    info.lpDirectory = str(system_dir())
    info.nShow = SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            raise LaunchCancelled()
        raise LaunchError(f"Windows could not start the administrator step (error {err}).")
    if not info.hProcess:
        raise LaunchError("Windows started the administrator step but gave no way to wait for it.")
    try:
        if k32.WaitForSingleObject(info.hProcess, int(timeout * 1000)) == WAIT_TIMEOUT:
            raise LaunchTimeout()
        code_out = wintypes.DWORD(0)
        if not k32.GetExitCodeProcess(info.hProcess, ctypes.byref(code_out)):
            raise LaunchError("Windows did not say how the administrator step ended.")
        return int(code_out.value)
    finally:
        k32.CloseHandle(info.hProcess)


_PS_FLAGS = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass"


def _ps_quote(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


def _helper_args(action: str, list_file: Path | None, sha: str) -> list[str]:
    args = ["-Action", action]
    if action == "apply":
        args += ["-List", str(list_file), "-Sha256", sha]
    return args


def installer_script(script: bytes, target_dir: Path, action: str, list_file: Path | None, sha: str,
                     install: bool, cleanup: bool = False) -> str:
    """The short fixed PowerShell text run with -EncodedCommand: (when `install`) writes the
    helper's bytes, checked against their SHA-256, into target_dir (made when missing, inheriting
    Program Files' rights), runs the helper, and (when `cleanup`, for uninstall) removes it after
    a successful run. .NET calls only."""
    dest = Path(target_dir) / HELPER_NAME
    parts = ["$ErrorActionPreference = 'Stop'",
             f"$dir = {_ps_quote(target_dir)}",
             f"$dest = {_ps_quote(dest)}"]
    if install:
        packed = base64.b64encode(gzip.compress(script, compresslevel=9, mtime=0)).decode("ascii")
        parts += [
            "try {",
            f" $in = [System.IO.MemoryStream]::new([System.Convert]::FromBase64String('{packed}'))",
            " $z = [System.IO.Compression.GZipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)",
            " $out = [System.IO.MemoryStream]::new(); $z.CopyTo($out); $z.Dispose(); $bytes = $out.ToArray()",
            " $h = [System.Security.Cryptography.SHA256]::Create()",
            " $got = [System.BitConverter]::ToString($h.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()",
            f" if ($got -cne '{_sha(script)}') {{ exit {EXIT_INSTALL_DAMAGED} }}",
            " if ([System.IO.Directory]::Exists($dir)) {",
            f"  if ([System.IO.File]::GetAttributes($dir) -band [System.IO.FileAttributes]::ReparsePoint) {{ exit {EXIT_INSTALL_FAILED} }}",
            " } else { [void][System.IO.Directory]::CreateDirectory($dir) }",
            " $tmp = $dest + '.new'",
            " [System.IO.File]::WriteAllBytes($tmp, $bytes)",
            " if ([System.IO.File]::Exists($dest)) { [System.IO.File]::Replace($tmp, $dest, [NullString]::Value) }"
            " else { [System.IO.File]::Move($tmp, $dest) }",
            f"}} catch {{ exit {EXIT_INSTALL_FAILED} }}",
        ]
    args = " ".join(a if a.startswith("-") else _ps_quote(a) for a in _helper_args(action, list_file, sha))
    parts += [f"& $dest {args}", "$code = $LASTEXITCODE"]
    if cleanup:
        parts += ["if ($code -eq 0) { try { [System.IO.File]::Delete($dest);"
                  " if ([System.IO.Directory]::GetFileSystemEntries($dir).Length -eq 0)"
                  " { [System.IO.Directory]::Delete($dir) } } catch { } }"]
    parts.append("exit $code")
    return "\n".join(parts) + "\n"


def build_params(action: str, list_file: Path | None, sha: str, *, script: bytes, target_dir: Path,
                 install: bool, cleanup: bool = False) -> str:
    """powershell.exe's command line (after the program name) for the elevated run."""
    if not install and not cleanup:
        quoted = '"' + str(Path(target_dir) / HELPER_NAME) + '"'
        rest = []
        for a in _helper_args(action, list_file, sha):
            rest.append(a if a.startswith("-") or " " not in a else f'"{a}"')
        return f"{_PS_FLAGS} -File {quoted} " + " ".join(rest)
    text = installer_script(script, target_dir, action, list_file, sha, install, cleanup)
    return f"{_PS_FLAGS} -EncodedCommand " + base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def _launch(params: str, launcher, timeout: float) -> tuple[int | None, Outcome | None]:
    launcher = launcher or shell_runas
    try:
        return int(launcher(str(powershell_exe()), params, timeout)), None
    except LaunchCancelled:
        return None, Outcome(CANCELLED_MSG, code="cancelled")
    except LaunchTimeout:
        return None, Outcome(TIMEOUT_MSG, code="timeout")
    except LaunchError as e:
        return None, Outcome(f"{e} The hosts file was not changed.", code="error")
    except Exception:
        return None, Outcome("The administrator step could not be started. The hosts file was not changed.",
                             code="error")


def _code_words(code: int, hdir: Path) -> str:
    msg = CODE_MSGS.get(code)
    if msg:
        return msg.format(dir=hdir)
    return (f"The administrator step stopped with a problem (code {code}). Look at the hosts file status "
            "again in a minute.")


def _code_name(code: int) -> str:
    return {EXIT_BLOCKED: "blocked", EXIT_CHANGED_BACK: "blocked", EXIT_SHA: "changed",
            EXIT_BAD_LIST: "refused", EXIT_UNREADABLE: "unreadable"}.get(code, "error")


def _prepare_run(cleanup: bool = False) -> tuple[bytes, Path, bool, Outcome | None]:
    script = packaged_script()
    hdir = helper_dir()
    state = helper_state(script)
    if state == "open":
        return script, hdir, False, Outcome(OPEN_FOLDER_MSG.format(dir=hdir), code="error")
    install = state != "current"
    if install:
        # the helper is copied from the installed copy, which your account can change: never hand
        # it to an administrator step when TacoGuard's own files are not the ones it installed
        # (TGUARD-20261127-04)
        from ..selfprotect import check_install, install_message
        problems = check_install()
        if problems:
            return script, hdir, False, Outcome(
                install_message(problems) + " Until then TacoGuard won't ask for administrator rights.",
                code="error")
    return script, hdir, install, None


def apply_elevated(settings, launcher=None, timeout: float = TIMEOUT_S, hosts_path=None) -> Outcome:
    """Write (or update) TacoGuard's block in the hosts file through ONE admin prompt."""
    hosts = Path(hosts_path) if hosts_path is not None else default_hosts_path()
    if not _ready_sources(settings):
        return Outcome(NO_LISTS_MSG, code="no_lists")
    try:
        prep = prepare(settings)
    except lists.ListRefused as e:
        return Outcome(f"{e} The hosts file was not changed.", code="refused")
    if not prep["names"]:
        return Outcome(NO_LISTS_MSG, code="no_lists")
    path, sha = write_list(settings, prep["names"])
    script, hdir, install, refused = _prepare_run()
    if refused is not None:
        return refused
    params = build_params("apply", path, sha, script=script, target_dir=hdir, install=install)
    code, early = _launch(params, launcher, timeout)
    if early is not None:
        return early
    block = read_block(hosts)
    if block["present"] and block["sha256"] == sha:
        _save_applied(settings, {"time": time.time(), "count": block["count"], "sha256": sha,
                                 "counts": prep["counts"], "present": True})
        msg = f"Blocked {block['count']:,} websites in Windows' hosts file."
        if install:
            msg += f" TacoGuard's small hosts helper is now in {hdir}."
        return Outcome(msg, ok=True, code="done")
    if code == EXIT_OK:
        return Outcome(NO_ANSWER_MSG, code="error")
    return Outcome(_code_words(code, hdir), code=_code_name(code))


def remove_elevated(settings, launcher=None, timeout: float = TIMEOUT_S, hosts_path=None,
                    cleanup: bool = False) -> Outcome:
    """Take TacoGuard's block out of the hosts file through ONE admin prompt. `cleanup` (uninstall)
    also removes the helper from Program Files afterwards."""
    hosts = Path(hosts_path) if hosts_path is not None else default_hosts_path()
    before = read_block(hosts)
    if before["readable"] and not before["present"] and not cleanup:
        return Outcome("The hosts file has no TacoGuard block, so nothing needed changing.", ok=True,
                       code="removed")
    script, hdir, install, refused = _prepare_run()
    if refused is not None:
        return refused
    params = build_params("remove", None, "", script=script, target_dir=hdir, install=install, cleanup=cleanup)
    code, early = _launch(params, launcher, timeout)
    if early is not None:
        return early
    after = read_block(hosts)
    if after["readable"] and not after["present"]:
        _save_applied(settings, {"time": time.time(), "count": 0, "sha256": "", "present": False})
        if before["present"]:
            return Outcome("TacoGuard's block was taken out of the hosts file.", ok=True, code="removed")
        return Outcome("The hosts file has no TacoGuard block, so nothing needed changing.", ok=True,
                       code="removed")
    if code == EXIT_OK:
        return Outcome(NO_ANSWER_MSG, code="error")
    return Outcome(_code_words(code, hdir), code=_code_name(code))
