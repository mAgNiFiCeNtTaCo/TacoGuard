"""Self-protection (Phase 4, contract in tacoguard/phase4.py). No admin rights, nothing outside
TacoGuard's own processes, files and its one Run value is ever touched.

    harden_process() -> bool
        Puts a protected DACL on THIS process: SYSTEM and Administrators keep full access; your own
        account (and so every other program running as you, without admin rights) may only look
        at it (name, start time, wait for it to end: PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_QUERY_INFORMATION | SYNCHRONIZE | READ_CONTROL; no memory reading);
        an OWNER RIGHTS (S-1-3-4) entry granting only READ_CONTROL
        takes away the owner's implicit right to change that DACL back. So Task Manager or a
        program without admin rights cannot end, pause, write into or inject into TacoGuard.
        Handles opened BEFORE the change keep their rights: the page still ends a guard or scan
        worker it started through its own process handle (and the venv launcher's job). A guard
        or page started by someone else is stopped through the stop file (Quit) only.
        Measured 2026-11-26 from a hardened child (same user, not elevated): OpenProcess with
        PROCESS_TERMINATE / SUSPEND_RESUME / VM_WRITE / VM_READ / CREATE_THREAD / WRITE_DAC is
        refused; psutil name(), create_time(), cmdline(), exe(), status(), username(),
        memory_info(), wait() still work; cwd() and environ() are refused (they read memory).
        A guard started by the page through the venv's python.exe launcher still ends when the
        page ends that launcher (Popen.kill: the launcher's job closes).
        Threads (review 2026-11-26): ending or freezing one thread is as bad as ending the
        process, so every thread gets the same kind of DACL (thread_sddl): the threads that exist
        (Toolhelp snapshot, harden_threads), every Python thread started later (a threading
        profile hook that runs once at the thread's start), and the guard sweeps again every
        minute for threads native code started. The token's default DACL would cover new threads
        by itself, but it also applies to the pipes subprocess creates (measured: capture_output
        then fails with "Access is denied"), so it is not used.
        The venv launcher (TacoGuard's own redirector, launcher_parent) is hardened the same way
        (harden_parent_launcher), so ending it can't end TacoGuard. An administrator still can.
    maybe_harden(settings, log=None) -> bool   harden_process() + harden_parent_launcher() when
        settings.self_protection, never while pytest runs (PYTEST_CURRENT_TEST); a failure only logs.

    check_install(settings) -> list[str]   the RUNNING installed copy against tacoguard-files.json
        (written by install.py / selfupdate.py from the copied tree / verified package):
        "changed: tacoguard/x.py", "extra: ...", "missing: ..." for .py/.pyw (and the page's own
        .js/.html). [] for a project-folder copy, an old install without the list, or no change.
    report_install_check(settings, store) -> list[str]   check_install + one guard event kind
        "self", level "warning" (at most once a day for the same list). Nothing else is done.
    write_manifest(version_dir, launcher=None) -> dict

    class OwnWatch(settings, store, ...)   the guard's look at TacoGuard's own things, every 60 s:
        check() -> list[int] (event ids)
        - the "TacoGuard" Run value (only for the installed copy, while settings.start_at_sign_in):
          removed or changed by another program -> event (never silently re-added);
        - the data folder's ACL (only when config.secure_root's marker says it was locked): an
          entry that lets any account other than yours, SYSTEM and Administrators write -> locked
          again (config.secure_root: the whole permission list replaced) and an event.
        settings.json changed by another program is NOT watched (it needs the page to record its
        own writes; see the Phase 4 report).
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import time
from ctypes import wintypes
from pathlib import Path

log = logging.getLogger("tacoguard.selfprotect")

# ---- process rights -----------------------------------------------------------------------------
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = 0x001FFFFF
# PROCESS_QUERY_INFORMATION too: psutil's wait() opens SYNCHRONIZE | PROCESS_QUERY_INFORMATION
# (the page, the installer and the self-update watchdog wait on TacoGuard's processes). It reads
# information only, no memory (VM_READ is not granted), and OpenProcessToken already works with
# "query limited", so it opens nothing new. Measured 2026-11-26.
USER_RIGHTS = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE | READ_CONTROL
OWNER_RIGHTS_SID = "S-1-3-4"
# thread rights: ending (TerminateThread) or freezing (SuspendThread) one thread of TacoGuard
# is as bad as ending the process, so threads get the same kind of DACL
THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SET_INFORMATION = 0x0020
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_ALL_ACCESS = 0x001FFFFF
THREAD_USER_RIGHTS = THREAD_QUERY_LIMITED_INFORMATION | THREAD_QUERY_INFORMATION | SYNCHRONIZE | READ_CONTROL

SE_KERNEL_OBJECT = 6
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
SDDL_REVISION_1 = 1
ERROR_ACCESS_DENIED = 5

HARDEN_TEST_ENV = "PYTEST_CURRENT_TEST"


def _k32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    return k32


def _adv():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    adv.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    adv.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    adv.SetSecurityInfo.restype = wintypes.DWORD
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p)]
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    return adv


def current_user_sid() -> str:
    """The string SID of the account this process runs as ("S-1-5-21-...")."""
    k32, adv = _k32(), _adv()
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        need = wintypes.DWORD()
        adv.GetTokenInformation(tok, TOKEN_USER_CLASS, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(max(need.value, 64))
        if not adv.GetTokenInformation(tok, TOKEN_USER_CLASS, buf, need, ctypes.byref(need)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        psid = ctypes.c_void_p.from_buffer(buf).value          # TOKEN_USER.User.Sid
        out = ctypes.c_wchar_p()
        if not adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return out.value
        finally:
            k32.LocalFree(out)
    finally:
        k32.CloseHandle(tok)


def process_sddl(user_sid: str) -> str:
    """The protected DACL put on TacoGuard's processes, as SDDL."""
    return (f"D:P(A;;0x{PROCESS_ALL_ACCESS:x};;;SY)(A;;0x{PROCESS_ALL_ACCESS:x};;;BA)"
            f"(A;;0x{USER_RIGHTS:x};;;{user_sid})(A;;0x{READ_CONTROL:x};;;OW)")


def thread_sddl(user_sid: str) -> str:
    """The protected DACL put on TacoGuard's threads, as SDDL (the same idea as process_sddl)."""
    return (f"D:P(A;;0x{THREAD_ALL_ACCESS:x};;;SY)(A;;0x{THREAD_ALL_ACCESS:x};;;BA)"
            f"(A;;0x{THREAD_USER_RIGHTS:x};;;{user_sid})(A;;0x{READ_CONTROL:x};;;OW)")


_sddl_cache: dict[str, str] = {}


def _sddls() -> tuple[str, str]:
    if "user" not in _sddl_cache:
        _sddl_cache["user"] = current_user_sid()
    sid = _sddl_cache["user"]
    return process_sddl(sid), thread_sddl(sid)


def _set_dacl(handle, sddl: str) -> int:
    """SetSecurityInfo(handle, protected DACL from `sddl`). 0 when Windows accepted it, else the
    Windows error."""
    k32, adv = _k32(), _adv()
    sd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
        return ctypes.get_last_error() or 1
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl),
                                             ctypes.byref(defaulted)) or not present or not dacl:
            return 1
        return int(adv.SetSecurityInfo(handle, SE_KERNEL_OBJECT,
                                       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                       None, None, dacl, None))
    finally:
        k32.LocalFree(sd)


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long), ("dwFlags", wintypes.DWORD)]


TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def thread_ids(pid: int | None = None) -> list[int]:
    """The ids of every thread of process `pid` (default: this one), from a Toolhelp snapshot."""
    pid = os.getpid() if pid is None else int(pid)
    k32 = _k32()
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return []
    out = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = k32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                out.append(int(te.th32ThreadID))
            te.dwSize = ctypes.sizeof(te)
            ok = k32.Thread32Next(snap, ctypes.byref(te))
    finally:
        k32.CloseHandle(snap)
    return out


def harden_threads(pid: int | None = None) -> int:
    """Puts thread_sddl on every existing thread of process `pid` (default: this one). Returns how
    many threads took it. Raises nothing."""
    try:
        k32 = _k32()
        k32.OpenThread.restype = wintypes.HANDLE
        k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        _, sddl = _sddls()
        n = 0
        for tid in thread_ids(pid):
            h = k32.OpenThread(WRITE_DAC, False, tid)
            if not h:
                continue
            try:
                if _set_dacl(h, sddl) == 0:
                    n += 1
            finally:
                k32.CloseHandle(h)
        return n
    except Exception:
        log.exception("Self-protection: hardening the threads failed")
        return 0


def harden_current_thread() -> bool:
    try:
        k32 = _k32()
        k32.GetCurrentThread.restype = wintypes.HANDLE
        return _set_dacl(k32.GetCurrentThread(), _sddls()[1]) == 0
    except Exception:
        return False


_hook_installed = False


def _install_thread_hook() -> None:
    """Every Python thread started from now on hardens itself first (threading.setprofile: the
    hook runs once at the thread's first call and then takes itself out, so it costs nothing
    afterwards). Windows' token default DACL would do this for every new thread, but it also
    applies to the pipes subprocess makes: measured 2026-11-26, subprocess with capture_output
    then fails with "Access is denied", so it is not used."""
    global _hook_installed
    if _hook_installed:
        return
    import sys
    import threading
    previous = threading.getprofile()

    def hook(frame, event, arg):
        sys.setprofile(previous)
        harden_current_thread()
        if previous is not None:
            return previous(frame, event, arg)
        return None

    threading.setprofile(hook)
    _hook_installed = True


def harden_process() -> bool:
    """Protect this process (see the module docstring): its process DACL, every thread it has now,
    and every Python thread it starts later. True when Windows accepted the process DACL. Raises
    nothing."""
    try:
        k32 = _k32()
        sddl, _ = _sddls()
        rc = _set_dacl(k32.GetCurrentProcess(), sddl)
        if rc != 0:
            log.warning("Self-protection: Windows refused the process rights (error %s)", rc)
            return False
        harden_threads()
        _install_thread_hook()
        return True
    except Exception:
        log.exception("Self-protection: hardening this process failed")
        return False


def launcher_parent():
    """The venv launcher this process was started through (venv\\Scripts\\python(w).exe, a small
    redirector whose job ends this process when it is ended), or None: its exe sits in the folder
    of sys.executable, is not this process's own exe, its command line names tacoguard, and it
    started before this process."""
    import sys
    import psutil
    try:
        me = psutil.Process()
        parent = me.parent()
        if parent is None:
            return None
        exe = parent.exe()
        if os.path.basename(exe).lower() not in ("python.exe", "pythonw.exe"):
            return None
        if os.path.normcase(os.path.dirname(exe)) != os.path.normcase(os.path.dirname(os.path.abspath(sys.executable))):
            return None
        if os.path.normcase(exe) == os.path.normcase(me.exe()):
            return None                           # an ordinary Python, not the redirector
        if "tacoguard" not in " ".join(parent.cmdline()).lower():
            return None
        if parent.create_time() > me.create_time() + 1.0:
            return None
        return parent
    except (psutil.Error, OSError, ValueError):
        return None


def harden_parent_launcher() -> bool:
    """Protect TacoGuard's own venv launcher (launcher_parent) like this process, so ending the
    launcher can't end TacoGuard. Handles opened before (the page's own Popen) keep working."""
    parent = launcher_parent()
    if parent is None:
        return False
    try:
        k32 = _k32()
        h = k32.OpenProcess(WRITE_DAC | PROCESS_QUERY_LIMITED_INFORMATION, False, int(parent.pid))
        if not h:
            return False
        try:
            if _set_dacl(h, _sddls()[0]) != 0:
                return False
        finally:
            k32.CloseHandle(h)
        harden_threads(parent.pid)
        return True
    except Exception:
        log.exception("Self-protection: hardening the launcher failed")
        return False


def harden_child(handle, pid: int, settings=None) -> bool:
    """Protect a helper program TacoGuard just started (clamd, TGUARD-20261127-03) like this
    process: `handle` is the Popen handle (it keeps full rights, so TacoGuard can still end it),
    `pid` its id for the thread pass. Off with settings.self_protection or while pytest runs.
    Never raises."""
    try:
        if settings is not None and not getattr(settings, "self_protection", True):
            return False
        if os.environ.get(HARDEN_TEST_ENV) or os.name != "nt":
            return False
        if _set_dacl(wintypes.HANDLE(int(handle)), _sddls()[0]) != 0:
            return False
        harden_threads(pid)
        return True
    except Exception:
        log.exception("Self-protection: protecting a helper program failed")
        return False


def maybe_harden(settings, logger=None) -> bool:
    """harden_process() (and harden_parent_launcher()) when settings.self_protection is on; never
    while pytest runs (tests that harden a child call harden_process() themselves). Never raises."""
    lg = logger or log
    try:
        if not getattr(settings, "self_protection", True):
            return False
        if os.environ.get(HARDEN_TEST_ENV):
            return False
        ok = harden_process()
        if ok:
            lg.info("Self-protection: only administrators can end or freeze this process (pid %s)",
                    os.getpid())
            if harden_parent_launcher():
                lg.info("Self-protection: TacoGuard's launcher process is protected too")
        else:
            lg.warning("Self-protection: this process could not be protected; TacoGuard runs anyway")
        return ok
    except Exception:
        try:
            lg.exception("Self-protection failed; TacoGuard runs anyway")
        except Exception:
            pass
        return False


def can_open(pid: int, access: int) -> tuple[bool, int]:
    """(opened, Windows error) for OpenProcess(access, pid): used by the tests and the page."""
    k32 = _k32()
    h = k32.OpenProcess(access, False, int(pid))
    if not h:
        return False, ctypes.get_last_error()
    k32.CloseHandle(h)
    return True, 0


# ---- the installed copy's own files ---------------------------------------------------------------
MANIFEST_NAME = "tacoguard-files.json"
# code: Python, the page's own script/markup, and the hosts helper TacoGuard installs into Program Files
CHECKED_SUFFIXES = (".py", ".pyw", ".js", ".html", ".ps1")
SKIP_DIRS = {"__pycache__"}
INSTALL_ALERT_KEY = "selfprotect_install_alert"
INSTALL_ALERT_REPEAT_S = 24 * 3600
INSTALL_TITLE = "TacoGuard's own files were changed"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def tree_hashes(folder) -> dict[str, str]:
    """{relative path with /: sha256} of every file in `folder` (no __pycache__ / .pyc, not the
    manifest itself)."""
    folder = Path(folder)
    out = {}
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn.endswith((".pyc", ".pyo")):
                continue
            p = Path(dirpath) / fn
            rel = p.relative_to(folder).as_posix()
            if rel == MANIFEST_NAME:
                continue
            out[rel] = _sha256_file(p)
    return out


def write_manifest(version_dir, launcher=None, launcher_sha256: str | None = None) -> dict:
    """Writes version_dir/tacoguard-files.json: the sha256 of every file in the version folder
    (and of the launcher TacoGuard.pyw when given). Same files -> same bytes (no dates), so
    install.py's "already installed" comparison still holds."""
    version_dir = Path(version_dir)
    data = {"format": 1, "files": tree_hashes(version_dir)}
    if launcher is not None and Path(launcher).is_file():
        data["launcher"] = _sha256_file(Path(launcher))
    elif launcher_sha256:
        data["launcher"] = str(launcher_sha256)
    tmp = version_dir / (MANIFEST_NAME + ".tmp")
    tmp.write_bytes(json.dumps(data, indent=1, sort_keys=True).encode("utf-8"))
    os.replace(tmp, version_dir / MANIFEST_NAME)
    return data


def read_manifest(version_dir) -> dict | None:
    try:
        data = json.loads((Path(version_dir) / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        return None
    return data


def _checked(rel: str) -> bool:
    return rel.lower().endswith(CHECKED_SUFFIXES)


def compare_tree(version_dir, manifest: dict, launcher=None) -> list[str]:
    """["changed: tacoguard/x.py", "extra: ...", "missing: ..."] for the code files."""
    version_dir = Path(version_dir)
    want = {k: v for k, v in manifest.get("files", {}).items() if _checked(k)}
    out = []
    seen = set()
    for dirpath, dirnames, filenames in os.walk(version_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            rel = p.relative_to(version_dir).as_posix()
            if not _checked(rel):
                continue
            seen.add(rel)
            if rel not in want:
                out.append(f"extra: {rel}")
                continue
            try:
                if _sha256_file(p) != want[rel]:
                    out.append(f"changed: {rel}")
            except OSError:
                out.append(f"changed: {rel}")
    out += [f"missing: {rel}" for rel in sorted(set(want) - seen)]
    if launcher is not None and manifest.get("launcher"):
        lp = Path(launcher)
        try:
            if _sha256_file(lp) != manifest["launcher"]:
                out.append(f"changed: {lp.name}")
        except OSError:
            out.append(f"missing: {lp.name}")
    return out


def running_version_dir() -> Path:
    import tacoguard
    return Path(tacoguard.__file__).resolve().parent.parent


def check_install(settings=None, *, version_dir=None, root=None) -> list[str]:
    """The running installed copy against the hash list written when it was installed. Empty
    for the project-folder copy, an install made before Phase 4 (no list) or no change."""
    try:
        if version_dir is None:
            from .selfupdate import running_from_install
            if not running_from_install():
                return []
            from .config import install_root
            version_dir, root = running_version_dir(), install_root()
        manifest = read_manifest(version_dir)
        if manifest is None:
            return []
        launcher = Path(root) / "TacoGuard.pyw" if root is not None else None
        return compare_tree(version_dir, manifest, launcher)
    except Exception:
        log.exception("Self-protection: the install check failed")
        return []


def _problem_words(p: str) -> str:
    kind, _, rel = p.partition(": ")
    return f"{rel.replace('/', chr(92))} ({kind})"


def install_message(problems: list[str]) -> str:
    shown = ", ".join(_problem_words(p) for p in problems[:5])
    more = len(problems) - 5
    if more > 0:
        shown += f" and {more} more"
    return (f"These files in TacoGuard's installed copy are not the ones TacoGuard installed: {shown}. "
            "Another program may have changed TacoGuard. To be safe, install TacoGuard again (run the "
            "installer from the project folder), then run a full scan.")


def report_install_check(settings, store, problems: list[str] | None = None) -> list[str]:
    """check_install() and, when something differs, one guard event (kind "self", level
    "warning"); the same list is reported at most once a day. Never raises."""
    try:
        if problems is None:
            t0 = time.perf_counter()
            problems = check_install(settings)
            log.info("Self-protection: install check took %.0f ms", (time.perf_counter() - t0) * 1000)
        if not problems:
            return []
        sig = hashlib.sha256("\n".join(problems).encode("utf-8")).hexdigest()
        try:
            last = json.loads(store.get_meta(INSTALL_ALERT_KEY) or "{}") or {}
        except (ValueError, TypeError):
            last = {}
        now = time.time()
        if last.get("sig") == sig and now - float(last.get("time") or 0) < INSTALL_ALERT_REPEAT_S:
            return problems
        store.add_guard_event("self", "warning", INSTALL_TITLE, install_message(problems),
                              data={"files": problems[:50]})
        store.set_meta(INSTALL_ALERT_KEY, json.dumps({"sig": sig, "time": now}))
        return problems
    except Exception:
        log.exception("Self-protection: could not report the install check")
        return problems or []


# ---- the data folder's ACL ------------------------------------------------------------------------
ACCESS_ALLOWED_ACE_TYPE = 0
FILE_WRITE_MASK = (0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100      # write/append data, EA, delete child, attributes
                   | 0x00010000 | WRITE_DAC | WRITE_OWNER                # delete, change rights, take ownership
                   | 0x10000000 | 0x40000000)                          # GENERIC_ALL, GENERIC_WRITE
BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-32-545": "Users",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-4": "Interactive users",
    "S-1-5-32-546": "Guests",
    "S-1-2-0": "Local users",
    "S-1-5-7": "Anonymous",
}


class _AceHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]


class _AllowedAce(ctypes.Structure):
    _fields_ = [("Header", _AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


class _Acl(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte), ("AclSize", ctypes.c_ushort),
                ("AceCount", ctypes.c_ushort), ("Sbz2", ctypes.c_ushort)]


INHERITED_ACE = 0x10


NULL_DACL = "(no permission list: everyone)"
OWNER_SECURITY_INFORMATION = 0x00000001
# accounts the data folder may give rights to besides your own: SYSTEM, Administrators, and the
# "creator owner" / "owner rights" placeholders (they stand for the owner, who is checked separately)
LOCK_OK_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"})


def _sid_str(psid: int) -> str:
    out = ctypes.c_wchar_p()
    if not _adv().ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out)):
        return ""
    try:
        return out.value or ""
    finally:
        _k32().LocalFree(out)


def folder_writer_sids(path, explicit_only: bool = False) -> list[str]:
    """String SIDs the folder's DACL lets write, change rights or delete; [NULL_DACL] for a missing
    (null) DACL. explicit_only: only entries set on this folder itself (not inherited from its
    parent). Raises OSError when Windows does not say."""
    k32, adv = _k32(), _adv()
    dacl, sd = ctypes.c_void_p(), ctypes.c_void_p()
    rc = adv.GetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None,
                                   ctypes.byref(dacl), None, ctypes.byref(sd))
    if rc != 0:
        raise OSError(rc, "GetNamedSecurityInfoW failed")
    try:
        if not dacl.value:
            return [NULL_DACL]
        acl = _Acl.from_address(dacl.value)
        found = []
        for i in range(acl.AceCount):
            pace = ctypes.c_void_p()
            if not adv.GetAce(dacl, i, ctypes.byref(pace)):
                continue
            ace = _AllowedAce.from_address(pace.value)
            if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE or not (ace.Mask & FILE_WRITE_MASK):
                continue
            if explicit_only and ace.Header.AceFlags & INHERITED_ACE:
                continue
            sid = _sid_str(pace.value + _AllowedAce.SidStart.offset)
            if sid and sid not in found:
                found.append(sid)
        return found
    finally:
        k32.LocalFree(sd)


def folder_owner_sid(path) -> str:
    """The string SID of the folder's owner. Raises OSError when Windows does not say."""
    k32, adv = _k32(), _adv()
    owner, sd = ctypes.c_void_p(), ctypes.c_void_p()
    rc = adv.GetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner),
                                   None, None, None, ctypes.byref(sd))
    if rc != 0:
        raise OSError(rc, "GetNamedSecurityInfoW failed")
    try:
        sid = _sid_str(owner.value) if owner.value else ""
        if not sid:
            raise OSError(1, "the folder has no owner")
        return sid
    finally:
        k32.LocalFree(sd)


def account_name(sid: str) -> str:
    """A readable name for a SID ("Everyone", "PC\\bob"), else the SID itself."""
    if sid in BROAD_SIDS:
        return BROAD_SIDS[sid]
    if sid == NULL_DACL:
        return "Everyone"
    try:
        adv = _adv()
        psid = ctypes.c_void_p()
        adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        if not adv.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
            return sid
        try:
            name, dom = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
            n1, n2, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
            adv.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                              ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                              ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
            if adv.LookupAccountSidW(None, psid, name, ctypes.byref(n1), dom, ctypes.byref(n2), ctypes.byref(use)):
                return f"{dom.value}\\{name.value}" if dom.value else name.value
            return sid
        finally:
            _k32().LocalFree(psid)
    except (OSError, AttributeError):
        return sid


def folder_others(path, explicit_only: bool = False, me: str | None = None) -> list[str]:
    """SIDs other than yours, SYSTEM and Administrators that the folder lets write."""
    me = me or current_user_sid()
    return [s for s in folder_writer_sids(path, explicit_only) if s != me and s not in LOCK_OK_SIDS]


def folder_open_to(path, explicit_only: bool = False) -> list[str]:
    """Names of the broad groups (Everyone, Users, ...) the folder's DACL lets write, change rights
    or delete; ["Everyone"] for a missing (null) DACL. [] when it is locked. explicit_only: only
    entries set on this folder itself (not inherited from its parent). Raises OSError when
    Windows does not say."""
    found = []
    for sid in folder_writer_sids(path, explicit_only):
        name = "Everyone" if sid == NULL_DACL else BROAD_SIDS.get(sid)
        if name and name not in found:
            found.append(name)
    return found


def lock_sddl(user_sid: str) -> str:
    """The data folder's protected DACL: full control for you, SYSTEM and Administrators only,
    inherited by everything inside."""
    return f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})"


def _sd_from(sddl: str) -> ctypes.c_void_p:
    sd = ctypes.c_void_p()
    if not _adv().ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
        raise OSError(ctypes.get_last_error() or 1, "ConvertStringSecurityDescriptorToSecurityDescriptorW failed")
    return sd


def create_locked_folder(path) -> bool:
    """Make the folder with the lock already on it (no moment where another account could get in).
    False when it already exists. Raises OSError when Windows refuses."""

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    k32 = _k32()
    sd = _sd_from(lock_sddl(current_user_sid()))
    try:
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
        k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
        if k32.CreateDirectoryW(str(path), ctypes.byref(sa)):
            return True
        err = ctypes.get_last_error()
        if err == 183:                      # ERROR_ALREADY_EXISTS
            return False
        raise OSError(err, "CreateDirectoryW failed")
    finally:
        k32.LocalFree(sd)


def lock_folder(path) -> int:
    """Replace the folder's whole DACL with lock_sddl (every other account's own entries go, and
    the folder stops inheriting from its parent); folders and files inside inherit it. 0 when
    Windows accepted it, else the Windows error."""
    k32, adv = _k32(), _adv()
    try:
        sd = _sd_from(lock_sddl(current_user_sid()))
    except OSError as e:
        return e.errno or 1
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl),
                                             ctypes.byref(defaulted)) or not present or not dacl:
            return 1
        adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        adv.SetNamedSecurityInfoW.restype = wintypes.DWORD
        return int(adv.SetNamedSecurityInfoW(str(path), SE_FILE_OBJECT,
                                             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                             None, None, dacl, None))
    finally:
        k32.LocalFree(sd)


def open_subfolders(root, me: str | None = None) -> list[Path]:
    """First-level subfolders of the data folder with their OWN entries that let another account
    write (inherited ones come from the locked data folder and are fine)."""
    out = []
    try:
        subs = [p for p in Path(root).iterdir() if p.is_dir() and not p.is_symlink()]
    except OSError:
        return out
    try:
        me = me or current_user_sid()
    except OSError:
        return out
    for p in sorted(subs):
        try:
            if folder_others(p, explicit_only=True, me=me):
                out.append(p)
        except OSError:
            continue
    return out


def data_folder_open_to(root) -> list[str]:
    """Names of the accounts other than yours, SYSTEM and Administrators that may write into the
    data folder itself or (by their own entries) into one of its first-level subfolders. Raises
    OSError when Windows does not say about the folder."""
    me = current_user_sid()
    sids = list(folder_others(root, me=me))
    for p in open_subfolders(root, me=me):
        for sid in folder_others(p, explicit_only=True, me=me):
            if sid not in sids:
                sids.append(sid)
    found = []
    for sid in sids:
        name = account_name(sid)
        if name not in found:
            found.append(name)
    return found


def relock_data_folder(settings) -> bool:
    """config.secure_root(force=True): the lock again (inheritance off, only your account + SYSTEM +
    Administrators), and first-level subfolders with their own entries for other accounts reset
    to inherit from it. The marker file stays all along. True when the folder is locked
    afterwards; False also when the folder belongs to another account."""
    from .config import DataFolderNotYours, secure_root
    root = Path(settings.root)
    try:
        note = secure_root(settings, force=True)
    except DataFolderNotYours as e:
        log.warning("Self-protection: %s", e)
        return False
    log.info("Self-protection: %s", note)
    try:
        return not data_folder_open_to(root)
    except OSError:
        return False


# ---- the guard's watch over TacoGuard's own things ------------------------------------------------
RUN_STATE_KEY = "selfprotect_run"
ACL_ALERT_KEY = "selfprotect_acl_alert"
RUN_REMOVED_TITLE = "TacoGuard's start-at-sign-in entry was removed by another program"
RUN_CHANGED_TITLE = "TacoGuard's start-at-sign-in entry was changed by another program"
ACL_TITLE = "TacoGuard's data folder was opened to other accounts"


class OwnWatch:
    """See the module docstring. key_path / root / installed are for tests (a key under
    HKCU\\Software\\TacoGuardTest, a temp install folder); by default: the real Run key, the
    install folder, and only when this copy runs from it."""

    def __init__(self, settings, store, *, key_path: str | None = None, root=None,
                 installed: bool | None = None):
        self.settings, self.store = settings, store
        self.key_path = key_path
        self._root = root
        self._installed = installed
        self.checks = 0

    @property
    def root(self) -> Path:
        if self._root is None:
            from .config import install_root
            self._root = install_root()
        return Path(self._root)

    @property
    def installed(self) -> bool:
        if self._installed is None:
            try:
                from .selfupdate import running_from_install
                self._installed = bool(running_from_install())
            except Exception:
                self._installed = False
        return self._installed

    def check(self) -> list[int]:
        """One look (the guard calls it every 60 s). Returns the ids of new events."""
        self.checks += 1
        ids: list[int] = []
        for step in (self._check_run, self._check_acl):
            try:
                ids += step()
            except Exception:
                log.exception("Self-protection: a check of TacoGuard's own things failed")
        return ids

    # ---- the Run value ---------------------------------------------------------------------
    def run_state(self) -> tuple[str, str]:
        """("off" | "ok" | "missing" | "changed", the value found)."""
        from . import autostart
        if not getattr(self.settings, "start_at_sign_in", False):
            return "off", ""
        found = autostart.status(self.key_path).get("command") or ""
        if not found:
            return "missing", ""
        want = autostart.command_for(self.root)
        if os.path.normcase(found.strip()) == os.path.normcase(want):
            return "ok", found
        return "changed", found

    def _check_run(self) -> list[int]:
        if not self.installed:
            return []
        state, found = self.run_state()
        try:
            prev = json.loads(self.store.get_meta(RUN_STATE_KEY) or "{}") or {}
        except (ValueError, TypeError):
            prev = {}
        prev_state = prev.get("state")
        if state in ("ok", "off") or prev_state is None:
            # fine, or the first look ever (a baseline)
            self.store.set_meta(RUN_STATE_KEY, json.dumps({"state": state}))
            return []
        if prev_state == state:
            return []                             # already reported
        if prev_state not in ("ok", "missing", "changed"):
            # it was off: Settings switched it on and the page could not add it, not another program
            self.store.set_meta(RUN_STATE_KEY, json.dumps({"state": state}))
            return []
        if prev.get("pending") != state:
            # seen once: Settings may be changing it right now; reported when the next look (a
            # minute later, maybe by the next guard process) still finds it so
            self.store.set_meta(RUN_STATE_KEY, json.dumps({"state": prev_state, "pending": state}))
            return []
        self.store.set_meta(RUN_STATE_KEY, json.dumps({"state": state}))
        what_to_do = ("TacoGuard did not change it back by itself. If you didn't do this, run a full scan. "
                      "To put TacoGuard's own entry back, switch 'Start TacoGuard when I sign in' off and "
                      "on again in Settings.")
        if state == "missing":
            eid = self.store.add_guard_event(
                "self", "warning", RUN_REMOVED_TITLE,
                "TacoGuard is set to start when you sign in to Windows, but its entry in your start-up "
                "programs is gone. " + what_to_do)
        else:
            shown = found if len(found) <= 200 else found[:200] + "..."
            eid = self.store.add_guard_event(
                "self", "warning", RUN_CHANGED_TITLE,
                f"TacoGuard's entry in your start-up programs now runs: {shown}. " + what_to_do,
                data={"command": found[:1000]})
        log.warning("Self-protection: the start-at-sign-in entry is %s", state)
        return [eid]

    # ---- the data folder's ACL -------------------------------------------------------------
    def _check_acl(self) -> list[int]:
        root = Path(self.settings.root)
        if not (root / ".locked").exists():
            return []                             # never locked (or a test folder): nothing to keep
        try:
            open_to = data_folder_open_to(root)
        except OSError:
            return []
        if not open_to:
            return []
        locked = relock_data_folder(self.settings)
        now = time.time()
        if not locked:
            try:
                last = float(self.store.get_meta(ACL_ALERT_KEY) or 0)
            except (TypeError, ValueError):
                last = 0.0
            if now - last < INSTALL_ALERT_REPEAT_S:
                return []                         # already told today
        self.store.set_meta(ACL_ALERT_KEY, str(now) if not locked else "0")
        who = ", ".join(open_to)
        if locked:
            msg = (f"Another program changed who may use TacoGuard's data folder ({root}): {who} could "
                   "change the files in it. TacoGuard locked it to your account and administrators again. "
                   "If you didn't do this, run a full scan.")
        else:
            msg = (f"Another program changed who may use TacoGuard's data folder ({root}): {who} can "
                   "change the files in it, and TacoGuard could not lock it again. If you didn't do this, "
                   "run a full scan.")
        log.warning("Self-protection: the data folder was open to %s (locked again: %s)", who, locked)
        return [self.store.add_guard_event("self", "warning", ACL_TITLE, msg,
                                           data={"open_to": open_to, "locked_again": locked})]


# ---- starting the page again ----------------------------------------------------------------------
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
SM_SHUTTINGDOWN = 0x2000


def windows_shutting_down() -> bool:
    try:
        return bool(ctypes.WinDLL("user32").GetSystemMetrics(SM_SHUTTINGDOWN))
    except Exception:
        return False


def launch_page(root, data_dir: str | None = None):
    """The installed launcher with --background (no browser), detached, no window: what the
    start-at-sign-in entry runs. Only the guard of the INSTALLED copy calls this."""
    import subprocess
    root = Path(root)
    cmd = [str(root / "venv" / "Scripts" / "pythonw.exe"), str(root / "TacoGuard.pyw"), "--background"]
    from .config import DEFAULT_DATA_DIR
    if data_dir and os.path.normcase(str(data_dir)) != os.path.normcase(DEFAULT_DATA_DIR):
        cmd += ["--data", str(data_dir)]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    base = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    kw = dict(cwd=str(root), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL, close_fds=True)
    try:
        return subprocess.Popen(cmd, creationflags=base | CREATE_BREAKAWAY_FROM_JOB, **kw)
    except OSError:
        return subprocess.Popen(cmd, creationflags=base, **kw)
