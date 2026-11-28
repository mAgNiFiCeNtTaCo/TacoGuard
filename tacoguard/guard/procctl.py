"""Pause (suspend), resume and end programs, safely. Shared by the guard and the page.

Only programs running under YOUR Windows account can be paused (no admin rights are used), and
some never are: Windows' own core programs, Explorer (the desktop and taskbar), Microsoft
Defender and TacoGuard itself. Windows tools that scripts often abuse (PowerShell, cmd, wscript,
mshta, rundll32, ...) CAN be paused even though they live in C:\\Windows.

A process is always named by (pid, create_time): Windows reuses pids, and acting on a pid that now
belongs to another program would be wrong. Every function checks the pair first.

The names in NEVER_PAUSE count only for the real program: one in Windows' own folder, in Microsoft
Defender's folders, in Edge's folders (msedgewebview2.exe), or one with a valid Microsoft
signature. A program named svchost.exe in AppData is not part of Windows.

TEST ONLY: the environment variable TACOGUARD_TEST_PAUSE_ONLY=<pid,pid,...> limits which programs
the guard may pause (pause_allowed). The app never sets it; it lets an end-to-end drill run a
harmless "ransomware" simulator on a real PC without any risk of pausing the user's own programs.
(pause_allowed reads it; the ransomware guard and the program watcher ask it before each pause.)
"""
from __future__ import annotations

import ctypes
import os
import re
import threading
from ctypes import wintypes
from dataclasses import dataclass

import psutil

PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TEST_PAUSE_ONLY_ENV = "TACOGUARD_TEST_PAUSE_ONLY"
RESUME_TRIES = 10

# Never paused, by name (lower case), when they are the real thing (see _real_place).
NEVER_PAUSE = frozenset({
    "system", "registry", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "explorer.exe", "sihost.exe", "fontdrvhost.exe",
    "ctfmon.exe", "taskhostw.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "searchhost.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "textinputhost.exe", "runtimebroker.exe", "securityhealthsystray.exe", "securityhealthservice.exe",
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "smartscreen.exe", "audiodg.exe",
    "conhost.exe", "dllhost.exe", "applicationframehost.exe", "lockapp.exe", "logonui.exe", "userinit.exe",
    "wudfhost.exe", "taskmgr.exe", "msedgewebview2.exe",
})
# In C:\Windows but often used by scripts and ransomware: these CAN be paused.
MAY_PAUSE_IN_WINDOWS = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
    "msiexec.exe", "cipher.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "schtasks.exe",
    "forfiles.exe", "robocopy.exe", "xcopy.exe", "notepad.exe",
})


@dataclass(frozen=True)
class ProcRef:
    pid: int
    create_time: float


class ProcError(Exception):
    """Plain-English reason an action could not be done ("That program has already closed.")."""


GONE = "That program has already closed."


def _windows_dir() -> str:
    return os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")).rstrip("\\") + "\\"


_PYTHON_NAME = re.compile(r"^pythonw?(\d+(\.\d+)?)?\.exe$")
CLAMAV_NAMES = frozenset({"clamd.exe", "clamscan.exe", "freshclam.exe"})


def _default_engines_dir() -> str:
    try:
        from ..config import DEFAULT_DATA_DIR
        base = os.environ.get("TACOGUARD_DATA") or DEFAULT_DATA_DIR
    except Exception:
        return ""
    return os.path.join(base, "engines")


def _under(path: str, folder: str) -> bool:
    if not path or not folder:
        return False
    p = os.path.normcase(os.path.abspath(path))
    f = os.path.normcase(os.path.abspath(folder)).rstrip("\\") + "\\"
    return p.startswith(f)


def _interpreters() -> set[str]:
    """The exact Python programs TacoGuard runs with (normcased): this interpreter, the base one
    a venv launcher starts, and the installed copy's venv. A python.exe anywhere else is not ours."""
    import sys
    paths = {sys.executable, getattr(sys, "_base_executable", "") or "",
             os.path.join(sys.base_prefix, "python.exe"), os.path.join(sys.prefix, "Scripts", "python.exe")}
    try:
        from ..config import install_root
        paths.add(str(install_root() / "venv" / "Scripts" / "python.exe"))
    except Exception:
        pass
    try:
        paths.add(psutil.Process().exe())
    except (psutil.Error, OSError):
        pass
    out = set()
    for p in filter(None, paths):
        d, n = os.path.split(os.path.abspath(p))
        stem = n.lower().removesuffix(".exe").removesuffix("w")
        for variant in (stem + ".exe", stem + "w.exe"):        # python.exe and pythonw.exe
            out.add(os.path.normcase(os.path.join(d, variant)))
    return out


def tacoguard_pids(engines_dir=None) -> set[int]:
    """TacoGuard's own processes, never paused or ended. Found by who started whom, never by name
    alone (a program can call itself python.exe and put "tacoguard" on its command line):
    - this process, and the chain of processes that started it while each is one of TacoGuard's
      own interpreters (_interpreters: exact paths) whose command line names tacoguard (the page,
      the launcher TacoGuard.pyw, the venv's python.exe launcher);
    - processes those started, and so on, that are such an interpreter too (the guard, scan
      workers, the real interpreter behind a venv launcher);
    - ClamAV's programs (clamd / clamscan / freshclam) only when they run from TacoGuard's own
      engines\\clamav folder.
    Nothing else: a browser the page opened, or a program downloaded and run from it, is NOT
    TacoGuard's. engines_dir: the data folder's engines folder (default: the default data folder's)."""
    me = os.getpid()
    out = {me}
    engines = str(engines_dir) if engines_dir else _default_engines_dir()
    clam_dir = os.path.join(engines, "clamav") if engines else ""
    known = _interpreters()
    try:
        procs = {p.pid: p for p in psutil.process_iter(["name", "ppid", "create_time"])}
    except psutil.Error:
        return out
    verdict: dict[int, bool] = {}

    def ours_python(pid: int) -> bool:
        if pid not in verdict:
            p = procs.get(pid)
            ok = False
            if p is not None and _PYTHON_NAME.match((p.info.get("name") or "").lower()):
                try:
                    ok = (os.path.normcase(os.path.abspath(p.exe() or "")) in known
                          and "tacoguard" in " ".join(p.cmdline()).lower())
                except (psutil.Error, OSError):
                    ok = False
            verdict[pid] = ok
        return verdict[pid]

    def parent_of(pid: int) -> int:
        p = procs.get(pid)
        if p is None:
            return 0
        ppid = int(p.info.get("ppid") or 0)
        parent = procs.get(ppid)
        # Windows reuses pids: a "parent" that started after its child is someone else
        if not parent or ppid == pid or (parent.info.get("create_time") or 0) > (p.info.get("create_time") or 0):
            return 0
        return ppid

    pid = parent_of(me)
    while pid and pid not in out and ours_python(pid):          # who started this process
        out.add(pid)
        pid = parent_of(pid)
    children: dict[int, list[int]] = {}
    for pid in procs:
        pp = parent_of(pid)
        if pp:
            children.setdefault(pp, []).append(pid)
    todo = list(out)
    while todo:                                                 # what those started
        for kid in children.get(todo.pop(), []):
            if kid not in out and ours_python(kid):
                out.add(kid)
                todo.append(kid)
    for pid, p in procs.items():
        if pid in out or (p.info.get("name") or "").lower() not in CLAMAV_NAMES or not clam_dir:
            continue
        try:
            if _under(p.exe() or "", clam_dir):
                out.add(pid)
        except (psutil.Error, OSError):
            continue
    return out


def pause_allowed(pid: int) -> bool:
    """TEST ONLY (see the module docstring): False when TACOGUARD_TEST_PAUSE_ONLY is set and does
    not list this pid. The app never sets the variable, so this is always True for users."""
    raw = os.environ.get(TEST_PAUSE_ONLY_ENV)
    if raw is None:
        return True
    allowed = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if part.isdigit():
            allowed.add(int(part))
    return pid in allowed


# ---- is a protected name the real program? ------------------------------------------------------
_sig_cache: dict[tuple[str, int], bool] = {}
_sig_lock = threading.Lock()


def _microsoft_signed(exe: str) -> bool:
    """A valid digital signature from Microsoft (Windows' own check, offline). Cached by path and
    modified time, so each program file is checked once."""
    try:
        st = os.stat(exe)
    except OSError:
        return False
    key = (os.path.normcase(exe), st.st_mtime_ns)
    with _sig_lock:
        hit = _sig_cache.get(key)
    if hit is not None:
        return hit
    try:
        from ..signing import check_signature
        from ..winpath import to_long
        sig = check_signature(to_long(exe))
        ok = bool(sig.valid and sig.signer.lower().startswith("microsoft"))
    except Exception:
        ok = False
    with _sig_lock:
        if len(_sig_cache) > 2000:
            _sig_cache.clear()
        _sig_cache[key] = ok
    return ok


def _real_places(name: str) -> list[str]:
    env = os.environ.get
    pf = env("ProgramFiles", r"C:\Program Files")
    pf86 = env("ProgramFiles(x86)", r"C:\Program Files (x86)")
    places = [env("SystemRoot", r"C:\Windows"),
              os.path.join(env("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform"),
              os.path.join(pf, "Windows Defender")]
    if name == "msedgewebview2.exe":
        for base in (pf86, pf):
            places += [os.path.join(base, "Microsoft", "EdgeWebView"), os.path.join(base, "Microsoft", "Edge")]
    return places


def _real_protected(p: psutil.Process, name: str) -> bool:
    """A NEVER_PAUSE name: is this the real program (its real place, or signed by Microsoft)?
    When Windows does not say where the program file is, it stays protected."""
    try:
        exe = p.exe() or ""
    except (psutil.Error, OSError):
        return True
    if not exe or not os.path.isabs(exe):
        return True
    if any(_under(exe, place) for place in _real_places(name)):
        return True
    return _microsoft_signed(exe)


def ref_of(pid: int) -> ProcRef | None:
    try:
        return ProcRef(pid, psutil.Process(pid).create_time())
    except psutil.Error:
        return None


def _proc(ref: ProcRef) -> psutil.Process:
    """The living process for `ref`, or ProcError(GONE) when it ended or the pid was reused."""
    try:
        p = psutil.Process(ref.pid)
        if abs(p.create_time() - ref.create_time) > 0.01:
            raise ProcError(GONE)
        return p
    except psutil.NoSuchProcess:
        raise ProcError(GONE) from None
    except psutil.AccessDenied:
        raise ProcError("Windows did not let TacoGuard look at that program.") from None


def is_alive(ref: ProcRef) -> bool:
    try:
        _proc(ref)
        return True
    except ProcError:
        return False


_my_user: list[str] = []


def _me() -> str:
    if not _my_user:
        try:
            _my_user.append(psutil.Process().username().lower())
        except psutil.Error:
            _my_user.append("")
    return _my_user[0]


def same_user(p: psutil.Process) -> bool:
    try:
        return bool(_me()) and p.username().lower() == _me()
    except psutil.Error:
        return False


def protected_reason(p: psutil.Process, own: set[int] | None = None) -> str | None:
    """Why this process must never be paused or ended by the guard, or None."""
    if p.pid in (0, 4):
        return "it is part of Windows"
    if p.pid in (own if own is not None else tacoguard_pids()):
        return "it is part of TacoGuard"
    try:
        name = p.name().lower()
    except psutil.Error:
        return "Windows did not say what it is"
    if name in NEVER_PAUSE and _real_protected(p, name):
        return "it is part of Windows or Microsoft Defender"
    try:
        exe = os.path.normcase(p.exe() or "")
    except psutil.Error:
        exe = ""
    if exe.startswith(_windows_dir()) and name not in MAY_PAUSE_IN_WINDOWS:
        return "it is part of Windows"
    if not same_user(p):
        return "it runs under another account (pausing it would need administrator rights)"
    return None


def _nt(func: str, ref: ProcRef) -> None:
    p = _proc(ref)
    ntdll = ctypes.WinDLL("ntdll")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    fn = getattr(ntdll, func)
    fn.argtypes = [wintypes.HANDLE]
    fn.restype = ctypes.c_long
    h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, p.pid)
    if not h:
        raise ProcError("Windows did not allow TacoGuard to do that to this program.")
    try:
        status = fn(h)
    finally:
        k32.CloseHandle(h)
    if status != 0:
        raise ProcError("Windows did not allow TacoGuard to do that to this program.")


def suspend(ref: ProcRef, own: set[int] | None = None) -> None:
    """Pause every thread of the program. Raises ProcError (protected, gone, refused)."""
    p = _proc(ref)
    why = protected_reason(p, own)
    if why:
        raise ProcError(f"TacoGuard does not pause this program: {why}.")
    if not pause_allowed(p.pid):
        raise ProcError("TacoGuard does not pause this program: a test setting limits which programs it may pause.")
    _nt("NtSuspendProcess", ref)


def resume(ref: ProcRef) -> None:
    """Let a paused program run again (no protection check: resuming is always allowed).
    A program paused twice (Windows counts pauses) needs a resume for each: this repeats until
    Windows no longer reports it paused (at most RESUME_TRIES times)."""
    _nt("NtResumeProcess", ref)
    for _ in range(RESUME_TRIES - 1):
        if not is_suspended(ref):
            return
        _nt("NtResumeProcess", ref)


def terminate(ref: ProcRef, own: set[int] | None = None, wait_s: float = 5.0) -> None:
    """End the program (only after the user chose it). A paused program is ended as it is."""
    p = _proc(ref)
    why = protected_reason(p, own)
    if why:
        raise ProcError(f"TacoGuard does not end this program: {why}.")
    try:
        p.kill()
        p.wait(timeout=wait_s)
    except psutil.NoSuchProcess:
        return
    except psutil.TimeoutExpired:
        raise ProcError("The program did not close within a few seconds.") from None
    except psutil.AccessDenied:
        raise ProcError("Windows did not allow TacoGuard to end this program.") from None


def is_suspended(ref: ProcRef) -> bool:
    """True when every thread of the program is paused (psutil reports 'stopped')."""
    try:
        return _proc(ref).status() == psutil.STATUS_STOPPED
    except (ProcError, psutil.Error):
        return False
