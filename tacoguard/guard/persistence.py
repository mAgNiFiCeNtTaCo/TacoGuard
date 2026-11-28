"""The start-up watch (the guard's "persistence" part): reports new or changed start-up entries.

Programs that want to start by themselves have a few places to sign up. This part reads them:
    Run / RunOnce keys (yours, all users, all users 32-bit), the Startup folders (yours, all users),
    Winlogon Shell / Userinit (only values that differ from Windows' defaults), Image File Execution
    Options "Debugger" values, AppInit_DLLs, services that start at boot or automatically, scheduled
    tasks (schtasks /query /xml ONE) and WMI event subscriptions (read once per start, when Windows
    lets a normal account read them).

How it notices changes, cheaply:
- registry keys: RegNotifyChangeKeyValue on every key, ONE thread waiting on all events at once
  (WaitForMultipleObjects) plus a stop and a wake event; a signal re-reads only that source after a
  1 s pause (services: at most every 10 s). A missing key is watched through its parent.
- Startup folders: the guard's folder hub (folders.WatchHub) when given, else re-read every 60 s.
- scheduled tasks: every 10 minutes, at below-normal priority (30 minutes when one run costs over 1 s
  of CPU time). Everything again every 6 hours as a safety net.

The first pass of a source is the baseline (rows in state "baseline", no events). After that a new
or changed entry gets state "new", its program file is checked (the guard's RealtimeChecker) and ONE
guard event is written (kind "persistence", data {"key": key}).

The page uses a PersistenceWatcher of its own (not started) for keep / undo / restore. Undo works
only for entries in YOUR account (your Run / RunOnce key, your Startup folder): the value or file is
backed up into the row's `backup` (+ settings.guard_dir/"startup-backup") and then removed.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import html
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import threading
import time
import winreg
import xml.etree.ElementTree as ET
from ctypes import wintypes

from .. import winpath
from ..model import MALWARE, SCANNED, SUSPICIOUS, explain, plain_error

log = logging.getLogger("tacoguard.guard")

HKCU = winreg.HKEY_CURRENT_USER
HKLM = winreg.HKEY_LOCAL_MACHINE
HIVE_NAMES = {HKCU: "HKCU", HKLM: "HKLM"}

_CV = r"Software\Microsoft\Windows\CurrentVersion"
_CV32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion"
_NT = r"Software\Microsoft\Windows NT\CurrentVersion"
_NT32 = r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion"

FOLDERID_STARTUP = "{B97D20BB-F46A-4C97-BA10-5E3608430854}"
FOLDERID_COMMON_STARTUP = "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}"

# source id -> (kind stored in the row's `source`, plain location, when it runs)
SOURCES = {
    "run:HKCU": ("run", "Your Run key", "every time you sign in"),
    "runonce:HKCU": ("runonce", "Your RunOnce key", "once, the next time you sign in"),
    "run:HKLM": ("run", "The all-users Run key", "every time anyone signs in"),
    "runonce:HKLM": ("runonce", "The all-users RunOnce key", "once, the next time anyone signs in"),
    "run:HKLM32": ("run", "The all-users Run key (32-bit programs)", "every time anyone signs in"),
    "runonce:HKLM32": ("runonce", "The all-users RunOnce key (32-bit programs)",
                       "once, the next time anyone signs in"),
    "startup:user": ("startup_folder", "Your Startup folder", "every time you sign in"),
    "startup:common": ("startup_folder", "The all-users Startup folder", "every time anyone signs in"),
    "winlogon:HKLM": ("winlogon", "Windows sign-in settings (Winlogon)", "as part of every sign-in"),
    "winlogon:HKCU": ("winlogon", "Your Windows sign-in settings (Winlogon)", "as part of your sign-in"),
    "ifeo:HKLM": ("ifeo", "Image File Execution Options", ""),
    "ifeo:HKLM32": ("ifeo", "Image File Execution Options (32-bit programs)", ""),
    "appinit:HKLM": ("appinit", "AppInit_DLLs", "inside most programs that show windows"),
    "appinit:HKLM32": ("appinit", "AppInit_DLLs (32-bit programs)", "inside most 32-bit programs that show windows"),
    "service": ("service", "Windows services", ""),
    "task": ("task", "Task Scheduler", "on the schedule set in Task Scheduler"),
    "wmi": ("wmi", "WMI event subscription", "when the Windows event it waits for happens"),
}
UNDOABLE = ("run:HKCU", "runonce:HKCU", "startup:user")
REG_KINDS = ("run", "runonce", "winlogon", "ifeo", "appinit", "service")
SUBTREE_KINDS = ("ifeo", "service")

WMI_DENIED_NOTE = "Checking WMI start-up hooks needs administrator rights, so TacoGuard skips them."
META_BASELINED = "persistence_baselined"

TASK_INTERVAL_S = 600.0
TASK_INTERVAL_SLOW_S = 1800.0
TASK_CPU_LIMIT_S = 1.0
FOLDER_POLL_S = 60.0
FULL_SCAN_S = 6 * 3600.0
DEBOUNCE_S = 1.0
MIN_INTERVAL_S = {"service": 10.0}
MAX_ITEMS = 20_000              # values / subkeys read from one key (a flooded key cannot hang us)
COMMAND_MAX = 2000              # characters kept of one command

_NO_UNDO = {
    "run": "Turning off a start-up entry for all users needs administrator rights. Open Task Manager > "
           "Startup apps to turn it off there.",
    "runonce": "Removing a start-up entry for all users needs administrator rights. Open Task Manager > "
               "Startup apps, or ask someone with an administrator account.",
    "startup_folder": "Turning off a start-up item for all users needs administrator rights. Open Task "
                      "Manager > Startup apps to turn it off there.",
    "task": "Scheduled tasks are changed in Task Scheduler: open it from the Start menu, find the task "
            "and choose Disable (most tasks need administrator rights).",
    "service": "Windows services are changed in the Services tool (services.msc), and turning one off "
               "needs administrator rights.",
    "winlogon": "This is a Windows sign-in setting; changing it needs administrator rights. If you did "
                "not set it up, ask someone you trust to look at it.",
    "ifeo": "This is a system-wide Windows setting; changing it needs administrator rights. If you did "
            "not set it up, ask someone you trust to look at it.",
    "appinit": "This is a system-wide Windows setting; changing it needs administrator rights. If you "
               "did not set it up, ask someone you trust to look at it.",
    "wmi": "WMI event subscriptions can only be removed with administrator rights.",
}

# ---- Windows calls ----------------------------------------------------------------------------
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateEventW.restype = wintypes.HANDLE
_k32.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
_k32.SetEvent.argtypes = (wintypes.HANDLE,)
_k32.CloseHandle.argtypes = (wintypes.HANDLE,)
_k32.WaitForMultipleObjects.restype = wintypes.DWORD
_k32.WaitForMultipleObjects.argtypes = (wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL,
                                        wintypes.DWORD)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_k32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
_k32.SetFileAttributesW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD)
_adv = ctypes.WinDLL("advapi32")
_adv.RegNotifyChangeKeyValue.restype = wintypes.LONG
_adv.RegNotifyChangeKeyValue.argtypes = (wintypes.HANDLE, wintypes.BOOL, wintypes.DWORD, wintypes.HANDLE,
                                         wintypes.BOOL)

REG_NOTIFY_CHANGE_NAME = 0x1
REG_NOTIFY_CHANGE_LAST_SET = 0x4
REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000
WAIT_TIMEOUT = 0x102
CREATE_NO_WINDOW = 0x08000000
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _view(hive) -> int:
    return winreg.KEY_WOW64_64KEY if hive == HKLM else 0


def _sysroot() -> str:
    return os.environ.get("SystemRoot") or r"C:\Windows"


def known_folder(guid: str) -> str | None:
    """Where a Windows known folder really is (it may have been moved), else None."""
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort), ("d3", ctypes.c_ushort),
                        ("d4", ctypes.c_ubyte * 8)]
        g = GUID()
        ole32 = ctypes.OleDLL("ole32")
        shell32 = ctypes.WinDLL("shell32")
        ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(g))
        out = ctypes.c_wchar_p()
        hr = shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out))
        value = out.value
        ctypes.WinDLL("ole32").CoTaskMemFree(out)
        return value if hr == 0 and value else None
    except Exception:
        return None


def default_roots() -> dict:
    """Where every source lives on this PC. Tests pass their own mapping (test keys, tmp folders)."""
    return {
        "run:HKCU": (HKCU, _CV + r"\Run"),
        "runonce:HKCU": (HKCU, _CV + r"\RunOnce"),
        "run:HKLM": (HKLM, _CV + r"\Run"),
        "runonce:HKLM": (HKLM, _CV + r"\RunOnce"),
        "run:HKLM32": (HKLM, _CV32 + r"\Run"),
        "runonce:HKLM32": (HKLM, _CV32 + r"\RunOnce"),
        "startup:user": known_folder(FOLDERID_STARTUP),
        "startup:common": known_folder(FOLDERID_COMMON_STARTUP),
        "winlogon:HKLM": (HKLM, _NT + r"\Winlogon"),
        "winlogon:HKCU": (HKCU, _NT + r"\Winlogon"),
        "ifeo:HKLM": (HKLM, _NT + r"\Image File Execution Options"),
        "ifeo:HKLM32": (HKLM, _NT32 + r"\Image File Execution Options"),
        "appinit:HKLM": (HKLM, _NT + r"\Windows"),
        "appinit:HKLM32": (HKLM, _NT32 + r"\Windows"),
        "service": (HKLM, r"SYSTEM\CurrentControlSet\Services"),
        "task": run_schtasks,
        "wmi": read_wmi,
    }


# ---- command lines -> the program they start --------------------------------------------------
_ENV = re.compile(r"%([^%\\/:*?\"<>|\r\n]+)%")


def expand_env(s: str) -> str:
    """%SystemRoot%-style variables (unknown ones stay as written). No $VAR expansion."""
    return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(0)), s)


def _native_fix(p: str) -> str:
    """Driver / NT path forms used by services: \\SystemRoot\\..., \\??\\C:\\..., System32\\..."""
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        return _sysroot() + p[len("\\systemroot"):]
    if low.startswith("systemroot\\"):
        return _sysroot() + p[len("systemroot"):]
    if low.startswith("\\??\\") or low.startswith("\\\\?\\"):
        return p[4:]
    if low.startswith("system32\\") or low.startswith("syswow64\\"):
        return os.path.join(_sysroot(), p)
    return p


def _tokens(s: str) -> list[str]:
    """Split arguments the way Windows does for ordinary cases: quotes group, and a quoted part
    joins the text right next to it ("x.dll",Entry -> x.dll,Entry)."""
    out, cur, quoted, started = [], [], False, False
    for ch in s:
        if ch == '"':
            quoted = not quoted
            started = True
        elif ch in " \t" and not quoted:
            if started:
                out.append("".join(cur))
                cur, started = [], False
        else:
            cur.append(ch)
            started = True
    if started:
        out.append("".join(cur))
    return out


def _search_dirs() -> list[str]:
    """Where Windows looks for a bare program name: its own folders, then PATH (absolute
    entries only; never the current folder)."""
    root = _sysroot()
    dirs = [os.path.join(root, "System32"), root, os.path.join(root, "SysWOW64")]
    for d in os.environ.get("PATH", "").split(";")[:64]:
        d = d.strip().strip('"')
        if d and os.path.isabs(d) and d not in dirs:
            dirs.append(d)
    return dirs


def _find_file(p: str, exts: tuple[str, ...] = (".exe",)) -> str | None:
    """The existing file a command names (absolute, or a bare name in Windows' own folders)."""
    p = p.strip().strip('"').strip()
    if not p or len(p) > 1000 or any(c in p for c in '<>|*?\r\n'):
        return None
    names = [p]
    if not os.path.splitext(p)[1]:
        names += [p + e for e in exts]
    has_dir = ("\\" in p) or ("/" in p) or (len(p) > 1 and p[1] == ":")
    if has_dir:
        cands = [n for n in names if os.path.isabs(n)]
    else:
        cands = [os.path.join(d, n) for d in _search_dirs() for n in names]
    for c in cands:
        try:
            if os.path.isfile(winpath.to_long(c)):
                return winpath.to_display(os.path.normpath(c))
        except (OSError, ValueError):
            continue
    return None


def split_command(command: str) -> tuple[str, list[str]]:
    """(program, arguments) of a command line. Quoted program paths, unquoted ones with spaces
    (longest existing prefix wins, as Windows does), %VARS% and driver path forms are handled."""
    s = _native_fix(expand_env((command or "").strip()))
    if not s:
        return "", []
    if s.startswith('"'):
        end = s.find('"', 1)
        prog = s[1:end] if end > 0 else s[1:]
        rest = s[end + 1:] if end > 0 else ""
        return prog.strip(), _tokens(rest)
    parts = s.split(" ")
    prog, rest = parts[0], parts[1:]
    if len(parts) > 1 and ("\\" in parts[0] or ":" in parts[0]):
        for i in range(len(parts), 0, -1):          # longest existing prefix first
            cand = " ".join(parts[:i])
            if _find_file(cand):
                prog, rest = cand, parts[i:]
                break
    return prog, _tokens(" ".join(rest))


def _first_plain_arg(args: list[str]) -> str:
    for a in args:
        if a and a[0] not in "/-":
            return a
    return ""


def resolve_target(command: str) -> str:
    """Display path of the program (or script / DLL) a command starts, or "" when not found."""
    try:
        prog, args = split_command(command)
        exe = _find_file(prog) if prog else None
        if not exe:
            return ""
        base = os.path.basename(exe).lower()
        inner = ""
        if base in ("rundll32.exe", "regsvr32.exe"):
            a = _first_plain_arg(args)
            inner = a.split(",", 1)[0]
            found = _find_file(inner, (".dll",)) if inner else None
            return found or exe
        if base in ("wscript.exe", "cscript.exe", "mshta.exe"):
            inner = _first_plain_arg(args)
        elif base in ("powershell.exe", "pwsh.exe"):
            for i, a in enumerate(args[:-1]):
                if a.lower() in ("-file", "-f", "/file"):
                    inner = args[i + 1]
                    break
        elif base == "cmd.exe":
            for i, a in enumerate(args[:-1]):
                if a.lower() in ("/c", "/k", "/r"):
                    inner = args[i + 1]
                    break
        if inner:
            found = _find_file(expand_env(inner), ())
            if found:
                return found
        return exe
    except Exception:
        return ""


# ---- Windows shortcuts (.lnk), read without COM ---------------------------------------------------
def _astr(data: bytes, off: int) -> str:
    end = data.index(b"\x00", off)
    return data[off:end].decode("mbcs", errors="replace")


def _wstr(data: bytes, off: int) -> str:
    end = off
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[off:end].decode("utf-16-le", errors="replace")


def parse_lnk(data: bytes) -> dict | None:
    """The useful fields of a shell link (MS-SHLLINK): {"target", "relative", "args", "workdir"}.
    Target comes from LinkInfo (local base path + suffix) or the environment-variable block.
    None when the file is not a shortcut. A shortcut that names its target only through a shell
    item list (Store apps, some special folders) gives target ""."""
    try:
        if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
            return None
        flags = struct.unpack_from("<I", data, 0x14)[0]
        pos = 0x4C
        if flags & 0x1:                              # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        target = ""
        if flags & 0x2:                              # HasLinkInfo
            li = pos
            li_size, hdr, li_flags, _vol, lbp, _cnr, cps = struct.unpack_from("<7I", data, li)
            lbp_u = cps_u = 0
            if hdr >= 0x24:
                lbp_u, cps_u = struct.unpack_from("<2I", data, li + 28)
            if li_flags & 0x1 and not flags & 0x100:  # VolumeIDAndLocalBasePath, not ForceNoLinkInfo
                base = _wstr(data, li + lbp_u) if lbp_u else _astr(data, li + lbp)
                suffix = _wstr(data, li + cps_u) if cps_u else (_astr(data, li + cps) if cps else "")
                target = base + suffix
            pos = li + li_size
        uni = bool(flags & 0x80)
        strings = {}
        for bit, name in ((0x4, "name"), (0x8, "relative"), (0x10, "workdir"), (0x20, "args"),
                          (0x40, "icon")):
            if flags & bit:
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                ln = n * 2 if uni else n
                raw = data[pos:pos + ln]
                pos += ln
                strings[name] = raw.decode("utf-16-le" if uni else "mbcs", errors="replace")
        if flags & 0x200 and not target:             # HasExpString: EnvironmentVariableDataBlock
            while pos + 8 <= len(data):
                size, sig = struct.unpack_from("<2I", data, pos)
                if size < 8:
                    break
                if sig == 0xA0000001 and size >= 0x314:
                    t = _wstr(data, pos + 8 + 260) or _astr(data, pos + 8)
                    target = expand_env(t)
                    break
                pos += size
        return {"target": target, "relative": strings.get("relative", ""), "args": strings.get("args", ""),
                "workdir": strings.get("workdir", "")}
    except (struct.error, ValueError, IndexError):
        return None


_PS_LNK = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
           "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:TACOGUARD_LNK);"
           "ConvertTo-Json -Compress @{target=$s.TargetPath;args=$s.Arguments}")


def _powershell(script: str, env_extra: dict | None = None, timeout: float = 30.0) -> str | None:
    """Run a short PowerShell script (no window, below-normal priority); its output, or None."""
    exe = os.path.join(_sysroot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-EncodedCommand", enc], capture_output=True, timeout=timeout, env=env,
                           stdin=subprocess.DEVNULL,
                           creationflags=CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", errors="replace").strip()


def lnk_via_shell(path: str) -> dict | None:
    """Ask Windows (WScript.Shell, through PowerShell) for a shortcut's target. Only used for a
    new shortcut the quick reader could not follow."""
    out = _powershell(_PS_LNK, {"TACOGUARD_LNK": winpath.to_display(path)})
    try:
        d = json.loads(out) if out else None
        return {"target": d.get("target") or "", "args": d.get("args") or ""} if isinstance(d, dict) else None
    except ValueError:
        return None


# ---- scheduled tasks ----------------------------------------------------------------------------
def _cpu_of(h) -> float:
    c, e, k, u = (wintypes.FILETIME() for _ in range(4))
    if not _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
        return 0.0
    val = lambda ft: (ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 1e7   # noqa: E731
    return val(k) + val(u)


def run_schtasks(timeout: float = 60.0) -> tuple[str, float] | None:
    """`schtasks /query /xml ONE` (every task this account can see, one XML document) at below-
    normal priority without a window. (text, CPU seconds the child used) or None."""
    exe = os.path.join(_sysroot(), "System32", "schtasks.exe")
    try:
        p = subprocess.Popen([exe, "/query", "/xml", "ONE"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS)
    except OSError:
        return None
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, p.pid)
    try:
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            return None
        cpu = _cpu_of(h) if h else 0.0
    finally:
        if h:
            _k32.CloseHandle(h)
    if p.returncode != 0 or not out:
        return None
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        text = out.decode("mbcs", errors="replace")
    return text, cpu


_TASK_HDR = re.compile(r"<!--\s*(\\[^\r\n]*?)\s*-->")
_TASK_OPEN = re.compile(r"<Task[\s>]")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_task(path: str, body: str) -> dict:
    task = {"path": path, "enabled": True, "exec": [], "com": []}
    if "<!DOCTYPE" not in body and "<!ENTITY" not in body:
        try:
            root = ET.fromstring(body)
            en = root.find("{*}Settings/{*}Enabled")
            if en is not None and (en.text or "").strip().lower() == "false":
                task["enabled"] = False
            actions = root.find("{*}Actions")
            for a in (list(actions) if actions is not None else []):
                kids = {_local(c.tag): (c.text or "").strip() for c in a}
                if _local(a.tag) == "Exec" and kids.get("Command"):
                    task["exec"].append((kids["Command"], kids.get("Arguments", "")))
                elif _local(a.tag) == "ComHandler" and kids.get("ClassId"):
                    task["com"].append((kids["ClassId"], kids.get("Data", "")))
            return task
        except ET.ParseError:
            pass
    # a task document Python's parser refused: read the few fields we need directly
    un = lambda s: html.unescape(s).strip()   # noqa: E731
    m = re.search(r"<Settings>.*?<Enabled>\s*(\w+)\s*</Enabled>", body, re.S)
    task["enabled"] = not (m and m.group(1).lower() == "false")
    for ex in re.findall(r"<Exec>(.*?)</Exec>", body, re.S):
        c = re.search(r"<Command>(.*?)</Command>", ex, re.S)
        a = re.search(r"<Arguments>(.*?)</Arguments>", ex, re.S)
        if c and un(c.group(1)):
            task["exec"].append((un(c.group(1)), un(a.group(1)) if a else ""))
    for ch in re.findall(r"<ComHandler>(.*?)</ComHandler>", body, re.S):
        c = re.search(r"<ClassId>(.*?)</ClassId>", ch, re.S)
        if c:
            task["com"].append((un(c.group(1)), ""))
    return task


def parse_tasks_xml(text: str) -> list[dict]:
    """Tasks in `schtasks /query /xml ONE` output: [{"path", "enabled", "exec": [(command, args)],
    "com": [(class id, data)]}]. Each task follows a comment holding its path."""
    out = []
    marks = list(_TASK_HDR.finditer(text or ""))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        chunk = text[m.end():end]
        s = _TASK_OPEN.search(chunk)
        e = chunk.rfind("</Task>")
        if not s or e < 0:
            continue
        out.append(_parse_task(m.group(1).strip(), chunk[s.start():e + len("</Task>")]))
    return out


def _com_dll(clsid: str) -> str:
    """The file a COM class id runs, display path or "": its DLL (HKCR\\CLSID\\{x}\\InprocServer32),
    else its program (LocalServer32), else the program of a Windows app package that registered it
    (packaged COM, as Windows' own SoftLanding / ActionCenter tasks use)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\InprocServer32") as k:
            val = winreg.QueryValueEx(k, "")[0]
        found = _find_file(_native_fix(expand_env(str(val))), (".dll",))
        if found:
            return found
    except (OSError, TypeError):
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\LocalServer32") as k:
            val = winreg.QueryValueEx(k, "")[0]
        found = resolve_target(str(val)) if isinstance(val, str) and val.strip() else ""
        if found:
            return found
    except (OSError, TypeError):
        pass
    return _packaged_com_exe(clsid)


_PKG_COM = r"SOFTWARE\Classes\PackagedCom"
_CLSID_RX = re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")


def package_path(full_name: str) -> str:
    """Where Windows installed an app package (GetPackagePathByFullName), or "" when it isn't
    installed. Windows' own answer: never the user-writable copies of package settings."""
    if os.name != "nt" or not full_name or len(full_name) > 200:
        return ""
    try:
        fn = ctypes.WinDLL("kernel32", use_last_error=True).GetPackagePathByFullName
        fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
        fn.restype = wintypes.LONG
        n = wintypes.UINT(0)
        if fn(full_name, ctypes.byref(n), None) not in (0, 122) or not 0 < n.value < 4096:
            return ""
        buf = ctypes.create_unicode_buffer(n.value)
        return buf.value if fn(full_name, ctypes.byref(n), buf) == 0 else ""
    except (OSError, AttributeError, ValueError):
        return ""


def _packaged_com_exe(clsid: str) -> str:
    """The program of a packaged COM class: read from the all-users registry only (an ordinary
    program can't write there), inside the folder Windows says the package is installed in."""
    if not _CLSID_RX.fullmatch(clsid or ""):
        return ""
    hk = winreg.HKEY_LOCAL_MACHINE
    try:
        with winreg.OpenKey(hk, rf"{_PKG_COM}\ClassIndex\{clsid}", 0, winreg.KEY_READ | _view(hk)) as k:
            packages = _subkeys(k)[:50]
    except OSError:
        return ""
    for pkg in reversed(packages):          # newest version last in the list: try it first
        root = package_path(pkg)
        if not root:
            continue
        try:
            with winreg.OpenKey(hk, rf"{_PKG_COM}\Package\{pkg}\Class\{clsid}", 0,
                                winreg.KEY_READ | _view(hk)) as k:
                server = _query(k, "ServerId")
            if not isinstance(server, int):
                continue
            with winreg.OpenKey(hk, rf"{_PKG_COM}\Package\{pkg}\Server\{server}", 0,
                                winreg.KEY_READ | _view(hk)) as k:
                exe = _query(k, "Executable")
        except OSError:
            continue
        if not isinstance(exe, str) or not exe.strip() or os.path.isabs(exe) or ":" in exe:
            continue
        path = os.path.normpath(os.path.join(root, exe.strip()))
        if winpath.is_under(path, root) and os.path.isfile(winpath.to_long(path)):
            return path
    return ""


# ---- WMI event subscriptions ------------------------------------------------------------------------
class WmiDenied(Exception):
    """Windows did not let this account read root\\subscription."""


_PS_WMI = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
try {
  $c=@(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { @{name=[string]$_.Name; cmd=[string]$_.CommandLineTemplate; exe=[string]$_.ExecutablePath} })
  $s=@(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { $t=[string]$_.ScriptText; if ($t.Length -gt 300) { $t=$t.Substring(0,300) }; @{name=[string]$_.Name; file=[string]$_.ScriptFileName; engine=[string]$_.ScriptingEngine; text=$t} })
  ConvertTo-Json -Compress -Depth 4 @{ok=1; cmd=$c; script=$s}
} catch {
  $d = ($_.Exception.HResult -eq -2147024891) -or ($_.CategoryInfo.Category.ToString() -eq 'PermissionDenied') -or ("$($_.Exception.Message)" -match 'denied')
  ConvertTo-Json -Compress @{ok=0; denied=[bool]$d}
}
"""


def read_wmi() -> list[dict] | None:
    """WMI consumers that run something: [{"class", "name", "command"}]. Raises WmiDenied when
    Windows refuses; None when PowerShell could not answer."""
    out = _powershell(_PS_WMI, timeout=45.0)
    try:
        d = json.loads(out) if out else None
    except ValueError:
        d = None
    if not isinstance(d, dict):
        return None
    if not d.get("ok"):
        if d.get("denied"):
            raise WmiDenied()
        return None
    items = []
    for c in d.get("cmd") or []:
        cmd = (c.get("cmd") or c.get("exe") or "").strip()
        items.append({"class": "CommandLineEventConsumer", "name": c.get("name") or "", "command": cmd})
    for s in d.get("script") or []:
        cmd = (s.get("file") or "").strip() or f"{s.get('engine') or 'script'}: {(s.get('text') or '').strip()}"
        items.append({"class": "ActiveScriptEventConsumer", "name": s.get("name") or "", "command": cmd})
    return items


# ---- reading the sources ----------------------------------------------------------------------------
class _Read:
    """One source's entries this pass. `unknown`: keys that could not be read (never 'removed').
    `dormant`: keys there but not starting by themselves right now (never 'removed' either)."""

    def __init__(self, entries: list[dict], unknown: set[str] | None = None,
                 dormant: set[str] | None = None):
        self.entries = entries
        self.unknown = unknown or set()
        self.dormant = dormant or set()


def _values(hive, path) -> list[tuple] | None:
    """[(name, data, type)] of a key; [] when it does not exist; None when it cannot be read."""
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _view(hive))
    except FileNotFoundError:
        return []
    except OSError:
        return None
    out = []
    with k:
        for i in range(MAX_ITEMS):
            try:
                out.append(winreg.EnumValue(k, i))
            except OSError:
                break
    return out


def _subkeys(k) -> list[str]:
    out = []
    for i in range(MAX_ITEMS):
        try:
            out.append(winreg.EnumKey(k, i))
        except OSError:
            break
    return out


def _query(k, name: str):
    try:
        return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _clip(s: str) -> str:
    s = str(s).replace("\r", " ").replace("\n", " ").replace("\x00", " ").strip()
    return s[:COMMAND_MAX]


def _entry(sid: str, item: str, name: str, command: str, location: str = "", **extra) -> dict:
    kind, where, _ = SOURCES[sid]
    e = {"key": f"{sid}:{item}", "source": kind, "location": location or where, "name": name,
         "command": _clip(command), "target": None, "sid": sid}
    e.update(extra)
    return e


def _read_run(sid, spec) -> _Read | None:
    vals = _values(*spec)
    if vals is None:
        return None
    out = []
    for name, data, typ in vals:
        if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(data, str) and data.strip():
            out.append(_entry(sid, name, name or "(Default)", data))
    return _Read(out)


_WINLOGON = ("Shell", "Userinit")


def _winlogon_default(name: str, value: str) -> bool:
    v = expand_env(value).strip().rstrip(",").strip().lower()
    root = _sysroot().lower()
    if name.lower() == "shell":
        return v in ("explorer.exe", root + "\\explorer.exe")
    return v in (root + "\\system32\\userinit.exe", "userinit.exe", "userinit")


def _read_winlogon(sid, spec) -> _Read | None:
    vals = _values(*spec)
    if vals is None:
        return None
    out = []
    for name, data, typ in vals:
        if name.lower() not in ("shell", "userinit") or not isinstance(data, str) or not data.strip():
            continue
        if _winlogon_default(name, data):
            continue
        # the first program in the list that is not Windows' own
        parts = [p.strip() for p in data.split(",") if p.strip()]
        odd = [p for p in parts if not _winlogon_default(name, p)] or parts
        out.append(_entry(sid, name.capitalize(), name.capitalize(), data, resolve=odd[0]))
    return _Read(out)


def _read_ifeo(sid, spec) -> _Read | None:
    hive, path = spec
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _view(hive))
    except FileNotFoundError:
        return _Read([])
    except OSError:
        return None
    out, unknown = [], set()
    with k:
        for sub in _subkeys(k):
            try:
                with winreg.OpenKey(k, sub) as sk:
                    dbg = _query(sk, "Debugger")
            except OSError:
                unknown.add(f"{sid}:{sub}")
                continue
            if isinstance(dbg, str) and dbg.strip():
                loc = f"{SOURCES[sid][1]}: the debugger for {sub}"
                out.append(_entry(sid, sub, sub, dbg, location=loc))
    return _Read(out, unknown)


def _read_appinit(sid, spec) -> _Read | None:
    hive, path = spec
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _view(hive)) as k:
            val = _query(k, "AppInit_DLLs")
    except FileNotFoundError:
        return _Read([])
    except OSError:
        return None
    if not isinstance(val, str) or not val.strip(" \x00"):
        return _Read([])
    # Windows splits the list at commas and spaces; a whole path with spaces is tried first
    v = val.strip(" \x00")
    cands = [v.split(",")[0].strip().strip('"'), re.split(r"[,\s]+", v)[0].strip('"')]
    first = next((c for c in cands if _find_file(c, (".dll",))), cands[-1])
    return _Read([_entry(sid, "AppInit_DLLs", "AppInit_DLLs", val, dll=first, resolve="")])


_SERVICE_WHEN = {0: "when Windows starts (a boot driver)", 1: "when Windows starts (a system driver)",
                 2: "automatically when Windows starts"}


def _read_services(sid, spec) -> _Read | None:
    hive, path = spec
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _view(hive))
    except FileNotFoundError:
        return _Read([])
    except OSError:
        return None
    out, unknown, dormant = [], set(), set()
    with k:
        for name in _subkeys(k):
            try:
                with winreg.OpenKey(k, name) as sk:
                    image = _query(sk, "ImagePath")
                    start = _query(sk, "Start")
                    if not isinstance(image, str) or not image.strip():
                        continue
                    if start == 3:
                        # "start when needed": Windows flips some services (BITS) between this and
                        # automatic by itself. Not a start-up entry, but not "removed" either, so
                        # flipping back is not reported as new again.
                        dormant.add(f"{sid}:{name}")
                        continue
                    if start not in (0, 1, 2):
                        continue
                    dll = _query(sk, "ServiceDll")
                    if not dll:
                        try:
                            with winreg.OpenKey(sk, "Parameters") as pk:
                                dll = _query(pk, "ServiceDll")
                        except OSError:
                            dll = None
            except OSError:
                unknown.add(f"{sid}:{name}")
                continue
            command, extra = image, {}
            if isinstance(dll, str) and dll.strip():
                command = f"{image}  (loads {dll})"
                extra["dll"] = dll.strip()
            out.append(_entry(sid, name, name, command, location=f"Windows services: {name}",
                              resolve=image, when=_SERVICE_WHEN[start], **extra))
    return _Read(out, unknown, dormant)


def _read_tasks(runner) -> tuple[_Read | None, float]:
    """(entries, CPU seconds this pass cost: the child's + parsing)."""
    t0 = time.thread_time()
    got = runner()
    if got is None:
        return None, time.thread_time() - t0
    text, child_cpu = (got, 0.0) if isinstance(got, str) else got
    if not isinstance(text, str) or "<Tasks" not in text:
        return None, time.thread_time() - t0          # no answer is not "every task was removed"
    out = []
    for t in parse_tasks_xml(text):
        if not t["enabled"] or not (t["exec"] or t["com"]):
            continue
        parts = [f"{c} {a}".strip() for c, a in t["exec"]] + [f"COM handler {c}" for c, _ in t["com"]]
        name = t["path"].rsplit("\\", 1)[-1] or t["path"]
        extra = {}
        if t["exec"]:
            c, a = t["exec"][0]
            extra["resolve"] = (c if c.startswith('"') else f'"{c}"') + (f" {a}" if a else "")
        else:
            extra["clsid"] = t["com"][0][0]
        out.append(_entry("task", t["path"], name, " ; ".join(parts), location=f"Task Scheduler: {t['path']}",
                          **extra))
    return _Read(out), child_cpu + (time.thread_time() - t0)


def _read_wmi(runner) -> _Read | None:
    items = runner()      # may raise WmiDenied
    if items is None:
        return None
    out = []
    for it in items:
        item = f"{it.get('class', '')}:{it.get('name', '')}"
        out.append(_entry("wmi", item, it.get("name") or "(no name)", it.get("command") or "",
                          location=f"WMI event subscription ({it.get('class', '')})"))
    return _Read(out)


# ---- the part -----------------------------------------------------------------------------------------
class _Watch:
    """One registry key watched with RegNotifyChangeKeyValue (async, its own auto-reset event).
    A key that does not exist yet is watched through its nearest existing parent."""

    def __init__(self, sid: str, hive, path: str, subtree: bool):
        self.sid, self.hive, self.path, self.subtree = sid, hive, path, subtree
        self.event = _k32.CreateEventW(None, False, False, None)
        self.key = None
        self.parent = False
        self.armed = False

    def _open(self) -> None:
        self.close_key()
        try:
            self.key = winreg.OpenKey(self.hive, self.path, 0, winreg.KEY_NOTIFY | _view(self.hive))
            self.parent = False
            return
        except OSError:
            pass
        p = self.path
        while "\\" in p:
            p = p.rsplit("\\", 1)[0]
            try:
                self.key = winreg.OpenKey(self.hive, p, 0, winreg.KEY_NOTIFY | _view(self.hive))
                self.parent = True
                return
            except OSError:
                continue

    def arm(self) -> bool:
        for _ in range(2):
            if self.key is None or self.parent:
                self._open()
            if self.key is None:
                break
            filt = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC
            if not self.parent:
                filt |= REG_NOTIFY_CHANGE_LAST_SET
            rc = _adv.RegNotifyChangeKeyValue(int(self.key), bool(self.subtree and not self.parent), filt,
                                              self.event, True)
            if rc == 0:
                self.armed = True
                return True
            self.close_key()          # deleted while watched: open it (or its parent) again
        self.armed = False
        return False

    def close_key(self) -> None:
        if self.key is not None:
            try:
                self.key.Close()
            except OSError:
                pass
        self.key = None

    def close(self) -> None:
        self.close_key()
        if self.event:
            _k32.CloseHandle(self.event)
            self.event = None


def _meta_get(store, key: str) -> str | None:
    # store.py has no meta helpers yet; the table exists (contract: guard_state lives there too)
    fn = getattr(store, "get_meta", None)
    if callable(fn):
        return fn(key)
    row = store._one("SELECT value FROM meta WHERE key=?", (key,))
    return row["value"] if row else None


def _meta_set(store, key: str, value: str) -> None:
    fn = getattr(store, "set_meta", None)
    if callable(fn):
        fn(key, value)
        return
    store._con().execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))


def _table_fingerprint(store) -> tuple:
    """(rows, newest last_seen) of the persistence table: changes whenever any row is written
    (put_persistence stamps last_seen), by this process or the page."""
    fn = getattr(store, "persistence_fingerprint", None)
    if callable(fn):
        return tuple(fn())
    row = store._one("SELECT COUNT(*) AS n, COALESCE(MAX(last_seen), 0) AS t FROM persistence")
    return (row["n"], row["t"]) if row else (0, 0)


def _sha256_file(long_path: str) -> str:
    h = hashlib.sha256()
    with open(long_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _enc_value(data, typ) -> dict:
    if isinstance(data, bytes):
        return {"b64": base64.b64encode(data).decode("ascii")}
    if data is None:
        return {"none": True}
    return {"v": data}


def _dec_value(d: dict):
    if "b64" in d:
        return base64.b64decode(d["b64"])
    if d.get("none"):
        return None
    return d.get("v")


class PersistenceWatcher:
    """The "persistence" part. `roots` maps source ids (SOURCES) to where they live:
    (hive, key path) for registry sources, a folder path for the Startup folders, a callable for
    "task" (returns schtasks XML text, or (text, child CPU seconds)) and "wmi" (list of consumers,
    raises WmiDenied). Only the sources in `roots` are read; None = this PC's real places."""

    def __init__(self, settings, store, checker=None, hub=None, roots: dict | None = None,
                 task_interval_s: float = TASK_INTERVAL_S, folder_poll_s: float = FOLDER_POLL_S,
                 full_scan_s: float = FULL_SCAN_S, debounce_s: float = DEBOUNCE_S):
        self.settings = settings
        self.store = store
        self.checker = checker
        self.hub = hub
        self.roots = default_roots() if roots is None else dict(roots)
        self.task_interval_s = task_interval_s
        self.folder_poll_s = folder_poll_s
        self.full_scan_s = full_scan_s
        self.debounce_s = debounce_s
        self.task_cpu_s = 0.0
        self.wmi_denied = False
        self._lock = threading.RLock()
        self._seen: dict[str, dict[str, str]] = {}       # sid -> {key: command} at the last pass
        self._fp: tuple | None = None                    # the table's fingerprint after that pass
        self._counts: dict[str, int] = {}                # sid -> entries at its last good read
        self._lnk_cache: dict[tuple, dict | None] = {}   # (path, size, mtime) -> parsed shortcut
        self._state = "off"
        self._message = "The start-up watch is off."
        self._notes: dict[str, str] = {}
        self._checked = 0
        self._thread: threading.Thread | None = None
        self._stop_ev = None
        self._wake_ev = None
        self._pending: set[str] = set()
        self._hub_tokens: list = []

    # ---- life cycle -----------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_ev = _k32.CreateEventW(None, True, False, None)
            self._wake_ev = _k32.CreateEventW(None, False, False, None)
            self._state, self._message = "starting", "Reading the start-up entries..."
            self._thread = threading.Thread(target=self._run, name="tacoguard-persistence", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        t = self._thread
        if self._stop_ev:
            _k32.SetEvent(self._stop_ev)
        if t:
            t.join(timeout=10)
        for tok in self._hub_tokens:
            try:
                self.hub.unsubscribe(tok)
            except Exception:
                pass
        self._hub_tokens = []
        if t is None or not t.is_alive():
            for attr in ("_stop_ev", "_wake_ev"):
                h = getattr(self, attr)
                if h:
                    _k32.CloseHandle(h)
                    setattr(self, attr, None)
            self._thread = None
        with self._lock:
            self._state, self._message = "off", "The start-up watch is off."

    def status(self) -> dict:
        with self._lock:
            msg = self._message
            notes = [n for n in self._notes.values() if n]
            if notes:
                msg = (msg + " " + " ".join(notes)).strip()
            return {"state": self._state, "message": msg, "watched": [], "checked": self._checked}

    # ---- passes ---------------------------------------------------------------------------
    def scan_now(self) -> list[str]:
        """One full pass over every source; the keys of entries that are new or changed."""
        return self._pass(list(self.roots), full=True)

    def _pass(self, sids: list[str], full: bool = False) -> list[str]:
        new: list[str] = []
        with self._lock:
            # the in-memory copy is trusted only while nobody else (the page: keep / undo /
            # restore) changed the table since this watcher's last pass
            trust = self._fp is not None and _table_fingerprint(self.store) == self._fp
            if not trust:
                self._seen.clear()
            by_sid: dict[str, dict[str, dict]] | None = None     # loaded only when something changed
            baselined: set[str] = set()
            changed_marker = False
            for sid in sids:
                if sid not in self.roots or sid not in SOURCES:
                    continue
                try:
                    res = self._read(sid, full)
                except Exception:
                    log.exception("start-up watch: reading %s failed", sid)
                    res = None
                if res is None:
                    continue
                cur = {e["key"]: e["command"] for e in res.entries}
                self._counts[sid] = len(cur)
                if not res.unknown and sid in self._seen and self._seen[sid] == cur:
                    continue
                if by_sid is None:
                    by_sid = {}
                    for r in self.store.list_persistence():
                        s = self.sid_of(r["key"])
                        if s:
                            by_sid.setdefault(s, {})[r["key"]] = r
                    try:
                        baselined = set(json.loads(_meta_get(self.store, META_BASELINED) or "[]"))
                    except (ValueError, TypeError):
                        baselined = set()
                srows = by_sid.get(sid, {})
                # a source's first pass is its baseline (the marker remembers sources with no entries)
                baseline = sid not in baselined and not srows
                try:
                    new += self._apply(sid, res, srows, baseline)
                except Exception:
                    log.exception("start-up watch: updating %s failed", sid)
                    continue
                self._seen[sid] = cur
                if sid not in baselined:
                    baselined.add(sid)
                    changed_marker = True
            if changed_marker:
                _meta_set(self.store, META_BASELINED, json.dumps(sorted(baselined)))
            self._fp = _table_fingerprint(self.store)
            total = sum(self._counts.values())
            self._checked = total
            places = len(self._counts)
            self._message = (f"Watching {total:,} start-up entries in {places} places. New ones are "
                             "reported here.")
        return new

    def _read(self, sid: str, full: bool) -> _Read | None:
        spec = self.roots[sid]
        kind = SOURCES[sid][0]
        if kind in ("run", "runonce"):
            return _read_run(sid, spec)
        if kind == "winlogon":
            return _read_winlogon(sid, spec)
        if kind == "ifeo":
            return _read_ifeo(sid, spec)
        if kind == "appinit":
            return _read_appinit(sid, spec)
        if kind == "service":
            return _read_services(sid, spec)
        if kind == "startup_folder":
            return self._read_startup(sid, spec)
        if kind == "task":
            res, cpu = _read_tasks(spec)
            if res is not None:
                self.task_cpu_s = cpu
                if cpu > TASK_CPU_LIMIT_S and self.task_interval_s < TASK_INTERVAL_SLOW_S:
                    self.task_interval_s = TASK_INTERVAL_SLOW_S
                self._notes.pop("task", None)
            else:
                self._notes["task"] = "The scheduled task list could not be read this time."
            return res
        if kind == "wmi":
            if self.wmi_denied or not full:        # once per start (and with the 6-hourly pass)
                return None
            try:
                res = _read_wmi(spec)
                self._notes.pop("wmi", None)
                return res
            except WmiDenied:
                self.wmi_denied = True
                self._notes["wmi"] = WMI_DENIED_NOTE
                return None
        return None

    def _read_startup(self, sid: str, folder) -> _Read | None:
        if not folder:
            return _Read([])
        try:
            items = list(os.scandir(winpath.to_long(folder)))
        except FileNotFoundError:
            return _Read([])
        except OSError:
            return None
        out = []
        for de in items[:MAX_ITEMS]:
            name = de.name
            if name.lower() == "desktop.ini":
                continue
            try:
                st = de.stat(follow_symlinks=False)
                if de.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            display = winpath.to_display(os.path.join(folder, name))
            if winpath.is_reparse(st):
                out.append(_entry(sid, name, name, display, target_fixed=""))
                continue
            if name.lower().endswith(".lnk"):
                info = self._shortcut(display, st)
                tgt = (info or {}).get("target", "")
                args = (info or {}).get("args", "")
                command = (f'"{tgt}" {args}'.strip() if tgt else f"{display} (a shortcut TacoGuard could not follow)")
                out.append(_entry(sid, name, name[:-4], command, resolve=command if tgt else ""))
            else:
                out.append(_entry(sid, name, name, display, target_fixed=display))
        return _Read(out)

    def _shortcut(self, display: str, st) -> dict | None:
        ck = (winpath.norm_key(display), st.st_size, st.st_mtime_ns)
        if ck in self._lnk_cache:
            return self._lnk_cache[ck]
        info = None
        if st.st_size <= 1 << 20:
            try:
                with open(winpath.to_long(display), "rb") as f:
                    info = parse_lnk(f.read())
            except OSError:
                info = None
        if info is not None and not info["target"] and info.get("relative"):
            info["target"] = os.path.normpath(os.path.join(os.path.dirname(display), info["relative"]))
        if info is not None and info["target"]:
            info["target"] = expand_env(info["target"])
        if info is None or not info["target"]:
            info = lnk_via_shell(display) or info     # once per new shortcut (cached below)
        self._lnk_cache[ck] = info
        if len(self._lnk_cache) > 500:
            self._lnk_cache.pop(next(iter(self._lnk_cache)))
        return info

    def _target(self, e: dict) -> str:
        if "target_fixed" in e:
            return e["target_fixed"]
        if e.get("clsid"):
            return _com_dll(e["clsid"])
        if e.get("dll"):
            found = _find_file(_native_fix(expand_env(e["dll"])), (".dll",))
            if found:
                return found
        src = e.get("resolve", e["command"])
        return resolve_target(src) if src else ""

    # ---- what changed -----------------------------------------------------------------------
    def _apply(self, sid: str, res: _Read, rows: dict[str, dict], baseline: bool) -> list[str]:
        new_keys = []
        present = set()
        for e in res.entries:
            key = e["key"]
            present.add(key)
            row = rows.get(key)
            fields = {"source": e["source"], "location": e["location"], "name": e["name"],
                      "command": e["command"]}
            if _tacoguards_own(e):
                # TacoGuard's own start-at-sign-in value: never reported
                if row is None or row["command"] != e["command"] or row["state"] not in ("kept", "baseline"):
                    if row is not None and row["state"] == "new" and row["event_id"]:
                        self.store.set_guard_event(row["event_id"], state="resolved", action="kept")
                    self.store.put_persistence(key, **fields, target=self._target(e),
                                               state="baseline" if baseline else "kept", event_id=0)
                continue
            if row is None:
                if baseline:
                    self.store.put_persistence(key, **fields, target=self._target(e), state="baseline")
                else:
                    self._report(e, fields, "new", row)
                    new_keys.append(key)
                continue
            st = row["state"]
            same = row["command"] == e["command"]
            if st == "undone":
                self._drop_backup_file(row.get("backup") or "")
                self._report(e, fields, "back" if same else "changed", row, backup="")
                new_keys.append(key)
            elif st == "removed":
                if not same:
                    self._report(e, fields, "changed", row)
                    new_keys.append(key)
                    continue
                ev = self.store.get_guard_event(row["event_id"]) if row["event_id"] else None
                if not row["event_id"]:
                    self.store.put_persistence(key, state="baseline")
                elif ev and ev.get("action") == "kept":
                    self.store.put_persistence(key, state="kept")
                elif ev and ev.get("action") == "undone":
                    self._report(e, fields, "back", row)
                    new_keys.append(key)
                elif ev and ev.get("action") == "removed":
                    # it went away by itself before you chose, and is back unchanged: the same alert
                    # opens again instead of a new one each time (Windows does this with some entries)
                    self.store.set_guard_event(ev["id"], state="new", action="")
                    self.store.put_persistence(key, **fields, state="new")
                else:
                    self._report(e, fields, "new", row)
                    new_keys.append(key)
            elif not same:
                if st == "new" and row["event_id"]:
                    self.store.set_guard_event(row["event_id"], state="resolved", action="replaced")
                self._report(e, fields, "changed", row)
                new_keys.append(key)
        for key, row in rows.items():
            if key in present or key in res.unknown or key in res.dormant:
                continue
            if row["state"] in ("removed", "undone") or row.get("backup"):
                continue          # turned off by you, or an undo / restore is half-way
            self.store.put_persistence(key, state="removed")
            if row["state"] == "new" and row["event_id"]:
                self.store.set_guard_event(row["event_id"], state="resolved", action="removed")
        return new_keys

    def _report(self, e: dict, fields: dict, how: str, row: dict | None, **more) -> int:
        """Check the entry's program and write its ONE event; the row becomes "new"."""
        target = self._target(e)
        result = None
        if self.checker is not None and target:
            try:
                result = self.checker.check_path(target)
            except Exception:
                log.exception("start-up watch: checking %s failed", target)
        level = "warning"
        if result is not None and result.status == SCANNED and result.level in (MALWARE, SUSPICIOUS):
            level = result.level
        sig = _signature(target)
        host, has_args, risky = script_host_risk(e["command"], target)
        if (level == "warning" and sig and sig.valid and _windows_own(target, sig.signer)
                and not (host and has_args)):
            level = "info"
        if risky and level == "info":
            level = "warning"
        name = e["name"]
        runs = target or e["command"][:120]
        title = {"new": f"New start-up entry: '{name}' runs {runs}",
                 "changed": f"Changed start-up entry: '{name}' now runs {runs}",
                 "back": f"Start-up entry came back: '{name}' runs {runs}"}[how]
        message = self._message_for(e, how, target, result, sig, row)
        if risky:
            message = f"{risky} {message}"
        eid = self.store.add_guard_event(
            "persistence", level, title, message, path=target,
            sha256=getattr(result, "sha256", "") or "",
            findings=[f.to_dict() for f in getattr(result, "findings", [])] if result else [],
            data={"key": e["key"]})
        self.store.put_persistence(e["key"], **fields, target=target, state="new", event_id=eid, **more)
        return eid

    def _message_for(self, e, how, target, result, sig, row) -> str:
        sid = e["sid"]
        kind, _, when = SOURCES[sid]
        when = e.get("when") or when
        parts = []
        if how == "back":
            parts.append("You turned this start-up entry off, and something has added it again.")
        elif how == "changed" and row:
            parts.append(f"It used to run: {row['command'][:300]}.")
        loc = e["location"] or SOURCES[sid][1]
        if loc.startswith(("Your ", "The ")):
            loc = loc[0].lower() + loc[1:]
        if kind == "ifeo":
            parts.append(f"It is in {loc}: Windows will start this instead of {e['name']} whenever "
                         f"{e['name']} is opened.")
        elif kind == "service":
            parts.append(f"It is a Windows service named {e['name']}, so it runs {when}." if when
                         else f"It is a Windows service named {e['name']}.")
        elif kind == "task":
            parts.append(f"It is a scheduled task ({e['location'].split(': ', 1)[-1]}), so it runs {when}.")
        else:
            parts.append(f"It is in {loc}, so it runs {when}." if when else f"It is in {loc}.")
        parts.append(f"It starts {target}." if target else f"The command is: {e['command'][:300]}.")
        if result is None:
            if self.checker is not None:
                parts.append("TacoGuard could not find the program file to check it." if not target
                             else "TacoGuard could not check the program file.")
        elif result.status == SCANNED and result.level == MALWARE:
            parts.append("The file check found malware: " + explain(result))
        elif result.status == SCANNED and result.level == SUSPICIOUS:
            parts.append("The file check found something suspicious: " + explain(result))
        elif result.status == SCANNED:
            parts.append("The file check found nothing wrong with it.")
        else:
            parts.append(explain(result))
        if sig is not None:
            parts.append(f"It has a valid digital signature from {sig.signer}." if sig.valid and sig.signer
                         else "It is not digitally signed." if sig.reason == "not signed" else "")
        parts.append("Keep it if you recognise it (for example a program you just installed).")
        if sid in UNDOABLE:
            parts.append("Undo turns it off and keeps a backup, so you can put it back later.")
        else:
            parts.append("TacoGuard cannot turn this one off for you: " + _NO_UNDO[kind])
        return " ".join(p for p in parts if p)

    # ---- the user's actions (the page calls these) ------------------------------------------
    def sid_of(self, key: str) -> str | None:
        best = None
        for sid in SOURCES:
            if key.startswith(sid + ":") and (best is None or len(sid) > len(best)):
                best = sid
        return best

    def _row(self, key: str) -> tuple[dict, str, str]:
        row = self.store.get_persistence(key)
        sid = self.sid_of(key)
        if not row or not sid:
            raise ValueError("TacoGuard does not know this start-up entry. Refresh the page and try again.")
        return row, sid, key[len(sid) + 1:]

    def keep(self, key: str) -> None:
        with self._lock:
            row, _, _ = self._row(key)
            if row["state"] == "undone":
                raise ValueError("This start-up entry is turned off. Use Restore if you want it back.")
            self.store.put_persistence(key, state="kept")
            if row["event_id"]:
                self.store.set_guard_event(row["event_id"], state="resolved", action="kept")

    def undo(self, key: str) -> str:
        with self._lock:
            row, sid, item = self._row(key)
            if sid not in UNDOABLE:
                raise ValueError(_NO_UNDO[SOURCES[sid][0]])
            if row["state"] == "undone":
                raise ValueError("This start-up entry is already turned off.")
            if row["state"] == "removed":
                raise ValueError("This start-up entry is no longer there, so there is nothing to undo.")
            if sid == "startup:user":
                self._undo_file(key, row, item)
            else:
                self._undo_reg(key, row, sid, item)
            if row["event_id"]:
                self.store.set_guard_event(row["event_id"], state="resolved", action="undone")
            return (f"Turned off '{row['name']}': it no longer starts by itself. TacoGuard kept a backup, "
                    "so you can put it back with Restore.")

    def _undo_reg(self, key, row, sid, item) -> None:
        hive, path = self.roots[sid]
        if hive != HKCU:
            raise ValueError(_NO_UNDO["run"])
        try:
            k = winreg.OpenKey(HKCU, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            if self._finish_cut_off_undo(key, row):
                return
            self.store.put_persistence(key, state="removed")
            raise ValueError("This start-up entry is no longer there, so there is nothing to undo.") from None
        except OSError as e:
            raise ValueError(f"Windows did not let TacoGuard change it ({plain_error(e)}).") from None
        with k:
            try:
                data, typ = winreg.QueryValueEx(k, item)
            except FileNotFoundError:
                if self._finish_cut_off_undo(key, row):
                    return
                self.store.put_persistence(key, state="removed")
                raise ValueError("This start-up entry is no longer there, so there is nothing to undo.") from None
            backup = {"kind": "registry", "hive": "HKCU", "path": path, "name": item, "type": typ,
                      "data": _enc_value(data, typ), "undone": time.time()}
            # backup first, then remove, then mark it: the guard never sees a gap it would report
            self.store.put_persistence(key, backup=json.dumps(backup))
            try:
                winreg.DeleteValue(k, item)
            except OSError as e:
                self.store.put_persistence(key, backup="")
                raise ValueError(f"Windows did not let TacoGuard remove it ({plain_error(e)}).") from None
        self.store.put_persistence(key, state="undone")

    def _finish_cut_off_undo(self, key: str, row: dict) -> bool:
        """An earlier undo was cut off after the entry was removed but before the row said so
        (TacoGuard closed in between): the backup is there, so it counts as undone and Restore
        stays possible. True when that was the case."""
        backup = row.get("backup") or ""
        try:
            b = json.loads(backup) if backup else None
        except ValueError:
            b = None
        if not isinstance(b, dict) or b.get("kind") not in ("registry", "file"):
            return False
        self.store.put_persistence(key, state="undone")
        return True

    def _backup_dir(self):
        d = self.settings.guard_dir / "startup-backup"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _undo_file(self, key, row, item) -> None:
        folder = self.roots.get("startup:user")
        if not folder or item in ("", ".", "..") or "\\" in item or "/" in item:
            raise ValueError("TacoGuard does not know this start-up entry. Refresh the page and try again.")
        src = os.path.join(folder, item)
        lsrc = winpath.to_long(src)
        try:
            st = os.lstat(lsrc)
        except FileNotFoundError:
            if self._finish_cut_off_undo(key, row):
                return
            self.store.put_persistence(key, state="removed")
            raise ValueError("This start-up item is no longer there, so there is nothing to undo.") from None
        except OSError as e:
            raise ValueError(f"TacoGuard could not look at it ({plain_error(e)}).") from None
        if winpath.is_reparse(st) or not os.path.isfile(lsrc):
            raise ValueError("This start-up item is a link or a folder. Remove it yourself in File Explorer "
                             "(press Win+R and type shell:startup).")
        try:
            sha = _sha256_file(lsrc)
            dest = self._backup_dir() / f"{sha[:16]}-{item}"
            ldest = winpath.to_long(str(dest))
            shutil.copyfile(lsrc, ldest)
            if _sha256_file(ldest) != sha:
                raise OSError("backup copy differs")
        except OSError as e:
            raise ValueError(f"TacoGuard could not keep a backup copy ({plain_error(e)}), so it did not "
                             "remove it.") from None
        attrs = getattr(st, "st_file_attributes", 0)
        backup = {"kind": "file", "folder": winpath.to_display(folder), "name": item, "backup": str(dest),
                  "sha256": sha, "size": st.st_size, "atime": st.st_atime, "mtime": st.st_mtime,
                  "attrs": attrs, "undone": time.time()}
        self.store.put_persistence(key, backup=json.dumps(backup))
        try:
            if attrs & 0x1:                   # read-only: Windows refuses to delete it otherwise
                _k32.SetFileAttributesW(lsrc, 0x80)
            os.remove(lsrc)
        except OSError as e:
            if attrs & 0x1:
                _k32.SetFileAttributesW(lsrc, attrs)
            self.store.put_persistence(key, backup="")
            try:
                os.remove(ldest)
            except OSError:
                pass
            raise ValueError(f"Windows did not let TacoGuard remove it ({plain_error(e)}).") from None
        self.store.put_persistence(key, state="undone")

    def restore(self, key: str) -> str:
        with self._lock:
            row, sid, item = self._row(key)
            if row["state"] != "undone" or not row.get("backup"):
                raise ValueError("There is no backup of this start-up entry to put back.")
            try:
                b = json.loads(row["backup"])
            except ValueError:
                raise ValueError("The backup of this start-up entry is damaged, so TacoGuard did not "
                                 "change anything.") from None
            # mark it first (backup kept): the guard sees the entry come back as expected
            self.store.put_persistence(key, state="kept")
            try:
                if b.get("kind") == "registry":
                    self._restore_reg(sid, item, b)
                elif b.get("kind") == "file":
                    self._restore_file(sid, item, b)
                else:
                    raise ValueError("The backup of this start-up entry is damaged, so TacoGuard did not "
                                     "change anything.")
            except BaseException:
                self.store.put_persistence(key, state="undone")
                raise
            self.store.put_persistence(key, backup="")
            if row["event_id"]:
                self.store.set_guard_event(row["event_id"], state="resolved", action="restored")
            return f"Put '{row['name']}' back: it starts by itself again."

    def _restore_reg(self, sid, item, b) -> None:
        spec = self.roots.get(sid)
        if (sid not in ("run:HKCU", "runonce:HKCU") or not spec or spec[0] != HKCU or b.get("hive") != "HKCU"
                or str(b.get("path", "")).casefold() != spec[1].casefold() or b.get("name") != item):
            raise ValueError("The backup does not match this start-up entry, so TacoGuard did not change "
                             "anything.")
        try:
            with winreg.CreateKeyEx(HKCU, spec[1], 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.QueryValueEx(k, item)
                    exists = True
                except FileNotFoundError:
                    exists = False
                if exists:
                    raise ValueError(f"Something named '{item or '(Default)'}' is already there, so TacoGuard "
                                     "did not overwrite it.")
                winreg.SetValueEx(k, item, 0, int(b["type"]), _dec_value(b["data"]))
        except OSError as e:
            raise ValueError(f"Windows did not let TacoGuard put it back ({plain_error(e)}).") from None

    def _restore_file(self, sid, item, b) -> None:
        folder = self.roots.get("startup:user")
        if (sid != "startup:user" or not folder or b.get("name") != item
                or winpath.norm_key(b.get("folder", "")) != winpath.norm_key(folder)):
            raise ValueError("The backup does not match this start-up entry, so TacoGuard did not change "
                             "anything.")
        bdir = self._backup_dir()
        bfile = str(b.get("backup", ""))
        if not winpath.is_under(bfile, str(bdir)):
            raise ValueError("The backup does not match this start-up entry, so TacoGuard did not change "
                             "anything.")
        lb = winpath.to_long(bfile)
        dest = winpath.to_long(os.path.join(folder, item))
        if os.path.lexists(dest):
            raise ValueError(f"Something named '{item}' is already in your Startup folder, so TacoGuard did "
                             "not overwrite it.")
        try:
            if _sha256_file(lb) != b.get("sha256"):
                raise ValueError("The backup copy is damaged, so TacoGuard did not put it back.")
        except OSError:
            raise ValueError("The backup copy is missing, so TacoGuard cannot put it back.") from None
        try:
            os.makedirs(winpath.to_long(folder), exist_ok=True)
            shutil.copyfile(lb, dest)
            os.utime(dest, (float(b.get("atime", time.time())), float(b.get("mtime", time.time()))))
            attrs = int(b.get("attrs", 0)) & (0x1 | 0x2 | 0x4 | 0x20)
            if attrs:
                _k32.SetFileAttributesW(dest, attrs)
        except OSError as e:
            raise ValueError(f"TacoGuard could not put it back ({plain_error(e)}).") from None
        try:
            os.remove(lb)
        except OSError:
            pass

    def _drop_backup_file(self, backup_json: str) -> None:
        """An undone entry came back by itself: its old backup copy is no longer needed."""
        try:
            b = json.loads(backup_json) if backup_json else {}
            if b.get("kind") == "file" and winpath.is_under(b.get("backup", ""), str(self._backup_dir())):
                os.remove(winpath.to_long(b["backup"]))
        except (OSError, ValueError, TypeError):
            pass

    # ---- the watching thread ----------------------------------------------------------------
    def _on_folder_event(self, sid: str):
        def cb(_ev):
            self._pending.add(sid)
            if self._wake_ev:
                _k32.SetEvent(self._wake_ev)
        return cb

    def _run(self) -> None:
        watches: list[_Watch] = []
        try:
            try:
                self.scan_now()
            except Exception:
                log.exception("start-up watch: first pass failed")
            for sid, spec in self.roots.items():
                if sid in SOURCES and SOURCES[sid][0] in REG_KINDS and isinstance(spec, tuple):
                    w = _Watch(sid, spec[0], spec[1], SOURCES[sid][0] in SUBTREE_KINDS)
                    w.arm()
                    watches.append(w)
            folder_sids = [s for s in self.roots if s in SOURCES and SOURCES[s][0] == "startup_folder"
                           and self.roots[s]]
            poll_folders = list(folder_sids)
            if self.hub is not None:
                for sid in folder_sids:
                    try:
                        self._hub_tokens.append(self.hub.subscribe(self.roots[sid], self._on_folder_event(sid),
                                                                   recursive=False))
                        poll_folders.remove(sid)
                    except Exception:
                        log.exception("start-up watch: folder hub refused %s", sid)
            with self._lock:
                self._state = "on"
            self._loop(watches, poll_folders)
        except Exception:
            log.exception("start-up watch stopped")
            with self._lock:
                self._state = "error"
                self._message = ("The start-up watch stopped after an unexpected problem; it starts again "
                                 "with TacoGuard.")
        finally:
            for w in watches:
                w.close()
            try:
                self.store.close()          # this thread's own database connection
            except Exception:
                pass

    def _loop(self, watches: list[_Watch], poll_folders: list[str]) -> None:
        now = time.monotonic()
        next_tasks = now + self.task_interval_s
        next_folders = now + self.folder_poll_s
        next_full = now + self.full_scan_s
        next_rearm = now + 60.0
        due: dict[str, float] = {}
        last_read: dict[str, float] = {}
        handles = [self._stop_ev, self._wake_ev] + [w.event for w in watches]
        arr = (wintypes.HANDLE * len(handles))(*handles)
        while True:
            now = time.monotonic()
            deadlines = list(due.values()) + [next_full, next_rearm]
            if "task" in self.roots:
                deadlines.append(next_tasks)
            if poll_folders:
                deadlines.append(next_folders)
            wait_ms = int(max(0.0, min(deadlines) - now) * 1000) + 1
            r = _k32.WaitForMultipleObjects(len(handles), arr, False, min(wait_ms, 0x7FFFFFFF))
            now = time.monotonic()
            if r == 0:
                return
            if r == 1:
                while self._pending:
                    due.setdefault(self._pending.pop(), now + self.debounce_s)
            elif 2 <= r < len(handles):
                w = watches[r - 2]
                w.arm()
                earliest = last_read.get(w.sid, 0.0) + MIN_INTERVAL_S.get(SOURCES[w.sid][0], 0.0)
                due.setdefault(w.sid, max(now + self.debounce_s, earliest))
            elif r != WAIT_TIMEOUT:
                if _k32.WaitForMultipleObjects(1, arr, False, 1000) == 0:   # failed wait: stay calm
                    return
                continue
            ready = [s for s, t in due.items() if t <= now]
            for s in ready:
                due.pop(s, None)
            if ready:
                self._safe_pass(ready)
                for s in ready:
                    last_read[s] = time.monotonic()
            if "task" in self.roots and now >= next_tasks:
                self._safe_pass(["task"])
                next_tasks = time.monotonic() + self.task_interval_s
            if poll_folders and now >= next_folders:
                self._safe_pass(poll_folders)
                next_folders = time.monotonic() + self.folder_poll_s
            if now >= next_rearm:
                for w in watches:
                    if not w.armed and w.arm():
                        due.setdefault(w.sid, now + self.debounce_s)
                next_rearm = now + 60.0
            if now >= next_full:
                try:
                    self.scan_now()
                except Exception:
                    log.exception("start-up watch: full pass failed")
                next_full = time.monotonic() + self.full_scan_s

    def _safe_pass(self, sids: list[str]) -> None:
        try:
            self._pass(sids)
        except Exception:
            log.exception("start-up watch: pass failed")


def _signature(target: str):
    """Windows' signature verdict for a program file, or None (not a file / not checked)."""
    if not target or not target.lower().endswith((".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx")):
        return None
    try:
        from ..signing import check_signature
        lp = winpath.to_long(target)
        return check_signature(lp) if os.path.isfile(lp) else None
    except Exception:
        return None


# Windows tools that run scripts or other programs (often used by malware to start itself).
SCRIPT_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "conhost.exe", "msiexec.exe", "certutil.exe",
    "bitsadmin.exe", "schtasks.exe", "forfiles.exe",
})
_RISKY = (
    (re.compile(r"\b(?:https?|ftp)://", re.I), "downloads something from the internet"),
    (re.compile(r"(?:^|[\s\"'])[-/](?:e|ec|en|enc\w*)\s+[\"']?[A-Za-z0-9+/]{16,}={0,2}", re.I),
     "runs a hidden (encoded) command"),
    (re.compile(r"(?:^|[\s\"'])[-/]w\w*\s+[\"']?hidden\b", re.I), "runs in a hidden window"),
    (re.compile(r"\b(?:javascript|vbscript):", re.I), "runs script code written into the entry itself"),
    (re.compile(r"scrobj\.dll", re.I), "loads script code through scrobj.dll"),
    (re.compile(r"--headless\b", re.I), "runs without a window (--headless)"),
)


def script_host_risk(command: str, target: str = "") -> tuple[str, bool, str]:
    """(script host / Windows tool name or "", whether the command has arguments, a plain reason
    when the command looks like a hidden or downloading start-up trick, else "")."""
    try:
        prog, args = split_command(command)
    except Exception:
        prog, args = "", []
    names = {os.path.basename(prog.strip().strip('"')).lower(), os.path.basename(target or "").lower()}
    host = ""
    for n in names:
        cand = n if n.endswith(".exe") else n + ".exe"
        if cand in SCRIPT_HOSTS:
            host = cand
            break
    has_args = bool(args)
    if not host:
        return "", has_args, ""
    found = [why for rx, why in _RISKY if rx.search(command or "")]
    if not found:
        return host, has_args, ""
    what = found[0] if len(found) == 1 else ", ".join(found[:-1]) + " and " + found[-1]
    return host, has_args, (f"It uses the Windows tool {host} in a way that {what}. Harmful programs often "
                            "start themselves like this, so make sure you recognise it.")


def _tacoguards_own(e: dict) -> bool:
    """TacoGuard's own start-at-sign-in value (autostart.py): exactly its command for the
    installed copy, in your Run key."""
    if e.get("sid") != "run:HKCU":
        return False
    try:
        from .. import autostart
        from ..config import install_root
        return e.get("name") == autostart.VALUE_NAME and e.get("command") == autostart.command_for(install_root())
    except Exception:
        return False


def _windows_own(target: str, signer: str) -> bool:
    """A Microsoft-signed file in Windows' or Microsoft's own folders: an update, not an intruder
    (Defender's services move to a new folder with every platform update)."""
    if not signer.lower().startswith("microsoft"):
        return False
    roots = [_sysroot(), os.environ.get("ProgramFiles", r"C:\Program Files"),
             os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
             os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft")]
    return any(r and winpath.is_under(target, r) for r in roots)
