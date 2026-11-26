"""TacoGuard launcher (copied into the install folder by `python -m tacoguard install`).

    venv\\Scripts\\pythonw.exe TacoGuard.pyw [args]     no window: starts the page (args default: serve)
    venv\\Scripts\\pythonw.exe TacoGuard.pyw --background
                                                      the same without opening the browser (the
                                                      start-at-sign-in entry, tacoguard/autostart.py)
    TacoGuard.cmd [args]                              console: runs the command and shows its output

A start while TacoGuard already runs opens the running one's page (`serve` sees the port in use),
except with --background, which then does nothing.

Reads current.json, puts versions\\<version> first on PYTHONPATH and runs `-m tacoguard <args>`
from that folder with the installed Python. Without a console the output goes to the data
folder's logs\\launcher.log. Uses only the standard library: it must work whatever version is current.

A self-update writes current.json with "pending": true (tacoguard/selfupdate.py); its watchdog
clears that once the new page answered. When the launcher finds "pending" with no health.json
from that version since the switch, and the watchdog is gone (or the switch is older than
PENDING_GIVE_UP_S), the update never finished starting: it switches back to "pending_from"
itself, records that in update_result.json and starts that version.
"""
import ctypes
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
DEFAULT_DATA = (r"D:\TacoGuard" if os.path.isdir("D:\\") else  # same rule as tacoguard/config.py
                os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local"),
                             "TacoGuard"))
LOG_MAX = 1024 * 1024
VERSION_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){1,3}$")
PENDING_GIVE_UP_S = 120            # the watchdog needs at most ~100 s for a good update


def data_dir(args):
    if "--data" in args:
        i = args.index("--data")
        if i + 1 < len(args):
            return args[i + 1]
    return os.environ.get("TACOGUARD_DATA") or DEFAULT_DATA


def open_log(args):
    try:
        logs = os.path.join(data_dir(args), "logs")
        os.makedirs(logs, exist_ok=True)
        path = os.path.join(logs, "launcher.log")
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX:
            os.replace(path, path + ".1")
        return open(path, "ab")
    except OSError:
        return None


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def write_json(path, obj):
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.1)


def valid(v):
    return isinstance(v, str) and bool(VERSION_RE.match(v))


def vkey(v):
    return tuple(int(x) for x in v.split("."))


def pid_alive(pid):
    """True while process `pid` runs (Windows; no third-party parts)."""
    try:
        pid = int(pid or 0)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ctypes.get_last_error() == 5          # access denied: it exists
    try:
        code = ctypes.c_ulong()
        if not k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code)):
            return False
        return code.value == 259                     # STILL_ACTIVE
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def older_installed(version):
    """The newest installed version older than `version` (what 'Go back' may offer next)."""
    try:
        names = os.listdir(os.path.join(ROOT, "versions"))
    except OSError:
        return None
    olds = [n for n in names if valid(n) and os.path.isdir(os.path.join(ROOT, "versions", n, "tacoguard"))
            and vkey(n) < vkey(version)]
    return max(olds, key=vkey) if olds else None


def finish_pending(cur, now=None):
    """An unfinished self-update switch (see the module docstring). Returns current.json as it
    should be used now (maybe switched back)."""
    if not cur.get("pending"):
        return cur
    now = time.time() if now is None else now
    new, old = cur.get("version"), cur.get("pending_from")
    since = float(cur.get("pending_since") or 0)
    health = read_json(os.path.join(ROOT, "health.json")) or {}
    if health.get("version") == new and float(health.get("time") or 0) >= since:
        # the new page did answer; only the watchdog's last step is missing
        cur = {k: v for k, v in cur.items() if not k.startswith("pending") and k != "watchdog_pid"}
        write_json(os.path.join(ROOT, "current.json"), cur)
        return cur
    watchdog = cur.get("watchdog_pid")               # missing for a moment right after the switch
    if (not watchdog or pid_alive(watchdog)) and now - since < PENDING_GIVE_UP_S:
        return cur                                   # the update is still starting
    if not valid(old) or not os.path.isdir(os.path.join(ROOT, "versions", old, "tacoguard")):
        return cur                                   # nothing known-good to go back to
    if cur.get("pending_mode") == "rollback":
        previous = new
        message = "TacoGuard %s didn't finish starting, so TacoGuard stayed on %s." % (new, old)
    else:
        previous = older_installed(old)
        message = "The last update didn't finish starting, so TacoGuard went back to %s." % old
    back = {"version": old, "previous": previous, "switched": now, "failed": new}
    write_json(os.path.join(ROOT, "current.json"), back)
    write_json(os.path.join(ROOT, "update_result.json"),
               {"ok": False, "message": message, "time": now, "from": old, "to": new, "by": "launcher"})
    for name in ("update.lock", "update_state.json"):
        try:
            os.remove(os.path.join(ROOT, name))
        except OSError:
            pass
    return back


def build_args(argv):
    """The tacoguard command line for the launcher's own arguments: none -> serve;
    --background -> serve --no-browser (other options such as --data are kept)."""
    args = list(argv)
    if "--background" not in args:
        return args or ["serve"]
    args = [a for a in args if a != "--background"]
    if "serve" not in args:
        args.append("serve")
    if "--no-browser" not in args:
        args.insert(args.index("serve") + 1, "--no-browser")
    return args


def main():
    args = build_args(sys.argv[1:])
    cur = read_json(os.path.join(ROOT, "current.json"))
    if cur is None or not valid(cur.get("version")):
        raise SystemExit("current.json names no valid version; run the TacoGuard installer again.")
    try:
        cur = finish_pending(cur)
    except Exception:                                # never stop the start over this
        pass
    version = cur["version"]
    vdir = os.path.join(ROOT, "versions", version)
    env = dict(os.environ)
    env.pop("PYTHONHOME", None)
    env["PYTHONPATH"] = vdir
    scripts = os.path.join(ROOT, "venv", "Scripts")
    windowless = os.path.basename(sys.executable).lower() == "pythonw.exe"
    if not windowless:                  # started with python.exe (TacoGuard.cmd): run here, show output
        return subprocess.call([os.path.join(scripts, "python.exe"), "-m", "tacoguard"] + args,
                               cwd=vdir, env=env)
    log = open_log(args)
    out = log if log is not None else subprocess.DEVNULL
    try:
        subprocess.Popen([os.path.join(scripts, "pythonw.exe"), "-m", "tacoguard"] + args, cwd=vdir,
                         env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                         close_fds=True, creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
    finally:
        if log is not None:
            log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
