"""Self-update of the installed copy (Phase 2). See the contract in tacoguard/updates/__init__.py.

    running_from_install() -> bool
    available(settings, app_update=None) -> dict | None
    install_update(settings, version, shutdown=None) -> dict    ONLY after the user clicks
    rollback(settings, shutdown=None) -> dict                   ONLY after the user clicks
    status(settings, app_update=None) -> dict                   everything the page shows
    report_health_when_up(settings) -> None                     `serve` calls this at start

How an update goes (install_update, in the running page's process):
  1. refuse when not installed, when a scan runs, or when another update is under way;
  2. verify the package again against its signed target entry (tacoguard.updates.signed);
  3. unpack it to versions/<new>.staging (no paths outside it, no links, size limits);
  4. its requirements.lock must equal the installed one (else: run the installer again); the hash
     list tacoguard-files.json is written from the unpacked files (Phase 4, selfprotect.py);
  5. versions/<new>: `python -m tacoguard selftest` must pass, else it is deleted and nothing changes;
  6. current.json -> {"version": new, "previous": old, "pending": true, "pending_since": epoch,
     "pending_from": old, "pending_mode": "update" | "rollback", "watchdog_pid": pid};
  7. start the WATCHDOG, a separate small process running the OLD version's code, then shut the
     page down (the `shutdown` callback the page passes in);
  8. the watchdog waits for the old page to exit, starts the new one (no window, no new browser
     tab), and waits up to 60 s for the new page to write health.json with its version and the
     watchdog's one-time code. A crash, an exit or silence means: stop it, switch current.json back,
     start the old version again and record "The update didn't start, so TacoGuard went back to
     <old>." The page reads that from status()["last_result"]. Once the new page answered, the
     watchdog removes the "pending" keys from current.json (clear_pending);
  9. if the watchdog itself dies before that, the launcher (tools/TacoGuard.pyw) finds "pending"
     without a health.json from the new version and goes back to pending_from by itself, recording
     "The last update didn't finish starting, so TacoGuard went back to <old>."

The updater (tacoguard/updates/updater.py) only RECORDS an app update. This module reads that
record from `app_update` (Updater.status()["app_update"]) or, when not given, from
updater.available_app(settings):
    {"version": "0.2.0", "notes": "...", "file": <absolute path in settings.updates_dir/app/>,
     "sha256": hex, "name": "tacoguard-0.2.0.zip"}     (optionally "length" / a full "target" entry)
Before installing, the raw signed list the updater keeps in settings.updates_dir/targets.json is
verified again against the trusted root, the entry is taken from it, and the file is checked with
signed.verify_file. Without that list nothing is installed (fail closed: the record in status.json
is not signed).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from pathlib import Path

from .model import plain_error
from . import __version__
from .config import install_root
from .install import (CREATE_NO_WINDOW, CURRENT, LOCK_NAME, compare_versions, package_version,
                      prune_versions, read_current, read_json, rmtree, run_selftest, same_lock,
                      valid_version, venv_python, version_env, version_tuple, write_current, write_json)

HEALTH_TIMEOUT_S = 60          # the new page must answer within this
SERVER_EXIT_WAIT_S = 30        # the old page gets this long to close
LOCK_STALE_S = 15 * 60
HEALTH = "health.json"
UPDATE_LOCK = "update.lock"
RESULT = "update_result.json"
NONCE_ENV = "TACOGUARD_HEALTH_NONCE"
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
MAX_PACKAGE_FILES = 5000
MAX_PACKAGE_BYTES = 300 * 1024**2
ALLOWED_TOP = {"tacoguard", LOCK_NAME, "LICENSE", "THIRD_PARTY_LICENSES.md", "README.md"}
WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}

NOT_INSTALLED_MSG = ("This copy runs from the project folder; install TacoGuard first "
                     "(python -m tacoguard install) to use self-update.")
SCAN_MSG = "Finish or pause the scan first."
NEW_PARTS_MSG = "This update needs new parts; run the TacoGuard installer again."
BUSY_MSG = "An update is already being installed. Wait a minute, then reload the page."
MISSING_LIST_MSG = ("TacoGuard's signed update list is missing, so this update can't be checked and was "
                    "not installed. Press 'Check for updates', then try again.")


class Refused(Exception):
    """Plain-English reason; nothing was changed."""


# ---------------------------------------------------------------------------------------------
# where we run from
# ---------------------------------------------------------------------------------------------
def _norm(p) -> str:
    return os.path.normcase(str(Path(p).resolve()))


def running_from_install() -> bool:
    """True when this process runs TacoGuard from install_root()/versions/<v>/tacoguard."""
    import tacoguard
    here = Path(tacoguard.__file__).resolve().parent
    return _norm(here.parent.parent) == _norm(install_root() / "versions")


# ---------------------------------------------------------------------------------------------
# what the updater recorded
# ---------------------------------------------------------------------------------------------
def _app_dir(settings) -> Path:
    return Path(settings.updates_dir) / "app"


def _recorded(settings, app_update=None) -> dict | None:
    """The updater's record, normalised to {"version", "file", "name", "target", "notes"}."""
    rec = app_update
    if rec is None:
        try:
            from .updates import updater as _u
            rec = _u.available_app(settings)
        except Exception:
            rec = (read_json(Path(settings.updates_dir) / "status.json") or {}).get("app_update")
    if not isinstance(rec, dict):
        return None
    target = dict(rec.get("target") or rec.get("entry") or {})
    custom = dict(target.get("custom") or rec.get("custom") or {})
    version = rec.get("version") or custom.get("version")
    if not valid_version(version):
        return None
    if "sha256" not in target and rec.get("sha256"):
        target["sha256"] = rec["sha256"]
    if "length" not in target and rec.get("length"):
        target["length"] = rec["length"]
    custom.setdefault("kind", "app")
    custom.setdefault("version", version)
    target["custom"] = custom
    file = str(rec.get("file") or "")
    return {"version": version, "file": file, "name": str(rec.get("name") or Path(file).name),
            "target": target, "notes": rec.get("notes") or custom.get("notes") or ""}


def _package_path(settings, rec: dict) -> Path | None:
    """The downloaded package, only when it lies in updates_dir/app (nothing outside it is used)."""
    if not rec.get("file"):
        return None
    app_dir = _app_dir(settings)
    p = Path(rec["file"])
    if not p.is_absolute():
        p = app_dir / p.name
    if _norm(p.parent) != _norm(app_dir):
        return None
    return p if p.is_file() else None


def available(settings, app_update=None) -> dict | None:
    """The recorded app update when it is newer than the running version, else None.
    {"version", "current", "notes", "size", "downloaded", "can_install", "message"}"""
    rec = _recorded(settings, app_update)
    if not rec or compare_versions(rec["version"], __version__) <= 0:
        return None
    pkg = _package_path(settings, rec)
    installed = running_from_install()
    if not installed:
        can, msg = False, NOT_INSTALLED_MSG
    elif pkg is None:
        can, msg = False, "The update is not downloaded yet. Press 'Check for updates', then try again."
    else:
        can, msg = True, f"TacoGuard {rec['version']} is ready to install."
    return {"version": rec["version"], "current": __version__, "notes": rec["notes"],
            "size": int(rec["target"].get("length") or 0), "downloaded": pkg is not None,
            "can_install": can, "message": msg}


# ---------------------------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------------------------
def _signed():
    """tacoguard.updates.signed (Helper E). Tests replace this function with a fake."""
    from .updates import signed
    return signed


def _verify_package(settings, rec: dict, pkg: Path) -> None:
    """Fail closed: the target entry must come from metadata that verifies against the trusted
    root again (when the updater stored targets.json), and the file must match it."""
    try:
        signed = _signed()
    except Exception:
        raise Refused("TacoGuard can't check this update's signature (the checking part is missing), "
                      "so it was not installed.") from None
    tpath = Path(settings.updates_dir) / "targets.json"
    try:
        # the raw signed list the updater kept: its signatures are checked again here, and the
        # entry is taken only from it (never from the unsigned record in status.json)
        if not tpath.is_file():
            raise Refused(MISSING_LIST_MSG)
        root = signed.load_trusted_root(settings)
        state = signed.load_state(settings) if hasattr(signed, "load_state") else {}
        meta = signed.verify_targets(root, tpath.read_bytes(), int(state.get("targets_version") or 0),
                                     str(state.get("targets_sha256") or ""))
        fresh = (meta.get("targets") or {}).get(rec["name"])
        if not fresh:
            raise Refused("This update is no longer listed in TacoGuard's signed release list. "
                          "Press 'Check for updates' and try again.")
        entry = dict(fresh)
        if not entry.get("sha256"):
            raise Refused("This update has no signed checksum, so it was not installed.")
        if "length" not in entry:        # the record keeps only the sha256; that is the real check
            entry["length"] = pkg.stat().st_size
        custom = entry.get("custom") or {}
        if custom.get("kind", "app") != "app" or custom.get("version", rec["version"]) != rec["version"]:
            raise Refused("The signed release list doesn't describe this file as TacoGuard "
                          f"{rec['version']}, so it was not installed.")
        min_app = custom.get("min_app")
        if valid_version(min_app) and compare_versions(__version__, min_app) < 0:
            raise Refused(f"This update needs TacoGuard {min_app} or newer first; run the TacoGuard "
                          "installer again.")
        signed.verify_file(pkg, entry)
    except Refused:
        raise
    except Exception as e:       # signed.UpdateRejected carries a plain reason
        if getattr(e, "kind", "") == "expired":
            raise Refused("TacoGuard's own update list has expired, so this update can't be installed "
                          "until a new release is published. Nothing was changed.") from None
        raise Refused(str(e) if isinstance(e, getattr(signed, "UpdateRejected", ())) else
                      "The update failed its signature check, so it was not installed.") from None


def _scan_active(settings) -> bool:
    db = Path(settings.db_path)
    if not db.is_file():
        return False
    from .store import Store
    st = Store(db)
    try:
        return bool(st.active_jobs())
    finally:
        st.close()


def _bad_name(name: str) -> bool:
    if not name or name.startswith("/") or ":" in name or "\0" in name:
        return True
    parts = name.rstrip("/").split("/")
    for p in parts:
        if p in ("", ".", "..") or p != p.rstrip(" .") or p.split(".")[0].lower() in WIN_RESERVED:
            return True
    return parts[0] not in ALLOWED_TOP


def safe_unpack(pkg: Path, dest: Path) -> None:
    """Unpack a release zip into `dest` (made fresh). Refuses absolute paths, '..', drive letters,
    links, encrypted members, unexpected top-level names and oversized content."""
    dest = Path(dest)
    rmtree(dest)
    dest.mkdir(parents=True)
    base = dest.resolve()
    try:
        zf = zipfile.ZipFile(pkg)
    except (zipfile.BadZipFile, OSError):
        raise Refused("The update file is damaged (not a zip), so it was not installed.") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_PACKAGE_FILES:
            raise Refused("The update file holds too many files, so it was not installed.")
        total = 0
        plan = []
        for info in infos:
            name = info.filename.replace("\\", "/")
            mode = info.external_attr >> 16
            if _bad_name(name) or stat.S_ISLNK(mode) or info.flag_bits & 0x1:
                raise Refused(f"The update file contains an unsafe entry ({info.filename!r}), so it was "
                              "not installed.")
            target = (dest / name).resolve()
            if not _norm(target).startswith(_norm(base) + os.sep):
                raise Refused(f"The update file contains an unsafe entry ({info.filename!r}), so it was "
                              "not installed.")
            total += info.file_size
            if total > MAX_PACKAGE_BYTES:
                raise Refused("The update file unpacks to more than expected, so it was not installed.")
            plan.append((info, name, target))
        for info, name, target in plan:
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1024 * 1024):
                    written += len(chunk)
                    if written > info.file_size:
                        raise Refused("The update file is damaged, so it was not installed.")
                    out.write(chunk)
    if not (dest / "tacoguard" / "__init__.py").is_file() or not (dest / LOCK_NAME).is_file():
        raise Refused("The update file is not a TacoGuard package, so it was not installed.")


# ---------------------------------------------------------------------------------------------
# the update lock (one update / rollback at a time)
# ---------------------------------------------------------------------------------------------
def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(int(pid))
    except Exception:
        return False


def _take_lock(root: Path) -> bool:
    lock = root / UPDATE_LOCK
    for _ in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            info = read_json(lock) or {}
            stale = (time.time() - float(info.get("time") or 0) > LOCK_STALE_S
                     or not _pid_alive(info.get("pid") or 0))
            if not stale:
                return False
            try:
                lock.unlink()
            except OSError:
                return False
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "time": time.time()}, f)
        return True
    return False


def _hand_lock(root: Path, pid: int) -> None:
    write_json(root / UPDATE_LOCK, {"pid": pid, "time": time.time()})


def _release_lock(root: Path) -> None:
    try:
        (root / UPDATE_LOCK).unlink()
    except OSError:
        pass


def _busy(root: Path) -> bool:
    info = read_json(root / UPDATE_LOCK)
    if not info:
        return False
    return time.time() - float(info.get("time") or 0) <= LOCK_STALE_S and _pid_alive(info.get("pid") or 0)


# ---------------------------------------------------------------------------------------------
# results, logs
# ---------------------------------------------------------------------------------------------
def _log(settings_or_dir, msg: str) -> None:
    try:
        d = Path(getattr(settings_or_dir, "log_dir", settings_or_dir))
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "selfupdate.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg.rstrip() + "\n")
    except OSError:
        pass


def _result(root: Path, ok: bool, message: str, **extra) -> None:
    write_json(root / RESULT, {"ok": ok, "message": message, "time": time.time(), **extra})


def last_result(settings=None) -> dict | None:
    """The outcome of the last update / rollback: {"ok", "message", "time", "from", "to"} or None."""
    return read_json(install_root() / RESULT)


def _no(message: str) -> dict:
    return {"ok": False, "restarting": False, "message": message}


# ---------------------------------------------------------------------------------------------
# install_update / rollback
# ---------------------------------------------------------------------------------------------
def _spawn(cmd: list[str], cwd: Path, env: dict, log_path: Path | None) -> subprocess.Popen:
    """A detached process with no window. Breaks away from a Windows job when allowed, so it
    outlives the page that started it."""
    out = subprocess.DEVNULL
    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            out = open(log_path, "ab")
        except OSError:
            out = subprocess.DEVNULL
    try:
        base = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        try:
            return subprocess.Popen(cmd, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, close_fds=True,
                                    creationflags=base | CREATE_BREAKAWAY_FROM_JOB)
        except OSError:
            return subprocess.Popen(cmd, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, close_fds=True, creationflags=base)
    finally:
        if out is not subprocess.DEVNULL:
            out.close()


def _start_watchdog(settings, root: Path, mode: str, old: str, new: str, server_pid: int,
                    timeout: float) -> subprocess.Popen:
    """Runs from the OLD version's folder (known to work), with the installed Python."""
    cmd = [str(venv_python(root, windowless=True)), "-m", "tacoguard.selfupdate", "watchdog",
           "--root", str(root), "--data", str(settings.data_dir), "--port", str(settings.port),
           "--mode", mode, "--from", old, "--to", new, "--server-pid", str(server_pid),
           "--timeout", str(timeout)]
    return _spawn(cmd, root / "versions" / old, version_env(root, old),
                  Path(settings.log_dir) / "selfupdate.log")


def _switch_and_restart(settings, root: Path, mode: str, old: str, new: str, previous_after: str | None,
                        shutdown, server_pid: int | None, timeout: float) -> None:
    before = read_json(root / CURRENT)
    # "pending" until the watchdog saw the new page answer; if the watchdog dies first, the
    # launcher (tools/TacoGuard.pyw) switches back to pending_from by itself
    pending = {"pending": True, "pending_since": time.time(), "pending_from": old, "pending_mode": mode}
    write_current(root, new, previous_after, **pending)
    try:
        proc = _start_watchdog(settings, root, mode, old, new,
                               os.getpid() if server_pid is None else server_pid, timeout)
    except OSError as e:
        write_json(root / CURRENT, before)
        raise Refused(f"Could not start the update helper ({plain_error(e)}), so nothing was changed.") from None
    cur = read_json(root / CURRENT) or {}
    if cur.get("pending") and cur.get("version") == new:     # the watchdog may already be done
        write_json(root / CURRENT, {**cur, "watchdog_pid": proc.pid})
    _hand_lock(root, proc.pid)
    write_json(root / "update_state.json", {"state": "restarting", "mode": mode, "from": old, "to": new,
                                            "since": time.time(), "watchdog_pid": proc.pid})
    _log(settings, f"{mode}: {old} -> {new}, watchdog pid {proc.pid}")
    if shutdown is not None:
        t = threading.Timer(1.0, shutdown)      # let the page's reply go out first
        t.daemon = True
        t.start()


def _write_manifest(root: Path, old: str, staging: Path) -> None:
    """Phase 4: the hash list of the new version (tacoguard/selfprotect.py), made from the files
    just unpacked from the verified package. The launcher is not part of a package, so its
    hash is carried over from the running version's list (when it has one)."""
    from .selfprotect import read_manifest, write_manifest
    old_list = read_manifest(root / "versions" / old) or {}
    write_manifest(staging, launcher_sha256=old_list.get("launcher"))


def previous_after_rollback(root: Path, version: str) -> str | None:
    """What 'previous' should be once we are back on `version`: the newest other installed
    version that is older than it (so 'Go back' never offers the version that just failed)."""
    vroot = Path(root) / "versions"
    olds = sorted((p.name for p in vroot.iterdir() if p.is_dir() and valid_version(p.name)
                   and compare_versions(p.name, version) < 0), key=version_tuple)
    return olds[-1] if olds else None


def install_update(settings, version: str, shutdown=None, *, _server_pid: int | None = None,
                   _health_timeout: float = HEALTH_TIMEOUT_S) -> dict:
    """ONLY after the user clicks. Returns {"ok", "restarting", "message"}. On ok the page closes
    by itself about a second later (`shutdown` is called) and the new page starts on the same
    port; the page should poll /api/ping and reload."""
    if not running_from_install():
        return _no(NOT_INSTALLED_MSG)
    root = install_root()
    if not valid_version(version):
        return _no("That isn't a valid version number.")
    cur = read_current(root)
    if not cur:
        return _no("The installed copy is missing its version file; run the TacoGuard installer again.")
    old = cur["version"]
    if compare_versions(version, old) <= 0:
        return _no(f"TacoGuard {old} is already installed; {version} is not newer.")
    rec = _recorded(settings)
    if not rec or rec["version"] != version:
        return _no("This update is no longer offered. Press 'Check for updates' and try again.")
    pkg = _package_path(settings, rec)
    if pkg is None:
        return _no("The update is not downloaded yet. Press 'Check for updates', then try again.")
    if _scan_active(settings):
        return _no(SCAN_MSG)
    if not _take_lock(root):
        return _no(BUSY_MSG)
    vroot = root / "versions"
    staging = vroot / f"{version}.staging"
    final = vroot / version
    handed = False
    try:
        _verify_package(settings, rec, pkg)
        safe_unpack(pkg, staging)
        if package_version(staging / "tacoguard") != version:
            raise Refused(f"The update file doesn't contain TacoGuard {version}, so it was not installed.")
        new_lock = (staging / LOCK_NAME).read_text(encoding="utf-8")
        have_lock = (root / LOCK_NAME).read_text(encoding="utf-8") if (root / LOCK_NAME).is_file() else ""
        if not same_lock(new_lock, have_lock):
            raise Refused(NEW_PARTS_MSG)
        _write_manifest(root, old, staging)
        if final.exists():
            rmtree(final)               # a leftover of an earlier failed try (never current: it's newer)
        os.replace(staging, final)
        ok, out = run_selftest(root, version, settings.data_dir)
        if not ok:
            rmtree(final)
            _log(settings, f"selftest of {version} failed:\n{out}")
            raise Refused(f"TacoGuard {version} failed its self-test, so nothing was changed. "
                          f"Details are in {Path(settings.log_dir) / 'selfupdate.log'}.")
        _switch_and_restart(settings, root, "update", old, version, old, shutdown, _server_pid,
                            _health_timeout)
        handed = True
        return {"ok": True, "restarting": True,
                "message": f"Installing TacoGuard {version}. The page restarts in a few seconds. If the new "
                           f"version doesn't start, TacoGuard goes back to {old} by itself."}
    except Refused as e:
        _log(settings, f"update to {version} refused: {e}")
        return _no(str(e))
    except Exception as e:
        _log(settings, f"update to {version} failed:\n{traceback.format_exc()}")
        return _no("The update could not be installed (details are in the TacoGuard log). Nothing was changed.")
    finally:
        rmtree(staging)
        if not handed:
            _release_lock(root)


def rollback(settings, shutdown=None, *, _server_pid: int | None = None,
             _health_timeout: float = HEALTH_TIMEOUT_S) -> dict:
    """ONLY after the user clicks: back to the previous installed version. Same shape and same
    watchdog as install_update."""
    if not running_from_install():
        return _no(NOT_INSTALLED_MSG)
    root = install_root()
    cur = read_current(root)
    if not cur:
        return _no("The installed copy is missing its version file; run the TacoGuard installer again.")
    old, prev = cur["version"], cur.get("previous")
    if not prev or not (root / "versions" / prev / "tacoguard").is_dir():
        return _no("There is no earlier version to go back to.")
    if _scan_active(settings):
        return _no(SCAN_MSG)
    if not _take_lock(root):
        return _no(BUSY_MSG)
    handed = False
    try:
        ok, out = run_selftest(root, prev, settings.data_dir)
        if not ok:
            _log(settings, f"selftest of {prev} failed:\n{out}")
            raise Refused(f"TacoGuard {prev} failed its self-test, so TacoGuard stays on {old}.")
        _switch_and_restart(settings, root, "rollback", old, prev, old, shutdown, _server_pid,
                            _health_timeout)
        handed = True
        return {"ok": True, "restarting": True,
                "message": f"Going back to TacoGuard {prev}. The page restarts in a few seconds."}
    except Refused as e:
        return _no(str(e))
    except Exception as e:
        _log(settings, f"rollback to {prev} failed:\n{traceback.format_exc()}")
        return _no("Could not go back (details are in the TacoGuard log). Nothing was changed.")
    finally:
        if not handed:
            _release_lock(root)


def status(settings, app_update=None) -> dict:
    """For the page; cheap, never raises.
    {"installed", "version", "current", "previous", "can_rollback", "busy", "update", "last_result",
     "message"}"""
    try:
        installed = running_from_install()
        root = install_root()
        cur = read_current(root) if installed else None
        prev = cur.get("previous") if cur else None
        can_rb = bool(installed and prev and (root / "versions" / prev / "tacoguard").is_dir())
        return {"installed": installed, "version": __version__,
                "current": cur["version"] if cur else None, "previous": prev, "can_rollback": can_rb,
                "busy": _busy(root) if installed else False, "update": available(settings, app_update),
                "last_result": last_result() if installed else None,
                "message": "" if installed else NOT_INSTALLED_MSG}
    except Exception as e:
        return {"installed": False, "version": __version__, "current": None, "previous": None,
                "can_rollback": False, "busy": False, "update": None, "last_result": None,
                "message": f"Could not read the update state ({plain_error(e)})."}


# ---------------------------------------------------------------------------------------------
# health: the new page says "started OK"
# ---------------------------------------------------------------------------------------------
def _listening_here(port: int) -> bool:
    import psutil
    try:
        for c in psutil.Process().net_connections(kind="tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port:
                return True
    except psutil.Error:
        pass
    return False


def report_health_when_up(settings, wait_s: float = 120.0) -> None:
    """Called by `serve` before the page starts. In the installed copy, a background thread waits
    until THIS process listens on the port and the page answers /api/ping, then writes
    health.json {"version", "pid", "port", "time", "nonce"}. Never raises."""
    try:
        if not running_from_install():
            return
        root = install_root()
        nonce = os.environ.get(NONCE_ENV, "")
        port = int(settings.port)
    except Exception:
        return

    def work():
        from .web.server import is_tacoguard_at
        deadline = time.time() + wait_s
        while time.time() < deadline:
            try:
                if _listening_here(port) and is_tacoguard_at(port, timeout=2.0):
                    write_json(root / HEALTH, {"version": __version__, "pid": os.getpid(), "port": port,
                                               "time": time.time(), "nonce": nonce})
                    return
            except Exception:
                pass
            time.sleep(0.5)

    threading.Thread(target=work, name="tacoguard-health", daemon=True).start()


# ---------------------------------------------------------------------------------------------
# the watchdog process
# ---------------------------------------------------------------------------------------------
def _server_cmd(root: Path, data: str, port: int) -> list[str]:
    return [str(venv_python(root, windowless=True)), "-m", "tacoguard", "--data", str(data), "serve",
            "--port", str(port), "--no-browser"]


def start_version(root: Path, version: str, data: str, port: int, nonce: str = "") -> subprocess.Popen:
    """Start the page of one installed version (what TacoGuard.pyw does), output to the log."""
    env = version_env(root, version)
    env[NONCE_ENV] = nonce
    return _spawn(_server_cmd(root, data, port), root / "versions" / version, env,
                  Path(data) / "logs" / "launcher.log")


def _kill_tree(proc: subprocess.Popen) -> None:
    import psutil
    try:
        p = psutil.Process(proc.pid)
        kids = p.children(recursive=True)
    except psutil.Error:
        kids = []
    for k in kids:
        try:
            k.kill()
        except psutil.Error:
            pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        pass


def _wait_exit(pid: int, wait_s: float, log) -> None:
    import psutil
    if not pid or pid == os.getpid():
        return
    try:
        p = psutil.Process(pid)
    except psutil.Error:
        return
    try:
        p.wait(wait_s)
        return
    except psutil.TimeoutExpired:
        pass
    except psutil.Error:
        return
    log(f"the old page (pid {pid}) did not close within {wait_s:.0f} s; stopping it")
    try:
        p.terminate()
        p.wait(10)
    except psutil.AccessDenied:
        # self-protection (tacoguard/selfprotect.py): without admin rights it can't be ended from
        # here; give it a little longer to close by itself
        log(f"the old page (pid {pid}) is protected and could not be ended; waiting {wait_s:.0f} s more")
        try:
            p.wait(wait_s)
        except psutil.Error:
            pass
    except psutil.Error:
        pass


PENDING_KEYS = ("pending", "pending_since", "pending_from", "pending_mode", "watchdog_pid")


def clear_pending(root: Path, version: str) -> None:
    """The new page answered: current.json loses its "pending" mark (see _switch_and_restart)."""
    cur = read_json(Path(root) / CURRENT)
    if cur and cur.get("version") == version and any(k in cur for k in PENDING_KEYS):
        write_json(Path(root) / CURRENT, {k: v for k, v in cur.items() if k not in PENDING_KEYS})


def _healthy(root: Path, version: str, nonce: str) -> bool:
    h = read_json(root / HEALTH) or {}
    return h.get("version") == version and h.get("nonce") == nonce


def watchdog(root: Path, data: str, port: int, mode: str, old: str, new: str, server_pid: int,
             timeout: float = HEALTH_TIMEOUT_S) -> int:
    root = Path(root)
    log_dir = Path(data) / "logs"

    def log(m):
        _log(log_dir, f"watchdog: {m}")

    try:
        _wait_exit(server_pid, SERVER_EXIT_WAIT_S, log)
        nonce = secrets.token_hex(16)
        log(f"starting {new} on port {port}")
        proc = start_version(root, new, data, port, nonce)
        deadline = time.time() + timeout
        healthy = False
        while time.time() < deadline:
            if _healthy(root, new, nonce):
                healthy = True
                break
            if proc.poll() is not None:          # it crashed or closed: not a working update
                log(f"{new} exited with code {proc.returncode} before it answered")
                break
            time.sleep(0.5)
        if healthy:
            log(f"{new} answered")
            clear_pending(root, new)
            if mode == "update":
                removed = prune_versions(root)
                if removed:
                    log("removed old versions: " + ", ".join(removed))
                _result(root, True, f"TacoGuard was updated to {new}.", **{"from": old, "to": new})
            else:
                _result(root, True, f"TacoGuard went back to {new}.", **{"from": old, "to": new})
            return 0
        # ---- it did not start: back to the old version --------------------------------------
        log(f"{new} did not start; going back to {old}")
        _kill_tree(proc)
        if mode == "update":
            write_current(root, old, previous_after_rollback(root, old), failed=new)
            rmtree(root / "versions" / new)
            message = f"The update didn't start, so TacoGuard went back to {old}."
        else:
            write_current(root, old, new, failed=new)
            message = f"TacoGuard {new} didn't start, so TacoGuard stayed on {old}."
        _result(root, False, message, **{"from": old, "to": new})
        nonce2 = secrets.token_hex(16)
        start_version(root, old, data, port, nonce2)
        end = time.time() + timeout
        while time.time() < end and not _healthy(root, old, nonce2):
            time.sleep(0.5)
        log(f"{old} {'answered' if _healthy(root, old, nonce2) else 'did not answer either'}")
        return 1
    except Exception:
        log("crashed:\n" + traceback.format_exc())
        return 2
    finally:
        _release_lock(root)
        try:
            (root / "update_state.json").unlink()
        except OSError:
            pass


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tacoguard.selfupdate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watchdog")
    w.add_argument("--root", required=True)
    w.add_argument("--data", required=True)
    w.add_argument("--port", type=int, required=True)
    w.add_argument("--mode", choices=("update", "rollback"), required=True)
    w.add_argument("--from", dest="old", required=True)
    w.add_argument("--to", dest="new", required=True)
    w.add_argument("--server-pid", type=int, default=0)
    w.add_argument("--timeout", type=float, default=HEALTH_TIMEOUT_S)
    a = ap.parse_args(argv)
    if not (valid_version(a.old) and valid_version(a.new)):
        return 2
    return watchdog(Path(a.root), a.data, a.port, a.mode, a.old, a.new, a.server_pid, a.timeout)


if __name__ == "__main__":
    sys.exit(_main())
