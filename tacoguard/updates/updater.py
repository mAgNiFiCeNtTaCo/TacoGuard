"""The background updater (CONTRACT in tacoguard/updates/__init__.py).

Components, checked one at a time in this order:
    clamav_signatures  ClamAV's freshclam on a STAGING copy of the signature folder (at most once an
                       hour; ClamAV's cool-downs are respected), sigtool + clamscan test-load
    yara_rules         YARA Forge (GitHub sha256 digest), license filter, compile test
    ml_model           TacoGuard's own signed package, test-loaded by detect.ml.self_test(folder)
    app                TacoGuard's own signed package, only downloaded + verified and RECORDED
                       (status()["app_update"]); installing is selfupdate.py's job, on a user click
    web_lists          Phase 4 bad-website lists (webblock.lists.refresh: checked + swapped there,
                       at most every 30 minutes per list whatever the cadence)

Game mode (phase4.game_mode(store)["active"]): the timed checks (at start and every
update_interval_h) wait until Game mode ends (looked at every GAME_MODE_RETRY_S, logged once per
wait), but after GAME_MODE_MAX_DEFER_S (24 h) of waiting they run anyway; a manual check_now()
still runs.

Files in settings.updates_dir:
    trusted.json        trusted root + last targets version (signed.py)
    status.json         what status() shows, kept across restarts
    journal.json        an unfinished swap (recover() finishes or undoes it)
    freshclam.json      last freshclam run and any cool-down (setup_fetch.py)
    staging/<name>/     a verified new set waiting to be swapped in; staging/<name>.ready.json
                        marks it complete (a folder without it is stale and removed at start)
    staging/downloads/  partial downloads (.part) that the next check resumes
    app/<version>.zip   a verified app update, waiting for the user
Swaps never happen while a scan job is queued or running (store.active_jobs()).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

from .. import __version__, config, setup_fetch
from . import signed, sources
from .signed import UpdateRejected

COMPONENTS = ("clamav_signatures", "yara_rules", "ml_model", "app", "web_lists")
STAGED_COMPONENTS = ("clamav_signatures", "yara_rules", "ml_model")   # swapped by this updater
LABELS = {"clamav_signatures": "ClamAV signatures", "yara_rules": "YARA rules",
          "ml_model": "machine-learning model", "app": "TacoGuard app", "web_lists": "website lists"}
MAX_ROOT_STEPS = 64
PENDING_POLL_S = 30
GAME_MODE_RETRY_S = 60
GAME_MODE_MAX_DEFER_S = 24 * 3600      # timed checks put off by Game mode run anyway after this
LOG_MAX = 1024 * 1024
ML_UNPACK_MAX = 1024**3
_LOG_LOCK = threading.Lock()


# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------

def version_key(text: str) -> tuple[int, ...]:
    """"0.2.0" -> (0, 2, 0), "2026.11.23" -> (2026, 11, 23); anything else -> ()."""
    return tuple(int(x) for x in re.findall(r"\d+", str(text or "")))


def _day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d") if epoch else "an unknown date"


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _rmtree(path: Path) -> None:
    if Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)


def log(settings, message: str) -> None:
    """One line in <data>\\logs\\updates.log (never raises)."""
    try:
        with _LOG_LOCK:
            path = Path(settings.log_dir) / "updates.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size > LOG_MAX:
                path.replace(path.with_name("updates.old.log"))
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")
    except Exception:
        pass


EXPIRED_MSG = ("TacoGuard's own update list has expired, so no new app or model updates are installed "
               "until a new release is published. Signatures and rules keep updating.")


def _rejected(e: UpdateRejected) -> tuple[str, str, str]:
    """(state, message, last_error) for a refused update. An expired list is not a sign of an
    attack: its own calm state "expired" (no warning banner). Everything else is "rejected"."""
    if getattr(e, "kind", "") == "expired":
        return "expired", EXPIRED_MSG, ""
    return "rejected", str(e), str(e)


def _plain(e: BaseException) -> str:
    if isinstance(e, (UpdateRejected, sources.SourceError, setup_fetch.FetchError)):
        return str(e)
    if isinstance(e, OSError):
        return (f"Could not write to the TacoGuard data folder ({e.strerror or e}). The set you have "
                "is kept.")
    return "Something unexpected went wrong (details are in the updates log). The set you have is kept."


# ---------------------------------------------------------------------------------------------
# Signed release metadata (shared with tools/release.py verify)
# ---------------------------------------------------------------------------------------------

def fetch_verified_targets(source, root: dict, last_version: int = 0, last_sha256: str = "",
                           now=None, root_files: list | None = None) -> tuple[dict, dict, bytes, bool]:
    """Follow root rotations in the source one version at a time, then verify targets.json.
    Returns (root, targets signed part, raw targets bytes, root_changed). root_files (optional
    list): gets the raw bytes of every root file that was verified, oldest first. Raises
    sources.SourceError (network / not published) or UpdateRejected."""
    source.refresh()
    start_root = root
    for _ in range(MAX_ROOT_STEPS):
        want = root["version"] + 1
        raw = source.fetch_bytes(f"root-{want}.json")
        if raw is None:
            latest = source.fetch_bytes("root.json")
            if latest is None:
                break
            try:
                latest_version = json.loads(latest.decode("utf-8"))["signed"]["version"]
            except (ValueError, KeyError, TypeError, AttributeError):
                latest_version = want              # let verify_root_update explain the damage
            if not isinstance(latest_version, int) or latest_version < want:
                break
            raw = latest                           # == want, or > want: refused as "skips"
        root = signed.verify_root_update(root, raw)
        if root_files is not None:
            root_files.append(raw)
    signed.check_root_fresh(root, now)
    root_changed = root["version"] != start_root["version"]
    if root_changed and signed.targets_keys_changed(start_root, root):
        last_version, last_sha256 = 0, ""
    raw_targets = source.fetch_bytes("targets.json")
    if raw_targets is None:
        raise UpdateRejected("The release has no signed update list (targets.json), so nothing "
                             "from it was used. Nothing was changed.")
    targets = signed.verify_targets(root, raw_targets, last_version, last_sha256, now)
    return root, targets, raw_targets, root_changed


def pick_target(targets: dict, kind: str, app_version: str = __version__) -> tuple[str, dict] | None:
    """(file name, entry) of the newest target of this kind that the running app may use
    (custom.min_app <= app_version)."""
    best = None
    running = version_key(app_version)
    for name, entry in targets.get("targets", {}).items():
        custom = entry.get("custom") or {}
        if custom.get("kind") != kind:
            continue
        if version_key(custom.get("min_app", "0")) > running:
            continue
        key = version_key(custom.get("version", ""))
        if best is None or key > best[0]:
            best = (key, name, entry)
    return (best[1], best[2]) if best else None


def needs_newer_app(targets: dict, kind: str, app_version: str = __version__) -> tuple[str, str] | None:
    """(version, min_app) of the newest target of this kind when pick_target skipped it because
    its custom.min_app is newer than the running app; None when nothing newer was skipped."""
    picked = pick_target(targets, kind, app_version)
    have = version_key(picked[1]["custom"].get("version", "")) if picked else ()
    running = version_key(app_version)
    best = None
    for entry in targets.get("targets", {}).values():
        custom = entry.get("custom") or {}
        if custom.get("kind") != kind or version_key(custom.get("min_app", "0")) <= running:
            continue
        key = version_key(custom.get("version", ""))
        if key > have and (best is None or key > best[0]):
            best = (key, str(custom.get("version", "")), str(custom.get("min_app", "")))
    return (best[1], best[2]) if best else None


def available_app(settings) -> dict | None:
    """The verified app update the updater recorded ({"version", "notes", "file", "sha256",
    "name"}) when its file is still there and newer than the running version; else None.
    For selfupdate.available(): it must verify the file again before installing."""
    info = _read_json(Path(settings.updates_dir) / "status.json").get("app_update")
    if not isinstance(info, dict) or not Path(str(info.get("file", ""))).is_file():
        return None
    if version_key(info.get("version", "")) <= version_key(__version__):
        return None
    return info


# ---------------------------------------------------------------------------------------------
# Updater
# ---------------------------------------------------------------------------------------------

class Updater:
    def __init__(self, settings, store, source=None):
        self.settings = settings
        self.store = store
        if source is None and os.environ.get("TACOGUARD_RELEASE_DIR"):
            # testing a release before it is published: a local folder with the same files. Not a
            # bypass: everything in it must still be signed by the trusted root's keys.
            source = sources.LocalFolderSource(Path(os.environ["TACOGUARD_RELEASE_DIR"]))
        self.source = source if source is not None else sources.GitHubReleaseSource(config.RELEASE_REPO)
        self.ml_self_test = None          # tests may set a callable(folder); default: detect.ml.self_test
        self.web_lists_refresh = None     # tests may set a callable(settings, store, progress) -> dict
        self._lock = threading.Lock()     # guards _status / _pending
        self._check_lock = threading.Lock()
        self._swap_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._recovered = False
        self._game_deferred_since = 0.0     # a timed check has waited for Game mode since then
        self._pending: dict[str, dict] = {}
        saved = _read_json(self._path("status.json"))
        comps = saved.get("components") if isinstance(saved.get("components"), dict) else {}
        self._status = {
            "checking": False,
            "last_check": float(saved.get("last_check") or 0),
            "next_check": 0.0,
            "message": "",
            "components": {n: {"version": "", "updated": 0.0, "state": "unknown", "message": "",
                               "last_error": "", **(comps.get(n) or {})} for n in COMPONENTS},
            "app_update": saved.get("app_update") if isinstance(saved.get("app_update"), dict) else None,
        }
        for comp in self._status["components"].values():
            if comp["state"] == "checking":
                comp["state"] = "unknown"
        self._refresh_versions()

    # ---- paths ---------------------------------------------------------------------------
    def _path(self, *parts) -> Path:
        return Path(self.settings.updates_dir).joinpath(*parts)

    @property
    def staging_dir(self) -> Path:
        return self._path("staging")

    @property
    def journal_path(self) -> Path:
        return self._path("journal.json")

    def _targets_of(self, name: str) -> tuple[Path, Path]:
        """(current, previous) folders a component's swap moves."""
        s = self.settings
        if name == "clamav_signatures":
            cur = Path(s.clamav_db_dir)
            return cur, cur.with_name(cur.name + ".previous")
        if name == "yara_rules":
            return Path(s.yara_dir) / "current", Path(s.yara_dir) / "previous"
        if name == "ml_model":
            return Path(s.ml_dir) / "current", Path(s.ml_dir) / "previous"
        raise ValueError(name)

    # ---- public API ----------------------------------------------------------------------
    def start(self, on_start: bool = True) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(on_start,), name="tacoguard-updater",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout)

    def check_now(self, wait: bool = False) -> None:
        """One check of every component. Never two at once: with wait=False a check that is
        already running is not doubled; with wait=True this waits for it, then checks."""
        if wait:
            self._check_all(blocking=True)
            return
        if self._check_lock.locked():
            return
        threading.Thread(target=self._thread_check, name="tacoguard-update-check", daemon=True).start()

    def status(self) -> dict:
        try:
            with self._lock:
                out = json.loads(json.dumps(self._status))
            out["checking"] = self._check_lock.locked() or out["checking"]
            return out
        except Exception:
            return {"checking": False, "last_check": 0, "next_check": 0, "message": "",
                    "components": {}, "app_update": None}

    def recover(self) -> list[str]:
        """At start: finish or undo a swap a crash interrupted, drop stale staging, and queue
        complete staged sets again. Returns plain notes (also logged)."""
        notes: list[str] = []
        with self._swap_lock:
            j = _read_json(self.journal_path)
            if j:
                notes.append(self._recover_journal(j))
            self.journal_path.unlink(missing_ok=True)
            notes += self._scan_staging()
            self._recovered = True
        for n in notes:
            log(self.settings, n)
        self._refresh_versions()
        self._save_status()
        return notes

    def apply_pending(self) -> list[str]:
        """Swap in every staged set, unless a scan is queued or running. Returns the names swapped."""
        done: list[str] = []
        with self._swap_lock:
            with self._lock:
                pending = dict(self._pending)
            for name, ready in pending.items():
                if self._scan_running():
                    self._set(name, state="waiting", message=ready["message_waiting"])
                    continue
                current, previous = self._targets_of(name)
                new = Path(ready["folder"])
                try:
                    self._swap(name, new, current, previous)
                except PermissionError:
                    self._set(name, state="waiting",
                              message=f"The update of the {LABELS[name]} is ready, but the files in "
                                      "use are locked right now. TacoGuard tries again shortly.")
                    continue
                except OSError as e:
                    self._drop_pending(name)
                    self._set(name, state="error", message=_plain(e), last_error=_plain(e))
                    log(self.settings, f"{name}: swap failed: {e!r}")
                    continue
                self._after_swap(name, ready)
                done.append(name)
        if done:
            self._refresh_versions()
            self._save_status()
        return done

    # ---- background thread ---------------------------------------------------------------
    def _interval_s(self) -> float:
        try:
            hours = float(self.settings.update_interval_h)
        except (TypeError, ValueError):
            hours = 4.0
        return max(1.0, min(24.0, hours)) * 3600

    def _run(self, on_start: bool) -> None:
        try:
            if not self._recovered:
                self.recover()
            if on_start and getattr(self.settings, "auto_update", True):
                if self._defer_for_game_mode():
                    pass
                else:
                    self._check_all(blocking=False)
            else:
                self._schedule_next()
            while not self._stop.is_set():
                auto = getattr(self.settings, "auto_update", True)
                with self._lock:
                    has_pending = bool(self._pending)
                    next_check = self._status["next_check"]
                if bool(auto) != bool(next_check):           # auto-update switched on or off
                    self._schedule_next()
                    with self._lock:
                        next_check = self._status["next_check"]
                wait = self._interval_s() if not next_check else max(1.0, next_check - time.time())
                if has_pending:
                    wait = min(wait, PENDING_POLL_S)
                self._wake.wait(wait)
                self._wake.clear()
                if self._stop.is_set():
                    break
                if has_pending:
                    self.apply_pending()
                if getattr(self.settings, "auto_update", True) and next_check and \
                        time.time() >= next_check:
                    if not self._defer_for_game_mode():
                        self._check_all(blocking=False)
        except Exception:
            log(self.settings, "updater thread stopped: " + traceback.format_exc())
        finally:
            self._close_store()

    def _thread_check(self) -> None:
        try:
            self._check_all(blocking=False)
        finally:
            self._close_store()

    def _close_store(self) -> None:
        try:
            self.store.close()            # this thread's own connection only
        except Exception:
            pass

    def _game_mode_active(self) -> bool:
        try:
            from .. import phase4
            return bool(phase4.game_mode(self.store)["active"])
        except Exception:
            return False

    def _defer_for_game_mode(self) -> bool:
        """A timed check is due. True when it waits for Game mode (looked at again every
        GAME_MODE_RETRY_S, logged once per wait); after GAME_MODE_MAX_DEFER_S of waiting it runs
        anyway (signatures must not get days old behind a Game mode left on)."""
        now = time.time()
        if not self._game_mode_active():
            if self._game_deferred_since:
                log(self.settings, "Game mode ended: the timed update check runs now")
            self._game_deferred_since = 0.0
            return False
        if not self._game_deferred_since:
            self._game_deferred_since = now
            log(self.settings, "Game mode is on: the timed update check waits until it ends")
        elif now - self._game_deferred_since >= GAME_MODE_MAX_DEFER_S:
            log(self.settings, "Game mode has been on for 24 hours: the timed update check runs anyway")
            self._game_deferred_since = 0.0
            return False
        with self._lock:
            self._status["next_check"] = now + GAME_MODE_RETRY_S
        return True

    def _schedule_next(self) -> None:
        with self._lock:
            auto = getattr(self.settings, "auto_update", True)
            base = self._status["last_check"] or time.time()
            self._status["next_check"] = base + self._interval_s() if auto else 0.0

    # ---- one check -----------------------------------------------------------------------
    def _check_all(self, blocking: bool) -> None:
        if not self._check_lock.acquire(blocking=blocking):
            return
        try:
            if not self._recovered:
                self.recover()
            with self._lock:
                self._status["checking"] = True
            try:
                self.settings.ensure_dirs()
            except OSError as e:
                for n in COMPONENTS:
                    self._set(n, state="error", message=_plain(e), last_error=_plain(e))
                return
            for name, step in (("clamav_signatures", self._check_clamav),
                               ("yara_rules", self._check_yara)):
                self._guard(name, step)
            self._check_own_channel()
            self._guard("web_lists", self._check_web_lists)
            with self._lock:
                self._status["last_check"] = time.time()
            self.apply_pending()
        finally:
            with self._lock:
                self._status["checking"] = False
                self._status["message"] = self._summary()
            self._schedule_next()
            self._refresh_versions()
            self._save_status()
            self._check_lock.release()

    def _guard(self, name: str, step, *args) -> None:
        self._set(name, state="checking", message=f"Checking for new {LABELS[name]}...")
        try:
            step(*args)
        except Exception as e:
            msg = _plain(e)
            if isinstance(e, UpdateRejected):              # "rejected": the page shows a banner
                state, shown, last_error = _rejected(e)
            else:
                state, shown, last_error = "error", msg, msg
            self._set(name, state=state, message=shown, last_error=last_error)
            log(self.settings, f"{name}: {msg}\n{traceback.format_exc()}")

    def _progress(self, name: str):
        def progress(msg: str) -> None:
            self._set(name, message=msg)
            log(self.settings, f"{name}: {msg}")
        return progress

    def _summary(self) -> str:
        comps = self._status["components"]
        if all(comps[n]["state"] == "offline" for n in ("clamav_signatures", "yara_rules")):
            return comps["clamav_signatures"]["message"]
        return ""

    # ---- ClamAV ---------------------------------------------------------------------------
    def _clamav_words(self) -> tuple[str, str]:
        """(plain description of the signatures in use, their date)"""
        from ..detect.clamav import database_info, describe_databases
        info = database_info(Path(self.settings.clamav_db_dir))
        daily = info.get("daily") or {}
        when = daily.get("stime") or daily.get("mtime") or 0
        return describe_databases(info), (_day(when) if info else "")

    def _check_clamav(self) -> None:
        name = "clamav_signatures"
        s = self.settings
        prog = Path(s.clamav_program_dir)
        words, day = self._clamav_words()
        if not (prog / "freshclam.exe").exists():
            self._set(name, state="not_installed",
                      message="The ClamAV program is not installed yet: press Get signatures.")
            return
        if name in self._pending:
            self._set(name, state="waiting", message=self._pending[name]["message_waiting"])
            return
        retry_at, why = setup_fetch.freshclam_wait(s)
        if retry_at:
            self._set(name, state="ok", message=f"{words} {why}")
            return
        stage = self.staging_dir / name
        _rmtree(stage)
        current = Path(s.clamav_db_dir)
        try:
            if current.is_dir():
                shutil.copytree(current, stage)
            else:
                stage.mkdir(parents=True)
            before, after = setup_fetch.run_freshclam(s, stage, self._progress(name))
        except setup_fetch.FetchError as e:
            _rmtree(stage)
            if e.kind == "offline":
                msg = (f"No internet: using signatures from {day}." if day else
                       "No internet: ClamAV signatures have not been downloaded yet.")
                self._set(name, state="offline", message=msg)
            elif e.kind in ("rate_limit", "blocked"):
                self._set(name, state="rate_limited", message=str(e), last_error=str(e))
            elif e.kind == "too_soon":
                self._set(name, state="ok", message=f"{words} {e}")
            else:
                raise
            log(s, f"{name}: {e}")
            return
        except BaseException:
            _rmtree(stage)
            raise
        from ..detect.clamav import database_version, describe_databases
        if current.is_dir() and not setup_fetch.databases_changed(before, after):
            _rmtree(stage)
            self._set(name, state="ok", message=f"{words} Up to date.", last_error="")
            return
        try:
            self._progress(name)("Checking the new ClamAV signatures with ClamAV's sigtool...")
            setup_fetch.verify_databases(prog, stage, after)
            self._progress(name)("Test-loading the new ClamAV signatures...")
            if not setup_fetch.clamscan_test(s, stage):
                log(s, f"{name}: clamscan.exe not found, the clamscan test-load was skipped")
        except BaseException:
            _rmtree(stage)
            raise
        new_words = describe_databases(after)
        self._stage_ready(name, stage, version=database_version(after),
                          message=f"{new_words} Signatures verified by ClamAV.")

    # ---- YARA -----------------------------------------------------------------------------
    def _check_yara(self) -> None:
        from ..detect import yara_rules
        name = "yara_rules"
        s = self.settings
        meta = yara_rules.read_meta(Path(s.yara_dir) / "current")
        day = (meta.get("published") or "")[:10] or (meta.get("installed") or "")[:10]
        try:
            release = setup_fetch.yara_latest_release()
        except setup_fetch.FetchError as e:
            if e.kind == "offline":
                self._set(name, state="offline",
                          message=f"No internet: using YARA rules from {day}." if day else
                          "No internet: YARA rules have not been downloaded yet.")
                return
            raise
        if setup_fetch.yara_is_current(s, release):
            self._set(name, state="ok", message=f"YARA Forge rules {release['tag']} are the newest.",
                      last_error="")
            return
        pending = self._pending.get(name)
        if pending and pending.get("version") == release["tag"]:
            self._set(name, state="waiting", message=pending["message_waiting"])
            return
        stage = self.staging_dir / name
        self._drop_pending(name)
        new_meta = setup_fetch.stage_yara_rules(s, release, stage, self._progress(name))
        self._stage_ready(name, stage, version=release["tag"],
                          message=setup_fetch.yara_installed_words(new_meta))

    # ---- website lists (Phase 4) -------------------------------------------------------------
    def _check_web_lists(self) -> None:
        """webblock.lists.refresh checks and swaps the lists itself (it never raises); this maps its
        answer to the component's state: ok | offline | error | off."""
        name = "web_lists"
        if not getattr(self.settings, "webblock_enabled", True):
            self._set(name, state="off", message="Website blocking is turned off in Settings.",
                      last_error="")
            return
        refresh = self.web_lists_refresh
        if refresh is None:
            from ..webblock import lists as web_lists
            refresh = web_lists.refresh
        res = refresh(self.settings, self.store, self._progress(name)) or {}
        if res.get("busy"):
            # the page's "Update the lists now" (or another TacoGuard process) is doing it right now
            self._set(name, message=str(res.get("message") or ""))
            return
        sources = {k: v for k, v in (res.get("sources") or {}).items() if isinstance(v, dict)}
        active = [v for v in sources.values() if v.get("state") not in ("off", "no_key")]
        message = str(res.get("message") or "")
        total = sum(int(v.get("count") or 0) for v in sources.values() if v.get("state") != "off")
        version = f"{total:,} sites" if total else ""
        if active and all(v.get("state") == "offline" for v in active):
            state, last_error = "offline", ""
        elif any(v.get("state") in ("error", "refused") for v in active) or res.get("ok") is False:
            state, last_error = "error", message
        elif not active:
            state, last_error = "off", ""
        else:
            state, last_error = "ok", ""
        extra = {"updated": time.time()} if res.get("changed") else {}
        self._set(name, state=state, message=message, last_error=last_error, version=version, **extra)

    # ---- TacoGuard's own channel (ML model + app) ----------------------------------------
    def _check_own_channel(self) -> None:
        for n in ("ml_model", "app"):
            self._set(n, state="checking", message=f"Checking for a new {LABELS[n]}...")
        try:
            targets = self._verified_targets()
        except sources.SourceError as e:
            if e.kind == "not_published":
                for n in ("ml_model", "app"):
                    self._set(n, state="not_published", message=str(e), last_error="")
            elif e.kind == "offline":
                ml = self._status["components"]["ml_model"]
                self._set("ml_model", state="offline",
                          message=f"No internet: using the machine-learning model from "
                                  f"{_day(ml['updated'])}." if ml["version"] else
                          "No internet: no machine-learning model has been downloaded yet.")
                self._set("app", state="offline",
                          message="No internet: could not check for a new TacoGuard version.")
            else:
                for n in ("ml_model", "app"):
                    self._set(n, state="error", message=str(e), last_error=str(e))
            log(self.settings, f"own channel: {e}")
            return
        except signed.NoTrustedRoot as e:
            for n in ("ml_model", "app"):
                self._set(n, state="not_published", message=str(e), last_error="")
            return
        except UpdateRejected as e:
            state, shown, last_error = _rejected(e)
            for n in ("ml_model", "app"):
                self._set(n, state=state, message=shown, last_error=last_error)
            log(self.settings, f"own channel {state} ({getattr(e, 'kind', '')}): {e}")
            return
        except Exception as e:
            for n in ("ml_model", "app"):
                self._set(n, state="error", message=_plain(e), last_error=_plain(e))
            log(self.settings, "own channel: " + traceback.format_exc())
            return
        self._guard("ml_model", self._check_ml, targets)
        self._guard("app", self._check_app, targets)

    def _verified_targets(self) -> dict:
        root = signed.load_trusted_root(self.settings)
        state = signed.load_state(self.settings)
        walked: list[bytes] = []
        root, targets, raw, _changed = fetch_verified_targets(
            self.source, root, int(state.get("targets_version") or 0),
            str(state.get("targets_sha256") or ""), root_files=walked)
        signed.remember(self.settings, root, targets, raw, root_files=walked)
        return targets

    def _download_target(self, name: str, entry: dict, dest: Path, comp: str) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            try:
                signed.verify_file(dest, entry)
                return dest
            except UpdateRejected:
                dest.unlink()
        self.source.download(name, dest, entry, self._progress(comp))
        try:
            signed.verify_file(dest, entry)
        except UpdateRejected:
            dest.unlink(missing_ok=True)
            raise
        return dest

    def _check_ml(self, targets: dict) -> None:
        name = "ml_model"
        picked = pick_target(targets, "ml_model")
        have = self._status["components"][name]["version"]
        blocked = needs_newer_app(targets, "ml_model")
        if blocked and have and version_key(blocked[0]) <= version_key(have):
            blocked = None
        blocked_msg = (f"A newer machine-learning model is available but needs TacoGuard {blocked[1]}; "
                       "install the app update first.") if blocked else ""
        if picked is None:
            self._set(name, state="ok", last_error="",
                      message=blocked_msg or ("The machine-learning model is up to date." if have else
                                              "No machine-learning model has been published yet."))
            return
        file_name, entry = picked
        version = entry["custom"].get("version", "")
        if have and version_key(version) <= version_key(have):
            self._set(name, state="ok", last_error="",
                      message=blocked_msg or f"The machine-learning model {have} is the newest.")
            return
        pending = self._pending.get(name)
        if pending and pending.get("version") == version:
            self._set(name, state="waiting", message=pending["message_waiting"])
            return
        self._drop_pending(name)
        zip_path = self._download_target(file_name, entry, self.staging_dir / "downloads" / file_name, name)
        stage = self.staging_dir / name
        _rmtree(stage)
        try:
            setup_fetch.safe_unzip(zip_path, stage, max_total=ML_UNPACK_MAX)
            _flatten(stage)
            self._progress(name)("Test-loading the new machine-learning model...")
            self._run_ml_self_test(stage)
        except BaseException:
            _rmtree(stage)
            raise
        zip_path.unlink(missing_ok=True)
        notes = entry["custom"].get("notes", "")
        self._stage_ready(name, stage, version=version,
                          message=f"Machine-learning model {version} installed."
                                  + (f" {notes}" if notes else ""),
                          extra={"sha256": entry["sha256"], "file": file_name})

    def _run_ml_self_test(self, folder: Path) -> None:
        test = self.ml_self_test
        if test is None:
            try:
                from ..detect import ml
                test = getattr(ml, "self_test", None)
            except Exception as e:
                log(self.settings, f"ml_model: the ML module could not be loaded ({e!r}); "
                                   "the test-load was skipped")
                return
            if test is None:
                log(self.settings, "ml_model: detect.ml.self_test does not exist yet; "
                                   "the test-load was skipped")
                return
        try:
            test(folder)
        except Exception as e:
            first = str(e).splitlines()[0] if str(e) else type(e).__name__
            raise UpdateRejected(f"The new machine-learning model did not pass its test-load "
                                 f"({first}), so the model you have is kept.", "test") from e

    def _check_app(self, targets: dict) -> None:
        name = "app"
        picked = pick_target(targets, "app")
        running = __version__
        if picked is None or version_key(picked[1]["custom"].get("version", "")) <= version_key(running):
            with self._lock:
                self._status["app_update"] = None
            blocked = needs_newer_app(targets, "app")
            if blocked and version_key(blocked[0]) > version_key(running):
                self._set(name, state="ok", last_error="",
                          message=f"TacoGuard {blocked[0]} is available but needs TacoGuard {blocked[1]} "
                                  "or newer first; run the TacoGuard installer again to get it.")
                return
            self._set(name, state="ok", last_error="",
                      message=f"TacoGuard {running} is the newest version.")
            return
        file_name, entry = picked
        version = entry["custom"]["version"]
        safe_version = re.sub(r"[^0-9A-Za-z.\-]", "_", version)
        app_dir = self._path("app")
        dest = self._download_target(file_name, entry, app_dir / f"{safe_version}.zip", name)
        for old in app_dir.glob("*.zip"):
            if old != dest:
                old.unlink(missing_ok=True)
        notes = entry["custom"].get("notes", "")
        with self._lock:
            self._status["app_update"] = {"version": version, "notes": notes, "file": str(dest),
                                          "sha256": entry["sha256"], "name": file_name}
        self._set(name, state="available", last_error="",
                  message=f"TacoGuard {version} is ready to install (you have {running})."
                          + (f" {notes}" if notes else ""))

    # ---- staging and swapping -------------------------------------------------------------
    def _ready_path(self, name: str) -> Path:
        return self.staging_dir / f"{name}.ready.json"

    def _stage_ready(self, name: str, folder: Path, version: str, message: str,
                     extra: dict | None = None) -> None:
        ready = {"component": name, "folder": str(folder), "version": version, "message": message,
                 "message_waiting": f"An update of the {LABELS[name]} ({version}) is downloaded and "
                                    "verified; it is switched on as soon as no scan is running.",
                 "staged": time.time(), **(extra or {})}
        signed.write_json_atomic(self._ready_path(name), ready)
        with self._lock:
            self._pending[name] = ready
        self._set(name, state="waiting", message=ready["message_waiting"])
        log(self.settings, f"{name}: staged {version}")

    def _drop_pending(self, name: str) -> None:
        with self._lock:
            self._pending.pop(name, None)
        self._ready_path(name).unlink(missing_ok=True)
        _rmtree(self.staging_dir / name)

    def _scan_running(self) -> bool:
        try:
            return bool(self.store.active_jobs())
        except Exception as e:
            log(self.settings, f"could not read the scan list ({e!r}); swap postponed")
            return True

    def _swap(self, name: str, new: Path, current: Path, previous: Path) -> None:
        """current -> previous, new -> current, with a journal so a crash at any point is finished
        or undone by recover()."""
        trash = previous.with_name(previous.name + ".trash")
        journal = {"component": name, "new": str(new), "current": str(current),
                   "previous": str(previous), "trash": str(trash), "step": "begin",
                   "started": time.time()}
        signed.write_json_atomic(self.journal_path, journal)
        _rmtree(trash)
        if previous.exists():
            os.replace(previous, trash)
        journal["step"] = "moving"
        signed.write_json_atomic(self.journal_path, journal)
        had_current = current.exists()
        current.parent.mkdir(parents=True, exist_ok=True)
        if had_current:
            try:
                os.replace(current, previous)
            except OSError:
                if trash.exists() and not previous.exists():
                    os.replace(trash, previous)
                self.journal_path.unlink(missing_ok=True)
                raise
        try:
            os.replace(new, current)
        except OSError:
            if had_current and previous.exists() and not current.exists():
                os.replace(previous, current)
                if trash.exists():
                    os.replace(trash, previous)
            self.journal_path.unlink(missing_ok=True)
            raise
        self.journal_path.unlink(missing_ok=True)
        _rmtree(trash)

    def _after_swap(self, name: str, ready: dict) -> None:
        with self._lock:
            self._pending.pop(name, None)
        self._ready_path(name).unlink(missing_ok=True)
        extra = {"version": ready.get("version", "")} if name == "ml_model" else {}
        if name == "ml_model":
            extra["updated"] = time.time()
        self._set(name, state="ok", message=ready["message"], last_error="", **extra)
        log(self.settings, f"{name}: switched to {ready.get('version')}")

    def _recover_journal(self, j: dict) -> str:
        name = str(j.get("component", "?"))
        new, current = Path(j.get("new", "")), Path(j.get("current", ""))
        previous, trash = Path(j.get("previous", "")), Path(j.get("trash", ""))
        label = LABELS.get(name, name)
        if not all(str(p) not in ("", ".") for p in (new, current, previous, trash)):
            return "An unreadable update journal was removed."
        if new.exists() and not current.exists():
            os.replace(new, current)               # the new set was verified before the swap began
            _rmtree(trash)
            ready = _read_json(self._ready_path(name))
            if ready:
                self._after_swap(name, ready)
            return f"An interrupted update of the {label} was finished."
        if not new.exists() and not current.exists() and previous.exists():
            os.replace(previous, current)
            if trash.exists():
                os.replace(trash, previous)
            return f"An interrupted update of the {label} was undone; the previous set is back."
        if current.exists() and new.exists():
            if trash.exists() and not previous.exists():
                os.replace(trash, previous)
            _rmtree(trash)
            return f"An interrupted update of the {label} was undone before anything moved."
        _rmtree(trash)
        if current.exists():
            self._ready_path(name).unlink(missing_ok=True)
        return f"An interrupted update of the {label} had already finished."

    def _scan_staging(self) -> list[str]:
        notes = []
        stage = self.staging_dir
        if not stage.is_dir():
            return notes
        for child in list(stage.iterdir()):
            if child.name == "downloads":
                for f in child.iterdir():          # keep .part files for resuming; drop the rest
                    if f.is_dir():
                        _rmtree(f)
                    elif not f.name.endswith(".part"):
                        f.unlink(missing_ok=True)
                continue
            if child.suffix == ".json" and child.name.endswith(".ready.json"):
                comp = child.name[: -len(".ready.json")]
                ready = _read_json(child)
                folder = Path(str(ready.get("folder", "")))
                if comp in STAGED_COMPONENTS and ready and folder.is_dir() and \
                        folder.parent == stage:
                    with self._lock:
                        self._pending[comp] = ready
                    self._set(comp, state="waiting", message=ready.get("message_waiting", ""))
                    notes.append(f"An update of the {LABELS[comp]} was ready from before; it is "
                                 "switched on when no scan is running.")
                else:
                    child.unlink(missing_ok=True)
                continue
        for child in list(stage.iterdir()):
            if child.is_dir() and child.name != "downloads" and child.name not in self._pending:
                _rmtree(child)
                notes.append(f"Removed an unfinished download ({child.name}).")
            elif child.is_file() and not child.name.endswith(".ready.json"):
                child.unlink(missing_ok=True)
        return notes

    # ---- status bookkeeping ----------------------------------------------------------------
    def _set(self, name: str, **fields) -> None:
        with self._lock:
            self._status["components"][name].update(fields)

    def _refresh_versions(self) -> None:
        """The versions and dates of the sets in use, from disk (cheap: headers and meta files)."""
        try:
            from ..detect.clamav import database_info, database_version
            info = database_info(Path(self.settings.clamav_db_dir))
            daily = info.get("daily") or {}
            self._set("clamav_signatures", version=database_version(info) if info else "",
                      updated=float(daily.get("stime") or daily.get("mtime") or 0))
        except Exception:
            pass
        try:
            from ..detect import yara_rules
            cur = Path(self.settings.yara_dir) / "current"
            meta = yara_rules.read_meta(cur)
            updated = (cur / yara_rules.META_NAME).stat().st_mtime if meta else 0.0
            self._set("yara_rules", version=str(meta.get("release", "")), updated=updated)
        except Exception:
            pass
        cur_ml, _ = self._targets_of("ml_model")
        if not cur_ml.is_dir():
            self._set("ml_model", version="", updated=0.0)
        self._set("app", version=__version__)

    def _save_status(self) -> None:
        try:
            with self._lock:
                data = {"last_check": self._status["last_check"],
                        "components": self._status["components"],
                        "app_update": self._status["app_update"]}
                signed.write_json_atomic(self._path("status.json"), data)
        except Exception as e:
            log(self.settings, f"could not save the update status: {e!r}")


def _flatten(folder: Path) -> None:
    """A package zipped with one top folder: lift its contents up."""
    entries = list(folder.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for child in inner.iterdir():
            os.replace(child, folder / child.name)
        inner.rmdir()
