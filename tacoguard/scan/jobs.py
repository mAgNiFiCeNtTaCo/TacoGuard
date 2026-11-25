"""Scan jobs, as the page and the command line use them.

CONTRACT (Helper A fills this in; signatures must stay):

    start_scan(settings, store, targets: list[str]) -> int
        Validate targets (each an existing file, folder or drive root like "D:\\"), create the job,
        start the low-priority worker process, return the job id. Raises ValueError with a
        plain-English message for a bad target.
    pause_scan(store, job_id)   -> None    asks the worker to stop after the current file (resumable)
    cancel_scan(store, job_id)  -> None    asks the worker to stop for good
    resume_scan(settings, store, job_id) -> None   restart a paused/interrupted job from its checkpoint
    recover_interrupted(store) -> list[int]
        Called at start-up: jobs marked running/queued whose worker is gone (stale heartbeat or dead
        pid) become 'interrupted' (resumable). Returns their ids.
    run_job_inline(settings, store, job_id, detectors=None) -> None
        Runs a job in THIS process (used by the worker itself, the CLI and tests). `detectors`
        defaults to tacoguard.detect.load_detectors(settings, store).

Only one job runs at a time. A second start_scan leaves its job 'queued'; the worker starts the
next queued job itself when it finishes (start_next_queued).
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from .. import winpath
from . import walker

HEARTBEAT_S = 5
STALE_S = 30
INTERRUPTED_MSG = "Stopped when the app closed. Press Resume to carry on."
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def start_scan(settings, store, targets: list[str]) -> int:
    clean = _validate(targets)
    job_id = store.create_job(clean)
    if not start_next_queued(settings, store):
        store.update_job(job_id, message="Waiting for the scan before it to finish.")
    return job_id


def _validate(targets: list[str]) -> list[str]:
    targets = [t for t in (targets or []) if str(t).strip()]
    if not targets:
        raise ValueError("Pick at least one file, folder or drive to scan.")
    out = []
    for t in targets:
        disp = walker.normalize_target(t)
        if not os.path.exists(winpath.to_long(disp)):
            raise ValueError(f"Not found: {str(t).strip()}. Check the spelling, or that the drive is plugged in.")
        out.append(disp)
    return out


def pause_scan(store, job_id: int) -> None:
    store.set_control(job_id, "pause")
    _set_if(store, job_id, ("queued",), "paused", "Paused before it started. Press Resume to start it.")


def cancel_scan(store, job_id: int) -> None:
    store.set_control(job_id, "cancel")
    _set_if(store, job_id, ("queued", "paused", "interrupted"), "cancelled", "Cancelled.")


def resume_scan(settings, store, job_id: int) -> None:
    job = store.get_job(job_id)
    if job is None:
        raise ValueError("That scan no longer exists.")
    if job["status"] not in ("paused", "interrupted"):
        raise ValueError(f"This scan cannot be resumed (it is {job['status']}).")
    store.update_job(job_id, status="queued", control="", pid=0, message="Waiting to resume.")
    start_next_queued(settings, store)


def recover_interrupted(store) -> list[int]:
    """Running jobs whose worker is gone become 'interrupted'. Queued jobs too, unless a live
    worker is still running (it will start them when it finishes)."""
    ids, live = [], False
    for job in store.active_jobs():
        if job["status"] == "running":
            if _worker_alive(job):
                live = True
                continue
            ids.append(job["id"])
    if not live:
        ids += [j["id"] for j in store.active_jobs() if j["status"] == "queued"]
    for job_id in ids:
        store.update_job(job_id, status="interrupted", current="", message=INTERRUPTED_MSG)
    return ids


def _worker_alive(job: dict) -> bool:
    """A fresh heartbeat with a living pid is alive. A stale heartbeat is alive too when the pid
    is still this job's own worker: a busy PC can starve a low-priority worker for a long time,
    and calling that 'interrupted' would start a second worker on the same job. Only a dead pid,
    or a pid Windows has since given to another program, makes the job interrupted."""
    fresh = time.time() - (job["heartbeat"] or 0) <= STALE_S
    if not job["pid"]:
        return fresh    # just claimed, the worker is starting
    import psutil
    if fresh:
        return psutil.pid_exists(job["pid"])
    return is_job_worker(job["pid"], job["id"], job["heartbeat"] or job["started"] or 0)


def is_job_worker(pid: int, job_id: int, seen_at: float) -> bool:
    """True when `pid` is the scan worker for this job: its command line names the worker and
    the job, and it was started before `seen_at` (the job's last sign of life), so it is not a
    newer process that happens to have been given the same number."""
    import psutil
    try:
        proc = psutil.Process(pid)
        cmd = proc.cmdline()
        created = proc.create_time()
    except psutil.Error:
        return False
    if "tacoguard.scan.worker" not in cmd:
        return False
    try:
        if int(cmd[cmd.index("--job") + 1]) != int(job_id):
            return False
    except (ValueError, IndexError):
        return False
    return created <= (seen_at or 0) + 2.0   # small slack: clocks are read at different moments


def _set_if(store, job_id: int, statuses: tuple[str, ...], status: str, message: str) -> None:
    # One statement so it cannot race with a worker claiming the job.
    q = ",".join("?" * len(statuses))
    store._con().execute(
        f"UPDATE jobs SET status=?, message=?, control='', finished=? WHERE id=? AND status IN ({q})",
        (status, message, time.time(), job_id, *statuses))


def _claim_next(store) -> int | None:
    """Marks the oldest queued job 'running', but only if no job runs now. Atomic in SQLite."""
    row = store._con().execute(
        "UPDATE jobs SET status='running', pid=0, heartbeat=?, message='Starting...' "
        "WHERE id=(SELECT id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1) "
        "AND NOT EXISTS (SELECT 1 FROM jobs WHERE status='running') RETURNING id",
        (time.time(),)).fetchone()
    return int(row[0]) if row else None


def _clear_dead_running(store) -> None:
    for job in store.active_jobs():
        if job["status"] == "running" and not _worker_alive(job):
            store.update_job(job["id"], status="interrupted", current="", message=INTERRUPTED_MSG)


def start_next_queued(settings, store) -> int | None:
    """Starts the worker for the oldest queued job when nothing is running. Returns its id."""
    _clear_dead_running(store)
    job_id = _claim_next(store)
    if job_id is not None:
        try:
            proc = launch_worker(settings, job_id)
        except OSError as e:
            store.update_job(job_id, status="failed", finished=time.time(),
                             message=f"Could not start the scan ({e.strerror or e}).")
            return None
        store.update_job(job_id, pid=proc.pid, heartbeat=time.time())
    return job_id


def launch_worker(settings, job_id: int) -> subprocess.Popen:
    """Starts `python -m tacoguard.scan.worker` without a console window."""
    cmd = [sys.executable, "-m", "tacoguard.scan.worker", "--data", str(settings.data_dir),
           "--job", str(job_id)]
    return subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                            creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)


def run_job_inline(settings, store, job_id: int, detectors=None) -> None:
    from . import engine

    stop = threading.Event()
    beat = threading.Thread(target=_heartbeat, args=(store, job_id, stop), daemon=True)
    beat.start()
    try:
        if detectors is None:
            from ..detect import load_detectors
            detectors = load_detectors(settings, store)
        engine.scan_job(settings, store, job_id, detectors)
    except Exception:
        log = write_crash_log(settings, job_id)
        store.update_job(job_id, status="failed", finished=time.time(), current="",
                         message=f"The scan stopped because of an unexpected problem. Details: {log}")
    finally:
        stop.set()
        beat.join(timeout=2)


def _heartbeat(store, job_id: int, stop: threading.Event) -> None:
    """Keeps the heartbeat fresh while one big file takes a long time to check."""
    try:
        while not stop.wait(HEARTBEAT_S):
            store.update_job(job_id, heartbeat=time.time())
    except Exception:
        pass
    finally:
        store.close()   # this thread's own connection


def write_crash_log(settings, job_id: int) -> str:
    try:
        log_dir = Path(settings.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        path = log_dir / f"scan-{job_id}-{time.strftime('%Y%m%d-%H%M%S')}.log"
        path.write_text(traceback.format_exc(), encoding="utf-8")
        return str(path)
    except OSError:
        return "(the log could not be written)"
