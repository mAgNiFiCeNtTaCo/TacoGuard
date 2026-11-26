"""The scan worker: a separate, low-priority process that runs one job, then starts the next queued one.

    python -m tacoguard.scan.worker --data DIR --job N

The worker runs at low priority (lower_priority) and inside a Windows job object that caps its
memory at 2 GB (limit_memory); programs it starts leave that job. Phase 4: with
settings.self_protection it hardens itself (tacoguard/selfprotect.py): other programs without
admin rights can't end or pause it; Pause / Cancel go through the store as before.

TEST ONLY: the environment variable TACOGUARD_TEST_DETECTORS=<module>:<function> makes the worker
use fake detectors from function(settings, store) instead of the real ones. Nothing else reads it,
and the app never sets it.
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
import time

TEST_DETECTORS_ENV = "TACOGUARD_TEST_DETECTORS"


def lower_priority(mode: str = "idle") -> str:
    """'idle': idle CPU priority (the scan only gets CPU time nobody else wants) and low disk
    priority. 'below_normal': below-normal CPU and low disk priority.

    Windows "background mode" is not used: it also lowers memory priority, and the scan then
    pages so heavily that it ran about 60 times slower. Programs the worker starts afterwards
    (clamd) are put at the same priority by their detector. Returns what was applied:
    'idle', 'below_normal' or 'normal' (Windows refused)."""
    try:
        import psutil
        p = psutil.Process()
        if mode == "below_normal":
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            applied = "below_normal"
        else:
            p.nice(psutil.IDLE_PRIORITY_CLASS)
            applied = "idle"
    except Exception:
        return "normal"
    try:
        p.ionice(psutil.IOPRIO_LOW)
    except Exception:
        pass        # CPU priority is the part that matters most; keep it
    return applied


MEMORY_LIMIT = 2 * 1024**3
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

_memory_job = []   # keeps the job handle open for the life of the process


def limit_memory(limit: int = MEMORY_LIMIT) -> bool:
    """Puts this process in a Windows job object that caps its memory at `limit` bytes. A
    runaway allocation (a hostile archive) then fails with MemoryError in this worker instead
    of slowing the whole PC down; the engine notes that file and carries on.

    Programs this worker starts (clamd, tar.exe) silently leave the job, so the cap is not
    theirs: clamd sits in its own kill-on-close job and needs over 1 GB for its signatures.
    Returns False when Windows refused (the scan then runs without the cap)."""
    try:
        import ctypes
        from ctypes import wintypes

        class _Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _Basic), ("IoInfo", ctypes.c_ulonglong * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return False
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_PROCESS_MEMORY
                                                 | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
        info.ProcessMemoryLimit = int(limit)
        if not (k32.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                            ctypes.byref(info), ctypes.sizeof(info))
                and k32.AssignProcessToJobObject(job, k32.GetCurrentProcess())):
            k32.CloseHandle(job)
            return False
        _memory_job.append(job)
        return True
    except Exception:
        return False


def _test_detectors(settings, store):
    spec = os.environ.get(TEST_DETECTORS_ENV, "")
    if not spec:
        return None
    module, _, func = spec.partition(":")
    return getattr(importlib.import_module(module), func)(settings, store)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tacoguard.scan.worker")
    ap.add_argument("--data", required=True)
    ap.add_argument("--job", type=int, required=True)
    args = ap.parse_args(argv)

    from ..config import load_settings
    from ..store import Store
    from . import jobs

    settings = load_settings(args.data)
    lower_priority(settings.scan_priority)
    limit_memory()
    try:
        from ..selfprotect import maybe_harden     # Phase 4: only admins may end / change it
        maybe_harden(settings)
    except Exception:
        pass
    store = Store(settings.db_path)
    store.update_job(args.job, pid=os.getpid(), heartbeat=time.time())
    try:
        jobs.run_job_inline(settings, store, args.job, _test_detectors(settings, store))
    except BaseException:
        log = jobs.write_crash_log(settings, args.job)
        store.update_job(args.job, status="failed", finished=time.time(), current="",
                         message=f"The scan stopped because of an unexpected problem. Details: {log}")
        return 1
    finally:
        try:
            jobs.start_next_queued(settings, store)
        except Exception:
            jobs.write_crash_log(settings, 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
