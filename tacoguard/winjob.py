"""Helper programs that die with TacoGuard.

A Windows job object with KILL_ON_JOB_CLOSE holds a helper program (clamd.exe, tar.exe). The
job's handle lives in our process: when our process ends for any reason (closed, crashed,
killed by Task Manager), Windows closes the handle and ends every program still in the job.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return k32


def kill_on_close_job(process_handle: int) -> int | None:
    """A job object with KILL_ON_JOB_CLOSE holding the process; None if Windows refuses.
    Keep the returned handle while the program runs, then close_job() it."""
    try:
        k32 = _kernel32()
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = k32.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                         ctypes.byref(limits), ctypes.sizeof(limits)) and \
            k32.AssignProcessToJobObject(job, process_handle)
        if not ok:
            k32.CloseHandle(job)
            return None
        return job
    except (AttributeError, OSError):
        return None


def close_job(job) -> None:
    """Closes the job's handle: any program still in it is ended."""
    if job:
        try:
            _kernel32().CloseHandle(job)
        except (AttributeError, OSError):
            pass


def process_in_job(process_handle: int, job) -> bool:
    """True when the process is in this job (used by tests)."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    result = wintypes.BOOL()
    if not k32.IsProcessInJob(process_handle, job, ctypes.byref(result)):
        return False
    return bool(result.value)
