from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from samples import MARKER, sample_bytes
from tacoguard.model import Confidence, Finding
from tacoguard.scan import jobs, walker

TESTS_DIR = Path(__file__).resolve().parent


# ---- fake detector used INSIDE the real worker process (via TACOGUARD_TEST_DETECTORS) --------

class SlowMarkerDetector:
    name, scans_members = "yara", True

    def __init__(self, log_path: str, delay: float):
        self.log_path, self.delay = log_path, delay

    def status(self):
        return {"ready": True, "message": "", "version": "slow-1", "updated": 0, "count": 1}

    def version(self):
        return "slow-1"

    def open(self):
        pass

    def close(self):
        pass

    def scan(self, item):
        time.sleep(self.delay)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(item.display + "\n")
        if MARKER in (item.data or b""):
            return [Finding(engine="yara", rule="Test_Marker", confidence=Confidence.HIGH, source="tests")]
        return []


def worker_detectors(settings, store):
    log = os.environ.get("TACOGUARD_TEST_SCANLOG", "")
    delay = float(os.environ.get("TACOGUARD_TEST_DELAY", "0"))
    return [SlowMarkerDetector(f"{log}.{os.getpid()}" if log else "", delay)]


@pytest.fixture
def worker_env(monkeypatch, tmp_path):
    monkeypatch.setenv("TACOGUARD_TEST_DETECTORS", "test_jobs:worker_detectors")
    monkeypatch.setenv("PYTHONPATH", str(TESTS_DIR))
    monkeypatch.setenv("TACOGUARD_TEST_SCANLOG", str(tmp_path / "scanlog"))
    return tmp_path / "scanlog"


def _folder(root: Path, n: int, bad_every: int = 0) -> Path:
    root.mkdir(parents=True)
    for i in range(n):
        data = sample_bytes() if bad_every and i % bad_every == 0 else f"clean {i}".encode()
        (root / f"file{i:05}.txt").write_bytes(data)
    return root


def _wait(store, job_id, cond, timeout=90.0):
    end = time.time() + timeout
    while time.time() < end:
        job = store.get_job(job_id)
        if cond(job):
            return job
        time.sleep(0.1)
    raise AssertionError(f"timed out; job is {store.get_job(job_id)}")


class _FakeProc:
    def __init__(self):
        self.pid = os.getpid()


@pytest.fixture
def launches(monkeypatch):
    calls = []
    monkeypatch.setattr(jobs, "launch_worker", lambda settings, job_id: (calls.append(job_id), _FakeProc())[1])
    return calls


# ---- API without a real worker ------------------------------------------------------------------

def test_bad_targets_give_plain_errors(settings, store, tmp_path):
    with pytest.raises(ValueError, match="at least one"):
        jobs.start_scan(settings, store, [])
    with pytest.raises(ValueError, match="Not found: .*nope"):
        jobs.start_scan(settings, store, [str(tmp_path / "nope")])
    assert store.list_jobs() == []


def test_second_scan_is_queued_then_started(settings, store, tmp_path, launches):
    a = jobs.start_scan(settings, store, [str(tmp_path)])
    b = jobs.start_scan(settings, store, [str(tmp_path)])
    assert launches == [a]
    assert store.get_job(a)["status"] == "running" and store.get_job(a)["pid"] == os.getpid()
    assert store.get_job(b)["status"] == "queued" and "Waiting" in store.get_job(b)["message"]
    store.update_job(a, status="done")
    assert jobs.start_next_queued(settings, store) == b and launches == [a, b]


def test_pause_cancel_resume_on_queued_jobs(settings, store, tmp_path, launches):
    a = jobs.start_scan(settings, store, [str(tmp_path)])
    b = jobs.start_scan(settings, store, [str(tmp_path)])
    jobs.pause_scan(store, b)
    assert store.get_job(b)["status"] == "paused"
    jobs.resume_scan(settings, store, b)
    assert store.get_job(b)["status"] == "queued"           # a still runs
    jobs.cancel_scan(store, b)
    assert store.get_job(b)["status"] == "cancelled"
    with pytest.raises(ValueError, match="cannot be resumed"):
        jobs.resume_scan(settings, store, b)
    jobs.pause_scan(store, a)
    assert store.get_job(a)["control"] == "pause" and store.get_job(a)["status"] == "running"


def test_recover_interrupted(settings, store, tmp_path):
    dead = psutil.Popen(["cmd", "/c", "exit"], creationflags=0x08000000)
    dead.wait()
    now = time.time()
    gone = store.create_job([str(tmp_path)])
    store.update_job(gone, status="running", pid=dead.pid, heartbeat=now)
    stale = store.create_job([str(tmp_path)])
    store.update_job(stale, status="running", pid=os.getpid(), heartbeat=now - 60)
    waiting = store.create_job([str(tmp_path)])
    assert sorted(jobs.recover_interrupted(store)) == [gone, stale, waiting]
    assert store.get_job(gone)["message"] == jobs.INTERRUPTED_MSG

    alive = store.create_job([str(tmp_path)])
    store.update_job(alive, status="running", pid=os.getpid(), heartbeat=time.time())
    behind = store.create_job([str(tmp_path)])
    assert jobs.recover_interrupted(store) == []
    assert store.get_job(behind)["status"] == "queued"


def _fake_worker(job_id: int) -> psutil.Popen:
    """A sleeping process whose command line looks like the scan worker for `job_id`."""
    return psutil.Popen([sys.executable, "-c", "import time; time.sleep(60)", "tacoguard.scan.worker",
                         "--job", str(job_id)], creationflags=0x08000000)


def test_starved_worker_with_stale_heartbeat_is_still_alive(settings, store, tmp_path, monkeypatch):
    """Review 2026-11-23: a live worker starved of CPU (old heartbeat) was called interrupted,
    and a resume would have started a second worker on the same job."""
    monkeypatch.setattr(jobs, "STALE_S", 0.5)
    job_id = store.create_job([str(tmp_path)])
    proc = _fake_worker(job_id)
    try:
        time.sleep(0.3)
        store.update_job(job_id, status="running", pid=proc.pid, heartbeat=time.time(), started=time.time())
        time.sleep(1.0)                                    # heartbeat is now stale
        assert jobs.recover_interrupted(store) == []
        assert store.get_job(job_id)["status"] == "running"
        other = store.create_job([str(tmp_path)])          # same pid, but not this job's worker
        store.update_job(other, status="running", pid=proc.pid, heartbeat=time.time() - 5)
        store.update_job(job_id, status="done")
        assert jobs.recover_interrupted(store) == [other]
    finally:
        proc.kill()
        proc.wait(10)
    assert jobs.recover_interrupted(store) == []


def _hardened_fake_worker(job_id: int) -> subprocess.Popen:
    """Like _fake_worker, but it hardens itself (self-protection): this test can't open it anew
    to end it; only its own Popen handle (opened before) still can."""
    base = getattr(sys, "_base_executable", None) or sys.executable
    root = str(Path(__file__).resolve().parents[1])
    code = (f"import sys, time; sys.path.insert(0, {root!r}); from tacoguard import selfprotect; "
            "print(selfprotect.harden_process(), flush=True); time.sleep(60)")
    return subprocess.Popen([base, "-c", code, "tacoguard.scan.worker", "--job", str(job_id)],
                            stdout=subprocess.PIPE, text=True, creationflags=0x08000000)


def test_hung_worker_that_cannot_be_ended_doesnt_block_new_scans(settings, store, tmp_path, launches,
                                                                 monkeypatch):
    monkeypatch.setattr(jobs, "STALE_S", 0.5)
    monkeypatch.setattr(jobs, "HUNG_S", 1.5)
    job_id = store.create_job([str(tmp_path)])
    proc = _hardened_fake_worker(job_id)
    plain = _fake_worker(job_id + 1000)
    try:
        assert proc.stdout.readline().strip() == "True"
        assert jobs.worker_protected(proc.pid) and not jobs.worker_protected(plain.pid)
        store.update_job(job_id, status="running", pid=proc.pid, heartbeat=time.time(), started=time.time())
        time.sleep(0.8)
        assert jobs._worker_state(store.get_job(job_id)) == "alive"          # stale, but not for long yet
        time.sleep(1.0)
        assert jobs._worker_state(store.get_job(job_id)) == "hung"
        new = jobs.start_scan(settings, store, [str(tmp_path)])             # a new scan can start
        assert launches == [new] and store.get_job(new)["status"] == "running"
        old = store.get_job(job_id)
        assert old["status"] == "interrupted" and old["message"] == jobs.HUNG_MSG
        assert "restart Windows to clear it" in jobs.HUNG_MSG
        # a stale worker TacoGuard CAN end (not hardened) is still just starved: left alone
        other = store.create_job([str(tmp_path)])
        store.update_job(new, status="done")
        store.update_job(other, status="running", pid=plain.pid, heartbeat=time.time() - 120, started=time.time())
        monkeypatch.setattr(jobs, "is_job_worker", lambda pid, jid, seen: True)
        assert jobs._worker_state(store.get_job(other)) == "alive"
    finally:
        for p in (proc, plain):
            p.kill()                                        # our own handles still may
            p.wait(10)


def test_reused_pid_with_stale_heartbeat_is_interrupted(settings, store, tmp_path):
    job_id = store.create_job([str(tmp_path)])
    proc = _fake_worker(job_id)                            # started AFTER the job's last heartbeat
    try:
        store.update_job(job_id, status="running", pid=proc.pid, heartbeat=time.time() - 120)
        assert jobs.recover_interrupted(store) == [job_id]
    finally:
        proc.kill()
        proc.wait(10)


MEMCAP_PROBE = r"""
import subprocess, sys
from tacoguard.scan import worker
assert worker.limit_memory(300 * 1024**2)
try:
    bytearray(600 * 1024**2)
    print("worker:no-limit")
except MemoryError:
    print("worker:MemoryError")
print("after:", len(bytearray(20 * 1024**2)))
r = subprocess.run([sys.executable, "-c", "print(len(bytearray(600 * 1024**2)))"], capture_output=True, text=True)
print("child:", r.stdout.strip())
"""


def test_worker_memory_cap_applies_to_the_worker_only():
    out = subprocess.run([sys.executable, "-c", MEMCAP_PROBE], capture_output=True, text=True, timeout=60,
                         cwd=str(TESTS_DIR.parent), creationflags=0x08000000)
    lines = out.stdout.split()
    assert "worker:MemoryError" in lines, out.stdout + out.stderr
    assert "20971520" in lines                              # small allocations still work after
    assert str(600 * 1024**2) in lines                      # clamd / tar.exe are not capped


PRIORITY_PROBE = r"""
import ctypes, sys
from ctypes import wintypes
import psutil
from tacoguard.scan import worker
k32 = ctypes.WinDLL("kernel32")
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.GetProcessInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
applied = worker.lower_priority(sys.argv[1])
memory = wintypes.ULONG(0)
k32.GetProcessInformation(k32.GetCurrentProcess(), 0, ctypes.byref(memory), 4)   # ProcessMemoryPriority
p = psutil.Process()
print(applied, p.nice(), p.ionice(), memory.value)
"""


@pytest.mark.parametrize("mode,cpu", [("idle", psutil.IDLE_PRIORITY_CLASS),
                                      ("below_normal", psutil.BELOW_NORMAL_PRIORITY_CLASS)])
def test_worker_priority_is_low_cpu_and_disk_but_not_background_mode(mode, cpu):
    """2026-11-23: Windows background mode also lowered memory priority, and YARA then took
    250 s instead of 4 s on the same files. Run in a child so pytest itself keeps its priority."""
    out = subprocess.run([sys.executable, "-c", PRIORITY_PROBE, mode], capture_output=True, text=True,
                         timeout=60, cwd=str(TESTS_DIR.parent), creationflags=0x08000000)
    applied, nice, io, memory = out.stdout.split()
    assert applied == mode, out.stderr
    assert int(nice) == cpu and int(io) == psutil.IOPRIO_LOW
    assert int(memory) == 5                 # MEMORY_PRIORITY_NORMAL (background mode makes it 1)


def test_inline_crash_marks_failed_with_log(settings, store, tmp_path, monkeypatch):
    from tacoguard.scan import engine

    def boom(*a, **k):
        raise RuntimeError("test crash")

    monkeypatch.setattr(engine, "scan_job", boom)
    job_id = store.create_job([str(tmp_path)])
    jobs.run_job_inline(settings, store, job_id, detectors=[])
    job = store.get_job(job_id)
    assert job["status"] == "failed" and "unexpected problem" in job["message"]
    logs = list(Path(settings.log_dir).glob("scan-*.log"))
    assert logs and "test crash" in logs[0].read_text(encoding="utf-8")


# ---- the real worker process ------------------------------------------------------------------

def test_worker_runs_queued_jobs_in_turn(settings, store, tmp_path, worker_env, monkeypatch):
    monkeypatch.setenv("TACOGUARD_TEST_DELAY", "0.005")
    a = jobs.start_scan(settings, store, [str(_folder(tmp_path / "a", 60, bad_every=20))])
    b = jobs.start_scan(settings, store, [str(_folder(tmp_path / "b", 5, bad_every=5))])
    assert store.get_job(b)["status"] == "queued"
    jb = _wait(store, b, lambda j: j["status"] in ("done", "failed"))
    ja = store.get_job(a)
    assert ja["status"] == "done" and jb["status"] == "done", (ja["message"], jb["message"])
    assert ja["counts"]["malware"] == 3 and jb["counts"]["malware"] == 1
    assert jb["started"] >= ja["finished"]


def test_killed_worker_is_interrupted_and_resumes_from_checkpoint(settings, store, tmp_path, worker_env,
                                                                  monkeypatch):
    monkeypatch.setenv("TACOGUARD_TEST_DELAY", "0.004")
    root = _folder(tmp_path / "many", 2000, bad_every=100)
    job_id = jobs.start_scan(settings, store, [str(root)])
    job = _wait(store, job_id, lambda j: j["status"] != "running" or (j["counts"].get("files", 0) >= 300
                                                                     and j["checkpoint"]))
    assert job["status"] == "running", job["message"]
    proc = psutil.Process(job["pid"])
    proc.kill()
    proc.wait(10)

    assert jobs.recover_interrupted(store) == [job_id]
    job = store.get_job(job_id)
    assert job["status"] == "interrupted" and job["message"] == jobs.INTERRUPTED_MSG
    checkpoint = walker.order_key(job["checkpoint"])
    first_logs = set(worker_env.parent.glob("scanlog.*"))

    jobs.resume_scan(settings, store, job_id)
    job = _wait(store, job_id, lambda j: j["status"] in ("done", "failed"), timeout=180)
    assert job["status"] == "done", job["message"]
    assert job["counts"]["files"] == 2000 and job["counts"]["malware"] == 20

    results = store.list_results(job_id)
    paths = [r["path"] for r in results]
    assert len(paths) == len(set(paths)) == 20

    (second_log,) = set(worker_env.parent.glob("scanlog.*")) - first_logs
    resumed = second_log.read_text(encoding="utf-8").splitlines()
    assert resumed and all(walker.order_key(p) > checkpoint for p in resumed)
    assert len(resumed) < 2000
