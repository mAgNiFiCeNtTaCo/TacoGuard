"""The guard core: WatchHub, FolderWatcher, RealtimeChecker, ProcessWatcher, Guard and the process.

Only harmless material: files holding the test marker (samples.py), and child processes the
tests start themselves (a sleeping Python). Nothing outside tmp_path is watched or changed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from samples import MARKER, WEAK_MARKER, sample_bytes
from tacoguard import allowlist, winpath
from tacoguard.config import Settings
from tacoguard.guard import checker as checker_mod
from tacoguard.guard import folders, procctl, processes, service
from tacoguard.guard.checker import RealtimeChecker
from tacoguard.guard.folders import FolderWatcher, FsEvent, WatchHub
from tacoguard.guard.processes import ProcessWatcher
from tacoguard.model import CLEAN, MALWARE, SKIPPED, SUSPICIOUS, Confidence, FileResult, Finding
from tacoguard.store import Store

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
# children the tests pause: the real interpreter (the venv's python.exe is a launcher that starts
# it as a grandchild, which pausing the launcher would not pause)
CHILD_PY = getattr(sys, "_base_executable", None) or sys.executable


class FakeDetector:
    """Flags MARKER (high) and WEAK_MARKER (medium). Thread-safe enough for the tests."""

    def __init__(self, name="yara", version="v1", signatures=True):
        self.name, self._version, self._signatures = name, version, signatures
        self.seen: list[str] = []
        self.opened = self.closed = 0

    def status(self):
        return {"ready": True, "message": "", "version": self._version, "updated": 0, "count": 1}

    def version(self):
        return self._version

    def open(self):
        self.opened += 1

    def close(self):
        self.closed += 1

    def has_signatures(self):
        return self._signatures

    def scan(self, item):
        self.seen.append(item.display)
        data = item.data
        if data is None:
            with open(item.path, "rb") as f:
                data = f.read()
        if MARKER in data:
            return [Finding(self.name, "Test_Marker", Confidence.HIGH, "tests")]
        if WEAK_MARKER in data:
            return [Finding(self.name, "Test_Weak", Confidence.MEDIUM, "tests")]
        return []


class FakeClam(FakeDetector):
    def __init__(self, ready=True):
        super().__init__("clamav", "c1")
        self.ready = ready

    def status(self):
        return {"ready": self.ready, "message": "", "version": "c1", "updated": 0, "count": 1}

    def scan(self, item):
        self.seen.append(item.display)
        return [Finding("clamav", "TacoGuard.Test.HarmlessSample-1", Confidence.HIGH, "test signature")]


def wait_for(fn, timeout=10.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


@pytest.fixture
def watched(tmp_path) -> Path:
    w = tmp_path / "watched"
    w.mkdir()
    return w


@pytest.fixture
def det():
    return FakeDetector()


@pytest.fixture
def chk(settings, store, det):
    c = RealtimeChecker(settings, store, [det])
    yield c
    c.close()


@pytest.fixture
def hub():
    h = WatchHub()
    h.RETRY_S = 0.3
    h.start()
    yield h
    h.stop()


def make_watcher(settings, store, chk, hub, watched, quiet=0.3):
    settings.watch_folders = [str(watched)]
    w = FolderWatcher(settings, store, chk, hub)
    w.QUIET_S = quiet
    w.start()
    return w


def events(store):
    return store.list_guard_events()


# ---- WatchHub ------------------------------------------------------------------------------------
def test_parse_notify_records():
    import struct
    a = "a.txt".encode("utf-16-le")
    b = "sub\\b.exe".encode("utf-16-le")
    first = struct.pack("<III", 0, 1, len(a)) + a
    first += b"\0" * (-len(first) % 4)
    rec1 = struct.pack("<III", len(first), 1, len(a)) + a + b"\0" * (len(first) - 12 - len(a))
    rec2 = struct.pack("<III", 0, 5, len(b)) + b
    assert folders.parse_notify(rec1 + rec2) == [("added", "a.txt"), ("renamed_to", "sub\\b.exe")]


def test_hub_reports_add_modify_rename_delete(hub, watched):
    got: list[FsEvent] = []
    hub.subscribe(str(watched), got.append)
    assert wait_for(lambda: hub.root_state(str(watched)) == "ok")
    p = watched / "a.txt"
    p.write_bytes(b"one")
    with open(p, "ab") as f:
        f.write(b"two")
    os.rename(p, watched / "b.txt")
    os.remove(watched / "b.txt")
    (watched / "sub").mkdir()
    (watched / "sub" / "c.txt").write_bytes(b"x")
    wanted = [("added", "a.txt"), ("modified", "a.txt"), ("renamed_from", "a.txt"),
              ("renamed_to", "b.txt"), ("removed", "b.txt"), ("added", os.path.join("sub", "c.txt"))]

    def seen():
        pairs = [(e.action, os.path.relpath(e.path, watched)) for e in got]
        return all(w in pairs for w in wanted)
    assert wait_for(seen), [(e.action, e.path) for e in got]
    assert all(isinstance(e.ts, float) for e in got)


def test_hub_several_subscribers_and_not_recursive(hub, watched):
    a, b = [], []
    ta = hub.subscribe(str(watched), a.append)
    hub.subscribe(str(watched), b.append, recursive=False)
    assert wait_for(lambda: hub.root_state(str(watched)) == "ok")
    (watched / "sub").mkdir()
    (watched / "sub" / "deep.txt").write_bytes(b"x")
    (watched / "top.txt").write_bytes(b"x")
    assert wait_for(lambda: any(e.path.endswith("top.txt") for e in b))
    assert wait_for(lambda: any(e.path.endswith("deep.txt") for e in a))
    assert not any(e.path.endswith("deep.txt") for e in b)
    hub.unsubscribe(ta)
    a.clear()
    (watched / "after.txt").write_bytes(b"x")
    assert wait_for(lambda: any(e.path.endswith("after.txt") for e in b))
    assert not a


def test_hub_root_missing_then_back(hub, tmp_path):
    root = tmp_path / "usb"
    got = []
    hub.subscribe(str(root), got.append)          # not there yet: retried, no crash
    assert wait_for(lambda: hub.root_state(str(root)) == "missing")
    root.mkdir()
    assert wait_for(lambda: hub.root_state(str(root)) == "ok", timeout=5)
    (root / "x.txt").write_bytes(b"x")
    assert wait_for(lambda: any(e.path.endswith("x.txt") for e in got))
    shutil.rmtree(root)                            # "unplugged": watching never blocked the delete
    assert not root.exists()
    assert wait_for(lambda: hub.root_state(str(root)) == "missing", timeout=5)
    got.clear()
    assert wait_for(lambda: _mkdir_ok(root), timeout=5)
    assert wait_for(lambda: hub.root_state(str(root)) == "ok", timeout=5)
    assert wait_for(lambda: any(e.action == "overflow" for e in got))   # "look again yourself"


def _mkdir_ok(p: Path) -> bool:
    try:
        p.mkdir(exist_ok=True)
        return True
    except OSError:
        return False


def test_hub_stop_is_quick(watched):
    h = WatchHub()
    h.subscribe(str(watched), lambda e: None)
    h.start()
    assert wait_for(lambda: h.root_state(str(watched)) == "ok")
    t = time.monotonic()
    h.stop()
    assert time.monotonic() - t < 2
    assert h.root_state(str(watched)) == "off"


def test_hub_does_not_lock_the_folder(hub, watched):
    hub.subscribe(str(watched), lambda e: None)
    assert wait_for(lambda: hub.root_state(str(watched)) == "ok")
    os.rename(watched, watched.with_name("renamed"))   # watching must never block this
    os.rename(watched.with_name("renamed"), watched)


# ---- which folders --------------------------------------------------------------------------------
def test_default_watch_folders_setting_wins(settings, tmp_path):
    settings.watch_folders = [str(tmp_path / "a"), str(tmp_path / "a" / "inner"), str(tmp_path / "b"),
                              str(tmp_path / "B")]
    got = folders.default_watch_folders(settings)
    assert got == [str(tmp_path / "a"), str(tmp_path / "b")]


def test_default_watch_folders_defaults(settings):
    settings.watch_folders = []
    got = folders.default_watch_folders(settings)
    assert got, "the usual folders exist on this PC"
    assert all(os.path.isdir(p) for p in got)
    assert any(p.lower().endswith("startup") for p in got)
    keys = [p.lower() for p in got]
    assert len(keys) == len(set(keys))


def test_is_partial_names():
    for name in ("a.exe.crdownload", "a.part", "x.PARTIAL", "y.download", "z.opdownload", "t.tmp", "~$doc.docx"):
        assert folders.is_partial("C:\\x\\" + name), name
    assert not folders.is_partial("C:\\x\\setup.exe")


# ---- FolderWatcher -------------------------------------------------------------------------------
def test_flagged_file_gives_one_event_and_no_duplicate(settings, store, chk, hub, watched, det):
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        bad = watched / "free-vbucks.exe"
        bad.write_bytes(sample_bytes())
        assert wait_for(lambda: len(events(store)) == 1)
        ev = events(store)[0]
        assert ev["kind"] == "file" and ev["level"] == MALWARE
        assert ev["title"].startswith("Quarantine suggested: ") and ev["title"].endswith("free-vbucks.exe")
        assert ev["path"] == str(bad) and ev["sha256"] and ev["findings"][0]["rule"] == "Test_Marker"
        assert "Test_Marker" in ev["message"]
        n_seen = len(det.seen)
        bad.write_bytes(sample_bytes())          # touched again: checked again, not reported again
        assert wait_for(lambda: len(det.seen) > n_seen)
        time.sleep(0.3)
        assert len(events(store)) == 1
        assert bad.exists()                      # never quarantined or deleted by the guard
        assert w.status()["checked"] >= 2
    finally:
        w.stop()


def test_duplicate_check_survives_a_new_checker(settings, store, det, watched):
    bad = watched / "x.exe"
    bad.write_bytes(sample_bytes())
    c1 = RealtimeChecker(settings, store, [det])
    assert c1.report(c1.check_path(str(bad)), "file")
    c2 = RealtimeChecker(settings, store, [det])     # e.g. after a guard restart
    first = events(store)[0]["id"]
    assert c2.report(c2.check_path(str(bad)), "file") == first
    assert len(events(store)) == 1


def test_clean_and_suspicious_files(settings, store, chk, hub, watched):
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        (watched / "notes.txt").write_bytes(b"just text")
        (watched / "mod-loader.exe").write_bytes(b"x" + WEAK_MARKER)
        assert wait_for(lambda: len(events(store)) == 1)
        time.sleep(0.5)
        evs = events(store)
        assert len(evs) == 1
        assert evs[0]["level"] == SUSPICIOUS and evs[0]["title"].startswith("Suspicious: ")
        assert "false alarm" in evs[0]["message"]
    finally:
        w.stop()


def test_partial_download_waits_for_its_final_name(settings, store, chk, hub, watched, det):
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        part = watched / "setup.exe.crdownload"
        part.write_bytes(sample_bytes())
        time.sleep(1.2)
        assert not det.seen and not events(store)
        os.rename(part, watched / "setup.exe")
        assert wait_for(lambda: len(events(store)) == 1)
        assert events(store)[0]["path"].endswith("setup.exe")
    finally:
        w.stop()


def test_quiet_rule_waits_until_writing_stops(settings, store, hub, watched):
    calls = []

    class Recorder:
        def check_path(self, p):
            calls.append((time.monotonic(), p))
            return FileResult(path=p)

        def report(self, *a, **k):
            return None

    w = make_watcher(settings, store, Recorder(), hub, watched, quiet=0.6)
    try:
        p = watched / "big.iso"
        with open(p, "wb") as f:
            for _ in range(10):                  # written in bursts for ~1.5 s
                f.write(b"x" * 4096)
                f.flush()
                os.fsync(f.fileno())
                time.sleep(0.15)
        done = time.monotonic()
        assert not calls, "checked while still being written"
        assert wait_for(lambda: calls, timeout=5)
        time.sleep(1.0)
        assert len(calls) == 1
        assert calls[0][0] >= done
    finally:
        w.stop()


def test_queue_is_capped_newest_kept(settings, store, chk, watched):
    h = WatchHub()                               # not started: events are fed by hand
    settings.watch_folders = [str(watched)]
    w = FolderWatcher(settings, store, chk, h)
    w.QUEUE_MAX = 5
    w.roots = [str(watched)]
    for i in range(20):
        w._on_event(FsEvent("added", str(watched / f"f{i:02}.txt"), ts=1000.0 + i))
    assert w.pending_count() == 5
    kept = sorted(os.path.basename(p.display) for p in w._pending.values())
    assert kept == [f"f{i:02}.txt" for i in range(15, 20)]
    assert folders.OVERFLOW_MSG in w.status()["message"]


def test_overflow_event_rescans_the_root(settings, store, chk, hub, watched):
    bad = watched / "old.exe"
    bad.write_bytes(sample_bytes())
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        time.sleep(0.5)
        assert not events(store)                 # it was there before the watch started
        w._on_event(FsEvent("overflow", str(watched)))
        assert wait_for(lambda: len(events(store)) == 1)
    finally:
        w.stop()


def test_junction_is_not_followed(settings, store, chk, hub, watched, tmp_path, det):
    outside = tmp_path / "outside"
    outside.mkdir()
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        link = watched / "j"
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        assert r.returncode == 0, r.stderr
        (outside / "bad.exe").write_bytes(sample_bytes())
        (link / "bad2.exe").write_bytes(sample_bytes())      # written through the junction
        time.sleep(1.5)
        assert not events(store)
        assert not det.seen
        assert not list(folders.iter_files(str(watched)))
        assert chk.check_path(str(link)) is None
    finally:
        w.stop()
        os.rmdir(watched / "j")                  # removes the junction only


def test_folder_moved_in_gets_its_files_checked(settings, store, chk, hub, watched, tmp_path):
    src = tmp_path / "unpacked"
    (src / "inner").mkdir(parents=True)
    (src / "inner" / "tool.exe").write_bytes(sample_bytes())
    w = make_watcher(settings, store, chk, hub, watched)
    try:
        os.rename(src, watched / "unpacked")
        assert wait_for(lambda: len(events(store)) == 1)
        assert events(store)[0]["path"].endswith(os.path.join("inner", "tool.exe"))
    finally:
        w.stop()


def test_own_data_folder_is_ignored(tmp_path, hub, det):
    s = Settings(data_dir=str(tmp_path / "w" / "data"))
    s.ensure_dirs()
    st = Store(s.db_path)
    c = RealtimeChecker(s, st, [det])
    w = make_watcher(s, st, c, hub, tmp_path / "w")
    try:
        (s.tmp_dir / "x.exe").write_bytes(sample_bytes())
        (tmp_path / "w" / "y.exe").write_bytes(sample_bytes())
        assert wait_for(lambda: len(st.list_guard_events()) == 1)
        time.sleep(0.5)
        assert [e["path"] for e in st.list_guard_events()] == [str(tmp_path / "w" / "y.exe")]
    finally:
        w.stop()
        c.close()
        st.close()


def test_in_use_file_is_tried_again(settings, store, hub, watched):
    results = [FileResult(path="", status="unreadable", notes=[folders.engine.IN_USE_NOTE]),
               FileResult(path="", findings=[Finding("yara", "R", Confidence.HIGH, "tests")])]
    calls = []

    class Flaky:
        def check_path(self, p):
            calls.append(p)
            r = results[min(len(calls) - 1, 1)]
            r.path = p
            return r

        def report(self, r, kind, extra=None):
            calls.append(("report", r.level))

    w = make_watcher(settings, store, Flaky(), hub, watched)
    w.IN_USE_RETRY_S = 0.2
    try:
        (watched / "locked.exe").write_bytes(b"data")
        assert wait_for(lambda: ("report", MALWARE) in calls, timeout=5)
    finally:
        w.stop()


# ---- RealtimeChecker ----------------------------------------------------------------------------
def test_checker_too_big_is_noted(settings, store, chk, watched):
    settings.realtime_max_file_size = 100
    p = watched / "huge.exe"
    p.write_bytes(b"x" * 500)
    r = chk.check_path(str(p))
    assert r.status == SKIPPED and "Scan tab" in r.notes[0]
    eid = chk.report(r, "file")
    ev = store.get_guard_event(eid)
    assert ev["level"] == "info" and ev["title"].startswith("Not checked (too big): ")


def test_checker_clean_trusted_and_gone(settings, store, chk, watched, det):
    clean = watched / "ok.txt"
    clean.write_bytes(b"fine")
    r = chk.check_path(str(clean))
    assert r.level == CLEAN and chk.report(r, "file") is None
    assert chk.check_path(str(watched / "missing.exe")) is None
    assert chk.check_path(str(watched)) is None
    trusted = watched / "trusted"
    trusted.mkdir()
    (trusted / "x.exe").write_bytes(sample_bytes())
    allowlist.trust_folder(store, str(trusted))
    time.sleep(checker_mod.TRUST_REFRESH_S + 0.1)
    r = chk.check_path(str(trusted / "x.exe"))
    assert r.status == "trusted" and chk.report(r, "file") is None
    assert not events(store)


def test_checker_without_signatures_checks_nothing(settings, store, watched):
    c = RealtimeChecker(settings, store, [FakeDetector(signatures=False)])
    (watched / "a.exe").write_bytes(sample_bytes())
    assert not c.ready()
    assert c.check_path(str(watched / "a.exe")) is None


def test_clamav_second_opinion_only_for_flagged_files(settings, store, watched, det):
    clam = FakeClam()
    settings.clamav_idle_stop_s = 1
    c = RealtimeChecker(settings, store, [det, clam])
    try:
        assert c.sig_version == "v1"                   # ClamAV is not part of the first checks
        (watched / "ok.txt").write_bytes(b"fine")
        c.check_path(str(watched / "ok.txt"))
        assert clam.opened == 0 and not c.clamav_running
        (watched / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
        r = c.check_path(str(watched / "weak.exe"))
        assert clam.opened == 1 and c.clamav_running
        assert {f.engine for f in r.findings} == {"yara", "clamav"}
        assert r.level == MALWARE                     # merged: the second opinion counts
        assert wait_for(lambda: not c.clamav_running, timeout=5)   # idle: stopped again
        assert clam.closed == 1
    finally:
        c.close()


def test_clamav_second_opinion_switches(settings, store, watched, det):
    (watched / "weak.exe").write_bytes(b"x" + WEAK_MARKER)
    clam = FakeClam()
    settings.realtime_clamav_second_opinion = False
    c = RealtimeChecker(settings, store, [det, clam])
    assert c.check_path(str(watched / "weak.exe")).level == SUSPICIOUS and clam.opened == 0
    settings.realtime_clamav_second_opinion = True
    clam.ready = False                                # ClamAV not set up
    assert c.check_path(str(watched / "weak.exe")).level == SUSPICIOUS and clam.opened == 0
    c2 = RealtimeChecker(settings, store, [det])
    c2.clamav_factory = lambda s: FakeClam()
    assert c2.check_path(str(watched / "weak.exe")).level == MALWARE
    c2.close()


# ---- ProcessWatcher ------------------------------------------------------------------------------
@pytest.fixture
def child():
    p = subprocess.Popen([CHILD_PY, "-c", "import time; time.sleep(120)"], creationflags=0x08000000)
    ref = wait_for(lambda: procctl.ref_of(p.pid), timeout=5)
    yield p, ref
    try:
        procctl.resume(ref)
    except procctl.ProcError:
        pass
    p.kill()
    p.wait(10)


def fake_program(tmp_path, data=None) -> Path:
    exe = tmp_path / "prog" / "fake-malware.exe"
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(data if data is not None else sample_bytes())
    return exe


def test_malware_program_is_paused(settings, store, chk, tmp_path, child):
    p, ref = child
    exe = fake_program(tmp_path)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    eid = pw.handle(ref, str(exe), "python.exe")
    ev = store.get_guard_event(eid)
    assert ev["kind"] == "process" and ev["level"] == MALWARE
    assert ev["title"] == f"Paused: {winpath.short_display(str(exe))} (it looked like malware)"
    rows = store.list_paused()
    assert len(rows) == 1 and rows[0]["pid"] == p.pid and rows[0]["event_id"] == eid
    assert ev["data"] == {"pid": p.pid, "create_time": ref.create_time, "paused_id": rows[0]["id"]}
    assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
    assert pw.paused == 1


def test_new_program_found_by_polling(settings, store, chk, tmp_path):
    exe = fake_program(tmp_path)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    real_resolve = pw._resolve
    mine: dict[int, object] = {}

    def resolve(pid):
        if pid in mine:
            found = real_resolve(pid)
            return (found[0], str(exe), "python.exe") if found else None
        return None                                 # nothing else on this PC is touched

    pw._resolve = resolve
    pw.start()
    proc = None
    try:
        proc = subprocess.Popen([CHILD_PY, "-c", "import time; time.sleep(120)"], creationflags=0x08000000)
        mine[proc.pid] = proc
        assert wait_for(lambda: store.list_paused(), timeout=10)
        ref = procctl.ref_of(proc.pid)
        assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
        assert pw.status()["state"] == "on" and pw.status()["checked"] >= 1
    finally:
        pw.stop()
        if proc is not None:
            r = procctl.ref_of(proc.pid)
            if r:
                try:
                    procctl.resume(r)
                except procctl.ProcError:
                    pass
            proc.kill()
            proc.wait(10)


def test_suspicious_program_only_alerts(settings, store, chk, tmp_path, child):
    p, ref = child
    exe = fake_program(tmp_path, b"x" + WEAK_MARKER)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(exe), "python.exe"))
    assert ev["level"] == SUSPICIOUS and ev["title"] == f"Suspicious: {winpath.short_display(str(exe))}"
    assert not store.list_paused() and not procctl.is_suspended(ref)


def test_pause_switched_off_only_alerts(settings, store, chk, tmp_path, child):
    p, ref = child
    settings.pause_malware_processes = False
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "python.exe"))
    assert ev["level"] == MALWARE and ev["title"].startswith("Quarantine suggested: ")
    assert not store.list_paused() and not procctl.is_suspended(ref)


def test_protected_program_is_not_paused(settings, store, chk, tmp_path, child):
    p, ref = child
    pw = ProcessWatcher(settings, store, chk, own={p.pid}, check_running=False)   # "TacoGuard's own"
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "python.exe"))
    assert "did not pause" in ev["message"] and "part of TacoGuard" in ev["message"]
    assert not store.list_paused() and not procctl.is_suspended(ref)


def test_pause_failure_is_recorded(settings, store, chk, tmp_path, child, monkeypatch):
    p, ref = child

    def refuse(r, own=None):
        raise procctl.ProcError("Windows did not allow TacoGuard to do that to this program.")
    monkeypatch.setattr(procctl, "suspend", refuse)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "python.exe"))
    assert ev["title"].endswith("(it could not be paused)")
    assert "could not pause" in ev["message"]
    row = store.get_paused(ev["data"]["paused_id"])
    assert row["state"] == "not_paused"           # not "resumed": you never pressed anything


def test_program_already_closed_is_checked_not_paused(settings, store, chk, tmp_path):
    proc = subprocess.Popen([CHILD_PY, "-c", "pass"], creationflags=0x08000000)
    ref = procctl.ref_of(proc.pid) or procctl.ProcRef(proc.pid, 1.0)
    proc.wait(10)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "x.exe"))
    assert ev["level"] == MALWARE and "already closed" in ev["message"]
    assert not store.list_paused()


def test_clean_program_checked_once(settings, store, chk, tmp_path, det):
    exe = fake_program(tmp_path, b"MZ harmless")
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ref = procctl.ProcRef(os.getpid(), 0.0)
    for _ in range(5):
        assert pw.handle(ref, str(exe), "x.exe") is None
    assert len(det.seen) == 1 and pw.checked == 1


def test_windows_programs_are_skipped(settings, store, chk):
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    proc = subprocess.Popen([cmd, "/k"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            creationflags=0x08000000)
    try:
        pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
        assert wait_for(lambda: psutil.pid_exists(proc.pid))
        assert pw._resolve(proc.pid) is None
        me = pw._resolve(os.getpid())
        assert me is not None and me[1].lower().endswith("python.exe")
    finally:
        proc.kill()
        proc.wait(10)


# ---- Guard (in-process) --------------------------------------------------------------------------
class StubPart:
    instances: list = []

    def __init__(self, *a, fail_status=False, fail_start=False):
        self.started = self.stopped = 0
        self.fail_status, self.fail_start = fail_status, fail_start
        StubPart.instances.append(self)

    def start(self):
        self.started += 1
        if self.fail_start:
            raise RuntimeError("boom")

    def stop(self):
        self.stopped += 1

    def status(self):
        if self.fail_status:
            return {"state": "error", "message": "It stopped."}
        return {"state": "on", "message": "Stub on.", "watched": ["X"], "checked": 7}


@pytest.fixture
def fast_guard(monkeypatch):
    monkeypatch.setattr(service.Guard, "TICK_S", 0.05)
    monkeypatch.setattr(service.Guard, "SETTINGS_CHECK_S", 0.1)
    monkeypatch.setattr(service.Guard, "HEARTBEAT_S", 0.2)
    monkeypatch.setattr(service.Guard, "PARENT_CHECK_S", 0.1)
    monkeypatch.setattr(service.Guard, "NOTIFY_CHECK_S", 0.1)
    monkeypatch.setattr(service.Guard, "RESTART_DELAY_S", 0.1)
    monkeypatch.setattr(service.Guard, "TRIM_AFTER_S", 0.2)
    StubPart.instances = []
    specs = dict(service.PART_SPECS)
    specs["processes"] = (lambda g: StubPart(), specs["processes"][1], specs["processes"][2])
    specs["ransomware"] = (lambda g: StubPart(), specs["ransomware"][1], specs["ransomware"][2])
    specs["persistence"] = (lambda g: StubPart(), specs["persistence"][1], specs["persistence"][2])
    specs["web"] = (lambda g: StubPart(), specs["web"][1], specs["web"][2])      # Phase 4 part
    monkeypatch.setattr(service, "PART_SPECS", specs)
    return specs


def guard_settings(settings, watched, **kw):
    settings.watch_folders = [str(watched)]
    settings.watch_processes = False
    settings.ransomware_guard = False
    settings.persistence_watch = False
    for k, v in kw.items():
        setattr(settings, k, v)
    settings.save()
    return settings


def heartbeat(store):
    row = store._con().execute("SELECT value FROM meta WHERE key='guard_state'").fetchone()
    return json.loads(row[0]) if row else None


def test_guard_start_stop_and_heartbeat_shape(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        hb = heartbeat(store)
        assert set(hb) == {"pid", "started", "heartbeat", "version", "parts", "notes"}
        assert hb["notes"] == []
        assert hb["pid"] == os.getpid() and hb["version"]
        assert set(hb["parts"]) == {"folders", "processes", "ransomware", "persistence", "web"}
        for part in hb["parts"].values():
            assert set(part) == {"state", "message", "watched", "checked"}
        assert hb["parts"]["folders"]["state"] == "on"
        assert hb["parts"]["folders"]["watched"] == [str(watched)]
        assert hb["parts"]["processes"]["state"] == "off"
        assert hb["parts"]["processes"]["message"] == service.OFF_MSG
        first = hb["heartbeat"]
        assert wait_for(lambda: heartbeat(store)["heartbeat"] > first, timeout=3)
        assert det.opened == 1
        (watched / "bad.exe").write_bytes(sample_bytes())
        assert wait_for(lambda: len(events(store)) == 1, timeout=10)
    finally:
        g.stop()
    hb = heartbeat(store)
    assert all(p["state"] == "off" for p in hb["parts"].values())
    assert det.closed == 1
    assert (settings.log_dir / "guard.log").exists()


def test_guard_parts_follow_settings_live(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        settings2 = Settings(data_dir=settings.data_dir)
        guard_settings(settings2, watched, watch_processes=True, persistence_watch=True)
        assert wait_for(lambda: heartbeat(store)["parts"]["processes"]["state"] == "on", timeout=5)
        hb = heartbeat(store)
        assert hb["parts"]["persistence"]["checked"] == 7
        assert g.settings.watch_processes is True              # changed in place
        proc_part = g.parts["processes"].inst
        guard_settings(settings2, watched, watch_processes=False, persistence_watch=True)
        assert wait_for(lambda: heartbeat(store)["parts"]["processes"]["state"] == "off", timeout=5)
        assert proc_part.stopped == 1
        other = watched.parent / "other"
        other.mkdir()
        settings2.watch_folders = [str(other)]
        settings2.save()
        assert wait_for(lambda: heartbeat(store)["parts"]["folders"]["watched"] == [str(other)], timeout=5)
    finally:
        g.stop()


def test_guard_stops_itself_when_realtime_turned_off(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        s2 = Settings(data_dir=settings.data_dir)
        guard_settings(s2, watched, realtime_enabled=False)
        assert g.wait(5)
        assert "turned off" in g.stop_reason
    finally:
        g.stop()


def test_guard_stop_file(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    settings.guard_dir.mkdir(parents=True, exist_ok=True)
    (settings.guard_dir / "stop").write_text("old")      # left over: removed at start
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        assert not (settings.guard_dir / "stop").exists()
        assert not g.wait(0.3)
        (settings.guard_dir / "stop").write_text("stop")
        assert g.wait(3)
    finally:
        g.stop()


def test_guard_stops_when_parent_ends(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    parent = subprocess.Popen([CHILD_PY, "-c", "import time; time.sleep(60)"], creationflags=0x08000000)
    try:
        g = service.Guard(settings, store, detectors=[det])
        g.parent_pid = parent.pid
        g.start()
        try:
            assert not g.wait(0.3)
            parent.kill()
            parent.wait(10)
            assert g.wait(5)
            assert "page" in g.stop_reason
        finally:
            g.stop()
    finally:
        if parent.poll() is None:
            parent.kill()


def test_missing_part_is_an_error_not_a_crash(settings, store, watched, det, fast_guard, monkeypatch):
    def missing(g):
        raise ImportError("no module named tacoguard.guard.ransom")
    specs = dict(service.PART_SPECS)
    specs["ransomware"] = (missing, specs["ransomware"][1], specs["ransomware"][2])
    specs["persistence"] = (lambda g: object(), specs["persistence"][1], specs["persistence"][2])  # no start()
    monkeypatch.setattr(service, "PART_SPECS", specs)
    guard_settings(settings, watched, ransomware_guard=True, persistence_watch=True)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        hb = heartbeat(store)
        for name in ("ransomware", "persistence"):
            assert hb["parts"][name]["state"] == "error"
            assert hb["parts"][name]["message"] == service.MISSING_PART_MSG
        assert hb["parts"]["folders"]["state"] == "on"
    finally:
        g.stop()


def test_crashing_part_is_restarted_at_most_three_times(settings, store, watched, det, fast_guard,
                                                        monkeypatch):
    made = []

    def crashing(g):
        made.append(StubPart(fail_status=True))
        return made[-1]
    specs = dict(service.PART_SPECS)
    specs["persistence"] = (crashing, specs["persistence"][1], specs["persistence"][2])
    monkeypatch.setattr(service, "PART_SPECS", specs)
    guard_settings(settings, watched, persistence_watch=True)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        assert wait_for(lambda: len(made) == 4, timeout=5)        # first start + 3 restarts
        time.sleep(0.5)
        assert len(made) == 4
        assert all(p.stopped == 1 for p in made)
        part = g.parts["persistence"]
        assert part.state == "error" and "waits an hour" in part.message
        assert heartbeat(store)["parts"]["folders"]["state"] == "on"   # the guard carries on
    finally:
        g.stop()
    log_text = (settings.log_dir / "guard.log").read_text("utf-8")
    assert "persistence" in log_text


def test_part_that_fails_to_start(settings, store, watched, det, fast_guard, monkeypatch):
    specs = dict(service.PART_SPECS)
    specs["ransomware"] = (lambda g: StubPart(fail_start=True), specs["ransomware"][1], specs["ransomware"][2])
    monkeypatch.setattr(service, "PART_SPECS", specs)
    guard_settings(settings, watched, ransomware_guard=True)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        st = heartbeat(store)["parts"]["ransomware"]
        assert st["state"] == "error" and "unexpected problem" in st["message"]
        assert "boom" not in st["message"]                         # never raw exception text
    finally:
        g.stop()


def test_ransomware_switched_off_removes_decoys(settings, store, watched, det, fast_guard, monkeypatch):
    removed = []

    class Ransom(StubPart):
        def remove_decoys(self):
            removed.append(1)
            return 3
    specs = dict(service.PART_SPECS)
    specs["ransomware"] = (lambda g: Ransom(), specs["ransomware"][1], specs["ransomware"][2])
    monkeypatch.setattr(service, "PART_SPECS", specs)
    guard_settings(settings, watched, ransomware_guard=True)
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        assert heartbeat(store)["parts"]["ransomware"]["state"] == "on"
        guard_settings(Settings(data_dir=settings.data_dir), watched, ransomware_guard=False)
        assert wait_for(lambda: removed, timeout=5)
    finally:
        g.stop()


def test_catch_up_checks_files_changed_while_down(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    old = watched / "before.exe"
    old.write_bytes(sample_bytes())
    t = time.time() - 3600
    os.utime(old, (t, t))
    new = watched / "missed.exe"
    new.write_bytes(sample_bytes())
    store._con().execute("INSERT OR REPLACE INTO meta(key, value) VALUES('guard_state', ?)",
                         (json.dumps({"heartbeat": time.time() - 60}),))
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        # missed.exe is seconds old, so the quiet rule holds it for 2 s; before.exe has an old
        # modified time but was created just now (like a file unpacked from an archive)
        assert wait_for(lambda: len(events(store)) == 2, timeout=10)
        assert {e["path"] for e in events(store)} == {str(new), str(old)}
    finally:
        g.stop()


def test_catch_up_skips_old_files(settings, store, watched, det, monkeypatch):
    guard_settings(settings, watched)
    p = watched / "old.exe"
    p.write_bytes(sample_bytes())
    files = folders.recent_files([str(watched)], since=time.time() + 10)
    assert files == []
    files = folders.recent_files([str(watched)], since=time.time() - 60)
    assert [f for f, _ in files] == [str(p)]
    assert folders.recent_files([str(watched)], since=0, max_age_s=-1) == []


def test_guard_notifies_new_events(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    store.add_guard_event("file", "malware", "Old event")           # before start: not shown
    g = service.Guard(settings, store, detectors=[det])
    shown = []
    threads = []

    def show(ev):
        threads.append(threading.current_thread().name)
        time.sleep(0.5)                                  # a toast blocks; nothing else waits
        shown.append(ev["title"])
    g.notify_fn = show
    g.notes_fn = lambda: "Windows has notifications switched off for TacoGuard."
    g.start()
    try:
        store.add_guard_event("persistence", "warning", "New start-up entry: 'X' runs y.exe")
        store.add_guard_event("guard", "info", "Just info")
        assert wait_for(lambda: shown, timeout=3)
        time.sleep(0.3)
        assert shown == ["New start-up entry: 'X' runs y.exe"]
        assert threads == ["tacoguard-notify"]
        assert wait_for(lambda: heartbeat(store)["notes"] == [
            "Windows has notifications switched off for TacoGuard."], timeout=3)
    finally:
        g.stop()


def test_guard_reloads_detectors_when_signatures_change(settings, store, watched, fast_guard, monkeypatch):
    guard_settings(settings, watched)
    made = []

    class Versioned(FakeDetector):
        current = "v1"

        def version(self):
            return Versioned.current

    def load(s, st=None):
        made.append(Versioned())
        return [made[-1]]
    monkeypatch.setattr("tacoguard.detect.load_detectors", load)
    monkeypatch.setattr(service.Guard, "DETECTOR_CHECK_S", 0.1)
    g = service.Guard(settings, store)
    g.start()
    try:
        assert g.checker.sig_version == "v1"
        Versioned.current = "v2"
        assert wait_for(lambda: g.checker.sig_version == "v2", timeout=5)
        assert any(d.closed for d in made)
    finally:
        g.stop()


def test_real_yara_works_from_every_part_thread(settings, store, watched, fast_guard, tmp_path):
    """YARA-X's scanner panics when used on another thread than the one that made it: the
    checker runs every check on its own engine thread, whichever part asks."""
    from samples import TEST_YARA_RULE
    folder = settings.yara_dir / "custom"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "test.yar").write_text(TEST_YARA_RULE, encoding="utf-8")
    guard_settings(settings, watched, ml_enabled=False, clamav_enabled=False)
    g = service.Guard(settings, store)
    g.start()
    try:
        assert [d.name for d in g.checker.detectors] == ["hash", "yara"]
        (watched / "a.exe").write_bytes(sample_bytes())             # the folder part's thread
        assert wait_for(lambda: len(events(store)) == 1, timeout=10)
        exe = fake_program(tmp_path)
        out = []
        t = threading.Thread(target=lambda: out.append(g.checker.check_path(str(exe))))
        t.start()
        t.join(30)
        assert out and out[0].level == MALWARE                       # yet another thread
        assert out[0].findings[0].rule == "TacoGuard_Test_Harmless_Sample"
    finally:
        g.stop()


def test_mutex_name_differs_for_other_data_folders(settings):
    assert service.mutex_name(settings) != service.MUTEX_NAME
    assert service.mutex_name(Settings()) == service.MUTEX_NAME


# ---- the guard process --------------------------------------------------------------------------
def test_guard_process_runs_single_instance_and_stops_on_stop_file(settings, watched, tmp_path):
    guard_settings(settings, watched)
    env = {k: v for k, v in os.environ.items() if not k.startswith("TACOGUARD")}
    cmd = [PY, "-m", "tacoguard.guard", "--data", settings.data_dir]
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env, creationflags=0x08000000,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    guard_pid, guard_proc = 0, None
    try:
        st = Store(settings.db_path)

        def ours():
            # the venv's python.exe is a launcher: the guard may be its child
            pids = {proc.pid} | {c.pid for c in psutil.Process(proc.pid).children()}
            hb = heartbeat(st) or {}
            return hb.get("pid") in pids and hb["parts"]["folders"]["state"] == "on" and hb["pid"]
        guard_pid = wait_for(ours, timeout=60)
        assert guard_pid
        guard_proc = psutil.Process(guard_pid)
        assert guard_proc.nice() == psutil.BELOW_NORMAL_PRIORITY_CLASS
        second = subprocess.run(cmd, cwd=str(ROOT), env=env, creationflags=0x08000000,
                                capture_output=True, timeout=60)
        assert second.returncode == service.EXIT_ALREADY_RUNNING
        (settings.guard_dir / "stop").write_text("stop")
        assert proc.wait(30) == 0, proc.stderr.read()
        hb = heartbeat(st)
        assert all(part["state"] == "off" for part in hb["parts"].values())
        st.close()
    finally:
        if guard_proc is not None and guard_proc.is_running():   # same process (pid + start time)
            guard_proc.kill()
        if proc.poll() is None:
            proc.kill()
        proc.wait(10)


# ---- review fixes (2026-11-24) --------------------------------------------------------------------
PING = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
# a harmless program that just waits (pings this PC itself, nothing leaves it)
PING_ARGS = ["-n", "60", "127.0.0.1"]


def _start_copy(tmp_path, folder: str, name: str) -> subprocess.Popen:
    d = tmp_path / folder
    d.mkdir(parents=True, exist_ok=True)
    exe = d / name
    shutil.copyfile(PING, exe)
    p = subprocess.Popen([str(exe), *PING_ARGS], stdout=subprocess.DEVNULL, creationflags=0x08000000)
    assert wait_for(lambda: procctl.ref_of(p.pid), timeout=5)
    return p


def _end(*procs):
    for p in procs:
        r = procctl.ref_of(p.pid)
        if r:
            try:
                procctl.resume(r)
            except procctl.ProcError:
                pass
        try:
            p.kill()
            p.wait(10)
        except OSError:
            pass


def test_own_pids_count_only_our_own_programs(tmp_path):
    # (the test's name must not contain "tacoguard": tmp_path is named after it and is on the
    # command lines below)
    assert "tacoguard" not in str(tmp_path).lower()
    engines = tmp_path / "data" / "engines"
    # a "TacoGuard" interpreter (its command line names tacoguard) that starts a plain Python child
    # (like a browser the page opened, or a program run from a download) and a ClamAV-named program
    spawn = ("import subprocess, sys, time\n"
             "a = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
             "b = subprocess.Popen([sys.argv[1], '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL)\n"
             "print(a.pid, b.pid, flush=True)\n"
             "time.sleep(60)\n")
    # an ordinary program (not TacoGuard) that starts two ClamAV-named copies: one inside
    # TacoGuard's engines folder, one elsewhere (this test process itself always counts as
    # TacoGuard's, so it must not be their parent)
    starter = ("import subprocess, sys, time\n"
               "a = subprocess.Popen([sys.argv[1], '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL)\n"
               "b = subprocess.Popen([sys.argv[2], '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL)\n"
               "print(a.pid, b.pid, flush=True)\n"
               "time.sleep(60)\n")
    copies = {}
    for folder, name in (("other", "clamscan.exe"), ("data/engines/clamav", "clamd.exe"), ("elsewhere", "clamd.exe")):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
        copies[folder] = tmp_path / folder / name
        shutil.copyfile(PING, copies[folder])
    taco = subprocess.Popen([CHILD_PY, "-c", spawn, str(copies["other"]), "tacoguard.scan.worker"],
                            stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
    plain = subprocess.Popen([CHILD_PY, "-c", starter, str(copies["data/engines/clamav"]), str(copies["elsewhere"])],
                             stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
    started: list[int] = []
    try:
        grandchild, clam_pid = (int(x) for x in taco.stdout.readline().split())
        in_engines, elsewhere = (int(x) for x in plain.stdout.readline().split())
        started += [grandchild, clam_pid, in_engines, elsewhere]
        own = procctl.tacoguard_pids(engines_dir=engines)
        assert os.getpid() in own
        assert taco.pid in own                    # names tacoguard on its command line
        assert clam_pid in own                    # ClamAV started by TacoGuard
        assert in_engines in own                  # ClamAV from TacoGuard's engines folder
        assert grandchild not in own              # started by TacoGuard, but not TacoGuard
        assert plain.pid not in own and elsewhere not in own
    finally:
        for pid in started:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        _end(taco, plain)


class FakeP:
    """Stands in for a psutil.Process in protected_reason (nothing is paused)."""

    def __init__(self, name, exe, pid=999_999):
        self.pid, self._name, self._exe = pid, name, exe

    def name(self):
        return self._name

    def exe(self):
        if isinstance(self._exe, Exception):
            raise self._exe
        return self._exe

    def username(self):
        return psutil.Process().username()


def test_protected_names_count_only_in_their_real_place(monkeypatch):
    win = os.environ.get("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(procctl, "_microsoft_signed", lambda exe: False)
    assert procctl.protected_reason(FakeP("svchost.exe", os.path.join(win, "System32", "svchost.exe")), set())
    defender = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender",
                            "Platform", "4.18.1", "MsMpEng.exe")
    assert procctl.protected_reason(FakeP("msmpeng.exe", defender), set())
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    webview = os.path.join(pf86, "Microsoft", "EdgeWebView", "Application", "1.0", "msedgewebview2.exe")
    assert procctl.protected_reason(FakeP("msedgewebview2.exe", webview), set())
    appdata = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "x")
    for name in ("svchost.exe", "explorer.exe", "runtimebroker.exe", "msedgewebview2.exe"):
        assert procctl.protected_reason(FakeP(name, os.path.join(appdata, name)), set()) is None, name
    # Windows does not say where it is: stays protected
    assert procctl.protected_reason(FakeP("svchost.exe", psutil.AccessDenied(1)), set())
    assert procctl.protected_reason(FakeP("explorer.exe", ""), set())
    # a Microsoft-signed copy elsewhere is still treated as Windows' own
    monkeypatch.setattr(procctl, "_microsoft_signed", lambda exe: True)
    assert procctl.protected_reason(FakeP("svchost.exe", os.path.join(appdata, "svchost.exe")), set())


def test_a_program_named_like_windows_outside_windows_can_be_paused(tmp_path, monkeypatch):
    p = _start_copy(tmp_path, "AppData/Roaming/x", "svchost.exe")
    try:
        ref = procctl.ref_of(p.pid)
        proc = psutil.Process(p.pid)
        # this copy of PING carries Microsoft's catalog signature, so the real check protects it ...
        if procctl._microsoft_signed(proc.exe()):
            assert procctl.protected_reason(proc, set())
        # ... and a copy that is not Microsoft's (the signature check says no) is not "part of Windows"
        monkeypatch.setattr(procctl, "_microsoft_signed", lambda exe: False)
        assert procctl.protected_reason(proc, set()) is None
        procctl.suspend(ref, own=set())
        assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
        procctl.resume(ref)
        assert wait_for(lambda: not procctl.is_suspended(ref), timeout=5)
    finally:
        _end(p)


def test_microsoft_signature_is_cached(tmp_path, monkeypatch):
    calls = []
    import tacoguard.signing as signing
    real = signing.check_signature

    def counting(path):
        calls.append(path)
        return real(path)
    monkeypatch.setattr(signing, "check_signature", counting)
    procctl._sig_cache.clear()
    exe = tmp_path / "x.exe"
    exe.write_bytes(b"MZ not really a program")
    assert procctl._microsoft_signed(str(exe)) is False
    assert procctl._microsoft_signed(str(exe)) is False
    assert len(calls) == 1


def test_resume_undoes_a_double_pause(child):
    p, ref = child
    procctl.suspend(ref, own=set())
    procctl._nt("NtSuspendProcess", ref)               # paused twice (as an old guard restart did)
    assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
    procctl.resume(ref)                                # one Resume is enough
    assert wait_for(lambda: not procctl.is_suspended(ref), timeout=5)


def test_test_pause_limit_env(monkeypatch, child):
    p, ref = child
    monkeypatch.delenv(procctl.TEST_PAUSE_ONLY_ENV, raising=False)
    assert procctl.pause_allowed(12345)
    monkeypatch.setenv(procctl.TEST_PAUSE_ONLY_ENV, f"1, {p.pid}")
    assert procctl.pause_allowed(p.pid) and not procctl.pause_allowed(12345)
    monkeypatch.setenv(procctl.TEST_PAUSE_ONLY_ENV, "1")
    with pytest.raises(procctl.ProcError, match="test setting"):
        procctl.suspend(ref, own=set())
    assert not procctl.is_suspended(ref)


def test_guard_restart_does_not_pause_twice_or_alert_again(settings, store, chk, tmp_path, child):
    p, ref = child
    exe = fake_program(tmp_path)
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    eid = pw.handle(ref, str(exe), "python.exe")
    assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
    n_events = len(events(store))
    # a fresh guard (restart, memory recycle) checks the running programs again
    chk2 = RealtimeChecker(settings, store, [FakeDetector()])
    try:
        pw2 = ProcessWatcher(settings, store, chk2, own=set(), check_running=False)
        assert pw2.handle(ref, str(exe), "python.exe") == eid
    finally:
        chk2.close()
    assert len(events(store)) == n_events and len(store.list_paused()) == 1
    procctl.resume(ref)                                # one Resume unfreezes it
    assert wait_for(lambda: not procctl.is_suspended(ref), timeout=5)
    store.set_paused_state(store.list_paused()[0]["id"], "resumed")
    # you resumed it: the next restart leaves it alone too
    chk3 = RealtimeChecker(settings, store, [FakeDetector()])
    try:
        pw3 = ProcessWatcher(settings, store, chk3, own=set(), check_running=False)
        assert pw3.handle(ref, str(exe), "python.exe") == eid
    finally:
        chk3.close()
    assert not procctl.is_suspended(ref) and len(events(store)) == n_events


def test_already_paused_program_is_not_paused_again(settings, store, chk, tmp_path, child, monkeypatch):
    p, ref = child
    procctl.suspend(ref, own=set())                    # paused by something else
    assert wait_for(lambda: procctl.is_suspended(ref), timeout=5)
    calls = []
    monkeypatch.setattr(procctl, "suspend", lambda r, own=None: calls.append(r))
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "python.exe"))
    assert calls == [] and ev["title"].startswith("Paused: ")
    (row,) = store.list_paused()
    assert row["pid"] == p.pid and ev["data"]["paused_id"] == row["id"]


def test_test_pause_limit_stops_the_program_watcher(settings, store, chk, tmp_path, child, monkeypatch):
    p, ref = child
    monkeypatch.setenv(procctl.TEST_PAUSE_ONLY_ENV, "1")
    pw = ProcessWatcher(settings, store, chk, own=set(), check_running=False)
    ev = store.get_guard_event(pw.handle(ref, str(fake_program(tmp_path)), "python.exe"))
    assert "did not pause" in ev["message"] and "test setting" in ev["message"]
    assert store.list_paused(("paused", "not_paused", "resumed")) == [] and not procctl.is_suspended(ref)


# ---- FolderWatcher overflow storms -------------------------------------------------------------------
def test_overflows_keep_one_rescan_per_root(settings, store, chk, watched, tmp_path):
    h = WatchHub()                               # not started: events are fed by hand
    other = tmp_path / "other"
    other.mkdir()
    settings.watch_folders = [str(watched), str(other)]
    w = FolderWatcher(settings, store, chk, h)
    w.roots = [str(watched), str(other)]
    for _ in range(50):
        w._on_event(FsEvent("overflow", str(watched)))
    w._on_event(FsEvent("overflow", str(other)))
    assert len(w._rescan) == 2
    key = winpath.norm_key(str(watched))
    w._rescan[key][1] = 100.0                    # an earlier overflow's start time is kept
    w._on_event(FsEvent("overflow", str(watched)))
    assert len(w._rescan) == 2 and w._rescan[key][1] == 100.0


def test_rescans_do_not_starve_file_checks(settings, store, chk, watched):
    h = WatchHub()
    settings.watch_folders = [str(watched)]
    w = FolderWatcher(settings, store, chk, h)
    w.roots = [str(watched)]
    w.RESCAN_BATCH = 3
    for i in range(5):
        w.enqueue([(str(watched / f"f{i}.txt"), 1000.0 + i)])
    w._on_event(FsEvent("overflow", str(watched)))
    got = []
    for _ in range(5):
        item = w._next()
        got.append("rescan" if isinstance(item, tuple) else "file")
    # files waiting are served first; the rescan comes after a batch of them
    assert got == ["file", "file", "file", "rescan", "file"]
    w._stop = True


# ---- the guard: leftover decoys, panics -------------------------------------------------------------
def test_leftover_decoys_are_removed_at_start_when_the_ransomware_guard_is_off(settings, store, watched, det,
                                                                              fast_guard, tmp_path):
    from tacoguard.guard import ransom
    canary = tmp_path / "Docs"
    canary.mkdir()
    settings.canary_folders = [str(canary)]
    placed = ransom.RansomGuard(settings, store, None).place_decoys()
    assert placed and all(Path(p).exists() for p in placed)
    guard_settings(settings, watched, ransomware_guard=False)      # switched off while the guard was down
    g = service.Guard(settings, store, detectors=[det])
    g.start()
    try:
        assert not any(Path(p).exists() for p in placed)
        assert not ransom.manifest_path(settings).exists()
    finally:
        g.stop()


class FakePanic(BaseException):
    """Like pyo3's PanicException: a BaseException, not an Exception."""


def test_control_loop_survives_a_panic(settings, store, watched, det, fast_guard, monkeypatch):
    guard_settings(settings, watched)
    g = service.Guard(settings, store, detectors=[det])
    boom = {"n": 0}
    real = g._check_parts_health

    def health():
        boom["n"] += 1
        if boom["n"] <= 3:
            raise FakePanic("a Rust panic")
        real()
    monkeypatch.setattr(g, "_check_parts_health", health)
    g.start()
    try:
        first = heartbeat(store)["heartbeat"]
        assert wait_for(lambda: boom["n"] > 3 and heartbeat(store)["heartbeat"] > first, timeout=5)
        assert g._thread.is_alive()
    finally:
        g.stop()


class PanicDetector(FakeDetector):
    def open(self):
        raise FakePanic("rule set panic")


def test_a_detector_that_panics_while_opening_does_not_stop_the_others(settings, store, watched, det, fast_guard):
    guard_settings(settings, watched)
    bad = PanicDetector(name="ml")
    g = service.Guard(settings, store, detectors=[bad, det])
    g.start()
    try:
        assert det.opened == 1 and [d.name for d in g.detectors] == ["yara"]
        assert any("could not start" in n for n in g.detector_notes)
        assert not any("rule set panic" in n for n in g.detector_notes)
        assert heartbeat(store)["parts"]["folders"]["state"] == "on"
    finally:
        g.stop()


def test_detector_loading_panic_is_caught(settings, store, watched, det, fast_guard, monkeypatch):
    guard_settings(settings, watched)
    import tacoguard.detect as detect_mod

    def panic(*a, **k):
        raise FakePanic("loading panic")
    monkeypatch.setattr(detect_mod, "load_detectors", panic)
    g = service.Guard(settings, store)                # loads its own detectors
    g.start()
    try:
        assert g.detectors == [] and heartbeat(store)["parts"]["folders"]["state"] == "on"
    finally:
        g.stop()
