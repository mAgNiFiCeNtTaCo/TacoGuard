from __future__ import annotations

import ctypes
import getpass
import hashlib
import io
import os
import random
import subprocess
import threading
import time
import zipfile
from ctypes import wintypes

import pytest

from samples import MARKER, sample_bytes
from tacoguard import allowlist, archives
from tacoguard.archives import ArchiveNote
from tacoguard.config import Settings
from tacoguard.store import Store
from tacoguard.detect.base import DetectorError, DetectorUnavailable
from tacoguard.model import (CLEAN, MALWARE, SCANNED, SKIPPED, TRUSTED, UNREADABLE, Confidence, FileResult,
                             Finding, ScanItem)
from tacoguard.scan import engine, walker


class FakeDetector:
    """Flags MARKER. Records every item it was given."""

    def __init__(self, name="yara", version="v1", scans_members=True, fail=False, unavailable="",
                 on_scan=None):
        self.name, self._version, self.scans_members = name, version, scans_members
        self.fail, self.unavailable, self.on_scan = fail, unavailable, on_scan
        self.seen: list[ScanItem] = []
        self.opened = self.closed = 0

    def status(self):
        return {"ready": True, "message": "", "version": self._version, "updated": 0, "count": 1}

    def version(self):
        return self._version

    def open(self):
        self.opened += 1
        if self.unavailable:
            raise DetectorUnavailable(self.unavailable)

    def close(self):
        self.closed += 1

    def scan(self, item):
        self.seen.append(item)
        if self.on_scan:
            self.on_scan(item)
        if self.fail:
            raise DetectorError("This check could not read the file")
        data = item.data
        if data is None:
            with open(item.path, "rb") as f:
                data = f.read()
        if MARKER in data:
            return [Finding(engine=self.name, rule="Test_Marker", confidence=Confidence.HIGH, source="tests")]
        return []


def run(settings, store, targets, detectors):
    job_id = store.create_job([str(t) for t in targets])
    engine.scan_job(settings, store, job_id, detectors)
    return store.get_job(job_id), store.list_results(job_id)


def entry_for(path):
    (e,) = [t for t in walker.walk([str(path)]) if isinstance(t, walker.FileEntry)]
    return e


def check(settings, store, path, detectors, sig="v1"):
    return engine.check_file(entry_for(path), detectors, allowlist.TrustChecker(store), settings, store, sig)


# ---- one file ---------------------------------------------------------------------------------

def test_small_file_read_once_and_given_as_bytes_and_path(settings, store, tmp_path):
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    d = FakeDetector()
    r = check(settings, store, p, [d])
    assert r.status == SCANNED and r.level == MALWARE
    assert r.sha256 == hashlib.sha256(sample_bytes()).hexdigest()
    assert d.seen[0].data == sample_bytes() and d.seen[0].path.startswith("\\\\?\\")


def test_big_file_is_streamed_and_given_as_path(settings, store, tmp_path):
    settings.limits.in_memory_max = 16
    p = tmp_path / "big.txt"
    p.write_bytes(b"y" * 3000 + MARKER)
    d = FakeDetector()
    r = check(settings, store, p, [d])
    assert d.seen[0].data is None and r.level == MALWARE
    assert r.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()


def test_detector_error_becomes_note_and_others_still_run(settings, store, tmp_path):
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    bad, good = FakeDetector("clamav", fail=True), FakeDetector("yara")
    r = check(settings, store, p, [bad, good])
    assert r.level == MALWARE and r.incomplete
    assert r.notes == ["This check could not read the file"]


def test_locked_file_is_unreadable(settings, store, tmp_path):
    p = tmp_path / "locked.txt"
    p.write_bytes(b"busy")
    e = entry_for(p)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    h = k32.CreateFileW(str(p), 0x80000000, 0, None, 3, 0x80, None)   # GENERIC_READ, no sharing
    assert h and h != wintypes.HANDLE(-1).value
    try:
        r = engine.check_file(e, [FakeDetector()], allowlist.TrustChecker(store), settings, store, "v1")
    finally:
        k32.CloseHandle(wintypes.HANDLE(h))
    assert r.status == UNREADABLE and r.notes == [engine.IN_USE_NOTE]


def test_region_locked_file_is_unreadable(settings, store, tmp_path):
    import msvcrt
    p = tmp_path / "region.txt"
    p.write_bytes(b"0123456789")
    e = entry_for(p)
    with open(p, "r+b") as f:
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 10)
        try:
            r = engine.check_file(e, [FakeDetector()], allowlist.TrustChecker(store), settings, store, "v1")
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 10)
    assert r.status == UNREADABLE and r.notes == [engine.IN_USE_NOTE]


def test_file_without_permission_is_unreadable(settings, store, tmp_path):
    p = tmp_path / "private.txt"
    p.write_bytes(b"x")
    user = f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}".lstrip("\\")
    e = entry_for(p)
    icacls = lambda *a: subprocess.run(["icacls", str(p), *a], capture_output=True, creationflags=0x08000000)
    if icacls("/deny", f"{user}:(R)").returncode != 0:
        pytest.skip("icacls deny failed")
    try:
        r = engine.check_file(e, [FakeDetector()], allowlist.TrustChecker(store), settings, store, "v1")
    finally:
        icacls("/remove:d", user)
    assert r.status == UNREADABLE and r.notes == [engine.NO_PERMISSION_NOTE]


def test_vanished_file_is_skipped_quietly(settings, store, tmp_path):
    p = tmp_path / "gone.txt"
    p.write_bytes(b"x")
    e = entry_for(p)
    p.unlink()
    assert engine.check_file(e, [FakeDetector()], allowlist.TrustChecker(store), settings, store, "v1") is None


def test_folder_and_hash_allowlist(settings, store, tmp_path):
    trusted_dir = tmp_path / "tools"
    trusted_dir.mkdir()
    (trusted_dir / "t.txt").write_bytes(sample_bytes())
    other = tmp_path / "o.txt"
    other.write_bytes(sample_bytes(prefix=b"other"))
    allowlist.trust_folder(store, str(trusted_dir))
    allowlist.trust_hash(store, hashlib.sha256(other.read_bytes()).hexdigest(), "mine")
    d = FakeDetector()
    a = check(settings, store, trusted_dir / "t.txt", [d])
    b = check(settings, store, other, [d])
    assert a.status == TRUSTED and "folder you trust" in a.notes[0]
    assert b.status == TRUSTED and "marked this exact file as safe" in b.notes[0]
    assert d.seen == []


# ---- cache ------------------------------------------------------------------------------------

def test_clean_cache_hit_and_invalidation(settings, store, tmp_path):
    p = tmp_path / "clean.txt"
    p.write_bytes(b"nothing here")
    d = FakeDetector()
    assert check(settings, store, p, [d]).level == CLEAN and len(d.seen) == 1
    r = check(settings, store, p, [d])
    assert r.level == CLEAN and r.sha256 and len(d.seen) == 1            # cache hit
    check(settings, store, p, [d], sig="v2")
    assert len(d.seen) == 2                                              # new signatures
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    check(settings, store, p, [d], sig="v2")
    assert len(d.seen) == 3                                              # file changed


def test_detections_are_never_cached(settings, store, tmp_path):
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    d = FakeDetector()
    check(settings, store, p, [d])
    check(settings, store, p, [d])
    assert len(d.seen) == 2


# ---- archives ---------------------------------------------------------------------------------

def _fake_archive(members: dict[str, bytes], locked: bool = False) -> bytes:
    """A made-up archive format: member contents hex-encoded, so the outer file never shows MARKER."""
    lines = [f"{name}={data.hex()}".encode() for name, data in members.items()]
    return b"\n".join([b"FAKEARC1", *lines] + ([b"LOCKED"] if locked else []))


def _fake_iter_members(item, limits, tmp_dir=None):
    data = item.data if item.data is not None else open(item.path, "rb").read()
    for line in data.split(b"\n")[1:]:
        if line == b"LOCKED":
            yield ArchiveNote("encrypted", "Password-protected archive: the files inside were not checked.")
        elif b"=" in line:
            name, hexed = line.split(b"=", 1)
            content, m = bytes.fromhex(hexed.decode()), name.decode()
            yield ScanItem(display=f"{item.display} > {m}", data=content, size=len(content), member=m,
                           depth=item.depth + 1)


@pytest.fixture
def fake_archives(monkeypatch):
    monkeypatch.setattr(archives, "archive_kind", lambda head: "zip" if head.startswith(b"FAKEARC") else None)
    monkeypatch.setattr(archives, "iter_members", _fake_iter_members)


def test_archive_members_checked_by_member_detectors_only(settings, store, tmp_path, fake_archives):
    p = tmp_path / "a.fake"
    p.write_bytes(_fake_archive({"ok.txt": b"hello", "inner\\bad.txt": MARKER}, locked=True))
    yara, clam = FakeDetector("yara"), FakeDetector("clamav", scans_members=False)
    stats = {}
    r = engine.check_file(entry_for(p), [yara, clam], allowlist.TrustChecker(store), settings, store, "v1",
                          stats=stats)
    assert stats["archives_members"] == 2
    assert [f.member for f in r.findings] == ["inner\\bad.txt"]
    assert r.incomplete and r.notes == ["Password-protected archive: the files inside were not checked."]
    assert len(clam.seen) == 1 and len(yara.seen) == 3


def test_allowlisted_member_is_skipped(settings, store, tmp_path, fake_archives):
    p = tmp_path / "a.fake"
    p.write_bytes(_fake_archive({"bad.txt": MARKER}))
    allowlist.trust_hash(store, hashlib.sha256(MARKER).hexdigest(), "fine")
    yara = FakeDetector("yara")
    r = check(settings, store, p, [yara])
    assert r.level == CLEAN and len(yara.seen) == 1


def test_real_zip_if_archives_ready(settings, store, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docs/readme.txt", b"hello")
        z.writestr("docs/sample.txt", sample_bytes())
    try:
        list(archives.iter_members(ScanItem(display="x.zip", data=buf.getvalue()), settings.limits))
    except NotImplementedError:
        pytest.skip("archives.iter_members is not implemented yet")
    p = tmp_path / "x.zip"
    p.write_bytes(buf.getvalue())
    r = check(settings, store, p, [FakeDetector("yara")])
    # the zip is stored uncompressed, so the outer file matches too; the member must be found as well
    assert r.level == MALWARE
    assert any(f.member.replace("/", "\\") == "docs\\sample.txt" for f in r.findings)


# ---- whole job --------------------------------------------------------------------------------

def _folder(tmp_path, n=10, bad=(3,)):
    root = tmp_path / "scan"
    root.mkdir()
    for i in range(n):
        (root / f"f{i:03}.txt").write_bytes(sample_bytes() if i in bad else f"clean {i}".encode())
    return root


def test_job_counts_message_and_only_notable_results(settings, store, tmp_path):
    root = _folder(tmp_path, 10, bad=(3, 7))
    settings.limits.max_file_size = 1000
    (root / "huge.bin").write_bytes(b"z" * 2000)
    d = FakeDetector()
    job, results = run(settings, store, [root], [d])
    c = job["counts"]
    assert job["status"] == "done" and d.opened == 1 and d.closed == 1
    assert (c["files"], c["clean"], c["malware"], c["skipped"]) == (10, 8, 2, 1)
    assert sorted(os.path.basename(r["path"]) for r in results) == ["f003.txt", "f007.txt", "huge.bin"]
    assert job["message"].startswith("Done: 10 files checked in ") and "0 suspicious, 2 malware, 0 could not be read, 1 skipped." in job["message"]
    assert job["checkpoint"] == str(root / "huge.bin") and job["sig_version"] == "v1"
    skipped = [r for r in results if r["status"] == SKIPPED][0]
    assert "limit" in skipped["reason"]


def test_one_detector_unavailable_is_noted(settings, store, tmp_path):
    root = _folder(tmp_path, 3)
    clam = FakeDetector("clamav", unavailable="signatures not downloaded yet")
    job, _ = run(settings, store, [root], [FakeDetector("yara"), clam])
    assert job["status"] == "done" and "ClamAV not used: signatures not downloaded yet." in job["message"]
    assert clam.closed == 1 and job["sig_version"] == "v1"


def test_no_detector_available_fails_plainly(settings, store, tmp_path):
    root = _folder(tmp_path, 3)
    d = FakeDetector("yara", unavailable="no rules yet")
    job, _ = run(settings, store, [root], [d])
    assert job["status"] == "failed" and job["message"] == engine.NO_SIGNATURES_MSG and d.closed == 1


def test_only_an_empty_hash_list_is_not_a_scan(settings, store, tmp_path):
    """Review 2026-11-23: with no YARA rules and no ClamAV, the empty known-bad list opened fine
    and the scan said 'Done' and cached every file as clean."""
    from tacoguard.detect.hashsets import HashDetector
    root = _folder(tmp_path, 3)
    yara = FakeDetector("yara", unavailable="YARA rules have not been downloaded yet")
    clam = FakeDetector("clamav", unavailable="The ClamAV program has not been downloaded yet")
    job, results = run(settings, store, [root], [HashDetector(settings), yara, clam])
    assert job["status"] == "failed" and job["message"] == engine.NO_SIGNATURES_MSG
    assert results == [] and store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 0
    # a known-bad list with entries is a real check on its own
    (settings.hashset_dir / "mine.txt").write_text("ab" * 32 + "  test\n", encoding="utf-8")
    job, _ = run(settings, store, [root], [HashDetector(settings), yara, clam])
    assert job["status"] == "done"
    # and YARA alone carries on as before, with the note about ClamAV
    job, _ = run(settings, store, [root], [HashDetector(settings), FakeDetector("yara"), clam])
    assert job["status"] == "done" and "ClamAV not used" in job["message"]


def test_detector_that_cannot_start_is_named_without_raw_windows_codes(settings, store, tmp_path):
    root = _folder(tmp_path, 2)

    class Broken(FakeDetector):
        def open(self):
            raise PermissionError(5, "Access is denied", "C:\\x")
    job, _ = run(settings, store, [root], [Broken("clamav")])
    assert job["status"] == "failed" and job["message"].startswith(engine.NO_CHECKS_MSG)
    assert "Windows refused access" in job["message"] and "WinError" not in job["message"]


def test_out_of_memory_on_one_file_is_noted_and_the_scan_goes_on(settings, store, tmp_path, monkeypatch):
    root = _folder(tmp_path, 4, bad=(3,))
    real = engine.check_file

    def check(entry, *a, **k):
        if entry.display.endswith("f001.txt"):
            raise MemoryError
        return real(entry, *a, **k)
    monkeypatch.setattr(engine, "check_file", check)
    hungry = FakeDetector("clamav", on_scan=lambda item: (_ for _ in ()).throw(MemoryError)
                          if item.display.endswith("f002.txt") else None)
    job, results = run(settings, store, [root], [FakeDetector(), hungry])
    assert job["status"] == "done" and job["counts"]["files"] == 4 and job["counts"]["malware"] == 1
    by_name = {os.path.basename(r["path"]): r for r in results}
    assert by_name["f001.txt"]["incomplete"] and by_name["f001.txt"]["notes"] == [engine.MEMORY_NOTE]
    assert by_name["f002.txt"]["incomplete"] and by_name["f002.txt"]["notes"] == [engine.MEMORY_NOTE]
    assert by_name["f003.txt"]["level"] == MALWARE


@pytest.mark.parametrize("control,status", [("pause", "paused"), ("cancel", "cancelled")])
def test_pause_and_cancel_between_files(settings, store, tmp_path, control, status):
    root = _folder(tmp_path, 10, bad=(1, 8))
    job_id = store.create_job([str(root)])

    def on_scan(item):
        if item.display.endswith("f004.txt"):
            store.set_control(job_id, control)

    d = FakeDetector(on_scan=on_scan)
    engine.scan_job(settings, store, job_id, [d])
    job = store.get_job(job_id)
    assert job["status"] == status and job["control"] == ""
    assert job["checkpoint"].endswith("f004.txt") and job["counts"]["files"] == 5
    if control == "pause":
        d2 = FakeDetector()
        engine.scan_job(settings, store, job_id, [d2])
        job = store.get_job(job_id)
        assert job["status"] == "done" and job["counts"]["files"] == 10
        assert [os.path.basename(i.display) for i in d2.seen][0] == "f005.txt"
        assert len(store.list_results(job_id)) == 2


def test_resume_does_not_report_twice(settings, store, tmp_path):
    root = _folder(tmp_path, 5, bad=(1,))
    job_id = store.create_job([str(root)])
    engine.scan_job(settings, store, job_id, [FakeDetector()])
    store.update_job(job_id, checkpoint="", counts={})   # as if killed before the first save
    engine.scan_job(settings, store, job_id, [FakeDetector()])
    assert len(store.list_results(job_id)) == 1


def test_resume_replaces_an_older_row_so_a_detection_is_never_lost(settings, store, tmp_path):
    """Review 2026-11-23: a file stored as 'could not be read' before a crash, flagged after the
    resume, kept only the old row."""
    root = _folder(tmp_path, 3, bad=(1,))
    job_id = store.create_job([str(root)])
    old = FileResult(path=str(root / "f001.txt"), status=UNREADABLE, notes=[engine.IN_USE_NOTE])
    store.add_result(job_id, old)                         # written just before the crash
    store.update_job(job_id, status="interrupted")
    engine.scan_job(settings, store, job_id, [FakeDetector()])
    job, results = store.get_job(job_id), store.list_results(job_id)
    assert len(results) == 1 and results[0]["level"] == MALWARE and results[0]["status"] == SCANNED
    assert job["counts"]["malware"] == 1 and job["counts"]["unreadable"] == 0 and job["counts"]["files"] == 3
    # the same result again changes nothing
    rid = results[0]["id"]
    store.update_job(job_id, checkpoint="", counts={})
    engine.scan_job(settings, store, job_id, [FakeDetector()])
    assert [r["id"] for r in store.list_results(job_id)] == [rid]
    assert store.get_job(job_id)["counts"]["malware"] == 1


def test_resume_removes_an_older_row_when_the_file_is_now_clean(settings, store, tmp_path):
    """Review 2026-11-23: a file stored as 'could not be read' before a crash and clean after the
    resume kept its old row, so the page listed it while the counts said 0 could not be read."""
    root = _folder(tmp_path, 3, bad=())
    job_id = store.create_job([str(root)])
    store.add_result(job_id, FileResult(path=str(root / "f001.txt"), status=UNREADABLE,
                                        notes=[engine.IN_USE_NOTE]))
    acted = store.add_result(job_id, FileResult(path=str(root / "f002.txt"), status=UNREADABLE,
                                                notes=[engine.IN_USE_NOTE]))
    store.set_result_action(acted, "trusted")             # the user already did something with it
    store.update_job(job_id, status="interrupted")
    engine.scan_job(settings, store, job_id, [FakeDetector()])
    job, results = store.get_job(job_id), store.list_results(job_id)
    assert job["counts"]["clean"] == 3 and job["counts"]["unreadable"] == 0
    assert [r["id"] for r in results] == [acted]           # only the row the user acted on stays
    assert store.remove_result(job_id, str(root / "f002.txt")) == 0


def test_throttle_limits_rate():
    t = engine.Throttle(4)                     # 4 MB/s, 1 MB burst
    start = time.monotonic()
    for _ in range(3):
        t.take(1024 * 1024)
    assert time.monotonic() - start >= 0.4
    off = engine.Throttle(0)
    start = time.monotonic()
    off.take(10**12)
    assert time.monotonic() - start < 0.1


def test_duration_wording():
    assert engine.fmt_duration(5) == "5 s"
    assert engine.fmt_duration(240) == "4 min"
    assert engine.fmt_duration(3 * 3600 + 120) == "3 h 2 min"


# ---- ClamAV checks several files at once ------------------------------------------------------

BROKEN_NOTE = "ClamAV could not check this file (test)."


class SlowClam(FakeDetector):
    """ClamAV-like: outer files only, a random delay per file. Flags files named in `bad`, fails
    with DetectorError on files named in `broken`. `parallel` lets the engine use its thread pool."""

    def __init__(self, parallel=True, bad=(), broken=(), seed=7, max_delay=0.03, on_scan=None):
        super().__init__("clamav", version="c1", scans_members=False, on_scan=on_scan)
        self.parallel, self.bad, self.broken, self.max_delay = parallel, set(bad), set(broken), max_delay
        self.rng, self.lock = random.Random(seed), threading.Lock()
        self.active = self.peak = 0
        self.threads: set[str] = set()

    def scan(self, item):
        name = os.path.basename(item.display)
        with self.lock:
            delay = self.rng.uniform(0, self.max_delay)
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.threads.add(threading.current_thread().name)
        try:
            time.sleep(delay)
            self.seen.append(item)
            if self.on_scan:
                self.on_scan(item)
            if name in self.broken:
                raise DetectorError(BROKEN_NOTE)
            if name in self.bad:
                return [Finding(engine="clamav", rule="Test.Clam", confidence=Confidence.HIGH, source="tests")]
            return []
        finally:
            with self.lock:
                self.active -= 1


CLAM_BAD = {"f010.txt", "a016.fake", "f031.txt"}
CLAM_BROKEN = {"f020.txt", "big024.bin"}


def _mixed_folder(tmp_path, n=40):
    """Clean files, YARA hits, archives (with a YARA hit inside), a streamed big file, a file over
    the size limit, ClamAV hits and ClamAV failures, in one folder."""
    root = tmp_path / "mixed"
    root.mkdir()
    for i in range(n):
        if i == 24:
            (root / f"big{i:03}.bin").write_bytes(b"b" * 10_000)              # over in_memory_max
        elif i == 30:
            (root / f"huge{i:03}.bin").write_bytes(b"h" * 60_000)             # over max_file_size
        elif i % 8 == 0:
            (root / f"a{i:03}.fake").write_bytes(_fake_archive({"in.txt": MARKER, "ok.txt": b"fine"}))
        elif i % 7 == 3:
            (root / f"f{i:03}.txt").write_bytes(sample_bytes(prefix=f"bad {i}\r\n".encode()))
        else:
            (root / f"f{i:03}.txt").write_bytes(f"clean {i}".encode())
    return root


def _job_settings(data_dir, threads):
    s = Settings(data_dir=str(data_dir))
    s.ensure_dirs()
    s.clamav_threads = threads
    s.limits.in_memory_max = 4096
    s.limits.max_file_size = 50_000
    return s


def _snapshot(store, job_id) -> dict:
    job = store.get_job(job_id)
    keys = ("path", "status", "level", "sha256", "size", "findings", "notes", "incomplete", "reason")
    return {
        "status": job["status"], "checkpoint": job["checkpoint"],
        "counts": {k: v for k, v in job["counts"].items() if k != "seconds"},
        "results": [{k: r[k] for k in keys} for r in store.list_results(job_id)],
        "cache": store._con().execute(
            "SELECT key, size, mtime_ns, sha256, sig_version FROM cache ORDER BY key").fetchall(),
    }


def _scan_in(data_dir, root, threads, clam, control_at=None):
    """Runs one job in its own data folder. `control_at`: (file name, 'pause'|'cancel') set from
    inside the ClamAV check of that file. Returns (settings, store, job_id); close the store."""
    s = _job_settings(data_dir, threads)
    st = Store(s.db_path)
    job_id = st.create_job([str(root)])
    if control_at:
        name, control = control_at
        clam.on_scan = lambda item: (st.set_control(job_id, control)
                                     if os.path.basename(item.display) == name else None)
    engine.scan_job(s, st, job_id, [FakeDetector("yara"), clam])
    return s, st, job_id


def _serial_snapshot(tmp_path, root) -> dict:
    s, st, job_id = _scan_in(tmp_path / "serial", root, 4, SlowClam(parallel=False, bad=CLAM_BAD,
                                                                     broken=CLAM_BROKEN, max_delay=0))
    try:
        return _snapshot(st, job_id)
    finally:
        st.close()


@pytest.mark.parametrize("threads", [1, 4, 8])
def test_parallel_clamav_gives_exactly_the_serial_results(tmp_path, fake_archives, threads):
    root = _mixed_folder(tmp_path)
    serial = _serial_snapshot(tmp_path, root)
    clam = SlowClam(bad=CLAM_BAD, broken=CLAM_BROKEN, seed=threads)
    s, st, job_id = _scan_in(tmp_path / "parallel", root, threads, clam)
    try:
        parallel = _snapshot(st, job_id)
    finally:
        st.close()

    assert parallel == serial
    assert serial["status"] == "done" and serial["counts"]["files"] == 39 and serial["counts"]["skipped"] == 1
    assert serial["counts"]["archives_members"] == 8 and serial["cache"]        # the walk really varied
    assert clam.threads and all(t.startswith("tacoguard-clamav") for t in clam.threads)
    assert 1 <= clam.peak <= threads and (threads == 1 or clam.peak > 1)
    assert all(item.member == "" for item in clam.seen)                          # outer files only
    by_name = {os.path.basename(r["path"]): r for r in parallel["results"]}
    assert by_name["f020.txt"]["notes"] == [BROKEN_NOTE] and by_name["f020.txt"]["incomplete"]
    assert by_name["big024.bin"]["notes"] == [BROKEN_NOTE]
    # the archive: ClamAV's finding on the outer file comes before YARA's on the file inside
    assert [(f["engine"], f["member"]) for f in by_name["a016.fake"]["findings"]] == [
        ("clamav", ""), ("yara", "in.txt")]


def _walk_order(root, max_file_size):
    return [t for t in walker.walk([str(root)], "", max_file_size)]


@pytest.mark.parametrize("control,status", [("pause", "paused"), ("cancel", "cancelled")])
def test_pause_and_cancel_mid_window_keep_a_true_checkpoint(tmp_path, fake_archives, control, status):
    root = _mixed_folder(tmp_path)
    serial = _serial_snapshot(tmp_path, root)
    clam = SlowClam(bad=CLAM_BAD, broken=CLAM_BROKEN, seed=3)
    s, st, job_id = _scan_in(tmp_path / "stopped", root, 4, clam, control_at=("f012.txt", control))
    try:
        stopped = _snapshot(st, job_id)
        assert stopped["status"] == status and st.get_job(job_id)["control"] == ""
        order = _walk_order(root, s.limits.max_file_size)
        names = [t.display for t in order]
        cut = names.index(stopped["checkpoint"])
        assert cut >= names.index(str(root / "f012.txt"))
        # everything up to the checkpoint is reported, nothing after it
        done = order[:cut + 1]
        assert stopped["counts"]["files"] == sum(isinstance(t, walker.FileEntry) for t in done)
        assert [r["path"] for r in stopped["results"]] == [
            r["path"] for r in serial["results"] if r["path"] in set(names[:cut + 1])]
        assert stopped["results"] == serial["results"][:len(stopped["results"])]
        assert {k for k, *_ in stopped["cache"]} <= {k for k, *_ in serial["cache"]}

        if control == "pause":
            again = SlowClam(bad=CLAM_BAD, broken=CLAM_BROKEN, seed=4)
            engine.scan_job(s, st, job_id, [FakeDetector("yara"), again])
            resumed = _snapshot(st, job_id)
            assert resumed == serial                    # nothing reported twice, nothing lost
            first = min(names.index(i.display) for i in again.seen)
            assert first > cut                          # resume starts after the checkpoint
    finally:
        st.close()


def test_memory_held_for_clamav_stays_under_the_cap(tmp_path, monkeypatch):
    root = tmp_path / "many"
    root.mkdir()
    for i in range(30):
        (root / f"m{i:03}.bin").write_bytes(bytes([i]) * 1000)
    windows = []

    class Watched(engine._Window):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            windows.append(self)
    monkeypatch.setattr(engine, "_Window", Watched)
    monkeypatch.setattr(engine, "WINDOW_MAX_BYTES", 3000)
    clam = SlowClam(max_delay=0.03)
    s, st, job_id = _scan_in(tmp_path / "data-mem", root, 8, clam)
    try:
        job = st.get_job(job_id)
    finally:
        st.close()
    assert job["status"] == "done" and job["counts"]["files"] == 30 and len(clam.seen) == 30
    (window,) = windows
    assert 2000 <= window.peak_bytes <= 3000 and window.held_bytes == 0
    assert clam.peak <= 3


def test_check_file_with_a_pool_returns_pending_and_merges_later(settings, store, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    p = tmp_path / "s.txt"
    p.write_bytes(b"nothing here")
    gate = threading.Event()
    clam = SlowClam(max_delay=0, on_scan=lambda item: gate.wait(5))
    with ThreadPoolExecutor(2) as pool:
        pending = engine.check_file(entry_for(p), [FakeDetector("yara"), clam], allowlist.TrustChecker(store),
                                    settings, store, "v1", pool=pool)
        assert isinstance(pending, engine.Pending) and not pending.done()
        assert pending.held_bytes == len(b"nothing here")
        assert store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 0   # not yet
        gate.set()
        r = pending.result()
    assert r.level == CLEAN and not r.incomplete and len(clam.seen) == 1
    assert store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 1


# ---- local learning (learning.py) hook ----------------------------------------------------------

def _mark_safe(store, rule, engine_name="yara", n=3, member=""):
    for i in range(n):
        f = Finding(engine=engine_name, rule=rule, confidence=Confidence.HIGH, source="tests", member=member)
        store.add_verdict(hashlib.sha256(f"safe {rule} {i}".encode()).hexdigest(), f"D:\\Games\\mod{i}.exe",
                          "not_a_threat",
                          [f.to_dict()])


def test_learning_lowers_a_rule_you_marked_safe_three_times(settings, store, tmp_path):
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    assert check(settings, store, p, [FakeDetector()]).level == MALWARE
    _mark_safe(store, "Test_Marker")
    r = check(settings, store, p, [FakeDetector()])
    (f,) = r.findings
    assert f.confidence == Confidence.MEDIUM and r.level == "suspicious"
    assert "you marked 3 files matching this rule as safe" in f.detail and "counts for less" in r.reason()
    settings.learning_enabled = False
    assert check(settings, store, p, [FakeDetector()]).level == MALWARE


def test_learning_applies_to_archive_members_and_pool_findings(settings, store, tmp_path, fake_archives):
    from concurrent.futures import ThreadPoolExecutor
    p = tmp_path / "a.fake"
    p.write_bytes(_fake_archive({"inner\\bad.txt": MARKER}))
    _mark_safe(store, "Test_Marker", member="x\\other.txt")
    _mark_safe(store, "Test.Clam", engine_name="clamav")
    r = check(settings, store, p, [FakeDetector()])
    assert [(f.member, int(f.confidence)) for f in r.findings] == [("inner\\bad.txt", 2)]
    clam = SlowClam(bad={"a.fake"}, max_delay=0)
    with ThreadPoolExecutor(2) as pool:
        r = engine.check_file(entry_for(p), [FakeDetector(), clam], allowlist.TrustChecker(store),
                              settings, store, "v1", pool=pool).result()
    assert sorted((f.engine, int(f.confidence)) for f in r.findings) == [("clamav", 2), ("yara", 2)]
    assert r.level == MALWARE      # two different engines at medium still agree: malware


# ---- a weak machine-learning score on its own is dropped ----------------------------------------

class FakeML:
    """ML-like detector: a fixed confidence for every item whose content contains `when`."""
    name, scans_members = "ml", True

    def __init__(self, confidence, when=b""):
        self.confidence, self.when = confidence, when

    def version(self):
        return "ml-1"

    def open(self):
        pass

    def close(self):
        pass

    def scan(self, item):
        data = item.data if item.data is not None else open(item.path, "rb").read()
        if self.when and self.when not in data:
            return []
        return [Finding("ml", "EMBER2024 PE model", self.confidence, "machine-learning model",
                        detail="machine-learning score 0.50 (test)", member=item.member)]


def test_lone_low_ml_finding_is_dropped_silently(settings, store, tmp_path):
    p = tmp_path / "tool.exe"
    p.write_bytes(b"MZ just a program")
    r = check(settings, store, p, [FakeML(Confidence.LOW)])
    assert r.findings == [] and r.notes == [] and r.level == CLEAN and not r.incomplete
    assert store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 1   # a normal clean file


def test_medium_ml_alone_is_still_suspicious(settings, store, tmp_path):
    p = tmp_path / "tool.exe"
    p.write_bytes(b"MZ just a program")
    r = check(settings, store, p, [FakeML(Confidence.MEDIUM)])
    assert [(f.engine, int(f.confidence)) for f in r.findings] == [("ml", 2)] and r.level == "suspicious"


def test_low_ml_stays_as_support_when_another_engine_matched_the_same_item(settings, store, tmp_path):
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    r = check(settings, store, p, [FakeDetector(), FakeML(Confidence.LOW)])
    assert sorted(f.engine for f in r.findings) == ["ml", "yara"]


def test_low_ml_is_judged_per_file_inside_an_archive(settings, store, tmp_path, fake_archives):
    p = tmp_path / "a.fake"
    p.write_bytes(_fake_archive({"bad.txt": MARKER + b" MZ", "other.exe": b"MZ plain"}))
    r = check(settings, store, p, [FakeDetector(), FakeML(Confidence.LOW, when=b"MZ")])
    # the YARA match is on bad.txt, so the weak ML score on bad.txt stays; other.exe's goes
    assert sorted((f.engine, f.member) for f in r.findings) == [("ml", "bad.txt"), ("yara", "bad.txt")]


def test_not_a_threat_clicks_never_switch_the_ml_check_off(settings, store, tmp_path):
    """Every ML finding has the same rule name: three 'not a threat' clicks on ML-flagged files
    must not lower (and so silently drop) every later ML MEDIUM, and nothing gets cached clean."""
    from tacoguard import learning
    _mark_safe(store, "EMBER2024 PE model", engine_name="ml")
    assert learning.learned_rules(store) == []
    p = tmp_path / "tool.exe"
    p.write_bytes(b"MZ just a program")
    for _ in range(2):
        r = check(settings, store, p, [FakeML(Confidence.MEDIUM)])
        assert [(f.engine, int(f.confidence)) for f in r.findings] == [("ml", 2)] and r.level == "suspicious"
    assert store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 0


def test_a_file_your_choices_cleared_is_not_cached(settings, store, tmp_path, monkeypatch):
    """If learning ever turns a finding into a clean result, the file must be checked again next
    time, so 'Forget', 'It's a threat' or turning learning off take effect."""
    from tacoguard import learning
    monkeypatch.setattr(learning, "NOT_LEARNED_ENGINES", ("hash",))   # the old, unsafe rule set
    _mark_safe(store, "EMBER2024 PE model", engine_name="ml")
    p = tmp_path / "tool.exe"
    p.write_bytes(b"MZ just a program")
    ml = FakeML(Confidence.MEDIUM)
    r = check(settings, store, p, [ml])
    assert r.findings == [] and r.level == CLEAN                      # lowered to LOW, then dropped
    assert store._con().execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 0
    learning.forget_rule(store, "ml", "EMBER2024 PE model")
    r = check(settings, store, p, [ml])
    assert r.level == "suspicious"                                    # checked again, not cached


def test_a_detector_note_is_shown_but_the_file_is_fully_checked(settings, store, tmp_path):
    from tacoguard.detect.base import DetectorNote

    class Skips(FakeDetector):
        def scan(self, item):
            self.seen.append(item)
            raise DetectorNote("Too many text strings inside to give it a machine-learning score; "
                               "checked with the other methods.")
    p = tmp_path / "s.txt"
    p.write_bytes(sample_bytes())
    r = check(settings, store, p, [FakeDetector(), Skips(name="ml")])
    assert r.level == MALWARE and not r.incomplete
    assert r.notes == ["Too many text strings inside to give it a machine-learning score; checked with "
                       "the other methods."]
    clean = tmp_path / "c.txt"
    clean.write_bytes(b"nothing here")
    skips = Skips(name="ml")
    r = check(settings, store, clean, [FakeDetector(), skips])
    assert r.level == CLEAN and not r.incomplete
    check(settings, store, clean, [FakeDetector(), skips])
    assert len(skips.seen) == 1                                       # cached like any clean file


def test_drop_lone_weak_ml_rule():
    ml_low = lambda m="": Finding("ml", "M", Confidence.LOW, "s", member=m)
    other = Finding("clamav", "C", Confidence.LOW, "s")
    assert engine.drop_lone_weak_ml([ml_low()]) == []
    assert engine.drop_lone_weak_ml([ml_low(), other]) == [ml_low(), other]
    assert engine.drop_lone_weak_ml([ml_low("x.exe"), other]) == [other]
    assert engine.drop_lone_weak_ml([ml_low(), ml_low("x.exe")]) == []
    medium = Finding("ml", "M", Confidence.MEDIUM, "s")
    assert engine.drop_lone_weak_ml([medium, ml_low()]) == [medium, ml_low()]   # MEDIUM ML supports it
