from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

import samples
from tacoguard.detect import clamav as C
from tacoguard.detect.base import DetectorError, DetectorUnavailable
from tacoguard.model import Confidence, ScanItem

# The real program is used read-only; tests never write into D:\TacoGuard.
REAL_PROGRAM = Path(r"D:\TacoGuard\engines\clamav")
REAL_DB = Path(r"D:\TacoGuard\signatures\clamav")
needs_clamd = pytest.mark.skipif(not (REAL_PROGRAM / "clamd.exe").exists(),
                                 reason="ClamAV program not set up in D:\\TacoGuard")


def _fake_cvd(path: Path, version: int, stime: int) -> None:
    head = f"ClamAV-VDB:23 Nov 2026 07-26 -0500:{version}:355843:90:x:y:builder:{stime}"
    path.write_bytes(head.encode().ljust(512, b" ") + b"rest of the database")


# ---- no clamd needed ----------------------------------------------------------------------

@pytest.mark.parametrize("name,confidence,detail", [
    ("Win.Trojan.Agent-1", Confidence.HIGH, ""),
    ("PUA.Win.Tool.Thing-2", Confidence.MEDIUM, "potentially unwanted program"),
    ("Heuristics.Encrypted.Zip", Confidence.LOW, "heuristic match"),
])
def test_signature_names_map_to_confidence(name, confidence, detail):
    f = C.make_finding(name)
    assert (f.confidence, f.detail, f.source) == (confidence, detail, C.OFFICIAL_SOURCE)


def test_odd_clamd_reply_is_plain_on_the_page_and_raw_in_the_log(settings):
    """Review 2026-11-23: clamd's raw reply text was shown on the page."""
    det = C.ClamAVDetector(settings, program_dir=settings.root / "no-program")
    item = ScanItem(display="C:\\x\\a.exe", data=b"x", size=1)
    raw = "stream: Can't allocate memory ERROR"
    with pytest.raises(DetectorError) as e:
        det._parse(raw, item)
    assert str(e.value) == C.ODD_ANSWER and "allocate" not in str(e.value)
    with pytest.raises(DetectorError) as e:
        det._parse("", item)
    assert str(e.value) == C.NO_ANSWER
    log = (settings.log_dir / "clamav-replies.log").read_text("utf-8")
    assert "Can't allocate memory" in log and "a.exe" in log and "(no answer)" in log


def test_test_signature_is_named_as_such():
    f = C.make_finding("TacoGuard.Test.HarmlessSample-1.UNOFFICIAL")
    assert f.rule == "TacoGuard.Test.HarmlessSample-1" and f.source == "test signature"


def test_database_headers_give_status_without_starting_clamd(settings):
    det = C.ClamAVDetector(settings, program_dir=settings.root / "no-program")
    assert det.status()["message"] == "ClamAV program not downloaded yet: press Get signatures."
    _fake_cvd(settings.clamav_db_dir / "daily.cld", 27850, 1795420000)
    _fake_cvd(settings.clamav_db_dir / "main.cvd", 62, 1700000000)
    info = C.database_info(settings.clamav_db_dir)
    assert info["daily"]["version"] == "27850" and info["main"]["version"] == "62"
    assert C.describe_databases(info).startswith("ClamAV signatures from 2026-11-2")
    assert "(daily 27850)" in C.describe_databases(info)
    assert det.version() == "clamav-main62-daily27850"
    with pytest.raises(DetectorUnavailable, match="program has not been downloaded"):
        det.open()


def test_no_signatures_is_unavailable(settings):
    det = C.ClamAVDetector(settings, program_dir=REAL_PROGRAM)
    if (REAL_PROGRAM / "clamd.exe").exists():
        assert det.status()["message"] == "Not downloaded yet: press Get signatures."
        with pytest.raises(DetectorUnavailable, match="signatures have not been downloaded"):
            det.open()


# ---- real clamd with the test-only signature (loads in about a second) ---------------------

@pytest.fixture
def test_clamd(settings):
    (settings.clamav_db_dir / "tacoguard-test.ndb").write_text(samples.TEST_CLAMAV_NDB, encoding="ascii")
    det = C.ClamAVDetector(settings, program_dir=REAL_PROGRAM)
    det.open()
    yield det
    det.close()


@pytest.mark.clamav
@needs_clamd
def test_scan_in_memory_and_on_disk(test_clamd, tmp_path):
    found = test_clamd.scan(ScanItem(display="mem", data=samples.sample_bytes()))
    assert [(f.rule, f.source, f.confidence) for f in found] == [
        ("TacoGuard.Test.HarmlessSample-1", "test signature", Confidence.HIGH)]
    assert test_clamd.scan(ScanItem(display="clean", data=b"nothing to see")) == []

    deep = "\\\\?\\" + str(tmp_path)
    for i in range(6):
        deep += f"\\level{i}_" + "y" * 45
    os.makedirs(deep)
    path = deep + "\\sample.txt"
    with open(path, "wb") as f:
        f.write(samples.sample_bytes())
    assert len(path) > 260
    assert [f.rule for f in test_clamd.scan(ScanItem(display="deep", path=path))] == [
        "TacoGuard.Test.HarmlessSample-1"]


@pytest.mark.clamav
@needs_clamd
def test_too_big_and_unreadable_files(test_clamd, tmp_path, monkeypatch):
    big = tmp_path / "big.bin"
    big.write_bytes(b"0" * 2048)
    monkeypatch.setattr(C, "STREAM_MAX", 1024)
    with pytest.raises(DetectorError, match="Too big for the ClamAV check"):
        test_clamd.scan(ScanItem(display="big", path=str(big)))
    with pytest.raises(DetectorError, match="could not read"):
        test_clamd.scan(ScanItem(display="gone", path=str(tmp_path / "missing.bin")))


@pytest.mark.parametrize("threads,max_threads", [(1, 2), (4, 5), (8, 9), (50, 9)])
def test_clamd_has_a_thread_for_every_file_sent_at_once(settings, threads, max_threads):
    settings.clamav_threads = threads
    det = C.ClamAVDetector(settings, program_dir=REAL_PROGRAM)
    det._port = 1
    conf = det._write_conf()
    try:
        assert f"MaxThreads {max_threads}" in conf.read_text(encoding="utf-8").splitlines()
    finally:
        conf.unlink()


@pytest.mark.clamav
@needs_clamd
def test_scans_from_several_threads_at_once(test_clamd):
    from concurrent.futures import ThreadPoolExecutor
    items = [ScanItem(display=f"m{i}", data=samples.sample_bytes(prefix=f"n{i}\r\n".encode()) if i % 3 == 0
                      else f"clean {i}".encode() * 1000) for i in range(48)]
    with ThreadPoolExecutor(8) as pool:
        found = list(pool.map(test_clamd.scan, items))
    assert [bool(f) for f in found] == [i % 3 == 0 for i in range(48)]


CHILD_PRIORITY = r'''
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from pathlib import Path
import psutil
from tacoguard.config import Settings
from tacoguard.detect.clamav import ClamAVDetector
from tacoguard.scan.worker import lower_priority
lower_priority("idle")
d = ClamAVDetector(Settings(data_dir=sys.argv[3]), program_dir=Path(sys.argv[4]))
d.open()
try:
    clamd = psutil.Process(d._proc.pid)
    print(clamd.nice(), clamd.ionice(), flush=True)
finally:
    d.close()
'''


@pytest.mark.clamav
@needs_clamd
def test_clamd_runs_at_the_workers_idle_priority(settings, tmp_path):
    (settings.clamav_db_dir / "tacoguard-test.ndb").write_text(samples.TEST_CLAMAV_NDB, encoding="ascii")
    script = tmp_path / "child.py"
    script.write_text(CHILD_PRIORITY, encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    out = subprocess.run([sys.executable, str(script), str(root), str(root / "tests"), settings.data_dir,
                          str(REAL_PROGRAM)], capture_output=True, text=True, timeout=120,
                         creationflags=C.CREATE_NO_WINDOW)
    nice, io = out.stdout.split()
    assert int(nice) == psutil.IDLE_PRIORITY_CLASS and int(io) == psutil.IOPRIO_LOW, out.stderr


@pytest.mark.clamav
@needs_clamd
def test_close_stops_clamd_and_is_safe_twice(test_clamd):
    proc = psutil.Process(test_clamd._proc.pid)
    test_clamd.close()
    test_clamd.close()
    assert not proc.is_running()
    with pytest.raises(DetectorError, match="not running"):
        test_clamd.scan(ScanItem(display="x", data=b"x"))


CHILD = r'''
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from pathlib import Path
from tacoguard.config import Settings
from tacoguard.detect.clamav import ClamAVDetector
s = Settings(data_dir=sys.argv[3])
d = ClamAVDetector(s, program_dir=Path(sys.argv[4]))
d.open()
print(d._proc.pid, flush=True)
import time
time.sleep(120)
'''


@pytest.mark.clamav
@needs_clamd
def test_clamd_dies_when_our_process_is_killed(settings, tmp_path):
    (settings.clamav_db_dir / "tacoguard-test.ndb").write_text(samples.TEST_CLAMAV_NDB, encoding="ascii")
    script = tmp_path / "child.py"
    script.write_text(CHILD, encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    child = subprocess.Popen([sys.executable, str(script), str(root), str(root / "tests"),
                              settings.data_dir, str(REAL_PROGRAM)],
                             stdout=subprocess.PIPE, text=True, creationflags=C.CREATE_NO_WINDOW)
    try:
        clamd_pid = int(child.stdout.readline())
        clamd = psutil.Process(clamd_pid)
        child.kill()
        child.wait(timeout=10)
        clamd.wait(timeout=15)
        assert not clamd.is_running()
    finally:
        if child.poll() is None:
            child.kill()


# ---- the real official database, read-only (EICAR stays in memory) ------------------------

@pytest.mark.clamav
@pytest.mark.slow
@pytest.mark.skipif(not (REAL_PROGRAM / "clamd.exe").exists() or not (REAL_DB / "daily.cvd").exists()
                    and not (REAL_DB / "daily.cld").exists(),
                    reason="real ClamAV signatures not set up in D:\\TacoGuard")
def test_eicar_in_memory_with_the_official_signatures(settings):
    det = C.ClamAVDetector(settings, program_dir=REAL_PROGRAM, db_dir=REAL_DB)
    started = time.monotonic()
    det.open()
    try:
        assert time.monotonic() - started < C.START_TIMEOUT
        found = det.scan(ScanItem(display="eicar (in memory)", data=samples.eicar()))
        assert len(found) == 1
        assert found[0].rule in ("Eicar-Signature", "Eicar-Test-Signature", "Win.Test.EICAR_HDB-1")
        assert found[0].source == C.OFFICIAL_SOURCE
        assert det.clamd_version().startswith("ClamAV 1.5")
    finally:
        det.close()
