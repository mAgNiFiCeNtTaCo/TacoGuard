"""Tests for the lead-owned core: wording, levels, store, allowlist, path helpers."""
from __future__ import annotations

import os

import pytest

from tacoguard import allowlist, winpath
from tacoguard.config import Settings, load_settings
from tacoguard.model import (CLEAN, MALWARE, SUSPICIOUS, TRUSTED, Confidence, FileResult, Finding,
                             verdict_level)


def F(engine="yara", conf=Confidence.MEDIUM, rule="R"):
    return Finding(engine, rule, conf, "test source")


def test_levels():
    assert verdict_level([]) == CLEAN
    assert verdict_level([F(conf=Confidence.LOW)]) == SUSPICIOUS
    assert verdict_level([F(conf=Confidence.MEDIUM)]) == SUSPICIOUS
    assert verdict_level([F(conf=Confidence.HIGH)]) == MALWARE
    # two different engines agreeing at medium -> malware; the same engine twice does not
    assert verdict_level([F("yara"), F("clamav")]) == MALWARE
    assert verdict_level([F("yara"), F("yara", rule="R2")]) == SUSPICIOUS


def test_wording_never_scary_for_weak():
    r = FileResult(path="x.exe", findings=[F(conf=Confidence.LOW)])
    text = r.reason().lower()
    assert "malware" not in text and "false alarm" in text
    strong = FileResult(path="x.exe", findings=[F(conf=Confidence.HIGH, rule="Generic_Stealer_Strings")])
    assert "'Generic_Stealer_Strings'" in strong.reason() and "high confidence" in strong.reason()


def test_plain_error_maps_every_exception_to_plain_words():
    """Review 2026-11-23: str(exc) of any exception (Python internals) reached the page."""
    import struct
    from tacoguard.model import PLAIN_ERROR_GENERIC, plain_error
    win = OSError(0, "The process cannot access the file", "C:\\secret\\a.txt", 32)
    assert plain_error(win) == "the file is in use by another program"
    assert plain_error(OSError(22, "[WinError 1117] The request could not be performed")).startswith("an I/O device error")
    assert plain_error(PermissionError(13, "Access is denied")) == "Windows refused access"
    assert plain_error(FileNotFoundError(2, "No such file")) == "the file was not found"
    assert plain_error(MemoryError()) == "not enough memory"
    for odd in (KeyError("filename"), struct.error("unpack requires a buffer of 4 bytes"),
                ValueError("<_io.BufferedReader name='C:\\\\x'> closed"), RuntimeError(),
                OSError(0, "Some odd failure", None, 4242)):
        assert plain_error(odd) == PLAIN_ERROR_GENERIC


def test_engine_notes_never_show_raw_exception_text(settings, store, tmp_path, monkeypatch):
    from tacoguard import archives
    from tacoguard.scan import engine
    from tacoguard.model import ScanItem

    class Odd:
        name = "yara"
        scans_members = True

        def scan(self, item):
            raise KeyError("internal_field_42")
    r = FileResult(path="x.bin")
    engine._run_detectors([Odd()], ScanItem(display="x.bin", data=b"x", size=1), r)
    assert r.incomplete and "internal_field_42" not in " ".join(r.notes) and "YARA" in r.notes[0]

    def broken(*a, **k):
        raise struct_error("unpack requires a buffer of 4 bytes")
    import struct
    struct_error = struct.error
    monkeypatch.setattr(archives, "iter_members", broken)
    r = FileResult(path="x.zip")
    engine._scan_members(ScanItem(display="x.zip", data=b"PK\x03\x04", size=4), [], allowlist.TrustChecker(store),
                         settings, r, None)
    assert r.notes == ["Could not look inside this archive (an unexpected problem)."]


def test_finding_roundtrip():
    f = Finding("clamav", "Win.Test", Confidence.HIGH, "src", member="a\\b.exe", license="DRL 1.1")
    assert Finding.from_dict(f.to_dict()) == f


def test_settings_roundtrip(tmp_path):
    s = Settings(data_dir=str(tmp_path))
    s.limits.archive_max_depth = 5
    s.save()
    s2 = load_settings(str(tmp_path))
    assert s2.limits.archive_max_depth == 5 and s2.data_dir == str(tmp_path)
    (tmp_path / "settings.json").write_text("{broken", encoding="utf-8")
    assert load_settings(str(tmp_path)).limits.archive_max_depth == 3   # falls back to defaults


def test_old_default_ml_size_limit_moves_to_the_new_default(tmp_path):
    """64 MB was the default until 2026-11-23 (and was saved with every settings.json); the ML
    check took up to 14 s and +600 MB on such programs, so the saved old default becomes 16 MB.
    A value the user picked themselves stays."""
    s = Settings(data_dir=str(tmp_path))
    assert s.ml_max_file_size == 16 * 1024**2
    s.ml_max_file_size = 64 * 1024**2
    s.save()
    assert load_settings(str(tmp_path)).ml_max_file_size == 16 * 1024**2
    s.ml_max_file_size = 32 * 1024**2
    s.save()
    assert load_settings(str(tmp_path)).ml_max_file_size == 32 * 1024**2


def test_winpath(tmp_path):
    long_dir = tmp_path / ("x" * 120) / ("y" * 120) / ("z" * 60)
    os.makedirs(winpath.to_long(long_dir))
    p = winpath.to_long(long_dir / "f.txt")
    with open(p, "wb") as fh:
        fh.write(b"ok")
    assert len(winpath.to_display(p)) > 260 and os.path.getsize(p) == 2
    assert winpath.is_under(r"C:\A\b\c.txt", "c:\\a")
    assert not winpath.is_under(r"C:\Ab\c.txt", "c:\\a")
    assert winpath.to_display(winpath.to_long(r"\\srv\share\x")) == r"\\srv\share\x"


def test_allowlist(store, tmp_path):
    with pytest.raises(allowlist.AllowlistError):
        allowlist.trust_hash(store, "nothex")
    with pytest.raises(allowlist.AllowlistError):
        allowlist.trust_folder(store, "C:\\")
    (tmp_path / "games").mkdir()
    allowlist.trust_folder(store, str(tmp_path / "games"), "my games")
    allowlist.trust_folder(store, str(tmp_path / "games"), "again")       # no duplicate
    assert len(store.list_allow("folder")) == 1
    tc = allowlist.TrustChecker(store)
    assert tc.folder_reason(str(tmp_path / "GAMES" / "x.exe"))
    assert tc.folder_reason(str(tmp_path / "gamesX" / "x.exe")) is None

    job = store.create_job([str(tmp_path)])
    rid = store.add_result(job, FileResult(path="a.exe", sha256="c" * 64, findings=[F()]))
    allowlist.mark_not_a_threat(store, rid)
    tc.refresh()
    assert tc.hash_reason("C" * 64)
    assert store.get_result(rid)["action"] == "trusted"
    assert store.list_verdicts()[0]["verdict"] == "not_a_threat"


def test_store_jobs_and_cache(store):
    j = store.create_job(["D:\\x"])
    store.update_job(j, status="running", counts={"files": 3})
    assert store.get_job(j)["counts"]["files"] == 3
    assert [x["id"] for x in store.active_jobs()] == [j]
    store.cache_put("k", 10, 5, "h" * 64, "v1")
    assert store.cache_get("k", 10, 5, "v1") == "h" * 64
    assert store.cache_get("k", 10, 5, "v2") is None
    assert store.cache_get("k", 11, 5, "v1") is None
    r = FileResult(path="t", status=TRUSTED, notes=["On your list."])
    rid = store.add_result(j, r)
    assert store.get_result(rid)["reason"] == "On your list."
