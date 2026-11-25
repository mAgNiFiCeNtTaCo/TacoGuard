from __future__ import annotations

import hashlib
import os

import pytest

import samples
from tacoguard.detect import load_detectors, signature_status
from tacoguard.detect.base import DetectorError
from tacoguard.detect.hashsets import HashDetector, parse_hash_file
from tacoguard.model import Confidence, ScanItem

SAMPLE = samples.sample_bytes()
SAMPLE_SHA = hashlib.sha256(SAMPLE).hexdigest()


def _write_list(settings, name="bad.txt", body=None):
    body = body if body is not None else (
        "# my list\n"
        f"{SAMPLE_SHA}  Harmless test sample\n"
        "not-a-hash line\n"
        f"{'A' * 64}\n")
    path = settings.hashset_dir / name
    path.write_text(body, encoding="utf-8")
    return path


def test_empty_folder_is_ready_with_no_entries(settings):
    det = HashDetector(settings)
    st = det.status()
    assert st["ready"] and st["count"] == 0
    assert det.version() == "hash-none"
    det.open()
    assert det.scan(ScanItem(display="x", data=SAMPLE)) == []


def test_parse_ignores_comments_and_junk(settings):
    entries = parse_hash_file(_write_list(settings))
    assert entries == {SAMPLE_SHA: "Harmless test sample", "a" * 64: ""}


def test_match_in_memory_and_on_disk(settings, tmp_path):
    _write_list(settings)
    det = HashDetector(settings)
    det.open()
    found = det.scan(ScanItem(display="mem", data=SAMPLE, member="inner\\a.txt"))
    assert len(found) == 1
    f = found[0]
    assert f.engine == "hash" and f.confidence == Confidence.HIGH
    assert f.rule == "Harmless test sample"
    assert f.source == "your known-bad list (bad.txt)"
    assert f.member == "inner\\a.txt"

    on_disk = tmp_path / "sample.bin"
    on_disk.write_bytes(SAMPLE)
    assert det.scan(ScanItem(display="disk", path="\\\\?\\" + str(on_disk)))
    assert det.scan(ScanItem(display="clean", data=b"clean bytes")) == []
    assert det.status()["count"] == 2


def test_uses_known_sha256_when_present(settings):
    _write_list(settings)
    det = HashDetector(settings)
    det.open()
    item = ScanItem(display="x", data=b"different bytes")
    item.sha256 = SAMPLE_SHA            # the engine may already know the fingerprint
    assert det.scan(item)


def test_unreadable_file_is_a_detector_error(settings, tmp_path):
    _write_list(settings)
    det = HashDetector(settings)
    det.open()
    with pytest.raises(DetectorError):
        det.scan(ScanItem(display="gone", path=str(tmp_path / "missing.bin")))


def test_version_changes_with_the_lists(settings):
    det = HashDetector(settings)
    path = _write_list(settings)
    v1 = det.version()
    os.utime(path, ns=(1, 1))
    assert det.version() != v1


def test_load_detectors_order_and_switches(settings):
    assert [d.name for d in load_detectors(settings)] == ["hash", "yara", "ml", "clamav"]
    settings.clamav_enabled = False
    settings.yara_enabled = False
    settings.ml_enabled = False
    assert [d.name for d in load_detectors(settings)] == ["hash"]


def test_signature_status_is_cheap_and_plain(settings):
    st = signature_status(settings)
    assert set(st) == {"hash", "yara", "ml", "clamav", "sig_version"}
    assert st["yara"]["ready"] is False
    assert st["yara"]["message"] == "Not downloaded yet: press Get signatures."
    assert st["clamav"]["ready"] is False
    assert "press Get signatures" in st["clamav"]["message"]
    assert st["ml"]["ready"] is False
    assert st["sig_version"].count("|") == 3
