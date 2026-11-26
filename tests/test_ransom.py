"""Ransomware guard (tacoguard/guard/ransom.py + decoys.py).

Everything happens in tmp_path: the canary folders are temp folders (settings.canary_folders),
change events come from a FakeHub the tests drive, and the only program ever paused is a
harmless child process started here (it scrambles a decoy file in tmp_path and keeps rewriting
its own scratch files). The guard is limited to that child's process tree (pid_filter), so no
other program on the PC is ever looked at for pausing.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path

import psutil
import pytest

from tacoguard import winpath
from tacoguard.guard import decoys, procctl, ransom

FOLDERS = ("Documents", "Desktop", "Pictures", "Downloads")
GIVEAWAY = ("tacoguard", "decoy", "canary")


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
@dataclass
class FakeEvent:
    action: str
    path: str
    ts: float


class FakeHub:
    """Stands in for folders.WatchHub: tests call deliver() to send change events."""

    def __init__(self):
        self.subs: dict[int, tuple[str, object, bool]] = {}
        self._n = 0

    def subscribe(self, root, callback, recursive=True):
        self._n += 1
        self.subs[self._n] = (root, callback, recursive)
        return self._n

    def unsubscribe(self, token):
        self.subs.pop(token, None)

    def deliver(self, action: str, path) -> None:
        path = str(path)
        for root, cb, _ in list(self.subs.values()):
            if action == "overflow" and winpath.norm_key(root) == winpath.norm_key(path):
                cb(FakeEvent(action, "", time.time()))
            elif winpath.is_under(path, root):
                cb(FakeEvent(action, path, time.time()))

    def rename(self, old, new) -> None:
        os.rename(old, new)
        self.deliver("renamed_from", old)
        self.deliver("renamed_to", new)


@pytest.fixture
def canaries(tmp_path, settings):
    paths = []
    for name in FOLDERS:
        p = tmp_path / "home" / name
        p.mkdir(parents=True)
        paths.append(p)
    settings.canary_folders = [str(p) for p in paths]
    return paths


@pytest.fixture
def hub():
    return FakeHub()


@pytest.fixture
def make_guard(settings, store, hub):
    made = []

    def make(pid_filter=lambda pid: False, start=True):
        g = ransom.RansomGuard(settings, store, hub, own_pids=lambda: {os.getpid()}, pid_filter=pid_filter)
        g.NEW_FILE_GRACE_S = 0.0
        g.RECREATE_DELAY_S = 0.0
        g.SAMPLE_GAP_S = 0.2
        made.append(g)
        if start:
            g.start()
        return g

    yield make
    for g in made:
        g.stop()


def decoys_in(folder: Path, settings) -> list[dict]:
    return [e for e in ransom.load_manifest(settings) if winpath.norm_key(e["folder"]) == winpath.norm_key(folder)]


def sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def scramble(path) -> None:
    """Rewrite a (hidden) file in place with random bytes, like ransomware would."""
    with open(path, "r+b") as f:
        n = len(f.read())
        f.seek(0)
        f.write(os.urandom(max(n, 4096)))
        f.truncate()


def ransom_events(store) -> list[dict]:
    return [e for e in store.list_guard_events() if e["kind"] == "ransomware"]


def settle(g, kick=True):
    assert g.flush(15)
    if kick:
        g._kick()
        assert g.flush(15)


def is_hidden(path) -> bool:
    a = decoys.attributes(str(path))
    return a is not None and bool(a & decoys.FILE_ATTRIBUTE_HIDDEN) and not a & decoys.FILE_ATTRIBUTE_SYSTEM


# ---------------------------------------------------------------------------------------------
# the decoy files themselves
# ---------------------------------------------------------------------------------------------
def _zip_xml_ok(data: bytes) -> list[str]:
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    for name in z.namelist():
        ET.fromstring(z.read(name))          # every part is well-formed XML
    return z.namelist()


def _jpeg_segments(data: bytes) -> list[int]:
    assert data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"
    markers, i = [], 2
    while True:
        assert data[i] == 0xFF
        m = data[i + 1]
        markers.append(m)
        length = int.from_bytes(data[i + 2:i + 4], "big")
        i += 2 + length
        if m == 0xDA:
            break
    return markers


def test_decoy_documents_are_valid():
    for _ in range(5):
        names = _zip_xml_ok(decoys.make("docx"))
        assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml"} <= set(names)
        names = _zip_xml_ok(decoys.make("xlsx"))
        assert {"xl/workbook.xml", "xl/worksheets/sheet1.xml", "xl/_rels/workbook.xml.rels"} <= set(names)
        pdf = decoys.make("pdf")
        assert pdf.startswith(b"%PDF-1.") and pdf.rstrip().endswith(b"%%EOF")
        xref_at = int(pdf.rsplit(b"startxref", 1)[1].split()[0])
        assert pdf[xref_at:xref_at + 4] == b"xref"
        # every xref offset points at "N 0 obj"
        lines = pdf[xref_at:].split(b"\n")
        count = int(lines[1].split()[1])
        for n, line in enumerate(lines[3:3 + count - 1], start=1):
            off = int(line.split()[0])
            assert pdf[off:].startswith(f"{n} 0 obj".encode())
        jpg = decoys.make("jpg")
        assert _jpeg_segments(jpg) == [0xE0, 0xDB, 0xC0, 0xC4, 0xC4, 0xDA]


def test_jpeg_decodes_with_windows(tmp_path):
    p = tmp_path / "img.jpg"
    p.write_bytes(decoys.make("jpg"))
    ps = ("Add-Type -AssemblyName System.Drawing; $b = New-Object System.Drawing.Bitmap('%s'); "
          "$c = $b.GetPixel($b.Width - 1, $b.Height - 1); Write-Output ($b.Width.ToString() + 'x' + "
          "$b.Height.ToString()); $b.Dispose()" % str(p))
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True,
                           text=True, timeout=60, creationflags=0x08000000)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("PowerShell not available")
    assert r.returncode == 0, r.stderr
    w, h = map(int, r.stdout.strip().split("x"))
    assert w >= 100 and h >= 100


def test_no_giveaway_words_in_names_or_contents():
    for kind in decoys.KINDS:
        for name in decoys._names(kind):
            assert not any(w in name.casefold() for w in GIVEAWAY)
            assert name.startswith("!")
        for _ in range(10):
            data = decoys.make(kind)
            blobs = [data]
            if kind in ("docx", "xlsx"):
                z = zipfile.ZipFile(io.BytesIO(data))
                blobs += [z.read(n) for n in z.namelist()] + [n.encode() for n in z.namelist()]
            for b in blobs:
                low = b.lower()
                assert not any(w.encode() in low for w in GIVEAWAY)


def test_decoy_contents_differ_every_time():
    for kind in decoys.KINDS:
        hashes = {hashlib.sha256(decoys.make(kind)).hexdigest() for _ in range(6)}
        assert len(hashes) == 6


# ---------------------------------------------------------------------------------------------
# placing, manifest, folders
# ---------------------------------------------------------------------------------------------
def test_place_decoys_hidden_varied_and_listed(settings, store, hub, canaries, make_guard):
    g = make_guard()
    st = g.status()
    assert st["state"] == "on" and st["checked"] == 3 * len(FOLDERS)
    assert sorted(st["watched"]) == sorted(str(p) for p in canaries)
    assert len(hub.subs) == len(FOLDERS)
    names_per_folder = []
    manifest = ransom.load_manifest(settings)
    assert len(manifest) == 3 * len(FOLDERS)
    for folder in canaries:
        entries = decoys_in(folder, settings)
        assert len(entries) == 3
        names = set()
        for e in entries:
            p = Path(e["path"])
            assert p.parent == folder and p.exists() and is_hidden(p)
            assert sha(p) == e["sha256"] and p.stat().st_size == e["size"]
            assert p.stat().st_mtime < time.time() - 86400      # looks like an older file
            names.add(p.name)
        names_per_folder.append(names)
    all_names = [n for s in names_per_folder for n in s]
    assert len(set(all_names)) == len(all_names)                 # every folder gets its own names
    assert any(n.endswith(".jpg") for n in names_per_folder[FOLDERS.index("Pictures")])
    # placing again changes nothing
    before = {e["path"]: e["sha256"] for e in manifest}
    g.place_decoys()
    assert {e["path"]: e["sha256"] for e in ransom.load_manifest(settings)} == before


def test_two_installs_share_no_decoy_hash(tmp_path, canaries, settings, store, hub, make_guard):
    make_guard()
    first = {e["sha256"] for e in ransom.load_manifest(settings)}
    from tacoguard.config import Settings
    from tacoguard.store import Store
    other = Settings(data_dir=str(tmp_path / "data2"))
    other.ensure_dirs()
    f2 = tmp_path / "other" / "Documents"
    f2.mkdir(parents=True)
    other.canary_folders = [str(f2)]
    st2 = Store(other.db_path)
    try:
        ransom.RansomGuard(other, st2, None).place_decoys()
        second = {e["sha256"] for e in ransom.load_manifest(other)}
    finally:
        st2.close()
    assert len(second) == 3 and not first & second


def test_never_overwrites_a_users_file_with_the_same_name(settings, store, hub, tmp_path, make_guard, monkeypatch):
    folder = tmp_path / "Docs"
    folder.mkdir()
    settings.canary_folders = [str(folder)]
    # the user already has every name the decoys could pick
    for kind in decoys.KINDS:
        for name in decoys._names(kind)[:-1]:
            (folder / name).write_bytes(b"mine")
    make_guard()
    for kind in decoys.KINDS:
        for name in decoys._names(kind)[:-1]:
            assert (folder / name).read_bytes() == b"mine"
    assert len(decoys_in(folder, settings)) == 3


def test_onedrive_and_missing_folders_get_no_decoys(settings, store, hub, tmp_path, monkeypatch, make_guard):
    od = tmp_path / "OneDrive"
    (od / "Documents").mkdir(parents=True)
    work = tmp_path / "OneDrive - Contoso" / "Desktop"
    work.mkdir(parents=True)
    plain = tmp_path / "Pictures"
    plain.mkdir()
    monkeypatch.setenv("OneDrive", str(od))
    settings.canary_folders = [str(od / "Documents"), str(work), str(tmp_path / "Gone"), str(plain)]
    assert ransom.in_onedrive(str(od / "Documents")) and ransom.in_onedrive(str(work))
    assert not ransom.in_onedrive(str(plain))
    g = make_guard()
    st = g.status()
    assert st["watched"] == [str(plain)]
    assert "inside OneDrive" in st["message"] and "Gone was not found" in st["message"]
    assert not any((od / "Documents").iterdir()) and not any(work.iterdir())
    assert len(decoys_in(plain, settings)) == 3


def test_manifest_written_atomically(settings, store, hub, canaries, make_guard, monkeypatch):
    g = make_guard(start=False)
    g.place_decoys()
    path = ransom.manifest_path(settings)
    good = path.read_bytes()
    assert len(json.loads(good)["decoys"]) == 12

    def broken(src, dst):
        raise OSError(28, "disk full")

    monkeypatch.setattr(ransom.os, "replace", broken)
    with pytest.raises(OSError):
        ransom.save_manifest(settings, [{"path": "x", "folder": "y", "sha256": "0", "size": 1}])
    assert path.read_bytes() == good                       # the old list is intact
    assert [p.name for p in path.parent.iterdir()] == [path.name]   # no temp file left behind


def test_controlled_folder_access_block_is_reported(settings, store, hub, canaries, make_guard, monkeypatch):
    real = decoys.write_new
    docs = canaries[0]

    def guarded(path, data, rng=None):
        if winpath.is_under(path, str(docs)):
            raise PermissionError(13, "Access is denied")
        return real(path, data, rng)

    monkeypatch.setattr(decoys, "write_new", guarded)
    monkeypatch.setattr(ransom, "cfa_enabled", lambda: True)
    g = make_guard()
    st = g.status()
    assert st["state"] == "on"
    assert str(docs) not in st["watched"] and len(st["watched"]) == 3
    assert ("Windows' Controlled Folder Access blocked TacoGuard's decoy files in Documents. Add TacoGuard's "
            "Python under 'Allow an app through Controlled folder access' to use them there.") in st["message"]
    assert decoys_in(docs, settings) == [] and not any(docs.iterdir())
    assert len(ransom.load_manifest(settings)) == 9


# ---------------------------------------------------------------------------------------------
# decoy triggers
# ---------------------------------------------------------------------------------------------
def test_changed_decoy_raises_one_alarm(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[0], settings)[0]
    scramble(e["path"])
    hub.deliver("modified", e["path"])
    settle(g)
    evs = ransom_events(store)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["level"] == "warning"
    assert ev["title"] == ("Possible ransomware: a decoy file in Documents was changed. "
                           "No program to pause was found.")
    assert "could not tell which program" in ev["message"]
    assert ev["data"]["decoy"] == e["path"] and ev["data"]["paused_ids"] == []
    assert "malware" not in (ev["title"] + ev["message"]).lower()


def test_touch_without_content_change_is_ignored(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[1], settings)[0]
    os.utime(e["path"], None)
    for action in ("modified", "added", "modified"):
        hub.deliver(action, e["path"])
    hub.deliver("overflow", str(canaries[1]))
    settle(g)
    assert ransom_events(store) == []


def test_deleted_decoy_comes_back_quietly(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[2], settings)[0]
    os.remove(e["path"])
    hub.deliver("removed", e["path"])
    settle(g)
    assert ransom_events(store) == []
    p = Path(e["path"])
    assert p.exists() and is_hidden(p)
    now = {x["path"]: x["sha256"] for x in ransom.load_manifest(settings)}
    assert now[e["path"]] == sha(p)
    hub.deliver("added", e["path"])        # its own re-creation event is harmless
    settle(g)
    assert ransom_events(store) == []


def test_decoy_renamed_to_new_extension_raises_alarm(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[0], settings)[0]
    locked = e["path"] + ".locked"
    hub.rename(e["path"], locked)
    settle(g)
    evs = ransom_events(store)
    assert len(evs) == 1 and "renamed to " + os.path.basename(locked) in evs[0]["message"]
    assert Path(locked).exists()           # never deleted by TacoGuard


def test_decoy_renamed_by_hand_is_followed(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[0], settings)[0]
    new = str(Path(e["path"]).with_name("!Old" + Path(e["path"]).suffix))
    hub.rename(e["path"], new)
    settle(g)
    assert ransom_events(store) == []
    assert new in [x["path"] for x in ransom.load_manifest(settings)]


def test_decoy_deleted_with_a_locked_copy_beside_it_raises_alarm(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[3], settings)[0]
    copy = e["path"] + ".crypt"
    Path(copy).write_bytes(os.urandom(8192))
    hub.deliver("added", copy)
    os.remove(e["path"])
    hub.deliver("removed", e["path"])
    settle(g)
    evs = ransom_events(store)
    assert len(evs) == 1 and "replaced by" in evs[0]["message"]


# ---------------------------------------------------------------------------------------------
# bursts
# ---------------------------------------------------------------------------------------------
def _files(folder: Path, n: int, content) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for i in range(n):
        p = folder / f"photo{i:03d}.txt"
        p.write_bytes(content(i))
        out.append(p)
    return out


def test_burst_of_renames_to_new_extension(settings, store, hub, canaries, make_guard):
    g = make_guard()
    files = _files(canaries[0] / "Work", 25, lambda i: b"plain text line\n" * 200)
    for p in files:
        hub.rename(str(p), str(p) + ".locked")
    settle(g)
    evs = ransom_events(store)
    assert len(evs) == 1                                   # one alarm for the whole burst
    ev = evs[0]
    assert ev["title"] == ("Possible ransomware: many files in Documents were changed at once. "
                           "No program to pause was found.")
    assert ev["data"]["count"] >= 20 and ev["data"]["trigger"] == "burst"


def test_burst_of_scrambled_rewrites_of_existing_files(settings, store, hub, canaries, make_guard):
    g = make_guard()
    files = _files(canaries[1] / "Stuff", 24, lambda i: b"hello " * 2000)
    for p in files:
        p.write_bytes(os.urandom(70_000))
        hub.deliver("modified", p)
        hub.deliver("modified", p)                         # several events per file count once
    settle(g)
    assert len(ransom_events(store)) == 1


def test_ordinary_bulk_work_is_not_a_burst(settings, store, hub, canaries, make_guard):
    g = make_guard()
    docs = canaries[0]
    # 1. extracting an archive: new files (added, then modified), random-looking content
    for i in range(40):
        p = docs / "unzipped" / f"part{i}.bin"
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(os.urandom(70_000))
        hub.deliver("added", p)
        hub.deliver("modified", p)
    # 2. renaming photos, same extension, ordinary content
    for p in _files(docs / "Photos", 25, lambda i: b"\xff\xd8\xff\xe0" + os.urandom(30_000)):
        hub.rename(str(p), str(p.with_name("Holiday " + p.name)))
    # 3. rewriting existing files whose content is compressed by nature (zip/docx header)
    for p in _files(docs / "Zips", 25, lambda i: b"x" * 1000):
        p.write_bytes(b"PK\x03\x04" + os.urandom(70_000))
        hub.deliver("modified", p)
    # 4. a browser finishing downloads (.crdownload -> real name)
    for i in range(25):
        p = docs / f"dl{i}.zip.crdownload"
        p.write_bytes(b"PK\x03\x04" + os.urandom(1000))
        hub.deliver("added", p)
        hub.rename(str(p), str(p)[: -len(".crdownload")])
    settle(g)
    assert ransom_events(store) == []
    assert g.samples_taken == 0


def test_decoy_deleted_during_a_building_burst_raises_alarm(settings, store, hub, canaries, make_guard):
    g = make_guard()
    for p in _files(canaries[0] / "W", 6, lambda i: b"abc" * 100):
        hub.rename(str(p), str(p) + ".enc")
    e = decoys_in(canaries[0], settings)[0]
    os.remove(e["path"])
    hub.deliver("removed", e["path"])
    settle(g)
    evs = ransom_events(store)
    assert len(evs) == 1 and "deleted while other files" in evs[0]["message"]


def test_write_sampling_only_while_a_burst_builds(settings, store, hub, canaries, make_guard):
    g = make_guard()
    settle(g)
    assert g.samples_taken == 0
    files = _files(canaries[2] / "P", 6, lambda i: b"abc" * 100)
    for p in files[:4]:
        hub.rename(str(p), str(p) + ".enc")
    settle(g)
    assert g.samples_taken == 0                            # 4 changes: nothing is sampled yet
    hub.rename(str(files[4]), str(files[4]) + ".enc")      # the 5th: a burst may be building
    settle(g)
    assert g.samples_taken >= 1
    assert g._next_timeout() is not None                   # 1 s samples while it builds
    g._now = lambda: time.time() + 60                      # window over: back to sleep
    g._kick()
    settle(g)
    assert g._next_timeout() is None and not g._rolling


# ---------------------------------------------------------------------------------------------
# cool-down and putting decoys back
# ---------------------------------------------------------------------------------------------
def test_cooldown_merges_triggers_into_one_alarm(settings, store, hub, canaries, make_guard):
    g = make_guard()
    clock = [time.time()]
    g._now = lambda: clock[0]
    a = decoys_in(canaries[0], settings)[0]
    b = decoys_in(canaries[1], settings)[0]
    c = decoys_in(canaries[2], settings)[0]
    scramble(a["path"])
    hub.deliver("modified", a["path"])
    settle(g, kick=False)
    clock[0] += 20
    scramble(b["path"])
    hub.deliver("modified", b["path"])
    settle(g, kick=False)
    evs = ransom_events(store)
    assert len(evs) == 1
    assert evs[0]["data"]["decoys"] == [a["path"], b["path"]]
    clock[0] += 61                                         # quiet for over a minute: a new burst
    scramble(c["path"])
    hub.deliver("modified", c["path"])
    settle(g, kick=False)
    assert len(ransom_events(store)) == 2


def test_changed_decoys_come_back_after_the_alert_is_resolved(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[0], settings)[0]
    scramble(e["path"])
    hub.deliver("modified", e["path"])
    settle(g)
    ev = ransom_events(store)[0]
    changed = sha(e["path"])
    assert changed != e["sha256"]
    os.remove(decoys_in(canaries[0], settings)[1]["path"])   # deleted during the alert: waits too
    hub.deliver("removed", decoys_in(canaries[0], settings)[1]["path"])
    settle(g)
    assert sha(e["path"]) == changed                       # left as it is while the alert is open
    store.set_guard_event(ev["id"], state="resolved", action="resumed")
    settle(g)
    entries = {x["path"]: x for x in decoys_in(canaries[0], settings)}
    assert len(entries) == ransom.DECOYS_PER_FOLDER
    for x in entries.values():
        assert Path(x["path"]).exists() and sha(x["path"]) == x["sha256"] and is_hidden(x["path"])
        if x["path"].endswith((".docx", ".xlsx")):
            _zip_xml_ok(Path(x["path"]).read_bytes())
    # the changed decoy is never written over: it stays as it is and a fresh decoy has another name
    assert e["path"] not in entries and sha(e["path"]) == changed
    assert len(ransom_events(store)) == 1
    assert g._alarm is None


def test_changed_decoys_come_back_after_ten_minutes(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[1], settings)[0]
    scramble(e["path"])
    hub.deliver("modified", e["path"])
    settle(g)
    changed = sha(e["path"])
    assert changed != e["sha256"]
    g._now = lambda: time.time() + 601
    settle(g)
    new = {x["path"]: x["sha256"] for x in decoys_in(canaries[1], settings)}
    assert e["path"] not in new and sha(e["path"]) == changed      # left alone, replaced by a fresh one
    assert len(new) == ransom.DECOYS_PER_FOLDER and all(sha(p) == h for p, h in new.items())
    assert ransom_events(store)[0]["state"] == "new"      # the alert itself stays for you


# ---------------------------------------------------------------------------------------------
# switching off
# ---------------------------------------------------------------------------------------------
def test_remove_decoys_leaves_changed_files_alone(settings, store, hub, canaries, make_guard):
    g = make_guard(start=False)
    placed = g.place_decoys()
    assert len(placed) == 12
    changed = decoys_in(canaries[0], settings)[0]["path"]
    scramble(changed)
    user_file = canaries[0] / "keep me.txt"
    user_file.write_text("mine")
    assert ransom.remove_decoys(settings) == 11
    assert Path(changed).exists() and user_file.exists()
    assert sum(1 for p in placed if Path(p).exists()) == 1
    assert ransom.load_manifest(settings) == []
    assert ransom.remove_decoys(settings) == 0


def test_stop_with_remove_takes_decoys_away(settings, store, hub, canaries, make_guard):
    g = make_guard()
    placed = [e["path"] for e in ransom.load_manifest(settings)]
    g.stop(remove=True)
    assert g.status()["state"] == "off" and hub.subs == {}
    assert not any(Path(p).exists() for p in placed)


def test_folder_dropped_from_settings_loses_its_decoys(settings, store, hub, canaries, make_guard):
    g = make_guard(start=False)
    g.place_decoys()
    gone = [e["path"] for e in decoys_in(canaries[3], settings)]
    settings.canary_folders = [str(p) for p in canaries[:3]]
    g.place_decoys()
    assert not any(Path(p).exists() for p in gone)
    assert len(ransom.load_manifest(settings)) == 9


def test_changed_at_start_is_reported_without_pausing(settings, store, hub, canaries, make_guard):
    g = make_guard(start=False)
    g.place_decoys()
    e = decoys_in(canaries[0], settings)[0]
    scramble(e["path"])
    g2 = make_guard()
    settle(g2)
    evs = ransom_events(store)
    assert len(evs) == 1 and "while TacoGuard was not running" in evs[0]["title"]
    assert g2.samples_taken == 0                       # stale evidence: no program is looked at
    assert store.list_paused(("paused", "resumed", "gone", "ended")) == []


def test_write_cut_off_by_a_crash_is_redone_quietly(settings, store, hub, canaries, make_guard):
    g = make_guard(start=False)
    g.place_decoys()
    entries = ransom.load_manifest(settings)
    e = entries[0]
    e["pending"] = True                                # as if the guard died while writing it
    with open(e["path"], "r+b") as f:                  # only half of it reached the disk
        f.truncate(max(1, e["size"] // 2))
    ransom.save_manifest(settings, entries)
    g2 = make_guard()
    settle(g2)
    assert ransom_events(store) == []
    now = {x["path"]: x for x in ransom.load_manifest(settings)}[e["path"]]
    assert sha(e["path"]) == now["sha256"] and "pending" not in now


def test_restart_does_not_repeat_an_alert(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[0], settings)[0]
    scramble(e["path"])
    hub.deliver("modified", e["path"])
    settle(g)
    assert len(ransom_events(store)) == 1
    ev = ransom_events(store)[0]
    changed = sha(e["path"])
    g.stop()                                           # the guard restarts before the alert was dealt with
    g2 = make_guard()
    settle(g2)
    assert len(ransom_events(store)) == 1
    # the alert is still open: the changed decoy stays exactly as it is (not written over)
    assert sha(e["path"]) == changed and e["path"] in [x["path"] for x in ransom.load_manifest(settings)]
    g2.stop()
    g3 = make_guard()                                  # another restart: still left alone
    settle(g3)
    assert sha(e["path"]) == changed and len(ransom_events(store)) == 1
    store.set_guard_event(ev["id"], state="resolved", action="dismissed")
    g3._await_checked = 0.0
    settle(g3)
    now = {x["path"]: x["sha256"] for x in decoys_in(canaries[0], settings)}
    assert e["path"] not in now and sha(e["path"]) == changed
    assert len(now) == ransom.DECOYS_PER_FOLDER and all(sha(p) == h for p, h in now.items())
    assert len(ransom_events(store)) == 1


# ---------------------------------------------------------------------------------------------
# suspects: a harmless "ransomware" child process
# ---------------------------------------------------------------------------------------------
SIMULATOR = r"""
import os, sys, time
target, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
print("ready", flush=True)
sys.stdin.readline()
with open(target, "r+b") as f:                    # scramble the decoy in place (it is hidden)
    n = len(f.read()); f.seek(0); f.write(os.urandom(max(n, 4096))); f.truncate()
print("locked", flush=True)
i = 0
while True:                                       # keep rewriting its OWN scratch files
    p = os.path.join(work, "copy%02d.txt" % (i % 20))
    with open(p, "wb") as f:
        f.write(os.urandom(256 * 1024))
    os.replace(p, p + ".locked")
    i += 1
    time.sleep(0.01)
"""


class Simulator:
    def __init__(self, target: str, work: Path):
        self.proc = subprocess.Popen([sys.executable, "-c", SIMULATOR, target, str(work)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
        assert self.proc.stdout.readline().strip() == "ready"
        root = psutil.Process(self.proc.pid)
        self.pids = {self.proc.pid} | {c.pid for c in root.children(recursive=True)}

    def go(self):
        self.proc.stdin.write("go\n")
        self.proc.stdin.flush()
        assert self.proc.stdout.readline().strip() == "locked"
        time.sleep(0.3)                                   # writing at full speed now

    def close(self):
        for pid in self.pids:
            ref = procctl.ref_of(pid)
            if ref:
                try:
                    procctl.resume(ref)
                except procctl.ProcError:
                    pass
        for pid in self.pids:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            pass


@pytest.fixture
def simulator(tmp_path):
    made = []

    def start(target):
        s = Simulator(target, tmp_path / "sim")
        made.append(s)
        return s

    yield start
    for s in made:
        s.close()


def test_simulated_ransomware_is_paused(settings, store, hub, canaries, make_guard, simulator):
    g0 = make_guard(start=False)
    g0.place_decoys()
    e = decoys_in(canaries[0], settings)[0]
    sim = simulator(e["path"])
    g = make_guard(pid_filter=lambda pid: pid in sim.pids)
    sim.go()
    hub.deliver("modified", e["path"])
    settle(g, kick=False)
    evs = ransom_events(store)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["title"] == "Possible ransomware: a decoy file in Documents was changed. Paused 1 program."
    assert "press Resume" in ev["message"] and "End it" in ev["message"] and "Quarantine" in ev["message"]
    (pid_row,) = ev["data"]["paused_ids"]
    row = store.get_paused(pid_row)
    assert row["state"] == "paused" and row["pid"] in sim.pids
    assert "writing a lot to your disk" in row["reason"] and "press Resume" in row["reason"]
    ref = procctl.ProcRef(row["pid"], row["create_time"])
    assert procctl.is_suspended(ref)
    (s,) = ev["data"]["suspects"]
    assert s["pid"] == row["pid"] and s["write_mb_s"] >= 1 and s["name"].lower().startswith("python")
    assert ev["data"]["decoy"] == e["path"]

    # you press Resume (the page does this) and resolve the alert: the same program is not paused again
    procctl.resume(ref)
    store.set_paused_state(pid_row, "resumed")
    store.set_guard_event(ev["id"], state="resolved", action="resumed")
    settle(g)
    now = {x["path"]: x["sha256"] for x in decoys_in(canaries[0], settings)}
    assert e["path"] not in now and len(now) == ransom.DECOYS_PER_FOLDER     # a fresh decoy, another name
    other = decoys_in(canaries[1], settings)[0]
    scramble(other["path"])
    hub.deliver("modified", other["path"])
    settle(g, kick=False)
    evs = ransom_events(store)
    assert len(evs) == 2 and evs[0]["data"]["paused_ids"] == []
    assert not procctl.is_suspended(ref)


def test_pausing_switched_off_only_reports(settings, store, hub, canaries, make_guard, simulator):
    settings.ransomware_pause = False
    g0 = make_guard(start=False)
    g0.place_decoys()
    e = decoys_in(canaries[2], settings)[0]
    sim = simulator(e["path"])
    g = make_guard(pid_filter=lambda pid: pid in sim.pids)
    sim.go()
    hub.deliver("modified", e["path"])
    settle(g, kick=False)
    (ev,) = ransom_events(store)
    assert ev["title"] == ("Possible ransomware: a decoy file in Pictures was changed. "
                           "Nothing was paused (pausing is off in Settings).")
    assert ev["data"]["suspects"] and ev["data"]["paused_ids"] == []
    assert store.list_paused(("paused", "resumed", "gone", "ended")) == []
    assert not any(procctl.is_suspended(procctl.ref_of(p)) for p in sim.pids if procctl.ref_of(p))


def _wait(cond, timeout=10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_with_the_real_folder_hub(settings, store, tmp_path):
    folders = pytest.importorskip("tacoguard.guard.folders")
    docs = tmp_path / "RealDocs"
    docs.mkdir()
    settings.canary_folders = [str(docs)]
    hub = folders.WatchHub()
    g = ransom.RansomGuard(settings, store, hub, own_pids=lambda: {os.getpid()}, pid_filter=lambda pid: False)
    g.RECREATE_DELAY_S = 0.5
    g.SAMPLE_GAP_S = 0.1
    g.start()
    hub.start()
    try:
        time.sleep(0.5)                                     # the watch thread is listening
        a, b = decoys_in(docs, settings)[:2]
        os.remove(b["path"])                                # deleted: comes back, no alert
        assert _wait(lambda: Path(b["path"]).exists() and sha(b["path"]) ==
                     {x["path"]: x["sha256"] for x in ransom.load_manifest(settings)}[b["path"]])
        assert ransom_events(store) == []
        scramble(a["path"])                                 # changed: one alert
        assert _wait(lambda: len(ransom_events(store)) == 1)
        assert ransom_events(store)[0]["data"]["decoy"] == a["path"]
    finally:
        g.stop()
        hub.stop()


def test_process_writes_snapshot_matches_psutil(tmp_path):
    snap = ransom.process_writes()
    assert len(snap) > 10
    me = psutil.Process()
    (tmp_path / "w.bin").write_bytes(os.urandom(2_000_000))
    ct, wb = ransom.process_writes()[os.getpid()]
    assert abs(ct - me.create_time()) < 0.01
    assert abs(wb - me.io_counters().write_bytes) < 1_000_000 and wb >= 2_000_000


def test_this_process_is_never_a_suspect(settings, store, hub, canaries, make_guard, tmp_path):
    g = make_guard(pid_filter=lambda pid: pid == os.getpid())
    stop = threading.Event()

    def writer():
        p = tmp_path / "busy.bin"
        while not stop.is_set():
            p.write_bytes(os.urandom(512 * 1024))

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        assert g._find_suspects() == []
    finally:
        stop.set()
        t.join(5)


# ---------------------------------------------------------------------------------------------
# review fixes (2026-11-24)
# ---------------------------------------------------------------------------------------------
CHILD_PY = getattr(sys, "_base_executable", None) or sys.executable
MB = 1024 * 1024


def test_finished_downloads_and_known_extensions_are_not_a_burst(settings, store, hub, canaries, make_guard):
    g = make_guard()
    docs = canaries[0]
    # qBittorrent finishing downloads: "movie.mkv.!qB" -> "movie.mkv" (random-looking content)
    for i in range(25):
        p = docs / "Torrents" / f"movie{i}.mkv.!qB"
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(os.urandom(70_000))
        hub.rename(str(p), str(p)[: -len(".!qB")])
    # an ordinary extension added ("backup.tar" -> "backup.tar.gz")
    for p in _files(docs / "Archives", 25, lambda i: b"plain text line\n" * 200):
        tar = p.with_suffix(".tar")
        os.rename(p, tar)
        hub.rename(str(tar), str(tar) + ".gz")
    settle(g)
    assert ransom_events(store) == []
    assert ".!qb" in ransom.TEMP_EXTS


def test_rename_rule():
    g = ransom.RansomGuard.__new__(ransom.RansomGuard)
    assert g._rename_locks(r"C:\x\Budget.xlsx", r"C:\x\Budget.xlsx.locked")
    assert g._rename_locks(r"C:\x\a.docx", r"C:\x\a.docx.id-1234.[mail].crypt")
    assert not g._rename_locks(r"C:\x\a.zip.crdownload", r"C:\x\a.zip")
    assert not g._rename_locks(r"C:\x\a.mkv.!QB", r"C:\x\a.mkv")              # any case
    assert not g._rename_locks(r"C:\x\a.mkv", r"C:\x\a.mkv.!qB")
    assert not g._rename_locks(r"C:\x\scan.jpg", r"C:\x\scan.jpg.pdf")         # an ordinary type


@pytest.fixture
def sleepers():
    made = []

    def start(n=1):
        out = []
        for _ in range(n):
            p = subprocess.Popen([CHILD_PY, "-c", "import time; time.sleep(120)"], creationflags=0x08000000)
            made.append(p)
            out.append(p)
        for p in out:
            assert _wait(lambda: procctl.ref_of(p.pid) is not None, 5)
        return out

    yield start
    for p in made:
        ref = procctl.ref_of(p.pid)
        if ref:
            try:
                procctl.resume(ref)
            except procctl.ProcError:
                pass
        p.kill()
        p.wait(10)


def _fake_samples(g, seq):
    """Feed _find_suspects these write counters instead of the PC's real ones."""
    it = iter(seq)
    calls = []

    def sample():
        calls.append(1)
        return next(it)
    g._sample = sample
    g.SAMPLE_GAP_S = 0.0
    return calls


def test_suspects_are_scored_by_writes_during_the_change(settings, store, hub, canaries, make_guard, sleepers):
    (p,) = sleepers(1)
    pid, ct = p.pid, psutil.Process(p.pid).create_time()
    g = make_guard(start=False)

    def run(*points):
        _fake_samples(g, [(t, {pid: (ct, int(mb * MB))}) for t, mb in points])
        return g._find_suspects()

    # a lone decoy change: samples at the trigger, +0.5 s and +1.0 s, writes in both intervals
    (s,) = run((0.0, 0), (0.5, 1.5), (1.0, 3.0))
    assert s["pid"] == pid and s["write_mb_s"] == 3.0
    assert run((0.0, 0), (0.5, 3.0), (1.0, 3.0)) == []          # stopped writing: not a suspect
    assert run((0.0, 0), (0.5, 0.75), (1.0, 1.5)) == []         # 1.5 MB/s: under the 2 MB/s floor
    # a burst: the 1 s samples kept while it was building count, plus the trigger and +0.5 s
    g._rolling.extend([(0.0, {pid: (ct, 0)}), (1.0, {pid: (ct, 4 * MB)}), (2.0, {pid: (ct, 8 * MB)})])
    calls = _fake_samples(g, [(3.0, {pid: (ct, 12 * MB)}), (3.5, {pid: (ct, 14 * MB)})])
    (s,) = g._find_suspects()
    assert len(calls) == 2 and s["write_mb_s"] == 4.0


def test_signed_programs_are_not_suspects_except_script_hosts(settings, store, hub, canaries, make_guard,
                                                            sleepers, monkeypatch):
    (p,) = sleepers(1)
    pid, ct = p.pid, psutil.Process(p.pid).create_time()
    g = make_guard(start=False)
    g._signed = lambda exe: True                       # say: validly signed (a game, Steam, OBS ...)
    points = [(0.0, 0), (0.5, 5.0), (1.0, 10.0)]
    _fake_samples(g, [(t, {pid: (ct, int(mb * MB))}) for t, mb in points])
    assert [s["pid"] for s in g._find_suspects()] == [pid]      # python.exe runs scripts: stays a suspect
    monkeypatch.setattr(ransom, "SCRIPT_HOSTS", frozenset())
    _fake_samples(g, [(t, {pid: (ct, int(mb * MB))}) for t, mb in points])
    assert g._find_suspects() == []
    assert "powershell.exe" in ransom.SCRIPT_HOSTS or "powershell.exe" in procctl.MAY_PAUSE_IN_WINDOWS


def _suspects_of(procs, rates):
    out = []
    for p, rate in zip(procs, rates):
        q = psutil.Process(p.pid)
        out.append({"pid": p.pid, "create_time": q.create_time(), "name": q.name(), "exe": q.exe(),
                    "write_mb_s": rate})
    return out


def test_at_most_two_programs_are_paused(settings, store, hub, canaries, make_guard, sleepers):
    procs = sleepers(3)
    g = make_guard()
    g._find_suspects = lambda exclude=frozenset(): _suspects_of(procs, (30.0, 20.0, 10.0))
    e = decoys_in(canaries[0], settings)[0]
    scramble(e["path"])
    hub.deliver("modified", e["path"])
    settle(g, kick=False)
    (ev,) = ransom_events(store)
    assert ev["title"] == "Possible ransomware: a decoy file in Documents was changed. Paused 2 programs."
    assert len(ev["data"]["paused_ids"]) == 2 and len(ev["data"]["suspects"]) == 3
    paused = {store.get_paused(i)["pid"] for i in ev["data"]["paused_ids"]}
    assert paused == {procs[0].pid, procs[1].pid}
    refs = [procctl.ref_of(p.pid) for p in procs]
    assert _wait(lambda: procctl.is_suspended(refs[0]) and procctl.is_suspended(refs[1]), 5)
    assert not procctl.is_suspended(refs[2])
    assert ("They were writing a lot to your disk at that moment. If you know these programs (a game, a "
            "download, a backup), press Resume.") in ev["message"]
    assert "Also writing at that moment, not paused:" in ev["message"]
    for i in ev["data"]["paused_ids"]:
        reason = store.get_paused(i)["reason"]
        assert reason.startswith("It was writing a lot to your disk at that moment (")
        assert reason.endswith("If you know this program (a game, a download, a backup), press Resume.")
    assert "malware" not in (ev["title"] + ev["message"]).lower()


def test_test_pause_limit_keeps_other_programs_running(settings, store, hub, canaries, make_guard, sleepers,
                                                       monkeypatch, caplog):
    procs = sleepers(3)
    monkeypatch.setenv(procctl.TEST_PAUSE_ONLY_ENV, str(procs[2].pid))
    g = make_guard()
    g._find_suspects = lambda exclude=frozenset(): _suspects_of(procs, (30.0, 20.0, 10.0))
    e = decoys_in(canaries[1], settings)[0]
    scramble(e["path"])
    with caplog.at_level("WARNING", logger="tacoguard.guard.ransom"):
        hub.deliver("modified", e["path"])
        settle(g, kick=False)
    (ev,) = ransom_events(store)
    (row_id,) = ev["data"]["paused_ids"]
    assert store.get_paused(row_id)["pid"] == procs[2].pid
    assert len(ev["data"]["suspects"]) == 3
    refs = [procctl.ref_of(p.pid) for p in procs]
    assert _wait(lambda: procctl.is_suspended(refs[2]), 5)
    assert not procctl.is_suspended(refs[0]) and not procctl.is_suspended(refs[1])
    assert ("It was writing a lot to your disk at that moment. If you know this program (a game, a download, "
            "a backup), press Resume.") in ev["message"]
    assert sum("TACOGUARD_TEST_PAUSE_ONLY" in r.message for r in caplog.records) == 2


def test_a_paused_program_is_never_paused_twice(settings, store, hub, canaries, make_guard, sleepers):
    (p,) = sleepers(1)
    g = make_guard(start=False)
    (s,) = _suspects_of([p], (9.0,))
    ref = procctl.ProcRef(s["pid"], s["create_time"])
    row = store.add_paused(s["pid"], s["create_time"], s["exe"], s["name"], "earlier")
    assert g._pause(dict(s), "again", g._own()) == row            # the existing row, no new pause
    assert len(store.list_paused(("paused", "not_paused", "resumed", "gone"))) == 1
    assert not procctl.is_suspended(ref)
    store.set_paused_state(row, "resumed")
    procctl.suspend(ref, own=set())                                 # paused by something else
    s2 = dict(s)
    assert g._pause(s2, "again", g._own()) is None and s2["not_paused"]
    assert len(store.list_paused(("paused", "not_paused", "resumed", "gone"))) == 1


def test_a_decoy_you_renamed_and_typed_into_is_never_overwritten(settings, store, hub, canaries, make_guard):
    g = make_guard()
    e = decoys_in(canaries[2], settings)[0]
    mine = str(Path(e["path"]).with_name("My notes" + Path(e["path"]).suffix))
    hub.rename(e["path"], mine)                      # renamed by hand: followed
    settle(g)
    assert mine in [x["path"] for x in ransom.load_manifest(settings)]
    with open(mine, "r+b") as f:                     # ... then you typed into it (it is hidden: in place)
        f.write(b"my own notes, keep them\n" * 50)
        f.truncate()
    hub.deliver("modified", mine)
    settle(g)
    (ev,) = ransom_events(store)
    store.set_guard_event(ev["id"], state="resolved", action="dismissed")
    settle(g)
    assert Path(mine).read_bytes() == b"my own notes, keep them\n" * 50
    now = decoys_in(canaries[2], settings)
    assert mine not in [x["path"] for x in now] and len(now) == ransom.DECOYS_PER_FOLDER
    assert all(sha(x["path"]) == x["sha256"] for x in now)
    g.remove_decoys()
    assert Path(mine).exists()                       # switching off never deletes it either
