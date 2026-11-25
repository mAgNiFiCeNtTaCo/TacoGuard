from __future__ import annotations

import getpass
import os
import subprocess

import pytest

from tacoguard import winpath
from tacoguard.scan import walker
from tacoguard.scan.walker import FileEntry, WalkNote

NO_WINDOW = 0x08000000


def _files(things):
    return [t for t in things if isinstance(t, FileEntry)]


def _notes(things):
    return [t for t in things if isinstance(t, WalkNote)]


def _make(root, rel, data=b"x"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "t"
    for rel in ["b.txt", "A.txt", "sub\\z.txt", "sub\\Y.txt", "sub.txt", "c\\deep\\d.txt", "a\\x.txt"]:
        _make(root, rel)
    return root


def test_order_is_sorted_depth_first_case_folded(tree):
    got = [os.path.relpath(f.display, tree) for f in _files(walker.walk([str(tree)]))]
    assert got == ["a\\x.txt", "A.txt", "b.txt", "c\\deep\\d.txt", "sub\\Y.txt", "sub\\z.txt", "sub.txt"]
    keys = [f.key for f in _files(walker.walk([str(tree)]))]
    assert keys == sorted(keys)


def test_resume_skips_up_to_and_including_checkpoint(tree):
    full = _files(walker.walk([str(tree)]))
    for i, f in enumerate(full):
        rest = _files(walker.walk([str(tree)], checkpoint=f.display))
        assert [r.display for r in rest] == [x.display for x in full[i + 1:]]


def test_resume_does_not_open_finished_folders(tree, monkeypatch):
    opened = []
    real = os.scandir
    monkeypatch.setattr(walker.os, "scandir", lambda p: (opened.append(winpath.to_display(p)), real(p))[1])
    rest = _files(walker.walk([str(tree)], checkpoint=str(tree / "sub\\Y.txt")))
    assert [os.path.relpath(f.display, tree) for f in rest] == ["sub\\z.txt", "sub.txt"]
    assert str(tree / "c") not in opened and str(tree / "a") not in opened


def test_multiple_targets_sorted_and_deduplicated(tree):
    got = _files(walker.walk([str(tree / "sub"), str(tree), str(tree / "b.txt")]))
    assert len(got) == 7


def test_single_file_target_and_missing_target(tree):
    got = list(walker.walk([str(tree / "b.txt"), str(tree / "nope.txt")]))
    assert [type(g) for g in got] == [FileEntry, WalkNote]
    assert got[1].kind == "missing"


def test_long_path_over_300_chars(tmp_path):
    folder = str(tmp_path)
    while len(folder) < 320:
        folder = os.path.join(folder, "a_rather_long_folder_name_for_testing")
    os.makedirs(winpath.to_long(folder))
    target = os.path.join(folder, "deep.txt")
    with open(winpath.to_long(target), "wb") as f:
        f.write(b"deep")
    got = _files(walker.walk([str(tmp_path)]))
    assert len(got) == 1 and got[0].display == target and len(target) > 300
    with open(got[0].path, "rb") as f:
        assert f.read() == b"deep"


def _junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True,
                       creationflags=NO_WINDOW)
    if r.returncode != 0:
        pytest.skip("could not create a junction here")


def test_junction_loop_is_not_followed(tmp_path):
    root = tmp_path / "loop"
    _make(root, "f.txt")
    _junction(root / "back", root)
    try:
        got = list(walker.walk([str(root)]))
        assert [os.path.basename(f.display) for f in _files(got)] == ["f.txt"]
        notes = _notes(got)
        assert len(notes) == 1 and notes[0].kind == "link" and notes[0].message == walker.LINK_NOTE
    finally:
        os.rmdir(root / "back")


def test_junction_as_target_is_resolved_once(tmp_path):
    real = tmp_path / "real"
    _make(real, "inside.txt")
    _junction(tmp_path / "j", real)
    try:
        got = _files(walker.walk([str(tmp_path / "j")]))
        assert [f.display for f in got] == [str(real / "inside.txt")]
    finally:
        os.rmdir(tmp_path / "j")


def _icacls(*args):
    return subprocess.run(["icacls", *map(str, args)], capture_output=True, text=True, creationflags=NO_WINDOW)


def test_folder_without_permission_is_noted(tmp_path):
    root = tmp_path / "p"
    _make(root, "ok.txt")
    locked = root / "locked"
    _make(locked, "secret.txt")
    user = f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}".lstrip("\\")
    if _icacls(locked, "/deny", f"{user}:(RD)").returncode != 0:
        pytest.skip("icacls deny failed")
    try:
        got = list(walker.walk([str(root)]))
        assert [os.path.basename(f.display) for f in _files(got)] == ["ok.txt"]
        notes = _notes(got)
        assert len(notes) == 1 and notes[0].kind == "denied" and notes[0].message == walker.DENIED_NOTE
    finally:
        _icacls(locked, "/remove:d", user)


def test_oversized_file_is_noted(tmp_path):
    _make(tmp_path, "small.bin", b"x" * 10)
    _make(tmp_path, "big.bin", b"x" * 5000)
    got = list(walker.walk([str(tmp_path)], max_file_size=2048))
    assert [os.path.basename(f.display) for f in _files(got)] == ["small.bin"]
    (note,) = _notes(got)
    assert note.kind == "too_big" and note.message == "Bigger than the 2 KB limit (4.9 KB), so it was skipped."


def test_size_wording():
    assert walker.too_big_note(int(3.4 * 1024**3), 2 * 1024**3) == \
        "Bigger than the 2 GB limit (3.4 GB), so it was skipped."


def test_cloud_placeholder_is_noted(tmp_path, monkeypatch):
    _make(tmp_path, "online.txt", b"1234567")
    _make(tmp_path, "local.txt", b"12")
    monkeypatch.setattr(walker.winpath, "is_cloud_placeholder", lambda st: st.st_size == 7)
    got = list(walker.walk([str(tmp_path)]))
    assert [os.path.basename(f.display) for f in _files(got)] == ["local.txt"]
    assert _notes(got)[0].kind == "cloud"


def test_drive_root_is_normalized():
    assert walker.normalize_target("C:") == "C:\\"
    assert walker.order_key("C:\\") == ("c:",)
