"""Archive unpacking: nesting, bomb limits, passwords, damage, RAR4/RAR5.

Test material: tests/samples.py only (sample_bytes with MARKER) plus filler zeros.
"""
from __future__ import annotations

import io
import os
import struct
import subprocess
import threading
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import py7zr
import pytest

import samples
from tacoguard import archives, winpath
from tacoguard.archives import ArchiveNote, archive_kind, clean_name, iter_members
from tacoguard.config import Limits
from tacoguard.model import ScanItem

TAR = archives.BSDTAR
RAR_EXE = r"C:\Program Files\WinRAR\Rar.exe"
needs_tar = pytest.mark.skipif(not os.path.exists(TAR), reason="Windows tar.exe missing")
needs_rar = pytest.mark.skipif(not os.path.exists(RAR_EXE), reason="WinRAR's Rar.exe not installed")


# ---- builders ---------------------------------------------------------------------------------

def make_zip(files: dict[str, bytes], method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_7z(files: dict[str, bytes], password: str | None = None, header_encryption=False) -> bytes:
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password, header_encryption=header_encryption) as z:
        for name, data in files.items():
            z.writestr(data, name)
    return buf.getvalue()


def _rar4_block(htype: int, flags: int, body: bytes) -> bytes:
    hdr = struct.pack("<BHH", htype, flags, 7 + len(body)) + body
    return struct.pack("<H", zlib.crc32(hdr) & 0xFFFF) + hdr


def make_rar4(files: dict[str, bytes], main_flags=0, file_flags=0) -> bytes:
    """A RAR 4 archive with stored (uncompressed) members, built by hand: WinRAR 7 can only
    write RAR5, and the RAR 4 stored layout is simple and well documented."""
    out = b"Rar!\x1a\x07\x00" + _rar4_block(0x73, main_flags, b"\x00" * 6)
    for name, data in files.items():
        n = name.encode()
        body = struct.pack("<IIBIIBBHI", len(data), len(data), 2, zlib.crc32(data), 0x5A000000,
                           20, 0x30, len(n), 0x20) + n
        out += _rar4_block(0x74, 0x8000 | file_flags, body) + data
    return out + _rar4_block(0x7B, 0x4000, b"")


def make_rar5(tmp_path: Path, files: dict[str, bytes], *switches: str) -> Path:
    src = tmp_path / "rar_src"
    for name, data in files.items():
        p = src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    out = tmp_path / f"made{len(list(tmp_path.glob('made*.rar')))}.rar"
    subprocess.run([RAR_EXE, "a", "-ma5", "-idq", "-r", "-y", *switches, str(out), "*"], cwd=src,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=True,
                   creationflags=0x08000000)
    for p in sorted(src.rglob("*"), reverse=True):
        p.rmdir() if p.is_dir() else p.unlink()
    src.rmdir()
    return out


def mem_item(data: bytes, display="test.zip") -> ScanItem:
    return ScanItem(display=display, data=data, size=len(data))


def disk_item(path: Path) -> ScanItem:
    return ScanItem(display=str(path), path=winpath.to_long(path), size=path.stat().st_size)


def run(item: ScanItem, limits: Limits | None = None, **kw):
    out = list(iter_members(item, limits or Limits(), **kw))
    return [x for x in out if isinstance(x, ScanItem)], [x for x in out if isinstance(x, ArchiveNote)]


# ---- basics -----------------------------------------------------------------------------------

def test_archive_kind():
    assert archive_kind(b"PK\x03\x04rest") == "zip"
    assert archive_kind(b"PK\x05\x06" + b"\x00" * 4) == "zip"
    assert archive_kind(b"7z\xbc\xaf\x27\x1c\x00\x04") == "7z"
    assert archive_kind(b"Rar!\x1a\x07\x00\x00") == "rar"
    assert archive_kind(b"Rar!\x1a\x07\x01\x00") == "rar"
    assert archive_kind(b"MZ\x90\x00\x03\x00\x00\x00") is None
    assert archive_kind(b"") is None


def test_clean_name():
    assert clean_name("../../evil.txt") == "evil.txt"
    assert clean_name("C:/Windows/x.dll") == "Windows\\x.dll"
    assert clean_name("/lead/./a\\b.txt") == "lead\\a\\b.txt"
    assert clean_name("..") == "(no name)"


def test_marker_member_path_and_display():
    data = make_zip({"docs/inner/sample.txt": samples.sample_bytes(), "readme.txt": b"plain"})
    items, notes = run(mem_item(data, "Downloads\\a.zip"))
    assert notes == []
    hit = [i for i in items if samples.MARKER in i.data]
    assert len(hit) == 1
    assert hit[0].member == "docs\\inner\\sample.txt"
    assert hit[0].display == "Downloads\\a.zip > docs\\inner\\sample.txt"
    assert hit[0].depth == 1 and hit[0].size == len(samples.sample_bytes())


def test_odd_names_are_cleaned_for_display():
    data = make_zip({"../../up.txt": samples.sample_bytes(), "/abs.txt": b"x"})
    items, _ = run(mem_item(data))
    assert sorted(i.member for i in items) == ["abs.txt", "up.txt"]


def test_zip_on_disk_and_empty_zip(tmp_path):
    p = tmp_path / "d.zip"
    p.write_bytes(make_zip({"s.txt": samples.sample_bytes()}))
    items, notes = run(disk_item(p))
    assert [i.member for i in items] == ["s.txt"] and notes == []
    empty = make_zip({})
    assert archive_kind(empty) == "zip"
    assert run(mem_item(empty)) == ([], [])


# ---- nesting ----------------------------------------------------------------------------------

def nested_chain() -> bytes:
    """outer.zip > l1.7z > l2.zip > l3.zip > sample.txt (the sample sits at depth 4)."""
    l3 = make_zip({"sample.txt": samples.sample_bytes()})
    l2 = make_zip({"l3.zip": l3})
    l1 = make_7z({"l2.zip": l2})
    return make_zip({"l1.7z": l1})


@pytest.mark.parametrize("max_depth", [1, 2, 3, 4])
def test_nesting_depth_limit(max_depth):
    items, notes = run(mem_item(nested_chain(), "outer.zip"), Limits(archive_max_depth=max_depth))
    chain = ["l1.7z", "l1.7z > l2.zip", "l1.7z > l2.zip > l3.zip", "l1.7z > l2.zip > l3.zip > sample.txt"]
    assert [i.member for i in items] == chain[:max_depth]
    assert [i.depth for i in items] == list(range(1, max_depth + 1))
    found = any(samples.MARKER in i.data for i in items)
    assert found == (max_depth == 4)
    if max_depth < 4:
        assert len(notes) == 1 and notes[0].kind == "limit"
        assert notes[0].member == chain[max_depth - 1]
    else:
        assert notes == []
    assert items[-1].display == "outer.zip > " + chain[max_depth - 1]


# ---- bombs and limits -------------------------------------------------------------------------

def test_zip_bomb_is_stopped_quickly_with_low_memory(tmp_path):
    bomb = tmp_path / "bomb.zip"
    zeros = bytes(1024 * 1024)
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("zeros.bin", "w", force_zip64=True) as fh:
            for _ in range(1024):  # 1 GB of zeros, streamed in
                fh.write(zeros)
    assert bomb.stat().st_size < 5 * 1024 * 1024
    tracemalloc.start()
    t0 = time.monotonic()
    items, notes = run(disk_item(bomb))
    elapsed = time.monotonic() - t0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert elapsed < 10
    assert peak < 64 * 1024 * 1024
    assert items == []
    assert [n.kind for n in notes] == ["limit"]
    assert "possible zip bomb" in notes[0].message


def test_7z_bomb_is_stopped():
    data = make_7z({"zeros.bin": bytes(50 * 1024 * 1024)})
    items, notes = run(mem_item(data, "b.7z"))
    assert items == [] and [n.kind for n in notes] == ["limit"]


def _patch_declared_size(data: bytes, new_size: int) -> bytes:
    """Rewrites the 'uncompressed size' in the local header and the central directory."""
    b = bytearray(data)
    assert b[:4] == b"PK\x03\x04"
    struct.pack_into("<I", b, 22, new_size)
    cd = b.index(b"PK\x01\x02")
    struct.pack_into("<I", b, cd + 24, new_size)
    return bytes(b)


def test_lying_header_never_unpacks_more_than_declared():
    real = samples.sample_bytes() + bytes(20 * 1024 * 1024)
    data = _patch_declared_size(make_zip({"liar.bin": real}), 1000)
    tracemalloc.start()
    items, notes = run(mem_item(data))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert all(i.size <= 1000 for i in items)
    assert [n.kind for n in notes] == ["damaged"] and notes[0].member == "liar.bin"
    assert peak < 16 * 1024 * 1024


def test_actual_bytes_are_capped_even_if_declared_sizes_pass():
    ctx = archives._Context(Limits(archive_member_max=1000, archive_max_total=10**9), "x", None)
    collector = archives._Collector(ctx, archives._Ratio(10**9, 100))
    collector.feed(b"a" * 1000)
    with pytest.raises(archives._Stop):
        collector.feed(b"a")
    ratio = archives._Ratio(1000, 100)
    with pytest.raises(archives._Stop):
        ratio.add(archives.RATIO_FLOOR + 1)


def test_total_limit_counts_across_nested_archives():
    inner = make_zip({f"f{i}.bin": os.urandom(400 * 1024) for i in range(3)}, zipfile.ZIP_STORED)
    outer = make_zip({"a.zip": inner, "b.zip": inner}, zipfile.ZIP_STORED)
    limits = Limits(archive_max_total=3 * 1024 * 1024)
    items, notes = run(mem_item(outer), limits)
    assert sum(i.size for i in items) <= limits.archive_max_total
    assert notes and notes[-1].kind == "limit" and "MB of files" in notes[-1].message


def test_member_over_member_max_is_skipped_but_rest_checked():
    data = make_zip({"big.bin": os.urandom(300 * 1024), "s.txt": samples.sample_bytes()})
    items, notes = run(mem_item(data), Limits(archive_member_max=200 * 1024))
    assert [i.member for i in items] == ["s.txt"]
    assert [(n.kind, n.member) for n in notes] == [("limit", "big.bin")]


def test_too_many_entries():
    data = make_zip({f"f{i}.txt": b"x" for i in range(60)})
    items, notes = run(mem_item(data), Limits(archive_max_entries=50))
    assert items == []
    assert [n.kind for n in notes] == ["limit"] and "more than 50 files" in notes[0].message


def test_entry_limit_counts_nested_files():
    inner = make_zip({f"f{i}.txt": b"x" for i in range(30)})
    outer = make_zip({"a.zip": inner, "b.zip": inner})
    items, notes = run(mem_item(outer), Limits(archive_max_entries=50))
    assert 30 <= len(items) <= 50
    assert notes[-1].kind == "limit"


# ---- passwords --------------------------------------------------------------------------------

@needs_tar
@pytest.mark.parametrize("method", ["zipcrypt", "aes256"])
def test_encrypted_zip(tmp_path, method):
    (tmp_path / "s.txt").write_bytes(samples.sample_bytes())
    out = tmp_path / "enc.zip"
    subprocess.run([TAR, "-a", "-c", "-f", str(out), "--options", f"zip:encryption={method}",
                    "--passphrase", "secret", "s.txt"], cwd=tmp_path, stdin=subprocess.DEVNULL,
                   capture_output=True, timeout=60, check=True)
    items, notes = run(disk_item(out))
    assert items == []
    assert [(n.kind, n.message) for n in notes] == [("encrypted", archives.MSG_ENCRYPTED)]


@pytest.mark.parametrize("header_encryption", [False, True])
def test_encrypted_7z(header_encryption):
    data = make_7z({"s.txt": samples.sample_bytes()}, password="secret", header_encryption=header_encryption)
    t0 = time.monotonic()
    items, notes = run(mem_item(data, "e.7z"))
    assert time.monotonic() - t0 < 5
    assert items == [] and [n.kind for n in notes] == ["encrypted"]


# ---- 7z ---------------------------------------------------------------------------------------

def test_7z_members_in_order_with_marker(tmp_path):
    files = {"a.txt": b"first", "dir/s.txt": samples.sample_bytes(), "empty.txt": b""}
    p = tmp_path / "x.7z"
    p.write_bytes(make_7z(files))
    items, notes = run(disk_item(p))
    assert notes == []
    assert {i.member: i.data for i in items} == {"a.txt": b"first", "dir\\s.txt": samples.sample_bytes(),
                                                 "empty.txt": b""}


def test_7z_helper_thread_stops_when_caller_stops():
    data = make_7z({f"f{i}.txt": samples.sample_bytes() for i in range(20)})
    gen = iter_members(mem_item(data, "x.7z"), Limits())
    first = next(gen)
    assert isinstance(first, ScanItem)
    gen.close()
    time.sleep(0.5)
    assert not [t for t in threading.enumerate() if t.name == "tacoguard-7z"]


# ---- RAR --------------------------------------------------------------------------------------

@needs_tar
@pytest.mark.parametrize("on_disk", [True, False])
def test_rar4_stored(tmp_path, on_disk):
    data = make_rar4({"a.txt": b"hello rar4", "sub\\s.txt": samples.sample_bytes()})
    assert archive_kind(data) == "rar"
    if on_disk:
        p = tmp_path / "r4.rar"
        p.write_bytes(data)
        items, notes = run(disk_item(p))
    else:
        items, notes = run(mem_item(data, "r4.rar"), tmp_dir=str(tmp_path / "tmp"))
    assert notes == []
    assert {i.member: i.data for i in items} == {"a.txt": b"hello rar4", "sub\\s.txt": samples.sample_bytes()}
    assert not list((tmp_path / "tmp").glob("*")) if not on_disk else True


@pytest.mark.parametrize("flags", [{"file_flags": 0x04}, {"main_flags": 0x80}])
def test_rar4_encrypted(flags):
    data = make_rar4({"a.txt": samples.sample_bytes()}, **flags)
    items, notes = run(mem_item(data, "e.rar"), tmp_dir=None)
    assert items == []
    assert [n.kind for n in notes] in (["encrypted"], ["unsupported"])


@needs_tar
@pytest.mark.parametrize("flags", [{"file_flags": 0x04}, {"main_flags": 0x80}])
def test_rar4_encrypted_on_disk(tmp_path, flags):
    p = tmp_path / "e.rar"
    p.write_bytes(make_rar4({"a.txt": samples.sample_bytes()}, **flags))
    items, notes = run(disk_item(p))
    assert items == [] and [n.kind for n in notes] == ["encrypted"]


@needs_tar
@needs_rar
@pytest.mark.parametrize("switches", [(), ("-s",), ("-m5",)])
def test_rar5(tmp_path, switches):
    files = {"a.txt": b"first file", "sub/s.txt": samples.sample_bytes(),
             "sub/zeros.bin": bytes(300 * 1024)}
    p = make_rar5(tmp_path, files, *switches)
    items, notes = run(disk_item(p))
    assert notes == []
    got = {i.member: i.data for i in items}
    assert got == {"a.txt": b"first file", "sub\\s.txt": samples.sample_bytes(),
                   "sub\\zeros.bin": bytes(300 * 1024)}
    assert all(i.depth == 1 and i.display == f"{p} > {i.member}" for i in items)


@needs_tar
@needs_rar
@pytest.mark.parametrize("switch", ["-hpsecret", "-psecret"])
def test_rar5_encrypted(tmp_path, switch):
    p = make_rar5(tmp_path, {"s.txt": samples.sample_bytes()}, switch)
    t0 = time.monotonic()
    items, notes = run(disk_item(p))
    assert time.monotonic() - t0 < 10
    assert items == [] and [(n.kind, n.message) for n in notes] == [("encrypted", archives.MSG_ENCRYPTED)]


@needs_tar
@needs_rar
def test_rar_inside_zip_uses_tmp_dir_and_cleans_up(tmp_path):
    rar = make_rar5(tmp_path, {"s.txt": samples.sample_bytes()}).read_bytes()
    outer = make_zip({"inner.rar": rar})
    tmp = tmp_path / "scan_tmp"
    items, notes = run(mem_item(outer, "o.zip"), tmp_dir=str(tmp))
    assert notes == []
    assert [i.member for i in items] == ["inner.rar", "inner.rar > s.txt"]
    assert items[1].data == samples.sample_bytes() and items[1].depth == 2
    assert list(tmp.iterdir()) == []
    items, notes = run(mem_item(outer, "o.zip"))  # no tmp_dir: says so instead of failing
    assert [i.member for i in items] == ["inner.rar"]
    assert [n.kind for n in notes] == ["unsupported"] and notes[0].member == "inner.rar"


@needs_tar
@needs_rar
@pytest.mark.parametrize("short_names", [True, False])
def test_rar_with_unicode_names(tmp_path, monkeypatch, short_names):
    if not short_names:  # drives with 8.3 names switched off: falls back to a copy in tmp_dir
        monkeypatch.setattr(archives, "_short_path", lambda p: None)
    p = make_rar5(tmp_path, {"caf\u00e9 \u00fc.txt": samples.sample_bytes()})
    target = tmp_path / "d\u00e9j\u00e0 \u2603" / "arch\u00efve \u2603.rar"  # tar.exe can't open this name
    target.parent.mkdir()
    p.rename(target)
    tmp = tmp_path / "t"
    items, notes = run(disk_item(target), tmp_dir=str(tmp))
    assert notes == []
    assert [i.member for i in items] == ["caf\u00e9 \u00fc.txt"]
    assert not tmp.exists() or list(tmp.iterdir()) == []  # 8.3 short name, or a cleaned-up copy


@needs_tar
@needs_rar
def test_rar_member_name_outside_ansi_is_reported_not_crashed(tmp_path):
    p = make_rar5(tmp_path, {"snow \u2603.txt": samples.sample_bytes(), "ok.txt": b"x"})
    items, notes = run(disk_item(p))
    assert items == [] and [n.kind for n in notes] == ["unsupported"]


@needs_tar
@needs_rar
def test_rar_too_big_member_skipped(tmp_path):
    p = make_rar5(tmp_path, {"big.bin": os.urandom(300 * 1024), "s.txt": samples.sample_bytes()})
    items, notes = run(disk_item(p), Limits(archive_member_max=200 * 1024))
    assert [i.member for i in items] == ["s.txt"]
    assert [(n.kind, n.member) for n in notes] == [("limit", "big.bin")]


@needs_tar
@needs_rar
def test_rar_tool_killed_when_caller_stops(tmp_path):
    p = make_rar5(tmp_path, {f"f{i}.bin": os.urandom(200 * 1024) for i in range(10)})
    gen = iter_members(disk_item(p), Limits())
    assert isinstance(next(gen), ScanItem)
    gen.close()
    p.unlink()  # a tar.exe still running would hold the archive open


@needs_tar
def test_rar_tool_runs_in_a_kill_on_close_job(tmp_path, monkeypatch):
    """Review 2026-11-23: if the scan worker died, tar.exe kept running. Now it sits in a job
    that Windows ends together with our process."""
    from tacoguard import winjob
    seen = []
    real = winjob.kill_on_close_job

    def recording(handle):
        job = real(handle)
        seen.append(winjob.process_in_job(handle, job) if job else False)
        return job
    monkeypatch.setattr(winjob, "kill_on_close_job", recording)
    p = tmp_path / "a.rar"
    p.write_bytes(make_rar4({"s.txt": samples.sample_bytes()}))
    items, notes = run(disk_item(p))
    assert [i.member for i in items] == ["s.txt"] and seen == [True]


def test_closing_the_job_ends_the_program():
    import sys
    from tacoguard import winjob
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            creationflags=0x08000000)
    try:
        job = winjob.kill_on_close_job(int(proc._handle))
        assert job and winjob.process_in_job(int(proc._handle), job)
        winjob.close_job(job)                 # what Windows does when our process dies
        assert proc.wait(timeout=10) is not None
    finally:
        if proc.poll() is None:
            proc.kill()


# ---- damage and unsupported ---------------------------------------------------------------------

def test_truncated_zip_is_damaged():
    data = make_zip({"s.txt": samples.sample_bytes() * 100, "t.txt": os.urandom(5000)})
    items, notes = run(mem_item(data[: len(data) // 2]))
    assert items == [] and [n.kind for n in notes] == ["damaged"]


def test_corrupted_zip_member_is_damaged_others_checked():
    data = bytearray(make_zip({"bad.bin": os.urandom(5000), "s.txt": samples.sample_bytes()},
                              zipfile.ZIP_STORED))
    data[100] ^= 0xFF  # inside bad.bin's data -> CRC mismatch
    items, notes = run(mem_item(bytes(data)))
    assert [i.member for i in items] == ["s.txt"]
    assert [(n.kind, n.member) for n in notes] == [("damaged", "bad.bin")]


def test_truncated_7z_is_damaged():
    data = make_7z({"s.txt": samples.sample_bytes(), "r.bin": os.urandom(20000)})
    items, notes = run(mem_item(data[:-40], "t.7z"))
    assert [n.kind for n in notes] == ["damaged"]


@needs_tar
@needs_rar
def test_truncated_rar_is_damaged(tmp_path):
    p = make_rar5(tmp_path, {"a.bin": os.urandom(100_000), "b.bin": os.urandom(100_000)})
    data = p.read_bytes()
    p.write_bytes(data[: len(data) // 2])
    items, notes = run(disk_item(p))
    assert [n.kind for n in notes] == ["damaged"]


def test_garbage_after_magic_is_damaged():
    for magic in (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07\x01\x00"):
        items, notes = run(mem_item(magic + os.urandom(200)), tmp_dir=None)
        assert items == [] and len(notes) == 1 and notes[0].kind in ("damaged", "unsupported")


def test_unknown_zip_method_is_unsupported():
    data = bytearray(make_zip({"s.txt": samples.sample_bytes()}, zipfile.ZIP_STORED))
    struct.pack_into("<H", data, 8, 97)  # local header method
    cd = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, cd + 10, 97)  # central directory method
    items, notes = run(mem_item(bytes(data)))
    assert items == [] and [(n.kind, n.member) for n in notes] == [("unsupported", "s.txt")]


# ---- file lists that would eat memory before the entries limit (review 2026-11-23) -------------

def forged_zip(n: int, declared: int = 1, zip64: bool = False) -> bytes:
    """One empty member, listed `n` times in the central directory; the end record says
    `declared`. Nothing harmful inside: empty entries only."""
    name, crc = b"a", zlib.crc32(b"")
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, 0, 0, len(name), 0) + name
    one = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, crc, 0, 0,
                      len(name), 0, 0, 0, 0, 0, 0) + name
    cd = one * n
    if not zip64:
        return local + cd + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, declared, declared,
                                        len(cd), len(local), 0)
    rec_pos = len(local) + len(cd)
    rec = struct.pack("<4sQHHLLQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, declared, declared, len(cd), len(local))
    loc = struct.pack("<4sLQL", b"PK\x06\x07", 0, rec_pos, 1)
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return local + cd + rec + loc + end


@pytest.mark.parametrize("zip64", [False, True])
def test_zip_central_directory_longer_than_end_record_says(zip64, monkeypatch):
    data = forged_zip(200_000, declared=1, zip64=zip64)
    index = archives.read_zip_index(io.BytesIO(data))
    assert index.entries == 1 and index.cd_size == 200_000 * 47 and index.cd_offset == 31

    def no_zipfile(*a, **k):
        raise AssertionError("zipfile must not list this archive")
    monkeypatch.setattr(archives.zipfile, "ZipFile", no_zipfile)
    tracemalloc.start()
    t0 = time.monotonic()
    items, notes = run(mem_item(data))
    elapsed, peak = time.monotonic() - t0, tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert items == [] and [n.message for n in notes] == [archives.MSG_ENTRIES.format(n=10_000)]
    assert elapsed < 5 and peak < 32 * 1024 * 1024


def test_zip_index_matches_zipfile_with_comment_and_prefix():
    data = b"prefix bytes " * 10 + make_zip({f"d/f{i}.txt": b"x" * i for i in range(40)})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.txt", b"x")
        zf.comment = b"a comment PK"
    for blob in (data, buf.getvalue()):
        fh = io.BytesIO(blob)
        index = archives.read_zip_index(fh)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            assert index.entries == len(zf.infolist()) and index.cd_offset == zf.start_dir
            assert archives.count_zip_records(fh, index, 10**6) == len(zf.infolist())


def test_zip_with_long_names_near_the_limit_is_not_refused():
    names = {("n" * 200) + f"{i:04}.txt": b"x" for i in range(90)}
    items, notes = run(mem_item(make_zip(names)), Limits(archive_max_entries=100))
    assert notes == [] and len(items) == 90


def make_7z_header_mode(files: dict[str, bytes], encoded: bool) -> bytes:
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as z:
        z.encoded_header_mode = encoded
        for name, data in files.items():
            z.writestr(data, name)
    return buf.getvalue()


@pytest.mark.parametrize("encoded", [False, True])
def test_7z_file_count_checked_before_py7zr_lists_it(encoded, monkeypatch):
    data = make_7z_header_mode({f"f{i}.txt": b"x" * (i % 7) for i in range(60)}, encoded)
    assert archives.count_7z_files(_plain_7z_header(data), 10**6) == 60
    monkeypatch.setattr(py7zr, "SevenZipFile", lambda *a, **k: pytest.fail("py7zr must not list it"))
    items, notes = run(mem_item(data, "x.7z"), Limits(archive_max_entries=50))
    assert items == [] and [n.message for n in notes] == [archives.MSG_ENTRIES.format(n=50)]


def _plain_7z_header(data: bytes) -> bytes:
    fh = io.BytesIO(data)
    offset, size = struct.unpack_from("<QQ", fh.read(32), 12)
    fh.seek(32 + offset)
    header = fh.read(size)
    if header[0] == 0x17:
        header = archives._7z_decode_header(fh, header, 10**9, AssertionError("too big"))
    return header


@pytest.mark.parametrize("encoded", [False, True])
def test_7z_header_too_big_for_the_limit_is_refused(encoded, monkeypatch):
    monkeypatch.setattr(archives, "INDEX_BYTES_FLOOR", 0)
    # 3 files with 2,000-character names: about 12 KB of header, over 1 KB x 3 allowed entries
    data = make_7z_header_mode({("x" * 2000) + str(i): b"hi" for i in range(3)}, encoded)
    monkeypatch.setattr(py7zr, "SevenZipFile", lambda *a, **k: pytest.fail("py7zr must not read it"))
    items, notes = run(mem_item(data, "x.7z"), Limits(archive_max_entries=3))
    assert items == [] and [n.kind for n in notes] == ["limit"]


def test_7z_normal_archives_still_open():
    for encoded in (False, True):
        data = make_7z_header_mode({"a.txt": b"hello", "s.txt": samples.sample_bytes()}, encoded)
        items, notes = run(mem_item(data, "x.7z"))
        assert notes == [] and {i.member for i in items} == {"a.txt", "s.txt"}


@pytest.mark.parametrize("filters", [
    [{"id": py7zr.FILTER_COPY}], [{"id": py7zr.FILTER_BZIP2}], [{"id": py7zr.FILTER_DEFLATE}],
    [{"id": py7zr.FILTER_X86}, {"id": py7zr.FILTER_LZMA2}], [{"id": py7zr.FILTER_PPMD}],
    [{"id": py7zr.FILTER_ZSTD}]])
def test_7z_other_methods_and_several_folders_still_open(tmp_path, filters):
    p = tmp_path / "multi.7z"
    with py7zr.SevenZipFile(p, "w", filters=filters) as z:
        z.writestr(b"hello", "a.txt")
        z.writestr(b"", "empty.txt")
    with py7zr.SevenZipFile(p, "a", filters=filters) as z:   # a second folder (block)
        z.writestr(samples.sample_bytes(), "dir/s.txt")
    items, notes = run(disk_item(p))
    assert notes == [] and {i.member for i in items} == {"a.txt", "empty.txt", "dir\\s.txt"}


def _7z_number(n: int) -> bytes:
    """7z's variable-length number (enough for values below 2**56)."""
    for extra in range(8):
        if n < (1 << (7 * (extra + 1))):
            break
    if extra == 0:
        return bytes([n])
    first = (0xFF << (8 - extra)) & 0xFF
    return bytes([first | (n >> (8 * extra))]) + (n & ((1 << (8 * extra)) - 1)).to_bytes(extra, "little")


def _7z_wrap(header: bytes) -> bytes:
    nxt = struct.pack("<QQL", 0, len(header), zlib.crc32(header))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<L", zlib.crc32(nxt)) + nxt + header


def forged_7z(numfiles: int, external: bool) -> bytes:
    """A 7z whose header declares `numfiles` files; with `external` its one folder record is
    stored elsewhere in the header (the UnpackInfo "external" flag), which py7zr follows."""
    folder = b"\x01\x00"                                   # 1 coder: Copy
    tail = b"\x0c\x00\x00\x00\x05" + _7z_number(numfiles) + b"\x00\x00" + b"\x00" * (numfiles + 16)
    if not external:
        return _7z_wrap(b"\x01\x04\x07\x0b\x01\x00" + folder + tail)
    head = b"\x01\x04\x07\x0b\x01\x01"
    at = len(head) + 1 + len(tail)
    while len(head) + len(_7z_number(at)) + len(tail) != at:
        at = len(head) + len(_7z_number(at)) + len(tail)
    header = head + _7z_number(at) + tail + folder
    assert header[at:at + 2] == folder
    return _7z_wrap(header)


def test_7z_external_folder_flag_is_followed_and_counted(monkeypatch):
    """Review 2026-11-23: the "external" flag used to make the pre-check give up and leave the
    archive to py7zr, which then built one entry per declared file (hundreds of MB)."""
    blob = forged_7z(3_000_000, external=True)
    assert archives.count_7z_files(blob[32:], 10**7) == 3_000_000
    monkeypatch.setattr(py7zr, "SevenZipFile", lambda *a, **k: pytest.fail("py7zr must not list it"))
    tracemalloc.start()
    try:
        items, notes = run(mem_item(blob, "x.7z"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert items == [] and [n.message for n in notes] == [archives.MSG_ENTRIES.format(n=Limits().archive_max_entries)]
    assert peak < 50 * 1024**2


def test_7z_header_the_check_cannot_follow_is_refused_before_py7zr(monkeypatch):
    # a valid checksum, but a header section py7zr's own reader doesn't expect (0x02 archive
    # properties), or a folder record pointing past the end of the header
    odd = _7z_wrap(b"\x01\x02\x00\x05" + _7z_number(3_000_000) + b"\x00\x00")
    past = bytearray(forged_7z(10, external=True))
    past[32 + 6] = 0x7F                                   # folder record "at" byte 127: past the end
    past = _7z_wrap(bytes(past[32:]))
    monkeypatch.setattr(py7zr, "SevenZipFile", lambda *a, **k: pytest.fail("py7zr must not read it"))
    for blob in (odd, past):
        items, notes = run(mem_item(blob, "x.7z"))
        assert items == [] and [(n.kind, n.message) for n in notes] == [("damaged", archives.MSG_7Z_LAYOUT)]


def test_7z_small_forged_archives_still_go_to_py7zr():
    # under the limit, both layouts are handed on (py7zr then judges the contents)
    for external in (False, True):
        items, notes = run(mem_item(forged_7z(3, external), "x.7z"))
        assert all(n.message != archives.MSG_7Z_LAYOUT for n in notes)


@needs_tar
def test_rar_listing_stops_at_the_entries_limit(tmp_path, monkeypatch):
    import rarfile
    seen = []
    real = archives._RarHeaderCounter.__call__

    def counting(self, h):
        seen.append(h)
        real(self, h)
    monkeypatch.setattr(archives._RarHeaderCounter, "__call__", counting)
    p = tmp_path / "many.rar"
    p.write_bytes(make_rar4({f"f{i}.txt": b"x" for i in range(200)}))
    items, notes = run(disk_item(p), Limits(archive_max_entries=50))
    assert items == [] and [n.message for n in notes] == [archives.MSG_ENTRIES.format(n=50)]
    assert len([h for h in seen if getattr(h, "type", None) == rarfile.RAR_BLOCK_FILE]) == 51


def test_running_out_of_memory_becomes_a_note(monkeypatch):
    def huge(*a, **k):
        raise MemoryError
    data = make_zip({"a.txt": b"x"})
    monkeypatch.setattr(archives.zipfile, "ZipFile", huge)
    items, notes = run(mem_item(data))
    assert items == [] and [(n.kind, n.message) for n in notes] == [("limit", archives.MSG_MEMORY)]
