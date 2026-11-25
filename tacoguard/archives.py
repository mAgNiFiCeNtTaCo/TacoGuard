"""Looking inside zip / 7z / rar archives, safely.

CONTRACT (Helper C fills this in; signatures must stay):

    archive_kind(head: bytes) -> str | None
        "zip" | "7z" | "rar" from the first bytes of a file (at least 8 bytes given), else None.

    iter_members(item: ScanItem, limits: Limits) -> Iterator[ScanItem | ArchiveNote]
        `item` is an archive (on disk via item.path, or in memory via item.data).
        Yields every file inside as an in-memory ScanItem (data set, member = path inside the
        OUTER archive joined with " > " for nested ones, display = item.display + " > " + member,
        depth = item.depth + 1). Nested archives are opened by this function itself, down to
        limits.archive_max_depth; the nested archive is yielded too (as a ScanItem) before its
        members. Yields an ArchiveNote instead whenever something could not be checked:
        password-protected, a limit was hit (possible zip bomb), damaged, unsupported method.
        Must never hang, never use more than about limits.archive_member_max of memory per
        member, and never write unpacked files to disk outside settings.tmp_dir.

How it works:
- zip: Python's zipfile. 7z: py7zr, unpacked on a helper thread that hands over one member at
  a time. rar: the rarfile package reads the headers (names, sizes, password flags) and Windows'
  own tar.exe (bsdtar / libarchive) unpacks, converting the RAR into a tar stream on a pipe.
  tar.exe runs in a kill-on-close job (tacoguard/winjob.py), so it ends if the scan worker dies.
- Optional `tmp_dir` (pass settings.tmp_dir): only used for a RAR that is itself inside another
  archive (or has a name tar.exe cannot read). It holds a copy of that packed RAR, never
  unpacked files, and is always cleaned up. Without it such a RAR gets an "unsupported" note.
- Limits are checked twice: against the sizes the archive declares (refused before unpacking)
  and against the bytes actually coming out (headers can lie).
- The file list itself is checked before zipfile / py7zr / rarfile read it: a small archive can
  declare millions of entries, and listing them would eat gigabytes. zip: the central directory
  is counted record by record (no objects built). 7z: the header's stored and unpacked sizes are
  bounded and its file count is read by a small parser that allocates nothing per entry (a
  header that parser can't follow is refused, not handed to py7zr). RAR:
  rarfile's per-header callback stops the listing once the limit is passed.
- Running out of memory anyway (the scan worker has a memory cap) ends that archive with a note.
"""
from __future__ import annotations

import ctypes
import io
import os
import queue
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass
from typing import Iterator

from . import winjob
from .config import Limits
from .model import ScanItem

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
RAR_MAGICS = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")

BSDTAR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe")
CREATE_NO_WINDOW = 0x08000000
READ_CHUNK = 64 * 1024
# A small file of repeated text can compress 1000:1 and is not a bomb; the ratio limit only
# applies once a member has unpacked past this size.
RATIO_FLOOR = 1024 * 1024
TOOL_IDLE_TIMEOUT_S = 60       # tar.exe sent nothing for this long while we waited -> killed
SEVENZIP_IDLE_TIMEOUT_S = 120  # the 7z helper thread made no progress for this long -> given up
STREAM_OVERHEAD = 64 * 1024**2  # tar headers on top of the unpacked bytes we allow from tar.exe

MSG_ENCRYPTED = "Password-protected archive: the files inside were not checked."
MSG_SOME_ENCRYPTED = "Some files in this archive are password-protected and were not checked."
MSG_BOMB = ("Stopped unpacking: this archive unpacks to far more than its size (possible zip bomb). "
            "The rest was not checked.")
MSG_TOTAL = ("Stopped unpacking: this archive holds more than {mb} MB of files (possible zip bomb). "
             "The rest was not checked.")
MSG_ENTRIES = "Stopped unpacking: this archive holds more than {n} files. The rest was not checked."
MSG_DEPTH = "Archive inside an archive more than {n} levels deep: it was not opened, so its files were not checked."
MSG_MEMBER_BIG = "A file inside is larger than {mb} MB, so it was not unpacked or checked."
MSG_DAMAGED = "This archive is damaged or incomplete, so not everything inside could be checked."
MSG_UNSUPPORTED = "This archive uses a packing method TacoGuard can't unpack, so the files inside were not checked."
MSG_SLOW = "Stopped unpacking: this archive took far too long to unpack. The rest was not checked."
MSG_NO_TAR = "RAR archives can't be opened on this PC (Windows' built-in tar tool is missing)."
MSG_RAR_NO_TMP = "This RAR archive could not be opened here (no temporary folder to work in)."
MSG_RAR_NAMES = ("This RAR archive has file names that Windows' built-in unpacker can't read, "
                 "so the files inside were not checked.")
MSG_7Z_LAYOUT = ("This 7z archive is damaged or laid out in a way TacoGuard can't check safely, "
                 "so it was not unpacked and the files inside were not checked.")
MSG_MEMORY = ("Stopped unpacking: this archive needed more memory than TacoGuard allows. "
              "The rest was not checked.")

# An archive's file list may use at most this many bytes per allowed entry (names are the bulk:
# a 260-character path is about 520 bytes in a 7z header), with a floor for small limits.
INDEX_BYTES_PER_ENTRY = 1024
INDEX_BYTES_FLOOR = 1024 * 1024
ZIP_CD_RECORD = 46            # smallest zip central directory record (no name, extra or comment)
SEVENZIP_ENCODED_STORED_MAX = 64 * 1024   # the stored part of an encoded 7z header is tiny


def index_bytes_limit(limits: Limits) -> int:
    return max(INDEX_BYTES_FLOOR, int(limits.archive_max_entries) * INDEX_BYTES_PER_ENTRY)


@dataclass
class ArchiveNote:
    kind: str       # "encrypted" | "limit" | "damaged" | "unsupported"
    message: str    # plain English, e.g. "Password-protected archive: the files inside were not checked."
    member: str = ""


def archive_kind(head: bytes) -> str | None:
    head = bytes(head[:8])
    if head.startswith(ZIP_MAGICS):
        return "zip"
    if head.startswith(SEVENZIP_MAGIC):
        return "7z"
    if head.startswith(RAR_MAGICS):
        return "rar"
    return None


def iter_members(item: ScanItem, limits: Limits, tmp_dir=None) -> Iterator[ScanItem | ArchiveNote]:
    ctx = _Context(limits, item.display, tmp_dir)
    try:
        src = item.data if item.data is not None else item.path
        if src is None:
            return
        kind = archive_kind(_head(src))
        if kind is None:
            return
        if kind == "rar" and item.path:
            src = item.path  # tar.exe needs a file on disk; avoids a temp copy
        yield from _walk(src, kind, "", item.depth, ctx)
    except _StopAll as stop:
        yield ArchiveNote(stop.kind, stop.message)
    except MemoryError:
        yield ArchiveNote("limit", MSG_MEMORY)
    except Exception:  # never let bad archive content break a scan
        yield ArchiveNote("damaged", MSG_DAMAGED)


# ---- shared state and limits ----------------------------------------------------------------

class _Stop(Exception):
    """Ends the current archive (the one being unpacked) with a note."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


class _StopAll(_Stop):
    """Ends the whole outer archive: its total size or file count budget is used up."""


class _Context:
    def __init__(self, limits: Limits, display: str, tmp_dir):
        self.limits = limits
        self.display = display
        self.tmp_dir = tmp_dir
        self.entries = 0
        self.total = 0

    def count_entry(self) -> None:
        self.entries += 1
        if self.entries > self.limits.archive_max_entries:
            raise _StopAll("limit", MSG_ENTRIES.format(n=self.limits.archive_max_entries))

    def add_bytes(self, n: int) -> None:
        self.total += n
        if self.total > self.limits.archive_max_total:
            raise _StopAll("limit", MSG_TOTAL.format(mb=self.limits.archive_max_total // 1024**2))

    def check_count(self, declared_entries: int) -> None:
        """Refuses an archive whose own file list is already over the limit (before listing it)."""
        if declared_entries > self.limits.archive_max_entries:
            raise _StopAll("limit", MSG_ENTRIES.format(n=self.limits.archive_max_entries))

    def too_big(self, declared: int, packed: int, skip_is_free: bool = True) -> bool:
        """Checks the sizes an archive declares, before unpacking. True = skip this member.

        In zip a skipped member costs nothing. In 7z and RAR it is still unpacked (and thrown
        away) to reach the next one, so there the total limit is checked first."""
        lim = self.limits
        if declared > RATIO_FLOOR and declared > lim.archive_max_ratio * max(packed, 1):
            raise _Stop("limit", MSG_BOMB)
        if skip_is_free and declared > lim.archive_member_max:
            return True
        if self.total + declared > lim.archive_max_total:
            raise _StopAll("limit", MSG_TOTAL.format(mb=lim.archive_max_total // 1024**2))
        return declared > lim.archive_member_max

    def big_note(self, member: str) -> ArchiveNote:
        return ArchiveNote("limit", MSG_MEMBER_BIG.format(mb=self.limits.archive_member_max // 1024**2), member)


class _Ratio:
    """Unpacked bytes against packed bytes, for one member (or one solid 7z block)."""

    def __init__(self, packed: int, limit: int):
        self.packed = max(int(packed or 0), 1)
        self.limit = limit
        self.unpacked = 0

    def add(self, n: int) -> None:
        self.unpacked += n
        if self.unpacked > RATIO_FLOOR and self.unpacked > self.limit * self.packed:
            raise _Stop("limit", MSG_BOMB)


class _Collector:
    """Gathers one member's bytes as they are unpacked, enforcing every limit on the way."""

    def __init__(self, ctx: _Context, ratio: _Ratio, keep: bool = True):
        self.ctx = ctx
        self.ratio = ratio
        self.keep = keep
        self.size = 0
        self.buf = io.BytesIO()

    def feed(self, chunk) -> None:
        n = len(chunk)
        self.size += n
        self.ctx.add_bytes(n)
        self.ratio.add(n)
        if self.keep:
            if self.size > self.ctx.limits.archive_member_max:
                raise _Stop("limit", MSG_BOMB)  # declared small, unpacks big: the header lied
            self.buf.write(chunk)

    def data(self) -> bytes:
        return self.buf.getvalue()


def _read_capped(fh, collector: _Collector) -> bytes:
    while True:
        chunk = fh.read(READ_CHUNK)
        if not chunk:
            return collector.data()
        collector.feed(chunk)


# ---- walking (nesting, names, notes) ----------------------------------------------------------

def _walk(src, kind: str, parent: str, depth: int, ctx: _Context) -> Iterator[ScanItem | ArchiveNote]:
    """One archive: yields its members and notes, and opens nested archives."""
    try:
        for entry in _OPENERS[kind](src, ctx):
            if isinstance(entry, ArchiveNote):
                entry.member = _join(parent, entry.member)
                yield entry
                continue
            name, data = entry
            member = _join(parent, name)
            yield ScanItem(display=f"{ctx.display} > {member}", data=data, size=len(data),
                           member=member, depth=depth + 1)
            inner = archive_kind(data[:8])
            if inner is None:
                continue
            if depth + 1 >= ctx.limits.archive_max_depth:
                yield ArchiveNote("limit", MSG_DEPTH.format(n=ctx.limits.archive_max_depth), member)
            else:
                yield from _walk(data, inner, member, depth + 1, ctx)
    except _StopAll:
        raise
    except _Stop as stop:
        yield ArchiveNote(stop.kind, stop.message, parent)
    except MemoryError:
        raise _StopAll("limit", MSG_MEMORY) from None
    except Exception as exc:
        yield _note_for_error(exc, parent)


def _join(parent: str, name: str) -> str:
    if parent and name:
        return f"{parent} > {name}"
    return parent or name


_DRIVE = re.compile(r"^[A-Za-z]:")
_CONTROL = re.compile(r"[\x00-\x1f]")


def clean_name(name: str) -> str:
    """Display form of a member name: backslashes, no drive, no leading slash, no '..'."""
    name = _CONTROL.sub("?", _DRIVE.sub("", str(name)))
    parts = [p for p in re.split(r"[\\/]+", name) if p not in ("", ".", "..")]
    return "\\".join(parts) or "(no name)"


def _note_for_error(exc: Exception, member: str = "") -> ArchiveNote:
    import py7zr.exceptions as e7
    import rarfile

    if isinstance(exc, (e7.PasswordRequired, rarfile.PasswordRequired, rarfile.RarWrongPassword)):
        return ArchiveNote("encrypted", MSG_ENCRYPTED, member)
    if isinstance(exc, (e7.UnsupportedCompressionMethodError, NotImplementedError)):
        return ArchiveNote("unsupported", MSG_UNSUPPORTED, member)
    return ArchiveNote("damaged", MSG_DAMAGED, member)


def _head(src) -> bytes:
    if isinstance(src, (bytes, bytearray, memoryview)):
        return bytes(src[:8])
    with open(src, "rb") as fh:
        return fh.read(8)


def _open_binary(src):
    if isinstance(src, (bytes, bytearray, memoryview)):
        return io.BytesIO(src)
    return open(src, "rb")


# ---- zip --------------------------------------------------------------------------------------

_ZIP_EOCD = struct.Struct("<4s4H2LH")        # end of central directory record, 22 bytes
_ZIP64_LOCATOR = struct.Struct("<4sLQL")     # 20 bytes, just before the end record
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")    # 56 bytes


@dataclass
class ZipIndex:
    entries: int        # entries the end record declares
    cd_offset: int      # where the central directory starts (as zipfile will compute it)
    cd_size: int        # bytes of central directory the end record declares


def read_zip_index(fh) -> ZipIndex | None:
    """Reads the zip's end record (and the zip64 one) the way zipfile will, without listing
    anything. None when there is no end record (zipfile will then call the file damaged)."""
    size = fh.seek(0, os.SEEK_END)
    if size < _ZIP_EOCD.size:
        return None
    # zipfile first tries an end record with no comment, then the last one in the final 64 KB
    fh.seek(size - _ZIP_EOCD.size)
    tail = fh.read(_ZIP_EOCD.size)
    if tail[:4] == b"PK\x05\x06" and tail[-2:] == b"\x00\x00":
        eocd_pos = size - _ZIP_EOCD.size
    else:
        start = max(0, size - (1 << 16) - _ZIP_EOCD.size)
        fh.seek(start)
        tail = fh.read(size - start)
        found = tail.rfind(b"PK\x05\x06")
        if found < 0 or len(tail) - found < _ZIP_EOCD.size:
            return None
        eocd_pos = start + found
        tail = tail[found:found + _ZIP_EOCD.size]
    _, _, _, _, entries, cd_size, _, _ = _ZIP_EOCD.unpack(tail[:_ZIP_EOCD.size])
    location = eocd_pos
    offset = eocd_pos - _ZIP64_LOCATOR.size
    if offset >= 0:                       # zip64: same steps as zipfile._EndRecData64
        fh.seek(offset)
        loc = fh.read(_ZIP64_LOCATOR.size)
        if len(loc) == _ZIP64_LOCATOR.size and loc[:4] == b"PK\x06\x07":
            _, _, reloff, _ = _ZIP64_LOCATOR.unpack(loc)
            offset -= _ZIP64_EOCD.size
            if reloff > offset:
                return None
            fh.seek(reloff)
            rec, location = fh.read(_ZIP64_EOCD.size), reloff
            if rec[:4] != b"PK\x06\x06" and reloff != offset:
                fh.seek(offset)
                rec, location = fh.read(_ZIP64_EOCD.size), offset
            if len(rec) != _ZIP64_EOCD.size or rec[:4] != b"PK\x06\x06":
                return None
            fields = _ZIP64_EOCD.unpack(rec)
            entries, cd_size = fields[7], fields[8]
    # zipfile allows data in front of the zip: the directory ends where the end record starts
    start_dir = location - cd_size
    return ZipIndex(entries, max(start_dir, 0), cd_size)


def count_zip_records(fh, index: ZipIndex, stop_after: int) -> int:
    """Counts central directory records one by one, as zipfile will read them, building nothing.
    Stops once more than `stop_after` were seen."""
    fh.seek(index.cd_offset)
    end = index.cd_offset + index.cd_size
    pos, n = index.cd_offset, 0
    while pos < end and n <= stop_after:
        head = fh.read(ZIP_CD_RECORD)
        if len(head) < ZIP_CD_RECORD or head[:4] != b"PK\x01\x02":
            break                        # zipfile stops here too (damaged directory)
        name_len, extra_len, comment_len = struct.unpack_from("<3H", head, 28)
        skip = name_len + extra_len + comment_len
        pos += ZIP_CD_RECORD + skip
        fh.seek(skip, os.SEEK_CUR)
        n += 1
    return n


def check_zip_index(fh, ctx: "_Context") -> None:
    """Refuses a zip whose file list is over the entries limit, before zipfile reads it
    (zipfile builds one object per listed entry, whatever the end record claims)."""
    try:
        index = read_zip_index(fh)
    finally:
        fh.seek(0)
    if index is None:
        return
    limit = ctx.limits.archive_max_entries
    ctx.check_count(index.entries)
    if index.cd_size > index_bytes_limit(ctx.limits):
        raise _StopAll("limit", MSG_ENTRIES.format(n=limit))
    try:
        ctx.check_count(count_zip_records(fh, index, limit))
    finally:
        fh.seek(0)


def _zip_entries(src, ctx: _Context):
    with _open_binary(src) as fh:
        check_zip_index(fh, ctx)
        yield from _zip_members(fh, ctx)


def _zip_members(fh, ctx: _Context):
    with zipfile.ZipFile(fh) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        locked = [i for i in infos if i.flag_bits & 0x1]
        if locked:
            yield ArchiveNote("encrypted", MSG_ENCRYPTED if len(locked) == len(infos) else MSG_SOME_ENCRYPTED)
        for info in infos:
            if info.flag_bits & 0x1:
                continue
            ctx.count_entry()
            name = clean_name(info.filename)
            if ctx.too_big(info.file_size, info.compress_size):
                yield ctx.big_note(name)
                continue
            try:
                collector = _Collector(ctx, _Ratio(info.compress_size, ctx.limits.archive_max_ratio))
                with zf.open(info) as member:
                    data = _read_capped(member, collector)
            except (NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError) as exc:
                yield _note_for_error(exc, name)
                continue
            yield name, data


# ---- 7z ---------------------------------------------------------------------------------------

class _Aborted(BaseException):
    """Stops the 7z helper thread. BaseException so py7zr's own handlers don't swallow it."""


def _7z_entries(src, ctx: _Context):
    import py7zr
    from py7zr.exceptions import PasswordRequired

    with _open_binary(src) as fh:
        try:
            check_7z_index(fh, ctx)
        finally:
            fh.seek(0)
        try:
            archive = py7zr.SevenZipFile(fh)  # a file object (not a path) keeps py7zr single-threaded
        except PasswordRequired:
            yield ArchiveNote("encrypted", MSG_ENCRYPTED)
            return
        with archive:
            if archive.needs_password():
                yield ArchiveNote("encrypted", MSG_ENCRYPTED)
                return
            ctx.check_count(len(archive.files))
            pump = _SevenZipPump(archive, ctx)
            try:
                yield from pump.entries()
            finally:
                pump.stop()


class _HeaderUnreadable(Exception):
    """Our small 7z header reader could not follow this header, so it is not unpacked."""


class _HeaderReader:
    """Walks 7z header bytes without building anything per entry (py7zr builds a dict per
    listed file before anyone can check the count)."""

    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.pos = 0

    def left(self) -> int:
        return len(self.data) - self.pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise _HeaderUnreadable
        b = self.data[self.pos]
        self.pos += 1
        return b

    def skip(self, n: int) -> None:
        if n < 0 or n > self.left():
            raise _HeaderUnreadable
        self.pos += n

    def number(self) -> int:
        """7z's variable-length UINT64 (same reading as py7zr.archiveinfo.read_uint64)."""
        first, mask, value = self.byte(), 0x80, 0
        for i in range(8):
            if first & mask == 0:
                return value | ((first & (mask - 1)) << (8 * i))
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def count(self, n: int, bits_each: int = 8) -> int:
        """A count the remaining bytes could hold, else unreadable."""
        if n < 0 or n * bits_each > self.left() * 8:
            raise _HeaderUnreadable
        return n

    def bits(self, n: int, as_list: bool = False):
        """A bit vector of n entries preceded by py7zr's 'all defined' byte. Returns how many
        are set, or (as_list) the bits themselves, None meaning all set."""
        if self.byte() != 0:
            return None if as_list else n
        self.count(n, 1)
        raw = bytes(self.data[self.pos:self.pos + (n + 7) // 8])
        self.pos += (n + 7) // 8
        if as_list:
            return [bool(raw[i // 8] & (0x80 >> (i % 8))) for i in range(n)]
        full, rest = divmod(n, 8)
        set_bits = sum(bin(b).count("1") for b in raw[:full])
        if rest:
            set_bits += bin(raw[full] >> (8 - rest)).count("1")
        return set_bits


def _7z_folders(r: _HeaderReader, nfolders: int) -> list[int]:
    """Skips nfolders folder records (coders, bind pairs, packed streams); returns each
    folder's number of output streams."""
    r.count(nfolders)
    outs = []
    for _ in range(nfolders):
        coders = r.number()
        if not 1 <= coders <= 64:
            raise _HeaderUnreadable
        tin = tout = 0
        for _ in range(coders):
            flag = r.byte()
            r.skip(flag & 0x0F)
            if flag & 0x10:
                tin, tout = tin + r.number(), tout + r.number()
            else:
                tin, tout = tin + 1, tout + 1
            if tin > 64 or tout > 64:
                raise _HeaderUnreadable
            if flag & 0x20:
                r.skip(r.number())
        for _ in range(tout - 1):                  # bind pairs
            r.number()
            r.number()
        packed = tin - (tout - 1)
        if packed < 1:
            raise _HeaderUnreadable
        if packed > 1:
            for _ in range(packed):
                r.number()
        outs.append(tout)
    return outs


def _7z_skip_streams(r: _HeaderReader, max_entries: int) -> None:
    """Skips a MainStreamsInfo block. Folders and streams are bounded by the entries limit
    (a valid archive never has more of them than it has files)."""
    pid = r.byte()
    if pid == 0x06:                                    # PackInfo
        r.number()
        n = r.count(r.number())
        pid = r.byte()
        if pid == 0x09:
            for _ in range(n):
                r.number()
            pid = r.byte()
            if pid == 0x0A:
                r.skip(4 * r.bits(n))
                pid = r.byte()
        if pid != 0x00:
            raise _HeaderUnreadable
        pid = r.byte()
    folders: list[bool] = []                           # per folder: CRC defined
    if pid == 0x07:                                    # UnpackInfo
        if r.byte() != 0x0B:
            raise _HeaderUnreadable
        nfolders = r.number()
        if nfolders > max_entries:
            raise _StopAll("limit", MSG_ENTRIES.format(n=max_entries))
        if r.byte() != 0x00:                           # "external": the folders sit elsewhere in
            at = r.number()                            # the header; py7zr jumps there, so do we
            back = r.pos
            if at > len(r.data):
                raise _HeaderUnreadable
            r.pos = at
            outs = _7z_folders(r, nfolders)
            r.pos = back
        else:
            outs = _7z_folders(r, nfolders)
        if r.byte() != 0x0C:
            raise _HeaderUnreadable
        for tout in outs:
            for _ in range(tout):
                r.number()
        pid = r.byte()
        folders = [False] * nfolders
        if pid == 0x0A:
            defined = r.bits(nfolders, as_list=True)
            folders = [True] * nfolders if defined is None else defined
            r.skip(4 * nfolders)                       # py7zr reads one CRC per folder
            pid = r.byte()
        if pid != 0x00:
            raise _HeaderUnreadable
        pid = r.byte()
    if pid == 0x08:                                    # SubStreamsInfo
        pid = r.byte()
        per_folder = [1] * len(folders)
        if pid == 0x0D:
            total = 0
            for i in range(len(folders)):
                per_folder[i] = r.number()
                total += per_folder[i]
                if total > max_entries:
                    raise _StopAll("limit", MSG_ENTRIES.format(n=max_entries))
            pid = r.byte()
        if pid == 0x09:
            for n in per_folder:
                for _ in range(n - 1):
                    r.number()
            pid = r.byte()
        if pid == 0x0A:
            digests = sum(n for n, crc in zip(per_folder, folders) if n != 1 or not crc)
            r.bits(digests)
            r.skip(4 * digests)                        # py7zr reads one CRC per stream here too
            pid = r.byte()
        if pid != 0x00:
            raise _HeaderUnreadable
        pid = r.byte()
    if pid != 0x00:
        raise _HeaderUnreadable


def count_7z_files(header: bytes, max_entries: int) -> int:
    """Number of files a plain (not encoded) 7z header lists; header[0] must be 0x01."""
    r = _HeaderReader(header)
    if r.byte() != 0x01:
        raise _HeaderUnreadable
    pid = r.byte()
    if pid == 0x04:
        _7z_skip_streams(r, max_entries)
        pid = r.byte()
    if pid == 0x05:
        return r.number()
    if pid != 0x00:              # py7zr only reads streams, then files, then the end mark
        raise _HeaderUnreadable
    return 0


def _7z_decode_header(fh, stored: bytes, limit: int, too_big: Exception) -> bytes:
    """Unpacks an encoded 7z header the way py7zr does, after checking its declared size
    (raises `too_big` when it declares more than `limit` bytes)."""
    from py7zr.archiveinfo import HeaderStreamsInfo

    streams = HeaderStreamsInfo.retrieve(io.BytesIO(stored[1:]))
    if not streams.packinfo.packsizes or not streams.unpackinfo.folders:
        raise _HeaderUnreadable
    sizes = []
    for folder in streams.unpackinfo.folders:
        unpacked = folder.unpacksizes
        if not isinstance(unpacked, (list, tuple)):
            unpacked = [unpacked]
        sizes.append(int(unpacked[-1]))
    if any(s < 0 for s in sizes) or sum(sizes) > limit:
        raise too_big
    out = bytearray()
    src = 32
    for folder, size in zip(streams.unpackinfo.folders, sizes):
        packed = streams.packinfo.packsizes[0]
        src += streams.packinfo.packpos
        fh.seek(src)
        decompressor = folder.get_decompressor(packed)
        start = len(out)
        while len(out) - start < size:
            before = (len(out), decompressor.consumed)
            out += decompressor.decompress(fh, max_length=size - (len(out) - start))
            if (len(out), decompressor.consumed) == before:
                raise _HeaderUnreadable
        src += packed
    return bytes(out)


def check_7z_index(fh, ctx: "_Context") -> None:
    """Refuses a 7z whose header is implausibly big for the entries limit, or lists more files
    than allowed, before py7zr reads it. A header py7zr itself would refuse straight away (bad
    checksum, wrong size, a password or packing method it can't undo) is left to py7zr, which
    then says damaged, encrypted or unsupported. Any other header this check can't follow is
    refused here (fail closed): py7zr might otherwise build millions of entries from it."""
    from py7zr.exceptions import PasswordRequired, UnsupportedCompressionMethodError

    max_entries = ctx.limits.archive_max_entries
    limit = index_bytes_limit(ctx.limits)
    too_many = _StopAll("limit", MSG_ENTRIES.format(n=max_entries))
    start = fh.read(32)
    if len(start) < 32 or not start.startswith(SEVENZIP_MAGIC):
        return
    next_offset, next_size, next_crc = struct.unpack_from("<QQL", start, 12)
    file_size = fh.seek(0, os.SEEK_END)
    if next_size == 0 or 32 + next_offset + next_size > file_size             or zlib.crc32(start[12:32]) != struct.unpack_from("<L", start, 8)[0]:
        return                                      # empty or damaged: py7zr reads no list
    if next_size > limit:
        raise too_many
    fh.seek(32 + next_offset)
    header = fh.read(next_size)
    if len(header) != next_size or zlib.crc32(header) != next_crc:
        return                                      # py7zr checks this too and stops
    try:
        if header[0] == 0x17:                       # encoded (packed) header
            if next_size > SEVENZIP_ENCODED_STORED_MAX:
                raise too_many
            try:
                header = _7z_decode_header(fh, header, limit, too_many)
            except (PasswordRequired, UnsupportedCompressionMethodError):
                return                              # py7zr can't unpack the list either
        files = count_7z_files(header, max_entries)
    except _StopAll:
        raise
    except MemoryError:
        raise
    except Exception:            # a layout we can't follow: refused, never handed to py7zr
        raise _Stop("damaged", MSG_7Z_LAYOUT) from None
    ctx.check_count(files)


class _SevenZipPump:
    """Runs py7zr's extraction on a helper thread with in-memory writers.

    py7zr pushes every member through one extract call; this turns that into a generator. The
    thread hands over one finished member, then waits until the caller asks for the next, so
    only one member is in memory and only one thread touches the shared limits at a time."""

    def __init__(self, archive, ctx: _Context):
        self.archive = archive
        self.ctx = ctx
        self.members = self._plan()
        self.out: queue.Queue = queue.Queue(maxsize=1)
        self.go = threading.Semaphore(0)
        self.abort = threading.Event()
        self.last_progress = time.monotonic()
        self.thread = threading.Thread(target=self._run, name="tacoguard-7z", daemon=True)

    def _plan(self) -> dict:
        """Gives every member a safe internal key (py7zr refuses odd names such as '..\\x')
        and checks each solid block's declared ratio before anything is unpacked."""
        members, blocks = {}, {}
        for idx, info in enumerate(self.archive.files.files_list):
            name = clean_name(info.get("filename", ""))
            key = f"m{idx}"
            info["filename"] = key
            folder = info.get("folder")
            if folder is not None and id(folder) not in blocks:
                packed = sum(info.get("packsizes") or [0])
                blocks[id(folder)] = [_Ratio(packed, self.ctx.limits.archive_max_ratio), 0]
            block = blocks.get(id(folder))
            if block is not None:
                block[1] += int(info.get("uncompressed") or 0)
            members[key] = (name, int(info.get("uncompressed") or 0), block[0] if block else None)
        for ratio, declared in blocks.values():
            if declared > RATIO_FLOOR and declared > ratio.limit * ratio.packed:
                raise _Stop("limit", MSG_BOMB)
        return members

    # -- helper thread side
    def _run(self) -> None:
        try:
            self.archive.extractall(factory=self)
            self._post(("done", None))
        except _Aborted:
            pass
        except BaseException as exc:  # handed to the caller's thread, which turns it into a note
            try:
                self._post(("error", exc))
            except _Aborted:
                pass

    def create(self, filename: str):  # py7zr WriterFactory
        if self.abort.is_set():
            raise _Aborted
        key = filename.replace("\\", "/").rsplit("/", 1)[-1]
        name, declared, ratio = self.members.get(key, (clean_name(filename), 0, None))
        self.ctx.count_entry()
        keep = not self.ctx.too_big(declared, ratio.packed if ratio else declared, skip_is_free=False)
        ratio = ratio or _Ratio(declared, self.ctx.limits.archive_max_ratio)
        return _SevenZipWriter(self, name, _Collector(self.ctx, ratio, keep))

    def _post(self, message) -> None:
        """Hands one message to the caller, then waits until the caller wants the next one."""
        while True:
            if self.abort.is_set():
                raise _Aborted
            try:
                self.out.put(message, timeout=0.25)
                break
            except queue.Full:
                continue
        while not self.go.acquire(timeout=0.25):
            if self.abort.is_set():
                raise _Aborted
        if self.abort.is_set():
            raise _Aborted

    # -- caller side
    def entries(self):
        self.thread.start()
        while True:
            kind, value = self._next()
            if kind == "done":
                return
            if kind == "error":
                raise value
            yield value
            self.go.release()

    def _next(self):
        while True:
            try:
                return self.out.get(timeout=0.5)
            except queue.Empty:
                if not self.thread.is_alive():
                    raise _Stop("damaged", MSG_DAMAGED)
                if time.monotonic() - self.last_progress > SEVENZIP_IDLE_TIMEOUT_S:
                    raise _Stop("limit", MSG_SLOW)

    def stop(self) -> None:
        self.abort.set()
        self.go.release()
        self.thread.join(timeout=10)


try:
    from py7zr.io import Py7zIO as _Py7zIO
except ImportError:  # pragma: no cover - py7zr is a project dependency
    _Py7zIO = object


class _SevenZipWriter(_Py7zIO):
    def __init__(self, pump: _SevenZipPump, name: str, collector: _Collector):
        self.pump = pump
        self.name = name
        self.collector = collector

    def write(self, s) -> int:
        if self.pump.abort.is_set():
            raise _Aborted
        self.pump.last_progress = time.monotonic()
        self.collector.feed(s)
        return len(s)

    def close(self) -> None:  # py7zr calls this once a member is complete
        if self.collector.keep:
            self.pump._post(("item", (self.name, self.collector.data())))
        else:
            self.pump._post(("item", self.pump.ctx.big_note(self.name)))

    def read(self, size=None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        pass

    def size(self) -> int:
        return self.collector.size

    def seekable(self) -> bool:
        return False


# ---- rar --------------------------------------------------------------------------------------

def _rar_entries(src, ctx: _Context):
    import rarfile

    if not os.path.exists(BSDTAR):
        yield ArchiveNote("unsupported", MSG_NO_TAR)
        return
    with _RarSource(src, ctx) as path:
        if path is None:
            yield ArchiveNote("unsupported", MSG_RAR_NO_TMP)
            return
        # reads headers only; never asks rarfile to unpack. The callback stops the listing once
        # it passes the entries limit, before rarfile has built a huge list.
        rf = rarfile.RarFile(path, info_callback=_RarHeaderCounter(ctx.limits.archive_max_entries))
        infos = [i for i in rf.infolist() if not i.is_dir()]
        ctx.check_count(len(infos))
        locked = [i for i in infos if i.needs_password()]
        if rf.needs_password() and (not infos or len(locked) == len(infos)):
            yield ArchiveNote("encrypted", MSG_ENCRYPTED)
            return
        if not all(_ansi_ok(i.filename) for i in rf.infolist()):
            yield ArchiveNote("unsupported", MSG_RAR_NAMES)
            return
        if locked:
            yield ArchiveNote("encrypted", MSG_SOME_ENCRYPTED)
        by_name = {clean_name(i.filename).casefold(): i for i in infos}
        yield from _bsdtar_members(path, by_name, bool(locked), ctx)


class _RarHeaderCounter:
    """rarfile calls this for every header it reads. File headers past the entries limit, or
    far too many headers of any kind (service records), stop the listing."""

    def __init__(self, max_entries: int):
        self.max_entries = int(max_entries)
        self.max_headers = 4 * self.max_entries + 64
        self.files = 0
        self.headers = 0

    def __call__(self, h) -> None:
        import rarfile

        self.headers += 1
        if isinstance(h, rarfile.Rar5FileInfo) or (
                isinstance(h, rarfile.Rar3Info) and getattr(h, "type", None) == rarfile.RAR_BLOCK_FILE):
            self.files += 1
        if self.files > self.max_entries or self.headers > self.max_headers:
            raise _StopAll("limit", MSG_ENTRIES.format(n=self.max_entries))


class _RarSource:
    """A path tar.exe can open. tar.exe reads its arguments in the ANSI code page and can't read
    a RAR from a pipe, so in-memory RARs and non-ASCII names go through a copy in tmp_dir."""

    def __init__(self, src, ctx: _Context):
        self.src = src
        self.ctx = ctx
        self.tmp = None

    def __enter__(self) -> str | None:
        if not isinstance(self.src, (bytes, bytearray, memoryview)):
            path = str(self.src)
            if path.isascii():
                return path
            short = _short_path(path)
            if short and short.isascii():
                return short
        if not self.ctx.tmp_dir:
            return None
        os.makedirs(self.ctx.tmp_dir, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="rar-", dir=self.ctx.tmp_dir)
        target = os.path.join(self.tmp, "archive.rar")
        if isinstance(self.src, (bytes, bytearray, memoryview)):
            with open(target, "wb") as fh:
                fh.write(self.src)
        else:
            shutil.copyfile(self.src, target)
        return target

    def __exit__(self, *exc) -> None:
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


def _ansi_ok(name: str) -> bool:
    """tar.exe (libarchive 3.8.9) crashes on RAR member names outside the PC's ANSI code page
    (for example emoji or Chinese on an English Windows), so those archives are not handed to it."""
    try:
        name.encode("mbcs", "strict")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _short_path(path: str) -> str | None:
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = ctypes.windll.kernel32.GetShortPathNameW(path, buf, len(buf))
        return buf.value if 0 < n < len(buf) else None
    except (AttributeError, OSError):
        return None


def _bsdtar_members(path: str, by_name: dict, some_locked: bool, ctx: _Context):
    """tar.exe re-packs the RAR as a plain tar stream on its stdout; we read it member by member."""
    cmd = [BSDTAR, "-c", "-f", "-", "--format", "pax", "@" + path]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW, bufsize=0)
    job = winjob.kill_on_close_job(int(proc._handle))   # tar.exe ends if this process dies
    pipe = _WatchedPipe(proc, ctx.limits.archive_max_total + STREAM_OVERHEAD)
    errors = _drain_stderr(proc)
    try:
        with tarfile.open(fileobj=pipe, mode="r|") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                ctx.count_entry()
                name = clean_name(m.name)
                info = by_name.get(name.casefold())
                declared = max(int(info.file_size) if info else 0, m.size)
                packed = int(info.compress_size) if info else m.size
                if ctx.too_big(declared, packed, skip_is_free=False):
                    ctx.add_bytes(m.size)  # tar.exe unpacks it anyway; it counts toward the total
                    yield ctx.big_note(name)
                    continue
                collector = _Collector(ctx, _Ratio(packed, ctx.limits.archive_max_ratio))
                yield name, _read_capped(tf.extractfile(m), collector)
        while pipe.read(READ_CHUNK):  # tar.exe pads its output; let it finish writing
            pass
        if pipe.timed_out:
            raise _Stop("limit", MSG_SLOW)
        if proc.wait(timeout=30) != 0 and not some_locked:
            yield ArchiveNote("damaged", MSG_DAMAGED)
    except tarfile.TarError:
        if pipe.timed_out:
            raise _Stop("limit", MSG_SLOW) from None
        if not some_locked:
            raise _Stop("damaged", MSG_DAMAGED) from None
    finally:
        _end_process(proc)
        winjob.close_job(job)
        pipe.close()
        errors.join(timeout=5)


class _WatchedPipe(io.RawIOBase):
    """tar.exe's stdout with a byte cap, and a watchdog that kills tar.exe when a read waits
    too long. The clock only runs while we wait for tar.exe, not while the caller scans."""

    def __init__(self, proc, max_bytes: int):
        self.proc = proc
        self.max_bytes = max_bytes
        self.read_total = 0
        self.timed_out = False
        self.waiting_since: float | None = None
        self._done = threading.Event()
        threading.Thread(target=self._watch, name="tacoguard-tar-watch", daemon=True).start()

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        self.waiting_since = time.monotonic()
        try:
            data = self.proc.stdout.read(len(b))
        finally:
            self.waiting_since = None
        n = len(data or b"")
        self.read_total += n
        if self.read_total > self.max_bytes:
            raise _StopAll("limit", MSG_BOMB)
        b[:n] = data or b""
        return n

    def _watch(self) -> None:
        while not self._done.wait(0.5):
            if self.proc.poll() is not None and self.waiting_since is None:
                return
            since = self.waiting_since
            if since is not None and time.monotonic() - since > TOOL_IDLE_TIMEOUT_S:
                self.timed_out = True
                _kill(self.proc)
                return

    def close(self) -> None:
        self._done.set()
        super().close()


def _drain_stderr(proc) -> threading.Thread:
    """Reads tar.exe's error output so it can never block on a full pipe; keeps nothing."""
    def drain():
        try:
            while proc.stderr.read(4096):
                pass
        except (OSError, ValueError):
            pass
    t = threading.Thread(target=drain, name="tacoguard-tar-stderr", daemon=True)
    t.start()
    return t


def _kill(proc) -> None:
    try:
        proc.kill()
    except OSError:
        pass


def _end_process(proc) -> None:
    if proc.poll() is None:
        _kill(proc)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    for f in (proc.stdout, proc.stderr):
        try:
            f.close()
        except OSError:
            pass


_OPENERS = {"zip": _zip_entries, "7z": _7z_entries, "rar": _rar_entries}
