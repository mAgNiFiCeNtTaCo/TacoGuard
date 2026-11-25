"""Walks files, folders and whole drives in a fixed order, so a stopped scan can resume.

Order: depth-first, children sorted by case-folded name. Every yielded thing carries `key`, a tuple
of case-folded path parts; walk order is exactly ascending `key` order, which is what makes resume
cheap: anything with key <= the checkpoint's key was already done.

Links (symlinks, junctions) inside a walk are not followed. A target that is itself a link is
resolved once.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator

from .. import winpath

LINK_NOTE = "Link to another place, not followed."
DENIED_NOTE = "Could not open this folder (no permission)."
CLOUD_NOTE = "Online-only cloud file (OneDrive or similar). Checking it would download it, so it was skipped."
MISSING_NOTE = "Not found. It may have been moved or deleted."


@dataclass
class FileEntry:
    path: str               # extended-length path, for disk access
    display: str            # what people see
    st: os.stat_result
    key: tuple


@dataclass
class WalkNote:
    display: str
    message: str            # plain English
    kind: str               # "link" | "denied" | "cloud" | "too_big" | "missing" | "error"
    key: tuple
    size: int = 0


def order_key(path: str) -> tuple:
    """Walk-order key of a path (works for files and folders, display or long form)."""
    return tuple(p for p in winpath.norm_key(path).split("\\") if p)


def fmt_size(n: int) -> str:
    for unit, size in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if n >= size:
            return f"{n / size:.1f}".rstrip("0").rstrip(".") + " " + unit
    return f"{n} bytes"


def too_big_note(size: int, limit: int) -> str:
    return f"Bigger than the {fmt_size(limit)} limit ({fmt_size(size)}), so it was skipped."


def normalize_target(target: str) -> str:
    """Display form of a target: absolute, 'D:' becomes 'D:\\', a link target resolved once."""
    t = winpath.to_display(str(target).strip().strip('"'))
    if len(t) == 2 and t[1] == ":":
        t += "\\"
    t = winpath.to_display(os.path.abspath(t))
    long = winpath.to_long(t)
    try:
        if os.path.islink(long) or os.path.isjunction(long):
            t = winpath.to_display(os.path.realpath(long))
    except OSError:
        pass
    return t


def prepare_targets(targets: list[str]) -> list[str]:
    """Normalized targets in walk order, without duplicates or targets inside other targets."""
    out: list[tuple[tuple, str]] = []
    for disp in sorted((normalize_target(t) for t in targets), key=order_key):
        k = order_key(disp)
        if any(k[:len(pk)] == pk for pk, _ in out):
            continue
        out.append((k, disp))
    return [d for _, d in out]


def walk(targets: list[str], checkpoint: str = "", max_file_size: int = 0) -> Iterator[FileEntry | WalkNote]:
    """Yields FileEntry for every file to check and WalkNote for anything not checked.
    `checkpoint` (a display path): skip everything up to and including it in walk order.
    `max_file_size` > 0: bigger files become a 'too_big' note."""
    stop = order_key(checkpoint) if checkpoint else None
    visited: set[tuple[int, int]] = set()
    for disp in prepare_targets(targets):
        yield from _walk_target(disp, stop, max_file_size, visited)


def _done(key: tuple, stop: tuple | None) -> bool:
    return stop is not None and key <= stop


def _walk_target(disp, stop, max_size, visited):
    long, key = winpath.to_long(disp), order_key(disp)
    try:
        st = os.stat(long)
    except FileNotFoundError:
        if not _done(key, stop):
            yield WalkNote(disp, MISSING_NOTE, "missing", key)
        return
    except OSError as e:
        if not _done(key, stop):
            yield WalkNote(disp, f"Could not open it ({e.strerror or e}).", "error", key)
        return
    if os.path.isdir(long):
        yield from _walk_dir(disp, long, key, stop, max_size, visited)
    elif not _done(key, stop):
        yield from _file(disp, long, st, key, max_size)


def _walk_dir(disp, long, key, stop, max_size, visited):
    if stop is not None and key < stop and stop[:len(key)] != key:
        return  # the whole folder comes before the checkpoint
    try:
        st = os.stat(long)
        ident = (st.st_dev, st.st_ino)
        if ident in visited:
            return
        visited.add(ident)
        with os.scandir(long) as it:
            entries = sorted(it, key=lambda e: (e.name.casefold(), e.name))
    except PermissionError:
        if not _done(key, stop):
            yield WalkNote(disp, DENIED_NOTE, "denied", key)
        return
    except FileNotFoundError:
        return  # removed while we were walking
    except OSError as e:
        if not _done(key, stop):
            yield WalkNote(disp, f"Could not open this folder ({e.strerror or e}).", "error", key)
        return
    for e in entries:
        ckey = key + (e.name.casefold(),)
        cdisp, clong = os.path.join(disp, e.name), os.path.join(long, e.name)
        try:
            if e.is_symlink() or e.is_junction():
                if not _done(ckey, stop):
                    yield WalkNote(cdisp, LINK_NOTE, "link", ckey)
                continue
            if e.is_dir(follow_symlinks=False):
                yield from _walk_dir(cdisp, clong, ckey, stop, max_size, visited)
                continue
            if _done(ckey, stop):
                continue
            cst = e.stat(follow_symlinks=False)
        except OSError:
            continue  # vanished mid-walk
        yield from _file(cdisp, clong, cst, ckey, max_size)


def _file(disp, long, st, key, max_size):
    if winpath.is_cloud_placeholder(st):
        yield WalkNote(disp, CLOUD_NOTE, "cloud", key, st.st_size)
    elif max_size and st.st_size > max_size:
        yield WalkNote(disp, too_big_note(st.st_size, max_size), "too_big", key, st.st_size)
    else:
        yield FileEntry(long, disp, st, key)
