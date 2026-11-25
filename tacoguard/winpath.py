"""Windows path helpers: long paths (over 260 characters), display form, comparison keys.

Rule for every module: touch the disk with `to_long(path)`, show people `to_display(path)`,
compare paths with `norm_key(path)`.
"""
from __future__ import annotations

import os
import stat as _stat

_EXT = "\\\\?\\"
_EXT_UNC = "\\\\?\\UNC\\"

# Windows file attribute bits we care about
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000


def to_long(path: str | os.PathLike) -> str:
    """Absolute extended-length form (\\\\?\\C:\\...), safe for paths longer than 260 characters."""
    p = os.fspath(path)
    if p.startswith(_EXT):
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\"):           # \\server\share\...
        return _EXT_UNC + p[2:]
    return _EXT + p


def to_display(path: str | os.PathLike) -> str:
    """The normal form people know (no \\\\?\\ prefix)."""
    p = os.fspath(path)
    if p.startswith(_EXT_UNC):
        return "\\\\" + p[len(_EXT_UNC):]
    if p.startswith(_EXT):
        return p[len(_EXT):]
    return p


def norm_key(path: str | os.PathLike) -> str:
    """Case-insensitive comparison key for a path (no prefix, backslashes, no trailing slash)."""
    p = to_display(os.path.abspath(to_display(path)))
    p = p.replace("/", "\\")
    if len(p) > 3:
        p = p.rstrip("\\")
    return p.casefold()


def is_under(path: str, folder: str) -> bool:
    """True when `path` is `folder` itself or anything inside it."""
    p, f = norm_key(path), norm_key(folder)
    if p == f:
        return True
    if not f.endswith("\\"):
        f += "\\"
    return p.startswith(f)


def short_display(path: str, home: str | None = None) -> str:
    """Shorter form for messages: 'Downloads\\x.exe' instead of 'C:\\Users\\me\\Downloads\\x.exe'."""
    d = to_display(path)
    home = home or os.path.expanduser("~")
    if is_under(d, home) and norm_key(d) != norm_key(home):
        return d[len(home):].lstrip("\\")
    return d


def is_cloud_placeholder(st: os.stat_result) -> bool:
    """OneDrive/Dropbox 'online-only' file: reading it would download it. We skip those."""
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN
                         | FILE_ATTRIBUTE_OFFLINE))


def is_reparse(st: os.stat_result) -> bool:
    """Symlink, junction or other reparse point (use with os.lstat)."""
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT) or _stat.S_ISLNK(st.st_mode)
