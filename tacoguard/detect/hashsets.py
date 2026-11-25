"""Known-bad hash lists: every *.txt in the hashsets folder.

One lower-case SHA-256 per line, optionally followed by whitespace and a name; '#' starts a comment.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..model import Confidence, Finding, ScanItem, plain_error
from .base import DetectorError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _list_files(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted((p for p in folder.glob("*.txt") if p.is_file()), key=lambda p: p.name.lower())


def parse_hash_file(path: Path) -> dict[str, str]:
    """{sha256: name or ""} from one list; lines that are not a SHA-256 are ignored."""
    found: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            first, *rest = line.split(None, 1)
            first = first.lower()
            if _SHA256.match(first):
                # sha256sum writes " *name" for binary mode
                found[first] = rest[0].strip().lstrip("*") if rest else ""
    return found


def sha256_of(item: ScanItem) -> str:
    known = getattr(item, "sha256", "")
    if known:
        return known.lower()
    if item.data is not None:
        return hashlib.sha256(item.data).hexdigest()
    h = hashlib.sha256()
    try:
        with open(item.path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError as e:
        raise DetectorError(f"Could not read this file to work out its fingerprint ({e.strerror or e}).") from e
    return h.hexdigest()


class HashDetector:
    name = "hash"
    scans_members = True

    def __init__(self, settings):
        self.folder = Path(settings.hashset_dir)
        self._hashes: dict[str, tuple[str, str]] = {}    # sha256 -> (list file name, entry name)
        self._count_cache: tuple[str, int] = ("", 0)

    def version(self) -> str:
        files = _list_files(self.folder)
        if not files:
            return "hash-none"
        stamp = "|".join(f"{p.name}:{p.stat().st_mtime_ns}:{p.stat().st_size}" for p in files)
        return "hash-" + hashlib.sha256(stamp.encode()).hexdigest()[:12]

    def status(self) -> dict:
        try:
            files = _list_files(self.folder)
            version = self.version()
            if self._count_cache[0] != version:
                self._count_cache = (version, sum(len(parse_hash_file(p)) for p in files))
            count = self._count_cache[1]
            updated = max((p.stat().st_mtime for p in files), default=0.0)
            if files:
                msg = f"Your known-bad list: {count} fingerprints in {len(files)} file(s)."
            else:
                msg = "No known-bad lists added (optional)."
            return {"ready": True, "message": msg, "version": version, "updated": updated, "count": count}
        except Exception as e:  # status must never raise
            return {"ready": False, "message": f"Could not read your known-bad lists: {plain_error(e)}",
                    "version": "hash-none", "updated": 0.0, "count": 0}

    def open(self) -> None:
        self._hashes = {}
        for p in _list_files(self.folder):
            try:
                entries = parse_hash_file(p)
            except OSError:
                continue          # an unreadable list is skipped; status() reports the readable ones
            for sha, label in entries.items():
                self._hashes.setdefault(sha, (p.name, label))

    def has_signatures(self) -> bool:
        """After open(): False when no list holds a single fingerprint (then this check can
        never find anything, and a scan with only this check would check nothing)."""
        return bool(self._hashes)

    def scan(self, item: ScanItem) -> list[Finding]:
        if not self._hashes:
            return []
        sha = sha256_of(item)
        hit = self._hashes.get(sha)
        if not hit:
            return []
        list_name, label = hit
        return [Finding("hash", label or f"SHA-256 {sha}", Confidence.HIGH,
                        f"your known-bad list ({list_name})", member=item.member)]

    def close(self) -> None:
        self._hashes = {}
