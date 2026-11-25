"""What every detector looks like (contract shared by the scan engine and the detectors)."""
from __future__ import annotations

from typing import Protocol

from ..model import Finding, ScanItem


class DetectorError(Exception):
    """A detector could not check this one item. The message is plain English and is shown
    to the user as a note on that file, e.g. "ClamAV could not read this file"."""


class DetectorNote(DetectorError):
    """Not a failure: this detector chose not to judge this item (e.g. the machine-learning check
    skips a program with too many text strings to score quickly). The message is shown as a
    note on the file, but the file does NOT count as incompletely checked."""


class DetectorUnavailable(Exception):
    """The detector cannot work at all right now (no signatures yet, program missing).
    The message is plain English, e.g. "ClamAV signatures have not been downloaded yet"."""


class Detector(Protocol):
    name: str              # "hash" | "yara" | "clamav"
    scans_members: bool    # True: also gets files unpacked from archives (in memory).
                           # ClamAV is False: it unpacks archives itself, so it gets only the outer file.

    def status(self) -> dict:
        """{"ready": bool, "message": plain English, "version": str, "updated": float epoch or 0,
        "count": number of signatures/rules or 0}. Must be cheap and never raise."""
        ...

    def version(self) -> str:
        """Short string that changes whenever the signatures change (used by the clean cache)."""
        ...

    def open(self) -> None:
        """Get ready to scan (load rules, start helper program). Raises DetectorUnavailable."""
        ...

    def scan(self, item: ScanItem) -> list[Finding]:
        """Check one item. item.data is set for in-memory items, item.path (extended-length)
        for files on disk; either may be set. Raises DetectorError for this item only."""
        ...

    def close(self) -> None:
        """Release everything (stop helper programs). Safe to call twice."""
        ...

    # Optional: parallel = True means scan() is safe to call from several threads at once and
    # mostly waits on another program (ClamAV). The scan engine then runs it for several outer
    # files at the same time (settings.clamav_threads); results are still reported in walk order.
    # Detectors without the attribute run one file at a time in the scan's own thread.
    #
    # Optional: has_signatures() -> bool, asked after open(). A detector that answers False
    # can never find anything (the hash detector with empty lists); a scan where every opened
    # detector answers False fails with "no signatures are installed yet" instead of "Done".
    # Detectors without the method count as having signatures.
