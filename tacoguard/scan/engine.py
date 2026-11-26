"""Checks files one by one and runs a whole scan job.

check_file() decides one file: trusted folder -> clean cache -> read once (hash + content) ->
trusted hash -> every detector -> files inside archives -> (only if something matched) the
file's digital signature (settings.trust_signed_programs) and (Phase 4) a MalwareBazaar lookup of
its fingerprint (add_lookup). scan_job() walks the targets, keeps the job row up to date (a few
times a second, not per file), obeys pause / cancel and waits between files while Game mode is on.

ClamAV is slow (clamd checks about 2 MB/s of Windows programs per thread), so a scan job sends
several files to it at once: the hash and YARA checks run here one file at a time, the ClamAV
check of each file goes to a thread pool (settings.clamav_threads), and _Window reports the
files strictly in walk order, so results, counts, the clean cache and the checkpoint are the
same as in a one-file-at-a-time scan.
"""
from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes

from .. import archives, learning, signing, winpath
from ..archives import ArchiveNote
from ..config import clamav_thread_count
from ..detect import clamav as clamav_names
from ..detect.base import DetectorError, DetectorNote, DetectorUnavailable
from ..model import (CLEAN, MALWARE, SCANNED, SKIPPED, SUSPICIOUS, TRUSTED, UNREADABLE, Confidence,
                     FileResult, Finding, ScanItem, plain_error, signature_note, signed_strong_detail)
from . import walker

CHUNK = 1024 * 1024
HEAD = 64
FLUSH_EVERY_S = 0.5
WINDOW_MAX_BYTES = 256 * 1024**2   # file contents held in memory while they wait for ClamAV

IN_USE_NOTE = "In use by another program, so it could not be read. Try again after closing it."
NO_PERMISSION_NOTE = "No permission to read this file."
MEMORY_NOTE = ("Checking this file needed more memory than TacoGuard allows, so it could not be "
               "fully checked.")
NO_SIGNATURES_MSG = ("Nothing was checked: no signatures are installed yet. Press Get / refresh "
                     "signatures on the Home page first.")
NO_CHECKS_MSG = "Nothing was checked: none of the checks could start."

DETECTOR_LABELS = {"hash": "Known-bad file list", "yara": "YARA rules", "clamav": "ClamAV",
                   "ml": "The machine-learning check", "lookup": "The MalwareBazaar lookup"}

GAME_MODE_WAIT_MSG = "Waiting: Game mode is on. The scan carries on when it ends."
GAME_MODE_POLL_S = 5.0        # while waiting: how often Game mode is looked at
GAME_MODE_CHECK_S = 1.0       # while scanning: at most this often

COUNT_KEYS = ("files", "bytes", "clean", "suspicious", "malware", "trusted", "skipped",
              "unreadable", "incomplete", "archives_members")


class Throttle:
    """Token bucket for disk reads: at most `mb_s` megabytes per second (0 = no limit)."""

    def __init__(self, mb_s: float):
        self.rate = max(0.0, float(mb_s or 0)) * 1024 * 1024
        self.capacity = self.rate / 4          # allow short bursts of a quarter second
        self.tokens = self.capacity
        self.last = time.monotonic()

    def take(self, n: int) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        self.tokens -= n
        if self.tokens < 0:
            time.sleep(-self.tokens / self.rate)


def _unreadable_note(e: OSError) -> str:
    code = getattr(e, "winerror", None)
    if code in (32, 33):
        return IN_USE_NOTE
    if code == 5 or (code is None and isinstance(e, PermissionError)):
        return NO_PERMISSION_NOTE
    return f"Could not be read ({plain_error(e)})."


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_INVALID_HANDLE = wintypes.HANDLE(-1).value


def open_for_read(path: str):
    """Like open(path, 'rb') but keeps the Windows error code (Python's open() turns 'in use' and
    'no permission' into the same error), and lets other programs read, write and delete meanwhile."""
    h = _k32.CreateFileW(path, 0x80000000, 0x7, None, 3, 0x08000000, None)  # read, share all, sequential
    if h is None or h == _INVALID_HANDLE:
        err = ctypes.get_last_error()
        raise OSError(0, ctypes.FormatError(err).strip(), path, err)
    try:
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
    except OSError:
        _k32.CloseHandle(wintypes.HANDLE(h))
        raise
    return os.fdopen(fd, "rb", buffering=0)


def read_file(path: str, keep_max: int, throttle: Throttle | None) -> tuple[str, bytes | None, bytes]:
    """One pass over the file: (sha256, whole content if it is at most keep_max bytes, first bytes)."""
    with open_for_read(path) as f:
        try:
            return _read_all(f, keep_max, throttle)
        except PermissionError as e:
            # The file opened fine, so a refusal now means another program locked part of it.
            raise OSError(0, "locked by another program", path, 33) from e


def _read_all(f, keep_max: int, throttle: Throttle | None) -> tuple[str, bytes | None, bytes]:
    h = hashlib.sha256()
    kept: list[bytes] | None = [] if keep_max > 0 else None
    total, head = 0, b""
    while chunk := f.read(CHUNK):
        if throttle:
            throttle.take(len(chunk))
        h.update(chunk)
        if not head:
            head = chunk[:HEAD]
        total += len(chunk)
        if kept is not None:
            if total > keep_max:
                kept = None    # grew past the in-memory limit while we read: detectors use the path
            else:
                kept.append(chunk)
    return h.hexdigest(), (b"".join(kept) if kept is not None else None), head


def _archive_kind(head: bytes) -> str | None:
    try:
        return archives.archive_kind(head)
    except NotImplementedError:
        return None


def _run_detectors(detectors, item: ScanItem, r: FileResult) -> None:
    for d in detectors:
        try:
            found = d.scan(item)
        except DetectorNote as e:          # the detector skipped this item on purpose
            r.notes.append(_where(str(e), item))
            continue
        except DetectorError as e:
            r.notes.append(_where(str(e), item))
            r.incomplete = True
            continue
        except MemoryError:
            r.notes.append(_where(MEMORY_NOTE, item))
            r.incomplete = True
            continue
        except Exception as e:  # a detector bug must not stop the scan
            r.notes.append(_where(f"{DETECTOR_LABELS.get(d.name, d.name)} failed on this file "
                                  f"({plain_error(e)}).", item))
            r.incomplete = True
            continue
        for f in found:
            if item.member and not f.member:
                f.member = item.member
            r.findings.append(f)


def _where(note: str, item: ScanItem) -> str:
    return f"{note} (inside the archive at '{item.member}')" if item.member else note


def _scan_members(item: ScanItem, detectors, trust, settings, r: FileResult, stats: dict | None) -> None:
    member_detectors = [d for d in detectors if getattr(d, "scans_members", False)]
    try:
        for m in archives.iter_members(item, settings.limits, tmp_dir=settings.tmp_dir):
            if isinstance(m, ArchiveNote):
                r.notes.append(_where(m.message, m) if m.member else m.message)
                r.incomplete = True
                continue
            if stats is not None:
                stats["archives_members"] = stats.get("archives_members", 0) + 1
            m.sha256 = hashlib.sha256(m.data or b"").hexdigest()   # hash detector reuses it
            if trust.hash_reason(m.sha256):
                continue
            _run_detectors(member_detectors, m, r)
    except NotImplementedError:
        r.notes.append("Looking inside archives is not available yet, so the files inside were not checked.")
        r.incomplete = True
    except MemoryError:
        r.notes.append(archives.MSG_MEMORY)
        r.incomplete = True
    except Exception as e:
        r.notes.append(f"Could not look inside this archive ({plain_error(e)}).")
        r.incomplete = True


def drop_lone_weak_ml(findings: list[Finding]) -> list[Finding]:
    """A LOW machine-learning finding counts only as supporting detail: when it is the only
    finding on its item (the file itself, or one file inside an archive) it is dropped silently.
    The low cut-off is a 1% false-alarm rate, too noisy on its own. MEDIUM ML alone still counts."""
    items_with_other = {f.member for f in findings
                        if not (f.engine == "ml" and f.confidence <= Confidence.LOW)}
    return [f for f in findings
            if not (f.engine == "ml" and f.confidence <= Confidence.LOW and f.member not in items_with_other)]


def _signature_can_soften(f: Finding) -> bool:
    """Matches a valid digital signature may soften: those about the file on disk itself (never a
    file inside an archive), not an exact known-bad hash, not a ClamAV 'revoked certificate' or
    test-file name."""
    if f.member or f.engine in ("hash", "lookup"):
        return False
    return f.engine != "clamav" or clamav_names.signature_trust_applies(f.rule)


def _signature_trust(r: FileResult, item: ScanItem, settings) -> bool:
    """settings.trust_signed_programs: when the file on disk has a valid digital signature, its
    weak (medium or low) matches are dropped into one note and strong ones are lowered to medium.
    While a strong match is there the weak ones stay, so a second engine agreeing still makes it
    malware (model.verdict_level). Runs after every detector, only for files with findings.
    Returns True when it changed the result."""
    if not getattr(settings, "trust_signed_programs", True) or not item.path or item.member:
        return False
    targets = [f for f in r.findings if _signature_can_soften(f)]
    if not targets:
        return False
    info = signing.check_signature(item.path)
    if not info.valid:
        return False
    signer = info.signer or "a publisher Windows trusts"
    strong = [f for f in targets if f.confidence > Confidence.MEDIUM]
    if strong:
        for f in strong:
            f.confidence = Confidence.MEDIUM
            extra = signed_strong_detail(signer)
            f.detail = f"{f.detail}; {extra}" if f.detail else extra
        return True
    r.findings = [f for f in r.findings if not any(f is t for t in targets)]
    r.notes.append(signature_note(targets, signer))
    return True


def _validly_signed(item: ScanItem | None) -> bool:
    if item is None or not item.path or item.member:
        return False
    try:
        return bool(signing.check_signature(item.path).valid)
    except Exception:
        return False


def add_lookup(r: FileResult, settings, store, item: ScanItem | None = None) -> bool:
    """Phase 4 (tacoguard/lookup.py): when the file on disk was flagged (suspicious or malware),
    settings.lookup_enabled and your abuse.ch key is saved, its SHA-256 is looked up on
    MalwareBazaar (cached, at most 30 an hour). Known there with a malware name and the file has
    no valid digital signature -> a HIGH "lookup" finding (the file becomes "malware"); known
    otherwise -> a MEDIUM one ("has a copy ... not proof on its own"); not known -> a note.
    Offline / no answer -> nothing changes. Never for clean files, and only the outer file's
    fingerprint (never a file inside an archive). Returns True when it changed the result."""
    if r.status != SCANNED or not r.findings or not r.sha256:
        return False
    if any(f.engine == "lookup" for f in r.findings):
        return False
    from .. import lookup
    try:
        if not lookup.ready(settings):
            return False
        info = lookup.lookup(settings, store, r.sha256)
    except Exception:              # lookup() never raises; belt and braces for the scan
        return False
    if info is None:
        return False
    signed = None                       # not checked: finding_for then says MEDIUM
    if info.get("found") and info.get("signature") and item is not None:
        signed = _validly_signed(item)
    f = lookup.finding_for(info, signed=signed)
    if f is not None:
        r.findings.append(f)
    elif lookup.NOT_FOUND_NOTE not in r.notes:
        r.notes.append(lookup.NOT_FOUND_NOTE)
    return True


class Pending:
    """One file's result, maybe still waiting for checks that run in the thread pool.
    result() waits for them, merges what they found and writes the clean cache, so call it from
    the scan's own thread, once."""

    def __init__(self, result: FileResult | None, future=None, finish=None, held_bytes: int = 0):
        self._result, self.future, self._finish = result, future, finish
        self.held_bytes = held_bytes        # file content kept in memory until result()

    def done(self) -> bool:
        return self.future is None or self.future.done()

    def cancel(self) -> None:
        """Drop the pool work if it has not started yet (the file then counts as not checked)."""
        if self.future is not None:
            self.future.cancel()

    def cancelled(self) -> bool:
        return self.future is not None and self.future.cancelled()

    def result(self) -> FileResult | None:
        if self.future is not None:
            self.future.result()
        if self._finish is not None:
            self._finish()
            self._finish = None
        return self._result


def check_file(entry, detectors, trust, settings, store, sig_version, *,
               throttle: Throttle | None = None, stats: dict | None = None, pool=None):
    """Check one walker.FileEntry. Returns None when the file vanished before it could be read.
    `stats` (optional) gets 'archives_members' bumped.

    With `pool` (a ThreadPoolExecutor), detectors marked `parallel` (ClamAV) run in the pool and
    a Pending is returned at once instead of the FileResult; everything else runs here first."""
    pending = _start_file(entry, detectors, trust, settings, store, sig_version, throttle, stats, pool)
    return pending if pool is not None else pending.result()


def _start_file(entry, detectors, trust, settings, store, sig_version, throttle, stats, pool) -> Pending:
    st = entry.st
    r = FileResult(path=entry.display, size=st.st_size)
    reason = trust.folder_reason(entry.display)
    if reason:
        r.status, r.notes = TRUSTED, [reason]
        return Pending(r)

    cache_key = winpath.norm_key(entry.display)
    cached = store.cache_get(cache_key, st.st_size, st.st_mtime_ns, sig_version)
    if cached:
        r.sha256 = cached
        reason = trust.hash_reason(cached)
        if reason:
            r.status, r.notes = TRUSTED, [reason]
        return Pending(r)

    limits = settings.limits
    keep = limits.in_memory_max if st.st_size <= limits.in_memory_max else 0
    try:
        r.sha256, data, head = read_file(entry.path, keep, throttle)
    except FileNotFoundError:
        return Pending(None)
    except OSError as e:
        r.status, r.notes = UNREADABLE, [_unreadable_note(e)]
        return Pending(r)

    reason = trust.hash_reason(r.sha256)
    if reason:
        r.status, r.notes = TRUSTED, [reason]
        return Pending(r)

    item = ScanItem(display=entry.display, path=entry.path, data=data, size=st.st_size)
    later = [d for d in detectors if pool is not None and getattr(d, "parallel", False)]
    _run_detectors([d for d in detectors if d not in later], item, r)
    # The pool's findings and notes go here, so the result reads as if the detectors had run in
    # list order (ClamAV is last), before the files inside an archive.
    at_finding, at_note = len(r.findings), len(r.notes)
    if _archive_kind(head):
        _scan_members(item, detectors, trust, settings, r, stats)
    part = FileResult(path=r.path)

    def finish() -> None:
        r.findings[at_finding:at_finding] = part.findings
        r.notes[at_note:at_note] = part.notes
        r.incomplete = r.incomplete or part.incomplete
        learned = False
        if r.findings:   # your own verdicts (learning.py), before the signed-program rule
            before = list(r.findings)
            r.findings, learned_notes = learning.adjust(r.findings, store, settings)
            r.notes.extend(learned_notes)
            # adjust() returns new Finding objects only for the ones it lowered
            learned = bool(learned_notes) or any(a is not b for a, b in zip(before, r.findings))
            r.findings = drop_lone_weak_ml(r.findings)
        # a file cleared by its signature is not cached: turning the setting off re-checks it.
        # Neither is a file your earlier choices changed: "Forget", "It's a threat" or turning
        # learning off must check it again.
        softened = _signature_trust(r, item, settings)
        # Phase 4: a flagged file's own fingerprint asked on MalwareBazaar, last, so neither your
        # earlier choices nor a digital signature can soften an exact known-malware match.
        add_lookup(r, settings, store, item)
        if not r.findings and not r.incomplete and not softened and not learned:
            store.cache_put(cache_key, st.st_size, st.st_mtime_ns, r.sha256, sig_version)

    if not later:
        return Pending(r, finish=finish)
    future = pool.submit(_run_detectors, later, item, part)
    return Pending(r, future, finish, held_bytes=len(data) if data is not None else 0)


# ---- whole job -------------------------------------------------------------------------------

def note_result(note: walker.WalkNote) -> FileResult:
    status = UNREADABLE if note.kind in ("denied", "error") else SKIPPED
    return FileResult(path=note.display, status=status, size=note.size, notes=[note.message])


def is_notable(r: FileResult) -> bool:
    return not (r.status == SCANNED and r.level == CLEAN and not r.incomplete)


def tally(counts: dict, r: FileResult, is_file: bool) -> None:
    """`is_file`: r is about a file the walk handed over (not a walk note such as a link)."""
    if is_file:
        counts["files"] += 1
        counts["bytes"] += r.size
    if r.status == SCANNED:
        counts[{CLEAN: "clean", SUSPICIOUS: "suspicious", MALWARE: "malware"}[r.level]] += 1
        if r.incomplete:
            counts["incomplete"] += 1
    else:
        counts[r.status] += 1          # trusted | skipped | unreadable


def fmt_duration(seconds: float) -> str:
    s = int(round(seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{round(s / 60)} min"
    return f"{s // 3600} h {(s % 3600) // 60} min"


def summary(counts: dict) -> str:
    text = (f"{counts['files']:,} files checked in {fmt_duration(counts.get('seconds', 0))}. "
            f"{counts['suspicious']:,} suspicious, {counts['malware']:,} malware, "
            f"{counts['unreadable']:,} could not be read")
    if counts["skipped"]:
        text += f", {counts['skipped']:,} skipped"
    return text + "."


def open_detectors(detectors) -> tuple[list, list[str]]:
    """Opens each detector. Returns (the ones that work, plain notes about the ones that don't)."""
    opened, notes, _ = _open_all(detectors)
    return opened, notes


def _open_all(detectors) -> tuple[list, list[str], bool]:
    """Like open_detectors, plus whether one failed for a reason other than 'not installed'."""
    opened, notes, broken = [], [], False
    for d in detectors:
        label = DETECTOR_LABELS.get(d.name, d.name)
        try:
            d.open()
            opened.append(d)
        except DetectorUnavailable as e:
            notes.append(f"{label} not used: {str(e).rstrip('.')}.")
        except Exception as e:
            broken = True
            notes.append(f"{label} not used: it could not start ({plain_error(e)}).")
    return opened, notes, broken


def has_signatures(detector) -> bool:
    """False only for a detector that says it can find nothing (the hash check with empty lists)."""
    check = getattr(detector, "has_signatures", None)
    if check is None:
        return True
    try:
        return bool(check())
    except Exception:
        return True


def close_detectors(detectors) -> None:
    for d in detectors:
        try:
            d.close()
        except Exception:
            pass


class _Progress:
    """Writes current/message/counts/checkpoint/heartbeat to the job row at most twice a second."""

    def __init__(self, store, job_id, counts, extra_note):
        self.store, self.job_id, self.counts, self.extra = store, job_id, counts, extra_note
        self.checkpoint = ""
        self.current = ""
        self.last = 0.0
        self.t0 = time.monotonic()
        self.base_seconds = counts.get("seconds", 0)

    def elapsed(self) -> float:
        return self.base_seconds + (time.monotonic() - self.t0)

    def maybe_flush(self) -> None:
        if time.monotonic() - self.last >= FLUSH_EVERY_S:
            self.flush()

    def flush(self, **fields) -> None:
        self.last = time.monotonic()
        self.counts["seconds"] = round(self.elapsed(), 1)
        message = fields.pop("message", None) or (
            f"Checking files: {self.counts['files']:,} so far." + (" " + self.extra if self.extra else ""))
        self.store.update_job(self.job_id, current=self.current, message=message, counts=self.counts,
                              checkpoint=self.checkpoint, heartbeat=time.time(), **fields)


def scan_job(settings, store, job_id: int, detectors) -> None:
    """Runs (or resumes) one job in this process. Always closes the detectors."""
    job = store.get_job(job_id)
    if job is None:
        raise ValueError(f"Scan {job_id} does not exist.")
    counts = {k: 0 for k in COUNT_KEYS}
    counts.update(job.get("counts") or {})
    now = time.time()
    store.update_job(job_id, status="running", pid=os.getpid(), heartbeat=now,
                     started=job["started"] or now, message="Getting the checks ready...")
    try:
        opened, notes, broken = _open_all(detectors)
        extra = " ".join(notes)
        if not any(has_signatures(d) for d in opened):
            # Only the (empty) known-bad list, or nothing at all, is ready: a "Done" here would
            # claim files were checked, and would fill the clean cache with unchecked files.
            message = (NO_CHECKS_MSG + " " + extra) if broken else NO_SIGNATURES_MSG
            store.update_job(job_id, status="failed", finished=time.time(), current="",
                             message=message.strip())
            return
        sig_version = "|".join(d.version() for d in opened)
        store.update_job(job_id, sig_version=sig_version)
        progress = _Progress(store, job_id, counts, extra)
        progress.checkpoint = job["checkpoint"]
        stopped = _loop(settings, store, job, opened, sig_version, progress)
        _finish(store, job_id, progress, stopped, extra)
    finally:
        close_detectors(detectors)


class _Window:
    """The files handed out but not reported yet, in walk order. A file is reported (counted,
    stored, checkpointed) only when it and every file before it are finished, so the checkpoint
    is always the last fully checked file in walk order and resume works as before.

    At most `max_files` wait at once, holding at most `max_bytes` of file content in memory."""

    def __init__(self, max_files: int, max_bytes: int, report):
        self.items: deque = deque()          # (walk thing, Pending, per-file stats)
        self.max_files, self.max_bytes = max_files, max_bytes
        self.report = report                 # report(thing, FileResult | None, stats)
        self.held_bytes = self.peak_bytes = 0

    def add(self, thing, pending: Pending, stats: dict) -> None:
        self.items.append((thing, pending, stats))
        self.held_bytes += pending.held_bytes
        self.peak_bytes = max(self.peak_bytes, self.held_bytes)
        while self.items and self.items[0][1].done():
            self._report_first()

    def make_room(self, need_bytes: int) -> None:
        """Waits (oldest file first) until one more file holding `need_bytes` fits."""
        while self.items and (len(self.items) >= self.max_files
                              or self.held_bytes + need_bytes > self.max_bytes):
            self._report_first()

    def drain(self) -> None:
        while self.items:
            self._report_first()

    def report_done(self) -> None:
        """Reports the files at the front that are finished, without waiting for any."""
        while self.items and self.items[0][1].done():
            self._report_first()

    def stop(self) -> None:
        """Pause / cancel: drop pool work that has not started, then report files in order up to
        the first dropped one. The files after it are checked again on resume."""
        for _, pending, _ in self.items:
            pending.cancel()
        while self.items and not self.items[0][1].cancelled():
            self._report_first()
        self.items.clear()       # the pool's shutdown waits for any of these still running
        self.held_bytes = 0

    def _report_first(self) -> None:
        thing, pending, stats = self.items.popleft()
        result = pending.result()            # waits for this file's ClamAV check
        self.held_bytes -= pending.held_bytes
        self.report(thing, result, stats)


def _memory_need(entry, settings) -> int:
    """Bytes check_file will keep in memory for this file (it reads small files whole)."""
    size = entry.st.st_size
    return size if size <= settings.limits.in_memory_max else 0


def _loop(settings, store, job, detectors, sig_version, progress) -> str:
    """Returns '' when every file was checked, else 'pause' or 'cancel'."""
    from ..allowlist import TrustChecker

    job_id, counts = job["id"], progress.counts
    trust = TrustChecker(store)
    throttle = Throttle(settings.limits.read_rate_mb_s)
    # Rows written before a crash but after the last saved checkpoint: those files are checked
    # again, and the new result replaces the old row when it differs (never a second row). A
    # file that is now clean and fully checked loses its old row, so the page matches the counts.
    already = store.result_fingerprints(job_id)

    def report(thing, r: FileResult | None, stats: dict) -> None:
        counts["archives_members"] += stats.get("archives_members", 0)
        if r is not None:
            tally(counts, r, isinstance(thing, walker.FileEntry))
            if is_notable(r):
                fingerprint = store.result_fingerprint(r)
                if r.path not in already:
                    store.add_result(job_id, r)
                elif already[r.path] != fingerprint:
                    store.replace_result(job_id, r)
                already[r.path] = fingerprint
            elif r.path in already:
                store.remove_result(job_id, r.path)
                del already[r.path]
        progress.checkpoint = thing.display

    threads = clamav_thread_count(settings)
    pool = None
    if any(getattr(d, "parallel", False) for d in detectors):
        pool = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="tacoguard-clamav")
    window = _Window(2 * threads, WINDOW_MAX_BYTES, report)
    game_checked = 0.0
    try:
        for thing in walker.walk(job["targets"], job["checkpoint"], settings.limits.max_file_size):
            control = (store.get_job(job_id) or {}).get("control", "")
            if control in ("pause", "cancel"):
                window.stop()
                return control
            if time.monotonic() - game_checked >= GAME_MODE_CHECK_S:
                game_checked = time.monotonic()
                control = _wait_for_game_mode(store, job_id, progress, window)
                if control:
                    window.stop()
                    return control
            stats: dict = {}
            if isinstance(thing, walker.WalkNote):
                pending = Pending(note_result(thing))
            else:
                window.make_room(_memory_need(thing, settings))
                progress.current = thing.display
                try:
                    pending = check_file(thing, detectors, trust, settings, store, sig_version,
                                         throttle=throttle, stats=stats, pool=pool)
                    if not isinstance(pending, Pending):     # no pool: already a FileResult
                        pending = Pending(pending)
                except MemoryError:     # the worker's memory cap: note it and carry on
                    pending = Pending(FileResult(path=thing.display, size=thing.st.st_size,
                                                 notes=[MEMORY_NOTE], incomplete=True))
            window.add(thing, pending, stats)
            progress.maybe_flush()
        window.drain()
        return ""
    finally:
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)


def _game_mode_on(store) -> bool:
    from .. import phase4
    try:
        return phase4.game_mode(store)["active"]
    except Exception:
        return False


def _wait_for_game_mode(store, job_id, progress, window) -> str:
    """Between two files: while Game mode is on, the scan waits (Game mode looked at every
    GAME_MODE_POLL_S, pause / cancel every second, heartbeat and counts kept up to date; files
    whose checks finished meanwhile are reported, so the checkpoint stays right). Returns ''
    when the scan may carry on, else 'pause' or 'cancel'. Waiting time doesn't count as scan time."""
    if not _game_mode_on(store):
        return ""
    t0 = time.monotonic()
    progress.current = ""
    progress.flush(message=GAME_MODE_WAIT_MSG)
    next_look = time.monotonic() + GAME_MODE_POLL_S
    try:
        while True:
            time.sleep(min(1.0, GAME_MODE_POLL_S))
            control = (store.get_job(job_id) or {}).get("control", "")
            if control in ("pause", "cancel"):
                return control
            if time.monotonic() >= next_look:
                next_look = time.monotonic() + GAME_MODE_POLL_S
                window.report_done()
                if not _game_mode_on(store):
                    return ""
                progress.flush(message=GAME_MODE_WAIT_MSG)     # heartbeat + counts
    finally:
        progress.t0 += time.monotonic() - t0     # not counted as checking time
        progress.flush()


def _finish(store, job_id, progress, stopped, extra) -> None:
    progress.current = ""
    c = progress.counts
    if stopped == "pause":
        msg, status = f"Paused after {c['files']:,} files. Press Resume to carry on.", "paused"
    elif stopped == "cancel":
        msg, status = f"Cancelled. {summary(c)}", "cancelled"
    else:
        msg, status = f"Done: {summary(c)}", "done"
    if extra:
        msg += " " + extra
    fields = {"status": status, "control": "", "message": msg}
    if status != "paused":
        fields["finished"] = time.time()
    progress.flush(**fields)
