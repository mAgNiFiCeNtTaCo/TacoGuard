"""ClamAV detector: a private clamd on 127.0.0.1, fed with zINSTREAM.

We read every file ourselves and stream it to clamd, so long paths, our own permission handling
and in-memory data all work the same way. ClamAV unpacks archives itself (scans_members=False).
"""
from __future__ import annotations

import hashlib
import os
import re
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from .. import winjob
from ..config import clamav_thread_count
from ..model import Confidence, Finding, ScanItem, plain_error
from .base import DetectorError, DetectorUnavailable

CREATE_NO_WINDOW = 0x08000000
STREAM_MAX = 512 * 1024**2
CHUNK = 1024**2
START_TIMEOUT = 180          # the full official database takes ~30-90 s to load
SCAN_TIMEOUT = 600
OFFICIAL_SOURCE = "ClamAV official signatures (Cisco Talos)"
TEST_SOURCE = "test signature"
TOO_BIG = "Too big for the ClamAV check (over 512 MB); checked with the other methods."
ODD_ANSWER = ("ClamAV could not check this file (it gave an answer TacoGuard did not understand); "
              "it was checked with the other methods.")
NO_ANSWER = "ClamAV gave no answer for this file; it was checked with the other methods."
REPLY_LOG_MAX = 1024**2
_LOG_LOCK = threading.Lock()
DB_EXTENSIONS = {".cvd", ".cld", ".cud", ".ndb", ".hdb", ".hsb", ".ldb", ".ldu", ".mdb", ".msb",
                 ".ndu", ".cdb", ".fp", ".sfp", ".ign", ".ign2", ".pdb", ".gdb", ".wdb", ".yar",
                 ".yara", ".idb", ".ftm", ".crb", ".cat", ".imp", ".ioc", ".info", ".cfg"}


# ---------------------------------------------------------------------------------------------
# Database files (cheap: headers only, never starts clamd)
# ---------------------------------------------------------------------------------------------

def _cvd_header(path: Path) -> dict:
    """The 512-byte text header of a .cvd/.cld: ClamAV-VDB:time:version:sigs:level:md5:dsig:builder:stime"""
    try:
        with open(path, "rb") as f:
            head = f.read(512).decode("ascii", "replace")
    except OSError:
        return {}
    parts = head.split(":")
    if len(parts) < 9 or parts[0] != "ClamAV-VDB":
        return {}
    try:
        stime = int(parts[8].strip("\0 ").split()[0])
    except (ValueError, IndexError):
        stime = 0
    return {"version": parts[2], "sigs": int(parts[3]) if parts[3].isdigit() else 0, "stime": stime}


def database_info(db_dir: Path) -> dict:
    """{"main": {...}, "daily": {...}, "bytecode": {...}, "<other file>": {...}} for the folder."""
    info: dict = {}
    if not db_dir.is_dir():
        return info
    for p in sorted(db_dir.iterdir()):
        if not p.is_file() or p.suffix.lower() not in DB_EXTENSIONS:
            continue
        st = p.stat()
        entry = {"path": str(p), "size": st.st_size, "mtime": st.st_mtime}
        if p.suffix.lower() in (".cvd", ".cld"):
            head = _cvd_header(p)
            if not head:
                continue
            entry.update(head)
            name = p.stem
            # freshclam may leave both main.cvd and main.cld for a moment: keep the newer version
            if name in info and int(info[name].get("version", 0)) >= int(head["version"] or 0):
                continue
            info[name] = entry
        else:
            info[p.name] = entry
    return info


def _day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d") if epoch else "an unknown date"


def describe_databases(info: dict) -> str:
    daily = info.get("daily")
    if daily:
        return f"ClamAV signatures from {_day(daily.get('stime') or daily['mtime'])} (daily {daily['version']})."
    if info:
        return f"ClamAV test signatures only ({', '.join(sorted(info))})."
    return "Not downloaded yet: press Get signatures."


def database_version(info: dict) -> str:
    official = [f"{k}{info[k]['version']}" for k in ("main", "daily", "bytecode") if k in info]
    extra = sorted(f"{k}:{v['size']}:{int(v['mtime'])}" for k, v in info.items()
                   if k not in ("main", "daily", "bytecode"))
    tag = "-".join(official) or "none"
    if extra:
        tag += "-x" + hashlib.sha256("|".join(extra).encode()).hexdigest()[:10]
    return "clamav-" + tag


# ---------------------------------------------------------------------------------------------
# Windows job object: clamd dies when our process dies
# ---------------------------------------------------------------------------------------------

# (the job object helper lives in tacoguard/winjob.py, shared with the RAR unpacker's tar.exe)
_kill_on_close_job = winjob.kill_on_close_job
_close_handle = winjob.close_job


def _same_priority_as_us(pid: int) -> None:
    """Give clamd this process's CPU and disk priority. In the scan worker (idle priority) clamd
    then only uses CPU time nobody else wants, like the worker itself."""
    try:
        import psutil
        me, clamd = psutil.Process(), psutil.Process(pid)
        clamd.nice(me.nice())
        clamd.ionice(me.ionice())
    except Exception:
        pass        # clamd still works at its own priority


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------------------------

class ClamAVDetector:
    """scan() may be called from several threads at once: each call opens its own socket and
    only reads _proc and _port, which change only in open() and close() (never during a scan)."""
    name = "clamav"
    scans_members = False
    parallel = True          # the engine runs scan() for several files at once in a thread pool

    def __init__(self, settings, program_dir: Path | None = None, db_dir: Path | None = None):
        self.settings = settings
        self.program_dir = Path(program_dir or settings.clamav_program_dir)
        self.db_dir = Path(db_dir or settings.clamav_db_dir)
        self._proc: subprocess.Popen | None = None
        self._job = None
        self._port = 0
        self._conf: Path | None = None
        self._stop = threading.Event()
        self.load_seconds = 0.0

    # ---- status ---------------------------------------------------------------------------
    def status(self) -> dict:
        try:
            info = database_info(self.db_dir)
            daily = info.get("daily", {})
            if not (self.program_dir / "clamd.exe").exists():
                ready, msg = False, "ClamAV program not downloaded yet: press Get signatures."
            elif not info:
                ready, msg = False, "Not downloaded yet: press Get signatures."
            else:
                ready, msg = True, describe_databases(info)
            count = sum(v.get("sigs", 0) for v in info.values())
            updated = daily.get("stime") or max((v["mtime"] for v in info.values()), default=0)
            return {"ready": ready, "message": msg, "version": database_version(info),
                    "updated": float(updated), "count": count}
        except Exception as e:  # status must never raise
            return {"ready": False, "message": f"Could not read the ClamAV signatures: {plain_error(e)}",
                    "version": "clamav-none", "updated": 0.0, "count": 0}

    def version(self) -> str:
        return database_version(database_info(self.db_dir))

    # ---- start / stop ---------------------------------------------------------------------
    def open(self) -> None:
        if self._proc and self._proc.poll() is None:
            return
        clamd = self.program_dir / "clamd.exe"
        if not clamd.exists():
            raise DetectorUnavailable("The ClamAV program has not been downloaded yet. Press Get signatures.")
        if not database_info(self.db_dir):
            raise DetectorUnavailable("ClamAV signatures have not been downloaded yet. Press Get signatures.")
        self._stop.clear()
        self._port = _free_port()
        self._conf = self._write_conf()
        started = time.monotonic()
        self._proc = subprocess.Popen(
            [str(clamd), f"--config-file={self._conf}"], cwd=str(self.program_dir),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW)
        self._job = _kill_on_close_job(int(self._proc._handle))
        _same_priority_as_us(self._proc.pid)
        try:                                     # other programs can't end or freeze it mid-scan
            from ..selfprotect import harden_child
            harden_child(self._proc._handle, self._proc.pid, self.settings)
        except ImportError:
            pass
        try:
            self._wait_ready(started)
        except BaseException:
            self.close()
            raise
        self.load_seconds = time.monotonic() - started

    def _write_conf(self) -> Path:
        tmp = self.settings.tmp_dir / "clamd-temp"
        tmp.mkdir(parents=True, exist_ok=True)
        self.settings.log_dir.mkdir(parents=True, exist_ok=True)
        lines = [
            f"TCPSocket {self._port}",
            "TCPAddr 127.0.0.1",
            f'DatabaseDirectory "{self.db_dir}"',
            f'TemporaryDirectory "{tmp}"',
            f'LogFile "{self.settings.log_dir / "clamd.log"}"',
            "LogFileUnlock yes", "LogTime yes", "LogFileMaxSize 5M", "LogRotate yes",
            "Foreground yes",
            "StreamMaxLength 512M", "MaxFileSize 512M", "MaxScanSize 1024M",
            "MaxRecursion 10", "MaxFiles 10000", "AlertEncrypted no",
            # one clamd thread per file the engine sends at once, plus one spare for PING/SHUTDOWN
            f"MaxThreads {clamav_thread_count(self.settings) + 1}",
            "ReadTimeout 300", "CommandReadTimeout 30",
            # one engine in memory at a time: reloading after an update pauses scans briefly
            # instead of needing a second ~1.2 GB copy
            "ConcurrentDatabaseReload no",
        ]
        if (self.program_dir / "certs").is_dir():
            lines.append(f'CVDCertsDirectory "{self.program_dir / "certs"}"')
        conf = self.settings.tmp_dir / f"clamd-{self._port}.conf"
        conf.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return conf

    def _wait_ready(self, started: float) -> None:
        while time.monotonic() - started < START_TIMEOUT:
            if self._stop.wait(0.5):
                raise DetectorUnavailable("ClamAV start was cancelled.")
            if self._proc.poll() is not None:
                raise DetectorUnavailable("ClamAV could not start: " + self._log_problem())
            try:
                if self._command(b"zPING\0", timeout=5) == "PONG":
                    return
            except OSError:
                continue        # still loading its signatures
        raise DetectorUnavailable("ClamAV took more than 3 minutes to load its signatures, so it "
                                  "was stopped. The other checks still run.")

    def _log_problem(self) -> str:
        try:
            lines = (self.settings.log_dir / "clamd.log").read_text("utf-8", "replace").splitlines()
        except OSError:
            return "no details were written."
        errors = [ln for ln in lines[-40:] if "ERROR" in ln.upper()]
        return (errors or lines[-1:] or ["no details were written."])[-1].strip()

    def cancel(self) -> None:
        """Interrupt a start that is still loading signatures (from another thread)."""
        self._stop.set()

    def close(self) -> None:
        self._stop.set()
        proc, self._proc = self._proc, None
        if proc and proc.poll() is None:
            try:
                self._command(b"zSHUTDOWN\0", timeout=5, expect_reply=False)
                proc.wait(timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()
                proc.wait(timeout=15)
        _close_handle(self._job)
        self._job = None
        if self._conf:
            self._conf.unlink(missing_ok=True)
            self._conf = None

    # ---- protocol -------------------------------------------------------------------------
    def _connect(self, timeout: float) -> socket.socket:
        return socket.create_connection(("127.0.0.1", self._port), timeout=timeout)

    @staticmethod
    def _read_reply(sock: socket.socket) -> str:
        buf = b""
        while not buf.endswith(b"\0"):
            block = sock.recv(4096)
            if not block:
                break
            buf += block
        return buf.rstrip(b"\0").decode("utf-8", "replace").strip()

    def _command(self, cmd: bytes, timeout: float = 30, expect_reply: bool = True) -> str:
        with self._connect(timeout) as sock:
            sock.sendall(cmd)
            return self._read_reply(sock) if expect_reply else ""

    def clamd_version(self) -> str:
        """"ClamAV 1.5.5/27850/Sun Nov 23 ..." from the running clamd."""
        return self._command(b"zVERSION\0")

    def _instream(self, chunks) -> str:
        with self._connect(SCAN_TIMEOUT) as sock:
            sock.sendall(b"zINSTREAM\0")
            for chunk in chunks:
                if chunk:
                    sock.sendall(struct.pack(">I", len(chunk)) + bytes(chunk))
            sock.sendall(struct.pack(">I", 0))
            return self._read_reply(sock)

    # ---- scanning -------------------------------------------------------------------------
    def scan(self, item: ScanItem) -> list[Finding]:
        if not self._proc or self._proc.poll() is not None:
            raise DetectorError("ClamAV is not running, so this file was checked with the other methods only.")
        if item.data is not None:
            if len(item.data) > STREAM_MAX:
                raise DetectorError(TOO_BIG)
            view = memoryview(item.data)
            reply = self._send(view[i:i + CHUNK] for i in range(0, len(view), CHUNK))
        elif item.path:
            reply = self._scan_path(item.path)
        else:
            return []
        return self._parse(reply, item)

    def _scan_path(self, path: str) -> str:
        try:
            if os.stat(path).st_size > STREAM_MAX:
                raise DetectorError(TOO_BIG)
            with open(path, "rb") as f:
                return self._send(iter(lambda: f.read(CHUNK), b""))
        except OSError as e:
            raise DetectorError(f"ClamAV could not read this file ({plain_error(e)}).") from e

    def _send(self, chunks) -> str:
        try:
            return self._instream(chunks)
        except (ConnectionError, socket.timeout) as e:
            if self._proc and self._proc.poll() is not None:
                raise DetectorError("ClamAV stopped unexpectedly; this file was checked with the "
                                    "other methods only.") from e
            raise DetectorError("ClamAV did not answer in time for this file.") from e

    def _parse(self, reply: str, item: ScanItem) -> list[Finding]:
        if reply.endswith("OK"):
            return []
        m = re.match(r"^stream: (.+) FOUND$", reply)
        if m:
            return [make_finding(m.group(1), item.member)]
        if "size limit exceeded" in reply.lower():
            raise DetectorError(TOO_BIG)
        self._log_reply(reply, item)
        if not reply:
            raise DetectorError(NO_ANSWER)
        raise DetectorError(ODD_ANSWER)

    def _log_reply(self, reply: str, item: ScanItem) -> None:
        """ClamAV's own words for a reply we don't understand go to <data>\\logs\\clamav-replies.log
        (the page shows a plain sentence instead)."""
        try:
            with _LOG_LOCK:
                log = Path(self.settings.log_dir) / "clamav-replies.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                if log.exists() and log.stat().st_size > REPLY_LOG_MAX:
                    log.replace(log.with_name("clamav-replies.old.log"))
                with open(log, "a", encoding="utf-8", errors="replace") as fh:
                    fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {item.display}  "
                             f"{(reply or '(no answer)')[:500]!r}\n")
        except Exception:
            pass        # logging must never break a scan


# ---------------------------------------------------------------------------------------------
# How sure a ClamAV name is, by its category
# ---------------------------------------------------------------------------------------------
# Official names are Platform.Category.Name-SigID-Rev (docs.clamav.net, "Signature Names"):
# Win.Trojan.Agent-123-0, Win.Packed.Mikey-9859688-0, PUA.Win.Tool.X-1, Heuristics.Encrypted.PDF.
# Categories that name harmful behaviour are strong. Packed / Packer / Tool / Adware and friends
# describe how a program is built or what it can do: legitimate programs match them too
# (2026-11-23: Win.Packed.Mikey-9859688-0 matched several well-known signed programs built on
# CEF / Electron), so they are medium. Anything not in the table is medium too.
_PACKED = ("packed program: the file is compressed or wrapped in a way malware often uses, which "
           "on its own is not proof of harm")
CATEGORY_CONFIDENCE: dict[str, tuple[Confidence, str]] = {
    **{c: (Confidence.HIGH, "") for c in (
        "trojan", "malware", "virus", "worm", "ransomware", "downloader", "dropper", "loader",
        "backdoor", "exploit", "keylogger", "spyware", "infostealer", "coinminer", "rootkit",
        "phishing", "botnet", "ircbot", "revoked")},
    "test": (Confidence.HIGH, "antivirus test file (harmless)"),
    "packed": (Confidence.MEDIUM, _PACKED),
    "packer": (Confidence.MEDIUM, _PACKED),
    "tool": (Confidence.MEDIUM, "tool: a program that can be used for good or harm (for example "
                                "remote control or password recovery)"),
    "adware": (Confidence.MEDIUM, "adware: shows ads or installs extra software"),
    "joke": (Confidence.MEDIUM, "joke program: meant to prank, not to cause harm"),
    "countermeasure": (Confidence.MEDIUM, "the file uses tricks to hide from security tools, which "
                                          "on its own is not proof of harm"),
    "proxy": (Confidence.MEDIUM, "proxy program: passes network traffic on; legitimate programs do "
                                 "this too"),
    "macro": (Confidence.MEDIUM, "document macro"),
    "file": (Confidence.MEDIUM, "file-type check"),
    "filetype": (Confidence.MEDIUM, "file-type check"),
}
UNKNOWN_CATEGORY = (Confidence.MEDIUM, "")
PUA_RULE = (Confidence.MEDIUM, "potentially unwanted program")
HEURISTIC_RULE = (Confidence.LOW, "heuristic match")
# Categories a valid digital signature must never soften (Win.Revoked.* = signed with a
# certificate known to be stolen or revoked; the antivirus test file is meant to be found).
NO_SIGNATURE_TRUST = {"revoked", "test"}


def signature_category(signature: str) -> str:
    """'packed' for 'Win.Packed.Mikey-9859688-0', 'test' for 'Eicar-Test-Signature', 'pua' for
    PUA.*, 'heuristics' for Heuristics.*, '' when the name has no category we know."""
    name = signature.removesuffix(".UNOFFICIAL")
    parts = name.split(".")
    first = parts[0].lower()
    if first in ("pua", "heuristics"):
        return first
    if "eicar" in name.lower() or name.startswith("TacoGuard.Test"):
        return "test"
    # Platform.Category.Name (the usual), or an older Category.Name
    for part in parts[1:2] + parts[:1]:
        if part.lower() in CATEGORY_CONFIDENCE:
            return part.lower()
    return ""


def make_finding(signature: str, member: str = "") -> Finding:
    # clamd adds ".UNOFFICIAL" to names from unsigned databases; the signature itself lacks it
    signature = signature.removesuffix(".UNOFFICIAL")
    if signature.startswith("TacoGuard.Test"):
        return Finding("clamav", signature, Confidence.HIGH, TEST_SOURCE, member=member)
    category = signature_category(signature)
    if category == "pua":
        confidence, detail = PUA_RULE
    elif category == "heuristics":
        confidence, detail = HEURISTIC_RULE
    else:
        confidence, detail = CATEGORY_CONFIDENCE.get(category, UNKNOWN_CATEGORY)
    return Finding("clamav", signature, confidence, OFFICIAL_SOURCE, detail=detail, member=member)


def signature_trust_applies(signature: str) -> bool:
    """False for names a valid digital signature must not soften (see NO_SIGNATURE_TRUST)."""
    return signature_category(signature) not in NO_SIGNATURE_TRUST
