"""First-time setup and manual refresh of the ClamAV program, ClamAV signatures and YARA rules.

CONTRACT (Helper B fills this in; signatures must stay):

    class FetchError(Exception)     plain-English message for the page

    fetch_all(settings, progress=print) -> dict
        Runs the three steps below in order, each verified; calls progress("plain words") as it goes.
        A failed step leaves the previous good copy in place and is reported, the other steps still
        run. Returns {"clamav_program": {...}, "clamav_signatures": {...}, "yara_rules": {...}},
        each {"ok": bool, "message": plain English, "changed": bool}.

    fetch_clamav_program(settings, progress) -> dict
    fetch_clamav_signatures(settings, progress) -> dict   (runs ClamAV's own freshclam)
    fetch_yara_rules(settings, progress) -> dict

Every host contacted must be listed in config.ENDPOINTS.

Shared with the background updater (tacoguard/updates/updater.py): run_freshclam (once an hour at
most, cool-downs remembered in updates\\freshclam.json), verify_databases, clamscan_test,
yara_latest_release, yara_is_current, stage_yara_rules, safe_unzip, _open, _download.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .config import ENDPOINTS

USER_AGENT = "TacoGuard/0.1"
HTTP_TIMEOUT = 60
CREATE_NO_WINDOW = 0x08000000

CLAMAV_VERSION = "1.5.5"
CLAMAV_ASSET = f"clamav-{CLAMAV_VERSION}.win.x64.zip"
CLAMAV_URL = ("https://github.com/Cisco-Talos/clamav/releases/download/"
              f"clamav-{CLAMAV_VERSION}/{CLAMAV_ASSET}")
CLAMAV_SHA256 = "90169f5e551010bfbd0208b50d9b2fa8988ef396cccbd46b0cc8cae03e22a4a4"
CLAMAV_RELEASE_API = f"https://api.github.com/repos/Cisco-Talos/clamav/releases/tags/clamav-{CLAMAV_VERSION}"
CLAMAV_INSTALL_MARKER = "tacoguard-install.json"
FRESHCLAM_TIMEOUT = 30 * 60

FORGE_RELEASE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
FORGE_ASSET = "yara-forge-rules-core.zip"

MISMATCH = "The download did not match its published checksum, so it was thrown away. Nothing was changed."
UNSAFE_ZIP = ("The download contained a file with an unsafe path, so it was not unpacked. "
              "Nothing was changed.")


class FetchError(Exception):
    """kind tells the updater what happened: "offline" (no connection), "http" (code = the HTTP
    status), "rate_limit" / "blocked" (ClamAV's servers asked us to wait), "too_soon" (TacoGuard's
    own once-an-hour freshclam limit), "too_big", or "" (anything else)."""

    def __init__(self, message: str, kind: str = "", code: int = 0, retry_at: float = 0.0):
        super().__init__(message)
        self.kind = kind
        self.code = code
        self.retry_at = retry_at


# ---------------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------------

def _result(ok: bool, message: str, changed: bool = False) -> dict:
    return {"ok": ok, "message": message, "changed": changed}


def _guarded(step, settings, progress) -> dict:
    """Run one step; any failure becomes a plain message and leaves the old copy in place."""
    try:
        return step(settings, progress)
    except FetchError as e:
        progress(str(e))
        return _result(False, str(e))
    except OSError as e:
        msg = f"Could not write to the TacoGuard data folder: {e.strerror or e}. Nothing was changed."
        progress(msg)
        return _result(False, msg)


def fetch_all(settings, progress=print) -> dict:
    settings.ensure_dirs()
    return {
        "clamav_program": fetch_clamav_program(settings, progress),
        "clamav_signatures": fetch_clamav_signatures(settings, progress),
        "yara_rules": fetch_yara_rules(settings, progress),
    }


# ---------------------------------------------------------------------------------------------
# HTTP (stdlib only, hosts limited to config.ENDPOINTS)
# ---------------------------------------------------------------------------------------------

def allowed_hosts() -> set[str]:
    hosts = set()
    for entry in ENDPOINTS:
        for h in entry["host"].split(","):
            if h.strip():
                hosts.add(h.strip().lower())
    return hosts


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in allowed_hosts():
        raise FetchError(f"TacoGuard refused to contact {host or url}: it is not on the list of "
                         "allowed internet addresses. Nothing was changed.")


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)   # GitHub sends downloads to its asset hosts; those must be listed too
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, headers: dict | None = None):
    _check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    opener = urllib.request.build_opener(_CheckedRedirects())
    try:
        try:
            return opener.open(req, timeout=HTTP_TIMEOUT)
        except urllib.error.URLError as e:
            # The site's root certificate isn't on this PC yet: let Windows fetch it (only roots
            # Microsoft trusts), then try once more with the same full check (winroots.py).
            from . import winroots
            if isinstance(e, urllib.error.HTTPError) or not winroots.missing_issuer(e) \
                    or not winroots.fetch_root(urllib.parse.urlsplit(url).hostname or ""):
                raise
            return urllib.request.build_opener(_CheckedRedirects()).open(req, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError as e:
        raise FetchError(_http_error_words(e, url), kind="http", code=e.code) from e
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        host = urllib.parse.urlsplit(url).hostname
        raise FetchError(f"Could not reach {host}. Check the internet connection and try again. "
                         "Nothing was changed.", kind="offline") from e


def _http_error_words(e: urllib.error.HTTPError, url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname
    if e.code in (403, 429) and "github" in (host or ""):
        return ("GitHub is limiting downloads from this internet connection right now. "
                "Try again in an hour. Nothing was changed.")
    if e.code == 404:
        return f"{host} says the file is not there (error 404). Nothing was changed."
    return f"{host} answered with error {e.code}. Try again later. Nothing was changed."


def _http_json(url: str) -> dict:
    with _open(url, {"Accept": "application/vnd.github+json"}) as resp:
        try:
            return json.loads(resp.read().decode("utf-8"))
        except ValueError as e:
            raise FetchError("GitHub sent an answer TacoGuard could not read. Nothing was changed.") from e


def _asset_digest(release: dict, asset_name: str) -> tuple[str, str]:
    """(download URL, sha256 hex) of a release asset, from the GitHub API's "digest" field."""
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                raise FetchError(f"GitHub published no checksum for {asset_name}, so it was not "
                                 "downloaded. Nothing was changed.")
            return asset["browser_download_url"], digest.split(":", 1)[1].lower()
    raise FetchError(f"The release has no file named {asset_name}. Nothing was changed.")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


TOO_BIG_DOWNLOAD = ("The download was bigger than the update list says it should be, so it was "
                    "thrown away. Nothing was changed.")
TOO_SLOW_DOWNLOAD = "The download was too slow and was stopped; TacoGuard will try again later."
# A download gets DOWNLOAD_GRACE_S plus its size at DOWNLOAD_MIN_RATE in total, and after the grace
# period its average speed must stay above DOWNLOAD_MIN_AVG_RATE (also when the size is unknown).
# Otherwise a server that sends a byte now and then would hold the update check (and its lock)
# for ever: the socket timeout only covers ONE read.
DOWNLOAD_GRACE_S = 120.0
DOWNLOAD_MIN_RATE = 50 * 1024
DOWNLOAD_MIN_AVG_RATE = 10 * 1024
READ_BLOCK = 64 * 1024


def download_deadline(size: int, grace: float | None = None, rate: float | None = None) -> float:
    """Seconds a download of `size` bytes may take in total (0 or less: size unknown)."""
    grace = DOWNLOAD_GRACE_S if grace is None else grace
    rate = DOWNLOAD_MIN_RATE if rate is None else rate
    return grace + max(0, int(size or 0)) / rate


def _read_block(resp) -> bytes:
    """What has arrived, up to READ_BLOCK bytes, without waiting for a whole block."""
    read1 = getattr(resp, "read1", None)
    return read1(READ_BLOCK) if read1 is not None else resp.read(READ_BLOCK)


def _download(url: str, dest: Path, sha256: str, progress, label: str,
              max_bytes: int | None = None) -> Path:
    """Download to dest via a resumable .part file; verify the checksum before anything uses it.
    max_bytes (when known, e.g. from signed metadata) stops a download that grows past it.
    A download that is too slow (see DOWNLOAD_GRACE_S) stops with FetchError kind "too_slow";
    its .part file is kept, so the next try resumes it."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and sha256_file(dest) == sha256:
        return dest
    part = dest.with_name(dest.name + ".part")
    have = part.stat().st_size if part.exists() else 0
    if max_bytes is not None and have > max_bytes:
        part.unlink()
        have = 0
    headers = {"Range": f"bytes={have}-"} if have else {}
    try:
        resp = _open(url, headers)
    except FetchError:
        if not have:
            raise
        part.unlink()          # a stale partial file the server will not continue: start over
        have, resp = 0, _open(url)
    started = time.monotonic()
    too_slow = False
    with resp:
        resumed = have and getattr(resp, "status", 200) == 206
        total = int(resp.headers.get("Content-Length") or 0) + (have if resumed else 0)
        done = first = have if resumed else 0
        expected = (max_bytes if max_bytes is not None else total) - first
        limit = download_deadline(expected) if expected > 0 else 0.0
        next_report = 0.0
        with open(part, "ab" if resumed else "wb") as out:
            try:
                for block in iter(lambda: _read_block(resp), b""):
                    out.write(block)
                    done += len(block)
                    if max_bytes is not None and done > max_bytes:
                        break
                    if total and done / total >= next_report:
                        progress(f"Downloading the {label}: {done * 100 // total}% of "
                                 f"{total / 1024**2:.0f} MB")
                        next_report += 0.25
                    spent = time.monotonic() - started
                    if (limit and spent > limit) or \
                            (spent > DOWNLOAD_GRACE_S and (done - first) / spent < DOWNLOAD_MIN_AVG_RATE):
                        too_slow = True
                        break
            except TimeoutError:          # nothing arrived for HTTP_TIMEOUT seconds
                too_slow = True
    if too_slow:
        progress(TOO_SLOW_DOWNLOAD)
        raise FetchError(TOO_SLOW_DOWNLOAD, kind="too_slow")
    if max_bytes is not None and done > max_bytes:
        part.unlink()
        raise FetchError(TOO_BIG_DOWNLOAD, kind="too_big")
    if sha256_file(part) != sha256:
        part.unlink()
        raise FetchError(MISMATCH)
    os.replace(part, dest)
    progress(f"The {label} download matches its published checksum.")
    return dest


# ---------------------------------------------------------------------------------------------
# Zip and folder helpers
# ---------------------------------------------------------------------------------------------

def _check_zip_member(info: zipfile.ZipInfo, root: str) -> None:
    name = info.filename.replace("\\", "/")
    parts = name.split("/")
    bad = (name.startswith("/") or ":" in name or ".." in parts
           or stat.S_ISLNK(info.external_attr >> 16))
    target = os.path.realpath(os.path.join(root, name))
    if bad or os.path.commonpath([root, target]) != root:
        raise FetchError(UNSAFE_ZIP)


def safe_unzip(zip_path: Path, dest: Path, max_total: int = 2 * 1024**3) -> None:
    """Unpack into a NEW folder, refusing absolute paths, '..', drive letters and links."""
    dest.mkdir(parents=True)
    root = os.path.realpath(dest)
    try:
        with zipfile.ZipFile(zip_path) as z:
            members = z.infolist()
            for info in members:
                _check_zip_member(info, root)
            if sum(i.file_size for i in members) > max_total:
                raise FetchError("The download unpacks to far more than expected, so it was not "
                                 "unpacked. Nothing was changed.")
            for info in members:
                z.extract(info, root)
    except zipfile.BadZipFile as e:
        raise FetchError("The download is not a readable zip file. Nothing was changed.") from e


def _flatten_single_folder(folder: Path) -> None:
    """ClamAV's zip holds one top folder (clamav-1.5.5.win.x64\\); lift its contents up."""
    entries = list(folder.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for child in inner.iterdir():
            os.replace(child, folder / child.name)
        inner.rmdir()


def _remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def swap_folders(new: Path, current: Path, previous: Path, keep_previous: bool) -> None:
    """current -> previous, new -> current; puts the old copy back if the second step fails."""
    _remove_tree(previous)
    if current.exists():
        try:
            os.replace(current, previous)
        except PermissionError as e:
            raise FetchError("The old copy is in use right now (a scan may be running). Try again "
                             "when no scan is running. Nothing was changed.") from e
    try:
        os.replace(new, current)
    except OSError:
        if previous.exists() and not current.exists():
            os.replace(previous, current)
        raise
    if not keep_previous:
        shutil.rmtree(previous, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# ClamAV program
# ---------------------------------------------------------------------------------------------

def _powershell() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def authenticode(paths: list[Path]) -> list[tuple[str, str, str]]:
    """[(file name, status, signer)] from Windows' own signature check. Paths go in through an
    environment variable so no file name is ever parsed as PowerShell code."""
    script = ("$env:TG_SIG_PATHS -split '\\|' | ForEach-Object { "
              "$s = Get-AuthenticodeSignature -LiteralPath $_; "
              "'{0}|{1}|{2}' -f (Split-Path $_ -Leaf), $s.Status, $s.SignerCertificate.Subject }")
    env = dict(os.environ, TG_SIG_PATHS="|".join(str(p) for p in paths))
    try:
        r = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=120, env=env,
                           creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return [(p.name, "Unknown", "") for p in paths]
    rows = []
    for line in r.stdout.splitlines():
        if line.count("|") >= 2:
            name, status, subject = line.split("|", 2)
            m = re.search(r"CN=(\"[^\"]+\"|[^,]+)", subject)
            rows.append((name, status, m.group(1).strip('"') if m else ""))
    return rows or [(p.name, "Unknown", "") for p in paths]


def _signature_words(rows: list[tuple[str, str, str]]) -> str:
    parts = []
    for name, status, signer in rows:
        if status == "Valid":
            parts.append(f"{name} is digitally signed by {signer}")
        elif status == "NotSigned":
            parts.append(f"{name} has no digital signature")
        else:
            parts.append(f"{name} signature check: {status}")
    return "Windows signature check: " + "; ".join(parts) + "."


def _installed_program(settings) -> dict:
    marker = settings.clamav_program_dir / CLAMAV_INSTALL_MARKER
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fetch_clamav_program(settings, progress=print) -> dict:
    return _guarded(_fetch_clamav_program, settings, progress)


def _fetch_clamav_program(settings, progress) -> dict:
    target = settings.clamav_program_dir
    have = _installed_program(settings)
    if have.get("sha256") == CLAMAV_SHA256 and (target / "clamd.exe").exists():
        return _result(True, f"ClamAV {CLAMAV_VERSION} is already installed.")

    progress(f"Checking GitHub's published checksum for ClamAV {CLAMAV_VERSION}...")
    try:
        _, digest = _asset_digest(_http_json(CLAMAV_RELEASE_API), CLAMAV_ASSET)
    except FetchError as e:
        digest = ""
        progress(f"Could not read GitHub's checksum ({e}); using the checksum built into TacoGuard.")
    if digest and digest != CLAMAV_SHA256:
        raise FetchError("GitHub lists a different checksum for ClamAV than the one built into "
                         "TacoGuard, so it was not downloaded. Nothing was changed.")

    zip_path = _download(CLAMAV_URL, settings.tmp_dir / CLAMAV_ASSET, CLAMAV_SHA256, progress,
                         f"ClamAV {CLAMAV_VERSION} program")
    new = target.with_name("clamav.new")
    _remove_tree(new)
    try:
        safe_unzip(zip_path, new)
        _flatten_single_folder(new)
        sig_text = _check_program_folder(new, progress)
        (new / CLAMAV_INSTALL_MARKER).write_text(json.dumps(
            {"version": CLAMAV_VERSION, "sha256": CLAMAV_SHA256, "installed": time.time()}),
            encoding="utf-8")
        swap_folders(new, target, target.with_name("clamav.previous"), keep_previous=False)
    except BaseException:
        shutil.rmtree(new, ignore_errors=True)
        raise
    zip_path.unlink(missing_ok=True)
    return _result(True, f"ClamAV {CLAMAV_VERSION} installed (download checksum verified). {sig_text}",
                   changed=True)


def _prune_build_files(folder: Path) -> None:
    """The zip carries ~750 MB of debug symbols and build libraries that clamd never loads."""
    for pattern in ("*.pdb", "*.lib"):
        for p in folder.glob(pattern):
            p.unlink()
    _remove_tree(folder / "include")


def _check_program_folder(folder: Path, progress) -> str:
    for exe in ("clamd.exe", "freshclam.exe", "sigtool.exe"):
        if not (folder / exe).exists():
            raise FetchError(f"The ClamAV download has no {exe}. Nothing was changed.")
    _prune_build_files(folder)
    progress("Asking Windows to check the ClamAV program's digital signature...")
    rows = authenticode([folder / "clamd.exe", folder / "freshclam.exe"])
    if any(status == "HashMismatch" for _, status, _ in rows):
        raise FetchError("Windows says the ClamAV program was changed after it was signed, so it "
                         "was thrown away. Nothing was changed.")
    return _signature_words(rows)


# ---------------------------------------------------------------------------------------------
# ClamAV signatures (ClamAV's own freshclam; ClamAV's servers allow only freshclam/cvdupdate)
# ---------------------------------------------------------------------------------------------

def freshclam_conf(settings, db_dir: Path | None = None) -> Path:
    """freshclam's config. db_dir (default: the live signature folder) lets the updater run
    freshclam on a staging copy."""
    prog = settings.clamav_program_dir
    db_dir = Path(db_dir or settings.clamav_db_dir)
    lines = [
        f'DatabaseDirectory "{db_dir}"',
        f'UpdateLogFile "{settings.log_dir / "freshclam.log"}"',
        "LogTime yes",
        "LogFileMaxSize 5M",
        "LogRotate yes",
        "DatabaseMirror database.clamav.net",
        # Versions come from a DNS lookup of current.cvd.clamav.net (freshclam's default). Turning
        # it off makes freshclam fetch every file header from the CDN, which failed in testing on
        # 2026-11-23 ("Malformed CVD header") and adds load ClamAV asks clients to avoid.
        "DNSDatabaseInfo current.cvd.clamav.net",
        "ConnectTimeout 60",
        "ReceiveTimeout 1800",
        "Checks 0",
    ]
    if (prog / "certs").is_dir():
        lines.append(f'CVDCertsDirectory "{prog / "certs"}"')
    name = "freshclam.conf" if db_dir == Path(settings.clamav_db_dir) else "freshclam-staging.conf"
    conf = settings.tmp_dir / name
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return conf


_FRESHCLAM_WORDS = [
    (re.compile(r"(\w+)\.c[vl]d (?:database )?is up[- ]to[- ]date \(version: (\d+)", re.I),
     "ClamAV {0} signatures are already up to date (version {1})."),
    (re.compile(r"(\w+)\.c[vl]d (?:database )?updated \(version: (\d+), sigs: (\d+)", re.I),
     "ClamAV {0} signatures updated to version {1} ({2} signatures)."),
    (re.compile(r"(\w+) database available for (?:update|download) \(local version: \d+, remote version: (\d+)\)", re.I),
     "Updating ClamAV {0} signatures to version {1}..."),
    (re.compile(r"(\w+) database available for download \(remote version: (\d+)\)", re.I),
     "Downloading ClamAV {0} signatures, version {1} (this can take a few minutes)..."),
    (re.compile(r"Testing database", re.I), "Checking that the new ClamAV signatures load..."),
    (re.compile(r"Database test passed", re.I), "The new ClamAV signatures load correctly."),
]

_FRESHCLAM_PROBLEMS = [
    (re.compile(r"cool-?down|error code 429|rate limit", re.I),
     "ClamAV's download servers asked TacoGuard to wait before downloading again (rate limit). "
     "The signatures you have are kept. Try again in a few hours."),
    (re.compile(r"error code 403|blocked", re.I),
     "ClamAV's download servers refused this connection for now. The signatures you have are "
     "kept. Try again tomorrow."),
    (re.compile(r"Can't connect|Couldn't resolve|could not resolve|Failed to get|"
                r"Connection timed out|Can't download", re.I),
     "Could not reach ClamAV's download servers. Check the internet connection and try again. "
     "The signatures you have are kept."),
    (re.compile(r"Malformed CVD header|Failed to find \w+ database|Update failed", re.I),
     "ClamAV's download servers did not answer properly just now. The signatures you have are "
     "kept. Try again in a few hours."),
]


def freshclam_words(line: str) -> str | None:
    """One freshclam output line in plain words, or None when it is noise."""
    for rx, words in _FRESHCLAM_WORDS:
        m = rx.search(line)
        if m:
            return words.format(*m.groups())
    return None


def freshclam_problem(lines: list[str]) -> str | None:
    for rx, words in _FRESHCLAM_PROBLEMS:
        if any(rx.search(line) for line in lines):
            return words
    return None


_PROBLEM_KINDS = ("rate_limit", "blocked", "offline", "")


def freshclam_problem_kind(lines: list[str]) -> str:
    """"rate_limit", "blocked", "offline" or "" for the first problem freshclam_problem names."""
    for (rx, _), kind in zip(_FRESHCLAM_PROBLEMS, _PROBLEM_KINDS):
        if any(rx.search(line) for line in lines):
            return kind
    return ""


# ClamAV asks clients not to check more than once an hour, and answers 429 ("cool-down") or 403
# when they do. TacoGuard remembers every run and every cool-down in updates\freshclam.json, for
# the page's "Get signatures" button and the background updater alike.
FRESHCLAM_MIN_INTERVAL = 3600
RATE_LIMIT_BACKOFF = 6 * 3600          # 429 without a time in freshclam's message
BLOCKED_BACKOFF = 24 * 3600            # 403
_COOLDOWN_UNTIL = re.compile(r"cool-?down until after:?\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)",
                             re.I)


def _freshclam_record_path(settings) -> Path:
    return Path(settings.updates_dir) / "freshclam.json"


def freshclam_record(settings) -> dict:
    """{"last_run": epoch, "retry_at": epoch, "reason": plain words} (empty when never run)."""
    try:
        return json.loads(_freshclam_record_path(settings).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_freshclam_record(settings, record: dict) -> None:
    path = _freshclam_record_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.replace(tmp, path)


def _clock(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))


def freshclam_wait(settings, now: float | None = None) -> tuple[float, str]:
    """(epoch when freshclam may run again, plain reason) or (0, "") when it may run now."""
    now = time.time() if now is None else now
    rec = freshclam_record(settings)
    retry_at = float(rec.get("retry_at") or 0)
    if retry_at > now:
        return retry_at, (rec.get("reason") or "ClamAV's download servers asked TacoGuard to wait.") \
            + f" The signatures you have are kept. Next try after {_clock(retry_at)}."
    next_ok = float(rec.get("last_run") or 0) + FRESHCLAM_MIN_INTERVAL
    if next_ok > now:
        return next_ok, ("ClamAV's signatures were checked less than an hour ago, and ClamAV asks "
                         "for at most one check an hour. The signatures you have are kept. Next "
                         f"check after {_clock(next_ok)}.")
    return 0.0, ""


def _cooldown_until(lines: list[str]) -> float:
    for line in lines:
        m = _COOLDOWN_UNTIL.search(line)
        if m:
            text = m.group(1).replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    return time.mktime(time.strptime(text, fmt))
                except ValueError:
                    continue
    return 0.0


def run_freshclam(settings, db_dir: Path, progress) -> tuple[dict, dict]:
    """Run ClamAV's freshclam on db_dir (the live folder or a staging copy). Returns
    (database_info before, after). Raises FetchError: kind "too_soon" when the hourly limit or a
    remembered cool-down forbids a run (freshclam is not started), "rate_limit" / "blocked" when
    ClamAV's servers ask us to wait (remembered), "offline", or "" for other failures."""
    from .detect.clamav import database_info

    prog = settings.clamav_program_dir
    if not (prog / "freshclam.exe").exists():
        raise FetchError("The ClamAV program is not installed, so its signatures could not be "
                         "downloaded.")
    now = time.time()
    retry_at, why = freshclam_wait(settings, now)
    if retry_at:
        raise FetchError(why, kind="too_soon", retry_at=retry_at)
    db_dir = Path(db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)
    before = database_info(db_dir)
    conf = freshclam_conf(settings, db_dir)
    _save_freshclam_record(settings, {"last_run": now})     # counts even when the run fails
    progress("Starting ClamAV's own updater (freshclam); the first download is about 110 MB...")

    def on_line(line: str) -> None:
        words = freshclam_words(line)
        if words:
            progress(words)

    cmd = [str(prog / "freshclam.exe"), f"--config-file={conf}", "--stdout", "--no-warnings"]
    code, lines = _run_streaming(cmd, FRESHCLAM_TIMEOUT, on_line)
    after = database_info(db_dir)
    # freshclam can report a cool-down or a failed connection and still exit 0/1 with the old
    # files in place: a named problem with nothing changed is a failure too
    reported = freshclam_problem(lines) is not None and not databases_changed(before, after)
    if code not in (0, 1) or not {"main", "daily"} <= after.keys() or reported:
        kind = freshclam_problem_kind(lines)
        problem = freshclam_problem(lines) or (
            f"ClamAV's updater stopped with error code {code}. The signatures you have are kept. "
            f"Details are in {settings.log_dir / 'freshclam.log'}.")
        retry_at = 0.0
        if kind in ("rate_limit", "blocked"):
            retry_at = _cooldown_until(lines) or now + (
                RATE_LIMIT_BACKOFF if kind == "rate_limit" else BLOCKED_BACKOFF)
            _save_freshclam_record(settings, {"last_run": now, "retry_at": retry_at,
                                              "reason": problem.split(" The signatures")[0]})
            problem = problem.split(" Try again")[0] + f" Next try after {_clock(retry_at)}."
        raise FetchError(problem, kind=kind, retry_at=retry_at)
    return before, after


def _run_streaming(cmd: list[str], timeout: float, on_line) -> tuple[int, list[str]]:
    """Run without a console window; hand every output line to on_line; kill at the timeout."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
                            text=True, encoding="utf-8", errors="replace")
    lines: queue.Queue = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(x) for x in proc.stdout], daemon=True)
    reader.start()
    seen: list[str] = []
    deadline = time.monotonic() + timeout
    while reader.is_alive() or not lines.empty():
        try:
            line = lines.get(timeout=0.5).rstrip()
        except queue.Empty:
            if time.monotonic() > deadline:
                proc.kill()
                raise FetchError("ClamAV's updater took longer than 30 minutes, so it was stopped. "
                                 "The signatures you have are kept.")
            continue
        if line:
            seen.append(line)
            on_line(line)
    return proc.wait(), seen


def fetch_clamav_signatures(settings, progress=print) -> dict:
    return _guarded(_fetch_clamav_signatures, settings, progress)


def _fetch_clamav_signatures(settings, progress) -> dict:
    from .detect.clamav import describe_databases

    prog = settings.clamav_program_dir
    db = settings.clamav_db_dir
    before, after = run_freshclam(settings, db, progress)
    progress("Checking the ClamAV signature files with ClamAV's sigtool...")
    _verify_databases(prog, db, after)
    return _result(True, describe_databases(after) + " Signatures verified by ClamAV.",
                   databases_changed(before, after))


def databases_changed(before: dict, after: dict) -> bool:
    return {k: v.get("version") for k, v in before.items()} != \
           {k: v.get("version") for k, v in after.items()}


IDLE_PRIORITY_CLASS = 0x00000040


def clamscan_test(settings, db_dir: Path, timeout: float = 900) -> bool:
    """Load the signature set in db_dir with ClamAV's clamscan and scan one tiny harmless file.
    True when it loaded; False when clamscan.exe is not there (the test was skipped). Raises
    FetchError when the set does not load."""
    prog = settings.clamav_program_dir
    exe = prog / "clamscan.exe"
    if not exe.exists():
        return False
    probe = Path(settings.tmp_dir) / "tacoguard-update-probe.txt"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_bytes(b"TacoGuard checks that new ClamAV signatures load. Harmless text.\n")
    cmd = [str(exe), f"--database={db_dir}", "--no-summary", "--stdout", str(probe)]
    if (prog / "certs").is_dir():
        cmd.insert(1, f"--cvdcertsdir={prog / 'certs'}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(prog),
                           creationflags=CREATE_NO_WINDOW | IDLE_PRIORITY_CLASS)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FetchError("ClamAV could not test-load the new signatures, so the signatures you "
                         "have are kept.") from e
    finally:
        probe.unlink(missing_ok=True)
    if r.returncode not in (0, 1):                 # 0 = clean, 1 = found, 2 = could not load
        raise FetchError("The new ClamAV signatures did not load in ClamAV's own test, so the "
                         "signatures you have are kept.")
    return True


def verify_databases(prog: Path, db: Path, info: dict) -> None:
    """sigtool --info on main/daily/bytecode; raises FetchError when one does not verify."""
    _verify_databases(prog, db, info)


def _verify_databases(prog: Path, db: Path, info: dict) -> None:
    for name, meta in info.items():
        if name not in ("main", "daily", "bytecode"):
            continue
        try:
            r = subprocess.run([str(prog / "sigtool.exe"), f"--info={meta['path']}"],
                               capture_output=True, text=True, timeout=600,
                               creationflags=CREATE_NO_WINDOW, cwd=str(prog))
        except (OSError, subprocess.TimeoutExpired) as e:
            raise FetchError(f"Could not check the ClamAV {name} signatures: {e}.") from e
        if r.returncode != 0 or "Verification OK" not in r.stdout:
            raise FetchError(f"ClamAV's sigtool could not verify the {name} signatures. They will be "
                             "downloaded again next time.")


# ---------------------------------------------------------------------------------------------
# YARA Forge rules
# ---------------------------------------------------------------------------------------------

def fetch_yara_rules(settings, progress=print) -> dict:
    return _guarded(_fetch_yara_rules, settings, progress)


def yara_latest_release() -> dict:
    """{"tag", "url", "sha256", "published"} of the newest YARA Forge core package (GitHub API)."""
    release = _http_json(FORGE_RELEASE_API)
    url, digest = _asset_digest(release, FORGE_ASSET)
    return {"tag": str(release.get("tag_name") or ""), "url": url, "sha256": digest,
            "published": str(release.get("published_at") or "")}


def yara_is_current(settings, release: dict) -> bool:
    from .detect import yara_rules

    current = settings.yara_dir / "current"
    old = yara_rules.read_meta(current)
    return old.get("release") == release["tag"] and old.get("sha256") == release["sha256"] and \
        (current / yara_rules.PACKAGE_NAME).exists()


def stage_yara_rules(settings, release: dict, new: Path, progress) -> dict:
    """Download (checksum-verified), license-filter and test-compile a YARA Forge release into the
    NEW folder `new` (removed first). Returns its meta. On any failure `new` is removed and a
    FetchError explains; the rules in use are never touched."""
    from .detect import yara_rules

    tag, digest = release["tag"], release["sha256"]
    zip_path = _download(release["url"], settings.tmp_dir / f"yara-forge-{tag}-core.zip", digest,
                         progress, f"YARA Forge rules {tag}")
    _remove_tree(new)
    try:
        progress("Removing rules whose license does not allow TacoGuard to use them...")
        meta = yara_rules.install_package(zip_path, new, release=tag, sha256=digest,
                                          published=release.get("published", ""))
        progress(f"Test-loading {meta['kept']} YARA rules...")
        yara_rules.compile_folder(new)       # also writes the compiled cache for a fast start
    except (yara_rules.yara_x.CompileError, ValueError, zipfile.BadZipFile) as e:
        shutil.rmtree(new, ignore_errors=True)
        zip_path.unlink(missing_ok=True)
        first = str(e).splitlines()[0] if str(e) else type(e).__name__
        raise FetchError(f"The new YARA rules did not load ({first}), so the rules you have are "
                         "kept.") from e
    except BaseException:
        shutil.rmtree(new, ignore_errors=True)
        raise
    zip_path.unlink(missing_ok=True)
    return meta


def yara_installed_words(meta: dict) -> str:
    dropped = ", ".join(s["name"] for s in meta["sources"] if s["kept"] == 0)
    return (f"YARA Forge rules {meta['release']} installed: {meta['kept']} rules kept, "
            f"{meta['dropped']} left out because of their license"
            + (f" ({dropped})" if dropped else "") + ".")


def _fetch_yara_rules(settings, progress) -> dict:
    current = settings.yara_dir / "current"
    progress("Checking for the newest YARA Forge rule release...")
    release = yara_latest_release()
    if yara_is_current(settings, release):
        return _result(True, f"YARA Forge rules {release['tag']} are already the newest.")
    new = settings.yara_dir / "new"
    meta = stage_yara_rules(settings, release, new, progress)
    try:
        swap_folders(new, current, settings.yara_dir / "previous", keep_previous=True)
    except BaseException:
        shutil.rmtree(new, ignore_errors=True)
        raise
    return _result(True, yara_installed_words(meta), changed=True)
