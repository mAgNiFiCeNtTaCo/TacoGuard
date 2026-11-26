"""The bad-website lists: download, check, swap, load (contract: tacoguard/phase4.py, "Website blocking").

Sources
    phishing   Phishing.Database "active" phishing domains (MIT license, Mitchell Krog and
               contributors), https://phish.co.za/latest/phishing-domains-ACTIVE.txt. No key.
    urlhaus    URLhaus (abuse.ch) websites that spread malware, downloaded with YOUR free abuse.ch key
               (tacoguard.secrets.get_key(settings, "abusech")). The key sits in the download address
               (abuse.ch's own design), so it is never written to a log, an error or a status message.
               abuse.ch asks for at most one download every 5 minutes; TacoGuard waits at least 30.

Every download is checked before use: it must be text (not a web page), have website names in it,
not shrink to less than half of the last good list, and mostly consist of valid names. Names are
lower-cased, converted to their xn-- (IDNA) form, and dropped when they are an IP address, a bare
top-level domain, a wildcard, or a PROTECTED domain (Windows Update, Microsoft, Google, GitHub,
abuse.ch, TacoGuard's own download hosts...). A protected name drops only that name, never the
whole list. A refused download keeps the last good list.

Memory: a Python set of ~400,000 domain strings costs ~45 MB, so the guard keeps only a sorted
array of 8-byte blake2b hashes (3 MB for 400,000 names, written at refresh time as domains.bin) and
looks names up with bisect. A lookup checks the name and each parent (a.b.evil.com -> b.evil.com
-> evil.com).
"""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from array import array
from pathlib import Path

from .. import setup_fetch
from ..config import ENDPOINTS

log = logging.getLogger("tacoguard.webblock")

SOURCE_NAMES = ("urlhaus", "phishing")        # malware sites first: they win when a name is on both
LABELS = {"phishing": "phishing list (Phishing.Database)",
          "urlhaus": "malware-site list (URLhaus)"}
KIND = {"phishing": "phishing", "urlhaus": "malware"}

PHISH_URL = "https://phish.co.za/latest/phishing-domains-ACTIVE.txt"
# The same file on GitHub (raw.githubusercontent.com is on config.ENDPOINTS), tried when phish.co.za fails.
PHISH_MIRROR = ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                "phishing-domains-ACTIVE.txt")
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v2/files/exports/"
# Export names, in the order tried. abuse.ch shows the exact names only to logged-in users; the
# host file (domains of active malware sites and those added in the last 48 h, without domains in
# the Tranco top 1M) is the best fit; recent.csv (URLs added in the last 30 days) is the one the
# public page names. The first that answers is remembered in state.json.
URLHAUS_FILES = ("hostfile.txt", "recent.csv")

MIN_INTERVAL_S = 30 * 60                       # never contact a list server more often than this
MAX_DOWNLOAD = 50 * 1024**2
DOWNLOAD_LIMIT_S = 10 * 60
MAX_INVALID_SHARE = 0.10                       # more lines than this that are not names: refused
SHRINK_LIMIT = 0.5
KEY_RX = re.compile(r"^[A-Za-z0-9_\-]{16,128}$")
NO_KEY_MSG = "Add your free abuse.ch key in Settings to use URLhaus."

# Never blocked: the name and everything under it.
PROTECTED = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "office.net",
    "microsoftonline.com", "msn.com", "bing.com", "skype.com", "xbox.com", "azure.com", "azureedge.net",
    "msftconnecttest.com", "msftncsi.com", "sharepoint.com", "onedrive.com", "outlook.com", "1drv.ms",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "gmail.com",
    "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org",
    "abuse.ch", "phish.co.za", "clamav.net", "cloudflare.com", "cloudflare-dns.com", "apple.com",
    "icloud.com", "amazon.com", "amazonaws.com", "cloudfront.net", "akamai.net", "akamaized.net",
    "akamaihd.net", "fastly.net", "mozilla.org", "mozilla.net", "firefox.com", "digicert.com",
    "letsencrypt.org", "globalsign.com", "sectigo.com", "verisign.com", "python.org", "pypi.org",
    "pythonhosted.org", "discord.com", "discordapp.com", "discordapp.net", "dropbox.com",
    "dropboxusercontent.com", "wikipedia.org", "steampowered.com", "steamcommunity.com",
    "facebook.com", "whatsapp.com", "instagram.com", "yahoo.com", "duckduckgo.com",
    # added 2026-11-26 (review): Microsoft sign-in, Edge, Office and Defender / SmartScreen hosts
    # (smartscreen.microsoft.com and *.smartscreen-prod.microsoft.com sit under microsoft.com),
    # certificate checks (OCSP / CRL), a big link shortener, payments, Apple and Steam
    "aka.ms", "msedge.net", "a-msedge.net", "b-msedge.net", "c-msedge.net", "e-msedge.net", "l-msedge.net",
    "s-msedge.net", "t-msedge.net", "office365.com", "microsoft365.com", "msftauth.net", "msauth.net",
    "msocsp.com", "live.net", "lencr.org", "pki.goog", "bit.ly", "paypal.com", "paypalobjects.com",
    "mzstatic.com", "cdn-apple.com", "apple-cloudkit.com", "icloud-content.com", "steamstatic.com",
    "steamcontent.com", "steamserver.net",
})
# Shared hosting: the bare name is never blocked, a site under it (evil.pages.dev) may be.
SHARED_PARENTS = frozenset({
    "github.io", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "blogspot.com",
    "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "r2.dev", "glitch.me",
    "weebly.com", "wixsite.com", "000webhostapp.com", "ngrok-free.app", "ngrok.io", "duckdns.org",
    "appspot.com", "windows.net", "web.core.windows.net", "sites.google.com", "s3.amazonaws.com",
    "translate.goog", "ipfs.io", "replit.dev", "repl.co", "onrender.com", "fly.dev", "surge.sh",
    "myshopify.com", "square.site", "godaddysites.com", "webflow.io", "framer.app", "notion.site",
})
# Second-level labels that make "co.uk" style public suffixes (never a site of its own).
_SUFFIX_SLD = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil",
                         "nic", "ltd", "plc", "sch", "nom", "info", "biz"})
_URL_HOST_RX = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


class ListRefused(Exception):
    """A download that failed a check; plain words (the last good list is kept)."""


# ---------------------------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------------------------

def _endpoint_hosts() -> set[str]:
    out = set()
    for entry in ENDPOINTS:
        for h in str(entry.get("host", "")).split(","):
            if h.strip():
                out.add(h.strip().lower().rstrip("."))
    return out


_ENDPOINT_FULL = frozenset(_endpoint_hosts())
_ENDPOINT_EXACT = frozenset(p for h in _ENDPOINT_FULL for p in
                            (".".join(h.split(".")[i:]) for i in range(1, len(h.split(".")) - 1)))


def parents(name: str):
    """"a.b.evil.com" -> a.b.evil.com, b.evil.com, evil.com (never the bare top-level domain)."""
    labels = name.split(".")
    for i in range(0, max(1, len(labels) - 1)):
        yield ".".join(labels[i:])


_ALWAYS = PROTECTED | _ENDPOINT_FULL


def is_protected(name: str) -> bool:
    """True for a name TacoGuard never blocks (see PROTECTED / SHARED_PARENTS / ENDPOINTS)."""
    if name in SHARED_PARENTS or name in _ENDPOINT_EXACT or name in _ALWAYS:
        return True
    i = name.find(".")
    while i >= 0:
        rest = name[i + 1:]
        if "." not in rest:
            return False
        if rest in _ALWAYS:
            return True
        i = name.find(".", i + 1)
    return False


_IPV4_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NAME_RX = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
                      r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


def is_ip(text: str) -> bool:
    t = text.strip("[]")
    if ":" not in t:
        if not _IPV4_RX.match(t):
            return False                  # fast path: most names are not IPs
    elif "%" in t:
        t = t.split("%", 1)[0]
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def normalize(text: str) -> str | None:
    """A valid website name in lower-case IDNA form, or None (IPs, wildcards, bare TLDs and
    malformed names give None). Protection is checked separately (is_protected)."""
    name = (text or "").strip().lower().rstrip(".")
    if not name or "*" in name:
        return None
    # Python's "idna" codec is IDNA 2003, whose mapping changes some names into OTHER names
    # ("faß.de" -> "fass.de", full-width letters -> ASCII). Such a name is dropped instead of
    # blocking a different site: only names already in ASCII, or whose round trip is exact, stay.
    if not name.isascii():
        try:
            ascii_name = name.encode("idna").decode("ascii")
            back = ascii_name.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return None
        if back != name:
            return None
        name = ascii_name
    elif "xn--" in name:
        try:
            back = name.encode("ascii").decode("idna")
            if back.encode("idna").decode("ascii") != name:
                return None
        except (UnicodeError, ValueError):
            return None
    if len(name) > 253 or not _NAME_RX.match(name):
        return None                       # also IPs, bare TLDs and numeric TLDs
    dot = name.find(".")
    if dot == name.rfind(".") and name[:dot] in _SUFFIX_SLD and len(name) - dot - 1 == 2:
        return None                       # "co.uk": a public suffix, not a site
    return name


def domain_hash(name: str) -> int:
    return int.from_bytes(hashlib.blake2b(name.encode("ascii"), digest_size=8).digest(), "little")


# ---------------------------------------------------------------------------------------------
# Parsing a download
# ---------------------------------------------------------------------------------------------

def _host_of(token: str) -> str:
    """The host of a URL-ish token ("http://user@evil.com:8080/x" -> "evil.com")."""
    rest = _URL_HOST_RX.sub("", token, count=1)
    rest = re.split(r"[/?#\\]", rest, maxsplit=1)[0]
    rest = rest.rsplit("@", 1)[-1]
    if rest.startswith("["):
        return rest.split("]", 1)[0] + "]"
    return rest.split(":", 1)[0]


def _decode(raw: bytes, label: str) -> str:
    head = raw[:65536]
    if b"\x00" in head:
        raise ListRefused(f"The {label} download wasn't a text list, so TacoGuard kept the last good list.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ListRefused(f"The {label} download wasn't a text list, so TacoGuard kept the last "
                          "good list.") from None
    start = text.lstrip()[:200].lower()
    if start.startswith("<") or "<html" in start:
        raise ListRefused(f"The {label} server sent a web page instead of the list, so TacoGuard kept "
                          "the last good list.")
    return text


def _csv_hosts(lines: list[str], stats: dict):
    """URLhaus CSV: '"id","dateadded","url","url_status",...'. Only rows still "online" count."""
    import csv
    url_i, status_i = 2, 3
    for line in lines:
        s = line.strip()
        if s.startswith("#"):
            cols = [c.strip().lower() for c in s.lstrip("#").split(",")]
            if "url" in cols:
                url_i = cols.index("url")
                status_i = cols.index("url_status") if "url_status" in cols else -1
            continue
        if not s:
            continue
        try:
            row = next(csv.reader([s]))
        except (csv.Error, StopIteration):
            stats["invalid"] += 1
            continue
        if len(row) <= url_i:
            stats["invalid"] += 1
            continue
        if status_i >= 0 and len(row) > status_i and row[status_i].strip().lower() not in ("online", ""):
            stats["offline"] += 1
            continue
        yield _host_of(row[url_i].strip())


def _plain_hosts(lines: list[str], stats: dict):
    """Plain domains, host-file lines ("0.0.0.0 evil.com") or one URL per line."""
    for line in lines:
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) >= 2 and is_ip(parts[0]):
            for p in parts[1:]:
                yield p
            continue
        yield _host_of(parts[0]) if "://" in parts[0] else parts[0]


def _iter_lines(text: str):
    """The lines of `text`, one at a time (str.splitlines or StringIO would hold a copy of all)."""
    start, n = 0, len(text)
    while start < n:
        end = text.find("\n", start)
        if end < 0:
            end = n
        yield text[start:end]
        start = end + 1


def parse(raw: bytes, label: str = "list") -> tuple[list[str], dict]:
    """(unique valid names in file order, counts) from a downloaded list. Raises ListRefused."""
    text = _decode(raw, label)
    stats = {"lines": 0, "invalid": 0, "ip": 0, "protected": 0, "offline": 0, "duplicate": 0}
    first = ""
    for ln in _iter_lines(text):
        s = ln.strip()
        if s and not s.startswith("#"):
            first = s
            break
    is_csv = first.startswith('"') and '","' in first
    lines = _iter_lines(text)                         # one line at a time (no list of 400k lines)
    hosts = _csv_hosts(lines, stats) if is_csv else _plain_hosts(lines, stats)
    out: list[str] = []
    seen: set[str] = set()                            # shares the strings kept in `out`
    for host in hosts:
        stats["lines"] += 1
        if is_ip(host):
            stats["ip"] += 1
            continue
        name = normalize(host)
        if name is None:
            stats["invalid"] += 1
            continue
        if is_protected(name):
            stats["protected"] += 1
            continue
        if name in seen:
            stats["duplicate"] += 1
            continue
        seen.add(name)
        out.append(name)
    del seen
    total = stats["lines"] + (stats["invalid"] if is_csv else 0)
    if total and stats["invalid"] > max(100, MAX_INVALID_SHARE * total):
        raise ListRefused(f"Too many lines of the {label} download weren't website names "
                          f"({stats['invalid']:,} of {total:,}), so TacoGuard kept the last good list.")
    if not out:
        raise ListRefused(f"The {label} download had no website names in it, so TacoGuard kept the "
                          "last good list.")
    return out, stats


# ---------------------------------------------------------------------------------------------
# DomainSet
# ---------------------------------------------------------------------------------------------

def _sorted_hashes(names) -> array:
    """Sorted, without repeats (two names with the same hash would count once; with 8-byte
    hashes and a few hundred thousand names that practically never happens)."""
    hashes = sorted(set(map(domain_hash, names)))
    return array("Q", hashes)


class DomainSet:
    """Lean membership test for the lists: {source: sorted array('Q') of name hashes}."""

    def __init__(self, parts: dict[str, array] | None = None, meta: dict | None = None):
        self.parts = {k: v for k, v in (parts or {}).items() if v is not None}
        self.meta = meta or {}

    @classmethod
    def from_domains(cls, lists: dict[str, list[str]]) -> "DomainSet":
        return cls({k: _sorted_hashes(v) for k, v in lists.items()})

    @staticmethod
    def _has(arr: array, h: int) -> bool:
        i = bisect.bisect_left(arr, h)
        return i < len(arr) and arr[i] == h

    def match(self, name: str) -> tuple[str, str] | None:
        """(source, the listed name: the name itself or a parent) or None. URLhaus first."""
        n = (name or "").strip().lower().rstrip(".")
        if not n:
            return None
        if not n.isascii():
            n = normalize(n) or ""
            if not n:
                return None
        if is_protected(n):
            return None
        order = [s for s in SOURCE_NAMES if s in self.parts] + \
            [s for s in self.parts if s not in SOURCE_NAMES]
        for p in parents(n):
            h = domain_hash(p)
            for src in order:
                if self._has(self.parts[src], h):
                    return src, p
        return None

    def __contains__(self, name: str) -> bool:
        return self.match(name) is not None

    def count(self, source: str | None = None) -> int:
        if source is not None:
            return len(self.parts.get(source, ()))
        return sum(len(v) for v in self.parts.values())

    def __len__(self) -> int:
        return self.count()

    @property
    def nbytes(self) -> int:
        return sum(v.itemsize * len(v) for v in self.parts.values())


# ---------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------

def _dir(settings) -> Path:
    return Path(settings.webblock_dir)


def current_dir(settings, source: str) -> Path:
    return _dir(settings) / "current" / source


def previous_dir(settings, source: str) -> Path:
    return _dir(settings) / "previous" / source


def _read_json(path: Path) -> dict:
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def _sha256_file(path: Path) -> str:
    return setup_fetch.sha256_file(path)


def read_meta(settings, source: str, which: str = "current") -> dict:
    folder = current_dir(settings, source) if which == "current" else previous_dir(settings, source)
    return _read_json(folder / "meta.json")


def _load_hashes(folder: Path) -> tuple[array | None, dict]:
    meta = _read_json(folder / "meta.json")
    try:
        raw = (folder / "domains.bin").read_bytes()
    except OSError:
        return None, {}
    if not meta or hashlib.sha256(raw).hexdigest() != meta.get("bin_sha256") or len(raw) % 8:
        return None, {}
    arr = array("Q")
    arr.frombytes(raw)
    return arr, meta


def _source_on(settings, source: str) -> bool:
    if source == "phishing":
        return bool(getattr(settings, "webblock_phishing_list", True))
    if source == "urlhaus":
        return bool(getattr(settings, "webblock_urlhaus_list", True))
    return False


def load(settings) -> DomainSet:
    """The lists in use (current, or previous when current is damaged), switched-off lists left out."""
    parts, metas = {}, {}
    for src in SOURCE_NAMES:
        if not _source_on(settings, src):
            continue
        for folder in (current_dir(settings, src), previous_dir(settings, src)):
            arr, meta = _load_hashes(folder)
            if arr is not None:
                parts[src], metas[src] = arr, meta
                break
    return DomainSet(parts, metas)


def stamp(settings) -> tuple:
    """Changes whenever a list is swapped (cheap: two stat calls per source)."""
    out = []
    for src in SOURCE_NAMES:
        for folder in (current_dir(settings, src), previous_dir(settings, src)):
            try:
                out.append((src, folder.name, (folder / "meta.json").stat().st_mtime_ns))
            except OSError:
                out.append((src, folder.name, 0))
    out.append(("switches", _source_on(settings, "phishing"), _source_on(settings, "urlhaus")))
    return tuple(out)


def read_domains(settings, source: str, expected_sha256: str | None = None) -> list[str]:
    """The names of a current list (for the hosts file), checked against its meta (or the given
    sha256). Raises ListRefused when the file does not match."""
    folder = current_dir(settings, source)
    meta = _read_json(folder / "meta.json")
    want = expected_sha256 or meta.get("sha256")
    path = folder / "domains.txt"
    try:
        raw = path.read_bytes()
    except OSError:
        raise ListRefused(f"The {LABELS.get(source, source)} has not been downloaded yet.") from None
    if not want or hashlib.sha256(raw).hexdigest() != want:
        raise ListRefused(f"The saved {LABELS.get(source, source)} doesn't match its checksum, so it "
                          "was not used.")
    return [ln for ln in raw.decode("ascii", errors="replace").split("\n") if ln]


# ---------------------------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------------------------

def http_open(url: str, headers: dict | None = None):
    """setup_fetch's checked HTTPS opener (hosts limited to config.ENDPOINTS, timeouts). Tests
    replace this function; while pytest runs the real one never goes on the internet."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise setup_fetch.FetchError("Tests never download the website lists.", kind="offline")
    return setup_fetch._open(url, headers)


def _mask(text: str, key: str | None) -> str:
    text = str(text or "")
    if key:
        text = text.replace(key, "(your key)")
    return text


def _download(url: str, dest: Path, label: str) -> bytes:
    dest.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    total = 0
    with http_open(url) as resp:
        with open(dest, "wb") as out:
            while True:
                block = resp.read(64 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_DOWNLOAD:
                    raise setup_fetch.FetchError(
                        f"The {label} download was bigger than {MAX_DOWNLOAD // 1024**2} MB, so it was "
                        "thrown away and the last good list kept.", kind="too_big")
                if time.monotonic() - started > DOWNLOAD_LIMIT_S:
                    raise setup_fetch.FetchError(setup_fetch.TOO_SLOW_DOWNLOAD, kind="too_slow")
                out.write(block)
    return dest.read_bytes()


def _order_newest_first(new: list[str], new_hashes: array, prev_folder: Path) -> list[str]:
    """Names not in the last list first (newest), then the rest in the last list's order. The
    hosts file takes the first 100,000, so the newest sites get blocked first."""
    prev_hashes, _ = _load_hashes(prev_folder)
    if prev_hashes is None or not len(prev_hashes):
        return new
    fresh = [n for n in new if not DomainSet._has(prev_hashes, domain_hash(n))]
    rest = []
    try:
        with open(prev_folder / "domains.txt", "r", encoding="ascii", errors="replace") as f:
            for line in f:
                n = line.strip()
                if n and DomainSet._has(new_hashes, domain_hash(n)):
                    rest.append(n)
    except OSError:
        return new
    out = fresh + rest
    return out if len(out) == len(new) else new


def _swap(settings, source: str, new: Path) -> None:
    cur, prev = current_dir(settings, source), previous_dir(settings, source)
    cur.parent.mkdir(parents=True, exist_ok=True)
    prev.parent.mkdir(parents=True, exist_ok=True)
    trash = prev.with_name(prev.name + ".trash")
    shutil.rmtree(trash, ignore_errors=True)
    if prev.exists():
        os.replace(prev, trash)
    had = cur.exists()
    if had:
        os.replace(cur, prev)
    try:
        os.replace(new, cur)
    except OSError:
        if had and prev.exists() and not cur.exists():
            os.replace(prev, cur)
            if trash.exists():
                os.replace(trash, prev)
        raise
    shutil.rmtree(trash, ignore_errors=True)


def install_list(settings, source: str, raw: bytes, fetched: float | None = None) -> dict:
    """Check a downloaded list and, when it passes, swap it in. Returns {"changed", "count",
    "message", "dropped"}; raises ListRefused (the last good list stays)."""
    label = LABELS[source]
    raw_sha = hashlib.sha256(raw).hexdigest()
    old = read_meta(settings, source)
    if old and old.get("raw_sha256") == raw_sha and (current_dir(settings, source) / "domains.bin").exists():
        return {"changed": False, "count": int(old.get("count") or 0), "dropped": old.get("dropped", {}),
                "message": f"The {label} is up to date ({int(old.get('count') or 0):,} sites)."}
    names, stats = parse(raw, label)
    old_count = int(old.get("count") or 0)
    if old_count and len(names) < SHRINK_LIMIT * old_count:
        raise ListRefused(f"The new {label} has far fewer sites than the last one ({len(names):,} "
                          f"instead of {old_count:,}), so TacoGuard kept the last good list.")
    hashes = _sorted_hashes(names)
    names = _order_newest_first(names, hashes, current_dir(settings, source))
    stage = _dir(settings) / "staging" / f"{source}-{uuid.uuid4().hex[:12]}"     # unique per run
    stage.mkdir(parents=True)
    try:
        txt = ("\n".join(names) + "\n").encode("ascii")
        binary = hashes.tobytes()
        (stage / "domains.txt").write_bytes(txt)
        (stage / "domains.bin").write_bytes(binary)
        dropped = {k: v for k, v in stats.items() if k in ("invalid", "ip", "protected", "offline",
                                                           "duplicate") and v}
        meta = {"source": source, "count": len(names), "sha256": hashlib.sha256(txt).hexdigest(),
                "bin_sha256": hashlib.sha256(binary).hexdigest(), "raw_sha256": raw_sha,
                "fetched": float(fetched or time.time()), "dropped": dropped}
        _write_json(stage / "meta.json", meta)
        _swap(settings, source, stage)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    note = f" ({dropped['protected']:,} protected names left out)" if dropped.get("protected") else ""
    return {"changed": True, "count": len(names), "dropped": dropped,
            "message": f"The {label} was updated: {len(names):,} sites{note}."}


# ---------------------------------------------------------------------------------------------
# Refresh (the updater's component "web_lists")
# ---------------------------------------------------------------------------------------------

def _state_path(settings) -> Path:
    return _dir(settings) / "state.json"


def _get_key(settings) -> str | None:
    try:
        from .. import secrets as tg_secrets           # Helper N's module (may not exist yet)
    except ImportError:
        return None
    try:
        key = tg_secrets.get_key(settings, "abusech")
    except Exception:
        return None
    key = (key or "").strip()
    return key or None


def _clock(epoch: float) -> str:
    return time.strftime("%H:%M", time.localtime(epoch))


def _source_result(state: str, message: str, count: int = 0, changed: bool = False) -> dict:
    return {"state": state, "message": message, "count": int(count), "changed": bool(changed)}


def _fetch_source(settings, source: str, urls: list[str], key: str | None, progress) -> tuple[bytes, str]:
    """(bytes, the export name that answered). Tries each URL; a 404 moves on to the next."""
    label = LABELS[source]
    hosts = setup_fetch.allowed_hosts()
    last: Exception | None = None
    tried = 0
    part = _dir(settings) / "staging" / f"{source}-{uuid.uuid4().hex[:12]}.download"    # unique per run
    for url in urls:
        from urllib.parse import urlsplit
        if (urlsplit(url).hostname or "").lower() not in hosts:
            continue
        tried += 1
        progress(f"Downloading the {label}...")
        try:
            raw = _download(url, part, label)
            return raw, url.rsplit("/", 1)[-1]
        except setup_fetch.FetchError as e:
            last = e
            if e.kind == "http" and e.code == 404:
                continue
            if e.kind == "offline" and url != urls[-1]:
                continue                                # a mirror may still answer
            if source == "phishing" and url != urls[-1]:
                # phish.co.za refused or failed (seen 2026-11-26: 503, then 403): the same list
                # on GitHub may still answer. (URLhaus: other errors are about the key; stop.)
                continue
            raise
        finally:
            try:
                part.unlink(missing_ok=True)
            except OSError:
                pass
    if last is not None:
        raise last
    if not tried:
        raise setup_fetch.FetchError(f"No allowed address for the {label}.", kind="")
    raise setup_fetch.FetchError(f"The {label} could not be downloaded.")


def _refresh_one(settings, source: str, state: dict, progress, now: float) -> dict:
    label = LABELS[source]
    st = state.setdefault(source, {})
    meta = read_meta(settings, source)
    have = int(meta.get("count") or 0)
    key = None
    if source == "urlhaus":
        key = _get_key(settings)
        if not key:
            return _source_result("no_key", NO_KEY_MSG, have)
        if not KEY_RX.match(key):
            return _source_result("error", "Your abuse.ch key doesn't look right (it should be letters "
                                           "and numbers only). Check it in Settings.", have)
    last = float(st.get("last_contact") or 0)
    if last and now - last < MIN_INTERVAL_S:
        msg = (f"The {label} was checked less than 30 minutes ago; next check after "
               f"{_clock(last + MIN_INTERVAL_S)}.")
        if have:
            msg = f"{have:,} sites in the {label}. " + msg
        return _source_result("ok", msg, have)
    if source == "phishing":
        urls = [PHISH_URL, PHISH_MIRROR]
    else:
        known = st.get("export")
        names = ([known] if known in URLHAUS_FILES else []) + [n for n in URLHAUS_FILES if n != known]
        urls = [URLHAUS_BASE + key + "/" + n for n in names]
    try:
        raw, export = _fetch_source(settings, source, urls, key, progress)
        st["last_contact"] = now
        if source == "urlhaus":
            st["export"] = export
        progress(f"Checking the {label}...")
        res = install_list(settings, source, raw, fetched=now)
        return _source_result("ok", res["message"], res["count"], res["changed"])
    except setup_fetch.FetchError as e:
        if e.kind != "offline":
            st["last_contact"] = now                    # the server answered: counts for the limit
        if e.kind == "offline":
            msg = (f"No internet: using the {label} from {_day(meta.get('fetched'))}." if have else
                   f"No internet: the {label} has not been downloaded yet.")
            return _source_result("offline", msg, have)
        if source == "urlhaus" and e.kind == "http" and e.code in (401, 403):
            return _source_result("error", "abuse.ch did not accept your key. Check it in Settings "
                                           "(auth.abuse.ch shows your key).", have)
        if e.kind == "http" and e.code == 429:
            return _source_result("error", f"The {label} server asked TacoGuard to wait; it tries "
                                           "again at the next update check.", have)
        return _source_result("error", _mask(str(e), key), have)
    except ListRefused as e:
        return _source_result("refused", str(e), have)
    except OSError as e:
        from ..model import plain_error
        return _source_result("error", f"Could not save the {label} ({plain_error(e)}). The last good "
                                       "list is kept.", have)
    except Exception as e:                              # never raise, never show raw text
        log.warning("%s refresh failed: %s", source, _mask(type(e).__name__, key))
        return _source_result("error", f"Something unexpected went wrong with the {label}. The last "
                                       "good list is kept.", have)


def _day(epoch) -> str:
    try:
        return time.strftime("%Y-%m-%d", time.localtime(float(epoch))) if epoch else "an earlier day"
    except (TypeError, ValueError, OverflowError):
        return "an earlier day"


REFRESH_LOCK_NAME = "refresh.lock"
REFRESH_LOCK_STALE_S = 30 * 60          # a lock file older than this was left by a run that died
BUSY_MSG = ("The website lists are being updated right now (by another part of TacoGuard). Try again "
            "in a few minutes.")
_refresh_lock = threading.Lock()          # one refresh at a time in this process


def _lock_path(settings) -> Path:
    return _dir(settings) / REFRESH_LOCK_NAME


def _take_file_lock(settings) -> Path | None:
    """The refresh lock between TacoGuard's processes (page, guard, updater): a file made with
    O_CREAT | O_EXCL. One older than 30 minutes is taken over. None when another run holds it."""
    path = _lock_path(settings)
    for attempt in (1, 2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except OSError:
                continue                                 # just went away: try again
            if attempt == 1 and age > REFRESH_LOCK_STALE_S:
                try:
                    path.unlink()
                except OSError:
                    return None
                continue
            return None
        except OSError:
            return None
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": os.getpid(), "time": time.time()}))
        return path
    return None


def busy(settings) -> bool:
    """True while a refresh runs (in this process or another TacoGuard process)."""
    if _refresh_lock.locked():
        return True
    try:
        return time.time() - _lock_path(settings).stat().st_mtime <= REFRESH_LOCK_STALE_S
    except OSError:
        return False


def refresh(settings, store=None, progress=None) -> dict:
    """Download, check and swap in each switched-on list (at most once per 30 minutes per list).
    One run at a time across TacoGuard's processes (a module lock + refresh.lock in
    settings.webblock_dir); a second one returns {"busy": True, "ok": True, "message": BUSY_MSG}.
    Never raises. Returns {"ok", "changed", "message", "busy", "sources": {name: {"state",
    "message", "count", "changed"}}}; state is ok | offline | error | refused | no_key | off."""
    out = {"ok": True, "changed": False, "message": "", "busy": False, "sources": {}}
    if not getattr(settings, "webblock_enabled", True):
        out["message"] = "Website blocking is turned off in Settings."
        out["sources"] = {s: _source_result("off", "Turned off in Settings.") for s in ("phishing", "urlhaus")}
        return out
    if not _refresh_lock.acquire(blocking=False):
        out.update(busy=True, message=BUSY_MSG)
        return out
    try:
        try:
            _dir(settings).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            from ..model import plain_error
            out.update(ok=False, message=f"Could not use the TacoGuard data folder ({plain_error(e)}).")
            return out
        lock = _take_file_lock(settings)
        if lock is None:
            out.update(busy=True, message=BUSY_MSG)
            return out
        try:
            return _refresh_locked(settings, progress, out)
        finally:
            try:
                lock.unlink(missing_ok=True)
            except OSError:
                pass
    finally:
        _refresh_lock.release()


def _clean_staging(settings, now: float) -> None:
    """Leftovers of runs that died (each run uses its own names), older than an hour."""
    try:
        entries = list((_dir(settings) / "staging").iterdir())
    except OSError:
        return
    for p in entries:
        try:
            if now - p.stat().st_mtime < 3600:
                continue
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
        except OSError:
            pass


def _refresh_locked(settings, progress, out: dict) -> dict:
    progress = progress or (lambda msg: None)
    now = time.time()
    _clean_staging(settings, now)
    state = _read_json(_state_path(settings))
    for source in ("phishing", "urlhaus"):
        if not _source_on(settings, source):
            res = _source_result("off", f"The {LABELS[source]} is turned off in Settings.")
        else:
            res = _refresh_one(settings, source, state, progress, now)
        key = _get_key(settings) if source == "urlhaus" else None
        res["message"] = _mask(res["message"], key)
        state.setdefault(source, {}).update(state=res["state"], message=res["message"], checked=now,
                                            count=res["count"])
        out["sources"][source] = res
        out["changed"] = out["changed"] or res["changed"]
    try:
        _write_json(_state_path(settings), state)
    except OSError:
        pass
    shown = [r["message"] for r in out["sources"].values() if r["state"] != "off"]
    out["message"] = " ".join(shown) or "Both website lists are turned off in Settings."
    out["ok"] = not any(r["state"] in ("error", "refused") for r in out["sources"].values())
    return out


def status(settings) -> dict:
    """What the page shows: {"enabled", "sources": {name: {"on", "count", "fetched", "state",
    "message", "label"}}, "total"}. Cheap (small JSON files), never raises."""
    state = _read_json(_state_path(settings))
    out = {"enabled": bool(getattr(settings, "webblock_enabled", True)), "sources": {}, "total": 0,
           "busy": busy(settings)}
    for src in ("phishing", "urlhaus"):
        meta = read_meta(settings, src)
        st = state.get(src) if isinstance(state.get(src), dict) else {}
        count = int(meta.get("count") or 0)
        message = str(st.get("message") or "")
        if src == "urlhaus" and not _get_key(settings):
            message = NO_KEY_MSG
            st = {**st, "state": "no_key"}
        out["sources"][src] = {"on": _source_on(settings, src), "label": LABELS[src], "kind": KIND[src],
                               "count": count, "fetched": float(meta.get("fetched") or 0),
                               "state": str(st.get("state") or ("ok" if count else "unknown")),
                               "message": message}
        if _source_on(settings, src):
            out["total"] += count
    return out
