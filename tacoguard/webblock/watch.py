"""WebWatcher: the guard part "web" (contract: tacoguard/phase4.py, "Website blocking").

Every 3 seconds it reads the names in Windows' DNS cache (dnsapi.dll DnsGetCacheDataTable: no admin
rights, no network) and looks only at names that were not in the cache at the last look. A name on
a list (or under a listed name) is a hit, unless it is one of your "never block" sites
(settings.webblock_allow), a name in TacoGuard's own hosts-file block, or a name whose cached
addresses are only 0.0.0.0 / :: (blocked already, by the hosts file or a DNS filter). For a hit it
asks the DNS cache, again without any network question (DnsQuery_W with DNS_QUERY_NO_WIRE_QUERY),
for the name's addresses, and Windows' TCP table (GetExtendedTcpTable through psutil, IPv4 + IPv6)
for the programs connected to them. A program that closed its connection before the check is
looked for again on the next two polls. At most HITS_PER_POLL hits are handled per poll (the rest
wait for the next polls).

It only REPORTS (one guard event kind "web", level "warning"); it never pauses or ends a program:
an address match is not proof, because many sites can share one address.
    phishing site     "Your PC looked up a phishing site: <domain>" (a lookup also happens for link
                      previews and prefetching, so it doesn't mean the page was opened)
    malware site      "A program was connected to a malware site's address: <program> -> <domain>",
                      or "Your PC looked up a malware site: <domain>" when no program was found
    Same domain + program: one event per 30 minutes, kept in the store (meta "web_dedupe") so a
    restart doesn't alert again.

TacoGuard changes nothing in the browser: blocking happens only in the hosts file (hosts.py) when
you turn it on. A browser using its own secure DNS (DNS over HTTPS) bypasses Windows' DNS cache, so
its visits can't be seen here; status() says so when a browser's settings show it.

Cost (measured 2026-11-26, this PC, Python 3.14; tests/test_webblock_watch.py measures it again):
a full hosts block puts 100,000 names in the DNS cache (Windows loads hosts entries into it).
Walking a 100,000-entry list takes ~0.1 s (about 1 microsecond per name, plus Windows' own
DnsFree); poll_once's own work is ~0.18 s the first time (every name hashed once against the
hosts block) and ~8 ms afterwards when nothing is new (a set difference with the last look). The
old walk through ctypes pointer objects took 350 microseconds per name at that size (35 s). The
wait between polls also grows with the time a poll took (POLL_BUDGET: at most ~1% of one core):
every 3 s with a normal cache of a few hundred names, about every 10-20 s with a full block.
Memory: the last look's names (~10 MB with 100,000 names; a few hundred KB normally).
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from array import array
from ctypes import wintypes
from pathlib import Path

from .. import phase4
from ..model import plain_error
from . import lists

log = logging.getLogger("tacoguard.guard")

POLL_S = 3.0
POLL_BUDGET = 0.01             # a poll may use about 1% of one core: wait >= 100x the time it took
MAX_WAIT_S = 120.0
RELOAD_CHECK_S = 60.0
DEDUPE_S = 30 * 60
DEDUPE_KEY = "web_dedupe"      # store meta: {"domain|program": epoch of the last event}
DEDUPE_MAX = 500
SEEN_FORGET_S = 120.0          # a name gone from the cache this long counts as new when it returns
RETRY_POLLS = 2                # a hit without a connected program is looked at again this often
HITS_PER_POLL = 20
PENDING_MAX = 500
DOH_CHECK_S = 30 * 60
EMPTY_POLLS_LIMIT = 20         # 1 minute of an empty DNS cache: it can't be read (see status())
NO_CACHE_RETRY_S = 300.0       # then look again every 5 minutes (Windows may allow it later)
SINKHOLE = frozenset({"0.0.0.0", "::"})
NO_CACHE_MSG = ("Windows doesn't let TacoGuard read its list of recently visited sites (the DNS cache) "
                "on this PC without administrator rights, so visits can't be noticed. Blocking in "
                "Windows' hosts file still works.")

BROWSERS = frozenset({
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
    "iexplore.exe", "msedgewebview2.exe", "arc.exe", "librewolf.exe", "waterfox.exe", "chromium.exe",
    "yandex.exe", "browser.exe", "floorp.exe", "zen.exe", "thorium.exe", "tor.exe", "palemoon.exe",
})

# ---- Windows DNS cache (dnsapi.dll) -----------------------------------------------------------
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_QUERY_NO_WIRE_QUERY = 0x10          # answer from the cache only, never ask a DNS server
DNS_FREE_FLAT = 0
DNS_FREE_RECORD_LIST = 1


class DNS_CACHE_ENTRY(ctypes.Structure):
    pass


DNS_CACHE_ENTRY._fields_ = [("pNext", ctypes.POINTER(DNS_CACHE_ENTRY)), ("pszName", ctypes.c_void_p),
                            ("wType", ctypes.c_ushort), ("wDataLength", ctypes.c_ushort),
                            ("dwFlags", ctypes.c_ulong)]


class DNS_RECORD_HEAD(ctypes.Structure):
    """The fixed start of DNS_RECORDW; the data (A: 4 bytes, AAAA: 16 bytes) follows it."""
    pass


DNS_RECORD_HEAD._fields_ = [("pNext", ctypes.POINTER(DNS_RECORD_HEAD)), ("pName", ctypes.c_wchar_p),
                            ("wType", ctypes.c_ushort), ("wDataLength", ctypes.c_ushort),
                            ("Flags", ctypes.c_ulong), ("dwTtl", ctypes.c_ulong),
                            ("dwReserved", ctypes.c_ulong)]
_DATA_OFFSET = ctypes.sizeof(DNS_RECORD_HEAD)   # 32 on 64-bit Windows

_dnsapi = None


def _api():
    global _dnsapi
    if _dnsapi is None:
        d = ctypes.WinDLL("dnsapi")
        d.DnsGetCacheDataTable.argtypes = [ctypes.POINTER(ctypes.POINTER(DNS_CACHE_ENTRY))]
        d.DnsGetCacheDataTable.restype = wintypes.BOOL
        d.DnsFree.argtypes = [ctypes.c_void_p, ctypes.c_int]
        d.DnsFree.restype = None
        d.DnsQuery_W.argtypes = [wintypes.LPCWSTR, ctypes.c_ushort, wintypes.DWORD, ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.POINTER(DNS_RECORD_HEAD)), ctypes.c_void_p]
        d.DnsQuery_W.restype = ctypes.c_long
        _dnsapi = d
    return _dnsapi


_NAME_OFFSET = DNS_CACHE_ENTRY.pszName.offset


def read_dns_cache() -> list[str]:
    """The names in Windows' DNS cache, lower case (no network, no admin). [] when it can't be read.

    Walks the list by raw address: following pNext through ctypes pointer objects keeps a chain
    of references that made each step slower than the last (measured 2026-11-26: 350 us per name
    at 100,000 names, against ~1 us this way)."""
    d = _api()
    head = ctypes.POINTER(DNS_CACHE_ENTRY)()
    if not d.DnsGetCacheDataTable(ctypes.byref(head)):
        return []
    names: list[str] = []
    addr = ctypes.cast(head, ctypes.c_void_p).value
    read_ptr = ctypes.c_void_p.from_address
    free = d.DnsFree
    while addr:
        nxt = read_ptr(addr).value
        name_ptr = read_ptr(addr + _NAME_OFFSET).value
        if name_ptr:
            try:
                names.append(ctypes.wstring_at(name_ptr).lower().rstrip("."))
            except (OSError, ValueError):
                pass
            free(name_ptr, DNS_FREE_FLAT)
        free(addr, DNS_FREE_FLAT)
        addr = nxt
    return names


def cached_addresses(name: str) -> set[str]:
    """The IPv4 / IPv6 addresses Windows' DNS cache holds for `name` (and its CNAME chain), without
    asking any DNS server (DNS_QUERY_NO_WIRE_QUERY)."""
    d = _api()
    out: set[str] = set()
    for qtype in (DNS_TYPE_A, DNS_TYPE_AAAA):
        res = ctypes.POINTER(DNS_RECORD_HEAD)()
        status = d.DnsQuery_W(name, qtype, DNS_QUERY_NO_WIRE_QUERY, None, ctypes.byref(res), None)
        if status != 0 or not res:
            continue
        try:
            rec = res
            while rec:
                r = rec.contents
                base = ctypes.cast(rec, ctypes.c_void_p).value + _DATA_OFFSET
                if r.wType == DNS_TYPE_A and r.wDataLength >= 4:
                    out.add(socket.inet_ntop(socket.AF_INET, ctypes.string_at(base, 4)))
                elif r.wType == DNS_TYPE_AAAA and r.wDataLength >= 16:
                    out.add(socket.inet_ntop(socket.AF_INET6, ctypes.string_at(base, 16)))
                rec = r.pNext
        finally:
            d.DnsFree(ctypes.cast(res, ctypes.c_void_p), DNS_FREE_RECORD_LIST)
    return out


def tcp_connections() -> list[tuple[int, str]]:
    """[(pid, remote address)] of every TCP connection (Windows' GetExtendedTcpTable with
    TCP_TABLE_OWNER_PID_ALL, IPv4 and IPv6, through psutil)."""
    import psutil
    out = []
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError):
        return out
    for c in conns:
        if c.raddr and c.pid:
            out.append((int(c.pid), _norm_ip(c.raddr[0])))
    return out


def _norm_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(a)
    except ValueError:
        return ip


def proc_info(pid: int) -> dict | None:
    """{"pid", "name", "exe", "create_time"} of a running program, or None."""
    import psutil
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {"pid": pid, "name": p.name(), "create_time": p.create_time()}
            try:
                info["exe"] = p.exe() or ""
            except (psutil.Error, OSError):
                info["exe"] = ""
        return info
    except (psutil.Error, OSError):
        return None


def hosts_block_hashes(hosts_path=None) -> array:
    """Sorted 8-byte hashes (lists.domain_hash) of the names in TacoGuard's hosts-file block."""
    from . import hosts as hosts_mod
    path = hosts_path if hosts_path is not None else hosts_mod.default_hosts_path()
    return array("Q", sorted({lists.domain_hash(n) for n in hosts_mod.read_block_names(path)
                              if n.isascii()}))


# ---- browsers' own secure DNS (read-only look at their settings files) --------------------------
def secure_dns_browsers() -> list[str]:
    """Browsers whose settings say they use their own secure DNS (then Windows' DNS cache does not
    see their lookups). Reads only local settings files; never raises."""
    found = []
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    chromium = {"Microsoft Edge": ("Microsoft", "Edge"), "Google Chrome": ("Google", "Chrome"),
                "Brave": ("BraveSoftware", "Brave-Browser"), "Vivaldi": ("Vivaldi",)}
    for label, parts in chromium.items():
        path = Path(local, *parts, "User Data", "Local State")
        try:
            if path.stat().st_size > 20 * 1024**2:
                continue
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            mode = str(((data.get("dns_over_https") or {}).get("mode") or "")).lower()
            if mode == "secure":
                found.append(label)
        except (OSError, ValueError, AttributeError):
            continue
    try:
        profiles = Path(roaming, "Mozilla", "Firefox", "Profiles")
        for prefs in list(profiles.glob("*/prefs.js"))[:10]:
            try:
                text = prefs.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if 'user_pref("network.trr.mode", 2)' in text or 'user_pref("network.trr.mode", 3)' in text:
                found.append("Firefox")
                break
    except OSError:
        pass
    return found


# ---- the part -----------------------------------------------------------------------------------
class WebWatcher:
    """start() / stop() / status() -> PART dict; poll_once() does one round (tests call it).

    Test hooks: dns_names() -> [names]; addresses(name) -> {ip}; connections() -> [(pid, ip)];
    proc(pid) -> {"pid", "name", "exe", "create_time"} | None; domains: a lists.DomainSet;
    hosts_path: the hosts file whose TacoGuard block is skipped (None = Windows' own);
    clock() -> epoch for the stored dedupe. `own` is accepted for older callers and not used."""

    def __init__(self, settings, store, checker=None, own: set[int] | None = None, dns_names=None,
                 addresses=None, connections=None, proc=None, domains=None, doh_check=None,
                 hosts_path=None, clock=None):
        self.settings, self.store, self.checker = settings, store, checker
        self._dns_names = dns_names or read_dns_cache
        self._addresses = addresses or cached_addresses
        self._connections = connections or tcp_connections
        self._proc = proc or proc_info
        self._doh_check = doh_check or secure_dns_browsers
        self._clock = clock or time.time
        self._fixed_domains = domains is not None
        self.domains = domains if domains is not None else lists.DomainSet()
        self._hosts_path = hosts_path
        self._block = array("Q")
        self._block_stamp = None
        self._stamp = None
        self._reload_at = 0.0
        self._prev: set[str] | None = None            # the cache's names at the last look
        self._seen: dict[str, float] = {}             # names checked lately (came back quickly: skip)
        self._prune_at = 0.0
        self._pending: dict[str, dict] = {}          # name -> {"hit": (src, dom), "tries": n}
        self._allow_src = None
        self._allow: frozenset[str] = frozenset()
        self._doh: list[str] = []
        self._doh_at = -DOH_CHECK_S
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.checked = 0
        self.hits = 0
        self.skipped_blocked = 0
        self.error = ""
        self.cache_ok = True
        self.last_poll_s = 0.0
        self._empty_polls = 0

    # ---- part interface ------------------------------------------------------------------
    def start(self) -> None:
        self._stop.clear()
        self.error = ""
        self._thread = threading.Thread(target=self._loop, name="tacoguard-web", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(10)
        self._thread = None

    def status(self) -> dict:
        part = {"state": "on", "message": "", "watched": [], "checked": int(self.checked)}
        if self.error:
            return {**part, "state": "error", "message": self.error}
        if not getattr(self.settings, "webblock_enabled", True):
            return {**part, "state": "off", "message": "Turned off in Settings."}
        n_phish, n_mal = self.domains.count("phishing"), self.domains.count("urlhaus")
        if not n_phish and not n_mal:
            msg = ("Waiting for the website lists: they download with the next update check "
                   "(press Check for updates to get them now).")
        else:
            parts = []
            if n_phish:
                parts.append(f"{n_phish:,} phishing sites")
            if n_mal:
                parts.append(f"{n_mal:,} malware sites")
            msg = "Watching for visits to " + " and ".join(parts) + ". It warns you; it never stops a program."
        if not self.cache_ok:      # a limit of this PC, not a fault: calm "off", no restarts
            return {**part, "state": "off", "message": NO_CACHE_MSG}
        if self._doh:
            msg += (" " + " and ".join(self._doh) + (" uses" if len(self._doh) == 1 else " use") +
                    " its own secure DNS, so TacoGuard can't see the sites it visits (the hosts file "
                    "block can't stop them either).")
        return {**part, "message": msg}

    # ---- loop ----------------------------------------------------------------------------
    def _loop(self) -> None:
        try:
            while not self._stop.is_set():
                t0 = time.monotonic()
                self.poll_once()
                spent = time.monotonic() - t0
                self.last_poll_s = spent
                # The cache can't be read here (see NO_CACHE_MSG): look again only now and then.
                every = POLL_S if self.cache_ok else NO_CACHE_RETRY_S
                every = max(every, min(MAX_WAIT_S, spent / POLL_BUDGET))   # a big cache: poll less often
                if self._stop.wait(max(0.5, every - spent)):
                    break
        except Exception as e:
            log.exception("The website watcher stopped")
            self.error = f"The website check stopped because of an unexpected problem ({plain_error(e)})."
        finally:
            try:
                self.store.close()
            except Exception:
                pass

    def _maybe_reload(self, now: float) -> None:
        if now < self._reload_at:
            return
        self._reload_at = now + RELOAD_CHECK_S
        if not self._fixed_domains:
            try:
                st = lists.stamp(self.settings)
                if st != self._stamp:
                    self.domains = lists.load(self.settings)
                    self._stamp = st
            except Exception:
                log.exception("Could not load the website lists")
        self._reload_block()

    def _reload_block(self) -> None:
        """TacoGuard's hosts-file block, read again only when the hosts file changed."""
        try:
            from . import hosts as hosts_mod
            path = Path(self._hosts_path) if self._hosts_path is not None else hosts_mod.default_hosts_path()
            try:
                st = path.stat()
                stamp = (st.st_mtime_ns, st.st_size)
            except OSError:
                stamp = None
            if stamp != self._block_stamp:
                self._block = hosts_block_hashes(path) if stamp else array("Q")
                self._block_stamp = stamp
        except Exception:
            log.exception("Could not read TacoGuard's block in the hosts file")

    def _maybe_doh(self, now: float) -> None:
        if now - self._doh_at < DOH_CHECK_S:
            return
        self._doh_at = now
        try:
            self._doh = list(self._doh_check() or [])
        except Exception:
            self._doh = []

    def _allowed(self, name: str) -> bool:
        src = getattr(self.settings, "webblock_allow", None) or []
        if src is not self._allow_src:
            from .hosts import allow_set
            self._allow, self._allow_src = allow_set(self.settings), src
        return bool(self._allow) and any(p in self._allow for p in lists.parents(name))

    def _in_block(self, name: str) -> bool:
        return bool(len(self._block)) and name.isascii() and lists.DomainSet._has(self._block,
                                                                                   lists.domain_hash(name))

    def poll_once(self) -> list[int]:
        """One round: new names in the DNS cache -> hits -> events. Returns the event ids written."""
        now = time.monotonic()
        self._maybe_reload(now)
        self._maybe_doh(now)
        if not getattr(self.settings, "webblock_enabled", True) or not len(self.domains):
            return []
        try:
            if phase4.protection_paused(self.store):
                return []
        except Exception:
            pass
        try:
            names = self._dns_names()
        except Exception:
            names = []
        # An empty cache for a whole minute: Windows doesn't let this account read it (seen on
        # Windows 11 build 26300: "ipconfig /displaydns" asks for administrator rights there).
        self._empty_polls = 0 if names else self._empty_polls + 1
        self.cache_ok = self._empty_polls < EMPTY_POLLS_LIMIT
        prev = self._prev
        current = set(names)
        new = current if prev is None else current - prev
        self._prev = current
        if now >= self._prune_at:
            self._prune_at = now + 30.0
            cutoff = now - SEEN_FORGET_S
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        for n in new:
            last = self._seen.get(n)
            if last is not None and now - last < SEEN_FORGET_S:
                continue                                  # gone from the cache a moment ago
            if self._in_block(n):
                self.skipped_blocked += 1                 # blocked by TacoGuard's own hosts block
                continue
            self._seen[n] = now
            self.checked += 1
            hit = self.domains.match(n)
            if hit is None or self._allowed(n):
                continue
            if n not in self._pending and len(self._pending) < PENDING_MAX:
                self._pending[n] = {"hit": hit, "tries": 0}
        events = []
        for name in list(self._pending)[:HITS_PER_POLL]:
            item = self._pending[name]
            done, ids = self._handle(name, item["hit"], last_try=item["tries"] >= RETRY_POLLS)
            events += ids
            item["tries"] += 1
            if done or item["tries"] > RETRY_POLLS:
                self._pending.pop(name, None)
        return events

    # ---- a hit -------------------------------------------------------------------------------
    def _programs_for(self, ips: set[str]) -> list[dict]:
        if not ips:
            return []
        try:
            conns = self._connections()
        except Exception:
            conns = []
        pids = sorted({pid for pid, ip in conns if _norm_ip(ip) in ips and pid not in (0, 4)})
        out = []
        for pid in pids[:10]:
            info = self._proc(pid)
            if info:
                out.append(info)
        return out

    def _handle(self, name: str, hit: tuple[str, str], last_try: bool) -> tuple[bool, list[int]]:
        source, domain = hit
        try:
            ips = {_norm_ip(a) for a in self._addresses(name)}
        except Exception:
            ips = set()
        if ips and ips <= SINKHOLE:
            self.skipped_blocked += 1                     # sent nowhere already: nothing to report
            return True, []
        progs = self._programs_for(ips)
        if not progs and not last_try:
            return False, []
        self.hits += 1
        if source == "phishing":
            eid = self._phishing_event(name, domain, progs)
            return True, [eid] if eid else []
        if not progs:
            eid = self._malware_event(name, domain, None)
            return True, [eid] if eid else []
        ids = []
        for info in progs:
            eid = self._malware_event(name, domain, info)
            if eid:
                ids.append(eid)
        return True, ids

    def _dedupe(self, domain: str, program: str) -> bool:
        """True when this domain + program had an event in the last 30 minutes (kept in the store,
        so a restart of the guard doesn't alert again)."""
        now = float(self._clock())
        key = f"{domain}|{program.lower()}"
        try:
            seen = json.loads(self.store.get_meta(DEDUPE_KEY) or "{}")
            if not isinstance(seen, dict):
                seen = {}
        except (ValueError, TypeError):
            seen = {}
        last = seen.get(key)
        if isinstance(last, (int, float)) and 0 <= now - last < DEDUPE_S:
            return True
        seen = {k: v for k, v in seen.items() if isinstance(v, (int, float)) and 0 <= now - v < DEDUPE_S}
        seen[key] = now
        if len(seen) > DEDUPE_MAX:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-DEDUPE_MAX:])
        try:
            self.store.set_meta(DEDUPE_KEY, json.dumps(seen))
        except Exception:
            pass
        return False

    def _phishing_event(self, name: str, domain: str, progs: list[dict]) -> int | None:
        who = progs[0]["name"] if progs else ""
        if self._dedupe(domain, who):
            return None
        hosts_on = bool(getattr(self.settings, "webblock_hosts", False))
        msg = (f"{name} is on Phishing.Database's list of active phishing sites: pages made to look "
               "like a real company's to steal passwords or card details. A look-up doesn't always mean "
               "the page was opened (browsers and chat apps also look up links to show previews). If you "
               "opened it and typed a password there, change it on the real site. TacoGuard didn't "
               "change anything in your browser.")
        if not hosts_on:
            msg += (" To block these sites, turn on blocking in Windows' hosts file under Settings > "
                    "Website blocking.")
        data = {"domain": domain, "name": name, "list": "phishing",
                "programs": [{"pid": p["pid"], "name": p["name"]} for p in progs]}
        return self.store.add_guard_event("web", "warning", f"Your PC looked up a phishing site: {domain}",
                                          msg, path=progs[0].get("exe", "") if progs else "", data=data)

    def _malware_event(self, name: str, domain: str, info: dict | None) -> int | None:
        program = info["name"] if info else ""
        if self._dedupe(domain, program):
            return None
        data = {"domain": domain, "name": name, "list": "urlhaus"}
        base = f"{name} is on URLhaus's list of websites that spread malware (abuse.ch). "
        if info is None:
            msg = base + ("TacoGuard couldn't tell which program looked it up (no program was connected "
                          "to its address any more). Nothing was changed.")
            return self.store.add_guard_event("web", "warning", f"Your PC looked up a malware site: {domain}",
                                              msg, data=data)
        data.update(pid=info["pid"], create_time=info.get("create_time", 0.0), program=program)
        title = f"A program was connected to a malware site's address: {program} -> {domain}"
        msg = base + (f"{program} had a connection to the address this name points to. Other websites can "
                      "share that address, so this is not proof: check what the program is before you act. "
                      "TacoGuard didn't pause or change it.")
        if program.lower() in BROWSERS:
            msg += " If your browser started a download from there, don't open it."
        return self.store.add_guard_event("web", "warning", title, msg, path=info.get("exe", ""), data=data)
