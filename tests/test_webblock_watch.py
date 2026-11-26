"""WebWatcher (tacoguard/webblock/watch.py) with a fake DNS cache and a fake TCP table. It only
reports: no program is ever paused (pausing is checked to never be called)."""
from __future__ import annotations

import ctypes
import struct
import time

import pytest

from tacoguard import phase4
from tacoguard.guard import procctl
from tacoguard.webblock import hosts as H
from tacoguard.webblock import lists as L
from tacoguard.webblock import watch as W


class FakeNet:
    def __init__(self, hosts_path):
        self.names: list[str] = []
        self.addrs: dict[str, set[str]] = {}
        self.conns: list[tuple[int, str]] = []
        self.procs: dict[int, dict] = {}
        self.hosts_path = hosts_path
        self.now = 1_000_000.0

    def watcher(self, settings, store, domains, **kw):
        return W.WebWatcher(settings, store, dns_names=lambda: list(self.names),
                            addresses=lambda n: set(self.addrs.get(n, ())), connections=lambda: list(self.conns),
                            proc=kw.pop("proc", lambda pid: self.procs.get(pid)), domains=domains,
                            doh_check=kw.pop("doh_check", lambda: []), hosts_path=self.hosts_path,
                            clock=lambda: self.now, **kw)


DOMAINS = L.DomainSet.from_domains({"phishing": ["phish-bank-login.example"],
                                    "urlhaus": ["malware-drop.example"]})


@pytest.fixture
def net(tmp_path, monkeypatch):
    def never(*a, **k):
        raise AssertionError("the website watcher must never pause a program")
    monkeypatch.setattr(procctl, "suspend", never)
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\r\n")
    return FakeNet(hosts)


def _events(store):
    return [e for e in store.list_guard_events() if e["kind"] == "web"]


def test_phishing_lookup_is_a_warning_and_deduped(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["www.phish-bank-login.example", "harmless.example"]
    net.addrs["www.phish-bank-login.example"] = {"192.0.2.10"}
    net.conns = [(4242, "192.0.2.10"), (4243, "198.51.100.1")]
    net.procs[4242] = {"pid": 4242, "name": "msedge.exe", "exe": r"C:\Edge\msedge.exe", "create_time": 1.0}
    ids = w.poll_once()
    assert len(ids) == 1
    ev = store.get_guard_event(ids[0])
    assert ev["level"] == "warning" and ev["title"] == "Your PC looked up a phishing site: phish-bank-login.example"
    assert "visited" not in ev["title"] and "link" in ev["message"] and "preview" in ev["message"]
    assert "didn't change anything in your browser" in ev["message"]
    assert "hosts file" in ev["message"]                 # how to turn on blocking
    assert ev["data"]["list"] == "phishing" and ev["data"]["programs"][0]["name"] == "msedge.exe"
    # another page of the same site a moment later: no second event (30 min per domain + program)
    net.names.append("img.phish-bank-login.example")
    net.addrs["img.phish-bank-login.example"] = {"192.0.2.10"}
    assert w.poll_once() == []
    assert len(_events(store)) == 1
    assert w.checked == 3 and w.status()["checked"] == 3


def test_a_program_on_a_malware_address_is_reported_never_paused(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["cdn.malware-drop.example"]
    net.addrs["cdn.malware-drop.example"] = {"2001:db8::7"}
    net.conns = [(5000, "2001:db8:0::7")]
    net.procs[5000] = {"pid": 5000, "name": "updater.exe", "exe": r"C:\Tools\updater.exe", "create_time": 2.0}
    (eid,) = w.poll_once()
    ev = store.get_guard_event(eid)
    assert ev["level"] == "warning"
    assert ev["title"] == "A program was connected to a malware site's address: updater.exe -> malware-drop.example"
    assert "share that address" in ev["message"] and "not proof" in ev["message"]
    assert "didn't pause" in ev["message"]
    assert not store.list_paused(("paused", "not_paused", "gone"))
    assert not hasattr(W, "WebWatcher._pause")


def test_browser_on_a_malware_address(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["malware-drop.example"]
    net.addrs["malware-drop.example"] = {"192.0.2.7"}
    net.conns = [(5001, "192.0.2.7")]
    net.procs[5001] = {"pid": 5001, "name": "chrome.exe", "exe": r"C:\Chrome\chrome.exe", "create_time": 2.0}
    (eid,) = w.poll_once()
    ev = store.get_guard_event(eid)
    assert ev["level"] == "warning" and "chrome.exe -> malware-drop.example" in ev["title"]
    assert "don't open it" in ev["message"]


def test_malware_hit_without_a_program_is_retried_then_reported(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["malware-drop.example"]
    net.addrs["malware-drop.example"] = {"192.0.2.99"}
    results = [w.poll_once() for _ in range(W.RETRY_POLLS + 1)]
    assert results[0] == [] and results[1] == []
    (eid,) = results[-1]
    ev = store.get_guard_event(eid)
    assert ev["title"] == "Your PC looked up a malware site: malware-drop.example"
    assert ev["level"] == "warning"
    assert w.poll_once() == []                              # not reported again


def test_program_found_on_a_later_poll(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["phish-bank-login.example"]
    net.addrs["phish-bank-login.example"] = {"192.0.2.10"}
    assert w.poll_once() == []
    net.conns = [(7, "192.0.2.10")]
    net.procs[7] = {"pid": 7, "name": "firefox.exe", "exe": "", "create_time": 1.0}
    (eid,) = w.poll_once()
    assert store.get_guard_event(eid)["data"]["programs"][0]["name"] == "firefox.exe"


@pytest.mark.parametrize("addrs", [{"0.0.0.0"}, {"::"}, {"0.0.0.0", "::"}])
def test_names_already_sent_nowhere_are_not_reported(settings, store, net, addrs):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["malware-drop.example", "phish-bank-login.example"]
    net.addrs = {n: set(addrs) for n in net.names}
    net.conns = [(9, "0.0.0.0")]
    net.procs[9] = {"pid": 9, "name": "app.exe", "exe": "", "create_time": 1.0}
    for _ in range(W.RETRY_POLLS + 2):
        assert w.poll_once() == []
    assert _events(store) == [] and w.skipped_blocked == 2
    # the same name with a real address: reported
    net.names = ["x.malware-drop.example"]
    net.addrs["x.malware-drop.example"] = {"0.0.0.0", "192.0.2.5"}
    net.conns = [(9, "192.0.2.5")]
    assert len(w.poll_once()) == 1


def test_names_in_tacoguards_hosts_block_are_skipped(settings, store, net):
    net.hosts_path.write_bytes(b"127.0.0.1 localhost\r\n" + (H.BEGIN + "\r\n0.0.0.0 phish-bank-login.example\r\n"
                                                             "0.0.0.0 malware-drop.example\r\n" + H.END + "\r\n").encode())
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["phish-bank-login.example", "malware-drop.example"]
    net.addrs = {n: {"192.0.2.1"} for n in net.names}       # even with an address, the block wins
    for _ in range(W.RETRY_POLLS + 2):
        assert w.poll_once() == []
    assert w.skipped_blocked == 2 and w.checked == 0
    # a name under a blocked one is not in the block itself: still checked
    net.names.append("www.phish-bank-login.example")
    net.addrs["www.phish-bank-login.example"] = {"192.0.2.1"}
    for _ in range(W.RETRY_POLLS + 1):
        w.poll_once()
    assert len(_events(store)) == 1


def test_never_block_list_is_respected(settings, store, net):
    settings.webblock_allow = ["phish-bank-login.example"]
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["login.phish-bank-login.example", "malware-drop.example"]
    net.addrs = {n: {"192.0.2.1"} for n in net.names}
    for _ in range(W.RETRY_POLLS + 1):
        w.poll_once()
    assert [e["data"]["domain"] for e in _events(store)] == ["malware-drop.example"]


def test_hits_are_capped_per_poll(settings, store, net):
    listed = [f"phish{i}.example" for i in range(50)]
    w = net.watcher(settings, store, L.DomainSet.from_domains({"phishing": listed}))
    net.names = listed
    net.addrs = {n: {"192.0.2.1"} for n in listed}
    net.conns = [(11, "192.0.2.1")]
    net.procs[11] = {"pid": 11, "name": "msedge.exe", "exe": "", "create_time": 1.0}
    counts = [len(w.poll_once()) for _ in range(4)]
    assert counts == [W.HITS_PER_POLL, W.HITS_PER_POLL, 10, 0]


def test_dedupe_survives_a_restart(settings, store, net):
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["phish-bank-login.example"]
    net.addrs["phish-bank-login.example"] = {"192.0.2.10"}
    net.conns = [(7, "192.0.2.10")]
    net.procs[7] = {"pid": 7, "name": "firefox.exe", "exe": "", "create_time": 1.0}
    assert len(w.poll_once()) == 1
    w2 = net.watcher(settings, store, DOMAINS)              # the guard started again
    net.now += 60
    assert w2.poll_once() == [] and len(_events(store)) == 1
    w3 = net.watcher(settings, store, DOMAINS)
    net.now += W.DEDUPE_S
    assert len(w3.poll_once()) == 1                          # half an hour later: again
    import json
    kept = json.loads(store.get_meta(W.DEDUPE_KEY))
    assert list(kept) == ["phish-bank-login.example|firefox.exe"]   # old entries pruned


def test_paused_protection_checks_nothing(settings, store, net):
    phase4.pause_protection(store, 600)
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["phish-bank-login.example"]
    assert w.poll_once() == [] and w.checked == 0
    phase4.resume_protection(store)
    w.poll_once()
    assert w.checked == 1


def test_status_messages(settings, store, net):
    w = net.watcher(settings, store, L.DomainSet())
    st = w.status()
    assert st["state"] == "on" and "Waiting for the website lists" in st["message"]
    assert set(st) == {"state", "message", "watched", "checked"}
    w = net.watcher(settings, store, DOMAINS, doh_check=lambda: ["Firefox"])
    net.names = ["a.example"]
    w.poll_once()
    st = w.status()
    assert "1 phishing sites" in st["message"] and "1 malware sites" in st["message"]
    assert "never stops a program" in st["message"] and "paused" not in st["message"]
    assert "Firefox uses its own secure DNS" in st["message"]
    # a DNS cache that stays empty: Windows doesn't let this account read it
    net.names = []
    for _ in range(W.EMPTY_POLLS_LIMIT):
        w.poll_once()
    st = w.status()
    assert st["state"] == "off" and st["message"] == W.NO_CACHE_MSG    # a limit, not a fault
    net.names = ["b.example"]
    w.poll_once()
    assert w.status()["state"] == "on"
    settings.webblock_enabled = False
    assert w.status()["state"] == "off"


def test_lists_are_reloaded_from_disk_when_they_change(settings, store, net):
    w = W.WebWatcher(settings, store, dns_names=lambda: list(net.names), addresses=lambda n: set(),
                     connections=lambda: [], doh_check=lambda: [], hosts_path=net.hosts_path)
    w.poll_once()
    assert w.domains.count() == 0
    L.install_list(settings, "phishing", b"fresh-phish.example\n")
    w._reload_at = 0                       # the 60 s look is due
    net.names = ["fresh-phish.example"]
    for _ in range(W.RETRY_POLLS + 1):
        w.poll_once()
    assert w.domains.count("phishing") == 1
    assert [e["title"] for e in _events(store)] == ["Your PC looked up a phishing site: fresh-phish.example"]


def test_start_and_stop_thread(settings, store, net, monkeypatch):
    monkeypatch.setattr(W, "POLL_S", 0.05)
    w = net.watcher(settings, store, DOMAINS)
    net.names = ["one.example", "two.example"]
    w.start()
    deadline = time.time() + 5
    while w.checked < 2 and time.time() < deadline:
        time.sleep(0.02)
    w.stop()
    assert w.checked == 2 and w._thread is None


def test_a_big_cache_costs_little_once_seen(settings, store, net):
    """100,000 names (what a full hosts block puts into Windows' DNS cache)."""
    names = [f"site{i}.blocked-example.com" for i in range(100_000)]
    text = H.BEGIN + "\r\n" + "".join(f"0.0.0.0 {n}\r\n" for n in names) + H.END + "\r\n"
    net.hosts_path.write_bytes(text.encode())
    dom = L.DomainSet.from_domains({"phishing": names})
    w = net.watcher(settings, store, dom)
    net.names = names
    t0 = time.perf_counter()
    assert w.poll_once() == []
    first = time.perf_counter() - t0
    t0 = time.perf_counter()
    assert w.poll_once() == []
    again = time.perf_counter() - t0
    print(f"100,000-name cache: first poll {first * 1000:.0f} ms (reads the hosts block too), "
          f"then {again * 1000:.1f} ms")
    assert w.skipped_blocked == 100_000 and w.checked == 0 and _events(store) == []
    assert again < 0.25


class _FakeCacheApi:
    """dnsapi stand-in: a linked list of DNS_CACHE_ENTRY in raw memory; DnsFree does nothing."""

    def __init__(self, n):
        self.bufs = [ctypes.create_unicode_buffer(f"Site{i}.Example.") for i in range(n)]
        size = ctypes.sizeof(W.DNS_CACHE_ENTRY)
        self.raw = (ctypes.c_char * (size * n))()
        base = ctypes.addressof(self.raw)
        for i in range(n):
            struct.pack_into("<QQ", self.raw, size * i, base + size * (i + 1) if i + 1 < n else 0,
                             ctypes.addressof(self.bufs[i]))
        self.base = base
        self.freed = 0

    def DnsGetCacheDataTable(self, ref):
        ref._obj.contents = W.DNS_CACHE_ENTRY.from_address(self.base)
        return True

    def DnsFree(self, p, kind):
        self.freed += 1


def test_cache_reader_walks_a_long_list_quickly(monkeypatch):
    fake = _FakeCacheApi(50_000)
    monkeypatch.setattr(W, "_dnsapi", fake)
    t0 = time.perf_counter()
    names = W.read_dns_cache()
    took = time.perf_counter() - t0
    print(f"reading a 50,000-name cache: {took * 1000:.0f} ms ({took / 50_000 * 1e6:.2f} us per name)")
    assert len(names) == 50_000 and names[0] == "site0.example" and names[-1] == "site49999.example"
    assert fake.freed == 100_000                       # every entry and every name freed
    assert took < 2.0                                   # the old walk took ~9 s for this many


def test_real_dns_cache_reader_does_not_raise():
    """Read-only: Windows' cache (may be empty or unreadable on some Windows builds)."""
    names = W.read_dns_cache()
    assert isinstance(names, list)
    assert isinstance(W.cached_addresses("localhost"), set)
