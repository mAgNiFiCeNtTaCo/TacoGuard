"""Website lists (tacoguard/webblock/lists.py). No network: the HTTP layer is faked."""
from __future__ import annotations

import io
import json
import logging
import sys
import tracemalloc
from pathlib import Path

import pytest

from tacoguard import setup_fetch as F
from tacoguard.webblock import lists as L

KEY = "TestKeyAbc123456789XYZ0987"           # a made-up key (never a real one)


# ---- names -------------------------------------------------------------------------------------

def test_normalize_names():
    assert L.normalize("Evil.Example.COM.") == "evil.example.com"
    assert L.normalize("bücher-shop.de") == "xn--bcher-shop-9db.de"
    for bad in ("", "*.evil.com", "com", "1.2.3.4", "::1", "[2001:db8::1]", "evil..com", "-bad-.com",
                "evil.123", "co.uk", "a" * 64 + ".com", "evil com"):
        assert L.normalize(bad) is None, bad
    assert L.normalize("sub.co.uk") == "sub.co.uk"


def test_protected_names():
    for name in ("microsoft.com", "update.microsoft.com", "dl.windowsupdate.com", "login.live.com",
                 "github.com", "raw.githubusercontent.com", "abuse.ch", "urlhaus-api.abuse.ch",
                 "phish.co.za", "database.clamav.net", "google.com", "www.apple.com", "amazon.com",
                 "cloudflare.com", "github.io", "pages.dev"):
        assert L.is_protected(name), name
    for name in ("evil.github.io", "phish.pages.dev", "micros0ft-login.com", "evil.com", "co.za.evil.net"):
        assert not L.is_protected(name), name


def test_more_protected_names_2026_11_26():
    for name in ("aka.ms", "c-msedge.net", "office365.com", "www.microsoft365.com", "logincdn.msftauth.net",
                 "aadcdn.msauth.net", "r3.o.lencr.org", "ocsp.digicert.com", "crl.sectigo.com",
                 "ocsp.globalsign.com", "c.pki.goog", "bit.ly", "www.paypal.com", "smartscreen.microsoft.com",
                 "eu.smartscreen-prod.microsoft.com", "wdcp.microsoft.com", "www.apple.com", "p01-ckdatabase.icloud.com",
                 "store.steampowered.com", "steamcommunity.com", "cdn.steamstatic.com"):
        assert L.is_protected(name), name
    for name in ("paypal-login.example", "steam-gift.example", "bit-ly.example"):
        assert not L.is_protected(name), name


def test_idna_names_whose_mapping_changes_them_are_dropped():
    assert L.normalize("bücher.example") == "xn--bcher-kva.example"          # exact round trip: kept
    assert L.normalize("xn--bcher-kva.example") == "xn--bcher-kva.example"   # clean punycode: kept
    for changed in ("faß.de",                      # IDNA 2003 maps ß -> ss: a different site
                    "ｍｉｃｒｏｓｏｆｔ.example",      # full-width letters map to ASCII
                    "xn--zz-zzzzzz.example",       # punycode that doesn't decode
                    "xn--.example"):
        assert L.normalize(changed) is None, changed
    names, stats = L.parse("ok-site.example\nfaß.de\nbücher.example\n".encode("utf-8"))
    assert names == ["ok-site.example", "xn--bcher-kva.example"] and stats["invalid"] == 1


# ---- parsing a download ------------------------------------------------------------------------

def test_parse_drops_protected_ips_and_bad_lines_but_keeps_the_list():
    raw = ("# Phishing.Database\n"
           "evil-login.com\r\n"
           "MICROSOFT.com\n"
           "account.microsoft.com\n"
           "evil.github.io\n"
           "github.io\n"
           "192.0.2.7\n"
           "2001:db8::5\n"
           "*.wild.com\n"
           "evil-login.com\n"
           "paypa1-secure.net\n").encode()
    names, stats = L.parse(raw, "test list")
    assert names == ["evil-login.com", "evil.github.io", "paypa1-secure.net"]
    assert stats["protected"] == 3 and stats["ip"] == 2 and stats["duplicate"] == 1 and stats["invalid"] == 1


def test_parse_hostfile_and_url_lines():
    raw = (b"# URLhaus host file\n127.0.0.1\tmalware-cdn.example\n0.0.0.0 bad.example.net\n"
           b"http://user@payload.example.org:8080/x.exe\nhttps://198.51.100.9/a.exe\n")
    names, stats = L.parse(raw)
    assert names == ["malware-cdn.example", "bad.example.net", "payload.example.org"]
    assert stats["ip"] == 1


def test_parse_urlhaus_csv_keeps_only_online_rows():
    raw = ('# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
           '"1","2026-11-25 10:00:00","http://drop.example.com/a.exe","online","","malware_download","","x","y"\n'
           '"2","2026-11-25 10:00:00","http://old.example.com/a.exe","offline","","malware_download","","x","y"\n'
           '"3","2026-11-25 10:00:00","http://203.0.113.4/a.exe","online","","malware_download","","x","y"\n'
           '"4","2026-11-25 10:00:00","https://cdn.discordapp.com/a.exe","online","","malware_download","","x","y"\n'
           ).encode()
    names, stats = L.parse(raw)
    assert names == ["drop.example.com"]
    assert stats["offline"] == 1 and stats["ip"] == 1 and stats["protected"] == 1


@pytest.mark.parametrize("raw, words", [
    (b"evil.com\n\x00\x01\x02binary", "wasn't a text list"),
    (b"\xff\xfe\xfa not utf-8 \xc3\x28", "wasn't a text list"),
    (b"<!DOCTYPE html><html><body>503</body></html>", "web page instead of the list"),
    (b"# only comments\n\n", "had no website names"),
    (b"192.0.2.1\n192.0.2.2\n", "had no website names"),
    (("\n".join(f"bad name {i}" for i in range(500)) + "\nok.com\n").encode(), "weren't website names"),
])
def test_parse_refuses_bad_downloads(raw, words):
    with pytest.raises(L.ListRefused, match=words):
        L.parse(raw, "phishing list")


# ---- installing / swapping ---------------------------------------------------------------------

def _names(n, prefix="site"):
    return [f"{prefix}{i}.example" for i in range(n)]


def test_install_swap_previous_and_shrink_refused(settings):
    first = ("\n".join(_names(100)) + "\n").encode()
    res = L.install_list(settings, "phishing", first)
    assert res["changed"] and res["count"] == 100
    assert L.read_meta(settings, "phishing")["count"] == 100
    # the same download again: nothing changes
    assert not L.install_list(settings, "phishing", first)["changed"]
    # shrunk to less than half: refused, last good kept
    with pytest.raises(L.ListRefused, match="far fewer sites"):
        L.install_list(settings, "phishing", ("\n".join(_names(40)) + "\n").encode())
    assert L.read_meta(settings, "phishing")["count"] == 100
    # a normal update: current -> previous, newest names first
    second = ("\n".join(_names(90) + ["new1.example", "new2.example"]) + "\n").encode()
    res = L.install_list(settings, "phishing", second)
    assert res["count"] == 92
    assert L.read_meta(settings, "phishing", "previous")["count"] == 100
    got = L.read_domains(settings, "phishing")
    assert got[:2] == ["new1.example", "new2.example"] and got[2:] == _names(90)
    assert not list((Path(settings.webblock_dir) / "staging").glob("phishing*"))


def test_read_domains_checks_the_checksum(settings):
    L.install_list(settings, "phishing", b"a-site.example\nb-site.example\n")
    path = L.current_dir(settings, "phishing") / "domains.txt"
    path.write_bytes(path.read_bytes() + b"microsoft.com\n")
    with pytest.raises(L.ListRefused, match="doesn't match its checksum"):
        L.read_domains(settings, "phishing")


# ---- DomainSet -----------------------------------------------------------------------------------

def test_domainset_parents_sources_and_protection():
    ds = L.DomainSet.from_domains({"phishing": ["evil.com", "shared.example"],
                                   "urlhaus": ["shared.example", "malware.net", "evil.github.io"]})
    assert ds.match("a.b.evil.com") == ("phishing", "evil.com")
    assert ds.match("EVIL.com.") == ("phishing", "evil.com")
    assert ds.match("x.shared.example") == ("urlhaus", "shared.example")      # malware wins
    assert ds.match("cdn.malware.net") == ("urlhaus", "malware.net")
    assert ds.match("evil.github.io") == ("urlhaus", "evil.github.io")
    assert ds.match("other.github.io") is None
    assert "notevil.com" not in ds and "com" not in ds and "" not in ds
    assert ds.count() == 5 and ds.count("urlhaus") == 3


def test_domainset_is_memory_lean(settings):
    names = [f"phish-{i}-login.example{i % 7}.com" for i in range(200_000)]
    L.install_list(settings, "phishing", ("\n".join(names) + "\n").encode())
    del names
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        ds = L.load(settings)
        used = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    assert ds.count("phishing") == 200_000
    assert ds.nbytes == 8 * 200_000
    assert used < 3 * 1024**2, used                    # a set of str would be ~20 MB here
    assert ds.match("www.phish-123-login.example4.com") == ("phishing", "phish-123-login.example4.com")


def test_load_respects_switches_and_falls_back_to_previous(settings):
    L.install_list(settings, "phishing", b"one.example\ntwo.example\n")
    L.install_list(settings, "urlhaus", b"bad.example\n")
    assert L.load(settings).count() == 3
    settings.webblock_urlhaus_list = False
    assert L.load(settings).count() == 3 - 1
    settings.webblock_urlhaus_list = True
    L.install_list(settings, "phishing", b"one.example\ntwo.example\nthree.example\n")
    (L.current_dir(settings, "phishing") / "domains.bin").write_bytes(b"\x00" * 8)   # damaged
    assert L.load(settings).count("phishing") == 2                                  # previous


# ---- refresh with a fake HTTP layer ------------------------------------------------------------

class FakeHTTP:
    def __init__(self):
        self.routes: dict[str, object] = {}     # url suffix -> bytes | FetchError
        self.calls: list[str] = []

    def __call__(self, url, headers=None):
        F._check_url(url)                       # every address must be on config.ENDPOINTS
        self.calls.append(url)
        for suffix, answer in self.routes.items():
            if url.endswith(suffix):
                if isinstance(answer, Exception):
                    raise answer
                return io.BytesIO(answer)
        raise F.FetchError("x answered with error 404. Try again later. Nothing was changed.",
                           kind="http", code=404)


@pytest.fixture
def http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(L, "http_open", fake)
    return fake


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.setattr(L, "_get_key", lambda settings: None)


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setattr(L, "_get_key", lambda settings: KEY)


PHISH = ("\n".join(_names(60, "phish")) + "\n").encode()


def test_refresh_phishing_and_no_key_skips_urlhaus(settings, store, http, no_key):
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    msgs = []
    out = L.refresh(settings, store, msgs.append)
    assert out["ok"] and out["changed"]
    assert out["sources"]["phishing"]["state"] == "ok" and out["sources"]["phishing"]["count"] == 60
    assert out["sources"]["urlhaus"] == {"state": "no_key", "message": L.NO_KEY_MSG, "count": 0,
                                         "changed": False}
    assert L.NO_KEY_MSG in out["message"]
    assert http.calls == [L.PHISH_URL]                      # the mirror is not on ENDPOINTS yet
    assert not any("abuse.ch" in u for u in http.calls)
    assert L.load(settings).count("phishing") == 60
    st = L.status(settings)
    assert st["sources"]["phishing"]["count"] == 60 and st["sources"]["urlhaus"]["message"] == L.NO_KEY_MSG


def test_only_one_refresh_at_a_time(settings, store, http, no_key, monkeypatch):
    import threading
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    gate, inside = threading.Event(), threading.Event()
    real = L._refresh_locked

    def slow(*a, **k):
        inside.set()
        gate.wait(10)
        return real(*a, **k)
    monkeypatch.setattr(L, "_refresh_locked", slow)
    results = []
    t = threading.Thread(target=lambda: results.append(L.refresh(settings, store)))
    t.start()
    try:
        assert inside.wait(10)
        assert L.busy(settings)
        assert (Path(settings.webblock_dir) / L.REFRESH_LOCK_NAME).exists()
        second = L.refresh(settings, store)                         # same process: the module lock
        assert second["busy"] and second["ok"] and second["message"] == L.BUSY_MSG and not http.calls
        assert L.status(settings)["busy"]
    finally:
        gate.set()
        t.join(10)
    assert results[0]["ok"] and results[0]["changed"] and not results[0]["busy"]
    assert not L.busy(settings) and not (Path(settings.webblock_dir) / L.REFRESH_LOCK_NAME).exists()


def test_the_lock_file_is_shared_with_other_processes_and_goes_stale(settings, store, http, no_key):
    import os
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    lock = Path(settings.webblock_dir) / L.REFRESH_LOCK_NAME
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text('{"pid": 1}')                                   # another TacoGuard process runs one
    out = L.refresh(settings, store)
    assert out["busy"] and not http.calls and lock.exists()
    old = lock.stat().st_mtime - L.REFRESH_LOCK_STALE_S - 60       # that process died long ago
    os.utime(lock, (old, old))
    assert not L.busy(settings)
    out = L.refresh(settings, store)
    assert not out["busy"] and out["changed"] and not lock.exists()


def test_staging_names_are_unique_per_run_and_old_leftovers_go(settings, store, http, no_key, monkeypatch):
    import os
    stage = Path(settings.webblock_dir) / "staging"
    (stage / "phishing").mkdir(parents=True)                        # an old run's leftovers
    (stage / "phishing.download").write_bytes(b"old")
    old = (stage / "phishing").stat().st_mtime - 7200
    for p in (stage / "phishing", stage / "phishing.download"):
        os.utime(p, (old, old))
    seen = []
    real = L._download

    def spy(url, dest, label):
        seen.append(dest.name)
        return real(url, dest, label)
    monkeypatch.setattr(L, "_download", spy)
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    assert L.refresh(settings, store)["changed"]
    assert seen and seen[0].startswith("phishing-") and seen[0].endswith(".download")
    assert list(stage.iterdir()) == []


def test_missing_secrets_module_means_no_key(settings, store, http, monkeypatch):
    monkeypatch.setitem(sys.modules, "tacoguard.secrets", None)     # import raises ImportError
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    out = L.refresh(settings, store)
    assert out["sources"]["urlhaus"]["state"] == "no_key"


def test_refresh_waits_30_minutes_and_offline_does_not_count(settings, store, http, no_key):
    http.routes["phishing-domains-ACTIVE.txt"] = F.FetchError("Could not reach phish.co.za.", kind="offline")
    out = L.refresh(settings, store)
    assert out["sources"]["phishing"]["state"] == "offline"
    assert "No internet" in out["sources"]["phishing"]["message"]
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    assert L.refresh(settings, store)["sources"]["phishing"]["count"] == 60     # offline didn't count
    n = len(http.calls)
    out = L.refresh(settings, store)
    assert len(http.calls) == n                                                 # not fetched again
    assert "less than 30 minutes ago" in out["sources"]["phishing"]["message"]
    assert out["sources"]["phishing"]["state"] == "ok"


def test_refresh_refused_list_keeps_last_good(settings, store, http, no_key, monkeypatch):
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    L.refresh(settings, store)
    monkeypatch.setattr(L, "MIN_INTERVAL_S", 0)
    http.routes["phishing-domains-ACTIVE.txt"] = b"<html>busy</html>"
    out = L.refresh(settings, store)
    assert not out["ok"] and out["sources"]["phishing"]["state"] == "refused"
    assert "web page" in out["message"]
    assert L.load(settings).count("phishing") == 60


def test_urlhaus_with_key_tries_hostfile_then_csv_and_never_shows_the_key(settings, store, http, key,
                                                                         caplog):
    caplog.set_level(logging.DEBUG)
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    http.routes["/recent.csv"] = (
        b'# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
        b'"1","2026-11-25","http://drop.example.com/a.exe","online","","malware_download","","x","y"\n')
    msgs = []
    out = L.refresh(settings, store, msgs.append)
    assert out["sources"]["urlhaus"]["state"] == "ok" and out["sources"]["urlhaus"]["count"] == 1
    urlhaus_calls = [u for u in http.calls if "abuse.ch" in u]
    assert urlhaus_calls == [L.URLHAUS_BASE + KEY + "/hostfile.txt", L.URLHAUS_BASE + KEY + "/recent.csv"]
    assert L.load(settings).match("drop.example.com") == ("urlhaus", "drop.example.com")
    # the export that worked is remembered: next time it is asked first
    state = json.loads((Path(settings.webblock_dir) / "state.json").read_text())
    assert state["urlhaus"]["export"] == "recent.csv"
    _assert_key_nowhere(settings, out, msgs, caplog)


def test_phishing_list_falls_back_to_github_when_phish_co_za_refuses(settings, store, http, no_key):
    """Seen 2026-11-26: phish.co.za answered 503, later 403; the same list on GitHub answered."""
    http.routes["latest/phishing-domains-ACTIVE.txt"] = F.FetchError(
        "phish.co.za answered with error 403. Try again later. Nothing was changed.", kind="http", code=403)
    http.routes["master/phishing-domains-ACTIVE.txt"] = PHISH
    out = L.refresh(settings, store)
    assert out["sources"]["phishing"]["state"] == "ok" and out["sources"]["phishing"]["count"] == 60
    assert any("raw.githubusercontent.com" in c for c in http.calls)


def test_urlhaus_rejected_key_and_error_text_are_masked(settings, store, http, key, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    http.routes["/hostfile.txt"] = F.FetchError("urlhaus-api.abuse.ch answered with error 401.", kind="http",
                                                code=401)
    out = L.refresh(settings, store)
    assert out["sources"]["urlhaus"]["state"] == "error"
    assert "did not accept your key" in out["sources"]["urlhaus"]["message"]
    _assert_key_nowhere(settings, out, [], caplog)
    # an error whose text carries the address (with the key in it) is masked
    monkeypatch.setattr(L, "MIN_INTERVAL_S", 0)
    http.routes["/hostfile.txt"] = F.FetchError(f"odd failure at {L.URLHAUS_BASE}{KEY}/hostfile.txt", kind="")
    out = L.refresh(settings, store)
    assert "(your key)" in out["sources"]["urlhaus"]["message"]
    _assert_key_nowhere(settings, out, [], caplog)


def test_odd_key_is_refused_before_any_download(settings, store, http, monkeypatch):
    monkeypatch.setattr(L, "_get_key", lambda s: "abc/../../x?y=1")
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH
    out = L.refresh(settings, store)
    assert out["sources"]["urlhaus"]["state"] == "error"
    assert not any("abuse.ch" in u for u in http.calls)


def _assert_key_nowhere(settings, out, msgs, caplog):
    assert KEY not in json.dumps(out)
    assert all(KEY not in m for m in msgs)
    assert all(KEY not in r.getMessage() for r in caplog.records)
    for p in Path(settings.root).rglob("*"):
        assert KEY not in p.name
        if p.is_file() and p.stat().st_size < 5 * 1024**2:
            assert KEY.encode() not in p.read_bytes(), p


def test_switched_off(settings, store, http, no_key):
    settings.webblock_enabled = False
    out = L.refresh(settings, store)
    assert out["message"] == "Website blocking is turned off in Settings." and not http.calls
    settings.webblock_enabled = True
    settings.webblock_phishing_list = False
    out = L.refresh(settings, store)
    assert out["sources"]["phishing"]["state"] == "off" and not http.calls


def test_the_real_downloader_never_goes_online_in_tests(settings, store, no_key):
    out = L.refresh(settings, store)                        # http_open is NOT faked here
    assert out["sources"]["phishing"]["state"] == "offline"


def test_a_too_big_download_is_thrown_away(settings, store, http, no_key, monkeypatch):
    monkeypatch.setattr(L, "MAX_DOWNLOAD", 1000)
    http.routes["phishing-domains-ACTIVE.txt"] = PHISH * 10
    out = L.refresh(settings, store)
    assert out["sources"]["phishing"]["state"] == "error" and "bigger than" in out["message"]
    assert not L.read_meta(settings, "phishing")
    assert not list((Path(settings.webblock_dir) / "staging").glob("*.download"))
