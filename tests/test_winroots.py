"""A missing root certificate: Windows is asked to fetch it, then ONE more fully checked try.
No network: the openers and winroots.fetch_root are replaced."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

import pytest

from tacoguard import lookup, setup_fetch, winroots


def cert_error(code: int) -> urllib.error.URLError:
    e = ssl.SSLCertVerificationError(1, "certificate verify failed")
    e.verify_code = code
    return urllib.error.URLError(e)


class FakeResp:
    def read(self, n=-1):
        return b""

    def close(self):
        pass


class Opener:
    """Fails with `errors` in order, then answers."""
    def __init__(self, errors):
        self.errors = list(errors)
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return FakeResp()


@pytest.fixture
def opener(monkeypatch):
    holder = {}

    def build(*handlers):
        return holder["o"]
    monkeypatch.setattr(urllib.request, "build_opener", build)
    return holder


def test_missing_issuer_is_recognised():
    assert winroots.missing_issuer(cert_error(20))
    assert winroots.missing_issuer(cert_error(2))
    assert not winroots.missing_issuer(cert_error(10))           # expired: a real problem
    assert not winroots.missing_issuer(cert_error(62))           # wrong host name
    assert not winroots.missing_issuer(urllib.error.URLError(OSError("no route")))
    assert not winroots.missing_issuer(None)


def test_fetch_root_never_runs_under_tests():
    assert winroots.fetch_root("urlhaus-api.abuse.ch") is False


URL = "https://urlhaus-api.abuse.ch/v2/files/exports/x/hostfile.txt"


def test_download_retries_once_after_windows_adds_the_root(opener, monkeypatch):
    asked = []
    monkeypatch.setattr(winroots, "fetch_root", lambda host: asked.append(host) or True)
    opener["o"] = Opener([cert_error(20)])
    assert isinstance(setup_fetch._open(URL), FakeResp)
    assert asked == ["urlhaus-api.abuse.ch"] and opener["o"].calls == 2


def test_no_retry_when_windows_does_not_trust_it(opener, monkeypatch):
    monkeypatch.setattr(winroots, "fetch_root", lambda host: False)
    opener["o"] = Opener([cert_error(20)])
    with pytest.raises(setup_fetch.FetchError) as e:
        setup_fetch._open(URL)
    assert e.value.kind == "offline" and opener["o"].calls == 1


def test_other_certificate_problems_are_never_retried(opener, monkeypatch):
    monkeypatch.setattr(winroots, "fetch_root", lambda host: pytest.fail("must not ask Windows"))
    opener["o"] = Opener([cert_error(10)])
    with pytest.raises(setup_fetch.FetchError):
        setup_fetch._open(URL)
    assert opener["o"].calls == 1


def test_second_failure_is_reported_not_looped(opener, monkeypatch):
    monkeypatch.setattr(winroots, "fetch_root", lambda host: True)
    opener["o"] = Opener([cert_error(20), cert_error(20), cert_error(20)])
    with pytest.raises(setup_fetch.FetchError):
        setup_fetch._open(URL)
    assert opener["o"].calls == 2


def test_lookup_retries_once_too(opener, monkeypatch):
    asked = []
    monkeypatch.setattr(winroots, "fetch_root", lambda host: asked.append(host) or True)
    opener["o"] = Opener([cert_error(20)])
    req = urllib.request.Request(lookup.API_URL, data=b"x", method="POST")
    assert isinstance(lookup._open_request(req, 5), FakeResp)
    assert asked == ["mb-api.abuse.ch"] and opener["o"].calls == 2


def test_windows_update_is_listed_as_an_endpoint():
    from tacoguard.config import ENDPOINTS
    assert any("ctldl.windowsupdate.com" in e["host"] for e in ENDPOINTS)
