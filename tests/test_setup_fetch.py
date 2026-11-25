"""setup_fetch against a local fake server (no internet). The ClamAV 'program' here is a zip of
plain text files named like the real ones; nothing in it runs."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tacoguard import setup_fetch as F
from tacoguard.detect import yara_rules as Y
from test_detect_yara import FORGE_PACKAGE


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeServer:
    """Serves {path: bytes} over plain HTTP on 127.0.0.1, with Range support."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.ranges: list[str] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = owner.files.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                rng = self.headers.get("Range")
                if rng:
                    owner.ranges.append(rng)
                    start = int(rng.split("=")[1].rstrip("-"))
                    self.send_response(206)
                    body = body[start:]
                else:
                    self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def release(self, path: str, tag: str, asset: str, data: bytes, digest: str | None = None):
        self.files[f"/dl/{asset}"] = data
        self.files[path] = json.dumps({
            "tag_name": tag, "published_at": "2026-11-22T06:26:18Z",
            "assets": [{"name": asset, "browser_download_url": f"{self.url}/dl/{asset}",
                        "digest": "sha256:" + (digest or _sha(data))}]}).encode()


@pytest.fixture
def server(monkeypatch):
    srv = FakeServer()
    real_check = F._check_url

    def check(url):
        if not url.startswith(srv.url + "/"):
            real_check(url)

    monkeypatch.setattr(F, "_check_url", check)
    monkeypatch.setattr(F, "FORGE_RELEASE_API", srv.url + "/api/forge")
    yield srv
    srv.httpd.shutdown()


def _quiet(_msg):
    pass


# ---- hosts -----------------------------------------------------------------------------------

def test_only_listed_https_hosts_are_contacted():
    F._check_url("https://api.github.com/repos/x")
    F._check_url("https://release-assets.githubusercontent.com/a")
    for bad in ("https://example.com/x", "http://github.com/x"):
        with pytest.raises(F.FetchError, match="not on the list"):
            F._check_url(bad)


def test_offline_gives_a_plain_message(settings, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    monkeypatch.setattr(F, "_check_url", lambda url: None)
    monkeypatch.setattr(F, "FORGE_RELEASE_API", dead + "/api")
    out = F.fetch_yara_rules(settings, _quiet)
    assert out == {"ok": False, "changed": False,
                   "message": "Could not reach 127.0.0.1. Check the internet connection and try "
                              "again. Nothing was changed."}


# ---- YARA Forge ------------------------------------------------------------------------------

def _forge_zip(text=FORGE_PACKAGE):
    return _zip({"packages/core/yara-rules-core.yar": text})


def test_yara_install_then_no_redownload(settings, server):
    server.release("/api/forge", "20261122", F.FORGE_ASSET, _forge_zip())
    out = F.fetch_yara_rules(settings, _quiet)
    assert out["ok"] and out["changed"], out
    assert "2 rules kept, 4 left out" in out["message"]
    meta = Y.read_meta(settings.yara_dir / "current")
    assert meta["release"] == "20261122" and meta["kept"] == 2
    assert {s["name"]: s["kept"] for s in meta["sources"]}["Unlicensed Source"] == 0
    assert not (settings.yara_dir / "new").exists()
    assert not list(settings.tmp_dir.glob("yara-forge-*"))        # download cleaned up

    again = F.fetch_yara_rules(settings, _quiet)
    assert again == {"ok": True, "changed": False,
                     "message": "YARA Forge rules 20261122 are already the newest."}


def test_yara_checksum_mismatch_changes_nothing(settings, server):
    server.release("/api/forge", "r1", F.FORGE_ASSET, _forge_zip())
    assert F.fetch_yara_rules(settings, _quiet)["ok"]
    before = (settings.yara_dir / "current" / Y.META_NAME).read_bytes()

    server.release("/api/forge", "r2", F.FORGE_ASSET, _forge_zip(), digest="00" * 32)
    out = F.fetch_yara_rules(settings, _quiet)
    assert out == {"ok": False, "changed": False, "message": F.MISMATCH}
    assert (settings.yara_dir / "current" / Y.META_NAME).read_bytes() == before
    assert not list(settings.tmp_dir.glob("*.part"))


def test_yara_rolls_back_when_the_new_rules_do_not_compile(settings, server):
    server.release("/api/forge", "r1", F.FORGE_ASSET, _forge_zip())
    assert F.fetch_yara_rules(settings, _quiet)["ok"]
    broken = FORGE_PACKAGE.replace("$a or ( $tricky and $re )", "$a or nonsense(")
    server.release("/api/forge", "r2", F.FORGE_ASSET, _forge_zip(broken))
    out = F.fetch_yara_rules(settings, _quiet)
    assert not out["ok"] and not out["changed"]
    assert "did not load" in out["message"]
    assert Y.read_meta(settings.yara_dir / "current")["release"] == "r1"
    assert not (settings.yara_dir / "new").exists()


def test_github_rate_limit_message(settings, server):
    out = F.fetch_yara_rules(settings, _quiet)           # /api/forge not published: 404
    assert not out["ok"] and "error 404" in out["message"]


# ---- ClamAV program --------------------------------------------------------------------------

FAKE_PROGRAM = {"clamav-1.5.5.win.x64/clamd.exe": "not a real program",
                "clamav-1.5.5.win.x64/freshclam.exe": "not a real program",
                "clamav-1.5.5.win.x64/sigtool.exe": "not a real program",
                "clamav-1.5.5.win.x64/libclamav.pdb": "debug symbols",
                "clamav-1.5.5.win.x64/certs/clamav.crt": "cert"}


@pytest.fixture
def clamav_server(server, monkeypatch):
    def publish(files=FAKE_PROGRAM, pinned=None, api_digest=None):
        data = _zip(files)
        server.release("/api/clamav", "clamav-1.5.5", F.CLAMAV_ASSET, data, digest=api_digest)
        monkeypatch.setattr(F, "CLAMAV_URL", f"{server.url}/dl/{F.CLAMAV_ASSET}")
        monkeypatch.setattr(F, "CLAMAV_RELEASE_API", server.url + "/api/clamav")
        monkeypatch.setattr(F, "CLAMAV_SHA256", pinned or _sha(data))
        return data
    monkeypatch.setattr(F, "authenticode", lambda paths: [(p.name, "Valid", "Cisco Systems, Inc.")
                                                          for p in paths])
    return publish


def test_clamav_program_install_and_swap(settings, clamav_server):
    clamav_server()
    out = F.fetch_clamav_program(settings, _quiet)
    assert out["ok"] and out["changed"], out
    assert "clamd.exe is digitally signed by Cisco Systems, Inc." in out["message"]
    prog = settings.clamav_program_dir
    assert (prog / "clamd.exe").exists() and (prog / "certs" / "clamav.crt").exists()
    assert not (prog / "libclamav.pdb").exists()
    assert not prog.with_name("clamav.new").exists() and not prog.with_name("clamav.previous").exists()
    assert F.fetch_clamav_program(settings, _quiet)["message"] == "ClamAV 1.5.5 is already installed."


def test_clamav_checksum_mismatch_changes_nothing(settings, clamav_server):
    clamav_server(pinned="11" * 32, api_digest="11" * 32)
    out = F.fetch_clamav_program(settings, _quiet)
    assert out == {"ok": False, "changed": False, "message": F.MISMATCH}
    assert not settings.clamav_program_dir.exists()
    assert not list(settings.tmp_dir.iterdir())


def test_clamav_refused_when_github_lists_another_checksum(settings, clamav_server):
    clamav_server(api_digest="22" * 32)
    out = F.fetch_clamav_program(settings, _quiet)
    assert not out["ok"] and "different checksum" in out["message"]


def test_path_traversal_zip_is_refused(settings, clamav_server, tmp_path):
    clamav_server({**FAKE_PROGRAM, "../../escaped.txt": "should never be written"})
    out = F.fetch_clamav_program(settings, _quiet)
    assert out == {"ok": False, "changed": False, "message": F.UNSAFE_ZIP}
    assert not list(tmp_path.rglob("escaped.txt"))
    assert not settings.clamav_program_dir.exists()
    assert not settings.clamav_program_dir.with_name("clamav.new").exists()


def test_tampered_signature_is_refused(settings, clamav_server, monkeypatch):
    clamav_server()
    monkeypatch.setattr(F, "authenticode", lambda paths: [(p.name, "HashMismatch", "") for p in paths])
    out = F.fetch_clamav_program(settings, _quiet)
    assert not out["ok"] and "changed after it was signed" in out["message"]
    assert not settings.clamav_program_dir.exists()


def test_download_resumes_a_partial_file(settings, server):
    data = b"0123456789" * 5000
    server.files["/dl/thing.zip"] = data
    dest = settings.tmp_dir / "thing.zip"
    dest.with_name("thing.zip.part").write_bytes(data[:20000])
    F._download(server.url + "/dl/thing.zip", dest, _sha(data), _quiet, "test file")
    assert dest.read_bytes() == data
    assert server.ranges == ["bytes=20000-"]


class _Trickle:
    """A local server that sends `size` bytes 10 at a time every 0.05 s (about 200 bytes/s);
    with send_length False it gives no Content-Length (size unknown until it closes)."""

    def __init__(self, size: int, send_length: bool = True):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                if send_length:
                    self.send_header("Content-Length", str(size))
                self.end_headers()
                try:
                    for _ in range(0, size, 10):
                        self.wfile.write(b"x" * 10)
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


@pytest.mark.parametrize("send_length,max_bytes", [(True, None), (False, 100_000), (False, None)])
def test_too_slow_download_is_stopped(settings, monkeypatch, send_length, max_bytes):
    """A per-read timeout alone never ends a download that trickles: there is a total deadline
    (size known) and a minimum average speed after the grace period (size known or not)."""
    srv = _Trickle(100_000, send_length)
    monkeypatch.setattr(F, "_check_url", lambda url: None)
    monkeypatch.setattr(F, "DOWNLOAD_GRACE_S", 0.6)
    monkeypatch.setattr(F, "DOWNLOAD_MIN_RATE", 1024 * 1024)
    monkeypatch.setattr(F, "DOWNLOAD_MIN_AVG_RATE", 10 * 1024)
    dest = settings.tmp_dir / "slow.zip"
    said = []
    t0 = time.monotonic()
    try:
        with pytest.raises(F.FetchError) as e:
            F._download(srv.url + "/slow.zip", dest, "0" * 64, said.append, "test file", max_bytes=max_bytes)
    finally:
        srv.httpd.shutdown()
    assert time.monotonic() - t0 < 5                       # 100 kB at 200 bytes/s would be 500 s
    assert e.value.kind == "too_slow"
    assert str(e.value) == "The download was too slow and was stopped; TacoGuard will try again later."
    assert said[-1] == str(e.value)
    assert not dest.exists() and dest.with_name("slow.zip.part").exists()   # kept for resuming


def test_download_deadline_scales_with_size():
    assert F.download_deadline(0) == F.DOWNLOAD_GRACE_S == 120
    assert F.download_deadline(50 * 1024 * 60) == 120 + 60           # 3 MB: one more minute


# ---- ClamAV signatures (freshclam is not run in tests) ---------------------------------------

def test_signatures_need_the_program(settings):
    out = F.fetch_clamav_signatures(settings, _quiet)
    assert not out["ok"] and "not installed" in out["message"]


def test_freshclam_lines_in_plain_words():
    assert F.freshclam_words("daily.cvd updated (version: 28192, sigs: 355843, f-level: 90, "
                             "builder: x)") == "ClamAV daily signatures updated to version 28192 " \
                                               "(355843 signatures)."
    assert F.freshclam_words("daily.cld database is up-to-date (version: 28193, sigs: 1, "
                             "f-level: 90, builder: x)") == \
        "ClamAV daily signatures are already up to date (version 28193)."
    assert F.freshclam_words("main database available for download (remote version: 63)") == \
        "Downloading ClamAV main signatures, version 63 (this can take a few minutes)..."
    assert F.freshclam_words("random noise") is None
    assert "rate limit" in F.freshclam_problem(["FreshClam received error code 429 from the ClamAV CDN"])
    assert "refused" in F.freshclam_problem(["received error code 403 from the ClamAV CDN"])
    assert "Could not reach" in F.freshclam_problem(["Can't connect to port 443 of host database.clamav.net"])
    assert "did not answer properly" in F.freshclam_problem(
        ["ERROR: remote_cvdhead: Malformed CVD header (too short)"])


def test_freshclam_conf_uses_only_the_listed_mirror(settings):
    text = F.freshclam_conf(settings).read_text(encoding="utf-8")
    assert "DatabaseMirror database.clamav.net" in text
    assert "DNSDatabaseInfo current.cvd.clamav.net" in text
    assert "current.cvd.clamav.net" in F.allowed_hosts()
    assert f'DatabaseDirectory "{settings.clamav_db_dir}"' in text
