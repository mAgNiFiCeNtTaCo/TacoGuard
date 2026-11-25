"""The background updater (tacoguard/updates/updater.py). No real internet: every network call goes
to a local HTTP server or fails as "offline"; freshclam is faked; test keys only."""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tacoguard import setup_fetch as F
from tacoguard.detect import yara_rules as Y
from tacoguard.detect.clamav import database_info
from tacoguard.updates import signed as S
from tacoguard.updates import sources, updater as U
from test_detect_yara import FORGE_PACKAGE
from test_setup_fetch import FakeServer, _zip
from test_signed import Release, ml_zip


# ---- fixtures ----------------------------------------------------------------------------------

@pytest.fixture
def offline(monkeypatch):
    """Every real network call fails like a PC without internet."""
    def no_net(url, headers=None):
        raise F.FetchError("Could not reach the internet. Nothing was changed.", kind="offline")
    monkeypatch.setattr(F, "_open", no_net)


@pytest.fixture
def release(tmp_path, monkeypatch):
    rel = Release(tmp_path / "release")
    rel.install_root(monkeypatch, tmp_path)
    return rel


def make_updater(settings, store, rel_or_source, self_test=None):
    src = rel_or_source if not isinstance(rel_or_source, Release) else \
        sources.LocalFolderSource(rel_or_source.folder)
    up = U.Updater(settings, store, source=src)
    up.ml_self_test = self_test or (lambda folder: None)
    return up


def ml_version_on_disk(settings, which="current") -> str:
    return json.loads((Path(settings.ml_dir) / which / "meta.json").read_text())["version"]


def publish_ml(rel: Release, version: str, marker: str = "model", **custom):
    rel.add(f"ml-model-{version}.zip", ml_zip(version, marker), "ml_model", version, **custom)
    return rel.publish()


# ---- ML model and app from the signed channel ------------------------------------------------

def test_ml_model_installs_then_swaps_and_keeps_previous(settings, store, release, offline):
    publish_ml(release, "2026.11.23")
    tested = []
    up = make_updater(settings, store, release, self_test=lambda folder: tested.append(folder))
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "ok" and st["version"] == "2026.11.23", st
    assert ml_version_on_disk(settings) == "2026.11.23"
    assert tested and not Path(tested[0]).exists()          # tested in staging, then moved

    release.files.clear()
    publish_ml(release, "2026.12.01")
    up.check_now(wait=True)
    assert ml_version_on_disk(settings) == "2026.12.01"
    assert ml_version_on_disk(settings, "previous") == "2026.11.23"
    assert not (Path(settings.updates_dir) / "journal.json").exists()
    assert not list((Path(settings.updates_dir) / "staging").glob("ml_model*"))
    # the trusted state remembers version 2, and keeps the raw signed list for selfupdate
    assert S.load_state(settings)["targets_version"] == 2
    stored = (Path(settings.updates_dir) / "targets.json").read_bytes()
    assert stored == (release.folder / "targets.json").read_bytes()
    assert S.verify_targets(S.load_trusted_root(settings), stored, 2,
                            S.load_state(settings)["targets_sha256"])["version"] == 2

    # up to date: nothing downloaded again
    up.check_now(wait=True)
    assert "is the newest" in up.status()["components"]["ml_model"]["message"]


def test_failed_self_test_keeps_the_current_model(settings, store, release, offline):
    publish_ml(release, "1.0")
    make_updater(settings, store, release).check_now(wait=True)
    release.files.clear()
    publish_ml(release, "2.0")

    def broken(folder):
        raise RuntimeError("test vector scored 0.1, expected 0.93")
    up = make_updater(settings, store, release, self_test=broken)
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "rejected"
    assert "did not pass its test-load (test vector scored 0.1, expected 0.93)" in st["message"]
    assert ml_version_on_disk(settings) == "1.0"


def test_missing_ml_self_test_hook_is_skipped_with_a_note(settings, store, release, offline, monkeypatch):
    import sys
    import types

    import tacoguard.detect as detect_pkg
    stub = types.ModuleType("tacoguard.detect.ml")              # an ml module without self_test
    monkeypatch.setitem(sys.modules, "tacoguard.detect.ml", stub)
    monkeypatch.setattr(detect_pkg, "ml", stub, raising=False)
    publish_ml(release, "1.0")
    up = U.Updater(settings, store, source=sources.LocalFolderSource(release.folder))
    up.check_now(wait=True)
    assert ml_version_on_disk(settings) == "1.0"
    assert "self_test does not exist yet" in (Path(settings.log_dir) / "updates.log").read_text()


def test_min_app_filter(settings, store, release, offline):
    release.publish()                                         # nothing published yet
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    assert up.status()["components"]["ml_model"]["message"] == "No machine-learning model has been published yet."
    publish_ml(release, "5.0", min_app="99.0.0")
    up.check_now(wait=True)
    assert not (Path(settings.ml_dir) / "current").exists()
    assert up.status()["components"]["ml_model"]["message"] == (
        "A newer machine-learning model is available but needs TacoGuard 99.0.0; install the app "
        "update first.")
    # an older model the app CAN use is installed; the note about the newer one stays
    release.add("ml-model-4.0.zip", ml_zip("4.0"), "ml_model", "4.0")
    release.publish()
    up.check_now(wait=True)
    assert ml_version_on_disk(settings) == "4.0"
    up.check_now(wait=True)
    assert "needs TacoGuard 99.0.0" in up.status()["components"]["ml_model"]["message"]


def test_app_that_needs_a_newer_app_first_is_named(settings, store, release, offline):
    release.add("tacoguard-99.1.0.zip", b"pretend app", "app", "99.1.0", min_app="99.0.0")
    release.publish()
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    st = up.status()
    assert st["app_update"] is None
    assert st["components"]["app"]["message"] == ("TacoGuard 99.1.0 is available but needs TacoGuard "
                                                  "99.0.0 or newer first; run the TacoGuard installer "
                                                  "again to get it.")
    assert U.needs_newer_app({"targets": {}}, "app") is None


def test_app_update_is_only_recorded(settings, store, release, offline):
    data = b"pretend app package"
    release.add("tacoguard-9.9.9.zip", data, "app", "9.9.9", notes="Faster scans.")
    release.publish()
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    info = up.status()["app_update"]
    assert info["version"] == "9.9.9" and info["notes"] == "Faster scans."
    assert Path(info["file"]).read_bytes() == data
    assert Path(info["file"]) == Path(settings.updates_dir) / "app" / "9.9.9.zip"
    assert up.status()["components"]["app"]["state"] == "available"
    assert U.available_app(settings)["sha256"] == info["sha256"]


def test_rejected_update_list_changes_nothing(settings, store, release, offline):
    publish_ml(release, "1.0")
    make_updater(settings, store, release).check_now(wait=True)
    release.files.clear()
    publish_ml(release, "2.0")
    raw = json.loads((release.folder / "targets.json").read_text())
    raw["signed"]["targets"]["ml-model-2.0.zip"]["custom"]["notes"] = "changed"
    (release.folder / "targets.json").write_text(json.dumps(raw))
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "rejected" and "does not match its contents" in st["message"]
    assert ml_version_on_disk(settings) == "1.0"


def test_expired_update_list_is_a_calm_state_not_a_refusal(settings, store, release, offline):
    publish_ml(release, "1.0")
    make_updater(settings, store, release).check_now(wait=True)
    release.files.clear()
    publish_ml(release, "2.0")
    release.publish(expires="2026-01-01T00:00:00Z")          # the newest list is out of date
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    for name in ("ml_model", "app"):
        st = up.status()["components"][name]
        assert st["state"] == "expired", st
        assert st["message"] == ("TacoGuard's own update list has expired, so no new app or model updates "
                                 "are installed until a new release is published. Signatures and rules "
                                 "keep updating.")
        assert st["last_error"] == ""
    assert ml_version_on_disk(settings) == "1.0"              # nothing from it was used


def test_failed_test_load_is_still_a_refusal(settings, store, release, offline):
    publish_ml(release, "1.0")

    def broken(folder):
        raise RuntimeError("scored 0.1")
    up = make_updater(settings, store, release, self_test=broken)
    up.check_now(wait=True)
    assert up.status()["components"]["ml_model"]["state"] == "rejected"


def test_tampered_file_is_thrown_away(settings, store, release, offline):
    publish_ml(release, "1.0")
    tampered = ml_zip("1.0", marker="mode1")                  # same size, different bytes
    assert len(tampered) == len((release.folder / "ml-model-1.0.zip").read_bytes())
    (release.folder / "ml-model-1.0.zip").write_bytes(tampered)
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    assert "does not match the checksum" in up.status()["components"]["ml_model"]["message"]
    assert not (Path(settings.ml_dir) / "current").exists()
    assert not list((Path(settings.updates_dir) / "staging" / "downloads").glob("*.zip"))


def test_rollback_attack_is_refused(settings, store, release, offline):
    publish_ml(release, "1.0")
    old = (release.folder / "targets.json").read_bytes()
    release.files.clear()
    publish_ml(release, "2.0")
    make_updater(settings, store, release).check_now(wait=True)
    (release.folder / "targets.json").write_bytes(old)
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    assert "(version 1 < 2)" in up.status()["components"]["ml_model"]["message"]


def test_channel_not_set_up_without_a_built_in_root(settings, store, tmp_path, monkeypatch, offline):
    monkeypatch.setattr(S, "SHIPPED_ROOT", tmp_path / "none.json")
    folder = tmp_path / "empty"
    folder.mkdir()
    up = make_updater(settings, store, sources.LocalFolderSource(folder))
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "not_published" and "isn't set up yet" in st["message"]


# ---- swaps, scans and crashes ----------------------------------------------------------------

def test_running_scan_defers_the_swap(settings, store, release, offline):
    publish_ml(release, "1.0")
    job = store.create_job([str(settings.root)])           # queued = a scan is about to run
    up = make_updater(settings, store, release)
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "waiting" and "as soon as no scan is running" in st["message"]
    assert not (Path(settings.ml_dir) / "current").exists()
    assert up.apply_pending() == []

    store.update_job(job, status="done")
    assert up.apply_pending() == ["ml_model"]
    assert ml_version_on_disk(settings) == "1.0"
    assert up.status()["components"]["ml_model"]["state"] == "ok"


def test_staged_set_survives_a_restart(settings, store, release, offline):
    publish_ml(release, "1.0")
    job = store.create_job([str(settings.root)])
    make_updater(settings, store, release).check_now(wait=True)
    store.update_job(job, status="done")
    again = make_updater(settings, store, release)
    notes = again.recover()
    assert any("ready from before" in n for n in notes)
    assert again.apply_pending() == ["ml_model"]
    assert ml_version_on_disk(settings) == "1.0"


class Crash(BaseException):
    """Stands in for the power going off: nothing after it runs."""


def _crash_on(monkeypatch, match):
    real = os.replace

    def fake(src, dst):
        if match(Path(src), Path(dst)):
            raise Crash()
        return real(src, dst)
    monkeypatch.setattr(U.os, "replace", fake)
    return real


def test_crash_mid_swap_is_finished_at_start(settings, store, release, offline, monkeypatch):
    publish_ml(release, "1.0")
    make_updater(settings, store, release).check_now(wait=True)
    release.files.clear()
    publish_ml(release, "2.0")
    staging = Path(settings.updates_dir) / "staging" / "ml_model"
    real = _crash_on(monkeypatch, lambda src, dst: src == staging)        # new -> current
    with pytest.raises(Crash):
        make_updater(settings, store, release).check_now(wait=True)
    monkeypatch.setattr(U.os, "replace", real)
    assert (Path(settings.updates_dir) / "journal.json").exists()
    assert not (Path(settings.ml_dir) / "current").exists()                # mid-swap

    up = make_updater(settings, store, release)
    notes = up.recover()
    assert any("was finished" in n for n in notes), notes
    assert ml_version_on_disk(settings) == "2.0"
    assert ml_version_on_disk(settings, "previous") == "1.0"
    assert up.status()["components"]["ml_model"]["version"] == "2.0"
    assert not (Path(settings.updates_dir) / "journal.json").exists()


def test_crash_before_anything_moved_is_undone(settings, store, release, offline, monkeypatch):
    publish_ml(release, "1.0")
    make_updater(settings, store, release).check_now(wait=True)
    release.files.clear()
    publish_ml(release, "2.0")
    current = Path(settings.ml_dir) / "current"
    real = _crash_on(monkeypatch, lambda src, dst: src == current)         # current -> previous
    with pytest.raises(Crash):
        make_updater(settings, store, release).check_now(wait=True)
    monkeypatch.setattr(U.os, "replace", real)
    up = make_updater(settings, store, release)
    notes = up.recover()
    assert any("undone before anything moved" in n for n in notes), notes
    assert ml_version_on_disk(settings) == "1.0"
    assert up.apply_pending() == ["ml_model"]                              # the staged set is kept
    assert ml_version_on_disk(settings) == "2.0"


def test_crash_after_current_moved_without_new_is_rolled_back(settings, store):
    up = U.Updater(settings, store, source=sources.LocalFolderSource(settings.root))
    current, previous = Path(settings.ml_dir) / "current", Path(settings.ml_dir) / "previous"
    previous.mkdir(parents=True)
    (previous / "meta.json").write_text('{"version": "old"}')
    S.write_json_atomic(up.journal_path, {
        "component": "ml_model", "new": str(Path(settings.updates_dir) / "staging" / "ml_model"),
        "current": str(current), "previous": str(previous),
        "trash": str(previous.with_name("previous.trash")), "step": "moving"})
    notes = up.recover()
    assert any("was undone" in n for n in notes)
    assert ml_version_on_disk(settings) == "old"


def test_recover_removes_stale_staging(settings, store):
    stage = Path(settings.updates_dir) / "staging"
    (stage / "ml_model").mkdir(parents=True)                 # no .ready.json: unfinished
    (stage / "ml_model" / "half.bin").write_bytes(b"x")
    (stage / "downloads").mkdir()
    (stage / "downloads" / "ml-model-1.zip.part").write_bytes(b"part")
    (stage / "downloads" / "old.zip").write_bytes(b"old")
    up = U.Updater(settings, store, source=sources.LocalFolderSource(settings.root))
    notes = up.recover()
    assert not (stage / "ml_model").exists()
    assert (stage / "downloads" / "ml-model-1.zip.part").exists()     # kept for resuming
    assert not (stage / "downloads" / "old.zip").exists()
    assert any("unfinished download" in n for n in notes)


# ---- offline -----------------------------------------------------------------------------------

def _fake_cvd(path: Path, version: int, stime: int = 1763892000) -> None:
    head = f"ClamAV-VDB:23 Nov 2026 10-00 +0000:{version}:100:90:md5:dsig:builder:{stime}"
    path.write_bytes(head.encode().ljust(512, b"\0") + b"body")


@pytest.fixture
def clamav(settings):
    prog = Path(settings.clamav_program_dir)
    prog.mkdir(parents=True, exist_ok=True)
    (prog / "freshclam.exe").write_text("not a real program")
    db = Path(settings.clamav_db_dir)
    _fake_cvd(db / "main.cvd", 62)
    _fake_cvd(db / "daily.cvd", 27850)
    return db


def test_offline_message(settings, store, clamav, release, offline, monkeypatch):
    monkeypatch.setattr(F, "_run_streaming",
                        lambda cmd, timeout, on_line: (1, ["Can't connect to port 443 of host database.clamav.net"]))
    up = U.Updater(settings, store, source=sources.GitHubReleaseSource("someone/tacoguard"))
    up.check_now(wait=True)
    st = up.status()
    day = time.strftime("%Y-%m-%d", time.localtime(1763892000))
    assert st["components"]["clamav_signatures"]["message"] == f"No internet: using signatures from {day}."
    assert st["components"]["clamav_signatures"]["state"] == "offline"
    assert st["components"]["yara_rules"]["state"] == "offline"
    assert st["components"]["ml_model"]["state"] == "offline"
    assert st["message"] == f"No internet: using signatures from {day}."
    assert database_info(clamav)["daily"]["version"] == "27850"          # kept
    assert not (Path(settings.updates_dir) / "staging" / "clamav_signatures").exists()


# ---- ClamAV ------------------------------------------------------------------------------------

class FakeFreshclam:
    """Stands in for freshclam.exe: writes a newer daily.cvd into the folder of its config."""

    def __init__(self, lines=None, code=0, daily=27851):
        self.calls = 0
        self.lines, self.code, self.daily = lines, code, daily

    def __call__(self, cmd, timeout, on_line):
        self.calls += 1
        conf = Path(cmd[1].split("=", 1)[1]).read_text(encoding="utf-8")
        db = Path(conf.split('DatabaseDirectory "', 1)[1].split('"', 1)[0])
        if self.lines is not None:
            return self.code, list(self.lines)
        _fake_cvd(db / "daily.cvd", self.daily, stime=1763978400)
        on_line(f"daily.cvd updated (version: {self.daily}, sigs: 100, f-level: 90, builder: x)")
        return 0, [f"daily.cvd updated (version: {self.daily}, sigs: 100)"]


@pytest.fixture
def clamav_checks(monkeypatch):
    seen = []
    monkeypatch.setattr(F, "_verify_databases", lambda prog, db, info: seen.append(("sigtool", Path(db))))
    monkeypatch.setattr(F, "clamscan_test", lambda settings, db: seen.append(("clamscan", Path(db))) or True)
    return seen


def test_clamav_update_in_staging_then_swap(settings, store, clamav, offline, monkeypatch, clamav_checks):
    fake = FakeFreshclam()
    monkeypatch.setattr(F, "_run_streaming", fake)
    up = U.Updater(settings, store, source=sources.LocalFolderSource(settings.root))
    up.check_now(wait=True)
    st = up.status()["components"]["clamav_signatures"]
    assert st["state"] == "ok" and "daily 27851" in st["message"], st
    assert database_info(clamav)["daily"]["version"] == "27851"
    previous = clamav.with_name("clamav.previous")
    assert database_info(previous)["daily"]["version"] == "27850"
    staging = Path(settings.updates_dir) / "staging" / "clamav_signatures"
    assert clamav_checks == [("sigtool", staging), ("clamscan", staging)]   # tested before the swap

    # asked again at once: freshclam is NOT run again (ClamAV allows one check an hour)
    up.check_now(wait=True)
    assert fake.calls == 1
    assert "at most one check an hour" in up.status()["components"]["clamav_signatures"]["message"]
    # the page's "Get signatures" button obeys the same limit
    out = F.fetch_clamav_signatures(settings, lambda m: None)
    assert not out["ok"] and "less than an hour ago" in out["message"] and fake.calls == 1


def test_clamav_rate_limit_backs_off(settings, store, clamav, offline, monkeypatch, clamav_checks):
    fake = FakeFreshclam(code=1, lines=[
        "WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN).",
        "You are on cool-down until after: 2099-01-02 03:04:05"])
    monkeypatch.setattr(F, "_run_streaming", fake)
    up = U.Updater(settings, store, source=sources.LocalFolderSource(settings.root))
    up.check_now(wait=True)
    st = up.status()["components"]["clamav_signatures"]
    assert st["state"] == "rate_limited"
    assert "rate limit" in st["message"] and "Next try after 2099-01-02 03:04" in st["message"]
    rec = F.freshclam_record(settings)
    assert rec["retry_at"] == time.mktime(time.strptime("2099-01-02 03:04:05", "%Y-%m-%d %H:%M:%S"))

    # even with the hourly limit passed, the cool-down holds
    rec["last_run"] = time.time() - 7200
    F._save_freshclam_record(settings, rec)
    up.check_now(wait=True)
    assert fake.calls == 1
    assert "Next try after 2099-01-02 03:04" in up.status()["components"]["clamav_signatures"]["message"]
    assert database_info(clamav)["daily"]["version"] == "27850"


def test_clamav_403_without_a_time_waits_a_day(settings, store, clamav, offline, monkeypatch, clamav_checks):
    monkeypatch.setattr(F, "_run_streaming", FakeFreshclam(code=1, lines=[
        "ERROR: FreshClam received error code 403 from the ClamAV Content Delivery Network (CDN)."]))
    before = time.time()
    U.Updater(settings, store, source=sources.LocalFolderSource(settings.root)).check_now(wait=True)
    rec = F.freshclam_record(settings)
    assert rec["retry_at"] >= before + F.BLOCKED_BACKOFF - 5


def test_clamav_set_that_does_not_load_is_not_swapped(settings, store, clamav, offline, monkeypatch):
    monkeypatch.setattr(F, "_run_streaming", FakeFreshclam())
    monkeypatch.setattr(F, "_verify_databases", lambda prog, db, info: None)

    def bad_load(settings, db):
        raise F.FetchError("The new ClamAV signatures did not load in ClamAV's own test, so the "
                           "signatures you have are kept.")
    monkeypatch.setattr(F, "clamscan_test", bad_load)
    up = U.Updater(settings, store, source=sources.LocalFolderSource(settings.root))
    up.check_now(wait=True)
    st = up.status()["components"]["clamav_signatures"]
    assert st["state"] == "error" and "did not load" in st["message"]
    assert database_info(clamav)["daily"]["version"] == "27850"
    assert not (Path(settings.updates_dir) / "staging" / "clamav_signatures").exists()


# ---- YARA (setup_fetch's download + license filter + compile test) ---------------------------

def test_yara_swap_reuses_setup_fetch(settings, store, release, monkeypatch):
    srv = FakeServer()
    real_check = F._check_url
    monkeypatch.setattr(F, "_check_url", lambda url: None if url.startswith(srv.url + "/") else real_check(url))
    monkeypatch.setattr(F, "FORGE_RELEASE_API", srv.url + "/api/forge")
    try:
        forge = _zip({"packages/core/yara-rules-core.yar": FORGE_PACKAGE})
        srv.release("/api/forge", "r1", F.FORGE_ASSET, forge)
        up = make_updater(settings, store, release)
        up.check_now(wait=True)
        st = up.status()["components"]["yara_rules"]
        assert st["state"] == "ok" and "2 rules kept" in st["message"], st
        assert Y.read_meta(Path(settings.yara_dir) / "current")["release"] == "r1"

        up.check_now(wait=True)
        assert "r1 are the newest" in up.status()["components"]["yara_rules"]["message"]

        srv.release("/api/forge", "r2", F.FORGE_ASSET, forge)
        up.check_now(wait=True)
        assert Y.read_meta(Path(settings.yara_dir) / "current")["release"] == "r2"
        assert Y.read_meta(Path(settings.yara_dir) / "previous")["release"] == "r1"
        assert up.status()["components"]["yara_rules"]["version"] == "r2"
    finally:
        srv.httpd.shutdown()


# ---- GitHub release source (local HTTP server) ------------------------------------------------

class FakeGitHub:
    """/repos/<repo>/releases/latest plus asset downloads, with Range support."""

    def __init__(self, repo: str):
        self.repo = repo
        self.release: dict | None = None
        self.files: dict[str, bytes] = {}
        self.ranges: list[str] = []
        self.slow: set[str] = set()               # these files trickle out, 5 bytes per 0.1 s
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                slow = False
                if self.path == f"/repos/{owner.repo}/releases/latest":
                    if owner.release is None:
                        self.send_error(404)
                        return
                    body, code = json.dumps(owner.release).encode(), 200
                elif self.path.startswith("/dl/") and self.path[4:] in owner.files:
                    body, code = owner.files[self.path[4:]], 200
                    slow = self.path[4:] in owner.slow
                    rng = self.headers.get("Range")
                    if rng:
                        owner.ranges.append(rng)
                        body, code = body[int(rng.split("=")[1].rstrip("-")):], 206
                else:
                    self.send_error(404)
                    return
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not slow:
                    self.wfile.write(body)
                    return
                try:
                    for i in range(0, len(body), 5):
                        self.wfile.write(body[i:i + 5])
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:                    # the client gave up
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def publish_folder(self, folder: Path, tag: str = "v1"):
        self.files = {p.name: p.read_bytes() for p in folder.iterdir()}
        self.release = {"tag_name": tag, "assets": [
            {"name": n, "size": len(b), "browser_download_url": f"{self.url}/dl/{n}"}
            for n, b in self.files.items()]}


@pytest.fixture
def github(monkeypatch):
    gh = FakeGitHub("someone/tacoguard")
    real_open = F._open

    def local_only(url, headers=None):
        if not url.startswith(gh.url + "/"):
            raise F.FetchError("Could not reach the internet. Nothing was changed.", kind="offline")
        return real_open(url, headers)
    monkeypatch.setattr(F, "_check_url", lambda url: None if url.startswith(gh.url + "/") else
                        (_ for _ in ()).throw(F.FetchError("not allowed")))
    monkeypatch.setattr(F, "_open", local_only)
    yield gh
    gh.httpd.shutdown()


def test_github_source_not_published_is_a_normal_state(settings, store, release, github):
    up = make_updater(settings, store, sources.GitHubReleaseSource(github.repo, api_base=github.url))
    up.check_now(wait=True)
    st = up.status()["components"]
    for name in ("ml_model", "app"):
        assert st[name]["state"] == "not_published"
        assert st[name]["message"] == "TacoGuard's own update channel isn't published yet."
        assert st[name]["last_error"] == ""


def test_github_source_resumes_a_truncated_download(settings, store, release, github):
    publish_ml(release, "2026.11.23")
    github.publish_folder(release.folder)
    data = (release.folder / "ml-model-2026.11.23.zip").read_bytes()
    part = Path(settings.updates_dir) / "staging" / "downloads" / "ml-model-2026.11.23.zip.part"
    part.parent.mkdir(parents=True)
    part.write_bytes(data[:100])
    up = make_updater(settings, store, sources.GitHubReleaseSource(github.repo, api_base=github.url))
    up.recover()
    assert part.exists()                                      # recover keeps partial downloads
    up.check_now(wait=True)
    assert github.ranges == ["bytes=100-"]
    assert ml_version_on_disk(settings) == "2026.11.23"
    assert not part.exists()


def test_github_source_refuses_a_download_longer_than_signed(settings, store, release, github):
    publish_ml(release, "1.0")
    github.publish_folder(release.folder)
    github.files["ml-model-1.0.zip"] += b"x" * 5000           # the server sends more than listed
    up = make_updater(settings, store, sources.GitHubReleaseSource(github.repo, api_base=github.url))
    up.check_now(wait=True)
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "error" and "bigger than the update list says" in st["message"]
    assert not (Path(settings.ml_dir) / "current").exists()


def test_a_too_slow_download_is_stopped_and_the_check_ends(settings, store, release, github, monkeypatch):
    """A server that trickles bytes must not hold the update check (and its lock) for ever."""
    monkeypatch.setattr(F, "DOWNLOAD_GRACE_S", 0.5)
    monkeypatch.setattr(F, "DOWNLOAD_MIN_RATE", 1024 * 1024)
    publish_ml(release, "1.0")
    github.publish_folder(release.folder)
    github.slow.add("ml-model-1.0.zip")
    assert len(github.files["ml-model-1.0.zip"]) > 200          # would take 4+ s at 50 bytes/s
    up = make_updater(settings, store, sources.GitHubReleaseSource(github.repo, api_base=github.url))
    t0 = time.monotonic()
    up.check_now(wait=True)
    assert time.monotonic() - t0 < 10
    st = up.status()["components"]["ml_model"]
    assert st["state"] == "error"
    assert st["message"] == "The download was too slow and was stopped; TacoGuard will try again later."
    assert not up._check_lock.locked() and up.status()["checking"] is False
    part = Path(settings.updates_dir) / "staging" / "downloads" / "ml-model-1.0.zip.part"
    assert part.exists()                                        # kept, so the next try resumes
    github.slow.clear()
    up.check_now(wait=True)
    assert ml_version_on_disk(settings) == "1.0" and github.ranges


def test_github_source_hosts_are_listed():
    hosts = F.allowed_hosts()
    for h in ("api.github.com", "github.com", "release-assets.githubusercontent.com"):
        assert h in hosts
    with pytest.raises(F.FetchError, match="not on the list"):
        F._check_url("http://api.github.com/repos/x")            # HTTPS only


# ---- thread and status -------------------------------------------------------------------------

def test_background_thread_checks_at_start_and_stops(settings, store, release, offline):
    publish_ml(release, "1.0")
    up = make_updater(settings, store, release)
    up.start(on_start=True)
    deadline = time.time() + 20
    while time.time() < deadline and not up.status()["last_check"]:
        time.sleep(0.05)
    while time.time() < deadline and up.status()["checking"]:
        time.sleep(0.05)
    up.stop()
    st = up.status()
    assert st["last_check"] and st["next_check"] > st["last_check"]
    assert ml_version_on_disk(settings) == "1.0"
    assert (Path(settings.log_dir) / "updates.log").exists()
    assert set(st["components"]) == {"clamav_signatures", "yara_rules", "ml_model", "app"}
    for comp in st["components"].values():
        assert set(comp) >= {"version", "updated", "state", "message", "last_error"}


def test_check_now_never_runs_two_at_once(settings, store, release, offline, monkeypatch):
    publish_ml(release, "1.0")
    up = make_updater(settings, store, release)
    gate, entered = threading.Event(), []

    def slow(*a):
        entered.append(1)
        gate.wait(10)
    monkeypatch.setattr(up, "_check_clamav", slow)
    up.check_now()
    deadline = time.time() + 10
    while not entered and time.time() < deadline:
        time.sleep(0.02)
    up.check_now()
    up.check_now()
    assert up.status()["checking"] is True
    gate.set()
    while up.status()["checking"] and time.time() < deadline:
        time.sleep(0.02)
    assert len(entered) == 1


def test_status_never_raises(settings, store, release):
    up = make_updater(settings, store, release)
    up._status = None                                          # broken on purpose
    assert up.status()["components"] == {}
