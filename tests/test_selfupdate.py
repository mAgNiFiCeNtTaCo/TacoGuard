"""Self-update of the installed copy: checks, switch, watchdog rollback, user rollback.

Temp install folder (TACOGUARD_INSTALL_ROOT), temp data folder, a free port (never 8799), no
network. The signature check is a fake that checks the sha256 like signed.verify_file does. The
"running page" is a dummy process; shutting it down = killing it.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import types
import zipfile
from pathlib import Path

import pytest

from tacoguard import __version__, install as inst, selfupdate as su
from tacoguard.config import Settings
from tacoguard.store import Store

from test_install import ROOT, _not_real, _run, golden, kill_installed  # noqa: F401  (fixture)

NEW = "9.0.0"           # newer than any real version


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert port != 8799
    return port


def make_package(path: Path, version: str = NEW, changes: dict | None = None, lock: str | None = None,
                 extra: dict | None = None) -> Path:
    """A release zip of this project with another version number (and optional edits)."""
    changes = dict(changes or {})
    init = (ROOT / "tacoguard" / "__init__.py").read_text(encoding="utf-8")
    changes.setdefault("tacoguard/__init__.py", init.replace(f'"{__version__}"', f'"{version}"'))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, src in inst.package_files(ROOT):
            if rel in changes:
                zf.writestr(rel, changes.pop(rel))
            else:
                zf.write(src, rel)
        for rel, text in changes.items():
            zf.writestr(rel, text)
        zf.writestr("requirements.lock", lock if lock is not None else inst.make_lock(ROOT))
        for rel, data in (extra or {}).items():
            zf.writestr(rel, data)
    return path


def offer(settings, pkg: Path, version: str = NEW) -> None:
    """What the updater records for a verified app update (updater._check_app / status.json)."""
    app = Path(settings.updates_dir) / "app"
    app.mkdir(parents=True, exist_ok=True)
    dest = app / f"{version}.zip"
    shutil.copyfile(pkg, dest)
    data = dest.read_bytes()
    name = f"tacoguard-{version}.zip"
    sha = hashlib.sha256(data).hexdigest()
    status = {"app_update": {"version": version, "notes": "Test update.", "file": str(dest),
                             "sha256": sha, "name": name}}
    (Path(settings.updates_dir) / "status.json").write_text(json.dumps(status), encoding="utf-8")
    # the raw signed list the updater keeps (FakeSigned "verifies" it by reading it)
    targets = {"signed": {"_type": "targets", "version": 1, "targets": {
        name: {"length": len(data), "sha256": sha, "custom": {"kind": "app", "version": version}}}}}
    (Path(settings.updates_dir) / "targets.json").write_text(json.dumps(targets), encoding="utf-8")


class FakeSigned:
    def __init__(self):
        self.calls = []

    def load_trusted_root(self, settings):
        return {"fake": "root"}

    def load_state(self, settings):
        return {}

    def verify_targets(self, root, raw, last_version, last_sha256=""):
        return json.loads(raw)["signed"]

    def verify_file(self, path, entry):
        self.calls.append((Path(path), dict(entry)))
        data = Path(path).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"] or len(data) != int(entry["length"]):
            raise ValueError("The downloaded file does not match the checksum in the signed update list.")


@pytest.fixture
def fake_signed(monkeypatch):
    f = FakeSigned()
    monkeypatch.setattr(su, "_signed", lambda: f)
    return f


@pytest.fixture
def data(tmp_path):
    s = Settings(data_dir=str(tmp_path / "data"))
    s.port = free_port()
    s.ensure_dirs()
    return s


@pytest.fixture
def installed(golden, tmp_path, monkeypatch):  # noqa: F811
    root = tmp_path / "root"
    shutil.copytree(golden, root)
    _not_real(root)
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(root))
    monkeypatch.setattr(su, "running_from_install", lambda: True)
    yield root
    kill_installed(root)


@pytest.fixture
def light(tmp_path, monkeypatch):
    """An install folder without a Python: enough for the checks made before anything runs."""
    root = tmp_path / "light"
    (root / "versions" / __version__ / "tacoguard").mkdir(parents=True)
    (root / "requirements.lock").write_text(inst.make_lock(ROOT), encoding="utf-8")
    inst.write_current(root, __version__, None)
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(root))
    monkeypatch.setattr(su, "running_from_install", lambda: True)
    return root


@pytest.fixture
def page():
    """A stand-in for the running page process."""
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], creationflags=0x08000000)
    yield p
    p.kill()


def wait_result(root: Path, timeout: float = 150) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r = inst.read_json(root / su.RESULT)
        if r and not (root / su.UPDATE_LOCK).exists():
            return r
        time.sleep(0.5)
    log = ""
    raise AssertionError("no update result within the time limit" + log)


def wait_health(root: Path, version: str, timeout: float = 90) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        h = inst.read_json(root / su.HEALTH) or {}
        if h.get("version") == version:
            return h
        time.sleep(0.5)
    raise AssertionError(f"{version} never reported healthy")


def _log(settings) -> str:
    p = Path(settings.log_dir) / "selfupdate.log"
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


# ---------------------------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------------------------
def test_not_installed_reports_but_refuses(data, tmp_path, fake_signed, monkeypatch):
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(tmp_path / "nowhere"))
    offer(data, make_package(tmp_path / "p.zip"))
    assert su.running_from_install() is False
    av = su.available(data)
    assert av["version"] == NEW and av["current"] == __version__
    assert av["can_install"] is False and av["message"] == su.NOT_INSTALLED_MSG
    out = su.install_update(data, NEW)
    assert out == {"ok": False, "restarting": False, "message": su.NOT_INSTALLED_MSG}
    assert su.rollback(data)["message"] == su.NOT_INSTALLED_MSG
    st = su.status(data)
    assert st["installed"] is False and st["update"]["version"] == NEW


def test_available_compares_numbers(data, tmp_path, light):
    assert su.available(data) is None
    offer(data, make_package(tmp_path / "old.zip", "0.0.9"), "0.0.9")
    assert su.available(data) is None
    av = su.available(data, app_update={"version": "0.10.0", "file": "x.zip", "sha256": "0" * 64})
    assert av["version"] == "0.10.0" and av["downloaded"] is False and av["can_install"] is False
    offer(data, make_package(tmp_path / "new.zip"))
    av = su.available(data)
    assert av["can_install"] is True and av["notes"] == "Test update."


# ---------------------------------------------------------------------------------------------
# refusals (nothing changes)
# ---------------------------------------------------------------------------------------------
def _unchanged(root: Path, before: bytes) -> None:
    assert (root / "current.json").read_bytes() == before
    assert not (root / "versions" / NEW).exists()
    assert not (root / "versions" / f"{NEW}.staging").exists()
    assert not (root / su.UPDATE_LOCK).exists()


def test_requirements_change_is_refused(data, tmp_path, light, fake_signed):
    before = (light / "current.json").read_bytes()
    lock = inst.make_lock(ROOT) + "numpy==999.0\n"
    offer(data, make_package(tmp_path / "p.zip", lock=lock))
    out = su.install_update(data, NEW)
    assert not out["ok"] and out["message"] == su.NEW_PARTS_MSG
    assert fake_signed.calls                      # checked before anything was unpacked for use
    _unchanged(light, before)


@pytest.mark.parametrize("bad", ["../evil.txt", "tacoguard/../../evil.txt", "/evil.txt", "C:/evil.txt",
                                 "tacoguard\\..\\..\\evil.txt", "other/evil.txt", "tacoguard/CON.py",
                                 "tacoguard/x.py:stream"])
def test_unsafe_zip_entries_are_refused(data, tmp_path, light, fake_signed, bad):
    before = (light / "current.json").read_bytes()
    pkg = make_package(tmp_path / "p.zip", extra={bad: "x"})
    offer(data, pkg)
    out = su.install_update(data, NEW)
    assert not out["ok"] and "unsafe entry" in out["message"], out
    for p in (tmp_path / "evil.txt", light / "evil.txt", light / "versions" / "evil.txt", Path("C:/evil.txt")):
        assert not p.exists()
    _unchanged(light, before)


def test_zip_link_entry_is_refused(tmp_path):
    pkg = make_package(tmp_path / "p.zip")
    with zipfile.ZipFile(pkg, "a") as zf:
        zi = zipfile.ZipInfo("tacoguard/link")
        zi.external_attr = (0o120777 << 16)
        zf.writestr(zi, "../../somewhere")
    with pytest.raises(su.Refused, match="unsafe entry"):
        su.safe_unpack(pkg, tmp_path / "out")


def test_scan_running_is_refused(data, tmp_path, light, fake_signed):
    before = (light / "current.json").read_bytes()
    st = Store(data.db_path)
    job = st.create_job([str(tmp_path)])
    st.update_job(job, status="running")
    st.close()
    offer(data, make_package(tmp_path / "p.zip"))
    out = su.install_update(data, NEW)
    assert not out["ok"] and out["message"] == su.SCAN_MSG
    _unchanged(light, before)


def test_bad_checksum_is_refused(data, tmp_path, light, fake_signed):
    before = (light / "current.json").read_bytes()
    offer(data, make_package(tmp_path / "p.zip"))
    tpath = Path(data.updates_dir) / "targets.json"
    targets = json.loads(tpath.read_text(encoding="utf-8"))
    for entry in targets["signed"]["targets"].values():
        entry["sha256"] = "0" * 64
    tpath.write_text(json.dumps(targets), encoding="utf-8")
    out = su.install_update(data, NEW)
    assert not out["ok"] and "signature check" in out["message"]
    _unchanged(light, before)


def test_the_unsigned_record_alone_is_never_trusted(data, tmp_path, light, fake_signed):
    """Without updates_dir/targets.json (the signed list) nothing is installed, even when the
    record in status.json matches the file."""
    before = (light / "current.json").read_bytes()
    offer(data, make_package(tmp_path / "p.zip"))
    (Path(data.updates_dir) / "targets.json").unlink()
    out = su.install_update(data, NEW)
    assert out == {"ok": False, "restarting": False, "message": su.MISSING_LIST_MSG}
    assert "Press 'Check for updates'" in out["message"]
    assert fake_signed.calls == []                     # the file was never checked against the record
    _unchanged(light, before)


def test_missing_signature_checker_fails_closed(data, tmp_path, light, monkeypatch):
    def boom():
        raise ImportError("no signed module")
    monkeypatch.setattr(su, "_signed", boom)
    offer(data, make_package(tmp_path / "p.zip"))
    out = su.install_update(data, NEW)
    assert not out["ok"] and "can't check this update's signature" in out["message"]


def test_package_outside_app_folder_is_not_used(data, tmp_path, light, fake_signed):
    pkg = make_package(tmp_path / "p.zip")
    rec = {"version": NEW, "file": str(pkg), "sha256": hashlib.sha256(pkg.read_bytes()).hexdigest()}
    av = su.available(data, app_update=rec)
    assert av["downloaded"] is False


def test_second_update_at_once_is_refused(data, tmp_path, light, fake_signed):
    (light / su.UPDATE_LOCK).write_text(json.dumps({"pid": os.getpid(), "time": time.time()}), encoding="utf-8")
    offer(data, make_package(tmp_path / "p.zip"))
    out = su.install_update(data, NEW)
    assert out["message"] == su.BUSY_MSG
    assert (light / su.UPDATE_LOCK).exists()      # someone else's lock is left alone


def test_wrong_version_inside_package_is_refused(data, tmp_path, light, fake_signed):
    before = (light / "current.json").read_bytes()
    pkg = make_package(tmp_path / "p.zip", version="8.0.0")
    offer(data, pkg, NEW)
    out = su.install_update(data, NEW)
    assert not out["ok"] and "doesn't contain TacoGuard" in out["message"]
    _unchanged(light, before)


# ---------------------------------------------------------------------------------------------
# with a real installed copy
# ---------------------------------------------------------------------------------------------
def test_failed_selftest_is_never_switched(data, tmp_path, installed, fake_signed):
    before = (installed / "current.json").read_bytes()
    pkg = make_package(tmp_path / "p.zip", changes={"tacoguard/model.py": "raise ImportError('broken on purpose')\n"})
    offer(data, pkg)
    out = su.install_update(data, NEW, shutdown=lambda: pytest.fail("must not shut down"))
    assert not out["ok"] and "failed its self-test" in out["message"]
    _unchanged(installed, before)
    assert "broken on purpose" in _log(data)


@pytest.mark.slow
def test_update_switches_and_keeps_previous(data, tmp_path, installed, fake_signed, page):
    offer(data, make_package(tmp_path / "p.zip"))
    closed = []
    out = su.install_update(data, NEW, shutdown=lambda: (closed.append(1), page.kill()),
                            _server_pid=page.pid)
    assert out["ok"] and out["restarting"], out
    res = wait_result(installed)
    assert res["ok"], (res, _log(data))
    assert res["message"] == f"TacoGuard was updated to {NEW}."
    assert closed == [1]
    cur = inst.read_current(installed)
    assert cur["version"] == NEW and cur["previous"] == __version__
    assert not any(k in cur for k in su.PENDING_KEYS)          # the watchdog cleared the mark
    assert (installed / "versions" / __version__ / "tacoguard").is_dir()
    h = inst.read_json(installed / su.HEALTH)
    assert h["version"] == NEW and h["port"] == data.port
    r = _run([installed / "TacoGuard.cmd", "--data", data.data_dir, "version"])
    assert f"TacoGuard {NEW} (installed copy)" in r.stdout
    st = su.status(data)
    assert st["current"] == NEW and st["previous"] == __version__ and st["can_rollback"]
    assert st["last_result"]["ok"] is True and st["busy"] is False


@pytest.mark.slow
def test_new_version_that_never_answers_is_rolled_back(data, tmp_path, installed, fake_signed, page):
    main = (ROOT / "tacoguard" / "__main__.py").read_text(encoding="utf-8")
    hook = '    if args.cmd == "serve":\n'
    assert hook in main
    broken = main.replace(hook, hook + "        return 3   # test: the page never starts\n", 1)
    offer(data, make_package(tmp_path / "p.zip", changes={"tacoguard/__main__.py": broken}))
    out = su.install_update(data, NEW, shutdown=page.kill, _server_pid=page.pid)
    assert out["ok"], out                                     # its selftest passes; its page doesn't start
    res = wait_result(installed)
    assert not res["ok"]
    assert res["message"] == f"The update didn't start, so TacoGuard went back to {__version__}."
    cur = inst.read_current(installed)
    assert cur["version"] == __version__ and cur.get("failed") == NEW
    assert not (installed / "versions" / NEW).exists()
    wait_health(installed, __version__)                       # the old version was started again
    assert su.status(data)["last_result"]["message"] == res["message"]


@pytest.mark.slow
def test_watchdog_times_out_a_silent_page(data, tmp_path, installed, fake_signed, page):
    main = (ROOT / "tacoguard" / "__main__.py").read_text(encoding="utf-8")
    hook = '    if args.cmd == "serve":\n'
    broken = main.replace(hook, hook + "        import time; time.sleep(600); return 3\n", 1)
    offer(data, make_package(tmp_path / "p.zip", changes={"tacoguard/__main__.py": broken}))
    out = su.install_update(data, NEW, shutdown=page.kill, _server_pid=page.pid, _health_timeout=8)
    assert out["ok"], out
    res = wait_result(installed)
    assert not res["ok"] and __version__ in res["message"]
    assert inst.read_current(installed)["version"] == __version__
    assert "did not start" in _log(data)


@pytest.mark.slow
def test_user_rollback(data, tmp_path, installed, fake_signed, page):
    su.safe_unpack(make_package(tmp_path / "p.zip"), installed / "versions" / NEW)
    inst.write_current(installed, NEW, __version__)
    out = su.rollback(data, shutdown=page.kill, _server_pid=page.pid)
    assert out["ok"], out
    res = wait_result(installed)
    assert res["ok"] and res["message"] == f"TacoGuard went back to {__version__}."
    cur = inst.read_current(installed)
    assert cur["version"] == __version__ and cur["previous"] == NEW
    assert wait_health(installed, __version__)["port"] == data.port


def test_rollback_without_previous(data, light):
    assert su.rollback(data)["message"] == "There is no earlier version to go back to."


# ---------------------------------------------------------------------------------------------
# the launcher finishes a switch whose watchdog died
# ---------------------------------------------------------------------------------------------
def _launcher(root: Path):
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("tg_launcher_test", str(ROOT / "tools" / "TacoGuard.pyw"))
    spec = importlib.util.spec_from_loader("tg_launcher_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    mod.ROOT = str(root)
    return mod


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"], creationflags=0x08000000)
    p.wait()
    return p.pid


def _switched(root: Path, mode="update", since=None, watchdog=None, old=__version__, new=NEW):
    (root / "versions" / new / "tacoguard").mkdir(parents=True, exist_ok=True)
    pending = {"pending": True, "pending_since": time.time() if since is None else since,
               "pending_from": old, "pending_mode": mode}
    if watchdog is not None:
        pending["watchdog_pid"] = watchdog
    inst.write_current(root, new, old, **pending)
    (root / su.UPDATE_LOCK).write_text(json.dumps({"pid": watchdog or 0, "time": time.time()}), encoding="utf-8")


def test_launcher_goes_back_when_the_watchdog_died(light):
    _switched(light, watchdog=_dead_pid())
    L = _launcher(light)
    cur = L.finish_pending(L.read_json(str(light / "current.json")))
    assert cur["version"] == __version__ and cur["failed"] == NEW and not cur.get("pending")
    assert inst.read_current(light) == cur
    res = inst.read_json(light / su.RESULT)
    assert res["ok"] is False
    assert res["message"] == f"The last update didn't finish starting, so TacoGuard went back to {__version__}."
    assert not (light / su.UPDATE_LOCK).exists()
    assert su.last_result()["message"] == res["message"]             # what the page shows


def test_launcher_waits_while_the_watchdog_still_works(light):
    _switched(light, watchdog=os.getpid())                          # alive, switched just now
    L = _launcher(light)
    cur = L.finish_pending(L.read_json(str(light / "current.json")))
    assert cur["version"] == NEW and cur["pending"] is True
    assert not (light / su.RESULT).exists()
    # ...but not forever: a switch older than PENDING_GIVE_UP_S without an answer goes back
    _switched(light, watchdog=os.getpid(), since=time.time() - L.PENDING_GIVE_UP_S - 1)
    cur = L.finish_pending(L.read_json(str(light / "current.json")))
    assert cur["version"] == __version__
    # and right after the switch, before the watchdog's pid is written, it waits too
    _switched(light, watchdog=None)
    assert L.finish_pending(L.read_json(str(light / "current.json")))["version"] == NEW


def test_launcher_keeps_a_new_version_that_answered(light):
    since = time.time() - 600
    _switched(light, watchdog=_dead_pid(), since=since)
    inst.write_json(light / su.HEALTH, {"version": NEW, "pid": 1, "port": 1, "time": since + 5, "nonce": "x"})
    L = _launcher(light)
    cur = L.finish_pending(L.read_json(str(light / "current.json")))
    assert cur["version"] == NEW and cur["previous"] == __version__
    assert not any(k in cur for k in su.PENDING_KEYS) and inst.read_current(light) == cur
    assert not (light / su.RESULT).exists()


def test_launcher_after_a_failed_user_rollback_stays(light):
    """Rollback mode: the 'new' version is the older one; the known-good one is pending_from."""
    (light / "versions" / "0.0.1" / "tacoguard").mkdir(parents=True)
    _switched(light, mode="rollback", watchdog=_dead_pid(), old=__version__, new="0.0.1")
    L = _launcher(light)
    cur = L.finish_pending(L.read_json(str(light / "current.json")))
    assert cur["version"] == __version__ and cur["previous"] == "0.0.1"
    assert inst.read_json(light / su.RESULT)["message"] == \
        f"TacoGuard 0.0.1 didn't finish starting, so TacoGuard stayed on {__version__}."


def test_watchdog_clears_pending_only_for_its_version(light):
    _switched(light, watchdog=123)
    su.clear_pending(light, "1.2.3")                               # another version: untouched
    assert inst.read_current(light)["pending"] is True
    su.clear_pending(light, NEW)
    cur = inst.read_current(light)
    assert cur["version"] == NEW and cur["previous"] == __version__
    assert not any(k in cur for k in su.PENDING_KEYS)


@pytest.mark.slow
def test_switch_done_watchdog_killed_launcher_falls_back(data, tmp_path, installed, fake_signed, page):
    import psutil
    offer(data, make_package(tmp_path / "p.zip"))
    # the page is NOT closed, so the watchdog waits for it; meanwhile it is killed
    out = su.install_update(data, NEW, shutdown=lambda: None, _server_pid=page.pid)
    assert out["ok"], out
    cur = inst.read_json(installed / "current.json")
    assert cur["version"] == NEW and cur["pending"] is True and cur["pending_from"] == __version__
    wd = psutil.Process(cur["watchdog_pid"])
    for k in wd.children(recursive=True):
        k.kill()
    wd.kill()
    wd.wait(10)
    page.kill()
    r = _run([installed / "TacoGuard.cmd", "--data", data.data_dir, "version"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"TacoGuard {__version__} (installed copy)" in r.stdout
    cur = inst.read_current(installed)
    assert cur["version"] == __version__ and cur.get("failed") == NEW and not cur.get("pending")
    res = inst.read_json(installed / su.RESULT)
    assert res["message"] == f"The last update didn't finish starting, so TacoGuard went back to {__version__}."
    assert not (installed / su.UPDATE_LOCK).exists()
    assert su.status(data)["last_result"]["message"] == res["message"]
