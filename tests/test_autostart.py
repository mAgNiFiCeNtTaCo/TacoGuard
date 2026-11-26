"""Start at sign-in (autostart.py), the install/uninstall hooks and the launcher's --background.

Only a test key under HKCU\\Software\\TacoGuardTest\\<random> is ever written; the real Run key is
read at most, and every write to it is refused while pytest runs."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
import types
import uuid
import winreg
from pathlib import Path

import pytest

from tacoguard import autostart, install as inst

ROOT = Path(__file__).resolve().parents[1]


def _delete_tree(path: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            subs, i = [], 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
        for s in subs:
            _delete_tree(path + "\\" + s)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


@pytest.fixture
def run_key():
    base = rf"Software\TacoGuardTest\{uuid.uuid4().hex}"
    yield base + r"\Run"
    _delete_tree(base)


@pytest.fixture
def fake_install(tmp_path) -> Path:
    """The files autostart looks for in an installed copy (nothing runs)."""
    root = tmp_path / "Programs" / "TacoGuard"
    (root / "venv" / "Scripts").mkdir(parents=True)
    (root / "venv" / "Scripts" / "pythonw.exe").write_bytes(b"")
    (root / "TacoGuard.pyw").write_text("# launcher\n", encoding="utf-8")
    (root / "current.json").write_text(json.dumps({"version": "0.3.0", "previous": None}), encoding="utf-8")
    return root


def _value(key: str, name: str = autostart.VALUE_NAME):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
        return winreg.QueryValueEx(k, name)


def test_enable_disable_on_a_test_key(run_key, fake_install):
    assert autostart.enabled(run_key) is False
    assert autostart.status(run_key)["enabled"] is False
    msg = autostart.enable(fake_install, key_path=run_key)
    assert msg == autostart.ON_MSG
    value, kind = _value(run_key)
    assert kind == winreg.REG_SZ
    assert value == (f'"{fake_install}\\venv\\Scripts\\pythonw.exe" "{fake_install}\\TacoGuard.pyw" '
                     "--background")
    assert autostart.enabled(run_key) is True
    st = autostart.status(run_key)
    assert st["enabled"] and st["command"] == value and st["message"] == autostart.ON_MSG
    assert autostart.enable(fake_install, key_path=run_key) == autostart.ON_MSG      # again: fine
    assert autostart.disable(key_path=run_key) == autostart.OFF_MSG
    assert autostart.enabled(run_key) is False
    assert autostart.disable(key_path=run_key) == autostart.OFF_MSG                  # already off


def test_dev_copy_is_refused(run_key, tmp_path):
    with pytest.raises(autostart.AutostartError) as e:
        autostart.enable(ROOT, key_path=run_key)                 # the project folder: no current.json
    assert "installed copy" in str(e.value)
    with pytest.raises(autostart.AutostartError):
        autostart.enable(tmp_path / "nothing", key_path=run_key)
    assert autostart.enabled(run_key) is False


def test_real_run_key_is_never_written_in_tests(fake_install):
    with pytest.raises(autostart.AutostartError):
        autostart.enable(fake_install)
    before = autostart.enabled()
    if before:   # only reading: a real entry (if the user has one) stays untouched
        with pytest.raises(autostart.AutostartError):
            autostart.disable()
        assert autostart.enabled()


def test_disable_only_for_its_own_install(run_key, fake_install, tmp_path):
    autostart.enable(fake_install, key_path=run_key)
    autostart.disable(key_path=run_key, only_for_root=tmp_path / "other")
    assert autostart.enabled(run_key) is True
    autostart.disable(key_path=run_key, only_for_root=fake_install)
    assert autostart.enabled(run_key) is False


def test_switched_off_in_task_manager_is_reported(run_key, fake_install):
    autostart.enable(fake_install, key_path=run_key)
    approved = run_key + r"\StartupApproved"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, approved, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, autostart.VALUE_NAME, 0, winreg.REG_BINARY, b"\x03" + b"\x00" * 11)
    st = autostart.status(run_key)
    assert st["enabled"] and st["approved"] is False and "Task Manager" in st["message"]
    assert "Task Manager" in autostart.enable(fake_install, key_path=run_key)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, approved, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, autostart.VALUE_NAME, 0, winreg.REG_BINARY, b"\x02" + b"\x00" * 11)
    assert autostart.status(run_key)["approved"] is True


def test_install_hook_follows_the_setting(run_key, fake_install, settings):
    settings.start_at_sign_in = True
    msg = inst.apply_autostart(settings, fake_install, key_path=run_key)
    assert "sign in" in msg and "Settings" in msg and autostart.enabled(run_key)
    settings.start_at_sign_in = False
    assert inst.apply_autostart(settings, fake_install, key_path=run_key) == autostart.OFF_MSG
    assert not autostart.enabled(run_key)
    settings.start_at_sign_in = True
    msg = inst.apply_autostart(settings, ROOT, key_path=run_key)           # not an installed copy
    assert msg.startswith("TacoGuard could not set itself to start") and not autostart.enabled(run_key)


def test_uninstall_hook_removes_entry_and_decoys(run_key, fake_install, settings, monkeypatch):
    import tacoguard.guard as guard_pkg
    calls = []
    fake = types.SimpleNamespace(remove_decoys=lambda s: calls.append(s) or 3)
    monkeypatch.setitem(sys.modules, "tacoguard.guard.ransom", fake)
    monkeypatch.setattr(guard_pkg, "ransom", fake, raising=False)
    autostart.enable(fake_install, key_path=run_key)
    notes = inst.remove_guard_leftovers(settings, fake_install, key_path=run_key)
    assert not autostart.enabled(run_key)
    assert calls == [settings] and any("Removed 3 decoy files" in n for n in notes)

    def broken(s):
        raise OSError("locked")
    monkeypatch.setattr(fake, "remove_decoys", broken)
    notes = inst.remove_guard_leftovers(settings, fake_install, key_path=run_key)
    assert any("decoys.json" in n for n in notes)                         # plain, never raises


def test_uninstall_hook_without_the_ransom_module(run_key, fake_install, settings, monkeypatch):
    import tacoguard.guard as guard_pkg
    monkeypatch.setitem(sys.modules, "tacoguard.guard.ransom", None)      # import fails
    monkeypatch.delattr(guard_pkg, "ransom", raising=False)
    autostart.enable(fake_install, key_path=run_key)
    assert inst.remove_guard_leftovers(settings, fake_install, key_path=run_key) == [autostart.OFF_MSG]


def _launcher():
    path = ROOT / "tools" / "TacoGuard.pyw"
    loader = importlib.machinery.SourceFileLoader("tacoguard_launcher_under_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_launcher_background_means_serve_without_browser():
    build = _launcher().build_args
    assert build([]) == ["serve"]
    assert build(["--background"]) == ["serve", "--no-browser"]
    assert build(["--data", "X", "--background"]) == ["--data", "X", "serve", "--no-browser"]
    assert build(["--background", "serve", "--port", "9000"]) == ["serve", "--no-browser", "--port", "9000"]
    assert build(["--data", "X", "selftest"]) == ["--data", "X", "selftest"]
    assert build(["serve"]) == ["serve"]


def test_uninstall_hook_stops_a_running_guard_before_removing_decoys(run_key, fake_install, settings, store,
                                                                     monkeypatch):
    import subprocess
    import time
    import psutil
    import tacoguard.guard as guard_pkg
    stop_file = settings.guard_dir / "stop"
    settings.guard_dir.mkdir(parents=True, exist_ok=True)
    # a stand-in guard (a harmless child): ends when the stop file appears, as the real one does
    code = ("import os, sys, time\nstop = sys.argv[1]\n"
            "while not os.path.exists(stop): time.sleep(0.05)\n")
    py = getattr(sys, "_base_executable", None) or sys.executable
    guard = subprocess.Popen([py, "-c", code, str(stop_file), "tacoguard.guard"], creationflags=0x08000000)
    try:
        store.set_meta("guard_state", json.dumps({"pid": guard.pid, "heartbeat": time.time()}))
        seen = []
        fake = types.SimpleNamespace(remove_decoys=lambda s: seen.append(psutil.pid_exists(guard.pid)
                                                                         and guard.poll() is None) or 2)
        monkeypatch.setitem(sys.modules, "tacoguard.guard.ransom", fake)
        monkeypatch.setattr(guard_pkg, "ransom", fake, raising=False)
        notes = inst.remove_guard_leftovers(settings, fake_install, key_path=run_key)
        assert seen == [False]                          # the guard had ended before the decoys went
        assert guard.poll() is not None and not stop_file.exists()
        assert "Real-time protection was stopped first." in notes
        assert any("Removed 2 decoy files" in n for n in notes)
        # no guard running: nothing to stop, no extra words
        assert inst.stop_running_guard(settings) == ""
    finally:
        if guard.poll() is None:
            guard.kill()
            guard.wait(10)
