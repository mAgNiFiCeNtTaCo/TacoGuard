"""Self-protection (tacoguard/selfprotect.py): process hardening on a child the test starts
itself (and that ends by itself), the installed copy's hash list, the watch over TacoGuard's own
Run value (a test key under HKCU\\Software\\TacoGuardTest) and data folder ACL (a temp folder).

Nothing here touches the real Run key, D:\\TacoGuard, the real install folder or any process
the test did not start.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
import winreg
from pathlib import Path

import psutil
import pytest

from tacoguard import autostart, selfprotect as sp
from tacoguard.config import Settings, secure_root

ROOT = Path(__file__).resolve().parents[1]
# the real interpreter (the venv's python.exe is a launcher: its child would be the hardened one)
CHILD_PY = getattr(sys, "_base_executable", None) or sys.executable
NO_WINDOW = 0x08000000
ICACLS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")

CHILD = r"""
import os, sys, time
sys.path.insert(0, sys.argv[1])
from tacoguard import selfprotect
ok = selfprotect.harden_process()
print(os.getpid(), ok, flush=True)
exit_file = sys.argv[2]
end = time.time() + 30                      # never left running: ends by itself after 30 s
while time.time() < end and not os.path.exists(exit_file):
    time.sleep(0.05)
"""


# ---- hardening ----------------------------------------------------------------------------------
def test_process_sddl_shape():
    sddl = sp.process_sddl("S-1-5-21-1-2-3-1001")
    assert sddl.startswith("D:P")                               # protected: nothing inherited
    assert "(A;;0x1fffff;;;SY)" in sddl and "(A;;0x1fffff;;;BA)" in sddl
    assert f"(A;;0x{sp.USER_RIGHTS:x};;;S-1-5-21-1-2-3-1001)" in sddl
    assert f"(A;;0x{sp.READ_CONTROL:x};;;OW)" in sddl           # OWNER RIGHTS: no implicit WRITE_DAC
    for bad in (sp.PROCESS_TERMINATE, sp.PROCESS_SUSPEND_RESUME, sp.PROCESS_VM_WRITE, sp.PROCESS_VM_READ,
                sp.PROCESS_CREATE_THREAD, sp.WRITE_DAC, sp.WRITE_OWNER, sp.PROCESS_DUP_HANDLE):
        assert not sp.USER_RIGHTS & bad
    assert sp.current_user_sid().startswith("S-1-5-")


def test_hardened_child_cannot_be_ended_but_can_be_seen(tmp_path):
    exit_file = tmp_path / "exit-now"
    child = subprocess.Popen([CHILD_PY, "-c", CHILD, str(ROOT), str(exit_file)], stdout=subprocess.PIPE,
                             text=True, creationflags=NO_WINDOW)
    try:
        pid_s, ok = child.stdout.readline().split()
        assert int(pid_s) == child.pid and ok == "True"
        for access in (sp.PROCESS_TERMINATE, sp.PROCESS_SUSPEND_RESUME, sp.PROCESS_VM_WRITE | sp.PROCESS_VM_OPERATION,
                       sp.PROCESS_CREATE_THREAD, sp.WRITE_DAC, sp.PROCESS_VM_READ, sp.PROCESS_DUP_HANDLE):
            assert sp.can_open(child.pid, access) == (False, sp.ERROR_ACCESS_DENIED), hex(access)
        for access in (sp.PROCESS_QUERY_LIMITED_INFORMATION, sp.SYNCHRONIZE, sp.READ_CONTROL):
            assert sp.can_open(child.pid, access)[0], hex(access)
        p = psutil.Process(child.pid)
        assert p.name().lower().startswith("python")
        assert abs(p.create_time() - psutil.Process(child.pid).create_time()) < 0.01
        assert "selfprotect" in " ".join(p.cmdline())           # page / procctl find TacoGuard's own
        assert p.is_running()
        with pytest.raises(psutil.AccessDenied):
            p.kill()                                            # psutil opens a new handle: refused
        with pytest.raises(psutil.TimeoutExpired):
            p.wait(0.2)                                         # waiting on it still works
        exit_file.write_text("bye")                             # it ends by itself
        assert child.wait(30) == 0
    finally:
        exit_file.write_text("bye")
        if child.poll() is None:
            child.kill()                                        # our own CreateProcess handle still may
            child.wait(10)


CHILD_THREADS = r"""
import os, subprocess, sys, threading, time
sys.path.insert(0, sys.argv[1])
from tacoguard import selfprotect
stop = threading.Event()
threading.Thread(target=stop.wait, args=(30,), daemon=True).start()      # a thread from before
ok = selfprotect.harden_process()
threading.Thread(target=stop.wait, args=(30,), daemon=True).start()      # a thread started after
time.sleep(0.3)
out = subprocess.run(["cmd", "/c", "echo pipes-work"], capture_output=True, text=True,
                     creationflags=0x08000000).stdout.strip()
print(os.getpid(), ok, out, flush=True)
exit_file = sys.argv[2]
end = time.time() + 30
while time.time() < end and not os.path.exists(exit_file):
    time.sleep(0.05)
"""


def _open_thread(tid: int, access: int) -> tuple[bool, int]:
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenThread.restype = wintypes.HANDLE
    k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    h = k32.OpenThread(access, False, tid)
    if not h:
        return False, ctypes.get_last_error()
    k32.CloseHandle(wintypes.HANDLE(h))
    return True, 0


def test_thread_sddl_shape():
    sddl = sp.thread_sddl("S-1-5-21-1-2-3-1001")
    assert sddl.startswith("D:P") and f"(A;;0x{sp.THREAD_USER_RIGHTS:x};;;S-1-5-21-1-2-3-1001)" in sddl
    for bad in (sp.THREAD_TERMINATE, sp.THREAD_SUSPEND_RESUME, sp.THREAD_SET_CONTEXT, sp.THREAD_SET_INFORMATION,
                sp.THREAD_GET_CONTEXT, sp.WRITE_DAC, sp.WRITE_OWNER):
        assert not sp.THREAD_USER_RIGHTS & bad


def test_every_thread_of_a_hardened_child_is_protected_and_pipes_still_work(tmp_path):
    exit_file = tmp_path / "exit-now"
    child = subprocess.Popen([CHILD_PY, "-c", CHILD_THREADS, str(ROOT), str(exit_file)], stdout=subprocess.PIPE,
                             text=True, creationflags=NO_WINDOW)
    try:
        pid_s, ok, out = child.stdout.readline().split()
        assert int(pid_s) == child.pid and ok == "True"
        assert out == "pipes-work"                      # subprocess with captured output still works
        tids = sp.thread_ids(child.pid)
        assert len(tids) >= 3                           # main + the thread from before + the one after
        for tid in tids:
            for access in (sp.THREAD_TERMINATE, sp.THREAD_SUSPEND_RESUME, sp.THREAD_SET_CONTEXT, sp.WRITE_DAC):
                assert _open_thread(tid, access) == (False, sp.ERROR_ACCESS_DENIED), (tid, hex(access))
            assert _open_thread(tid, sp.THREAD_QUERY_LIMITED_INFORMATION)[0]
    finally:
        exit_file.write_text("bye")
        try:
            child.wait(30)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(10)


CHILD_VIA_LAUNCHER = r"""
import os, sys, time
sys.path.insert(0, sys.argv[1])
from tacoguard import selfprotect
ok = selfprotect.harden_process()
parent = selfprotect.launcher_parent()
print(os.getpid(), ok, parent.pid if parent else 0, selfprotect.harden_parent_launcher(), flush=True)
exit_file = sys.argv[2]
end = time.time() + 30
while time.time() < end and not os.path.exists(exit_file):
    time.sleep(0.05)
"""


def test_the_venv_launcher_parent_is_hardened_too(tmp_path):
    if os.path.normcase(sys.executable) == os.path.normcase(CHILD_PY):
        pytest.skip("this Python is not a venv launcher")
    exit_file = tmp_path / "exit-now"
    launcher = subprocess.Popen([sys.executable, "-c", CHILD_VIA_LAUNCHER, str(ROOT), str(exit_file)],
                                stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
    try:
        pid_s, ok, parent_s, parent_ok = launcher.stdout.readline().split()
        assert ok == "True" and int(parent_s) == launcher.pid and int(pid_s) != launcher.pid
        assert parent_ok == "True"
        for access in (sp.PROCESS_TERMINATE, sp.PROCESS_SUSPEND_RESUME, sp.WRITE_DAC):
            assert sp.can_open(launcher.pid, access) == (False, sp.ERROR_ACCESS_DENIED), hex(access)
        for tid in sp.thread_ids(launcher.pid):
            assert _open_thread(tid, sp.THREAD_TERMINATE) == (False, sp.ERROR_ACCESS_DENIED)
        assert sp.can_open(launcher.pid, sp.SYNCHRONIZE)[0]
    finally:
        exit_file.write_text("bye")
        try:
            launcher.wait(30)
        except subprocess.TimeoutExpired:
            launcher.kill()                     # our own handle (opened before) may still end it
            launcher.wait(10)


def test_launcher_parent_is_none_for_a_plain_python(monkeypatch):
    # the test process itself: its parent is the venv launcher, but its command line runs pytest,
    # not TacoGuard, so it is never taken for TacoGuard's own launcher
    parent = sp.launcher_parent()
    assert parent is None or "tacoguard" in " ".join(parent.cmdline()).lower()


def test_own_handle_still_ends_a_hardened_child(tmp_path):
    """The page ends a guard it started through its own process handle (opened before the
    child hardened itself)."""
    exit_file = tmp_path / "never"
    child = subprocess.Popen([CHILD_PY, "-c", CHILD, str(ROOT), str(exit_file)], stdout=subprocess.PIPE,
                             text=True, creationflags=NO_WINDOW)
    try:
        assert child.stdout.readline().split()[1] == "True"
        child.kill()
        assert child.wait(10) != 0
    finally:
        exit_file.write_text("bye")
        if child.poll() is None:
            child.kill()


def test_maybe_harden_never_in_tests_or_when_off(settings, monkeypatch):
    called = []
    monkeypatch.setattr(sp, "harden_process", lambda: called.append(1) or True)
    assert os.environ.get("PYTEST_CURRENT_TEST")
    assert sp.maybe_harden(settings) is False and called == []
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    settings.self_protection = False
    assert sp.maybe_harden(settings) is False and called == []
    settings.self_protection = True
    assert sp.maybe_harden(settings) is True and called == [1]

    def boom():
        raise RuntimeError("x")
    monkeypatch.setattr(sp, "harden_process", boom)
    assert sp.maybe_harden(settings) is False                  # a failure only logs


# ---- the installed copy's hash list --------------------------------------------------------------
def _fake_version(base: Path) -> Path:
    v = base / "versions" / "9.9.9"
    for rel, text in {"tacoguard/__init__.py": "__version__ = '9.9.9'\n", "tacoguard/a.py": "A = 1\n",
                      "tacoguard/sub/b.py": "B = 2\n", "tacoguard/web/static/app.js": "let x = 1;\n",
                      "tacoguard/web/static/index.html": "<p>hi</p>\n", "LICENSE": "licence\n",
                      "requirements.lock": "x==1\n"}.items():
        (v / rel).parent.mkdir(parents=True, exist_ok=True)
        (v / rel).write_text(text, encoding="utf-8")
    (base / "TacoGuard.pyw").write_text("launcher\n", encoding="utf-8")
    return v


def test_manifest_write_and_check(tmp_path):
    v = _fake_version(tmp_path)
    data = sp.write_manifest(v, launcher=tmp_path / "TacoGuard.pyw")
    assert set(data["files"]) == {"tacoguard/__init__.py", "tacoguard/a.py", "tacoguard/sub/b.py",
                                  "tacoguard/web/static/app.js", "tacoguard/web/static/index.html",
                                  "LICENSE", "requirements.lock"}
    first = (v / sp.MANIFEST_NAME).read_bytes()
    sp.write_manifest(v, launcher=tmp_path / "TacoGuard.pyw")
    assert (v / sp.MANIFEST_NAME).read_bytes() == first           # same files -> same bytes
    assert sp.check_install(version_dir=v, root=tmp_path) == []
    (v / "tacoguard" / "__pycache__").mkdir()
    (v / "tacoguard" / "__pycache__" / "a.cpython-314.pyc").write_bytes(b"compiled")
    (v / "LICENSE").write_text("changed licence\n", encoding="utf-8")      # not code: not reported
    assert sp.check_install(version_dir=v, root=tmp_path) == []

    (v / "tacoguard" / "a.py").write_text("A = 'evil'\n", encoding="utf-8")
    (v / "tacoguard" / "sub" / "extra.py").write_text("import os\n", encoding="utf-8")
    (v / "tacoguard" / "sub" / "b.py").unlink()
    (v / "tacoguard" / "web" / "static" / "app.js").write_text("evil()\n", encoding="utf-8")
    (tmp_path / "TacoGuard.pyw").write_text("evil launcher\n", encoding="utf-8")
    assert sp.check_install(version_dir=v, root=tmp_path) == [
        "changed: tacoguard/a.py", "extra: tacoguard/sub/extra.py", "changed: tacoguard/web/static/app.js",
        "missing: tacoguard/sub/b.py", "changed: TacoGuard.pyw"]


def test_check_install_without_list_or_from_project(tmp_path, settings):
    v = _fake_version(tmp_path)
    assert sp.check_install(version_dir=v, root=tmp_path) == []      # an install from before Phase 4
    assert sp.check_install(settings) == []                           # the project folder copy


def test_report_install_check_event_and_once_a_day(settings, store):
    problems = [f"changed: tacoguard/m{i}.py" for i in range(7)]
    out = sp.report_install_check(settings, store, problems)
    assert out == problems
    evs = store.list_guard_events()
    assert len(evs) == 1
    ev = evs[0]
    assert (ev["kind"], ev["level"], ev["title"]) == ("self", "warning", "TacoGuard's own files were changed")
    assert "tacoguard\\m0.py (changed)" in ev["message"] and "tacoguard\\m4.py" in ev["message"]
    assert "m5.py" not in ev["message"] and "and 2 more" in ev["message"]
    assert "install TacoGuard again" in ev["message"]
    sp.report_install_check(settings, store, problems)                 # same list: not again today
    assert len(store.list_guard_events()) == 1
    sp.report_install_check(settings, store, problems[:1])             # a different list: reported
    assert len(store.list_guard_events()) == 2
    assert sp.report_install_check(settings, store, []) == []


def test_install_check_is_fast_on_a_real_sized_copy(tmp_path):
    v = tmp_path / "versions" / "1.0.0"
    shutil.copytree(ROOT / "tacoguard", v / "tacoguard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    sp.write_manifest(v)
    t0 = time.perf_counter()
    assert sp.check_install(version_dir=v, root=tmp_path) == []
    took = time.perf_counter() - t0
    n = len(sp.read_manifest(v)["files"])
    print(f"install check: {n} files in {took * 1000:.0f} ms")
    assert took < 1.0


# ---- the Run value -----------------------------------------------------------------------------
@pytest.fixture
def test_key():
    path = rf"Software\TacoGuardTest\{uuid.uuid4().hex}"
    yield path
    for sub in (path + r"\StartupApproved", path):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            pass
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\TacoGuardTest")   # only when empty
    except OSError:
        pass


def _fake_install(root: Path) -> Path:
    (root / "venv" / "Scripts").mkdir(parents=True)
    (root / "venv" / "Scripts" / "pythonw.exe").write_bytes(b"")
    (root / "TacoGuard.pyw").write_text("launcher\n", encoding="utf-8")
    (root / "current.json").write_text('{"version": "9.9.9"}', encoding="utf-8")
    return root


def _set_value(key_path: str, value: str) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, autostart.VALUE_NAME, 0, winreg.REG_SZ, value)


def _del_value(key_path: str) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.DeleteValue(k, autostart.VALUE_NAME)


def test_run_value_removed_or_changed_is_reported_never_fixed(settings, store, tmp_path, test_key):
    root = _fake_install(tmp_path / "install")
    autostart.enable(root, key_path=test_key)
    settings.start_at_sign_in = True
    w = sp.OwnWatch(settings, store, key_path=test_key, root=root, installed=True)
    assert w.run_state()[0] == "ok"
    assert w.check() == []                                  # baseline
    _del_value(test_key)
    assert w.check() == []                                  # seen once: Settings may be changing it
    ids = w.check()                                         # still gone a minute later: reported
    assert len(ids) == 1
    ev = store.get_guard_event(ids[0])
    assert (ev["kind"], ev["level"], ev["title"]) == ("self", "warning", sp.RUN_REMOVED_TITLE)
    assert "did not change it back" in ev["message"] and "Settings" in ev["message"]
    assert not autostart.enabled(test_key)                  # never silently re-added
    assert w.check() == [] and w.check() == []              # reported once
    # put back (Settings off and on), then another program points it elsewhere
    autostart.enable(root, key_path=test_key)
    assert w.check() == []
    _set_value(test_key, r'"C:\Somewhere\other.exe" --run')
    assert w.check() == []
    ids = w.check()
    assert len(ids) == 1
    ev = store.get_guard_event(ids[0])
    assert ev["title"] == sp.RUN_CHANGED_TITLE and "other.exe" in ev["message"]
    assert autostart.status(test_key)["command"] == r'"C:\Somewhere\other.exe" --run'   # left as it is


def test_run_value_quiet_when_switched_off_or_not_installed(settings, store, tmp_path, test_key):
    root = _fake_install(tmp_path / "install")
    autostart.enable(root, key_path=test_key)
    settings.start_at_sign_in = True
    w = sp.OwnWatch(settings, store, key_path=test_key, root=root, installed=True)
    assert w.check() == []
    # the user switches start at sign-in off in Settings: the page removes the value
    settings.start_at_sign_in = False
    autostart.disable(key_path=test_key)
    assert w.check() == [] and w.check() == []
    # switched on again but the entry could not be added: not another program's doing
    settings.start_at_sign_in = True
    assert w.check() == [] and w.check() == []
    assert store.list_guard_events() == []
    # a removal confirmed after the guard restarted (the first look is kept in the store)
    autostart.enable(root, key_path=test_key)
    assert w.check() == []
    _del_value(test_key)
    assert w.check() == []
    w2 = sp.OwnWatch(settings, store, key_path=test_key, root=root, installed=True)
    assert len(w2.check()) == 1
    # the project-folder copy never looks at the Run value
    dev = sp.OwnWatch(settings, store, key_path=test_key, root=root, installed=False)
    _set_value(test_key, "x.exe")
    assert dev.check() == [] and dev.check() == []


# ---- the data folder's ACL ------------------------------------------------------------------------
def _icacls(*args) -> None:
    r = subprocess.run([ICACLS, *map(str, args)], capture_output=True, text=True, creationflags=NO_WINDOW)
    assert r.returncode == 0, r.stdout + r.stderr


def test_data_folder_acl_relocked_and_reported(tmp_path, store):
    s = Settings(data_dir=str(tmp_path / "locked-data"))
    s.root.mkdir(parents=True)
    assert "locked" in secure_root(s).lower()
    assert (s.root / ".locked").exists()
    assert sp.folder_open_to(s.root) == []
    w = sp.OwnWatch(s, store, installed=False)
    assert w.check() == []
    _icacls(s.root, "/grant", "*S-1-1-0:(OI)(CI)M")             # another program opens it to Everyone
    assert sp.folder_open_to(s.root) == ["Everyone"]
    ids = w.check()
    assert len(ids) == 1
    ev = store.get_guard_event(ids[0])
    assert (ev["kind"], ev["level"], ev["title"]) == ("self", "warning", sp.ACL_TITLE)
    assert "Everyone" in ev["message"] and "locked it to your account" in ev["message"]
    assert ev["data"]["locked_again"] is True
    assert sp.folder_open_to(s.root) == []                      # locked again
    assert (s.root / ".locked").exists()
    assert w.check() == []
    # inheritance switched back on: the drive's own entries (Users / Authenticated Users) come back
    _icacls(s.root, "/inheritance:e")
    if sp.folder_open_to(s.root):
        assert len(w.check()) == 1
        assert sp.folder_open_to(s.root) == []


def test_a_subfolder_opened_by_its_own_entry_is_found_and_reset(tmp_path, store):
    s = Settings(data_dir=str(tmp_path / "locked-data"))
    s.root.mkdir(parents=True)
    secure_root(s)
    sub = s.root / "quarantine"
    sub.mkdir()
    (sub / "item.bin").write_bytes(b"x")
    assert sp.data_folder_open_to(s.root) == [] and sp.open_subfolders(s.root) == []
    _icacls(sub, "/grant", "*S-1-5-32-545:(OI)(CI)M")           # Users may change the quarantine
    assert sp.folder_open_to(s.root) == []                       # the data folder itself is fine
    assert sp.open_subfolders(s.root) == [sub] and sp.data_folder_open_to(s.root) == ["Users"]
    w = sp.OwnWatch(s, store, installed=False)
    (eid,) = w.check()
    ev = store.get_guard_event(eid)
    assert "Users" in ev["message"] and ev["data"]["locked_again"] is True
    assert sp.open_subfolders(s.root) == [] and sp.data_folder_open_to(s.root) == []
    assert (s.root / ".locked").exists() and (sub / "item.bin").read_bytes() == b"x"


def test_forced_lock_keeps_the_marker_when_icacls_fails(tmp_path, monkeypatch):
    s = Settings(data_dir=str(tmp_path / "locked-data"))
    s.root.mkdir(parents=True)
    secure_root(s)
    marker = s.root / ".locked"
    assert marker.exists()
    assert secure_root(s) == "Data folder already locked to your account and administrators."
    calls = []

    class Failed:
        returncode, stdout, stderr = 5, "", "Access is denied."

    def failing_run(cmd, **kw):
        calls.append(cmd)
        return Failed()
    monkeypatch.setattr(subprocess, "run", failing_run)
    note = secure_root(s, force=True)
    assert calls and note.startswith("Could not lock the data folder") and "Access is denied" in note
    assert marker.exists()                                      # still counts as "was locked"
    monkeypatch.undo()
    assert sp.relock_data_folder(s) is True and marker.exists()


def test_unlocked_folder_without_marker_is_left_alone(tmp_path, store):
    s = Settings(data_dir=str(tmp_path / "plain"))
    s.root.mkdir(parents=True)
    _icacls(s.root, "/grant", "*S-1-1-0:(OI)(CI)M")
    assert "Everyone" in sp.folder_open_to(s.root)
    assert sp.OwnWatch(s, store, installed=False).check() == []
    assert "Everyone" in sp.folder_open_to(s.root)              # never locked by TacoGuard: not touched


# ---- starting the page again ------------------------------------------------------------------------
def test_launch_page_command(monkeypatch, tmp_path):
    seen = {}

    class FakePopen:
        def __init__(self, cmd, **kw):
            seen["cmd"], seen["kw"] = cmd, kw
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    sp.launch_page(tmp_path, str(tmp_path / "data"))
    assert seen["cmd"][:3] == [str(tmp_path / "venv" / "Scripts" / "pythonw.exe"), str(tmp_path / "TacoGuard.pyw"),
                               "--background"]
    assert seen["cmd"][3:] == ["--data", str(tmp_path / "data")]
    assert seen["kw"]["creationflags"] & sp.CREATE_NO_WINDOW
    assert "PYTHONPATH" not in seen["kw"]["env"]
