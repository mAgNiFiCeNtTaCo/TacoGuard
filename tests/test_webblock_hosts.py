"""The hosts-file block: tacoguard/webblock/hosts.py (user level) and hosts-helper.ps1 (the admin step).

The helper is the REAL script run by the REAL Windows PowerShell, NOT elevated, on a COPY whose
hosts path line points at a temp file (the test does that text substitution; the script itself has
no hosts path parameter) and whose DNS flush is off. "Program Files\\TacoGuard" is a temp folder.
No admin prompt, never the real hosts file, no DNS flush.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from tacoguard.webblock import hosts as H
from tacoguard.webblock import lists as L

ORIGINAL = (b"# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n"
            b"# localhost name resolution is handled within DNS itself.\r\n"
            b"#\t127.0.0.1       localhost\r\n"
            b"10.0.0.5 nas.home\r\n")
HOSTS_LINE = "$HostsPath = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'drivers\\etc\\hosts')"
FLUSH_LINE = "$FlushDns = $true"
PS_FLAGS = ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


def test_copy(hosts_file: Path) -> bytes:
    """The packaged script with its hosts path pointed at the temp file and no DNS flush."""
    text = H.packaged_script().decode("ascii")
    assert text.count(HOSTS_LINE) == 1 and text.count(FLUSH_LINE) == 1
    return text.replace(HOSTS_LINE, "$HostsPath = '" + str(hosts_file).replace("'", "''") + "'") \
        .replace(FLUSH_LINE, "$FlushDns = $false").encode("ascii")


test_copy.__test__ = False          # a helper, not a test


@pytest.fixture
def hosts_file(tmp_path):
    p = tmp_path / "etc" / "hosts"
    p.parent.mkdir()
    p.write_bytes(ORIGINAL)
    return p


@pytest.fixture
def helper(tmp_path, hosts_file, monkeypatch):
    """Program Files\\TacoGuard is a temp folder; the packaged script is the test copy."""
    pf = tmp_path / "Program Files" / "TacoGuard"
    script = test_copy(hosts_file)
    monkeypatch.setattr(H, "helper_dir", lambda: pf)
    monkeypatch.setattr(H, "packaged_script", lambda: script)
    return {"dir": pf, "script": script}


class RealPowerShell:
    """Stands in for the admin prompt: runs the exact command line, NOT elevated."""

    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, exe, params, timeout):
        self.calls.append(params)
        assert Path(exe) == H.powershell_exe() and Path(exe).parent.parent.parent.name.lower() == "system32"
        r = subprocess.run(f'"{exe}" {params}', capture_output=True, timeout=120, creationflags=0x08000000)
        return r.returncode


@pytest.fixture
def launcher(helper):
    return RealPowerShell()


def run_helper(tmp_path, script: bytes, *args) -> int:
    path = tmp_path / "helper-copy.ps1"
    path.write_bytes(script)
    r = subprocess.run([str(H.powershell_exe()), *PS_FLAGS, "-File", str(path), *args], capture_output=True,
                       timeout=120, creationflags=0x08000000)
    return r.returncode


def write_list(tmp_path, names_or_bytes) -> tuple[Path, str]:
    data = names_or_bytes if isinstance(names_or_bytes, bytes) else "".join(n + "\n" for n in names_or_bytes).encode()
    p = tmp_path / "list.txt"
    p.write_bytes(data)
    return p, hashlib.sha256(data).hexdigest()


def _lists(settings, phishing=("phish-one.example", "phish-two.example"), malware=("drop.example",)):
    if phishing:
        L.install_list(settings, "phishing", ("\n".join(phishing) + "\n").encode())
    if malware:
        L.install_list(settings, "urlhaus", ("\n".join(malware) + "\n").encode())


def _block_lines(data: bytes, encoding="utf-8") -> list[str]:
    text = data.decode(encoding)
    start = text.index(H.BEGIN)
    end = text.index(H.END)
    return text[start:end].splitlines()[2:]


# ---- the script itself ---------------------------------------------------------------------------
def test_script_is_plain_ascii_net_only_and_has_no_hosts_parameter():
    raw = H.packaged_script_path().read_bytes()
    raw.decode("ascii")                                          # ASCII only
    text = raw.decode("ascii")
    assert text.count(HOSTS_LINE) == 1 and text.count(FLUSH_LINE) == 1
    # no cmdlets (a cmdlet from a module would make PowerShell load modules from PSModulePath,
    # which includes folders the user can write)
    code = "\n".join(ln.split("#", 1)[0] for ln in text.splitlines())
    assert not re.search(r"\b(Get|Set|New|Out|Write|Test|Invoke|Remove|Add|Start|Copy|Move|Import|Select|"
                         r"Where|ForEach|Join|Split|Resolve|Convert)-[A-Za-z]", code), "a cmdlet is used"
    assert "Import-Module" not in text and "iex" not in code.lower().split()
    param = re.search(r"param\((.*?)\)\n", text, re.S).group(1)
    assert "$Action" in param and "$List" in param and "$Sha256" in param and "Hosts" not in param
    assert "hosts.tacoguard-original" in text                    # the one backup name
    assert "ipconfig.exe" in text and "[Environment]::SystemDirectory" in text


def test_paths_come_from_windows():
    assert H.default_hosts_path().parts[-3:] == ("drivers", "etc", "hosts")
    assert H.default_hosts_path().parent.parent.parent == H.system_dir()
    assert H.powershell_exe().is_file() and H.powershell_exe().name == "powershell.exe"
    pf = H.program_files()
    assert pf.is_dir() and pf.name.lower() == "program files"
    assert H.helper_path() == pf / "TacoGuard" / "hosts-helper.ps1"
    assert H.backup_path(H.default_hosts_path()).name == "hosts.tacoguard-original"


# ---- end to end through the user-level side ------------------------------------------------------
def test_first_use_installs_the_helper_then_apply_replace_remove(settings, hosts_file, helper, launcher):
    _lists(settings)
    p = H.plan(settings, hosts_path=hosts_file)
    assert p["ready"] and p["domains"] == 3 and p["malware"] == 1 and not p["current"]
    assert p["helper"]["first_use"] and p["helper"]["state"] == "missing"
    assert "doesn't block these sites yet" in p["message"]
    out = H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    assert out.ok and out.code == "done"
    assert out == f"Blocked 3 websites in Windows' hosts file. TacoGuard's small hosts helper is now in {helper['dir']}."
    assert "-EncodedCommand" in launcher.calls[0] and "-File" not in launcher.calls[0]
    assert (helper["dir"] / "hosts-helper.ps1").read_bytes() == helper["script"]   # installed exactly
    data = hosts_file.read_bytes()
    assert data.startswith(ORIGINAL)                            # every line outside the block kept
    assert b"\n" not in data.replace(b"\r\n", b"")              # CRLF kept everywhere
    assert _block_lines(data) == ["0.0.0.0 drop.example", "0.0.0.0 phish-one.example",
                                  "0.0.0.0 phish-two.example"]   # malware first
    assert H.backup_path(hosts_file).read_bytes() == ORIGINAL
    listed = H.list_path(settings)
    assert listed.read_bytes() == b"drop.example\nphish-one.example\nphish-two.example\n"
    p = H.plan(settings, hosts_path=hosts_file)
    assert p["current"] and not p["changed_by_other"] and p["helper"]["state"] == "current"
    assert "up to date" in p["message"]

    # newer lists: the block is REPLACED (never a second one), at the same place, by the installed helper
    L.install_list(settings, "phishing", b"phish-one.example\nphish-two.example\nphish-three.example\n")
    assert not H.plan(settings, hosts_path=hosts_file)["current"]
    out = H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    assert out == "Blocked 4 websites in Windows' hosts file." and out.ok
    assert launcher.calls[1].split(" -File ")[1].startswith('"' + str(helper["dir"] / "hosts-helper.ps1") + '"')
    assert "-Sha256 " + hashlib.sha256(H.list_path(settings).read_bytes()).hexdigest() in launcher.calls[1]
    data = hosts_file.read_bytes()
    assert data.count(H.BEGIN.encode()) == 1 and data.count(H.END.encode()) == 1
    assert data.startswith(ORIGINAL) and len(_block_lines(data)) == 4

    # take it out: the file is back to what it was (plus the one empty line before the block)
    out = H.remove_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    assert out == "TacoGuard's block was taken out of the hosts file." and out.ok and out.code == "removed"
    assert hosts_file.read_bytes() in (ORIGINAL, ORIGINAL + b"\r\n")
    p = H.plan(settings, hosts_path=hosts_file)
    assert not p["current"] and not p["changed_by_other"] and not p["block"]["present"]
    # nothing to take out: no prompt at all
    n = len(launcher.calls)
    out = H.remove_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    assert out.ok and "nothing needed changing" in out and len(launcher.calls) == n


def test_an_updated_helper_is_installed_again(settings, hosts_file, helper, launcher, monkeypatch):
    _lists(settings)
    H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    newer = helper["script"] + b"# TacoGuard was updated\r\n"
    monkeypatch.setattr(H, "packaged_script", lambda: newer)
    assert H.plan(settings, hosts_path=hosts_file)["helper"] == {"state": "old", "dir": str(helper["dir"]),
                                                                  "first_use": True}
    L.install_list(settings, "phishing", b"phish-one.example\nphish-two.example\nphish-new.example\n")
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    assert "-EncodedCommand" in launcher.calls[-1]
    assert (helper["dir"] / "hosts-helper.ps1").read_bytes() == newer


def test_command_lines_are_short_and_fixed(settings, tmp_path, helper):
    script = helper["script"]
    lst = tmp_path / "with space" / "hosts-list.txt"
    p = H.build_params("apply", lst, "ab" * 32, script=script, target_dir=helper["dir"], install=True)
    assert p.startswith("-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ")
    print(f"first-use command line: {len(p):,} characters")
    assert len(p) < 20000                                       # Windows' limit is 32,767
    text = base64.b64decode(p.split()[-1]).decode("utf-16-le")
    assert hashlib.sha256(script).hexdigest() in text           # the installer checks the bytes it writes
    assert "& $dest -Action 'apply' -List '" + str(lst) + "' -Sha256 '" + "ab" * 32 + "'" in text
    assert not re.search(r"\b(Get|Set|New|Out|Write|Invoke|Import)-[A-Za-z]", text)
    p2 = H.build_params("apply", lst, "ab" * 32, script=script, target_dir=helper["dir"], install=False)
    assert p2 == ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'
                  + str(helper["dir"] / "hosts-helper.ps1") + f'" -Action apply -List "{lst}" -Sha256 ' + "ab" * 32)


UTF16_TEXT = "# hosts in UTF-16\r\n127.0.0.1 localhost\r\n"


@pytest.mark.parametrize("original,encoding", [
    (b"127.0.0.1 localhost\n::1 localhost\n", "utf-8"),                     # LF only
    (b"\xef\xbb\xbf# hosts with a BOM\r\n127.0.0.1 localhost", "utf-8"),    # BOM, no newline at the end
    (b"", "utf-8"),                                                         # empty file
    (b"\xff\xfe" + UTF16_TEXT.encode("utf-16-le"), "utf-16"),               # UTF-16 with its BOM
    (b"# caf\xe9 (ANSI)\r\n10.1.1.1 printer\r\n", "latin-1"),              # not UTF-8: bytes kept
])
def test_outside_bytes_encoding_and_line_endings_are_kept(settings, hosts_file, helper, launcher, original,
                                                          encoding):
    hosts_file.write_bytes(original)
    _lists(settings)
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    data = hosts_file.read_bytes()
    if original.startswith(b"\xef\xbb\xbf"):
        assert data.startswith(original + b"\r\n") and data.count(b"\xef\xbb\xbf") == 1
    else:
        assert data.startswith(original)
    if encoding == "utf-16":
        assert data.startswith(b"\xff\xfe") and len(_block_lines(data, "utf-16")) == 3
    else:
        assert len(_block_lines(data, encoding)) == 3
    if original and b"\r\n" not in original and encoding != "utf-16":
        assert b"\r\n" not in data
    assert H.remove_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    after = hosts_file.read_bytes()
    nl = "\r\n".encode("utf-16-le") if encoding == "utf-16" else (b"\n" if b"\r\n" not in original else b"\r\n")
    if original.startswith(b"\xef\xbb\xbf"):
        assert after == original + b"\r\n" + b"\r\n" or after == original + b"\r\n"
    else:
        assert after in (original, original + nl)
    assert H.backup_path(hosts_file).read_bytes() == original        # the file before TacoGuard's block


def test_damaged_and_doubled_blocks_are_repaired(settings, hosts_file, helper, launcher):
    hosts_file.write_bytes(ORIGINAL + (H.BEGIN + "\r\n0.0.0.0 old.example\r\n").encode() +
                           b"192.168.1.2 printer.home\r\n")
    assert H.plan(settings, hosts_path=hosts_file)["block"]["damaged"]
    _lists(settings)
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    data = hosts_file.read_bytes()
    assert data.count(H.BEGIN.encode()) == 1 and b"old.example" not in data
    assert b"192.168.1.2 printer.home\r\n" in data and b"10.0.0.5 nas.home" in data
    # two blocks (someone copied it): one remains
    text = data.decode()
    block = text[text.index(H.BEGIN):text.index(H.END) + len(H.END)] + "\r\n"
    hosts_file.write_bytes((text + block).encode())
    L.install_list(settings, "phishing", b"phish-one.example\nphish-two.example\nphish-3.example\n")
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    assert hosts_file.read_bytes().count(H.BEGIN.encode()) == 1


def test_cap_keeps_malware_sites_first(settings, hosts_file, helper, launcher, monkeypatch):
    monkeypatch.setattr(H, "CAP", 50)
    _lists(settings, phishing=[f"phish{i}.example" for i in range(40)],
           malware=[f"drop{i}.example" for i in range(30)])
    p = H.plan(settings, hosts_path=hosts_file)
    assert p["capped"] and p["domains"] == 50 and p["malware"] == 30 and p["phishing"] == 20
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file) == \
        "Blocked 50 websites in Windows' hosts file. TacoGuard's small hosts helper is now in " + str(helper["dir"]) + "."
    lines = _block_lines(hosts_file.read_bytes())
    assert len(lines) == 50 and all("drop" in ln for ln in lines[:30])


def test_block_never_lists_protected_unusual_or_allowed_names(settings, hosts_file, helper, launcher):
    L.install_list(settings, "phishing", b"phish-one.example\nmicrosoft.com\nlogin.live.com\nunder_score.example\n"
                                         b"trusted.example\nshop.trusted.example\nsmartscreen.microsoft.com\n"
                                         b"aka.ms\nsteamstatic.com\n")
    settings.webblock_allow = ["Trusted.Example", "not a name"]
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    assert _block_lines(hosts_file.read_bytes()) == ["0.0.0.0 phish-one.example"]
    # the allow list changes: the block is no longer what TacoGuard would write
    settings.webblock_allow = []
    p = H.plan(settings, hosts_path=hosts_file)
    assert not p["current"] and p["domains"] == 3 and "newer lists are ready" in p["message"]


# ---- the helper's own checks (run directly, not elevated, on the test copy) ----------------------
def test_helper_refuses_a_checksum_mismatch(tmp_path, hosts_file):
    script = test_copy(hosts_file)
    lst, _ = write_list(tmp_path, ["phish-one.example"])
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", "0" * 64) == H.EXIT_SHA
    assert hosts_file.read_bytes() == ORIGINAL
    assert not H.backup_path(hosts_file).exists()


@pytest.mark.parametrize("content", [
    b"phish-one.example\nwindowsupdate.com\n",          # a protected name the helper knows itself
    b"phish-one.example\nupdate.microsoft.com\n",
    b"phish-one.example\n192.168.1.1\n",                # an IP address
    b"phish-one.example\nUPPER.example\n",              # not lower case
    b"phish-one.example\nspace .example\n",
    b"phish-one.example\n-dash.example\n",
    b"phish-one.example\nlocalhost\n",                  # no dot
    b"phish-one.example\r\nphish-two.example\r\n",      # CR
    b"phish-one.example\n\nphish-two.example\n",        # an empty line
    b"phish-one.example",                               # no newline at the end
    b"caf\xc3\xa9.example\n",                           # not ASCII
    b"phish-one.example\n0.0.0.0 evil.example\n",       # a hosts line smuggled in
])
def test_helper_refuses_a_list_with_a_bad_line(tmp_path, hosts_file, content):
    script = test_copy(hosts_file)
    lst, sha = write_list(tmp_path, content)
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", sha) == H.EXIT_BAD_LIST
    assert hosts_file.read_bytes() == ORIGINAL


def test_helper_refuses_odd_requests_and_list_paths(tmp_path, hosts_file):
    script = test_copy(hosts_file)
    lst, sha = write_list(tmp_path, ["phish-one.example"])
    assert run_helper(tmp_path, script, "-Action", "format-disk") == H.EXIT_USAGE
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", "nothex") == H.EXIT_USAGE
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", "relative.txt", "-Sha256", sha) == H.EXIT_BAD_LIST
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(tmp_path / "missing.txt"),
                      "-Sha256", sha) == H.EXIT_BAD_LIST
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(tmp_path), "-Sha256", sha) == H.EXIT_BAD_LIST
    big = tmp_path / "big.txt"
    with open(big, "wb") as f:
        f.truncate(8 * 1024 * 1024 + 1)
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(big), "-Sha256", sha) == H.EXIT_BAD_LIST
    assert hosts_file.read_bytes() == ORIGINAL


def test_helper_refuses_a_reparse_point_list(tmp_path, hosts_file):
    import _winapi
    script = test_copy(hosts_file)
    lst, sha = write_list(tmp_path, ["phish-one.example"])
    link = tmp_path / "link.txt"
    try:
        os.symlink(lst, link)                       # a file symlink (needs Developer Mode or admin)
        targets = [link]
    except OSError:
        targets = []
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(tmp_path / "etc"), str(junction))   # no special rights needed
    targets.append(junction)
    for t in targets:
        assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(t), "-Sha256", sha) == H.EXIT_BAD_LIST, t
    assert hosts_file.read_bytes() == ORIGINAL


def test_helper_writes_the_backup_once_only(tmp_path, hosts_file):
    script = test_copy(hosts_file)
    lst, sha = write_list(tmp_path, ["phish-one.example"])
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", sha) == 0
    assert H.backup_path(hosts_file).read_bytes() == ORIGINAL
    hosts_file.write_bytes(hosts_file.read_bytes() + b"10.9.9.9 added-later.home\r\n")
    lst, sha = write_list(tmp_path, ["phish-one.example", "phish-two.example"])
    assert run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", sha) == 0
    assert b"added-later.home" in hosts_file.read_bytes()
    assert H.backup_path(hosts_file).read_bytes() == ORIGINAL           # the first original, kept
    assert run_helper(tmp_path, script, "-Action", "remove") == 0
    assert H.backup_path(hosts_file).read_bytes() == ORIGINAL
    assert sorted(p.name for p in hosts_file.parent.iterdir()) == ["hosts", "hosts.tacoguard-original"]
    # same request again: nothing changes, nothing written
    before = hosts_file.stat().st_mtime_ns
    assert run_helper(tmp_path, script, "-Action", "remove") == 0
    assert hosts_file.stat().st_mtime_ns == before


def test_helper_reports_a_read_only_hosts_file_as_blocked(tmp_path, hosts_file):
    import stat
    script = test_copy(hosts_file)
    lst, sha = write_list(tmp_path, ["phish-one.example"])
    hosts_file.chmod(stat.S_IREAD)
    try:
        code = run_helper(tmp_path, script, "-Action", "apply", "-List", str(lst), "-Sha256", sha)
    finally:
        hosts_file.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert code == H.EXIT_BLOCKED
    assert hosts_file.read_bytes() == ORIGINAL
    assert not (hosts_file.parent / "hosts.tacoguard-new").exists()


# ---- plain words ---------------------------------------------------------------------------------
def test_admin_prompt_answers_in_plain_words(settings, hosts_file, helper):
    _lists(settings)

    def said_no(exe, params, timeout):
        raise H.LaunchCancelled()

    def too_slow(exe, params, timeout):
        raise H.LaunchTimeout()

    out = H.apply_elevated(settings, launcher=said_no, hosts_path=hosts_file)
    assert out == H.CANCELLED_MSG and not out.ok and out.code == "cancelled" and "answer was No" in out
    assert H.apply_elevated(settings, launcher=too_slow, hosts_path=hosts_file) == H.TIMEOUT_MSG
    assert H.apply_elevated(settings, launcher=lambda e, p, t: 0, hosts_path=hosts_file) == H.NO_ANSWER_MSG
    out = H.apply_elevated(settings, launcher=lambda e, p, t: H.EXIT_BLOCKED, hosts_path=hosts_file)
    assert out == H.BLOCKED_MSG and "Defender" in out and out.code == "blocked" and not out.ok
    assert "changed back right away" in H.apply_elevated(settings, launcher=lambda e, p, t: 7, hosts_path=hosts_file)
    assert "changed after you clicked" in H.apply_elevated(settings, launcher=lambda e, p, t: 4, hosts_path=hosts_file)
    assert str(helper["dir"]) in H.apply_elevated(settings, launcher=lambda e, p, t: 10, hosts_path=hosts_file)
    assert "(code 77)" in H.apply_elevated(settings, launcher=lambda e, p, t: 77, hosts_path=hosts_file)
    # the real prompt never shows in tests
    out = H.apply_elevated(settings, hosts_path=hosts_file)
    assert "Tests never show a real admin prompt" in out and not out.ok
    assert hosts_file.read_bytes() == ORIGINAL


def test_a_helper_folder_others_can_change_is_never_run(settings, hosts_file, helper, monkeypatch):
    _lists(settings)
    monkeypatch.setattr(H, "helper_state", lambda script=None: "open")
    calls = []
    out = H.apply_elevated(settings, launcher=lambda e, p, t: calls.append(p) or 0, hosts_path=hosts_file)
    assert not out.ok and "can be changed by other accounts" in out and calls == []


def test_a_changed_install_never_gets_the_helper_installed(settings, hosts_file, helper, monkeypatch):
    """TGUARD-20261127-04: the helper is copied from the installed copy, which the user's account can
    change, so the admin step is refused while the install check finds changed files."""
    from tacoguard import selfprotect
    _lists(settings)
    monkeypatch.setattr(selfprotect, "check_install", lambda *a, **k: ["changed: tacoguard/webblock/hosts-helper.ps1"])
    calls = []
    out = H.apply_elevated(settings, launcher=lambda e, p, t: calls.append(p) or 0, hosts_path=hosts_file)
    assert not out.ok and calls == [] and "not the ones TacoGuard installed" in out
    assert "won't ask for administrator rights" in out
    assert hosts_file.read_bytes() == ORIGINAL


def test_no_lists_yet(settings, hosts_file, helper):
    calls = []
    out = H.apply_elevated(settings, launcher=lambda e, p, t: calls.append(p) or 0, hosts_path=hosts_file)
    assert out == H.NO_LISTS_MSG and not out.ok and not calls
    assert H.plan(settings, hosts_path=hosts_file)["message"] == H.NO_LISTS_MSG


def test_changes_by_someone_else_are_reported_not_fought(settings, hosts_file, helper, launcher):
    _lists(settings)
    H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    data = hosts_file.read_bytes()
    hosts_file.write_bytes(data.replace(b"0.0.0.0 drop.example\r\n", b""))
    p = H.plan(settings, hosts_path=hosts_file)
    assert p["changed_by_other"] and not p["current"] and "changed by another program" in p["message"]
    assert not p["offer_due"]
    hosts_file.write_bytes(ORIGINAL)
    p = H.plan(settings, hosts_path=hosts_file)
    assert p["changed_by_other"] and "taken out of the hosts file" in p["message"]
    assert hosts_file.read_bytes() == ORIGINAL                  # plan() only reads


def test_weekly_offer_and_removal_offer(settings, hosts_file, helper, launcher):
    _lists(settings)
    assert not H.plan(settings, hosts_path=hosts_file)["offer_due"]     # hosts blocking is off
    settings.webblock_hosts = True
    assert H.plan(settings, hosts_path=hosts_file)["offer_due"]
    H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file)
    L.install_list(settings, "phishing", b"phish-one.example\nphish-two.example\nphish-new.example\n")
    p = H.plan(settings, hosts_path=hosts_file)
    assert not p["offer_due"] and not p["offer_remove"]                 # applied less than 7 days ago
    applied = json.loads(H.applied_path(settings).read_text())
    applied["time"] -= 8 * 86400
    H.applied_path(settings).write_text(json.dumps(applied))
    assert H.plan(settings, hosts_path=hosts_file)["offer_due"]
    # website blocking or the hosts block switched off while the block is still there: removal offered
    settings.webblock_enabled = False
    assert H.plan(settings, hosts_path=hosts_file)["offer_remove"]
    settings.webblock_enabled, settings.webblock_hosts = True, False
    assert H.plan(settings, hosts_path=hosts_file)["offer_remove"]


def test_remove_for_uninstall_takes_the_helper_away_too(settings, hosts_file, helper, launcher):
    _lists(settings)
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    assert (helper["dir"] / "hosts-helper.ps1").exists()
    out = H.remove_elevated(settings, launcher=launcher, hosts_path=hosts_file, cleanup=True)
    assert out.ok and "-EncodedCommand" in launcher.calls[-1]
    assert not helper["dir"].exists()
    assert H.BEGIN.encode() not in hosts_file.read_bytes()


# ---- leaving no block behind: the command line and uninstall ---------------------------------------
def test_hosts_command_status_and_remove(settings, hosts_file, helper, launcher):
    from tacoguard.__main__ import hosts_command
    lines = []
    assert hosts_command(settings, "status", hosts_path=hosts_file, out=lines.append) == 0
    assert lines[0] == "The hosts file has no TacoGuard block."
    lines.clear()
    assert hosts_command(settings, "remove", launcher=launcher, hosts_path=hosts_file, out=lines.append) == 0
    assert "nothing needed changing" in lines[0] and launcher.calls == []      # no prompt for nothing
    _lists(settings)
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok
    lines.clear()
    hosts_command(settings, "status", hosts_path=hosts_file, out=lines.append)
    assert lines[0] == "TacoGuard's block is in the hosts file (3 websites)."

    def said_no(exe, params, timeout):
        raise H.LaunchCancelled()
    lines.clear()
    assert hosts_command(settings, "remove", launcher=said_no, hosts_path=hosts_file, out=lines.append) == 1
    assert lines == [H.CANCELLED_MSG]
    lines.clear()
    assert hosts_command(settings, "remove", launcher=launcher, hosts_path=hosts_file, out=lines.append) == 0
    assert lines == ["TacoGuard's block was taken out of the hosts file."]


def test_hosts_command_is_on_the_command_line():
    from tacoguard import __main__ as M
    with pytest.raises(SystemExit):
        M.main(["hosts", "format-disk"])


def test_uninstall_takes_the_block_out_or_says_how(settings, hosts_file, helper, launcher):
    from tacoguard import install
    assert install.remove_hosts_leftover(settings, launcher=launcher, hosts_path=hosts_file) == ""   # no block
    assert launcher.calls == []
    _lists(settings)
    assert H.apply_elevated(settings, launcher=launcher, hosts_path=hosts_file).ok

    def said_no(exe, params, timeout):
        raise H.LaunchCancelled()
    note = install.remove_hosts_leftover(settings, launcher=said_no, hosts_path=hosts_file)
    assert "still in Windows' hosts file" in note and "you said No" in note
    assert note.endswith(install.hosts_remove_command()) and "-m tacoguard hosts remove" in note
    note = install.remove_hosts_leftover(settings, launcher=launcher, hosts_path=hosts_file)
    assert note == "TacoGuard's block was taken out of Windows' hosts file."
    assert H.BEGIN.encode() not in hosts_file.read_bytes()
    assert not helper["dir"].exists()                           # the helper went with it


def test_reading_the_block_matches_the_prepared_list(tmp_path):
    names = ["a-site.example", "b-site.example"]
    text = "x\r\n" + H.BEGIN + "\r\n" + H.NOTE_PREFIX + " note\r\n" + "".join(f"0.0.0.0 {n}\r\n" for n in names) \
        + H.END + "\r\n"
    p = tmp_path / "hosts"
    p.write_bytes(text.encode())
    b = H.read_block(p)
    assert b == {"readable": True, "present": True, "count": 2, "damaged": False,
                 "sha256": hashlib.sha256(b"a-site.example\nb-site.example\n").hexdigest()}
    assert H.read_block_names(p) == names
    assert H.read_block(tmp_path / "none") == {"readable": True, "present": False, "count": 0, "sha256": "",
                                               "damaged": False}
