"""The installed copy: layout, launcher, scan worker from the installed copy, re-install, uninstall.

Every test uses a temp install folder (TACOGUARD_INSTALL_ROOT) and a temp data folder; the real
%LOCALAPPDATA%\\Programs\\TacoGuard, Start menu and desktop are never touched. The parts are copied
from this .venv (deps="copy"), so no network is used.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from tacoguard import __version__, install as inst
from tacoguard.config import Settings

ROOT = Path(__file__).resolve().parents[1]
REAL_ROOT = Path(os.environ.get("LOCALAPPDATA", r"C:\nowhere")) / "Programs" / "TacoGuard"
NO_WINDOW = 0x08000000


def _not_real(root: Path) -> None:
    assert os.path.normcase(str(Path(root).resolve())) != os.path.normcase(str(REAL_ROOT.resolve()))


def kill_installed(root: Path) -> None:
    """Stop every process running from this test install folder."""
    import psutil
    base = os.path.normcase(str(Path(root).resolve()))
    for p in psutil.process_iter(["pid"]):
        try:
            if os.path.normcase(p.cwd()).startswith(base) or base in os.path.normcase(" ".join(p.cmdline())):
                for k in p.children(recursive=True):
                    k.kill()
                p.kill()
        except (psutil.Error, OSError):
            pass


@pytest.fixture(scope="session")
def golden(tmp_path_factory):
    """One real install (venv + copied parts + selftest), copied by each test that needs one."""
    base = tmp_path_factory.mktemp("golden")
    root = base / "root"
    _not_real(root)
    s = Settings(data_dir=str(base / "data"))
    s.ensure_dirs()
    out = inst.install(s, ROOT, root=root, deps="copy")
    if not out["ok"]:
        pytest.fail("install into a temp folder failed: " + out["message"])
    return root


@pytest.fixture
def installed(golden, tmp_path, monkeypatch):
    root = tmp_path / "root"
    shutil.copytree(golden, root)
    _not_real(root)
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(root))
    yield root
    kill_installed(root)


def _run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=180, creationflags=NO_WINDOW, **kw)


# ---------------------------------------------------------------------------------------------
def test_layout(installed):
    root = installed
    v = __version__
    assert (root / inst.MARKER).is_file()
    assert (root / "venv" / "Scripts" / "python.exe").is_file()
    assert (root / "venv" / "Scripts" / "pythonw.exe").is_file()
    assert inst.same_lock((root / "requirements.lock").read_text(encoding="utf-8"), inst.make_lock(ROOT))
    vdir = root / "versions" / v
    assert (vdir / "tacoguard" / "__init__.py").is_file()
    assert (vdir / "tacoguard" / "web" / "static" / "index.html").is_file()
    assert (vdir / "THIRD_PARTY_LICENSES.md").is_file()          # the page's licence list reads it
    assert (vdir / "requirements.lock").is_file()
    assert not (vdir / "tests").exists()
    assert sorted(rel for rel, _ in inst.package_files(ROOT)) == sorted(
        p.relative_to(vdir).as_posix() for p in vdir.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
        and p.name not in ("requirements.lock", "tacoguard-files.json"))
    # Phase 4: the hash list of this version (selfprotect.py) matches what was installed
    from tacoguard import selfprotect
    assert (vdir / selfprotect.MANIFEST_NAME).is_file()
    assert selfprotect.check_install(version_dir=vdir, root=root) == []
    cur = json.loads((root / "current.json").read_text(encoding="utf-8"))
    assert cur["version"] == v and cur["previous"] is None
    assert (root / "TacoGuard.pyw").is_file() and (root / "TacoGuard.cmd").is_file()
    # the installed parts are the pinned ones, nothing extra like pytest
    site = root / "venv" / "Lib" / "site-packages"
    assert not (site / "pytest").exists()
    assert (site / "yara_x").exists() and (site / "cryptography").exists()


def test_launcher_runs_version_and_selftest(installed, tmp_path):
    data = tmp_path / "data"
    r = _run([installed / "TacoGuard.cmd", "--data", data, "version"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"TacoGuard {__version__} (installed copy)" in r.stdout
    r = _run([installed / "TacoGuard.cmd", "--data", data, "selftest"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "self-test passed" in r.stdout
    assert str((installed / "versions" / __version__ / "tacoguard").resolve()) in r.stdout


def test_windowless_launcher_logs_to_data_folder(installed, tmp_path):
    data = tmp_path / "data"
    pyw = installed / "venv" / "Scripts" / "pythonw.exe"
    r = _run([pyw, installed / "TacoGuard.pyw", "--data", data, "selftest"])
    assert r.returncode == 0
    log = data / "logs" / "launcher.log"
    deadline = time.time() + 60
    while time.time() < deadline:
        if log.is_file() and "self-test passed" in log.read_text(encoding="utf-8", errors="replace"):
            break
        time.sleep(0.3)
    assert "self-test passed" in log.read_text(encoding="utf-8", errors="replace")


def test_scan_worker_starts_from_installed_copy(installed, tmp_path):
    """jobs.launch_worker uses sys.executable -m tacoguard.scan.worker with cwd PROJECT_ROOT,
    which in the installed copy is versions/<v>: the worker must find the package there."""
    data = tmp_path / "data"
    s = Settings(data_dir=str(data))
    s.yara_enabled = False
    s.clamav_enabled = False
    s.ml_enabled = False
    s.save()
    s.hashset_dir.mkdir(parents=True, exist_ok=True)
    (s.hashset_dir / "bad.txt").write_text("0" * 64 + "\n", encoding="utf-8")   # a list to check against
    target = tmp_path / "files"
    target.mkdir()
    (target / "hello.txt").write_text("harmless test file\n", encoding="utf-8")
    script = tmp_path / "run_scan.py"
    script.write_text(
        "import sys, time\n"
        "from tacoguard.config import load_settings\n"
        "from tacoguard.store import Store\n"
        "from tacoguard.scan import jobs\n"
        "s = load_settings(sys.argv[1]); s.ensure_dirs(); st = Store(s.db_path)\n"
        "print('root', jobs.PROJECT_ROOT)\n"
        "jid = jobs.start_scan(s, st, [sys.argv[2]])\n"
        "end = time.time() + 120\n"
        "while time.time() < end:\n"
        "    j = st.get_job(jid)\n"
        "    if j['status'] not in ('queued', 'running'): break\n"
        "    time.sleep(0.3)\n"
        "print('status', j['status'], j['message'])\n", encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(installed / "versions" / __version__))
    r = _run([installed / "venv" / "Scripts" / "python.exe", script, data, target], cwd=str(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"root {installed / 'versions' / __version__}".lower() in r.stdout.lower()
    assert "status done" in r.stdout, r.stdout


def test_reinstall_is_idempotent(installed, tmp_path):
    s = Settings(data_dir=str(tmp_path / "data"))
    before = (installed / "current.json").read_bytes()
    # a frozen copy of the project (files here may change while tests run): refresh once, then a
    # second run must change nothing
    snap = tmp_path / "project"
    for rel, src in inst.package_files(ROOT):
        (snap / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, snap / rel)
    for rel in ("pyproject.toml", "tools/TacoGuard.pyw"):
        (snap / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, snap / rel)
    first = inst.install(s, snap, root=installed, deps="copy")
    assert first["ok"], first["message"]
    assert set(first["changed"]) <= {"version " + __version__, "parts"}
    digest = inst.tree_digest(installed / "versions" / __version__)
    out = inst.install(s, snap, root=installed, deps="copy")
    assert out["ok"], out["message"]
    assert out["changed"] == []
    assert "already installed" in out["message"]
    assert (installed / "current.json").read_bytes() == before
    assert inst.tree_digest(installed / "versions" / __version__) == digest


def test_install_refuses_a_folder_that_is_not_ours(tmp_path):
    root = tmp_path / "someone_else"
    root.mkdir()
    (root / "their_file.txt").write_text("keep me", encoding="utf-8")
    out = inst.install(Settings(data_dir=str(tmp_path / "data")), ROOT, root=root, deps="copy")
    assert not out["ok"] and "aren't TacoGuard's" in out["message"]
    assert (root / "their_file.txt").read_text(encoding="utf-8") == "keep me"
    assert not (root / inst.MARKER).exists()


def test_install_refuses_overlap_with_data_folder(tmp_path):
    data = tmp_path / "data"
    out = inst.install(Settings(data_dir=str(data)), ROOT, root=data / "app", deps="copy")
    assert not out["ok"] and "overlap" in out["message"]


def test_uninstall_keeps_data_and_removes_shortcut(installed, tmp_path):
    data = tmp_path / "data"
    s = Settings(data_dir=str(data))
    s.ensure_dirs()
    s.save()
    (s.quarantine_dir / "item.tgq").write_bytes(b"encrypted")
    menu = tmp_path / "startmenu"                     # never the real Start menu
    lnk = inst.make_shortcut(installed, menu)
    assert lnk.is_file()
    marker = json.loads((installed / inst.MARKER).read_text(encoding="utf-8"))
    marker["shortcut"] = str(lnk)
    (installed / inst.MARKER).write_text(json.dumps(marker), encoding="utf-8")
    out = inst.uninstall(s, root=installed)
    assert out["ok"], out["message"]
    assert not installed.exists()
    assert not lnk.exists()
    assert (data / "settings.json").is_file()
    assert (s.quarantine_dir / "item.tgq").read_bytes() == b"encrypted"


def test_setup_uninstall_step_through_the_launcher(installed, tmp_path):
    """TacoGuard's Setup uninstaller runs `TacoGuard.pyw uninstall --root <app> --keep-files`: the
    launcher and the venv redirector that started it don't count as "TacoGuard is running", the
    files stay (Setup deletes them), and the data folder comes from the install marker."""
    marker = json.loads((installed / inst.MARKER).read_text(encoding="utf-8"))
    assert marker["data_dir"]
    r = _run([installed / "venv" / "Scripts" / "python.exe", installed / "TacoGuard.pyw",
              "uninstall", "--root", installed, "--keep-files"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ready to be removed" in r.stdout and marker["data_dir"] in r.stdout
    assert (installed / "current.json").is_file() and (installed / "venv").is_dir()


def test_setup_uninstall_step_waits_for_a_running_copy(installed):
    busy = subprocess.Popen([str(installed / "venv" / "Scripts" / "python.exe"), "-c",
                             "import time; time.sleep(60)  # tacoguard"], creationflags=NO_WINDOW)
    try:
        deadline = time.time() + 30
        while not inst.installed_copy_running(installed) and time.time() < deadline:
            time.sleep(0.3)
        r = _run([installed / "venv" / "Scripts" / "python.exe", installed / "TacoGuard.pyw",
                  "uninstall", "--root", installed, "--keep-files"])
        assert r.returncode == 3, r.stdout + r.stderr
        assert "Quit" in r.stdout
    finally:
        busy.kill()


def test_cli_root_is_the_normal_folder_only_without_the_test_variable(tmp_path, monkeypatch):
    from tacoguard.__main__ import _chosen_root
    monkeypatch.delenv("TACOGUARD_INSTALL_ROOT", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    normal = tmp_path / "Programs" / "TacoGuard"
    assert _chosen_root(None) is None
    assert _chosen_root(str(normal)) is None                  # start at sign-in + clean-up apply
    assert _chosen_root(str(tmp_path / "other")) == (tmp_path / "other").resolve()
    monkeypatch.setenv("TACOGUARD_INSTALL_ROOT", str(normal))   # tests: never the normal folder
    assert _chosen_root(str(normal)) == normal.resolve()


def test_install_step_arguments():
    import importlib.util
    spec = importlib.util.spec_from_file_location("install_step", ROOT / "tools" / "install_step.py")
    step = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(step)
    assert step.tacoguard_args(r"C:\x") == ["install", "--offline", "--root", r"C:\x"]
    assert step.tacoguard_args(r"C:\x", r"C:\d", sign_in=False) == [
        "--data", r"C:\d", "install", "--offline", "--root", r"C:\x", "--no-sign-in"]


def test_data_folder_on_d_only_when_d_is_a_hard_disk(monkeypatch):
    from tacoguard import config
    real_isdir = os.path.isdir
    monkeypatch.setattr(config.os.path, "isdir", lambda p: p == "D:\\" or (p != r"D:\TacoGuard" and real_isdir(p)))
    monkeypatch.setattr(config, "_fixed_drive", lambda root: True)
    assert config._default_data_dir() == r"D:\TacoGuard"
    monkeypatch.setattr(config, "_fixed_drive", lambda root: False)          # a DVD or USB drive
    assert config._default_data_dir().endswith(r"\TacoGuard") and not config._default_data_dir().startswith("D:")
    monkeypatch.setattr(config.os.path, "isdir", lambda p: p in ("D:\\", r"D:\TacoGuard"))
    assert config._default_data_dir() == r"D:\TacoGuard"                     # an existing folder is kept


def test_installer_pieces():
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_installer", ROOT / "tools" / "build_installer.py")
    bi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bi)
    png = (ROOT / "tacoguard" / "web" / "static" / "icon.png").read_bytes()
    ico = bi.png_to_ico(png)
    assert ico[:6] == b"\0\0\1\0\1\0" and ico[22:] == png
    with pytest.raises(ValueError):
        bi.png_to_ico(b"GIF89a" + b"\0" * 30)
    assert bi._left_out("Doc/html/index.html") and bi._left_out("Lib/tkinter/__init__.py")
    assert bi._left_out("DLLs/_tkinter.pyd") and not bi._left_out("Lib/venv/__init__.py")
    assert not bi._left_out("Lib/testing.py") and not bi._left_out("python.exe")


def test_uninstall_refuses_folder_without_marker(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    out = inst.uninstall(Settings(data_dir=str(tmp_path / "data")), root=root)
    assert not out["ok"]
    assert (root / "a.txt").exists()


# ---------------------------------------------------------------------------------------------
# pieces
# ---------------------------------------------------------------------------------------------
def test_versions_compare_as_numbers():
    assert inst.compare_versions("0.10.0", "0.9.9") == 1
    assert inst.compare_versions("1.0", "1.0.0") == 0
    assert inst.compare_versions("0.1.0", "0.2.0") == -1
    for bad in ("", "1", "1.x", "../1.0", "1.0.0.0.0", "1.0-rc1", None):
        assert not inst.valid_version(bad)


def test_markers():
    assert inst.eval_marker('sys_platform != "cygwin"')
    assert inst.eval_marker('platform_python_implementation == "CPython"')
    assert not inst.eval_marker("platform_python_implementation == 'PyPy'")
    assert not inst.eval_marker('extra == "test"')
    assert inst.eval_marker('extra == "test"', extra="test")
    assert inst.eval_marker('python_version >= "3.9" and (os_name == "nt" or os_name == "posix")')
    assert inst.eval_marker('python_version < "3.100"')        # numbers, not text
    assert not inst.eval_marker('python_version < "3.11"')


def test_lock_follows_dependencies():
    pins = inst.parse_lock(inst.make_lock(ROOT))
    for name in ("yara-x", "cryptography", "cffi", "py7zr", "psutil", "rarfile"):
        assert name in pins
    assert "pytest" not in pins and "pip" not in pins
    assert "backports-zstd" not in pins                          # only for Python < 3.14
    assert inst.same_lock("# c\nA_b==1.0\n", "a-b==1.0")
    assert not inst.same_lock("a==1.0", "a==1.1")


def test_build_package_is_repeatable(tmp_path):
    a = inst.build_package(ROOT, tmp_path / "a.zip")
    b = inst.build_package(ROOT, tmp_path / "b.zip", lock=None)
    assert a["sha256"] == b["sha256"] and a["version"] == __version__
    names = zipfile.ZipFile(tmp_path / "a.zip").namelist()
    assert "tacoguard/__init__.py" in names and "requirements.lock" in names
    assert not any("__pycache__" in n or n.startswith("tests/") or n.endswith(".pyc") for n in names)


def test_prune_keeps_current_and_two_old(tmp_path):
    root = tmp_path / "root"
    for v in ("0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0.staging"):
        (root / "versions" / v).mkdir(parents=True)
    (root / "versions" / "notours").mkdir()
    inst.write_current(root, "0.5.0", "0.2.0")
    removed = inst.prune_versions(root)
    left = sorted(p.name for p in (root / "versions").iterdir())
    assert left == ["0.2.0", "0.4.0", "0.5.0", "notours"]
    assert set(removed) == {"0.1.0", "0.3.0", "0.6.0.staging"}
