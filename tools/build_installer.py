"""Builds TacoGuard's Setup: dist\\TacoGuard-Setup-<version>.exe (Inno Setup 6, per user, no admin).

    .venv\\Scripts\\python.exe tools\\build_installer.py            build it
    .venv\\Scripts\\python.exe tools\\build_installer.py --test     build it, then install it silently into a
                                                                temp folder (temp data folder, own port),
                                                                check it, and uninstall it again

What goes in (staged in build\\installer\\stage, see installer\\TacoGuard.iss):
    runtime\\   python.org's full Windows package of Python PY_VERSION (the same package python.org's
               install manager uses), checked against PY_SHA256 and kept in build\\installer\\cache.
               The help files, IDLE, Tk and the C headers are left out (TacoGuard uses none of them).
    setup\\app\\     TacoGuard's files as `python -m tacoguard install` copies them, + pyproject.toml and
                    tools\\TacoGuard.pyw
    setup\\parts\\   every part in requirements.lock, copied from this .venv (install.copy_parts)
    setup\\install_step.py, .tacoguard-install.json, TacoGuard.ico, LICENSE.txt

Run it with the project's .venv Python: its version must be PY_VERSION, because the copied parts
are built for it. The only download is the Python package from www.python.org (a build-time
download on this PC; the installed TacoGuard never contacts python.org).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tacoguard import install as inst          # noqa: E402

BUILD = ROOT / "build" / "installer"
STAGE = BUILD / "stage"
CACHE = BUILD / "cache"
DIST = ROOT / "dist"
ISS = ROOT / "installer" / "TacoGuard.iss"

PY_VERSION = "3.14.10"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-amd64.zip"
# SHA-256 as python.org lists it in https://www.python.org/ftp/python/index-windows.json (the install
# manager's index; checked 2026-11-27). A different file stops the build.
PY_SHA256 = {"3.14.10": "cc28026a650970cc1570bb127312f1f9634eb67abfe157ae6ca1acbbc627d091"}

# parts of Python TacoGuard never uses (left out of runtime\)
PY_LEAVE_OUT_DIRS = ("Lib/test", "Lib/idlelib", "Lib/tkinter", "Lib/turtledemo", "Lib/site-packages",
                     "tcl", "include", "libs", "Tools", "Doc")
PY_LEAVE_OUT_FILES = ("DLLs/_tkinter.pyd", "DLLs/tcl86t.dll", "DLLs/tk86t.dll", "Lib/turtle.py")

ISCC = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"), Path(r"C:\Program Files\Inno Setup 6\ISCC.exe")]
NO_WINDOW = 0x08000000
TEST_PORT = 8897


def say(msg: str) -> None:
    print(msg, flush=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def python_zip() -> Path:
    """The python.org package, downloaded once and checked every time."""
    want = PY_SHA256.get(PY_VERSION)
    if not want:
        sys.exit(f"No checksum on record for Python {PY_VERSION}: add python.org's SHA-256 to PY_SHA256.")
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"python-{PY_VERSION}-amd64.zip"
    if not path.is_file():
        say(f"Downloading {PY_URL}")
        tmp = path.with_suffix(".part")
        with urllib.request.urlopen(PY_URL, timeout=120) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        os.replace(tmp, path)
    got = sha256(path)
    if got != want:
        path.unlink()
        sys.exit(f"The Python package's SHA-256 is {got}, not python.org's {want}. Stopped (file removed).")
    return path


def _left_out(name: str) -> bool:
    name = name.replace("\\", "/")
    return any(name == d or name.startswith(d + "/") for d in PY_LEAVE_OUT_DIRS) or name in PY_LEAVE_OUT_FILES


def unpack_python(zip_path: Path, dest: Path) -> int:
    """Unpacks the package into dest without the parts in PY_LEAVE_OUT_*. Returns the file count."""
    n = 0
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir() or _left_out(name):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest) + os.sep):
                sys.exit(f"Unsafe path in the Python package: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
    for need in ("python.exe", "pythonw.exe", "Lib/venv/scripts/nt/venvlauncher.exe",
                 "Lib/venv/scripts/nt/venvwlauncher.exe"):
        if not (dest / need).is_file():
            sys.exit(f"The Python package has no {need}; TacoGuard's Setup needs it.")
    return n


def png_to_ico(png: bytes) -> bytes:
    """A one-image .ico holding the PNG as it is (Windows Vista and later read PNG icons)."""
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    w, h = struct.unpack(">II", png[16:24])
    if w > 256 or h > 256:
        raise ValueError("icons are at most 256 x 256")
    entry = struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(png), 6 + 16)
    return struct.pack("<HHH", 0, 1, 1) + entry + png


def stage(version: str) -> dict:
    if sys.version.split()[0] != PY_VERSION:
        sys.exit(f"Run this with the project's .venv (Python {PY_VERSION}); this is {sys.version.split()[0]}.")
    say(f"TacoGuard {version}: staging in {STAGE}")
    inst.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    n = unpack_python(python_zip(), STAGE / "runtime")
    say(f"  Python {PY_VERSION} from python.org ({n} files)")

    app = STAGE / "setup" / "app"
    for rel, src in inst.package_files(ROOT):
        dst = app / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    shutil.copy2(ROOT / "pyproject.toml", app / "pyproject.toml")
    (app / "tools").mkdir()
    shutil.copy2(ROOT / "tools" / inst.LAUNCHER, app / "tools" / inst.LAUNCHER)
    if inst.package_version(app / "tacoguard") != version:
        sys.exit("The staged copy has the wrong version number.")

    lock = inst.make_lock(ROOT)
    pins = inst.parse_lock(lock)
    inst.copy_parts(STAGE / "setup" / "parts", pins)
    say(f"  {len(pins)} parts from requirements.lock")
    shutil.copy2(ROOT / "tools" / "install_step.py", STAGE / "setup" / "install_step.py")

    marker = {"app": "TacoGuard", "note": "Made by TacoGuard's Setup. Uninstall it from Windows' Installed apps; "
                                          "your data folder is kept."}
    (STAGE / inst.MARKER).write_text(json.dumps(marker, indent=2), encoding="utf-8")
    (STAGE / "TacoGuard.ico").write_bytes(png_to_ico((ROOT / "tacoguard" / "web" / "static" / "icon.png").read_bytes()))
    shutil.copy2(ROOT / "LICENSE", STAGE / "LICENSE.txt")
    files = sum(len(f) for _, _, f in os.walk(STAGE))
    size = sum(p.stat().st_size for p in STAGE.rglob("*") if p.is_file())
    say(f"  staged {files:,} files, {size / 1e6:.0f} MB")
    return {"files": files, "bytes": size, "lock": lock}


def compile_setup(version: str) -> Path:
    iscc = next((p for p in ISCC if p.is_file()), None)
    if not iscc:
        sys.exit("Inno Setup 6 not found: winget install JRSoftware.InnoSetup")
    DIST.mkdir(exist_ok=True)
    say("Compressing with Inno Setup (a few minutes) ...")
    subprocess.run([str(iscc), "/Q", f"/DAppVersion={version}", f"/DStage={STAGE}", f"/DOutDir={DIST}", str(ISS)],
                   check=True)
    exe = DIST / f"TacoGuard-Setup-{version}.exe"
    digest = sha256(exe)
    (DIST / f"{exe.name}.sha256").write_text(f"{digest}  {exe.name}\n", encoding="ascii")
    say(f"Built {exe} ({exe.stat().st_size / 1e6:.1f} MB), SHA-256 {digest}")
    return exe


# ---------------------------------------------------------------------------------------------
# --test: a real silent install into a temp folder, checked, then uninstalled
# ---------------------------------------------------------------------------------------------
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{D2B848E6-E9C6-4B97-80B0-C817204CC46D}_is1"


def _uninstall_entry() -> str | None:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as k:
            return winreg.QueryValueEx(k, "InstallLocation")[0]
    except OSError:
        return None


def _run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=600, creationflags=NO_WINDOW, **kw)


def _kill_tree(proc) -> None:
    import psutil
    try:
        p = psutil.Process(proc.pid)
        for k in p.children(recursive=True):
            k.kill()
        p.kill()
    except psutil.Error:
        pass


def _page_check(app: Path, data: Path, version: str) -> str:
    """Starts the test copy's page on TEST_PORT, reads the page and one API answer, stops it."""
    import re
    proc = subprocess.Popen([str(app / "venv" / "Scripts" / "python.exe"), str(app / inst.LAUNCHER),
                             "--data", str(data), "serve", "--port", str(TEST_PORT), "--no-browser"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
    try:
        html, deadline = "", time.time() + 90
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{TEST_PORT}/", timeout=5) as r:
                    html = r.read().decode("utf-8", "replace")
                break
            except OSError:
                time.sleep(1)
        if "TacoGuard" not in html:
            return "the page did not answer"
        m = re.search(r'name="tacoguard-token" content="([^"]+)"', html)
        if not m:
            return "the page has no token"
        req = urllib.request.Request(f"http://127.0.0.1:{TEST_PORT}/api/allowlist",
                                     headers={"X-TacoGuard-Token": m.group(1)})
        with urllib.request.urlopen(req, timeout=10) as r:
            json.loads(r.read())
        return ""
    finally:
        _kill_tree(proc)
        proc.wait(30)


def test_setup(exe: Path, version: str) -> bool:
    if _uninstall_entry():
        say("A TacoGuard made by Setup is already installed on this PC; the test would clash with it. Skipped.")
        return False
    tmp = Path(tempfile.mkdtemp(prefix="tg-setup-test-"))
    app, data = tmp / "app", tmp / "data"
    data.mkdir()
    # a quiet test copy: no guard, no downloads, no tray, no process hardening, no start at sign-in
    (data / "settings.json").write_text(json.dumps({
        "realtime_enabled": False, "auto_update": False, "webblock_enabled": False, "tray_enabled": False,
        "self_protection": False, "start_at_sign_in": False}), encoding="utf-8")
    problems = []

    def check(ok, what):
        say(f"  {'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            problems.append(what)

    say(f"Test install into {app}")
    t0 = time.time()
    r = _run([exe, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/DIR={app}",
              "/MERGETASKS=!startmenu,!desktopicon,!signin", f"/data={data}", f"/LOG={tmp / 'setup.log'}"])
    check(r.returncode == 0, f"Setup finished (exit code {r.returncode}, {time.time() - t0:.0f} s)")
    if r.returncode != 0 and (app / "setup-log.txt").is_file():
        say((app / "setup-log.txt").read_text(encoding="utf-8", errors="replace")[-2000:])
    cur = inst.read_current(app) or {}
    check(cur.get("version") == version, f"current.json says {cur.get('version')}")
    check(not (app / "setup").exists(), "the setup folder was removed after the install step")
    cfg = (app / "venv" / "pyvenv.cfg").read_text(encoding="utf-8") if (app / "venv" / "pyvenv.cfg").is_file() else ""
    home = next((ln.split("=", 1)[1].strip() for ln in cfg.splitlines() if ln.startswith("home")), "")
    check(os.path.normcase(home) == os.path.normcase(str(app / "runtime")), "venv is made from runtime\\")
    r = _run([app / "TacoGuard.cmd", "--data", data, "selftest"])
    check(r.returncode == 0 and f"TacoGuard {version} self-test passed" in r.stdout, "self-test passed")
    r = _run([app / "venv" / "Scripts" / "python.exe", "-c",
              "import numpy, scipy, lightgbm, yara_x, cryptography, py7zr, rarfile, psutil, pefile, signify; print('ok')"])
    check(r.stdout.strip() == "ok", "every part loads " + (r.stderr.strip()[-300:] if r.returncode else ""))
    err = _page_check(app, data, version)
    check(not err, "the page starts and answers" + (f" ({err})" if err else ""))
    check(_uninstall_entry() is not None, "listed in Installed apps")

    say("Test uninstall")
    r = _run([app / "unins000.exe", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
    deadline = time.time() + 120
    while app.exists() and time.time() < deadline:
        time.sleep(1)
    check(not app.exists(), "the install folder is gone")
    check(_uninstall_entry() is None, "no longer listed in Installed apps")
    check((data / "settings.json").is_file(), "the data folder was kept")
    if not problems:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        say(f"Left for a look: {tmp}")
    say("Setup test passed." if not problems else f"Setup test FAILED: {len(problems)} problem(s).")
    return not problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--test", action="store_true", help="also install, check and uninstall it in a temp folder")
    ap.add_argument("--stage-only", action="store_true", help="stage the files, don't compile")
    a = ap.parse_args(argv)
    version = inst.package_version(ROOT / "tacoguard")
    stage(version)
    if a.stage_only:
        return 0
    exe = compile_setup(version)
    if a.test:
        return 0 if test_setup(exe, version) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
