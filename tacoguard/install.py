"""The installed copy of TacoGuard (Phase 2), per user, no admin rights.

    python -m tacoguard install [--shortcut] [--offline]
    python -m tacoguard uninstall
    python -m tacoguard selftest

Layout of config.install_root() (%LOCALAPPDATA%\\Programs\\TacoGuard):

    .tacoguard-install.json   marker: this folder belongs to TacoGuard (uninstall needs it)
    venv\\                     Python made from the same base interpreter as the one running the
                              installer, with exactly the parts listed in requirements.lock
    requirements.lock         name==version of every part TacoGuard needs (pinned to the project's .venv)
    versions\\<version>\\       tacoguard\\ package (no tests, no __pycache__), licences, requirements.lock,
                              tacoguard-files.json (Phase 4: sha256 of every file + the launcher,
                              checked by the page at start, tacoguard/selfprotect.py)
    current.json              {"version": "...", "previous": "..."}, switched with os.replace
    TacoGuard.pyw             launcher: reads current.json, runs `-m tacoguard serve` from that version
    TacoGuard.cmd             the same launcher in a console window (for `version`, `selftest`, ...)
    health.json, update.lock, update_result.json   self-update state (tacoguard/selfupdate.py)

The data folder (D:\\TacoGuard: settings, database, quarantine) is never inside the install folder
and uninstall never touches it. No service or scheduled task is created. Phase 3: when
settings.start_at_sign_in is on, install adds ONE value to your own Run key (tacoguard/autostart.py:
the installed launcher with --background); uninstall removes it again, and removes the guard's
decoy files (tacoguard/guard/ransom.py). A custom `root` (tests) never touches the Run key unless
asked (autostart=True with a test key).

A release package (what self-update installs) is a zip with the same files as versions\\<version>\\:
build it with build_package(); selfupdate.py unpacks and checks it.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import zipfile
from pathlib import Path

from . import __version__
from .config import install_root

MARKER = ".tacoguard-install.json"
LOCK_NAME = "requirements.lock"
CURRENT = "current.json"
LAUNCHER = "TacoGuard.pyw"
LAUNCHER_CMD = "TacoGuard.cmd"
SHORTCUT_NAME = "TacoGuard.lnk"
EXTRA_FILES = ("LICENSE", "THIRD_PARTY_LICENSES.md", "README.md")
VERSION_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){1,3}$")
CREATE_NO_WINDOW = 0x08000000
KEEP_OLD_VERSIONS = 2
POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


class InstallError(Exception):
    """Plain-English reason the install could not go on."""


# ---------------------------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------------------------
def valid_version(v) -> bool:
    return isinstance(v, str) and bool(VERSION_RE.match(v))


def version_tuple(v: str) -> tuple[int, ...]:
    """'0.2.10' -> (0, 2, 10, 0). Raises ValueError for anything else."""
    if not valid_version(v):
        raise ValueError(f"not a version number: {v!r}")
    parts = [int(p) for p in v.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def compare_versions(a: str, b: str) -> int:
    ta, tb = version_tuple(a), version_tuple(b)
    return (ta > tb) - (ta < tb)


def package_version(pkg_dir: Path) -> str | None:
    """The __version__ written in <pkg_dir>/__init__.py, read as text (nothing is imported)."""
    try:
        text = (Path(pkg_dir) / "__init__.py").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    return m.group(1) if m and valid_version(m.group(1)) else None


# ---------------------------------------------------------------------------------------------
# requirements.lock: the project's dependencies, pinned to what is installed in this Python
# ---------------------------------------------------------------------------------------------
def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_TOKEN = re.compile(r"""\s*(\(|\)|===|==|!=|<=|>=|~=|<|>|not\s+in\b|in\b|and\b|or\b|not\b|"[^"]*"|'[^']*'|[A-Za-z_][A-Za-z0-9_.]*)""")
_VERSION_VARS = {"python_version", "python_full_version", "implementation_version"}


def _marker_env(extra: str) -> dict:
    impl = sys.implementation
    iv = impl.version
    impl_version = f"{iv.major}.{iv.minor}.{iv.micro}"
    import platform
    return {
        "os_name": os.name, "sys_platform": sys.platform, "platform_system": platform.system(),
        "platform_machine": platform.machine(), "platform_release": platform.release(),
        "platform_python_implementation": platform.python_implementation(),
        "implementation_name": impl.name, "implementation_version": impl_version,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_full_version": platform.python_version(), "extra": extra,
    }


def _vt_loose(s: str) -> tuple:
    out = []
    for p in s.split("."):
        m = re.match(r"\d+", p)
        out.append(int(m.group(0)) if m else 0)
    return tuple(out + [0] * (4 - len(out)))


def eval_marker(marker: str, extra: str = "") -> bool:
    """A small evaluator for dependency markers (PEP 508): enough for `python_version < "3.14"`,
    `sys_platform != "cygwin"`, `extra == "test"` joined with and / or / brackets."""
    toks, pos = [], 0
    marker = marker.strip()
    while pos < len(marker):
        m = _TOKEN.match(marker, pos)
        if not m:
            raise ValueError(f"cannot read marker {marker!r}")
        toks.append(re.sub(r"\s+", " ", m.group(1)))
        pos = m.end()
    env = _marker_env(extra)
    i = 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def value(tok):
        if tok[0] in "\"'":
            return tok[1:-1], None
        if tok not in env:
            raise ValueError(f"unknown marker name {tok!r}")
        return env[tok], tok

    def atom():
        if peek() == "(":
            take()
            r = expr()
            if take() != ")":
                raise ValueError("unbalanced brackets in marker")
            return r
        lv, lname = value(take())
        op = take()
        rv, rname = value(take())
        if (lname or rname) in _VERSION_VARS and op not in ("in", "not in"):
            a, b = _vt_loose(lv), _vt_loose(rv)
        else:
            a, b = lv, rv
        if op in ("==", "==="):
            return a == b
        if op == "!=":
            return a != b
        if op == "<":
            return a < b
        if op == "<=":
            return a <= b
        if op == ">":
            return a > b
        if op == ">=":
            return a >= b
        if op == "~=":
            return a >= b
        if op == "in":
            return lv in rv
        if op == "not in":
            return lv not in rv
        raise ValueError(f"unknown marker operator {op!r}")

    def conj():
        r = atom()
        while peek() == "and":
            take()
            r = atom() and r
        return r

    def expr():
        r = conj()
        while peek() == "or":
            take()
            r = conj() or r
        return r

    result = expr()
    if i != len(toks):
        raise ValueError(f"cannot read marker {marker!r}")
    return bool(result)


def _parse_req(req: str) -> tuple[str, set[str], str]:
    """'py7zr[full] (>=1.0) ; python_version < "3.14"' -> ('py7zr', {'full'}, 'python_version < "3.14"')."""
    spec, _, marker = req.partition(";")
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[([^\]]*)\])?", spec)
    if not m:
        raise ValueError(f"cannot read requirement {req!r}")
    extras = {canonical(e) for e in (m.group(3) or "").split(",") if e.strip()}
    return m.group(1), extras, marker.strip()


def _wanted(marker: str, extras: set[str]) -> bool:
    if not marker:
        return True
    return any(eval_marker(marker, e) for e in ({""} | extras))


def project_requirements(project_root: Path) -> list[str]:
    data = tomllib.loads((Path(project_root) / "pyproject.toml").read_text(encoding="utf-8"))
    return list(data.get("project", {}).get("dependencies", []))


def resolve_lock(requirements: list[str]) -> dict[str, str]:
    """Every distribution the requirements need (followed through their own requirements) with
    the version installed in THIS Python. Raises InstallError when one is missing."""
    found: dict[str, str] = {}
    todo = [(r, set()) for r in requirements]
    while todo:
        req, _ = todo.pop()
        name, extras, marker = _parse_req(req)
        if not _wanted(marker, set()):
            continue
        key = canonical(name)
        if key in found:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            raise InstallError(f"The part '{name}' that TacoGuard needs is not installed in this Python. "
                               "Run `.venv\\Scripts\\python.exe -m pip install -e .` in the project folder "
                               "first.") from None
        found[key] = dist.version
        for sub in dist.requires or []:
            sname, sextras, smarker = _parse_req(sub)
            if _wanted(smarker, extras):
                todo.append((f"{sname}[{','.join(sextras)}]" if sextras else sname, set()))
    return dict(sorted(found.items()))


def lock_text(pins: dict[str, str]) -> str:
    lines = ["# TacoGuard's parts, pinned. Self-update refuses a version whose list differs."]
    lines += [f"{k}=={v}" for k, v in sorted(pins.items())]
    return "\n".join(lines) + "\n"


def make_lock(project_root: Path) -> str:
    return lock_text(resolve_lock(project_requirements(project_root)))


def parse_lock(text: str) -> dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, sep, ver = line.partition("==")
        if not sep:
            raise ValueError(f"bad line in requirements.lock: {line!r}")
        out[canonical(name.strip())] = ver.strip()
    return out


def same_lock(a: str, b: str) -> bool:
    try:
        return parse_lock(a) == parse_lock(b)
    except ValueError:
        return False


# ---------------------------------------------------------------------------------------------
# the files that make up one version (also the content of a release package)
# ---------------------------------------------------------------------------------------------
def package_files(project_root: Path) -> list[tuple[str, Path]]:
    """(relative path with /, absolute path) of the tacoguard package (no __pycache__ / .pyc)
    plus the licence files, sorted."""
    root = Path(project_root)
    pkg = root / "tacoguard"
    out = []
    for dirpath, dirnames, filenames in os.walk(pkg):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
        for fn in sorted(filenames):
            if fn.endswith((".pyc", ".pyo", ".tmp")):
                continue
            p = Path(dirpath) / fn
            out.append((p.relative_to(root).as_posix(), p))
    for name in EXTRA_FILES:
        if (root / name).is_file():
            out.append((name, root / name))
    return sorted(out)


def tree_digest(folder: Path) -> str:
    """One sha256 over every file's relative path and content (folders compared as a whole)."""
    h = hashlib.sha256()
    folder = Path(folder)
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if fn.endswith((".pyc", ".pyo")):
                continue
            p = Path(dirpath) / fn
            h.update(p.relative_to(folder).as_posix().encode("utf-8") + b"\0")
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def build_package(project_root: Path, out_path: Path, lock: str | None = None) -> dict:
    """A release zip of this project's TacoGuard (for tools/release.py). Same bytes for the same
    files (fixed dates, sorted), so a rebuilt release does not look like a changed one.
    Returns {"file", "version", "length", "sha256"}."""
    project_root = Path(project_root)
    version = package_version(project_root / "tacoguard")
    if not version:
        raise InstallError("Could not read the version number in tacoguard/__init__.py.")
    lock = lock if lock is not None else make_lock(project_root)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        entries = [(rel, p.read_bytes()) for rel, p in package_files(project_root)]
        entries.append((LOCK_NAME, lock.encode("utf-8")))
        for rel, data in sorted(entries):
            zi = zipfile.ZipInfo(rel, date_time=(2020, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, data)
    os.replace(tmp, out_path)
    data = out_path.read_bytes()
    return {"file": str(out_path), "version": version, "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


# ---------------------------------------------------------------------------------------------
# small helpers shared with selfupdate.py
# ---------------------------------------------------------------------------------------------
def write_json(path: Path, obj) -> None:
    """Write JSON next to `path` and swap it in with os.replace (retried: a reader may hold it)."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.1)


def read_json(path: Path) -> dict | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def read_current(root: Path | None = None) -> dict | None:
    """current.json, or None when missing / damaged / naming a bad version."""
    root = Path(root or install_root())
    cur = read_json(root / CURRENT)
    if not cur or not valid_version(cur.get("version")):
        return None
    if cur.get("previous") is not None and not valid_version(cur.get("previous")):
        cur["previous"] = None
    return cur


def write_current(root: Path, version: str, previous: str | None, **extra) -> None:
    obj = {"version": version, "previous": previous, "switched": time.time(), **extra}
    write_json(Path(root) / CURRENT, obj)


def venv_python(root: Path, windowless: bool = False) -> Path:
    return Path(root) / "venv" / "Scripts" / ("pythonw.exe" if windowless else "python.exe")


def version_env(root: Path, version: str) -> dict:
    """Environment for running one installed version: its folder first (and only) on PYTHONPATH."""
    env = dict(os.environ)
    env.pop("PYTHONHOME", None)
    env["PYTHONPATH"] = str(Path(root) / "versions" / version)
    return env


def rmtree(path: Path) -> None:
    def onexc(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if Path(path).exists():
        shutil.rmtree(path, onexc=onexc)


def run_selftest(root: Path, version: str, data_dir: str, timeout: float = 180) -> tuple[bool, str]:
    """Runs `python -m tacoguard selftest` from versions/<version> in the installed Python.
    OK only when it exits 0 AND says it ran that version from that folder."""
    vdir = Path(root) / "versions" / version
    cmd = [str(venv_python(root)), "-m", "tacoguard", "--data", str(data_dir), "selftest"]
    try:
        r = subprocess.run(cmd, cwd=str(vdir), env=version_env(root, version), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"the self-test could not run ({e})"
    out = (r.stdout or "") + (r.stderr or "")
    expected = f"TacoGuard {version} "
    where = os.path.normcase(str((vdir / "tacoguard").resolve()))
    ok = r.returncode == 0 and expected in out and where in os.path.normcase(out)
    return ok, out.strip()


def prune_versions(root: Path, keep_old: int = KEEP_OLD_VERSIONS) -> list[str]:
    """Delete versions beyond current + previous + the newest others (at most `keep_old` old
    ones in all), and leftover staging folders. Returns what was removed."""
    root = Path(root)
    vroot = root / "versions"
    cur = read_current(root)
    if not cur or not vroot.is_dir():
        return []
    current, previous = cur["version"], cur.get("previous")
    names = [p.name for p in vroot.iterdir() if p.is_dir()]
    olds = sorted((n for n in names if valid_version(n) and n != current),
                  key=version_tuple, reverse=True)
    keep = {current}
    if previous in olds:
        keep.add(previous)
    for n in olds:
        if len(keep) >= keep_old + 1:
            break
        keep.add(n)
    removed = []
    for n in names:
        if n in keep:
            continue
        if not valid_version(n) and not n.endswith((".staging", ".old")):
            continue        # not ours: leave it alone
        rmtree(vroot / n)
        removed.append(n)
    return removed


def installed_copy_running(root: Path | None = None) -> bool:
    """True when a TacoGuard process runs from this install folder (server, scan worker)."""
    import psutil
    root = Path(root or install_root()).resolve()
    venv = os.path.normcase(str(root / "venv"))
    versions = os.path.normcase(str(root / "versions"))
    me = os.getpid()
    for p in psutil.process_iter(["name", "pid"]):
        if p.info["pid"] == me or not (p.info["name"] or "").lower().startswith("python"):
            continue
        try:
            cmd = os.path.normcase(" ".join(p.cmdline()))
        except (psutil.Error, OSError):
            continue
        try:
            cwd = os.path.normcase(p.cwd())
        except (psutil.Error, OSError):
            cwd = ""        # a hardened TacoGuard process (selfprotect.py) hides its folder
        if cwd.startswith(versions) or venv in cmd or versions in cmd:
            if "tacoguard" in cmd:
                return True
    return False


# ---------------------------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------------------------
def _same_or_inside(a: Path, b: Path) -> bool:
    a, b = os.path.normcase(str(Path(a).resolve())), os.path.normcase(str(Path(b).resolve()))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def _check_root(root: Path, settings, project_root: Path) -> None:
    data = Path(settings.data_dir)
    if _same_or_inside(root, data) or _same_or_inside(data, root):
        raise InstallError(f"The install folder {root} and the data folder {data} overlap. "
                           "Pick another install folder.")
    if _same_or_inside(root, project_root):
        raise InstallError("The install folder can't be inside the project folder.")
    if root.parent == root or _same_or_inside(Path.home(), root):
        raise InstallError(f"{root} is not a safe place for an install folder.")
    if root.exists() and any(root.iterdir()) and not (root / MARKER).is_file():
        raise InstallError(f"{root} already holds files that aren't TacoGuard's, so nothing was changed.")


def _python_works(py: Path) -> bool:
    if not py.is_file():
        return False
    try:
        r = subprocess.run([str(py), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                           capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() == "%d.%d" % sys.version_info[:2]


def _make_venv(root: Path, with_pip: bool, progress) -> None:
    base = getattr(sys, "_base_executable", None) or sys.executable
    progress(f"Making TacoGuard's own Python from {base} ...")
    cmd = [base, "-m", "venv", str(root / "venv")]
    if not with_pip:
        cmd.insert(3, "--without-pip")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0:
        raise InstallError("Could not make TacoGuard's own Python: " + (r.stderr or r.stdout).strip()[-400:])


def _site_packages(root: Path) -> Path:
    return root / "venv" / "Lib" / "site-packages"


def _copy_parts(root: Path, pins: dict[str, str], progress) -> None:
    """Copy each pinned distribution's files from this Python into the installed one (offline)."""
    dest_root = _site_packages(root)
    dest_root.mkdir(parents=True, exist_ok=True)
    for name, version in pins.items():
        dist = md.distribution(name)
        if dist.version != version:
            raise InstallError(f"{name} changed while installing; run the installer again.")
        files = dist.files
        if not files:
            raise InstallError(f"Can't copy {name}: its file list is missing. Use the installer without --offline.")
        progress(f"Copying {name} {version}")
        for f in files:
            rel = Path(str(f))
            if ".." in rel.parts or "__pycache__" in rel.parts or rel.suffix in (".pyc", ".pyo"):
                continue
            src = Path(dist.locate_file(f))
            if not src.is_file():
                continue
            dst = dest_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def _pip_parts(root: Path, lock_file: Path, progress) -> None:
    progress("Downloading TacoGuard's parts with pip (pypi.org), pinned to requirements.lock ...")
    cmd = [str(venv_python(root)), "-m", "pip", "install", "--no-deps", "--only-binary=:all:",
           "--disable-pip-version-check", "--no-input", "-r", str(lock_file)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0:
        raise InstallError("pip could not install TacoGuard's parts: " + (r.stderr or r.stdout).strip()[-600:]
                           + "\nYou can also run the installer with --offline to copy them from the project's .venv.")


def _launcher_source(project_root: Path) -> Path:
    src = Path(project_root) / "tools" / LAUNCHER
    if not src.is_file():
        src = Path(__file__).resolve().parents[1] / "tools" / LAUNCHER
    return src


def _write_launchers(root: Path, project_root: Path) -> None:
    src = _launcher_source(project_root)
    if not src.is_file():
        raise InstallError(f"The launcher template tools\\{LAUNCHER} is missing from the project folder.")
    shutil.copyfile(src, root / LAUNCHER)
    cmd = ('@echo off\r\n'
           'rem TacoGuard in a console window, e.g. "TacoGuard.cmd version" or "TacoGuard.cmd selftest"\r\n'
           '"%~dp0venv\\Scripts\\python.exe" "%~dp0TacoGuard.pyw" %*\r\n')
    (root / LAUNCHER_CMD).write_bytes(cmd.encode("ascii"))


def default_shortcut_dir() -> Path:
    appdata = os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"


def make_shortcut(root: Path, shortcut_dir: Path) -> Path:
    """A .lnk that runs the launcher with pythonw (no console window). WScript.Shell through
    Windows PowerShell; the paths go in through environment variables (no quoting problems)."""
    shortcut_dir = Path(shortcut_dir)
    shortcut_dir.mkdir(parents=True, exist_ok=True)
    lnk = shortcut_dir / SHORTCUT_NAME
    env = dict(os.environ, TG_LNK=str(lnk), TG_TARGET=str(venv_python(root, windowless=True)),
               TG_ARGS=f'"{root / LAUNCHER}"', TG_WD=str(root),
               TG_DESC="TacoGuard: a second-opinion malware scanner")
    script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:TG_LNK); "
              "$s.TargetPath = $env:TG_TARGET; $s.Arguments = $env:TG_ARGS; "
              "$s.WorkingDirectory = $env:TG_WD; $s.Description = $env:TG_DESC; $s.Save()")
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", script], env=env, capture_output=True, text=True, timeout=120,
                       creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0 or not lnk.is_file():
        raise InstallError("Could not make the Start-menu shortcut: " + (r.stderr or r.stdout).strip()[-300:])
    return lnk


def apply_autostart(settings, root: Path, key_path: str | None = None) -> str:
    """Start at sign-in for the installed copy in `root`, as settings.start_at_sign_in says.
    Returns a plain sentence for the install message ("" when nothing was asked)."""
    from . import autostart
    try:
        if getattr(settings, "start_at_sign_in", False):
            return autostart.enable(root, key_path=key_path) + " (Change this in Settings.)"
        return autostart.disable(key_path=key_path, only_for_root=root)
    except autostart.AutostartError as e:
        return f"TacoGuard could not set itself to start when you sign in: {e}"


GUARD_STOP_WAIT_S = 10.0


def _running_guard(settings):
    """The guard process of this data folder (its heartbeat's pid, still running with
    tacoguard.guard in its command line), or None."""
    db = Path(settings.db_path)
    if not db.is_file():
        return None
    try:
        import sqlite3
        import urllib.parse
        uri = "file:" + urllib.parse.quote(str(db).replace("\\", "/")) + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            row = con.execute("SELECT value FROM meta WHERE key='guard_state'").fetchone()
        finally:
            con.close()
        pid = int(json.loads(row[0]).get("pid") or 0) if row and row[0] else 0
    except Exception:
        return None
    if pid <= 0 or pid == os.getpid():
        return None
    try:
        import psutil
        p = psutil.Process(pid)
        return p if "tacoguard.guard" in " ".join(p.cmdline()).lower() else None
    except Exception:
        return None


def stop_running_guard(settings, wait_s: float = GUARD_STOP_WAIT_S) -> str:
    """Asks a running guard to stop (its "stop" file, as the page does), waits up to wait_s, then
    ends it. Returns a plain sentence ("" when no guard ran). Never raises."""
    p = _running_guard(settings)
    if p is None:
        return ""
    stop = Path(settings.guard_dir) / "stop"
    try:
        stop.parent.mkdir(parents=True, exist_ok=True)
        stop.write_text("stop\n", encoding="utf-8")
    except OSError:
        pass
    note = "Real-time protection was stopped first."
    try:
        try:
            p.wait(wait_s)
        except Exception:
            try:
                p.kill()
                p.wait(5)
            except Exception:
                note = "Real-time protection could not be stopped; it may put its decoy files back."
    finally:
        try:
            stop.unlink(missing_ok=True)
        except OSError:
            pass
    return note


def remove_guard_leftovers(settings, root: Path, key_path: str | None = None) -> list[str]:
    """For uninstall: the start-at-sign-in entry (only when it starts this copy) and the guard's
    decoy files (a guard still running is stopped first, so it can't put them back). Returns
    plain sentences. Never raises."""
    notes = []
    try:
        from . import autostart
        if autostart.enabled(key_path):
            notes.append(autostart.disable(key_path=key_path, only_for_root=root))
    except Exception as e:
        notes.append(f"The start-at-sign-in entry could not be removed ({e}).")
    try:
        from .guard import ransom
    except ImportError:
        return notes
    try:
        stopped = stop_running_guard(settings)
        if stopped:
            notes.append(stopped)
    except Exception:
        pass
    try:
        fn = getattr(ransom, "remove_decoys", None)
        if callable(fn):
            n = fn(settings)
        else:
            n = ransom.RansomGuard(settings, None, None).remove_decoys()
        if n:
            notes.append(f"Removed {n} decoy file{'s' if n != 1 else ''} TacoGuard had made.")
    except Exception:
        notes.append("Some of TacoGuard's decoy files could not be removed. They are small hidden files "
                     "listed in the data folder's guard\\decoys.json.")
    return notes


def install(settings, project_root, shortcut: bool = False, *, deps: str = "pip",
            root: Path | None = None, shortcut_dir: Path | None = None, progress=None,
            autostart: bool | None = None, autostart_key: str | None = None) -> dict:
    """Install (or refresh) the per-user copy. deps="pip" downloads the pinned parts from pypi.org;
    deps="copy" copies them from the Python running this (offline). Running it again changes only
    what differs. autostart (None = settings.start_at_sign_in, but only for the default install
    folder) applies start at sign-in. Returns {"ok", "message", "root", "version", "changed": [...]}."""
    progress = progress or (lambda m: None)
    project_root = Path(project_root).resolve()
    if autostart is None:
        autostart = root is None
    root = Path(root or install_root())
    changed: list[str] = []
    try:
        if not (project_root / "pyproject.toml").is_file():
            raise InstallError("Run the installer from TacoGuard's project folder "
                               "(the folder with pyproject.toml).")
        version = package_version(project_root / "tacoguard")
        if not version:
            raise InstallError("Could not read the version number in tacoguard/__init__.py.")
        _check_root(root, settings, project_root)
        lock = make_lock(project_root)
        pins = parse_lock(lock)
        root.mkdir(parents=True, exist_ok=True)
        marker = read_json(root / MARKER) or {}
        marker.update({"app": "TacoGuard", "created": marker.get("created") or time.time(),
                       "note": "Made by `python -m tacoguard install`. `python -m tacoguard uninstall` "
                               "removes this folder; your data folder is kept."})
        write_json(root / MARKER, marker)

        # 1. TacoGuard's own Python with exactly the locked parts
        lock_file = root / LOCK_NAME
        old_lock = lock_file.read_text(encoding="utf-8") if lock_file.is_file() else ""
        py_ok = _python_works(venv_python(root))
        if not (py_ok and same_lock(old_lock, lock)):
            if py_ok and installed_copy_running(root):
                raise InstallError("TacoGuard is running from the installed copy. Close it (Quit on the "
                                   "page) and run the installer again.")
            if not py_ok:
                rmtree(root / "venv")
                _make_venv(root, with_pip=(deps == "pip"), progress=progress)
            if deps == "copy":
                _copy_parts(root, pins, progress)
            else:
                tmp_lock = root / (LOCK_NAME + ".new")
                tmp_lock.write_text(lock, encoding="utf-8")
                _pip_parts(root, tmp_lock, progress)
                tmp_lock.unlink(missing_ok=True)
            lock_file.write_text(lock, encoding="utf-8")
            changed.append("parts")

        # 2. this version's files
        vroot = root / "versions"
        vroot.mkdir(exist_ok=True)
        staging = vroot / f"{version}.staging"
        rmtree(staging)
        for rel, src in package_files(project_root):
            dst = staging / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        (staging / LOCK_NAME).write_text(lock, encoding="utf-8")
        # Phase 4: the hash list the page compares the running copy with (selfprotect.check_install);
        # the same files give the same list, so an unchanged version still counts as installed
        from .selfprotect import write_manifest
        write_manifest(staging, launcher=_launcher_source(project_root))
        final = vroot / version
        if final.is_dir() and tree_digest(final) == tree_digest(staging):
            rmtree(staging)
        else:
            if final.is_dir():
                if installed_copy_running(root):
                    rmtree(staging)
                    raise InstallError(f"TacoGuard {version} is running from the installed copy. Close it "
                                       "(Quit on the page) and run the installer again.")
                old = vroot / f"{version}.old"
                rmtree(old)
                os.replace(final, old)
                os.replace(staging, final)
                rmtree(old)
            else:
                os.replace(staging, final)
            changed.append(f"version {version}")

        # 3. launchers
        _write_launchers(root, project_root)

        # 4. self-test the installed copy before pointing current.json at it
        progress(f"Testing TacoGuard {version} from the installed copy ...")
        ok, out = run_selftest(root, version, settings.data_dir)
        if not ok:
            raise InstallError(f"The installed copy failed its self-test, so it was not switched on.\n{out[-1500:]}")
        cur = read_current(root)
        if not cur or cur["version"] != version:
            write_current(root, version, cur["version"] if cur else None)
            changed.append("current version")

        # 5. optional Start-menu shortcut
        if shortcut:
            lnk = make_shortcut(root, shortcut_dir or default_shortcut_dir())
            marker["shortcut"] = str(lnk)
            write_json(root / MARKER, marker)
            changed.append("shortcut")
        prune_versions(root)
    except InstallError as e:
        return {"ok": False, "message": str(e), "root": str(root), "version": None, "changed": changed}
    if changed:
        msg = (f"TacoGuard {version} is installed in {root}. Start it with {root / LAUNCHER}"
               + (" or the Start-menu shortcut." if shortcut else "."))
    else:
        msg = f"TacoGuard {version} is already installed in {root} and up to date."
    if autostart:
        note = apply_autostart(settings, root, key_path=autostart_key)
        if note:
            msg += " " + note
    return {"ok": True, "message": msg, "root": str(root), "version": version, "changed": changed}


def hosts_remove_command() -> str:
    """The exact command that takes TacoGuard's hosts-file block out later (run in the project
    folder, with the Python that is running this)."""
    return f'"{sys.executable}" -m tacoguard hosts remove'


def remove_hosts_leftover(settings, *, launcher=None, hosts_path=None) -> str:
    """For uninstall: when TacoGuard's block is in Windows' hosts file, take it out (ONE admin
    prompt through the hosts helper, which is removed from Program Files afterwards). Returns a
    plain sentence ("" when there was no block). Never raises."""
    try:
        from .webblock import hosts
        path = hosts_path if hosts_path is not None else hosts.default_hosts_path()
        block = hosts.read_block(path)
        if not block["present"]:
            return ""
        res = hosts.remove_elevated(settings, launcher=launcher, hosts_path=path, cleanup=True)
        if getattr(res, "ok", False):
            return "TacoGuard's block was taken out of Windows' hosts file."
        if getattr(res, "code", "") == "cancelled":
            return ("TacoGuard's block is still in Windows' hosts file (you said No to Windows' prompt). "
                    "To take it out later, run this in TacoGuard's project folder: " + hosts_remove_command())
        return (f"TacoGuard's block is still in Windows' hosts file: {res} To take it out later, run this "
                "in TacoGuard's project folder: " + hosts_remove_command())
    except Exception:
        return ("TacoGuard couldn't check Windows' hosts file for its block. To take it out later, run this "
                "in TacoGuard's project folder: " + hosts_remove_command())


def uninstall(settings, *, root: Path | None = None, cleanup: bool | None = None,
              autostart_key: str | None = None, hosts_launcher=None, hosts_path=None) -> dict:
    """Remove the installed copy: only a folder carrying TacoGuard's marker, never the data
    folder or quarantine. cleanup (None = only for the default install folder) also removes the
    start-at-sign-in entry, the guard's decoy files and TacoGuard's block in Windows' hosts file
    (one admin prompt; when you say No, the message gives the command for later). Returns
    {"ok", "message"}."""
    if cleanup is None:
        cleanup = root is None
    root = Path(root or install_root())
    marker = read_json(root / MARKER)
    if not root.exists():
        return {"ok": True, "message": f"TacoGuard is not installed in {root}; nothing to remove."}
    if not marker or marker.get("app") != "TacoGuard":
        return {"ok": False, "message": f"{root} doesn't carry TacoGuard's install marker, so nothing was removed."}
    data = Path(settings.data_dir)
    for keep in (data, Path(settings.quarantine_dir)):
        if _same_or_inside(keep, root) or _same_or_inside(root, keep):
            return {"ok": False, "message": f"The data folder {data} overlaps the install folder, so nothing was removed."}
    if installed_copy_running(root):
        return {"ok": False, "message": "TacoGuard is running from the installed copy. Close it (Quit on the "
                                        "page) and run uninstall again."}
    lnk = marker.get("shortcut")
    if lnk and Path(lnk).name == SHORTCUT_NAME and Path(lnk).is_file():
        try:
            Path(lnk).unlink()
        except OSError:
            pass
    notes = remove_guard_leftovers(settings, root, key_path=autostart_key) if cleanup else []
    if cleanup:
        note = remove_hosts_leftover(settings, launcher=hosts_launcher, hosts_path=hosts_path)
        if note:
            notes.append(note)
    rmtree(root)
    extra = "".join(" " + n for n in notes)
    if root.exists():
        return {"ok": False, "message": f"Some files in {root} could not be removed (in use?). Close TacoGuard "
                                        "and run uninstall again." + extra}
    return {"ok": True, "message": f"TacoGuard's installed copy was removed from {root}. Your settings, scan "
                                   f"history and quarantine in {data} were kept." + extra}


# ---------------------------------------------------------------------------------------------
# selftest (run after install and before every self-update switch)
# ---------------------------------------------------------------------------------------------
def selftest(settings) -> tuple[bool, list[str]]:
    """Imports every module, loads settings, opens the database read-only and asks each detector
    for its status (nothing is started: no ClamAV, no scan). Returns (ok, plain lines)."""
    import importlib
    import pkgutil
    import sqlite3
    import urllib.parse

    import tacoguard
    lines, ok = [], True
    where = Path(tacoguard.__file__).resolve().parent
    bad = []

    def onerror(name):
        bad.append(name)

    for mod in pkgutil.walk_packages(tacoguard.__path__, "tacoguard.", onerror=onerror):
        try:
            importlib.import_module(mod.name)
        except Exception as e:
            bad.append(f"{mod.name} ({type(e).__name__}: {e})")
    if bad:
        ok = False
        lines.append("Could not load these parts: " + "; ".join(bad))
    else:
        lines.append("All parts load.")
    try:
        from .config import load_settings
        s = load_settings(settings.data_dir)
        s.to_json()
        lines.append(f"Settings read from {s.root}.")
    except Exception as e:
        ok = False
        lines.append(f"Could not read the settings: {e}")
    db = Path(settings.db_path)
    if db.is_file():
        try:
            uri = "file:" + urllib.parse.quote(str(db).replace("\\", "/")) + "?mode=ro"
            con = sqlite3.connect(uri, uri=True, timeout=10)
            con.execute("SELECT count(*) FROM jobs").fetchone()
            con.close()
            lines.append("Database opens (read-only).")
        except Exception as e:
            ok = False
            lines.append(f"Could not open the database: {e}")
    else:
        lines.append("No database yet (fine for a new install).")
    try:
        from .detect import _all_detectors
        for name, det in _all_detectors(settings).items():
            st = det.status()
            if not isinstance(st, dict) or "ready" not in st:
                raise ValueError(f"{name} gave no status")
        lines.append("Detectors answer (not started).")
    except Exception as e:
        ok = False
        lines.append(f"The detectors could not be checked: {type(e).__name__}: {e}")
    try:
        from .web import server
        missing = [n for n in {v[0] for v in server.STATIC_FILES.values()}
                   if not (server.STATIC_DIR / n).is_file()]
        if missing:
            raise FileNotFoundError(", ".join(sorted(missing)))
        lines.append("Page files present.")
    except Exception as e:
        ok = False
        lines.append(f"The page files are missing: {e}")
    head = f"TacoGuard {__version__} self-test {'passed' if ok else 'FAILED'} (from {where})"
    return ok, [head] + lines
