"""Build, check and publish a signed TacoGuard release folder. Run by the project lead.

    python tools/release.py build --out <dir> [--ml <zip>] [--app] [--notes "plain words"]
                                  [--version N] [--previous <dir>] [--keys-dir <dir>]
    python tools/release.py verify <dir> [--root <root.json>]
    python tools/release.py publish <dir> --yes      (GitHub release on config.RELEASE_REPO via gh)

Release folder layout (exactly what the GitHub release holds):
    targets.json                signed by the release (targets) key; version = previous + 1,
                                expires in 180 days; lists every file below with length + sha256
    tacoguard-<app version>.zip install.build_package: the tacoguard/ package (no __pycache__),
                                the pinned requirements list, LICENSE,
                                THIRD_PARTY_LICENSES.md                   (with --app)
    ml-model-<version>.zip      the ML package as given                (with --ml)
    root-<N>.json, root.json    every signed root after version 1, and the newest as root.json
                                (only once the keys were rotated)
Files of the previous release that this build does not replace are carried over, so the
latest release always holds the newest app AND the newest model.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import keys as keytool  # noqa: E402
from tacoguard import __version__, config, setup_fetch  # noqa: E402
from tacoguard.updates import signed, sources, updater  # noqa: E402

TARGETS_DAYS = 180
SECRET_LIKE = re.compile(r"(\.key|\.pem|\.dpapi|\.env|\.pfx|\.p12)$|(^|[\\/])\.env", re.I)


class ReleaseError(Exception):
    pass


def _sha(path: Path) -> str:
    return setup_fetch.sha256_file(path)


def _entry(path: Path, kind: str, version: str, min_app: str, notes: str) -> dict:
    return {"length": path.stat().st_size, "sha256": _sha(path),
            "custom": {"kind": kind, "version": version, "min_app": min_app, "notes": notes}}


# ---------------------------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------------------------

def check_no_secrets(project: Path = ROOT) -> None:
    """Refuse to package anything that looks like a key or secret."""
    from tacoguard import install
    for rel, _path in install.package_files(project):
        if SECRET_LIKE.search(rel):
            raise ReleaseError(f"{rel} looks like a key or secret, so the app package was not built.")
    for name in ("LICENSE", "THIRD_PARTY_LICENSES.md"):
        if not (project / name).is_file():
            raise ReleaseError(f"{name} is missing from the project folder.")


def build_app_zip(dest: Path, project: Path = ROOT) -> dict:
    """tacoguard-<version>.zip via install.build_package (the same layout self-update installs:
    the tacoguard/ package without __pycache__, the pinned requirements list, LICENSE,
    THIRD_PARTY_LICENSES.md). Same inputs -> same bytes. Returns {"file", "version", ...}."""
    from tacoguard import install
    check_no_secrets(project)
    if Path(dest).exists():
        raise ReleaseError(f"{dest} already exists.")
    try:
        return install.build_package(project, Path(dest))
    except install.InstallError as e:
        raise ReleaseError(str(e)) from e


def ml_version(zip_path: Path, given: str = "") -> str:
    if given:
        return given
    try:
        with zipfile.ZipFile(zip_path) as z:
            metas = [n for n in z.namelist() if n.rsplit("/", 1)[-1] == "meta.json" and n.count("/") <= 1]
            if metas:
                v = json.loads(z.read(metas[0]).decode("utf-8")).get("version")
                if v:
                    return str(v)
    except (zipfile.BadZipFile, ValueError, OSError):
        pass
    m = re.search(r"(\d+(?:\.\d+)+)", zip_path.stem)
    if m:
        return m.group(1)
    raise ReleaseError("Could not tell the ML package's version: give it with --ml-version.")


def check_zip_safe(zip_path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = str(Path(tmp).resolve())
        try:
            with zipfile.ZipFile(zip_path) as z:
                for info in z.infolist():
                    setup_fetch._check_zip_member(info, root)
                bad = z.testzip()
        except zipfile.BadZipFile as e:
            raise ReleaseError(f"{zip_path.name} is not a readable zip file.") from e
        except setup_fetch.FetchError as e:
            raise ReleaseError(f"{zip_path.name}: {e}") from e
        if bad:
            raise ReleaseError(f"{zip_path.name} is damaged ({bad}).")


# ---------------------------------------------------------------------------------------------
# Previous release
# ---------------------------------------------------------------------------------------------

def read_targets(folder: Path) -> dict | None:
    try:
        return json.loads((folder / "targets.json").read_text(encoding="utf-8"))["signed"]
    except (OSError, ValueError, KeyError):
        return None


def find_previous(out: Path) -> Path | None:
    """The sibling release folder with the highest targets version."""
    best = None
    parent = out.resolve().parent
    if not parent.is_dir():
        return None
    for d in parent.iterdir():
        if not d.is_dir() or d.resolve() == out.resolve():
            continue
        t = read_targets(d)
        if t and isinstance(t.get("version"), int) and (best is None or t["version"] > best[0]):
            best = (t["version"], d)
    return best[1] if best else None


# ---------------------------------------------------------------------------------------------
# build / verify / publish
# ---------------------------------------------------------------------------------------------

def build(out: Path, ml: Path | None = None, app: bool = False, version: int | None = None,
          previous: Path | None = None, keys_dir: Path | None = None, notes: str = "",
          ml_version_text: str = "", ml_min_app: str = __version__, app_min_app: str = "0.1.0",
          project: Path = ROOT, days: int = TARGETS_DAYS, shipped_root: Path | None = None,
          say=print, self_test=None) -> dict:
    out = Path(out)
    keys_dir = Path(keys_dir or config.signing_dir())
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"{out} is not empty. Give a new folder for each release.")
    if not ml and not app:
        raise ReleaseError("Nothing to release: give --ml <zip>, --app, or both.")
    previous = Path(previous) if previous else find_previous(out)
    prev_targets = read_targets(previous) if previous else None
    prev_version = int(prev_targets["version"]) if prev_targets else 0
    if version is None:
        version = prev_version + 1
    if version <= prev_version:
        raise ReleaseError(f"Version {version} is not newer than the previous release ({prev_version}).")

    targets_key = keytool.load_private(keys_dir, "targets")
    root, _ = keytool.latest_root(keys_dir)
    if signed.keyid_for(targets_key) not in root["roles"]["targets"]["keyids"]:
        raise ReleaseError("The release key in the keys folder is not trusted by the newest root. "
                           "Nothing was built.")

    out.mkdir(parents=True, exist_ok=True)
    try:
        entries: dict[str, dict] = {}
        if app:
            name = f"tacoguard-{__version__}.zip"
            built = build_app_zip(out / name, project)
            entries[name] = _entry(out / name, "app", built["version"], app_min_app, notes)
            say(f"App package {name}: {entries[name]['length']:,} bytes.")
        if ml:
            ml = Path(ml)
            check_zip_safe(ml)
            v = ml_version(ml, ml_version_text)
            name = f"ml-model-{v}.zip"
            shutil.copyfile(ml, out / name)
            entries[name] = _entry(out / name, "ml_model", v, ml_min_app, notes)
            say(f"ML package {name}: {entries[name]['length']:,} bytes.")
        replaced = {e["custom"]["kind"] for e in entries.values()}
        for name, entry in (prev_targets or {}).get("targets", {}).items():
            kind = (entry.get("custom") or {}).get("kind")
            if kind in replaced or name in entries:
                continue
            src = previous / name
            try:
                signed.verify_file(src, entry)
            except signed.UpdateRejected:
                say(f"Not carried over from {previous}: {name} (missing or changed).")
                continue
            shutil.copyfile(src, out / name)
            entries[name] = entry
            say(f"Carried over from the previous release: {name}.")
        expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=days)) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        targets = {"_type": "targets", "version": version, "expires": expires, "targets": entries}
        (out / "targets.json").write_bytes(
            signed.dump_metadata(signed.sign_metadata(targets, [targets_key])))
        hist = keytool.root_history(keys_dir)
        for v, src in hist:
            if v >= 2:
                shutil.copyfile(src, out / src.name)
        if hist and hist[-1][0] >= 2:
            shutil.copyfile(hist[-1][1], out / "root.json")
        say(f"Signed targets.json version {version}, valid until {expires[:10]}.")
        report = verify(out, root_file=shipped_root, say=say, self_test=self_test)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    return {"version": version, "files": sorted(p.name for p in out.iterdir()), **report}


def verify(folder: Path, root_file: Path | None = None, say=print, self_test=None) -> dict:
    """Check a release folder exactly like the app: root chain from the built-in (or given)
    root, targets.json signatures + expiry, every listed file's length + sha256, ML packages
    unpacked safely and test-loaded."""
    folder = Path(folder)
    root_path = Path(root_file) if root_file else signed.SHIPPED_ROOT
    try:
        root = signed.parse_root(root_path.read_bytes())
    except FileNotFoundError as e:
        raise ReleaseError(f"No trusted root at {root_path}: run 'keys.py init' first.") from e
    root, targets, _raw, changed = updater.fetch_verified_targets(sources.LocalFolderSource(folder), root)
    listed = targets["targets"]
    for name, entry in sorted(listed.items()):
        signed.verify_file(folder / name, entry)
        kind = entry.get("custom", {}).get("kind")
        if kind == "ml_model":
            _ml_test(folder / name, self_test, say)
        say(f"OK  {name}  ({kind}, version {entry.get('custom', {}).get('version')}, "
            f"{entry['length']:,} bytes)")
    known = set(listed) | {"targets.json", "root.json"}
    extras = sorted(p.name for p in folder.iterdir()
                    if p.name not in known and not re.fullmatch(r"root-\d+\.json", p.name))
    if extras:
        raise ReleaseError("The folder holds files the update list does not name: " + ", ".join(extras))
    say(f"Release version {targets['version']} verified (root version {root['version']}"
        + (", keys rotated" if changed else "") + f"), valid until {targets['expires'][:10]}.")
    return {"targets_version": targets["version"], "root_version": root["version"],
            "expires": targets["expires"]}


def _ml_test(zip_path: Path, self_test, say) -> None:
    if self_test is None:
        try:
            from tacoguard.detect import ml
            self_test = getattr(ml, "self_test", None)
        except Exception:
            self_test = None
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "model"
        setup_fetch.safe_unzip(zip_path, dest, max_total=updater.ML_UNPACK_MAX)
        updater._flatten(dest)
        if self_test is None:
            say(f"Note: tacoguard.detect.ml.self_test is not available, {zip_path.name} was not "
                "test-loaded.")
            return
        self_test(dest)


def publish(folder: Path, yes: bool = False, say=print) -> int:
    folder = Path(folder)
    report = verify(folder, say=say)
    tag = f"v{report['targets_version']}"
    files = sorted(str(p) for p in folder.iterdir() if p.is_file())
    cmd = ["gh", "release", "create", tag, *files, "--repo", config.RELEASE_REPO,
           "--title", f"TacoGuard update {report['targets_version']}",
           "--notes", "Signed TacoGuard update. TacoGuard checks every file against targets.json "
                      "before using it."]
    if not yes:
        say("Would run: " + " ".join(cmd[:4]) + f" ... ({len(files)} files) --repo {config.RELEASE_REPO}")
        say("Add --yes to publish. Publishing makes the release public to every TacoGuard install.")
        return 0
    return subprocess.run(cmd).returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="release.py", description="Signed TacoGuard releases.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument("--ml")
    b.add_argument("--ml-version", default="")
    b.add_argument("--ml-min-app", default=__version__)
    b.add_argument("--app", action="store_true")
    b.add_argument("--app-min-app", default="0.1.0")
    b.add_argument("--notes", default="")
    b.add_argument("--version", type=int)
    b.add_argument("--previous")
    b.add_argument("--keys-dir", default=str(config.signing_dir()))
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--root")
    p = sub.add_parser("publish")
    p.add_argument("dir")
    p.add_argument("--yes", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "build":
            r = build(Path(args.out), ml=Path(args.ml) if args.ml else None, app=args.app,
                      version=args.version, previous=Path(args.previous) if args.previous else None,
                      keys_dir=Path(args.keys_dir), notes=args.notes,
                      ml_version_text=args.ml_version, ml_min_app=args.ml_min_app,
                      app_min_app=args.app_min_app)
            print(f"Release folder {args.out}: " + ", ".join(r["files"]))
        elif args.cmd == "verify":
            verify(Path(args.dir), Path(args.root) if args.root else None)
        else:
            return publish(Path(args.dir), yes=args.yes)
    except (ReleaseError, keytool.KeyError_, signed.UpdateRejected, sources.SourceError,
            setup_fetch.FetchError) as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
