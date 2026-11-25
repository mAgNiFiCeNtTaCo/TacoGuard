"""TacoGuard's release signing keys. Run by the project lead only, never by tests on the real folder.

    python tools/keys.py init                     make the root key + release (targets) key and
                                                  tacoguard/data/root.json (signed by the root key)
    python tools/keys.py backup --to E:\\TacoGuard-signing-backup
                                                  passphrase-encrypted copy of both private keys
    python tools/keys.py restore --from E:\\TacoGuard-signing-backup
    python tools/keys.py rotate-targets           new release key; root re-signed as version + 1
    python tools/keys.py show                     key ids and root version (no secrets)
Every command takes --dir (default: config.signing_dir(), i.e. %USERPROFILE%\\.tacoguard-signing);
init and rotate-targets take --out (default: tacoguard/data/root.json).

Keys folder:
    root.key, targets.key     raw Ed25519 private keys, protected by Windows DPAPI (this Windows
                              account on this PC only)
    roots/root-<N>.json       every signed root version (public; releases carry them)
    retired/                  release keys replaced by rotate-targets (DPAPI-protected)
Key material is never printed. Existing keys are never overwritten.

Backup folder (backup / restore):
    root.key.backup, targets.key.backup   one JSON file per key: {"format": BACKUP_FORMAT,
                              "version": 1, "role", "kdf": "scrypt", "n", "r", "p", "salt", "nonce",
                              "ciphertext"} (hex). The key is scrypt(passphrase, salt; n=2**18, r=8,
                              p=2: about a second and 256 MB per key on this PC), the 32 raw private
                              key bytes are sealed with AES-256-GCM; everything but the ciphertext
                              is authenticated too, so a changed role or setting is refused.
    roots/root-<N>.json       copies of the signed roots, README.txt
restore also reads the older root.key.pem / targets.key.pem backups (PKCS#8, weak PBKDF2) and asks
you to make a new backup.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: E402

from tacoguard import config, dpapi  # noqa: E402
from tacoguard.updates import signed  # noqa: E402

ROOT_YEARS = 5
MIN_PASSPHRASE = 12
CREATE_NEW_CONSOLE = 0x00000010
DEFAULT_OUT = ROOT / "tacoguard" / "data" / "root.json"
BACKUP_FORMAT = "tacoguard-signing-key-backup"
BACKUP_VERSION = 1
BACKUP_SUFFIX = ".key.backup"
OLD_BACKUP_SUFFIX = ".key.pem"            # before 2026-11-23: PKCS#8 PEM, PBKDF2 2048 rounds
BACKUP_FILES = tuple(f"{role}{BACKUP_SUFFIX}" for role in ("root", "targets"))
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 18, 8, 2   # ~1.2 s and 256 MB per key on this PC (2026-11-23)
SCRYPT_LIMITS = {"n": (2 ** 14, 2 ** 22), "r": (1, 32), "p": (1, 16)}   # what restore accepts


class KeyError_(Exception):
    """Plain-English problem (the CLI prints it and exits with code 1)."""


# ---------------------------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------------------------

def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def _write_new(path: Path, data: bytes) -> None:
    """Create a file that must not exist yet (never overwrite a key)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except FileExistsError as e:
        raise KeyError_(f"{path} already exists, so nothing was overwritten.") from e


def _save_private(path: Path, key: Ed25519PrivateKey) -> None:
    _write_new(path, dpapi.protect(_raw_private(key)))


def load_private(keys_dir: Path, role: str) -> Ed25519PrivateKey:
    path = Path(keys_dir) / f"{role}.key"
    if not path.is_file():
        raise KeyError_(f"There is no {role} key in {keys_dir}. Run 'keys.py init' or 'keys.py restore'.")
    try:
        return Ed25519PrivateKey.from_private_bytes(dpapi.unprotect(path.read_bytes()))
    except (OSError, ValueError) as e:
        raise KeyError_(f"The {role} key in {keys_dir} could not be unlocked (it belongs to another "
                        "Windows account, or it is damaged). Restore it from the backup.") from e


def _expires(years: int = ROOT_YEARS) -> str:
    when = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=365 * years)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def root_signed(version: int, root_keys: list, targets_keys: list, years: int = ROOT_YEARS) -> dict:
    keys = {signed.keyid_for(k): signed.key_entry(k) for k in [*root_keys, *targets_keys]}
    return {"_type": "root", "version": version, "expires": _expires(years), "keys": keys,
            "roles": {"root": {"keyids": [signed.keyid_for(k) for k in root_keys], "threshold": 1},
                      "targets": {"keyids": [signed.keyid_for(k) for k in targets_keys],
                                  "threshold": 1}}}


def root_history(keys_dir: Path) -> list[tuple[int, Path]]:
    folder = Path(keys_dir) / "roots"
    out = []
    if folder.is_dir():
        for p in folder.glob("root-*.json"):
            try:
                out.append((int(p.stem.split("-", 1)[1]), p))
            except ValueError:
                continue
    return sorted(out)


def latest_root(keys_dir: Path) -> tuple[dict, bytes]:
    hist = root_history(keys_dir)
    if not hist:
        raise KeyError_(f"No signed root found in {Path(keys_dir) / 'roots'}. Run 'keys.py init'.")
    raw = hist[-1][1].read_bytes()
    return signed.parse_root(raw, "The newest root in the keys folder"), raw


def _write_root(keys_dir: Path, out: Path, doc: dict) -> Path:
    data = signed.dump_metadata(doc)
    version = doc["signed"]["version"]
    _write_new(Path(keys_dir) / "roots" / f"root-{version}.json", data)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, out)
    return out


# ---------------------------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------------------------

def init_keys(keys_dir: Path, out: Path = DEFAULT_OUT) -> dict:
    keys_dir = Path(keys_dir)
    for name in ("root.key", "targets.key"):
        if (keys_dir / name).exists():
            raise KeyError_(f"{keys_dir / name} already exists. TacoGuard never overwrites a signing "
                            "key; use 'rotate-targets' to replace the release key.")
    if root_history(keys_dir):
        raise KeyError_(f"{keys_dir / 'roots'} already holds signed roots; refusing to start over.")
    root_key, targets_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _save_private(keys_dir / "root.key", root_key)
    _save_private(keys_dir / "targets.key", targets_key)
    doc = signed.sign_metadata(root_signed(1, [root_key], [targets_key]), [root_key])
    path = _write_root(keys_dir, out, doc)
    return {"root_keyid": signed.keyid_for(root_key), "targets_keyid": signed.keyid_for(targets_key),
            "root_json": str(path), "version": 1, "expires": doc["signed"]["expires"]}


def rotate_targets(keys_dir: Path, out: Path = DEFAULT_OUT) -> dict:
    keys_dir = Path(keys_dir)
    root_key = load_private(keys_dir, "root")
    old_targets = load_private(keys_dir, "targets")
    current, _ = latest_root(keys_dir)
    if signed.keyid_for(root_key) not in current["roles"]["root"]["keyids"]:
        raise KeyError_("The root key in the keys folder is not the one the newest root trusts. "
                        "Nothing was changed.")
    if (keys_dir / "roots" / f"root-{current['version'] + 1}.json").exists():
        raise KeyError_(f"root-{current['version'] + 1}.json already exists. Nothing was changed.")
    retired = keys_dir / "retired" / f"targets-{signed.keyid_for(old_targets)[:16]}.key"
    if retired.exists():
        raise KeyError_(f"{retired} already exists. Nothing was changed.")
    new_path = keys_dir / "targets.key.new"
    notes = []
    if new_path.exists():                # left by an earlier rotation that failed before the fix
        _remove_unused_new_key(new_path, current)
        notes.append("An unused new release key left by an earlier failed rotation was removed.")
    new_targets = Ed25519PrivateKey.generate()
    _save_private(new_path, new_targets)
    moved = False
    try:
        root_keys = [root_key]
        doc = signed.sign_metadata(root_signed(current["version"] + 1, root_keys, [new_targets]), root_keys)
        # check it the way the app will, before anything is moved
        signed.verify_root_update(current, signed.dump_metadata(doc))
        retired.parent.mkdir(parents=True, exist_ok=True)
        os.replace(keys_dir / "targets.key", retired)
        try:
            os.replace(new_path, keys_dir / "targets.key")
        except OSError:
            os.replace(retired, keys_dir / "targets.key")      # put the old key back
            raise
        moved = True
    except (KeyError_, signed.UpdateRejected) as e:
        raise KeyError_(f"{str(e).rstrip('.')}. The new release key was not used and has been "
                        "removed; the old one is still in place.") from e
    except OSError as e:
        raise KeyError_(f"The release key could not be swapped ({e.strerror or e}). The new key was "
                        "removed; the old one is still in place.") from e
    finally:
        if not moved:
            new_path.unlink(missing_ok=True)
    path = _write_root(keys_dir, out, doc)
    return {"targets_keyid": signed.keyid_for(new_targets), "retired": str(retired),
            "root_json": str(path), "version": doc["signed"]["version"], "notes": notes}


def _remove_unused_new_key(path: Path, current_root: dict) -> None:
    """targets.key.new from a failed rotation: never published, so it may go, unless the newest
    root somehow trusts it (then a person must look)."""
    try:
        key = Ed25519PrivateKey.from_private_bytes(dpapi.unprotect(path.read_bytes()))
        trusted = signed.keyid_for(key) in current_root["roles"]["targets"]["keyids"]
    except (OSError, ValueError):
        trusted = False                  # unreadable: it can't sign anything anyway
    if trusted:
        raise KeyError_(f"{path} is the release key the newest root trusts, but it was never put "
                        "in place. Rename it to targets.key by hand (after a backup). Nothing was changed.")
    path.unlink()


def _passphrase_text(passphrase) -> str:
    if isinstance(passphrase, (bytes, bytearray)):
        try:
            return bytes(passphrase).decode("utf-8")
        except UnicodeDecodeError:
            raise KeyError_("The passphrase could not be read. Nothing was written.") from None
    return str(passphrase)


def check_passphrase(passphrase) -> bytes:
    """The passphrase as UTF-8 bytes; refuses one shorter than MIN_PASSPHRASE characters."""
    text = _passphrase_text(passphrase)
    if len(text) < MIN_PASSPHRASE:
        raise KeyError_(f"The passphrase must be at least {MIN_PASSPHRASE} characters long (yours has "
                        f"{len(text)}). A few unrelated words work well. Nothing was written.")
    return text.encode("utf-8")


def _backup_header(role: str, n: int, r: int, p: int, salt: bytes, nonce: bytes) -> dict:
    return {"format": BACKUP_FORMAT, "version": BACKUP_VERSION, "role": role, "kdf": "scrypt",
            "n": n, "r": r, "p": p, "salt": salt.hex(), "nonce": nonce.hex()}


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _kek(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def seal_key(role: str, key: Ed25519PrivateKey, passphrase: bytes) -> bytes:
    """The backup file for one key (see the module docstring)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    header = _backup_header(role, SCRYPT_N, SCRYPT_R, SCRYPT_P, salt, nonce)
    kek = _kek(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(kek).encrypt(nonce, _raw_private(key), _aad(header))
    return (json.dumps({**header, "ciphertext": ct.hex()}, indent=1, sort_keys=True) + "\n").encode("utf-8")


def open_key(data: bytes, role: str, passphrase: bytes, name: str) -> Ed25519PrivateKey:
    """Reads a backup file made by seal_key. Raises KeyError_ with plain words."""
    damaged = KeyError_(f"{name} is not a TacoGuard key backup or it is damaged. Nothing was restored.")
    try:
        doc = json.loads(data.decode("utf-8"))
        if not isinstance(doc, dict) or doc.get("format") != BACKUP_FORMAT:
            raise damaged
        if doc.get("version") != BACKUP_VERSION:
            raise KeyError_(f"{name} was made by a newer TacoGuard (backup format "
                            f"{doc.get('version')}). Use that version's keys.py. Nothing was restored.")
        if doc.get("role") != role or doc.get("kdf") != "scrypt":
            raise damaged
        n, r, p = (doc.get(k) for k in ("n", "r", "p"))
        for k, v in (("n", n), ("r", r), ("p", p)):
            lo, hi = SCRYPT_LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise damaged
        if n & (n - 1):
            raise damaged
        salt, nonce = bytes.fromhex(doc["salt"]), bytes.fromhex(doc["nonce"])
        ct = bytes.fromhex(doc["ciphertext"])
        if len(salt) < 16 or len(nonce) != 12:
            raise damaged
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError):
        raise damaged from None
    header = _backup_header(role, n, r, p, salt, nonce)
    try:
        raw = AESGCM(_kek(passphrase, salt, n, r, p)).decrypt(nonce, ct, _aad(header))
    except InvalidTag:
        raise KeyError_("The passphrase is wrong, or the backup is damaged. Nothing was "
                        "restored.") from None
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError:
        raise damaged from None


def backup_keys(keys_dir: Path, to_dir: Path, passphrase) -> list[Path]:
    passphrase = check_passphrase(passphrase)
    keys_dir, to_dir = Path(keys_dir), Path(to_dir)
    keys = {role: load_private(keys_dir, role) for role in ("root", "targets")}
    for name in (*BACKUP_FILES, *(f"{role}{OLD_BACKUP_SUFFIX}" for role in keys)):
        if (to_dir / name).exists():
            raise KeyError_(f"{to_dir / name} already exists, so nothing was overwritten. Pick an "
                            "empty folder for the backup.")
    sealed = {role: seal_key(role, key, passphrase) for role, key in keys.items()}
    written = []
    for role, data in sealed.items():
        path = to_dir / f"{role}{BACKUP_SUFFIX}"
        _write_new(path, data)
        written.append(path)
    for version, src in root_history(keys_dir):
        dst = to_dir / "roots" / src.name
        if not dst.exists():
            _write_new(dst, src.read_bytes())
            written.append(dst)
    readme = to_dir / "README.txt"
    if not readme.exists():
        _write_new(readme, (
            "TacoGuard release signing keys, encrypted with the passphrase typed at backup time.\n"
            "Restore on a new PC or Windows account with:\n"
            "    python tools/keys.py restore --from <this folder>\n"
            "Keep this folder and the passphrase in separate safe places.\n").encode("utf-8"))
        written.append(readme)
    return written


def _open_old_pem(src: Path, passphrase: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(src.read_bytes(), passphrase)
    except (ValueError, TypeError) as e:
        raise KeyError_("The passphrase is wrong, or the backup is damaged. Nothing was "
                        "restored.") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyError_(f"{src.name} is not an Ed25519 key. Nothing was restored.")
    return key


def restore_keys(from_dir: Path, keys_dir: Path, passphrase) -> dict:
    """Reads root.key.backup / targets.key.backup (or an older backup's .pem files). The result's
    "old_format" is True when the old, weakly protected files were used."""
    from_dir, keys_dir = Path(from_dir), Path(keys_dir)
    passphrase = _passphrase_text(passphrase).encode("utf-8")
    for role in ("root", "targets"):
        if (keys_dir / f"{role}.key").exists():
            raise KeyError_(f"{keys_dir / (role + '.key')} already exists, so nothing was overwritten.")
    keys = {}
    old_format = False
    for role in ("root", "targets"):
        src = from_dir / f"{role}{BACKUP_SUFFIX}"
        old = from_dir / f"{role}{OLD_BACKUP_SUFFIX}"
        if src.is_file():
            keys[role] = open_key(src.read_bytes(), role, passphrase, src.name)
        elif old.is_file():
            keys[role] = _open_old_pem(old, passphrase)
            old_format = True
        else:
            raise KeyError_(f"The backup folder has no {src.name}. Nothing was restored.")
    for role, key in keys.items():
        _save_private(keys_dir / f"{role}.key", key)
    roots = from_dir / "roots"
    copied = 0
    if roots.is_dir():
        for src in sorted(roots.glob("root-*.json")):
            dst = keys_dir / "roots" / src.name
            if not dst.exists():
                _write_new(dst, src.read_bytes())
                copied += 1
    return {"root_keyid": signed.keyid_for(keys["root"]),
            "targets_keyid": signed.keyid_for(keys["targets"]), "roots_copied": copied,
            "old_format": old_format}


def show(keys_dir: Path) -> dict:
    out = {"dir": str(keys_dir)}
    for role in ("root", "targets"):
        out[role] = signed.keyid_for(load_private(keys_dir, role)) if (Path(keys_dir) / f"{role}.key").exists() \
            else "(none)"
    try:
        root, _ = latest_root(keys_dir)
        out["root_version"], out["root_expires"] = root["version"], root["expires"]
    except KeyError_:
        out["root_version"] = "(none)"
    return out


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------

def _ask_passphrase(twice: bool) -> bytes:
    if twice:
        print(f"Pick a passphrase of at least {MIN_PASSPHRASE} characters (a few unrelated words work "
              "well). Without it the backup can't be opened.")
    first = getpass.getpass("Backup passphrase (not shown while you type): ")
    if twice:
        check_passphrase(first)              # say so now, not after typing it twice
        second = getpass.getpass("Type the same passphrase again: ")
        if first != second:
            raise KeyError_("The two passphrases are different. Nothing was written.")
    return first.encode("utf-8")


def _in_own_console(argv: list[str], title: str) -> int:
    """getpass needs a real console. Open one, run this same command there, and wait."""
    print(f"A new window named '{title}' opened. Type the passphrase there (it is not shown while "
          "you type). This window waits until you are done.", flush=True)
    cmd = [sys.executable, str(Path(__file__).resolve()), *argv, "--in-console"]
    proc = subprocess.Popen(cmd, creationflags=CREATE_NEW_CONSOLE, cwd=str(ROOT))
    code = proc.wait()
    print("Done." if code == 0 else "The passphrase window reported a problem (see the message "
          "it showed). Nothing else was changed.", flush=True)
    return code


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="keys.py", description="TacoGuard release signing keys.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "rotate-targets", "show", "backup", "restore"):
        p = sub.add_parser(name)
        p.add_argument("--dir", default=str(config.signing_dir()), help="keys folder")
        if name in ("init", "rotate-targets"):
            p.add_argument("--out", default=str(DEFAULT_OUT), help="where root.json is written")
        if name == "backup":
            p.add_argument("--to", required=True, help="backup folder (e.g. a USB stick)")
        if name == "restore":
            p.add_argument("--from", dest="from_dir", required=True, help="backup folder")
        if name in ("backup", "restore"):
            p.add_argument("--in-console", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    keys_dir = Path(args.dir)
    try:
        if args.cmd == "init":
            r = init_keys(keys_dir, Path(args.out))
            print(f"Made a root key ({r['root_keyid'][:16]}...) and a release key "
                  f"({r['targets_keyid'][:16]}...) in {keys_dir}, protected for this Windows account.")
            print(f"Wrote {r['root_json']} (root version 1, valid until {r['expires'][:10]}).")
            print("Next: back the keys up with  python tools/keys.py backup --to <USB folder>")
        elif args.cmd == "rotate-targets":
            r = rotate_targets(keys_dir, Path(args.out))
            for note in r.get("notes", []):
                print(note)
            print(f"New release key {r['targets_keyid'][:16]}...; the old one moved to {r['retired']}.")
            print(f"Wrote {r['root_json']} (root version {r['version']}). Make a new backup now, and "
                  "ship this root.json with the next release.")
        elif args.cmd == "show":
            for k, v in show(keys_dir).items():
                print(f"{k}: {v}")
        elif args.cmd in ("backup", "restore"):
            if not args.in_console and not sys.stdin.isatty():
                return _in_own_console(argv, f"TacoGuard key {args.cmd}")
            code = 0
            try:
                if args.cmd == "backup":
                    files = backup_keys(keys_dir, Path(args.to), _ask_passphrase(twice=True))
                    print(f"Wrote {len(files)} files to {args.to}. The private keys there are encrypted "
                          "with your passphrase; keep the passphrase somewhere else.")
                else:
                    r = restore_keys(Path(args.from_dir), keys_dir, _ask_passphrase(twice=False))
                    print(f"Restored the root key ({r['root_keyid'][:16]}...) and release key "
                          f"({r['targets_keyid'][:16]}...) into {keys_dir}, protected for this "
                          f"Windows account; {r['roots_copied']} signed root files copied.")
                    if r.get("old_format"):
                        print("This backup was made in the older, weaker format. Make a new one now "
                              "with  python tools/keys.py backup --to <empty USB folder>  and then "
                              "delete the old backup.")
            except (KeyError_, signed.UpdateRejected) as e:
                print(str(e), file=sys.stderr)
                code = 1
            if args.in_console:
                input("Press Enter to close this window.")
            return code
    except (KeyError_, signed.UpdateRejected) as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
