"""Signed metadata for TacoGuard's own packages (TUF-style root + targets, Ed25519).

See the CONTRACT in tacoguard/updates/__init__.py. Everything here works on bytes and dicts; the
network side is in sources.py and the order of steps in updater.fetch_verified_targets.

Trusted state, settings.updates_dir/"trusted.json" (written atomically):
    {"root": <signed part of the newest trusted root>, "targets_version": int,
     "targets_sha256": hex of the raw targets.json bytes last trusted, "updated": epoch}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SHIPPED_ROOT = Path(__file__).resolve().parents[1] / "data" / "root.json"
STATE_NAME = "trusted.json"
META_MAX = 1024 * 1024                    # root.json / targets.json are tiny; refuse anything bigger
TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64 = re.compile(r"[0-9a-f]{64}")
NOTHING = "Nothing was changed."

ROOT_LABEL = "The new list of trusted release keys"
TARGETS_LABEL = "The update list"


class UpdateRejected(Exception):
    """Plain-English reason, shown on the page. `kind` says what failed:
    "signature" (not signed by the trusted keys), "checksum" (a file doesn't match its entry),
    "rollback" (older than what TacoGuard already trusts), "expired" (the list is past its date:
    not an attack sign, the updater shows it calmly), "format" (damaged or unexpected content),
    "test" (a new set failed its test-load, raised by the updater), "not_set_up" (NoTrustedRoot)."""

    def __init__(self, message: str = "", kind: str = "format"):
        super().__init__(message)
        self.kind = kind


class NoTrustedRoot(UpdateRejected):
    """No built-in root.json yet: TacoGuard's own update channel is not set up."""

    def __init__(self, message: str = ""):
        super().__init__(message, "not_set_up")


# ---------------------------------------------------------------------------------------------
# Keys and canonical bytes
# ---------------------------------------------------------------------------------------------

def canonical_bytes(signed: dict) -> bytes:
    return json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def public_raw(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def keyid_for(key) -> str:
    """sha256 hex of the raw 32-byte public key (bytes, a public key or a private key)."""
    raw = key if isinstance(key, (bytes, bytearray)) else public_raw(key)
    return hashlib.sha256(bytes(raw)).hexdigest()


def key_entry(key) -> dict:
    return {"keytype": "ed25519", "public": public_raw(key).hex()}


def sign_metadata(signed: dict, private_keys) -> dict:
    """{"signed": signed, "signatures": [...]} signed by every key given (tools and tests)."""
    data = canonical_bytes(signed)
    return {"signed": signed,
            "signatures": [{"keyid": keyid_for(k), "sig": k.sign(data).hex()} for k in private_keys]}


def dump_metadata(doc: dict) -> bytes:
    """How tools write root.json / targets.json (readable; signatures cover the canonical form)."""
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------------------------
# Parsing and checks
# ---------------------------------------------------------------------------------------------

def _parse(raw: bytes, label: str, kind: str) -> tuple[dict, list]:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > META_MAX:
        raise UpdateRejected(f"{label} is far bigger than expected, so it was rejected. {NOTHING}")
    try:
        doc = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise UpdateRejected(f"{label} could not be read (it is damaged), so it was rejected. "
                             f"{NOTHING}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("signed"), dict) or \
            not isinstance(doc.get("signatures"), list):
        raise UpdateRejected(f"{label} is not in the expected format, so it was rejected. {NOTHING}")
    signed = doc["signed"]
    if signed.get("_type") != kind:
        raise UpdateRejected(f"{label} is the wrong kind of file (expected {kind}), so it was "
                             f"rejected. {NOTHING}")
    version = signed.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise UpdateRejected(f"{label} has no valid version number, so it was rejected. {NOTHING}")
    expires_at(signed, label)
    return signed, doc["signatures"]


def expires_at(signed: dict, label: str = TARGETS_LABEL) -> datetime:
    text = signed.get("expires")
    try:
        if not isinstance(text, str) or not text.endswith("Z"):
            raise ValueError(text)
        when = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as e:
        raise UpdateRejected(f"{label} has no valid expiry date, so it was rejected. {NOTHING}") from e
    return when.astimezone(timezone.utc)


def _now(now: datetime | float | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, (int, float)):
        return datetime.fromtimestamp(now, timezone.utc)
    return now


def _check_expiry(signed: dict, label: str, now=None) -> None:
    until = expires_at(signed, label)
    if until <= _now(now):
        raise UpdateRejected(
            f"{label} has expired (it was valid until {until:%Y-%m-%d}), so it was rejected. {NOTHING} "
            "Old update lists are refused because someone could replay them to hide newer fixes.",
            "expired")


def _check_root_shape(signed: dict, label: str) -> None:
    bad = UpdateRejected(f"{label} is not in the expected format, so it was rejected. {NOTHING}")
    keys = signed.get("keys")
    roles = signed.get("roles")
    if not isinstance(keys, dict) or not isinstance(roles, dict):
        raise bad
    for keyid, entry in keys.items():
        if not isinstance(entry, dict) or entry.get("keytype") != "ed25519":
            raise bad
        public = entry.get("public")
        if not isinstance(public, str) or not HEX64.fullmatch(public):
            raise bad
        # a key listed under a made-up keyid could be counted twice towards a threshold
        if keyid != keyid_for(bytes.fromhex(public)):
            raise bad
    for role in ("root", "targets"):
        r = roles.get(role)
        if not isinstance(r, dict) or not isinstance(r.get("keyids"), list):
            raise bad
        threshold = r.get("threshold")
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
            raise bad
        ids = r["keyids"]
        if len(set(ids)) != len(ids) or any(k not in keys for k in ids) or threshold > len(ids):
            raise bad


def _check_signatures(signed: dict, signatures: list, root: dict, role: str, label: str) -> None:
    """The role's threshold of DISTINCT trusted keyids must have signed the canonical bytes."""
    keys = root["keys"]
    allowed = set(root["roles"][role]["keyids"])
    threshold = root["roles"][role]["threshold"]
    data = canonical_bytes(signed)
    good: set[str] = set()
    trusted_seen = bad_sig = False
    for s in signatures:
        if not isinstance(s, dict):
            continue
        keyid, sig = s.get("keyid"), s.get("sig")
        if keyid not in allowed or keyid in good or not isinstance(sig, str):
            continue
        trusted_seen = True
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[keyid]["public"])).verify(
                bytes.fromhex(sig), data)
        except (InvalidSignature, ValueError):
            bad_sig = True
            continue
        good.add(keyid)
    if len(good) >= threshold:
        return
    if not good and bad_sig:
        raise UpdateRejected(f"{label}'s signature does not match its contents (it may have been "
                             f"changed on the way), so it was rejected. {NOTHING}", "signature")
    if not good and not trusted_seen:
        raise UpdateRejected(f"{label} is signed by a key TacoGuard does not trust, so it was "
                             f"rejected. {NOTHING}", "signature")
    raise UpdateRejected(f"{label} needs {threshold} signatures from TacoGuard's release keys but "
                         f"has only {len(good)}, so it was rejected. {NOTHING}", "signature")


# ---------------------------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------------------------

def parse_root(raw: bytes, label: str = "The built-in list of trusted release keys") -> dict:
    """A root that must be signed by its OWN root threshold (the shipped root, a stored one)."""
    signed, signatures = _parse(raw, label, "root")
    _check_root_shape(signed, label)
    _check_signatures(signed, signatures, signed, "root", label)
    return signed


ROOTS_DIR = "roots"           # updates_dir/roots/root-<version>.json: the signed files, as published


def stored_root_path(settings, version: int) -> Path:
    return Path(settings.updates_dir) / ROOTS_DIR / f"root-{int(version)}.json"


def load_trusted_root(settings) -> dict:
    """The signed part of the newest trusted root: tacoguard/data/root.json, then every newer
    signed root file stored by an earlier update (updates_dir/roots/root-<v>.json), each checked
    again against the one before it (verify_root_update) at every load. A stored file that is
    missing or fails its check ends the walk there: nothing stored on this PC is trusted on its
    own (TGUARD-20261127-07). trusted.json's "root" is kept for the page, never trusted."""
    try:
        raw = SHIPPED_ROOT.read_bytes()
    except FileNotFoundError:
        raw = None
    except OSError as e:
        raise NoTrustedRoot("TacoGuard could not read its built-in release key list "
                            f"({e.strerror or e}), so its own updates are switched off.") from e
    if raw is None:
        raise NoTrustedRoot("TacoGuard's own update channel isn't set up yet (no release key is "
                            "built in), so only ClamAV and YARA updates run.")
    root = parse_root(raw)
    for _ in range(MAX_STORED_ROOTS):
        try:
            nxt = stored_root_path(settings, root["version"] + 1).read_bytes()
        except OSError:
            break
        try:
            root = verify_root_update(root, nxt)
        except UpdateRejected:
            break
    return root


MAX_STORED_ROOTS = 100


def verify_root_update(trusted: dict, new_bytes: bytes) -> dict:
    """The signed part of the next root (trusted version + 1). It must be signed by the threshold
    of the OLD root's root keys AND of its own root keys. Expiry of in-between roots is not checked
    (a long-offline PC must be able to walk the chain); check_root_fresh does the final one."""
    signed, signatures = _parse(new_bytes, ROOT_LABEL, "root")
    have, got = trusted["version"], signed["version"]
    if got < have:
        raise UpdateRejected(
            f"{ROOT_LABEL} is older than the one already installed (version {got} < {have}): "
            "this can be an attack that tries to bring back old keys, so it was rejected. "
            f"{NOTHING}", "rollback")
    if got == have:
        raise UpdateRejected(f"{ROOT_LABEL} has the same version ({got}) as the one already "
                             f"installed, so it was not used. {NOTHING}", "rollback")
    if got != have + 1:
        raise UpdateRejected(
            f"{ROOT_LABEL} skips a version (TacoGuard has version {have}, this is version {got}); "
            f"key changes must be followed one step at a time, so it was rejected. {NOTHING}")
    _check_root_shape(signed, ROOT_LABEL)
    _check_signatures(signed, signatures, trusted, "root", ROOT_LABEL)
    _check_signatures(signed, signatures, signed, "root", ROOT_LABEL)
    return signed


def check_root_fresh(root: dict, now=None) -> None:
    _check_expiry(root, "TacoGuard's list of trusted release keys", now)


def targets_keys_changed(old_root: dict, new_root: dict) -> bool:
    """TUF: when the release keys change, the remembered targets version is reset (so a release
    signed with a stolen, now-replaced key cannot block updates by using a huge version)."""
    o, n = old_root["roles"]["targets"], new_root["roles"]["targets"]
    return set(o["keyids"]) != set(n["keyids"]) or o["threshold"] != n["threshold"]


# ---------------------------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------------------------

def _check_targets_shape(signed: dict) -> None:
    bad = UpdateRejected(f"{TARGETS_LABEL} is not in the expected format, so it was rejected. {NOTHING}")
    targets = signed.get("targets")
    if not isinstance(targets, dict):
        raise bad
    for name, entry in targets.items():
        if not isinstance(name, str) or not TARGET_NAME.fullmatch(name) or ".." in name:
            raise bad
        if not isinstance(entry, dict):
            raise bad
        length = entry.get("length")
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            raise bad
        if not isinstance(entry.get("sha256"), str) or not HEX64.fullmatch(entry["sha256"]):
            raise bad
        custom = entry.get("custom", {})
        if not isinstance(custom, dict):
            raise bad
        for k in ("kind", "version", "min_app", "notes"):
            if k in custom and not isinstance(custom[k], str):
                raise bad


def verify_targets(root: dict, targets_bytes: bytes, last_version: int, last_sha256: str = "",
                   now=None) -> dict:
    """The signed part of targets.json, after checking: signatures (root's targets role), expiry,
    no rollback (version >= last_version), and the same version only with the same bytes."""
    signed, signatures = _parse(targets_bytes, TARGETS_LABEL, "targets")
    _check_signatures(signed, signatures, root, "targets", TARGETS_LABEL)
    version = signed["version"]
    if version < int(last_version or 0):
        raise UpdateRejected(
            f"{TARGETS_LABEL} is older than the one already installed (version {version} < "
            f"{last_version}): this can be an attack that tries to bring back old software, so it "
            f"was rejected. {NOTHING}", "rollback")
    if version == int(last_version or 0) and last_sha256 and \
            not hmac.compare_digest(hashlib.sha256(bytes(targets_bytes)).hexdigest(), last_sha256):
        raise UpdateRejected(
            f"{TARGETS_LABEL} has the same version number ({version}) as the one already installed "
            "but different contents. A real release always gets a new number, so it was rejected. "
            f"{NOTHING}", "rollback")
    _check_expiry(signed, TARGETS_LABEL, now)
    _check_targets_shape(signed)
    return signed


def verify_file(path, target_entry: dict) -> None:
    """Length first (cheap), then the sha256, read in 1 MB blocks."""
    path = Path(path)
    name = path.name
    try:
        size = path.stat().st_size
    except OSError as e:
        raise UpdateRejected(f"The downloaded file {name} could not be read, so it was not used. "
                             f"{NOTHING}", "checksum") from e
    if size != int(target_entry["length"]):
        raise UpdateRejected(f"The downloaded file {name} has the wrong size ({size} bytes, the "
                             f"update list says {target_entry['length']}), so it was thrown away. "
                             f"{NOTHING}", "checksum")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    if not hmac.compare_digest(h.hexdigest(), str(target_entry["sha256"]).lower()):
        raise UpdateRejected(f"The downloaded file {name} does not match the checksum in the signed "
                             f"update list, so it was thrown away. {NOTHING}", "checksum")


# ---------------------------------------------------------------------------------------------
# Trusted state
# ---------------------------------------------------------------------------------------------

def state_path(settings) -> Path:
    return Path(settings.updates_dir) / STATE_NAME


def load_state(settings) -> dict:
    try:
        data = json.loads(state_path(settings).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_json_atomic(path: Path, data) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def save_state(settings, state: dict) -> None:
    write_json_atomic(state_path(settings), {**state, "updated": time.time()})


TARGETS_COPY = "targets.json"


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def remember(settings, root: dict, targets: dict, targets_bytes: bytes,
             root_files: list[bytes] | tuple = ()) -> None:
    """Store the verified root and targets version (call only after both verified), the raw
    signed targets.json bytes in updates_dir/targets.json so selfupdate can verify the signatures
    again before it installs anything, and the raw signed root files the update walked
    (root_files, oldest first) so load_trusted_root can check the chain again."""
    for rb in root_files:
        try:
            v = json.loads(bytes(rb).decode("utf-8"))["signed"]["version"]
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
            continue
        if isinstance(v, int) and v > 0:
            write_bytes_atomic(stored_root_path(settings, v), bytes(rb))
    write_bytes_atomic(Path(settings.updates_dir) / TARGETS_COPY, bytes(targets_bytes))
    save_state(settings, {"root": root, "targets_version": int(targets["version"]),
                          "targets_sha256": hashlib.sha256(bytes(targets_bytes)).hexdigest()})
