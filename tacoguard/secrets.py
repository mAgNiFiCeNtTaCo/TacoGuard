"""Your own keys for online services (Phase 4: the free abuse.ch key), kept protected by Windows.

    get_key(settings, name="abusech") -> str | None      None when not set or it can't be read
    set_key(settings, name, value) -> None               raises ValueError (plain words) for a bad key
    clear_key(settings, name="abusech") -> bool          True when a saved key was removed
    has_key(settings, name="abusech") -> bool            cheap: is a key file there at all
    key_hint(settings, name="abusech") -> str            "ending in ...a1b2", or "" when no key

The key is stored in settings.secrets_dir/<name>.dpapi, encrypted with Windows DPAPI for this
Windows account only (tacoguard/dpapi.py), written atomically. It is never logged, never printed,
never put in an error message and never shown back in full: the page shows only its last 4
characters. Only TacoGuard's abuse.ch lookups (lookup.py, webblock/lists.py) send it, and only to
abuse.ch hosts listed in config.ENDPOINTS.

(This module is tacoguard.secrets; Python's own `secrets` module is still what `import secrets`
gives every other file.)
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path

log = logging.getLogger("tacoguard.secrets")

ABUSECH = "abusech"
_NAME = re.compile(r"^[a-z0-9_]{1,32}$")
# abuse.ch Auth-Keys are long strings of letters and digits; allow a little room either way.
_KEY = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_MAGIC = "TacoGuard secret v1"

BAD_KEY_MSG = ("That doesn't look like an abuse.ch key. Copy the Auth-Key from your account page on "
               "auth.abuse.ch (letters and digits, at least 20 characters) and paste it again.")
SAVE_FAILED_MSG = "Windows could not save the key safely, so it was not saved. Try again."

_cache: dict[str, tuple[tuple, str | None]] = {}    # file path -> ((mtime_ns, size), key)
_lock = threading.Lock()


def _path(settings, name: str) -> Path:
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError("Unknown key name.")
    return Path(settings.secrets_dir) / f"{name}.dpapi"


def clean_key(value) -> str:
    """The key with spaces and line breaks taken out; raises ValueError(BAD_KEY_MSG) when it does
    not look like a key. The message never contains the value."""
    if not isinstance(value, str):
        raise ValueError(BAD_KEY_MSG)
    key = re.sub(r"\s+", "", value)
    if not _KEY.match(key):
        raise ValueError(BAD_KEY_MSG)
    return key


def set_key(settings, name: str, value) -> None:
    key = clean_key(value)                # before anything touches the disk
    path = _path(settings, name)
    from . import dpapi
    payload = json.dumps({"magic": _MAGIC, "name": name, "value": key}).encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    try:
        blob = dpapi.protect(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        log.warning("Could not save the %s key", name)
        raise ValueError(SAVE_FAILED_MSG) from None
    with _lock:
        _cache.pop(str(path), None)
    log.info("Saved a new %s key", name)


def get_key(settings, name: str = ABUSECH) -> str | None:
    try:
        path = _path(settings, name)
        st = os.stat(path)
    except (OSError, ValueError):
        return None
    stamp = (st.st_mtime_ns, st.st_size)
    with _lock:
        hit = _cache.get(str(path))
        if hit and hit[0] == stamp:
            return hit[1]
    key = _read(path, name)
    with _lock:
        _cache[str(path)] = (stamp, key)
    return key


def _read(path: Path, name: str) -> str | None:
    from . import dpapi
    try:
        doc = json.loads(dpapi.unprotect(path.read_bytes()).decode("utf-8"))
        if not (isinstance(doc, dict) and doc.get("magic") == _MAGIC and doc.get("name") == name):
            raise ValueError("wrong file")
        return clean_key(doc.get("value"))
    except Exception:          # damaged, another Windows account's file, or not ours: no details
        log.warning("The saved %s key could not be read; add it again in Settings", name)
        return None


def has_key(settings, name: str = ABUSECH) -> bool:
    try:
        return _path(settings, name).is_file()
    except (OSError, ValueError):
        return False


def clear_key(settings, name: str = ABUSECH) -> bool:
    path = _path(settings, name)
    with _lock:
        _cache.pop(str(path), None)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    log.info("Removed the %s key", name)
    return True


def key_hint(settings, name: str = ABUSECH) -> str:
    key = get_key(settings, name)
    return f"ending in ...{key[-4:]}" if key else ""


def key_stamp(settings, name: str = ABUSECH) -> str:
    """Changes whenever the key file is saved again (no part of the key is in it). lookup.py
    uses it to try again at once after you paste a new key."""
    try:
        st = os.stat(_path(settings, name))
        return f"{st.st_mtime_ns}:{st.st_size}"
    except (OSError, ValueError):
        return ""
