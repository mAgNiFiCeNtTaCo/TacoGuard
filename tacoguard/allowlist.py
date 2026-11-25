"""Your trusted list (by file hash or by folder) and your verdicts.

"Not a threat" puts the file's hash on the trusted list AND records the verdict, so the same file
is never flagged again, wherever it is. Phase 2's local learning reads only these verdicts.
"""
from __future__ import annotations

import os
import re

from . import winpath
from .store import Store

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AllowlistError(ValueError):
    pass


def trust_hash(store: Store, sha256: str, note: str = "", path: str = "") -> int:
    h = (sha256 or "").strip().lower()
    if not _SHA256.match(h):
        raise AllowlistError("That is not a SHA-256 hash (64 letters and digits).")
    label = f"{note} ({winpath.to_display(path)})" if path and note else (note or winpath.to_display(path))
    return store.add_allow("hash", h, h, label)


def trust_folder(store: Store, folder: str, note: str = "") -> int:
    disp = winpath.to_display(os.path.abspath(winpath.to_display(folder)))
    if not os.path.isdir(winpath.to_long(disp)):
        raise AllowlistError(f"Folder not found: {disp}")
    key = winpath.norm_key(disp)
    if len(key) <= 3:
        raise AllowlistError("Trusting a whole drive would switch scanning off there. Pick a folder instead.")
    return store.add_allow("folder", disp, key, note)


def untrust(store: Store, allow_id: int) -> None:
    store.remove_allow(allow_id)


class TrustChecker:
    """Fast checks during a scan. Reloads from the store when refresh() is called."""

    def __init__(self, store: Store):
        self.store = store
        self.refresh()

    def refresh(self) -> None:
        self.hashes = self.store.allowed_hashes()
        self.folders = [(f["key"], f["value"]) for f in self.store.allowed_folders()]

    def folder_reason(self, path: str) -> str | None:
        for key, disp in self.folders:
            if winpath.is_under(path, key):
                return f"Inside a folder you trust ({disp}), so it was not checked."
        return None

    def hash_reason(self, sha256: str) -> str | None:
        if sha256 and sha256.lower() in self.hashes:
            return "You marked this exact file as safe earlier, so it was not checked again."
        return None


def mark_not_a_threat(store: Store, result_id: int) -> int:
    r = store.get_result(result_id)
    if not r:
        raise AllowlistError("That result no longer exists.")
    if not r["sha256"]:
        raise AllowlistError("This file has no hash (it could not be read), so it cannot be trusted by hash.")
    store.add_verdict(r["sha256"], r["path"], "not_a_threat", r["findings"])
    allow_id = trust_hash(store, r["sha256"], "You said: not a threat", r["path"])
    store.set_result_action(result_id, "trusted")
    return allow_id


def mark_confirmed_threat(store: Store, result_id: int) -> None:
    r = store.get_result(result_id)
    if not r:
        raise AllowlistError("That result no longer exists.")
    store.add_verdict(r["sha256"], r["path"], "confirmed_threat", r["findings"])
    store.set_result_action(result_id, "confirmed")
