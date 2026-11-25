"""Quarantine: an encrypted, non-runnable store for files you decided to put away.

CONTRACT (Helper C fills this in; signatures must stay):

    class QuarantineError(Exception)   plain-English message for the page

    class Quarantine(settings, store)
        put(path, reason, findings, result_id=0) -> int
            Encrypt the file at `path` (display or long path) into settings.quarantine_dir,
            verify the encrypted copy, then remove the original. Returns the quarantine id.
            Never removes the original unless the encrypted copy is verified. Checks free space
            first. A locked file -> QuarantineError("... is in use by another program ...").
        restore(qid, trust=False) -> str
            Decrypt back to the original path (or a free name next to it if that name is taken now,
            recreating the folder if needed), check the SHA-256, then delete the encrypted copy.
            trust=True also adds the file's hash to the allowlist with a 'restored by you' note.
            Returns the display path it was restored to.
        delete(qid) -> None
            Permanently delete the encrypted copy (only ever called from a user click).
        items() -> list[dict]           records in state 'quarantined', newest first
        recover() -> list[str]
            Finish or roll back operations cut off by a crash or the app closing
            (states pending / restoring / deleting). Returns plain-English notes. Called at start-up.
        used_bytes() -> int             disk space used by the quarantine folder

Blob format (file "<32 random hex>.tgq", never the original name or extension):
    header  = b"TGQ1" + chunk size (uint32 LE) + 16 random bytes (this blob's id)
    chunks  = for each 1 MiB of the file: 12-byte nonce + AES-256-GCM(ciphertext + 16-byte tag)
    Each chunk's associated data is header + chunk index (uint64) + is-last flag (1 byte), so a
    changed, reordered, swapped-in (from another blob) or cut-off chunk fails to decrypt.
The AES key is random, made once, and stored in key.dpapi protected by Windows DPAPI (only this
Windows account on this PC can unlock it).

Every step is recorded in the store first, so a crash at any point can be finished or rolled
back by recover(): the original file is deleted only after the encrypted copy is verified, and
the row stays 'pending' until the original is gone.
"""
from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
import secrets
import shutil
import stat
import struct
from ctypes import wintypes
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import allowlist, dpapi, winpath
from .model import Finding, plain_error

MAGIC = b"TGQ1"
CHUNK = 1024 * 1024
NONCE = 12
TAG = 16
HEADER_LEN = len(MAGIC) + 4 + 16
MAX_CHUNK = 16 * 1024 * 1024   # refuse silly chunk sizes in a damaged header
SPACE_MARGIN = 64 * 1024 * 1024
KEY_FILE = "key.dpapi"
BLOB_EXT = ".tgq"

README = """\
TacoGuard quarantine folder
===========================

The files here are programs or documents you chose to put away. Each one is encrypted
(AES-256), renamed to random letters with the extension .tgq, and cannot run or open.

Please don't move, rename or edit anything in this folder by hand. To get a file back, or
to delete it for good, use the Quarantine page in TacoGuard.

key.dpapi holds the encryption key, locked to your Windows account. Without it the
quarantined files cannot be restored.
"""


MSG_BUSY = "This file is already being restored or deleted."
MSG_KEY_LOST = ("The quarantine key is missing or can't be unlocked by this Windows account, so "
                "quarantined files can't be restored. Nothing was changed.")


class QuarantineError(Exception):
    pass


class _Damaged(Exception):
    """The encrypted copy failed its checks (changed, cut off, or not a TacoGuard blob)."""


class Quarantine:
    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self.dir = Path(settings.quarantine_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._aes: AESGCM | None = None
        readme = self.dir / "README.txt"
        if not readme.exists():
            readme.write_text(README, encoding="utf-8")

    # ---- public ----------------------------------------------------------------------------
    def put(self, path, reason: str, findings, result_id: int = 0) -> int:
        long = winpath.to_long(path)
        display = winpath.to_display(long)
        name = os.path.basename(display)
        if not os.path.isfile(long):
            raise QuarantineError(f"{name} was not found (it may have been moved or deleted). Nothing was changed.")
        _check_space(self.dir, os.stat(long).st_size,
                     "Not enough free disk space to quarantine this file safely. Nothing was changed.")
        self._cipher()  # a key problem should stop us before anything is written
        original = _Original.open(long, name)
        try:
            return self._put_open(original, display, name, reason, findings, result_id)
        finally:
            original.close()

    def restore(self, qid: int, trust: bool = False) -> str:
        row = self._row(qid, "quarantined")
        name = os.path.basename(row["original_path"])
        blob = self.dir / row["blob"]
        self._cipher()  # a key problem should stop us before anything is written
        original = winpath.to_long(row["original_path"])
        # Claimed in one statement: a second click (or a second page) gets a plain answer
        # instead of fighting over the same files.
        if not self.store.claim_quarantine(qid, "quarantined", "restoring",
                                           winpath.to_display(_free_name(original))):
            raise QuarantineError(MSG_BUSY)
        try:
            if not blob.exists():
                raise QuarantineError(f"The quarantined copy of {name} is missing, so it can't be restored.")
            folder = os.path.dirname(original)
            os.makedirs(folder, exist_ok=True)
            _check_space(folder, row["size"], "Not enough free disk space to restore this file safely. "
                                              "Nothing was changed.")
        except Exception as exc:
            self.store.set_quarantine_state(qid, "quarantined", "Restore failed; the file is still in quarantine.")
            raise QuarantineError(_plain(exc, name, "restore")) from exc
        part = self._restore_part(row)
        try:
            sha = self._decrypt_to(blob, part)
            if sha != row["sha256"]:
                raise _Damaged
            target = self._place(qid, part, original)
        except Exception as exc:
            _remove(part)
            self.store.set_quarantine_state(qid, "quarantined", "Restore failed; the file is still in quarantine.")
            if isinstance(exc, _Damaged):
                raise QuarantineError(f"The quarantined copy of {name} is damaged, so it was not restored. "
                                      "Nothing was written.") from None
            raise QuarantineError(_plain(exc, name, "restore")) from exc
        shown = winpath.to_display(target)
        self._drop_blob(blob)
        self.store.set_quarantine_state(qid, "restored", shown)
        if row["result_id"]:
            self.store.set_result_action(row["result_id"], "restored")
        if trust:
            allowlist.trust_hash(self.store, row["sha256"], "Restored by you", shown)
        return shown

    def delete(self, qid: int) -> None:
        row = self._row(qid, "quarantined")
        if not self.store.claim_quarantine(qid, "quarantined", "deleting"):
            raise QuarantineError(MSG_BUSY)
        try:
            self._drop_blob(self.dir / row["blob"])
        except OSError as exc:
            self.store.set_quarantine_state(qid, "quarantined")
            raise QuarantineError(_plain(exc, os.path.basename(row["original_path"]), "delete")) from exc
        self.store.set_quarantine_state(qid, "deleted")
        if row["result_id"]:
            self.store.set_result_action(row["result_id"], "deleted")

    def items(self) -> list[dict]:
        return self.store.list_quarantine(("quarantined",))

    def recover(self) -> list[str]:
        notes = []
        steps = {"pending": self._recover_pending, "restoring": self._recover_restoring,
                 "deleting": self._recover_deleting}
        for row in self.store.list_quarantine(tuple(steps)):
            name = os.path.basename(row["original_path"])
            try:
                notes.append(steps[row["state"]](row, name))
            except Exception as exc:  # one stuck record must not block the others
                notes.append(f"{name}: an interrupted quarantine step could not be finished "
                             f"({plain_error(exc)}).")
        return notes

    def used_bytes(self) -> int:
        total = 0
        with os.scandir(self.dir) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
        return total

    # ---- put steps -------------------------------------------------------------------------
    def _put_open(self, original: "_Original", display: str, name: str, reason, findings, result_id) -> int:
        blob = secrets.token_hex(16) + BLOB_EXT
        final, part = self.dir / blob, self.dir / (blob + ".part")
        qid = self.store.add_quarantine(display, "", original.size, reason, _findings(findings), blob, result_id)
        try:
            sha, size = self._encrypt(original.file, part)
            if self._blob_sha(part) != sha:
                raise _Damaged
            os.replace(part, final)
            self.store.set_quarantine_hash(qid, sha, size)
            original.delete()
        except Exception as exc:  # a crash (not an error) leaves 'pending' for recover()
            _remove(part)
            _remove(final)
            message = _plain(exc, name, "quarantine")
            self.store.set_quarantine_state(qid, "failed", message)
            raise QuarantineError(message) from exc
        self.store.set_quarantine_state(qid, "quarantined")
        if result_id:
            self.store.set_result_action(result_id, "quarantined")
        return qid

    def _encrypt(self, src, part: Path) -> tuple[str, int]:
        aes = self._cipher()
        header = MAGIC + struct.pack("<I", CHUNK) + os.urandom(16)
        digest, size, index = hashlib.sha256(), 0, 0
        with open(part, "xb") as out:
            out.write(header)
            chunk = _read_full(src, CHUNK)
            while True:
                following = _read_full(src, CHUNK) if len(chunk) == CHUNK else b""
                last = not following
                digest.update(chunk)
                size += len(chunk)
                nonce = os.urandom(NONCE)
                out.write(nonce + aes.encrypt(nonce, chunk, _aad(header, index, last)))
                if last:
                    break
                chunk, index = following, index + 1
            out.flush()
            os.fsync(out.fileno())
        return digest.hexdigest(), size

    # ---- reading blobs -----------------------------------------------------------------------
    def _chunks(self, blob: Path):
        """Decrypted chunks of a blob, in order. Raises _Damaged on any failed check."""
        aes = self._cipher()
        with open(blob, "rb") as f:
            header = f.read(HEADER_LEN)
            if len(header) != HEADER_LEN or not header.startswith(MAGIC):
                raise _Damaged
            chunk_size = struct.unpack_from("<I", header, len(MAGIC))[0]
            if not 0 < chunk_size <= MAX_CHUNK:
                raise _Damaged
            record = NONCE + chunk_size + TAG
            current, index = f.read(record), 0
            while True:
                following = f.read(record) if len(current) == record else b""
                last = not following
                if len(current) < NONCE + TAG:
                    raise _Damaged
                try:
                    yield aes.decrypt(current[:NONCE], current[NONCE:], _aad(header, index, last))
                except InvalidTag:
                    raise _Damaged from None
                if last:
                    return
                current, index = following, index + 1

    def _blob_sha(self, blob: Path) -> str:
        digest = hashlib.sha256()
        for chunk in self._chunks(blob):
            digest.update(chunk)
        return digest.hexdigest()

    def _blob_ok(self, blob: Path, sha256: str) -> bool:
        try:
            return bool(sha256) and blob.exists() and self._blob_sha(blob) == sha256
        except _Damaged:
            return False

    def _decrypt_to(self, blob: Path, part: str) -> str:
        digest = hashlib.sha256()
        with open(part, "wb") as out:
            for chunk in self._chunks(blob):
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        return digest.hexdigest()

    def _place(self, qid: int, part: str, original: str) -> str:
        """Renames the restored file into place under the first free name. The chosen name is
        recorded first so recover() can find a restore that was cut off right after."""
        while True:
            target = _free_name(original)
            self.store.set_quarantine_state(qid, "restoring", winpath.to_display(target))
            try:
                os.rename(part, target)  # never replaces an existing file on Windows
                return target
            except FileExistsError:
                continue  # someone created that name just now: take the next one

    def _drop_blob(self, blob: Path) -> None:
        try:
            os.remove(blob)
        except FileNotFoundError:
            pass

    def _restore_part(self, row: dict) -> str:
        folder = os.path.dirname(winpath.to_long(row["original_path"]))
        return os.path.join(folder, row["blob"][: -len(BLOB_EXT)] + ".restore.part")

    # ---- recovery --------------------------------------------------------------------------
    def _recover_pending(self, row: dict, name: str) -> str:
        blob = self.dir / row["blob"]
        _remove(self.dir / (row["blob"] + ".part"))
        if os.path.exists(winpath.to_long(row["original_path"])):
            _remove(blob)
            self.store.set_quarantine_state(row["id"], "failed",
                                            "Quarantine was interrupted; the file was left where it was.")
            return f"{name}: quarantine was interrupted; the file was left where it was."
        if self._blob_ok(blob, row["sha256"]):
            self.store.set_quarantine_state(row["id"], "quarantined", "Finished after an interruption.")
            return f"{name}: quarantine was interrupted after the file was put away; it is safely in quarantine."
        _remove(blob)
        self.store.set_quarantine_state(row["id"], "failed",
                                        "Quarantine was interrupted and the file is no longer there.")
        return f"{name}: quarantine was interrupted and the file is no longer where it was."

    def _recover_restoring(self, row: dict, name: str) -> str:
        blob = self.dir / row["blob"]
        target = winpath.to_long(row["message"]) if row["message"] else ""
        _remove(self._restore_part(row))
        restored = bool(target) and os.path.isfile(target) and _file_sha(target) == row["sha256"]
        if restored:
            self._drop_blob(blob)
            self.store.set_quarantine_state(row["id"], "restored", row["message"])
            return f"{name}: restore was interrupted at the very end; the file is back at {row['message']}."
        if blob.exists():
            self.store.set_quarantine_state(row["id"], "quarantined",
                                            "Restore was interrupted; the file is still in quarantine.")
            return f"{name}: restore was interrupted; the file is still in quarantine."
        self.store.set_quarantine_state(row["id"], "failed", "Restore was interrupted and the file was lost.")
        return f"{name}: restore was interrupted and neither the restored file nor the quarantined copy was found."

    def _recover_deleting(self, row: dict, name: str) -> str:
        self._drop_blob(self.dir / row["blob"])
        self.store.set_quarantine_state(row["id"], "deleted")
        return f"{name}: a permanent delete was interrupted; it is now finished."

    # ---- helpers ---------------------------------------------------------------------------
    def _row(self, qid: int, state: str) -> dict:
        row = self.store.get_quarantine(qid)
        if not row:
            raise QuarantineError("That quarantine record no longer exists.")
        if row["state"] in ("restoring", "deleting") and state == "quarantined":
            raise QuarantineError(MSG_BUSY)
        if row["state"] != state:
            raise QuarantineError(f"{os.path.basename(row['original_path'])} is not in quarantine "
                                  f"(it is {row['state']}).")
        return row

    def _cipher(self) -> AESGCM:
        if self._aes is None:
            self._aes = AESGCM(self._key())
        return self._aes

    def _key(self) -> bytes:
        path = self.dir / KEY_FILE
        if not path.exists():
            # A new key would make every file already in quarantine impossible to restore, and
            # would hide that the old key is gone. Only an empty quarantine gets a new key.
            if self._holds_files():
                raise QuarantineError(MSG_KEY_LOST)
            created = self._create_key(path)
            if created:
                return created
        try:
            key = dpapi.unprotect(path.read_bytes())
        except OSError:
            raise QuarantineError(MSG_KEY_LOST) from None
        if len(key) != 32:
            raise QuarantineError("The quarantine key file is damaged, so quarantined files can't be "
                                  "restored. Nothing was changed.")
        return key

    def _holds_files(self) -> bool:
        """Any encrypted copy on disk, or any record that still needs one."""
        if self.store.count_quarantine(("pending", "quarantined", "restoring", "deleting")):
            return True
        try:
            with os.scandir(self.dir) as it:
                return any(e.name.lower().endswith((BLOB_EXT, BLOB_EXT + ".part")) for e in it)
        except OSError:
            return True

    def _create_key(self, path: Path) -> bytes | None:
        key = os.urandom(32)
        tmp = path.with_name(f"key.{secrets.token_hex(4)}.tmp")
        with open(tmp, "xb") as f:
            f.write(dpapi.protect(key))
            f.flush()
            os.fsync(f.fileno())
        try:
            os.rename(tmp, path)  # fails if another TacoGuard process made the key first
            return key
        except FileExistsError:
            _remove(tmp)
            return None


# ---- module helpers --------------------------------------------------------------------------

def _aad(header: bytes, index: int, last: bool) -> bytes:
    return header + struct.pack("<QB", index, 1 if last else 0)


def _read_full(f, n: int) -> bytes:
    parts, got = [], 0
    while got < n:
        b = f.read(n - got)
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


def _file_sha(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _free_name(path: str) -> str:
    """The path itself if free, else 'name (restored).ext', 'name (restored 2).ext', ..."""
    if not os.path.lexists(path):
        return path
    stem, ext = os.path.splitext(path)
    n = 1
    while True:
        candidate = f"{stem} (restored){ext}" if n == 1 else f"{stem} (restored {n}){ext}"
        if not os.path.lexists(candidate):
            return candidate
        n += 1


def _remove(path) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _check_space(folder, size: int, message: str) -> None:
    if shutil.disk_usage(folder).free < size + SPACE_MARGIN:
        raise QuarantineError(message)


def _findings(findings) -> list[Finding]:
    return [f if isinstance(f, Finding) else Finding.from_dict(f) for f in (findings or [])]


ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_DISK_FULL = 112


def _plain(exc: Exception, name: str, action: str) -> str:
    if isinstance(exc, QuarantineError):
        return str(exc)
    if isinstance(exc, _Damaged):
        return f"The encrypted copy of {name} could not be verified. Nothing was changed."
    code = getattr(exc, "winerror", None)
    if code in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION):
        return f"{name} is in use by another program. Close it and try again. Nothing was changed."
    if code == ERROR_DISK_FULL:
        return f"The disk filled up while trying to {action} {name}. Nothing was changed."
    if code == ERROR_ACCESS_DENIED or isinstance(exc, PermissionError):
        return f"Windows did not allow TacoGuard to {action} {name}. Nothing was changed."
    return f"Could not {action} {name} ({plain_error(exc)}). Nothing was changed."


# ---- the original file, held open ---------------------------------------------------------------

GENERIC_READ = 0x80000000
DELETE = 0x00010000
FILE_SHARE_READ = 0x1
OPEN_EXISTING = 3
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_DISPOSITION_INFO_CLASS = 4
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k32.SetFileInformationByHandle.restype = wintypes.BOOL


class _Disposition(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]


class _Original:
    """The file being quarantined, opened so that no other program can change or delete it
    while we encrypt it, and deleted through the same handle: what was verified is exactly
    what gets removed. Programs that already have it open for writing make the open fail."""

    def __init__(self, long_path: str, name: str, file, size: int):
        self.path = long_path
        self.name = name
        self.file = file
        self.size = size

    @classmethod
    def open(cls, long_path: str, name: str) -> "_Original":
        handle = _k32.CreateFileW(long_path, GENERIC_READ | DELETE, FILE_SHARE_READ, None,
                                  OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, None)
        if handle in (None, INVALID_HANDLE_VALUE):
            raise QuarantineError(_plain(ctypes.WinError(ctypes.get_last_error()), name, "quarantine"))
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        f = os.fdopen(fd, "rb", buffering=0)
        return cls(long_path, name, f, os.fstat(fd).st_size)

    def delete(self) -> None:
        attrs = os.stat(self.path).st_file_attributes
        read_only = bool(attrs & stat.FILE_ATTRIBUTE_READONLY)
        if read_only:
            os.chmod(self.path, stat.S_IWRITE | stat.S_IREAD)  # Windows won't delete read-only files
        info = _Disposition(True)
        handle = msvcrt.get_osfhandle(self.file.fileno())
        if not _k32.SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO_CLASS,
                                               ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            if read_only:
                os.chmod(self.path, stat.S_IREAD)
            raise ctypes.WinError(err)
        self.close()  # the file disappears when our handle closes

    def close(self) -> None:
        # Errors here are ignored on purpose: after delete() set the disposition, a failed close
        # must not look like a failed quarantine (that would roll back and remove the blob).
        try:
            self.file.close()
        except OSError:
            pass
