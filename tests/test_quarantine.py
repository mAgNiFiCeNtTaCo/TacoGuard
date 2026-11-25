"""Quarantine: encryption, verification, restore, delete, locked files, crashes, recovery.

Test material: tests/samples.py only (sample_bytes with MARKER). EICAR is never written to disk.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import stat
from ctypes import wintypes
from pathlib import Path

import pytest

import samples
from tacoguard import dpapi, quarantine as qmod, winpath
from tacoguard.model import Confidence, Finding
from tacoguard.quarantine import Quarantine, QuarantineError


class SimulatedCrash(BaseException):
    """Stands in for the process dying: not an Exception, so no rollback code runs."""


FINDING = Finding(engine="yara", rule="TacoGuard_Test_Harmless_Sample", confidence=Confidence.HIGH,
                  source="TacoGuard tests")


@pytest.fixture
def q(settings, store) -> Quarantine:
    return Quarantine(settings, store)


def make_sample(folder: Path, name="sample.exe", extra=b"") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_bytes(samples.sample_bytes() + extra)
    return p


def sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def blob_path(q: Quarantine, store, qid: int) -> Path:
    return q.dir / store.get_quarantine(qid)["blob"]


# ---- DPAPI ------------------------------------------------------------------------------------

def test_dpapi_round_trip():
    secret = os.urandom(32)
    sealed = dpapi.protect(secret)
    assert sealed != secret and secret not in sealed
    assert dpapi.unprotect(sealed) == secret
    with pytest.raises(OSError):
        dpapi.unprotect(sealed[:-5] + b"xxxxx")


# ---- put / restore / delete -------------------------------------------------------------------

def test_put_encrypts_and_restore_gives_identical_file(q, store, tmp_path):
    big = os.urandom(3 * qmod.CHUNK + 123)  # several chunks plus a short last one
    original = make_sample(tmp_path / "files", extra=big)
    before = sha(original)
    qid = q.put(str(original), "test reason", [FINDING])
    assert not original.exists()
    row = store.get_quarantine(qid)
    assert row["state"] == "quarantined" and row["sha256"] == before and row["size"] == len(samples.sample_bytes()) + len(big)
    blob = q.dir / row["blob"]
    assert blob.suffix == ".tgq" and "sample" not in blob.name and ".exe" not in blob.name
    data = blob.read_bytes()
    assert data.startswith(b"TGQ1")
    assert samples.MARKER not in data
    assert (q.dir / "key.dpapi").exists() and (q.dir / "README.txt").exists()
    assert [i["id"] for i in q.items()] == [qid]
    assert q.used_bytes() >= len(data)

    restored = q.restore(qid)
    assert restored == str(original)
    assert sha(original) == before
    assert not blob.exists()
    assert store.get_quarantine(qid)["state"] == "restored"
    assert q.items() == []


def test_exact_chunk_multiple_and_empty_file(q, tmp_path):
    for name, data in (("exact.bin", os.urandom(2 * qmod.CHUNK)), ("empty.bin", b"")):
        p = tmp_path / name
        p.write_bytes(data)
        qid = q.put(str(p), "r", [])
        assert not p.exists()
        q.restore(qid)
        assert p.read_bytes() == data


def test_findings_as_dicts_are_accepted(q, store, tmp_path):
    p = make_sample(tmp_path)
    qid = q.put(str(p), "r", [FINDING.to_dict()])
    assert store.get_quarantine(qid)["findings"][0]["rule"] == FINDING.rule


def test_restore_to_taken_name_and_missing_folder(q, store, tmp_path):
    folder = tmp_path / "gone" / "deeper"
    p = make_sample(folder)
    qid1 = q.put(str(p), "r", [])
    p.write_bytes(b"a new file with the same name")
    shown = q.restore(qid1)
    assert shown == str(folder / "sample (restored).exe")
    assert Path(shown).read_bytes() == samples.sample_bytes()
    assert p.read_bytes() == b"a new file with the same name"

    qid2 = q.put(shown, "r", [])
    shutil.rmtree(tmp_path / "gone")
    assert winpath.to_display(q.restore(qid2)) == str(folder / "sample (restored).exe")
    assert (folder / "sample (restored).exe").read_bytes() == samples.sample_bytes()

    p.write_bytes(samples.sample_bytes())
    qid3 = q.put(str(p), "r", [])
    p.write_bytes(b"taken")  # now both sample.exe and sample (restored).exe exist
    assert q.restore(qid3) == str(folder / "sample (restored 2).exe")


def test_restore_with_trust_adds_allowlist(q, store, tmp_path):
    p = make_sample(tmp_path)
    digest = sha(p)
    qid = q.put(str(p), "r", [])
    q.restore(qid, trust=True)
    rows = store.list_allow("hash")
    assert [r["key"] for r in rows] == [digest]
    assert "Restored by you" in rows[0]["note"]


def test_delete(q, store, tmp_path):
    p = make_sample(tmp_path)
    qid = q.put(str(p), "r", [])
    blob = blob_path(q, store, qid)
    q.delete(qid)
    assert not blob.exists() and not p.exists()
    assert store.get_quarantine(qid)["state"] == "deleted"
    with pytest.raises(QuarantineError):
        q.restore(qid)


def test_result_action_is_recorded(q, store, tmp_path):
    from tacoguard.model import FileResult
    job = store.create_job(["x"])
    p = make_sample(tmp_path)
    rid = store.add_result(job, FileResult(path=str(p), findings=[FINDING]))
    qid = q.put(str(p), "r", [FINDING], result_id=rid)
    assert store.get_result(rid)["action"] == "quarantined"
    q.restore(qid)
    assert store.get_result(rid)["action"] == "restored"


# ---- damaged blobs ----------------------------------------------------------------------------

def _quarantined(q, store, tmp_path, size=2 * qmod.CHUNK + 500):
    p = make_sample(tmp_path / "f", extra=os.urandom(size))
    qid = q.put(str(p), "r", [])
    return p, qid, blob_path(q, store, qid)


def _assert_refused(q, store, qid, p):
    with pytest.raises(QuarantineError) as err:
        q.restore(qid)
    assert "damaged" in str(err.value) and "Nothing was written" in str(err.value)
    assert not p.exists()
    assert not [x for x in p.parent.iterdir()]  # no .part left behind
    assert store.get_quarantine(qid)["state"] == "quarantined"


def test_tampered_blob_is_refused(q, store, tmp_path):
    p, qid, blob = _quarantined(q, store, tmp_path)
    data = bytearray(blob.read_bytes())
    data[qmod.HEADER_LEN + qmod.CHUNK // 2] ^= 0x01
    blob.write_bytes(bytes(data))
    _assert_refused(q, store, qid, p)


@pytest.mark.parametrize("cut", ["mid_chunk", "chunk_boundary", "header_only"])
def test_truncated_blob_is_refused(q, store, tmp_path, cut):
    p, qid, blob = _quarantined(q, store, tmp_path)
    data = blob.read_bytes()
    record = qmod.NONCE + qmod.CHUNK + qmod.TAG
    keep = {"mid_chunk": len(data) - 100, "chunk_boundary": qmod.HEADER_LEN + 2 * record,
            "header_only": qmod.HEADER_LEN}[cut]
    blob.write_bytes(data[:keep])
    _assert_refused(q, store, qid, p)


def test_swapped_chunks_are_refused(q, store, tmp_path):
    p, qid, blob = _quarantined(q, store, tmp_path)
    data = blob.read_bytes()
    record = qmod.NONCE + qmod.CHUNK + qmod.TAG
    h, c0, c1 = data[:qmod.HEADER_LEN], data[qmod.HEADER_LEN:qmod.HEADER_LEN + record], \
        data[qmod.HEADER_LEN + record:qmod.HEADER_LEN + 2 * record]
    blob.write_bytes(h + c1 + c0 + data[qmod.HEADER_LEN + 2 * record:])
    _assert_refused(q, store, qid, p)


# ---- refusals that change nothing -------------------------------------------------------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CloseHandle.argtypes = [wintypes.HANDLE]


def test_locked_file_is_refused_and_left_intact(q, store, tmp_path):
    p = make_sample(tmp_path)
    before = sha(p)
    handle = _k32.CreateFileW(str(p), 0x80000000, 0, None, 3, 0, None)  # GENERIC_READ, share nothing
    assert handle not in (None, ctypes.c_void_p(-1).value)
    try:
        with pytest.raises(QuarantineError) as err:
            q.put(str(p), "r", [])
        assert str(err.value) == "sample.exe is in use by another program. Close it and try again. Nothing was changed."
    finally:
        _k32.CloseHandle(handle)
    assert sha(p) == before
    assert not list(q.dir.glob("*.tgq*"))
    assert q.items() == []


def test_open_for_writing_elsewhere_is_refused(q, tmp_path):
    p = make_sample(tmp_path)
    with open(p, "ab"):  # another program writing to it
        with pytest.raises(QuarantineError, match="in use by another program"):
            q.put(str(p), "r", [])
    assert p.read_bytes() == samples.sample_bytes()


def test_full_disk_is_refused(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    usage = shutil.disk_usage(tmp_path)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: usage._replace(free=10 * 1024 * 1024))
    with pytest.raises(QuarantineError) as err:
        q.put(str(p), "r", [])
    assert str(err.value) == "Not enough free disk space to quarantine this file safely. Nothing was changed."
    assert p.read_bytes() == samples.sample_bytes()
    assert not list(q.dir.glob("*.tgq*")) and store.list_quarantine(("pending", "failed", "quarantined")) == []


def test_full_disk_on_restore_is_refused(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    qid = q.put(str(p), "r", [])
    usage = shutil.disk_usage(tmp_path)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: usage._replace(free=0))
    with pytest.raises(QuarantineError, match="Not enough free disk space"):
        q.restore(qid)
    assert store.get_quarantine(qid)["state"] == "quarantined" and not p.exists()


def test_missing_file(q, tmp_path):
    with pytest.raises(QuarantineError, match="was not found"):
        q.put(str(tmp_path / "nope.exe"), "r", [])


def test_read_only_original(q, tmp_path):
    p = make_sample(tmp_path)
    os.chmod(p, stat.S_IREAD)
    qid = q.put(str(p), "r", [])
    assert not p.exists()
    q.restore(qid)
    assert p.read_bytes() == samples.sample_bytes()


def test_path_longer_than_260_characters(q, tmp_path):
    folder = winpath.to_long(tmp_path)
    for _ in range(6):
        folder = os.path.join(folder, "a" * 50)
    os.makedirs(folder)
    long_file = os.path.join(folder, "sample.exe")
    with open(long_file, "wb") as f:
        f.write(samples.sample_bytes())
    display = winpath.to_display(long_file)
    assert len(display) > 260
    qid = q.put(display, "r", [])
    assert not os.path.exists(long_file)
    assert q.restore(qid) == display
    with open(long_file, "rb") as f:
        assert f.read() == samples.sample_bytes()


# ---- crashes and recovery ---------------------------------------------------------------------

def _crash(*_a, **_k):
    raise SimulatedCrash


def test_crash_after_blob_written_before_original_deleted(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    monkeypatch.setattr(qmod._Original, "delete", _crash)
    with pytest.raises(SimulatedCrash):
        q.put(str(p), "r", [])
    row = store.list_quarantine(("pending",))[0]
    assert (q.dir / row["blob"]).exists() and p.exists()
    monkeypatch.undo()
    notes = q.recover()
    assert notes == ["sample.exe: quarantine was interrupted; the file was left where it was."]
    assert store.get_quarantine(row["id"])["state"] == "failed"
    assert not list(q.dir.glob("*.tgq*"))
    assert p.read_bytes() == samples.sample_bytes()
    assert q.recover() == []


def test_crash_while_writing_blob(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path, extra=os.urandom(qmod.CHUNK))
    real = Quarantine._encrypt

    def half_then_crash(self, src, part):
        part.write_bytes(b"TGQ1 partial")
        raise SimulatedCrash
    monkeypatch.setattr(Quarantine, "_encrypt", half_then_crash)
    with pytest.raises(SimulatedCrash):
        q.put(str(p), "r", [])
    monkeypatch.setattr(Quarantine, "_encrypt", real)
    assert len(q.recover()) == 1
    assert not list(q.dir.glob("*.tgq*")) and p.exists()


def test_crash_after_original_deleted_before_state_saved(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    real_delete = qmod._Original.delete

    def delete_then_crash(self):
        real_delete(self)
        raise SimulatedCrash
    monkeypatch.setattr(qmod._Original, "delete", delete_then_crash)
    with pytest.raises(SimulatedCrash):
        q.put(str(p), "r", [])
    monkeypatch.undo()
    assert not p.exists()
    row = store.list_quarantine(("pending",))[0]
    notes = q.recover()
    assert len(notes) == 1 and "safely in quarantine" in notes[0]
    assert store.get_quarantine(row["id"])["state"] == "quarantined"
    q.restore(row["id"])
    assert p.read_bytes() == samples.sample_bytes()


def test_crash_during_restore_then_recover_and_restore_again(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path / "f", extra=os.urandom(qmod.CHUNK))
    before = sha(p)
    qid = q.put(str(p), "r", [])

    def partial_then_crash(self, blob, part):
        with open(part, "wb") as f:
            f.write(b"partly restored")
        raise SimulatedCrash
    monkeypatch.setattr(Quarantine, "_decrypt_to", partial_then_crash)
    with pytest.raises(SimulatedCrash):
        q.restore(qid)
    monkeypatch.undo()
    assert store.get_quarantine(qid)["state"] == "restoring"
    assert any(x.suffix == ".part" for x in p.parent.iterdir())
    assert q.recover() == ["sample.exe: restore was interrupted; the file is still in quarantine."]
    assert store.get_quarantine(qid)["state"] == "quarantined"
    assert list(p.parent.iterdir()) == []
    q.restore(qid)
    assert sha(p) == before


def test_crash_after_restore_rename_before_blob_removed(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    qid = q.put(str(p), "r", [])
    blob = blob_path(q, store, qid)
    monkeypatch.setattr(Quarantine, "_drop_blob", _crash)
    with pytest.raises(SimulatedCrash):
        q.restore(qid)
    monkeypatch.undo()
    assert p.exists() and blob.exists()
    notes = q.recover()
    assert len(notes) == 1 and "the file is back" in notes[0]
    assert store.get_quarantine(qid)["state"] == "restored" and not blob.exists()


def test_crash_during_delete_is_finished(q, store, tmp_path, monkeypatch):
    p = make_sample(tmp_path)
    qid = q.put(str(p), "r", [])
    blob = blob_path(q, store, qid)
    monkeypatch.setattr(Quarantine, "_drop_blob", _crash)
    with pytest.raises(SimulatedCrash):
        q.delete(qid)
    monkeypatch.undo()
    assert store.get_quarantine(qid)["state"] == "deleting"
    assert len(q.recover()) == 1
    assert store.get_quarantine(qid)["state"] == "deleted" and not blob.exists()


def test_key_survives_a_new_quarantine_object(settings, store, tmp_path):
    p = make_sample(tmp_path)
    qid = Quarantine(settings, store).put(str(p), "r", [])
    Quarantine(settings, store).restore(qid)
    assert p.read_bytes() == samples.sample_bytes()


def test_unreadable_key_refuses_before_touching_file(settings, store, tmp_path):
    (Path(settings.quarantine_dir) / "key.dpapi").write_bytes(b"not a dpapi blob")
    p = make_sample(tmp_path)
    with pytest.raises(QuarantineError, match="key"):
        Quarantine(settings, store).put(str(p), "r", [])
    assert p.read_bytes() == samples.sample_bytes()


# ---- review 2026-11-23: lost key, double clicks ----------------------------------------------

def test_missing_key_is_never_replaced_while_files_are_quarantined(settings, store, tmp_path):
    p = make_sample(tmp_path)
    qid = Quarantine(settings, store).put(str(p), "r", [])
    key = Path(settings.quarantine_dir) / "key.dpapi"
    key.unlink()
    with pytest.raises(QuarantineError) as err:
        Quarantine(settings, store).restore(qid)
    assert str(err.value) == qmod.MSG_KEY_LOST
    assert not key.exists() and store.get_quarantine(qid)["state"] == "quarantined"
    other = make_sample(tmp_path / "b")
    with pytest.raises(QuarantineError, match="key is missing"):
        Quarantine(settings, store).put(str(other), "r", [])
    assert not key.exists() and other.read_bytes() == samples.sample_bytes()
    # a stray encrypted copy with no record is enough to refuse too
    store.set_quarantine_state(qid, "failed")
    with pytest.raises(QuarantineError, match="key is missing"):
        Quarantine(settings, store).put(str(other), "r", [])
    # an empty quarantine may make a new key
    for blob in Path(settings.quarantine_dir).glob("*.tgq"):
        blob.unlink()
    Quarantine(settings, store).put(str(other), "r", [])
    assert key.exists()


def test_key_from_another_account_gives_the_plain_message(settings, store, tmp_path):
    p = make_sample(tmp_path)
    qid = Quarantine(settings, store).put(str(p), "r", [])
    (Path(settings.quarantine_dir) / "key.dpapi").write_bytes(b"not a dpapi blob")
    with pytest.raises(QuarantineError) as err:
        Quarantine(settings, store).restore(qid)
    assert str(err.value) == qmod.MSG_KEY_LOST


@pytest.mark.parametrize("first,second", [("restore", "restore"), ("restore", "delete"),
                                          ("delete", "restore"), ("delete", "delete")])
def test_second_click_while_busy_gets_a_plain_answer(q, store, tmp_path, monkeypatch, first, second):
    p = make_sample(tmp_path, extra=b"x" * 1000)
    qid = q.put(str(p), "r", [])
    answers = []
    real_decrypt, real_drop = Quarantine._decrypt_to, Quarantine._drop_blob

    def click_again():          # the other click arrives while the first is half way
        try:
            getattr(Quarantine(q.settings, store), second)(qid)
            answers.append("ok")
        except QuarantineError as e:
            answers.append(str(e))

    def decrypt(self, blob, part):
        click_again()
        return real_decrypt(self, blob, part)

    def drop(self, blob):
        if not answers:
            click_again()
        return real_drop(self, blob)
    monkeypatch.setattr(Quarantine, "_decrypt_to", decrypt)
    monkeypatch.setattr(Quarantine, "_drop_blob", drop)
    getattr(q, first)(qid)
    assert answers == [qmod.MSG_BUSY]
    assert store.get_quarantine(qid)["state"] == ("restored" if first == "restore" else "deleted")
    files = sorted(x.name for x in tmp_path.iterdir() if x.is_file())
    assert files == (["sample.exe"] if first == "restore" else [])


def test_plain_error_never_shows_windows_codes():
    text = qmod._plain(OSError(5, "[WinError 1234] Some odd failure"), "a.exe", "restore")
    assert "WinError" not in text and "Some odd failure" not in text and "unexpected problem" in text
