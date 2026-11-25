"""tools/keys.py and tools/release.py, in temp folders only (never config.signing_dir(), never the
real tacoguard/data/root.json, never GitHub)."""
from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import keys as K  # noqa: E402
import release as R  # noqa: E402
from tacoguard import __version__, config  # noqa: E402
from tacoguard.updates import signed as S  # noqa: E402
from tacoguard.updates import sources, updater as U  # noqa: E402
from test_signed import ml_zip  # noqa: E402

PASS = b"correct horse battery staple"


@pytest.fixture
def keydir(tmp_path):
    d = tmp_path / "signing"
    assert d != config.signing_dir()
    out = tmp_path / "root.json"
    info = K.init_keys(d, out)
    return d, out, info


def _quiet(_msg):
    pass


# ---- keys ------------------------------------------------------------------------------------

def test_init_makes_protected_keys_and_a_signed_root(keydir, capsys, tmp_path):
    d, out, info = keydir
    assert (d / "root.key").is_file() and (d / "targets.key").is_file()
    root = S.parse_root(out.read_bytes())
    assert root["version"] == 1
    assert root["roles"]["root"]["keyids"] == [info["root_keyid"]]
    assert root["roles"]["targets"]["keyids"] == [info["targets_keyid"]]
    assert (d / "roots" / "root-1.json").read_bytes() == out.read_bytes()
    # the key files are DPAPI blobs, not raw keys
    raw = K._raw_private(K.load_private(d, "root"))
    assert raw not in (d / "root.key").read_bytes()
    # init refuses to overwrite
    with pytest.raises(K.KeyError_, match="already exists"):
        K.init_keys(d, tmp_path / "again.json")


def test_cli_never_prints_key_material(tmp_path, capsys):
    d = tmp_path / "signing"
    assert K.main(["init", "--dir", str(d), "--out", str(tmp_path / "root.json")]) == 0
    assert K.main(["show", "--dir", str(d)]) == 0
    text = capsys.readouterr().out
    for role in ("root", "targets"):
        key = K.load_private(d, role)
        assert K._raw_private(key).hex() not in text
        assert S.public_raw(key).hex() not in text           # not even the full public key
    assert K.main(["init", "--dir", str(d), "--out", str(tmp_path / "root.json")]) == 1


@pytest.fixture
def fast_scrypt(monkeypatch):
    """Cheaper scrypt so the backup tests stay quick; test_backup_uses_strong_scrypt checks the
    real settings."""
    monkeypatch.setattr(K, "SCRYPT_N", 2 ** 14)
    monkeypatch.setattr(K, "SCRYPT_P", 1)


def test_backup_and_restore(keydir, tmp_path, fast_scrypt):
    d, _out, info = keydir
    backup = tmp_path / "usb" / "TacoGuard-signing-backup"
    files = K.backup_keys(d, backup, PASS)
    assert {p.name for p in files} >= {"root.key.backup", "targets.key.backup", "root-1.json", "README.txt"}
    doc = json.loads((backup / "root.key.backup").read_bytes())
    assert doc["format"] == K.BACKUP_FORMAT and doc["version"] == 1 and doc["kdf"] == "scrypt"
    assert doc["role"] == "root" and len(bytes.fromhex(doc["salt"])) == 16 and len(bytes.fromhex(doc["nonce"])) == 12
    raw = K._raw_private(K.load_private(d, "root"))
    assert raw.hex() not in json.dumps(doc) and len(bytes.fromhex(doc["ciphertext"])) == 32 + 16
    with pytest.raises(K.KeyError_, match="already exists"):
        K.backup_keys(d, backup, PASS)

    fresh = tmp_path / "new-pc"
    with pytest.raises(K.KeyError_, match="passphrase is wrong"):
        K.restore_keys(backup, fresh, b"not the passphrase at all")
    r = K.restore_keys(backup, fresh, PASS)
    assert r["root_keyid"] == info["root_keyid"] and r["targets_keyid"] == info["targets_keyid"]
    assert r["old_format"] is False
    assert (fresh / "roots" / "root-1.json").exists()
    with pytest.raises(K.KeyError_, match="already exists"):
        K.restore_keys(backup, fresh, PASS)


@pytest.mark.parametrize("short", [b"short", "elevenchars", "é" * 11])
def test_backup_refuses_a_short_passphrase(keydir, tmp_path, short):
    d, _out, _info = keydir
    with pytest.raises(K.KeyError_, match="at least 12 characters") as e:
        K.backup_keys(d, tmp_path / "other", short)
    assert "Nothing was written" in str(e.value)
    assert not (tmp_path / "other").exists()
    # 12 characters counts characters, not bytes (12 accented letters are 24 bytes)
    assert K.check_passphrase("é" * 12) == ("é" * 12).encode("utf-8")


def test_backup_uses_strong_scrypt(keydir):
    """scrypt n=2**18, r=8, p=2 (about a second and 256 MB per key), never the old PBKDF2-2048."""
    d, _out, _info = keydir
    key = K.load_private(d, "targets")
    data = K.seal_key("targets", key, PASS)
    doc = json.loads(data)
    assert (doc["n"], doc["r"], doc["p"]) == (2 ** 18, 8, 2)
    back = K.open_key(data, "targets", PASS, "targets.key.backup")
    assert K._raw_private(back) == K._raw_private(key)


def test_backup_file_tampering_is_refused(keydir, fast_scrypt):
    d, _out, _info = keydir
    data = json.loads(K.seal_key("root", K.load_private(d, "root"), PASS))
    as_targets = json.dumps(dict(data, role="targets")).encode()         # renamed to the other role
    with pytest.raises(K.KeyError_, match="damaged"):
        K.open_key(as_targets, "targets", PASS, "targets.key.backup")
    weaker = json.dumps(dict(data, n=2 ** 15)).encode()                  # settings changed
    with pytest.raises(K.KeyError_, match="passphrase is wrong, or the backup is damaged"):
        K.open_key(weaker, "root", PASS, "root.key.backup")
    huge = json.dumps(dict(data, n=2 ** 30)).encode()                    # would eat all memory
    with pytest.raises(K.KeyError_, match="damaged"):
        K.open_key(huge, "root", PASS, "root.key.backup")
    newer = json.dumps(dict(data, version=2)).encode()
    with pytest.raises(K.KeyError_, match="newer TacoGuard"):
        K.open_key(newer, "root", PASS, "root.key.backup")


def test_restore_still_reads_an_old_pem_backup(keydir, tmp_path):
    from cryptography.hazmat.primitives import serialization
    d, _out, info = keydir
    old = tmp_path / "old-backup"
    old.mkdir()
    for role in ("root", "targets"):
        pem = K.load_private(d, role).private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.BestAvailableEncryption(PASS))
        (old / f"{role}.key.pem").write_bytes(pem)
    r = K.restore_keys(old, tmp_path / "pc2", PASS)
    assert r["old_format"] is True and r["root_keyid"] == info["root_keyid"]


def test_backup_without_a_console_opens_its_own_window(keydir, tmp_path, monkeypatch, capsys):
    d, _out, _info = keydir
    launched = []

    class FakeProc:
        def wait(self):
            return 0
    monkeypatch.setattr(K.sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(K.subprocess, "Popen", lambda cmd, **kw: launched.append((cmd, kw)) or FakeProc())
    assert K.main(["backup", "--to", str(tmp_path / "b"), "--dir", str(d)]) == 0
    cmd, kw = launched[0]
    assert kw["creationflags"] == K.CREATE_NEW_CONSOLE and "--in-console" in cmd
    assert "Type the passphrase there" in capsys.readouterr().out


def test_rotate_targets(keydir, tmp_path):
    d, out, info = keydir
    v1 = S.parse_root(out.read_bytes())
    r = K.rotate_targets(d, out)
    assert r["version"] == 2 and r["targets_keyid"] != info["targets_keyid"]
    assert Path(r["retired"]).exists()
    v2 = S.verify_root_update(v1, out.read_bytes())
    assert v2["roles"]["targets"]["keyids"] == [r["targets_keyid"]]
    assert S.keyid_for(K.load_private(d, "targets")) == r["targets_keyid"]
    assert (d / "roots" / "root-2.json").exists()
    assert not (d / "targets.key.new").exists() and r["notes"] == []


def test_failed_rotation_removes_the_new_key_and_a_later_one_works(keydir, monkeypatch):
    d, out, info = keydir
    before = (d / "targets.key").read_bytes()

    def refuse(trusted, raw):
        raise S.UpdateRejected("The new list of trusted release keys is not in the expected format, "
                               "so it was rejected.")
    monkeypatch.setattr(K.signed, "verify_root_update", refuse)
    with pytest.raises(K.KeyError_, match="has been removed; the old one is still in place"):
        K.rotate_targets(d, out)
    assert not (d / "targets.key.new").exists()
    assert (d / "targets.key").read_bytes() == before
    assert not (d / "roots" / "root-2.json").exists()
    assert not (d / "retired").exists() or not any((d / "retired").iterdir())
    monkeypatch.undo()
    r = K.rotate_targets(d, out)
    assert r["version"] == 2 and r["targets_keyid"] != info["targets_keyid"]


def test_rotation_clears_a_leftover_new_key_from_an_older_version(keydir):
    d, out, _info = keydir
    K._save_private(d / "targets.key.new", K.Ed25519PrivateKey.generate())   # what the old bug left
    r = K.rotate_targets(d, out)
    assert r["version"] == 2 and not (d / "targets.key.new").exists()
    assert r["notes"] == ["An unused new release key left by an earlier failed rotation was removed."]


# ---- release build / verify ------------------------------------------------------------------

def _ml_package(tmp_path, version="2026.11.23") -> Path:
    p = tmp_path / f"ml-package-{version}.zip"
    p.write_bytes(ml_zip(version))
    return p


def test_build_verify_and_app_package(keydir, tmp_path):
    d, root_json, _ = keydir
    out = tmp_path / "releases" / "001"
    r = R.build(out, ml=_ml_package(tmp_path), app=True, keys_dir=d, notes="First signed release.",
                shipped_root=root_json, say=_quiet, self_test=lambda folder: None)
    app_name = f"tacoguard-{__version__}.zip"
    assert r["version"] == 1
    assert set(r["files"]) == {"targets.json", "ml-model-2026.11.23.zip", app_name}
    targets = json.loads((out / "targets.json").read_text())["signed"]
    assert targets["targets"]["ml-model-2026.11.23.zip"]["custom"]["kind"] == "ml_model"
    assert targets["targets"][app_name]["custom"]["notes"] == "First signed release."

    with zipfile.ZipFile(out / app_name) as z:
        names = z.namelist()
    assert "tacoguard/__init__.py" in names and "tacoguard/updates/signed.py" in names
    assert {"requirements.lock", "LICENSE", "THIRD_PARTY_LICENSES.md"} <= set(names)
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc") or n.startswith("tests/")]

    # verify (the app's own checks) passes, and a changed byte fails it
    assert R.verify(out, root_json, say=_quiet, self_test=lambda f: None)["targets_version"] == 1
    data = bytearray((out / "ml-model-2026.11.23.zip").read_bytes())
    data[-1] ^= 1
    (out / "ml-model-2026.11.23.zip").write_bytes(bytes(data))
    with pytest.raises(S.UpdateRejected, match="does not match the checksum"):
        R.verify(out, root_json, say=_quiet, self_test=lambda f: None)


def test_app_zip_is_reproducible(tmp_path):
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    R.build_app_zip(a)
    R.build_app_zip(b)
    assert a.read_bytes() == b.read_bytes()


def test_build_refuses_a_non_empty_folder_and_nothing_to_release(keydir, tmp_path):
    d, _root, _ = keydir
    out = tmp_path / "r"
    out.mkdir()
    (out / "x").write_text("x")
    with pytest.raises(R.ReleaseError, match="not empty"):
        R.build(out, app=True, keys_dir=d, say=_quiet)
    with pytest.raises(R.ReleaseError, match="Nothing to release"):
        R.build(tmp_path / "r2", keys_dir=d, say=_quiet)


def test_extra_files_in_a_release_fail_verify(keydir, tmp_path):
    d, root_json, _ = keydir
    out = tmp_path / "releases" / "001"
    R.build(out, ml=_ml_package(tmp_path), keys_dir=d, shipped_root=root_json, say=_quiet,
            self_test=lambda f: None)
    (out / "notes.txt").write_text("not listed")
    with pytest.raises(R.ReleaseError, match="does not name: notes.txt"):
        R.verify(out, root_json, say=_quiet, self_test=lambda f: None)


def test_release_then_updater_installs_the_ml_model(keydir, tmp_path, settings, store, monkeypatch):
    d, root_json, _ = keydir
    monkeypatch.setattr(S, "SHIPPED_ROOT", root_json)
    monkeypatch.setattr(U.setup_fetch, "_open", lambda url, headers=None: (_ for _ in ()).throw(
        U.setup_fetch.FetchError("offline", kind="offline")))
    out = tmp_path / "releases" / "001"
    R.build(out, ml=_ml_package(tmp_path), app=True, keys_dir=d, shipped_root=root_json,
            say=_quiet, self_test=lambda f: None)
    tested = []
    up = U.Updater(settings, store, source=sources.LocalFolderSource(out))
    up.ml_self_test = lambda folder: tested.append(sorted(p.name for p in Path(folder).iterdir()))
    up.check_now(wait=True)
    assert tested == [["meta.json", "model.bin"]]
    meta = json.loads((Path(settings.ml_dir) / "current" / "meta.json").read_text())
    assert meta["version"] == "2026.11.23"
    assert up.status()["components"]["ml_model"]["version"] == "2026.11.23"
    assert up.status()["app_update"] is None          # same version as the running app

    # second release after a key rotation: version 2, the root chain is carried, the app is
    # carried over, and the updater (trusting root v1) follows the chain
    K.rotate_targets(d, tmp_path / "root-after-rotation.json")
    out2 = tmp_path / "releases" / "002"
    r2 = R.build(out2, ml=_ml_package(tmp_path, "2026.12.01"), keys_dir=d, shipped_root=root_json,
                 say=_quiet, self_test=lambda f: None)
    assert r2["version"] == 2 and r2["root_version"] == 2
    assert {"root.json", "root-2.json", f"tacoguard-{__version__}.zip"} <= set(r2["files"])
    up2 = U.Updater(settings, store, source=sources.LocalFolderSource(out2))
    up2.ml_self_test = lambda folder: None
    up2.check_now(wait=True)
    meta = json.loads((Path(settings.ml_dir) / "current" / "meta.json").read_text())
    assert meta["version"] == "2026.12.01"
    assert S.load_trusted_root(settings)["version"] == 2


def test_publish_without_yes_does_not_run_gh(keydir, tmp_path, monkeypatch):
    d, root_json, _ = keydir
    out = tmp_path / "releases" / "001"
    R.build(out, ml=_ml_package(tmp_path), keys_dir=d, shipped_root=root_json, say=_quiet,
            self_test=lambda f: None)
    monkeypatch.setattr(S, "SHIPPED_ROOT", root_json)
    monkeypatch.setattr(R, "_ml_test", lambda *a: None)
    monkeypatch.setattr(R.subprocess, "run", lambda *a, **k: pytest.fail("gh must not run"))
    lines = []
    assert R.publish(out, yes=False, say=lines.append) == 0
    assert any("Add --yes to publish" in x for x in lines)
    assert any(config.RELEASE_REPO in x for x in lines)


def test_secret_looking_files_stop_the_app_build(tmp_path):
    proj = tmp_path / "proj"
    (proj / "tacoguard").mkdir(parents=True)
    (proj / "tacoguard" / "__init__.py").write_text("")
    (proj / "tacoguard" / "release.key").write_bytes(b"x")
    (proj / "pyproject.toml").write_text('[project]\ndependencies = ["x"]\n')
    (proj / "LICENSE").write_text("L")
    (proj / "THIRD_PARTY_LICENSES.md").write_text("T")
    with pytest.raises(R.ReleaseError, match="looks like a key"):
        R.build_app_zip(tmp_path / "a.zip", proj)


def test_unsafe_ml_package_is_refused(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../escape.txt", "x")
    p = tmp_path / "ml-model-1.0.zip"
    p.write_bytes(buf.getvalue())
    with pytest.raises(R.ReleaseError, match="unsafe path"):
        R.check_zip_safe(p)
