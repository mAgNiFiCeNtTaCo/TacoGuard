"""Signed metadata (tacoguard/updates/signed.py). Test keys are generated per test; nothing here
touches the real signing folder or the network."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tacoguard.updates import signed as S
from tacoguard.updates import sources, updater

FUTURE = "2031-11-23T00:00:00Z"
PAST = "2026-01-01T00:00:00Z"


# ---- helpers shared with test_updater.py and test_release_tools.py ---------------------------

def new_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def root_signed(version, root_keys, targets_keys, root_threshold=1, targets_threshold=1,
                expires=FUTURE) -> dict:
    keys = {S.keyid_for(k): S.key_entry(k) for k in [*root_keys, *targets_keys]}
    return {"_type": "root", "version": version, "expires": expires, "keys": keys,
            "roles": {"root": {"keyids": [S.keyid_for(k) for k in root_keys],
                               "threshold": root_threshold},
                      "targets": {"keyids": [S.keyid_for(k) for k in targets_keys],
                                  "threshold": targets_threshold}}}


def doc(signed_part: dict, signers) -> bytes:
    return S.dump_metadata(S.sign_metadata(signed_part, signers))


def entry_for(data: bytes, kind: str, version: str, min_app: str = "0.1.0", notes: str = "") -> dict:
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "custom": {"kind": kind, "version": version, "min_app": min_app, "notes": notes}}


def targets_signed(version: int, files: dict[str, dict], expires=FUTURE) -> dict:
    return {"_type": "targets", "version": version, "expires": expires, "targets": files}


def ml_zip(version: str, marker: str = "model") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json", json.dumps({"version": version, "thresholds": {}}))
        z.writestr("model.bin", f"{marker} {version} ".encode() * 50)
    return buf.getvalue()


class Release:
    """A release folder with a root (v1) and targets signed by test keys."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.root_key = new_key()
        self.targets_key = new_key()
        self.root = root_signed(1, [self.root_key], [self.targets_key])
        self.root_bytes = doc(self.root, [self.root_key])
        self.version = 0
        self.files: dict[str, dict] = {}

    def add(self, name: str, data: bytes, kind: str, version: str, **custom) -> dict:
        (self.folder / name).write_bytes(data)
        self.files[name] = entry_for(data, kind, version, **custom)
        return self.files[name]

    def publish(self, version: int | None = None, expires=FUTURE, signers=None) -> bytes:
        self.version = version or self.version + 1
        raw = doc(targets_signed(self.version, dict(self.files), expires), signers or [self.targets_key])
        (self.folder / "targets.json").write_bytes(raw)
        return raw

    def install_root(self, monkeypatch, tmp_path: Path) -> Path:
        path = tmp_path / "shipped-root.json"
        path.write_bytes(self.root_bytes)
        monkeypatch.setattr(S, "SHIPPED_ROOT", path)
        return path


# ---- targets -----------------------------------------------------------------------------------

def test_valid_chain_and_file(tmp_path):
    rel = Release(tmp_path / "rel")
    data = ml_zip("2026.11.23")
    entry = rel.add("ml-model-2026.11.23.zip", data, "ml_model", "2026.11.23")
    raw = rel.publish()
    root = S.parse_root(rel.root_bytes)
    t = S.verify_targets(root, raw, 0)
    assert t["version"] == 1 and "ml-model-2026.11.23.zip" in t["targets"]
    S.verify_file(rel.folder / "ml-model-2026.11.23.zip", entry)


def test_bad_signature_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    raw = rel.publish()
    d = json.loads(raw)
    d["signed"]["version"] = 99                     # changed after signing
    with pytest.raises(S.UpdateRejected, match="does not match its contents"):
        S.verify_targets(rel.root, json.dumps(d).encode(), 0)


def test_wrong_key_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    raw = rel.publish(signers=[new_key()])
    with pytest.raises(S.UpdateRejected) as e:
        S.verify_targets(rel.root, raw, 0)
    assert str(e.value) == ("The update list is signed by a key TacoGuard does not trust, so it was "
                            "rejected. Nothing was changed.")


def test_threshold_two_needs_two_distinct_keys():
    k1, k2, rk = new_key(), new_key(), new_key()
    root = root_signed(1, [rk], [k1, k2], targets_threshold=2)
    t = targets_signed(1, {})
    with pytest.raises(S.UpdateRejected, match="needs 2 signatures .* has only 1"):
        S.verify_targets(root, doc(t, [k1]), 0)
    # the same key twice still counts once
    one = S.sign_metadata(t, [k1])
    one["signatures"] = one["signatures"] * 2
    with pytest.raises(S.UpdateRejected, match="has only 1"):
        S.verify_targets(root, json.dumps(one).encode(), 0)
    assert S.verify_targets(root, doc(t, [k1, k2]), 0)["version"] == 1


def test_key_under_a_made_up_keyid_is_refused():
    rk, tk = new_key(), new_key()
    root = root_signed(1, [rk], [tk])
    fake_id = "ab" * 32
    root["keys"][fake_id] = S.key_entry(tk)          # same key listed twice under two ids
    root["roles"]["targets"]["keyids"].append(fake_id)
    with pytest.raises(S.UpdateRejected, match="not in the expected format"):
        S.parse_root(doc(root, [rk]))


def test_expired_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    raw = rel.publish(expires="2026-12-01T00:00:00Z")
    after = datetime(2026, 12, 2, tzinfo=timezone.utc)
    with pytest.raises(S.UpdateRejected) as e:
        S.verify_targets(rel.root, raw, 0, now=after)
    assert "has expired (it was valid until 2026-12-01)" in str(e.value)
    assert S.verify_targets(rel.root, raw, 0, now=after - timedelta(days=2))


def test_rejections_say_what_kind(tmp_path):
    """The updater shows an expired list calmly and everything else as a refused update."""
    rel = Release(tmp_path / "rel")
    data = b"file"
    entry = rel.add("a.zip", data, "app", "9.0.0")
    raw = rel.publish(version=3, expires="2026-12-01T00:00:00Z")
    after = datetime(2026, 12, 2, tzinfo=timezone.utc)
    before = after - timedelta(days=2)

    def kind(fn):
        with pytest.raises(S.UpdateRejected) as e:
            fn()
        return e.value.kind
    assert kind(lambda: S.verify_targets(rel.root, raw, 0, now=after)) == "expired"
    assert kind(lambda: S.check_root_fresh(dict(rel.root, expires=PAST))) == "expired"
    assert kind(lambda: S.verify_targets(rel.root, raw, 5, now=before)) == "rollback"
    assert kind(lambda: S.verify_targets(rel.root, rel.publish(signers=[new_key()]), 0, now=before)) == "signature"
    tampered = json.loads(raw)
    tampered["signed"]["version"] = 99
    assert kind(lambda: S.verify_targets(rel.root, json.dumps(tampered).encode(), 0, now=before)) == "signature"
    assert kind(lambda: S.verify_targets(rel.root, b"{not json", 0)) == "format"
    (rel.folder / "a.zip").write_bytes(b"fil!")
    assert kind(lambda: S.verify_file(rel.folder / "a.zip", entry)) == "checksum"
    assert S.NoTrustedRoot("x").kind == "not_set_up" and isinstance(S.NoTrustedRoot("x"), S.UpdateRejected)


def test_rollback_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    raw = rel.publish(version=3)
    with pytest.raises(S.UpdateRejected) as e:
        S.verify_targets(rel.root, raw, 5)
    assert "is older than the one already installed (version 3 < 5): this can be an attack that " \
           "tries to bring back old software" in str(e.value)


def test_same_version_different_bytes_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    first = rel.publish(version=4)
    sha = hashlib.sha256(first).hexdigest()
    assert S.verify_targets(rel.root, first, 4, sha)["version"] == 4      # same bytes: fine
    rel.add("x.zip", b"other", "app", "9.0.0")
    second = rel.publish(version=4)
    with pytest.raises(S.UpdateRejected, match="same version number"):
        S.verify_targets(rel.root, second, 4, sha)


def test_unsafe_target_name_is_rejected(tmp_path):
    rel = Release(tmp_path / "rel")
    t = targets_signed(1, {"../evil.zip": entry_for(b"x", "app", "1.0")})
    with pytest.raises(S.UpdateRejected, match="not in the expected format"):
        S.verify_targets(rel.root, doc(t, [rel.targets_key]), 0)


def test_wrong_kind_of_file(tmp_path):
    rel = Release(tmp_path / "rel")
    with pytest.raises(S.UpdateRejected, match="wrong kind of file"):
        S.verify_targets(rel.root, rel.root_bytes, 0)
    with pytest.raises(S.UpdateRejected, match="could not be read"):
        S.verify_targets(rel.root, b"\xff not json", 0)


# ---- files -------------------------------------------------------------------------------------

def test_file_length_and_checksum_mismatch(tmp_path):
    p = tmp_path / "f.zip"
    p.write_bytes(b"hello world")
    good = entry_for(b"hello world", "app", "1")
    S.verify_file(p, good)
    with pytest.raises(S.UpdateRejected, match="wrong size"):
        S.verify_file(p, {**good, "length": 5})
    with pytest.raises(S.UpdateRejected, match="does not match the checksum"):
        S.verify_file(p, {**good, "sha256": "0" * 64})


# ---- root rotation -----------------------------------------------------------------------------

def test_root_rotation_good():
    old, new, tk = new_key(), new_key(), new_key()
    v1 = root_signed(1, [old], [tk])
    v2 = root_signed(2, [new], [tk])
    got = S.verify_root_update(v1, doc(v2, [old, new]))
    assert got["version"] == 2 and got["roles"]["root"]["keyids"] == [S.keyid_for(new)]


def test_root_rotation_skipped_version():
    old, tk = new_key(), new_key()
    v1 = root_signed(1, [old], [tk])
    v3 = root_signed(3, [old], [tk])
    with pytest.raises(S.UpdateRejected, match="skips a version"):
        S.verify_root_update(v1, doc(v3, [old]))


def test_root_rotation_signed_only_by_new_key():
    old, new, tk = new_key(), new_key(), new_key()
    v1 = root_signed(1, [old], [tk])
    v2 = root_signed(2, [new], [tk])
    with pytest.raises(S.UpdateRejected, match="does not trust"):
        S.verify_root_update(v1, doc(v2, [new]))
    with pytest.raises(S.UpdateRejected, match="does not trust"):
        S.verify_root_update(v1, doc(v2, [old]))       # and the new threshold must be met too


def test_root_rotation_older_version():
    k, tk = new_key(), new_key()
    v2 = root_signed(2, [k], [tk])
    with pytest.raises(S.UpdateRejected, match=r"older than the one already installed \(version 1 < 2\)"):
        S.verify_root_update(v2, doc(root_signed(1, [k], [tk]), [k]))


def test_chain_of_two_rotations_followed_one_step_at_a_time(tmp_path):
    k1, k2, k3, tk = new_key(), new_key(), new_key(), new_key()
    folder = tmp_path / "rel"
    folder.mkdir()
    v1 = root_signed(1, [k1], [tk])
    (folder / "root-2.json").write_bytes(doc(root_signed(2, [k2], [tk]), [k1, k2]))
    v3 = doc(root_signed(3, [k3], [tk]), [k2, k3])
    (folder / "root-3.json").write_bytes(v3)
    (folder / "root.json").write_bytes(v3)
    (folder / "targets.json").write_bytes(doc(targets_signed(1, {}), [tk]))
    root, targets, _raw, changed = updater.fetch_verified_targets(sources.LocalFolderSource(folder), v1)
    assert root["version"] == 3 and changed and targets["version"] == 1


def test_only_newest_root_present_and_it_skips_is_refused(tmp_path):
    k1, k2, tk = new_key(), new_key(), new_key()
    folder = tmp_path / "rel"
    folder.mkdir()
    (folder / "root.json").write_bytes(doc(root_signed(3, [k2], [tk]), [k1, k2]))
    (folder / "targets.json").write_bytes(doc(targets_signed(1, {}), [tk]))
    with pytest.raises(S.UpdateRejected, match="skips a version"):
        updater.fetch_verified_targets(sources.LocalFolderSource(folder), root_signed(1, [k1], [tk]))


def test_new_release_key_resets_the_remembered_version(tmp_path):
    rk, t_old, t_new = new_key(), new_key(), new_key()
    folder = tmp_path / "rel"
    folder.mkdir()
    v1 = root_signed(1, [rk], [t_old])
    (folder / "root-2.json").write_bytes(doc(root_signed(2, [rk], [t_new]), [rk]))
    (folder / "targets.json").write_bytes(doc(targets_signed(1, {}), [t_new]))
    root, targets, _raw, _ = updater.fetch_verified_targets(sources.LocalFolderSource(folder), v1,
                                                            last_version=50)
    assert root["version"] == 2 and targets["version"] == 1


# ---- trusted root and state --------------------------------------------------------------------

def test_no_built_in_root_means_channel_not_set_up(settings, monkeypatch, tmp_path):
    monkeypatch.setattr(S, "SHIPPED_ROOT", tmp_path / "missing-root.json")
    with pytest.raises(S.NoTrustedRoot, match="isn't set up yet"):
        S.load_trusted_root(settings)


def test_stored_newer_root_wins(settings, monkeypatch, tmp_path):
    k, tk = new_key(), new_key()
    shipped = tmp_path / "root.json"
    shipped.write_bytes(doc(root_signed(1, [k], [tk]), [k]))
    monkeypatch.setattr(S, "SHIPPED_ROOT", shipped)
    assert S.load_trusted_root(settings)["version"] == 1
    v2 = root_signed(2, [k], [tk])
    S.remember(settings, v2, targets_signed(7, {}), b"raw", root_files=[doc(v2, [k])])
    assert S.load_trusted_root(settings)["version"] == 2
    state = S.load_state(settings)
    assert state["targets_version"] == 7 and state["targets_sha256"] == hashlib.sha256(b"raw").hexdigest()
    assert not list(Path(settings.updates_dir).glob("*.tmp"))


def test_a_stored_root_is_checked_again_every_time(settings, monkeypatch, tmp_path):
    """TGUARD-20261127-07: a newer key list written into trusted.json (or a stored root file
    without the old keys' signatures) is never trusted on its own."""
    k, tk = new_key(), new_key()
    evil, evil_t = new_key(), new_key()
    shipped = tmp_path / "root.json"
    shipped.write_bytes(doc(root_signed(1, [k], [tk]), [k]))
    monkeypatch.setattr(S, "SHIPPED_ROOT", shipped)
    forged = root_signed(2, [evil], [evil_t])
    S.save_state(settings, {"root": forged, "targets_version": 0})          # trusted.json edited
    assert S.load_trusted_root(settings)["version"] == 1
    S.write_bytes_atomic(S.stored_root_path(settings, 2), doc(forged, [evil]))   # signed by itself only
    assert S.load_trusted_root(settings)["version"] == 1
    S.write_bytes_atomic(S.stored_root_path(settings, 2), b"{ not json")
    assert S.load_trusted_root(settings)["version"] == 1
    # the real next root, signed by the old key and its own: trusted, and a gap stops the walk
    v2 = root_signed(2, [k], [tk])
    S.write_bytes_atomic(S.stored_root_path(settings, 2), doc(v2, [k]))
    S.write_bytes_atomic(S.stored_root_path(settings, 4), doc(root_signed(4, [k], [tk]), [k]))
    assert S.load_trusted_root(settings)["version"] == 2


def test_the_updater_stores_the_root_files_it_walked(tmp_path, settings):
    k1, k2, tk = new_key(), new_key(), new_key()
    v1 = root_signed(1, [k1], [tk])
    v2 = root_signed(2, [k2], [tk])
    folder = tmp_path / "rel"
    folder.mkdir()
    (folder / "root-2.json").write_bytes(doc(v2, [k1, k2]))
    (folder / "targets.json").write_bytes(doc(targets_signed(1, {}), [tk]))
    walked = []
    root, targets, _raw, changed = updater.fetch_verified_targets(sources.LocalFolderSource(folder), v1,
                                                                  root_files=walked)
    assert changed and root["version"] == 2 and walked == [doc(v2, [k1, k2])]


def test_built_in_root_must_be_self_signed(settings, monkeypatch, tmp_path):
    k, tk = new_key(), new_key()
    shipped = tmp_path / "root.json"
    shipped.write_bytes(doc(root_signed(1, [k], [tk]), [new_key()]))
    monkeypatch.setattr(S, "SHIPPED_ROOT", shipped)
    with pytest.raises(S.UpdateRejected, match="does not trust"):
        S.load_trusted_root(settings)
