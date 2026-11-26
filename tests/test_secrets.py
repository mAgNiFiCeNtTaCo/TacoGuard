"""tacoguard/secrets.py: the abuse.ch key, DPAPI-protected in the temp settings folder only."""
from __future__ import annotations

import logging

import pytest

from tacoguard import dpapi, secrets

KEY = "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv12Wx34"   # made up, key-shaped


@pytest.fixture(autouse=True)
def _fresh_cache():
    secrets._cache.clear()
    yield
    secrets._cache.clear()


def test_round_trip_in_the_temp_secrets_folder(settings):
    assert secrets.get_key(settings) is None and not secrets.has_key(settings)
    assert secrets.key_hint(settings) == ""
    secrets.set_key(settings, "abusech", KEY)
    path = settings.secrets_dir / "abusech.dpapi"
    assert path.is_file() and secrets.has_key(settings)
    assert KEY.encode() not in path.read_bytes()             # encrypted on disk
    assert secrets.get_key(settings) == KEY
    secrets._cache.clear()
    assert secrets.get_key(settings, "abusech") == KEY      # read back from the file
    assert not list(settings.secrets_dir.glob("*.tmp"))
    assert secrets.clear_key(settings) is True
    assert secrets.get_key(settings) is None and not path.exists()
    assert secrets.clear_key(settings) is False


def test_spaces_and_line_breaks_are_taken_out(settings):
    secrets.set_key(settings, "abusech", f"  {KEY[:20]} \r\n{KEY[20:]}\n")
    assert secrets.get_key(settings) == KEY


@pytest.mark.parametrize("bad", ["", "short", "x" * 19, "y" * 129, KEY + "!", "key with ;semicolon" * 2,
                                 KEY[:30] + "é", None, 12345678901234567890])
def test_bad_keys_are_refused_and_nothing_is_written(settings, bad):
    with pytest.raises(ValueError) as e:
        secrets.set_key(settings, "abusech", bad)
    assert str(e.value) == secrets.BAD_KEY_MSG
    if isinstance(bad, str) and bad:
        assert bad not in str(e.value)
    assert not secrets.has_key(settings)


def test_a_new_key_replaces_the_old_one(settings):
    secrets.set_key(settings, "abusech", KEY)
    assert secrets.get_key(settings) == KEY
    other = "Z" * 40
    secrets.set_key(settings, "abusech", other)
    assert secrets.get_key(settings) == other
    assert secrets.key_hint(settings) == "ending in ...ZZZZ"


def test_key_hint_shows_only_the_last_four(settings):
    secrets.set_key(settings, "abusech", KEY)
    hint = secrets.key_hint(settings)
    assert hint == "ending in ...Wx34"
    assert KEY[:-4] not in hint


def test_name_is_checked(settings):
    for name in ("../x", "ABC", "", "a/b", "x" * 33):
        with pytest.raises(ValueError):
            secrets.set_key(settings, name, KEY)
        assert secrets.get_key(settings, name) is None
    assert not list(settings.root.rglob("*.dpapi"))


def test_damaged_or_swapped_file_reads_as_no_key(settings, caplog):
    secrets.set_key(settings, "abusech", KEY)
    path = settings.secrets_dir / "abusech.dpapi"
    path.write_bytes(b"not a DPAPI blob")
    with caplog.at_level(logging.DEBUG):
        assert secrets.get_key(settings) is None
    assert "could not be read" in caplog.text
    # a file protected for another name is not taken
    secrets.set_key(settings, "other", KEY)
    path.write_bytes((settings.secrets_dir / "other.dpapi").read_bytes())
    secrets._cache.clear()
    assert secrets.get_key(settings, "abusech") is None


def test_the_key_never_appears_in_logs_or_errors(settings, caplog, monkeypatch, capsys):
    with caplog.at_level(logging.DEBUG):
        secrets.set_key(settings, "abusech", KEY)
        secrets.get_key(settings)
        secrets.key_hint(settings)
        def broken(_data):
            raise dpapi.DpapiError(5, "Windows could not protect the data.")
        monkeypatch.setattr(dpapi, "protect", broken)
        with pytest.raises(ValueError) as e:
            secrets.set_key(settings, "abusech", "Q" * 30 + KEY[-6:])
        assert KEY[-6:] not in str(e.value) and e.value.__cause__ is None and e.value.__suppress_context__
        secrets.clear_key(settings)
    out = capsys.readouterr()
    for text in (caplog.text, out.out, out.err):
        assert KEY not in text and KEY[-6:] not in text
    assert "Saved a new abusech key" in caplog.text


def test_failed_save_keeps_the_old_key(settings, monkeypatch):
    secrets.set_key(settings, "abusech", KEY)
    monkeypatch.setattr(dpapi, "protect", lambda d: (_ for _ in ()).throw(OSError(5, "no")))
    with pytest.raises(ValueError):
        secrets.set_key(settings, "abusech", "N" * 30)
    secrets._cache.clear()
    assert secrets.get_key(settings) == KEY


def test_key_stamp_changes_when_saved_again(settings):
    assert secrets.key_stamp(settings) == ""
    secrets.set_key(settings, "abusech", KEY)
    a = secrets.key_stamp(settings)
    assert a and KEY not in a
    secrets.set_key(settings, "abusech", "M" * 60)
    assert secrets.key_stamp(settings) != a
