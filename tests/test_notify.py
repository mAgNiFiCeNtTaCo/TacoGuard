"""Windows notifications (guard/notify.py). No real toast is ever shown here: the PowerShell runner,
the registration, the clock and the timer are all fakes. Registration is tested on a test key
under HKCU\\Software\\TacoGuardTest only."""
from __future__ import annotations

import base64
import re
import uuid
import winreg

import pytest

from tacoguard.guard import notify


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeTimer:
    made: list["FakeTimer"] = []

    def __init__(self, delay, fn):
        self.delay, self.fn, self.started, self.daemon = delay, fn, False, False
        FakeTimer.made.append(self)

    def start(self):
        self.started = True


@pytest.fixture
def fakes():
    FakeTimer.made = []
    shown = []
    clock = FakeClock()

    def runner(script):
        shown.append(script)
        return "shown"
    n = notify.Notifier(runner=runner, register=lambda: True, clock=clock, timer_factory=FakeTimer)
    return n, shown, clock


def _xml_of(script: str) -> str:
    data = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script).group(1)
    return base64.b64decode(data).decode("utf-8")


def test_xml_is_escaped_and_only_local_urls_launch():
    xml = notify.toast_xml('Paused: <x> & "y" \'z\'', "line\x00two\x07", "http://127.0.0.1:8799/#protection")
    assert "<x>" not in xml and "&lt;x&gt; &amp; &quot;y&quot; &apos;z&apos;" in xml
    assert "\x00" not in xml and "\x07" not in xml
    assert 'activationType="protocol" launch="http://127.0.0.1:8799/#protection"' in xml
    for bad in ("https://evil.example/", "file:///C:/x.exe", "ms-settings:", 'http://127.0.0.1:1/"><x a="'):
        assert "launch=" not in notify.toast_xml("t", "m", bad)
    assert "launch=" not in notify.toast_xml("t", "m", None)
    long = notify.toast_xml("t" * 500, "m" * 5000)
    assert "t" * notify.TITLE_MAX not in long and "..." in long


def test_script_carries_the_text_only_as_base64():
    title = "x'; Remove-Item C:\\ -Recurse; '"
    script = notify.toast_script(notify.toast_xml(title, "msg"))
    assert "Remove-Item" not in script                 # the text is data, never script code
    assert "CreateToastNotifier('TacoGuard')" in script
    assert "Remove-Item" in _xml_of(script)
    assert "Setting" in script and "'shown'" in script   # reports when Windows has toasts off


def test_rate_limit_merges_the_rest(fakes):
    n, shown, clock = fakes
    assert n.notify("Suspicious: Desktop\\a.exe", "ML score 0.71", notify.page_url(8799)) is True
    assert len(shown) == 1 and "a.exe" in _xml_of(shown[0])
    clock.t += 3
    assert n.notify("Suspicious: Desktop\\b.exe", "m") is True        # queued, not shown yet
    clock.t += 1
    assert n.notify("Paused: Downloads\\c.exe", "m") is True
    assert len(shown) == 1 and len(FakeTimer.made) == 1               # one timer for the window
    assert FakeTimer.made[0].started and FakeTimer.made[0].delay == pytest.approx(7)
    clock.t += 6
    assert n.flush() is True
    assert len(shown) == 2
    xml = _xml_of(shown[1])
    assert "Suspicious: Desktop\\b.exe and 1 more" in xml and "Protection tab" in xml
    # the merged toast starts a new quiet window
    clock.t += 2
    n.notify("x", "y")
    assert len(shown) == 2 and len(FakeTimer.made) == 2
    clock.t += 10
    n.flush()
    assert len(shown) == 3 and ">x<" in _xml_of(shown[2])            # a single one is shown as it is
    assert n.flush() is False                                         # nothing left


def test_after_the_window_a_toast_shows_at_once(fakes):
    n, shown, clock = fakes
    n.notify("a", "b")
    clock.t += 10.5
    n.notify("c", "d")
    assert len(shown) == 2 and not FakeTimer.made


def test_never_raises_and_says_false_when_not_shown():
    def boom(script):
        raise RuntimeError("PowerShell exploded")
    assert notify.Notifier(runner=boom, register=lambda: True).notify("t", "m") is False
    calls = []
    n = notify.Notifier(runner=lambda s: calls.append(s) or "shown", register=lambda: False)
    assert n.notify("t", "m") is False and calls == [] and n.last == "not registered"
    n = notify.Notifier(runner=lambda s: "off:DisabledForUser", register=lambda: True)
    assert n.notify("t", "m") is False
    assert "turned off" in n.off_message and "Protection tab" in n.off_message
    n = notify.Notifier(runner=lambda s: "failed", register=lambda: True)
    assert n.notify("t", "m") is False and n.off_message == ""


def test_notify_event_levels_and_link(fakes):
    n, shown, clock = fakes
    assert notify.notify_event({"level": "info", "title": "Guard started"}, 8799, notifier=n) is False
    assert notify.notify_event("not a dict", 8799, notifier=n) is False
    assert shown == []
    ev = {"level": "malware", "title": "Quarantine suggested: Downloads\\free-vbucks.exe",
          "message": "Matched YARA rule 'Generic_Stealer_Strings' (open rule set, high confidence)."}
    assert notify.notify_event(ev, 8799, notifier=n) is True
    xml = _xml_of(shown[0])
    assert "free-vbucks.exe" in xml and 'launch="http://127.0.0.1:8799/#protection"' in xml
    for level in ("warning", "suspicious"):
        clock.t += 11
        assert notify.notify_event(dict(ev, level=level), 8799, notifier=n) is True


@pytest.fixture
def test_key():
    base = rf"Software\TacoGuardTest\{uuid.uuid4().hex}"
    yield base + r"\AppUserModelId\TacoGuard"
    _delete_tree(base)


def _delete_tree(path: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            subs = []
            i = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
        for s in subs:
            _delete_tree(path + "\\" + s)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def _values(path: str) -> dict:
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
        i = 0
        while True:
            try:
                name, value, kind = winreg.EnumValue(k, i)
            except OSError:
                break
            out[name] = (value, kind)
            i += 1
    return out


def test_register_app_id_on_a_test_key(test_key, tmp_path):
    icon = tmp_path / "icon.png"
    icon.write_bytes(b"\x89PNG fake")
    assert notify.register_app_id(test_key, icon=icon) is True
    v = _values(test_key)
    assert v == {"DisplayName": ("TacoGuard", winreg.REG_SZ), "IconUri": (str(icon), winreg.REG_SZ)}
    assert notify.register_app_id(test_key, icon=icon) is True          # again: nothing changes
    assert _values(test_key) == v
    assert notify.register_app_id(test_key, icon=tmp_path / "missing.png") is True
    assert _values(test_key)["DisplayName"][0] == "TacoGuard"


def test_shipped_icon_exists():
    assert notify.ICON.is_file() and notify.ICON.read_bytes()[:4] == b"\x89PNG"
    assert notify.AUMID_KEY == r"Software\Classes\AppUserModelId\TacoGuard"
