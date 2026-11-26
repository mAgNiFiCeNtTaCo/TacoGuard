"""The taskbar icon (tacoguard/tray.py): colour, tooltip, menu and commands from TacoGuard's state,
and the icon's life cycle against a FAKE Windows shell (no real icon is ever added by these tests).
The only real Windows calls here draw an icon in memory and make/destroy a hidden window."""
from __future__ import annotations

import threading
import time

import pytest

from tacoguard import phase4, tray
from tacoguard.model import Confidence, FileResult, Finding
from tacoguard.web import server
from test_web import _missing_module


# ---------------------------------------------------------------------------------------------
# pure decisions
# ---------------------------------------------------------------------------------------------
def view(**kw):
    v = {"paused_until": 0.0, "game_mode": False, "game_reason": "", "game_manual": False,
         "guard_state": "on", "attention": 0, "realtime": True, "can_update": True}
    v.update(kw)
    return v


@pytest.mark.parametrize("kw,colour", [
    ({}, tray.GREEN),
    ({"attention": 2}, tray.ORANGE),
    ({"guard_state": "warn"}, tray.ORANGE),
    ({"paused_until": time.time() + 600}, tray.GREY),
    ({"realtime": False, "guard_state": "off"}, tray.GREY),
    ({"guard_state": "error"}, tray.GREY),
    ({"guard_state": "starting"}, tray.GREY),
    ({"paused_until": time.time() + 600, "attention": 1}, tray.ORANGE),     # something needs you wins
    ({"game_mode": True}, tray.GREEN),
])
def test_colour(kw, colour):
    assert tray.colour_for(view(**kw)) == colour


def test_tooltip_words_and_length():
    assert tray.tooltip_for(view()) == "TacoGuard: protection is on"
    until = time.mktime((2026, 11, 26, 15, 30, 0, 0, 0, -1))
    assert tray.tooltip_for(view(paused_until=until)) == "TacoGuard: protection paused until 15:30"
    assert tray.tooltip_for(view(attention=1, game_mode=True)) == \
        "TacoGuard: protection is on; 1 alert needs you; Game mode on"
    assert tray.tooltip_for(view(attention=3)) == "TacoGuard: protection is on; 3 alerts need you"
    assert tray.tooltip_for(view(realtime=False, guard_state="off")) == "TacoGuard: real-time protection is off"
    assert tray.tooltip_for(view(guard_state="mystery")).startswith("TacoGuard: checking")
    long = tray.tooltip_for(view(attention=10**120, game_mode=True))
    assert len(long) <= tray.TIP_MAX and long.endswith("...")


def test_menu_items():
    items = tray.menu_for(view())
    labels = [label for _, label, flags in items if not flags & tray.MF_SEPARATOR]
    assert labels == ["Open TacoGuard", "Pause protection for 1 hour", "Turn on Game mode (up to 4 hours)",
                      "Check for updates", "Quit TacoGuard"]
    items = tray.menu_for(view(paused_until=time.time() + 60, game_mode=True, can_update=False))
    d = {cmd: (label, flags) for cmd, label, flags in items if cmd}
    assert d[tray.CMD_PAUSE] == ("Resume protection", tray.MF_STRING)
    assert d[tray.CMD_GAME][0] == "Turn off Game mode"
    assert d[tray.CMD_UPDATES][1] & tray.MF_GRAYED
    # real-time protection off in Settings: nothing to pause
    d = {cmd: flags for cmd, _, flags in tray.menu_for(view(realtime=False)) if cmd}
    assert d[tray.CMD_PAUSE] & tray.MF_GRAYED


class FakeApp:
    def __init__(self):
        self.calls = []
        self.update_ok = True

    def open_page(self):
        self.calls.append("open")

    def pause_protection(self, s):
        self.calls.append(("pause", s))

    def resume_protection(self):
        self.calls.append("resume")

    def switch_game_mode(self, on):
        self.calls.append(("game", on))

    def start_update_check(self):
        self.calls.append("update")
        return self.update_ok

    def quit(self):
        self.calls.append("quit")


def test_commands():
    app = FakeApp()
    assert tray.run_command(app, tray.CMD_PAUSE, view()) and app.calls[-1] == ("pause", 3600)
    tray.run_command(app, tray.CMD_PAUSE, view(paused_until=time.time() + 5))
    assert app.calls[-1] == "resume"
    tray.run_command(app, tray.CMD_GAME, view())
    assert app.calls[-1] == ("game", True)
    tray.run_command(app, tray.CMD_GAME, view(game_mode=True))
    assert app.calls[-1] == ("game", False)
    assert tray.run_command(app, tray.CMD_UPDATES, view()) == "checking for updates"
    n = len(app.calls)
    assert tray.run_command(app, tray.CMD_UPDATES, view(can_update=False)) == "" and len(app.calls) == n
    tray.run_command(app, tray.CMD_OPEN, view())
    assert app.calls[-1] == "open"
    tray.run_command(app, tray.CMD_QUIT, view())
    assert app.calls[-1] == "quit"
    assert tray.run_command(app, 999, view()) == ""


# ---------------------------------------------------------------------------------------------
# the icons
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("colour", [tray.GREEN, tray.ORANGE, tray.GREY])
def test_shield_pixels(colour):
    px = tray.shield_pixels(colour)
    assert len(px) == 32 * 32 * 4

    def at(x, y):
        i = (y * 32 + x) * 4
        return tuple(px[i:i + 4])
    assert at(0, 0)[3] == 0 and at(31, 31)[3] == 0 and at(0, 31)[3] == 0   # transparent corners
    assert at(16, 6)[3] == 255 and at(7, 10)[3] == 255                      # solid inside
    b, g, r, _ = at(16, 27)                                                 # fill near the point
    fill = tray.COLOURS[colour]
    assert (r, g, b) in (fill[0], fill[1]) or at(16, 27)[3] < 255


def test_icons_differ():
    assert len({tray.shield_pixels(c) for c in (tray.GREEN, tray.ORANGE, tray.GREY)}) == 3


def test_real_icon_and_hidden_window_are_made_and_freed():
    """Real Windows calls, but no notification-area icon: an icon handle in memory, and a hidden
    window that is destroyed again."""
    shell = tray.Win32Shell()
    for c in (tray.GREEN, tray.ORANGE, tray.GREY):
        h = shell.make_icon(c)
        assert h
        shell.destroy_icon(h)
    seen = []
    hwnd = shell.create_window(lambda msg, wp, lp: seen.append(msg) or None)
    try:
        assert hwnd and shell.taskbar_created_message() >= 0xC000
    finally:
        shell.destroy_window(hwnd)
        shell.unregister()
    assert tray.WM_DESTROY in seen


# ---------------------------------------------------------------------------------------------
# the life cycle, with a fake shell
# ---------------------------------------------------------------------------------------------
class FakeShell:
    def __init__(self, loop_error=None):
        self.calls = []
        self.menu_answer = 0
        self.menus = []
        self.icons_alive = set()
        self.loop_error = loop_error
        self.added = False
        self._quit = threading.Event()
        self.handler = None
        self.modify_ok = True

    def create_window(self, handler):
        self.handler = handler
        self.calls.append("create")
        return 4242

    def taskbar_created_message(self):
        return 0xC123

    def set_timer(self, hwnd, ms):
        self.calls.append(("timer", ms))

    def run_loop(self):
        if self.loop_error:
            raise self.loop_error
        self._quit.wait(10)

    def close_window(self, hwnd):     # what the real WM_CLOSE leads to
        self.handler(tray.WM_CLOSE, 0, 0)

    def destroy_window(self, hwnd):
        self.calls.append("destroy")
        self.handler(tray.WM_DESTROY, 0, 0)

    def quit_loop(self):
        self._quit.set()

    def unregister(self):
        self.calls.append("unregister")

    def add_icon(self, hwnd, hicon, tip):
        self.calls.append(("add", hicon, tip))
        self.added = True
        return True, True

    def modify_icon(self, hwnd, hicon, tip):
        self.calls.append(("modify", hicon, tip))
        return self.modify_ok

    def delete_icon(self, hwnd):
        self.calls.append("delete")
        self.added = False
        return True

    def make_icon(self, colour):
        self.icons_alive.add(colour)
        return colour

    def destroy_icon(self, h):
        self.icons_alive.discard(h)

    def cursor_pos(self):
        return (5, 6)

    def show_menu(self, hwnd, items, x, y):
        self.menus.append((items, x, y))
        return self.menu_answer


@pytest.fixture
def app(settings, monkeypatch):
    for name in ("_load_updater_module", "_load_selfupdate", "_load_signed"):
        monkeypatch.setattr(server, name, _missing_module)
    a = server.App(settings)
    opened = []
    a.open_page = lambda: opened.append(time.time())
    a.opened = opened
    quits = []
    a.quit = lambda: quits.append(1)
    a.quits = quits
    yield a
    a.close()


def _wait(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def test_tray_view_from_the_real_app(app):
    v = tray.tray_view(app)
    assert v["guard_state"] == "off" and v["attention"] == 0 and v["can_update"] is False
    assert tray.colour_for(v) == tray.GREY
    app.store.add_guard_event("file", "suspicious", "Suspicious: Desktop\\x.exe")
    job = app.store.create_job(["C:\\Users\\me"])
    app.store.add_result(job, FileResult(path="C:\\Users\\me\\y.exe", sha256="ab" * 32,
                                         findings=[Finding("yara", "R", Confidence.MEDIUM, "test")]))
    phase4.pause_protection(app.store, 600)
    phase4.set_game_mode(app.store, True, manual=True, reason="you switched it on")
    v = tray.tray_view(app)
    assert v["attention"] == 2 and v["paused_until"] > time.time() and v["game_mode"] and v["game_manual"]
    assert tray.colour_for(v) == tray.ORANGE
    assert "2 alerts need you" in tray.tooltip_for(v) and "Game mode on" in tray.tooltip_for(v)


def test_tray_view_never_raises(app):
    app.protection_brief = lambda: 1 / 0
    v = tray.tray_view(app)
    assert v["guard_state"] == "unknown"


def test_life_cycle_adds_and_always_removes_the_icon(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    assert t.start() is True and t.running
    adds = [c for c in shell.calls if c[0] == "add"]
    assert len(adds) == 1 and adds[0][1] == tray.GREY and adds[0][2].startswith("TacoGuard: ")
    assert ("timer", 60000) in shell.calls
    t.stop()
    assert not t.running and not t.added and "delete" in shell.calls and not shell.added
    assert "unregister" in shell.calls and shell.icons_alive == set()


def test_icon_removed_even_when_the_loop_breaks(app):
    shell = FakeShell(loop_error=RuntimeError("boom"))
    t = tray.Tray(app, shell=shell)
    t.start()
    assert _wait(lambda: not t.running)
    assert "delete" in shell.calls and not shell.added and shell.icons_alive == set()
    assert t.error


def test_refresh_talks_to_windows_only_on_change(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    t.start()
    try:
        n = len(shell.calls)
        t.on_message(tray.WM_TIMER, 1, 0)
        assert len(shell.calls) == n                              # nothing changed
        app.store.add_guard_event("file", "malware", "Quarantine suggested: x.exe")
        t.on_message(tray.WM_TIMER, 1, 0)
        mod = shell.calls[-1]
        assert mod[0] == "modify" and mod[1] == tray.ORANGE and "1 alert needs you" in mod[2]
        shell.modify_ok = False                                   # Explorer lost the icon
        app.store.add_guard_event("file", "malware", "Quarantine suggested: y.exe")
        t.on_message(tray.WM_TIMER, 1, 0)
        assert not t.added
        t.on_message(tray.WM_TIMER, 1, 0)
        assert shell.calls[-1][0] == "add" and t.added            # added again
    finally:
        t.stop()


def test_explorer_restart_adds_the_icon_again(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    t.start()
    try:
        before = sum(1 for c in shell.calls if c[0] == "add")
        assert t.on_message(0xC123, 0, 0) == 0
        assert sum(1 for c in shell.calls if c[0] == "add") == before + 1
    finally:
        t.stop()


def test_right_click_menu_and_left_click_open(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    t.start()
    try:
        shell.menu_answer = tray.CMD_PAUSE
        app.settings.realtime_enabled = True
        wparam = (300 << 16) | (1200 & 0xFFFF)                     # x = 1200, y = 300 (version 4)
        t.on_message(tray.CALLBACK_MSG, wparam, tray.WM_CONTEXTMENU | (tray.ICON_ID << 16))
        items, x, y = shell.menus[-1]
        assert (x, y) == (1200, 300)
        assert [lab for c, lab, f in items if c == tray.CMD_PAUSE] == ["Pause protection for 1 hour"]
        assert phase4.protection_paused(app.store) > time.time() + 3500
        # right button up alone does nothing with version 4 (WM_CONTEXTMENU comes too)
        n = len(shell.menus)
        t.on_message(tray.CALLBACK_MSG, 0, tray.WM_RBUTTONUP)
        assert len(shell.menus) == n
        shell.menu_answer = tray.CMD_PAUSE                         # now it says Resume
        t.on_message(tray.CALLBACK_MSG, wparam, tray.WM_CONTEXTMENU)
        assert [lab for c, lab, f in shell.menus[-1][0] if c == tray.CMD_PAUSE] == ["Resume protection"]
        assert phase4.protection_paused(app.store) == 0
        shell.menu_answer = tray.CMD_GAME
        t.on_message(tray.CALLBACK_MSG, wparam, tray.WM_CONTEXTMENU)
        g = phase4.game_mode(app.store)
        assert g["active"] and g["manual"]
        shell.menu_answer = 0                                      # menu closed without a choice
        t.on_message(tray.CALLBACK_MSG, wparam, tray.WM_CONTEXTMENU)
        assert phase4.game_mode(app.store)["active"]
        shell.menu_answer = tray.CMD_QUIT
        t.on_message(tray.CALLBACK_MSG, wparam, tray.WM_CONTEXTMENU)
        assert app.quits == [1]
        # left click opens the page once, even as a double-click
        t.on_message(tray.CALLBACK_MSG, 0, tray.NIN_SELECT)
        t.on_message(tray.CALLBACK_MSG, 0, tray.WM_LBUTTONDBLCLK)
        assert _wait(lambda: len(app.opened) == 1)
        time.sleep(0.1)
        assert len(app.opened) == 1
    finally:
        t.stop()


def test_old_shell_without_version_4_uses_button_up(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    t.start()
    try:
        t.version4 = False
        t.on_message(tray.CALLBACK_MSG, 0, tray.WM_RBUTTONUP)
        assert shell.menus and shell.menus[-1][1:] == (5, 6)      # at the mouse pointer
        t.on_message(tray.CALLBACK_MSG, 0, tray.WM_LBUTTONUP)
        assert _wait(lambda: len(app.opened) == 1)
    finally:
        t.stop()


def test_menu_action_errors_are_logged_not_raised(app):
    shell = FakeShell()
    t = tray.Tray(app, shell=shell, refresh_s=60)
    t.start()
    try:
        def boom(on):
            raise RuntimeError("x")
        app.switch_game_mode = boom
        assert t.command(tray.CMD_GAME) == ""
    finally:
        t.stop()
    assert "tray menu action failed" in (app.settings.log_dir / "web.log").read_text(encoding="utf-8")


def test_app_starts_and_stops_the_tray_with_the_setting(app, monkeypatch):
    made = []

    class FakeTray:
        def __init__(self, a):
            self.running = False
            made.append(self)

        def start(self):
            self.running = True
            return True

        def stop(self):
            self.running = False

        def refresh(self):
            pass

    monkeypatch.setattr(server, "_load_tray", lambda: type("M", (), {"Tray": FakeTray}))
    app.settings.tray_enabled = True
    app.apply_tray()
    assert not made                                              # not managed: tests never add an icon
    app.start_tray()
    assert len(made) == 1 and made[0].running and app.tray is made[0]
    app.settings.tray_enabled = False
    app.apply_tray()
    assert app.tray is None and not made[0].running
    app.settings.tray_enabled = True
    app.apply_tray()
    assert len(made) == 2 and made[1].running
    app.stop_tray()
    assert not made[1].running
