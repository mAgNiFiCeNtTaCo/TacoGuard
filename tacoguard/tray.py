"""The TacoGuard icon in the taskbar's notification area (Phase 4, contract: tacoguard/phase4.py).

    Tray(app).start() / .stop()       one icon, its own thread with a Windows message loop
    tray_view(app) -> dict             what the icon shows (cheap: a few store reads)
    colour_for(view) / tooltip_for(view) / menu_for(view)   the pure decisions (tests)

The page process owns it (web/server.py App.start_tray, only when serve() runs and
settings.tray_enabled; never under pytest). It uses only Windows' own shell calls through ctypes:
a hidden ordinary window (tray icons can't belong to a message-only window) and
Shell_NotifyIconW with NOTIFYICON_VERSION_4. The icons are drawn in code: a shield in green (all
well), orange (something needs you) or grey (protection paused or off).

Left click: opens the page. Right click: Open TacoGuard, Pause protection for 1 hour / Resume
protection, Turn on / off Game mode, Check for updates, Quit TacoGuard (the same clean stop as the
page's own Stop button). When Explorer restarts ("TaskbarCreated") the icon is added again. The
icon is always removed on the way out (window close, thread end, and atexit), so no ghost icon
stays behind.

Cost: the icon looks at TacoGuard's state every REFRESH_S seconds (a few SQLite reads, well
under 1 ms) and only talks to Windows when the colour or the tooltip changed.
"""
from __future__ import annotations

import atexit
import ctypes
import math
import os
import threading
import time
import traceback
from ctypes import wintypes

from . import phase4

REFRESH_S = 5.0
TIP_MAX = 127                       # NOTIFYICONDATAW.szTip holds 128 WCHARs with the final 0
PAUSE_SECONDS = 3600
OPEN_DEBOUNCE_S = 1.5

GREEN, ORANGE, GREY = "green", "orange", "grey"

CMD_OPEN, CMD_PAUSE, CMD_GAME, CMD_UPDATES, CMD_QUIT = 1, 2, 3, 4, 5

# Windows constants
WM_NULL, WM_DESTROY, WM_CLOSE, WM_QUERYENDSESSION, WM_ENDSESSION = 0x0000, 0x0002, 0x0010, 0x0011, 0x0016
WM_CONTEXTMENU, WM_TIMER, WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONUP = 0x007B, 0x0113, 0x0202, 0x0203, 0x0205
WM_APP = 0x8000
CALLBACK_MSG = WM_APP + 1
NIN_SELECT, NIN_KEYSELECT = 0x0400, 0x0401
NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETVERSION = 0, 1, 2, 4
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_SHOWTIP = 0x01, 0x02, 0x04, 0x80
NOTIFYICON_VERSION_4 = 4
MF_STRING, MF_GRAYED, MF_CHECKED, MF_SEPARATOR = 0x0000, 0x0001, 0x0008, 0x0800
TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD = 0x0002, 0x0080, 0x0100
ICON_ID = 1
TIMER_ID = 1


# ---------------------------------------------------------------------------------------------
# what the icon shows (pure; tests)
# ---------------------------------------------------------------------------------------------
def tray_view(app) -> dict:
    """The facts the icon needs, read from the page process's App. Never raises."""
    view = {"paused_until": 0.0, "game_mode": False, "game_reason": "", "game_manual": False,
            "guard_state": "unknown", "attention": 0, "realtime": True, "can_update": False}
    try:
        store, s = app.store, app.settings
        view["realtime"] = bool(getattr(s, "realtime_enabled", True))
        view["paused_until"] = phase4.protection_paused(store)
        gm = phase4.game_mode(store)
        view.update(game_mode=gm["active"], game_reason=gm["reason"], game_manual=gm["manual"])
        brief = app.protection_brief()
        view["guard_state"] = str(brief.get("state") or "unknown")
        open_results = sum(1 for d in store.latest_detections(500) if not d.get("action"))
        view["attention"] = int(brief.get("attention") or 0) + open_results
        view["can_update"] = app.get_updater() is not None
    except Exception:
        try:
            app.log.error("tray view failed\n%s", traceback.format_exc())
        except Exception:
            pass
    return view


def colour_for(view: dict) -> str:
    """Orange when something needs you (it wins: you should see it even while paused), grey when
    protection is paused, off or not running, green otherwise."""
    if view.get("attention") or view.get("guard_state") == "warn":
        return ORANGE
    if view.get("paused_until") or not view.get("realtime", True) or \
            view.get("guard_state") not in ("on", "warn"):
        return GREY
    return GREEN


def _clock(t: float) -> str:
    try:
        return time.strftime("%H:%M", time.localtime(float(t)))
    except (ValueError, OverflowError, OSError):
        return "later"


GUARD_WORDS = {
    "on": "protection is on",
    "warn": "one part of protection has a problem",
    "error": "real-time protection stopped",
    "starting": "real-time protection is starting",
    "off": "real-time protection is off",
    "unavailable": "real-time protection isn't available",
}


def tooltip_for(view: dict) -> str:
    """One line, at most 127 characters: "TacoGuard: protection is on" plus what needs you."""
    if view.get("paused_until"):
        head = f"protection paused until {_clock(view['paused_until'])}"
    elif not view.get("realtime", True):
        head = GUARD_WORDS["off"]
    else:
        head = GUARD_WORDS.get(view.get("guard_state"), "checking protection...")
    bits = [head]
    n = int(view.get("attention") or 0)
    if n:
        bits.append(f"{n} alert{'s' if n != 1 else ''} {'need' if n != 1 else 'needs'} you")
    if view.get("game_mode"):
        bits.append("Game mode on")
    tip = "TacoGuard: " + "; ".join(bits)
    return tip if len(tip) <= TIP_MAX else tip[:TIP_MAX - 3] + "..."


def menu_for(view: dict) -> list[tuple[int, str, int]]:
    """(command id, label, flags) top to bottom; id 0 = a separator line."""
    paused = bool(view.get("paused_until"))
    game = bool(view.get("game_mode"))
    return [
        (CMD_OPEN, "Open TacoGuard", MF_STRING),
        (0, "", MF_SEPARATOR),
        (CMD_PAUSE, "Resume protection" if paused else "Pause protection for 1 hour",
         MF_STRING if view.get("realtime", True) or paused else MF_GRAYED),
        (CMD_GAME, "Turn off Game mode" if game else "Turn on Game mode (up to 4 hours)", MF_STRING),
        (CMD_UPDATES, "Check for updates", MF_STRING if view.get("can_update") else MF_GRAYED),
        (0, "", MF_SEPARATOR),
        (CMD_QUIT, "Quit TacoGuard", MF_STRING),
    ]


def run_command(app, cmd: int, view: dict) -> str:
    """Do what a menu item says. Returns a short note for the log ("" for nothing)."""
    if cmd == CMD_OPEN:
        app.open_page()
        return "opened the page"
    if cmd == CMD_PAUSE:
        if view.get("paused_until"):
            app.resume_protection()
            return "protection resumed"
        app.pause_protection(PAUSE_SECONDS)
        return "protection paused for 1 hour"
    if cmd == CMD_GAME:
        on = not view.get("game_mode")
        app.switch_game_mode(on)
        return "Game mode " + ("on" if on else "off")
    if cmd == CMD_UPDATES:
        if view.get("can_update") and app.start_update_check():
            return "checking for updates"
        return ""
    if cmd == CMD_QUIT:
        app.quit()
        return "quit"
    return ""


# ---------------------------------------------------------------------------------------------
# the icons, drawn in code: 32x32 BGRA, top-down, straight alpha
# ---------------------------------------------------------------------------------------------
SIZE = 32
COLOURS = {   # (fill, border) as RGB
    GREEN: ((46, 160, 67), (20, 96, 38)),
    ORANGE: ((236, 142, 0), (150, 80, 0)),
    GREY: ((138, 145, 153), (80, 86, 94)),
}
_TOP, _SHOULDER, _BOTTOM, _HALF = 2.5, 14.0, 30.0, 13.0


def _in_shield(x: float, y: float, inset: float = 0.0) -> bool:
    top, bottom, half = _TOP + inset, _BOTTOM - inset * 1.6, _HALF - inset
    if y < top or y > bottom or half <= 0:
        return False
    dx = abs(x - SIZE / 2)
    if y <= _SHOULDER:
        corner = 3.0                                 # rounded top corners
        if y < top + corner and dx > half - corner:
            return math.hypot(dx - (half - corner), y - (top + corner)) <= corner
        return dx <= half
    t = (y - _SHOULDER) / (bottom - _SHOULDER)
    return dx <= half * (1 - t ** 1.6)


def _seg(px, py, ax, ay, bx, by) -> float:
    vx, vy, wx, wy = bx - ax, by - ay, px - ax, py - ay
    t = max(0.0, min(1.0, (wx * vx + wy * vy) / (vx * vx + vy * vy)))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def _in_symbol(colour: str, x: float, y: float) -> bool:
    if colour == GREEN:        # a tick
        return min(_seg(x, y, 9.5, 15.5, 14.0, 20.5), _seg(x, y, 14.0, 20.5, 22.5, 10.5)) <= 1.9
    if colour == ORANGE:       # an exclamation mark
        return _seg(x, y, 16, 8, 16, 17) <= 2.0 or math.hypot(x - 16, y - 22.0) <= 2.1
    return _seg(x, y, 12.5, 9, 12.5, 20) <= 1.9 or _seg(x, y, 19.5, 9, 19.5, 20) <= 1.9   # pause bars


def shield_pixels(colour: str) -> bytes:
    """32x32 pixels, 4 bytes each (blue, green, red, alpha), rows from the top. 4x4 samples per
    pixel smooth the edges."""
    fill, border = COLOURS[colour]
    white = (255, 255, 255)
    out = bytearray(SIZE * SIZE * 4)
    n = 4
    for py in range(SIZE):
        for px in range(SIZE):
            r = g = b = hits = 0
            for sy in range(n):
                for sx in range(n):
                    x, y = px + (sx + 0.5) / n, py + (sy + 0.5) / n
                    if not _in_shield(x, y):
                        continue
                    if not _in_shield(x, y, inset=2.0):
                        c = border
                    elif _in_symbol(colour, x, y):
                        c = white
                    else:
                        c = fill
                    r, g, b, hits = r + c[0], g + c[1], b + c[2], hits + 1
            if hits:
                i = (py * SIZE + px) * 4
                out[i:i + 4] = bytes((b // hits, g // hits, r // hits, round(255 * hits / (n * n))))
    return bytes(out)


# ---------------------------------------------------------------------------------------------
# Windows (ctypes). Private DLL objects, so argtypes set here never affect other modules.
# ---------------------------------------------------------------------------------------------
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HANDLE),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
                ("hIconSm", wintypes.HICON)]


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD), ("guidItem", GUID),
                ("hBalloonIcon", wintypes.HICON)]


class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wintypes.BOOL), ("xHotspot", wintypes.DWORD), ("yHotspot", wintypes.DWORD),
                ("hbmMask", wintypes.HBITMAP), ("hbmColor", wintypes.HBITMAP)]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


def _sig(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


class Win32Shell:
    """The real Windows calls. Everything except close_window() and delete_icon() must run on the
    tray's own thread (the one that made the window)."""

    def __init__(self):
        u = ctypes.WinDLL("user32", use_last_error=True)
        s = ctypes.WinDLL("shell32", use_last_error=True)
        g = ctypes.WinDLL("gdi32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        H, U, W, L, B = wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM, wintypes.BOOL
        self.GetModuleHandleW = _sig(k.GetModuleHandleW, wintypes.HMODULE, wintypes.LPCWSTR)
        self.RegisterClassExW = _sig(u.RegisterClassExW, wintypes.ATOM, ctypes.POINTER(WNDCLASSEXW))
        self.UnregisterClassW = _sig(u.UnregisterClassW, B, wintypes.LPCWSTR, wintypes.HINSTANCE)
        self.CreateWindowExW = _sig(u.CreateWindowExW, H, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    H, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID)
        self.DestroyWindow = _sig(u.DestroyWindow, B, H)
        self.DefWindowProcW = _sig(u.DefWindowProcW, LRESULT, H, U, W, L)
        self.GetMessageW = _sig(u.GetMessageW, ctypes.c_int, ctypes.POINTER(wintypes.MSG), H, U, U)
        self.TranslateMessage = _sig(u.TranslateMessage, B, ctypes.POINTER(wintypes.MSG))
        self.DispatchMessageW = _sig(u.DispatchMessageW, LRESULT, ctypes.POINTER(wintypes.MSG))
        self.PostMessageW = _sig(u.PostMessageW, B, H, U, W, L)
        self.PostQuitMessage = _sig(u.PostQuitMessage, None, ctypes.c_int)
        self.RegisterWindowMessageW = _sig(u.RegisterWindowMessageW, U, wintypes.LPCWSTR)
        self.SetTimer = _sig(u.SetTimer, ctypes.c_size_t, H, ctypes.c_size_t, U, ctypes.c_void_p)
        self.KillTimer = _sig(u.KillTimer, B, H, ctypes.c_size_t)
        self.CreatePopupMenu = _sig(u.CreatePopupMenu, wintypes.HMENU)
        self.AppendMenuW = _sig(u.AppendMenuW, B, wintypes.HMENU, U, ctypes.c_size_t, wintypes.LPCWSTR)
        self.SetMenuDefaultItem = _sig(u.SetMenuDefaultItem, B, wintypes.HMENU, U, U)
        self.TrackPopupMenu = _sig(u.TrackPopupMenu, ctypes.c_int, wintypes.HMENU, U, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, H, ctypes.c_void_p)
        self.DestroyMenu = _sig(u.DestroyMenu, B, wintypes.HMENU)
        self.SetForegroundWindow = _sig(u.SetForegroundWindow, B, H)
        self.GetCursorPos = _sig(u.GetCursorPos, B, ctypes.POINTER(wintypes.POINT))
        self.CreateIconIndirect = _sig(u.CreateIconIndirect, wintypes.HICON, ctypes.POINTER(ICONINFO))
        self.DestroyIcon = _sig(u.DestroyIcon, B, wintypes.HICON)
        self.Shell_NotifyIconW = _sig(s.Shell_NotifyIconW, B, wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW))
        self.CreateDIBSection = _sig(g.CreateDIBSection, wintypes.HBITMAP, wintypes.HDC,
                                     ctypes.POINTER(BITMAPINFO), U, ctypes.POINTER(ctypes.c_void_p),
                                     wintypes.HANDLE, wintypes.DWORD)
        self.CreateBitmap = _sig(g.CreateBitmap, wintypes.HBITMAP, ctypes.c_int, ctypes.c_int, U, U,
                                 ctypes.c_void_p)
        self.DeleteObject = _sig(g.DeleteObject, B, wintypes.HGDIOBJ)
        self._proc = None              # keeps the window procedure alive
        self._class = ""
        self._hinst = None

    # ---- window ------------------------------------------------------------------------------
    def create_window(self, handler) -> int:
        """A hidden ordinary window whose messages go to handler(msg, wparam, lparam) -> int | None
        (None = Windows' default handling)."""
        self._hinst = self.GetModuleHandleW(None)

        def proc(hwnd, msg, wparam, lparam):
            try:
                out = handler(int(msg), int(wparam or 0), int(lparam or 0))
            except Exception:
                out = None
            if out is None:
                return self.DefWindowProcW(hwnd, msg, wparam, lparam)
            return out

        self._proc = WNDPROC(proc)
        self._class = f"TacoGuardTray{os.getpid()}_{id(self)}"
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._proc
        wc.hInstance = self._hinst
        wc.lpszClassName = self._class
        if not self.RegisterClassExW(ctypes.byref(wc)):
            raise OSError(ctypes.get_last_error(), "RegisterClassExW failed")
        hwnd = self.CreateWindowExW(0, self._class, "TacoGuard", 0, 0, 0, 0, 0, None, None, self._hinst, None)
        if not hwnd:
            err = ctypes.get_last_error()
            self.UnregisterClassW(self._class, self._hinst)
            raise OSError(err, "CreateWindowExW failed")
        return int(hwnd)

    def taskbar_created_message(self) -> int:
        return int(self.RegisterWindowMessageW("TaskbarCreated"))

    def set_timer(self, hwnd: int, ms: int) -> None:
        self.SetTimer(hwnd, TIMER_ID, int(ms), None)

    def run_loop(self) -> None:
        msg = wintypes.MSG()
        while True:
            r = self.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r == 0 or r == -1:
                break
            self.TranslateMessage(ctypes.byref(msg))
            self.DispatchMessageW(ctypes.byref(msg))

    def close_window(self, hwnd: int) -> None:
        self.PostMessageW(hwnd, WM_CLOSE, 0, 0)

    def destroy_window(self, hwnd: int) -> None:
        try:
            self.KillTimer(hwnd, TIMER_ID)
        except Exception:
            pass
        self.DestroyWindow(hwnd)

    def quit_loop(self) -> None:
        self.PostQuitMessage(0)

    def unregister(self) -> None:
        if self._class:
            self.UnregisterClassW(self._class, self._hinst)
            self._class = ""

    # ---- the notification-area icon ---------------------------------------------------------
    def _nid(self, hwnd: int, hicon=None, tip: str | None = None) -> NOTIFYICONDATAW:
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = ICON_ID
        if hicon is not None:
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
            nid.uCallbackMessage = CALLBACK_MSG
            nid.hIcon = hicon
            nid.szTip = (tip or "TacoGuard")[:TIP_MAX]
        return nid

    def add_icon(self, hwnd: int, hicon, tip: str) -> tuple[bool, bool]:
        """(added, version 4 accepted)."""
        nid = self._nid(hwnd, hicon, tip)
        if not self.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            return False, False
        nid.uVersion = NOTIFYICON_VERSION_4
        return True, bool(self.Shell_NotifyIconW(NIM_SETVERSION, ctypes.byref(nid)))

    def modify_icon(self, hwnd: int, hicon, tip: str) -> bool:
        nid = self._nid(hwnd, hicon, tip)
        return bool(self.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid)))

    def delete_icon(self, hwnd: int) -> bool:
        nid = self._nid(hwnd)
        return bool(self.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid)))

    def make_icon(self, colour: str):
        pixels = shield_pixels(colour)
        bmi = BITMAPINFO()
        h = bmi.bmiHeader
        h.biSize, h.biWidth, h.biHeight = ctypes.sizeof(BITMAPINFOHEADER), SIZE, -SIZE   # top-down
        h.biPlanes, h.biBitCount, h.biCompression = 1, 32, 0                             # BI_RGB
        bits = ctypes.c_void_p()
        color = self.CreateDIBSection(None, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
        if not color or not bits.value:
            raise OSError(ctypes.get_last_error(), "CreateDIBSection failed")
        mask = None
        try:
            ctypes.memmove(bits.value, pixels, len(pixels))
            zeros = ctypes.create_string_buffer(SIZE * SIZE // 8)
            mask = self.CreateBitmap(SIZE, SIZE, 1, 1, zeros)
            info = ICONINFO(True, 0, 0, mask, color)
            hicon = self.CreateIconIndirect(ctypes.byref(info))
            if not hicon:
                raise OSError(ctypes.get_last_error(), "CreateIconIndirect failed")
            return hicon
        finally:
            self.DeleteObject(color)          # the icon keeps its own copies
            if mask:
                self.DeleteObject(mask)

    def destroy_icon(self, hicon) -> None:
        if hicon:
            self.DestroyIcon(hicon)

    # ---- the menu ----------------------------------------------------------------------------
    def cursor_pos(self) -> tuple[int, int]:
        pt = wintypes.POINT()
        self.GetCursorPos(ctypes.byref(pt))
        return pt.x, pt.y

    def show_menu(self, hwnd: int, items, x: int, y: int) -> int:
        menu = self.CreatePopupMenu()
        try:
            for cmd, label, flags in items:
                if flags & MF_SEPARATOR:
                    self.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                else:
                    self.AppendMenuW(menu, flags, cmd, label)
            self.SetMenuDefaultItem(menu, CMD_OPEN, 0)
            self.SetForegroundWindow(hwnd)            # so the menu closes when you click elsewhere
            cmd = self.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, x, y, 0, hwnd, None)
            self.PostMessageW(hwnd, WM_NULL, 0, 0)
            return int(cmd or 0)
        finally:
            self.DestroyMenu(menu)


def _signed16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


# ---------------------------------------------------------------------------------------------
# the tray icon
# ---------------------------------------------------------------------------------------------
class Tray:
    def __init__(self, app, shell=None, refresh_s: float = REFRESH_S):
        self.app = app
        self.shell = shell
        self.refresh_s = refresh_s
        self.hwnd = 0
        self.added = False
        self.version4 = False
        self.taskbar_msg = 0
        self.icons: dict[str, object] = {}
        self.shown: tuple[str, str] | None = None       # (colour, tooltip) Windows has now
        self.view: dict = {}
        self.last_open = 0.0
        self.error = ""
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._atexit = False

    # ---- control (any thread) ------------------------------------------------------------------
    def start(self, wait: float = 5.0) -> bool:
        """Start the icon's thread; True once the icon is in the notification area."""
        if self._thread is not None and self._thread.is_alive():
            return self.added
        self._ready.clear()
        self.error = ""
        self._thread = threading.Thread(target=self._run, name="tacoguard-tray", daemon=True)
        self._thread.start()
        if not self._atexit:
            atexit.register(self._remove_icon)
            self._atexit = True
        self._ready.wait(wait)
        return self.added

    def stop(self, timeout: float = 5.0) -> None:
        t = self._thread
        if self.hwnd and self.shell is not None:
            try:
                self.shell.close_window(self.hwnd)
            except Exception:
                pass
        if t is not None and t is not threading.current_thread():
            t.join(timeout)
        self._remove_icon()                  # also when the thread didn't get to it
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ---- the tray thread -------------------------------------------------------------------------
    def _run(self) -> None:
        try:
            if self.shell is None:
                self.shell = Win32Shell()
            self.hwnd = self.shell.create_window(self.on_message)
            self.taskbar_msg = self.shell.taskbar_created_message()
            self.refresh(force=True)
            self.shell.set_timer(self.hwnd, int(self.refresh_s * 1000))
            self._ready.set()
            self.shell.run_loop()
        except Exception:
            self.error = "The TacoGuard icon could not be added to the taskbar."
            self._log_error("tray failed")
        finally:
            self._ready.set()
            self._remove_icon()
            for hicon in list(self.icons.values()):
                try:
                    self.shell.destroy_icon(hicon)
                except Exception:
                    pass
            self.icons.clear()
            if self.hwnd:
                try:
                    self.shell.destroy_window(self.hwnd)
                except Exception:
                    pass
                self.hwnd = 0
            try:
                self.shell.unregister()
            except Exception:
                pass
            try:
                self.app.store.close()        # this thread's SQLite connection
            except Exception:
                pass

    def _log_error(self, what: str) -> None:
        try:
            self.app.log.error("%s\n%s", what, traceback.format_exc())
        except Exception:
            pass

    def _icon(self, colour: str):
        if colour not in self.icons:
            self.icons[colour] = self.shell.make_icon(colour)
        return self.icons[colour]

    def refresh(self, force: bool = False) -> None:
        """Look at TacoGuard's state; tell Windows only when the colour or the tooltip changed."""
        with self._lock:
            self.view = tray_view(self.app)
            want = (colour_for(self.view), tooltip_for(self.view))
            if not force and self.added and want == self.shown:
                return
            hicon = self._icon(want[0])
            if not self.added:
                self.added, self.version4 = self.shell.add_icon(self.hwnd, hicon, want[1])
                if self.added:
                    self.shown = want
            elif self.shell.modify_icon(self.hwnd, hicon, want[1]):
                self.shown = want
            else:                              # Explorer lost it: add it again next time
                self.added = False

    def _remove_icon(self) -> None:
        with self._lock:
            if self.added and self.hwnd and self.shell is not None:
                try:
                    self.shell.delete_icon(self.hwnd)
                except Exception:
                    pass
            self.added = False
            self.shown = None

    # ---- messages (the tray thread) ----------------------------------------------------------
    def on_message(self, msg: int, wparam: int, lparam: int):
        if msg == CALLBACK_MSG:
            event = lparam & 0xFFFF
            if event == WM_CONTEXTMENU or (event == WM_RBUTTONUP and not self.version4):
                x, y = (_signed16(wparam), _signed16(wparam >> 16)) if self.version4 else self.shell.cursor_pos()
                self.show_menu(x, y)
            elif event in (NIN_SELECT, NIN_KEYSELECT, WM_LBUTTONDBLCLK) or \
                    (event == WM_LBUTTONUP and not self.version4):
                self.open_page()
            return 0
        if self.taskbar_msg and msg == self.taskbar_msg:      # Explorer restarted: add the icon again
            self.added = False
            self.refresh(force=True)
            return 0
        if msg == WM_TIMER:
            try:
                self.refresh()
            except Exception:
                self._log_error("tray refresh failed")
            return 0
        if msg in (WM_CLOSE, WM_ENDSESSION):
            self._remove_icon()
            if msg == WM_CLOSE:
                self.shell.destroy_window(self.hwnd)
                self.hwnd = 0
                return 0
            return None
        if msg == WM_DESTROY:
            self._remove_icon()
            self.shell.quit_loop()
            return 0
        return None

    def open_page(self) -> None:
        now = time.monotonic()
        if now - self.last_open < OPEN_DEBOUNCE_S:     # a double-click is one open, not two
            return
        self.last_open = now
        threading.Thread(target=self._safe, args=(self.app.open_page,), name="tacoguard-tray-open",
                         daemon=True).start()

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception:
            self._log_error("tray action failed")

    def show_menu(self, x: int, y: int) -> None:
        view = tray_view(self.app)
        cmd = self.shell.show_menu(self.hwnd, menu_for(view), x, y)
        if cmd:
            self.command(cmd, view)

    def command(self, cmd: int, view: dict | None = None) -> str:
        view = view if view is not None else tray_view(self.app)
        if cmd == CMD_OPEN:
            self.open_page()
            return "opened the page"
        try:
            note = run_command(self.app, cmd, view)
        except Exception:
            self._log_error("tray menu action failed")
            return ""
        if cmd != CMD_QUIT:
            try:
                self.refresh()
            except Exception:
                self._log_error("tray refresh failed")
        return note
