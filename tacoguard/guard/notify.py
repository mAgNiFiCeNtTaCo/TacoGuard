"""Windows notifications (toasts) for guard events, with no extra Python packages.

TacoGuard is not a packaged (Store) app, so Windows must know its name before it shows a toast
from it. The first toast registers it once, in your own part of the registry (no admin rights):

    HKCU\\Software\\Classes\\AppUserModelId\\TacoGuard
        DisplayName = "TacoGuard"                                        (REG_SZ)
        IconUri     = "<this copy>\\tacoguard\\web\\static\\icon.png"      (REG_SZ, when the file exists)

(written again only when a value differs, e.g. the icon moved with a self-update). The toast is
shown by a short Windows PowerShell script (WinRT ToastNotificationManager, no window). The text
goes in as XML-escaped, base64-encoded data, never as script code. Clicking the toast opens
TacoGuard's page (activationType="protocol", only http://127.0.0.1 / localhost addresses).

Rate limit: at most one toast per 10 s. Toasts asked for inside that window are merged into one
"... and N more" toast sent when the window ends.

    notify(title, message, url=None) -> bool        False when Windows couldn't show it (also when
                                                     notifications are switched off in Windows
                                                     Settings: see Notifier.off_message); never raises
    notify_event(event: dict, port) -> bool          for a guard_events row (levels malware,
                                                     warning, suspicious; others are not shown)

notify() waits for PowerShell (about 1-2 s): call it from a worker thread, not from a folder
watcher callback.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import threading
import time
import winreg
from pathlib import Path
from xml.sax.saxutils import escape

APP_ID = "TacoGuard"
AUMID_KEY = r"Software\Classes\AppUserModelId\TacoGuard"
DISPLAY_NAME = "TacoGuard"
ICON = Path(__file__).resolve().parents[1] / "web" / "static" / "icon.png"
MIN_GAP_S = 10.0
TITLE_MAX = 120
TEXT_MAX = 300
TIMEOUT_S = 20
CREATE_NO_WINDOW = 0x08000000
NOTIFY_LEVELS = ("malware", "warning", "suspicious")
POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
_URL_OK = re.compile(r"^http://(127\.0\.0\.1|localhost):\d{1,5}/[A-Za-z0-9#/_.-]*$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$xml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__XML__'))
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('__APPID__')
if ([string]$notifier.Setting -ne 'Enabled') { 'off:' + [string]$notifier.Setting; exit 0 }
$notifier.Show($toast)
'shown'
"""
# What Windows said about the last toast: "shown", "off:DisabledForUser" (notifications are off in
# Windows Settings > System > Notifications), "off:DisabledForApplication" (off for TacoGuard
# only), "failed", "not registered".
OFF_WORDS = {
    "off:DisabledForUser": "Windows notifications are turned off (Settings > System > Notifications), so "
                           "TacoGuard's alerts only show on its Protection tab.",
    "off:DisabledForApplication": "Notifications from TacoGuard are turned off in Windows Settings > System > "
                                  "Notifications, so its alerts only show on its Protection tab.",
    "off:DisabledByGroupPolicy": "Notifications are turned off by your organisation's policy, so TacoGuard's "
                                 "alerts only show on its Protection tab.",
}


def _clean(text, limit: int) -> str:
    s = _CONTROL.sub(" ", str(text or "")).strip()
    return s if len(s) <= limit else s[:limit - 3].rstrip() + "..."


def toast_xml(title: str, message: str, url: str | None = None) -> str:
    """The toast's XML; every value XML-escaped. A url that isn't TacoGuard's page is left out."""
    def esc(s: str) -> str:
        return escape(s, {'"': "&quot;", "'": "&apos;"})
    launch = ""
    if url and _URL_OK.match(url):
        launch = f' activationType="protocol" launch="{esc(url)}"'
    texts = f"<text>{esc(_clean(title, TITLE_MAX))}</text>"
    msg = _clean(message, TEXT_MAX)
    if msg:
        texts += f"<text>{esc(msg)}</text>"
    return f'<toast{launch}><visual><binding template="ToastGeneric">{texts}</binding></visual></toast>'


def toast_script(xml: str) -> str:
    data = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    return _SCRIPT.replace("__XML__", data).replace("__APPID__", APP_ID)


def run_powershell(script: str) -> str:
    """Runs a script in Windows PowerShell without a window. Returns its last output line
    ("shown", "off:<Windows setting>"), or "failed"."""
    if not os.path.isfile(POWERSHELL):
        return "failed"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, timeout=TIMEOUT_S, stdin=subprocess.DEVNULL,
                           creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return "failed"
    lines = (r.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    return lines[-1].strip() if r.returncode == 0 and lines else "failed"


def register_app_id(key_path: str = AUMID_KEY, icon: Path | None = ICON) -> bool:
    """Writes DisplayName (and IconUri) under HKCU\\<key_path> when they differ. True when set."""
    wanted = {"DisplayName": DISPLAY_NAME}
    if icon is not None and Path(icon).is_file():
        wanted["IconUri"] = str(icon)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as k:
            for name, value in wanted.items():
                try:
                    old, _ = winreg.QueryValueEx(k, name)
                except OSError:
                    old = None
                if old != value:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        return True
    except OSError:
        return False


class Notifier:
    """Shows toasts, at most one per `gap` seconds; the rest are merged into one later toast."""

    def __init__(self, runner=run_powershell, register=register_app_id, gap: float = MIN_GAP_S,
                 clock=time.monotonic, timer_factory=threading.Timer):
        self.runner, self.register = runner, register
        self.gap, self.clock, self.timer_factory = gap, clock, timer_factory
        self._lock = threading.Lock()
        self._last: float | None = None
        self._pending: list[tuple[str, str, str | None]] = []
        self._timer = None
        self._registered = False
        self.last = ""                    # what Windows said about the last toast (see OFF_WORDS)

    @property
    def off_message(self) -> str:
        """Plain words when Windows has notifications switched off, else ""."""
        return OFF_WORDS.get(self.last, "")

    def notify(self, title: str, message: str, url: str | None = None) -> bool:
        try:
            with self._lock:
                now = self.clock()
                if self._last is not None and now - self._last < self.gap:
                    self._pending.append((str(title or ""), str(message or ""), url))
                    self._arm(now)
                    return True
                self._last = now
            return self._show(title, message, url)
        except Exception:
            return False

    def _arm(self, now: float) -> None:
        if self._timer is not None:
            return
        delay = max(0.0, (self._last or now) + self.gap - now)
        t = self.timer_factory(delay, self.flush)
        t.daemon = True
        self._timer = t
        t.start()

    def flush(self) -> bool:
        """Sends what waited during the quiet window as one toast."""
        try:
            with self._lock:
                self._timer = None
                pending, self._pending = self._pending, []
                if not pending:
                    return False
                self._last = self.clock()
            if len(pending) == 1:
                title, message, url = pending[0]
            else:
                title = f"{pending[0][0]} and {len(pending) - 1} more"
                message = "Open TacoGuard's Protection tab to see them all."
                url = next((p[2] for p in reversed(pending) if p[2]), None)
            return self._show(title, message, url)
        except Exception:
            return False

    def _show(self, title, message, url) -> bool:
        if not self._registered:
            self._registered = bool(self.register())
        if not self._registered:
            self.last = "not registered"
            return False
        out = self.runner(toast_script(toast_xml(title, message, url)))
        self.last = str(out or "failed").strip()
        return self.last == "shown"


_default = Notifier()


def notify(title: str, message: str, url: str | None = None) -> bool:
    return _default.notify(title, message, url)


def off_message() -> str:
    """Plain words when the last toast wasn't shown because Windows has notifications off."""
    return _default.off_message      # a property: this is already the text


def page_url(port) -> str:
    return f"http://127.0.0.1:{int(port)}/#protection"


def notify_event(event: dict, port, notifier: Notifier | None = None) -> bool:
    """A toast for one guard_events row. Only levels malware / warning / suspicious are shown."""
    try:
        if not isinstance(event, dict) or event.get("level") not in NOTIFY_LEVELS:
            return False
        title = str(event.get("title") or "TacoGuard")
        message = str(event.get("message") or "")
        return (notifier or _default).notify(title, message, page_url(port))
    except Exception:
        return False
