"""Start TacoGuard when you sign in to Windows (Phase 3). Per user, no admin rights.

One value in your own Run key, nothing else:

    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run    "TacoGuard" =
        "<install root>\\venv\\Scripts\\pythonw.exe" "<install root>\\TacoGuard.pyw" --background

`--background` starts the page without opening the browser (tools/TacoGuard.pyw). Only the
INSTALLED copy is ever registered (install.py's layout: current.json, venv\\, TacoGuard.pyw); a
development copy refuses with a plain message. The path stays the same across self-updates
(the launcher reads current.json).

Windows' Task Manager > Startup apps can switch the entry off without deleting it (it writes
...\\Explorer\\StartupApproved\\Run). status() reports that; TacoGuard never overrides it.

    enabled(key_path=None) -> bool
    enable(install_root, key_path=None) -> str        raises AutostartError (plain words)
    disable(key_path=None, only_for_root=None) -> str
    status(key_path=None) -> dict

Tests pass key_path (a key under HKCU\\Software\\TacoGuardTest\\...). While pytest runs, the real
Run key is never written (AutostartError instead).
"""
from __future__ import annotations

import os
import winreg
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
VALUE_NAME = "TacoGuard"
BACKGROUND_FLAG = "--background"

NOT_INSTALLED_MSG = ("Starting at sign-in works for the installed copy of TacoGuard only. This copy runs "
                     "from its project folder: install TacoGuard (python -m tacoguard install) to use it.")
ON_MSG = "TacoGuard starts by itself when you sign in to Windows (without opening the page)."
OFF_MSG = "TacoGuard won't start by itself when you sign in to Windows."
SWITCHED_OFF_IN_WINDOWS = ("Windows' Startup apps list has TacoGuard switched off. To change that, open "
                           "Task Manager > Startup apps.")


class AutostartError(ValueError):
    """Plain-English reason the Run entry was not changed."""


def command_for(install_root) -> str:
    root = Path(install_root)
    return f'"{root / "venv" / "Scripts" / "pythonw.exe"}" "{root / "TacoGuard.pyw"}" {BACKGROUND_FLAG}'


def _approved_path(key_path: str | None) -> str:
    return APPROVED_KEY if key_path is None else key_path + r"\StartupApproved"


def _writable(key_path: str | None) -> str:
    path = key_path or RUN_KEY
    if path == RUN_KEY and os.environ.get("PYTEST_CURRENT_TEST"):
        raise AutostartError("Tests never change the real Run key.")
    return path


def _read(key_path: str | None) -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path or RUN_KEY) as k:
            value, kind = winreg.QueryValueEx(k, VALUE_NAME)
    except OSError:
        return None
    return str(value) if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else None


def _approved(key_path: str | None) -> bool | None:
    """False when Task Manager switched the entry off, True when on, None when Windows has no say."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _approved_path(key_path)) as k:
            value, kind = winreg.QueryValueEx(k, VALUE_NAME)
    except OSError:
        return None
    if kind != winreg.REG_BINARY or not value:
        return None
    return not (value[0] & 1)          # 02 / 06 = on, 03 / 07 = switched off


def enabled(key_path: str | None = None) -> bool:
    return _read(key_path) is not None


def _check_installed(root: Path) -> None:
    if not ((root / "current.json").is_file() and (root / "TacoGuard.pyw").is_file()
            and (root / "venv" / "Scripts" / "pythonw.exe").is_file()):
        raise AutostartError(NOT_INSTALLED_MSG)


def enable(install_root, key_path: str | None = None) -> str:
    root = Path(install_root)
    _check_installed(root)
    path = _writable(key_path)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, command_for(root))
    except OSError:
        raise AutostartError("Windows did not let TacoGuard add itself to your start-up programs.") from None
    if _approved(key_path) is False:
        return ON_MSG + " " + SWITCHED_OFF_IN_WINDOWS
    return ON_MSG


def disable(key_path: str | None = None, only_for_root=None) -> str:
    """Removes the value. With only_for_root, only when it starts the copy in that folder."""
    current = _read(key_path)
    if current is None:
        return OFF_MSG
    if only_for_root is not None:
        where = os.path.normcase(str(Path(only_for_root)))
        if where not in os.path.normcase(current):
            return OFF_MSG
    path = _writable(key_path)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, VALUE_NAME)
    except FileNotFoundError:
        pass
    except OSError:
        raise AutostartError("Windows did not let TacoGuard remove itself from your start-up programs.") from None
    return OFF_MSG


def status(key_path: str | None = None) -> dict:
    """{"enabled", "approved", "command", "message"} for the page. Never raises."""
    try:
        cmd = _read(key_path)
        approved = _approved(key_path) if cmd else None
    except Exception:
        cmd, approved = None, None
    if cmd is None:
        msg = OFF_MSG
    elif approved is False:
        msg = SWITCHED_OFF_IN_WINDOWS
    else:
        msg = ON_MSG
    return {"enabled": cmd is not None, "approved": approved, "command": cmd or "", "message": msg}
