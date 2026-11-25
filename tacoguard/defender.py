"""Microsoft Defender status, read only.

TacoGuard never changes Defender or any Windows security setting. This module only READS:
`Get-MpComputerStatus` (Defender's own status) and the AntiVirusProduct list Windows Security keeps
in root/SecurityCenter2. Results are cached for 5 minutes.

    get_status(force=False) -> dict    blocking (up to ~15 s the first time), never raises
    peek() -> dict | None              non-blocking: the cached status (refreshes it in the
                                       background when it is older than 5 minutes)
    parse_status(raw: dict) -> dict    turns the PowerShell JSON into plain-English status
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

CACHE_SECONDS = 300
TIMEOUT_SECONDS = 15
OLD_SIGNATURE_DAYS = 3
CREATE_NO_WINDOW = 0x08000000

POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

# Read-only: two Get-* commands, nothing else.
_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$out = [ordered]@{}
try {
  $s = Get-MpComputerStatus
  $upd = ''
  if ($s.AntivirusSignatureLastUpdated) { $upd = $s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
  $out.mp = [ordered]@{
    AMServiceEnabled = $s.AMServiceEnabled
    AntivirusEnabled = $s.AntivirusEnabled
    RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
    AntivirusSignatureAge = $s.AntivirusSignatureAge
    AntivirusSignatureVersion = $s.AntivirusSignatureVersion
    AntivirusSignatureLastUpdated = $upd
    AMRunningMode = $s.AMRunningMode
    IsTamperProtected = $s.IsTamperProtected
  }
} catch { $out.mp_error = $_.Exception.Message }
try {
  $out.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
    ForEach-Object { [ordered]@{ displayName = $_.displayName; productState = $_.productState } })
} catch { $out.av_error = $_.Exception.Message }
$out | ConvertTo-Json -Depth 4 -Compress
"""

_lock = threading.Lock()
_cache: dict | None = None
_cache_time = 0.0
_refreshing = False

MSG_OK = "Microsoft Defender is on and up to date. TacoGuard works next to it as a second opinion."
HOW_TO_TURN_ON = ("To turn it back on, open Windows Security, go to Virus & threat protection > "
                  "Manage settings, and switch Real-time protection on. TacoGuard never changes "
                  "Defender's settings.")


def _run_powershell() -> dict:
    """Runs the read-only script. Returns the parsed JSON, or {"error": "..."}."""
    if not os.path.isfile(POWERSHELL):
        return {"error": "Windows PowerShell was not found, so Defender's status could not be read."}
    encoded = base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, timeout=TIMEOUT_SECONDS, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return {"error": "Windows took too long to answer (more than 15 seconds)."}
    except OSError as e:
        return {"error": f"Could not start Windows PowerShell ({e.strerror or e})."}
    text = r.stdout.decode("utf-8", errors="replace").strip().lstrip("\ufeff")
    start = text.find("{")
    if start < 0:
        return {"error": "Windows did not return Defender's status."}
    try:
        return json.loads(text[start:])
    except ValueError:
        return {"error": "Defender's status could not be understood."}


def _parse_time(value) -> float:
    """Epoch seconds from '2026-11-23T08:00:00.0000000Z' or PowerShell 5's '/Date(1700000000000)/'."""
    if not value:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value)
    m = re.search(r"Date\((-?\d+)", s)
    if m:
        return int(m.group(1)) / 1000.0
    s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _is_defender(name: str) -> bool:
    n = (name or "").lower()
    return "windows defender" in n or "microsoft defender" in n


def parse_status(raw: dict) -> dict:
    """Plain-English Defender status from the script's JSON.

    level: "ok" (on and current), "warn" (on but something to look at), "off" (real-time
    protection is off), "unknown" (could not read)."""
    out = {
        "available": False, "level": "unknown", "message": "", "advice": "",
        "realtime_on": None, "antivirus_on": None, "running_mode": "",
        "signature_age_days": None, "signature_updated": 0.0, "signature_version": "",
        "other_products": [], "checked": time.time(),
    }
    raw = raw if isinstance(raw, dict) else {}
    av = raw.get("av") or []
    if isinstance(av, dict):
        av = [av]
    for p in av:
        if not isinstance(p, dict):
            continue
        name = str(p.get("displayName") or "").strip()
        if not name or _is_defender(name):
            continue
        try:
            state = int(p.get("productState") or 0)
        except (TypeError, ValueError):
            state = 0
        out["other_products"].append({"name": name, "on": bool(state & 0x1000)})
    others_on = [p["name"] for p in out["other_products"] if p["on"]]

    mp = raw.get("mp")
    if raw.get("error") or not isinstance(mp, dict):
        why = raw.get("error") or raw.get("mp_error") or "no answer from Windows"
        out["message"] = f"Could not read Microsoft Defender's status ({str(why).strip()[:200]})."
        if others_on:
            out["message"] += f" Windows lists this antivirus as on: {', '.join(others_on)}."
        out["advice"] = "You can check it yourself in Windows Security > Virus & threat protection."
        return out

    out["available"] = True
    out["realtime_on"] = bool(mp.get("RealTimeProtectionEnabled"))
    out["antivirus_on"] = bool(mp.get("AntivirusEnabled"))
    out["running_mode"] = str(mp.get("AMRunningMode") or "")
    age = mp.get("AntivirusSignatureAge")
    try:
        age = int(age)
        out["signature_age_days"] = age if 0 <= age < 4000 else None
    except (TypeError, ValueError):
        pass
    out["signature_updated"] = _parse_time(mp.get("AntivirusSignatureLastUpdated"))
    out["signature_version"] = str(mp.get("AntivirusSignatureVersion") or "")
    passive = "passive" in out["running_mode"].lower()

    if passive and others_on:
        out["level"] = "ok"
        out["message"] = (f"{', '.join(others_on)} is your main antivirus and Microsoft Defender is in "
                          "passive mode. TacoGuard works next to them as a second opinion.")
        return out
    if not out["antivirus_on"] or not out["realtime_on"]:
        out["level"] = "off"
        what = "Microsoft Defender is turned off" if not out["antivirus_on"] else \
            "Microsoft Defender's real-time protection is off"
        out["message"] = (f"{what}. That is your PC's always-on protection; TacoGuard only checks files "
                          "when you ask, so it can't replace it.")
        if others_on:
            out["message"] += f" Windows lists another antivirus as on: {', '.join(others_on)}."
        out["advice"] = HOW_TO_TURN_ON
        return out
    age = out["signature_age_days"]
    if age is not None and age > OLD_SIGNATURE_DAYS:
        out["level"] = "warn"
        out["message"] = (f"Microsoft Defender is on, but its virus definitions are {age} days old. "
                          "TacoGuard works next to it as a second opinion.")
        out["advice"] = ("Windows Update normally refreshes them. You can also open Windows Security > "
                         "Virus & threat protection > Protection updates and press 'Check for updates'.")
        return out
    out["level"] = "ok"
    out["message"] = MSG_OK
    if others_on:
        out["message"] += f" Windows also lists another antivirus as on: {', '.join(others_on)}."
    return out


def get_status(force: bool = False) -> dict:
    """Defender status, cached for 5 minutes. Blocking; never raises."""
    global _cache, _cache_time
    with _lock:
        if not force and _cache is not None and time.time() - _cache_time < CACHE_SECONDS:
            return dict(_cache)
    try:
        st = parse_status(_run_powershell())
    except Exception as e:  # never let a status check break the page
        st = parse_status({"error": f"unexpected problem: {type(e).__name__}"})
    with _lock:
        _cache, _cache_time = st, time.time()
    return dict(st)


def peek() -> dict | None:
    """The cached status without waiting. Starts a background refresh when it is missing or old."""
    global _refreshing
    with _lock:
        fresh = _cache is not None and time.time() - _cache_time < CACHE_SECONDS
        cached = dict(_cache) if _cache is not None else None
        start = not fresh and not _refreshing
        if start:
            _refreshing = True
    if start:
        def work():
            global _refreshing
            try:
                get_status(force=True)
            finally:
                with _lock:
                    _refreshing = False
        threading.Thread(target=work, name="defender-status", daemon=True).start()
    return cached
