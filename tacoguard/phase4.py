"""Phase 4: web blocking, hash lookup, tray + dashboard, Game mode, self-protection.

CONTRACT shared by the Phase 4 parts (and the small shared state helpers below, written in the
contract step). User's choices (2026-11-26): website blocking = always notice (no admin) PLUS the
Windows hosts file when the user approves the admin prompt; MalwareBazaar lookups only for files
TacoGuard flagged (+ a "Look up" button); abuse.ch features are built and switch on when the user
pastes their own free abuse.ch key (auth.abuse.ch, not-for-profit use; its data may not train AI).

== Shared state (this file; through store meta, so page, guard and scan worker all see it) ==
    game_mode(store) -> {"active": bool, "manual": bool, "reason": str, "since": epoch}
    set_game_mode(store, active, manual, reason="")     the page / tray (manual) or gamemode.py (auto)
    protection_paused(store) -> float      epoch until which real-time protection is paused (0 = not)
    pause_protection(store, seconds) / resume_protection(store)
  Game mode means: scans wait between files (resume when it ends), the updater skips its timed checks
  (a manual "Check now" still runs; after 24 h of waiting they run anyway), ClamAV is not started for
  second opinions, no toasts (alerts still go to the page and the tray icon turns orange). Real-time
  checks KEEP running. A Game mode you switched on ends after 4 hours (game_mode() reports it off)
  or when TacoGuard restarts.
  Paused protection means: the guard keeps running but its parts don't check or pause anything until
  the time passes; the tray icon is grey; the page says so with a "Resume now" button.

== Website blocking, package tacoguard/webblock/ (Helper M) ==
    lists.py   refresh(settings, store, progress=None) -> dict   download + check + swap the domain lists
               (Phishing.Database active domains from phish.co.za; URLhaus domains via
               urlhaus-api.abuse.ch with the user's key when set). Each list is validated (size bounds,
               one domain per line, idna, no IPs/wildcards/TLD-only, never a protected domain such as
               microsoft.com / windowsupdate.com / github.com / abuse.ch / TacoGuard's own endpoints; a
               non-ASCII name whose IDNA 2003 mapping changes it is dropped), kept as
               settings.webblock_dir/current|previous; a list that shrank by more than half or fails a
               check is refused (last good kept, plain message). Called by the updater (component
               "web_lists", same 4-hour cadence, never more often than every 30 min). One run at a time
               across processes (module lock + webblock_dir/refresh.lock, stale after 30 min); a second
               one answers {"busy": True, "message": ...}. busy(settings) -> bool for the page.
               load(settings) -> DomainSet   fast membership incl. parent domains (a.b.evil.com -> evil.com)
               settings.webblock_allow: your "never block these sites" domains (and their subdomains):
               left out of the hosts block and never reported by the watcher.
    watch.py   class WebWatcher(settings, store, checker=None)   a guard PART named "web": polls the
               Windows DNS cache (DnsGetCacheDataTable, no admin) every 3 s (less often when a poll took
               long) for new names, matches them (skipping names in TacoGuard's own hosts block and names
               cached only as 0.0.0.0 / ::); at most 20 hits handled per poll; a hit -> find programs
               with TCP connections to that name's addresses (GetExtendedTcpTable) -> one guard event kind
               "web", level "warning" ("Your PC looked up a phishing site: <domain>"; "A program was
               connected to a malware site's address: <program> -> <domain>"; never "malware" from a
               domain alone). It REPORTS ONLY: it never pauses or ends a program (an address can be
               shared by many sites). Same domain + program: once per 30 min (store meta "web_dedupe").
               Notes in its status when a browser uses secure DNS (then the cache can't see it).
    hosts.py   plan(settings) -> dict (how many domains, whether the block in the file is current: count
               + sha256 of the block's names against the prepared list, the helper's state);
               apply_elevated(settings) -> Outcome (a str with .ok / .code) writes ONLY a marked block
               (# BEGIN TacoGuard ... # END TacoGuard) of "0.0.0.0 domain" lines into
               <System32>\\drivers\\etc\\hosts through ONE admin prompt: Windows PowerShell (System32)
               runs the fixed script hosts-helper.ps1 from <Program Files>\\TacoGuard (admin-only; the
               first use / after an update, a short -EncodedCommand installer puts it there first)
               with -List <webblock_dir\\hosts-list.txt> -Sha256 <hex>. The script re-checks the list
               (size, checksum, every line), keeps everything outside the block byte for byte, keeps a
               copy of the original once (hosts.tacoguard-original), caps the block (100,000 domains),
               flushes the DNS cache, writes nothing in the data folder and answers only by exit code.
               remove_elevated(settings, cleanup=False) -> Outcome takes the block out (cleanup: also
               the helper, for uninstall). Never runs without a user click (or the weekly offer the
               user accepts); the page saves settings.webblock_hosts only when the outcome is ok.
               Defender may flag hosts changes that redirect Microsoft domains: the block only ever
               maps to 0.0.0.0 and never lists protected domains. If Defender or the user changes the
               file, TacoGuard reports it, never fights it. `python -m tacoguard hosts status|remove`;
               uninstall takes the block out too (one prompt) or prints that command.

== Hash lookup, tacoguard/lookup.py + tacoguard/secrets.py (Helper N) ==
    secrets.get_key(settings, name="abusech") -> str | None ; set_key(settings, name, value) ; clear_key
               DPAPI-protected file in settings.secrets_dir; never logged, never shown back in full (the
               page shows "key ending in ...a1b2"), never sent anywhere but abuse.ch hosts.
    lookup.lookup(settings, store, sha256, force=False) -> dict | None
               {"found": bool, "signature": str, "file_type": str, "first_seen": str, "tags": [...],
                "link": "https://bazaar.abuse.ch/sample/<sha256>/"}; cached 7 days (store lookups table),
               10 s timeout, max 30 lookups per hour, None when off / no key / offline (never raises).
    lookup.finding_for(info, signed=None) -> Finding | None   engine "lookup": known with a malware
               name AND the file has no valid digital signature (signed=False, from
               signing.check_signature) -> HIGH ("MalwareBazaar lists this exact file as '<signature>'
               malware"); known otherwise -> MEDIUM ("MalwareBazaar has a copy of this file (uploaded
               as <signature or 'unnamed'>), which is not proof on its own"); not known -> None (a note
               "MalwareBazaar doesn't know this file" is added by the caller).
    Hooks: scan/engine.py (finish of a flagged file) and guard/checker.py (flagged result) call it when
    settings.lookup_enabled and a key is set; model.ENGINE_NAMES gets "lookup".

== Tray + dashboard + Game mode (Helper O) ==
    tray.py    class Tray(app)  a hidden window + Shell_NotifyIconW in the page process (ctypes, no new
               library): icon green / orange (needs you) / grey (paused or off); menu: Open TacoGuard,
               Pause protection for 1 hour / Resume protection, Game mode on/off, Check for updates, Quit.
               Tooltip = the one-line protection summary.
    gamemode.py  detect() -> (bool, reason)  SHQueryUserNotificationState (full-screen D3D game,
               presentation mode, busy full-screen app); a small thread in the page process every 10 s
               when settings.game_mode_auto, writes set_game_mode(...). Manual switch wins until turned off
               (or 4 hours, or a restart). Windows' "busy" answer counts only after it lasted 3 minutes.
    Page: Home becomes a dashboard (protection state per part, last scan, signatures/updates age, alerts
    waiting, Game mode / paused banner), Settings gets the Phase 4 groups (web blocking incl. the hosts
    button and its status, abuse.ch key field, lookup switch, tray, Game mode, self-protection).

== Self-protection, tacoguard/selfprotect.py (Helper P) ==
    harden_process() -> bool   DACL on TacoGuard's own process AND each of its threads (existing ones
               via a Toolhelp snapshot, later Python threads via a thread-start hook; the guard sweeps
               again every minute): only SYSTEM / Administrators may end, suspend, write or inject into
               it; an OWNER RIGHTS ACE stops other programs running as the same user from simply
               changing that DACL. The venv launcher parent (TacoGuard's own redirector) is hardened
               too. Called by page, guard and scan worker at start. (Quit from the page or tray still
               works; Task Manager without admin cannot end it; an administrator still can.) The token
               default DACL is NOT used: it breaks subprocess pipes (measured 2026-11-26).
               A scan worker without a heartbeat for 10 min that TacoGuard can't end is marked
               'interrupted' ("A scan helper stopped answering; restart Windows to clear it"), so new
               scans can start.
    check_install(settings) -> list[str]   the installed copy's files against the hash list written at
               install / self-update from the verified release; changed or extra .py files -> an alert.
    watch_own(...)   TacoGuard's Run value, its data folder ACL (the folder and the own entries of its
               first-level subfolders), its settings.json changed by another program -> alert (never
               silently "fixed" except re-locking the data folder ACL: config.secure_root(force=True),
               which never deletes the .locked marker first).
    Guard <-> page: when the page process dies without Quit (no stop file), the guard of the INSTALLED copy
    starts the launcher again with --background before it exits; the page already restarts the guard.
"""
from __future__ import annotations

import json
import time


def _get(store, key: str) -> dict:
    try:
        return json.loads(store.get_meta(key) or "{}") or {}
    except (ValueError, TypeError):
        return {}


MANUAL_GAME_MODE_MAX_S = 4 * 3600     # Game mode you switched on ends by itself after this long


def game_mode(store) -> dict:
    """The shared Game mode state. One you switched on (manual) that is older than 4 hours counts
    as off for every reader (page, guard, scan worker, updater)."""
    d = _get(store, "game_mode")
    out = {"active": bool(d.get("active")), "manual": bool(d.get("manual")),
           "reason": str(d.get("reason") or ""), "since": float(d.get("since") or 0)}
    if out["active"] and out["manual"] and out["since"] and time.time() - out["since"] >= MANUAL_GAME_MODE_MAX_S:
        out.update(active=False, reason="", since=0.0)
    return out


def set_game_mode(store, active: bool, manual: bool, reason: str = "") -> None:
    old = game_mode(store)
    since = old["since"] if (old["active"] and active) else (time.time() if active else 0.0)
    store.set_meta("game_mode", json.dumps({"active": bool(active), "manual": bool(manual),
                                            "reason": reason, "since": since}))


def protection_paused(store) -> float:
    until = float(_get(store, "protection_pause").get("until") or 0)
    return until if until > time.time() else 0.0


def pause_protection(store, seconds: float) -> float:
    until = time.time() + max(60.0, min(float(seconds), 24 * 3600.0))
    store.set_meta("protection_pause", json.dumps({"until": until}))
    return until


def resume_protection(store) -> None:
    store.set_meta("protection_pause", json.dumps({"until": 0}))
