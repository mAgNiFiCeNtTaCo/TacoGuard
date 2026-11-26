"""Phase 3: real-time protection. CONTRACT shared by the guard process, its parts and the page.

The guard is ONE separate process, started and watched by the page process (web/server.py App):
    python -m tacoguard.guard --data DIR
It runs while TacoGuard runs (settings.realtime_enabled), at below-normal CPU and low disk
priority, inside a job object capping its memory at 512 MB. Budget (whole TacoGuard idle, page +
guard): under 1% CPU and 150 MB RAM. Measured 2026-11-24: page 35 MB; hash + YARA + ML loaded
98 MB with OMP_NUM_THREADS=1 (tacoguard/__init__.py). ClamAV is NOT loaded by the guard unless a
file another check flagged needs a second opinion (then clamd starts, and stops after
settings.clamav_idle_stop_s).

Talking between processes: ONLY through the SQLite store (store.py, Phase 3 tables) and
settings.json. The guard writes guard_events / paused / persistence rows and a heartbeat in
`meta` (key "guard_state", JSON below); the page reads them and does the user's actions itself
(resume / end / quarantine a program, keep / undo a start-up entry). The guard re-reads
settings.json when its mtime changes (checked every 5 s) and applies on/off switches live.

    meta "guard_state" = {"pid": int, "started": epoch, "heartbeat": epoch (every 10 s),
        "version": str, "parts": {"folders": PART, "processes": PART, "ransomware": PART,
        "persistence": PART}}
    PART = {"state": "on" | "off" | "starting" | "error", "message": plain English,
            "watched": [display paths] (folders/ransomware), "checked": int (files/programs/entries)}
    guard_state also has "notes": [plain words], e.g. "Windows has notifications switched off".

Built 2026-11-24 (notes from the build):
- Mutex: the real data folder uses Local\\TacoGuardGuard, any other data folder Local\\TacoGuardGuard-<hash>.
- YARA-X scanners only work on the thread that made them: every check runs on the checker's one
  engine thread (RealtimeChecker.call / check_path); load() opens detectors there.
- Memory: a fresh guard holds ~84 MB private; ML feature code and YARA-X keep what they used (170-180
  MB after checking ~100 programs). After 30 s without checks the guard trims its working set and,
  when it still holds over 115 MB, exits with EXIT_RECYCLE (75) at most once per 30 min; the page's
  GuardSupervisor starts a fresh one at once (not counted as a crash).
- RealtimeChecker.report(result, kind, extra) accepts extra keys title, level, note, data, dedupe;
  too-big files give an "info" event "Not checked (too big): ...".
- Start-up entries of Microsoft-signed programs in Windows / Program Files are level "info".
- paused.state also "not_paused" (Windows refused the pause); paused.event_id links the alert.
- Decoy folders by default also include "Downloads" at the top of each fixed drive (D:\\Downloads).

Event levels: "malware" | "suspicious" (model.verdict_level words; never "malware" for a weak
result), "warning" (ransomware-like activity, a new start-up entry), "info".
Wording: model.explain() for file results; titles are short and calm:
    "Quarantine suggested: Downloads\\free-vbucks.exe"  /  "Suspicious: Desktop\\mod-loader.exe"
    "Paused: Downloads\\x.exe (it looked like malware)"
    "Possible ransomware: a decoy file in Documents was changed. Paused 1 program."
    "New start-up entry: 'Updater' runs C:\\Users\\...\\upd.exe"
The guard NEVER quarantines, deletes or changes a user file by itself. It may only: pause a
program (procctl.suspend) under the rules below, and create / re-create its own decoy files.

== guard/procctl.py (written in the contract step) ==
    ProcRef(pid, create_time); ref_of(pid); suspend(ref, own=None); resume(ref); terminate(ref, own=None)
    is_alive(ref); is_suspended(ref); protected_reason(proc, own=None); tacoguard_pids(engines_dir=None);
    ProcError; pause_allowed(pid) (TEST ONLY: env TACOGUARD_TEST_PAUSE_ONLY limits pausing)
    tacoguard_pids = TacoGuard's own interpreters (command line names tacoguard) + ClamAV programs
    in the engines folder or started by them; never their other children (a browser, a download).
    NEVER_PAUSE names count only in their real place or with a Microsoft signature.
    resume() repeats until the program is no longer paused (undoes a double pause).
    Every pause is recorded with store.add_paused BEFORE suspend() returns to the caller's flow, so
    a crash never leaves an unrecorded paused program. The page lists store.list_paused() and checks
    is_alive() (state "gone" when the program ended).

== guard/service.py + guard/__main__.py (Helper I) ==
    main(argv) -> int          the guard process: single instance (named mutex "Local\\TacoGuardGuard"),
                               priority + memory cap, loads detectors once, starts the parts below,
                               heartbeat, settings reload, clean stop on CTRL_BREAK / a "stop" file
                               (settings.guard_dir / "stop") / the page process ending (parent pid gone).
    class Guard(settings, store, detectors=None, hub=None)   the same, in-process (tests): start(), stop()
    At start: look at files in the watched folders changed since the last heartbeat (missed while
    the guard was down; at most the newest 500, newer than 7 days) and check them.

== guard/checker.py (Helper I) ==
    class RealtimeChecker(settings, store, detectors)
        check_path(display_path) -> FileResult | None     one file, reusing scan.engine.check_file
            (trust lists, clean cache, archives, learning, signed-program rule, lone-weak-ML rule).
            Files over settings.realtime_max_file_size get a SKIPPED note. Thread-safe (one lock).
            ClamAV second opinion (settings.realtime_clamav_second_opinion): only when the first
            checks found something and ClamAV is set up.
        report(result, kind, extra=None) -> int | None   writes the guard event for a flagged result

== guard/folders.py (Helper I) ==
    class WatchHub()           one ReadDirectoryChangesW thread per watched root; others SUBSCRIBE:
        subscribe(root: str, callback, recursive=True) -> token     callback(FsEvent) from the hub thread;
            must be quick (queue the work). Several subscribers may share one root.
        unsubscribe(token);  start();  stop()
    FsEvent(action: "added"|"modified"|"removed"|"renamed_from"|"renamed_to"|"overflow", path: display, ts)
        "overflow": Windows' buffer filled; the subscriber re-checks its root itself.
    class FolderWatcher(settings, store, checker, hub)    the "folders" part: new / changed files in the
        watched folders are checked when they have been quiet for 2 s (size + mtime stable), not while
        still being written (*.crdownload, *.part, *.partial, *.download, *.opdownload, *.tmp, ~$*
        are waited for until renamed). At most 1 check at a time, queue capped at 2,000 (overflow:
        "Many files changed at once; TacoGuard checks the newest ones first"). Links/junctions are
        not followed. A malware or suspicious result -> guard event (never quarantined by itself).
    default_watch_folders(settings) -> list[str]   your Downloads (known folder + "Downloads" at the
        top of each fixed drive), Desktop, Documents, your Startup folder; settings.watch_folders wins
        when not empty. Folders inside OneDrive are watched but get no decoys.

== guard/processes.py (Helper I) ==
    class ProcessWatcher(settings, store, checker)  the "processes" part: new pids every 1 s (a set
        difference of psutil.pids(); cheap). Each new program's file is checked once (results are
        cached by path + size + mtime through the clean cache). Result "malware" and
        settings.pause_malware_processes -> pause it (procctl; protected programs never), event
        level "malware" with data {"paused_id"}. "suspicious" -> event only. Programs gone before
        the check: checked anyway (the file stays), no pause.

== guard/ransom.py (Helper J) ==
    class RansomGuard(settings, store, hub)          the "ransomware" part
        Decoys: 2-3 hidden files per folder in canary_folders (default Documents, Desktop, Pictures,
        Downloads; never inside OneDrive), ordinary names and valid small contents (docx/xlsx/pdf/jpg
        made by TacoGuard, synthetic). Manifest settings.guard_dir/"decoys.json" (path, size, sha256).
        Trigger: a decoy modified, renamed or overwritten (content differs from the manifest), or a
        burst (>= 20 renames/rewrites in one watched folder within 10 s, new extension or high-entropy
        content). A decoy simply deleted (by you, in Explorer) re-creates it without alarm.
        Suspects: programs under your account whose disk writes grew DURING the triggering
        activity (the 1 s samples kept while a burst builds + trigger + 0.5 s; a lone decoy change:
        trigger, +0.5 s, +1.0 s with writes in both intervals), at least 2 MB/s, not protected, not
        TacoGuard, no valid digital signature unless a script host. At most the top 2 are paused;
        a program already paused is never paused twice. (Review fixes 2026-11-24.)
        settings.ransomware_pause -> pause them (procctl), record paused rows, event level "warning"
        with data {"paused_ids": [...], "decoy": path}. No suspect found: event only, plain words.
        Decoys are re-created after an alarm once the user resolved it (or after 10 min): a deleted
        one at its own path (exclusive create), a CHANGED one never written over: it is dropped from
        the manifest and a fresh decoy gets another free name (also after a restart: the alert's
        state in the store decides).
        remove_decoys() -> int   used when the ransomware guard is switched off or TacoGuard uninstalls.

== guard/persistence.py (Helper K) ==
    class PersistenceWatcher(settings, store, checker)   the "persistence" part
        Sources: Run / RunOnce (HKCU, HKLM, HKLM WOW6432Node), Startup folders (yours + all users),
        Winlogon Shell / Userinit, Image File Execution Options "Debugger", AppInit_DLLs, services
        (HKLM\\SYSTEM\\CurrentControlSet\\Services ImagePath), scheduled tasks (schtasks /query /xml,
        every 10 min, below-normal priority), WMI event subscriptions (if Windows lets a normal
        account read them; otherwise the part says so once).
        Registry keys: RegNotifyChangeKeyValue (event-driven, no polling). First run = baseline
        (state "baseline", no events). Later: a new or changed entry -> state "new", its program
        file is checked (checker), event level "warning" (or the file's level when worse).
        undo(key) -> str    only for entries in YOUR account (HKCU Run/RunOnce, your Startup
            folder): backed up to the row's `backup` + settings.guard_dir/"startup-backup", then
            removed. Raises ValueError(plain words) for others ("needs administrator rights: open
            Task Manager > Startup apps" etc.).
        restore(key) -> str   puts an undone entry back.  keep(key) -> None   accepts it (state "kept").

== guard/notify.py (Helper L) ==
    notify(title, message, url=None) -> bool    Windows notification (toast) for a guard event,
        rate-limited (max 1 per 10 s; the rest are merged "and 3 more"). Never raises.

== autostart.py (Helper L) ==
    enabled() -> bool; enable(install_root) -> str; disable() -> str   one HKCU Run value "TacoGuard"
        -> the INSTALLED launcher with --background (no browser). Only the installed copy is ever
        registered (a dev copy refuses with a plain message). Applied when settings.start_at_sign_in
        changes and by `install`.
"""
