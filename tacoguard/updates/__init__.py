"""Phase 2: verified updates. CONTRACT shared by the updater, self-update, the ML model and the page.

== Signed metadata (TacoGuard's own packages), module `updates/signed.py` (Helper E) ==
TUF-style, Ed25519 (cryptography package). Canonical bytes for signing:
    json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

root.json    {"signed": {"_type": "root", "version": 1, "expires": "2031-11-23T00:00:00Z",
                         "keys": {<keyid>: {"keytype": "ed25519", "public": <hex>}},
                         "roles": {"root":    {"keyids": [...], "threshold": 1},
                                   "targets": {"keyids": [...], "threshold": 1}}},
              "signatures": [{"keyid": <keyid>, "sig": <hex>}]}
             keyid = sha256 hex of the raw 32-byte public key.
             The trusted root ships inside the app: tacoguard/data/root.json.
             A newer root (version + 1) is accepted only if signed by the threshold of the OLD root AND
             of itself (TUF rotation); chains of several steps are followed one at a time.
targets.json {"signed": {"_type": "targets", "version": N, "expires": ISO-8601 UTC,
                         "targets": {<file name>: {"length": int, "sha256": hex,
                                     "custom": {"kind": "ml_model" | "app", "version": "...",
                                                "min_app": "0.2.0", "notes": "plain words"}}}},
              "signatures": [...]}
Rules: signatures must meet the role threshold with distinct keyids; expired metadata is refused
(clear message); version lower than the last trusted one is refused (rollback); same version with
different bytes is refused; every downloaded file must match length + sha256 before use.

    class UpdateRejected(Exception)    plain-English reason, shown on the page; .kind is "signature",
                                       "checksum", "rollback", "expired", "format", "test" or
                                       "not_set_up". The updater shows "expired" as its own calm
                                       component state "expired" (no warning banner).
    load_trusted_root(settings) -> dict          (data/root.json, then the newer signed root files stored in
                                                  updates_dir/roots, each checked again against the one before)
    verify_root_update(trusted: dict, new_bytes: bytes) -> dict
    verify_targets(root: dict, targets_bytes: bytes, last_version: int) -> dict   (the "signed" part)
    verify_file(path, target_entry: dict) -> None

== Where TacoGuard's own packages come from ==
GitHub releases of config.RELEASE_REPO. The LATEST release holds: targets.json, every file it lists
(e.g. ml-model-2026.11.23.zip, tacoguard-0.2.0.zip) and, when the root keys change, root.json.
A "source" abstraction lets tests and the first install use a local folder with the same files.

== Updater, module `updates/updater.py` (Helper E) ==
    class Updater(settings, store)
        start(on_start=True) -> None        background thread: check at start (if settings.auto_update)
                                            and every settings.update_interval_h hours; stop() ends it
        check_now(wait=False) -> None       one check of every component (one at a time, never two at once)
        status() -> dict                    {"checking": bool, "last_check": epoch, "next_check": epoch,
                                             "components": {name: {"version", "updated", "state",
                                             "message", "last_error"}}, "app_update": {...} | None}
                                            cheap, never raises
    Components: "clamav_signatures" (freshclam, ClamAV's own signed CVDs), "yara_rules" (YARA Forge,
    GitHub sha256 digest), "ml_model" (own signed package), "app" (own signed package: only RECORDED as
    available for self-update, never installed by the updater).
    Every component: download into staging, verify, test-load (ClamAV: databases load; YARA: compiles;
    ML: model loads and scores its built-in test vector to the expected value), then swap
    current -> previous, new -> current with a journal (updates_dir/journal.json) so a crash mid-swap is
    finished or rolled back at the next start (recover()). A failure leaves the last good set in place.
    A swap waits while a scan job is running (staged and applied right after). No internet: keep the
    last set, say when it was last updated.

== Self-update, module `selfupdate.py` + installed copy `install.py` (Helper F) ==
    install.install(settings, project_root, shortcut=False) -> dict    python -m tacoguard install
    selfupdate.available(settings) -> dict | None      verified "app" target newer than the running one
    selfupdate.install_update(settings, version) -> dict   ONLY after the user clicks; verify again,
                                       unpack beside the current version, self-test, switch, restart the
                                       page, roll back automatically if the new version does not start
    selfupdate.rollback(settings) -> dict              back to the previous version (user click)
    selfupdate.running_from_install() -> bool
    Fail closed: nothing is installed without updates_dir/targets.json (verified again). The switch
    marks current.json "pending" until the watchdog saw the new page answer; if the watchdog dies,
    the launcher (tools/TacoGuard.pyw) switches back by itself.

== ML model, module `detect/ml.py` (Helper G) ==
    class MLDetector  (Detector protocol, name "ml", scans_members=True)   model in settings.ml_dir/current
    ML alone is never HIGH: score >= meta["thresholds"]["fpr_0.001"] -> MEDIUM,
    >= ["fpr_0.01"] -> LOW; below -> no finding. detail "machine-learning score 0.97 ...".

== Local learning, module `learning.py` (Helper H) ==
    adjust(findings, store, settings) -> (findings, notes)   only from YOUR verdicts in the store
"""
