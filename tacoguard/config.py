"""Where TacoGuard keeps its data, and its settings.

The data folder defaults to D:\\TacoGuard (%LOCALAPPDATA%\\TacoGuard on a PC without a D: drive). Override it with the TACOGUARD_DATA environment
variable or the --data command-line option (tests always use a temp folder).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

def _default_data_dir() -> str:
    """D:\\TacoGuard (keeps the system drive free); a PC without a D: drive uses
    %LOCALAPPDATA%\\TacoGuard instead."""
    if os.path.isdir("D:\\"):
        return r"D:\TacoGuard"
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
    return os.path.join(base, "TacoGuard")


DEFAULT_DATA_DIR = _default_data_dir()
DEFAULT_PORT = 8799

# Every internet address TacoGuard can contact. The Settings page shows this list.
# Keep it complete: a new download or lookup must be added here first.
UPDATE_WHEN = ("When TacoGuard starts and every 4 hours while it runs (change it in Settings), "
               "and when you press 'Check for updates'.")

# TacoGuard's own GitHub repository: signed releases of the app, the ML model and rule settings.
RELEASE_REPO = "mAgNiFiCeNtTaCo/TacoGuard"

ENDPOINTS = [
    {
        "host": "api.github.com",
        "why": "Reads the published checksums of the ClamAV program and the YARA Forge rules, and the list "
               "of TacoGuard's own signed releases, before downloading anything.",
        "when": UPDATE_WHEN,
        "sends": "Nothing about you or your files.",
    },
    {
        "host": "github.com, objects.githubusercontent.com, release-assets.githubusercontent.com",
        "why": "Downloads the ClamAV program (Cisco Talos), the YARA Forge rule package, and TacoGuard's own "
               f"signed updates (github.com/{RELEASE_REPO}: the app, the ML model, rule settings).",
        "when": UPDATE_WHEN,
        "sends": "Nothing about you or your files.",
    },
    {
        "host": "database.clamav.net",
        "why": "ClamAV's own updater (freshclam) downloads Cisco Talos's signed virus signatures.",
        "when": UPDATE_WHEN,
        "sends": "Nothing about you or your files (freshclam sends its version number).",
    },
    {
        "host": "current.cvd.clamav.net",
        "why": "freshclam looks up this name (a DNS question, no download) to learn the newest signature versions, so it downloads only when something changed.",
        "when": UPDATE_WHEN,
        "sends": "Nothing about you or your files (an ordinary DNS lookup).",
    },
]


@dataclass
class Limits:
    max_file_size: int = 2 * 1024**3          # files bigger than this are skipped (and listed)
    in_memory_max: int = 32 * 1024**2         # files up to this size are read once into memory
    archive_max_depth: int = 3                # archive inside archive inside archive
    archive_max_total: int = 500 * 1024**2    # unpacked bytes per outer archive
    archive_max_entries: int = 10_000         # files per outer archive
    archive_max_ratio: int = 100              # unpacked size / packed size per member
    archive_member_max: int = 200 * 1024**2   # one member bigger than this is not unpacked
    read_rate_mb_s: float = 80.0              # disk read throttle for scans (0 = no throttle)


@dataclass
class Settings:
    data_dir: str = DEFAULT_DATA_DIR
    port: int = DEFAULT_PORT
    limits: Limits = field(default_factory=Limits)
    clamav_enabled: bool = True
    yara_enabled: bool = True
    clamav_idle_stop_s: int = 600             # stop the ClamAV helper this long after the last scan
    scan_priority: str = "idle"               # "idle" or "below_normal"
    clamav_threads: int = 4                   # files ClamAV checks at the same time (1..8)
    # a validly signed program: weak matches are dropped (with a note), strong ones lowered to
    # medium (scan/engine.py _signature_trust)
    trust_signed_programs: bool = True
    # ---- Phase 2 ----------------------------------------------------------------------
    auto_update: bool = True                  # check at start and every update_interval_h while running
    update_interval_h: float = 4.0            # 1..24
    signatures_max_age_days: int = 7          # older than this: the page warns that signatures are stale
    ml_enabled: bool = True                   # machine-learning score for Windows programs (PE files)
    # Bigger programs get no ML score. Measured 2026-11-23 (200 programs from C:\Program Files, a
    # scan running beside it): the upstream feature code (pefile parse, strings) took up to 14 s
    # and +600 MB on 40-60 MB programs; up to 16 MB the worst real one took 3.4 s / +41 MB, and
    # synthetic worst cases at 16 MB stay under 3 s / +60 MB (detect/ml.py also skips files with
    # too many text strings). Was 64 MB.
    ml_max_file_size: int = 16 * 1024**2
    learning_enabled: bool = True             # adjust trust from YOUR verdicts only (tacoguard/learning.py)
    # ---- Phase 3: real-time protection (tacoguard/guard/, contract in guard/__init__.py) -----
    realtime_enabled: bool = True             # the guard process runs while TacoGuard runs
    start_at_sign_in: bool = True             # HKCU Run entry for the installed copy (autostart.py)
    watch_folders: list = field(default_factory=list)   # [] = the defaults (guard.default_watch_folders)
    watch_processes: bool = True              # check each newly started program once
    pause_malware_processes: bool = True      # a strong "malware" result pauses that program, then asks
    ransomware_guard: bool = True             # decoy files + mass-change check
    ransomware_pause: bool = True             # pause the programs writing when a decoy is changed
    canary_folders: list = field(default_factory=list)  # [] = Documents, Desktop, Pictures, Downloads
    persistence_watch: bool = True            # report new start-up entries
    realtime_max_file_size: int = 256 * 1024**2   # bigger new files: noted, "scan it from the Scan tab"
    realtime_clamav_second_opinion: bool = True   # start ClamAV only for a file another check flagged
    # ---- derived paths -------------------------------------------------------------
    @property
    def root(self) -> Path:
        return Path(self.data_dir)

    @property
    def db_path(self) -> Path:
        return self.root / "tacoguard.db"

    @property
    def settings_path(self) -> Path:
        return self.root / "settings.json"

    @property
    def clamav_program_dir(self) -> Path:      # unpacked ClamAV portable zip
        return self.root / "engines" / "clamav"

    @property
    def clamav_db_dir(self) -> Path:           # main/daily/bytecode .cvd/.cld
        return self.root / "signatures" / "clamav"

    @property
    def yara_dir(self) -> Path:                # current/ and previous/ rule sets
        return self.root / "signatures" / "yara"

    @property
    def hashset_dir(self) -> Path:             # *.txt lists of bad SHA-256 hashes
        return self.root / "hashsets"

    @property
    def quarantine_dir(self) -> Path:
        return self.root / "quarantine"

    @property
    def tmp_dir(self) -> Path:
        return self.root / "tmp"

    @property
    def log_dir(self) -> Path:
        return self.root / "logs"

    @property
    def ml_dir(self) -> Path:                  # current/ and previous/ ML model packages
        return self.root / "models" / "ml"

    @property
    def updates_dir(self) -> Path:             # trusted metadata state, staging, the update journal
        return self.root / "updates"

    @property
    def guard_dir(self) -> Path:               # Phase 3: decoy manifest, start-up entry backups
        return self.root / "guard"

    def ensure_dirs(self) -> None:
        for p in (self.root, self.clamav_program_dir.parent, self.clamav_db_dir, self.yara_dir,
                  self.hashset_dir, self.quarantine_dir, self.tmp_dir, self.log_dir, self.ml_dir,
                  self.updates_dir, self.guard_dir):
            p.mkdir(parents=True, exist_ok=True)

    # ---- load / save ---------------------------------------------------------------
    def to_json(self) -> dict:
        d = asdict(self)
        d.pop("data_dir", None)  # the folder is chosen by env/CLI, not stored inside itself
        return d

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.settings_path.with_suffix(".json.tmp")
        tmp.write_bytes(json.dumps(self.to_json(), indent=2).encode("utf-8"))
        os.replace(tmp, self.settings_path)


def install_root() -> Path:
    """Where the installed copy of TacoGuard lives (Phase 2): %LOCALAPPDATA%\\Programs\\TacoGuard.
    The project folder stays a development copy; self-update only ever changes the installed copy."""
    if os.environ.get("TACOGUARD_INSTALL_ROOT"):          # tests use a temp folder
        return Path(os.environ["TACOGUARD_INSTALL_ROOT"])
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
    return Path(base) / "Programs" / "TacoGuard"


def signing_dir() -> Path:
    """The release signing keys (DPAPI-protected, this Windows account only). Outside every project
    and outside the data folder. Never in git, never uploaded."""
    return Path(os.path.expanduser("~")) / ".tacoguard-signing"


CLAMAV_THREADS_MAX = 8


def clamav_thread_count(settings) -> int:
    """settings.clamav_threads kept within 1..CLAMAV_THREADS_MAX (a hand-edited settings.json
    may hold anything)."""
    try:
        n = int(getattr(settings, "clamav_threads", 1))
    except (TypeError, ValueError):
        n = 1
    return max(1, min(CLAMAV_THREADS_MAX, n))


def secure_root(settings: "Settings") -> str:
    """Lock the data folder to the current user, SYSTEM and Administrators (no admin rights needed:
    the user owns the folder). Done once; a marker file records it. Returns a plain-English note."""
    import getpass
    import subprocess

    root = settings.root
    root.mkdir(parents=True, exist_ok=True)
    marker = root / ".locked"
    if marker.exists():
        return "Data folder already locked to your account and administrators."
    user = os.environ.get("USERDOMAIN", "") + "\\" + getpass.getuser() if os.environ.get("USERDOMAIN") \
        else getpass.getuser()
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    cmd = [icacls, str(root), "/inheritance:r",
           "/grant:r", f"{user}:(OI)(CI)F",
           "/grant:r", "*S-1-5-18:(OI)(CI)F",        # SYSTEM
           "/grant:r", "*S-1-5-32-544:(OI)(CI)F"]    # Administrators
    r = subprocess.run(cmd, capture_output=True, text=True, creationflags=0x08000000)
    if r.returncode != 0:
        return "Could not lock the data folder: " + (r.stderr or r.stdout).strip()
    marker.write_text("locked by TacoGuard\n", encoding="utf-8")
    return "Data folder locked to your account and administrators."


_lock = threading.Lock()


OLD_ML_MAX_FILE_SIZE = 64 * 1024**2       # the default before 2026-11-23


def _merge(dc_type, raw: dict):
    """Build a dataclass from a dict, ignoring unknown keys and keeping defaults for missing ones."""
    obj = dc_type()
    for f in fields(dc_type):
        if f.name in raw:
            val = raw[f.name]
            if f.name == "limits" and isinstance(val, dict):
                val = _merge(Limits, val)
            setattr(obj, f.name, val)
    return obj


def load_settings(data_dir: str | None = None) -> Settings:
    data_dir = data_dir or os.environ.get("TACOGUARD_DATA") or DEFAULT_DATA_DIR
    with _lock:
        s = Settings(data_dir=str(data_dir))
        if s.settings_path.exists():
            try:
                raw = json.loads(s.settings_path.read_bytes().decode("utf-8"))
                if isinstance(raw, dict) and raw.get("ml_max_file_size") == OLD_ML_MAX_FILE_SIZE:
                    raw.pop("ml_max_file_size")     # the old default, saved with the rest: use the new one
                s = _merge(Settings, raw)
                s.data_dir = str(data_dir)
            except (ValueError, OSError):
                pass  # a broken settings file falls back to defaults; the page shows defaults
        return s
