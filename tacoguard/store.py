"""The one SQLite database: scan jobs, notable results, quarantine records, allowlist, verdicts,
the clean-file cache, and (Phase 3) guard events, paused programs and start-up entries.

Safe to use from several threads and from the scan worker process at the same time (WAL mode,
one connection per thread, busy timeout). Every write is its own short transaction.

Only NOTABLE results are stored per job (detections, unreadable, skipped, trusted, incomplete);
clean files only bump the job's counters, so a drive scan does not fill the disk.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .model import CLEAN, FileResult, Finding

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL,
    targets TEXT NOT NULL,              -- JSON list of display paths
    status TEXT NOT NULL,               -- queued|running|paused|done|cancelled|failed|interrupted
    control TEXT NOT NULL DEFAULT '',   -- ''|pause|cancel  (set by the page, read by the worker)
    checkpoint TEXT NOT NULL DEFAULT '',-- last fully checked path, in walk order (for resume)
    counts TEXT NOT NULL DEFAULT '{}',  -- JSON: files, bytes, clean, suspicious, malware, ...
    current TEXT NOT NULL DEFAULT '',   -- file being checked now (display path)
    message TEXT NOT NULL DEFAULT '',   -- plain-English status line
    sig_version TEXT NOT NULL DEFAULT '',
    pid INTEGER NOT NULL DEFAULT 0,
    heartbeat REAL NOT NULL DEFAULT 0,
    started REAL NOT NULL DEFAULT 0,
    finished REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    path TEXT NOT NULL,                 -- display path
    status TEXT NOT NULL,               -- model.SCANNED|TRUSTED|SKIPPED|UNREADABLE
    level TEXT NOT NULL,                -- clean|suspicious|malware
    sha256 TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL DEFAULT '[]',
    notes TEXT NOT NULL DEFAULT '[]',
    incomplete INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',    -- ''|quarantined|trusted|confirmed|restored|deleted
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS results_job ON results(job_id, level);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,        -- display path it came from
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    reason TEXT NOT NULL,
    findings TEXT NOT NULL DEFAULT '[]',
    blob TEXT NOT NULL,                 -- file name inside the quarantine folder
    state TEXT NOT NULL,                -- pending|quarantined|restoring|restored|deleting|deleted|failed
    message TEXT NOT NULL DEFAULT '',
    result_id INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL,
    updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- hash|folder
    value TEXT NOT NULL,                -- lower-case sha256, or a folder's display path
    key TEXT NOT NULL,                  -- sha256, or winpath.norm_key(folder)
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    UNIQUE(kind, key)
);

CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    verdict TEXT NOT NULL,              -- not_a_threat|confirmed_threat
    findings TEXT NOT NULL DEFAULT '[]',
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS verdicts_hash ON verdicts(sha256);

CREATE TABLE IF NOT EXISTS learning_ignores (   -- rules you told TacoGuard to forget (learning.py)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engine TEXT NOT NULL,
    rule TEXT NOT NULL,
    created REAL NOT NULL,
    UNIQUE(engine, rule)
);

CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,               -- norm_key(path)
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    sig_version TEXT NOT NULL,
    checked REAL NOT NULL
);

-- ---- Phase 3: real-time protection (contract: tacoguard/guard/__init__.py) ----------------
CREATE TABLE IF NOT EXISTS guard_events (   -- what the guard saw; the page's Protection tab
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL,
    kind TEXT NOT NULL,                 -- file|process|ransomware|persistence|guard
    level TEXT NOT NULL,                -- info|suspicious|malware|warning
    title TEXT NOT NULL,                -- one plain line: "Paused: Downloads\\x.exe"
    message TEXT NOT NULL DEFAULT '',   -- plain-English reason (model.explain wording)
    path TEXT NOT NULL DEFAULT '',      -- display path of the file / program, if any
    sha256 TEXT NOT NULL DEFAULT '',
    findings TEXT NOT NULL DEFAULT '[]',
    data TEXT NOT NULL DEFAULT '{}',    -- JSON extras (pids, entry key, ...)
    state TEXT NOT NULL DEFAULT 'new',  -- new|seen|resolved
    action TEXT NOT NULL DEFAULT ''     -- what the user chose: resumed|ended|quarantined|trusted|kept|undone|...
);
CREATE INDEX IF NOT EXISTS guard_events_state ON guard_events(state, id);

CREATE TABLE IF NOT EXISTS paused (         -- programs TacoGuard paused (suspended); survives crashes
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    create_time REAL NOT NULL,          -- psutil create_time: tells a reused pid apart
    exe TEXT NOT NULL DEFAULT '',       -- display path of the program
    name TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    event_id INTEGER NOT NULL DEFAULT 0,
    paused_at REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'paused',  -- paused|resumed|ended|gone|not_paused
    updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS lookups (        -- Phase 4: MalwareBazaar answers, cached (tacoguard/lookup.py)
    sha256 TEXT PRIMARY KEY,
    found INTEGER NOT NULL,             -- 1 = known to MalwareBazaar, 0 = not known
    data TEXT NOT NULL DEFAULT '{}',    -- JSON: signature, file_type, first_seen, tags (from the answer)
    checked REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS persistence (    -- start-up entries: the baseline and what changed
    key TEXT PRIMARY KEY,               -- stable id, e.g. "run:HKCU:Software\\...\\Run:Name"
    source TEXT NOT NULL,               -- run|runonce|startup_folder|task|service|winlogon|ifeo|...
    location TEXT NOT NULL,             -- where it lives, plain ("Your Run key", "Task Scheduler: \\X")
    name TEXT NOT NULL,
    command TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',    -- display path of the program it starts, if found
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    state TEXT NOT NULL,                -- baseline|new|kept|undone|removed
    backup TEXT NOT NULL DEFAULT '',    -- JSON needed to restore an undone entry
    event_id INTEGER NOT NULL DEFAULT 0
);
"""

JOB_ACTIVE = ("queued", "running")
JOB_RESUMABLE = ("paused", "interrupted")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        con = self._con()
        con.executescript(SCHEMA)
        con.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema', ?)", (str(SCHEMA_VERSION),))

    # ---- connection ------------------------------------------------------------------
    def _con(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA busy_timeout=30000")
            self._local.con = con
        return con

    def close(self) -> None:
        con = getattr(self._local, "con", None)
        if con is not None:
            con.close()
            self._local.con = None

    def _one(self, sql: str, args=()) -> dict | None:
        row = self._con().execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args=()) -> list[dict]:
        return [dict(r) for r in self._con().execute(sql, args).fetchall()]

    # ---- jobs ------------------------------------------------------------------------
    def create_job(self, targets: list[str]) -> int:
        cur = self._con().execute(
            "INSERT INTO jobs(created, targets, status, message) VALUES(?, ?, 'queued', 'Waiting to start')",
            (time.time(), json.dumps(targets)))
        return int(cur.lastrowid)

    def get_job(self, job_id: int) -> dict | None:
        j = self._one("SELECT * FROM jobs WHERE id=?", (job_id,))
        if j:
            j["targets"] = json.loads(j["targets"])
            j["counts"] = json.loads(j["counts"] or "{}")
        return j

    def list_jobs(self, limit: int = 20) -> list[dict]:
        rows = self._all("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
        for j in rows:
            j["targets"] = json.loads(j["targets"])
            j["counts"] = json.loads(j["counts"] or "{}")
        return rows

    def update_job(self, job_id: int, **fields) -> None:
        """update_job(5, status='running', counts={...}, message='...')"""
        if not fields:
            return
        if "counts" in fields and not isinstance(fields["counts"], str):
            fields["counts"] = json.dumps(fields["counts"])
        cols = ", ".join(f"{k}=?" for k in fields)
        self._con().execute(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))

    def set_control(self, job_id: int, control: str) -> None:
        self._con().execute("UPDATE jobs SET control=? WHERE id=?", (control, job_id))

    def active_jobs(self) -> list[dict]:
        return [self.get_job(r["id"]) for r in
                self._all("SELECT id FROM jobs WHERE status IN ('queued','running') ORDER BY id")]

    # ---- results ---------------------------------------------------------------------
    def add_result(self, job_id: int, r: FileResult) -> int:
        cur = self._con().execute(
            "INSERT INTO results(job_id, path, status, level, sha256, size, findings, notes, incomplete,"
            " reason, created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, r.path, r.status, r.level, r.sha256, r.size,
             json.dumps([f.to_dict() for f in r.findings]), json.dumps(r.notes), int(r.incomplete),
             r.reason(), time.time()))
        return int(cur.lastrowid)

    def get_result(self, result_id: int) -> dict | None:
        r = self._one("SELECT * FROM results WHERE id=?", (result_id,))
        return _decode_result(r) if r else None

    def list_results(self, job_id: int, levels: tuple[str, ...] | None = None) -> list[dict]:
        if levels:
            q = ",".join("?" * len(levels))
            rows = self._all(f"SELECT * FROM results WHERE job_id=? AND level IN ({q}) ORDER BY id",
                             (job_id, *levels))
        else:
            rows = self._all("SELECT * FROM results WHERE job_id=? ORDER BY id", (job_id,))
        return [_decode_result(r) for r in rows]

    # A result that matters for resume: same values -> same fingerprint.
    @staticmethod
    def result_fingerprint(r: FileResult) -> tuple:
        return (r.status, r.level, r.sha256, int(r.size), json.dumps([f.to_dict() for f in r.findings]),
                json.dumps(r.notes), int(r.incomplete))

    def result_fingerprints(self, job_id: int) -> dict[str, tuple]:
        """{display path: fingerprint} of a job's stored results (no JSON decoding)."""
        rows = self._con().execute(
            "SELECT path, status, level, sha256, size, findings, notes, incomplete FROM results "
            "WHERE job_id=? ORDER BY id", (job_id,)).fetchall()
        return {row[0]: (row[1], row[2], row[3], int(row[4]), row[5], row[6], int(row[7])) for row in rows}

    def replace_result(self, job_id: int, r: FileResult) -> int:
        """Overwrites the stored result for this job and path (keeps its id and any action taken).
        Returns how many rows changed."""
        cur = self._con().execute(
            "UPDATE results SET status=?, level=?, sha256=?, size=?, findings=?, notes=?, incomplete=?,"
            " reason=?, created=? WHERE job_id=? AND path=?",
            (r.status, r.level, r.sha256, r.size, json.dumps([f.to_dict() for f in r.findings]),
             json.dumps(r.notes), int(r.incomplete), r.reason(), time.time(), job_id, r.path))
        return cur.rowcount

    def remove_result(self, job_id: int, path: str) -> int:
        """Deletes this job's stored result for this path, unless the user already acted on it
        (quarantine, trust, ...). Used on resume when a file checked again is now clean.
        Returns how many rows went."""
        cur = self._con().execute("DELETE FROM results WHERE job_id=? AND path=? AND action=''",
                                  (job_id, path))
        return cur.rowcount

    # Sections of a scan's results page, worked out in SQL (a drive scan can store many rows).
    RESULT_SECTIONS = {
        "detections": "level IN ('malware', 'suspicious')",
        "not_checked": "level NOT IN ('malware', 'suspicious') AND status != 'trusted'"
                       " AND (status IN ('skipped', 'unreadable') OR incomplete != 0)",
        "trusted": "level NOT IN ('malware', 'suspicious') AND status = 'trusted'",
    }

    def count_result_sections(self, job_id: int) -> dict[str, int]:
        """{"detections": n, "not_checked": n, "trusted": n} for one job."""
        parts = ", ".join(f"COALESCE(SUM(CASE WHEN {cond} THEN 1 ELSE 0 END), 0)"
                          for cond in self.RESULT_SECTIONS.values())
        row = self._con().execute(f"SELECT {parts} FROM results WHERE job_id=?", (job_id,)).fetchone()
        return {name: int(row[i]) for i, name in enumerate(self.RESULT_SECTIONS)}

    def list_result_section(self, job_id: int, section: str, offset: int = 0, limit: int = 200) -> list[dict]:
        """One page of one section, oldest first (same order as list_results)."""
        cond = self.RESULT_SECTIONS[section]
        rows = self._all(f"SELECT * FROM results WHERE job_id=? AND {cond} ORDER BY id LIMIT ? OFFSET ?",
                         (job_id, int(limit), int(offset)))
        return [_decode_result(r) for r in rows]

    def latest_detections(self, limit: int = 200) -> list[dict]:
        rows = self._all("SELECT * FROM results WHERE level != ? ORDER BY id DESC LIMIT ?", (CLEAN, limit))
        return [_decode_result(r) for r in rows]

    def set_result_action(self, result_id: int, action: str) -> None:
        self._con().execute("UPDATE results SET action=? WHERE id=?", (action, result_id))

    # ---- quarantine records ------------------------------------------------------------
    def add_quarantine(self, original_path: str, sha256: str, size: int, reason: str,
                       findings: list[Finding], blob: str, result_id: int = 0) -> int:
        now = time.time()
        cur = self._con().execute(
            "INSERT INTO quarantine(original_path, sha256, size, reason, findings, blob, state, result_id,"
            " created, updated) VALUES(?,?,?,?,?,?, 'pending', ?, ?, ?)",
            (original_path, sha256, size, reason, json.dumps([f.to_dict() for f in findings]), blob,
             result_id, now, now))
        return int(cur.lastrowid)

    def set_quarantine_state(self, qid: int, state: str, message: str = "") -> None:
        self._con().execute("UPDATE quarantine SET state=?, message=?, updated=? WHERE id=?",
                            (state, message, time.time(), qid))

    def claim_quarantine(self, qid: int, from_state: str, to_state: str, message: str = "") -> bool:
        """Moves a record from one state to another in one statement. False when it was not in
        `from_state` any more (someone else got there first)."""
        cur = self._con().execute(
            "UPDATE quarantine SET state=?, message=?, updated=? WHERE id=? AND state=?",
            (to_state, message, time.time(), qid, from_state))
        return cur.rowcount == 1

    def count_quarantine(self, states: tuple[str, ...]) -> int:
        qm = ",".join("?" * len(states))
        return int(self._con().execute(f"SELECT COUNT(*) FROM quarantine WHERE state IN ({qm})",
                                       states).fetchone()[0])

    def set_quarantine_hash(self, qid: int, sha256: str, size: int) -> None:
        """The hash is only known once the file has been read (while it is encrypted)."""
        self._con().execute("UPDATE quarantine SET sha256=?, size=?, updated=? WHERE id=?",
                            (sha256, size, time.time(), qid))

    def get_quarantine(self, qid: int) -> dict | None:
        q = self._one("SELECT * FROM quarantine WHERE id=?", (qid,))
        if q:
            q["findings"] = json.loads(q["findings"])
        return q

    def list_quarantine(self, states: tuple[str, ...] = ("quarantined",)) -> list[dict]:
        qm = ",".join("?" * len(states))
        rows = self._all(f"SELECT * FROM quarantine WHERE state IN ({qm}) ORDER BY id DESC", states)
        for q in rows:
            q["findings"] = json.loads(q["findings"])
        return rows

    # ---- allowlist -------------------------------------------------------------------
    def add_allow(self, kind: str, value: str, key: str, note: str = "") -> int:
        con = self._con()
        con.execute("INSERT OR IGNORE INTO allowlist(kind, value, key, note, created) VALUES(?,?,?,?,?)",
                    (kind, value, key, note, time.time()))
        row = con.execute("SELECT id FROM allowlist WHERE kind=? AND key=?", (kind, key)).fetchone()
        return int(row["id"])

    def remove_allow(self, allow_id: int) -> None:
        self._con().execute("DELETE FROM allowlist WHERE id=?", (allow_id,))

    def list_allow(self, kind: str | None = None) -> list[dict]:
        if kind:
            return self._all("SELECT * FROM allowlist WHERE kind=? ORDER BY id DESC", (kind,))
        return self._all("SELECT * FROM allowlist ORDER BY id DESC")

    def allowed_hashes(self) -> set[str]:
        return {r["key"] for r in self._all("SELECT key FROM allowlist WHERE kind='hash'")}

    def allowed_folders(self) -> list[dict]:
        return self._all("SELECT * FROM allowlist WHERE kind='folder'")

    # ---- verdicts (your own decisions; Phase 2 learns trust only from these) ------------
    def add_verdict(self, sha256: str, path: str, verdict: str, findings: list[dict]) -> int:
        cur = self._con().execute(
            "INSERT INTO verdicts(sha256, path, verdict, findings, created) VALUES(?,?,?,?,?)",
            (sha256, path, verdict, json.dumps(findings), time.time()))
        return int(cur.lastrowid)

    def list_verdicts(self, limit: int = 500) -> list[dict]:
        return self._all("SELECT * FROM verdicts ORDER BY id DESC LIMIT ?", (limit,))

    # ---- local learning (tacoguard/learning.py) ------------------------------------------
    def learning_stamp(self) -> tuple:
        """Changes whenever a verdict or a forgotten rule is added or removed (cheap)."""
        con = self._con()
        v = con.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM verdicts").fetchone()
        i = con.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM learning_ignores").fetchone()
        return (int(v[0]), int(v[1]), int(i[0]), int(i[1]))

    def learning_ignores(self) -> list[dict]:
        return self._all("SELECT * FROM learning_ignores ORDER BY id")

    def add_learning_ignore(self, engine: str, rule: str) -> None:
        self._con().execute("INSERT OR IGNORE INTO learning_ignores(engine, rule, created) VALUES(?,?,?)",
                            (engine, rule, time.time()))

    def remove_learning_ignore(self, engine: str, rule: str) -> int:
        cur = self._con().execute("DELETE FROM learning_ignores WHERE engine=? AND rule=?", (engine, rule))
        return cur.rowcount

    # ---- clean cache -----------------------------------------------------------------
    def cache_get(self, key: str, size: int, mtime_ns: int, sig_version: str) -> str | None:
        """sha256 of a file already found clean with these signatures, else None."""
        r = self._one("SELECT sha256 FROM cache WHERE key=? AND size=? AND mtime_ns=? AND sig_version=?",
                      (key, size, mtime_ns, sig_version))
        return r["sha256"] if r else None

    def cache_put(self, key: str, size: int, mtime_ns: int, sha256: str, sig_version: str) -> None:
        self._con().execute(
            "INSERT OR REPLACE INTO cache(key, size, mtime_ns, sha256, sig_version, checked) VALUES(?,?,?,?,?,?)",
            (key, size, mtime_ns, sha256, sig_version, time.time()))

    def cache_trim(self, max_rows: int = 400_000) -> None:
        """Keeps the cache well under 100 MB: drops the oldest rows past max_rows."""
        con = self._con()
        n = con.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        if n > max_rows:
            con.execute("DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY checked LIMIT ?)",
                        (n - max_rows,))

    # ---- small key/value state (meta table) --------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        r = self._one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        self._con().execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))

    # ---- Phase 3: guard events, paused programs, start-up entries ---------------------------
    def persistence_fingerprint(self) -> tuple:
        """Changes whenever a start-up row is added, changed or removed (cheap)."""
        r = self._con().execute("SELECT COUNT(*), COALESCE(MAX(last_seen), 0), "
                                "COALESCE(SUM(LENGTH(state)), 0) FROM persistence").fetchone()
        return (int(r[0]), float(r[1]), int(r[2]))

    def add_guard_event(self, kind: str, level: str, title: str, message: str = "", path: str = "",
                        sha256: str = "", findings: list | None = None, data: dict | None = None) -> int:
        cur = self._con().execute(
            "INSERT INTO guard_events(created, kind, level, title, message, path, sha256, findings, data) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (time.time(), kind, level, title, message, path, sha256, json.dumps(findings or []),
             json.dumps(data or {})))
        return int(cur.lastrowid)

    def get_guard_event(self, event_id: int) -> dict | None:
        r = self._one("SELECT * FROM guard_events WHERE id=?", (event_id,))
        return _decode_event(r) if r else None

    def list_guard_events(self, states: tuple[str, ...] | None = None, limit: int = 200,
                          after_id: int = 0) -> list[dict]:
        """Newest first. `after_id` returns only events newer than that id."""
        sql, args = "SELECT * FROM guard_events WHERE id>?", [after_id]
        if states:
            sql += f" AND state IN ({','.join('?' * len(states))})"
            args += list(states)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [_decode_event(r) for r in self._all(sql, tuple(args))]

    def set_guard_event(self, event_id: int, state: str | None = None, action: str | None = None,
                        data: dict | None = None, title: str | None = None,
                        message: str | None = None, level: str | None = None) -> None:
        sets, args = [], []
        for col, val in (("state", state), ("action", action), ("title", title), ("message", message),
                         ("level", level)):
            if val is not None:
                sets.append(f"{col}=?")
                args.append(val)
        if data is not None:
            sets.append("data=?")
            args.append(json.dumps(data))
        if sets:
            self._con().execute(f"UPDATE guard_events SET {', '.join(sets)} WHERE id=?", (*args, event_id))

    def trim_guard_events(self, keep: int = 5000) -> None:
        self._con().execute("DELETE FROM guard_events WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM "
                            "guard_events) - ? AND state='resolved'", (keep,))

    def add_paused(self, pid: int, create_time: float, exe: str, name: str, reason: str,
                   event_id: int = 0) -> int:
        now = time.time()
        cur = self._con().execute(
            "INSERT INTO paused(pid, create_time, exe, name, reason, event_id, paused_at, state, updated) "
            "VALUES(?,?,?,?,?,?,?,'paused',?)", (pid, create_time, exe, name, reason, event_id, now, now))
        return int(cur.lastrowid)

    def get_paused(self, paused_id: int) -> dict | None:
        return self._one("SELECT * FROM paused WHERE id=?", (paused_id,))

    def list_paused(self, states: tuple[str, ...] = ("paused",)) -> list[dict]:
        q = ",".join("?" * len(states))
        return self._all(f"SELECT * FROM paused WHERE state IN ({q}) ORDER BY id DESC", states)

    def set_paused_state(self, paused_id: int, state: str) -> None:
        """state: paused|resumed|ended|gone|not_paused (Windows refused the pause; it kept running)."""
        self._con().execute("UPDATE paused SET state=?, updated=? WHERE id=?", (state, time.time(), paused_id))

    def set_paused_event(self, paused_id: int, event_id: int) -> None:
        self._con().execute("UPDATE paused SET event_id=?, updated=? WHERE id=?",
                            (event_id, time.time(), paused_id))

    def get_persistence(self, key: str) -> dict | None:
        return self._one("SELECT * FROM persistence WHERE key=?", (key,))

    def list_persistence(self, states: tuple[str, ...] | None = None) -> list[dict]:
        if not states:
            return self._all("SELECT * FROM persistence ORDER BY source, name")
        q = ",".join("?" * len(states))
        return self._all(f"SELECT * FROM persistence WHERE state IN ({q}) ORDER BY first_seen DESC", states)

    def put_persistence(self, key: str, **fields) -> None:
        """Insert or update one start-up entry (fields: source, location, name, command, target,
        state, backup, event_id; first_seen/last_seen are kept up to date here)."""
        now = time.time()
        old = self.get_persistence(key)
        if old is None:
            row = {"source": "", "location": "", "name": "", "command": "", "target": "", "state": "new",
                   "backup": "", "event_id": 0, **fields}
            self._con().execute(
                "INSERT INTO persistence(key, source, location, name, command, target, first_seen, "
                "last_seen, state, backup, event_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (key, row["source"], row["location"], row["name"], row["command"], row["target"], now, now,
                 row["state"], row["backup"], int(row["event_id"])))
            return
        allowed = {"source", "location", "name", "command", "target", "state", "backup", "event_id"}
        sets = [f"{k}=?" for k in fields if k in allowed]
        args = [fields[k] for k in fields if k in allowed]
        self._con().execute(f"UPDATE persistence SET {', '.join(sets + ['last_seen=?'])} WHERE key=?",
                            (*args, now, key))

    # ---- Phase 4: MalwareBazaar lookup cache --------------------------------------------------
    def get_lookup(self, sha256: str) -> dict | None:
        r = self._one("SELECT * FROM lookups WHERE sha256=?", (sha256.lower(),))
        if r:
            r["data"] = json.loads(r["data"] or "{}")
            r["found"] = bool(r["found"])
        return r

    def put_lookup(self, sha256: str, found: bool, data: dict | None = None) -> None:
        self._con().execute("INSERT OR REPLACE INTO lookups(sha256, found, data, checked) VALUES(?,?,?,?)",
                            (sha256.lower(), int(bool(found)), json.dumps(data or {}), time.time()))

    def delete_persistence(self, key: str) -> None:
        self._con().execute("DELETE FROM persistence WHERE key=?", (key,))


def _decode_event(r: dict) -> dict:
    r["findings"] = json.loads(r["findings"] or "[]")
    r["data"] = json.loads(r["data"] or "{}")
    return r


def _decode_result(r: dict) -> dict:
    r["findings"] = json.loads(r["findings"])
    r["notes"] = json.loads(r["notes"])
    r["incomplete"] = bool(r["incomplete"])
    return r
