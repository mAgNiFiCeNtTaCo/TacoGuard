"""Local learning: TacoGuard adjusts trust ONLY from your own verdicts on the Detections page.

It never reads file contents for this, never trains a model and never uploads anything. All it
uses is the verdicts table (store.py): which files (by SHA-256) you called "not a threat" or
"it's a threat", and which rules matched them.

Two things are learned:

1. Rule feedback. When you marked files with at least LEARN_AFTER (3) DIFFERENT fingerprints as
   "not a threat", all matched by the same rule (engine + rule name), and you never confirmed a
   file matching that rule as a threat, that rule counts for less: its findings drop one
   confidence step (high -> medium, medium -> low; low stays low) with a plain note. One
   "it's a threat" for the rule cancels this. Exact known-bad fingerprints (engine "hash") are
   never softened, and neither is the machine-learning check (engine "ml"): all its findings
   share one rule name, so learning it would switch the whole check off after three clicks.
   The page can forget a learned rule (forget_rule); it is then not learned
   again until you choose "Use again" (unforget_rule).
2. Your own known-bad list. Every file you confirmed as a threat goes (by fingerprint) into
   <hashsets>/your-confirmed-threats.txt, so the known-bad check flags copies of it anywhere with
   high confidence. If you later say "not a threat" for the same fingerprint it is taken off.

For each fingerprint only your LATEST verdict counts (you can change your mind).
settings.learning_enabled False: nothing is adjusted and your known-bad list file is removed
(it is rebuilt from the verdicts when learning is turned on again).

    adjust(findings, store, settings) -> (findings, notes)     called by scan/engine.py per file
    learned_rules(store) -> [{engine, rule, safe_files, since, active, state}]
    forget_rule(store, engine, rule) / unforget_rule(store, engine, rule)
    sync_confirmed_list(store, settings) -> int                called by the page after a verdict
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import replace
from pathlib import Path

from .model import Confidence, Finding

LEARN_AFTER = 3                                   # different files marked safe for one rule
CONFIRMED_LIST = "your-confirmed-threats.txt"     # in settings.hashset_dir
NOT_A_THREAT = "not_a_threat"
CONFIRMED = "confirmed_threat"
# exact fingerprints are never softened (your known-bad list, a MalwareBazaar lookup); the ML
# check has one rule name for every finding
NOT_LEARNED_ENGINES = ("hash", "ml", "lookup")

ACTIVE, CANCELLED, FORGOTTEN = "active", "cancelled", "forgotten"
STATE_WORDS = {
    ACTIVE: "Counts for less now.",
    CANCELLED: "Back to normal: you confirmed a file matching this rule as a threat.",
    FORGOTTEN: "Forgotten: you asked TacoGuard to stop learning from this rule.",
}
READ_FAILED_NOTE = "Your earlier choices could not be read, so they were not used for this file."

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_cache: dict[str, tuple[tuple, dict]] = {}        # db path -> (store stamp, computed state)
_cache_lock = threading.Lock()


def lowered_detail(n: int) -> str:
    return f"you marked {n} files matching this rule as safe, so it counts for less"


# ---- reading the verdicts --------------------------------------------------------------------
def _findings_of(row: dict) -> list[dict]:
    raw = row.get("findings")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except ValueError:
            return []
    return [f for f in raw or [] if isinstance(f, dict)]


def _latest_verdicts(store) -> list[dict]:
    """Your latest verdict per fingerprint, oldest first. A verdict without a fingerprint
    (a file that could not be read) stands on its own."""
    rows = store.list_verdicts(limit=1_000_000)
    rows.sort(key=lambda r: r["id"])
    latest: dict[str, dict] = {}
    for r in rows:
        sha = (r.get("sha256") or "").strip().lower()
        latest[sha if sha else f"id:{r['id']}"] = dict(r, sha256=sha)
    return sorted(latest.values(), key=lambda r: r["id"])


def _compute(store) -> dict:
    safe: dict[tuple, dict[str, float]] = {}      # (engine, rule) -> {sha256: when}
    confirmed: set[tuple] = set()
    confirmed_files: dict[str, str] = {}          # sha256 -> path
    for v in _latest_verdicts(store):
        keys = {(str(f.get("engine", "")), str(f.get("rule", ""))) for f in _findings_of(v)}
        keys = {k for k in keys if k[0] and k[1]}
        if v["verdict"] == NOT_A_THREAT and v["sha256"]:
            for k in keys:
                if k[0] not in NOT_LEARNED_ENGINES:
                    safe.setdefault(k, {})[v["sha256"]] = float(v.get("created") or 0)
        elif v["verdict"] == CONFIRMED:
            confirmed.update(keys)
            if _SHA256.match(v["sha256"]):
                confirmed_files[v["sha256"]] = v.get("path") or ""
    ignored = {(r["engine"], r["rule"]): float(r["created"]) for r in store.learning_ignores()}
    rules: dict[tuple, dict] = {}
    for k, files in safe.items():
        if len(files) < LEARN_AFTER and k not in ignored:
            continue
        times = sorted(files.values())
        since = times[LEARN_AFTER - 1] if len(times) >= LEARN_AFTER else (times[-1] if times else 0.0)
        state = FORGOTTEN if k in ignored else CANCELLED if k in confirmed else ACTIVE
        if state == ACTIVE and len(files) < LEARN_AFTER:
            continue
        rules[k] = {"engine": k[0], "rule": k[1], "safe_files": len(files), "since": since,
                    "active": state == ACTIVE, "state": state}
    for k, when in ignored.items():               # forgotten rules stay listed, so they can be used again
        rules.setdefault(k, {"engine": k[0], "rule": k[1], "safe_files": len(safe.get(k, {})),
                             "since": when, "active": False, "state": FORGOTTEN})
    return {"rules": rules, "confirmed_files": confirmed_files, "safe": safe}


def _state(store) -> dict:
    stamp = store.learning_stamp()
    key = str(getattr(store, "path", id(store)))
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] == stamp:
            return hit[1]
    state = _compute(store)
    with _cache_lock:
        _cache[key] = (stamp, state)
    return state


# ---- used by the scan ------------------------------------------------------------------------
def adjust(findings: list[Finding], store, settings) -> tuple[list[Finding], list[str]]:
    """Lowers findings of rules you taught TacoGuard to trust less. Never raises."""
    if not findings or not getattr(settings, "learning_enabled", True):
        return findings, []
    try:
        rules = _state(store)["rules"]
    except Exception:
        return findings, [READ_FAILED_NOTE]
    out: list[Finding] = []
    for f in findings:
        learned = None if f.engine in NOT_LEARNED_ENGINES else rules.get((f.engine, f.rule))
        if learned and learned["active"] and f.confidence > Confidence.LOW:
            extra = lowered_detail(learned["safe_files"])
            f = replace(f, confidence=Confidence(int(f.confidence) - 1),
                        detail=f"{f.detail}; {extra}" if f.detail else extra)
        out.append(f)
    return out, []


# ---- used by the page ------------------------------------------------------------------------
def learned_rules(store) -> list[dict]:
    """[{engine, rule, safe_files, since, active, state, state_text}], newest first."""
    rules = [dict(r, state_text=STATE_WORDS[r["state"]]) for r in _state(store)["rules"].values()]
    return sorted(rules, key=lambda r: (-r["since"], r["engine"], r["rule"]))


def forget_rule(store, engine: str, rule: str) -> None:
    """Stop using (and stop learning) this rule's feedback. Your verdicts themselves are kept."""
    store.add_learning_ignore(engine, rule)


def unforget_rule(store, engine: str, rule: str) -> bool:
    return store.remove_learning_ignore(engine, rule) > 0


def safe_count(store, engine: str, rule: str) -> int:
    """How many different files matching this rule you marked as safe (latest verdicts)."""
    return len(_state(store)["safe"].get((engine, rule), {}))


def confirmed_count(store, settings) -> int:
    """How many fingerprints your own known-bad list holds (0 while learning is off)."""
    if not getattr(settings, "learning_enabled", True):
        return 0
    return len(_state(store)["confirmed_files"])


def confirmed_list_path(settings) -> Path:
    return Path(settings.hashset_dir) / CONFIRMED_LIST


def _label(path: str) -> str:
    name = re.split(r"[\\/]", path or "")[-1]
    name = re.sub(r"[#\r\n\t]", " ", name).strip()[:120]
    return f"you confirmed this file as a threat ({name})" if name else "you confirmed this file as a threat"


def sync_confirmed_list(store, settings) -> int:
    """Writes your known-bad list from your verdicts. Only touches the file when its content
    changes (a new file date means new signatures, so the clean-file cache is used less).
    Returns how many fingerprints it holds."""
    path = confirmed_list_path(settings)
    files = _state(store)["confirmed_files"] if getattr(settings, "learning_enabled", True) else {}
    if not files:
        if path.exists():
            path.unlink()
        return 0
    lines = ["# Your own known-bad list: files you confirmed as a threat on TacoGuard's page.",
             "# Written by TacoGuard from your choices; edits here are replaced."]
    lines += [f"{sha}  {_label(p)}" for sha, p in sorted(files.items())]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    try:
        if path.read_bytes() == data:
            return len(files)
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")      # not *.txt: the known-bad check never reads it
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return len(files)
