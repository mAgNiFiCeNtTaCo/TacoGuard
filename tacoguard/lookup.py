"""MalwareBazaar (abuse.ch) hash lookup for files TacoGuard flagged.

    lookup(settings, store, sha256, force=False) -> dict | None
        {"found": bool, "signature": str, "file_type": str, "first_seen": str, "tags": [str],
         "link": "https://bazaar.abuse.ch/sample/<sha256>/", "checked": epoch, "cached": bool,
         "message": plain words}
        None when lookups are off (settings.lookup_enabled; `force` = the page's "Look up" button
        ignores the switch), no key is set, the hourly limit is reached, or abuse.ch could not be
        asked or answered oddly. Never raises. status(store) says why in plain words.
    finding_for(info, signed=None) -> Finding | None   a "lookup" finding for a known file, else
                                             None: HIGH only with a malware name AND signed=False
                                             (no valid digital signature), otherwise MEDIUM
    ready(settings) -> bool                  lookups on and a key saved (no network, no decrypting)
    status(store) -> {"state", "message", "when"}   the last outcome, for the page
    NOT_FOUND_NOTE                           the note callers add when MalwareBazaar doesn't know it

Only the SHA-256 hash is sent (POST https://mb-api.abuse.ch/api/v1/, query=get_info, the user's
key in the Auth-Key header). Never the file, its name or its contents. Answers are cached in the
store's lookups table: 7 days for a known file, 1 day for "not known". At most 30 questions an
hour (counted in store meta, so restarts and other TacoGuard processes share the count). After an
offline / error answer TacoGuard waits 5 minutes, after a refused key until the key is saved again
(or an hour), before it asks again on its own. abuse.ch's data is never used to train anything.
"""
from __future__ import annotations

import http.client
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import secrets
from .model import Confidence, Finding, plain_error

log = logging.getLogger("tacoguard.lookup")

API_URL = "https://mb-api.abuse.ch/api/v1/"
SAMPLE_URL = "https://bazaar.abuse.ch/sample/{}/"
SOURCE = "MalwareBazaar (abuse.ch)"
ENGINE = "lookup"
TIMEOUT_S = 10
MAX_ANSWER = 1024 * 1024
FOUND_TTL_S = 7 * 24 * 3600
NOT_FOUND_TTL_S = 24 * 3600
FORCE_FRESH_S = 600                  # the "Look up" button reuses an answer this new
RATE_MAX = 30
RATE_WINDOW_S = 3600
ERROR_BACKOFF_S = 300
AUTH_BACKOFF_S = 3600

RATE_META = "lookup_rate"
STATUS_META = "lookup_status"

NOT_FOUND_NOTE = "MalwareBazaar doesn't know this exact file."
AUTH_MSG = ("abuse.ch didn't accept your key. Check it on auth.abuse.ch and paste it again in "
            "Settings.")
OFFLINE_MSG = "Could not reach MalwareBazaar (abuse.ch). TacoGuard will try again later."
ODD_MSG = "MalwareBazaar sent an answer TacoGuard could not read. TacoGuard will try again later."
LIMIT_MSG = (f"TacoGuard asks MalwareBazaar at most {RATE_MAX} times an hour, and that many were "
             "asked already. It will ask again later.")
BUSY_MSG = "MalwareBazaar is busy right now. TacoGuard will try again later."
NO_KEY_MSG = "Add your free abuse.ch key in Settings to look files up on MalwareBazaar."
OFF_MSG = "MalwareBazaar lookups are switched off in Settings."

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AUTH_STATES = {"no_api_key", "unknown_auth_key", "invalid_auth_key", "wrong_auth_key",
                "user_blacklisted", "unauthorized", "unknown_api_key", "invalid_api_key"}
_NOT_FOUND_STATES = {"hash_not_found", "no_results"}
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


class _Odd(Exception):
    """abuse.ch answered something TacoGuard can't use."""


class _Auth(Exception):
    pass


class _Busy(Exception):
    pass


# ---- HTTP (faked in tests) -------------------------------------------------------------------
class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None          # never follow: the key must not go anywhere else


def _open_request(req: urllib.request.Request, timeout: float):
    """Opens the request (TLS certificate checked). Tests replace this function."""
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirects())
    return opener.open(req, timeout=timeout)


def _read_capped(resp) -> bytes:
    body = resp.read(MAX_ANSWER + 1)
    if len(body) > MAX_ANSWER:
        raise _Odd("answer too big")
    return body


def _ask(key: str, sha256: str) -> dict:
    """One POST to MalwareBazaar. Returns the parsed JSON answer (a dict), or raises
    _Auth / _Busy / _Odd / OSError (offline, timeout)."""
    from .setup_fetch import USER_AGENT, _check_url
    _check_url(API_URL)                              # must be in config.ENDPOINTS
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("ascii")
    req = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "User-Agent": USER_AGENT, "Accept": "application/json", "Auth-Key": key,
        "Content-Type": "application/x-www-form-urlencoded"})
    try:
        resp = _open_request(req, TIMEOUT_S)
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            text = _read_capped(e)
        except Exception:
            text = b""
        finally:
            e.close()
        if code in (401, 403):
            raise _Auth() from None
        if code == 429 or code >= 500:
            raise _Busy() from None
        doc = _parse(text, strict=False)
        if doc is not None and str(doc.get("query_status", "")) in _AUTH_STATES:
            raise _Auth() from None
        raise _Odd(f"http {code}") from None
    except urllib.error.URLError:
        raise OSError("offline") from None
    try:
        return _parse(_read_capped(resp), strict=True)
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _parse(body: bytes, strict: bool) -> dict | None:
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        if strict:
            raise _Odd("not json") from None
        return None
    if not isinstance(doc, dict):
        if strict:
            raise _Odd("not an object")
        return None
    return doc


def _text(v, limit: int) -> str:
    if v is None or isinstance(v, (dict, list)):
        return ""
    return _CTRL.sub(" ", str(v)).strip()[:limit]


def _info_from_answer(doc: dict, sha256: str) -> dict:
    """{"found": ..., ...} from a parsed answer; raises _Auth / _Odd."""
    state = str(doc.get("query_status") or "").strip().lower()
    if state in _NOT_FOUND_STATES:
        return {"found": False}
    if state in _AUTH_STATES or "auth" in state or "api_key" in state:
        raise _Auth()
    if state != "ok":
        raise _Odd(f"query_status {state[:40]!r}")
    data = doc.get("data")
    entry = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else None
    if entry is None:
        raise _Odd("no data")
    got = str(entry.get("sha256_hash") or "").strip().lower()
    if got and got != sha256:
        raise _Odd("another file's answer")
    tags = entry.get("tags")
    tags = [t for t in (_text(x, 50) for x in tags[:20]) if t] if isinstance(tags, list) else []
    return {"found": True, "signature": _text(entry.get("signature"), 100),
            "file_type": _text(entry.get("file_type"), 30),
            "first_seen": _text(entry.get("first_seen"), 30), "tags": tags}


# ---- shared state (store meta) ---------------------------------------------------------------
def _meta(store, key: str):
    try:
        return json.loads(store.get_meta(key) or "null")
    except (ValueError, TypeError):
        return None


def status(store) -> dict:
    """The last lookup outcome: {"state": ""|ok|auth|offline|error|busy|limit, "message", "when"}."""
    d = _meta(store, STATUS_META)
    d = d if isinstance(d, dict) else {}
    return {"state": str(d.get("state") or ""), "message": str(d.get("message") or ""),
            "when": float(d.get("when") or 0)}


def _set_status(store, state: str, message: str, key_stamp: str = "") -> None:
    try:
        store.set_meta(STATUS_META, json.dumps({"state": state, "message": message, "when": time.time(),
                                                "key_stamp": key_stamp}))
    except Exception:
        pass


def _backing_off(store, key_stamp: str) -> bool:
    d = _meta(store, STATUS_META)
    if not isinstance(d, dict):
        return False
    age = time.time() - float(d.get("when") or 0)
    state = d.get("state")
    if state == "auth":
        return d.get("key_stamp") == key_stamp and age < AUTH_BACKOFF_S
    return state in ("offline", "error", "busy") and age < ERROR_BACKOFF_S


def _take_rate_slot(store) -> bool:
    """Counts one question against the hourly limit. False when the limit is reached. One SQLite
    write transaction, so the page, the guard and a scan worker never ask more than 30 together."""
    con = store._con()
    now = time.time()
    con.execute("BEGIN IMMEDIATE")
    try:
        row = con.execute("SELECT value FROM meta WHERE key=?", (RATE_META,)).fetchone()
        try:
            stamps = json.loads(row[0]) if row else []
        except (ValueError, TypeError):
            stamps = []
        if not isinstance(stamps, list):
            stamps = []
        stamps = [float(t) for t in stamps if isinstance(t, (int, float)) and now - RATE_WINDOW_S < t <= now + 60]
        ok = len(stamps) < RATE_MAX
        if ok:
            stamps.append(now)
            con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (RATE_META, json.dumps(stamps)))
        con.execute("COMMIT")
        return ok
    except BaseException:
        con.execute("ROLLBACK")
        raise


def rate_left(store) -> int:
    """How many lookups are left this hour."""
    stamps = _meta(store, RATE_META)
    now = time.time()
    used = len([t for t in stamps if isinstance(t, (int, float)) and now - RATE_WINDOW_S < t]) \
        if isinstance(stamps, list) else 0
    return max(0, RATE_MAX - used)


# ---- the lookup ------------------------------------------------------------------------------
def ready(settings) -> bool:
    return bool(getattr(settings, "lookup_enabled", False)) and secrets.has_key(settings, secrets.ABUSECH)


def _result(sha256: str, found: bool, data: dict, checked: float, cached: bool) -> dict:
    info = {"found": bool(found), "signature": str(data.get("signature") or ""),
            "file_type": str(data.get("file_type") or ""), "first_seen": str(data.get("first_seen") or ""),
            "tags": [str(t) for t in (data.get("tags") or []) if isinstance(t, str)],
            "link": SAMPLE_URL.format(sha256), "checked": float(checked), "cached": cached}
    info["message"] = found_words(info) if found else NOT_FOUND_NOTE
    return info


def found_words(info: dict) -> str:
    """Plain words for a "known" answer, true whatever the file is: MalwareBazaar holds a copy
    (anyone can upload a file there, so this alone is not proof)."""
    sig = info.get("signature") or ""
    text = f"MalwareBazaar has a copy of this exact file, uploaded as '{sig or 'unnamed'}'"
    if info.get("first_seen"):
        text += f" (first seen {info['first_seen']})"
    return text + "."


def lookup(settings, store, sha256: str, force: bool = False) -> dict | None:
    try:
        return _lookup(settings, store, sha256, force)
    except Exception as e:           # never raises; never the key in a log line
        log.info("MalwareBazaar lookup failed (%s)", plain_error(e))
        return None


def _lookup(settings, store, sha256: str, force: bool) -> dict | None:
    sha256 = str(sha256 or "").strip().lower()
    if not _SHA256.match(sha256):
        return None
    if not force and not getattr(settings, "lookup_enabled", False):
        return None
    cached = store.get_lookup(sha256)
    if cached:
        age = time.time() - float(cached["checked"] or 0)
        ttl = FORCE_FRESH_S if force else (FOUND_TTL_S if cached["found"] else NOT_FOUND_TTL_S)
        if 0 <= age < ttl:
            return _result(sha256, cached["found"], cached["data"] or {}, cached["checked"], True)
    key = secrets.get_key(settings, secrets.ABUSECH)
    if not key:
        if force:
            _set_status(store, "no_key", NO_KEY_MSG)
        return None
    stamp = secrets.key_stamp(settings, secrets.ABUSECH)
    if not force and _backing_off(store, stamp):
        return None
    if not _take_rate_slot(store):
        _set_status(store, "limit", LIMIT_MSG, stamp)
        log.info("MalwareBazaar lookup skipped: the hourly limit is reached")
        return None
    short = sha256[:12]
    try:
        doc = _ask(key, sha256)
        info = _info_from_answer(doc, sha256)
    except _Auth:
        _set_status(store, "auth", AUTH_MSG, stamp)
        log.info("MalwareBazaar lookup: abuse.ch did not accept the key")
        return None
    except _Busy:
        _set_status(store, "busy", BUSY_MSG, stamp)
        log.info("MalwareBazaar lookup: abuse.ch is busy")
        return None
    except _Odd as e:
        _set_status(store, "error", ODD_MSG, stamp)
        log.info("MalwareBazaar lookup of %s: unusable answer (%s)", short, e)
        return None
    except (OSError, http.client.HTTPException) as e:
        _set_status(store, "offline", OFFLINE_MSG, stamp)
        log.info("MalwareBazaar lookup of %s: could not reach abuse.ch (%s)", short, type(e).__name__)
        return None
    found = info.pop("found")
    store.put_lookup(sha256, found, info)
    now = time.time()
    _set_status(store, "ok", "MalwareBazaar answered.", stamp)
    log.info("MalwareBazaar lookup of %s: %s", short, "known" if found else "not known")
    return _result(sha256, found, info, now, False)


def finding_for(info: dict | None, signed: bool | None = None) -> Finding | None:
    """A "lookup" finding when MalwareBazaar knows this exact file; None otherwise (the caller adds
    NOT_FOUND_NOTE for a "not known" answer).

    HIGH only when the answer names the malware (a non-empty signature) AND the file has no valid
    digital signature (`signed` is False: the caller checked with signing.check_signature).
    Otherwise (no name, a signed file, or the signature not checked) MEDIUM: "MalwareBazaar has
    a copy of this file (uploaded as ...), which is not proof on its own." Anyone can upload a
    file to MalwareBazaar, signed installers included."""
    if not info or not info.get("found"):
        return None
    sig = str(info.get("signature") or "")
    seen = f", first seen {info['first_seen']}" if info.get("first_seen") else ""
    if sig and signed is False:
        conf = Confidence.HIGH
        detail = f"MalwareBazaar lists this exact file as '{sig}' malware{seen}"
    else:
        conf = Confidence.MEDIUM
        detail = (f"MalwareBazaar has a copy of this file (uploaded as '{sig or 'unnamed'}'), which is not "
                  f"proof on its own{seen}")
        if signed:
            detail += "; the file has a valid digital signature"
    if info.get("file_type"):
        detail += f" ({info['file_type']} file)"
    return Finding(engine=ENGINE, rule=sig or "unnamed upload", confidence=conf, source=SOURCE,
                   detail=detail, author="abuse.ch", license="abuse.ch terms of use",
                   reference=str(info.get("link") or ""))
