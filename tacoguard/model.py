"""Shared data shapes and the plain-English wording of results.

Every module talks in these types. Wording rules (keep them):
- Only a strong result is called "malware". Anything weaker is "suspicious".
- Always say which rule or signature matched, where it comes from and how confident it is.
- Never scary words for low confidence.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def word(self) -> str:
        return {1: "low", 2: "medium", 3: "high"}[int(self)]


# Verdict levels for a whole file
CLEAN = "clean"
SUSPICIOUS = "suspicious"
MALWARE = "malware"

# FileResult.status values
SCANNED = "scanned"        # checked (look at level for the outcome)
TRUSTED = "trusted"        # on your allowlist (hash or folder); not checked
SKIPPED = "skipped"        # not checked on purpose: too big, online-only cloud file, link...
UNREADABLE = "unreadable"  # could not be read: in use by another program, no permission, vanished

ENGINE_NAMES = {
    "hash": "known-bad file list",
    "clamav": "ClamAV signature",
    "yara": "YARA rule",
    "ml": "machine-learning check",
}


@dataclass
class Finding:
    engine: str                 # "hash" | "clamav" | "yara"
    rule: str                   # signature / rule name, exactly as the source names it
    confidence: Confidence
    source: str                 # who wrote it, e.g. "ClamAV official signatures (Cisco Talos)",
                                # "YARA Forge: Signature Base (DRL 1.1)", "your known-bad list"
    detail: str = ""            # optional plain words: rule description, "potentially unwanted program"
    member: str = ""            # path inside an archive ("inner\\setup.exe"), "" = the file itself
    author: str = ""
    license: str = ""
    reference: str = ""         # URL of the rule / source

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = int(self.confidence)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["confidence"] = Confidence(int(d.get("confidence", 1)))
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**known)


@dataclass
class ScanItem:
    """One thing to check: a file on disk, or a file unpacked from an archive (in memory)."""
    display: str                # what people see: "Downloads\\a.zip > inner\\b.exe"
    path: str | None = None     # extended-length path on disk (winpath.to_long), when on disk
    data: bytes | None = None   # the content, when in memory (archive members, small files)
    size: int = 0
    member: str = ""            # path inside the outer archive, "" for the outer file
    depth: int = 0              # 0 = file on disk, 1 = inside one archive, ...


@dataclass
class FileResult:
    path: str                   # display path of the file on disk
    status: str = SCANNED
    sha256: str = ""
    size: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # plain English: "Password-protected archive: ..."
    incomplete: bool = False    # True when part of it could not be checked (archive limits, encrypted)

    @property
    def level(self) -> str:
        return verdict_level(self.findings)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "status": self.status, "sha256": self.sha256, "size": self.size,
            "findings": [f.to_dict() for f in self.findings], "notes": list(self.notes),
            "incomplete": self.incomplete, "level": self.level, "reason": self.reason(),
        }

    def reason(self) -> str:
        return explain(self)


def verdict_level(findings: list[Finding]) -> str:
    """HIGH from any engine -> malware. Two different engines at MEDIUM or above -> malware.
    Anything else that matched -> suspicious."""
    if not findings:
        return CLEAN
    if any(f.confidence >= Confidence.HIGH for f in findings):
        return MALWARE
    strong_engines = {f.engine for f in findings if f.confidence >= Confidence.MEDIUM}
    if len(strong_engines) >= 2:
        return MALWARE
    return SUSPICIOUS


def describe_finding(f: Finding) -> str:
    """"YARA rule 'X' (YARA Forge: Signature Base, high confidence)"."""
    what = ENGINE_NAMES.get(f.engine, f.engine)
    where = f" inside the archive at '{f.member}'" if f.member else ""
    extra = f"; {f.detail}" if f.detail else ""
    return f"{what} '{f.rule}'{where} ({f.source}, {f.confidence.word} confidence{extra})"


# ---- digital signatures (the scan engine's signed-program rule uses these words) -------------
SIGNED_PHRASE = "because the file has a valid digital signature from"
_SHORT_ENGINE = {"clamav": "ClamAV", "yara": "YARA rule", "hash": "known-bad list"}


def _short_finding(f: Finding) -> str:
    """"ClamAV 'Win.Packed.Mikey-9859688-0', packed program"."""
    label = f.detail.split(":", 1)[0].split(";", 1)[0].strip() if f.detail else ""
    text = f"{_SHORT_ENGINE.get(f.engine, f.engine)} '{f.rule}'"
    return f"{text}, {label}" if label and len(label) <= 40 else text


def signature_note(ignored: list[Finding], signer: str) -> str:
    """The note for weak matches dropped because the file is validly signed."""
    parts = [_short_finding(f) for f in ignored]
    if len(parts) == 1:
        return f"A weak match ({parts[0]}) was ignored {SIGNED_PHRASE} {signer}."
    return f"{len(parts)} weak matches ({'; '.join(parts)}) were ignored {SIGNED_PHRASE} {signer}."


def signed_strong_detail(signer: str) -> str:
    """Added to a strong match on a validly signed file (it is lowered to medium, never hidden)."""
    return (f"the file has a valid digital signature from {signer}; signed malware exists "
            "(stolen certificates), so check before trusting it")


def explain(r: FileResult) -> str:
    """One or two plain sentences saying why this file got its result."""
    if r.status == TRUSTED:
        return r.notes[0] if r.notes else "On your trusted list, so it was not checked."
    if r.status == SKIPPED:
        return r.notes[0] if r.notes else "Not checked."
    if r.status == UNREADABLE:
        return r.notes[0] if r.notes else "Could not be read."
    signed = [n for n in r.notes if SIGNED_PHRASE in n]
    notes = [n for n in r.notes if SIGNED_PHRASE not in n]
    if not r.findings:
        base = " ".join(signed) if signed else "No match in any signature or rule."
        if r.incomplete:
            base += " Part of it could not be checked: " + " ".join(notes)
        return base
    ordered = sorted(r.findings, key=lambda f: -int(f.confidence))
    parts = [describe_finding(f) for f in ordered[:3]]
    more = f" and {len(ordered) - 3} more" if len(ordered) > 3 else ""
    text = "Matched " + "; and ".join(parts) + more + "."
    if r.level == SUSPICIOUS:
        text += (" A single weaker match like this is sometimes a false alarm: game mods, trainers, "
                 "admin tools and packed programs often trigger them.")
    if r.incomplete and notes:
        text += " " + " ".join(notes)
    if signed:
        text += " " + " ".join(signed)
    return text


# Windows error codes (winerror) with words of our own. Anything else gets a generic phrase:
# raw exception text (Python internals, paths, codes) never reaches the page.
_WINERROR_WORDS = {
    2: "the file was not found", 3: "the folder was not found",
    5: "Windows refused access",
    15: "the drive was not found", 21: "the drive is not ready",
    23: "the disk could not be read (a data error)",
    32: "the file is in use by another program", 33: "the file is in use by another program",
    39: "the disk is full", 112: "the disk is full",
    123: "the file name is not valid", 206: "the file name or path is too long",
    225: "Windows' antivirus blocked the file", 226: "Windows' antivirus removed the file",
    1117: "an I/O device error (the disk or device may be failing or unplugged)",
    1224: "the file is in use by another program",
    1450: "Windows ran low on resources", 1455: "Windows ran low on memory",
    1920: "Windows could not open the file",
    10053: "the connection was lost", 10054: "the connection was lost",
    10060: "the connection timed out", 10061: "the connection was refused",
}
# The same for errno values (an OSError without a Windows code).
_ERRNO_WORDS = {2: "the file was not found", 13: "Windows refused access", 28: "the disk is full", 36: "the file name is too long"}
_TYPE_WORDS = ((FileNotFoundError, "the file was not found"), (PermissionError, "Windows refused access"),
               (TimeoutError, "it took too long"), (ConnectionError, "the connection was lost"),
               (IsADirectoryError, "it is a folder, not a file"),
               (NotADirectoryError, "part of the path is not a folder"),
               (FileExistsError, "a file with that name already exists"))
PLAIN_ERROR_GENERIC = "an unexpected problem"


def plain_error(exc: BaseException) -> str:
    """Words for an unexpected error, never Python's or Windows' own text (no "[WinError 32]",
    no internal messages). Known Windows errors get a short description, anything else a
    generic phrase. Meant to sit inside a sentence: f"Could not do X ({plain_error(e)})."."""
    if isinstance(exc, MemoryError):
        return "not enough memory"
    if not isinstance(exc, OSError):
        return PLAIN_ERROR_GENERIC
    code = getattr(exc, "winerror", None)
    if code is None:   # codes written into the message, e.g. OSError(22, "[WinError 1117] ...")
        m = re.search(r"\[WinError (-?\d+)\]", str(exc.strerror or ""))
        code = int(m.group(1)) if m else None
    if code in _WINERROR_WORDS:
        return _WINERROR_WORDS[code]
    for kind, words in _TYPE_WORDS:
        if isinstance(exc, kind):
            return words
    if exc.errno in _ERRNO_WORDS:
        return _ERRNO_WORDS[exc.errno]
    return PLAIN_ERROR_GENERIC
