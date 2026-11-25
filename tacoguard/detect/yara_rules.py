"""YARA detector (YARA-X) and the YARA Forge license filter.

Folder layout (settings.yara_dir):
    current/   yara-forge-rules-core.zip (the verified download, unchanged), meta.json,
               compiled-<key>.bin (compiled rules cache)
    previous/  the set before the last update
    custom/    your own *.yar / *.yara rules (optional)

The rule text is never unpacked to disk: Microsoft Defender's machine-learning scanner flags the
plain YARA Forge .yar file (it is full of malware strings), but leaves the zip alone. The license
filter runs on the text in memory before anything is compiled, so left-out rules never load.
Each source repository is compiled into its own namespace, which tells us where a match came from.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import zipfile
from dataclasses import dataclass, field
from importlib import metadata as _pkg_metadata
from pathlib import Path

import yara_x

from ..model import Confidence, Finding, ScanItem, plain_error
from .base import DetectorError, DetectorUnavailable

PACKAGE_NAME = "yara-forge-rules-core.zip"
META_NAME = "meta.json"
CUSTOM_NAMESPACE = "custom"
POLICY_PATH = Path(__file__).resolve().parents[1] / "data" / "yara_license_policy.json"
SCAN_TIMEOUT_S = 60
DETAIL_MAX = 200

_BLOCK_START = re.compile(r"(?m)^/\*\n \* YARA Rule Set\n")
_RULE_START = re.compile(r"(?m)^(?:(?:private|global)\s+)*rule\s+(\w+)")
_IMPORT = re.compile(r'(?m)^import[ \t]+"[^"]+"')
_META_STRING = re.compile(r'(?m)^\s+(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')


def yara_x_version() -> str:
    try:
        return _pkg_metadata.version("yara-x")
    except _pkg_metadata.PackageNotFoundError:
        return "unknown"


# ---------------------------------------------------------------------------------------------
# YARA Forge package layout
# ---------------------------------------------------------------------------------------------

@dataclass
class ForgeRule:
    name: str
    text: str
    meta: dict


@dataclass
class ForgeSource:
    name: str
    repo: str
    license_text: str
    declared: int                 # "Number of Rules" in the source's header block
    rules: list[ForgeRule] = field(default_factory=list)


def _header_field(head: str, label: str) -> str:
    m = re.search(rf"(?m)^ \* {re.escape(label)}: ?(.*)$", head)
    return m.group(1).strip() if m else ""


def _rule_meta(rule_text: str) -> dict:
    """String meta values. YARA Forge always writes meta first, so stop at strings:/condition:."""
    head = re.split(r"(?m)^\s+(?:strings|condition):", rule_text, maxsplit=1)[0]
    return {k: v for k, v in _META_STRING.findall(head)}


def _split_rules(body: str) -> list[ForgeRule]:
    """YARA Forge writes every rule header at the start of a line and indents everything inside a
    rule, so a column-0 'rule NAME' line is a rule start even if strings contain braces."""
    starts = list(_RULE_START.finditer(body))
    rules = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(body)
        text = body[m.start():end].rstrip() + "\n"
        rules.append(ForgeRule(m.group(1), text, _rule_meta(text)))
    return rules


def parse_forge_package(text: str) -> tuple[list[str], list[ForgeSource]]:
    """(import lines, sources) from a YARA Forge package file."""
    text = text.replace("\r\n", "\n")
    pieces = _BLOCK_START.split(text)
    imports = _IMPORT.findall(pieces[0])
    sources = []
    for piece in pieces[1:]:
        head, _, body = piece.partition("*/")
        license_text = head.split(" * LICENSE", 1)[1] if " * LICENSE" in head else ""
        license_text = "\n".join(line.lstrip(" *") for line in license_text.splitlines()).strip()
        declared = _header_field(head, "Number of Rules")
        sources.append(ForgeSource(
            name=_header_field(head, "Repository Name") or "unnamed source",
            repo=_header_field(head, "Repository"),
            license_text=license_text,
            declared=int(declared) if declared.isdigit() else -1,
            rules=_split_rules(body)))
    return imports, sources


# ---------------------------------------------------------------------------------------------
# License policy (data: tacoguard/data/yara_license_policy.json)
# ---------------------------------------------------------------------------------------------

def load_policy(path: Path = POLICY_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def policy_digest(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I | re.M)


def _denied(text: str, policy: dict) -> str:
    for d in policy.get("deny", []):
        if _rx(d["pattern"]).search(text or ""):
            return d["why"]
    return ""


def license_short(text: str, policy: dict) -> str:
    """The short license name for a license text, or "" when it is not a known allowed license.
    The match nearest the top wins: license files often quote other licenses further down
    (CAPE's GPL-3.0 file also mentions the Apache License of a bundled part)."""
    best = None
    for order, a in enumerate(policy.get("allow", [])):
        m = _rx(a["pattern"]).search(text or "")
        if m and (best is None or (m.start(), order) < best[0]):
            best = ((m.start(), order), a["short"])
    return best[1] if best else ""


def _source_decision(src: ForgeSource, policy: dict) -> tuple[str, str]:
    """(license short name, reason it is left out or "")."""
    text = src.license_text.strip()
    if not text or any(m.lower() in text.lower() for m in policy.get("no_license_markers", [])):
        return "", "no license file"
    if any(u.lower() in src.repo.lower() for u in policy.get("deny_source_urls", [])):
        return "", "source not allowed"
    why = _denied(text, policy)
    if why:
        return "", why
    short = license_short(text, policy)
    return (short, "") if short else ("", "license not recognised")


def _rule_denied(rule: ForgeRule, policy: dict) -> bool:
    url = rule.meta.get("source_url", "").lower()
    if any(u.lower() in url for u in policy.get("deny_source_urls", [])):
        return True
    return bool(_denied(rule.meta.get("license", ""), policy))


def _drop_dependents(kept: list[ForgeRule], dropped_names: set[str]) -> list[ForgeRule]:
    """A kept rule whose condition uses a left-out (private) rule would not compile: leave it out too."""
    changed = True
    while changed and dropped_names:
        changed = False
        names = re.compile(r"\b(" + "|".join(map(re.escape, sorted(dropped_names))) + r")\b")
        still = []
        for r in kept:
            if names.search(r.text.split("condition:", 1)[-1]):
                dropped_names.add(r.name)
                changed = True
            else:
                still.append(r)
        kept = still
    return kept


def _namespace(name: str, used: set[str]) -> str:
    base = "forge_" + (re.sub(r"\W+", "_", name).strip("_").lower() or "source")
    ns, n = base, 2
    while ns in used:
        ns, n = f"{base}_{n}", n + 1
    used.add(ns)
    return ns


def apply_policy(imports: list[str], sources: list[ForgeSource], policy: dict) -> list[dict]:
    """One entry per source: name, repo, namespace, license, kept, dropped, reason, text."""
    out, used = [], set()
    for src in sources:
        short, reason = _source_decision(src, policy)
        kept = [] if reason else [r for r in src.rules if not _rule_denied(r, policy)]
        dropped_names = {r.name for r in src.rules} - {r.name for r in kept}
        kept = _drop_dependents(kept, dropped_names)
        if not reason and len(kept) < len(src.rules):
            reason = "some rules have a non-commercial or excluded license"
        text = "\n".join(imports) + "\n\n" + "\n".join(r.text for r in kept) if kept else ""
        out.append({"name": src.name, "repo": src.repo, "namespace": _namespace(src.name, used),
                    "license": short, "kept": len(kept), "dropped": len(src.rules) - len(kept),
                    "declared": src.declared, "reason": reason, "text": text})
    return out


def read_package_text(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".yar")]
        if len(names) != 1:
            raise ValueError(f"expected one .yar file in the package, found {len(names)}")
        return z.read(names[0]).decode("utf-8", "replace")


def filtered_sources(folder: Path, policy: dict | None = None) -> list[dict]:
    imports, sources = parse_forge_package(read_package_text(folder / PACKAGE_NAME))
    return apply_policy(imports, sources, policy or load_policy())


# ---------------------------------------------------------------------------------------------
# Install (called by setup_fetch on a NEW folder before it is swapped in)
# ---------------------------------------------------------------------------------------------

def read_meta(folder: Path) -> dict:
    try:
        return json.loads((folder / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def install_package(zip_path: Path, folder: Path, release: str, sha256: str, published: str = "") -> dict:
    """Copy the verified zip into `folder`, run the license filter and write meta.json."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / PACKAGE_NAME).write_bytes(Path(zip_path).read_bytes())
    policy = load_policy()
    entries = filtered_sources(folder, policy)
    meta = {
        "release": release, "sha256": sha256, "published": published,
        "installed": time.strftime("%Y-%m-%d %H:%M:%S"), "policy_sha256": policy_digest(policy),
        "kept": sum(e["kept"] for e in entries), "dropped": sum(e["dropped"] for e in entries),
        "sources": [{k: v for k, v in e.items() if k != "text"} for e in entries],
    }
    (folder / META_NAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


# ---------------------------------------------------------------------------------------------
# Compiling (with a cache of the compiled rules for a fast start)
# ---------------------------------------------------------------------------------------------

def _custom_files(yara_dir: Path) -> list[Path]:
    folder = yara_dir / "custom"
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".yar", ".yara"))


def _custom_sources(yara_dir: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """([(file name, text)] that compile on their own, [plain-English problems])."""
    good, problems = [], []
    for p in _custom_files(yara_dir):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            c = yara_x.Compiler()
            c.enable_includes(False)
            c.add_source(text)
            good.append((p.name, text))
        except (OSError, yara_x.CompileError) as e:
            problems.append(f"Your rule file {p.name} has a problem and was skipped: {str(e).splitlines()[0]}")
    return good, problems


def _compile(namespaced: list[tuple[str, str]]) -> yara_x.Rules:
    c = yara_x.Compiler()
    c.enable_includes(False)
    for ns, text in namespaced:
        c.new_namespace(ns)
        c.add_source(text)
    return c.build()


def _cache_key(namespaced: list[tuple[str, str]]) -> str:
    h = hashlib.sha256(yara_x_version().encode())
    for ns, text in namespaced:
        h.update(b"\0" + ns.encode() + b"\0" + text.encode("utf-8"))
    return h.hexdigest()


def compile_folder(folder: Path, custom: list[tuple[str, str]] | None = None) -> tuple[yara_x.Rules, list[dict]]:
    """Compiled rules for a rule-set folder (+ custom rules), from the cache when it matches.
    Raises yara_x.CompileError / ValueError / OSError when the set cannot be built."""
    have_package = (folder / PACKAGE_NAME).exists()
    entries = filtered_sources(folder) if have_package else []
    namespaced = [(e["namespace"], e["text"]) for e in entries if e["text"]]
    namespaced += [(CUSTOM_NAMESPACE, text) for _, text in (custom or [])]
    if not namespaced:
        raise ValueError("no rules")
    if not have_package:
        return _compile(namespaced), entries       # only your own rules: quick, no cache needed
    key = _cache_key(namespaced)
    cache = folder / f"compiled-{key[:24]}.bin"
    if cache.exists():
        try:
            with open(cache, "rb") as f:
                return yara_x.Rules.deserialize_from(f), entries
        except Exception:
            cache.unlink(missing_ok=True)          # stale or broken cache: rebuild below
    rules = _compile(namespaced)
    for old in folder.glob("compiled-*.bin"):
        old.unlink(missing_ok=True)
    tmp = cache.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        rules.serialize_into(f)
    tmp.replace(cache)
    return rules, entries


# ---------------------------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------------------------

def score_confidence(score) -> Confidence:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return Confidence.MEDIUM
    if value >= 80:
        return Confidence.HIGH
    if value >= 60:
        return Confidence.MEDIUM
    return Confidence.LOW


# Rules whose names mark them as tool detections. Such rules also match legitimate admin and
# security programs (SEKOIA_Tool_Nping_Strings matches the real nping.exe from Nmap), so they
# give at most medium confidence. A name that also marks malware, an APT group's tool or an
# exploit keeps its score (e.g. SIGNATURE_BASE_APT_HKTL_Proxy_Tool_Jun23_1, HKTL_Cobaltstrike_*).
TOOL_WORDS = {"tool", "tools", "hktl", "hacktool", "pua", "recotool"}
STRONG_WORDS = {"apt", "mal", "malware", "expl", "exploit", "cobaltstrike", "ransom", "ransomware",
                "backdoor", "trojan", "webshell", "stealer", "infostealer"}
TOOL_DETAIL = "tool detection: also matches legitimate admin and security tools"


def is_tool_rule(name: str) -> bool:
    words = {w.lower() for w in name.split("_") if w}
    return bool(words & TOOL_WORDS) and not words & STRONG_WORDS


class YaraDetector:
    name = "yara"
    scans_members = True

    def __init__(self, settings, timeout_s: int = SCAN_TIMEOUT_S):
        self.yara_dir = Path(settings.yara_dir)
        self.timeout_s = timeout_s
        self._scanner: yara_x.Scanner | None = None
        self._sources: dict[str, dict] = {}       # namespace -> {"name", "license"}
        self._policy: dict = {}
        self._lock = threading.Lock()
        self.problems: list[str] = []

    @property
    def current(self) -> Path:
        return self.yara_dir / "current"

    def version(self) -> str:
        meta = read_meta(self.current)
        parts = [meta.get("release", "none"), str(meta.get("sha256", ""))[:12]]
        try:
            parts.append(policy_digest(load_policy())[:8])
        except (OSError, ValueError):
            pass
        custom = _custom_files(self.yara_dir)
        if custom:
            stamp = "|".join(f"{p.name}:{p.stat().st_mtime_ns}:{p.stat().st_size}" for p in custom)
            parts.append("c" + hashlib.sha256(stamp.encode()).hexdigest()[:10])
        return "yara-" + "-".join(parts)

    def status(self) -> dict:
        try:
            meta = read_meta(self.current)
            custom = _custom_files(self.yara_dir)
            have_forge = bool(meta) and (self.current / PACKAGE_NAME).exists()
            if have_forge:
                day = (meta.get("published") or "")[:10] or meta.get("installed", "")[:10]
                msg = (f"YARA Forge rules from {day} (release {meta.get('release')}, "
                       f"{meta.get('kept', 0)} rules)")
                msg += f" plus {len(custom)} file(s) of your own rules." if custom else "."
            elif custom:
                msg = f"Only your own YARA rules ({len(custom)} file(s)); YARA Forge rules not downloaded yet."
            else:
                msg = "Not downloaded yet: press Get signatures."
            updated = (self.current / META_NAME).stat().st_mtime if have_forge else 0.0
            return {"ready": have_forge or bool(custom), "message": msg, "version": self.version(),
                    "updated": updated, "count": int(meta.get("kept", 0)) if have_forge else 0}
        except Exception as e:  # status must never raise
            return {"ready": False, "message": f"Could not read the YARA rules: {plain_error(e)}",
                    "version": "yara-none", "updated": 0.0, "count": 0}

    def open(self) -> None:
        custom, self.problems = _custom_sources(self.yara_dir)
        try:
            rules, entries = compile_folder(self.current, custom)
        except ValueError:
            raise DetectorUnavailable("YARA rules have not been downloaded yet. Press Get signatures.")
        except (OSError, yara_x.CompileError, zipfile.BadZipFile) as e:
            raise DetectorUnavailable(f"The YARA rules could not be loaded ({str(e).splitlines()[0]}). "
                                      "Press Get signatures to download them again.") from e
        self._sources = {e["namespace"]: {"name": e["name"], "license": e["license"]} for e in entries}
        self._policy = load_policy()
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(self.timeout_s)
        self._scanner = scanner

    def scan(self, item: ScanItem) -> list[Finding]:
        if self._scanner is None:
            raise DetectorError("The YARA rules are not loaded.")
        with self._lock:
            try:
                if item.data is not None:
                    results = self._scanner.scan(item.data)
                elif item.path:
                    results = self._scanner.scan_file(item.path)
                else:
                    return []
            except yara_x.TimeoutError as e:
                raise DetectorError(f"The YARA check took longer than {self.timeout_s} seconds on this "
                                    "file, so it was stopped; checked with the other methods.") from e
            except yara_x.ScanError as e:
                why = str(e).rsplit(": ", 1)[-1]       # drop yara-x's "can not open `path`" prefix
                raise DetectorError(f"The YARA check could not read this file ({why}).") from e
        return [self._finding(rule, item.member) for rule in results.matching_rules]

    def _finding(self, rule, member: str) -> Finding:
        meta = {k: v for k, v in rule.metadata}
        desc = str(meta.get("description", ""))
        reference = str(meta.get("source_url") or meta.get("reference") or "")
        if rule.namespace == CUSTOM_NAMESPACE:
            source, lic = "your own rules", str(meta.get("license", ""))
        else:
            src = self._sources.get(rule.namespace, {"name": rule.namespace, "license": ""})
            # a rule may carry its own (allowed) license inside a source, e.g. CC BY 4.0
            lic = license_short(str(meta.get("license", "")), self._policy) or src["license"]
            source = f"YARA Forge: {src['name']} ({lic})" if lic else f"YARA Forge: {src['name']}"
        confidence = score_confidence(meta.get("score"))
        detail = desc if len(desc) <= DETAIL_MAX else ""
        if rule.namespace != CUSTOM_NAMESPACE and is_tool_rule(rule.identifier):
            confidence = min(confidence, Confidence.MEDIUM)
            detail = f"{TOOL_DETAIL}; {detail}" if detail else TOOL_DETAIL
        return Finding("yara", rule.identifier, confidence, source, detail=detail, member=member,
                       author=str(meta.get("author", "")), license=lic, reference=reference)

    def close(self) -> None:
        self._scanner = None
