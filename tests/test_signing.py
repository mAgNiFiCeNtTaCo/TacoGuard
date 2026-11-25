"""False-positive fixes of 2026-11-23: ClamAV confidence by category, YARA tool rules, and the
signed-program rule (Windows' digital signature check)."""
from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from types import SimpleNamespace

import pytest

from samples import MARKER, WEAK_MARKER, eicar, sample_bytes
from tacoguard import allowlist, signing, winpath
from tacoguard.detect import clamav as C
from tacoguard.detect import yara_rules as Y
from tacoguard.model import (CLEAN, MALWARE, SIGNED_PHRASE, SUSPICIOUS, Confidence, FileResult,
                             Finding, ScanItem)
from tacoguard.scan import engine, walker

NOTEPAD = r"C:\Windows\System32\notepad.exe"      # catalog-signed on Windows 11
EXPLORER = r"C:\Windows\explorer.exe"             # signature inside the file


# ---- ClamAV: confidence by category ----------------------------------------------------------

@pytest.mark.parametrize("name,confidence,detail_start", [
    ("Win.Trojan.Agent-123-0", Confidence.HIGH, ""),
    ("Win.Ransomware.Lockbit-1-0", Confidence.HIGH, ""),
    ("Win.Malware.Generic-2-0.UNOFFICIAL", Confidence.HIGH, ""),
    ("Doc.Downloader.Emotet-3-0", Confidence.HIGH, ""),
    ("Win.Coinminer.Generic-4-0", Confidence.HIGH, ""),
    ("Win.Revoked.Cert-5-0", Confidence.HIGH, ""),
    ("Trojan.Agent-77", Confidence.HIGH, ""),                     # older name without a platform
    ("Win.Packed.Mikey-9859688-0", Confidence.MEDIUM, "packed program: the file is compressed"),
    ("Win.Packer.Themida-6-0", Confidence.MEDIUM, "packed program"),
    ("Win.Tool.Mimikatz-7-0", Confidence.MEDIUM, "tool:"),
    ("Win.Adware.Thing-8-0", Confidence.MEDIUM, "adware"),
    ("Win.Joke.Prank-9-0", Confidence.MEDIUM, "joke program"),
    ("Win.Countermeasure.X-10-0", Confidence.MEDIUM, "the file uses tricks"),
    ("Win.Proxy.Socks-11-0", Confidence.MEDIUM, "proxy program"),
    ("Win.Whatever.Thing-12-0", Confidence.MEDIUM, ""),            # unknown category
    ("PUA.Win.Tool.Thing-2", Confidence.MEDIUM, "potentially unwanted program"),
    ("PUA.Win.Trojan.Looks-3", Confidence.MEDIUM, "potentially unwanted program"),
    ("Heuristics.Encrypted.PDF", Confidence.LOW, "heuristic match"),
    ("Heuristics.Phishing.Email.SpoofedDomain", Confidence.LOW, "heuristic match"),
    ("Win.Test.EICAR_HDB-1", Confidence.HIGH, "antivirus test file (harmless)"),
    ("Eicar-Test-Signature", Confidence.HIGH, "antivirus test file (harmless)"),
])
def test_clamav_category_table(name, confidence, detail_start):
    f = C.make_finding(name)
    assert f.confidence == confidence and f.detail.startswith(detail_start), (name, f)
    assert f.source == C.OFFICIAL_SOURCE and f.rule == name.removesuffix(".UNOFFICIAL")
    if not detail_start:
        assert confidence == Confidence.MEDIUM or f.detail == ""


def test_clamav_signature_trust_exceptions():
    assert not C.signature_trust_applies("Win.Revoked.Cert-5-0")
    assert not C.signature_trust_applies("Win.Test.EICAR_HDB-1")
    assert not C.signature_trust_applies("Eicar-Test-Signature")
    assert C.signature_trust_applies("Win.Packed.Mikey-9859688-0")
    assert C.signature_trust_applies("Win.Trojan.Agent-1-0")


# ---- YARA: tool rules ------------------------------------------------------------------------

@pytest.mark.parametrize("name,tool", [
    ("SEKOIA_Tool_Nping_Strings", True),
    ("SIGNATURE_BASE_HKTL_Sentinelone_Remotepotato0_Privesc", True),
    ("FIREEYE_RT_Hacktool_MSIL_Sharphound_3", True),
    ("DITEKSHEN_INDICATOR_TOOL_PWS_Mimikatz", True),
    ("DITEKSHEN_INDICATOR_TOOLS_Localpotato", True),
    ("DITEKSHEN_PUA_Win_Ultrasurf", True),
    ("SIGNATURE_BASE_APT_HKTL_Proxy_Tool_Jun23_1", False),      # an APT group's tool
    ("SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_Strings", False),
    ("SIGNATURE_BASE_EXPL_HKTL_LNX_Dirtyfraglpe_May26", False),
    ("SIGNATURE_BASE_MAL_APT_NK_Andariel_HHSD_Filetransfertool", False),
    ("SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings", False),
    ("SIGNATURE_BASE_Generic_Stealer_Strings", False),
])
def test_yara_tool_rule_names(name, tool):
    assert Y.is_tool_rule(name) is tool


def _yara_finding(identifier, score, namespace="forge_sekoia", description="Detects NPing"):
    det = Y.YaraDetector(SimpleNamespace(yara_dir="."))
    det._sources = {"forge_sekoia": {"name": "SEKOIA", "license": "DRL 1.1"}}
    rule = SimpleNamespace(identifier=identifier, namespace=namespace,
                           metadata=[("score", score), ("description", description)])
    return det._finding(rule, "")


def test_yara_tool_rule_is_at_most_medium_with_plain_detail():
    f = _yara_finding("SEKOIA_Tool_Nping_Strings", 90)
    assert f.confidence == Confidence.MEDIUM
    assert f.detail == Y.TOOL_DETAIL + "; Detects NPing"
    assert _yara_finding("SEKOIA_Tool_Nping_Strings", 40).confidence == Confidence.LOW
    strong = _yara_finding("SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_Strings", 90)
    assert strong.confidence == Confidence.HIGH and strong.detail == "Detects NPing"
    # your own rules are never capped
    own = _yara_finding("My_Tool_Rule", 90, namespace=Y.CUSTOM_NAMESPACE)
    assert own.confidence == Confidence.HIGH


# ---- Windows' signature check ----------------------------------------------------------------

def test_catalog_signed_windows_file_is_valid():
    info = signing.check_signature(winpath.to_long(NOTEPAD))
    assert info.valid and info.signer == "Microsoft Windows", info


def test_embedded_signature_is_valid_and_fast():
    path = winpath.to_long(EXPLORER)
    info = signing.check_signature(path)
    assert info.valid and "Microsoft" in info.signer and "inside the file" in info.reason, info
    t = time.perf_counter()
    for _ in range(5):
        signing.check_signature(path)
    assert (time.perf_counter() - t) / 5 < 0.1          # explorer.exe is a few MB


def test_unsigned_and_non_programs_are_not_valid(tmp_path):
    exe = tmp_path / "unsigned.exe"
    exe.write_bytes(b"MZ" + b"\0" * 1022)
    info = signing.check_signature(winpath.to_long(str(exe)))
    assert not info.valid and info.signer == ""
    text = tmp_path / "note.txt"
    text.write_bytes(sample_bytes())
    t = time.perf_counter()
    info = signing.check_signature(winpath.to_long(str(text)))
    assert not info.valid and "not a Windows program" in info.reason
    assert time.perf_counter() - t < 0.05
    assert not signing.check_signature(winpath.to_long(str(tmp_path / "missing.exe"))).valid
    empty = tmp_path / "empty.dll"
    empty.write_bytes(b"")
    assert not signing.check_signature(winpath.to_long(str(empty))).valid


def test_tampered_signed_copy_is_not_valid(tmp_path):
    data = bytearray(open(EXPLORER, "rb").read())
    data[len(data) // 3] ^= 0xFF                        # one changed byte inside the signed code
    p = tmp_path / "explorer-copy.exe"
    p.write_bytes(bytes(data))
    info = signing.check_signature(winpath.to_long(str(p)))
    assert not info.valid and "changed after signing" in info.reason, info


def test_long_path_and_locked_file(tmp_path):
    deep = "\\\\?\\" + str(tmp_path)
    for i in range(6):
        deep += f"\\level{i}_" + "y" * 45
    os.makedirs(deep)
    path = deep + "\\explorer.exe"
    with open(EXPLORER, "rb") as src, open(path, "wb") as dst:
        dst.write(src.read())
    assert len(path) > 260
    assert signing.check_signature(path).valid
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    h = k32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)     # no sharing: locked
    assert h and h != wintypes.HANDLE(-1).value
    try:
        info = signing.check_signature(path)
    finally:
        k32.CloseHandle(wintypes.HANDLE(h))
    assert not info.valid and "could not be opened" in info.reason


# ---- the signed-program rule in the engine ---------------------------------------------------

class Fake:
    """Returns the given findings for any file containing MARKER (or always, with always=True)."""

    def __init__(self, name, findings, always=False, scans_members=True, members_only=False):
        self.name, self.findings, self.always, self.scans_members = name, findings, always, scans_members
        self.members_only = members_only

    def version(self):
        return "v1"

    def scan(self, item):
        if self.members_only and not item.member:
            return []
        data = item.data if item.data is not None else open(item.path, "rb").read()
        if self.always or MARKER in data:
            return [Finding(**vars(f)) for f in self.findings]    # fresh copies every time
        return []


def F(engine_name="clamav", rule="Win.Packed.Mikey-9859688-0", conf=Confidence.MEDIUM, detail=""):
    return Finding(engine_name, rule, conf, "tests", detail=detail)


@pytest.fixture
def signed(monkeypatch):
    calls = []

    def fake(path):
        calls.append(path)
        return signing.SignatureInfo(True, "NVIDIA Corporation", "signed (signature inside the file)")
    monkeypatch.setattr(signing, "check_signature", fake)
    return calls


def _entry(path):
    (e,) = [t for t in walker.walk([str(path)]) if isinstance(t, walker.FileEntry)]
    return e


def _check(settings, store, path, detectors):
    return engine.check_file(_entry(path), detectors, allowlist.TrustChecker(store), settings, store, "v1")


def _cached(store, path):
    e = _entry(path)
    return store.cache_get(winpath.norm_key(e.display), e.st.st_size, e.st.st_mtime_ns, "v1")


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "app.dll"
    p.write_bytes(sample_bytes())
    return p


def test_signed_file_weak_match_becomes_a_note_and_is_not_cached(settings, store, sample, signed):
    r = _check(settings, store, sample, [Fake("clamav", [C.make_finding("Win.Packed.Mikey-9859688-0")])])
    assert r.findings == [] and r.level == CLEAN and not engine.is_notable(r)
    assert r.notes == ["A weak match (ClamAV 'Win.Packed.Mikey-9859688-0', packed program) was ignored "
                       "because the file has a valid digital signature from NVIDIA Corporation."]
    assert r.reason() == r.notes[0] and "malware" not in r.reason()
    assert signed and signed[0].startswith("\\\\?\\")
    assert not _cached(store, sample)        # turning the setting off must check it again


def test_signed_file_several_weak_matches_one_note(settings, store, sample, signed):
    r = _check(settings, store, sample, [
        Fake("clamav", [C.make_finding("Win.Packed.Mikey-9859688-0")]),
        Fake("yara", [F("yara", "SEKOIA_Tool_Nping_Strings", detail=Y.TOOL_DETAIL)])])
    assert r.findings == [] and len(r.notes) == 1
    assert r.notes[0].startswith("2 weak matches (ClamAV 'Win.Packed.Mikey-9859688-0', packed program; "
                                 "YARA rule 'SEKOIA_Tool_Nping_Strings', tool detection) were ignored")


def test_signed_file_strong_match_is_lowered_never_hidden(settings, store, sample, signed):
    r = _check(settings, store, sample, [Fake("yara", [F("yara", "Fake_Strong", Confidence.HIGH, "desc")])])
    assert r.level == SUSPICIOUS and engine.is_notable(r)
    (f,) = r.findings
    assert f.confidence == Confidence.MEDIUM
    assert f.detail == ("desc; the file has a valid digital signature from NVIDIA Corporation; signed "
                        "malware exists (stolen certificates), so check before trusting it")
    assert "malware exists" in r.reason() and r.reason().startswith("Matched")


def test_signed_file_strong_match_keeps_a_second_engine(settings, store, sample, signed):
    """Two engines at medium after lowering: still malware (model.verdict_level)."""
    r = _check(settings, store, sample, [Fake("yara", [F("yara", "Weak_Yara")]),
                                         Fake("clamav", [F("clamav", "Win.Trojan.Agent-1-0", Confidence.HIGH)])])
    assert [x.confidence for x in r.findings] == [Confidence.MEDIUM, Confidence.MEDIUM]
    assert r.level == MALWARE


def test_unsigned_file_is_unchanged(settings, store, sample, monkeypatch):
    monkeypatch.setattr(signing, "check_signature", lambda p: signing.SignatureInfo(False, "", "not signed"))
    r = _check(settings, store, sample, [Fake("clamav", [C.make_finding("Win.Packed.Mikey-9859688-0")])])
    assert r.level == SUSPICIOUS and r.notes == []


def test_setting_off_and_clean_files_never_check_the_signature(settings, store, sample, tmp_path, signed):
    settings.trust_signed_programs = False
    r = _check(settings, store, sample, [Fake("clamav", [C.make_finding("Win.Packed.Mikey-9859688-0")])])
    assert r.level == SUSPICIOUS and signed == []
    settings.trust_signed_programs = True
    clean = tmp_path / "clean.dll"
    clean.write_bytes(b"MZ nothing here")
    r = _check(settings, store, clean, [Fake("clamav", [F()])])
    assert r.level == CLEAN and signed == [] and _cached(store, clean)


def test_hash_revoked_and_test_matches_are_not_softened(settings, store, sample, signed):
    r = _check(settings, store, sample, [Fake("hash", [F("hash", "known-bad", Confidence.HIGH)]),
                                         Fake("clamav", [C.make_finding("Win.Revoked.Cert-5-0")])])
    assert [x.confidence for x in r.findings] == [Confidence.HIGH, Confidence.HIGH] and signed == []
    r = _check(settings, store, sample, [Fake("clamav", [C.make_finding("Win.Test.EICAR_HDB-1")])])
    assert r.level == MALWARE and r.findings[0].detail == "antivirus test file (harmless)"


def test_archive_members_are_never_trusted_by_signature(settings, store, tmp_path, signed):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inner/app.dll", sample_bytes())
    p = tmp_path / "pack.zip"
    p.write_bytes(buf.getvalue())
    r = _check(settings, store, p, [Fake("yara", [F("yara", "Weak_Member")], members_only=True)])
    assert len(r.findings) == 1 and "app.dll" in r.findings[0].member and r.level == SUSPICIOUS
    assert signed == []


def test_pooled_clamav_findings_are_included(settings, store, sample, signed):
    """The rule runs after the pooled ClamAV check is merged (scan jobs use the pool)."""
    from concurrent.futures import ThreadPoolExecutor
    clam = Fake("clamav", [C.make_finding("Win.Packed.Mikey-9859688-0")], scans_members=False)
    clam.parallel = True
    with ThreadPoolExecutor(2) as pool:
        pending = engine.check_file(_entry(sample), [clam], allowlist.TrustChecker(store), settings,
                                    store, "v1", pool=pool)
        r = pending.result()
    assert r.findings == [] and SIGNED_PHRASE in r.notes[0]


def test_real_signed_file_with_a_strong_fake_match_is_suspicious(settings, store):
    """No monkeypatch: Windows' own check on notepad.exe (catalog-signed)."""
    r = _check(settings, store, NOTEPAD, [Fake("yara", [F("yara", "Fake_Strong", Confidence.HIGH)], always=True)])
    assert r.level == SUSPICIOUS
    assert "valid digital signature from Microsoft Windows" in r.findings[0].detail


def test_real_unsigned_file_keeps_its_result(settings, store, sample):
    r = _check(settings, store, sample, [Fake("yara", [F("yara", "Fake_Strong", Confidence.HIGH)])])
    assert r.level == MALWARE


def test_eicar_in_memory_is_never_softened(settings, signed):
    item = ScanItem(display="memory", data=eicar(), size=68)
    r = FileResult(path="memory", findings=[C.make_finding("Win.Test.EICAR_HDB-1")])
    assert engine._signature_trust(r, item, settings) is False and r.level == MALWARE and signed == []


def test_weak_marker_sample_unchanged_when_unsigned(settings, store, tmp_path):
    p = tmp_path / "weak.txt"
    p.write_bytes(b"x" + WEAK_MARKER)
    weak = Fake("yara", [F("yara", "TacoGuard_Test_Weak_Sample", Confidence.LOW)], always=True)
    r = _check(settings, store, p, [weak])
    assert r.level == SUSPICIOUS and r.notes == []
