"""Local learning (tacoguard/learning.py): trust adjusted only from the user's own verdicts."""
from __future__ import annotations

import hashlib
import time

import pytest

from tacoguard import allowlist, learning
from tacoguard.detect.hashsets import HashDetector
from tacoguard.model import Confidence, FileResult, Finding, ScanItem


def _f(rule="Win.Packed.Mikey-1", engine="clamav", conf=Confidence.HIGH, member=""):
    return Finding(engine, rule, conf, "tests", member=member)


def _sha(i) -> str:
    return hashlib.sha256(f"file {i}".encode()).hexdigest()


def _verdict(store, i, verdict="not_a_threat", findings=None, path=None):
    findings = findings if findings is not None else [_f()]
    return store.add_verdict(_sha(i) if isinstance(i, int) else i, path or f"D:\\Games\\mod{i}.exe",
                             verdict, [f.to_dict() for f in findings])


def _adjust(store, settings, findings):
    return learning.adjust([Finding.from_dict(f.to_dict()) for f in findings], store, settings)


# ---- rule feedback -----------------------------------------------------------------------------
def test_three_different_files_lower_the_rule_one_step(store, settings):
    for i in range(2):
        _verdict(store, i)
    out, notes = _adjust(store, settings, [_f()])
    assert out[0].confidence == Confidence.HIGH and notes == []          # 2 files: not yet
    _verdict(store, 2)
    out, notes = _adjust(store, settings, [_f(), _f("Other_Rule"), _f(conf=Confidence.MEDIUM),
                                           _f(conf=Confidence.LOW)])
    assert [int(f.confidence) for f in out] == [2, 3, 1, 1]
    assert out[0].detail == "you marked 3 files matching this rule as safe, so it counts for less"
    assert out[1].detail == "" and out[3].detail == ""                    # low stays low, untouched
    assert notes == []
    # the verdict level follows: one ClamAV match at medium is suspicious, not malware
    assert FileResult("x", findings=out[:1]).level == "suspicious"


def test_same_file_marked_three_times_counts_once(store, settings):
    for _ in range(3):
        _verdict(store, 7)
    _verdict(store, 8)
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH
    assert learning.learned_rules(store) == []
    assert learning.safe_count(store, "clamav", "Win.Packed.Mikey-1") == 2


def test_rule_is_engine_and_name(store, settings):
    for i in range(3):
        _verdict(store, i, findings=[_f(engine="yara", rule="Same_Name")])
    out, _ = _adjust(store, settings, [_f(engine="clamav", rule="Same_Name"), _f(engine="yara", rule="Same_Name")])
    assert [int(f.confidence) for f in out] == [3, 2]


def test_confirmed_threat_cancels_the_rule(store, settings):
    for i in range(4):
        _verdict(store, i)
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.MEDIUM
    _verdict(store, 99, "confirmed_threat")
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH
    (rule,) = learning.learned_rules(store)
    assert rule["active"] is False and rule["state"] == learning.CANCELLED and rule["safe_files"] == 4


def test_latest_verdict_per_file_counts(store, settings):
    for i in range(3):
        _verdict(store, i)
    _verdict(store, 2, "confirmed_threat")          # changed their mind about file 2
    out, _ = _adjust(store, settings, [_f()])
    assert out[0].confidence == Confidence.HIGH        # 2 safe files left, and a confirmed one
    _verdict(store, 2, "not_a_threat")                 # and back again
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.MEDIUM


def test_known_bad_hash_matches_are_never_softened(store, settings):
    for i in range(5):
        _verdict(store, i, findings=[_f(engine="hash", rule="from a list")])
    assert _adjust(store, settings, [_f(engine="hash", rule="from a list")])[0][0].confidence == Confidence.HIGH
    assert learning.learned_rules(store) == []


def test_machine_learning_findings_are_never_softened(store, settings):
    """All ML findings share one rule name, so learning it would switch the ML check off."""
    ml = lambda: _f(engine="ml", rule="EMBER2024 PE model", conf=Confidence.MEDIUM)
    for i in range(5):
        _verdict(store, i, findings=[ml()])
    out, notes = _adjust(store, settings, [ml()])
    assert out[0].confidence == Confidence.MEDIUM and notes == []
    assert learning.learned_rules(store) == []
    assert learning.safe_count(store, "ml", "EMBER2024 PE model") == 0


def test_archive_member_findings_are_lowered_too(store, settings):
    for i in range(3):
        _verdict(store, i, findings=[_f(member="inner\\a.exe")])
    out, _ = _adjust(store, settings, [_f(member="other\\b.exe")])
    assert out[0].confidence == Confidence.MEDIUM and out[0].member == "other\\b.exe"


def test_learning_disabled_changes_nothing(store, settings):
    for i in range(3):
        _verdict(store, i)
    settings.learning_enabled = False
    findings = [_f()]
    out, notes = learning.adjust(findings, store, settings)
    assert out is findings and out[0].confidence == Confidence.HIGH and notes == []


def test_forget_and_use_again(store, settings):
    for i in range(3):
        _verdict(store, i)
    learning.forget_rule(store, "clamav", "Win.Packed.Mikey-1")
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH
    _verdict(store, 3)                                 # more safe files: still not re-learned
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH
    (rule,) = learning.learned_rules(store)
    assert rule["state"] == learning.FORGOTTEN and rule["safe_files"] == 4 and not rule["active"]
    assert learning.unforget_rule(store, "clamav", "Win.Packed.Mikey-1") is True
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.MEDIUM
    assert learning.unforget_rule(store, "clamav", "Win.Packed.Mikey-1") is False


def test_learned_rules_list_for_the_page(store, settings):
    t0 = time.time()
    for i in range(3):
        _verdict(store, i)
    for i in range(3, 6):
        _verdict(store, i, findings=[_f(engine="yara", rule="Tool_Rule")])
    rules = learning.learned_rules(store)
    assert {(r["engine"], r["rule"]) for r in rules} == {("clamav", "Win.Packed.Mikey-1"), ("yara", "Tool_Rule")}
    for r in rules:
        assert set(r) >= {"engine", "rule", "safe_files", "since", "active", "state", "state_text"}
        assert r["safe_files"] == 3 and r["active"] is True and r["since"] >= t0 - 1


def test_computation_is_cached_until_the_verdicts_change(store, settings, monkeypatch):
    for i in range(3):
        _verdict(store, i)
    calls = []
    real = learning._compute
    monkeypatch.setattr(learning, "_compute", lambda s: calls.append(1) or real(s))
    for _ in range(5):
        _adjust(store, settings, [_f()])
    assert len(calls) == 1
    _verdict(store, 3)
    _adjust(store, settings, [_f()])
    learning.forget_rule(store, "clamav", "Win.Packed.Mikey-1")
    _adjust(store, settings, [_f()])
    assert len(calls) == 3


def test_a_broken_store_never_breaks_the_scan(settings):
    class Broken:
        path = "nowhere"

        def learning_stamp(self):
            raise OSError("database is locked")
    findings = [_f()]
    out, notes = learning.adjust(findings, Broken(), settings)
    assert out == findings and notes == [learning.READ_FAILED_NOTE]


def test_verdicts_from_the_real_allowlist_flow(store, settings):
    """The page's buttons store the findings as dicts; learning reads exactly those."""
    job = store.create_job(["D:\\Games"])
    for i in range(3):
        rid = store.add_result(job, FileResult(path=f"D:\\Games\\mod{i}.exe", sha256=_sha(i), findings=[_f()]))
        allowlist.mark_not_a_threat(store, rid)
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.MEDIUM


# ---- your own known-bad list -------------------------------------------------------------------
def test_confirmed_threats_go_to_your_known_bad_list(store, settings):
    path = settings.hashset_dir / learning.CONFIRMED_LIST
    assert learning.sync_confirmed_list(store, settings) == 0 and not path.exists()
    _verdict(store, 1, "confirmed_threat", path="D:\\Downloads\\bad#1.exe")
    _verdict(store, 2, "confirmed_threat")
    _verdict(store, 3, "not_a_threat")
    assert learning.sync_confirmed_list(store, settings) == 2
    text = path.read_text(encoding="utf-8")
    assert _sha(1) in text and _sha(2) in text and _sha(3) not in text
    # the existing known-bad check reads it and flags a copy with high confidence
    det = HashDetector(settings)
    det.open()
    data = b"pretend copy"
    item = ScanItem(display="E:\\copy.exe", data=data)
    item.sha256 = _sha(1)
    (hit,) = det.scan(item)
    assert hit.confidence == Confidence.HIGH and "your-confirmed-threats.txt" in hit.source
    assert "you confirmed this file as a threat (bad 1.exe)" == hit.rule      # '#' would start a comment
    # nothing changed: the file is not rewritten (its date is part of the signature version)
    mtime = path.stat().st_mtime_ns
    time.sleep(0.02)
    learning.sync_confirmed_list(store, settings)
    assert path.stat().st_mtime_ns == mtime
    assert not list(settings.hashset_dir.glob("*.tmp"))


def test_not_a_threat_later_takes_it_off_the_list(store, settings):
    path = settings.hashset_dir / learning.CONFIRMED_LIST
    _verdict(store, 1, "confirmed_threat")
    _verdict(store, 2, "confirmed_threat")
    learning.sync_confirmed_list(store, settings)
    _verdict(store, 1, "not_a_threat")
    assert learning.sync_confirmed_list(store, settings) == 1
    assert _sha(1) not in path.read_text(encoding="utf-8")
    _verdict(store, 2, "not_a_threat")
    assert learning.sync_confirmed_list(store, settings) == 0 and not path.exists()


def test_learning_off_removes_the_list_and_on_brings_it_back(store, settings):
    path = settings.hashset_dir / learning.CONFIRMED_LIST
    _verdict(store, 1, "confirmed_threat")
    learning.sync_confirmed_list(store, settings)
    settings.learning_enabled = False
    assert learning.sync_confirmed_list(store, settings) == 0 and not path.exists()
    settings.learning_enabled = True
    assert learning.sync_confirmed_list(store, settings) == 1 and path.exists()


def test_confirmed_without_a_fingerprint_is_not_listed(store, settings):
    store.add_verdict("", "D:\\locked.exe", "confirmed_threat", [_f().to_dict()])
    assert learning.sync_confirmed_list(store, settings) == 0
    # ...but it still cancels learning for its rule
    for i in range(3):
        _verdict(store, i)
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH


@pytest.mark.parametrize("bad", ["", "not json", "{}", "[1, 2]"])
def test_odd_stored_findings_are_ignored(store, settings, bad):
    store._con().execute("INSERT INTO verdicts(sha256, path, verdict, findings, created) VALUES(?,?,?,?,?)",
                         (_sha(50), "x", "not_a_threat", bad, time.time()))
    assert learning.learned_rules(store) == []
    assert _adjust(store, settings, [_f()])[0][0].confidence == Confidence.HIGH
